#ifndef AUTH_SHARE_POOL_H__
#define AUTH_SHARE_POOL_H__
#include "emp-ag2pc/helper.h"
#include "emp-tool/io/net_io_channel.h"
#include "emp-ot/ot_extension/iknp.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/ot_extension/softspoken/softspoken.h"
#include "emp-ag2pc/share_bundle.h"
#include <memory>

// Choose the OT extension backend used for the per-pair COT mesh.
// Every operation in this file goes through OTExtension's public API
// (set_delta, set_choice_seed, rcot_send, rcot_recv, base-class Δ and
// io fields), so swapping is a one-line typedef change. Candidates:
//   IKNP        — low setup, ~κ B/COT, fastest on small batches.
//   SoftSpoken<8> — low bandwidth (~κ/8 B/COT), higher compute.
//   Ferret      — ferret_b13 default; smallest steady-state bandwidth.
using OTExt = emp::SoftSpoken<8>;

#ifdef WRK_PROFILE
// Profiler: accumulates this party's COT (rcot) send+recv bytes so draw_and_seed
// can split its communication into COT vs the rest of the triple protocol.
inline uint64_t g_wrk_cot_bytes = 0;
#endif

// Π_aShare (Figure P-aShare, ashare.tex) + amortized pool. Step numbers
// in the comments below refer to that figure. check1 implements steps
// 3–7 (gadget-tail Δ-consistency) using pair-specific x^{me,j}; check2
// implements steps 10–12 (universal-hash share check). Step 8 (sample
// x^me) and step 9 (Fix) are collapsed into the COT itself: under the
// pinned-bit invariant bit0(Δ)=1, bit0(K)=0, bit0(M)=choice (enforced
// by COT post-processing), the receiver's choice IS x^me and the MAC
// relation M = K ⊕ x · Δ already holds straight out of rcot — no Fix
// exchange or KEY update is needed. The share x^me_k is recoverable as
// bit0(MAC[k]).
//
// Two small implementation choices:
//
// (1) Step 2's F_mCOT extension is a single ext_len = length + csp
//     tuple batch per peer. Positions [0, length) are the output
//     aShares; positions [length, ext_len) are s-tuples consumed by
//     check1's gadget packing. Labeling only — no protocol change.
//
// (2) FZero (step 4) is implemented via pairwise seed-and-expand under
//     the ideal-cipher assumption on the AES-based PRG; see check1.
//
// Streaming-friendly API split (Stage 2/3):
//   - process_phase1(MAC, KEY, length) — COT extension + step 8/9 fix.
//     Caller-allocated SoA arrays; csp tail dropped on return.
//   - check2_init(seed, length) / check2_chunk(start, n, MAC, KEY) /
//     check2_finalize() — universal-hash MAC consistency, with caller
//     driving the chunk loop. Seed comes from a sampleRandom done by
//     the caller (AuthSharePool's compute() does it internally;
//     TriplePool can share its own LAND-check seed).
//   - compute() is a thin wrapper for standalone use: process_phase1 +
//     internal sampleRandom + single full-range check2.
//   - draw(n, out) is a one-shot convenience: compute() into transient
//     SoA scratch, transpose into caller's AoS bundles. No persistent
//     pool — each call eats csp = 128 sacrificial bits regardless of
//     n, so prefer one large draw to many small ones.
class AuthSharePool { public:
	// Two COT instances against the single peer: abit1 (I am the OT sender,
	// ALICE) runs on recv_io, abit2 (I am the receiver, BOB) on send_io, so
	// the two run on separate sockets without contending. The OTExt typedef at
	// the top of this file selects the backend (IKNP / SoftSpoken / Ferret);
	// ctor takes (role, io) upfront, so we store unique_ptrs and construct in
	// the body of the AuthSharePool ctor.
	std::unique_ptr<OTExt> abit1;
	std::unique_ptr<OTExt> abit2;
	NetIO *send_io, *recv_io;
	ThreadPool *pool;
	int party;
	PRG prg;
	block Delta;
	int csp = 128;


	// `choice_seed_in` (optional): when non-null, all of this party's COT
	// receiver instances (abit2) seed their choice_prg from the same
	// block. With a shared choice seed, the choice bits Pi commits in
	// COT(i, j) are identical across j by construction, so x^me_k =
	// bit0(MAC[k]) is automatically consistent across peers —
	// step 8/9's r_choice/d exchange + K-update is unnecessary. When null,
	// we sample one internally; that's the default and gives the same
	// behavior. Pass an explicit seed only for determinism / testing.
	AuthSharePool(NetIO *io1, NetIO *io2, ThreadPool *pool, int party,
			const block *choice_seed_in = nullptr)
		: send_io(party == 1 ? io1 : io2), recv_io(party == 1 ? io2 : io1),
		  pool(pool), party(party) {
			// Enable the Fiat-Shamir transcript on both channels from the very
			// start of the protocol, so their digests bind the full transcript
			// (not just from the COT's first rcot onward). The per-channel role
			// is opposite on the two ends (party 1 vs 2), which is all the
			// digests need to agree; the COT's own lazy enable_fs then no-ops.
			if (!send_io->fs_enabled()) send_io->enable_fs(/*send_first=*/party == 1);
			if (!recv_io->fs_enabled()) recv_io->enable_fs(/*send_first=*/party == 1);

			// Step 1 (Fig.13 Init): pick Δ_me with two pinned bits:
			//   bit 0 of Δ — share-value encoding (always 1; lets bit0(M) carry
			//                the authenticated bit when bit0(K)=0).
			//   bit 1 of Δ — half-gate Λ_γ recovery: bit1(Δ_2)=1 and
			//                bit1(Δ_1)=0, so bit1(Δ_1 ⊕ Δ_2) = 1, which
			//                TriplePool's LaAND decoding d = LSB1(⊕ s^p) and
			//                2pc.h's b_γ = LSB1(m_{γ,0}^2) both rely on.
			bool tmp[128];
			prg.random_bool(tmp, 128);
			tmp[0] = true;
			tmp[1] = (party != 1);

			// Wire the two COTs to separate sockets so they run concurrently:
			// abit1 (I'm the OT sender, ALICE) on recv_io, abit2 (I'm the
			// receiver, BOB) on send_io. My abit1 pairs with the peer's abit2 on
			// the same physical socket. The OTExt ctor takes (role, io) upfront
			// and owns its base OT; set_delta below replaces abit1's
			// ctor-sampled Δ with our protocol Δ_me.
			abit1 = std::make_unique<OTExt>(ALICE, recv_io);
			abit2 = std::make_unique<OTExt>(BOB, send_io);

			// Install Δ_me on every sender instance. set_delta only updates
			// the Δ bits; the base-OT round-trip that ships Δ to the peer
			// happens lazily inside the first rcot_send / rcot_recv call.
			abit1->set_delta(tmp);

			// Shared choice seed: same r vector across all of Pi's COT
			// receiver instances, so x^me is implicitly consistent across peer
			// pairs without any step 8/9 fix-up exchange. set_choice_seed
			// is the OTExtension-level API — works the same regardless of
			// which concrete OTExt backend is in use.

			Delta = abit1->Delta;
		}

	// On entry, MAC[i]/KEY[i] may have any size; compute() grows them to
	// length + csp for the COT + gadget-tail check, then shrinks back to
	// length (preserving capacity). The output share x^me_k is implicit
	// in bit0(MAC[k]) — no separate share buffer.
	//
	// Stage 2 split: compute() is now a thin wrapper over process_phase1 +
	// the streaming check2 (init / chunk / finalize). The behavioral
	// contract (final MAC/KEY contents, network rounds, abort conditions)
	// is unchanged — TriplePool can later call the pieces directly to
	// interleave check2_chunk with its own per-region work.
	void compute(BlockVec &MAC, BlockVec &KEY, int length) {
		process_phase1(MAC, KEY, length);

#ifdef EMP_DEBUG_PHASE
		_phase("[abit] aShare", party);
		check_MAC(send_io, recv_io, MAC, KEY, Delta, length, party);
		_phase("", party);
#endif
	}

	// Phase 1: COT extension + step 8/9 fix, no check2.
	// On entry, MAC[i]/KEY[i] may have any size; on return they are exactly
	// `length` blocks each, with MAC = KEY ⊕ x^me · Δ and bit0(MAC) = x^me
	// across all peers (honest case). The csp tail used for check1 is
	// minted but discarded — re-enable check1 to consume it.
	void process_phase1(BlockVec &MAC, BlockVec &KEY, int length) {
		// Step 2 (COT-Extend): ext_len = length + csp random tuples.
		// Positions [0, length) are output aShares; [length, ext_len) are
		// s-tuples reserved for check1's gadget packing (currently unused —
		// COT still mints them so the FS check covers the same width as
		// before; we just don't pin/consume them).
		int ext_len = length + csp;
		MAC.resize(ext_len);
		KEY.resize(ext_len);

		// Step 8/9 ELIDED: with the shared choice_prg seed set in the ctor,
		// all of Pi's abit2 receivers commit the SAME choice bits
		// across peer pairs. So bit0(MAC[k]) = bit0(MAC[k])
		// = ... = x^me_k automatically — no need to sample x^me, exchange
		// r_choice/d, or update K. The pinned-bit invariants (bit0(Δ)=1,
		// bit0(K)=0, bit0(M)=choice) hold straight out of rcot's bit-0
		// post-processing. Honest Pi gets a consistent share by
		// construction; a malicious Pi using non-shared seeds across peers
		// would produce mismatched per-peer bit0(MAC), and check2's per-
		// peer Mw verification catches that — soundness preserved.
		// abit1 runs on recv_io, abit2 on send_io; each task flushes its own
		// channel so the two COTs proceed in parallel.
#ifdef WRK_PROFILE
		int64_t _cot0 = io_count(send_io, recv_io);
#endif
		vector<future<void>> res;
		{
			res.push_back(pool->enqueue([this, &KEY, ext_len]() {
				abit1->rcot(KEY.data(), ext_len);
				recv_io->flush();
			}));
			res.push_back(pool->enqueue([this, &MAC, ext_len]() {
				abit2->rcot(MAC.data(), ext_len);
				send_io->flush();
			}));
		}
		joinNclean(res);
#ifdef WRK_PROFILE
		g_wrk_cot_bytes += (uint64_t)(io_count(send_io, recv_io) - _cot0);
#endif

		// Drop the sacrificial tail; output region is [0, length).
		MAC.resize(length);
		KEY.resize(length);
	}

	// One-shot mint helper: run compute() into a fresh SoA scratch and
	// transpose into AoS bundles. Each call runs a full Π_aShare protocol
	// (csp tail + sampleRandom + check2 closing exchange), so prefer one
	// large draw to many small ones — the per-call fixed cost amortizes.
	// No persistent pool: scratch is stack-local to the call.
	void draw(int n, AShareBundleVec &out_bundle) {
		BlockVec tmac, tkey;
		compute(tmac, tkey, n);
		out_bundle.resize(n);
		for (int i = 0; i < n; ++i) {
			AShareBundle &wb = out_bundle[i];
			wb.mac = tmac[i];
			wb.key = tkey[i];
		}
	}
};
#endif // AUTH_SHARE_POOL_H__
