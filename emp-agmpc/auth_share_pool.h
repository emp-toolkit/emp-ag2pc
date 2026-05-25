#ifndef AUTH_SHARE_POOL_H__
#define AUTH_SHARE_POOL_H__
#include "emp-agmpc/helper.h"
#include "emp-agmpc/netmp.h"
#include "emp-ot/ot_extension/iknp.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/ot_extension/softspoken/softspoken.h"
#include "emp-agmpc/share_bundle.h"
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
// bit0(MAC[any non-self peer][k]).
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
template <int nP>
class AuthSharePool { public:
	// Each party holds COT instances against every peer: abit1 is used as
	// sender when party < peer and as receiver otherwise (abit2 is the
	// mirror). Slot [party] is unused. The OTExt typedef at the top of
	// this file selects the backend (IKNP / SoftSpoken / Ferret); ctor
	// takes (role, io) upfront, so we store unique_ptrs and construct
	// per-peer in the body of the AuthSharePool ctor.
	std::unique_ptr<OTExt> abit1[nP + 1];
	std::unique_ptr<OTExt> abit2[nP + 1];
	NetIOMP<nP> *io;
	ThreadPool *pool;
	int party;
	PRG prg;
	block Delta;
	Hash hash;
	int csp = 128;
	GaloisFieldPacking packer;

	// ==== Streaming check2 state (Stage 2 split) ====
	// Set up by check2_init, accumulated by check2_chunk, drained by
	// check2_finalize. Lifetime is per-call: each check2_init resets to a
	// fresh session.
	int check2_length = 0;
	BlockVec check2_coeff;
	block check2_bw;
	block check2_Mw[nP + 1];
	block check2_Kw[nP + 1];
	std::unique_ptr<EchoBC<nP>> check2_echo;

	// `choice_seed_in` (optional): when non-null, all of this party's COT
	// receiver instances (abit2[peer]) seed their choice_prg from the same
	// block. With a shared choice seed, the choice bits Pi commits in
	// COT(i, j) are identical across j by construction, so x^me_k =
	// bit0(MAC[any_peer][k]) is automatically consistent across peers —
	// step 8/9's r_choice/d exchange + K-update is unnecessary. When null,
	// we sample one internally; that's the default and gives the same
	// behavior. Pass an explicit seed only for determinism / testing.
	AuthSharePool(NetIOMP<nP> *io, ThreadPool *pool, int party,
			const block *choice_seed_in = nullptr)
		: io(io), pool(pool), party(party) {
			// Step 1 (Fig.13 Init): pick Δ_me with two pinned bits:
			//   bit 0 of Δ — share-value encoding (always 1; lets bit0(M) carry
			//                the authenticated bit when bit0(K)=0).
			//   bit 1 of Δ — half-gate Λ_γ recovery: bit1(Δ_j)=1 for j≠1,
			//                bit1(Δ_1) = nP mod 2. So bit1(⊕_p Δ_p) = 1, which
			//                TriplePool's LaAND decoding d = LSB1(⊕ s^p) and
			//                mpc.h's b_γ = LSB1(m_{γ,0}^2) both rely on.
			bool tmp[128];
			prg.random_bool(tmp, 128);
			tmp[0] = true;
			if (party == 1) tmp[1] = (nP % 2 == 1);
			else tmp[1] = true;

			// Wire each Cot to its peer's IO channel. For the (party < peer)
			// pair, party acts as sender on channel 0 (abit1) and receiver on
			// channel 1 (abit2); the mirror holds for (party > peer). The
			// OTExt ctor takes (role, io) upfront and owns its base OT, so
			// we construct directly with the routed channel rather than
			// poking io post-construction. Pass party_=ALICE on abit1
			// (sender) and party_=BOB on abit2 (receiver). set_delta below
			// replaces the abit1 ctor-sampled Δ with our protocol Δ_me.
			for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
				bool me_smaller = party < peer;
				abit1[peer] = std::make_unique<OTExt>(
					ALICE, io->get(peer, /*swap=*/me_smaller ? false : true));
				abit2[peer] = std::make_unique<OTExt>(
					BOB, io->get(peer, /*swap=*/me_smaller ? true : false));
			}

			// Install Δ_me on every sender instance. set_delta only updates
			// the Δ bits; the base-OT round-trip that ships Δ to the peer
			// happens lazily inside the first rcot_send / rcot_recv call.
			for (int peer = 1; peer <= nP; ++peer) if (peer != party)
				abit1[peer]->set_delta(tmp);

			// Shared choice seed: same r vector across all of Pi's COT
			// receiver instances, so x^me is implicitly consistent across peer
			// pairs without any step 8/9 fix-up exchange. set_choice_seed
			// is the OTExtension-level API — works the same regardless of
			// which concrete OTExt backend is in use.
			block choice_seed;
			if (choice_seed_in) choice_seed = *choice_seed_in;
			else prg.random_block(&choice_seed, 1);
			for (int peer = 1; peer <= nP; ++peer) if (peer != party)
				abit2[peer]->set_choice_seed(choice_seed);

			Delta = abit1[party == 1 ? 2 : 1]->Delta;
		}

	// On entry, MAC[i]/KEY[i] may have any size; compute() grows them to
	// length + csp for the COT + gadget-tail check, then shrinks back to
	// length (preserving capacity). The output share x^me_k is implicit
	// in bit0(MAC[any non-self peer][k]) — no separate share buffer.
	//
	// Stage 2 split: compute() is now a thin wrapper over process_phase1 +
	// the streaming check2 (init / chunk / finalize). The behavioral
	// contract (final MAC/KEY contents, network rounds, abort conditions)
	// is unchanged — TriplePool can later call the pieces directly to
	// interleave check2_chunk with its own per-region work.
	void compute(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) {
		process_phase1(MAC, KEY, length);

		// Step 10 seed: collectively-sampled, derived after MAC/KEY are
		// committed (post-step-9), so adversary can't adapt MAC/KEY to it.
		block seed = sampleRandom(io, &prg, pool, party);
		check2_init(seed, length);
		check2_chunk(0, length, MAC, KEY);
		check2_finalize();

#ifdef EMP_DEBUG_PHASE
		_phase("[abit] aShare", party);
		check_MAC(io, MAC, KEY, Delta, length, party);
		_phase("", party);
#endif
	}

	// Phase 1: COT extension + step 8/9 fix, no check2.
	// On entry, MAC[i]/KEY[i] may have any size; on return they are exactly
	// `length` blocks each, with MAC = KEY ⊕ x^me · Δ and bit0(MAC) = x^me
	// across all peers (honest case). The csp tail used for check1 is
	// minted but discarded — re-enable check1 to consume it.
	void process_phase1(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) {
		// Step 2 (COT-Extend): ext_len = length + csp random tuples per peer.
		// Positions [0, length) are output aShares; [length, ext_len) are
		// s-tuples reserved for check1's gadget packing (currently unused —
		// COT still mints them so the FS check covers the same width as
		// before; we just don't pin/consume them).
		int ext_len = length + csp;
		for (int i = 1; i <= nP; ++i) if (i != party) {
			MAC[i].resize(ext_len);
			KEY[i].resize(ext_len);
		}

		// Step 8/9 ELIDED: with the shared choice_prg seed set in the ctor,
		// all of Pi's abit2[peer] receivers commit the SAME choice bits
		// across peer pairs. So bit0(MAC[peer1][k]) = bit0(MAC[peer2][k])
		// = ... = x^me_k automatically — no need to sample x^me, exchange
		// r_choice/d, or update K. The pinned-bit invariants (bit0(Δ)=1,
		// bit0(K)=0, bit0(M)=choice) hold straight out of rcot's bit-0
		// post-processing. Honest Pi gets a consistent share by
		// construction; a malicious Pi using non-shared seeds across peers
		// would produce mismatched per-peer bit0(MAC), and check2's per-
		// peer Mw verification catches that — soundness preserved.
		// Same channel-routing caveat as in the ctor: io->flush(peer) hits
		// the abit2 channel, so we must flush abit1.io directly.
#ifdef WRK_PROFILE
		int64_t _cot0 = io->count();
#endif
		vector<future<void>> res;
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			bool me_smaller = party < peer;
			res.push_back(pool->enqueue([this, KEY, ext_len, peer, me_smaller]() {
				abit1[peer]->rcot(KEY[peer].data(), ext_len);
				io->get(peer, me_smaller ? false : true)->flush();
			}));
			res.push_back(pool->enqueue([this, MAC, ext_len, peer, me_smaller]() {
				abit2[peer]->rcot(MAC[peer].data(), ext_len);
				io->get(peer, me_smaller ? true : false)->flush();
			}));
		}
		joinNclean(res);
#ifdef WRK_PROFILE
		g_wrk_cot_bytes += (uint64_t)(io->count() - _cot0);
#endif

		// Drop the sacrificial tail; output region is [0, length).
		for (int i = 1; i <= nP; ++i) if (i != party) {
			MAC[i].resize(length);
			KEY[i].resize(length);
		}
	}

	// Begin a streaming check2 session of `length` aShares with the given
	// collectively-sampled seed. Allocates coefficients[length] and zeroes
	// the per-peer accumulators; subsequent check2_chunk calls fold their
	// slice into bw / Mw[peer] / Kw[peer]. EchoBC is owned by check2 — its
	// bw broadcast and finalize happen in check2_finalize.
	void check2_init(block seed, int length) {
		check2_length = length;
		check2_coeff.resize(length);
		PRG prg2(&seed);
		prg2.random_block(check2_coeff.data(), length);
		check2_bw = zero_block;
		for (int i = 0; i <= nP; ++i) {
			check2_Mw[i] = zero_block;
			check2_Kw[i] = zero_block;
		}
		check2_echo.reset(new EchoBC<nP>(io, pool, party));
	}

	// Accumulate Mw[peer]/Kw[peer]/bw partial sums over [start, start+n).
	// Caller may invoke this any number of times in any order over disjoint
	// sub-ranges of [0, length); result before finalize is the sum over all
	// invoked ranges. Streaming use-case: TriplePool walks each region of
	// its 3*LB aShare batch and feeds a chunk per region.
	void check2_chunk(int start, int n,
			BlockVec MAC[nP + 1], BlockVec KEY[nP + 1]) {
		// w^me partial: bw += Σ_{k in chunk} coeff[k] · bit0(MAC[any_peer][k]).
		// Branchless tab[bit] mirrors the original loop; bit0(MAC) is the
		// same across peers post-step-9, so we only need one peer's MAC.
		int any_peer = (party == 1) ? 2 : 1;
		block tab[2] = {zero_block, zero_block};
		for (int k = start; k < start + n; ++k) {
			tab[1] = check2_coeff[k];
			check2_bw = check2_bw ^ tab[LSB(MAC[any_peer][k])];
		}
		// Mw/Kw partial: vector_inn_prdt_sum_red writes Σ coeff·v into a
		// fresh block; XOR into running accumulator.
		block partial;
		for (int i = 1; i <= nP; ++i) if (i != party) {
			vector_inn_prdt_sum_red(&partial, check2_coeff.data() + start,
					MAC[i].data() + start, n);
			check2_Mw[i] = check2_Mw[i] ^ partial;
			vector_inn_prdt_sum_red(&partial, check2_coeff.data() + start,
					KEY[i].data() + start, n);
			check2_Kw[i] = check2_Kw[i] ^ partial;
		}
	}

	// Close the check2 session: broadcast bw via FBC, exchange Mw with each
	// peer, verify M_me[w^peer] = K_me[w^peer] ⊕ w^peer · Δ_me. Aborts on
	// cheating. echo.finalize() also runs, ensuring all_bcast transcripts
	// agreed across parties.
	void check2_finalize() {
		block bw_recv[nP + 1];
		check2_echo->all_bcast(check2_bw, bw_recv);

		vector<future<void>> res;
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			res.push_back(pool->enqueue([this, peer]() {
				io->send_data(peer, &check2_Mw[peer], sizeof(block));
				io->flush(peer);
			}));
			res.push_back(pool->enqueue([this, &bw_recv, peer]() {
				block Mw_recv, tmp;
				io->recv_data(peer, &Mw_recv, sizeof(block));
				gfmul(bw_recv[peer], Delta, &tmp);
				block Kw_check = check2_Kw[peer] ^ tmp;
				if (!cmpBlock(&Kw_check, &Mw_recv, 1))
					error("cheat aShare\n");
			}));
		}
		joinNclean(res);

		check2_echo->finalize();
		check2_echo.reset();
		check2_coeff.clear();
		check2_coeff.shrink_to_fit();
	}

	// Steps 3–7 (Fig.13): gadget-tail Δ-consistency check.
	void check1(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length, EchoBC<nP> &echo) {
		// Step 3: pack the csp s-tuple tail through the gadget g = (1, X, …,
		// X^{λ-1}) to get pair-specific x^{me,j} ∈ F_{2^λ} (one per peer).
		//   Mx[j] = M_j[x^{me,j}] from MAC tail
		//   Kx[j] = K_me[x^{j,me}] from KEY tail
		//   xv[j] = x^{me,j}        from bit0 of MAC[j] tail (carries choice)
		block Mx[nP + 1], Kx[nP + 1], xv[nP + 1];
		for (int i = 1; i <= nP; ++i) if (i != party) {
			packer.packing(&Mx[i], MAC[i].data() + length);
			packer.packing(&Kx[i], KEY[i].data() + length);
			// ⟨g, s⟩ = ∑ s_k · X^k packs the 128 choice bits into a 128-bit
			// field element; bit_k of the block is s_k. Read s_k from bit0
			// of the MAC tail entry directly.
			bool tail_bits[128];
			for (int k = 0; k < 128; ++k)
				tail_bits[k] = LSB(MAC[i][length + k]);
			xv[i] = bool_to_block(tail_bits);
		}
		Mx[party] = zero_block;
		Kx[party] = zero_block;
		xv[party] = zero_block;  // spec sets x^{me,me} := 0

		// Step 4 (FZero): produce u^me ∈ (F_{2^λ})^nP with ⊕_p u^p_k = 0 for
		// every column k. See fzero_xor in helper.h.
		block u_me[nP];
		for (int k = 0; k < nP; ++k) u_me[k] = zero_block;
		fzero_xor<nP>(io, &prg, pool, party, u_me, nP);

		vector<future<void>> res;

		// Step 5: y^me_k = x^{me,k} ⊕ u^me_k (with x^{me,me} := 0 so the k+1==me
		// column is just u^me_k). Broadcast y^me via FBC (echo). Index k
		// (0-based) here corresponds to column k+1 (1-indexed parties).
		block y_me[nP];
		for (int k = 0; k < nP; ++k)
			y_me[k] = xv[k + 1] ^ u_me[k];

		block y_storage[nP + 1][nP];
		block *y_view[nP + 1];
		for (int p = 1; p <= nP; ++p) y_view[p] = y_storage[p];
		echo.all_bcast(y_me, nP, y_view);

		// Step 6: y_j = ⊕_p y^p_j (column sum). By zero-share, y_j = ⊕_{p≠j} x^{p,j}.
		// Build z^me with z^me_j = M_j[x^{me,j}] for j ≠ me and
		// z^me_me = ⊕_{j≠me} K_me[x^{j,me}] ⊕ y_me · Δ_me. Commit via hash.
		block y_global[nP];
		for (int k = 0; k < nP; ++k) {
			y_global[k] = zero_block;
			for (int p = 1; p <= nP; ++p) y_global[k] ^= y_view[p][k];
		}

		block z[nP + 1];
		for (int i = 1; i <= nP; ++i) z[i] = Mx[i];
		block tD;
		gfmul(y_global[party - 1], Delta, &tD);
		z[party] = tD;
		for (int i = 1; i <= nP; ++i) if (i != party) z[party] ^= Kx[i];

		char z_dgst[nP + 1][Hash::DIGEST_SIZE];
		Hash::hash_once(z_dgst[party], z + 1, nP * sizeof(block));
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			res.push_back(pool->enqueue([this, &z_dgst, peer]() {
				io->send_data(peer, z_dgst[party], Hash::DIGEST_SIZE);
				io->flush(peer);
			}));
			res.push_back(pool->enqueue([this, &z_dgst, peer]() {
				io->recv_data(peer, z_dgst[peer], Hash::DIGEST_SIZE);
			}));
		}
		joinNclean(res);

		// Step 7: open z^me; verify ⊕_p z^p_j = 0 for every column j.
		// Columns where j = some party p collapse via MAC = KEY ⊕ x · Δ_p
		// to a Δ-consistency identity that holds iff Δ_p is consistent across
		// p's COT instances (and the y-construction is faithful).
		block z_storage[nP + 1][nP];
		block *z_recv[nP + 1];
		for (int i = 1; i <= nP; ++i) z_recv[i] = (i == party ? z + 1 : z_storage[i]);
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			res.push_back(pool->enqueue([this, &z, peer]() {
				io->send_data(peer, z + 1, nP * sizeof(block));
				io->flush(peer);
			}));
			res.push_back(pool->enqueue([this, &z_recv, &z_dgst, peer]() {
				io->recv_data(peer, z_recv[peer], nP * sizeof(block));
				char chk[Hash::DIGEST_SIZE];
				Hash::hash_once(chk, z_recv[peer], nP * sizeof(block));
				if (memcmp(chk, z_dgst[peer], Hash::DIGEST_SIZE) != 0)
					error("cheat check1: commit mismatch\n");
			}));
		}
		joinNclean(res);

		for (int k = 0; k < nP; ++k) {
			block sum = zero_block;
			for (int p = 1; p <= nP; ++p) sum ^= z_recv[p][k];
			if (!cmpBlock(&sum, &zero_block, 1))
				error("cheat check1\n");
		}
	}

	// One-shot mint helper: run compute() into a fresh SoA scratch and
	// transpose into AoS bundles. Each call runs a full Π_aShare protocol
	// (csp tail + sampleRandom + check2 closing exchange), so prefer one
	// large draw to many small ones — the per-call fixed cost amortizes.
	// No persistent pool: scratch is stack-local to the call.
	void draw(int n, AShareBundleVec<nP> &out_bundle) {
		BlockVec tmac[nP + 1], tkey[nP + 1];
		compute(tmac, tkey, n);
		out_bundle.resize(n);
		for (int i = 0; i < n; ++i) {
			AShareBundle<nP> &wb = out_bundle[i];
			for (int j = 1, k = 0; j <= nP; ++j) {
				if (j == party) continue;
				wb.mac(k) = tmac[j][i];
				wb.key(k) = tkey[j][i];
				++k;
			}
		}
	}
};
#endif // AUTH_SHARE_POOL_H__
