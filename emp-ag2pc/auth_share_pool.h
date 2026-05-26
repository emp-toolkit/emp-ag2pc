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

#ifdef AG2PC_PROFILE
// Profiler: accumulates this party's COT (rcot) send+recv bytes so draw_and_seed
// can split its communication into COT vs the rest of the triple protocol.
inline uint64_t g_ag2pc_cot_bytes = 0;
#endif

// Authenticated-bit (aShare) generation via correlated OT. For a shared bit
// x = x_A ⊕ x_B each party holds (MAC, KEY) with MAC = KEY ⊕ x·Δ under the
// peer's Δ. The bit-0/bit-1 Δ pinning (bit0(Δ)=1, bit0(K)=0, enforced by the
// COT's bit-0 post-processing) makes bit0(MAC) carry the share bit x directly:
// the COT receiver's choice IS x and M = K ⊕ x·Δ holds straight out of rcot, so
// no separate sample-x / fix step is needed; the share x_k is read back as
// bit0(MAC[k]).
//
// API:
//   - process_phase1(MAC, KEY, length): COT extension into caller buffers,
//     returning `length` aShares (a csp-bit sacrificial tail is over-minted
//     and dropped).
//   - compute(): process_phase1 (plus an optional debug MAC check).
//   - draw(n, out): a compute() transposed into AoS bundles. No persistent
//     pool — each call mints fresh and pays the csp tail, so prefer one large
//     draw to many small ones.
class AuthSharePool { public:
	// Two COT instances against the single peer: abit1 (I am the OT sender,
	// ALICE) runs on recv_io, abit2 (I am the receiver, BOB) on send_io, so
	// the two run on separate sockets without contending. The OTExt typedef at
	// the top of this file selects the backend (IKNP / SoftSpoken / Ferret);
	// ctor takes (role, io) upfront, so we store unique_ptrs and construct in
	// the body of the AuthSharePool ctor.
	std::unique_ptr<OTExt> abit1;
	std::unique_ptr<OTExt> abit2;
	// io = the primary channel (sequential comm); sib = the second channel.
	// send_io/recv_io alias (io, sib) by party and are used only by the duplex
	// COTs below. All borrowed; the owner (TriplePool/C2PC) frees sib.
	NetIO *io, *sib, *send_io, *recv_io;
	ThreadPool *pool;
	int party;
	PRG prg;
	block Delta;
	int csp = 128;


	AuthSharePool(NetIO *io, NetIO *sib, ThreadPool *pool, int party)
		: io(io), sib(sib),
		  send_io(party == 1 ? io : sib), recv_io(party == 1 ? sib : io),
		  pool(pool), party(party) {
			// Enable the Fiat-Shamir transcript on both channels from the start,
			// so their digests bind the full transcript. The per-channel role is
			// opposite on the two ends (party 1 vs 2), which is all the digests
			// need to agree; the COT's own lazy enable_fs then no-ops.
			if (!io->fs_enabled())  io->enable_fs(/*send_first=*/party == 1);
			if (!sib->fs_enabled()) sib->enable_fs(/*send_first=*/party == 1);

			// Pick Δ_me with two pinned bits:
			//   bit 0 — share-value encoding: always 1, so bit0(M) carries the
			//           authenticated bit when bit0(K)=0.
			//   bit 1 — set so bit1(Δ_1 ⊕ Δ_2) = 1 (bit1(Δ_2)=1, bit1(Δ_1)=0);
			//           the half-gate parity recovery relies on this invariant.
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

			// Install Δ_me on the sender instance. set_delta only updates the
			// Δ bits; the base-OT round-trip that ships Δ to the peer happens
			// lazily inside the first rcot call.
			abit1->set_delta(tmp);
			Delta = abit1->Delta;
		}

	// Mint `length` aShares into MAC/KEY (resized as needed). The share x_k is
	// implicit in bit0(MAC[k]) — no separate share buffer.
	void compute(BlockVec &MAC, BlockVec &KEY, int length) {
		process_phase1(MAC, KEY, length);

#ifdef EMP_DEBUG_PHASE
		_phase("[abit] aShare", party);
		check_MAC(io, MAC, KEY, Delta, length, party);
		_phase("", party);
#endif
	}

	// COT extension. On return MAC/KEY are exactly `length` blocks each with
	// MAC = KEY ⊕ x·Δ and bit0(MAC) = x. The share bit is the COT choice bit
	// (pinned bit-0 invariant), so this is the whole aShare step.
	void process_phase1(BlockVec &MAC, BlockVec &KEY, int length) {
		// Extend to length + csp; the csp tail is a sacrificial margin dropped
		// before return.
		int ext_len = length + csp;
		MAC.resize(ext_len);
		KEY.resize(ext_len);

		// abit1 runs on recv_io, abit2 on send_io; each task flushes its own
		// channel so the two COTs proceed in parallel.
#ifdef AG2PC_PROFILE
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
#ifdef AG2PC_PROFILE
		g_ag2pc_cot_bytes += (uint64_t)(io_count(send_io, recv_io) - _cot0);
#endif

		// Drop the sacrificial tail; output region is [0, length).
		MAC.resize(length);
		KEY.resize(length);
	}

	// Mint n aShares into a fresh scratch and transpose into AoS bundles.
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
