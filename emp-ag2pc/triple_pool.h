#ifndef TRIPLE_POOL_H__
#define TRIPLE_POOL_H__
#include "emp-ag2pc/auth_share_pool.h"
#include "emp-tool/io/net_io_channel.h"
#include "emp-tool/crypto/mitccrh.h"
#include "emp-tool/crypto/prp.h"
#include <thread>

using namespace emp;

#ifdef WRK_PROFILE
// Profiler: this party's send+recv bytes spent in the half-gate phi exchange.
inline uint64_t g_wrk_phi_bytes = 0;
#endif

// Π_LaAND followed by Π_Prep bucketing + amortized pool: AND-triple
// generation via half-gate garbled-AND + phi-based triple check (P:LaAND),
// then circular-shift bucketing to remove leakage (P:aAND). See triple.tex.
//
// Deviations from the paper:
//
// (1) FZero (P:LaAND step 3) is implemented via pairwise seed-and-expand
//     under the ICM assumption on the AES-based PRG: each pair shares a
//     λ-bit seed, both expand into LB+1 blocks via PRG, XOR into local
//     (z^i, u^i). Each seed contributes to exactly two parties so
//     Σ_p z^p_k = 0 and Σ_p u^p = 0. (Same construction as
//     AuthSharePool::check1.)
//
// (2) F_Com is collapsed to a single send for both d^i (steps 6→7) and
//     α^i (steps 9→10).  No value derived from the committed bits is
//     sent before the matching open, so equivocation is impossible —
//     the commitment phase is redundant.  α^i is hash-committed first
//     (one round) and then opened, since the α-check needs binding.
//
// (3) The B-1 sequential OpenToAll calls in P:aAND step 4 (one per
//     non-first leaky triple in each bucket) are batched into a single
//     all-to-all exchange of the full d-vector, dropping the bucket
//     combine to one round.
//
// Pool semantics (Phase C):
//   - compute() is the refill primitive: mints exactly `length` fresh
//     triples into caller-supplied buffers. Bucket size B drops with
//     `length` (5 / 4 / 3 at thresholds 3.1K / 280K), so big batches
//     shrink the per-triple cost meaningfully — hence min_refill
//     defaults to 280000 (the bucket-3 threshold).
//   - draw(n, ...) is the amortized API: pulls n triples from an
//     internal pool, refilling via compute(min_refill) when short.
//   - preprocess(n) eagerly mints up to n triples for measured-window
//     benchmarks.
class TriplePool {
public:
  ThreadPool *pool;
  int party;
  NetIO *io1, *io2;
  AuthSharePool abit;
  block Delta;
  PRG prg;

  // ==== Pool storage (Phase C) ====
  // AoS-by-triple layout: pool_triples[t] holds three AShareBundles (slots
  // 0/1/2) for triple t. Internal compute() still emits SoA per-peer
  // slot-major arrays — refill_internal transposes once on insert so
  // consumers read AoS via draw(). The triple's share bits live in
  // bit0(pool_triples[t].b[s].mac) for slots a/b/c at s=0/1/2.
  TripleBundleVec pool_triples;
  size_t cursor = 0;
  // Floor for refill batch size. Any draw smaller than this still mints
  // `min_refill` triples to amortize the per-call protocol overhead
  // (csp tail, closing exchanges). Set at the bucket_size=4
  // threshold from Figure 16: anything ≥ 3100 already gets B=4, so this
  // floor doesn't push us into a worse bucket. Genuinely large workloads
  // (≥ 280K triples) still hit B=3 naturally because `batch = max(needed,
  // min_refill)` ≥ needed ≥ 280K. The previous floor of 280000 was tuned
  // for B=3 always but threw away ~90% of the minted triples on
  // SHA-256-sized circuits where the actual demand is ~22K.
  size_t min_refill = 3100;

  TriplePool(NetIO *io1, NetIO *io2, ThreadPool *pool, int party)
      : pool(pool), party(party), io1(io1), io2(io2),
        abit(io1, io2, pool, party), Delta(abit.Delta) {}

  // The duplex channel pair to the peer. io1 carries 1->2, io2 carries 2->1;
  // send/recv pick by sign(idx - party). We reach them directly to send bit
  // vectors via the channel's packed send_bool/recv_bool (8 bits/byte) rather
  // than one byte per bit.
  NetIO *send_ch(int dst) { return party < dst ? io1 : io2; }
  NetIO *recv_ch(int src) { return src < party ? io1 : io2; }

  // Bucket size B vs. number of triples ℓ_2 — picked from the leak-rate bound
  // max(1/2^ssp + (2B+1)/ℓ^{B-1}, ...) (see triple.tex theorem for Π_aAND).
  // Floor at 320 so tiny calls still hit safe (B,ℓ) pairs.
  int get_bucket_size(int size) {
    size = max(size, 320);
    if (size >= 280 * 1000)
      return 3;
    else if (size >= 3100)
      return 4;
    else
      return 5;
  }

  // Leaky-AND generation method. COT/aShare generation, the aShare consistency
  // check, and the final Π_aAND bucketing are shared across methods; only the
  // middle leaky-AND step and its COT demand differ. HalfGate = WRK's garbled
  // half-gate phi exchange (current). CutChoose = an OT-based cut-and-choose
  // (FKOS / TinyOT style) — not implemented; the seam is here to drop it in.
  enum class LeakyAnd { HalfGate, CutChoose };
  static constexpr LeakyAnd kLeakyAnd = LeakyAnd::HalfGate;
  static constexpr int cutchoose_T = 3;  // correctness-sacrifice bucket size

  // Authenticated bits to mint for LB leaky-triple slots under the active
  // method. Half-gate needs 3*LB (a, b, r); a cut-and-choose method returns
  // more (it does the multiplication via OT rather than a garbled gate).
  static int leaky_abit_len(int LB) {
    // half-gate: 3·LB (a,b,r). cut-choose: 3·(T·LB) candidates → sacrifice keeps
    // LB (the ~T× / "triple-the-COT" overhead) → Π_Prep then buckets LB→length.
    return kLeakyAnd == LeakyAnd::HalfGate ? 3 * LB : 3 * cutchoose_T * LB;
  }

  // ===== Cut-and-choose (FKOS) leaky-AND (dormant while kLeakyAnd==HalfGate) =====
  // The OT-multiply / sacrifice path + self-tests live in their own file to keep
  // this one half-gate-focused. Included inside the class so they stay inline
  // TriplePool members (multiply_unauth, make_leaky_triples_cutchoose,
  // cutchoose_leaky, open_bits, and the *_selftest entry points).
  #include "emp-ag2pc/triple_pool_cutchoose.h"

  // The output share-bits are implicit: bit0(MAC[k])
  // gives the k-th share-bit for slot k/length (a / b / c at offsets
  // 0 / length / 2*length). bit0(KEY[*]) = 0 throughout.
  // Stage 4d: optional out_aos. When non-null, bucketing also writes its
  // per-output-index XOR results into pool_triples-shaped AoS bundles
  // (one TripleBundle per output index), eliminating the standalone
  // transpose pass at refill. SoA MAC/KEY writes are still produced for
  // the debug check_MAC / check_correctness path.
  void compute(block *MAC, block *KEY, int length,
               TripleBundle *out_aos = nullptr) {
    int bucket_size = get_bucket_size(length);
    int LB = length * bucket_size;
    // Authenticated bits per leaky-AND slot, set by the active leaky-AND method
    // (half-gate: 3·LB = a, b, r). abit's internal sacrificial tail (csp
    // positions for the gadget Δ-check in abit.check1) is grown and dropped
    // inside abit.compute — it doesn't appear in our buffers on output. We
    // over-reserve MAC/KEY by csp to avoid the realloc when abit grows.
    int abit_len = leaky_abit_len(LB);

    BlockVec tMAC, tKEY;
    // tKEYphi[party] is the s^i / t^i accumulator (overwritten in step 5b);
    // tKEYphi[peer] holds the sender-side half-gate output. tMACphi holds the
    // single peer's receiver-side half-gate output (the would-be tMACphi[party]
    // is never written or read, so it is just one buffer rather than a slot
    // array). s[party]/s[peer] are the two parties' garbling-parity shares and
    // s[0] their opened XOR.
    BlockVec tKEYphi[3], tMACphi;
    BlockVec phi(LB);
    vector<unsigned char> s[3];
    vector<unsigned char> tr;

    tr.reserve(abit_len);
    tMAC.reserve(abit_len + abit.csp);
    tKEY.reserve(abit_len + abit.csp);
    tMACphi.resize(LB);
    for (int i = 1; i <= 2; ++i)
      tKEYphi[i].resize(LB);
    for (int i = 0; i <= 2; ++i) s[i].resize(LB);

#ifdef EMP_DEBUG_PHASE
    _phase("", party);
#endif

    // steps 1+2: Init + Gen aShares.  Stage 4a: split abit.compute into
    // process_phase1 (now) + check2_init/chunk/finalize (deferred to the
    // end of TriplePool::compute). Defers integrity verification, but the
    // verification still runs before TriplePool's outputs are consumed —
    // so cheating is still caught, just slightly later. Lets us interleave
    // check2_chunk with per-region passes in subsequent stages.
    abit.process_phase1(tMAC, tKEY, abit_len);
    // Share bits live in bit 0 of MAC (any non-self peer carries the same
    // bit). Pull them out into tr once so the existing tr-indexed code
    // below stays unchanged; Step D will fold these reads inline.
    {
      int any_peer = (party == 1) ? 2 : 1;
      tr.resize(abit_len);
      for (int k = 0; k < abit_len; ++k)
        tr[k] = LSB(tMAC[k]);
    }

    vector<future<void>> res;

    // ======================================================================
    // SWAPPABLE leaky-AND generation (half-gate phi method). Consumes the
    // a/b/r authenticated bits in tMAC/tKEY (+ share bits tr) and produces LB
    // leaky-but-checked AND triples in the a/b/c slot layout that bucketing
    // reads (r -> c). Scratch (tKEYphi/tMACphi/phi/s) is captured by ref. To
    // use a different method (e.g. OT-based cut-and-choose), add a sibling with
    // the same contract + its own leaky_abit_len, and dispatch at the call.
    // ======================================================================
    auto produce_leaky_ands_halfgate = [&]() {
    // step 3 (FZero): produce (z^i ∈ F_{2^λ}^LB, u^i ∈ F_{2^λ}) with
    // Σ_p z^p_k = 0 (column-wise) and Σ_p u^p = 0. See fzero_xor in
    // helper.h. We pack into a single LB+1-block buffer; step 4 then
    // XORs the b·Δ ⊕ K ⊕ M terms into phi[0..LB) on top of z^i.
    BlockVec z_u(LB + 1, zero_block);
    fzero_xor(io1, io2, &prg, pool, party, z_u.data(), LB + 1);
    for (int k = 0; k < LB; ++k) phi[k] = z_u[k];
    block u_zero = z_u[LB];
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] zero", party);
#endif

    // step 4: Φ^i_k = b^i·Δ_i ⊕ ⊕_{j≠i} (K_i[b^j] ⊕ M_j[b^i]) ⊕ z^i_k.
    // z^i_k is already in phi[k] from step 3, so we XOR-in the rest.
    int width = (LB + pool->size() - 1) / pool->size();
    for (int wi = 0; wi < pool->size(); ++wi) {
      int st = wi * width, ed = std::min((wi + 1) * width, LB);
      res.push_back(pool->enqueue([this, st, ed, LB, &tKEY, &tMAC, &phi, &tr]() {
        for (int k = st; k < ed; ++k) {
          phi[k] ^= (select_mask[tr[LB + k]] & Delta);
          { const int j = 3 - party;
            phi[k] ^= tKEY[LB + k];
            phi[k] ^= tMAC[LB + k];
          }
        }
      }));
    }
    joinNclean(res);
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] phi compute", party);
#endif

    // step 5(a): half-gate phi exchange via MITCCRH.
    // Per peer-pair, both sides instantiate MITCCRH<8> with the same
    // public start_point S_pair = makeBlock(min,max) so their AES keys
    // (S_pair ⊕ makeBlock(gid,0)) advance in lockstep. Sender's hash<8,2>
    // uses 8 keys × 2 blocks (key, key⊕Delta); receiver's hash<8,1> uses
    // the same 8 keys × 1 block (mac). Output: pad[i] = H(x) = AES(x)⊕x.
    // Network is streamed in `hg_chunk` blocks; the per-task scratch
    // buffer is allocated once and reused across chunks.
    int hg_chunk = 1 << 16;
#ifdef WRK_PROFILE
    int64_t _phi0 = io_count(io1, io2);
#endif
    { const int peer = 3 - party;
      block pair_seed = makeBlock((uint64_t)std::min(party, peer),
                                  (uint64_t)std::max(party, peer));
      res.push_back(pool->enqueue([this, &tKEY, &tKEYphi, &phi, LB, peer, pair_seed, hg_chunk]() {
        MITCCRH<8> mitc;
        mitc.setS(pair_seed);
        block pad[16];
        BlockVec tmp(std::min(hg_chunk, LB));
        for (int ci = 0; ci < (LB + hg_chunk - 1) / hg_chunk; ++ci) {
          int st = hg_chunk * ci, ed = std::min(hg_chunk * (ci + 1), LB);
          for (int k0 = st; k0 < ed; k0 += 8) {
            int batch = std::min(8, ed - k0);
            for (int j = 0; j < 8; ++j) {
              block key = (j < batch) ? tKEY[k0 + j] : zero_block;
              pad[2 * j]     = key;
              pad[2 * j + 1] = key ^ Delta;
            }
            mitc.hash<8, 2>(pad);
            for (int j = 0; j < batch; ++j) {
              tKEYphi[peer][k0 + j] = pad[2 * j];
              tmp[k0 + j - st]      = pad[2 * j] ^ pad[2 * j + 1] ^ phi[k0 + j];
            }
          }
          io_send(io1, io2, party, peer, tmp.data(), (ed - st) * sizeof(block));
          io_flush(io1, io2, party, peer);
        }
      }));
      res.push_back(pool->enqueue([this, &tMAC, &tMACphi, &tr, LB, peer, pair_seed, hg_chunk]() {
        MITCCRH<8> mitc;
        mitc.setS(pair_seed);
        block pad[8];
        BlockVec wire(std::min(hg_chunk, LB));
        for (int ci = 0; ci < (LB + hg_chunk - 1) / hg_chunk; ++ci) {
          int st = hg_chunk * ci, ed = std::min(hg_chunk * (ci + 1), LB);
          io_recv(io1, io2, party, peer, wire.data(), (ed - st) * sizeof(block));
          for (int k0 = st; k0 < ed; k0 += 8) {
            int batch = std::min(8, ed - k0);
            for (int j = 0; j < 8; ++j)
              pad[j] = (j < batch) ? tMAC[k0 + j] : zero_block;
            mitc.hash<8, 1>(pad);
            for (int j = 0; j < batch; ++j) {
              block w = wire[k0 + j - st] & select_mask[tr[k0 + j]];
              tMACphi[k0 + j] = pad[j] ^ w;
            }
          }
        }
      }));
    }
    joinNclean(res);
#ifdef WRK_PROFILE
    g_wrk_phi_bytes += (uint64_t)(io_count(io1, io2) - _phi0);
#endif
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] half-gate exchange", party);
#endif

    // step 5(b): s^i_k = a^i·φ^i ⊕ ⊕_{j≠i}(K_i[a^j]_φ ⊕ M_j[a^i]_φ
    //   ⊕ K_i[r^j] ⊕ M_j[r^i]) ⊕ r^i·Δ_i.  Stored back into tKEYphi[party]
    //   (overwriting the j=party slot, which was unused in step 5(a)).
    for (int wi = 0; wi < pool->size(); ++wi) {
      int st = wi * width, ed = std::min((wi + 1) * width, LB);
      res.push_back(pool->enqueue([this, st, ed, LB, &tKEYphi, &tMACphi, &tKEY, &tMAC, &phi, &tr]() {
        for (int k = st; k < ed; ++k) {
          tKEYphi[party][k] = zero_block;
          { const int j = 3 - party;
            tKEYphi[party][k] = tKEYphi[party][k] ^ tKEYphi[j][k];
            tKEYphi[party][k] = tKEYphi[party][k] ^ tMACphi[k];
            tKEYphi[party][k] = tKEYphi[party][k] ^ tKEY[2 * LB + k];
            tKEYphi[party][k] = tKEYphi[party][k] ^ tMAC[2 * LB + k];
          }
          tKEYphi[party][k] = tKEYphi[party][k] ^ (phi[k] & select_mask[tr[k]]);
          tKEYphi[party][k] = tKEYphi[party][k] ^ (Delta  & select_mask[tr[2 * LB + k]]);
        }
      }));
    }
    joinNclean(res);

    // step 6 (Commit) collapsed into step 7 (Open): a single send of
    // d^i_k = LSB1(s^i_k) per peer (bit 1 carries garbling parity under
    // the bit-0/bit-1 Δ convention; see auth_share_pool.h ctor). The
    // α-check at step 10 binds d after the fact, so no separate
    // commitment round is needed.
    for (int k = 0; k < LB; ++k)
      s[party][k] = LSB1(tKEYphi[party][k]);
    { const int peer = 3 - party;
      res.push_back(pool->enqueue([this, &s, LB, peer]() {
        io_send(io1, io2, party, peer, s[party].data(), LB);
        io_flush(io1, io2, party, peer);
      }));
      res.push_back(pool->enqueue([this, &s, LB, peer]() {
        io_recv(io1, io2, party, peer, s[peer].data(), LB);
      }));
    }
    joinNclean(res);

    // steps 7 + (part of) 11: combine d = ⊕_i d^i; compute t^i = s^i ⊕ d·Δ_i
    // (folded into T = tKEYphi[party]).  We also fold d into the r-share
    // in-place so r becomes c = r ⊕ d (paper step 11): only P1 flips its
    // r-bit, and every P_(j≠1) flips K_j[c^1] = K_j[r^1] ⊕ d·Δ_j to
    // maintain MAC consistency on the new c^1 bit.
    //
    // Bit-0 pinned variant (matches AuthSharePool fix): peer j uses
    // (Δ_j ⊕ e_0) so bit 0 of tKEY[1] stays at 0; P1 instead flips bit 0
    // of tMAC[2*LB + k] by d so bit0(tMAC) tracks c^1 = r^1 ⊕ d
    // across all peers. tr[2*LB + k] is mirrored to keep the legacy byte
    // vector in sync (Step E removes it).
    {
      block *T = tKEYphi[party].data();
      block dxor = Delta ^ bit0_mask;
      for (int k = 0; k < LB; ++k) {
        s[0][k] = (s[1][k] != s[2][k]);
        block mask_s = select_mask[s[0][k]];
        if (party == 1) {
          tr[2 * LB + k] = (s[0][k] != tr[2 * LB + k]);
          if (s[0][k])
            tMAC[2 * LB + k] = tMAC[2 * LB + k] ^ bit0_mask;
        } else {
          tKEY[2 * LB + k] = tKEY[2 * LB + k] ^ (dxor & mask_s);
        }
        T[k] = T[k] ^ (Delta & mask_s);
      }
    }
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] combine s", party);
#endif

    // steps 8+9+10: FRand → H'; commit-open α^i = H'(t^i) ⊕ u^i; check
    // Σ_i α^i = 0 in F_{2^λ}.  We reuse `phi` as scratch for the
    // λ-coefficients (already sized LB).  No-reduction inner-product
    // gives a 2-block α^i (univ. hash output before mod reduction); u^i
    // is folded into the low half — Σ_p u^p = 0 keeps the column sum
    // invariant after the cross-party XOR.
    block S = RO("WRK RO", zero_block).absorb(io1->get_digest()).absorb(io2->get_digest()).squeeze_block();
    PRG jprg(&S);
    jprg.random_block(phi.data(), LB);
    BlockVec ip[3];
    for (int i = 0; i <= 2; ++i) ip[i].resize(2);
    vector_inn_prdt_sum_no_red(ip[party].data(), phi.data(), tKEYphi[party].data(), LB);
    ip[party][0] ^= u_zero;

    char dgst_me[Hash::DIGEST_SIZE], dgst_peer[Hash::DIGEST_SIZE];
    Hash::hash_once(dgst_me, ip[party].data(), sizeof(block) * 2);

    { const int peer = 3 - party;
      res.push_back(pool->enqueue([this, &dgst_me, peer]() {
        io_send(io1, io2, party, peer, dgst_me, Hash::DIGEST_SIZE);
        io_flush(io1, io2, party, peer);
      }));
      res.push_back(pool->enqueue([this, &dgst_peer, peer]() {
        io_recv(io1, io2, party, peer, dgst_peer, Hash::DIGEST_SIZE);
      }));
    }
    joinNclean(res);

    vector<future<bool>> res2;
    { const int peer = 3 - party;
      res.push_back(pool->enqueue([this, &ip, peer]() {
        io_send(io1, io2, party, peer, ip[party].data(), sizeof(block) * 2);
        io_flush(io1, io2, party, peer);
      }));
      res2.push_back(pool->enqueue([this, &ip, &dgst_peer, peer]() -> bool {
        io_recv(io1, io2, party, peer, ip[peer].data(), sizeof(block) * 2);
        char chk[Hash::DIGEST_SIZE];
        Hash::hash_once(chk, ip[peer].data(), sizeof(block) * 2);
        return memcmp(chk, dgst_peer, Hash::DIGEST_SIZE) != 0;
      }));
    }
    joinNclean(res);
    if (joinNcleanCheat(res2)) error("LaAND alpha: commit-open mismatch");

    xorBlocks_arr(ip[1].data(), ip[1].data(), ip[2].data(), 2);
    if (!cmpBlock(&ip[1][0], &zero_block, 1) || !cmpBlock(&ip[1][1], &zero_block, 1))
      error("LaAND alpha: Sigma alpha != 0");
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] LAND check", party);
#endif
    };  // end produce_leaky_ands_halfgate

    // Run the active leaky-AND method.
    if constexpr (kLeakyAnd == LeakyAnd::HalfGate) produce_leaky_ands_halfgate();
    else { (void)produce_leaky_ands_halfgate; cutchoose_leaky(tMAC, tKEY, tr, LB); }

    // Π_aAND (P:aAND): bucketing via per-row circular shifts on a
    // bucket_size × length matrix.  Row 0 is fixed, rows 1..B-1 get a random
    // shift r_k ∈ [0, length).  We don't materialize a permutation array:
    // bucket i's k-th slot is leaky triple (k * length + (i + r_k) mod length),
    // which is sequential in i (with at most one wraparound), so each row is
    // streamed once per bucket range.
    block S = RO("WRK RO", zero_block).absorb(io1->get_digest()).absorb(io2->get_digest()).squeeze_block();
    vector<unsigned char> d[3];
    for (int i = 1; i <= 2; ++i)
      d[i].resize(length * (bucket_size - 1));
    vector<int> rk(bucket_size);
    rk[0] = 0;
    {
      vector<uint32_t> raw(bucket_size - 1);
      PRG prg2(&S);
      prg2.random_data(raw.data(), (bucket_size - 1) * sizeof(uint32_t));
      for (int k = 1; k < bucket_size; ++k)
        rk[k] = (int)(raw[k - 1] % (uint32_t)length);
    }

    int T2U = pool->size();
    int width3 = (length + T2U - 1) / T2U;
    for (int ti = 0; ti < T2U; ++ti) {
      int st = width3 * ti, ed = std::min(length, width3 * (ti + 1));
      res.push_back(pool->enqueue([this, bucket_size, length, LB, &d, MAC, KEY, &tMAC, &tKEY, &rk, &tr, st, ed, out_aos]() {
        // Row 0 (no shift): bucket i's representative is leaky triple i.
        // Slot-major layout: slot s of dst at MAC[s*length + i], slot s
        // of src at tMAC. When out_aos is non-null, also
        // initialize the AoS bundle for each i (Stage 4d: fuses the
        // SoA→AoS transpose into bucketing's existing per-i write).
        {
          for (int s = 0; s < 3; ++s) {
            memcpy(MAC + s * length + st, tMAC.data() + s * LB + st, (ed - st) * sizeof(block));
            memcpy(KEY + s * length + st, tKEY.data() + s * LB + st, (ed - st) * sizeof(block));
          }
          if (out_aos) {
            for (int i = st; i < ed; ++i) {
              out_aos[i].b[0].mac = tMAC[i];
              out_aos[i].b[0].key = tKEY[i];
              out_aos[i].b[1].mac = tMAC[LB + i];
              out_aos[i].b[1].key = tKEY[LB + i];
              out_aos[i].b[2].mac = tMAC[2 * LB + i];
              out_aos[i].b[2].key = tKEY[2 * LB + i];
            }
          }
        }
        // Rows k = 1..B-1: XOR in row k, shifted by r_k.  For i ∈ [st, ed),
        // source position within row k is p = (i + r_k) mod length; split the
        // range at the one wraparound so both segments are strictly sequential.
        // Share bits are carried implicitly by bit0(MAC[*]); no separate
        // byte vector update is needed. AoS slot 1 (b) is NOT updated here
        // — bucketing only XORs slot 0 (a) and slot 2 (c=r); the b-slot
        // diff is tracked in d[party] and resolved at the closing d-mask.
        for (int k = 1; k < bucket_size; ++k) {
          int shift = rk[k];
          int cut = std::max(st, std::min(ed, length - shift));
          int base = k * length;
          {
            for (int i = st; i < cut; ++i) {
              int src = base + i + shift;
              MAC[i]              = MAC[i]              ^ tMAC[src];
              MAC[2 * length + i] = MAC[2 * length + i] ^ tMAC[2 * LB + src];
              KEY[i]              = KEY[i]              ^ tKEY[src];
              KEY[2 * length + i] = KEY[2 * length + i] ^ tKEY[2 * LB + src];
              if (out_aos) {
                out_aos[i].b[0].mac = out_aos[i].b[0].mac ^ tMAC[src];
                out_aos[i].b[0].key = out_aos[i].b[0].key ^ tKEY[src];
                out_aos[i].b[2].mac = out_aos[i].b[2].mac ^ tMAC[2 * LB + src];
                out_aos[i].b[2].key = out_aos[i].b[2].key ^ tKEY[2 * LB + src];
              }
            }
            for (int i = cut; i < ed; ++i) {
              int src = base + i + shift - length;
              MAC[i]              = MAC[i]              ^ tMAC[src];
              MAC[2 * length + i] = MAC[2 * length + i] ^ tMAC[2 * LB + src];
              KEY[i]              = KEY[i]              ^ tKEY[src];
              KEY[2 * length + i] = KEY[2 * length + i] ^ tKEY[2 * LB + src];
              if (out_aos) {
                out_aos[i].b[0].mac = out_aos[i].b[0].mac ^ tMAC[src];
                out_aos[i].b[0].key = out_aos[i].b[0].key ^ tKEY[src];
                out_aos[i].b[2].mac = out_aos[i].b[2].mac ^ tMAC[2 * LB + src];
                out_aos[i].b[2].key = out_aos[i].b[2].key ^ tKEY[2 * LB + src];
              }
            }
          }
          // d[party][...] tracks the b-slot bucket-row XOR (= bit0(tMAC b-tail)
          // diff) and is exchanged across peers below. Same XOR pattern that
          // the MAC/KEY rows above carry, restricted to the b-slot.
          for (int i = st; i < cut; ++i) {
            int src = base + i + shift;
            d[party][(bucket_size - 1) * i + (k - 1)] = tr[LB + i] != tr[LB + src];
          }
          for (int i = cut; i < ed; ++i) {
            int src = base + i + shift - length;
            d[party][(bucket_size - 1) * i + (k - 1)] = tr[LB + i] != tr[LB + src];
          }
        }
      }));
    }
    joinNclean(res);
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] bucketing", party);
#endif

    { const int peer = 3 - party;
      res.push_back(pool->enqueue([this, &d, length, bucket_size, peer]() {
        io_send(io1, io2, party, peer, d[party].data(), (bucket_size - 1) * length);
        io_flush(io1, io2, party, peer);
      }));
      res.push_back(pool->enqueue([this, &d, length, bucket_size, peer]() {
        io_recv(io1, io2, party, peer, d[peer].data(), (bucket_size - 1) * length);
      }));
    }
    joinNclean(res);
    for (int j = 0; j < (bucket_size - 1) * length; ++j)
      d[1][j] = d[1][j] != d[2][j];

    for (int i = 0; i < length; ++i) {
      {
        for (int k = 1; k < bucket_size; ++k) {
          int src = k * length + (i + rk[k]) % length;
          block mask = select_mask[d[1][(bucket_size - 1) * i + k - 1]];
          MAC[2 * length + i] = MAC[2 * length + i] ^ (tMAC[src] & mask);
          KEY[2 * length + i] = KEY[2 * length + i] ^ (tKEY[src] & mask);
          if (out_aos) {
            // Mirror the SoA c-slot XOR into AoS slot 2. The masked value
            // is the b-region row k contribution to c (Figure 16's r⊕d
            // in-place flip).
            out_aos[i].b[2].mac = out_aos[i].b[2].mac ^ (tMAC[src] & mask);
            out_aos[i].b[2].key = out_aos[i].b[2].key ^ (tKEY[src] & mask);
          }
        }
      }
    }
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] bucket d exchange", party);
#endif

#ifdef EMP_DEBUG_PHASE
    _phase("[triple] check2", party);

    BlockVec MAC_dbg(MAC, MAC + 3 * length);
    BlockVec KEY_dbg(KEY, KEY + 3 * length);
    check_MAC(io1, io2, MAC_dbg, KEY_dbg, Delta, length * 3, party);
    check_correctness(io1, io2, MAC_dbg, length, party);
#endif
  }

  // Vector overload: resize output buffers and dispatch to the pointer-array
  // implementation. MAC/KEY peer-slots are sized length*3 (slot-major a/b/c).
  // MAC[party]/KEY[party] are unused; share-bits are recoverable as
  // bit0(MAC[k]). out_aos forwards as-is.
  void compute(BlockVec &MAC, BlockVec &KEY, int length,
               TripleBundle *out_aos = nullptr) {
    MAC.resize(length * 3);
    KEY.resize(length * 3);
    compute(MAC.data(), KEY.data(), length, out_aos);
  }

  // ==== Pool API (Phase C) ====

  // Available pool entries (i.e. unconsumed triples).
  size_t available() const { return pool_triples.size() - cursor; }

  void set_min_refill(size_t n) { min_refill = n; }

  // Ensure the pool holds at least n unconsumed triples. Refills via a
  // single compute(batch) call where batch = max(needed, min_refill).
  void preprocess(size_t n) {
    if (available() >= n) return;
    size_t need = n - available();
    size_t batch = std::max(need, min_refill);
    refill_internal(batch);
  }

  // Pull n triples from the pool. out_triples[i] holds the three slot
  // bundles (mac, key for every peer) of triple i. Slot s's share-bit is
  // recoverable as bit0(out_triples[i].b[s].mac).
  void draw(int n, TripleBundleVec &out_triples) {
    if (available() < (size_t)n)
      preprocess(n);
    out_triples.resize(n);
    memcpy(out_triples.data(), pool_triples.data() + cursor,
           n * sizeof(TripleBundle));
    cursor += n;
  }

private:
  // Stage 4d: compact (drop consumed prefix), grow pool_triples by `batch`,
  // then run compute() with out_aos pointing into the freshly grown slots.
  // The standalone SoA→AoS transpose is gone — bucketing writes AoS in
  // place during its per-row XOR loop. The SoA tmac/tkey buffers still
  // exist (compute() needs them as protocol scratch / output for the
  // debug check_MAC path) but the pool no longer reads them post-compute.
  void refill_internal(size_t batch) {
    if (cursor > 0) {
      pool_triples.erase(pool_triples.begin(), pool_triples.begin() + cursor);
      cursor = 0;
    }
    size_t base = pool_triples.size();
    pool_triples.resize(base + batch);
    BlockVec tmac, tkey;
    compute(tmac, tkey, (int)batch, pool_triples.data() + base);
  }
};
#endif // TRIPLE_POOL_H__
