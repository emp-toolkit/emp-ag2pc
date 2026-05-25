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
template <int nP>
class TriplePool {
public:
  ThreadPool *pool;
  int party;
  NetIO *io1, *io2;
  AuthSharePool<nP> abit;
  block Delta;
  PRG prg;

  // ==== Pool storage (Phase C) ====
  // AoS-by-triple layout: pool_triples[t] holds three AShareBundles (slots
  // 0/1/2) for triple t. Internal compute() still emits SoA per-peer
  // slot-major arrays — refill_internal transposes once on insert so
  // consumers read AoS via draw(). The triple's share bits live in
  // bit0(pool_triples[t].b[s].mac(any slot)) for slots a/b/c at s=0/1/2.
  TripleBundleVec<nP> pool_triples;
  size_t cursor = 0;
  // Floor for refill batch size. Any draw smaller than this still mints
  // `min_refill` triples to amortize the per-call protocol overhead
  // (sampleRandom, csp tail, closing exchanges). Set at the bucket_size=4
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

  // ===== Cut-and-choose (FKOS) Stage 1: OT multiplication =====
  // Lean variant (no 2κ key doubling, per design): reuse the a-aShare COT
  // correlation (aMAC/aKEY under Δ) as the correlation-robust hash input.
  // Produces UNAUTHENTICATED product bit-shares z with ⊕_p z^p = (⊕_p a^p) ∧
  // (⊕_p b^p). One communication round (each party ships an s vector per peer).
  //   a^me = bit0(aMAC[any-peer][k]). For peer j:
  //     aMAC[j][k] = M_j[a^me] = K_j[a^me] ⊕ a^me·Δ_j   (me = OT receiver to j)
  //     aKEY[j][k] = K_me[a^j]                            (me = OT sender to j)
  //   send-role (a^j·b^me): s = H(K_me[a^j]) ⊕ H(K_me[a^j]⊕Δ_me) ⊕ b^me; keep v0=H(K_me[a^j])
  //   recv-role (a^me·b^j): n = H(M_j[a^me]) ⊕ a^me·s_recv = H(K_j[a^me]) ⊕ a^me·b^j
  //   z^me = a^me·b^me ⊕ ⊕_{j≠me} ( v0_send ⊕ n_recv )   (the ⊕H terms cancel in Σ_p)
  void multiply_unauth(BlockVec aMAC[nP + 1], BlockVec aKEY[nP + 1],
                       const std::vector<uint8_t> &b, int len,
                       std::vector<uint8_t> &z) {
    PRP prp;  // fixed public key → same correlation-robust H on all parties
    auto H = [&](block x) -> uint8_t {
      block y = x;
      prp.permute_block(&y, 1);
      return (uint8_t)(LSB(y ^ x));  // π(x)⊕x, low bit
    };
    int ap = (party == 1) ? 2 : 1;  // any peer slot carries a^me in bit0
    z.assign(len, 0);
    const int peer = 3 - party;
    std::vector<uint8_t> s_send(len), s_recv(len);
    for (int k = 0; k < len; ++k) z[k] = (uint8_t)(LSB(aMAC[ap][k]) & b[k]);
    for (int k = 0; k < len; ++k) {
      uint8_t v0 = H(aKEY[peer][k]);
      s_send[k] = (uint8_t)(v0 ^ H(aKEY[peer][k] ^ Delta) ^ b[k]);
      z[k] ^= v0;
    }
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([this, &s_send, len, peer]() {
      send_ch(peer)->send_bool((const bool *)s_send.data(), len);
      send_ch(peer)->flush();
    }));
    res.push_back(pool->enqueue([this, &s_recv, len, peer]() {
      recv_ch(peer)->recv_bool((bool *)s_recv.data(), len);
    }));
    joinNclean(res);
    for (int k = 0; k < len; ++k) {
      uint8_t ame = (uint8_t)LSB(aMAC[ap][k]);
      z[k] ^= (uint8_t)(H(aMAC[peer][k]) ^ (ame & s_recv[k]));
    }
  }

  // Self-test: gen random authenticated a, b; multiply; open a,b,z to P1 and
  // check ⊕z == (⊕a)∧(⊕b). Prints GOOD/BAD at party 1.
  void cutchoose_mult_selftest(int len) {
    BlockVec aMAC[nP + 1], aKEY[nP + 1], bMAC[nP + 1], bKEY[nP + 1];
    abit.process_phase1(aMAC, aKEY, len);
    abit.process_phase1(bMAC, bKEY, len);
    int ap = (party == 1) ? 2 : 1;
    std::vector<uint8_t> a(len), b(len), z;
    for (int k = 0; k < len; ++k) { a[k] = (uint8_t)LSB(aMAC[ap][k]); b[k] = (uint8_t)LSB(bMAC[ap][k]); }
    multiply_unauth(aMAC, aKEY, b, len, z);
    if (party != 1) {
      io_send(io1, io2, party, 1, a.data(), len); io_send(io1, io2, party, 1, b.data(), len);
      io_send(io1, io2, party, 1, z.data(), len); io_flush(io1, io2, party, 1);
    } else {
      bool ok = true;
      std::vector<uint8_t> A(a), B(b), Z(z);
      { const int p = 2;
        std::vector<uint8_t> ta(len), tb(len), tz(len);
        io_recv(io1, io2, party, p, ta.data(), len); io_recv(io1, io2, party, p, tb.data(), len);
        io_recv(io1, io2, party, p, tz.data(), len);
        for (int k = 0; k < len; ++k) { A[k] ^= ta[k]; B[k] ^= tb[k]; Z[k] ^= tz[k]; }
      }
      for (int k = 0; k < len; ++k) if (Z[k] != (uint8_t)(A[k] & B[k])) ok = false;
      printf("cutchoose_mult (len=%d): %s\n", len, ok ? "GOOD!" : "BAD!");
    }
  }

  // ===== Cut-and-choose Stage 2: authenticated leaky triple =====
  // From a/b/r aShares (a=[0,LB), b=[LB,2LB), r=[2LB,3LB) of tMAC/tKEY) produce
  // an authenticated AND triple (a, b, c=a∧b) with c overwriting the r-region.
  // Lean authentication (no doubling): c = r ⊕ d with d = (a∧b)⊕r opened public,
  // reusing the half-gate's r→c flip (d here comes from the OT multiplication).
  // Honest-correct; a malicious wrong product is caught by Stage 3's sacrifice.
  void make_leaky_triples_cutchoose(BlockVec tMAC[nP + 1], BlockVec tKEY[nP + 1],
                                    int LB) {
    int ap = (party == 1) ? 2 : 1;
    std::vector<uint8_t> b(LB), z;
    for (int k = 0; k < LB; ++k) b[k] = (uint8_t)LSB(tMAC[ap][LB + k]);
    multiply_unauth(tMAC, tKEY, b, LB, z);  // a-region at offset 0; ⊕z = a∧b
    // d^me = z^me ⊕ r^me; open d = ⊕_p d^p (all-to-all XOR).
    std::vector<uint8_t> dme(LB);
    for (int k = 0; k < LB; ++k)
      dme[k] = (uint8_t)(z[k] ^ LSB(tMAC[ap][2 * LB + k]));
    std::vector<uint8_t> dr(LB);
    const int peer = 3 - party;
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([this, &dme, LB, peer]() {
      send_ch(peer)->send_bool((const bool *)dme.data(), LB);
      send_ch(peer)->flush();
    }));
    res.push_back(pool->enqueue([this, &dr, LB, peer]() {
      recv_ch(peer)->recv_bool((bool *)dr.data(), LB);
    }));
    joinNclean(res);
    std::vector<uint8_t> d(dme);
    for (int k = 0; k < LB; ++k) d[k] ^= dr[k];
    // c = r ⊕ d (public d) on the r-region: P1 flips bit0(MAC) by d; every other
    // party flips its key for peer 1 by Δ⊕e_0 to keep the MAC on c consistent.
    block dxor = Delta ^ bit0_mask;
    for (int k = 0; k < LB; ++k) {
      if (!d[k]) continue;
      if (party == 1) {
        tMAC[2][2 * LB + k] = tMAC[2][2 * LB + k] ^ bit0_mask;
      } else {
        tKEY[1][2 * LB + k] = tKEY[1][2 * LB + k] ^ dxor;
      }
    }
  }

  // Seam middle for LeakyAnd::CutChoose. tMAC/tKEY hold 3·T·LB aShares
  // (process_phase1 sized by leaky_abit_len): candidates a=[0,N) b=[N,2N) r=[2N,3N),
  // N=T·LB. Make N leaky triples, run the cyclic-shift correctness sacrifice
  // (abort on a bad triple), then COMPACT the LB row-0 heads into a=[0,LB)
  // b=[LB,2LB) c=[2LB,3LB) so the existing Π_Prep combine consumes them. tr is
  // rebuilt over [0,3LB) for the bucketing's b-region reads.
  void cutchoose_leaky(BlockVec tMAC[nP + 1], BlockVec tKEY[nP + 1],
                       std::vector<unsigned char> &tr, int LB) {
    const int T = cutchoose_T, N = T * LB;
    make_leaky_triples_cutchoose(tMAC, tKEY, N);  // c = a∧b → [2N,3N)
    int ap = (party == 1) ? 2 : 1;
    block S = sampleRandom<nP>(io1, io2, &prg, pool, party);
    std::vector<int> shift(T, 0);
    { PRG p2(&S); std::vector<uint32_t> raw(T); p2.random_data(raw.data(), T * sizeof(uint32_t));
      for (int r = 1; r < T; ++r) shift[r] = (int)(raw[r] % (uint32_t)LB); }
    auto bit = [&](int region, int g) { return (uint8_t)LSB(tMAC[ap][region * N + g]); };
    int P = LB * (T - 1);
    std::vector<uint8_t> rho(P), sig(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB, e = i * (T - 1) + (r - 1);
        rho[e] = (uint8_t)(bit(0, i) ^ bit(0, g));
        sig[e] = (uint8_t)(bit(1, i) ^ bit(1, g));
      }
    std::vector<uint8_t> RHO = open_bits(rho, P), SIG = open_bits(sig, P), v(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB, e = i * (T - 1) + (r - 1);
        uint8_t V = (uint8_t)(bit(2, i) ^ bit(2, g) ^ (RHO[e] & bit(1, g)) ^ (SIG[e] & bit(0, g)));
        if (party == 1) V ^= (uint8_t)(RHO[e] & SIG[e]);
        v[e] = V;
      }
    std::vector<uint8_t> Vpub = open_bits(v, P);
    for (int e = 0; e < P; ++e)
      if (Vpub[e]) error("cut-and-choose sacrifice: incorrect AND triple");
    // Compact row-0 heads: a already at [0,LB); move b,c heads down.
    { const int j = 3 - party;
      memcpy(&tMAC[j][LB], &tMAC[j][N], LB * sizeof(block));
      memcpy(&tMAC[j][2 * LB], &tMAC[j][2 * N], LB * sizeof(block));
      memcpy(&tKEY[j][LB], &tKEY[j][N], LB * sizeof(block));
      memcpy(&tKEY[j][2 * LB], &tKEY[j][2 * N], LB * sizeof(block));
    }
    tr.resize(3 * LB);
    for (int k = 0; k < 3 * LB; ++k) tr[k] = (uint8_t)LSB(tMAC[ap][k]);
  }

  // Self-test: gen 3·LB aShares (a,b,r); build the leaky triple; verify the
  // c-region MAC is valid (check_MAC aborts on tamper) and ⊕c == (⊕a)∧(⊕b).
  void cutchoose_triple_selftest(int LB) {
    BlockVec tMAC[nP + 1], tKEY[nP + 1];
    abit.process_phase1(tMAC, tKEY, 3 * LB);
    int ap = (party == 1) ? 2 : 1;
    std::vector<uint8_t> a(LB), b(LB);
    for (int k = 0; k < LB; ++k) { a[k] = (uint8_t)LSB(tMAC[ap][k]); b[k] = (uint8_t)LSB(tMAC[ap][LB + k]); }
    make_leaky_triples_cutchoose(tMAC, tKEY, LB);
    std::vector<uint8_t> c(LB);
    for (int k = 0; k < LB; ++k) c[k] = (uint8_t)LSB(tMAC[ap][2 * LB + k]);
    // Authentication check on the c-region (aborts via error() on bad MAC).
    BlockVec cMAC[nP + 1], cKEY[nP + 1];
    { const int j = 3 - party;
      cMAC[j].assign(tMAC[j].begin() + 2 * LB, tMAC[j].begin() + 3 * LB);
      cKEY[j].assign(tKEY[j].begin() + 2 * LB, tKEY[j].begin() + 3 * LB);
    }
    check_MAC<nP>(io1, io2, cMAC, cKEY, Delta, LB, party);
    if (party != 1) {
      io_send(io1, io2, party, 1, a.data(), LB); io_send(io1, io2, party, 1, b.data(), LB);
      io_send(io1, io2, party, 1, c.data(), LB); io_flush(io1, io2, party, 1);
    } else {
      bool ok = true;
      std::vector<uint8_t> A(a), B(b), C(c);
      { const int p = 2;
        std::vector<uint8_t> ta(LB), tb(LB), tc(LB);
        io_recv(io1, io2, party, p, ta.data(), LB); io_recv(io1, io2, party, p, tb.data(), LB);
        io_recv(io1, io2, party, p, tc.data(), LB);
        for (int k = 0; k < LB; ++k) { A[k] ^= ta[k]; B[k] ^= tb[k]; C[k] ^= tc[k]; }
      }
      for (int k = 0; k < LB; ++k) if (C[k] != (uint8_t)(A[k] & B[k])) ok = false;
      printf("cutchoose_triple (LB=%d): %s (MAC verified)\n", LB, ok ? "GOOD!" : "BAD!");
    }
  }

  // Open a per-party bit-share vector: returns the public ⊕_p share^p at every
  // party (all-to-all XOR). (Value-level open; MAC binding checked separately.)
  std::vector<uint8_t> open_bits(const std::vector<uint8_t> &share, int len) {
    std::vector<uint8_t> r(len);
    const int peer = 3 - party;
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([this, &share, len, peer]() {
      send_ch(peer)->send_bool((const bool *)share.data(), len);
      send_ch(peer)->flush();
    }));
    res.push_back(pool->enqueue([this, &r, len, peer]() {
      recv_ch(peer)->recv_bool((bool *)r.data(), len);
    }));
    joinNclean(res);
    std::vector<uint8_t> pub(share);
    for (int k = 0; k < len; ++k) pub[k] ^= r[k];
    return pub;
  }

  // ===== Cut-and-choose Stage 3: bucket-sacrifice (correctness) =====
  // Generate N = T·LB candidate triples, arrange as a T-by-LB matrix, CYCLIC-shift
  // rows 1..T-1 by shared random r_k (per design, not a random permutation), and
  // for each column (bucket) sacrifice the T-1 shifted partners against the row-0
  // head: open ρ=a0⊕a1, σ=b0⊕b1 and check V = c0⊕c1⊕ρ·b1⊕σ·a1⊕ρσ == 0. A wrong
  // triple in a bucket with a good head yields V=1 → abort. Heads are the output.
  //   `tamper`: if >=0, flip the VALUE of candidate `tamper`'s c (simulated cheat).
  //   NOTE: value-level check; the batch MAC-binding of V (malicious soundness)
  //   and Phase-I cut-and-choose are the remaining hardening (see plan ⚠).
  void cutchoose_sacrifice_selftest(int LB, int T, int tamper = -1) {
    int N = T * LB;
    BlockVec tMAC[nP + 1], tKEY[nP + 1];
    abit.process_phase1(tMAC, tKEY, 3 * N);
    make_leaky_triples_cutchoose(tMAC, tKEY, N);  // a=[0,N) b=[N,2N) c=[2N,3N)
    int ap = (party == 1) ? 2 : 1;
    if (tamper >= 0 && party == 1)  // flip ⊕c by flipping bit0 of c-MAC on P1
      tMAC[2][2 * N + tamper] = tMAC[2][2 * N + tamper] ^ bit0_mask;

    // Cyclic shifts r_k for rows 1..T-1 from a shared seed.
    block S = sampleRandom<nP>(io1, io2, &prg, pool, party);
    std::vector<int> shift(T, 0);
    { PRG p2(&S); std::vector<uint32_t> raw(T); p2.random_data(raw.data(), T * sizeof(uint32_t));
      for (int r = 1; r < T; ++r) shift[r] = (int)(raw[r] % (uint32_t)LB); }

    auto bit = [&](int region, int g) { return (uint8_t)LSB(tMAC[ap][region * N + g]); };
    int P = LB * (T - 1);  // number of sacrifice pairs
    std::vector<uint8_t> rho(P), sig(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB;   // partner global index
        int e = i * (T - 1) + (r - 1);
        rho[e] = (uint8_t)(bit(0, i) ^ bit(0, g));   // a0 ⊕ a1
        sig[e] = (uint8_t)(bit(1, i) ^ bit(1, g));   // b0 ⊕ b1
      }
    std::vector<uint8_t> RHO = open_bits(rho, P), SIG = open_bits(sig, P);
    std::vector<uint8_t> v(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB;
        int e = i * (T - 1) + (r - 1);
        // V^me = c0 ⊕ c1 ⊕ ρ·b1 ⊕ σ·a1 (⊕ ρσ at P1)
        uint8_t V = (uint8_t)(bit(2, i) ^ bit(2, g) ^ (RHO[e] & bit(1, g)) ^ (SIG[e] & bit(0, g)));
        if (party == 1) V ^= (uint8_t)(RHO[e] & SIG[e]);
        v[e] = V;
      }
    std::vector<uint8_t> Vpub = open_bits(v, P);
    int bad = 0;
    for (int e = 0; e < P; ++e) if (Vpub[e]) ++bad;
    if (party == 1)
      printf("cutchoose_sacrifice (LB=%d T=%d tamper=%d): %s (%d/%d sacrifice checks nonzero)\n",
             LB, T, tamper, bad == 0 ? "ALL PASS" : "CHEAT DETECTED", bad, P);
  }

  // The output share-bits are implicit: bit0(MAC[any non-self peer][k])
  // gives the k-th share-bit for slot k/length (a / b / c at offsets
  // 0 / length / 2*length). bit0(KEY[*]) = 0 throughout.
  // Stage 4d: optional out_aos. When non-null, bucketing also writes its
  // per-output-index XOR results into pool_triples-shaped AoS bundles
  // (one TripleBundle per output index), eliminating the standalone
  // transpose pass at refill. SoA MAC/KEY writes are still produced for
  // the debug check_MAC / check_correctness path.
  void compute(block *MAC[nP + 1], block *KEY[nP + 1], int length,
               TripleBundle<nP> *out_aos = nullptr) {
    int bucket_size = get_bucket_size(length);
    int LB = length * bucket_size;
    // Authenticated bits per leaky-AND slot, set by the active leaky-AND method
    // (half-gate: 3·LB = a, b, r). abit's internal sacrificial tail (csp
    // positions for the gadget Δ-check in abit.check1) is grown and dropped
    // inside abit.compute — it doesn't appear in our buffers on output. We
    // over-reserve MAC/KEY by csp to avoid the realloc when abit grows.
    int abit_len = leaky_abit_len(LB);

    BlockVec tMAC[nP + 1], tKEY[nP + 1];
    BlockVec tKEYphi[nP + 1], tMACphi[nP + 1];
    BlockVec phi(LB);
    vector<unsigned char> s[nP + 1];
    vector<unsigned char> tr;

    tr.reserve(abit_len);
    // tKEYphi[party] is the s^i / t^i accumulator (overwritten in step 5b).
    // tKEYphi[j], tMACphi[j] for j != party hold half-gate outputs from peer j;
    // tMACphi[party] is never written or read (sender writes tKEYphi[peer],
    // receiver writes tMACphi[peer]), so we skip its allocation.
    for (int i = 1; i <= nP; ++i) {
      tMAC[i].reserve(abit_len + abit.csp);
      tKEY[i].reserve(abit_len + abit.csp);
      tKEYphi[i].resize(LB);
      if (i != party) tMACphi[i].resize(LB);
    }
    for (int i = 0; i <= nP; ++i) s[i].resize(LB);

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
        tr[k] = LSB(tMAC[any_peer][k]);
    }

    // aShare consistency check (check2), run as one shared pass over the
    // pristine a/b/r shares BEFORE the leaky-AND step mutates them (the c=r⊕d
    // flip), so it stays independent of which leaky-AND method runs. Seed is
    // sampled AFTER process_phase1 commits MAC/KEY so the adversary can't adapt.
    block check2_seed = sampleRandom<nP>(io1, io2, &prg, pool, party);
    abit.check2_init(check2_seed, abit_len);
    abit.check2_chunk(0, abit_len, tMAC, tKEY);
    abit.check2_finalize();

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
    fzero_xor<nP>(io1, io2, &prg, pool, party, z_u.data(), LB + 1);
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
            phi[k] ^= tKEY[j][LB + k];
            phi[k] ^= tMAC[j][LB + k];
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
              block key = (j < batch) ? tKEY[peer][k0 + j] : zero_block;
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
              pad[j] = (j < batch) ? tMAC[peer][k0 + j] : zero_block;
            mitc.hash<8, 1>(pad);
            for (int j = 0; j < batch; ++j) {
              block w = wire[k0 + j - st] & select_mask[tr[k0 + j]];
              tMACphi[peer][k0 + j] = pad[j] ^ w;
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
            tKEYphi[party][k] = tKEYphi[party][k] ^ tMACphi[j][k];
            tKEYphi[party][k] = tKEYphi[party][k] ^ tKEY[j][2 * LB + k];
            tKEYphi[party][k] = tKEYphi[party][k] ^ tMAC[j][2 * LB + k];
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
    // of tMAC[peer][2*LB + k] by d so bit0(tMAC) tracks c^1 = r^1 ⊕ d
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
            tMAC[2][2 * LB + k] = tMAC[2][2 * LB + k] ^ bit0_mask;
        } else {
          tKEY[1][2 * LB + k] = tKEY[1][2 * LB + k] ^ (dxor & mask_s);
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
    block S = sampleRandom<nP>(io1, io2, &prg, pool, party);
    PRG jprg(&S);
    jprg.random_block(phi.data(), LB);
    BlockVec ip[nP + 1];
    for (int i = 0; i <= nP; ++i) ip[i].resize(2);
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
    block S = sampleRandom<nP>(io1, io2, &prg, pool, party);
    vector<unsigned char> d[nP + 1];
    for (int i = 1; i <= nP; ++i)
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
        // Slot-major layout: slot s of dst at MAC[j][s*length + i], slot s
        // of src at tMAC[j][s*LB + i]. When out_aos is non-null, also
        // initialize the AoS bundle for each i (Stage 4d: fuses the
        // SoA→AoS transpose into bucketing's existing per-i write).
        { const int j = 3 - party;
          for (int s = 0; s < 3; ++s) {
            memcpy(MAC[j] + s * length + st, tMAC[j].data() + s * LB + st, (ed - st) * sizeof(block));
            memcpy(KEY[j] + s * length + st, tKEY[j].data() + s * LB + st, (ed - st) * sizeof(block));
          }
          if (out_aos) {
            int slot = peer_slot(party, j);
            for (int i = st; i < ed; ++i) {
              out_aos[i].b[0].mac(slot) = tMAC[j][i];
              out_aos[i].b[0].key(slot) = tKEY[j][i];
              out_aos[i].b[1].mac(slot) = tMAC[j][LB + i];
              out_aos[i].b[1].key(slot) = tKEY[j][LB + i];
              out_aos[i].b[2].mac(slot) = tMAC[j][2 * LB + i];
              out_aos[i].b[2].key(slot) = tKEY[j][2 * LB + i];
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
          { const int j = 3 - party;
            int slot = out_aos ? peer_slot(party, j) : 0;
            for (int i = st; i < cut; ++i) {
              int src = base + i + shift;
              MAC[j][i]              = MAC[j][i]              ^ tMAC[j][src];
              MAC[j][2 * length + i] = MAC[j][2 * length + i] ^ tMAC[j][2 * LB + src];
              KEY[j][i]              = KEY[j][i]              ^ tKEY[j][src];
              KEY[j][2 * length + i] = KEY[j][2 * length + i] ^ tKEY[j][2 * LB + src];
              if (out_aos) {
                out_aos[i].b[0].mac(slot) = out_aos[i].b[0].mac(slot) ^ tMAC[j][src];
                out_aos[i].b[0].key(slot) = out_aos[i].b[0].key(slot) ^ tKEY[j][src];
                out_aos[i].b[2].mac(slot) = out_aos[i].b[2].mac(slot) ^ tMAC[j][2 * LB + src];
                out_aos[i].b[2].key(slot) = out_aos[i].b[2].key(slot) ^ tKEY[j][2 * LB + src];
              }
            }
            for (int i = cut; i < ed; ++i) {
              int src = base + i + shift - length;
              MAC[j][i]              = MAC[j][i]              ^ tMAC[j][src];
              MAC[j][2 * length + i] = MAC[j][2 * length + i] ^ tMAC[j][2 * LB + src];
              KEY[j][i]              = KEY[j][i]              ^ tKEY[j][src];
              KEY[j][2 * length + i] = KEY[j][2 * length + i] ^ tKEY[j][2 * LB + src];
              if (out_aos) {
                out_aos[i].b[0].mac(slot) = out_aos[i].b[0].mac(slot) ^ tMAC[j][src];
                out_aos[i].b[0].key(slot) = out_aos[i].b[0].key(slot) ^ tKEY[j][src];
                out_aos[i].b[2].mac(slot) = out_aos[i].b[2].mac(slot) ^ tMAC[j][2 * LB + src];
                out_aos[i].b[2].key(slot) = out_aos[i].b[2].key(slot) ^ tKEY[j][2 * LB + src];
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
      { const int j = 3 - party;
        int slot = out_aos ? peer_slot(party, j) : 0;
        for (int k = 1; k < bucket_size; ++k) {
          int src = k * length + (i + rk[k]) % length;
          block mask = select_mask[d[1][(bucket_size - 1) * i + k - 1]];
          MAC[j][2 * length + i] = MAC[j][2 * length + i] ^ (tMAC[j][src] & mask);
          KEY[j][2 * length + i] = KEY[j][2 * length + i] ^ (tKEY[j][src] & mask);
          if (out_aos) {
            // Mirror the SoA c-slot XOR into AoS slot 2. The masked value
            // is the b-region row k contribution to c (Figure 16's r⊕d
            // in-place flip).
            out_aos[i].b[2].mac(slot) = out_aos[i].b[2].mac(slot) ^ (tMAC[j][src] & mask);
            out_aos[i].b[2].key(slot) = out_aos[i].b[2].key(slot) ^ (tKEY[j][src] & mask);
          }
        }
      }
    }
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] bucket d exchange", party);
#endif

#ifdef EMP_DEBUG_PHASE
    _phase("[triple] check2", party);

    BlockVec MAC_dbg[nP + 1];
    { const int i = 3 - party;
      MAC_dbg[i].assign(MAC[i], MAC[i] + 3 * length);
    }
    BlockVec KEY_dbg[nP + 1];
    { const int i = 3 - party;
      KEY_dbg[i].assign(KEY[i], KEY[i] + 3 * length);
    }
    check_MAC<nP>(io1, io2, MAC_dbg, KEY_dbg, Delta, length * 3, party);
    check_correctness<nP>(io1, io2, MAC_dbg, length, party);
#endif
  }

  // Vector overload: resize output buffers and dispatch to the pointer-array
  // implementation. MAC/KEY peer-slots are sized length*3 (slot-major a/b/c).
  // MAC[party]/KEY[party] are unused; share-bits are recoverable as
  // bit0(MAC[any non-self peer][k]). out_aos forwards as-is.
  void compute(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length,
               TripleBundle<nP> *out_aos = nullptr) {
    { const int i = 3 - party;
      MAC[i].resize(length * 3);
      KEY[i].resize(length * 3);
    }
    block *MAC_p[nP + 1], *KEY_p[nP + 1];
    { const int i = 3 - party;
      MAC_p[i] = MAC[i].data();
      KEY_p[i] = KEY[i].data();
    }
    compute(MAC_p, KEY_p, length, out_aos);
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
  // recoverable as bit0(out_triples[i].b[s].mac(0)).
  void draw(int n, TripleBundleVec<nP> &out_triples) {
    if (available() < (size_t)n)
      preprocess(n);
    out_triples.resize(n);
    memcpy(out_triples.data(), pool_triples.data() + cursor,
           n * sizeof(TripleBundle<nP>));
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
    BlockVec tmac[nP + 1], tkey[nP + 1];
    compute(tmac, tkey, (int)batch, pool_triples.data() + base);
  }
};
#endif // TRIPLE_POOL_H__
