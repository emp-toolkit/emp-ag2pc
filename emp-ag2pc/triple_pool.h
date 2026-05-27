#ifndef TRIPLE_POOL_H__
#define TRIPLE_POOL_H__
#include "emp-ag2pc/helper.h"
#include "emp-ag2pc/share_bundle.h"
#include "emp-tool/io/net_io_channel.h"
#include "emp-tool/crypto/mitccrh.h"
#include "emp-tool/crypto/prp.h"
#include "emp-ot/ot_extension/iknp.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/ot_extension/softspoken/softspoken.h"
#include <atomic>
#include <memory>
#include <thread>

using namespace emp;

// OT-extension backend for the per-pair COT mesh (aShares + leaky-AND COTs).
// Swappable by this one typedef: IKNP (low setup) / SoftSpoken (low bandwidth)
// / Ferret (smallest steady-state bandwidth). The streaming leaky-AND reads
// OTExt::kSenderSendsOnExtend to keep each socket one-directional.
using OTExt = emp::SoftSpoken<8>;

#ifdef AG2PC_PROFILE
#include <chrono>
#include <cstdio>
// Profiler: this party's send+recv bytes spent in the half-gate phi exchange,
// and (separately) in the COT (rcot) extension.
inline uint64_t g_ag2pc_phi_bytes = 0;
inline uint64_t g_ag2pc_cot_bytes = 0;
// Sub-phase timer for TriplePool::compute (decomposes the step-4 black box);
// prints elapsed since the last marker at P1. _tp_t lives in compute() scope so
// the half-gate lambda (captures by ref) and the post-lambda bucketing share it.
#define AG2PC_TP_BEGIN() auto _tp_t = std::chrono::steady_clock::now()
#define AG2PC_TP(name)                                                           \
  do {                                                                         \
    auto _n = std::chrono::steady_clock::now();                                \
    if (party == 1)                                                            \
      printf("[ag2pc-tp]   %-24s %9.3f ms\n", (name),                            \
             std::chrono::duration<double, std::milli>(_n - _tp_t).count());     \
    _tp_t = _n;                                                                  \
  } while (0)
#else
#define AG2PC_TP_BEGIN() ((void)0)
#define AG2PC_TP(name) ((void)0)
#endif

#ifdef AG2PC_MEMPROFILE
#include <sys/resource.h>
#include <cstdio>
#include <algorithm>
// Peak resident set so far (KiB). Monotonic, so sampling it at phase boundaries
// localizes which phase grows the footprint. macOS getrusage reports ru_maxrss
// in bytes, Linux in KiB.
inline long ag2pc_peak_rss_kib() {
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
#if defined(__APPLE__)
  return ru.ru_maxrss / 1024;
#else
  return ru.ru_maxrss;
#endif
}
// One row of the per-array byte census: total MiB and bytes per AND gate (the
// per-gate unit the workload is measured in). div is the AND count.
inline void ag2pc_mem_row(const char *label, double bytes, double div) {
  printf("[ag2pc-mem]   %-18s %10.2f MiB  %9.1f B/AND\n", label,
         bytes / (1024.0 * 1024.0), div > 0 ? bytes / div : 0.0);
}
#endif

// Leaky-AND (eprint 2018/578, Fig. 5) followed by Π_Prep bucketing + amortized
// pool: per-triple half-gate garbled-AND with an F_eq consistency check, then
// circular-shift bucketing to remove leakage (P:aAND). The leaky-AND is batched
// over LB triples; see produce_leaky_ands_halfgate.
//
// (1) No shared-zero mask. The y-contribution C^me = y·Δ_me ⊕ K[y] ⊕ M[y] is
//     computed locally; C^A ⊕ C^B = y·(Δ_A⊕Δ_B) holds from the MAC relation,
//     and the half-gate hash already hides C on the wire.
//
// (2) The consistency check is an F_eq on L^me = S^me ⊕ d·Δ_me: hash the
//     L-vector to one digest and run a rush-secure equality (commit H(D) then
//     open D).
//
// (3) The B-1 sequential OpenToAll calls in P:aAND step 4 (one per
//     non-first leaky triple in each bucket) are batched into a single
//     all-to-all exchange of the full d-vector, dropping the bucket
//     combine to one round.
//
// Pool semantics:
//   - compute() is the refill primitive: mints exactly `length` fresh
//     triples into caller-supplied buffers. Bucket size B drops with
//     `length` (5 / 4 / 3 at thresholds 3.1K / 280K), so big batches
//     shrink the per-triple cost — hence the min_refill floor sits at the
//     bucket-4 threshold (3100) so a small draw never forces a worse bucket.
//   - draw(n, ...) is the amortized API: pulls n triples from an
//     internal pool, refilling via compute(min_refill) when short.
//   - preprocess(n) eagerly mints up to n triples for measured-window
//     benchmarks.
class TriplePool {
public:
  ThreadPool *pool;
  int party;
  // io = primary channel (sequential comm). sib_owned holds the spawned sibling
  // when this object created it (the one-io ctor); it's null when a sibling was
  // handed in. send_io/recv_io alias (io, sib) by party for the duplex sites.
  NetIO *io;
  std::unique_ptr<NetIO> sib_owned;
  NetIO *sib, *send_io, *recv_io;
  // aShare / leaky-AND COT mesh. abit1 is the OT-sender (ALICE, produces KEY),
  // abit2 the OT-receiver (BOB, produces MAC) with MAC = KEY ⊕ x·Δ and
  // bit0(MAC)=x. Their sockets adapt to the backend's extend direction
  // (init_abit_) so the send-dominant role sits on send_io, matching the
  // half-gate.
  PRG prg;
  std::unique_ptr<OTExt> abit1, abit2;
  NetIO *io_abit1, *io_abit2;
  block Delta;

  // AoS-by-triple pool: pool_triples[t] holds the three AShareBundles (a/b/c)
  // of triple t; share bit s is bit0(.b[s].mac). draw() serves from here.
  TripleBundleVec pool_triples;
  size_t cursor = 0;
  // Floor on the refill batch so small draws still amortize the per-call
  // overhead. 3100 is the bucket_size=4 threshold, so the floor never forces a
  // worse bucket; large workloads refill at their own size (≥280K → B=3).
  size_t min_refill = 3100;

  // Borrowing ctor: the caller (C2PC) owns the sibling and threads it in.
  TriplePool(NetIO *io, NetIO *sib, ThreadPool *pool, int party)
      : pool(pool), party(party), io(io), sib(sib),
        send_io(party == 1 ? io : sib), recv_io(party == 1 ? sib : io) {
    init_abit_();
  }

  // Owning ctor: spawn (and own) the sibling channel from the single io.
  TriplePool(NetIO *io, ThreadPool *pool, int party)
      : pool(pool), party(party), io(io),
        sib_owned(io->make_sibling()), sib(sib_owned.get()),
        send_io(party == 1 ? io : sib_owned.get()),
        recv_io(party == 1 ? sib_owned.get() : io) {
    init_abit_();
  }

  // ===== COT-based aShare generation =====
  // Δ pinning + adaptive abit→socket wiring so the COT's send-dominant role (per
  // OTExt::kSenderSendsOnExtend) sits on send_io, matching the half-gate
  // (garbler sends on send_io, eval recvs on recv_io) — no socket direction flip.
  void init_abit_() {
    if (!io->fs_enabled())  io->enable_fs(/*send_first=*/party == 1);
    if (!sib->fs_enabled()) sib->enable_fs(/*send_first=*/party == 1);
    // Δ_me with two pinned bits: bit0=1 (share-value encoding; bit0(M) carries
    // the bit when bit0(K)=0), bit1 set so bit1(Δ_1⊕Δ_2)=1 (half-gate parity).
    bool tmp[128];
    prg.random_bool(tmp, 128);
    tmp[0] = true;
    tmp[1] = (party != 1);
    io_abit1 = OTExt::kSenderSendsOnExtend ? send_io : recv_io;  // ALICE (KEY)
    io_abit2 = OTExt::kSenderSendsOnExtend ? recv_io : send_io;  // BOB   (MAC)
    abit1 = std::make_unique<OTExt>(ALICE, io_abit1);
    abit2 = std::make_unique<OTExt>(BOB,   io_abit2);
    abit1->set_delta(tmp);
    Delta = abit1->Delta;
  }

  // One-shot COT extension: mint `length` aShares into MAC/KEY (resized). The
  // share x_k is implicit in bit0(MAC[k]); MAC = KEY ⊕ x·Δ straight from rcot.
  // Used by draw() and the cut-and-choose path (the half-gate streams instead).
  void process_phase1(BlockVec &MAC, BlockVec &KEY, int length) {
    MAC.resize(length);
    KEY.resize(length);
#ifdef AG2PC_PROFILE
    int64_t _cot0 = io_count(send_io, recv_io);
#endif
    vector<future<void>> res;
    res.push_back(pool->enqueue([this, &KEY, length]() {
      abit1->rcot(KEY.data(), length);
      io_abit1->flush();
    }));
    res.push_back(pool->enqueue([this, &MAC, length]() {
      abit2->rcot(MAC.data(), length);
      io_abit2->flush();
    }));
    joinNclean(res);
#ifdef AG2PC_PROFILE
    g_ag2pc_cot_bytes += (uint64_t)(io_count(send_io, recv_io) - _cot0);
#endif
  }

  // AoS draw: n aShares as AShareBundle{mac,key} (the layout 2pc consumes).
  // No persistent pool — each call mints fresh, so prefer one large draw.
  void draw(int n, AShareBundleVec &out_bundle) {
    BlockVec tmac, tkey;
    process_phase1(tmac, tkey, n);
    out_bundle.resize(n);
    for (int i = 0; i < n; ++i) {
      out_bundle[i].mac = tmac[i];
      out_bundle[i].key = tkey[i];
    }
  }

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

  // Leaky-AND method. The COT/aShare generation and the Π_aAND bucketing are
  // shared; only the middle leaky-AND step differs. HalfGate = garbled
  // half-gate (active). CutChoose = OT-based cut-and-choose (see
  // triple_pool_cutchoose.h).
  enum class LeakyAnd { HalfGate, CutChoose };
  static constexpr LeakyAnd kLeakyAnd = LeakyAnd::HalfGate;
  static constexpr int cutchoose_T = 3;  // correctness-sacrifice bucket size

  // Authenticated bits to mint for LB leaky-triple slots: half-gate needs 3·LB
  // (a, b, r); cut-and-choose mints T× more candidates for its sacrifice.
  static int leaky_abit_len(int LB) {
    return kLeakyAnd == LeakyAnd::HalfGate ? 3 * LB : 3 * cutchoose_T * LB;
  }

  // The CutChoose leaky-AND path lives in its own file (OT multiply, sacrifice,
  // self-tests). It is #included inside the class so the methods stay inline
  // TriplePool members; dormant while kLeakyAnd == HalfGate.
  #include "emp-ag2pc/triple_pool_cutchoose.h"

  // Mint `length` AND triples into MAC/KEY, slot-major a/b/c: share bit s of
  // triple k is bit0(MAC[s*length+k]), bit0(KEY)=0. If out_aos is non-null the
  // triples are also written as AoS TripleBundles (the layout draw() serves).
  void compute(block *MAC, block *KEY, int length,
               TripleBundle *out_aos = nullptr) {
    int bucket_size = get_bucket_size(length);
    int LB = length * bucket_size;
    // a/b/r authenticated bits for the LB leaky triples.
    int abit_len = leaky_abit_len(LB);

    BlockVec tMAC, tKEY;
    // Half-gate output: the eval thread writes S^me per leaky triple into Sout
    // (folded in place to L^me for the F_eq check). The garbler thread is
    // read-only over the aShares; C^me and the sender pad H(K) are recomputed
    // on the eval thread, so the two threads share only read-only data (no
    // lock). s[party]/s[peer] are the garbling-parity shares, s[0] = XOR.
    BlockVec Sout;
    vector<unsigned char> s[3];
    vector<unsigned char> tr;

    tr.reserve(abit_len);
    tMAC.reserve(abit_len);
    tKEY.reserve(abit_len);
    Sout.resize(LB);
    for (int i = 0; i <= 2; ++i) s[i].resize(LB);

#ifdef EMP_DEBUG_PHASE
    _phase("", party);
#endif

    vector<future<void>> res;
    AG2PC_TP_BEGIN();

    // Half-gate leaky-AND (eprint 2018/578, Fig. 5). Consumes the a/b/r aShares in
    // tMAC/tKEY (+ share bits tr) and produces LB leaky AND triples in the
    // a/b/c layout the bucketing reads (r -> c). The CutChoose sibling has the
    // same contract + its own leaky_abit_len.
    auto produce_leaky_ands_halfgate = [&]() {
    // Stream the leaky-AND a chunk at a time: produce one chunk of COT and run
    // the half-gate on it, looping. The COTs form ONE streaming session
    // (begin / next* / end) so the malicious consistency check runs once over
    // the whole stream; the half-gate consumes each chunk's COTs before that
    // end()-check (the F_eq + abort-on-check gate acceptance).
    //
    // C^me = y·Δ ⊕ K[y] ⊕ M[y] (C^A ⊕ C^B = y·(Δ_A⊕Δ_B)); the half-gate hash
    // hides C, so phi = C directly. Per chunk the garbler hashes (K, K⊕Δ) with
    // hash<8,2> and ships G = H(K) ⊕ H(K⊕Δ) ⊕ C on send_io; the eval recvs G on
    // recv_io and recomputes C and the sender pad H(K) itself (hash<8,2> over
    // (M, K) under the same tweak via renew_ks(st)), forms E = H(M) ⊕ x·G, and
    // writes S^me = H(K) ⊕ E ⊕ (K[r]⊕M[r]) ⊕ x·C ⊕ r·Δ into Sout. The two
    // threads share only the read-only aShares (no lock).
    tMAC.resize(abit_len);
    tKEY.resize(abit_len);
    tr.resize(abit_len);
    AG2PC_TP("alloc 3.LB COT bufs");
    // W = the OT backend's internal chunk: every next() is one full optimal
    // batch. The send-dominant COT role sits on send_io (init_abit_), so the COT
    // and half-gate never flip a socket's direction.
    const int W = (int)abit1->chunk_size();
    BlockVec stageK((size_t)W), stageM((size_t)W);  // only the final partial chunk
    const block pair_seed = makeBlock((uint64_t)std::min(party, 3 - party),
                                      (uint64_t)std::max(party, 3 - party));
#ifdef AG2PC_PROFILE
    int64_t _mark = io_count(send_io, recv_io);
#endif
    // open the COT session (concurrent base-OT on the two sockets)
    {
      vector<future<void>> rb;
      rb.push_back(pool->enqueue([this]() { abit1->begin(); io_abit1->flush(); }));
      rb.push_back(pool->enqueue([this]() { abit2->begin(); io_abit2->flush(); }));
      joinNclean(rb);
    }
#ifdef AG2PC_PROFILE
    g_ag2pc_cot_bytes += (uint64_t)(io_count(send_io, recv_io) - _mark);
    _mark = io_count(send_io, recv_io);
#endif
    AG2PC_TP("COT begin (+base OT)");
    // Fuse the COT and half-gate into two long-lived threads so each role reads
    // the chunk it just produced while it is cache-warm, instead of writing the
    // chunk and re-loading it across a phase boundary. The send thread produces
    // tMAC (abit2) + derives tr, the recv thread produces tKEY (abit1); a
    // 2-thread barrier per chunk gates the half-gate (both roles read both COT
    // halves, so both COTs must finish first). tr is written by the send thread
    // before the barrier, so it is read-only for both roles afterward.
    const int nchunks = (LB + W - 1) / W;
    std::atomic<int> bar_cnt{0};
    std::atomic<uint64_t> bar_gen{0};
    auto barrier = [&]() {
      uint64_t g = bar_gen.load(std::memory_order_acquire);
      if (bar_cnt.fetch_add(1, std::memory_order_acq_rel) == 1) {  // 2nd arriver
        bar_cnt.store(0, std::memory_order_relaxed);
        bar_gen.store(g + 1, std::memory_order_release);
      } else {
        while (bar_gen.load(std::memory_order_acquire) == g)
          std::this_thread::yield();
      }
    };
    // send thread (send_io): abit2 -> tMAC, derive tr, then garbler ships G.
    res.push_back(pool->enqueue([&, this]() {
      MITCCRH<8> mitc; mitc.setS(pair_seed);
      block pad[16];
      BlockVec tmp(W);
      for (int ci = 0; ci < nchunks; ++ci) {
        const int st = ci * W, ed = std::min(st + W, LB), Wc = ed - st;
        for (int reg = 0; reg <= 2; ++reg) {
          block *dst = tMAC.data() + (size_t)reg * LB + st;
          if (Wc == W) abit2->next(dst);
          else { abit2->next(stageM.data());
                 memcpy(dst, stageM.data(), (size_t)Wc * sizeof(block)); }
        }
        for (int reg = 0; reg <= 2; ++reg)
          for (int k = st; k < ed; ++k)
            tr[(size_t)reg * LB + k] = LSB(tMAC[(size_t)reg * LB + k]);
        io_abit2->flush();
        barrier();                              // tKEY now ready too
        mitc.renew_ks((uint64_t)st);
        for (int k0 = st; k0 < ed; k0 += 8) {
          int batch = std::min(8, ed - k0);
          for (int j = 0; j < 8; ++j) {
            block key = (j < batch) ? tKEY[k0 + j] : zero_block;
            pad[2 * j]     = key;
            pad[2 * j + 1] = key ^ Delta;
          }
          mitc.hash<8, 2>(pad);
          for (int j = 0; j < batch; ++j) {
            int k = k0 + j;
            block C = (select_mask[tr[LB + k]] & Delta) ^ tKEY[LB + k] ^ tMAC[LB + k];
            tmp[k - st] = pad[2 * j] ^ pad[2 * j + 1] ^ C;
          }
        }
        send_io->send_data(tmp.data(), (size_t)Wc * sizeof(block));
        send_io->flush();
      }
    }));
    // recv thread (recv_io): abit1 -> tKEY, then eval recvs G and writes Sout.
    res.push_back(pool->enqueue([&, this]() {
      MITCCRH<8> mitc; mitc.setS(pair_seed);
      block pad[16];
      BlockVec wire(W);
      for (int ci = 0; ci < nchunks; ++ci) {
        const int st = ci * W, ed = std::min(st + W, LB), Wc = ed - st;
        for (int reg = 0; reg <= 2; ++reg) {
          block *dst = tKEY.data() + (size_t)reg * LB + st;
          if (Wc == W) abit1->next(dst);
          else { abit1->next(stageK.data());
                 memcpy(dst, stageK.data(), (size_t)Wc * sizeof(block)); }
        }
        io_abit1->flush();
        barrier();                              // tMAC + tr now ready
        mitc.renew_ks((uint64_t)st);
        recv_io->recv_data(wire.data(), (size_t)Wc * sizeof(block));
        for (int k0 = st; k0 < ed; k0 += 8) {
          int batch = std::min(8, ed - k0);
          for (int j = 0; j < 8; ++j) {
            pad[2 * j]     = (j < batch) ? tMAC[k0 + j] : zero_block;  // -> H(M)
            pad[2 * j + 1] = (j < batch) ? tKEY[k0 + j] : zero_block;  // -> H(K)
          }
          mitc.hash<8, 2>(pad);
          for (int j = 0; j < batch; ++j) {
            int k = k0 + j;
            block HM = pad[2 * j], HK = pad[2 * j + 1];
            block E = HM ^ (wire[k - st] & select_mask[tr[k]]);
            block C = (select_mask[tr[LB + k]] & Delta) ^ tKEY[LB + k] ^ tMAC[LB + k];
            Sout[k] = HK ^ E
                    ^ tKEY[2 * LB + k] ^ tMAC[2 * LB + k]
                    ^ (C & select_mask[tr[k]])
                    ^ (Delta & select_mask[tr[2 * LB + k]]);
          }
        }
      }
    }));
    joinNclean(res);
#ifdef AG2PC_PROFILE
    g_ag2pc_phi_bytes += (uint64_t)(io_count(send_io, recv_io) - _mark);
    _mark = io_count(send_io, recv_io);
#endif
    AG2PC_TP("COT + half-gate loop");
    // close the COT session: the single malicious consistency check.
    {
      vector<future<void>> re;
      re.push_back(pool->enqueue([this]() { abit1->end(); io_abit1->flush(); }));
      re.push_back(pool->enqueue([this]() { abit2->end(); io_abit2->flush(); }));
      joinNclean(re);
    }
#ifdef AG2PC_PROFILE
    g_ag2pc_cot_bytes += (uint64_t)(io_count(send_io, recv_io) - _mark);
#endif
    AG2PC_TP("COT end (consistency)");
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] streaming leaky-AND", party);
#endif

    // Open d^me = LSB1(s^me) to the peer (bit 1 carries the garbling parity
    // under the bit-0/bit-1 Δ convention); d = d^A ⊕ d^B.
    for (int k = 0; k < LB; ++k)
      s[party][k] = LSB1(Sout[k]);
    { const int peer = 3 - party;
      res.push_back(pool->enqueue([this, &s, LB, peer]() {
        send_io->send_bool((const bool *)s[party].data(), LB);  // 1 bit/elt, packed
        send_io->flush();
      }));
      res.push_back(pool->enqueue([this, &s, LB, peer]() {
        recv_io->recv_bool((bool *)s[peer].data(), LB);
      }));
    }
    joinNclean(res);

    // steps 7 + (part of) 11: combine d = ⊕_i d^i; compute t^i = s^i ⊕ d·Δ_i
    // (folded into T = Sout).  We also fold d into the r-share
    // in-place so r becomes c = r ⊕ d (paper step 11): only P1 flips its
    // r-bit, and every P_(j≠1) flips K_j[c^1] = K_j[r^1] ⊕ d·Δ_j to
    // maintain MAC consistency on the new c^1 bit.
    //
    // Bit-0 pinned variant (matches the init_abit_ Δ pinning): peer j uses
    // (Δ_j ⊕ e_0) so bit 0 of tKEY[1] stays at 0; P1 instead flips bit 0
    // of tMAC[2*LB + k] by d so bit0(tMAC) tracks c^1 = r^1 ⊕ d
    // across all peers. tr[2*LB + k] is mirrored to keep the legacy byte
    // vector in sync (Step E removes it).
    {
      block *T = Sout.data();
      block dxor = Delta ^ bit0_mask;
      for (int k = 0; k < LB; ++k) {
        s[0][k] = (s[1][k] != s[2][k]);
        block mask_s = select_mask[s[0][k]];
        if (party == 1) {
          tr[2 * LB + k] = (s[0][k] != tr[2 * LB + k]);
          tMAC[2 * LB + k] = tMAC[2 * LB + k] ^ (bit0_mask & mask_s);
        } else {
          tKEY[2 * LB + k] = tKEY[2 * LB + k] ^ (dxor & mask_s);
        }
        T[k] = T[k] ^ (Delta & mask_s);
      }
    }
    AG2PC_TP("d-open + combine s");
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] combine s", party);
#endif

    // step 5 (F_eq): the leaky-AND consistency check. After the step-7 fold,
    // Sout[k] = S^me_k ⊕ d_k·Δ_me = L^me_k (eprint 2018/578, Fig. 5). On honest
    // execution L^A_k = L^B_k for every k, so a batched equality of D = H(L)
    // catches a cheating multiplication.
    //
    // The check is an equality, so it is realized as the RO-model EQ protocol
    // of eprint 2018/578: party A commits c = H(x‖r) with a fresh random nonce
    // r, party B then sends its value y, and only then A opens (x, r); B
    // verifies H(x‖r)==c and x==y. The asymmetric order makes it rush-safe (a
    // symmetric "both commit, both open" lets a rushing party echo the peer's
    // commitment and opening to pass with a bad triple), and the nonce keeps
    // the commitment hiding. We run EQ on x := D = H(L-vector), so the revealed
    // values stay digest-sized; D^A == D^B iff the L-vectors match. Only the
    // equality verdict leaks (the leaky-AND's allowed ≤1 bit).
    char Dme[Hash::DIGEST_SIZE], Dpeer[Hash::DIGEST_SIZE];
    Hash::hash_once(Dme, Sout.data(), (size_t)LB * sizeof(block));
    if (party == 1) {                                 // A
      block r; PRG().random_block(&r, 1);
      char com[Hash::DIGEST_SIZE];
      { Hash h; h.put(Dme, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(com); }
      io->send_data(com, Hash::DIGEST_SIZE);          // 1. c = H(x‖r)
      io->flush();
      io->recv_data(Dpeer, Hash::DIGEST_SIZE);        // 2. B sends y
      io->send_data(Dme, Hash::DIGEST_SIZE);          // 3. A opens x, r
      io->send_data(&r, sizeof(block));
      io->flush();
    } else {                                          // B
      char com[Hash::DIGEST_SIZE], chk[Hash::DIGEST_SIZE];
      block r;
      io->recv_data(com, Hash::DIGEST_SIZE);          // 1.
      io->send_data(Dme, Hash::DIGEST_SIZE);          // 2. send y (before A opens)
      io->flush();
      io->recv_data(Dpeer, Hash::DIGEST_SIZE);        // 3. recv x
      io->recv_data(&r, sizeof(block));               //    and r
      { Hash h; h.put(Dpeer, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(chk); }
      if (memcmp(chk, com, Hash::DIGEST_SIZE) != 0)
        error("LaAND F_eq: commit-open mismatch");
    }
    if (memcmp(Dme, Dpeer, Hash::DIGEST_SIZE) != 0)
      error("LaAND F_eq: leaky-AND check failed");
    AG2PC_TP("F_eq check");
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] LAND check", party);
#endif
    };  // end produce_leaky_ands_halfgate

    // Run the active leaky-AND method. HalfGate streams its own COT (above);
    // CutChoose mints all aShares up front, then runs the cut-and-choose.
    if constexpr (kLeakyAnd == LeakyAnd::HalfGate) produce_leaky_ands_halfgate();
    else {
      (void)produce_leaky_ands_halfgate;
      process_phase1(tMAC, tKEY, abit_len);
      tr.resize(abit_len);
      for (int k = 0; k < abit_len; ++k) tr[k] = LSB(tMAC[k]);
      cutchoose_leaky(tMAC, tKEY, tr, LB);
    }

    // Π_aAND (P:aAND): bucketing via per-row circular shifts on a
    // bucket_size × length matrix.  Row 0 is fixed, rows 1..B-1 get a random
    // shift r_k ∈ [0, length).  We don't materialize a permutation array:
    // bucket i's k-th slot is leaky triple (k * length + (i + r_k) mod length),
    // which is sequential in i (with at most one wraparound), so each row is
    // streamed once per bucket range.
    // Public coin: absorb both channels' digests in a fixed (io, sib) order —
    // same labeled pairs on both ends, so both parties derive the same S.
    block S = RO("AG2PC RO", zero_block)
                  .absorb(io->get_digest())
                  .absorb(sib->get_digest())
                  .squeeze_block();
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
    AG2PC_TP("bucketing (shift-XOR)");
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] bucketing", party);
#endif

    { const int peer = 3 - party;
      res.push_back(pool->enqueue([this, &d, length, bucket_size, peer]() {
        send_io->send_bool((const bool *)d[party].data(), (bucket_size - 1) * length);
        send_io->flush();
      }));
      res.push_back(pool->enqueue([this, &d, length, bucket_size, peer]() {
        recv_io->recv_bool((bool *)d[peer].data(), (bucket_size - 1) * length);
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
    AG2PC_TP("bucket d-exch + c-fold");
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] bucket d exchange", party);
#endif

#ifdef AG2PC_MEMPROFILE
    if (party == 1) {
      const double A = (double)std::max(1, length);   // 1 triple per AND gate
      printf("[ag2pc-mem] TriplePool::compute  length=%d bucket=%d LB=%d "
             "abit_len=%d\n", length, bucket_size, LB, abit_len);
      ag2pc_mem_row("tMAC+tKEY",  (double)(tMAC.capacity() + tKEY.capacity()) * sizeof(block), A);
      ag2pc_mem_row("Sout",       (double)Sout.capacity() * sizeof(block), A);
      ag2pc_mem_row("tr+s+d",     (double)(tr.capacity() + s[0].capacity() + s[1].capacity()
                                  + s[2].capacity() + d[1].capacity() + d[2].capacity()), A);
      ag2pc_mem_row("MAC+KEY out", 2.0 * 3.0 * (double)length * sizeof(block), A);
      ag2pc_mem_row("stage(const)", 2.0 * (double)abit1->chunk_size() * sizeof(block), A);
      ag2pc_mem_row("pool_triples", (double)pool_triples.capacity() * sizeof(TripleBundle), A);
      printf("[ag2pc-mem]   peakRSS-so-far %8ld KiB\n", ag2pc_peak_rss_kib());
    }
#endif

#ifdef EMP_DEBUG_PHASE
    _phase("[triple] check2", party);

    BlockVec MAC_dbg(MAC, MAC + 3 * length);
    BlockVec KEY_dbg(KEY, KEY + 3 * length);
    check_MAC(io, MAC_dbg, KEY_dbg, Delta, length * 3, party);
    check_correctness(io, MAC_dbg, length, party);
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

  // ==== Pool API ====

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
  // Compact (drop consumed prefix), grow pool_triples by `batch`, then run
  // compute() with out_aos pointing into the freshly grown slots. Bucketing
  // writes the AoS bundles in place during its per-row XOR loop; the SoA
  // tmac/tkey buffers are compute()'s scratch / output for the debug check_MAC
  // path but the pool no longer reads them post-compute.
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
