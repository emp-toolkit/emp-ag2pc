#ifndef TRIPLE_POOL_H__
#define TRIPLE_POOL_H__
#include "emp-ag2pc/helper.h"
#include "emp-ag2pc/share_bundle.h"
#include "emp-ag2pc/profiling.h"
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
//
// SoftSpoken<k>: k is the compute/bandwidth knob (k ∈ {1,2,4,8}). Smaller k =
// fewer AES calls per COT but more bytes on the wire; larger k = the reverse.
// k=4 sits at the COT-compute floor on a fast/local link while staying well
// below k=2's bandwidth; raise toward k=8 on a bandwidth-tight link.
using OTExt = emp::SoftSpoken<4>;

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

  // Share generator: mint `count` checked random authenticated shares into the
  // mac/key spans (one COT session per call — abit1->rcot is begin/next*/end with
  // a single consistency check). bit0(mac)=x, mac = key ⊕ x·Δ. Pointer form so a
  // leaky-AND layer can fill a whole region triple (3·L) or just one region (the
  // in-place representative's fresh r). Shared by the leaky-AND layers,
  // process_phase1 / draw, and the cut-and-choose path.
  void gen_cot_shares(block *mac, block *key, int count) {
#ifdef AG2PC_PROFILE
    int64_t _cot0 = io_count(send_io, recv_io);
    uint64_t _ct0 = tp_now_ns();
#endif
    vector<future<void>> res;
    res.push_back(pool->enqueue([this, key, count]() {
      abit1->rcot(key, count);
      io_abit1->flush();
    }));
    res.push_back(pool->enqueue([this, mac, count]() {
      abit2->rcot(mac, count);
      io_abit2->flush();
    }));
    joinNclean(res);
#ifdef AG2PC_PROFILE
    g_tp_cot_ns += tp_now_ns() - _ct0;
    g_ag2pc_cot_bytes += (uint64_t)(io_count(send_io, recv_io) - _cot0);
#endif
  }

  // One-shot COT extension: mint `length` aShares into MAC/KEY (resized).
  void process_phase1(BlockVec &MAC, BlockVec &KEY, int length) {
    MAC.resize(length);
    KEY.resize(length);
    gen_cot_shares(MAC.data(), KEY.data(), length);
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

  // ===== Leaky-AND layer primitives (eprint 2018/578, Fig. 5 + P:aAND) =====
  // A "layer" is L candidate triples in SoA region-major order, stride L:
  // region a=[0,L), b=[L,2L), r/c=[2L,3L); the share bit of region g triple i is
  // LSB(mac[g*L+i]). Region 2 holds the output mask r before leaky_and_halfgate
  // and the leaky product c=a∧b after (the fold is in place). gen_cot_shares
  // fills a layer (or one region); the same leaky_and_halfgate / bucket_one_layer
  // serve both the generic and the in-place (function-dependent) paths.

  // Half-gate leaky-AND over the L candidates whose 3L authenticated shares are in
  // mac/key. The garbler ships G on send_io; the eval recovers S^me on recv_io and
  // writes it locally; an s-open folds d into region 2 (r -> c = a∧b) in place; the
  // F_eq equality check (rush-safe) aborts on a cheating multiplication. The
  // per-element share bit is just LSB(mac[...]), read inline (cache-hot — mac is
  // loaded for the hashes anyway), so there is no separate tr array. gmitc/emitc
  // persist across a bucket's layers (one setS in the caller), so the per-gate
  // tweak (gid) keeps advancing and never repeats. No COT: the shares are given
  // (COT and/or copied wire masks), which is why this serves both representative
  // and sacrifices.
  void leaky_and_halfgate(block *mac, block *key, int L,
                          MITCCRH<8> &gmitc, MITCCRH<8> &emitc) {
    BlockVec Sout(L);
    vector<future<void>> res;
#ifdef AG2PC_PROFILE
    uint64_t _hg0 = tp_now_ns();
#endif
    // Pipeline G one hash-batch (8 gates) at a time: the garbler ships each batch
    // as it is built (NetIO coalesces the writes; one flush at the end) so the
    // evaluator recvs and computes it while the garbler builds the next —
    // overlapping the two halves instead of blocking on the whole G.
    res.push_back(pool->enqueue([&, this]() {            // garbler on send_io
      block pad[16], g8[8];
      for (int k0 = 0; k0 < L; k0 += 8) {
        int batch = std::min(8, L - k0);
        for (int j = 0; j < 8; ++j) {
          block kk = (j < batch) ? key[k0 + j] : zero_block;
          pad[2 * j] = kk;
          pad[2 * j + 1] = kk ^ Delta;
        }
        gmitc.hash<8, 2>(pad);
        for (int j = 0; j < batch; ++j) {
          int k = k0 + j;
          block C = (select_mask[LSB(mac[L + k])] & Delta) ^ key[L + k] ^ mac[L + k];
          g8[j] = pad[2 * j] ^ pad[2 * j + 1] ^ C;
        }
        send_io->send_data(g8, (size_t)batch * sizeof(block));
      }
      send_io->flush();
    }));
    res.push_back(pool->enqueue([&, this]() {            // eval on recv_io
      block pad[16], w8[8];
      for (int k0 = 0; k0 < L; k0 += 8) {
        int batch = std::min(8, L - k0);
        recv_io->recv_data(w8, (size_t)batch * sizeof(block));
        for (int j = 0; j < 8; ++j) {
          pad[2 * j]     = (j < batch) ? mac[k0 + j] : zero_block;  // -> H(M)
          pad[2 * j + 1] = (j < batch) ? key[k0 + j] : zero_block;  // -> H(K)
        }
        emitc.hash<8, 2>(pad);
        for (int j = 0; j < batch; ++j) {
          int k = k0 + j;
          block HM = pad[2 * j], HK = pad[2 * j + 1];
          block E = HM ^ (w8[j] & select_mask[LSB(mac[k])]);
          block C = (select_mask[LSB(mac[L + k])] & Delta) ^ key[L + k] ^ mac[L + k];
          Sout[k] = HK ^ E ^ key[2 * L + k] ^ mac[2 * L + k]
                  ^ (C & select_mask[LSB(mac[k])])
                  ^ (Delta & select_mask[LSB(mac[2 * L + k])]);
        }
      }
    }));
    joinNclean(res);
#ifdef AG2PC_PROFILE
    g_tp_hg_ns += tp_now_ns() - _hg0;
    uint64_t _so0 = tp_now_ns();
#endif

    // s-open + combine: d = ⊕_party LSB1(S). Fold d into Sout (-> L^me) and into
    // region 2 (r -> c = r⊕d): P1 flips bit0(mac[2L+k]); the peer flips key by
    // (Δ⊕e_0) so bit0(key) stays pinned. The c-region share bit then reads back as
    // LSB(mac[2L+k]) with no separate mirror to maintain.
    vector<unsigned char> s_me(L), s_peer(L);
    for (int k = 0; k < L; ++k) s_me[k] = LSB1(Sout[k]);
    res.push_back(pool->enqueue([&, this]() {
      send_io->send_bool((const bool *)s_me.data(), L);
      send_io->flush();
    }));
    res.push_back(pool->enqueue([&, this]() {
      recv_io->recv_bool((bool *)s_peer.data(), L);
    }));
    joinNclean(res);
    {
      block dxor = Delta ^ bit0_mask;
      for (int k = 0; k < L; ++k) {
        unsigned char d = (s_me[k] != s_peer[k]);
        block mask_s = select_mask[d];
        if (party == 1) {
          mac[2 * L + k] = mac[2 * L + k] ^ (bit0_mask & mask_s);
        } else {
          key[2 * L + k] = key[2 * L + k] ^ (dxor & mask_s);
        }
        Sout[k] = Sout[k] ^ (Delta & mask_s);
      }
    }
#ifdef AG2PC_PROFILE
    g_tp_sopen_ns += tp_now_ns() - _so0;
    uint64_t _fq0 = tp_now_ns();
#endif

    // F_eq: EQ on D = H(L-vector) (eprint 2018/578). A commits H(x‖r), B sends y,
    // A opens (x,r); asymmetric order is rush-safe, the nonce keeps it hiding.
    char Dme[Hash::DIGEST_SIZE], Dpeer[Hash::DIGEST_SIZE];
    Hash::hash_once(Dme, Sout.data(), (size_t)L * sizeof(block));
    if (party == 1) {
      block r; PRG().random_block(&r, 1);
      char com[Hash::DIGEST_SIZE];
      { Hash h; h.put(Dme, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(com); }
      io->send_data(com, Hash::DIGEST_SIZE);
      io->recv_data(Dpeer, Hash::DIGEST_SIZE);
      io->send_data(Dme, Hash::DIGEST_SIZE);
      io->send_data(&r, sizeof(block)); io->flush();
    } else {
      char com[Hash::DIGEST_SIZE], chk[Hash::DIGEST_SIZE];
      block r;
      io->recv_data(com, Hash::DIGEST_SIZE);
      io->send_data(Dme, Hash::DIGEST_SIZE);
      io->recv_data(Dpeer, Hash::DIGEST_SIZE);
      io->recv_data(&r, sizeof(block));
      { Hash h; h.put(Dpeer, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(chk); }
      if (memcmp(chk, com, Hash::DIGEST_SIZE) != 0)
        error("LaAND F_eq: commit-open mismatch");
    }
    if (memcmp(Dme, Dpeer, Hash::DIGEST_SIZE) != 0)
      error("LaAND F_eq: leaky-AND check failed");
#ifdef AG2PC_PROFILE
    g_tp_feq_ns += tp_now_ns() - _fq0;
#endif
  }

  // Fold one bucketing layer into the accumulator (P:aAND combine): with the
  // layer cyclically reindexed by r (src=(i+r) mod L, split at the one wraparound),
  // acc.a ^= layer.a, acc.c ^= layer.c ⊕ d·layer.a, where d = bit_b(acc) ⊕
  // bit_b(layer) is opened over (send_io, recv_io). acc.b is untouched (it stays
  // the representative's b across all layers). Call B-1 times per bucket.
  void bucket_one_layer(block *am, block *ak,
                        const block *lm, const block *lk,
                        int L, int r) {
#ifdef AG2PC_PROFILE
    uint64_t _b0 = tp_now_ns();
#endif
    vector<unsigned char> d_me(L), d_peer(L);
    const int cut = L - r;                       // r ∈ [0,L); src wraps at i==cut
    for (int i = 0; i < L; ++i) {
      int src = (i < cut) ? i + r : i + r - L;
      am[i]         = am[i]         ^ lm[src];              // a ^= layer.a
      am[2 * L + i] = am[2 * L + i] ^ lm[2 * L + src];      // c ^= layer.c
      ak[i]         = ak[i]         ^ lk[src];
      ak[2 * L + i] = ak[2 * L + i] ^ lk[2 * L + src];
      d_me[i] = LSB(am[L + i]) ^ LSB(lm[L + src]);          // b-share diff (bit0 of b-region mac)
    }
    vector<future<void>> res;
    res.push_back(pool->enqueue([&, this]() {
      send_io->send_bool((const bool *)d_me.data(), L);
      send_io->flush();
    }));
    res.push_back(pool->enqueue([&, this]() {
      recv_io->recv_bool((bool *)d_peer.data(), L);
    }));
    joinNclean(res);
    for (int i = 0; i < L; ++i) {
      int src = (i < cut) ? i + r : i + r - L;
      block m = select_mask[(unsigned char)(d_me[i] ^ d_peer[i])];
      am[2 * L + i] = am[2 * L + i] ^ (lm[src] & m);        // c ^= layer.a · d
      ak[2 * L + i] = ak[2 * L + i] ^ (lk[src] & m);
    }
#ifdef AG2PC_PROFILE
    g_tp_bkt_ns += tp_now_ns() - _b0;
#endif
  }

  // Generate B-1 fresh sacrifice layers (COT + half-gate), then bucket them all
  // into acc. The shifts are drawn from the public coin AFTER every candidate is
  // committed (all leaky-ANDs done), so a cheater cannot bias which candidates
  // co-bucket. On return acc holds L secure triples (a/b = layer 0's, c secure).
  // The caller has already filled+leaky'd layer 0 (acc) with gmitc/emitc, which
  // continue here so each layer's tweaks stay distinct.
  void layered_bucket_into_acc(block *am, block *ak, int B,
                               int L, MITCCRH<8> &gmitc, MITCCRH<8> &emitc) {
    struct Lyr { BlockVec mac, key; };
    std::vector<Lyr> sac(B - 1);
    for (int k = 0; k < B - 1; ++k) {
      sac[k].mac.resize((size_t)3 * L);
      sac[k].key.resize((size_t)3 * L);
      gen_cot_shares(sac[k].mac.data(), sac[k].key.data(), 3 * L);
      leaky_and_halfgate(sac[k].mac.data(), sac[k].key.data(), L, gmitc, emitc);
    }
    // Public coin: same labeled (io, sib) digests on both ends -> same S.
    block S = RO("AG2PC RO", zero_block)
                  .absorb(io->get_digest()).absorb(sib->get_digest()).squeeze_block();
    std::vector<int> rk(B - 1);
    { PRG prg2(&S);
      std::vector<uint32_t> raw(B - 1);
      prg2.random_data(raw.data(), (B - 1) * sizeof(uint32_t));
      for (int k = 0; k < B - 1; ++k) rk[k] = (int)(raw[k] % (uint32_t)L); }
    for (int k = 0; k < B - 1; ++k)
      bucket_one_layer(am, ak, sac[k].mac.data(), sac[k].key.data(), L, rk[k]);
  }

  // Generic half-gate triple generation: layer 0 (the output MAC/KEY, all COT) +
  // B-1 fresh sacrifice layers, bucketed. Output is the slot-major a/b/c triple in
  // MAC/KEY (+ AoS out_aos) — identical contract to the old fused compute().
  void compute_halfgate(block *MAC, block *KEY, int length, TripleBundle *out_aos) {
    if (length == 0) return;     // AND-free chunk: nothing to mint
    const int B = get_bucket_size(length);
    const int L = length;
    const block pair_seed = makeBlock((uint64_t)std::min(party, 3 - party),
                                      (uint64_t)std::max(party, 3 - party));
    MITCCRH<8> gmitc, emitc;
    gmitc.setS(pair_seed);
    emitc.setS(pair_seed);
    AG2PC_TP_BEGIN();
    gen_cot_shares(MAC, KEY, 3 * L);                          // layer 0 = MAC/KEY
    leaky_and_halfgate(MAC, KEY, L, gmitc, emitc);
    AG2PC_TP("layer 0 (gen+leaky)");
    layered_bucket_into_acc(MAC, KEY, B, L, gmitc, emitc);
    AG2PC_TP("sacrifice layers + bucket");
    if (out_aos) {
      for (int i = 0; i < L; ++i) {
        out_aos[i].b[0].mac = MAC[i];         out_aos[i].b[0].key = KEY[i];
        out_aos[i].b[1].mac = MAC[L + i];     out_aos[i].b[1].key = KEY[L + i];
        out_aos[i].b[2].mac = MAC[2 * L + i]; out_aos[i].b[2].key = KEY[2 * L + i];
      }
    }
#ifdef AG2PC_PROFILE
    if (party == 1) {
      const double A = (double)std::max(1, length);
      printf("[ag2pc-mem] compute_halfgate length=%d bucket=%d (acc + %d sacrifice "
             "layers, 3L each)\n", length, B, B - 1);
      ag2pc_mem_row("acc MAC+KEY", 2.0 * 3.0 * (double)L * sizeof(block), A);
      ag2pc_mem_row("sacrifice", 2.0 * 3.0 * (double)L * sizeof(block) * (B - 1), A);
      printf("[ag2pc-mem]   peakRSS-so-far %8ld KiB\n", ag2pc_peak_rss_kib());
    }
#endif
  }

  // In-place (function-dependent) AND-share generation (KRRW §5.2 bucket-saving).
  // For each AND gate the bucket's representative (layer 0) is the leaky-AND of the
  // gate's OWN input wire masks (rep_a = λ_α, rep_b = λ_β) instead of fresh random
  // (a,b); only its output randomness r is freshly COT'd. The B-1 sacrifice layers
  // are fresh, exactly as in compute_halfgate. So per gate we mint (3B-2)·num_ands
  // COTs (vs 3B·num_ands generic) and the Beaver x/y reconciliation is gone — the
  // representative is already on the real masks. out_sigma[ai] is the authenticated
  // share of σ = λ_α∧λ_β (bit0(mac)=σ, bit0(key)=0), drop-in for the garbler /
  // evaluator. λ_γ stays a fresh independent wire mask (kept by the caller), so the
  // construction is constant-round.
  void compute_inplace(const AShareBundleVec &rep_a, const AShareBundleVec &rep_b,
                       int num_ands, AShareBundleVec &out_sigma) {
    out_sigma.clear();
    if (num_ands == 0) return;   // AND-free chunk (e.g. an output-only checkpoint)
    const int B = get_bucket_size(num_ands);
    const int L = num_ands;
    const block pair_seed = makeBlock((uint64_t)std::min(party, 3 - party),
                                      (uint64_t)std::max(party, 3 - party));
    MITCCRH<8> gmitc, emitc;
    gmitc.setS(pair_seed);
    emitc.setS(pair_seed);
    AG2PC_TP_BEGIN();
#ifdef AG2PC_PROFILE
    g_tp_cot_ns = g_tp_hg_ns = 0;
    g_tp_sopen_ns = g_tp_feq_ns = g_tp_bkt_ns = 0;
#endif
    // layer 0 (acc): region a = λ_α, b = λ_β (copied wire masks, no COT); region r
    // = fresh COT (the representative's only minted share).
    BlockVec acc_mac((size_t)3 * L), acc_key((size_t)3 * L);
    for (int i = 0; i < L; ++i) {
      acc_mac[i]     = rep_a[i].mac;  acc_key[i]     = rep_a[i].key;
      acc_mac[L + i] = rep_b[i].mac;  acc_key[L + i] = rep_b[i].key;
    }
    gen_cot_shares(acc_mac.data() + 2 * L, acc_key.data() + 2 * L, L);   // region r
    leaky_and_halfgate(acc_mac.data(), acc_key.data(), L, gmitc, emitc);
    AG2PC_TP("in-place layer 0 (rep + r + leaky)");
    layered_bucket_into_acc(acc_mac.data(), acc_key.data(), B, L, gmitc, emitc);
    AG2PC_TP("sacrifice layers + bucket");
    // The bucketing combines the a-inputs, so acc now holds a valid triple
    // (X, Y, Z=X∧Y) with X = λ_α ⊕ Σ(sacrifice a) and Y = λ_β (the b-region is
    // kept, not combined). Reconcile (X,Y) back to (λ_α,λ_β) with the Beaver
    // opening xb = λ_α⊕X, yb = λ_β⊕Y, then σ = Z ⊕ xb·Y ⊕ yb·X (+ the xb·yb
    // λ_{αβ}⊕=1 correction) — the proven generic σ derivation. With the in-place
    // representative yb is identically 0 (Y already = λ_β), so this opens
    // num_ands bits on the a-side; the b-side reveal is the constant 0.
    std::vector<unsigned char> xb_me(L), yb_me(L), xb_pe(L), yb_pe(L);
    for (int i = 0; i < L; ++i) {
      xb_me[i] = (unsigned char)(LSB(rep_a[i].mac) ^ LSB(acc_mac[i]));
      yb_me[i] = (unsigned char)(LSB(rep_b[i].mac) ^ LSB(acc_mac[L + i]));
    }
    {
      vector<future<void>> res;
      res.push_back(pool->enqueue([&, this]() {
        send_io->send_bool((const bool *)xb_me.data(), L);
        send_io->send_bool((const bool *)yb_me.data(), L);
        send_io->flush();
      }));
      res.push_back(pool->enqueue([&, this]() {
        recv_io->recv_bool((bool *)xb_pe.data(), L);
        recv_io->recv_bool((bool *)yb_pe.data(), L);
      }));
      joinNclean(res);
    }
    out_sigma.resize(L);
    {
      block dxor = Delta ^ bit0_mask;
      for (int i = 0; i < L; ++i) {
        unsigned char xb = xb_me[i] ^ xb_pe[i];
        unsigned char yb = yb_me[i] ^ yb_pe[i];
        AShareBundle &sb = out_sigma[i];
        sb.mac = acc_mac[2 * L + i] ^ (select_mask[xb] & acc_mac[L + i])
                                    ^ (select_mask[yb] & acc_mac[i]);
        sb.key = acc_key[2 * L + i] ^ (select_mask[xb] & acc_key[L + i])
                                    ^ (select_mask[yb] & acc_key[i]);
        block both = select_mask[xb & yb];
        if (party != 1) sb.key = sb.key ^ (both & dxor);
        else            sb.mac = sb.mac ^ (both & bit0_mask);
      }
    }
    AG2PC_TP("a-side reconcile (sigma)");
#ifdef AG2PC_PROFILE
    if (party == 1) {
      auto ms = [](uint64_t ns) { return ns / 1e6; };
      printf("[ag2pc-tp]   -- inplace_triples breakdown (B=%d layers) --\n", B);
      printf("[ag2pc-tp]     COT extend       %8.1f ms  (%llu B)\n",
             ms(g_tp_cot_ns), (unsigned long long)g_ag2pc_cot_bytes);
      printf("[ag2pc-tp]     half-gate join   %8.1f ms\n", ms(g_tp_hg_ns));
      printf("[ag2pc-tp]     s-open + combine %8.1f ms\n", ms(g_tp_sopen_ns));
      printf("[ag2pc-tp]     F_eq             %8.1f ms\n", ms(g_tp_feq_ns));
      printf("[ag2pc-tp]     bucket layers    %8.1f ms\n", ms(g_tp_bkt_ns));
    }
#endif
  }

  // Mint `length` AND triples into MAC/KEY, slot-major a/b/c: share bit s of
  // triple k is bit0(MAC[s*length+k]), bit0(KEY)=0. If out_aos is non-null the
  // triples are also written as AoS TripleBundles (the layout draw() serves).
  void compute(block *MAC, block *KEY, int length,
               TripleBundle *out_aos = nullptr) {
    compute_halfgate(MAC, KEY, length, out_aos);
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
