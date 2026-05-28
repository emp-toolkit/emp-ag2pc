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

// Leaky-AND (eprint 2018/578, Fig. 5) followed by Π_aAND bucketing: per-candidate
// half-gate garbled-AND with an F_eq consistency check, then circular-shift
// bucketing to remove leakage. The leaky-AND is batched over L candidates; see
// leaky_and_halfgate.
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
// Triple API: compute_inplace is the sole triple primitive (function-dependent,
// KRRW §5.2 — see its comment). aShares come from draw(); both route through
// gen_cot_shares, which draws from a COT session held open for the object's
// lifetime (begin in the ctor, end in the dtor — see init_abit_). No persistent
// triple pool: each call mints exactly what it needs, abit straight into the
// caller's buffers.
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

  // Close the COT sessions opened in init_abit_ (and reopened after the last
  // reveal by flush_cot_check). end() runs the final segment's deferred
  // subspace-VOLE check and must fire before abit1/abit2 destruct
  // (StreamingExtension aborts if torn down mid-session). abit1 (recv_io) and
  // abit2 (send_io) close on different channels and cross to the peer's opposite
  // role, so run them concurrently to avoid a cross-party end/end deadlock.
  ~TriplePool() {
    vector<future<void>> res;
    res.push_back(pool->enqueue([this]() { abit1->end(); io_abit1->flush(); }));
    res.push_back(pool->enqueue([this]() { abit2->end(); io_abit2->flush(); }));
    joinNclean(res);
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
    // Open the COT sessions: begin() does the base-OT bootstrap (first call) and
    // starts a session; gen_cot_shares then draws via next_n. The session stays
    // open across compute() calls and is closed (subspace-VOLE check) + reopened
    // at each reveal by flush_cot_check, so the round-end work amortizes over a
    // whole reveal segment instead of firing per draw, while still gating output.
    // begin() must run after set_delta (it consumes Δ) and concurrently on
    // abit1/abit2 (they bootstrap on different channels, crossing to the peer's
    // opposite role).
    vector<future<void>> res;
    res.push_back(pool->enqueue([this]() { abit1->begin(); io_abit1->flush(); }));
    res.push_back(pool->enqueue([this]() { abit2->begin(); io_abit2->flush(); }));
    joinNclean(res);
  }

  // Share generator: mint `count` random authenticated shares into the mac/key
  // spans by drawing from the open COT session (next_n refills the chunk buffer
  // as needed; the consistency check is deferred to the next reveal's
  // flush_cot_check, or teardown). bit0(mac)=x, mac = key ⊕ x·Δ. Pointer form so a leaky-AND
  // layer can fill a whole region triple (3·L) or just one region (the in-place
  // representative's fresh r). Shared by the leaky-AND layers and draw().
  void gen_cot_shares(block *mac, block *key, int count) {
#ifdef AG2PC_PROFILE
    int64_t _cot0 = io_count(send_io, recv_io);
    uint64_t _ct0 = tp_now_ns();
#endif
    vector<future<void>> res;
    res.push_back(pool->enqueue([this, key, count]() {
      abit1->next_n(key, count);
      io_abit1->flush();
    }));
    res.push_back(pool->enqueue([this, mac, count]() {
      abit2->next_n(mac, count);
      io_abit2->flush();
    }));
    joinNclean(res);
#ifdef AG2PC_PROFILE
    g_tp_cot_ns += tp_now_ns() - _ct0;
    g_ag2pc_cot_bytes += (uint64_t)(io_count(send_io, recv_io) - _cot0);
#endif
  }

  // Run the COT session's deferred consistency check now, then reopen a fresh
  // session. The caller (C2PC::decode) invokes this before every reveal so the
  // subspace-VOLE check — which validates every COT minted since the last
  // begin() — gates output release: a malicious peer's malformed COTs abort here,
  // before any secret is opened, rather than at teardown. end() carries the only
  // I/O (sacrificial chunk + check open), so cross abit1/abit2 concurrently as in
  // the ctor; the immediate begin() just resets the per-session counters (the
  // base-OT bootstrap already ran), so it is local and adds no round.
  void flush_cot_check() {
    vector<future<void>> res;
    res.push_back(pool->enqueue([this]() {
      abit1->end(); io_abit1->flush(); abit1->begin();
    }));
    res.push_back(pool->enqueue([this]() {
      abit2->end(); io_abit2->flush(); abit2->begin();
    }));
    joinNclean(res);
  }

  // AoS draw: n aShares as AShareBundle{mac,key} (the layout 2pc consumes for
  // wire / λ_γ masks). Each call mints fresh from the COT session, so prefer one
  // large draw. abit hands back two contiguous streams (mac, key); interleaving
  // them into the AoS bundle is the one unavoidable copy here.
  void draw(int n, AShareBundleVec &out_bundle) {
    BlockVec tmac(n), tkey(n);
    gen_cot_shares(tmac.data(), tkey.data(), n);
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

  // ===== Leaky-AND layer primitives (eprint 2018/578, Fig. 5 + P:aAND) =====
  // A "layer" is L candidate triples in SoA region-major order, stride L:
  // region a=[0,L), b=[L,2L), r/c=[2L,3L); the share bit of region g triple i is
  // LSB(mac[g*L+i]). Region 2 holds the output mask r before leaky_and_halfgate
  // and the leaky product c=a∧b after (the fold is in place). gen_cot_shares
  // fills a layer (or one region); the same leaky_and_halfgate / bucket_one_layer
  // serve both the generic and the in-place (function-dependent) paths.

  // Half-gate leaky-AND over the L candidates whose 3L authenticated shares are in
  // mac/key. The garbler ships G on send_io; the eval recovers S^me on recv_io and
  // writes it locally; an s-open folds d into region 2 (r -> c = a∧b) in place.
  // Rather than run the F_eq equality check here, the post-fold L-vector is fed
  // into the running hash `feq`: the caller hashes every bucket layer in and runs
  // one batched F_eq (feq_check) after all B layers, since any single inconsistent
  // layer changes the combined digest. The per-element share bit is just
  // LSB(mac[...]), read inline (cache-hot — mac is loaded for the hashes anyway),
  // so there is no separate tr array. gmitc/emitc persist across a bucket's layers
  // (one setS in the caller), so the per-gate tweak (gid) keeps advancing and never
  // repeats. No COT: the shares are given (COT and/or copied wire masks), which is
  // why this serves both representative and sacrifices.
  void leaky_and_halfgate(block *mac, block *key, int L,
                          MITCCRH<8> &gmitc, MITCCRH<8> &emitc, Hash &feq) {
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

    // Accumulate this layer's L-vector into the batched F_eq hash. The actual
    // commit-open equality (feq_check) runs once in the caller after every layer
    // is folded in — one round instead of one per layer.
    feq.put(Sout.data(), (size_t)L * sizeof(block));
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
                               int L, MITCCRH<8> &gmitc, MITCCRH<8> &emitc,
                               Hash &feq) {
    struct Lyr { BlockVec mac, key; };
    std::vector<Lyr> sac(B - 1);
    for (int k = 0; k < B - 1; ++k) {
      sac[k].mac.resize((size_t)3 * L);
      sac[k].key.resize((size_t)3 * L);
      gen_cot_shares(sac[k].mac.data(), sac[k].key.data(), 3 * L);
      leaky_and_halfgate(sac[k].mac.data(), sac[k].key.data(), L, gmitc, emitc, feq);
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

  // In-place (function-dependent) AND-share generation (KRRW §5.2 bucket-saving).
  // For each AND gate the bucket's representative (layer 0) is the leaky-AND of the
  // gate's OWN input wire masks (rep_a = λ_α, rep_b = λ_β) instead of fresh random
  // (a,b); only its output randomness r is freshly COT'd. The B-1 sacrifice layers
  // are fresh generic candidates. So per gate we mint (3B-2)·num_ands
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
    // One running F_eq hash over every layer's L-vector; checked once below.
    Hash feq;
    gen_cot_shares(acc_mac.data() + 2 * L, acc_key.data() + 2 * L, L);   // region r
    leaky_and_halfgate(acc_mac.data(), acc_key.data(), L, gmitc, emitc, feq);
    AG2PC_TP("in-place layer 0 (rep + r + leaky)");
    layered_bucket_into_acc(acc_mac.data(), acc_key.data(), B, L, gmitc, emitc, feq);
    AG2PC_TP("sacrifice layers + bucket");
    // Single batched F_eq for the whole bucket: any one inconsistent layer changes
    // the combined digest, so this one commit-open replaces the per-layer checks.
    {
#ifdef AG2PC_PROFILE
      uint64_t _fq = tp_now_ns();
#endif
      char Dme[Hash::DIGEST_SIZE]; feq.digest(Dme);
      feq_check(io, party, Dme, "LaAND F_eq: leaky-AND check failed");
#ifdef AG2PC_PROFILE
      g_tp_feq_ns += tp_now_ns() - _fq;
#endif
    }
    AG2PC_TP("F_eq (batched)");
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

};
#endif // TRIPLE_POOL_H__
