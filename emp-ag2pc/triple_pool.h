#ifndef TRIPLE_POOL_H__
#define TRIPLE_POOL_H__
#include "emp-ag2pc/auth_share_pool.h"
#include "emp-tool/io/net_io_channel.h"
#include "emp-tool/crypto/mitccrh.h"
#include "emp-tool/crypto/prp.h"
#include <thread>

using namespace emp;

#ifdef AG2PC_PROFILE
// Profiler: this party's send+recv bytes spent in the half-gate phi exchange.
inline uint64_t g_ag2pc_phi_bytes = 0;
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
  NetIO *send_io, *recv_io;   // my outgoing / incoming channel to the peer
  AuthSharePool abit;
  block Delta;

  // AoS-by-triple pool: pool_triples[t] holds the three AShareBundles (a/b/c)
  // of triple t; share bit s is bit0(.b[s].mac). draw() serves from here.
  TripleBundleVec pool_triples;
  size_t cursor = 0;
  // Floor on the refill batch so small draws still amortize the per-call
  // overhead. 3100 is the bucket_size=4 threshold, so the floor never forces a
  // worse bucket; large workloads refill at their own size (≥280K → B=3).
  size_t min_refill = 3100;

  TriplePool(NetIO *io1, NetIO *io2, ThreadPool *pool, int party)
      : pool(pool), party(party),
        send_io(party == 1 ? io1 : io2), recv_io(party == 1 ? io2 : io1),
        abit(io1, io2, pool, party), Delta(abit.Delta) {}

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
    // a/b/r authenticated bits for the LB leaky triples. abit over-mints a csp
    // tail and drops it, so reserve +csp to avoid a realloc.
    int abit_len = leaky_abit_len(LB);

    BlockVec tMAC, tKEY;
    // Half-gate scratch: tKEYphi[peer] is the sender-side output, tKEYphi[party]
    // the s/t accumulator, tMACphi the receiver-side output (one peer, one
    // buffer). s[party]/s[peer] are the two garbling-parity shares, s[0] = XOR.
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

    // Generate the a/b/r aShares via COT.
    abit.process_phase1(tMAC, tKEY, abit_len);
    // Share bits are bit0(MAC); pull them into tr for the bit-indexed code.
    {
      tr.resize(abit_len);
      for (int k = 0; k < abit_len; ++k)
        tr[k] = LSB(tMAC[k]);
    }

    vector<future<void>> res;

    // Half-gate leaky-AND (eprint 2018/578, Fig. 5). Consumes the a/b/r aShares in
    // tMAC/tKEY (+ share bits tr) and produces LB leaky AND triples in the
    // a/b/c layout the bucketing reads (r -> c). The CutChoose sibling has the
    // same contract + its own leaky_abit_len.
    auto produce_leaky_ands_halfgate = [&]() {
    // C^me = y^me·Δ_me ⊕ K[y^peer] ⊕ M[y^me] over the b-region; C^A ⊕ C^B =
    // y·(Δ_A⊕Δ_B) from the MAC relation. The half-gate hash hides C on the
    // wire, so phi = C directly (no extra mask).
    int width = (LB + pool->size() - 1) / pool->size();
    for (int wi = 0; wi < pool->size(); ++wi) {
      int st = wi * width, ed = std::min((wi + 1) * width, LB);
      res.push_back(pool->enqueue([this, st, ed, LB, &tKEY, &tMAC, &phi, &tr]() {
        for (int k = st; k < ed; ++k)
          phi[k] = (select_mask[tr[LB + k]] & Delta) ^ tKEY[LB + k] ^ tMAC[LB + k];
      }));
    }
    joinNclean(res);
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] C (phi)", party);
#endif

    // Half-gate φ-exchange via MITCCRH<8>: both sides key from the same public
    // pair_seed so their AES keys advance in lockstep; the sender hashes
    // (key, key⊕Δ) with hash<8,2>, the receiver hashes (mac) with hash<8,1>,
    // giving pad = H(x) = AES(x)⊕x. Streamed in hg_chunk blocks.
    int hg_chunk = 1 << 16;
#ifdef AG2PC_PROFILE
    int64_t _phi0 = io_count(send_io, recv_io);
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
          send_io->send_data(tmp.data(), (ed - st) * sizeof(block));
          send_io->flush();
        }
      }));
      res.push_back(pool->enqueue([this, &tMAC, &tMACphi, &tr, LB, peer, pair_seed, hg_chunk]() {
        MITCCRH<8> mitc;
        mitc.setS(pair_seed);
        block pad[8];
        BlockVec wire(std::min(hg_chunk, LB));
        for (int ci = 0; ci < (LB + hg_chunk - 1) / hg_chunk; ++ci) {
          int st = hg_chunk * ci, ed = std::min(hg_chunk * (ci + 1), LB);
          recv_io->recv_data(wire.data(), (ed - st) * sizeof(block));
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
#ifdef AG2PC_PROFILE
    g_ag2pc_phi_bytes += (uint64_t)(io_count(send_io, recv_io) - _phi0);
#endif
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] half-gate exchange", party);
#endif

    // Accumulate s^me into tKEYphi[party]: a·φ ⊕ (half-gate outputs for the
    // peer) ⊕ (r-region K ⊕ M) ⊕ r·Δ.
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

    // Open d^me = LSB1(s^me) to the peer (bit 1 carries the garbling parity
    // under the bit-0/bit-1 Δ convention); d = d^A ⊕ d^B.
    for (int k = 0; k < LB; ++k)
      s[party][k] = LSB1(tKEYphi[party][k]);
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

    // step 5 (F_eq): the leaky-AND consistency check. After the step-7 fold,
    // tKEYphi[party][k] = S^me_k ⊕ d_k·Δ_me = L^me_k (eprint 2018/578, Fig. 5). On honest
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
    Hash::hash_once(Dme, tKEYphi[party].data(), (size_t)LB * sizeof(block));
    if (party == 1) {                                 // A
      block r; PRG().random_block(&r, 1);
      char com[Hash::DIGEST_SIZE];
      { Hash h; h.put(Dme, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(com); }
      send_io->send_data(com, Hash::DIGEST_SIZE);     // 1. c = H(x‖r)
      send_io->flush();
      recv_io->recv_data(Dpeer, Hash::DIGEST_SIZE);   // 2. B sends y
      send_io->send_data(Dme, Hash::DIGEST_SIZE);     // 3. A opens x, r
      send_io->send_data(&r, sizeof(block));
      send_io->flush();
    } else {                                          // B
      char com[Hash::DIGEST_SIZE], chk[Hash::DIGEST_SIZE];
      block r;
      recv_io->recv_data(com, Hash::DIGEST_SIZE);     // 1.
      send_io->send_data(Dme, Hash::DIGEST_SIZE);     // 2. send y (before A opens)
      send_io->flush();
      recv_io->recv_data(Dpeer, Hash::DIGEST_SIZE);   // 3. recv x
      recv_io->recv_data(&r, sizeof(block));          //    and r
      { Hash h; h.put(Dpeer, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(chk); }
      if (memcmp(chk, com, Hash::DIGEST_SIZE) != 0)
        error("LaAND F_eq: commit-open mismatch");
    }
    if (memcmp(Dme, Dpeer, Hash::DIGEST_SIZE) != 0)
      error("LaAND F_eq: leaky-AND check failed");
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
    // Public coin: absorb the two channel digests in canonical (1->2, 2->1)
    // order so both parties derive the same S regardless of local send/recv role.
    block S = RO("AG2PC RO", zero_block)
                  .absorb((party == 1 ? send_io : recv_io)->get_digest())
                  .absorb((party == 1 ? recv_io : send_io)->get_digest())
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
#ifdef EMP_DEBUG_PHASE
    _phase("[triple] bucket d exchange", party);
#endif

#ifdef EMP_DEBUG_PHASE
    _phase("[triple] check2", party);

    BlockVec MAC_dbg(MAC, MAC + 3 * length);
    BlockVec KEY_dbg(KEY, KEY + 3 * length);
    check_MAC(send_io, recv_io, MAC_dbg, KEY_dbg, Delta, length * 3, party);
    check_correctness(send_io, recv_io, MAC_dbg, length, party);
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
