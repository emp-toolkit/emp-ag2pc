#ifndef C2PC_H__
#define C2PC_H__
#include "emp-ag2pc/auth_share_pool.h"
#include "emp-ag2pc/triple_pool.h"
#include "emp-tool/io/net_io_channel.h"
#include "emp-ag2pc/share_bundle.h"
#include "emp-ag2pc/secure_wires.h"
#include "emp-ag2pc/circuit_layout.h"
#include "emp-ag2pc/wire_graph.h"
#include <array>
#include <vector>
using namespace emp;

// Opt-in phase profiler: compile with -DWRK_PROFILE (or #define before include).
// At P1, each WRK_PHASE prints the wall time and this party's send+recv byte
// delta since the matching WRK_PHASE_BEGIN. Zero-cost when WRK_PROFILE is unset.
// Requires `io1`/`io2` (NetIO*) and `party` in scope — both are C2PC members.
#ifdef WRK_PROFILE
#include <chrono>
#include <cstdio>
#define WRK_PHASE_BEGIN()                                                      \
  auto _wrk_t = std::chrono::steady_clock::now();                              \
  int64_t _wrk_c = io_count(io1, io2)
#define WRK_PHASE(name)                                                        \
  do {                                                                         \
    auto _n = std::chrono::steady_clock::now();                                \
    int64_t _c = io_count(io1, io2);                                                  \
    if (party == 1)                                                            \
      printf("[wrk] %-22s %9.3f ms  %12lld B\n", (name),                       \
             std::chrono::duration<double, std::milli>(_n - _wrk_t).count(),   \
             (long long)(_c - _wrk_c));                                        \
    _wrk_t = _n;                                                               \
    _wrk_c = _c;                                                               \
  } while (0)
#else
#define WRK_PHASE_BEGIN() ((void)0)
#define WRK_PHASE(name) ((void)0)
#endif

// Multi-party authenticated garbling protocol Π_MPC of agc.tex
// (Figures P:MPC-1, P:MPC-2, P:MPC-3). The half-gate construction:
// every Pi (i ≥ 2) sends 2 ciphertexts G_{γ,0/1}^i and 3 ciphertexts
// per cross peer S_{γ,0/1/2}^{i,j}; P2 additionally sends b_γ; P1
// recovers Λ_γ = b_γ ⊕ LSB1(m_{γ,Λ_γ}^2). The bit-1 Δ convention
// is set in auth_share_pool.h: bit1(Δ_j) = 1 for j ≠ 1 and
// bit1(Δ_1) = nP mod 2. Bit 0 is reserved for share-value encoding.
//
// API:
//   process_input(bits, n, owner) → SecureWires  // steps 3 + 8 + 9
//   compute(WireGraph, inputs)    → SecureWires  // steps 4-13, fpre on demand
//   decode(wires, recipient)      → vector<bool> // step 14
//
// Output wires of compute() carry full SecureWire state. process_input() and
// compute() draw aShares/triples from the amortized pools owned by
// AuthSharePool / TriplePool; preprocess(num_triples) pre-mints into the pool.
// The frontend (a recording backend, see wrk_backend.h) drives this from native
// Bit/Integer code; circuits are consumed as WireGraph, not BristolFormat.

template <int nP>
class C2PC {
public:
  // Long-lived setup: COT mesh + Δ + TriplePool (which owns the inner
  // AuthSharePool). Constructed once per session and reused across all
  // process_input / compute / decode calls. Both pools amortize their
  // refill costs across however many draw() calls land between refills.
  TriplePool<nP> *fpre = nullptr;
  NetIO *io1, *io2;
  ThreadPool *pool;
  int party;
  block Delta;
  PRG prg;

  C2PC(NetIO *io1_, NetIO *io2_, ThreadPool *pool_, int party_)
      : io1(io1_), io2(io2_), pool(pool_), party(party_) {
    fpre = new TriplePool<nP>(io1_, io2_, pool_, party_);
    Delta = fpre->Delta;
  }
  ~C2PC() { delete fpre; }

  // Eagerly mint num_triples triples into TriplePool's pool so subsequent
  // compute() calls draw from cache. AuthSharePool no longer has a pool
  // (Stage 3 refactor) — its aShares are minted lazily inside each
  // process_input / compute call. num_abits is accepted for backward-compat
  // signature but unused.
  void preprocess(size_t num_triples, size_t /*num_abits*/) {
    fpre->preprocess(num_triples);
  }

  // ====== New API ======

  // Steps 3 + 8 + 9 of agc.tex on n new input wires owned by `owner`.
  // At `owner`, `inputs` must point to n cleartext bits; non-owners may
  // pass nullptr. Internally:
  //   - abit.compute mints n authenticated λ-shares
  //   - Pi (i ≥ 2) samples m_{w, 0}^i at random
  //   - all parties open Λ_w = ⊕_p λ_w^p ⊕ x_w  (owner's x)
  //   - Pi (i ≥ 2) ships m_{w, Λ_w}^i = label0 ⊕ Λ·Δ to P1
  // Can be called multiple times (e.g. one call per owner, or one call
  // per logical batch); returned bundles compose via concat().
  SecureWires<nP> process_input(const bool *inputs, int n, int owner);

  // Steps 4-13 of agc.tex on a WireGraph. Input bundles must already be
  // process_input'd and supplied in WireGraph.inputs (per-owner) order; they
  // occupy wires [0, num_in). Mints AND triples + AND-output share pool fresh
  // inside this call (preprocessing on-demand). Aborts via error() on
  // cheating-detection failure. Outputs are extracted by explicit id
  // (g.output_ids), in that order; output wires carry full state.
  SecureWires<nP> compute(const WireGraph &g,
                          const std::vector<SecureWires<nP>> &inputs);

  // Step 14 (output decode): all Pi ≠ recipient send λ_w^p to recipient;
  // recipient computes y_w = Λ_w ⊕ λ_w. Returns the n cleartext bits at
  // `recipient`; empty vector at non-recipients.
  std::vector<bool> decode(const SecureWires<nP> &wires, int recipient);

  // Concatenate two SecureWires bundles wire-by-wire.
  static SecureWires<nP> concat(const SecureWires<nP> &a,
                                const SecureWires<nP> &b);

private:
  // Per-call scratch shared across the protocol-step methods below. The heavy
  // arrays size to num_slots (slot-reuse, see circuit_layout.h), not num_wire;
  // WIRE / LABEL / EVAL hide the wire-id -> slot indirection.
  struct ComputeCtx {
    const CircuitView *cf = nullptr;
    int num_in = 0, num_ands = 0, num_slots = 0;
    std::vector<int> phys;                  // logical wire id -> physical slot
    std::vector<unsigned char> mask_input;  // Λ_w, indexed by wire id
    AShareBundleVec<nP> wire_slot;          // share bundles, indexed by slot
    BlockVec label_slot;                    // m_{w,0} at Pi (i>=2), by slot
    BlockVec eval_slot[nP + 1];             // m_{w,Λ} at P1, by slot
    TripleBundleVec<nP> ANDS_bundle;        // AND triples, by and_index
    AShareBundleVec<nP> sigma;              // Beaver-corrected AND shares
    MITCCRH<nP - 1> mitc;                   // half-gate hash (garble / evaluate)
    std::vector<std::array<std::array<block, 2>, nP + 1>> G;                     // P1: G_{γ,*}
    std::vector<std::array<std::array<std::array<block, 3>, nP + 1>, nP + 1>> S; // P1: S_{γ,*}
    std::vector<unsigned char> b_buf_at_P1; // P1: b_γ from P2
    block hp_seed;                          // step-11 hash seed (used in 12, 13)
    AShareBundle<nP> &WIRE(int w) { return wire_slot[phys[w]]; }
    block &LABEL(int w) { return label_slot[phys[w]]; }
    block &EVAL(int j, int w) { return eval_slot[j][phys[w]]; }
  };

  // agc.tex steps 4-13, one method per phase over a shared ComputeCtx; the
  // body of each is the verbatim crypto of that step. compute_impl (below) is
  // the orchestrator that runs them in protocol order.
  void load_inputs(ComputeCtx &ctx, const SecureWires<nP> *const *inputs,
                   int n_inputs);
  void draw_and_seed(ComputeCtx &ctx);          // step 4: triples + AND-out seed
  void beaver_pass(ComputeCtx &ctx);            // step 5
  void garble_and_ship(ComputeCtx &ctx);        // steps 6-7, sender Pi (i>=2)
  void receive_garbling(ComputeCtx &ctx);       // steps 6-7, P1 receive
  void p1_evaluate(ComputeCtx &ctx);            // step 10, P1
  void check_label_hash(ComputeCtx &ctx);       // steps 11-12
  void check_tgamma(ComputeCtx &ctx);           // step 13
  SecureWires<nP> gather_outputs(ComputeCtx &ctx,
                                 const std::vector<int> &output_ids);

  // Half-gate hash tweak: unique across (gate_idx, sender, dest) within a call.
  static block tweak_block(int gate_idx, int sender, int dest) {
    return makeBlock((uint64_t)gate_idx, (uint64_t)(sender * (nP + 1) + dest));
  }

  // Free-XOR share propagation: recompute a fabric wire's share bundle as the
  // componentwise XOR of its (live) inputs. bit0 (the share-bit) rides along.
  static void xor_share(AShareBundle<nP> &out, const AShareBundle<nP> &a,
                        const AShareBundle<nP> &b) {
    for (int t = 0; t < AShareBundle<nP>::N; ++t) out.km[t] = a.km[t] ^ b.km[t];
  }

  // Orchestrator: builds ComputeCtx, then runs the step methods in order.
  SecureWires<nP> compute_impl(const CircuitView *cf,
                               const std::vector<int> &output_ids,
                               const SecureWires<nP> *const *inputs,
                               int n_inputs);
};

// ==========================================================================
// Implementation
// ==========================================================================

template <int nP>
SecureWires<nP> C2PC<nP>::concat(const SecureWires<nP> &a,
                                       const SecureWires<nP> &b) {
  SecureWires<nP> r = a;
  r.append(b);
  return r;
}

template <int nP>
SecureWires<nP> C2PC<nP>::process_input(const bool *inputs, int n, int owner) {
  WRK_PHASE_BEGIN();
  SecureWires<nP> sw;
  sw.Lambda.resize(n);
  if (party != 1)
    sw.label0.resize(n);
  else
    { const int j = 2; sw.eval_label[j].resize(n); }
  // Step 3 (Π_aShare): n authenticated λ-shares — drawn from pool. The pool
  // stores AoS-by-wire, so draw is a single memcpy into sw.wire_bundle.
  // Each share-bit λ_w^i is implicit in bit0(sw.wire_bundle[w].mac(0)).
  fpre->abit.draw(n, sw.wire_bundle);

  // Step 3 (cont.): Pi (i ≥ 2) samples m_{w, 0}^i for each input wire.
  if (party != 1)
    prg.random_block(sw.label0.data(), n);

  // Step 8: open Λ_w = ⊕_p λ_w^p ⊕ x_w. Owner XORs its bit into the
  // contribution; non-owners contribute just their share. Read λ_w^i from
  // bit0 of any peer slot's MAC.
  std::vector<unsigned char> v(n);
  for (int i = 0; i < n; ++i)
    v[i] = (unsigned char)LSB(sw.wire_bundle[i].mac(0));
  if (party == owner)
    for (int i = 0; i < n; ++i) v[i] ^= (unsigned char)inputs[i];

  if (party != 1) {
    io_send(io1, io2, party, 1, v.data(), n);
    io_flush(io1, io2, party, 1);
    io_recv(io1, io2, party, 1, sw.Lambda.data(), n);
  } else {
    std::vector<std::vector<unsigned char>> tmp(nP + 1);
    { const int p2 = 2; tmp[p2].resize(n); }    std::vector<future<void>> res;
    { const int p2 = 2;
      int party2 = p2;
      res.push_back(pool->enqueue([this, &tmp, n, party2]() {
        io_recv(io1, io2, party, party2, tmp[party2].data(), n);
      }));
    }
    joinNclean(res);
    for (int i = 0; i < n; ++i) {
      sw.Lambda[i] = v[i];
      { const int p2 = 2; sw.Lambda[i] = sw.Lambda[i] ^ tmp[p2][i]; }
    }
    { const int p2 = 2;
      int party2 = p2;
      res.push_back(pool->enqueue([this, &sw, n, party2]() {
        io_send(io1, io2, party, party2, sw.Lambda.data(), n);
        io_flush(io1, io2, party, party2);
      }));
    }
    joinNclean(res);
  }

  // Step 9: Pi (i ≥ 2) ships m_{w, Λ_w}^i = label0[w] ⊕ Λ_w · Δ to P1.
  if (party != 1) {
    BlockVec tmp(n);
    for (int i = 0; i < n; ++i)
      tmp[i] = sw.Lambda[i] ? (sw.label0[i] ^ Delta) : sw.label0[i];
    io_send(io1, io2, party, 1, tmp.data(), n * sizeof(block));
    io_flush(io1, io2, party, 1);
  } else {
    std::vector<future<void>> res;
    { const int p2 = 2;
      int party2 = p2;
      res.push_back(pool->enqueue([this, &sw, n, party2]() {
        io_recv(io1, io2, party, party2, sw.eval_label[party2].data(),
                      n * sizeof(block));
      }));
    }
    joinNclean(res);
  }
  WRK_PHASE(owner == 1 ? "process_input[owner1]" : "process_input[ownerN]");
  return sw;
}

// WireGraph marshals directly: gate list as-is, outputs taken by explicit id.
template <int nP>
SecureWires<nP> C2PC<nP>::compute(const WireGraph &g,
                                        const std::vector<SecureWires<nP>> &inputs) {
  std::vector<const SecureWires<nP> *> ptrs;
  ptrs.reserve(inputs.size());
  for (const auto &s : inputs) ptrs.push_back(&s);
  CircuitView cv{g.num_wire, g.num_gate(), g.num_ands, g.gates.data()};
  if (!g.last_use.empty()) cv.last_use = g.last_use.data();  // recorder-supplied
  return compute_impl(&cv, g.output_ids, ptrs.data(), (int)ptrs.size());
}

template <int nP>
SecureWires<nP> C2PC<nP>::compute_impl(const CircuitView *cf,
                                             const std::vector<int> &output_ids,
                                             const SecureWires<nP> *const *inputs,
                                             int n_inputs) {
  ComputeCtx ctx;
  ctx.cf = cf;
  ctx.num_ands = cf->num_ands;
  for (int b = 0; b < n_inputs; ++b) ctx.num_in += (int)inputs[b]->size();

  // Slot-reuse layout (circuit_layout.h): inputs + AND-outputs + circuit-outputs
  // persist; XOR/NOT "fabric" wires share a recycled pool bounded by live width.
  // The heavy per-wire arrays size to num_slots, not num_wire.
  WireLayout layout = compute_wire_layout(*cf, ctx.num_in, output_ids);
  ctx.phys = std::move(layout.phys);
  ctx.num_slots = layout.num_slots;
  ctx.mask_input.assign(cf->num_wire, 0);
  ctx.wire_slot.resize(ctx.num_slots);
  if (party != 1) ctx.label_slot.resize(ctx.num_slots);
  else { const int j = 2; ctx.eval_slot[j].resize(ctx.num_slots); }  ctx.mitc.setS(zero_block);

  WRK_PHASE_BEGIN();
  load_inputs(ctx, inputs, n_inputs);     WRK_PHASE("load_inputs");
  draw_and_seed(ctx);                      WRK_PHASE("draw_and_seed[step4]");
  beaver_pass(ctx);                        WRK_PHASE("beaver_pass[step5]");
  if (party != 1) garble_and_ship(ctx);    // steps 6-7 (sender Pi, i>=2)
  else            receive_garbling(ctx);   WRK_PHASE("garble/recv[step6-7]");
  if (party == 1) p1_evaluate(ctx);        WRK_PHASE("p1_evaluate[step10]");
  check_label_hash(ctx);                   WRK_PHASE("check_label[step12]");
  check_tgamma(ctx);                       WRK_PHASE("check_tgamma[step13]");
  SecureWires<nP> r = gather_outputs(ctx, output_ids);  WRK_PHASE("gather_outputs");
  return r;
}

// Copy each input SecureWires bundle into wire indices [0, num_in) in order;
// inputs occupy slots [0, num_in). SecureWires is AoS, so this is a pure memcpy.
template <int nP>
void C2PC<nP>::load_inputs(ComputeCtx &ctx, const SecureWires<nP> *const *inputs,
                           int n_inputs) {
  size_t off = 0;
  for (int b = 0; b < n_inputs; ++b) {
    const SecureWires<nP> &in = *inputs[b];
    size_t n = in.size();
    memcpy(ctx.mask_input.data() + off, in.Lambda.data(), n);
    memcpy(&ctx.wire_slot[off], in.wire_bundle.data(),
           n * sizeof(AShareBundle<nP>));
    if (party != 1) {
      memcpy(ctx.label_slot.data() + off, in.label0.data(), n * sizeof(block));
    } else {
      { const int j = 2;
        memcpy(ctx.eval_slot[j].data() + off, in.eval_label[j].data(),
               n * sizeof(block)); }
    }
    off += n;
  }
}

// Step 4: draw AND triples + seed each AND-output wire's share state from the
// preprocessing pool. ANDS_bundle[ai].b[s] holds triple ai's slot-s share
// bundle; the slot-s share-bit is implicit in bit0(.mac(0)).
template <int nP>
void C2PC<nP>::draw_and_seed(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle<nP> & { return ctx.WIRE(w); };
#ifdef WRK_PROFILE
  int64_t _all0 = io_count(io1, io2);
  uint64_t _cot0 = g_wrk_cot_bytes, _phi0 = g_wrk_phi_bytes;
#endif
  fpre->draw(num_ands, ctx.ANDS_bundle);

  // Seed AND-output share state from the per-aShare preprocessing pool.
  // Scoped: preprocess_bundle dies at the closing brace, freeing num_ands
  // aShares before the heavy garble allocations.
  {
    AShareBundleVec<nP> preprocess_bundle;
    fpre->abit.draw(num_ands, preprocess_bundle);

    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (g.is_and()) WIRE(g.out) = preprocess_bundle[g.and_index()];
    }
  }
#ifdef WRK_PROFILE
  if (party == 1) {
    uint64_t all = (uint64_t)(io_count(io1, io2) - _all0), cot = g_wrk_cot_bytes - _cot0,
             phi = g_wrk_phi_bytes - _phi0;
    printf("[wrk]   draw_and_seed split: COT %llu B, phi-exchange %llu B, "
           "other-non-COT %lld B\n",
           (unsigned long long)cot, (unsigned long long)phi,
           (long long)(all - cot - phi));
  }
#endif
}

// Step 5: fused free-XOR/NOT share propagation + Beaver derivation of the AND
// gates' corrected shares (sigma). Pass A recomputes the share bundle for every
// XOR/NOT output (fabric wires land in recycled slots, freed at last read) and,
// on each AND, reads its (now-live) input shares to form the Beaver masks x/y.
// Fusing share-prop with Beaver is required: fabric slots are recycled within
// the sweep, so a later standalone Beaver pass would read stale slots. The bit-0
// share encoding XORs / copies with the high bits, so λ_w propagates implicitly.
// sigma[ai] is AND-gate ai's corrected share-bundle: the slot-s share of triple
// ai lives in bit0(ANDS_bundle[ai].b[s].mac(0)), and the Beaver XOR pattern gives
// bit0(sigma) = ANDS[2] ⊕ (xb?ANDS[1]) ⊕ (yb?ANDS[0]). The xb && yb correction is
// "λ_{αβ} ⊕= 1" (P1-only): at P1 flip bit0 of every sb.mac(s); at non-P1 update
// sb.key(peer_slot(*,1)) by (Δ ⊕ e_0) so bit0(KEY)=0 stays pinned.
template <int nP>
void C2PC<nP>::beaver_pass(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle<nP> & { return ctx.WIRE(w); };
  auto &ANDS_bundle = ctx.ANDS_bundle;
  auto &sigma = ctx.sigma;
  sigma.resize(num_ands);
  std::vector<unsigned char> x[nP + 1], y[nP + 1];
  for (int j = 1; j <= nP; ++j) {
    x[j].resize(num_ands);
    y[j].resize(num_ands);
  }
  {
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (g.is_and()) {
        int ai = g.and_index();
        unsigned char v_in0 = (unsigned char)LSB(WIRE(g.in0).mac(0));
        unsigned char v_in1 = (unsigned char)LSB(WIRE(g.in1).mac(0));
        unsigned char a0 = (unsigned char)LSB(ANDS_bundle[ai].b[0].mac(0));
        unsigned char a1 = (unsigned char)LSB(ANDS_bundle[ai].b[1].mac(0));
        x[party][ai] = v_in0 ^ a0;
        y[party][ai] = v_in1 ^ a1;
      } else if (g.is_not()) {
        WIRE(g.out) = WIRE(g.in0);
      } else {  // XOR
        xor_share(WIRE(g.out), WIRE(g.in0), WIRE(g.in1));
      }
    }
  }
  std::vector<future<void>> res;
  { const int party2 = 3 - party;
    res.push_back(pool->enqueue([this, &x, &y, num_ands, party2]() {
      io_send(io1, io2, party, party2, x[party].data(), num_ands);
      io_send(io1, io2, party, party2, y[party].data(), num_ands);
      io_flush(io1, io2, party, party2);
    }));
    res.push_back(pool->enqueue([this, &x, &y, num_ands, party2]() {
      io_recv(io1, io2, party, party2, x[party2].data(), num_ands);
      io_recv(io1, io2, party, party2, y[party2].data(), num_ands);
    }));
  }
  joinNclean(res);
  { const int i = 2;
    for (int j = 0; j < num_ands; ++j) {
      x[1][j] = x[1][j] ^ x[i][j];
      y[1][j] = y[1][j] ^ y[i][j];
    } }
  {
    block dxor = Delta ^ bit0_mask;
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (!g.is_and()) continue;
      int ai = g.and_index();
      AShareBundle<nP> &sb = sigma[ai];
      const TripleBundle<nP> &tb = ANDS_bundle[ai];
      bool xb = x[1][ai], yb = y[1][ai];
      for (int t = 0; t < AShareBundle<nP>::N; ++t) {
        block v = tb.b[2].km[t];
        if (xb) v = v ^ tb.b[1].km[t];
        if (yb) v = v ^ tb.b[0].km[t];
        sb.km[t] = v;
      }
      if (xb && yb) {
        if (party != 1) {
          sb.key(peer_slot(party, 1)) = sb.key(peer_slot(party, 1)) ^ dxor;
        } else {
          for (int s = 0; s < AShareBundle<nP>::K; ++s)
            sb.mac(s) = sb.mac(s) ^ bit0_mask;
        }
      }
    }
  }
}

// Steps 6-7: sender Pi (i >= 2) garbles each AND gate and ships to P1. Per gate γ:
//   G_buf[2γ..)     = (G_{γ,0}^i, G_{γ,1}^i)
//   S_buf[j][3γ..)  = (S_{γ,0}^{i,j}, S_{γ,1}^{i,j}, S_{γ,2}^{i,j}), j∈[2,nP], j≠i
//   b_buf[γ]        = LSB1(m_{γ,0}^2)  (party 2 only)
// Half-gate hash uses MITCCRH (eprint/2019/1168): H_τ(x) = σ(x) ⊕
// AES_{start_point ⊕ τ}(σ(x)); tweak_block(γ, sender, dest) is unique across
// (γ, sender, dest). BatchSize = nP-1: each renew_ks schedules one
// (γ, sender)→(d∈[2,nP]) batch — d == sender is the self tweak feeding G_{γ,*};
// d ≠ sender feeds S_{γ,*}^{sender,d}.
template <int nP>
void C2PC<nP>::garble_and_ship(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle<nP> & { return ctx.WIRE(w); };
  auto LABEL = [&](int w) -> block & { return ctx.LABEL(w); };
  auto &sigma = ctx.sigma;
  auto &mitc = ctx.mitc;
  {
    BlockVec G_buf(2 * num_ands);
    std::vector<BlockVec> S_buf(nP + 1);
    if (2 != party) { const int j = 2; S_buf[j].resize(3 * num_ands); }
    std::vector<unsigned char> b_buf;
    if (party == 2) b_buf.resize(num_ands);

    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (!g.is_and()) {
        if (g.is_not()) {
          LABEL(out) = LABEL(in0) ^ Delta;
          WIRE(out) = WIRE(in0);
        } else {  // XOR
          LABEL(out) = LABEL(in0) ^ LABEL(in1);
          // Recompute fabric share into its (recycled) slot for downstream ANDs.
          xor_share(WIRE(out), WIRE(in0), WIRE(in1));
        }
        continue;
      }
      int ai = g.and_index();
      block ml_a0 = LABEL(in0), ml_a1 = ml_a0 ^ Delta;
      block ml_b0 = LABEL(in1), ml_b1 = ml_b0 ^ Delta;

      // Build (nP-1) tweaks for d ∈ [2, nP] and 4 blocks per tweak; one
      // batched renew_ks + hash_cir consumes the whole gate's sender-side
      // half-gate hashes.
      block tweaks[nP - 1];
      block buf[(nP - 1) * 4];
      { const int d = 2;
        int k = d - 2;
        tweaks[k] = tweak_block(ai, party, d);
        buf[4 * k]     = ml_a0;
        buf[4 * k + 1] = ml_a1;
        buf[4 * k + 2] = ml_b0;
        buf[4 * k + 3] = ml_b1;
      }
      mitc.renew_ks(tweaks);
      mitc.template hash_cir<nP - 1, 4>(buf);

      const AShareBundle<nP> &wb_in0 = WIRE(in0);
      const AShareBundle<nP> &wb_in1 = WIRE(in1);
      const AShareBundle<nP> &wb_out = WIRE(out);
      const AShareBundle<nP> &sb     = sigma[ai];

      block H_a0_self = zero_block, H_a1_self = zero_block;
      block H_b0_self = zero_block, H_b1_self = zero_block;
      { const int d = 2;
        int k = d - 2;
        if (d == party) {
          H_a0_self = buf[4 * k];     H_a1_self = buf[4 * k + 1];
          H_b0_self = buf[4 * k + 2]; H_b1_self = buf[4 * k + 3];
        } else {
          int ds = peer_slot(party, d);
          S_buf[d][3 * ai]     = buf[4 * k]     ^ buf[4 * k + 1] ^ wb_in1.mac(ds);
          S_buf[d][3 * ai + 1] = buf[4 * k + 2] ^ buf[4 * k + 3] ^ wb_in0.mac(ds);
          S_buf[d][3 * ai + 2] = buf[4 * k]     ^ buf[4 * k + 2]
                                 ^ wb_out.mac(ds) ^ sb.mac(ds);
        }
      }

      block sumK_a = zero_block, sumK_b = zero_block;
      block sumK_ab = zero_block, sumK_g = zero_block;
      for (int s = 0; s < AShareBundle<nP>::K; ++s) {
        sumK_a  = sumK_a  ^ wb_in0.key(s);
        sumK_b  = sumK_b  ^ wb_in1.key(s);
        sumK_ab = sumK_ab ^ sb.key(s);
        sumK_g  = sumK_g  ^ wb_out.key(s);
      }
      // λ_w^i is bit0(mac(0)). Branchless: select_mask[bit] gives 0 or
      // all-ones, so (Δ & select_mask[bit]) collapses to bit ? Δ : 0.
      block la_dot  = select_mask[LSB(wb_in0.mac(0))] & Delta;
      block lb_dot  = select_mask[LSB(wb_in1.mac(0))] & Delta;
      block lab_dot = select_mask[LSB(sb.mac(0))]     & Delta;
      block lg_dot  = select_mask[LSB(wb_out.mac(0))] & Delta;

      block G0 = H_a0_self ^ H_a1_self ^ sumK_b ^ lb_dot;
      block G1 = H_b0_self ^ H_b1_self ^ ml_a0 ^ sumK_a ^ la_dot;
      block ml_g0 = H_a0_self ^ H_b0_self ^ sumK_ab ^ lab_dot ^ sumK_g ^ lg_dot;

      LABEL(out) = ml_g0;
      G_buf[2 * ai]     = G0;
      G_buf[2 * ai + 1] = G1;
      if (party == 2) b_buf[ai] = (unsigned char)(LSB1(ml_g0));
    }
    io_send(io1, io2, party, 1, G_buf.data(), 2 * num_ands * sizeof(block));
    // No cross-garbler S terms with a single garbler (party 2): this loop is
    // empty for 2pc.
    if (party == 2) io_send(io1, io2, party, 1, b_buf.data(), num_ands);
    io_flush(io1, io2, party, 1);
  }
}

// Steps 6-7: P1 receives G, S, b from each Pi (i >= 2) into ctx (consumed by
// p1_evaluate). Streams are independent so run them in parallel.
template <int nP>
void C2PC<nP>::receive_garbling(ComputeCtx &ctx) {
  const int num_ands = ctx.num_ands;
  auto &G = ctx.G;
  auto &S = ctx.S;
  auto &b_buf_at_P1 = ctx.b_buf_at_P1;
  G.resize(num_ands);
  S.resize(num_ands);
  b_buf_at_P1.resize(num_ands);
  std::vector<future<void>> rres;
    { const int p2 = 2;
      rres.push_back(
          pool->enqueue([this, &G, &S, &b_buf_at_P1, num_ands, p2]() {
            BlockVec G_buf(2 * num_ands);
            io_recv(io1, io2, party, p2, G_buf.data(), 2 * num_ands * sizeof(block));
            for (int g = 0; g < num_ands; ++g) {
              G[g][p2][0] = G_buf[2 * g];
              G[g][p2][1] = G_buf[2 * g + 1];
            }
            if (2 != p2) { const int j = 2;
              BlockVec S_buf(3 * num_ands);
              io_recv(io1, io2, party, p2, S_buf.data(), 3 * num_ands * sizeof(block));
              for (int g = 0; g < num_ands; ++g) {
                S[g][p2][j][0] = S_buf[3 * g];
                S[g][p2][j][1] = S_buf[3 * g + 1];
                S[g][p2][j][2] = S_buf[3 * g + 2];
              }
            }
            if (p2 == 2) io_recv(io1, io2, party, p2, b_buf_at_P1.data(), num_ands);
          }));
    }
    joinNclean(rres);
  }

// Step 10: P1 evaluates each gate topologically, recovering eval-labels and the
// public mask. XOR/NOT propagate locally; AND combines the received G/S
// ciphertexts with the half-gate hashes. Called only at P1.
template <int nP>
void C2PC<nP>::p1_evaluate(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  auto WIRE = [&](int w) -> AShareBundle<nP> & { return ctx.WIRE(w); };
  auto EVAL = [&](int j, int w) -> block & { return ctx.EVAL(j, w); };
  auto &mask_input = ctx.mask_input;
  auto &sigma = ctx.sigma;
  auto &mitc = ctx.mitc;
  auto &G = ctx.G;
  auto &S = ctx.S;
  auto &b_buf_at_P1 = ctx.b_buf_at_P1;
  {
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (!g.is_and()) {
        if (g.is_not()) {
          mask_input[out] = mask_input[in0] ^ 1;
          { const int j = 2; EVAL(j, out) = EVAL(j, in0); }          WIRE(out) = WIRE(in0);
        } else {  // XOR
          { const int j = 2; EVAL(j, out) = EVAL(j, in0) ^ EVAL(j, in1); }
          mask_input[out] = mask_input[in0] ^ mask_input[in1];
          // Recompute fabric share for the per-AND Mr term below.
          xor_share(WIRE(out), WIRE(in0), WIRE(in1));
        }
      } else {  // AND
        int ai = g.and_index();
        bool La = mask_input[in0], Lb = mask_input[in1];
        // M_j[r^s] for sender s ∈ [1, nP] and recipient j ∈ [2, nP], j ≠ s.
        // At P1, peer_slot(1, i) = i - 2 for i ∈ [2, nP].
        const AShareBundle<nP> &wb_in0 = WIRE(in0);
        const AShareBundle<nP> &wb_in1 = WIRE(in1);
        const AShareBundle<nP> &wb_out = WIRE(out);
        const AShareBundle<nP> &sb     = sigma[ai];
        block Mr[nP + 1][nP + 1];
        { const int i = 2;
          int s = i - 2;
          block t = sb.mac(s) ^ wb_out.mac(s);
          if (La) t = t ^ wb_in1.mac(s);
          if (Lb) t = t ^ wb_in0.mac(s);
          Mr[1][i] = t;
        }
        // Pass 1: per sender s, batch all (γ, s, d ∈ [2,nP]) tweaks into
        // one renew_ks + hash_cir call (matching sender s's batch). d == s
        // is the self tweak — cache its outputs for pass 2 instead of
        // feeding S.
        block self_Ha[nP + 1], self_Hb[nP + 1];
        { const int s = 2;
          block tweaks[nP - 1];
          block buf[(nP - 1) * 2];
          { const int d = 2;
            int k = d - 2;
            tweaks[k] = tweak_block(ai, s, d);
            buf[2 * k]     = EVAL(s, in0);
            buf[2 * k + 1] = EVAL(s, in1);
          }
          mitc.renew_ks(tweaks);
          mitc.template hash_cir<nP - 1, 2>(buf);
          { const int d = 2;
            int k = d - 2;
            if (d == s) {
              self_Ha[s] = buf[2 * k];
              self_Hb[s] = buf[2 * k + 1];
            } else {
              block t = buf[2 * k] ^ buf[2 * k + 1] ^ S[ai][s][d][2];
              if (La) t = t ^ S[ai][s][d][0];
              if (Lb) t = t ^ S[ai][s][d][1];
              Mr[s][d] = t;
            }
          }
        }
        // Pass 2: combine cached self hashes with G + Mr column to produce
        // eval_labels[i][out]. Must follow pass 1 since it reads Mr[s][i]
        // for all s ≠ i.
        { const int i = 2;
          block t = self_Ha[i] ^ self_Hb[i];
          if (La) t = t ^ G[ai][i][0];
          if (Lb) t = t ^ G[ai][i][1] ^ EVAL(i, in0);
          t = t ^ Mr[1][i];  // the single s != i (= 2) is s = 1
          EVAL(i, out) = t;
        }
        mask_input[out] =
            (unsigned char)(b_buf_at_P1[ai] ^ LSB1(EVAL(2, out)));
      }
    }
  }
}

// Steps 11-12: P1 samples the polynomial-hash seed h'_seed; both parties then run
// the streaming label-hash check (step 12). h'_s({a_w}) = ⊕_w a_w·s^{w+1} is
// linear in {a_w}, which step 13's ⊕_p z_p = h'(⊕_p {M_1[t_w^p]}) check requires.
template <int nP>
void C2PC<nP>::check_label_hash(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_in = ctx.num_in;
  const int num_ands = ctx.num_ands;
  auto LABEL = [&](int w) -> block & { return ctx.LABEL(w); };
  auto EVAL = [&](int j, int w) -> block & { return ctx.EVAL(j, w); };
  auto &mask_input = ctx.mask_input;
  block &hp_seed = ctx.hp_seed;
  std::vector<unsigned char> Lambda_AND(num_ands);
  if (party == 1) {
    prg.random_block(&hp_seed, 1);
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (g.is_and()) Lambda_AND[g.and_index()] = mask_input[g.out];
    }
  }

  // Step 12: label-hash check, computed as a *streaming* inner product so the
  // per-wire labels never need to all be live at once. h = ⊕_w coeff[w]·a_w
  // with coeff[w] = hp_seed^(w+1); per-term gfmul + XOR-accumulate equals the
  // deferred-reduction vector_inn_prdt_sum_red by linearity of reduce(). The
  // coeff is keyed to *processing position* (inputs, then gate outputs in gate
  // order) — identical on both parties for the same circuit — so the hash is
  // consistent regardless of wire-id ordering (the numeric out id need not equal
  // num_in+gi). Each wire is folded exactly once; fabric labels are re-propagated
  // from the persisted base on the fly.
  if (party == 1) {
    block acc[nP + 1];
    { const int j = 2; acc[j] = zero_block; }    block pw = hp_seed, term;
    for (int w = 0; w < num_in; ++w) {
      { const int j = 2; gfmul(EVAL(j, w), pw, &term); acc[j] = acc[j] ^ term; }
      gfmul(pw, hp_seed, &pw);
    }
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (!g.is_and())  // AND output eval-labels persist (set during evaluation)
        { const int j = 2;
          EVAL(j, g.out) = g.is_not() ? EVAL(j, g.in0)
                                      : EVAL(j, g.in0) ^ EVAL(j, g.in1); }
      { const int j = 2; gfmul(EVAL(j, g.out), pw, &term); acc[j] = acc[j] ^ term; }
      gfmul(pw, hp_seed, &pw);
    }
    std::vector<future<void>> r2;
    { const int p2 = 2;
      int party2 = p2;
      r2.push_back(pool->enqueue([this, &hp_seed, &Lambda_AND, &acc, num_ands, party2]() {
        io_send(io1, io2, party, party2, &hp_seed, sizeof(block));
        io_send(io1, io2, party, party2, Lambda_AND.data(), num_ands);
        io_send(io1, io2, party, party2, &acc[party2], sizeof(block));
        io_flush(io1, io2, party, party2);
      }));
    }
    joinNclean(r2);
  } else {
    block h_i;
    io_recv(io1, io2, party, 1, &hp_seed, sizeof(block));
    io_recv(io1, io2, party, 1, Lambda_AND.data(), num_ands);
    io_recv(io1, io2, party, 1, &h_i, sizeof(block));

    // Re-propagate Λ and labels from the persisted base while streaming the
    // hash of shifted[w] = mask[w] ? label^Δ : label. XOR/NOT are local; AND
    // outputs come from P1's broadcast (Lambda_AND).
    block acc = zero_block, pw = hp_seed, term;
    auto fold = [&](int w) {
      block lab = LABEL(w);
      block sh = mask_input[w] ? (lab ^ Delta) : lab;
      gfmul(sh, pw, &term); acc = acc ^ term;
      gfmul(pw, hp_seed, &pw);
    };
    for (int w = 0; w < num_in; ++w) fold(w);
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (g.is_and()) {
        mask_input[out] = Lambda_AND[g.and_index()];  // AND output label persists
      } else if (g.is_not()) {
        mask_input[out] = mask_input[in0] ^ 1;
        LABEL(out) = LABEL(in0) ^ Delta;
      } else {  // XOR
        mask_input[out] = mask_input[in0] ^ mask_input[in1];
        LABEL(out) = LABEL(in0) ^ LABEL(in1);
      }
      fold(out);
    }
    if (!cmpBlock(&h_i, &acc, 1))
      error("cheat in label-hash check (step 12)");
  }
}

// Step 13: t_γ check. ⊕_p M_1[t_γ^p] = (y_α y_β ⊕ y_γ)·Δ_1 = 0 on honest gates;
// h' linearity then gives ⊕_p z_p = 0. coeff_ands is the uni-hash of hp_seed.
template <int nP>
void C2PC<nP>::check_tgamma(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle<nP> & { return ctx.WIRE(w); };
  auto &mask_input = ctx.mask_input;
  auto &sigma = ctx.sigma;
  block &hp_seed = ctx.hp_seed;
  BlockVec coeff_ands(num_ands);
  if (num_ands > 0) uni_hash_coeff_gen(coeff_ands.data(), hp_seed, num_ands);
  BlockVec M1_t(num_ands);
  if (party == 1) {
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (!g.is_and()) {  // recompute fabric share for downstream ANDs
        if (g.is_not()) { WIRE(out) = WIRE(in0); }
        else {            // XOR
          xor_share(WIRE(out), WIRE(in0), WIRE(in1));
        }
        continue;
      }
      int ai = g.and_index();
      bool La = mask_input[in0], Lb = mask_input[in1], Lg = mask_input[out];
      bool v_in0 = (bool)LSB(WIRE(in0).mac(0));
      bool v_in1 = (bool)LSB(WIRE(in1).mac(0));
      bool v_out = (bool)LSB(WIRE(out).mac(0));
      bool v_sig = (bool)LSB(sigma[ai].mac(0));
      bool t1 = (La & Lb) ^ Lg ^ (La & v_in1) ^ (Lb & v_in0) ^ v_sig ^ v_out;
      block m = t1 ? Delta : zero_block;
      const AShareBundle<nP> &wb_in0 = WIRE(in0);
      const AShareBundle<nP> &wb_in1 = WIRE(in1);
      const AShareBundle<nP> &wb_out = WIRE(out);
      const AShareBundle<nP> &sb     = sigma[ai];
      for (int s = 0; s < AShareBundle<nP>::K; ++s) {
        if (La) m = m ^ wb_in1.key(s);
        if (Lb) m = m ^ wb_in0.key(s);
        m = m ^ sb.key(s) ^ wb_out.key(s);
      }
      M1_t[ai] = m;
    }
    block z1 = zero_block;
    if (num_ands > 0)
      vector_inn_prdt_sum_red(&z1, M1_t.data(), coeff_ands.data(), num_ands);

    BlockVec z_recv(nP + 1);
    std::vector<future<void>> r3;
    { const int p2 = 2;
      int party2 = p2;
      r3.push_back(pool->enqueue([this, &z_recv, party2]() {
        io_recv(io1, io2, party, party2, &z_recv[party2], sizeof(block));
      }));
    }
    joinNclean(r3);
    block sum = z1;
    { const int i = 2; sum = sum ^ z_recv[i]; }    if (!cmpBlock(&sum, &zero_block, 1))
      error("cheat in t_gamma check (step 13)");
  } else {
    // Non-P1: peer 1 always exists, slot = peer_slot(party, 1).
    int s = peer_slot(party, 1);
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (!g.is_and()) {  // recompute fabric share for downstream ANDs
        if (g.is_not()) { WIRE(out) = WIRE(in0); }
        else {            // XOR
          xor_share(WIRE(out), WIRE(in0), WIRE(in1));
        }
        continue;
      }
      int ai = g.and_index();
      bool La = mask_input[in0], Lb = mask_input[in1];
      block m = sigma[ai].mac(s) ^ WIRE(out).mac(s);
      if (La) m = m ^ WIRE(in1).mac(s);
      if (Lb) m = m ^ WIRE(in0).mac(s);
      M1_t[ai] = m;
    }
    block z_i = zero_block;
    if (num_ands > 0)
      vector_inn_prdt_sum_red(&z_i, M1_t.data(), coeff_ands.data(), num_ands);
    io_send(io1, io2, party, 1, &z_i, sizeof(block));
    io_flush(io1, io2, party, 1);
  }
}

// Gather output SecureWires by explicit wire id; outputs are pinned to permanent
// slots and need not be contiguous or at the tail.
template <int nP>
SecureWires<nP> C2PC<nP>::gather_outputs(ComputeCtx &ctx,
                                         const std::vector<int> &output_ids) {
  auto WIRE = [&](int w) -> AShareBundle<nP> & { return ctx.WIRE(w); };
  auto LABEL = [&](int w) -> block & { return ctx.LABEL(w); };
  auto EVAL = [&](int j, int w) -> block & { return ctx.EVAL(j, w); };
  auto &mask_input = ctx.mask_input;
  SecureWires<nP> out;
  int n3 = (int)output_ids.size();
  out.Lambda.resize(n3);
  out.wire_bundle.resize(n3);
  for (int i = 0; i < n3; ++i) {
    out.Lambda[i] = mask_input[output_ids[i]];
    out.wire_bundle[i] = WIRE(output_ids[i]);
  }
  if (party != 1) {
    out.label0.resize(n3);
    for (int i = 0; i < n3; ++i) out.label0[i] = LABEL(output_ids[i]);
  } else {
    { const int j = 2;
      out.eval_label[j].resize(n3);
      for (int i = 0; i < n3; ++i) out.eval_label[j][i] = EVAL(j, output_ids[i]);
    }
  }
  return out;
}

template <int nP>
std::vector<bool> C2PC<nP>::decode(const SecureWires<nP> &wires,
                                         int recipient) {
  int n = (int)wires.size();
  WRK_PHASE_BEGIN();
  // Reveal to ALL parties: reconstruct at P1, then P1 broadcasts. Needed for
  // reactive host branching — every party must learn the same value.
  if (recipient == PUBLIC) {
    std::vector<bool> v = decode(wires, 1);  // only P1 holds it after this
    std::vector<unsigned char> buf(n);
    if (party == 1) {
      for (int i = 0; i < n; ++i) buf[i] = v[i];
      std::vector<future<void>> res;
      { const int p = 2;
        int p2 = p;
        res.push_back(pool->enqueue([this, &buf, n, p2]() {
          io_send(io1, io2, party, p2, buf.data(), n);
          io_flush(io1, io2, party, p2);
        }));
      }
      joinNclean(res);
      return v;
    }
    io_recv(io1, io2, party, 1, buf.data(), n);
    std::vector<bool> out(n);
    for (int i = 0; i < n; ++i) out[i] = (buf[i] & 1);
    return out;
  }
  std::vector<bool> result;
  // Each party reads its own λ-share from bit0 of any peer slot's MAC.
  std::vector<unsigned char> my_share(n);
  for (int i = 0; i < n; ++i)
    my_share[i] = (unsigned char)LSB(wires.wire_bundle[i].mac(0));
  if (party != recipient) {
    io_send(io1, io2, party, recipient, my_share.data(), n);
    io_flush(io1, io2, party, recipient);
  } else {
    result.resize(n);
    std::vector<std::vector<unsigned char>> tmp(nP + 1);
    const int party2 = 3 - recipient;  // the single non-recipient party
    tmp[party2].resize(n);
    std::vector<future<void>> res;
    res.push_back(pool->enqueue([this, &tmp, n, party2]() {
      io_recv(io1, io2, party, party2, tmp[party2].data(), n);
    }));
    joinNclean(res);
    for (int i = 0; i < n; ++i) {
      unsigned char v = my_share[i] ^ wires.Lambda[i] ^ tmp[party2][i];
      result[i] = (v & 1);
    }
  }
  WRK_PHASE("decode[step14]");
  return result;
}

#endif // C2PC_H__
