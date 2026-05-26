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

// Opt-in phase profiler: compile with -DAG2PC_PROFILE (or #define before include).
// At P1, each AG2PC_PHASE prints the wall time and this party's send+recv byte
// delta since the matching AG2PC_PHASE_BEGIN. Zero-cost when AG2PC_PROFILE is unset.
// Requires `send_io`/`recv_io` (NetIO*) and `party` in scope — C2PC members.
#ifdef AG2PC_PROFILE
#include <chrono>
#include <cstdio>
#define AG2PC_PHASE_BEGIN()                                                      \
  auto _ag2pc_t = std::chrono::steady_clock::now();                              \
  int64_t _ag2pc_c = io_count(send_io, recv_io)
#define AG2PC_PHASE(name)                                                        \
  do {                                                                         \
    auto _n = std::chrono::steady_clock::now();                                \
    int64_t _c = io_count(send_io, recv_io);                                                  \
    if (party == 1)                                                            \
      printf("[ag2pc] %-22s %9.3f ms  %12lld B\n", (name),                       \
             std::chrono::duration<double, std::milli>(_n - _ag2pc_t).count(),   \
             (long long)(_c - _ag2pc_c));                                        \
    _ag2pc_t = _n;                                                               \
    _ag2pc_c = _c;                                                               \
  } while (0)
#else
#define AG2PC_PHASE_BEGIN() ((void)0)
#define AG2PC_PHASE(name) ((void)0)
#endif

// Two-party authenticated garbling protocol Π_MPC of agc.tex
// (Figures P:MPC-1, P:MPC-2, P:MPC-3) specialized to two parties. The half-gate
// construction: the garbler P2 sends 2 ciphertexts G_{γ,0/1}^2 (no cross-peer
// S terms with a single garbler) plus b_γ; P1 recovers
// Λ_γ = b_γ ⊕ LSB1(m_{γ,Λ_γ}^2). The bit-1 Δ convention is set in
// auth_share_pool.h: bit1(Δ_2) = 1 and bit1(Δ_1) = 0, so bit1(Δ_1 ⊕ Δ_2) = 1.
// Bit 0 is reserved for share-value encoding.
//
// API:
//   process_input(bits, n, owner) → SecureWires  // steps 3 + 8 + 9
//   compute(WireGraph, inputs)    → SecureWires  // steps 4-13, fpre on demand
//   decode(wires, recipient)      → vector<bool> // step 14
//
// Output wires of compute() carry full SecureWire state. process_input() and
// compute() draw aShares/triples from the amortized pools owned by
// AuthSharePool / TriplePool; preprocess(num_triples) pre-mints into the pool.
// The frontend (a recording backend, see ag2pc_backend.h) drives this from native
// Bit/Integer code; circuits are consumed as WireGraph, not BristolFormat.

class C2PC {
public:
  // Long-lived setup: COT mesh + Δ + TriplePool (which owns the inner
  // AuthSharePool). Constructed once per session and reused across all
  // process_input / compute / decode calls. Both pools amortize their
  // refill costs across however many draw() calls land between refills.
  TriplePool *fpre = nullptr;
  NetIO *send_io, *recv_io;   // my outgoing / incoming channel to the peer
  ThreadPool *pool;
  int party;
  block Delta;
  PRG prg;

  C2PC(NetIO *io1, NetIO *io2, ThreadPool *pool_, int party_)
      : send_io(party_ == 1 ? io1 : io2), recv_io(party_ == 1 ? io2 : io1),
        pool(pool_), party(party_) {
    fpre = new TriplePool(io1, io2, pool_, party_);
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
  SecureWires process_input(const bool *inputs, int n, int owner);

  // Steps 4-13 of agc.tex on a WireGraph. Input bundles must already be
  // process_input'd and supplied in WireGraph.inputs (per-owner) order; they
  // occupy wires [0, num_in). Mints AND triples + AND-output share pool fresh
  // inside this call (preprocessing on-demand). Aborts via error() on
  // cheating-detection failure. Outputs are extracted by explicit id
  // (g.output_ids), in that order; output wires carry full state.
  SecureWires compute(const WireGraph &g,
                          const std::vector<SecureWires> &inputs);

  // Step 14 (output decode): all Pi ≠ recipient send λ_w^p to recipient;
  // recipient computes y_w = Λ_w ⊕ λ_w. Returns the n cleartext bits at
  // `recipient`; empty vector at non-recipients.
  std::vector<bool> decode(const SecureWires &wires, int recipient);

  // Concatenate two SecureWires bundles wire-by-wire.
  static SecureWires concat(const SecureWires &a,
                                const SecureWires &b);

private:
  // Per-call scratch shared across the protocol-step methods below. The heavy
  // arrays size to num_slots (slot-reuse, see circuit_layout.h), not num_wire;
  // WIRE / LABEL / EVAL hide the wire-id -> slot indirection.
  struct ComputeCtx {
    const CircuitView *cf = nullptr;
    int num_in = 0, num_ands = 0, num_slots = 0;
    std::vector<int> phys;                  // logical wire id -> physical slot
    std::vector<unsigned char> mask_input;  // Λ_w, indexed by wire id
    AShareBundleVec wire_slot;          // share bundles, indexed by slot
    BlockVec label_slot;                    // m_{w,0} at Pi (i>=2), by slot
    BlockVec eval_slot;                // m_{w,Λ} at P1 (single garbler P2)
    TripleBundleVec ANDS_bundle;        // AND triples, by and_index
    AShareBundleVec sigma;              // Beaver-corrected AND shares
    MITCCRH<1> mitc;                   // half-gate hash (garble / evaluate)
    std::vector<std::array<block, 2>> G;    // P1: G_{γ,0/1} from the garbler P2
    std::vector<unsigned char> b_buf_at_P1; // P1: b_γ from P2
    block hp_seed;                          // step-11 hash seed (used in 12, 13)
    AShareBundle &WIRE(int w) { return wire_slot[phys[w]]; }
    block &LABEL(int w) { return label_slot[phys[w]]; }
    block &EVAL(int w) { return eval_slot[phys[w]]; }
  };

  // agc.tex steps 4-13, one method per phase over a shared ComputeCtx; the
  // body of each is the verbatim crypto of that step. compute_impl (below) is
  // the orchestrator that runs them in protocol order.
  void load_inputs(ComputeCtx &ctx, const SecureWires *const *inputs,
                   int n_inputs);
  void draw_and_seed(ComputeCtx &ctx);          // step 4: triples + AND-out seed
  void beaver_pass(ComputeCtx &ctx);            // step 5
  void garble_and_ship(ComputeCtx &ctx);        // steps 6-7, sender Pi (i>=2)
  void receive_garbling(ComputeCtx &ctx);       // steps 6-7, P1 receive
  void p1_evaluate(ComputeCtx &ctx);            // step 10, P1
  void check_label_hash(ComputeCtx &ctx);       // steps 11-12
  void check_tgamma(ComputeCtx &ctx);           // step 13
  SecureWires gather_outputs(ComputeCtx &ctx,
                                 const std::vector<int> &output_ids);

  // Half-gate hash tweak: unique across (gate_idx, sender, dest) within a call.
  static block tweak_block(int gate_idx, int sender, int dest) {
    return makeBlock((uint64_t)gate_idx, (uint64_t)(sender * (3) + dest));
  }

  // Free-XOR share propagation: recompute a fabric wire's share bundle as the
  // componentwise XOR of its (live) inputs. bit0 (the share-bit) rides along.
  static void xor_share(AShareBundle &out, const AShareBundle &a,
                        const AShareBundle &b) {
    out.mac = a.mac ^ b.mac;
    out.key = a.key ^ b.key;
  }

  // Orchestrator: builds ComputeCtx, then runs the step methods in order.
  SecureWires compute_impl(const CircuitView *cf,
                               const std::vector<int> &output_ids,
                               const SecureWires *const *inputs,
                               int n_inputs);
};

// ==========================================================================
// Implementation
// ==========================================================================

SecureWires C2PC::concat(const SecureWires &a,
                                       const SecureWires &b) {
  SecureWires r = a;
  r.append(b);
  return r;
}

SecureWires C2PC::process_input(const bool *inputs, int n, int owner) {
  AG2PC_PHASE_BEGIN();
  SecureWires sw;
  sw.Lambda.resize(n);
  if (party != 1)
    sw.label0.resize(n);
  else
    sw.eval_label.resize(n);
  // Step 3 (Π_aShare): n authenticated λ-shares — drawn from pool. The pool
  // stores AoS-by-wire, so draw is a single memcpy into sw.wire_bundle.
  // Each share-bit λ_w^i is implicit in bit0(sw.wire_bundle[w].mac).
  fpre->abit.draw(n, sw.wire_bundle);

  // Step 3 (cont.): Pi (i ≥ 2) samples m_{w, 0}^i for each input wire.
  if (party != 1)
    prg.random_block(sw.label0.data(), n);

  // Step 8: open Λ_w = ⊕_p λ_w^p ⊕ x_w. Owner XORs its bit into the
  // contribution; non-owners contribute just their share. Read λ_w^i from
  // bit0 of any peer slot's MAC.
  std::vector<unsigned char> v(n);
  for (int i = 0; i < n; ++i)
    v[i] = (unsigned char)LSB(sw.wire_bundle[i].mac);
  if (party == owner)
    for (int i = 0; i < n; ++i) v[i] ^= (unsigned char)inputs[i];

  if (party != 1) {
    send_io->send_data(v.data(), n);
    send_io->flush();
    recv_io->recv_data(sw.Lambda.data(), n);
  } else {
    std::vector<unsigned char> tmp(n);
    std::vector<future<void>> res;
    { const int party2 = 2;
      res.push_back(pool->enqueue([this, &tmp, n, party2]() {
        recv_io->recv_data(tmp.data(), n);
      }));
    }
    joinNclean(res);
    for (int i = 0; i < n; ++i)
      sw.Lambda[i] = v[i] ^ tmp[i];
    { const int party2 = 2;
      res.push_back(pool->enqueue([this, &sw, n, party2]() {
        send_io->send_data(sw.Lambda.data(), n);
        send_io->flush();
      }));
    }
    joinNclean(res);
  }

  // Step 9: Pi (i ≥ 2) ships m_{w, Λ_w}^i = label0[w] ⊕ Λ_w · Δ to P1.
  if (party != 1) {
    BlockVec tmp(n);
    for (int i = 0; i < n; ++i)
      tmp[i] = sw.Lambda[i] ? (sw.label0[i] ^ Delta) : sw.label0[i];
    send_io->send_data(tmp.data(), n * sizeof(block));
    send_io->flush();
  } else {
    std::vector<future<void>> res;
    { const int party2 = 2;
      res.push_back(pool->enqueue([this, &sw, n, party2]() {
        recv_io->recv_data(sw.eval_label.data(),
                      n * sizeof(block));
      }));
    }
    joinNclean(res);
  }
  AG2PC_PHASE(owner == 1 ? "process_input[owner1]" : "process_input[ownerN]");
  return sw;
}

// WireGraph marshals directly: gate list as-is, outputs taken by explicit id.
SecureWires C2PC::compute(const WireGraph &g,
                                        const std::vector<SecureWires> &inputs) {
  std::vector<const SecureWires *> ptrs;
  ptrs.reserve(inputs.size());
  for (const auto &s : inputs) ptrs.push_back(&s);
  CircuitView cv{g.num_wire, g.num_gate(), g.num_ands, g.gates.data()};
  if (!g.last_use.empty()) cv.last_use = g.last_use.data();  // recorder-supplied
  return compute_impl(&cv, g.output_ids, ptrs.data(), (int)ptrs.size());
}

SecureWires C2PC::compute_impl(const CircuitView *cf,
                                             const std::vector<int> &output_ids,
                                             const SecureWires *const *inputs,
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
  else ctx.eval_slot.resize(ctx.num_slots);  ctx.mitc.setS(zero_block);

  AG2PC_PHASE_BEGIN();
  load_inputs(ctx, inputs, n_inputs);     AG2PC_PHASE("load_inputs");
  draw_and_seed(ctx);                      AG2PC_PHASE("draw_and_seed[step4]");
  beaver_pass(ctx);                        AG2PC_PHASE("beaver_pass[step5]");
  if (party != 1) garble_and_ship(ctx);    // steps 6-7 (sender Pi, i>=2)
  else            receive_garbling(ctx);   AG2PC_PHASE("garble/recv[step6-7]");
  if (party == 1) p1_evaluate(ctx);        AG2PC_PHASE("p1_evaluate[step10]");
  check_label_hash(ctx);                   AG2PC_PHASE("check_label[step12]");
  check_tgamma(ctx);                       AG2PC_PHASE("check_tgamma[step13]");
  SecureWires r = gather_outputs(ctx, output_ids);  AG2PC_PHASE("gather_outputs");
  return r;
}

// Copy each input SecureWires bundle into wire indices [0, num_in) in order;
// inputs occupy slots [0, num_in). SecureWires is AoS, so this is a pure memcpy.
void C2PC::load_inputs(ComputeCtx &ctx, const SecureWires *const *inputs,
                           int n_inputs) {
  size_t off = 0;
  for (int b = 0; b < n_inputs; ++b) {
    const SecureWires &in = *inputs[b];
    size_t n = in.size();
    memcpy(ctx.mask_input.data() + off, in.Lambda.data(), n);
    memcpy(&ctx.wire_slot[off], in.wire_bundle.data(),
           n * sizeof(AShareBundle));
    if (party != 1) {
      memcpy(ctx.label_slot.data() + off, in.label0.data(), n * sizeof(block));
    } else {
      memcpy(ctx.eval_slot.data() + off, in.eval_label.data(),
             n * sizeof(block));
    }
    off += n;
  }
}

// Step 4: draw AND triples + seed each AND-output wire's share state from the
// preprocessing pool. ANDS_bundle[ai].b[s] holds triple ai's slot-s share
// bundle; the slot-s share-bit is implicit in bit0(.mac).
void C2PC::draw_and_seed(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
#ifdef AG2PC_PROFILE
  int64_t _all0 = io_count(send_io, recv_io);
  uint64_t _cot0 = g_ag2pc_cot_bytes, _phi0 = g_ag2pc_phi_bytes;
#endif
  fpre->draw(num_ands, ctx.ANDS_bundle);

  // Seed AND-output share state from the per-aShare preprocessing pool.
  // Scoped: preprocess_bundle dies at the closing brace, freeing num_ands
  // aShares before the heavy garble allocations.
  {
    AShareBundleVec preprocess_bundle;
    fpre->abit.draw(num_ands, preprocess_bundle);

    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (g.is_and()) WIRE(g.out) = preprocess_bundle[g.and_index()];
    }
  }
#ifdef AG2PC_PROFILE
  if (party == 1) {
    uint64_t all = (uint64_t)(io_count(send_io, recv_io) - _all0), cot = g_ag2pc_cot_bytes - _cot0,
             phi = g_ag2pc_phi_bytes - _phi0;
    printf("[ag2pc]   draw_and_seed split: COT %llu B, phi-exchange %llu B, "
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
// ai lives in bit0(ANDS_bundle[ai].b[s].mac), and the Beaver XOR pattern gives
// bit0(sigma) = ANDS[2] ⊕ (xb?ANDS[1]) ⊕ (yb?ANDS[0]). The xb && yb correction is
// "λ_{αβ} ⊕= 1" (P1-only): at P1 flip bit0 of sb.mac; at non-P1 update sb.key by
// (Δ ⊕ e_0) so bit0(KEY)=0 stays pinned.
void C2PC::beaver_pass(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto &ANDS_bundle = ctx.ANDS_bundle;
  auto &sigma = ctx.sigma;
  sigma.resize(num_ands);
  std::vector<unsigned char> x[3], y[3];
  for (int j = 1; j <= 2; ++j) {
    x[j].resize(num_ands);
    y[j].resize(num_ands);
  }
  {
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (g.is_and()) {
        int ai = g.and_index();
        unsigned char v_in0 = (unsigned char)LSB(WIRE(g.in0).mac);
        unsigned char v_in1 = (unsigned char)LSB(WIRE(g.in1).mac);
        unsigned char a0 = (unsigned char)LSB(ANDS_bundle[ai].b[0].mac);
        unsigned char a1 = (unsigned char)LSB(ANDS_bundle[ai].b[1].mac);
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
      send_io->send_bool((const bool *)x[party].data(), num_ands);  // 1 bit/AND, packed
      send_io->send_bool((const bool *)y[party].data(), num_ands);
      send_io->flush();
    }));
    res.push_back(pool->enqueue([this, &x, &y, num_ands, party2]() {
      recv_io->recv_bool((bool *)x[party2].data(), num_ands);
      recv_io->recv_bool((bool *)y[party2].data(), num_ands);
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
      AShareBundle &sb = sigma[ai];
      const TripleBundle &tb = ANDS_bundle[ai];
      bool xb = x[1][ai], yb = y[1][ai];
      // Beaver select-XOR on both fields: σ = ANDS[2] ⊕ (xb?ANDS[1]) ⊕ (yb?ANDS[0]).
      sb.mac = tb.b[2].mac ^ (xb ? tb.b[1].mac : zero_block)
                           ^ (yb ? tb.b[0].mac : zero_block);
      sb.key = tb.b[2].key ^ (xb ? tb.b[1].key : zero_block)
                           ^ (yb ? tb.b[0].key : zero_block);
      if (xb && yb) {
        if (party != 1) {
          sb.key = sb.key ^ dxor;
        } else {
          sb.mac = sb.mac ^ bit0_mask;
        }
      }
    }
  }
}

// Steps 6-7: the garbler P2 garbles each AND gate and ships to P1. Per gate γ:
//   G_buf[2γ..)     = (G_{γ,0}^2, G_{γ,1}^2)
//   b_buf[γ]        = LSB1(m_{γ,0}^2)
// With a single garbler there are no cross-garbler S_{γ,*}^{i,j} terms.
// Half-gate hash uses MITCCRH (eprint/2019/1168): H_τ(x) = σ(x) ⊕
// AES_{start_point ⊕ τ}(σ(x)); tweak_block(γ, sender, dest) is unique across
// (γ, sender, dest). BatchSize = 1: each renew_ks schedules the single
// (γ, sender=2)→(d=2) self tweak feeding G_{γ,*}.
void C2PC::garble_and_ship(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto LABEL = [&](int w) -> block & { return ctx.LABEL(w); };
  auto &sigma = ctx.sigma;
  auto &mitc = ctx.mitc;
  {
    BlockVec G_buf(2 * num_ands);
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

      // The single tweak for d = 2 with 4 blocks; one batched renew_ks +
      // hash_cir consumes the whole gate's sender-side half-gate hashes.
      block tweaks[1];
      block buf[4];
      { const int d = 2;
        int k = d - 2;
        tweaks[k] = tweak_block(ai, party, d);
        buf[4 * k]     = ml_a0;
        buf[4 * k + 1] = ml_a1;
        buf[4 * k + 2] = ml_b0;
        buf[4 * k + 3] = ml_b1;
      }
      mitc.renew_ks(tweaks);
      mitc.template hash_cir<1, 4>(buf);

      const AShareBundle &wb_in0 = WIRE(in0);
      const AShareBundle &wb_in1 = WIRE(in1);
      const AShareBundle &wb_out = WIRE(out);
      const AShareBundle &sb     = sigma[ai];

      // Single garbler (d == party == 2): only the self tweak fires, so the
      // four self hashes are just buf[0..3]; no cross-garbler S terms.
      block H_a0_self = buf[0], H_a1_self = buf[1];
      block H_b0_self = buf[2], H_b1_self = buf[3];

      block sumK_a  = wb_in0.key;
      block sumK_b  = wb_in1.key;
      block sumK_ab = sb.key;
      block sumK_g  = wb_out.key;
      // λ_w^i is bit0(mac). Branchless: select_mask[bit] gives 0 or all-ones,
      // so (Δ & select_mask[bit]) collapses to bit ? Δ : 0.
      block la_dot  = select_mask[LSB(wb_in0.mac)] & Delta;
      block lb_dot  = select_mask[LSB(wb_in1.mac)] & Delta;
      block lab_dot = select_mask[LSB(sb.mac)]     & Delta;
      block lg_dot  = select_mask[LSB(wb_out.mac)] & Delta;

      block G0 = H_a0_self ^ H_a1_self ^ sumK_b ^ lb_dot;
      block G1 = H_b0_self ^ H_b1_self ^ ml_a0 ^ sumK_a ^ la_dot;
      block ml_g0 = H_a0_self ^ H_b0_self ^ sumK_ab ^ lab_dot ^ sumK_g ^ lg_dot;

      LABEL(out) = ml_g0;
      G_buf[2 * ai]     = G0;
      G_buf[2 * ai + 1] = G1;
      if (party == 2) b_buf[ai] = (unsigned char)(LSB1(ml_g0));
    }
    send_io->send_data(G_buf.data(), 2 * num_ands * sizeof(block));
    if (party == 2) send_io->send_data(b_buf.data(), num_ands);
    send_io->flush();
  }
}

// Steps 6-7: P1 receives G, b from the garbler P2 into ctx (consumed by
// p1_evaluate). With a single garbler there are no cross-garbler S terms.
void C2PC::receive_garbling(ComputeCtx &ctx) {
  const int num_ands = ctx.num_ands;
  auto &G = ctx.G;
  auto &b_buf_at_P1 = ctx.b_buf_at_P1;
  G.resize(num_ands);
  b_buf_at_P1.resize(num_ands);
  std::vector<future<void>> rres;
    { const int p2 = 2;
      rres.push_back(
          pool->enqueue([this, &G, &b_buf_at_P1, num_ands, p2]() {
            BlockVec G_buf(2 * num_ands);
            recv_io->recv_data(G_buf.data(), 2 * num_ands * sizeof(block));
            for (int g = 0; g < num_ands; ++g) {
              G[g][0] = G_buf[2 * g];
              G[g][1] = G_buf[2 * g + 1];
            }
            recv_io->recv_data(b_buf_at_P1.data(), num_ands);
          }));
    }
    joinNclean(rres);
  }

// Step 10: P1 evaluates each gate topologically, recovering eval-labels and the
// public mask. XOR/NOT propagate locally; AND combines the received G
// ciphertexts with the half-gate hashes. Called only at P1.
void C2PC::p1_evaluate(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto EVAL = [&](int w) -> block & { return ctx.EVAL(w); };
  auto &mask_input = ctx.mask_input;
  auto &sigma = ctx.sigma;
  auto &mitc = ctx.mitc;
  auto &G = ctx.G;
  auto &b_buf_at_P1 = ctx.b_buf_at_P1;
  {
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (!g.is_and()) {
        if (g.is_not()) {
          mask_input[out] = mask_input[in0] ^ 1;
          EVAL(out) = EVAL(in0);
          WIRE(out) = WIRE(in0);
        } else {  // XOR
          EVAL(out) = EVAL(in0) ^ EVAL(in1);
          mask_input[out] = mask_input[in0] ^ mask_input[in1];
          // Recompute fabric share for the per-AND Mr term below.
          xor_share(WIRE(out), WIRE(in0), WIRE(in1));
        }
      } else {  // AND
        int ai = g.and_index();
        bool La = mask_input[in0], Lb = mask_input[in1];
        const AShareBundle &wb_in0 = WIRE(in0);
        const AShareBundle &wb_in1 = WIRE(in1);
        const AShareBundle &wb_out = WIRE(out);
        const AShareBundle &sb     = sigma[ai];
        block Mr;  // M_2[r^1]: the single (sender=1, receiver=2) cross term
        { block t = sb.mac ^ wb_out.mac;
          if (La) t = t ^ wb_in1.mac;
          if (Lb) t = t ^ wb_in0.mac;
          Mr = t;
        }
        // Pass 1: the single garbler's (s=2, d=2) self tweak — one renew_ks +
        // hash_cir call; cache its two outputs for pass 2.
        block self_Ha, self_Hb;
        { block tweaks[1] = {tweak_block(ai, 2, 2)};
          block buf[2] = {EVAL(in0), EVAL(in1)};
          mitc.renew_ks(tweaks);
          mitc.template hash_cir<1, 2>(buf);
          self_Ha = buf[0];
          self_Hb = buf[1];
        }
        // Pass 2: combine the cached self hashes with G + the Mr cross term to
        // produce the eval-label at out.
        { block t = self_Ha ^ self_Hb;
          if (La) t = t ^ G[ai][0];
          if (Lb) t = t ^ G[ai][1] ^ EVAL(in0);
          t = t ^ Mr;  // the single cross term (sender s = 1, receiver = 2)
          EVAL(out) = t;
        }
        mask_input[out] =
            (unsigned char)(b_buf_at_P1[ai] ^ LSB1(EVAL(out)));
      }
    }
  }
}

// Steps 11-12: P1 samples the polynomial-hash seed h'_seed; both parties then run
// the streaming label-hash check (step 12). h'_s({a_w}) = ⊕_w a_w·s^{w+1} is
// linear in {a_w}, which step 13's ⊕_p z_p = h'(⊕_p {M_1[t_w^p]}) check requires.
void C2PC::check_label_hash(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_in = ctx.num_in;
  const int num_ands = ctx.num_ands;
  auto LABEL = [&](int w) -> block & { return ctx.LABEL(w); };
  auto EVAL = [&](int w) -> block & { return ctx.EVAL(w); };
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
    block acc = zero_block;
    block pw = hp_seed, term;
    for (int w = 0; w < num_in; ++w) {
      gfmul(EVAL(w), pw, &term); acc = acc ^ term;
      gfmul(pw, hp_seed, &pw);
    }
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      if (!g.is_and())  // AND output eval-labels persist (set during evaluation)
        EVAL(g.out) = g.is_not() ? EVAL(g.in0) : EVAL(g.in0) ^ EVAL(g.in1);
      gfmul(EVAL(g.out), pw, &term); acc = acc ^ term;
      gfmul(pw, hp_seed, &pw);
    }
    std::vector<future<void>> r2;
    { const int party2 = 2;
      r2.push_back(pool->enqueue([this, &hp_seed, &Lambda_AND, &acc, num_ands, party2]() {
        send_io->send_data(&hp_seed, sizeof(block));
        send_io->send_bool((const bool *)Lambda_AND.data(), num_ands);  // 1 bit/AND, packed
        send_io->send_data(&acc, sizeof(block));
        send_io->flush();
      }));
    }
    joinNclean(r2);
  } else {
    block h_i;
    recv_io->recv_data(&hp_seed, sizeof(block));
    recv_io->recv_bool((bool *)Lambda_AND.data(), num_ands);
    recv_io->recv_data(&h_i, sizeof(block));

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
void C2PC::check_tgamma(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
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
      bool v_in0 = (bool)LSB(WIRE(in0).mac);
      bool v_in1 = (bool)LSB(WIRE(in1).mac);
      bool v_out = (bool)LSB(WIRE(out).mac);
      bool v_sig = (bool)LSB(sigma[ai].mac);
      bool t1 = (La & Lb) ^ Lg ^ (La & v_in1) ^ (Lb & v_in0) ^ v_sig ^ v_out;
      block m = t1 ? Delta : zero_block;
      const AShareBundle &wb_in0 = WIRE(in0);
      const AShareBundle &wb_in1 = WIRE(in1);
      const AShareBundle &wb_out = WIRE(out);
      const AShareBundle &sb     = sigma[ai];
      if (La) m = m ^ wb_in1.key;
      if (Lb) m = m ^ wb_in0.key;
      m = m ^ sb.key ^ wb_out.key;
      M1_t[ai] = m;
    }
    block z1 = zero_block;
    if (num_ands > 0)
      vector_inn_prdt_sum_red(&z1, M1_t.data(), coeff_ands.data(), num_ands);

    block z_recv;
    std::vector<future<void>> r3;
    { const int party2 = 2;
      r3.push_back(pool->enqueue([this, &z_recv, party2]() {
        recv_io->recv_data(&z_recv, sizeof(block));
      }));
    }
    joinNclean(r3);
    block sum = z1 ^ z_recv;
    if (!cmpBlock(&sum, &zero_block, 1))
      error("cheat in t_gamma check (step 13)");
  } else {
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
      block m = sigma[ai].mac ^ WIRE(out).mac;
      if (La) m = m ^ WIRE(in1).mac;
      if (Lb) m = m ^ WIRE(in0).mac;
      M1_t[ai] = m;
    }
    block z_i = zero_block;
    if (num_ands > 0)
      vector_inn_prdt_sum_red(&z_i, M1_t.data(), coeff_ands.data(), num_ands);
    send_io->send_data(&z_i, sizeof(block));
    send_io->flush();
  }
}

// Gather output SecureWires by explicit wire id; outputs are pinned to permanent
// slots and need not be contiguous or at the tail.
SecureWires C2PC::gather_outputs(ComputeCtx &ctx,
                                         const std::vector<int> &output_ids) {
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto LABEL = [&](int w) -> block & { return ctx.LABEL(w); };
  auto EVAL = [&](int w) -> block & { return ctx.EVAL(w); };
  auto &mask_input = ctx.mask_input;
  SecureWires out;
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
    out.eval_label.resize(n3);
    for (int i = 0; i < n3; ++i) out.eval_label[i] = EVAL(output_ids[i]);
  }
  return out;
}

std::vector<bool> C2PC::decode(const SecureWires &wires,
                                         int recipient) {
  int n = (int)wires.size();
  AG2PC_PHASE_BEGIN();
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
          send_io->send_data(buf.data(), n);
          send_io->flush();
        }));
      }
      joinNclean(res);
      return v;
    }
    recv_io->recv_data(buf.data(), n);
    std::vector<bool> out(n);
    for (int i = 0; i < n; ++i) out[i] = (buf[i] & 1);
    return out;
  }
  std::vector<bool> result;
  // Each party reads its own λ-share from bit0 of any peer slot's MAC.
  std::vector<unsigned char> my_share(n);
  for (int i = 0; i < n; ++i)
    my_share[i] = (unsigned char)LSB(wires.wire_bundle[i].mac);
  if (party != recipient) {
    send_io->send_data(my_share.data(), n);
    send_io->flush();
  } else {
    result.resize(n);
    const int party2 = 3 - recipient;  // the single non-recipient party
    std::vector<unsigned char> tmp(n);
    recv_io->recv_data(tmp.data(), n);
    for (int i = 0; i < n; ++i) {
      unsigned char v = my_share[i] ^ wires.Lambda[i] ^ tmp[i];
      result[i] = (v & 1);
    }
  }
  AG2PC_PHASE("decode[step14]");
  return result;
}

#endif // C2PC_H__
