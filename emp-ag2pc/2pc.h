#ifndef C2PC_H__
#define C2PC_H__
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
// With -DAG2PC_MEMPROFILE each phase line also carries the peak RSS reached by
// its end (ag2pc_peak_rss_kib, defined in triple_pool.h); the jump between two
// phases is that phase's contribution to the high-water mark.
#ifdef AG2PC_MEMPROFILE
#define AG2PC_PHASE_RSS_FMT "  peakRSS %8ld KiB"
#define AG2PC_PHASE_RSS_ARG , ag2pc_peak_rss_kib()
#else
#define AG2PC_PHASE_RSS_FMT ""
#define AG2PC_PHASE_RSS_ARG
#endif
#define AG2PC_PHASE_BEGIN()                                                      \
  auto _ag2pc_t = std::chrono::steady_clock::now();                              \
  int64_t _ag2pc_c = io_count(send_io, recv_io)
#define AG2PC_PHASE(name)                                                        \
  do {                                                                         \
    auto _n = std::chrono::steady_clock::now();                                \
    int64_t _c = io_count(send_io, recv_io);                                                  \
    if (party == 1)                                                            \
      printf("[ag2pc] %-22s %9.3f ms  %12lld B" AG2PC_PHASE_RSS_FMT "\n", (name), \
             std::chrono::duration<double, std::milli>(_n - _ag2pc_t).count(),   \
             (long long)(_c - _ag2pc_c) AG2PC_PHASE_RSS_ARG);                     \
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
// TriplePool::init_abit_: bit1(Δ_2) = 1 and bit1(Δ_1) = 0, so bit1(Δ_1 ⊕ Δ_2) = 1.
// Bit 0 is reserved for share-value encoding.
//
// API:
//   process_input(bits, n, owner) → SecureWires  // steps 3 + 8 + 9
//   compute(WireGraph, inputs)    → SecureWires  // steps 4-13, fpre on demand
//   decode(wires, recipient)      → vector<bool> // step 14
//
// Output wires of compute() carry full SecureWire state. process_input() and
// compute() draw aShares/triples from TriplePool (which mints aShares via COT
// and amortizes triples in a pool); preprocess(num_triples) pre-mints triples.
// The frontend (a recording backend, see ag2pc_backend.h) drives this from native
// Bit/Integer code; circuits are consumed as WireGraph, not BristolFormat.

class C2PC {
public:
  // Long-lived setup: TriplePool (COT mesh + Δ + the triple pool). Constructed
  // once per session and reused across all process_input / compute / decode
  // calls; the triple pool amortizes refill costs across draw() calls.
  TriplePool *fpre = nullptr;
  // io = primary channel (sequential comm); sib = a second channel spawned from
  // it, owned here. send_io/recv_io alias (io, sib) by party for the duplex
  // beaver pass; everything sequential uses io directly.
  NetIO *io;
  std::unique_ptr<NetIO> sib_owned;
  NetIO *sib, *send_io, *recv_io;
  ThreadPool *pool;
  int party;
  block Delta;
  PRG prg;

  // Takes a single NetIO; spawns and owns the sibling channel.
  C2PC(NetIO *io, ThreadPool *pool_, int party_)
      : io(io), sib_owned(io->make_sibling()), sib(sib_owned.get()),
        send_io(party_ == 1 ? io : sib_owned.get()),
        recv_io(party_ == 1 ? sib_owned.get() : io),
        pool(pool_), party(party_) {
    fpre = new TriplePool(io, sib_owned.get(), pool_, party_);
    Delta = fpre->Delta;
  }
  ~C2PC() { delete fpre; }

  // Eagerly mint num_triples triples into TriplePool's pool so subsequent
  // compute() calls draw from cache. aShares are minted lazily inside each
  // process_input / compute call (no aShare pool). num_abits is accepted for
  // backward-compat signature but unused.
  void preprocess(size_t num_triples, size_t /*num_abits*/) {
    fpre->preprocess(num_triples);
  }

  // ====== New API ======

  // Steps 3 + 8 + 9 of agc.tex on n new input wires owned by `owner`.
  // At `owner`, `inputs` must point to n cleartext bits; non-owners may
  // pass nullptr. Internally:
  //   - fpre->draw mints n authenticated λ-shares
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
    MITCCRH<8> mitc;                   // half-gate hash (garble / evaluate)
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
  // Garbled tables are streamed: garble_and_ship sends them in kGarbleChunk-
  // AND-gate chunks; p1_evaluate recvs each chunk on demand during evaluation,
  // so neither side ever holds the full-circuit G buffer.
  static constexpr int kGarbleChunk = 1 << 16;
  void garble_and_ship(ComputeCtx &ctx);        // steps 6-7, garbler P2
  void p1_evaluate(ComputeCtx &ctx);            // steps 6-7 recv + step 10, P1
  void check_cgamma(ComputeCtx &ctx);           // KRRW Fig.3 steps 6-8 (c_γ check)

  SecureWires gather_outputs(ComputeCtx &ctx,
                                 const std::vector<int> &output_ids);

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
  fpre->draw(n, sw.wire_bundle);

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
    io->send_data(v.data(), n);
    io->flush();
    io->recv_data(sw.Lambda.data(), n);
  } else {
    std::vector<unsigned char> tmp(n);
    io->recv_data(tmp.data(), n);
    for (int i = 0; i < n; ++i)
      sw.Lambda[i] = v[i] ^ tmp[i];
    io->send_data(sw.Lambda.data(), n);
    io->flush();
  }

  // Step 9: Pi (i ≥ 2) ships m_{w, Λ_w}^i = label0[w] ⊕ Λ_w · Δ to P1.
  if (party != 1) {
    BlockVec tmp(n);
    for (int i = 0; i < n; ++i)
      tmp[i] = sw.label0[i] ^ (select_mask[sw.Lambda[i]] & Delta);
    io->send_data(tmp.data(), n * sizeof(block));
    io->flush();
  } else {
    io->recv_data(sw.eval_label.data(), n * sizeof(block));
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
  else ctx.eval_slot.resize(ctx.num_slots);

  AG2PC_PHASE_BEGIN();
  load_inputs(ctx, inputs, n_inputs);     AG2PC_PHASE("load_inputs");
  draw_and_seed(ctx);                      AG2PC_PHASE("draw_and_seed[step4]");
  beaver_pass(ctx);                        AG2PC_PHASE("beaver_pass[step5]");
  // Half-gate hash start point: drawn fresh from the FS transcript (identical on
  // both parties via get_digest's canonical d_AB‖d_BA; advances every reactive
  // round so the gid-derived gate tweaks never repeat).
  ctx.mitc.setS(RO("AG2PC half-gate", zero_block)
                    .absorb(io->get_digest()).absorb(sib->get_digest())
                    .squeeze_block());
  if (party != 1) garble_and_ship(ctx);    // steps 6-7: garbler P2 ships G in chunks
  AG2PC_PHASE("garble/recv[step6-7]");
  if (party == 1) p1_evaluate(ctx);        // P1 streams G in and evaluates
  AG2PC_PHASE("p1_evaluate[step10]");
  check_cgamma(ctx);                       AG2PC_PHASE("check[c_gamma]");
  SecureWires r = gather_outputs(ctx, output_ids);  AG2PC_PHASE("gather_outputs");
#ifdef AG2PC_MEMPROFILE
  if (party == 1) {
    const double A = (double)std::max(1, ctx.num_ands);
    printf("[ag2pc-mem] ComputeCtx  num_wire=%d num_slots=%d num_ands=%d "
           "num_gate=%d\n", cf->num_wire, ctx.num_slots, ctx.num_ands, cf->num_gate);
    ag2pc_mem_row("phys",         (double)ctx.phys.capacity() * sizeof(int), A);
    ag2pc_mem_row("mask_input",   (double)ctx.mask_input.capacity(), A);
    ag2pc_mem_row("wire_slot",    (double)ctx.wire_slot.capacity() * sizeof(AShareBundle), A);
    ag2pc_mem_row("eval/label",   (double)(party == 1 ? ctx.eval_slot.capacity()
                                  : ctx.label_slot.capacity()) * sizeof(block), A);
    ag2pc_mem_row("ANDS_bundle",  (double)ctx.ANDS_bundle.capacity() * sizeof(TripleBundle), A);
    ag2pc_mem_row("sigma",        (double)ctx.sigma.capacity() * sizeof(AShareBundle), A);
    ag2pc_mem_row("circuit.gates", (double)cf->num_gate * sizeof(Gate), A);
    if (cf->last_use) ag2pc_mem_row("circuit.last_use", (double)cf->num_gate * sizeof(int), A);
    printf("[ag2pc-mem]   peakRSS-so-far %8ld KiB\n", ag2pc_peak_rss_kib());
  }
#endif
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

// Step 4: draw the AND triples — ANDS_bundle[ai].b[s] is triple ai's slot-s
// share bundle, the slot-s share-bit is bit0(.mac). The AND-output seed draw and
// its seeding sweep are folded into beaver_pass (one circuit walk for both).
void C2PC::draw_and_seed(ComputeCtx &ctx) {
  const int num_ands = ctx.num_ands;
#ifdef AG2PC_PROFILE
  int64_t _all0 = io_count(send_io, recv_io);
  uint64_t _cot0 = g_ag2pc_cot_bytes, _phi0 = g_ag2pc_phi_bytes;
#endif
  fpre->draw(num_ands, ctx.ANDS_bundle);
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
  // Step 4 (folded in): draw the AND-output seed shares and seed them during this
  // same share-prop sweep — fabric slots are recycled here, so seeding in a
  // separate earlier pass would just walk the circuit twice. preprocess_bundle
  // frees at function end, before the heavy garble allocations.
  AG2PC_TP_BEGIN();
  AShareBundleVec preprocess_bundle;
  fpre->draw(num_ands, preprocess_bundle);
  AG2PC_TP("aShare draw (AND-out masks)");
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
        WIRE(g.out) = preprocess_bundle[ai];  // seed AND-output share state
      } else if (g.is_not()) {
        WIRE(g.out) = WIRE(g.in0);
      } else {  // XOR
        xor_share(WIRE(g.out), WIRE(g.in0), WIRE(g.in1));
      }
    }
  }
  AG2PC_TP("share-prop + x/y masks");
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
  AG2PC_TP("x/y exchange");
  { const int i = 2;
    for (int j = 0; j < num_ands; ++j) {
      x[1][j] = x[1][j] ^ x[i][j];
      y[1][j] = y[1][j] ^ y[i][j];
    } }
  {
    block dxor = Delta ^ bit0_mask;
    // σ depends only on ai-indexed data (ANDS_bundle + the exchanged x/y), never
    // on wire structure, so this is a tight per-AND loop, not a gate sweep.
    for (int ai = 0; ai < num_ands; ++ai) {
      AShareBundle &sb = sigma[ai];
      const TripleBundle &tb = ANDS_bundle[ai];
      bool xb = x[1][ai], yb = y[1][ai];
      // Beaver select-XOR on both fields: σ = ANDS[2] ⊕ (xb?ANDS[1]) ⊕ (yb?ANDS[0]).
      sb.mac = tb.b[2].mac ^ (select_mask[xb] & tb.b[1].mac)
                           ^ (select_mask[yb] & tb.b[0].mac);
      sb.key = tb.b[2].key ^ (select_mask[xb] & tb.b[1].key)
                           ^ (select_mask[yb] & tb.b[0].key);
      // λ_{αβ} ⊕= 1 correction, gated on xb·yb: P1 flips bit0(mac), peer flips
      // key by (Δ ⊕ e_0). The party split is loop-invariant; only xb·yb is data.
      block both = select_mask[xb & yb];
      if (party != 1) sb.key = sb.key ^ (both & dxor);
      else            sb.mac = sb.mac ^ (both & bit0_mask);
    }
  }
  AG2PC_TP("sigma derive");
}

// Steps 6-7: the garbler P2 garbles each AND gate and ships to P1. Per gate γ:
//   G_buf[2γ..)     = (G_{γ,0}^2, G_{γ,1}^2)
//   b_buf[γ]        = LSB1(m_{γ,0}^2)
// With a single garbler there are no cross-garbler S_{γ,*}^{i,j} terms.
// Half-gate hash uses MITCCRH (eprint/2019/1168): H_τ(x) = σ(x) ⊕
// AES_{start_point ⊕ τ}(σ(x)). gid auto-increment mode (BatchSize 8): one
// hash_cir per AND advances the gid by one on both garbler and evaluator (same
// gate order, K=1), so they share the per-gate tweak τ = makeBlock(gid,0) with
// no per-gate re-key — MITCCRH schedules the keys 8-wide every 8 gates.
void C2PC::garble_and_ship(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto LABEL = [&](int w) -> block & { return ctx.LABEL(w); };
  auto &sigma = ctx.sigma;
  auto &mitc = ctx.mitc;
  {
    // Ship G in chunks of kGarbleChunk AND gates (in and_index order) so the
    // full-circuit G buffer never materializes; the send is one-directional
    // (P2 -> P1), so chunking adds flushes but no extra rounds.
    const int C = kGarbleChunk;
    const int cap = std::min(C, num_ands);
    BlockVec G_chunk(2 * cap);
    std::vector<unsigned char> b_chunk(party == 2 ? cap : 0);
    int nfilled = 0;
    auto flush_chunk = [&]() {
      if (nfilled == 0) return;
      send_io->send_data(G_chunk.data(), (size_t)2 * nfilled * sizeof(block));
      if (party == 2) send_io->send_data(b_chunk.data(), nfilled);
      send_io->flush();
      nfilled = 0;
    };

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

      // Single garbler's (s=2,d=2) self hashes. gid auto-increment mode: one
      // hash_cir per AND (K=1), so the key counter stays in lockstep with the
      // evaluator's hash_cir<1,2> and both derive the same per-gate tweak; the
      // key schedule batches 8-wide every 8 gates inside MITCCRH.
      block buf[4] = {ml_a0, ml_a1, ml_b0, ml_b1};
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
      G_chunk[2 * nfilled]     = G0;
      G_chunk[2 * nfilled + 1] = G1;
      if (party == 2) b_chunk[nfilled] = (unsigned char)(LSB1(ml_g0));
      if (++nfilled == C) flush_chunk();
    }
    flush_chunk();
  }
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
  const int num_ands = ctx.num_ands;
  // Stream the garbled tables: recv one kGarbleChunk-AND-gate chunk at a time,
  // on demand as evaluation reaches each AND gate (in and_index order), so the
  // full-circuit G buffer never materializes.
  const int C = kGarbleChunk;
  const int cap = std::min(C, num_ands);
  BlockVec G_chunk(2 * cap);
  std::vector<unsigned char> b_chunk(cap);
  int chunk_base = 0, chunk_len = 0;   // current chunk covers ai in [base, base+len)
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
        if (ai >= chunk_base + chunk_len) {        // pull the next garbled-table chunk
          chunk_base += chunk_len;
          chunk_len = std::min(C, num_ands - chunk_base);
          recv_io->recv_data(G_chunk.data(), (size_t)2 * chunk_len * sizeof(block));
          recv_io->recv_data(b_chunk.data(), chunk_len);
        }
        const int loc = ai - chunk_base;
        bool La = mask_input[in0], Lb = mask_input[in1];
        const AShareBundle &wb_in0 = WIRE(in0);
        const AShareBundle &wb_in1 = WIRE(in1);
        const AShareBundle &wb_out = WIRE(out);
        const AShareBundle &sb     = sigma[ai];
        block Mr;  // M_2[r^1]: the single (sender=1, receiver=2) cross term
        { block t = sb.mac ^ wb_out.mac;
          t = t ^ (select_mask[La] & wb_in1.mac);
          t = t ^ (select_mask[Lb] & wb_in0.mac);
          Mr = t;
        }
        // Pass 1: the single garbler's (s=2, d=2) self hashes — one hash_cir
        // (gid auto-increment, lockstep with the garbler); cache for pass 2.
        block self_Ha, self_Hb;
        { block buf[2] = {EVAL(in0), EVAL(in1)};
          mitc.template hash_cir<1, 2>(buf);
          self_Ha = buf[0];
          self_Hb = buf[1];
        }
        // Pass 2: combine the cached self hashes with G + the Mr cross term to
        // produce the eval-label at out.
        { block t = self_Ha ^ self_Hb;
          t = t ^ (select_mask[La] & G_chunk[2 * loc]);
          t = t ^ (select_mask[Lb] & (G_chunk[2 * loc + 1] ^ EVAL(in0)));
          t = t ^ Mr;  // the single cross term (sender s = 1, receiver = 2)
          EVAL(out) = t;
        }
        mask_input[out] =
            (unsigned char)(b_chunk[loc] ^ LSB1(EVAL(out)));
      }
    }
  }
}

// KRRW Figure 3 correctness check (steps 6-8), specialized to 2 parties. After
// evaluation P1 holds the public masked value ẑ_w = z_w ⊕ λ_w of every wire.
//   Step 6: P1 broadcasts the AND-output ẑ (Lambda_AND); P2 derives the rest by
//     propagation (XOR/NOT masks are linear).
//   Step 7: each party forms its authenticated share of the check bit
//     c_γ = (ẑ_α⊕λ_α)∧(ẑ_β⊕λ_β) ⊕ (ẑ_γ⊕λ_γ) = z_α z_β ⊕ z_γ, which is 0 on a
//     correct gate. c_γ is affine in the authenticated masks (λ_α,λ_β,λ_γ and
//     λ*_γ=λ_α∧λ_β via σ), so the share — its MAC term M1_t[ai] — is local: pure
//     bit-ops + 128-bit XORs, no gfmul.
//   Step 8: "c_γ = 0 for all γ" is, for 2 parties, exactly M1_t^{P1} == M1_t^{P2}
//     (their XOR is c_γ·Δ). So P2 sends H(M1_t) and P1 compares to its own; P1
//     never reveals its digest, so the equality test is rush-safe (P2 cannot
//     forge a hash over P1's secret keys). No universal hash / random-linear
//     combination — that batching is only needed to open ⊕_p across >2 parties.
void C2PC::check_cgamma(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto &mask_input = ctx.mask_input;
  auto &sigma = ctx.sigma;
  std::vector<unsigned char> Lambda_AND(num_ands);
  BlockVec M1_t(num_ands);

  if (party == 1) {
    // Steps 6+7: one bit-op sweep — recompute fabric shares, gather each AND
    // output's masked value ẑ, and form its c_γ MAC term M1_t.
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (!g.is_and()) {  // recompute fabric share for downstream ANDs
        if (g.is_not()) { WIRE(out) = WIRE(in0); }
        else { xor_share(WIRE(out), WIRE(in0), WIRE(in1)); }
        continue;
      }
      int ai = g.and_index();
      bool La = mask_input[in0], Lb = mask_input[in1], Lg = mask_input[out];
      Lambda_AND[ai] = (unsigned char)Lg;  // step 6: ẑ of this AND output
      bool v_in0 = (bool)LSB(WIRE(in0).mac);
      bool v_in1 = (bool)LSB(WIRE(in1).mac);
      bool v_out = (bool)LSB(WIRE(out).mac);
      bool v_sig = (bool)LSB(sigma[ai].mac);
      bool t1 = (La & Lb) ^ Lg ^ (La & v_in1) ^ (Lb & v_in0) ^ v_sig ^ v_out;
      block m = select_mask[t1] & Delta;
      const AShareBundle &wb_in0 = WIRE(in0);
      const AShareBundle &wb_in1 = WIRE(in1);
      const AShareBundle &wb_out = WIRE(out);
      const AShareBundle &sb     = sigma[ai];
      m = m ^ (select_mask[La] & wb_in1.key);
      m = m ^ (select_mask[Lb] & wb_in0.key);
      m = m ^ sb.key ^ wb_out.key;
      M1_t[ai] = m;
    }
    io->send_bool((const bool *)Lambda_AND.data(), num_ands);  // step 6: 1 bit/AND
    io->flush();
    // Step 8: c_γ = 0 ∀γ ⟺ M1_t^{P1} == M1_t^{P2}; compare digests (rush-safe).
    char D1[Hash::DIGEST_SIZE], D2[Hash::DIGEST_SIZE];
    Hash::hash_once(D1, M1_t.data(), (size_t)num_ands * sizeof(block));
    io->recv_data(D2, Hash::DIGEST_SIZE);
    if (memcmp(D1, D2, Hash::DIGEST_SIZE) != 0)
      error("cheat in c_gamma check (KRRW Fig.3)");
  } else {
    io->recv_bool((bool *)Lambda_AND.data(), num_ands);  // step 6
    // Steps 6+7: propagate masks from the broadcast ẑ, recompute fabric shares,
    // form each AND's c_γ MAC term M1_t. The t_γ term reads the input masks set
    // earlier in this same gate-ordered sweep.
    for (int gi = 0; gi < cf->num_gate; ++gi) {
      const Gate &g = cf->gates[gi];
      int in0 = g.in0, in1 = g.in1, out = g.out;
      if (!g.is_and()) {
        if (g.is_not()) {
          mask_input[out] = mask_input[in0] ^ 1;
          WIRE(out) = WIRE(in0);
        } else {  // XOR
          mask_input[out] = mask_input[in0] ^ mask_input[in1];
          xor_share(WIRE(out), WIRE(in0), WIRE(in1));
        }
        continue;
      }
      int ai = g.and_index();
      mask_input[out] = Lambda_AND[ai];  // AND output ẑ from P1's broadcast
      bool La = mask_input[in0], Lb = mask_input[in1];
      block m = sigma[ai].mac ^ WIRE(out).mac;
      m = m ^ (select_mask[La] & WIRE(in1).mac);
      m = m ^ (select_mask[Lb] & WIRE(in0).mac);
      M1_t[ai] = m;
    }
    // Step 8: send P2's c_γ MAC digest for P1 to compare.
    char D2[Hash::DIGEST_SIZE];
    Hash::hash_once(D2, M1_t.data(), (size_t)num_ands * sizeof(block));
    io->send_data(D2, Hash::DIGEST_SIZE);
    io->flush();
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
      io->send_data(buf.data(), n);
      io->flush();
      return v;
    }
    io->recv_data(buf.data(), n);
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
    io->send_data(my_share.data(), n);
    io->flush();
  } else {
    result.resize(n);
    std::vector<unsigned char> tmp(n);
    io->recv_data(tmp.data(), n);
    for (int i = 0; i < n; ++i) {
      unsigned char v = my_share[i] ^ wires.Lambda[i] ^ tmp[i];
      result[i] = (v & 1);
    }
  }
  AG2PC_PHASE("decode[step14]");
  return result;
}

#endif // C2PC_H__
