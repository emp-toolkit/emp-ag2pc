#ifndef C2PC_H__
#define C2PC_H__
#include "emp-ag2pc/triple_pool.h"
#include "emp-ag2pc/profiling.h"
#include "emp-tool/io/net_io_channel.h"
#include "emp-ag2pc/share_bundle.h"
#include "emp-ag2pc/circuit_layout.h"
#include "emp-ag2pc/wire_graph.h"
#include <array>
#include <vector>
using namespace emp;

// Two-party authenticated garbling protocol Π_MPC of agc.tex
// (Figures P:MPC-1, P:MPC-2, P:MPC-3) specialized to two parties. Role
// convention in this codebase: **party 1 is the garbler, party 2 is the
// evaluator** (note this is the inverse of agc.tex's Pi convention, where P1 is
// the evaluator and Pi (i ≥ 2) are garblers; agc.tex superscripts in formulas
// below have been renumbered to this codebase's convention).
//
// The half-gate construction: the garbler P1 sends 2 ciphertexts G_{γ,0/1}^1
// (no cross-peer S terms with a single garbler) plus b_γ; the evaluator P2
// recovers Λ_γ = b_γ ⊕ LSB1(m_{γ,Λ_γ}^1). The bit-1 Δ convention is set in
// TriplePool::init_abit_: bit1(Δ_1) = 1 and bit1(Δ_2) = 0, so
// bit1(Δ_1 ⊕ Δ_2) = 1. Bit 0 is reserved for share-value encoding.
//
// API:
//   process_inputs(owners, bits_per_owner) → SecureWires[]  // KRRW Fig.3 inputs
//   compute(WireGraph, inputs)             → SecureWires    // steps 4-13
//   decode(wires, recipient)               → vector<bool>   // step 14
//
// Output wires of compute() carry full SecureWire state. process_inputs() and
// compute() draw aShares from TriplePool (COT-minted) and build each AND gate's
// σ = λ_α∧λ_β in place via TriplePool::compute_inplace (no generic triple pool).
// The frontend (a recording backend, see ag2pc_backend.h) drives this from native
// Bit/Integer code; circuits are consumed as WireGraph, not BristolFormat.

class C2PC {
public:
  // Long-lived setup: TriplePool (COT mesh + Δ). Constructed once per session and
  // reused across all process_inputs / compute / decode calls; it holds the COT
  // session open across compute() calls and runs the COT consistency check before
  // each reveal (decode) so the check gates output release.
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

  // Takes a single NetIO; spawns and owns the sibling channel. ssp is the
  // statistical security parameter forwarded to TriplePool (bucket sizing).
  C2PC(NetIO *io, ThreadPool *pool_, int party_, int ssp = 40)
      : io(io), sib_owned(io->make_sibling()), sib(sib_owned.get()),
        send_io(party_ == 1 ? io : sib_owned.get()),
        recv_io(party_ == 1 ? sib_owned.get() : io),
        pool(pool_), party(party_) {
    fpre = new TriplePool(io, sib_owned.get(), pool_, party_, ssp);
    Delta = fpre->Delta;
  }
  ~C2PC() { delete fpre; }

  // ====== New API ======

  // KRRW Fig.3 input phase, batched across both owners' input wires in a
  // single protocol call. owners[k] is the owner for bits_per_owner[k]
  // (length K, typically 1 or 2); returns K SecureWires bundles, one per
  // owner. Internally:
  //   - fpre->draw mints all n_total authenticated λ-shares (one COT batch)
  //   - the garbler samples m_{w, 0} for every wire
  //   - authenticated share open: each party ships (its λ^self bits + Hash of
  //     the matching MACs) plus, in the same message, the x_w bits for the
  //     wires it owns. Sent in parallel on the duplex pair so the whole
  //     exchange is one one-way latency. Hashes are verified before Γ is used.
  //   - the garbler ships m_{w,Γ_w} = label0 ⊕ Γ_w·Δ for all wires (one-way).
  // Net: 2 message rounds (~1 RTT) for the whole input phase, regardless of
  // owner count.
  std::vector<SecureWires> process_inputs(
      const std::vector<int> &owners,
      const std::vector<std::vector<bool>> &bits_per_owner);

  // Steps 4-13 of agc.tex on a WireGraph. Input bundles must already be
  // process_inputs'd and supplied in WireGraph.inputs (per-owner) order; they
  // occupy wires [0, num_in). Mints each AND gate's σ-share (compute_inplace) and
  // fresh λ_γ output masks inside this call. Aborts via error() on
  // cheating-detection failure. Outputs are extracted by explicit id
  // (g.output_ids), in that order; output wires carry full state.
  SecureWires compute(const WireGraph &g,
                          const std::vector<SecureWires> &inputs);

  // Step 14 (output decode): all Pi ≠ recipient send λ_w^p to recipient;
  // recipient computes y_w = Λ_w ⊕ λ_w. Returns the n cleartext bits at
  // `recipient`; empty vector at non-recipients.
  std::vector<bool> decode(const SecureWires &wires, int recipient);

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
    BlockVec label_slot;                    // m_{w,0} at the garbler P1, by slot
    BlockVec eval_slot;                // m_{w,Λ} at the evaluator P2 (single garbler P1)
    AShareBundleVec rep_a, rep_b;       // each AND gate's input masks λ_α, λ_β (by and_index)
    AShareBundleVec lambda_gamma;       // fresh AND-output masks λ_γ (by and_index)
    AShareBundleVec sigma;              // σ = λ_α∧λ_β from the in-place leaky-AND
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
  // step 4-5: one share-prop sweep that seeds each AND output's fresh mask λ_γ and
  // materializes every AND gate's input masks (λ_α, λ_β) into rep_a/rep_b, which the
  // in-place leaky-AND then consumes (no generic triple, no Beaver x/y exchange).
  void collect_masks(ComputeCtx &ctx);
  // Garbled tables are streamed: garble_and_ship sends them in kGarbleChunk-
  // AND-gate chunks; evaluate recvs each chunk on demand during evaluation,
  // so neither side ever holds the full-circuit G buffer.
  static constexpr int kGarbleChunk = 1 << 16;
  void garble_and_ship(ComputeCtx &ctx);        // steps 6-7, garbler P1
  void evaluate(ComputeCtx &ctx);               // steps 6-7 recv + step 10, evaluator P2
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

std::vector<SecureWires> C2PC::process_inputs(
    const std::vector<int> &owners,
    const std::vector<std::vector<bool>> &bits_per_owner) {
  AG2PC_PHASE_BEGIN();
  const int K = (int)owners.size();
  int n_total = 0;
  std::vector<int> off_per_owner(K);
  for (int k = 0; k < K; ++k) {
    off_per_owner[k] = n_total;
    n_total += (int)bits_per_owner[k].size();
  }
  if (n_total == 0) {
    AG2PC_PHASE("process_inputs");
    return std::vector<SecureWires>(K);
  }

  // Combined bundle for every input wire across all owners.
  SecureWires sw;
  sw.Lambda.resize(n_total);
  sw.wire_bundle.resize(n_total);
  if (party == 1) sw.label0.resize(n_total);          // garbler
  else            sw.eval_label.resize(n_total);      // evaluator

  // Step 3 (Π_aShare): n_total authenticated λ-shares from the open COT
  // session. One draw covers both owners.
  fpre->draw(n_total, sw.wire_bundle);

  // Step 3 (cont.): the garbler samples m_{w,0} for every wire.
  if (party == 1) prg.random_block(sw.label0.data(), n_total);

  // Per-wire metadata: which owner, and the x_w bit for wires this party owns
  // (zero for wires this party doesn't own — those x's are folded in by the
  // peer in their own message below).
  std::vector<int> owner_of_wire(n_total);
  std::vector<unsigned char> own_x_bits(n_total, 0);
  for (int k = 0; k < K; ++k) {
    int o = owners[k];
    bool i_own = (o == party);
    for (size_t i = 0; i < bits_per_owner[k].size(); ++i) {
      int idx = off_per_owner[k] + (int)i;
      owner_of_wire[idx] = o;
      if (i_own) own_x_bits[idx] = (unsigned char)bits_per_owner[k][i];
    }
  }

  // KRRW Fig.3 authenticated share open + (folded into the same message) the
  // owner's x_w bits, both directions in parallel on the duplex pair.
  //
  // Each party ships:
  //   (a) λ^self bits for ALL wires (n_total bytes) — the raw share open
  //   (b) Hash of the matching MACs (DIGEST_SIZE bytes) — authenticates (a);
  //       peer recomputes expected MAC = K_peer ⊕ bit · Δ_peer from its own
  //       wire_bundle.key + Delta, hashes those, compares — abort on mismatch.
  //   (c) own_x_bits packed for wires this party owns (n_owned bytes) — the
  //       unauthenticated owner contribution Γ_w := x_w ⊕ λ_w gets folded in
  //       by the recipient using (a) + own λ^self below. Γ_w itself is bound
  //       downstream by the c_γ check that runs at chunk end.
  std::vector<unsigned char> share_msg(n_total);
  BlockVec my_macs(n_total);
  for (int i = 0; i < n_total; ++i) {
    share_msg[i] = (unsigned char)LSB(sw.wire_bundle[i].mac);
    my_macs[i]   = sw.wire_bundle[i].mac;
  }
  char D_me[Hash::DIGEST_SIZE];
  Hash::hash_once(D_me, my_macs.data(), (size_t)n_total * sizeof(block));

  std::vector<unsigned char> own_x_packed;
  std::vector<int> peer_idx_list;             // wire indices peer owns
  for (int i = 0; i < n_total; ++i) {
    if (owner_of_wire[i] == party) own_x_packed.push_back(own_x_bits[i]);
    else                            peer_idx_list.push_back(i);
  }

  std::vector<unsigned char> peer_share(n_total);
  char D_peer[Hash::DIGEST_SIZE];
  std::vector<unsigned char> peer_x_packed(peer_idx_list.size());
  {
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([&]() {
      send_io->send_data(share_msg.data(), n_total);
      send_io->send_data(D_me, Hash::DIGEST_SIZE);
      if (!own_x_packed.empty())
        send_io->send_data(own_x_packed.data(), own_x_packed.size());
      send_io->flush();
    }));
    res.push_back(pool->enqueue([&]() {
      recv_io->recv_data(peer_share.data(), n_total);
      recv_io->recv_data(D_peer, Hash::DIGEST_SIZE);
      if (!peer_x_packed.empty())
        recv_io->recv_data(peer_x_packed.data(), peer_x_packed.size());
    }));
    joinNclean(res);
  }

  // Verify peer's MAC hash before using their share.
  BlockVec exp_macs(n_total);
  for (int i = 0; i < n_total; ++i)
    exp_macs[i] = sw.wire_bundle[i].key ^ (select_mask[peer_share[i]] & Delta);
  char D_exp[Hash::DIGEST_SIZE];
  Hash::hash_once(D_exp, exp_macs.data(), (size_t)n_total * sizeof(block));
  if (memcmp(D_exp, D_peer, Hash::DIGEST_SIZE) != 0)
    error("process_inputs: peer share-MAC hash mismatch");

  // Reconstruct Γ_w = λ_w ⊕ x_w = (λ^self ⊕ λ^peer) ⊕ x_w for every wire.
  // own_x_bits is 0 for peer-owned, so this folds in my own x only.
  for (int i = 0; i < n_total; ++i)
    sw.Lambda[i] = (unsigned char)(share_msg[i] ^ peer_share[i] ^ own_x_bits[i]);
  // Add peer's x bits for the wires they own.
  for (size_t i = 0; i < peer_idx_list.size(); ++i)
    sw.Lambda[peer_idx_list[i]] ^= peer_x_packed[i];

  // Garbler ships m_{w,Γ_w} for every input wire.
  if (party == 1) {
    BlockVec labels(n_total);
    for (int i = 0; i < n_total; ++i)
      labels[i] = sw.label0[i] ^ (select_mask[sw.Lambda[i]] & Delta);
    io->send_data(labels.data(), (size_t)n_total * sizeof(block));
    io->flush();
  } else {
    io->recv_data(sw.eval_label.data(), (size_t)n_total * sizeof(block));
  }
  AG2PC_PHASE("process_inputs");

  // Slice the combined bundle back into per-owner SecureWires.
  std::vector<SecureWires> result(K);
  for (int k = 0; k < K; ++k) {
    int off = off_per_owner[k];
    int n = (int)bits_per_owner[k].size();
    result[k] = sw.slice((size_t)off, (size_t)(off + n));
  }
  return result;
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
  if (party == 1) ctx.label_slot.resize(ctx.num_slots);  // garbler
  else ctx.eval_slot.resize(ctx.num_slots);              // evaluator

  AG2PC_PHASE_BEGIN();
  load_inputs(ctx, inputs, n_inputs);     AG2PC_PHASE("load_inputs");
  // Step 4: fresh AND-output masks λ_γ. Step 5a: one share-prop sweep seeds them and
  // materializes every AND gate's input masks (λ_α,λ_β). Step 5b: the in-place
  // leaky-AND turns those into σ=λ_α∧λ_β directly — no generic triple, no Beaver.
  fpre->draw(ctx.num_ands, ctx.lambda_gamma); AG2PC_PHASE("draw lambda_gamma[step4]");
  collect_masks(ctx);                      AG2PC_PHASE("collect_masks[step5a]");
  fpre->compute_inplace(ctx.rep_a, ctx.rep_b, ctx.num_ands, ctx.sigma);
  AG2PC_PHASE("inplace_triples[step5b]");
  // Half-gate hash start point: drawn fresh from the FS transcript (identical on
  // both parties via get_digest's canonical d_AB‖d_BA; advances every reactive
  // round so the gid-derived gate tweaks never repeat).
  ctx.mitc.setS(RO("AG2PC half-gate", zero_block)
                    .absorb(io->get_digest()).absorb(sib->get_digest())
                    .squeeze_block());
  if (party == 1) garble_and_ship(ctx);    // steps 6-7: garbler P1 ships G in chunks
  AG2PC_PHASE("garble[step6-7]");
  if (party != 1) evaluate(ctx);           // evaluator P2 streams G in and evaluates
  AG2PC_PHASE("evaluate[step10]");
  check_cgamma(ctx);                       AG2PC_PHASE("check[c_gamma]");
  // Run the deferred COT subspace-VOLE check now (only fires if this chunk
  // actually minted COTs). Pulls the per-reveal check up to chunk-end so
  // back-to-back reveals with no new gates between them share a single check.
  fpre->maybe_flush_cot_check();           AG2PC_PHASE("cot_check");
  SecureWires r = gather_outputs(ctx, output_ids);  AG2PC_PHASE("gather_outputs");
#ifdef AG2PC_PROFILE
  if (party == 1) {
    const double A = (double)std::max(1, ctx.num_ands);
    printf("[ag2pc-mem] ComputeCtx  num_wire=%d num_slots=%d num_ands=%d "
           "num_gate=%d\n", cf->num_wire, ctx.num_slots, ctx.num_ands, cf->num_gate);
    ag2pc_mem_row("phys",         (double)ctx.phys.capacity() * sizeof(int), A);
    ag2pc_mem_row("mask_input",   (double)ctx.mask_input.capacity(), A);
    ag2pc_mem_row("wire_slot",    (double)ctx.wire_slot.capacity() * sizeof(AShareBundle), A);
    ag2pc_mem_row("eval/label",   (double)(party == 1 ? ctx.label_slot.capacity()
                                  : ctx.eval_slot.capacity()) * sizeof(block), A);
    ag2pc_mem_row("rep_a+rep_b",  (double)(ctx.rep_a.capacity() + ctx.rep_b.capacity()) * sizeof(AShareBundle), A);
    ag2pc_mem_row("lambda_gamma", (double)ctx.lambda_gamma.capacity() * sizeof(AShareBundle), A);
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
    if (party == 1) {              // garbler holds m_{w,0} in label0
      memcpy(ctx.label_slot.data() + off, in.label0.data(), n * sizeof(block));
    } else {                         // evaluator holds m_{w,Λ_w} in eval_label
      memcpy(ctx.eval_slot.data() + off, in.eval_label.data(),
             n * sizeof(block));
    }
    off += n;
  }
}

// Step 4-5a: one share-prop sweep. Free-XOR/NOT propagate each wire's share bundle
// (fabric wires recycle within the sweep, so this must materialize per-AND data as
// it goes — a later pass would read stale slots). For every AND gate it copies the
// (now-live) input masks λ_α,λ_β into rep_a/rep_b and seeds the output wire with a
// fresh mask λ_γ. The in-place leaky-AND (TriplePool::compute_inplace) then consumes
// rep_a/rep_b to build σ=λ_α∧λ_β directly — no generic triple, no Beaver x/y exchange.
void C2PC::collect_masks(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  ctx.rep_a.resize(num_ands);
  ctx.rep_b.resize(num_ands);
  AG2PC_TP_BEGIN();
  for (int gi = 0; gi < cf->num_gate; ++gi) {
    const Gate &g = cf->gates[gi];
    if (g.is_and()) {
      int ai = g.and_index();
      ctx.rep_a[ai] = WIRE(g.in0);            // λ_α (value copy survives slot recycle)
      ctx.rep_b[ai] = WIRE(g.in1);            // λ_β
      WIRE(g.out) = ctx.lambda_gamma[ai];     // seed fresh AND-output mask λ_γ
    } else if (g.is_not()) {
      WIRE(g.out) = WIRE(g.in0);
    } else {  // XOR
      xor_share(WIRE(g.out), WIRE(g.in0), WIRE(g.in1));
    }
  }
  AG2PC_TP("share-prop + collect rep masks");
}

// Steps 6-7: the garbler P1 garbles each AND gate and ships to the evaluator
// P2. Per gate γ:
//   G_buf[2γ..)     = (G_{γ,0}^1, G_{γ,1}^1)
//   b_buf[γ]        = LSB1(m_{γ,0}^1)
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
  // Ship G in chunks of kGarbleChunk AND gates (in and_index order) so the
  // full-circuit G buffer never materializes; the send is one-directional
  // (P1 -> P2), so chunking adds flushes but no extra rounds. The compute
  // (this thread) fills chunks into the pipe; a pool thread drains them with
  // blocking send + flush, so the next chunk's hashes overlap the previous
  // chunk's send.
  struct GarbleChunk {
    BlockVec G;
    std::vector<unsigned char> b;
    int nfilled = 0;
  };
  const int C = kGarbleChunk;
  const int cap = std::min(C, num_ands);
  chunk_pipe<GarbleChunk> pipe(2, [&](GarbleChunk &c) {
    c.G.resize(2 * cap);
    c.b.resize(cap);    // garbler always ships b (this function only runs at P1)
  });
  auto sender_fut = pool->enqueue([&] {
    while (auto *slot = pipe.consumer_slot()) {
      send_io->send_data(slot->G.data(), (size_t)2 * slot->nfilled * sizeof(block));
      send_io->send_data(slot->b.data(), slot->nfilled);
      send_io->flush();
      pipe.consumer_release();
    }
  });

  GarbleChunk *cur = &pipe.producer_slot();
  cur->nfilled = 0;
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

    // Single garbler's (s=1,d=1) self hashes. gid auto-increment mode: one
    // hash_cir per AND (K=1), so the key counter stays in lockstep with the
    // evaluator's hash_cir<1,2> and both derive the same per-gate tweak; the
    // key schedule batches 8-wide every 8 gates inside MITCCRH.
    block buf[4] = {ml_a0, ml_a1, ml_b0, ml_b1};
    mitc.template hash_cir<1, 4>(buf);

    const AShareBundle &wb_in0 = WIRE(in0);
    const AShareBundle &wb_in1 = WIRE(in1);
    const AShareBundle &wb_out = WIRE(out);
    const AShareBundle &sb     = sigma[ai];

    // Single garbler (d == party == 1): only the self tweak fires, so the
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
    cur->G[2 * cur->nfilled]     = G0;
    cur->G[2 * cur->nfilled + 1] = G1;
    cur->b[cur->nfilled] = (unsigned char)(LSB1(ml_g0));
    if (++cur->nfilled == C) {
      pipe.producer_publish();
      cur = &pipe.producer_slot();
      cur->nfilled = 0;
    }
  }
  if (cur->nfilled > 0) pipe.producer_publish();
  pipe.producer_close();
  sender_fut.get();
}

// Step 10: the evaluator P2 walks each gate topologically, recovering
// eval-labels and the public mask. XOR/NOT propagate locally; AND combines the
// received G ciphertexts with the half-gate hashes. Called only at the
// evaluator (P2).
void C2PC::evaluate(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto EVAL = [&](int w) -> block & { return ctx.EVAL(w); };
  auto &mask_input = ctx.mask_input;
  auto &sigma = ctx.sigma;
  auto &mitc = ctx.mitc;
  const int num_ands = ctx.num_ands;
  // Stream the garbled tables: a pool thread blocks on recv one
  // kGarbleChunk-AND-gate chunk at a time and hands it to the compute loop via
  // the pipe; the compute loop drains chunks in and_index order. The depth-2
  // pipe lets the next chunk arrive while the current one is being evaluated,
  // so the recv stall overlaps the per-AND hash work.
  struct EvalChunk {
    BlockVec G;
    std::vector<unsigned char> b;
    int len = 0;
  };
  const int C = kGarbleChunk;
  const int cap = std::min(C, num_ands);
  chunk_pipe<EvalChunk> pipe(2, [&](EvalChunk &c) {
    c.G.resize(2 * cap);
    c.b.resize(cap);
  });
  auto recv_fut = pool->enqueue([&] {
    int recv_base = 0;
    while (recv_base < num_ands) {
      EvalChunk &slot = pipe.producer_slot();
      slot.len = std::min(C, num_ands - recv_base);
      recv_io->recv_data(slot.G.data(), (size_t)2 * slot.len * sizeof(block));
      recv_io->recv_data(slot.b.data(), slot.len);
      pipe.producer_publish();
      recv_base += slot.len;
    }
    pipe.producer_close();
  });

  EvalChunk *cur = nullptr;
  int loc = 0;  // ai within cur (0 .. cur->len)
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
      continue;
    }
    if (cur == nullptr || loc == cur->len) {     // drain the next chunk
      if (cur != nullptr) pipe.consumer_release();
      cur = pipe.consumer_slot();                // recv side has more by induction
      loc = 0;
    }
    bool La = mask_input[in0], Lb = mask_input[in1];
    const AShareBundle &wb_in0 = WIRE(in0);
    const AShareBundle &wb_in1 = WIRE(in1);
    const AShareBundle &wb_out = WIRE(out);
    const AShareBundle &sb     = sigma[g.and_index()];
    block Mr;  // M_1[r^2]: the single (sender=2, receiver=1) cross term
    { block t = sb.mac ^ wb_out.mac;
      t = t ^ (select_mask[La] & wb_in1.mac);
      t = t ^ (select_mask[Lb] & wb_in0.mac);
      Mr = t;
    }
    // Pass 1: the single garbler's (s=1, d=1) self hashes — one hash_cir
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
      t = t ^ (select_mask[La] & cur->G[2 * loc]);
      t = t ^ (select_mask[Lb] & (cur->G[2 * loc + 1] ^ EVAL(in0)));
      t = t ^ Mr;  // the single cross term (sender s = 2, receiver = 1)
      EVAL(out) = t;
    }
    mask_input[out] =
        (unsigned char)(cur->b[loc] ^ LSB1(EVAL(out)));
    ++loc;
  }
  if (cur != nullptr) pipe.consumer_release();
  recv_fut.get();
}

// KRRW Figure 3 correctness check (steps 6-8), specialized to 2 parties. After
// evaluation the evaluator (P2) holds the public masked value ẑ_w = z_w ⊕ λ_w
// of every wire.
//   Step 6: the evaluator broadcasts the AND-output ẑ (Lambda_AND); the garbler
//     (P1) derives the rest by propagation (XOR/NOT masks are linear).
//   Step 7: each party forms its authenticated share of the check bit
//     c_γ = (ẑ_α⊕λ_α)∧(ẑ_β⊕λ_β) ⊕ (ẑ_γ⊕λ_γ) = z_α z_β ⊕ z_γ, which is 0 on a
//     correct gate. c_γ is affine in the authenticated masks (λ_α,λ_β,λ_γ and
//     λ*_γ=λ_α∧λ_β via σ), so the share — its MAC term M1_t[ai] — is local: pure
//     bit-ops + 128-bit XORs, no gfmul.
//   Step 8: "c_γ = 0 for all γ" is, for 2 parties, exactly M1_t at the garbler
//     == M1_t at the evaluator (their XOR is c_γ·Δ). So the garbler sends
//     H(M1_t) and the evaluator compares to its own; the evaluator never reveals
//     its digest, so the equality test is rush-safe (the garbler cannot forge a
//     hash over the evaluator's secret keys). No universal hash / random-linear
//     combination — that batching is only needed to open ⊕_p across >2 parties.
void C2PC::check_cgamma(ComputeCtx &ctx) {
  const CircuitView *cf = ctx.cf;
  const int num_ands = ctx.num_ands;
  // No ANDs in this chunk → c_γ is vacuous (the check is over γ ∈ AND set).
  // Skip the digest exchange entirely; lets empty chunks (back-to-back
  // reveal-then-reveal with no gates between) cost zero network rounds here.
  if (num_ands == 0) return;
  auto WIRE = [&](int w) -> AShareBundle & { return ctx.WIRE(w); };
  auto &mask_input = ctx.mask_input;
  auto &sigma = ctx.sigma;
  std::vector<unsigned char> Lambda_AND(num_ands);
  BlockVec M1_t(num_ands);

  if (party != 1) {              // evaluator side
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
    // Step 8: c_γ = 0 ∀γ ⟺ M1_t^{eval} == M1_t^{garbler}; compare digests (rush-safe).
    char D1[Hash::DIGEST_SIZE], D2[Hash::DIGEST_SIZE];
    Hash::hash_once(D1, M1_t.data(), (size_t)num_ands * sizeof(block));
    io->recv_data(D2, Hash::DIGEST_SIZE);
    if (memcmp(D1, D2, Hash::DIGEST_SIZE) != 0)
      error("cheat in c_gamma check (KRRW Fig.3)");
  } else {                         // garbler side
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
      mask_input[out] = Lambda_AND[ai];  // AND output ẑ from the evaluator's broadcast
      bool La = mask_input[in0], Lb = mask_input[in1];
      block m = sigma[ai].mac ^ WIRE(out).mac;
      m = m ^ (select_mask[La] & WIRE(in1).mac);
      m = m ^ (select_mask[Lb] & WIRE(in0).mac);
      M1_t[ai] = m;
    }
    // Step 8: send the garbler's c_γ MAC digest for the evaluator to compare.
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
  if (party == 1) {              // garbler holds label0 (m_{w,0})
    out.label0.resize(n3);
    for (int i = 0; i < n3; ++i) out.label0[i] = LABEL(output_ids[i]);
  } else {                         // evaluator holds eval_label (m_{w,Λ_w})
    out.eval_label.resize(n3);
    for (int i = 0; i < n3; ++i) out.eval_label[i] = EVAL(output_ids[i]);
  }
  return out;
}

std::vector<bool> C2PC::decode(const SecureWires &wires,
                                         int recipient) {
  int n = (int)wires.size();
  AG2PC_PHASE_BEGIN();
  // Reveal to ALL parties: reconstruct at the evaluator (P2), then P2 broadcasts.
  // Needed for reactive host branching — every party must learn the same value.
  if (recipient == PUBLIC) {
    std::vector<bool> v = decode(wires, 2);  // only P2 holds it after this
    std::vector<unsigned char> buf(n);
    if (party != 1) {
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
  // Authenticated open of each party's λ-share to the recipient (KRRW Fig.3
  // open). The non-recipient ships (n share bits, Hash(n MACs)); the recipient
  // recomputes the expected MAC for each bit as KEY ⊕ bit·Δ — using its own
  // wire_bundle[i].key plus Delta — hashes those, and compares the digest to
  // the one shipped. A flipped bit forces a flipped MAC (by Δ_peer, which the
  // sender doesn't know), so the digest mismatch aborts here before the secret
  // is consumed. The chunk-level c_γ and COT-correlation checks (run in
  // run_chunk_) gate this in turn: any tampered MAC structure has aborted
  // already, so the only thing the per-reveal hash needs to catch is a sender
  // flipping a bit at decode-time.
  std::vector<unsigned char> my_share(n);
  BlockVec my_macs(n);
  for (int i = 0; i < n; ++i) {
    my_share[i] = (unsigned char)LSB(wires.wire_bundle[i].mac);
    my_macs[i]  = wires.wire_bundle[i].mac;
  }
  if (party != recipient) {
    char D[Hash::DIGEST_SIZE];
    Hash::hash_once(D, my_macs.data(), (size_t)n * sizeof(block));
    io->send_data(my_share.data(), n);
    io->send_data(D, Hash::DIGEST_SIZE);
    io->flush();
  } else {
    result.resize(n);
    std::vector<unsigned char> tmp(n);
    char D_peer[Hash::DIGEST_SIZE];
    io->recv_data(tmp.data(), n);
    io->recv_data(D_peer, Hash::DIGEST_SIZE);
    BlockVec exp_macs(n);
    for (int i = 0; i < n; ++i)
      exp_macs[i] = wires.wire_bundle[i].key ^ (select_mask[tmp[i]] & Delta);
    char D_exp[Hash::DIGEST_SIZE];
    Hash::hash_once(D_exp, exp_macs.data(), (size_t)n * sizeof(block));
    if (memcmp(D_exp, D_peer, Hash::DIGEST_SIZE) != 0)
      error("decode: peer share-MAC hash mismatch");
    for (int i = 0; i < n; ++i) {
      unsigned char v = my_share[i] ^ wires.Lambda[i] ^ tmp[i];
      result[i] = (v & 1);
    }
  }
  AG2PC_PHASE("decode[step14]");
  return result;
}

#endif // C2PC_H__
