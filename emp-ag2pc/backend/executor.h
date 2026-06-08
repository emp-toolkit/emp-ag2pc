#ifndef EMP_AG2PC_EXECUTOR_H__
#define EMP_AG2PC_EXECUTOR_H__

// The AG2PC authenticated-garbling EXECUTOR. AG2PCExecutor drives the protocol
// passes (backend/passes.h) over a single gate-stream SOURCE — the one place the
// 5-pass sequence + inter-pass crypto lives. Two SOURCE kinds feed it:
//   * a stored BooleanProgram (run_program), replayed via emp::execute_program;
//   * a pure circuit body replayed live (run_source + ag2pc_detail::body_replay),
//     once per pass, with no materialized IR.
// Because every pass is the SAME definition driven over the SAME gate stream, the
// transcript is identical across passes AND across the two source kinds.
//
// AG2PCExecutor holds an AG2PCProtocol* (the crypto core) and works purely on
// SecureWires bundles; the typed-value <-> bundle gather/scatter lives in
// AG2PCCtx, which owns the wire-id bookkeeping.

#include "emp-tool/emp-tool.h"                 // RO, Hash, block, NetIO, ThreadPool
#include "emp-tool/context/context.h"         // execute_program, ProgramWorkspace
#include "emp-tool/circuits/value_traits.h"    // value_traits<T>
#include "emp-tool/frontend/circuit_fn.h"      // circuit_fn_traits / circuit_contract / RecordValue
#include "emp-ag2pc/backend/passes.h"          // LambdaState + the 5 passes + canonical check
#include "emp-ag2pc/backend/protocol.h"        // AG2PCProtocol
#include "emp-ag2pc/backend/secure_wires.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace emp {
namespace ag2pc_detail {

// Append one SecureWires bundle onto another (label0 / eval_label only when
// populated — exactly one is, by party).
inline void append_bundle(SecureWires& dst, const SecureWires& s) {
  dst.Lambda.insert(dst.Lambda.end(), s.Lambda.begin(), s.Lambda.end());
  dst.wire_bundle.insert(dst.wire_bundle.end(), s.wire_bundle.begin(),
                         s.wire_bundle.end());
  if (!s.label0.empty())
    dst.label0.insert(dst.label0.end(), s.label0.begin(), s.label0.end());
  if (!s.eval_label.empty())
    dst.eval_label.insert(dst.eval_label.end(), s.eval_label.begin(),
                          s.eval_label.end());
}

// Run one pass over the source, by lvalue reference (a pass is stateful:
// counters, freelist, chunk pipe, sender future — never copy it). begin()/end()
// are detected and called when present (the threaded garble/evaluate passes).
// end() runs via a scope guard so that if source(pass) throws, the chunk pipe is
// still closed and the sender/receiver thread is joined rather than left live.
template <class Pass, class Source>
inline std::vector<uint32_t> run_pass(Pass& pass, Source& source) {
  if constexpr (requires { pass.begin(); }) pass.begin();
  struct EndGuard {
    Pass& p;
    ~EndGuard() { if constexpr (requires { p.end(); }) p.end(); }
  } guard{pass};
  return source(pass);   // EndGuard::~EndGuard() calls p.end() on the way out (normal or exception)
}

// BodySource. Build typed args over `pass` from the input wire ids [0, total),
// invoke the body (both forms: [](auto a, auto b){...} and [](auto& ctx, auto a,
// auto b){...}), and pack the output wire ids. The contract is re-checked against
// the pass (same value types → same verdict as the RecordCtx check at the call site).
// ArgVs are circuit value types over RecordCtx (the rec:: aliases).
template <class F, class Pass, class... AS, std::size_t... I>
inline std::vector<uint32_t> body_replay_impl(Pass& pass, F& body,
                                              std::index_sequence<I...>) {
  using W = typename Pass::Wire;   // uint32_t
  const std::array<int, sizeof...(AS)> widths{{(int)value_traits<AS>::width()...}};
  std::array<int, sizeof...(AS)> base{};
  uint32_t total = 0;
  for (std::size_t k = 0; k < sizeof...(AS); ++k) { base[k] = (int)total; total += (uint32_t)widths[k]; }
  std::vector<W> ids((size_t)total);
  for (uint32_t i = 0; i < total; ++i) ids[i] = (W)i;

  using PassTr = frontend::circuit_fn_traits<Pass, F, typename AS::template rebind<Pass>...>;
  (void)sizeof(frontend::circuit_contract<PassTr>);
  if constexpr (PassTr::ok) {
    std::tuple<typename AS::template rebind<Pass>...> targs{
        AS::template rebind<Pass>::from_wires(pass, ids.data() + base[I])...};
    auto ret = [&] {
      if constexpr (PassTr::wants_ctx)
        return std::apply([&](auto&&... a) { return body(pass, std::move(a)...); }, targs);
      else
        return std::apply([&](auto&&... a) { return body(std::move(a)...); }, targs);
    }();
    using Ret = std::decay_t<decltype(ret)>;
    std::array<W, (std::size_t)Ret::width()> ow{};
    ret.pack_wires(ow.data());
    return std::vector<uint32_t>(ow.begin(), ow.end());
  } else {
    return {};
  }
}
template <class... AS, class F, class Pass>
inline std::vector<uint32_t> body_replay(Pass& pass, F& body) {
  return body_replay_impl<F, Pass, AS...>(pass, body, std::index_sequence_for<AS...>{});
}

}  // namespace ag2pc_detail

// ===========================================================================
// AG2PCExecutor — runs a BooleanProgram or a live body source through the five
// authenticated-garbling passes over an AG2PCProtocol.
// ===========================================================================
struct AG2PCExecutor {
  AG2PCProtocol* proto = nullptr;
  uint64_t total_ands = 0;   // garbled ANDs across every run (post-DCE), all strategies

  // The 5-pass core. Sequences liveness -> input load -> size/mask collect ->
  // triples -> garble/evaluate -> c_gamma -> COT check -> gather, driving every
  // pass over the SAME source.
  template <class Source>
  SecureWires run_source(const SecureWires& in_wires, Source& source) {
    AG2PCProtocol* mpc = proto;
    int num_in = (int)in_wires.size();

    LambdaState st;
    st.party = mpc->party;
    st.Delta = mpc->Delta;
    st.num_inputs = num_in;

#ifdef AG2PC_PROFILE
    // Names consumed by AG2PC_PHASE.
    NetIO* send_io = mpc->send_io, *recv_io = mpc->recv_io;
    int party = st.party;
#endif
    AG2PC_PHASE_BEGIN();

    // Pass 0: liveness.
    std::vector<uint32_t> out_ids;
    {
      LivenessPass lp(st);
      out_ids = ag2pc_detail::run_pass(lp, source);
      lp.commit(out_ids);
    }
    const int n_out = (int)out_ids.size();

    // Inputs occupy slots [0,num_in).
    st.phys.assign(st.num_wires, -1);
    for (int i = 0; i < num_in; ++i) st.phys[i] = i;
    st.num_slots = num_in;
    st.wire_slot.assign(num_in, AShareBundle{});
    st.mask_input.assign(num_in, 0);
    if (st.party == 1) st.label_slot.assign(num_in, zero_block);
    else               st.eval_slot.assign(num_in, zero_block);
    for (int i = 0; i < num_in; ++i) {
      st.wire_slot[i] = in_wires.wire_bundle[i];
      st.mask_input[i] = in_wires.Lambda[i];
      if (st.party == 1) st.label_slot[i] = in_wires.label0[i];
      else               st.eval_slot[i] = in_wires.eval_label[i];
    }
    AG2PC_PHASE("liveness+load_inputs");

    // Pass 1: slot assignment and mask collection.
    {
      SizeMaskPass sp(st, mpc->fpre);
      ag2pc_detail::run_pass(sp, source);
      sp.commit_sizes();
    }
    AG2PC_PHASE("fused[size+collect_masks]");

    // c_gamma witness buffers.
    st.M1_t.resize(std::max(1, st.num_ands));
    st.Lambda_AND.assign(std::max(1, st.num_ands), 0);

    // Function-dependent leaky-AND shares.
    mpc->fpre->compute_inplace(st.rep_a, st.rep_b, st.num_ands, st.sigma);
    AG2PC_PHASE("inplace_triples[step5b]");

    // Half-gate tweak seed from the transcript.
    st.mitc.setS(RO("AG2PC half-gate", zero_block)
                     .absorb(mpc->io->get_digest())
                     .absorb(mpc->sib->get_digest())
                     .squeeze_block());

    // Pass 2: garble or evaluate (begin/end run the threaded send/recv).
    if (st.party == 1) {
      GarblePass gp(st, mpc->send_io, mpc->pool);
      ag2pc_detail::run_pass(gp, source);
    } else {
      EvaluatePass ep(st, mpc->recv_io, mpc->pool);
      ag2pc_detail::run_pass(ep, source);
    }
    AG2PC_PHASE("garble_or_evaluate[step6-10]");

    // c_gamma exchange.
    if (st.num_ands > 0) {
      if (st.party != 1) {
        mpc->io->send_bool((const bool*)st.Lambda_AND.data(), st.num_ands);
        mpc->io->flush();
        char D1[Hash::DIGEST_SIZE], D2[Hash::DIGEST_SIZE];
        Hash::hash_once(D1, st.M1_t.data(), (size_t)st.num_ands * sizeof(block));
        mpc->io->recv_data(D2, Hash::DIGEST_SIZE);
        if (memcmp(D1, D2, Hash::DIGEST_SIZE) != 0)
          error("lambda c_gamma check failed");
      } else {
        mpc->io->recv_bool((bool*)st.Lambda_AND.data(), st.num_ands);
        PostCheckPass pp(st);
        ag2pc_detail::run_pass(pp, source);
        char D2[Hash::DIGEST_SIZE];
        Hash::hash_once(D2, st.M1_t.data(), (size_t)st.num_ands * sizeof(block));
        mpc->io->send_data(D2, Hash::DIGEST_SIZE);
        mpc->io->flush();
      }
    }
    AG2PC_PHASE("check[c_gamma]");

    // COT subspace-VOLE check.
    mpc->fpre->maybe_flush_cot_check();
    AG2PC_PHASE("cot_check");

    // Gather outputs.
    SecureWires out;
    out.Lambda.resize(n_out);
    out.wire_bundle.resize(n_out);
    if (st.party == 1) out.label0.resize(n_out);
    else               out.eval_label.resize(n_out);
    for (int i = 0; i < n_out; ++i) {
      uint32_t id = out_ids[i];
      out.Lambda[i] = st.minp(id);
      out.wire_bundle[i] = st.wslot(id);
      if (st.party == 1) out.label0[i] = st.lbl(id);
      else               out.eval_label[i] = st.evl(id);
    }
    AG2PC_PHASE("gather_outputs");

    total_ands += (uint64_t)st.num_ands;   // count what was actually garbled
    return out;
  }

  // ProgramSource. Inputs bind to wire ids [0, num_inputs); the result bundle is
  // exactly the program's declared outputs. The program must be RecordCtx-
  // canonical (ag2pc's own producers always are); externally supplied programs are
  // validated, not trusted.
  SecureWires run_program(const emp::circuit::BooleanProgram& prog,
                          const SecureWires& inputs) {
    ag2pc_require_record_canonical(prog);
    check_secure_wires(inputs, proto->party, "run_program inputs");
    const uint32_t num_inputs = (uint32_t)inputs.size();
    if (num_inputs != prog.num_inputs)
      error("run_program: input bundle width != program num_inputs");

    // Drive each pass over the stored program via emp::execute_program (its
    // dispatcher is CtxReplayAdapter). Input wire VALUES are the ids [0,n): on a
    // canonical program the pass wire-id counter equals the program id, so the
    // scratch is the identity and LambdaState indexes by id, exactly as a live
    // body replay does.
    auto source = [&prog, num_inputs](auto& pass) -> std::vector<uint32_t> {
      using Pass = std::decay_t<decltype(pass)>;
      using W = typename Pass::Wire;   // uint32_t
      std::vector<W> in((size_t)num_inputs);
      for (uint32_t i = 0; i < num_inputs; ++i) in[i] = (W)i;
      ProgramWorkspace<W> ws;
      const std::vector<W>& ow = emp::execute_program(
          pass, prog, std::span<const W>(in.data(), in.size()), ws);
      return std::vector<uint32_t>(ow.begin(), ow.end());
    };
    return run_source(inputs, source);
  }
};

}  // namespace emp
#endif  // EMP_AG2PC_EXECUTOR_H__
