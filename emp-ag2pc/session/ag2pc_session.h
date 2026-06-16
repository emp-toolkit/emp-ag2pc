#ifndef EMP_AG2PC_SESSION_H__
#define EMP_AG2PC_SESSION_H__

// AG2PCSession — the public handle for two-party authenticated garbling (KRRW),
// the AG2PC peer of ClearSession. It owns the I/O boundary (input / reveal /
// checkpoint), the crypto protocol, the authenticated carried state, and an
// internal multipass engine; circuits authored in the typed.h value model run on
// its gate context three ways:
//
//   AG2PCSession sess(io, &pool, party);
//   using Ctx = AG2PCSession::DirectCtx; using UInt32 = UInt_T<Ctx,32>;
//   auto a  = sess.input<UInt32>(ALICE, x);              // eager, authenticated now
//   auto z1 = a + b;                                     // DIRECT: record into a chunk
//   auto z2 = sess.run([](auto p, auto q){ return p+q; }, a, b);  // LIVE BODY replay
//   auto z3 = sess.run(compiled_circuit, a, b);          // COMPILED program replay
//   auto out = sess.reveal(z1, PUBLIC);                  // std::optional<uint64_t>
//
// Three execution strategies, named without ambiguity:
//   * DIRECT / chunked   — operators (a+b) and emp-tool's frontend::run record gates
//                          into the session's gate context, flushed at reveal/checkpoint.
//   * COMPILED replay    — sess.run(circuit, args...): a stored typed Circuit run
//                          standalone through all AG2PC passes.
//   * LIVE BODY replay   — sess.run(body, args...): a pure body replayed live per pass;
//                          byte-identical transcript to the compiled replay.
//
// Wire liveness is EXPLICIT — there is no refcount / global singleton. A value's
// wire ids are either MATERIALIZED (authenticated state held in carried_; from
// input / run / a flush output) or PENDING (produced by a gate op into the
// not-yet-flushed chunk on the gate context). reveal/checkpoint take explicit keep
// lists; any id that is neither materialized nor pending is stale and errors loudly.

#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/context/context.h"            // BooleanContext, RecordCtx, execute_program
#include "emp-tool/ir/program.h"                 // circuit::Gate / Op / BooleanProgram
#include "emp-tool/circuits/typed.h"             // UInt_T / Int_T / BitVec_T / Float_T / Bit_T
#include "emp-tool/circuits/frontend/circuit_fn.h"        // Circuit, RecordValue, circuit_fn_traits, is_circuit_v
#include "emp-tool/ir/session/session_io.h"            // Session / DirectSession / SessionIO
#include "emp-ag2pc/session/ag2pc_ctx.h"         // AG2PCCtx (the gate recorder)
#include "emp-ag2pc/backend/protocol.h"          // AG2PCProtocol
#include "emp-ag2pc/backend/engine.h"            // AG2PCEngine, ag2pc_detail::{append_bundle,body_replay}
#include "emp-ag2pc/backend/secure_wires.h"      // SecureWires / AShareBundle
#include "emp-ag2pc/backend/flush_plan.h"        // ag2pc_detail::plan_flush / FlushPlan

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace emp {

class AG2PCSession {
public:
  using DirectCtx = AG2PCCtx;
  // AG2PC reveal is recipient-only: the non-recipient party learns nothing, so
  // reveal returns std::nullopt there (vs ClearSession, where everyone learns it).
  template <class V> using reveal_t = std::optional<typename V::clear_t>;

  AG2PCSession(NetIO* io, ThreadPool* pool, int party, int ssp = 40)
      : proto_(io, pool, party, ssp), engine_{&proto_} {}
  AG2PCSession(const AG2PCSession&) = delete;
  AG2PCSession& operator=(const AG2PCSession&) = delete;

  // The gate context, for value construction that is not I/O — e.g. public
  // constants UInt_T<DirectCtx,32>::constant(sess.direct_ctx(), 7), operators, or frontend::run.
  DirectCtx& direct_ctx() { return ctx_; }

  int party() const { return proto_.party; }
  // Total ANDs actually garbled across every flush / run (post-DCE), all strategies.
  uint64_t num_and() const { return engine_.total_ands; }
  int process_input_calls() const { return proto_.process_input_calls; }

  // Advanced escape hatch: the SecureWires-level crypto protocol (the engine stays
  // internal). Most users never need this.
  AG2PCProtocol& protocol() { return proto_; }

  // ---- typed input (eager: authenticated immediately → materialized) ----
  // input<V>(owner, clear): V is a value type over THIS session's DirectCtx, e.g.
  // UInt_T<DirectCtx,32>. Called by both parties; only `owner`'s clear is used.
  // PUBLIC builds a public constant (no OT).
  template <WireValue V>
  V input(int owner, const typename V::clear_t& clear) {
    static_assert(std::same_as<typename V::context_type, DirectCtx>,
        "AG2PCSession::input<V>: V must be a value over this session's DirectCtx");
    const auto eb = V::encode(clear);                    // std::array<bool, V::width()>
    std::vector<uint8_t> bits(eb.begin(), eb.end());     // batch protocol storage is runtime-sized
    SecureWires bundle = authenticate_(owner, bits);
    std::vector<uint32_t> ids = materialize_(bundle);
    return V::from_wires(ctx_, ids.data());
  }

  // ---- multi-owner input batch: ONE process_inputs across heterogeneous owners.
  // auto b = sess.input_batch();
  // auto a = b.add<UInt32>(ALICE, x);  auto y = b.add<UInt32>(BOB, z);  b.finish();
  // add<V>() returns a real value bound to reserved ids. finish() authenticates and
  // materializes every value in one phase. Before finish() those ids are reserved but
  // unmaterialized: a gate over one still records (the recorder rejects only a
  // never-allocated id), but it has no carried state, so the next flush errors as a
  // stale operand iff such a value is reachable from a reveal/keep.
  class InputBatch {
  public:
    template <WireValue V>
    V add(int owner, const typename V::clear_t& clear) {
      if (finished_) error("AG2PCSession::input_batch: add() after finish()");
      static_assert(std::same_as<typename V::context_type, DirectCtx>,
          "AG2PCSession::input_batch add<V>: V must be a value over this session's DirectCtx");
      const auto eb = V::encode(clear);                  // std::array<bool, V::width()>
      std::vector<uint8_t> bits(eb.begin(), eb.end());   // batch protocol storage is runtime-sized
      std::vector<uint32_t> ids = sess_->ctx_.reserve_ids(bits.size());  // reserved, unmaterialized until finish()
      owners_.push_back(owner);
      bits_.push_back(std::move(bits));
      ids_.push_back(ids);
      return V::from_wires(sess_->ctx_, ids.data());
    }
    void finish() {
      if (finished_) error("AG2PCSession::input_batch: finish() called twice");
      finished_ = true;
      sess_->batch_finish_(owners_, bits_, ids_);
    }
  private:
    friend class AG2PCSession;
    explicit InputBatch(AG2PCSession* s) : sess_(s) {}
    AG2PCSession* sess_;
    std::vector<int> owners_;
    std::vector<std::vector<uint8_t>> bits_;
    std::vector<std::vector<uint32_t>> ids_;
    bool finished_ = false;
  };
  InputBatch input_batch() { return InputBatch(this); }

  // ---- reveal: flush keeping v (and the explicit keep...), then decode v.
  // keep... carries pending values forward only; it does not prune materialized
  // state. Any pending value NOT in {v, keep...} is dropped at the flush.
  // Settlement (session contract, ir/session/session.h): AG2PC settles AT
  // REVEAL — the flush runs the deferred authenticated-AND / COT consistency
  // checks before decode produces a cleartext, so a returned value is final,
  // never provisional. Recipient domain: PUBLIC, ALICE, or BOB only; the
  // XOR-share sentinel has no meaning in this protocol and is rejected.
  template <WireValue V, class... Keep>
  reveal_t<V> reveal(const V& v, int recipient, const Keep&... keep) {
    static_assert(std::same_as<typename V::context_type, DirectCtx>,
        "AG2PCSession::reveal<V>: V must be a value over this session's DirectCtx");
    if (recipient != PUBLIC && recipient != ALICE && recipient != BOB)
      error("AG2PCSession::reveal: recipient must be PUBLIC, ALICE, or BOB (XOR-share reveal is not supported)");
#if EMP_CONTEXT_CHECKS
    if (v.context() != &ctx_) error("AG2PCSession::reveal: value is bound to a different context");
#endif
    std::vector<uint32_t> keep_ids = value_ids_(v);
    (append_ids_(keep_ids, keep), ...);
    flush_(keep_ids);
    SecureWires bundle = gather_carried_(value_ids_(v));
    std::vector<uint8_t> bits = proto_.decode(bundle, recipient);
    constexpr int W = V::width();
    if ((int)bits.size() != W) return std::nullopt;   // non-recipient
    std::array<bool, (std::size_t)W> bb{};
    for (int i = 0; i < W; ++i) bb[(std::size_t)i] = (bool)bits[(std::size_t)i];
    return V::decode(bb.data());
  }

  // ---- checkpoint(keep...): flush + prune carried state to exactly keep...
  // checkpoint() with no args drops all pending work and prunes ALL carried state.
  template <class... Keep>
  void checkpoint(const Keep&... keep) {
    std::vector<uint32_t> keep_ids;
    (append_ids_(keep_ids, keep), ...);
    flush_(keep_ids);
    std::unordered_set<uint32_t> keepset(keep_ids.begin(), keep_ids.end());
    for (auto it = carried_.begin(); it != carried_.end(); ) {
      if (!keepset.count(it->first)) it = carried_.erase(it);
      else ++it;
    }
  }

  // ---- COMPILED replay: a stored typed Circuit replayed standalone through the
  // passes. Prefer this for any .empbc / hand-built circuit.
  template <frontend::RecordValue RetV, frontend::RecordValue... ArgVs>
  typename RetV::template rebind<DirectCtx>
  run(const frontend::Circuit<RetV, ArgVs...>& c,
      const typename ArgVs::template rebind<DirectCtx>&... args) {
    SecureWires bundle;
    (append_arg_(bundle, args), ...);
    if ((uint32_t)bundle.size() != c.program().num_inputs)
      error("AG2PCSession::run: total argument width != circuit input count");
    SecureWires out = engine_.run_program(c.program(), bundle);
    return wrap_output_<typename RetV::template rebind<DirectCtx>>(out);
  }

  // ---- LIVE BODY replay: a pure body replayed live, once per pass (no stored IR).
  // ArgVs are deduced from the argument value types; the return value type comes
  // from the body's contract. Byte-identical transcript to the compiled replay.
  template <class F, class... Args,
            std::enable_if_t<!frontend::is_circuit_v<std::decay_t<F>>, int> = 0>
  auto run(F&& body, const Args&... args) {
    static_assert(
        (frontend::RecordValue<typename std::decay_t<Args>::template rebind<RecordCtx>> && ...),
        "AG2PCSession::run: each argument must be a WireValue (Bit_T/UInt_T/Int_T/Float_T/BitVec_T)");
    using Tr = frontend::circuit_fn_traits<
        RecordCtx, std::decay_t<F>,
        typename std::decay_t<Args>::template rebind<RecordCtx>...>;
    (void)sizeof(frontend::circuit_contract<Tr>);
    if constexpr (Tr::ok) {
      SecureWires bundle;
      (append_arg_(bundle, args), ...);
      auto source = [&body](auto& pass) -> std::vector<uint32_t> {
        return ag2pc_detail::body_replay<
            typename std::decay_t<Args>::template rebind<RecordCtx>...>(pass, body);
      };
      SecureWires out = engine_.run_source(bundle, source);
      using RetV = typename Tr::value_return;   // value type over RecordCtx
      return wrap_output_<typename RetV::template rebind<DirectCtx>>(out);
    } else {
      return frontend::invalid_circuit_fn{};   // unreachable after the contract asserts
    }
  }

  // ---- typed raw-program escape hatch (advanced): a loaded/hand-authored
  // BooleanProgram run over materialized typed args, with an explicit RetV value
  // type over DirectCtx (e.g. BitVec<128>). Prefer run(circuit, ...) — wrap the program
  // into a typed frontend::Circuit at load time — and reach for this only for the
  // genuinely-untyped raw case.
  template <WireValue RetV, class... Args>
  RetV run_artifact(const circuit::BooleanProgram& prog, const Args&... args) {
    static_assert(std::same_as<typename RetV::context_type, DirectCtx>,
        "AG2PCSession::run_artifact<RetV>: RetV must be a value over this session's DirectCtx");
    SecureWires bundle;
    (append_arg_(bundle, args), ...);
    if ((uint32_t)bundle.size() != prog.num_inputs)
      error("AG2PCSession::run_artifact: total argument width != program num_inputs");
    if ((uint32_t)RetV::width() != prog.outputs.size())
      error("AG2PCSession::run_artifact: RetV width != program output count");
    SecureWires out = engine_.run_program(prog, bundle);
    return wrap_output_<RetV>(out);
  }

private:
  // Authenticated state carried across chunk boundaries (one per materialized id).
  struct CarriedState {
    AShareBundle bundle;
    unsigned char Lambda = 0;   // publicly-opened mask
    block label0 = zero_block;  // garbler-side m_{w,0}        (P1)
    block evlbl  = zero_block;  // evaluator-side m_{w,Lambda} (P2)
  };

  AG2PCProtocol proto_;
  AG2PCCtx ctx_;                                      // the gate recorder
  AG2PCEngine engine_;                               // internal multipass runner
  std::unordered_map<uint32_t, CarriedState> carried_;  // materialized id -> state

  SecureWires authenticate_(int owner, const std::vector<uint8_t>& bits) {
    if (owner == PUBLIC) return proto_.public_wires(bits);
    if (owner != ALICE && owner != BOB)
      error("AG2PCSession::input: owner must be ALICE, BOB, or PUBLIC");
    std::vector<SecureWires> subs =
        proto_.process_inputs(std::vector<int>{owner},
                              std::vector<std::vector<uint8_t>>{bits});
    return std::move(subs[0]);
  }

  // batch finish: PUBLIC adds via public_wires (no OT); ALICE/BOB adds in ONE
  // process_inputs call; then materialize every reserved id.
  void batch_finish_(const std::vector<int>& owners,
                     const std::vector<std::vector<uint8_t>>& bits,
                     const std::vector<std::vector<uint32_t>>& ids) {
    std::vector<int> sec_owners;
    std::vector<std::vector<uint8_t>> sec_bits;
    std::vector<int> sec_add;
    for (size_t a = 0; a < owners.size(); ++a) {
      if (owners[a] == PUBLIC) {
        materialize_into_(ids[a], proto_.public_wires(bits[a]));
      } else if (owners[a] == ALICE || owners[a] == BOB) {
        sec_owners.push_back(owners[a]);
        sec_bits.push_back(bits[a]);
        sec_add.push_back((int)a);
      } else {
        error("AG2PCSession::input_batch: owner must be ALICE, BOB, or PUBLIC");
      }
    }
    if (!sec_owners.empty()) {
      std::vector<SecureWires> subs = proto_.process_inputs(sec_owners, sec_bits);
      for (size_t j = 0; j < sec_add.size(); ++j)
        materialize_into_(ids[sec_add[j]], subs[j]);
    }
  }

  // ---- carried-state <-> SecureWires ----
  void carry_load_(CarriedState& c, const SecureWires& s, size_t i, bool is_eval) const {
    c.Lambda = s.Lambda[i];
    c.bundle = s.wire_bundle[i];
    if (is_eval) c.evlbl = s.eval_label[i];
    else         c.label0 = s.label0[i];
  }
  void carry_store_(const CarriedState& c, SecureWires& s, size_t i, bool is_eval) const {
    s.Lambda[i] = c.Lambda;
    s.wire_bundle[i] = c.bundle;
    if (is_eval) s.eval_label[i] = c.evlbl;
    else         s.label0[i] = c.label0;
  }

  // Store an n-wire bundle into the given (already reserved) ids → materialized.
  void materialize_into_(const std::vector<uint32_t>& ids, const SecureWires& bundle) {
    const bool is_eval = (proto_.party != 1);
    if (bundle.size() != ids.size()) error("AG2PCSession: materialize width mismatch");
    for (size_t i = 0; i < ids.size(); ++i)
      carry_load_(carried_[ids[i]], bundle, i, is_eval);
  }
  // Reserve fresh ids on the gate context for an n-wire bundle and materialize them.
  std::vector<uint32_t> materialize_(const SecureWires& bundle) {
    std::vector<uint32_t> ids = ctx_.reserve_ids(bundle.size());
    materialize_into_(ids, bundle);
    return ids;
  }

  // Gather materialized wires (caller order) into a SecureWires bundle.
  SecureWires gather_carried_(const std::vector<uint32_t>& ids) const {
    SecureWires s;
    const bool is_eval = (proto_.party != 1);
    s.Lambda.resize(ids.size());
    s.wire_bundle.resize(ids.size());
    if (is_eval) s.eval_label.resize(ids.size());
    else         s.label0.resize(ids.size());
    for (size_t i = 0; i < ids.size(); ++i) {
      auto it = carried_.find(ids[i]);
      if (it == carried_.end())
        error("AG2PCSession: wire has no carried state (stale, or unflushed pending wire)");
      carry_store_(it->second, s, i, is_eval);
    }
    return s;
  }

  template <class V>
  std::vector<uint32_t> value_ids_(const V& v) const {
    std::vector<uint32_t> ids((size_t)V::width());
    v.pack_wires(ids.data());
    return ids;
  }
  template <class V>
  void append_ids_(std::vector<uint32_t>& dst, const V& v) const {
#if EMP_CONTEXT_CHECKS
    // Keep/carry values for reveal(...) and checkpoint(...) both funnel through here
    // (developer-misuse guard only — same contract as append_arg_).
    if (v.context() != &ctx_) error("AG2PCSession: keep value is bound to a different context");
#endif
    std::vector<uint32_t> ids = value_ids_(v);
    dst.insert(dst.end(), ids.begin(), ids.end());
  }

  // run() argument: must be fully materialized (the pending-value rule — a
  // non-materialized arg is a loud error here, before any network op).
  template <class A>
  void append_arg_(SecureWires& bundle, const A& a) {
    static_assert(std::is_same_v<typename A::context_type, DirectCtx>,
        "AG2PCSession::run: argument must be a value over AG2PCSession::DirectCtx");
#if EMP_CONTEXT_CHECKS
    if (a.context() != &ctx_) error("AG2PCSession::run: argument belongs to a different context");
#endif
    std::vector<uint32_t> ids = value_ids_(a);
    for (uint32_t id : ids)
      if (!carried_.count(id))
        error("AG2PCSession::run: argument is unflushed — checkpoint it first; cross-mode mixing not yet supported");
    ag2pc_detail::append_bundle(bundle, gather_carried_(ids));
  }

  template <class RetV>
  RetV wrap_output_(const SecureWires& out) {
    std::vector<uint32_t> ids = materialize_(out);
    return RetV::from_wires(ctx_, ids.data());
  }

  // Run the pending chunk, materializing exactly the PENDING keep ids; clear the
  // chunk. Non-local operands of reachable gates MUST be materialized (loud error
  // otherwise — this is where deferred stale-operand detection lands). If no keep
  // id is pending, drop the chunk without running (so a reveal of an
  // already-materialized value, or checkpoint(), is a pure prune).
  void flush_(const std::vector<uint32_t>& keep_ids) {
    for (uint32_t id : keep_ids)
      if (!ctx_.is_pending(id) && !carried_.count(id))
        error("AG2PCSession: keep/reveal wire is stale");

    bool any_pending = false;
    for (uint32_t id : keep_ids) if (ctx_.is_pending(id)) { any_pending = true; break; }
    if (!any_pending) { ctx_.drop_chunk(); return; }

    // Pure planning (DCE + compaction + stale-operand detection); see plan_flush.
    ag2pc_detail::FlushPlan plan = ag2pc_detail::plan_flush(
        ctx_.chunk_gates(), keep_ids,
        [this](uint32_t id) { return carried_.count(id) != 0; });
    if (!plan.ok)
      error("AG2PCSession::flush: gate operand has no carried state (stale wire)");

    SecureWires input_bundle = gather_carried_(plan.input_ids);
    SecureWires result = engine_.run_program(plan.prog, input_bundle);

    const bool is_eval = (proto_.party != 1);
    for (size_t i = 0; i < plan.output_ids.size(); ++i)
      carry_load_(carried_[plan.output_ids[i]], result, i, is_eval);

    ctx_.drop_chunk();
  }
};

static_assert(Session<AG2PCSession>);
static_assert(DirectSession<AG2PCSession>);
static_assert(SessionIO<AG2PCSession, UInt_T<AG2PCSession::DirectCtx, 32>>);
static_assert(CheckpointingSession<AG2PCSession>);

}  // namespace emp
#endif  // EMP_AG2PC_SESSION_H__
