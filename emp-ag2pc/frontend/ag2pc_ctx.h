#ifndef EMP_AG2PC_CTX_H__
#define EMP_AG2PC_CTX_H__

// AG2PCCtx — the single public handle for two-party authenticated garbling, the
// AG2PC peer of SH2PCCtx. It IS a C++20 BooleanContext (Wire = a bare recorder id;
// gate ops record into the current chunk) and owns the crypto protocol + executor,
// so circuits authored in the typed.h value model run on it three ways:
//
//   AG2PCCtx ctx(io, &pool, party);
//   using UInt32 = UInt_T<AG2PCCtx, 32>;
//   auto a  = ctx.input<UInt32>(ALICE, x);              // eager, authenticated now
//   auto z1 = a + b;                                    // DIRECT: record into a chunk
//   auto z2 = ctx.run_body([](auto p,auto q){return p+q;}, a, b);  // LIVE BODY replay
//   auto z3 = ctx.run(compiled_circuit, a, b);          // COMPILED program replay
//   auto out = ctx.reveal(z1, PUBLIC);                  // std::optional<uint64_t>
//
// Three execution strategies, named without ambiguity:
//   * DIRECT / chunked   — operators (a+b) and emp-tool's frontend::run record gates
//                          into the current chunk, flushed at reveal/checkpoint.
//   * COMPILED replay    — ctx.run(circuit, args...): a stored program run standalone
//                          through all AG2PC passes.
//   * LIVE BODY replay   — ctx.run_body(body, args...): a pure body replayed live per
//                          pass; byte-identical transcript to the compiled replay.
// Prefer ctx.run(circuit, ...) for standalone compiled replay; frontend::run on an
// AG2PCCtx is just another way to emit DIRECT gates into the current chunk.
//
// Wire liveness is EXPLICIT — there is no refcount / global singleton. A value's
// wire ids are either MATERIALIZED (authenticated state carried in carried_; from
// input / run / run_body / a flush output) or PENDING (produced by a gate op into
// the not-yet-flushed chunk). reveal/checkpoint take explicit keep lists; any id
// that is neither materialized nor pending is stale and every lookup errors loudly.

#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/context.h"            // BooleanContext, execute_program
#include "emp-tool/circuits/boolean_program.h"    // circuit::Gate / Op / BooleanProgram
#include "emp-tool/circuits/value_traits.h"       // value_traits<T>
#include "emp-tool/frontend/circuit_fn.h"         // Circuit, RecordValue, circuit_fn_traits
#include "emp-ag2pc/backend/protocol.h"           // AG2PCProtocol
#include "emp-ag2pc/backend/executor.h"           // AG2PCExecutor, ag2pc_detail
#include "emp-ag2pc/backend/secure_wires.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace emp {

namespace ag2pc_detail {

// Pure, network-free planning for a direct-chunk flush. Given the recorded chunk
// gates, the recorder ids to keep, and a predicate telling whether a NON-chunk id
// is materialized, compute the compacted RecordCtx-canonical program plus the
// recorder-id ordering for its inputs and outputs. `ok` is false iff a needed gate
// operand is neither chunk-local nor materialized (a stale wire) — the caller turns
// that into a loud error. No protocol / carried state / sockets touched, so the
// trickiest direct-chunk logic (DCE + compaction + stale detection) is unit-testable.
struct FlushPlan {
  circuit::BooleanProgram prog;        // compacted; gate i has out == num_inputs + i
  std::vector<uint32_t> input_ids;     // recorder ids feeding program inputs, in order
  std::vector<uint32_t> output_ids;    // pending keep recorder ids = program outputs, in order
  bool ok = true;
};

template <class IsMaterialized>
inline FlushPlan plan_flush(const std::vector<circuit::Gate>& chunk_gates,
                            const std::vector<uint32_t>& keep_ids,
                            IsMaterialized&& is_materialized) {
  FlushPlan plan;
  const int G = (int)chunk_gates.size();
  std::unordered_map<uint32_t, int> wire_to_gate;
  wire_to_gate.reserve((size_t)G * 2);
  for (int gi = 0; gi < G; ++gi) wire_to_gate[chunk_gates[gi].out] = gi;

  // Reachability from the pending keep ids.
  std::vector<char> needed((size_t)G, 0);
  std::vector<uint32_t> stack;
  for (uint32_t id : keep_ids)
    if (wire_to_gate.count(id)) stack.push_back(id);
  while (!stack.empty()) {
    uint32_t w = stack.back(); stack.pop_back();
    auto it = wire_to_gate.find(w);
    if (it == wire_to_gate.end()) continue;     // carried operand (program input)
    int gi = it->second;
    if (needed[gi]) continue;
    needed[gi] = 1;
    const circuit::Gate& g = chunk_gates[gi];
    if (!g.is_const()) {                         // const operands are normalized-0 dummies
      stack.push_back(g.in0);
      if (!g.is_not()) stack.push_back(g.in1);
    }
  }

  // Carried (materialized) operands of needed gates become program inputs,
  // numbered [0, num_inputs) in first-seen order.
  std::unordered_map<uint32_t, uint32_t> remap;   // recorder id -> compact id
  auto note_input = [&](uint32_t v) {
    if (wire_to_gate.count(v)) return;            // chunk-local, not an input
    if (remap.count(v)) return;
    if (!is_materialized(v)) { plan.ok = false; return; }
    remap[v] = (uint32_t)plan.input_ids.size();
    plan.input_ids.push_back(v);
  };
  for (int gi = 0; gi < G; ++gi) {
    if (!needed[gi]) continue;
    const circuit::Gate& g = chunk_gates[gi];
    if (!g.is_const()) { note_input(g.in0); if (!g.is_not()) note_input(g.in1); }
  }
  const uint32_t num_inputs = (uint32_t)plan.input_ids.size();

  // Compact the needed gates in emission order; out_c == num_inputs + index, so
  // the program is RecordCtx-canonical (what the executor requires).
  uint32_t cid = num_inputs;
  for (int gi = 0; gi < G; ++gi) {
    if (!needed[gi]) continue;
    const circuit::Gate& g = chunk_gates[gi];
    uint32_t out_c = cid++;
    remap[g.out] = out_c;
    uint32_t ni0 = g.is_const() ? 0u : remap[g.in0];
    uint32_t ni1 = (g.is_const() || g.is_not()) ? 0u : remap[g.in1];
    plan.prog.gates.push_back({ni0, ni1, out_c, g.op});
  }
  plan.prog.num_inputs = num_inputs;
  plan.prog.num_wires  = cid;

  // Outputs = the pending keep ids (each is a reachability root, hence needed),
  // deduped, in keep order.
  std::unordered_set<uint32_t> emitted;
  for (uint32_t id : keep_ids) {
    if (!wire_to_gate.count(id)) continue;        // already materialized
    if (!emitted.insert(id).second) continue;
    plan.prog.outputs.push_back(remap[id]);
    plan.output_ids.push_back(id);
  }
  return plan;
}

}  // namespace ag2pc_detail

class AG2PCCtx {
public:
  using Wire = uint32_t;   // bare recorder id (no refcount); std::regular

  AG2PCCtx(NetIO* io, ThreadPool* pool, int party, int ssp = 40)
      : proto_(io, pool, party, ssp), exec_{&proto_} {}
  AG2PCCtx(const AG2PCCtx&) = delete;
  AG2PCCtx& operator=(const AG2PCCtx&) = delete;

  int party() const { return proto_.party; }
  // Total ANDs actually garbled across every flush / run / run_body (post-DCE),
  // i.e. across all three execution strategies.
  uint64_t num_and() const { return exec_.total_ands; }
  int process_input_calls() const { return proto_.process_input_calls; }

  // Raw escape hatches for advanced use (the SecureWires-level protocol/executor).
  AG2PCProtocol& protocol() { return proto_; }
  AG2PCExecutor& executor() { return exec_; }

  // ---- BooleanContext gate ops: record into the current chunk (pending) ----
  Wire public_bit(bool v) {
    int idx = v ? 1 : 0;
    if (const_wire_[idx] < 0) {
      uint32_t o = alloc_id_();
      chunk_gates_.push_back({0, 0, o, v ? circuit::Op::Const1 : circuit::Op::Const0});
      pending_.insert(o);
      const_wire_[idx] = (int64_t)o;
    }
    return (Wire)const_wire_[idx];
  }
  Wire and_gate(Wire a, Wire b) {
    require_operand_(a); require_operand_(b);
    uint32_t o = alloc_id_();
    chunk_gates_.push_back({a, b, o, circuit::Op::And});
    pending_.insert(o);
    return o;
  }
  Wire xor_gate(Wire a, Wire b) {
    require_operand_(a); require_operand_(b);
    uint32_t o = alloc_id_();
    chunk_gates_.push_back({a, b, o, circuit::Op::Xor});
    pending_.insert(o);
    return o;
  }
  Wire not_gate(Wire a) {
    require_operand_(a);
    uint32_t o = alloc_id_();
    chunk_gates_.push_back({a, 0, o, circuit::Op::Not});
    pending_.insert(o);
    return o;
  }

  // ---- typed input (eager: authenticated immediately → materialized) ----
  // input<T>(owner, x): T is a value type over THIS context, e.g.
  // UInt_T<AG2PCCtx,32>. Called by both parties; only `owner`'s clear is used.
  // PUBLIC builds a public constant (no OT).
  template <class T, class Clear>
  T input(int owner, Clear clear) {
    static_assert(std::is_same_v<typename T::context_type, AG2PCCtx>,
        "AG2PCCtx::input<T>: T must be a value type over AG2PCCtx (e.g. UInt_T<AG2PCCtx,32>)");
    std::vector<bool> bits = encode_<T>(clear);
    SecureWires bundle = authenticate_(owner, bits);
    std::vector<uint32_t> ids = materialize_(bundle);
    return T::from_wires(*this, ids.data());
  }

  // ---- multi-owner input batch: ONE process_inputs across heterogeneous owners.
  // auto b = ctx.input_batch();
  // auto a = b.add<UInt32>(ALICE, x);  auto y = b.add<UInt32>(BOB, z);  b.finish();
  // add<T>() returns a real value bound to reserved ids; it is STALE (errors on
  // use) until finish() authenticates and materializes every value in one phase.
  class InputBatch {
  public:
    template <class T, class Clear>
    T add(int owner, Clear clear) {
      if (finished_) error("AG2PCCtx::input_batch: add() after finish()");
      static_assert(std::is_same_v<typename T::context_type, AG2PCCtx>,
          "AG2PCCtx::input_batch add<T>: T must be a value type over AG2PCCtx");
      std::vector<bool> bits = ctx_->encode_<T>(clear);
      const int W = (int)bits.size();
      std::vector<uint32_t> ids((size_t)W);
      for (int i = 0; i < W; ++i) ids[i] = ctx_->alloc_id_();   // reserved (stale until finish)
      owners_.push_back(owner);
      bits_.push_back(std::move(bits));
      ids_.push_back(ids);
      return T::from_wires(*ctx_, ids.data());
    }
    void finish() {
      if (finished_) error("AG2PCCtx::input_batch: finish() called twice");
      finished_ = true;
      ctx_->batch_finish_(owners_, bits_, ids_);
    }
  private:
    friend class AG2PCCtx;
    explicit InputBatch(AG2PCCtx* c) : ctx_(c) {}
    AG2PCCtx* ctx_;
    std::vector<int> owners_;
    std::vector<std::vector<bool>> bits_;
    std::vector<std::vector<uint32_t>> ids_;
    bool finished_ = false;
  };
  InputBatch input_batch() { return InputBatch(this); }

  // ---- reveal: flush keeping v (and the explicit keep...), then decode v.
  // keep... carries pending values forward only; it does not prune materialized
  // state. Any pending value NOT in {v, keep...} is dropped at the flush.
  template <class T, class... Keep>
  std::optional<typename T::clear_t> reveal(const T& v, int recipient, const Keep&... keep) {
    static_assert(std::is_same_v<typename T::context_type, AG2PCCtx>,
        "AG2PCCtx::reveal<T>: T must be a value type over AG2PCCtx");
#if EMP_CONTEXT_CHECKS
    if (v.context() != this) error("AG2PCCtx::reveal: value is bound to a different context");
#endif
    std::vector<uint32_t> keep_ids = value_ids_(v);
    (append_ids_(keep_ids, keep), ...);
    flush_(keep_ids);
    SecureWires bundle = gather_carried_(value_ids_(v));
    std::vector<bool> bits = proto_.decode(bundle, recipient);
    const int W = value_traits<T>::width();
    if ((int)bits.size() != W) return std::nullopt;   // non-recipient
    auto bb = std::make_unique<bool[]>((size_t)W);
    for (int i = 0; i < W; ++i) bb[i] = (bool)bits[i];
    return value_traits<T>::decode(bb.get());
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

  // ---- COMPILED replay: a stored Circuit replayed standalone through the passes.
  template <frontend::RecordValue RetV, frontend::RecordValue... ArgVs>
  typename RetV::template rebind<AG2PCCtx>
  run(const frontend::Circuit<RetV, ArgVs...>& c,
      const typename ArgVs::template rebind<AG2PCCtx>&... args) {
    SecureWires bundle;
    (append_arg_(bundle, args), ...);
    if ((uint32_t)bundle.size() != c.program().num_inputs)
      error("AG2PCCtx::run: total argument width != circuit input count");
    SecureWires out = exec_.run_program(c.program(), bundle);
    return wrap_output_<typename RetV::template rebind<AG2PCCtx>>(out);
  }

  // ---- LIVE BODY replay: a pure body replayed live, once per pass (no stored IR).
  // ArgVs are deduced from the argument value types; the return value type comes
  // from the body's contract. NOT the same as frontend::run (which records direct
  // gates into the chunk) — run_body is a standalone pass replay.
  template <class F, class... Args>
  auto run_body(F&& body, const Args&... args) {
    static_assert(
        (frontend::RecordValue<typename std::decay_t<Args>::template rebind<RecordCtx>> && ...),
        "AG2PCCtx::run_body: each argument must be a circuit value (Bit/UInt/Int/Float/Bits)");
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
      SecureWires out = exec_.run_source(bundle, source);
      using RetV = typename Tr::value_return;   // value type over RecordCtx
      return wrap_output_<typename RetV::template rebind<AG2PCCtx>>(out);
    } else {
      return frontend::invalid_circuit_fn{};   // unreachable after the contract asserts
    }
  }

  // ---- typed raw-program escape hatch: a loaded/hand-authored BooleanProgram
  // (e.g. an AES/SHA .empbc builtin) run over materialized typed args. RetV is a
  // value type over AG2PCCtx, e.g. Bits_T<AG2PCCtx,128> — use Bits_T / raw bits
  // for wide I/O, never a UInt_T clear codec beyond 64 bits.
  template <class RetV, class... Args>
  RetV run_program(const circuit::BooleanProgram& prog, const Args&... args) {
    static_assert(std::is_same_v<typename RetV::context_type, AG2PCCtx>,
        "AG2PCCtx::run_program<RetV>: RetV must be a value type over AG2PCCtx");
    SecureWires bundle;
    (append_arg_(bundle, args), ...);
    if ((uint32_t)bundle.size() != prog.num_inputs)
      error("AG2PCCtx::run_program: total argument width != program num_inputs");
    if ((uint32_t)RetV::width() != prog.outputs.size())
      error("AG2PCCtx::run_program: RetV width != program output count");
    SecureWires out = exec_.run_program(prog, bundle);
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
  AG2PCExecutor exec_;

  uint32_t next_id_ = 0;                              // monotonic recorder id
  std::vector<circuit::Gate> chunk_gates_;            // current chunk (recorder ids)
  std::unordered_set<uint32_t> pending_;              // ids produced in the current chunk
  std::unordered_map<uint32_t, CarriedState> carried_;  // materialized id -> state
  int64_t const_wire_[2] = {-1, -1};                 // per-chunk Const0/Const1 dedup

  uint32_t alloc_id_() {
    if (next_id_ == UINT32_MAX) error("AG2PCCtx: recorder wire id overflow");
    return next_id_++;
  }

  void require_operand_(Wire a) const {
    if (!pending_.count(a) && !carried_.count(a))
      error("AG2PCCtx: operand wire is stale (used after a prune/reveal, or before input_batch().finish())");
  }

  template <class T, class Clear>
  std::vector<bool> encode_(Clear clear) const {
    const int W = value_traits<T>::width();
    std::vector<bool> bits = value_traits<T>::encode(clear);
    // Always enforced: a short/long encoding is a codec bug; never silently pad.
    if ((int)bits.size() != W) error("AG2PCCtx::input: T::encode width != T::width()");
    return bits;
  }

  SecureWires authenticate_(int owner, const std::vector<bool>& bits) {
    if (owner == PUBLIC) return proto_.public_wires(bits);
    if (owner != ALICE && owner != BOB)
      error("AG2PCCtx::input: owner must be ALICE, BOB, or PUBLIC");
    std::vector<SecureWires> subs =
        proto_.process_inputs(std::vector<int>{owner},
                              std::vector<std::vector<bool>>{bits});
    return std::move(subs[0]);
  }

  // batch finish: PUBLIC adds via public_wires (no OT); ALICE/BOB adds in ONE
  // process_inputs call; then materialize every reserved id.
  void batch_finish_(const std::vector<int>& owners,
                     const std::vector<std::vector<bool>>& bits,
                     const std::vector<std::vector<uint32_t>>& ids) {
    std::vector<int> sec_owners;
    std::vector<std::vector<bool>> sec_bits;
    std::vector<int> sec_add;
    for (size_t a = 0; a < owners.size(); ++a) {
      if (owners[a] == PUBLIC) {
        materialize_into_(ids[a], proto_.public_wires(bits[a]));
      } else if (owners[a] == ALICE || owners[a] == BOB) {
        sec_owners.push_back(owners[a]);
        sec_bits.push_back(bits[a]);
        sec_add.push_back((int)a);
      } else {
        error("AG2PCCtx::input_batch: owner must be ALICE, BOB, or PUBLIC");
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
    if (bundle.size() != ids.size()) error("AG2PCCtx: materialize width mismatch");
    for (size_t i = 0; i < ids.size(); ++i)
      carry_load_(carried_[ids[i]], bundle, i, is_eval);
  }
  // Allocate fresh ids for an n-wire bundle and materialize them.
  std::vector<uint32_t> materialize_(const SecureWires& bundle) {
    std::vector<uint32_t> ids(bundle.size());
    for (size_t i = 0; i < ids.size(); ++i) ids[i] = alloc_id_();
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
        error("AG2PCCtx: wire has no carried state (stale, or unflushed pending wire)");
      carry_store_(it->second, s, i, is_eval);
    }
    return s;
  }

  template <class T>
  std::vector<uint32_t> value_ids_(const T& v) const {
    std::vector<uint32_t> ids((size_t)value_traits<T>::width());
    v.pack_wires(ids.data());
    return ids;
  }
  template <class T>
  void append_ids_(std::vector<uint32_t>& dst, const T& v) const {
    std::vector<uint32_t> ids = value_ids_(v);
    dst.insert(dst.end(), ids.begin(), ids.end());
  }

  // run/run_body argument: must be fully materialized (cross-mode mixing deferred).
  template <class A>
  void append_arg_(SecureWires& bundle, const A& a) {
    static_assert(std::is_same_v<typename A::context_type, AG2PCCtx>,
        "AG2PCCtx::run: argument must be a value over AG2PCCtx");
#if EMP_CONTEXT_CHECKS
    if (a.context() != this) error("AG2PCCtx::run: argument belongs to a different context");
#endif
    std::vector<uint32_t> ids = value_ids_(a);
    for (uint32_t id : ids)
      if (!carried_.count(id))
        error("AG2PCCtx::run: argument is unflushed — checkpoint it first; cross-mode mixing not yet supported");
    ag2pc_detail::append_bundle(bundle, gather_carried_(ids));
  }

  template <class RetV>
  RetV wrap_output_(const SecureWires& out) {
    std::vector<uint32_t> ids = materialize_(out);
    return RetV::from_wires(*this, ids.data());
  }

  // Run the pending chunk, materializing exactly the PENDING keep ids; clear the
  // chunk. Non-local operands of reachable gates MUST be materialized (loud error
  // otherwise). If no keep id is pending, drop the chunk without running (so a
  // reveal of an already-materialized value, or checkpoint(), is a pure prune).
  void flush_(const std::vector<uint32_t>& keep_ids) {
    for (uint32_t id : keep_ids)
      if (!pending_.count(id) && !carried_.count(id))
        error("AG2PCCtx: keep/reveal wire is stale");

    bool any_pending = false;
    for (uint32_t id : keep_ids) if (pending_.count(id)) { any_pending = true; break; }
    if (!any_pending) { drop_chunk_(); return; }

    // Pure planning (DCE + compaction + stale-operand detection); see plan_flush.
    ag2pc_detail::FlushPlan plan = ag2pc_detail::plan_flush(
        chunk_gates_, keep_ids,
        [this](uint32_t id) { return carried_.count(id) != 0; });
    if (!plan.ok)
      error("AG2PCCtx::flush: gate operand has no carried state (stale wire)");

    SecureWires input_bundle = gather_carried_(plan.input_ids);
    SecureWires result = exec_.run_program(plan.prog, input_bundle);

    const bool is_eval = (proto_.party != 1);
    for (size_t i = 0; i < plan.output_ids.size(); ++i)
      carry_load_(carried_[plan.output_ids[i]], result, i, is_eval);

    drop_chunk_();
  }

  void drop_chunk_() {
    chunk_gates_.clear();
    pending_.clear();
    const_wire_[0] = const_wire_[1] = -1;
  }
};

static_assert(BooleanContext<AG2PCCtx>);

}  // namespace emp
#endif  // EMP_AG2PC_CTX_H__
