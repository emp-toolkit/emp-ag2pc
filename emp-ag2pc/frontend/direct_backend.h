#ifndef EMP_AG2PC_DIRECT_BACKEND_H__
#define EMP_AG2PC_DIRECT_BACKEND_H__
#include "emp-tool/execution/backend.h"
#include "emp-ag2pc/backend/session.h"
#include "emp-ag2pc/backend/engine.h"   // AG2PCEngine::run_program (the shared engine)
#include "emp-tool/frontend/boolean_program.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace emp {

// Recording backend that lets people author ag2pc circuits in emp-tool's native
// Bit / Integer / Float frontend. Authenticated garbling is multi-pass and needs
// the whole circuit, so this backend *records* gates and runs the protocol once
// per chunk (at a checkpoint or the terminal reveal).
//
// Wire carrier: AG2PCWire (4-byte non-trivially-copyable handle). Each Bit's
// destructor / copy fires a refcount hook on the backend, so the backend always
// knows which wire ids are still pinned by a live user-side Bit. That lets
// checkpoint_keep_all() drop every wire whose Bit has gone out of scope —
// without any stale-handle footgun.
//
// Recording layout (flat arrays, free-list-reused slot ids):
//   meta_[id] = { refcount, op, parents }     — per-slot persistent recording state
//   carried_[id] = { Lambda, mac, key, label } — per-alive-id state from prior chunks
//   free_ids_                                 — stack of ids returnable for reuse
//   chunk_gates_, chunk_inputs_               — current-chunk gate / input log
//
// Slot ids: monotonic next_id_; dead ids returned to free_ids_ ONLY at chunk
// boundaries (never mid-chunk — chunk_gates_ may still reference them).

class AG2PCBackend;

// 4-byte wire carrier with refcount semantics. Pin on construct/copy, unpin on
// destruct/overwrite — all routed to AG2PCBackend::singleton_'s pin/unpin. A
// null/moved-from carrier has id == -1 and does no bookkeeping.
struct AG2PCWire {
  int id;

  AG2PCWire() noexcept : id(-1) {}
  explicit AG2PCWire(int i) noexcept : id(i) { pin_(); }
  AG2PCWire(const AG2PCWire &o) noexcept : id(o.id) { pin_(); }
  AG2PCWire(AG2PCWire &&o) noexcept : id(o.id) { o.id = -1; }
  AG2PCWire &operator=(const AG2PCWire &o) noexcept {
    if (this != &o) { unpin_(); id = o.id; pin_(); }
    return *this;
  }
  AG2PCWire &operator=(AG2PCWire &&o) noexcept {
    if (this != &o) { unpin_(); id = o.id; o.id = -1; }
    return *this;
  }
  ~AG2PCWire() noexcept { unpin_(); }

 private:
  // Defined out-of-line below so they can reference AG2PCBackend::singleton_.
  void pin_()   noexcept;
  void unpin_() noexcept;
};
static_assert(sizeof(AG2PCWire) == sizeof(int),
              "AG2PCWire must be a plain int carrier");

class AG2PCBackend : public Backend {
 public:
  AG2PCBackend(NetIO *io, ThreadPool *pool_, int party_, int ssp = 40) {
    this->party = party_;
    mpc = new AG2PCSession(io, pool_, party_, ssp);
    if (singleton_ != nullptr)
      error("AG2PCBackend: another AG2PCBackend is already installed");
    singleton_ = this;
  }
  ~AG2PCBackend() override {
    delete mpc;
    if (singleton_ == this) singleton_ = nullptr;
  }

  size_t wire_bytes() const override { return sizeof(AG2PCWire); }

  // Public constants are first-class CONST0/CONST1 gates, allocated a real
  // recorder id and canonicalized per chunk (repeats alias the same wire). A
  // constant is therefore an ordinary wire — it can be revealed or carried like
  // any other, and a constant-only chunk is legal. The CONST gate has no
  // operands; run_chunk_ assigns it a compact id after the inputs.
  void public_label(void *out, bool b) override {
    int idx = b ? 1 : 0;
    if (const_wire_[idx] < 0) {
      int o = alloc_id_();
      chunk_gates_.push_back({-1, -1, o,
                              b ? frontend::Op::CONST1 : frontend::Op::CONST0});
      const_wire_[idx] = o;
    }
    *static_cast<AG2PCWire *>(out) = AG2PCWire(const_wire_[idx]);
  }

  void feed(void *out, int from_party, const bool *in, size_t n) override {
    if (from_party == PUBLIC) {
      for (size_t i = 0; i < n; ++i)
        public_label(static_cast<AG2PCWire *>(out) + i, in[i]);
      return;
    }
    // A secret input arriving after real compute gates would break the "inputs
    // first" wire layout of the current chunk — transparently flush the chunk
    // (carrying every alive wire forward) so this input starts a fresh chunk.
    // Costs one protocol round. (Recorded CONST gates don't count: they read no
    // inputs, so they impose no ordering on a later secret feed.)
    if (chunk_real_gates_ > 0) checkpoint_keep_all();
    InputRec rec;
    rec.owner = from_party;
    rec.bits.assign(in, in + n);
    rec.ids.resize(n);
    for (size_t i = 0; i < n; ++i) {
      int id = alloc_id_();
      rec.ids[i] = id;
      *(static_cast<AG2PCWire *>(out) + i) = AG2PCWire(id);
    }
    chunk_inputs_.push_back(std::move(rec));
  }

  void and_gate(void *out, const void *l, const void *r) override {
    int a = id_of_(l), b = id_of_(r);
    int o = alloc_id_();
    chunk_gates_.push_back({a, b, o, frontend::Op::AND});
    *static_cast<AG2PCWire *>(out) = AG2PCWire(o);
    ++ands_;
    ++chunk_real_gates_;
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int a = id_of_(l), b = id_of_(r);
    int o = alloc_id_();
    chunk_gates_.push_back({a, b, o, frontend::Op::XOR});
    *static_cast<AG2PCWire *>(out) = AG2PCWire(o);
    ++chunk_real_gates_;
  }
  void not_gate(void *out, const void *in) override {
    int a = id_of_(in);
    int o = alloc_id_();
    chunk_gates_.push_back({a, -1, o, frontend::Op::NOT});
    *static_cast<AG2PCWire *>(out) = AG2PCWire(o);
    ++chunk_real_gates_;
  }

  // Reveal: flush the current chunk (everyone alive carries forward; the
  // reveal-target wires are alive because they're still referenced by the
  // user's `in` array), then decode the requested ids to `to_party`.
  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    std::vector<int> rev(n);
    for (size_t i = 0; i < n; ++i) rev[i] = id_of_(static_cast<const AG2PCWire *>(in) + i);
    checkpoint_keep_all();   // carry every alive wire (including rev[]) forward
    SecureWires sub = gather_carried_(rev);
    std::vector<bool> bits = mpc->decode(sub, to_party);
    if (!bits.empty())
      for (size_t i = 0; i < n; ++i) out[i] = bits[i];
  }

  // Run the protocol on the current chunk, carry every alive wire forward
  // (alive == has at least one live user-side Bit handle), reclaim dead slot
  // ids onto the free list. Replaces the old explicit checkpoint(keep, n):
  // with refcount tracking, the user can't under-specify keep, and the
  // backend doesn't risk dropping a wire whose Bit is still in scope.
  void checkpoint_keep_all() { run_chunk_(); }

  uint64_t num_and() override { return ands_; }
  void finalize() override {}

  // For tests: how many process_inputs calls this run made (one per chunk
  // that has any input, regardless of owner count, since the call is batched).
  int process_input_calls = 0;

  // For tests / instrumentation: how many slot ids are currently pinned by
  // some user-side Bit handle. The new test_keep_all checks this to confirm
  // {Bit b;}-style dead wires actually drop from the carry.
  size_t live_wire_count() const {
    return (size_t)next_id_ - free_ids_.size() - pending_dead_ids_.size();
  }

  // Singleton install/uninstall lets the 4-byte AG2PCWire reach the backend
  // without growing the carrier. set in ctor, nulled in dtor; AG2PCWire's
  // pin_/unpin_ no-op when null (graceful post-finalize destruction).
  static AG2PCBackend *singleton_;

  // Refcount hooks called from AG2PCWire's ctor/copy/dtor. Bounds-checked
  // because default-constructed (null, id = -1) and out-of-range carriers flow
  // through the same path and must be skipped.
  void pin(int id) {
    if (id < 0 || (size_t)id >= meta_.size()) return;   // null / out of range
    ++meta_[id].refcount;
  }
  void unpin(int id) {
    if (id < 0 || (size_t)id >= meta_.size()) return;
    if (--meta_[id].refcount == 0)
      pending_dead_ids_.push_back(id);   // reclaimable at next chunk
  }

 private:
  // 5 bytes (8 with alignment) per recorder slot — `alive` distinguishes
  // "allocated, in use" from "free / never allocated"; `refcount` is the
  // user-side Bit handle count.
  struct WireMeta {
    uint32_t refcount = 0;
    bool     alive = false;
  };

  // Per-alive-id authenticated state carried across chunks (sparse — only
  // entries for wires actually held by a Bit across a chunk boundary).
  struct CarriedState {
    AShareBundle bundle;        // {mac, key} — Lambda is bit0(mac) for the share-bit
    unsigned char Lambda = 0;   // publicly-opened mask
    block label0 = zero_block;  // garbler-side m_{w,0}      (P1)
    block evlbl  = zero_block;  // evaluator-side m_{w,Lambda} (P2)
  };

  struct InputRec {
    int owner;
    std::vector<bool> bits;
    std::vector<int>  ids;
  };

  AG2PCSession *mpc = nullptr;
  std::vector<WireMeta> meta_;                  // indexed by slot id
  std::unordered_map<int, CarriedState> carried_;  // recorder id -> cross-chunk state
  std::vector<int> free_ids_;                   // stack: returned at chunk boundary
  std::vector<frontend::Gate> chunk_gates_;     // current-chunk gate log (frontend IR)
  std::vector<InputRec> chunk_inputs_;          // current-chunk input registrations
  int next_id_ = 0;                             // gid for never-allocated slots
  uint64_t ands_ = 0;
  // Canonical CONST0/CONST1 wire ids for the current chunk (-1 = not yet
  // emitted). public_label aliases repeats to these so each chunk holds at most
  // one c0 and one c1 wire; reset at every chunk boundary.
  int const_wire_[2] = {-1, -1};
  // Count of real compute gates (AND/XOR/NOT — excluding CONST0/CONST1) recorded
  // this chunk. A secret feed after a real gate must start a fresh chunk; CONST
  // gates impose no such ordering (they read no inputs), so they don't count.
  size_t chunk_real_gates_ = 0;
  // Slots whose refcount hit 0 mid-chunk; their ids stay reserved until the
  // next checkpoint, then are pushed to free_ids_ in bulk.
  std::vector<int> pending_dead_ids_;

  static int id_of_(const void *p) {
    return static_cast<const AG2PCWire *>(p)->id;
  }

  // Allocate a slot id for a new wire. Prefer free_ids_ (slot-reuse) for
  // cache compactness; otherwise grow meta_ by one entry.
  int alloc_id_() {
    int id;
    if (!free_ids_.empty()) {
      id = free_ids_.back();
      free_ids_.pop_back();
      meta_[id] = WireMeta{};
    } else {
      id = next_id_++;
      meta_.emplace_back();
      // AG2PCWire destructors call unpin_() noexcept; keep enough spare room
      // that pending_dead_ids_.push_back(id) never allocates on that path.
      if (pending_dead_ids_.capacity() < meta_.capacity())
        pending_dead_ids_.reserve(meta_.capacity());
    }
    meta_[id].alive = true;
    return id;
  }

  // Per-wire copy between SecureWires position i and CarriedState. The is_eval
  // branch picks the role-specific label slot (evaluator P2 holds eval_label,
  // garbler P1 holds label0); the other fields are role-independent.
  static void carry_load_(CarriedState &c, const SecureWires &s, size_t i, bool is_eval) {
    c.Lambda = s.Lambda[i];
    c.bundle = s.wire_bundle[i];
    if (is_eval) c.evlbl  = s.eval_label[i];
    else         c.label0 = s.label0[i];
  }
  static void carry_store_(const CarriedState &c, SecureWires &s, size_t i, bool is_eval) {
    s.Lambda[i] = c.Lambda;
    s.wire_bundle[i] = c.bundle;
    if (is_eval) s.eval_label[i] = c.evlbl;
    else         s.label0[i] = c.label0;
  }

  // Build the input SecureWires bundle from carried_ entries for the given
  // recorder ids (in caller order).
  SecureWires gather_carried_(const std::vector<int> &ids) const {
    SecureWires s;
    const bool is_eval = (party != 1);
    s.Lambda.resize(ids.size());
    s.wire_bundle.resize(ids.size());
    if (is_eval) s.eval_label.resize(ids.size());
    else         s.label0.resize(ids.size());
    for (size_t i = 0; i < ids.size(); ++i) {
      auto it = carried_.find(ids[i]);
      if (it == carried_.end())
        error("AG2PCBackend: gather_carried_ id has no carried state");
      carry_store_(it->second, s, i, is_eval);
    }
    return s;
  }

  // Stash a freshly-computed SecureWires bundle into carried_, keyed by
  // recorder id (in caller order).
  void stash_carried_(const std::vector<int> &ids, const SecureWires &s) {
    const bool is_eval = (party != 1);
    for (size_t i = 0; i < ids.size(); ++i)
      carry_load_(carried_[ids[i]], s, i, is_eval);
  }

  // Reclaim every id whose refcount hit 0 and that no longer needs to live
  // (chunk_gates_ has been consumed): push onto free_ids_, drop any carried
  // state. Called at every chunk boundary.
  void reclaim_dead_slots_() {
    if (pending_dead_ids_.empty()) return;
    for (int id : pending_dead_ids_) {
      WireMeta &m = meta_[id];
      if (m.refcount == 0 && m.alive) {
        free_ids_.push_back(id);
        carried_.erase(id);
        m = WireMeta{};
      }
    }
    pending_dead_ids_.clear();
  }

  // Run the current chunk through the protocol: pick out the reachable subgraph
  // (DCE from the alive-pinned ids), assemble a frontend::BooleanProgram with
  // compact ids, execute it on the shared engine (AG2PCEngine::run_program),
  // and stash every alive id's fresh state into carried_ so it survives to the
  // next chunk. reveal() gathers its decode targets from carried_ separately
  // (no decode-output slicing needed here).
  //
  // The recorder is just a buffering/chunking adapter: it emits a per-chunk
  // BooleanProgram and hands it to the one protocol executor (run_engine_).
  // There is no private garbling/evaluation path here.
  //
  // Memory: the per-chunk scratch is held as flat vectors sized to meta_.size()
  // / chunk_gates_.size() — index-by-id is O(1) and dense; we never pay the
  // 2–3× hash-table footprint that an unordered_map<int,int> would cost at
  // 10 M chunk-local wires. The chunk's gate list is moved (not copied) into
  // prog.gates and compacted in place, so we never hold two gate vectors at once.
  void run_chunk_() {
    if (chunk_gates_.empty() && chunk_inputs_.empty()) {
      reclaim_dead_slots_();
      return;
    }

    const int N = (int)meta_.size();
    const int G = (int)chunk_gates_.size();

    // wire_to_gate[id] = gate index in chunk_gates_ that produced id, else -1.
    std::vector<int> wire_to_gate(N, -1);
    for (int gi = 0; gi < G; ++gi)
      wire_to_gate[chunk_gates_[gi].out] = gi;

    // is_chunk_input[id] = was id registered as a new input THIS chunk?
    std::vector<char> is_chunk_input(N, 0);
    for (auto &r : chunk_inputs_)
      for (int id : r.ids) is_chunk_input[id] = 1;

    // Reachability: DFS-backward from alive chunk-local wires over parents.
    // A gate is needed iff its output is alive or has a needed consumer; gates
    // whose outputs were never pinned by a Bit ({Bit b;} pattern) and have no
    // live descendant are pruned — the protocol never pays for them.
    std::vector<char> needed(G, 0);
    std::vector<int> stack;
    for (int id = 0; id < N; ++id)
      if (meta_[id].refcount > 0 && wire_to_gate[id] >= 0) stack.push_back(id);
    while (!stack.empty()) {
      int w = stack.back();
      stack.pop_back();
      if (w < 0 || w >= N) continue;
      int gi = wire_to_gate[w];
      if (gi < 0 || needed[gi]) continue;
      needed[gi] = 1;
      const frontend::Gate &gg = chunk_gates_[gi];
      stack.push_back(gg.in0);
      if (!gg.is_not()) stack.push_back(gg.in1);
    }

    // Mark which non-chunk-local ids the needed gates actually read — those
    // become program inputs (either carried-from-prior or new chunk_input).
    // CONST gate operands are -1 and fall through the v<0 guard; the constants
    // themselves are chunk-local gates (handled by the reachability walk above).
    std::vector<char> input_needed(N, 0);
    auto note = [&](int v) {
      if (v < 0 || v >= N) return;
      if (wire_to_gate[v] >= 0) return;       // chunk-local (its producer is also needed)
      input_needed[v] = 1;
    };
    for (int gi = 0; gi < G; ++gi) {
      if (!needed[gi]) continue;
      const frontend::Gate &gg = chunk_gates_[gi];
      note(gg.in0);
      if (!gg.is_not()) note(gg.in1);
    }

    // Compact-id remap (flat, indexed by recorder id; -1 = unmapped).
    std::vector<int> remap(N, -1);
    int cid = 0;

    frontend::BooleanProgram prog;
    // One flat input bundle: positions [0, num_in) align with compact ids
    // [0, num_in) — exactly the order run_program binds inputs to wire ids.
    // prog.inputs mirrors that layout (carried group, then per-owner groups) so
    // the IR's declared input width matches input_bundle.size() exactly.
    SecureWires input_bundle;

    // 4a. Carried-from-prior-chunk inputs the needed gates reference. carried_in
    //     is built in id order so it's already sorted.
    std::vector<int> carried_in;
    for (int id = 0; id < N; ++id)
      if (input_needed[id] && !is_chunk_input[id]) carried_in.push_back(id);
    if (!carried_in.empty()) {
      append_bundle_(input_bundle, gather_carried_(carried_in));
      prog.inputs.push_back({cid, (int)carried_in.size()});
      for (int id : carried_in) remap[id] = cid++;
    }

    // 4b. New inputs grouped per owner. Include any input still alive (its Bit
    //     handle is in scope) OR referenced by a needed gate — an alive-but-
    //     unreferenced input still needs process_inputs fired so its state lives
    //     in carried_ for the NEXT chunk. Only dead-and-unreferenced inputs prune.
    //     The per-owner bit arrays go into a single batched mpc->process_inputs
    //     call so the whole input phase is one protocol invocation (~1 RTT on
    //     the wire), not one per owner.
    std::vector<int> owners;
    for (auto &r : chunk_inputs_)
      if (std::find(owners.begin(), owners.end(), r.owner) == owners.end())
        owners.push_back(r.owner);
    std::sort(owners.begin(), owners.end());
    std::vector<int> kept_owners;
    std::vector<std::vector<bool>> kept_bits;
    for (int owner : owners) {
      int base = cid;
      std::vector<bool> bits;
      for (auto &r : chunk_inputs_) {
        if (r.owner != owner) continue;
        for (size_t i = 0; i < r.ids.size(); ++i) {
          int id = r.ids[i];
          bool alive = (meta_[id].refcount > 0);
          if (!alive && !input_needed[id]) continue;
          remap[id] = cid++;
          bits.push_back(r.bits[i]);
        }
      }
      int cnt = cid - base;
      if (cnt == 0) continue;
      prog.inputs.push_back({base, cnt});
      kept_owners.push_back(owner);
      kept_bits.push_back(std::move(bits));
    }
    if (!kept_owners.empty()) {
      auto sub = mpc->process_inputs(kept_owners, kept_bits);
      for (auto &s : sub) append_bundle_(input_bundle, s);
      ++process_input_calls;
    }

    // At this point cid == the number of true input wires (carried + freshly
    // fed), and input_bundle has exactly that many positions. CONST gates below
    // get compact ids >= cid (produced by replay, not bound from input_bundle).

    // 4c. Move chunk_gates_ INTO prog.gates (O(1)) and compact in place: each
    //     needed gate (AND/XOR/NOT and CONST0/CONST1) gets rewritten with
    //     remapped operands + a fresh compact output id, written into the next
    //     write slot; pruned gates are skipped. Emission order is preserved, so
    //     a CONST gate is compacted (and thus produced on replay) before any
    //     gate that reads it. This avoids the 2× peak of a fresh prog.gates
    //     vector growing while chunk_gates_ is still alive.
    auto rm = [&](int v) -> int { return remap[v]; };   // v in [0, N); flat lookup
    prog.gates = std::move(chunk_gates_);           // chunk_gates_ left empty
    int write_idx = 0;
    for (int gi = 0; gi < (int)prog.gates.size(); ++gi) {
      if (!needed[gi]) continue;
      frontend::Gate gg = prog.gates[gi];           // value copy (16 B)
      int compact_out = cid++;
      remap[gg.out] = compact_out;
      int ni0 = gg.is_const() ? -1 : rm(gg.in0);
      int ni1 = (gg.is_const() || gg.is_not()) ? -1 : rm(gg.in1);
      prog.gates[write_idx++] = frontend::Gate{ni0, ni1, compact_out, gg.op};
    }
    prog.gates.resize(write_idx);

    // 5. Program outputs = every alive id that ended up in the program (had its
    //    remap entry set in 4a/4b/4d). Alive ids carried over from a prior chunk
    //    but unused this chunk stay in carried_ unchanged.
    std::vector<int> all_out_recorder;
    for (int id = 0; id < N; ++id)
      if (meta_[id].refcount > 0 && remap[id] >= 0)
        all_out_recorder.push_back(id);

    prog.num_wire = cid;
    prog.outputs.reserve(all_out_recorder.size());
    for (int id : all_out_recorder) prog.outputs.push_back(remap[id]);

    // 6. Run the protocol on the shared engine. run_program binds input_bundle
    //    positions to wire ids [0, input_bundle.size()), replays the gates
    //    through run_engine_, and gathers prog.outputs.
    AG2PCEngine runner(mpc);
    SecureWires result = runner.run_program(prog, input_bundle, prog.outputs);

    // 7. Stash every alive id's fresh state into carried_ so the next chunk
    //    can find it (and reveal() can gather it).
    stash_carried_(all_out_recorder, result);

    // 8. Consume per-chunk state; reclaim dead slots onto the free list. The
    //    constant cache and real-gate counter reset so the next chunk re-emits
    //    its own CONST gates (a carried constant lives on as an ordinary wire).
    chunk_inputs_.clear();
    const_wire_[0] = const_wire_[1] = -1;
    chunk_real_gates_ = 0;
    reclaim_dead_slots_();
  }

  // Concatenate one per-owner / carried SecureWires bundle onto the flat input
  // bundle, preserving wire order. Only the role-relevant label vector is
  // present (label0 for the garbler P1, eval_label for the evaluator P2); the
  // role-independent fields (Lambda, wire_bundle) always carry.
  void append_bundle_(SecureWires &dst, const SecureWires &src) const {
    dst.Lambda.insert(dst.Lambda.end(), src.Lambda.begin(), src.Lambda.end());
    dst.wire_bundle.insert(dst.wire_bundle.end(),
                           src.wire_bundle.begin(), src.wire_bundle.end());
    if (party == 1)
      dst.label0.insert(dst.label0.end(), src.label0.begin(), src.label0.end());
    else
      dst.eval_label.insert(dst.eval_label.end(),
                            src.eval_label.begin(), src.eval_label.end());
  }
};

// Out-of-line so they can reference AG2PCBackend::singleton_ (declared above).
inline void AG2PCWire::pin_() noexcept {
  if (id >= 0 && AG2PCBackend::singleton_ != nullptr)
    AG2PCBackend::singleton_->pin(id);
}
inline void AG2PCWire::unpin_() noexcept {
  if (id >= 0 && AG2PCBackend::singleton_ != nullptr)
    AG2PCBackend::singleton_->unpin(id);
}

inline AG2PCBackend *AG2PCBackend::singleton_ = nullptr;

// The user-facing setup_ag2pc / reveal_ag2pc / checkpoint_ag2pc_keep_all /
// finalize_ag2pc free functions live in frontend/ag2pc.h (the public entry).

}  // namespace emp
#endif  // EMP_AG2PC_DIRECT_BACKEND_H__
