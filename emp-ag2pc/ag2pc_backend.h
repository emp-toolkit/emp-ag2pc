#ifndef EMP_AG2PC_BACKEND_H__
#define EMP_AG2PC_BACKEND_H__
#include "emp-tool/execution/backend.h"
#include "emp-ag2pc/2pc.h"
#include "emp-ag2pc/wire_graph.h"
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
    mpc = new C2PC(io, pool_, party_, ssp);
    if (singleton_ != nullptr)
      error("AG2PCBackend: another AG2PCBackend is already installed");
    singleton_ = this;
  }
  ~AG2PCBackend() override {
    delete mpc;
    if (singleton_ == this) singleton_ = nullptr;
  }

  size_t wire_bytes() const override { return sizeof(AG2PCWire); }

  // Public constants get sentinel ids (consume no slot, stay out of the
  // input/gate id space). They are resolved to real wires inside run_chunk —
  // c0 = XOR(w0,w0), c1 = NOT c0 — so a constant may legally appear before any
  // input is fed.
  void public_label(void *out, bool b) override {
    if (b) used_c1_ = true; else used_c0_ = true;
    *static_cast<AG2PCWire *>(out) = AG2PCWire(b ? kConst1 : kConst0);
  }

  void feed(void *out, int from_party, const bool *in, size_t n) override {
    if (from_party == PUBLIC) {
      for (size_t i = 0; i < n; ++i)
        public_label(static_cast<AG2PCWire *>(out) + i, in[i]);
      return;
    }
    // A secret input arriving after gates would break the "inputs first" wire
    // layout of the current chunk — transparently flush the chunk (carrying
    // every alive wire forward) so this input starts a fresh chunk. Costs one
    // protocol round.
    if (!chunk_gates_.empty()) checkpoint_keep_all();
    InputRec rec;
    rec.owner = from_party;
    rec.bits.assign(in, in + n);
    rec.ids.resize(n);
    for (size_t i = 0; i < n; ++i) {
      int id = alloc_id_(OP_INPUT, -1, -1);
      rec.ids[i] = id;
      *(static_cast<AG2PCWire *>(out) + i) = AG2PCWire(id);
    }
    chunk_inputs_.push_back(std::move(rec));
  }

  void and_gate(void *out, const void *l, const void *r) override {
    int a = id_of_(l), b = id_of_(r);
    int o = alloc_id_(OP_AND, a, b);
    chunk_gates_.push_back({a, b, o, Gate::AND_PENDING});
    *static_cast<AG2PCWire *>(out) = AG2PCWire(o);
    ++ands_;
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int a = id_of_(l), b = id_of_(r);
    int o = alloc_id_(OP_XOR, a, b);
    chunk_gates_.push_back({a, b, o, Gate::XOR_TAG});
    *static_cast<AG2PCWire *>(out) = AG2PCWire(o);
  }
  void not_gate(void *out, const void *in) override {
    int a = id_of_(in);
    int o = alloc_id_(OP_NOT, a, -1);
    chunk_gates_.push_back({a, 0, o, Gate::NOT_TAG});
    *static_cast<AG2PCWire *>(out) = AG2PCWire(o);
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
  void checkpoint_keep_all() { run_chunk_({}, /*carry_alive=*/true); }

  uint64_t num_and() override { return ands_; }
  void finalize() override {}

  // For tests: how many process_input calls this run made (per owner).
  int process_input_calls = 0;

  // For tests / instrumentation: how many slot ids are currently pinned by
  // some user-side Bit handle. The new test_keep_all checks this to confirm
  // {Bit b;}-style dead wires actually drop from the carry.
  size_t live_wire_count() const {
    return (size_t)next_id_ - free_ids_.size() - free_buffered_dead_;
  }

  // Singleton install/uninstall lets the 4-byte AG2PCWire reach the backend
  // without growing the carrier. set in ctor, nulled in dtor; AG2PCWire's
  // pin_/unpin_ no-op when null (graceful post-finalize destruction).
  static AG2PCBackend *singleton_;

  // Refcount hooks called from AG2PCWire's ctor/copy/dtor. Bounds-checked
  // because constant sentinels (kConst0/kConst1) flow through the same
  // carrier and have negative ids that must be skipped.
  void pin(int id) {
    if (id < 0 || (size_t)id >= meta_.size()) return;   // sentinel / null
    ++meta_[id].refcount;
  }
  void unpin(int id) {
    if (id < 0 || (size_t)id >= meta_.size()) return;
    if (--meta_[id].refcount == 0) ++free_buffered_dead_;   // reclaimable at next chunk
  }

 private:
  enum WireOp : uint8_t {
    OP_NONE = 0, OP_INPUT, OP_AND, OP_XOR, OP_NOT, OP_CONST,
  };

  struct WireMeta {
    uint32_t refcount = 0;
    uint8_t  op = OP_NONE;
    int      parents[2] = {-1, -1};   // -1 = no parent / sentinel
  };

  // Per-alive-id authenticated state carried across chunks (sparse — only
  // entries for wires actually held by a Bit across a chunk boundary).
  struct CarriedState {
    AShareBundle bundle;        // {mac, key} — Lambda is bit0(mac) for the share-bit
    unsigned char Lambda = 0;   // publicly-opened mask
    block label0 = zero_block;  // garbler-side m_{w,0}
    block evlbl  = zero_block;  // P1-side m_{w,Lambda}
  };

  struct InputRec {
    int owner;
    std::vector<bool> bits;
    std::vector<int>  ids;
  };

  C2PC *mpc = nullptr;
  std::vector<WireMeta> meta_;                  // indexed by slot id
  std::unordered_map<int, CarriedState> carried_;  // recorder id -> cross-chunk state
  std::vector<int> free_ids_;                   // stack: returned at chunk boundary
  std::vector<Gate> chunk_gates_;               // current-chunk gate log
  std::vector<InputRec> chunk_inputs_;          // current-chunk input registrations
  int next_id_ = 0;                             // gid for never-allocated slots
  uint64_t ands_ = 0;
  bool used_c0_ = false, used_c1_ = false;
  // Count of slots whose refcount hit 0 mid-chunk; their ids stay reserved
  // until the next checkpoint, then are pushed to free_ids_ in bulk.
  size_t free_buffered_dead_ = 0;
  static constexpr int kConst0 = -2, kConst1 = -3;  // public-constant sentinels

  static int id_of_(const void *p) {
    return static_cast<const AG2PCWire *>(p)->id;
  }

  // Allocate a slot id for a new wire. Prefer free_ids_ (slot-reuse) for
  // cache compactness; otherwise grow meta_ by one entry.
  int alloc_id_(WireOp op, int p0, int p1) {
    int id;
    if (!free_ids_.empty()) {
      id = free_ids_.back();
      free_ids_.pop_back();
      meta_[id] = WireMeta{};
    } else {
      id = next_id_++;
      meta_.emplace_back();
    }
    meta_[id].op = (uint8_t)op;
    meta_[id].parents[0] = p0;
    meta_[id].parents[1] = p1;
    return id;
  }

  // Build the input SecureWires bundle from carried_ entries for the given
  // recorder ids (in caller order).
  SecureWires gather_carried_(const std::vector<int> &ids) const {
    SecureWires s;
    s.Lambda.resize(ids.size());
    s.wire_bundle.resize(ids.size());
    const bool is_p1 = (party == 1);
    if (is_p1) s.eval_label.resize(ids.size());
    else        s.label0.resize(ids.size());
    for (size_t i = 0; i < ids.size(); ++i) {
      auto it = carried_.find(ids[i]);
      if (it == carried_.end())
        error("AG2PCBackend: gather_carried_ id has no carried state");
      const CarriedState &c = it->second;
      s.Lambda[i] = c.Lambda;
      s.wire_bundle[i] = c.bundle;
      if (is_p1) s.eval_label[i] = c.evlbl;
      else        s.label0[i] = c.label0;
    }
    return s;
  }

  // Stash a freshly-computed SecureWires bundle into carried_, keyed by
  // recorder id (in caller order).
  void stash_carried_(const std::vector<int> &ids, const SecureWires &s) {
    const bool is_p1 = (party == 1);
    for (size_t i = 0; i < ids.size(); ++i) {
      CarriedState &c = carried_[ids[i]];
      c.Lambda = s.Lambda[i];
      c.bundle = s.wire_bundle[i];
      if (is_p1) c.evlbl  = s.eval_label[i];
      else        c.label0 = s.label0[i];
    }
  }

  // Reclaim every id whose refcount hit 0 and that no longer needs to live
  // (chunk_gates_ has been consumed): push onto free_ids_, drop any carried
  // state. Called at every chunk boundary.
  void reclaim_dead_slots_() {
    if (free_buffered_dead_ == 0) return;
    for (int id = 0; id < (int)meta_.size(); ++id) {
      WireMeta &m = meta_[id];
      if (m.refcount == 0 && m.op != OP_NONE) {
        free_ids_.push_back(id);
        carried_.erase(id);
        m = WireMeta{};
      }
    }
    free_buffered_dead_ = 0;
  }

  // Backward reachability over chunk_gates_'s parent edges, seeded from the
  // alive wire ids: a gate is "needed" iff its output is alive or has a needed
  // consumer. Gates whose outputs were never pinned by a Bit (the {Bit b;}
  // pattern) and have no live descendant are pruned — the protocol never
  // pays for them.
  // Returns the list of needed gate indices in chunk_gates_ in topological
  // (recording) order.
  std::vector<int> reachable_gates_from_alive_() const {
    // 1. For every wire id produced THIS chunk, look up its gate index.
    //    chunk_gates_ is in recording order, and recording assigns ids
    //    monotonically (free_ids_ doesn't fire mid-chunk), so the id->gate
    //    map for chunk-local wires is sparse over [some_min, next_id_).
    std::unordered_map<int, int> wire_to_gate;
    wire_to_gate.reserve(chunk_gates_.size());
    for (int gi = 0; gi < (int)chunk_gates_.size(); ++gi)
      wire_to_gate.emplace(chunk_gates_[gi].out, gi);

    // 2. Mark + walk: from each alive id, DFS-backward over parents
    //    confined to chunk-local wires. Inputs/carried/constants stop the walk.
    std::vector<char> needed(chunk_gates_.size(), 0);
    std::vector<int> stack;
    for (int id = 0; id < (int)meta_.size(); ++id)
      if (meta_[id].refcount > 0) stack.push_back(id);
    while (!stack.empty()) {
      int w = stack.back();
      stack.pop_back();
      auto it = wire_to_gate.find(w);
      if (it == wire_to_gate.end()) continue;        // input / carried / sentinel
      int gi = it->second;
      if (needed[gi]) continue;
      needed[gi] = 1;
      const Gate &gg = chunk_gates_[gi];
      stack.push_back(gg.in0);
      if (gg.op != Gate::NOT_TAG) stack.push_back(gg.in1);
    }

    std::vector<int> out;
    out.reserve(chunk_gates_.size());
    for (int gi = 0; gi < (int)chunk_gates_.size(); ++gi)
      if (needed[gi]) out.push_back(gi);
    return out;
  }

  // Run the current chunk through the protocol. If `decode_out_ids` is empty,
  // the chunk is being checkpointed (no caller-visible outputs — just carry
  // alive state forward). Otherwise, return SecureWires for those ids
  // (caller will decode them).
  //
  // Recorder ids are sparse over [0, next_id_); the WireGraph requires dense
  // ids starting at 0, so this function builds a per-chunk remap.
  SecureWires run_chunk_(const std::vector<int> &decode_out_ids,
                         bool carry_alive) {
    // 1. Reachable gates from alive (DCE).
    std::vector<int> needed_gates = reachable_gates_from_alive_();

    // 2. Collect inputs needed by the reachable gates:
    //    - Prior-chunk carried (in carried_).
    //    - This chunk's new chunk_inputs_ (but only ids actually referenced).
    //    - Public-constant sentinels (kConst0/kConst1) — resolved to fresh
    //      gates at the start of the chunk.
    //    Output wire ids produced THIS chunk are NOT inputs; they're gate
    //    outputs and get fresh compact ids when we emit them.
    std::unordered_set<int> needed_inputs;
    bool need_c0 = false, need_c1 = false;
    auto note_id = [&](int id) {
      if (id == kConst0) { need_c0 = true; return; }
      if (id == kConst1) { need_c0 = need_c1 = true; return; }
      if (id < 0) return;
      // If id is produced by ANY needed chunk gate, it's an internal wire
      // (not an input). Check via wire_to_gate; if not chunk-local, it must
      // be carried or a new input.
      // Optimization: we'll build a chunk_local set below.
      needed_inputs.insert(id);
    };
    std::unordered_set<int> chunk_local_outputs;
    for (int gi : needed_gates) chunk_local_outputs.insert(chunk_gates_[gi].out);
    for (int gi : needed_gates) {
      const Gate &gg = chunk_gates_[gi];
      if (!chunk_local_outputs.count(gg.in0)) note_id(gg.in0);
      if (gg.op != Gate::NOT_TAG && !chunk_local_outputs.count(gg.in1)) note_id(gg.in1);
    }
    // decode_out_ids must also be available — they're all alive, so either
    // chunk-local (already covered) or carried (must be inputs).
    for (int id : decode_out_ids)
      if (!chunk_local_outputs.count(id)) note_id(id);

    // 3. Split needed_inputs into (carried-from-prior-chunk) and
    //    (this-chunk's new inputs registered in chunk_inputs_).
    std::unordered_map<int, std::pair<int, int>> input_owner_pos;  // id -> (owner, position-within-owner)
    // Build a map: id -> (owner) for chunk_inputs_; we'll order owners later.
    std::unordered_map<int, int> id_to_owner;
    for (auto &r : chunk_inputs_)
      for (int id : r.ids) id_to_owner[id] = r.owner;

    std::vector<int> carried_in;
    carried_in.reserve(needed_inputs.size());
    for (int id : needed_inputs) {
      if (id_to_owner.count(id)) continue;     // new input, handled below
      carried_in.push_back(id);                 // must be a carried prior-chunk id
    }
    std::sort(carried_in.begin(), carried_in.end());

    // 4. Assemble the WireGraph in compact-id space:
    //    [0, n_carried)                                — prior-chunk carried
    //    [n_carried, n_carried + n_new)                — new inputs, owner-grouped
    //    [n_carried + n_new, ...)                      — gate outputs (in recording order)
    //    Plus prepended c0 / c1 gates if constants used.
    WireGraph g;
    std::vector<SecureWires> bundles;
    std::unordered_map<int, int> remap;   // recorder id -> compact WireGraph id
    int cid = 0;

    // 4a. Carried inputs.
    int n_carried = (int)carried_in.size();
    if (n_carried > 0) {
      bundles.push_back(gather_carried_(carried_in));
      for (int id : carried_in) remap[id] = cid++;
    }

    // 4b. New inputs grouped per owner. Include any input that is still alive
    //     (Bit handle in scope) OR referenced by a needed gate this chunk —
    //     an alive-but-unreferenced input still needs process_input fired so
    //     its authenticated state lives in carried_ for the NEXT chunk to use.
    //     Only dead-and-unreferenced inputs are pruned.
    std::vector<int> owners;
    for (auto &r : chunk_inputs_)
      if (std::find(owners.begin(), owners.end(), r.owner) == owners.end())
        owners.push_back(r.owner);
    std::sort(owners.begin(), owners.end());
    for (int owner : owners) {
      int base = cid;
      std::vector<bool> bits;
      for (auto &r : chunk_inputs_)
        if (r.owner == owner)
          for (size_t i = 0; i < r.ids.size(); ++i) {
            int id = r.ids[i];
            bool alive = (meta_[id].refcount > 0);
            if (!alive && !needed_inputs.count(id)) continue;   // dead + unreferenced → prune
            remap[id] = cid++;
            bits.push_back(r.bits[i]);
          }
      int cnt = cid - base;
      if (cnt == 0) continue;
      g.inputs.push_back({owner, base, cnt});
      std::unique_ptr<bool[]> buf(new bool[cnt]);
      for (int i = 0; i < cnt; ++i) buf[i] = bits[i];
      bundles.push_back(mpc->process_input(buf.get(), cnt, owner));
      ++process_input_calls;
    }

    // 4c. Public-constant resolution: synthesize c0/c1 as gates if needed.
    if (need_c0 || need_c1) {
      if (cid == 0)
        error("AG2PCBackend: public constant requires >=1 input");
      int c0 = cid++;
      g.gates.push_back({0, 0, c0, Gate::XOR_TAG});
      remap[kConst0] = c0;
      if (need_c1) {
        int c1 = cid++;
        g.gates.push_back({c0, 0, c1, Gate::NOT_TAG});
        remap[kConst1] = c1;
      }
    }

    // 4d. Emit needed chunk_gates_ in recording order with remapped operand ids.
    auto rm = [&](int v) -> int {
      auto it = remap.find(v);
      if (it == remap.end())
        error("AG2PCBackend: gate operand id missing in remap");
      return it->second;
    };
    for (int gi : needed_gates) {
      const Gate &gg = chunk_gates_[gi];
      int compact_out = cid++;
      remap[gg.out] = compact_out;
      Gate emit{rm(gg.in0), (gg.op == Gate::NOT_TAG ? 0 : rm(gg.in1)),
                compact_out, gg.op};
      g.gates.push_back(emit);
    }

    // 5. WireGraph output ids: every alive id that's actually IN the WireGraph
    //    (i.e., has a remap entry — chunk_inputs_ that survived 4b, carried_in
    //    referenced by a gate, or a reachable gate output). Alive ids that are
    //    carried-from-prior-and-unused stay in carried_ unchanged — their
    //    state is already correct and they don't need a WireGraph slot.
    std::vector<int> all_out_recorder;
    if (carry_alive) {
      for (int id = 0; id < (int)meta_.size(); ++id)
        if (meta_[id].refcount > 0 && remap.count(id))
          all_out_recorder.push_back(id);
    }
    // (no decode targets: reveal() gathers from carried_ separately, after
    //  this chunk has stashed every alive id's state.)

    g.num_wire = cid;
    g.output_ids.reserve(all_out_recorder.size());
    for (int id : all_out_recorder) g.output_ids.push_back(rm(id));
    g.output_to.assign(g.output_ids.size(), 0);

    // 6. Liveness + AND-index numbering. Same shape as the old run_chunk;
    //    operates on the compact WireGraph.
    g.last_use.assign(g.num_wire, -1);
    int ng = g.num_gate(), ai = 0;
    for (int gi = 0; gi < ng; ++gi) {
      Gate &gg = g.gates[gi];
      g.last_use[gg.in0] = gi;
      g.last_use[gg.in1] = gi;
      if (gg.op == Gate::AND_PENDING) gg.op = ai++;
    }
    g.num_ands = ai;

    // 7. Run the protocol.
    SecureWires result = mpc->compute(g, bundles);

    // 8. Stash every alive id's fresh state into carried_; the chunk-local
    //    Bit handles still hold these ids and will reference carried_ in the
    //    next chunk's run_chunk.
    if (carry_alive) stash_carried_(all_out_recorder, result);
    SecureWires decoded;
    if (!decode_out_ids.empty()) {
      // Slice out the decode targets from result.
      // all_out_recorder is sorted; find index of each decode_out_id.
      decoded.Lambda.resize(decode_out_ids.size());
      decoded.wire_bundle.resize(decode_out_ids.size());
      const bool is_p1 = (party == 1);
      if (is_p1) decoded.eval_label.resize(decode_out_ids.size());
      else        decoded.label0.resize(decode_out_ids.size());
      for (size_t k = 0; k < decode_out_ids.size(); ++k) {
        auto it = std::lower_bound(all_out_recorder.begin(),
                                   all_out_recorder.end(), decode_out_ids[k]);
        int idx = (int)(it - all_out_recorder.begin());
        decoded.Lambda[k] = result.Lambda[idx];
        decoded.wire_bundle[k] = result.wire_bundle[idx];
        if (is_p1) decoded.eval_label[k] = result.eval_label[idx];
        else        decoded.label0[k] = result.label0[idx];
      }
    }

    // 9. Consume chunk_gates_ / chunk_inputs_; reclaim dead slots.
    chunk_gates_.clear();
    chunk_inputs_.clear();
    used_c0_ = used_c1_ = false;
    reclaim_dead_slots_();

    return decoded;
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

inline AG2PCBackend *setup_ag2pc(NetIO *io, ThreadPool *pool, int party,
                                 int ssp = 40) {
  auto *b = new AG2PCBackend(io, pool, party, ssp);
  backend = b;
  return b;
}

// Reveal n wire carriers to ALL parties (returns the values, keeps all alive
// wires live, continues recording). A single Bit can also use
// `x.reveal<bool>(PUBLIC)` directly.
inline void reveal_ag2pc(bool *out, void *wires, int n) {
  backend->reveal(out, PUBLIC, wires, n);
}

// Force evaluation of the chunk recorded so far. Every wire still pinned by a
// live user-side Bit carries its authenticated state into the next chunk;
// wires whose Bit handles have gone out of scope are dropped (RAII-driven —
// no `keep[]` list to maintain). Caps gate-list and triple-gen transient
// memory for long compositions.
inline void checkpoint_ag2pc_keep_all() {
  static_cast<AG2PCBackend *>(backend)->checkpoint_keep_all();
}

inline void finalize_ag2pc() {
  if (backend == nullptr) return;
  backend->finalize();
  delete backend;
  backend = nullptr;
}

}  // namespace emp
#endif  // EMP_AG2PC_BACKEND_H__
