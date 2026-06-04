#ifndef EMP_AG2PC_DIRECT_BACKEND_H__
#define EMP_AG2PC_DIRECT_BACKEND_H__
#include "emp-tool/execution/backend.h"
#include "emp-ag2pc/backend/session.h"
#include "emp-ag2pc/backend/engine.h"
#include "emp-tool/frontend/boolean_program.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace emp {

// Object-mode backend for emp-tool's Bit / Integer / Float APIs. It records the
// current chunk as a BooleanProgram and executes the chunk on AG2PCEngine.
//
// AG2PCWire is a refcounted wire id. Live Bit objects pin ids across chunk
// boundaries; dead ids are reclaimed at the next chunk boundary.
//
// Recording layout (flat arrays, free-list-reused slot ids):
//   meta_[id] = { refcount, op, parents }     — per-slot persistent recording state
//   carried_[id] = { Lambda, mac, key, label } — cross-chunk carried state
//   free_ids_                                 — stack of ids returnable for reuse
//   chunk_gates_, chunk_inputs_               — current-chunk gate / input log
//
// Slot ids are reclaimed only at chunk boundaries.

class AG2PCBackend;

// 4-byte wire carrier with refcount hooks.
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
  // Defined after AG2PCBackend.
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

  // Public constants are canonical CONST0/CONST1 wires within each chunk.
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
    // Secret inputs start a fresh chunk after compute gates.
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

  // Flush the current chunk, then decode the requested wires.
  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    std::vector<int> rev(n);
    for (size_t i = 0; i < n; ++i) rev[i] = id_of_(static_cast<const AG2PCWire *>(in) + i);
    checkpoint_keep_all();
    SecureWires sub = gather_carried_(rev);
    std::vector<bool> bits = mpc->decode(sub, to_party);
    if (!bits.empty())
      for (size_t i = 0; i < n; ++i) out[i] = bits[i];
  }

  // Execute the current chunk and carry live wires forward.
  void checkpoint_keep_all() { run_chunk_(); }

  uint64_t num_and() override { return ands_; }
  void finalize() override {}

  // Number of batched input phases executed.
  int process_input_calls = 0;

  // Number of recorder ids currently pinned by user-side Bit objects.
  size_t live_wire_count() const {
    return (size_t)next_id_ - free_ids_.size() - pending_dead_ids_.size();
  }

  // Installed backend for AG2PCWire refcount hooks.
  static AG2PCBackend *singleton_;

  // Refcount hooks called from AG2PCWire.
  void pin(int id) {
    if (id < 0 || (size_t)id >= meta_.size()) return;
    ++meta_[id].refcount;
  }
  void unpin(int id) {
    if (id < 0 || (size_t)id >= meta_.size()) return;
    if (--meta_[id].refcount == 0)
      pending_dead_ids_.push_back(id);
  }

 private:
  // Per-recorder-slot ownership state.
  struct WireMeta {
    uint32_t refcount = 0;
    bool     alive = false;
  };

  // Authenticated state carried across chunks.
  struct CarriedState {
    AShareBundle bundle;
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
  // Per-chunk canonical CONST0/CONST1 wire ids.
  int const_wire_[2] = {-1, -1};
  // Compute gates recorded in the current chunk, excluding CONST0/CONST1.
  size_t chunk_real_gates_ = 0;
  // Dead ids pending chunk-boundary reclamation.
  std::vector<int> pending_dead_ids_;

  static int id_of_(const void *p) {
    return static_cast<const AG2PCWire *>(p)->id;
  }

  // Allocate a recorder id.
  int alloc_id_() {
    int id;
    if (!free_ids_.empty()) {
      id = free_ids_.back();
      free_ids_.pop_back();
      meta_[id] = WireMeta{};
    } else {
      id = next_id_++;
      meta_.emplace_back();
      // unpin_() is noexcept; avoid allocation on its pending_dead_ids_ push.
      if (pending_dead_ids_.capacity() < meta_.capacity())
        pending_dead_ids_.reserve(meta_.capacity());
    }
    meta_[id].alive = true;
    return id;
  }

  // Per-wire copy between SecureWires and carried state.
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

  // Gather carried wires in caller order.
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

  // Stash freshly computed carried wires in caller order.
  void stash_carried_(const std::vector<int> &ids, const SecureWires &s) {
    const bool is_eval = (party != 1);
    for (size_t i = 0; i < ids.size(); ++i)
      carry_load_(carried_[ids[i]], s, i, is_eval);
  }

  // Reclaim ids whose refcount reached zero during the chunk.
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

  // Execute the reachable part of the current chunk as a BooleanProgram.
  void run_chunk_() {
    if (chunk_gates_.empty() && chunk_inputs_.empty()) {
      reclaim_dead_slots_();
      return;
    }

    const int N = (int)meta_.size();
    const int G = (int)chunk_gates_.size();

    // Producer gate for each chunk-local wire.
    std::vector<int> wire_to_gate(N, -1);
    for (int gi = 0; gi < G; ++gi)
      wire_to_gate[chunk_gates_[gi].out] = gi;

    // Wires registered as inputs in this chunk.
    std::vector<char> is_chunk_input(N, 0);
    for (auto &r : chunk_inputs_)
      for (int id : r.ids) is_chunk_input[id] = 1;

    // Reachability from alive chunk-local wires.
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

    // Non-local wires read by needed gates become program inputs.
    std::vector<char> input_needed(N, 0);
    auto note = [&](int v) {
      if (v < 0 || v >= N) return;
      if (wire_to_gate[v] >= 0) return;
      input_needed[v] = 1;
    };
    for (int gi = 0; gi < G; ++gi) {
      if (!needed[gi]) continue;
      const frontend::Gate &gg = chunk_gates_[gi];
      note(gg.in0);
      if (!gg.is_not()) note(gg.in1);
    }

    // Compact-id remap by recorder id.
    std::vector<int> remap(N, -1);
    int cid = 0;

    frontend::BooleanProgram prog;
    // One flat input bundle matching compact ids [0, num_in).
    SecureWires input_bundle;

    // 1. Carried inputs referenced by needed gates.
    std::vector<int> carried_in;
    for (int id = 0; id < N; ++id)
      if (input_needed[id] && !is_chunk_input[id]) carried_in.push_back(id);
    if (!carried_in.empty()) {
      append_bundle_(input_bundle, gather_carried_(carried_in));
      prog.inputs.push_back({cid, (int)carried_in.size()});
      for (int id : carried_in) remap[id] = cid++;
    }

    // 2. New inputs grouped by owner.
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

    // CONST gates receive compact ids after the input range.

    // 3. Compact needed gates in emission order.
    auto rm = [&](int v) -> int { return remap[v]; };
    prog.gates = std::move(chunk_gates_);
    int write_idx = 0;
    for (int gi = 0; gi < (int)prog.gates.size(); ++gi) {
      if (!needed[gi]) continue;
      frontend::Gate gg = prog.gates[gi];
      int compact_out = cid++;
      remap[gg.out] = compact_out;
      int ni0 = gg.is_const() ? -1 : rm(gg.in0);
      int ni1 = (gg.is_const() || gg.is_not()) ? -1 : rm(gg.in1);
      prog.gates[write_idx++] = frontend::Gate{ni0, ni1, compact_out, gg.op};
    }
    prog.gates.resize(write_idx);

    // 4. Outputs are live recorder ids updated by this chunk.
    std::vector<int> all_out_recorder;
    for (int id = 0; id < N; ++id)
      if (meta_[id].refcount > 0 && remap[id] >= 0)
        all_out_recorder.push_back(id);

    prog.num_wire = cid;
    prog.outputs.reserve(all_out_recorder.size());
    for (int id : all_out_recorder) prog.outputs.push_back(remap[id]);

    // 5. Execute the compact program.
    AG2PCEngine runner(mpc);
    SecureWires result = runner.run_program(prog, input_bundle, prog.outputs);

    // 6. Stash fresh carried state.
    stash_carried_(all_out_recorder, result);

    // 7. Reset per-chunk state and reclaim dead ids.
    chunk_inputs_.clear();
    const_wire_[0] = const_wire_[1] = -1;
    chunk_real_gates_ = 0;
    reclaim_dead_slots_();
  }

  // Concatenate one SecureWires bundle onto the flat input bundle.
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

// AG2PCWire refcount hooks.
inline void AG2PCWire::pin_() noexcept {
  if (id >= 0 && AG2PCBackend::singleton_ != nullptr)
    AG2PCBackend::singleton_->pin(id);
}
inline void AG2PCWire::unpin_() noexcept {
  if (id >= 0 && AG2PCBackend::singleton_ != nullptr)
    AG2PCBackend::singleton_->unpin(id);
}

inline AG2PCBackend *AG2PCBackend::singleton_ = nullptr;

}  // namespace emp
#endif  // EMP_AG2PC_DIRECT_BACKEND_H__
