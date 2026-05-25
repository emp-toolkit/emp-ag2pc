#ifndef EMP_AG2PC_WRK_BACKEND_H__
#define EMP_AG2PC_WRK_BACKEND_H__
#include "emp-tool/execution/backend.h"
#include "emp-ag2pc/2pc.h"
#include "emp-ag2pc/wire_graph.h"
#include <algorithm>
#include <cstring>
#include <memory>
#include <vector>

namespace emp {

// Recording backend that lets people author WRK circuits in emp-tool's native
// Bit / Integer / Float frontend. Unlike a streaming GC backend, it does NOT run
// the protocol per gate: WRK is multi-pass and needs the whole circuit, so this
// backend *records* a WireGraph and runs the protocol once, at the (single,
// terminal) reveal.
//
// Scope (this version): all inputs are fed before any gate, and no gate is
// emitted after the first reveal — one straight-line segment.
//
// The native wire type stays Bit_T<block>; the block is used only as a carrier
// for an int wire id (low 4 bytes). Public constants are synthesized as ordinary
// gates (c0 = XOR(w,w), c1 = NOT(c0)) so the protocol needs no special handling.
template <int nP> class WRKBackend : public Backend {
public:
  WRKBackend(NetIO *io1_, NetIO *io2_, ThreadPool *pool_, int party_) {
    this->party = party_;
    mpc = new C2PC<nP>(io1_, io2_, pool_, party_);
  }
  ~WRKBackend() override { delete mpc; }

  size_t wire_bytes() const override { return sizeof(block); }

  // Public constants get sentinel ids (consume no gid, stay out of the input/
  // gate id space). They are resolved to real wires at reveal — c0 = XOR(w0,w0),
  // c1 = NOT c0 — so a constant may legally appear before any input is fed.
  void public_label(void *out, bool b) override {
    if (b) used_c1 = true; else used_c0 = true;
    set_id(out, b ? kConst1 : kConst0);
  }

  void feed(void *out, int from_party, const bool *in, size_t n) override {
    if (from_party == PUBLIC) {
      for (size_t i = 0; i < n; ++i) public_label((block *)out + i, in[i]);
      return;
    }
    // A secret input arriving after gates would break the "inputs first" wire
    // layout of the current span — transparently flush (keep everything live)
    // so this input starts a fresh span. Costs one protocol round.
    if (!gates_.empty()) flush_keep_all();
    InputRec rec;
    rec.owner = from_party;
    rec.bits.assign(in, in + n);
    rec.ids.resize(n);
    for (size_t i = 0; i < n; ++i) {
      rec.ids[i] = gid++;
      set_id((block *)out + i, rec.ids[i]);
    }
    input_log.push_back(std::move(rec));
  }

  void and_gate(void *out, const void *l, const void *r) override {
    int o = gid++;
    push(id_of(l), id_of(r), o, AND_GATE);
    set_id(out, o);
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int o = gid++;
    push(id_of(l), id_of(r), o, XOR_GATE);
    set_id(out, o);
  }
  void not_gate(void *out, const void *in) override {
    int o = gid++;
    push(id_of(in), 0, o, NOT_GATE);
    set_id(out, o);
  }

  // Non-terminal and liveness-neutral: evaluate the span so far keeping ALL wires
  // live (ids preserved), decode the requested wires to `to_party`, and continue
  // recording. For host branching use to_party == PUBLIC (all parties learn).
  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    std::vector<int> rev(n);
    for (size_t i = 0; i < n; ++i) rev[i] = id_of((const block *)in + i);
    flush_keep_all();  // carried_[k] = wire k's authenticated state, ids preserved
    SecureWires<nP> sub = slice(carried_, rev);
    std::vector<bool> bits = mpc->decode(sub, to_party);
    if (!bits.empty())
      for (size_t i = 0; i < n; ++i) out[i] = bits[i];
  }

  // Force the protocol to evaluate the gates recorded so far, keeping the `keep`
  // wires live (as authenticated SecureWires) and discarding the gate list. The
  // kept wires become the inputs of the next chunk — so a long composition (e.g.
  // AES x10) can checkpoint partway and stay at one chunk's gate-list memory
  // instead of the whole circuit's. Cost: one constant-round WRK instance per
  // chunk (more rounds for less memory). `keep` are the wires (Bit carriers) to
  // preserve; their ids are rewritten in place to the next chunk's [0, n).
  void checkpoint(void *keep, int n) {
    std::vector<int> out_ids(n);
    for (int i = 0; i < n; ++i) out_ids[i] = id_of((block *)keep + i);
    carried_ = run_chunk(out_ids);  // authenticated state of the kept wires
    // Compact: kept wires occupy [0, n) as carried inputs of the next span.
    gid = n;
    used_c0 = used_c1 = false;
    for (int i = 0; i < n; ++i) set_id((block *)keep + i, i);
  }

  uint64_t num_and() override { return ands_; }
  void finalize() override {}

  // For tests: how many process_input calls the terminal reveal made (= number
  // of distinct input owners, NOT number of Integer/feed calls).
  int process_input_calls = 0;

private:
  struct InputRec {
    int owner;
    std::vector<bool> bits;
    std::vector<int> ids;
  };

  C2PC<nP> *mpc = nullptr;
  int64_t gid = 0;
  std::vector<Gate> gates_;       // typed; moved into WireGraph at a boundary
  std::vector<InputRec> input_log;
  SecureWires<nP> carried_;       // kept wires carried in from the previous chunk
  uint64_t ands_ = 0;
  bool used_c0 = false, used_c1 = false;
  static constexpr int kConst0 = -2, kConst1 = -3;  // public-constant sentinels

  // Build a WireGraph from the gates recorded since the last boundary, assemble
  // its input bundles (process_input per owner on the first chunk; the carried
  // SecureWires on later chunks), resolve constants + liveness, and run the WRK
  // protocol. out_ids: the wire ids that become this chunk's outputs (revealed
  // wires, or wires kept across a checkpoint). Returns their authenticated state.
  SecureWires<nP> run_chunk(std::vector<int> &out_ids) {
    WireGraph g;
    g.gates = std::move(gates_);
    std::vector<SecureWires<nP>> bundles;

    // Carried wires (authenticated from a prior span) occupy [0, n_carried);
    // new process_input inputs are grouped per owner immediately after, at
    // [n_carried, n_carried+n_new). A span may have either or both.
    int n_carried = (int)carried_.size();
    if (n_carried > 0) {
      bundles.push_back(std::move(carried_));
      carried_ = SecureWires<nP>{};
    }
    int n_new = 0;
    for (auto &r : input_log) n_new += (int)r.ids.size();
    const int num_in = n_carried + n_new;

    // Group new inputs by owner -> grouped final ids in [n_carried, num_in).
    // New-input provisional ids are contiguous from n_carried (gid started there
    // after the last boundary). perm is identity on the carried prefix.
    std::vector<int> perm(num_in);
    for (int i = 0; i < n_carried; ++i) perm[i] = i;
    std::vector<int> owners;
    for (auto &r : input_log)
      if (std::find(owners.begin(), owners.end(), r.owner) == owners.end())
        owners.push_back(r.owner);
    std::sort(owners.begin(), owners.end());
    std::vector<std::vector<bool>> owner_bits(owners.size());
    int final_id = n_carried;
    for (size_t oi = 0; oi < owners.size(); ++oi) {
      int owner = owners[oi], base = final_id;
      for (auto &r : input_log)
        if (r.owner == owner)
          for (size_t i = 0; i < r.ids.size(); ++i) {
            perm[r.ids[i]] = final_id++;
            owner_bits[oi].push_back(r.bits[i]);
          }
      g.inputs.push_back({owner, base, final_id - base});
    }
    // Remap only new-input operands (in [n_carried, num_in)); carried prefix and
    // gate-output ids are unchanged.
    auto remap = [&](int v) { return (v >= n_carried && v < num_in) ? perm[v] : v; };
    for (auto &gg : g.gates) { gg.in0 = remap(gg.in0); gg.in1 = remap(gg.in1); }
    for (auto &o : out_ids) o = remap(o);
    for (size_t oi = 0; oi < owners.size(); ++oi) {
      int cnt = (int)owner_bits[oi].size();
      std::unique_ptr<bool[]> buf(new bool[cnt]);
      for (int i = 0; i < cnt; ++i) buf[i] = owner_bits[oi][i];
      bundles.push_back(mpc->process_input(buf.get(), cnt, owners[oi]));
      ++process_input_calls;
    }
    input_log.clear();

    // Resolve public-constant sentinels to real wires (c0 = XOR(w0,w0) = 0,
    // c1 = NOT c0 = 1, referencing wire 0); prepend so they evaluate first.
    int c0 = -1, c1 = -1;
    std::vector<Gate> pre;
    if (used_c0 || used_c1) {
      if (num_in == 0) error("WRKBackend: public constant requires >=1 input");
      c0 = (int)gid++;
      pre.push_back({0, 0, c0, Gate::XOR_TAG});
      if (used_c1) { c1 = (int)gid++; pre.push_back({c0, 0, c1, Gate::NOT_TAG}); }
    }
    auto rc = [&](int v) { return v == kConst0 ? c0 : (v == kConst1 ? c1 : v); };
    for (auto &gg : g.gates) { gg.in0 = rc(gg.in0); gg.in1 = rc(gg.in1); }
    for (auto &o : out_ids) o = rc(o);
    g.gates.insert(g.gates.begin(), pre.begin(), pre.end());

    g.num_wire = (int)gid;
    g.output_ids = out_ids;
    g.output_to.assign(out_ids.size(), 0);  // recipients handled by the caller

    // Liveness + AND-index numbering computed here (frontend), so the protocol
    // need not re-scan: last_use[w] = last gate reading w; and_index is assigned
    // to AND gates in topological order. This is the only place op is finalized.
    g.last_use.assign(g.num_wire, -1);
    int ng = g.num_gate(), ai = 0;
    for (int gi = 0; gi < ng; ++gi) {
      Gate &gg = g.gates[gi];
      g.last_use[gg.in0] = gi;
      g.last_use[gg.in1] = gi;
      if (gg.op == Gate::AND_PENDING) gg.op = ai++;
    }
    g.num_ands = ai;
    return mpc->compute(g, bundles);
  }

  // Evaluate the span so far keeping EVERY wire live: out_ids = [0,gid) in
  // recorder order, so the returned bundle is indexed by recorder id (the remap
  // inside run_chunk is consistent), i.e. carried_[k] == wire k's state. Ids are
  // preserved (gid unchanged), so existing Bit objects keep referencing the right
  // wires. gates_/input_log are consumed; constant flags reset.
  void flush_keep_all() {
    std::vector<int> all((size_t)gid);
    for (int i = 0; i < gid; ++i) all[i] = i;
    carried_ = run_chunk(all);
    used_c0 = used_c1 = false;
  }
  // Gather a sub-bundle (Lambda + wire shares, which is all decode needs) at the
  // given wire ids.
  static SecureWires<nP> slice(const SecureWires<nP> &w,
                               const std::vector<int> &ids) {
    SecureWires<nP> s;
    s.Lambda.resize(ids.size());
    s.wire_bundle.resize(ids.size());
    for (size_t i = 0; i < ids.size(); ++i) {
      s.Lambda[i] = w.Lambda[ids[i]];
      s.wire_bundle[i] = w.wire_bundle[ids[i]];
    }
    return s;
  }

  static int id_of(const void *p) {
    int v;
    std::memcpy(&v, p, sizeof(int));
    return v;
  }
  static void set_id(void *p, int v) {
    block b = zero_block;
    std::memcpy(&b, &v, sizeof(int));
    std::memcpy(p, &b, sizeof(block));
  }
  void push(int a, int b, int o, int t) {
    int op = (t == AND_GATE)   ? Gate::AND_PENDING
             : (t == NOT_GATE) ? Gate::NOT_TAG
                               : Gate::XOR_TAG;
    gates_.push_back({a, b, o, op});
    if (t == AND_GATE) ++ands_;
  }
};

template <int nP>
inline WRKBackend<nP> *setup_wrk_backend(NetIO *io1, NetIO *io2, ThreadPool *pool,
                                         int party) {
  auto *b = new WRKBackend<nP>(io1, io2, pool, party);
  backend = b;
  return b;
}

// Force evaluation of the circuit recorded so far, keeping `keep` (n wire
// carriers, e.g. a Bit array) live as authenticated inputs to the next chunk.
// Caps gate-list memory for long compositions at one chunk's worth.
// Reveal n wire carriers to ALL parties (returns the values, keeps all wires
// live, continues). Use for values the host will branch on. A single Bit can
// also use `x.reveal<bool>(PUBLIC)` directly.
template <int nP>
inline void wrk_reveal(bool *out, void *wires, int n) {
  backend->reveal(out, PUBLIC, wires, n);
}

template <int nP>
inline void wrk_checkpoint(void *keep, int n) {
  static_cast<WRKBackend<nP> *>(backend)->checkpoint(keep, n);
}

inline void finalize_wrk_backend() {
  if (backend == nullptr) return;
  backend->finalize();
  delete backend;
  backend = nullptr;
}

}  // namespace emp
#endif  // EMP_AG2PC_WRK_BACKEND_H__
