#ifndef EMP_AG2PC_ENGINE_H__
#define EMP_AG2PC_ENGINE_H__

#include "emp-tool/emp-tool.h"
#include "emp-tool/frontend/executor.h"
#include "emp-ag2pc/backend/session.h"               // AG2PCSession
#include "emp-ag2pc/backend/secure_wires.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace emp {

// Stream-mode wire id. Replayed phases must emit identical ids.
struct LambdaWire {
  int id = -1;
  LambdaWire() = default;
  explicit LambdaWire(int i) noexcept : id(i) {}
  // Keep memcpy-style copies visible to -Wclass-memaccess.
  ~LambdaWire() {}
};

// Per-run phase state. Logical wire ids map to physical slots; XOR/NOT scratch
// wires can reuse slots after their last read.
struct LambdaState {
  int party = 0;
  block Delta = zero_block;
  int num_inputs = 0;
  int num_ands = 0;
  int num_wires = 0;     // logical wire ids (inputs + emitted), from liveness pass
  int num_slots = 0;     // physical slots (size of the per-wire arrays)

  // Slot map and liveness, indexed by logical wire id.
  std::vector<int> phys;
  std::vector<int> last_use;        // last gate index reading w (-1 if never)
  std::vector<char> persist;        // 1 if w keeps its slot to the end

  // Per-slot state. Access through phys[].
  AShareBundleVec wire_slot;
  std::vector<unsigned char> mask_input;
  BlockVec label_slot;                 // garbler only
  BlockVec eval_slot;                  // evaluator only
  // Per-AND state.
  AShareBundleVec rep_a, rep_b;
  AShareBundleVec sigma;
  // c_gamma check state.
  BlockVec M1_t;
  std::vector<unsigned char> Lambda_AND;

  MITCCRH<8> mitc;

  // Logical wire id -> physical slot.
  AShareBundle&  wslot(int w) { return wire_slot[phys[w]]; }
  unsigned char& minp(int w)  { return mask_input[phys[w]]; }
  block&         lbl(int w)   { return label_slot[phys[w]]; }
  block&         evl(int w)   { return eval_slot[phys[w]]; }
};

// Phase backend base.
class PhaseBackend : public Backend {
 public:
  explicit PhaseBackend(int p) : Backend(p) {}
  size_t wire_bytes() const override { return sizeof(LambdaWire); }
  // Stream bodies receive secret inputs as SecureWires; feed() handles PUBLIC.
  void feed(void *out, int from_party, const bool *in, size_t n) override {
    if (from_party != PUBLIC)
      error("AG2PCEngine: secret input feed() is forbidden inside the lambda. "
            "Process inputs with mpc->process_inputs(...) before run_circuit.");
    for (size_t i = 0; i < n; ++i)
      public_label(static_cast<LambdaWire *>(out) + i, in[i]);
  }
  void reveal(bool * /*out*/, int /*to*/, const void * /*in*/, size_t /*n*/) override {
    error("AG2PCEngine: reveal() is forbidden inside the lambda. Decode the "
          "returned SecureWires with mpc->decode(...) after run_circuit.");
  }
};

// Phase 0: liveness over the replayed circuit.
class LivenessBackend : public PhaseBackend {
 public:
  LambdaState &s;
  int wid;
  int gi = 0;   // gate index over AND/XOR/NOT
  std::vector<int> last_use;
  std::vector<char> persist;

  explicit LivenessBackend(LambdaState &st)
      : PhaseBackend(st.party), s(st), wid(st.num_inputs) {
    last_use.assign(st.num_inputs, -1);
    persist.assign(st.num_inputs, 1);
  }

  static int ID(const void *p) { return static_cast<const LambdaWire *>(p)->id; }
  int emit_(void *out, bool is_persist) {
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    last_use.push_back(-1);
    persist.push_back(is_persist ? 1 : 0);
    return id;
  }

  void public_label(void *out, bool /*b*/) override { emit_(out, /*persist=*/false); }
  void and_gate(void *out, const void *l, const void *r) override {
    int i0 = ID(l), i1 = ID(r);
    emit_(out, /*persist=*/true);
    last_use[i0] = gi; last_use[i1] = gi; ++gi;
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int i0 = ID(l), i1 = ID(r);
    emit_(out, /*persist=*/false);
    last_use[i0] = gi; last_use[i1] = gi; ++gi;
  }
  void not_gate(void *out, const void *in) override {
    int i = ID(in);
    emit_(out, /*persist=*/false);
    last_use[i] = gi; ++gi;
  }

  // Commit liveness to state and pin the circuit outputs (extracted at the end).
  void commit(const std::vector<int> &out_ids) {
    s.num_wires = wid;
    for (int id : out_ids)
      if (id >= 0 && id < wid) persist[id] = 1;
    s.last_use = std::move(last_use);
    s.persist  = std::move(persist);
  }
};

// Phase 1: slot assignment and mask collection.
class FusedSizeCollectMasksBackend : public PhaseBackend {
 public:
  LambdaState &s;
  TriplePool *fpre;
  int wid;
  int ai = 0;
  int gi = 0;                  // gate index over AND/XOR/NOT
  std::vector<int> freelist;   // recycled fabric slots
  AShareBundleVec lg_buf;
  int lg_off = 0;
  static constexpr int kLgBatch = 1 << 14;

  FusedSizeCollectMasksBackend(LambdaState &st, TriplePool *f)
      : PhaseBackend(st.party), s(st), fpre(f), wid(st.num_inputs) {
    s.rep_a.clear();
    s.rep_b.clear();
    // Input slots are already loaded at [0, num_inputs).
  }

  AShareBundle next_lambda_gamma() {
    if (lg_off >= (int)lg_buf.size()) {
      lg_buf.clear();
      fpre->draw(kLgBatch, lg_buf);
      lg_off = 0;
    }
    return lg_buf[lg_off++];
  }

  // Assign a physical slot to a newly emitted logical wire.
  int alloc_slot(int id) {
    int slot;
    if (!s.persist[id] && !freelist.empty()) {
      slot = freelist.back();
      freelist.pop_back();
    } else {
      slot = s.num_slots++;
      s.wire_slot.resize(s.num_slots);
      s.mask_input.resize(s.num_slots, 0);
    }
    s.phys[id] = slot;
    return slot;
  }
  // Recycle fabric slots at last read.
  void free_if_dead(int w) {
    if (!s.persist[w] && s.last_use[w] == gi) freelist.push_back(s.phys[w]);
  }

  void public_label(void *out, bool b) override {
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    int slot = alloc_slot(id);
    s.wire_slot[slot] = AShareBundle{};
    s.mask_input[slot] = b ? 1 : 0;
  }
  void and_gate(void *out, const void *l, const void *r) override {
    int i0 = static_cast<const LambdaWire *>(l)->id;
    int i1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    // Read operand shares before (re)allocating slots.
    AShareBundle a = s.wslot(i0);
    AShareBundle b = s.wslot(i1);
    s.rep_a.push_back(a);
    s.rep_b.push_back(b);
    AShareBundle lg = next_lambda_gamma();
    int slot = alloc_slot(id);          // AND output: permanent slot
    s.wire_slot[slot] = lg;
    s.mask_input[slot] = 0;
    free_if_dead(i0);
    if (i1 != i0) free_if_dead(i1);
    ++gi; ++ai;
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int i0 = static_cast<const LambdaWire *>(l)->id;
    int i1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    // Compute the XOR into a temporary first — alloc_slot may grow/realloc
    // wire_slot, invalidating references into it.
    AShareBundle r_out;
    r_out.mac = s.wslot(i0).mac ^ s.wslot(i1).mac;
    r_out.key = s.wslot(i0).key ^ s.wslot(i1).key;
    int slot = alloc_slot(id);
    s.wire_slot[slot] = r_out;
    s.mask_input[slot] = 0;
    free_if_dead(i0);
    if (i1 != i0) free_if_dead(i1);
    ++gi;
  }
  void not_gate(void *out, const void *in) override {
    int i = static_cast<const LambdaWire *>(in)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    AShareBundle tmp = s.wslot(i);     // copy out before potential realloc
    int slot = alloc_slot(id);
    s.wire_slot[slot] = tmp;
    s.mask_input[slot] = 0;
    free_if_dead(i);
    ++gi;
  }

  // Commit final per-run storage sizes.
  void commit_sizes() {
    s.num_ands = ai;
    s.sigma.resize(std::max(1, s.num_ands));
    if (s.party == 1) s.label_slot.resize(s.num_slots);
    else              s.eval_slot.resize(s.num_slots);
  }
};

// Per-chunk staging shared by garble (producer) and evaluate (consumer).
// Same shape as AG2PCSession::StreamChunk: 2 ciphertexts per AND + 1 b-bit per AND.
struct LambdaStreamChunk {
  BlockVec G;
  std::vector<unsigned char> b;
  int n = 0;
};

// ===========================================================================
// Phase 2 — garble (P1): produces G ciphertexts per AND, ships in chunks via
// chunk_pipe — the compute (this thread) fills the next slot while a pool
// thread drains the previous slot via send + flush.
// ===========================================================================
class GarbleBackend : public PhaseBackend {
 public:
  LambdaState &s;
  int wid;
  int ai = 0;
  static constexpr int kBatch = 1 << 16;
  ThreadPool *pool;
  NetIO *send_io;
  chunk_pipe<LambdaStreamChunk> pipe;
  std::future<void> sender_fut;
  LambdaStreamChunk *cur;

  GarbleBackend(LambdaState &st, NetIO *sio, ThreadPool *p)
      : PhaseBackend(st.party), s(st), wid(st.num_inputs),
        pool(p), send_io(sio),
        pipe(2, [&st](LambdaStreamChunk &c) {
          int cap = std::min(kBatch, std::max(1, st.num_ands));
          c.G.resize(2 * cap);
          c.b.resize(cap);
        }) {
    sender_fut = pool->enqueue([this] {
      while (auto *slot = pipe.consumer_slot()) {
        send_io->send_data(slot->G.data(),
                           (size_t)2 * slot->n * sizeof(block));
        send_io->send_data(slot->b.data(), (size_t)slot->n);
        send_io->flush();
        pipe.consumer_release();
      }
    });
    cur = &pipe.producer_slot();
    cur->n = 0;
  }

  void finish() {
    if (cur->n > 0) pipe.producer_publish();
    pipe.producer_close();
    sender_fut.get();
  }

  // Slot-reuse means fabric (XOR/NOT) wire SHARES don't persist from the fused
  // pass — so this phase re-propagates them (cheap, deterministic) alongside the
  // labels, exactly as the fused pass did. AND-output shares (λ_γ, random) and
  // input shares live in permanent slots and are read directly.
  void public_label(void *out, bool b) override {
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    s.wslot(id) = AShareBundle{};      // const share is 0
    // c1 acts as NOT(c0): garbler's m_{w,0} for the "1" constant is Δ to flip
    // the eval-label parity when Λ_w = 1; eval-side label is set to 0 by the
    // matching phase backend (no message needed — both sides synthesize).
    s.lbl(id) = b ? s.Delta : zero_block;
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int i0 = static_cast<const LambdaWire *>(l)->id;
    int i1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    AShareBundle sh;
    sh.mac = s.wslot(i0).mac ^ s.wslot(i1).mac;
    sh.key = s.wslot(i0).key ^ s.wslot(i1).key;
    block lb = s.lbl(i0) ^ s.lbl(i1);
    s.wslot(id) = sh;
    s.lbl(id) = lb;
  }
  void not_gate(void *out, const void *in) override {
    int i = static_cast<const LambdaWire *>(in)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    AShareBundle sh = s.wslot(i);
    block lb = s.lbl(i) ^ s.Delta;
    s.wslot(id) = sh;
    s.lbl(id) = lb;
  }
  void and_gate(void *out, const void *l, const void *r) override {
    int in0 = static_cast<const LambdaWire *>(l)->id;
    int in1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    int my_ai = ai++;

    block ml_a0 = s.lbl(in0), ml_a1 = ml_a0 ^ s.Delta;
    block ml_b0 = s.lbl(in1), ml_b1 = ml_b0 ^ s.Delta;
    block buf[4] = {ml_a0, ml_a1, ml_b0, ml_b1};
    s.mitc.template hash_cir<1, 4>(buf);

    const AShareBundle &wb_in0 = s.wslot(in0);
    const AShareBundle &wb_in1 = s.wslot(in1);
    const AShareBundle &wb_out = s.wslot(id);
    const AShareBundle &sb     = s.sigma[my_ai];

    block H_a0_self = buf[0], H_a1_self = buf[1];
    block H_b0_self = buf[2], H_b1_self = buf[3];

    block sumK_a  = wb_in0.key;
    block sumK_b  = wb_in1.key;
    block sumK_ab = sb.key;
    block sumK_g  = wb_out.key;
    block la_dot  = select_mask[LSB(wb_in0.mac)] & s.Delta;
    block lb_dot  = select_mask[LSB(wb_in1.mac)] & s.Delta;
    block lab_dot = select_mask[LSB(sb.mac)]     & s.Delta;
    block lg_dot  = select_mask[LSB(wb_out.mac)] & s.Delta;

    block G0 = H_a0_self ^ H_a1_self ^ sumK_b ^ lb_dot;
    block G1 = H_b0_self ^ H_b1_self ^ ml_a0 ^ sumK_a ^ la_dot;
    block ml_g0 = H_a0_self ^ H_b0_self ^ sumK_ab ^ lab_dot ^ sumK_g ^ lg_dot;

    s.lbl(id) = ml_g0;
    cur->G[2 * cur->n]     = G0;
    cur->G[2 * cur->n + 1] = G1;
    cur->b[cur->n] = (unsigned char)LSB1(ml_g0);
    if (++cur->n == kBatch) {
      pipe.producer_publish();
      cur = &pipe.producer_slot();
      cur->n = 0;
    }
  }
};

// ===========================================================================
// Phase 2 — evaluate (P2): consume G chunks, derive output labels, and build
// the c_gamma witness.
// ===========================================================================
class EvaluateBackend : public PhaseBackend {
 public:
  LambdaState &s;
  int wid;
  int ai = 0;
  static constexpr int kBatch = 1 << 16;
  ThreadPool *pool;
  NetIO *recv_io;
  chunk_pipe<LambdaStreamChunk> pipe;
  std::future<void> recv_fut;
  LambdaStreamChunk *cur = nullptr;
  int loc = 0;

  EvaluateBackend(LambdaState &st, NetIO *rio, ThreadPool *p)
      : PhaseBackend(st.party), s(st), wid(st.num_inputs),
        pool(p), recv_io(rio),
        pipe(2, [&st](LambdaStreamChunk &c) {
          int cap = std::min(kBatch, std::max(1, st.num_ands));
          c.G.resize(2 * cap);
          c.b.resize(cap);
        }) {
    recv_fut = pool->enqueue([this] {
      int recv_base = 0;
      while (recv_base < s.num_ands) {
        LambdaStreamChunk &slot = pipe.producer_slot();
        slot.n = std::min(kBatch, s.num_ands - recv_base);
        recv_io->recv_data(slot.G.data(),
                           (size_t)2 * slot.n * sizeof(block));
        recv_io->recv_data(slot.b.data(), (size_t)slot.n);
        pipe.producer_publish();
        recv_base += slot.n;
      }
      pipe.producer_close();
    });
  }

  void finish() {
    if (cur != nullptr) pipe.consumer_release();
    recv_fut.get();
  }

  // Re-propagate fabric shares alongside evaluator labels and masks.
  void public_label(void *out, bool b) override {
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    s.wslot(id) = AShareBundle{};  // const share is 0
    s.evl(id) = zero_block;        // evaluator's label for both 0 and 1 is 0
    s.minp(id) = b ? 1 : 0;        // const's opened mask = its public bit
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int i0 = static_cast<const LambdaWire *>(l)->id;
    int i1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    AShareBundle sh;
    sh.mac = s.wslot(i0).mac ^ s.wslot(i1).mac;
    sh.key = s.wslot(i0).key ^ s.wslot(i1).key;
    block ev = s.evl(i0) ^ s.evl(i1);
    unsigned char mi = s.minp(i0) ^ s.minp(i1);
    s.wslot(id) = sh;
    s.evl(id) = ev;
    s.minp(id) = mi;
  }
  void not_gate(void *out, const void *in) override {
    int i = static_cast<const LambdaWire *>(in)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    AShareBundle sh = s.wslot(i);
    block ev = s.evl(i);
    unsigned char mi = s.minp(i) ^ 1;
    s.wslot(id) = sh;
    s.evl(id) = ev;
    s.minp(id) = mi;
  }
  void and_gate(void *out, const void *l, const void *r) override {
    int in0 = static_cast<const LambdaWire *>(l)->id;
    int in1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    int my_ai = ai++;
    if (cur == nullptr || loc == cur->n) {
      if (cur != nullptr) pipe.consumer_release();
      cur = pipe.consumer_slot();
      loc = 0;
    }
    bool La = s.minp(in0), Lb = s.minp(in1);
    const AShareBundle &wb_in0 = s.wslot(in0);
    const AShareBundle &wb_in1 = s.wslot(in1);
    const AShareBundle &wb_out = s.wslot(id);
    const AShareBundle &sb     = s.sigma[my_ai];

    block Mr;
    { block t = sb.mac ^ wb_out.mac;
      t = t ^ (select_mask[La] & wb_in1.mac);
      t = t ^ (select_mask[Lb] & wb_in0.mac);
      Mr = t; }
    block self_Ha, self_Hb;
    { block buf[2] = {s.evl(in0), s.evl(in1)};
      s.mitc.template hash_cir<1, 2>(buf);
      self_Ha = buf[0];
      self_Hb = buf[1]; }
    block t = self_Ha ^ self_Hb;
    t = t ^ (select_mask[La] & cur->G[2 * loc]);
    t = t ^ (select_mask[Lb] & (cur->G[2 * loc + 1] ^ s.evl(in0)));
    t = t ^ Mr;
    s.evl(id) = t;
    bool Lg = (bool)(cur->b[loc] ^ LSB1(t));
    s.minp(id) = (unsigned char)Lg;

    // c_gamma witness for this AND.
    s.Lambda_AND[my_ai] = (unsigned char)Lg;
    {
      bool v_in0 = (bool)LSB(wb_in0.mac);
      bool v_in1 = (bool)LSB(wb_in1.mac);
      bool v_out = (bool)LSB(wb_out.mac);
      bool v_sig = (bool)LSB(sb.mac);
      bool t1 = (La & Lb) ^ Lg ^ (La & v_in1) ^ (Lb & v_in0) ^ v_sig ^ v_out;
      block m = select_mask[t1] & s.Delta;
      m = m ^ (select_mask[La] & wb_in1.key);
      m = m ^ (select_mask[Lb] & wb_in0.key);
      m = m ^ sb.key ^ wb_out.key;
      s.M1_t[my_ai] = m;
    }
    ++loc;
  }
};

// ===========================================================================
// Phase 3 (P1 garbler only): build the c_gamma witness after receiving
// Lambda_AND from the evaluator.
// ===========================================================================
class PostRecvCheckBackend : public PhaseBackend {
 public:
  LambdaState &s;
  int wid;
  int ai = 0;

  explicit PostRecvCheckBackend(LambdaState &st)
      : PhaseBackend(st.party), s(st), wid(st.num_inputs) {}

  // Re-propagate fabric SHARES (slot-reused) alongside the garbler's masks; the
  // AND case reads operand + output shares to recompute M1_t.
  void public_label(void *out, bool b) override {
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    s.wslot(id) = AShareBundle{};  // const share is 0
    s.minp(id) = b ? 1 : 0;        // const's opened mask = its public bit
  }
  void xor_gate(void *out, const void *l, const void *r) override {
    int i0 = static_cast<const LambdaWire *>(l)->id;
    int i1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    AShareBundle sh;
    sh.mac = s.wslot(i0).mac ^ s.wslot(i1).mac;
    sh.key = s.wslot(i0).key ^ s.wslot(i1).key;
    unsigned char mi = s.minp(i0) ^ s.minp(i1);
    s.wslot(id) = sh;
    s.minp(id) = mi;
  }
  void not_gate(void *out, const void *in) override {
    int i = static_cast<const LambdaWire *>(in)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    AShareBundle sh = s.wslot(i);
    unsigned char mi = s.minp(i) ^ 1;
    s.wslot(id) = sh;
    s.minp(id) = mi;
  }
  void and_gate(void *out, const void *l, const void *r) override {
    int in0 = static_cast<const LambdaWire *>(l)->id;
    int in1 = static_cast<const LambdaWire *>(r)->id;
    int id = wid++;
    static_cast<LambdaWire *>(out)->id = id;
    int my_ai = ai++;
    s.minp(id) = s.Lambda_AND[my_ai];
    bool La = s.minp(in0), Lb = s.minp(in1);
    block m = s.sigma[my_ai].mac ^ s.wslot(id).mac;
    m = m ^ (select_mask[La] & s.wslot(in1).mac);
    m = m ^ (select_mask[Lb] & s.wslot(in0).mac);
    s.M1_t[my_ai] = m;
  }
};

// Collects stream-mode inputs built with EMP constructors. `feed` records input
// bits and assigns stable LambdaWire ids; `process` shares them once, grouped by
// owner. After processing, the input bundle is frozen and reusable.
class AG2PCInputs : public Backend {
  struct Entry { int owner; int base; int width; std::vector<bool> bits; };
  AG2PCSession *mpc_;
  Backend *saved_;
  int next_ = 0;
  std::vector<Entry> pending_;
  bool frozen_ = false;
  SecureWires bundle_;

 public:
  explicit AG2PCInputs(AG2PCSession *m)
      : Backend(m->party), mpc_(m), saved_(backend) { backend = this; }
  ~AG2PCInputs() override { backend = saved_; }

  AG2PCInputs(const AG2PCInputs &) = delete;
  AG2PCInputs &operator=(const AG2PCInputs &) = delete;
  AG2PCInputs(AG2PCInputs &&) = delete;
  AG2PCInputs &operator=(AG2PCInputs &&) = delete;

  size_t wire_bytes() const override { return sizeof(LambdaWire); }

  // Assign placeholder wire ids; sharing happens in process().
  void feed(void *out, int from_party, const bool *in, size_t n) override {
    if (frozen_)
      error("AG2PCInputs: inputs are frozen (a run already happened); construct all "
            "inputs before the first run (the frozen bundle can be re-run as-is)");
    if (from_party == PUBLIC)
      error("AG2PCInputs: public constants belong inside the run body, not here");
    int base = next_;
    next_ += (int)n;
    pending_.push_back({from_party, base, (int)n, std::vector<bool>(in, in + n)});
    for (size_t i = 0; i < n; ++i)
      static_cast<LambdaWire *>(out)[i] = LambdaWire(base + (int)i);
  }
  void public_label(void *, bool) override {
    error("AG2PCInputs: public constants belong inside the run body, not here");
  }
  void and_gate(void *, const void *, const void *) override {
    error("AG2PCInputs: gates belong inside the run body, not here");
  }
  void xor_gate(void *, const void *, const void *) override {
    error("AG2PCInputs: gates belong inside the run body, not here");
  }
  void not_gate(void *, const void *) override {
    error("AG2PCInputs: gates belong inside the run body, not here");
  }
  void reveal(bool *, int, const void *, size_t) override {
    error("AG2PCInputs: reveal after run, via AG2PCSession::decode");
  }

  // Returns wires in placeholder-id order.
  const SecureWires &process() {
    if (frozen_) return bundle_;
    frozen_ = true;

    std::vector<int> owners;
    for (const Entry &e : pending_)
      if (std::find(owners.begin(), owners.end(), e.owner) == owners.end())
        owners.push_back(e.owner);
    std::sort(owners.begin(), owners.end());
    auto owner_index = [&](int o) {
      return (int)(std::find(owners.begin(), owners.end(), o) - owners.begin());
    };

    std::vector<std::vector<bool>> bits(owners.size());
    std::vector<int> ent_oi(pending_.size()), ent_off(pending_.size());
    for (size_t k = 0; k < pending_.size(); ++k) {
      int oi = owner_index(pending_[k].owner);
      ent_oi[k]  = oi;
      ent_off[k] = (int)bits[oi].size();
      bits[oi].insert(bits[oi].end(), pending_[k].bits.begin(), pending_[k].bits.end());
    }

    std::vector<SecureWires> sub;
    if (!owners.empty()) sub = mpc_->process_inputs(owners, bits);

    const bool is_eval = (mpc_->party != 1);
    bundle_.Lambda.resize(next_);
    bundle_.wire_bundle.resize(next_);
    if (is_eval) bundle_.eval_label.resize(next_);
    else         bundle_.label0.resize(next_);
    for (size_t k = 0; k < pending_.size(); ++k) {
      const SecureWires &s = sub[ent_oi[k]];
      int off = ent_off[k], base = pending_[k].base;
      for (int j = 0; j < pending_[k].width; ++j) {
        bundle_.Lambda[base + j]      = s.Lambda[off + j];
        bundle_.wire_bundle[base + j] = s.wire_bundle[off + j];
        if (is_eval) bundle_.eval_label[base + j] = s.eval_label[off + j];
        else         bundle_.label0[base + j]     = s.label0[off + j];
      }
    }
    return bundle_;
  }
};

// Decoded output handle for AG2PCInputs runs.
struct Opened {
  AG2PCSession *mpc;
  SecureWires wires;

  std::vector<bool> reveal_bits(int recipient) const {
    return mpc->decode(wires, recipient);
  }
  template <typename T>
  T reveal(int recipient) const {
    std::vector<bool> b = mpc->decode(wires, recipient);
    if constexpr (std::is_same_v<T, std::vector<bool>>) {
      return b;
    } else if constexpr (std::is_same_v<T, bool>) {
      return !b.empty() && b[0];
    } else {
      T v = 0;
      for (size_t i = 0; i < b.size() && i < sizeof(T) * 8; ++i)
        if (b[i]) v |= (T(1) << i);
      return v;
    }
  }
  operator SecureWires() const { return wires; }
};

// Streaming AG2PC executor. A circuit source replays gates against each phase
// backend and returns packed output wire ids.
class AG2PCEngine {
 public:
  AG2PCSession *mpc;
  explicit AG2PCEngine(AG2PCSession *m) : mpc(m) {}

  // Run a deterministic wire-generic body over typed input bundles.
  template <typename... Ins, typename F>
  SecureWires run(const std::vector<SecureWires> &inputs, F body) {
    auto prep = prepare_typed_inputs_<Ins...>(inputs);
    using Tr = emp::frontend::circuit_fn_traits<F, rebind_t<Ins, LambdaWire>...>;
    auto replay = make_frontend_body_replay_<Tr>(body, prep.args);
    return run_engine_(prep.in_wires, replay);
  }

  // Run a nullary body that captures AG2PCInputs-created circuit objects.
  template <typename F>
  Opened run(AG2PCInputs &inputs, F body) {
    using Tr = emp::frontend::circuit_fn_traits<F>;
    const SecureWires &in = inputs.process();
    auto replay = [&body]() -> std::vector<int> {
      (void)sizeof(emp::frontend::circuit_contract<Tr>);
      if constexpr (Tr::ok) return pack_output_ids_(body());
      else return {};
    };
    return Opened{mpc, run_engine_(in, replay)};
  }

  // Replay a compiled frontend circuit over typed input bundles.
  template <typename... Ins, typename RetRec>
  SecureWires run_compiled(const frontend::TypedCircuit<RetRec> &tc,
                           const std::vector<SecureWires> &inputs) {
    auto prep = prepare_typed_inputs_<Ins...>(inputs);
    auto replay = make_compiled_frontend_replay_(tc, prep.args);
    return run_engine_(prep.in_wires, replay);
  }

  // Flat bit-vector source:
  //   void lambda(const std::vector<Bit_T<LambdaWire>>& in,
  //                     std::vector<Bit_T<LambdaWire>>& out)
  template <typename F>
  SecureWires run_circuit(const SecureWires &in_wires, int n_out, F lambda) {
    auto replay =
        make_flat_lambda_replay_((int)in_wires.size(), n_out, std::move(lambda));
    return run_engine_(in_wires, replay);
  }

  // Replay a raw BooleanProgram. Inputs bind to wire ids [0, num_inputs); the
  // result bundle is exactly the program's declared outputs. The program is
  // produced correct-by-construction (the direct backend's chunk compaction),
  // so structure is trusted here and validated where programs are built/loaded.
  SecureWires run_program(const emp::circuit::BooleanProgram &prog,
                          const SecureWires &inputs) {
    // run_program is a public stream-mode source, so the program may be
    // externally supplied. Validate once (bounds / topological / dense) before
    // the phase visitors index wire buffers directly across the 5 replays — an
    // out-of-range gate would otherwise OOB. Cheap next to 5 garbling passes.
    emp::circuit::validate_program(prog);
    const uint32_t num_inputs = (uint32_t)inputs.size();
    if (num_inputs != prog.num_inputs)
      error("run_program: input bundle width != program num_inputs");

    // Replay the SAME gate stream against each phase backend (run_engine_ calls
    // this lambda once per phase, swapping the global backend). The gate
    // dispatch is the shared for_each_gate primitive; only input seeding (wire
    // ids, not values) and output-id extraction are AG2PC-specific.
    auto replay = [&prog, num_inputs]() -> std::vector<int> {
      std::vector<LambdaWire> buf(prog.num_wires);
      for (uint32_t i = 0; i < num_inputs; ++i) buf[i] = LambdaWire(i);
      struct PhaseVisitor {
        std::vector<LambdaWire> &buf;
        void and_gate(uint32_t o, uint32_t a, uint32_t b) { backend->and_gate(&buf[o], &buf[a], &buf[b]); }
        void xor_gate(uint32_t o, uint32_t a, uint32_t b) { backend->xor_gate(&buf[o], &buf[a], &buf[b]); }
        void not_gate(uint32_t o, uint32_t a)             { backend->not_gate(&buf[o], &buf[a]); }
        void const_gate(uint32_t o, bool v)               { backend->public_label(&buf[o], v); }
      };
      emp::circuit::for_each_gate(prog, PhaseVisitor{buf});
      std::vector<int> ids(prog.outputs.size());
      for (size_t i = 0; i < prog.outputs.size(); ++i) ids[i] = buf[prog.outputs[i]].id;
      return ids;
    };
    return run_engine_(inputs, replay);
  }

 private:
  // Append one SecureWires bundle onto another.
  static void append_bundle_(SecureWires &dst, const SecureWires &s) {
    dst.Lambda.insert(dst.Lambda.end(), s.Lambda.begin(), s.Lambda.end());
    dst.wire_bundle.insert(dst.wire_bundle.end(), s.wire_bundle.begin(),
                           s.wire_bundle.end());
    if (!s.label0.empty())
      dst.label0.insert(dst.label0.end(), s.label0.begin(), s.label0.end());
    if (!s.eval_label.empty())
      dst.eval_label.insert(dst.eval_label.end(), s.eval_label.begin(),
                            s.eval_label.end());
  }

  // Assemble one typed argument of shape Arg from LambdaWire ids [base, base+n).
  template <typename Arg>
  static Arg make_one_arg_(int base, int n) {
    std::vector<LambdaWire> w(n);
    for (int k = 0; k < n; ++k) w[k] = LambdaWire(base + k);
    return assemble<Arg>(w.data(), n);
  }
  template <typename... Args, std::size_t... I>
  static std::tuple<Args...> make_args_(const std::vector<int> &base,
                                        const std::vector<int> &width,
                                        std::index_sequence<I...>) {
    return std::tuple<Args...>{make_one_arg_<Args>(base[I], width[I])...};
  }

  // Circuit sources replay the same gate stream for each phase and return
  // flattened output wire ids.

  template <typename... Ins>
  struct Prepared {
    SecureWires in_wires;
    std::tuple<rebind_t<Ins, LambdaWire>...> args;
  };

  // Concatenate input bundles and build typed LambdaWire arguments.
  template <typename... Ins>
  Prepared<Ins...> prepare_typed_inputs_(const std::vector<SecureWires> &inputs) {
    if (sizeof...(Ins) != inputs.size())
      error("AG2PCEngine: input bundle count != argument type count");
    // Runtime-width types declare pack_size 0.
    const std::array<int, sizeof...(Ins)> decl{
        {(int)rebind_t<Ins, LambdaWire>{}.pack_size()...}};
    for (size_t a = 0; a < inputs.size(); ++a)
      if (decl[a] > 0 && decl[a] != (int)inputs[a].size())
        error("AG2PCEngine: input bundle width != declared argument width");

    Prepared<Ins...> p;
    std::vector<int> base(inputs.size()), width(inputs.size());
    int off = 0;
    for (size_t a = 0; a < inputs.size(); ++a) {
      append_bundle_(p.in_wires, inputs[a]);
      base[a]  = off;
      width[a] = (int)inputs[a].size();
      off += (int)inputs[a].size();
    }
    p.args = make_args_<rebind_t<Ins, LambdaWire>...>(
        base, width, std::index_sequence_for<Ins...>{});
    return p;
  }

  // Flatten a returned circuit value into wire ids.
  template <typename T>
  static std::vector<int> pack_output_ids_(const T &out_val) {
    auto ow = pack_wires(out_val);
    std::vector<int> ids(ow.size());
    for (size_t i = 0; i < ow.size(); ++i) ids[i] = ow[i].id;
    return ids;
  }

  // Body source with the emp-tool frontend contract.
  template <typename Tr, typename F, typename ArgsTuple>
  static auto make_frontend_body_replay_(F &body, ArgsTuple &args) {
    return [&body, &args]() -> std::vector<int> {
      (void)sizeof(emp::frontend::circuit_contract<Tr>);
      if constexpr (Tr::ok) {
        auto out = std::apply(
            [&](auto &...a) { return emp::frontend::run(body, a...); }, args);
        return pack_output_ids_(out);
      } else {
        return {};
      }
    };
  }

  // Compiled-circuit source.
  template <typename RetRec, typename ArgsTuple>
  static auto make_compiled_frontend_replay_(const frontend::TypedCircuit<RetRec> &tc,
                                             ArgsTuple &args) {
    return [&tc, &args]() -> std::vector<int> {
      auto out = std::apply(
          [&](auto &...a) { return emp::frontend::run(tc, a...); }, args);
      return pack_output_ids_(out);
    };
  }

  // Flat-lambda source with pre-bound input ids.
  template <typename F>
  static auto make_flat_lambda_replay_(int num_in, int n_out, F lambda) {
    std::vector<Bit_T<LambdaWire>> in_bits(num_in), out_bits(n_out);
    for (int i = 0; i < num_in; ++i) in_bits[i].bit = LambdaWire(i);
    return [lambda = std::move(lambda), in_bits = std::move(in_bits),
            out_bits = std::move(out_bits)]() mutable -> std::vector<int> {
      lambda(in_bits, out_bits);
      std::vector<int> ids(out_bits.size());
      for (size_t i = 0; i < out_bits.size(); ++i) ids[i] = out_bits[i].bit.id;
      return ids;
    };
  }

  // Runs liveness, size/mask collection, garble/evaluate, c_gamma, and output.
  template <typename Replay>
  SecureWires run_engine_(const SecureWires &in_wires, Replay replay) {
    Backend *saved = backend;
    int num_in = (int)in_wires.size();

    LambdaState st;
    st.party = mpc->party;
    st.Delta = mpc->Delta;
    st.num_inputs = num_in;

#ifdef AG2PC_PROFILE
    // Names consumed by AG2PC_PHASE.
    NetIO *send_io = mpc->send_io, *recv_io = mpc->recv_io;
    int party = st.party;
#endif
    AG2PC_PHASE_BEGIN();

    // Phase 0: liveness.
    std::vector<int> out_ids;
    {
      LivenessBackend lb(st);
      backend = &lb;
      out_ids = replay();
      lb.commit(out_ids);
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

    // Phase 1: slot assignment and mask collection.
    {
      FusedSizeCollectMasksBackend fb(st, mpc->fpre);
      backend = &fb;
      replay();
      fb.commit_sizes();
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

    // Phase 2: garble or evaluate.
    if (st.party == 1) {
      GarbleBackend gb(st, mpc->send_io, mpc->pool);
      backend = &gb;
      replay();
      gb.finish();
    } else {
      EvaluateBackend eb(st, mpc->recv_io, mpc->pool);
      backend = &eb;
      replay();
      eb.finish();
    }
    AG2PC_PHASE("garble_or_evaluate[step6-10]");

    // c_gamma exchange.
    if (st.num_ands > 0) {
      if (st.party != 1) {
        mpc->io->send_bool((const bool *)st.Lambda_AND.data(), st.num_ands);
        mpc->io->flush();
        char D1[Hash::DIGEST_SIZE], D2[Hash::DIGEST_SIZE];
        Hash::hash_once(D1, st.M1_t.data(),
                        (size_t)st.num_ands * sizeof(block));
        mpc->io->recv_data(D2, Hash::DIGEST_SIZE);
        if (memcmp(D1, D2, Hash::DIGEST_SIZE) != 0)
          error("lambda c_gamma check failed");
      } else {
        mpc->io->recv_bool((bool *)st.Lambda_AND.data(), st.num_ands);
        PostRecvCheckBackend pb(st);
        backend = &pb;
        replay();
        char D2[Hash::DIGEST_SIZE];
        Hash::hash_once(D2, st.M1_t.data(),
                        (size_t)st.num_ands * sizeof(block));
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
      int id = out_ids[i];
      out.Lambda[i] = st.minp(id);
      out.wire_bundle[i] = st.wslot(id);
      if (st.party == 1) out.label0[i] = st.lbl(id);
      else               out.eval_label[i] = st.evl(id);
    }
    AG2PC_PHASE("gather_outputs");

    backend = saved;
    return out;
  }
};

using LambdaRunner = AG2PCEngine;

}  // namespace emp
#endif  // EMP_AG2PC_ENGINE_H__
