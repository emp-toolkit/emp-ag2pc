#ifndef EMP_AG2PC_PASSES_H__
#define EMP_AG2PC_PASSES_H__

// The AG2PC authenticated-garbling protocol as a sequence of PASSES, each a
// C++20 emp::BooleanContext (circuits/context.h) over one shared LambdaState.
// A pass declares only its per-gate behavior (public_bit / and_gate / xor_gate /
// not_gate, value-return), plus optional begin()/end() for setup/teardown; the
// executor (engine.h) sequences the passes and the inter-pass crypto.
//
// Because a pass is a BooleanContext, the SAME pass definition drives any circuit
// source: a stored BooleanProgram (emp::execute_program / for_each_gate) or a
// pure circuit body replayed live (streaming) — they produce the identical gate
// stream, so identical transcripts.
//
// Wire = uint32_t is the logical wire id (== emission id == LambdaState index).
// A pass holds a wire-id counter `wid` (next id, starting at num_inputs) that, on
// a RecordContext-canonical program, equals the program's gate.out — so the slot
// layout matches across passes and equals the canonical record-order numbering.
//
// public_bit DEDUPS the two constants (cache c0_/c1_), mirroring emp-tool's
// RecordContext: a body using a constant repeatedly emits ONE const wire, so the
// live (streaming) gate stream matches the compiled BooleanProgram's.

#include "emp-tool/emp-tool.h"                  // block, MITCCRH, select_mask, LSB/LSB1, ThreadPool, RO, Hash
#include "emp-tool/ir/program.h"     // BooleanProgram, Op
#include "emp-tool/ir/validate.h"   // validate_program
#include "emp-ag2pc/backend/secure_wires.h"     // AShareBundle / AShareBundleVec / SecureWires
#include "emp-ag2pc/backend/triple_pool.h"      // TriplePool
#include "emp-ag2pc/backend/helper.h"           // chunk_pipe, LSB, LSB1

#include <algorithm>
#include <cstdint>
#include <future>
#include <vector>

namespace emp {

// ===========================================================================
// Shared per-run state. Logical wire ids map to physical slots; XOR/NOT scratch
// wires can reuse slots after their last read. Indexed by logical wire id.
// ===========================================================================
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

// Per-chunk staging shared by garble (producer) and evaluate (consumer):
// 2 ciphertexts per AND + 1 b-bit per AND.
struct LambdaStreamChunk {
  BlockVec G;
  std::vector<unsigned char> b;
  int n = 0;
};

// AG2PC consumes only RecordContext-canonical programs (what its own producers —
// frontend::compile and the direct-backend chunk compaction — emit). Beyond the
// dense/topological invariants validate_program checks, require (1) gate.out ==
// num_inputs + i, so the pass wire-id counter equals the program id, and (2) at
// most one Const0 and one Const1 gate, because the pass contexts dedup public_bit
// (two Const0 wires would both replay to the cached wire and corrupt the layout).
// Non-canonical programs are rejected, not adapted.
inline void ag2pc_require_record_canonical(const emp::circuit::BooleanProgram& p) {
  emp::circuit::validate_program(p);   // bounds / single-def / read-before-define / dense
  int n_c0 = 0, n_c1 = 0;
  for (size_t i = 0; i < p.gates.size(); ++i) {
    if (p.gates[i].out != p.num_inputs + (uint32_t)i)
      error("ag2pc: program is not RecordContext-canonical (gate out != num_inputs + i)");
    if (p.gates[i].op == emp::circuit::Op::Const0) ++n_c0;
    if (p.gates[i].op == emp::circuit::Op::Const1) ++n_c1;
  }
  if (n_c0 > 1 || n_c1 > 1)
    error("ag2pc: program has duplicate constant gates (pass contexts dedup public_bit)");
}

// ===========================================================================
// Pass 0 — liveness. last_use / persist over the gate stream; AND outputs
// persist, linear/const wires are recyclable; circuit outputs are pinned by
// commit(). Pure analysis: no crypto, no IO.
// ===========================================================================
struct LivenessPass {
  using Wire = uint32_t;
  LambdaState& s;
  uint32_t wid;
  int gi = 0;                       // gate index over AND/XOR/NOT
  std::vector<int> last_use;
  std::vector<char> persist;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  explicit LivenessPass(LambdaState& st) : s(st), wid((uint32_t)st.num_inputs) {
    last_use.assign(st.num_inputs, -1);
    persist.assign(st.num_inputs, 1);
  }

  uint32_t emit_(bool is_persist) {
    uint32_t id = wid++;
    last_use.push_back(-1);
    persist.push_back(is_persist ? 1 : 0);
    return id;
  }

  Wire public_bit(bool v) {
    int64_t& c = v ? c1_ : c0_;
    if (c < 0) c = (int64_t)emit_(/*persist=*/false);
    return (Wire)c;
  }
  Wire and_gate(Wire i0, Wire i1) {
    uint32_t id = emit_(/*persist=*/true);
    last_use[i0] = gi; last_use[i1] = gi; ++gi;
    return id;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = emit_(/*persist=*/false);
    last_use[i0] = gi; last_use[i1] = gi; ++gi;
    return id;
  }
  Wire not_gate(Wire i) {
    uint32_t id = emit_(/*persist=*/false);
    last_use[i] = gi; ++gi;
    return id;
  }

  // Commit liveness to state and pin the circuit outputs (extracted at the end).
  void commit(const std::vector<uint32_t>& out_ids) {
    s.num_wires = (int)wid;
    for (uint32_t id : out_ids)
      if (id < wid) persist[id] = 1;
    s.last_use = std::move(last_use);
    s.persist  = std::move(persist);
  }
};

// ===========================================================================
// Pass 1 — slot assignment + mask collection. Assigns physical slots (recycling
// dead linear/const slots via a freelist), seeds wire shares, and for each AND
// records operand shares (rep_a/rep_b) and draws the fresh λ_γ output mask.
// ===========================================================================
struct SizeMaskPass {
  using Wire = uint32_t;
  LambdaState& s;
  TriplePool* fpre;
  uint32_t wid;
  int ai = 0;
  int gi = 0;                       // gate index over AND/XOR/NOT
  std::vector<int> freelist;        // recycled fabric slots
  AShareBundleVec lg_buf;
  int lg_off = 0;
  static constexpr int kLgBatch = 1 << 14;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  SizeMaskPass(LambdaState& st, TriplePool* f)
      : s(st), fpre(f), wid((uint32_t)st.num_inputs) {
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
  int alloc_slot(uint32_t id) {
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
  void free_if_dead(uint32_t w) {
    if (!s.persist[w] && s.last_use[w] == gi) freelist.push_back(s.phys[w]);
  }

  Wire public_bit(bool v) {
    int64_t& c = v ? c1_ : c0_;
    if (c < 0) {
      uint32_t id = wid++;
      int slot = alloc_slot(id);
      s.wire_slot[slot] = AShareBundle{};
      s.mask_input[slot] = v ? 1 : 0;
      c = (int64_t)id;
    }
    return (Wire)c;
  }
  Wire and_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
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
    return id;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
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
    return id;
  }
  Wire not_gate(Wire i) {
    uint32_t id = wid++;
    AShareBundle tmp = s.wslot(i);     // copy out before potential realloc
    int slot = alloc_slot(id);
    s.wire_slot[slot] = tmp;
    s.mask_input[slot] = 0;
    free_if_dead(i);
    ++gi;
    return id;
  }

  // Commit final per-run storage sizes.
  void commit_sizes() {
    s.num_ands = ai;
    s.sigma.resize(std::max(1, s.num_ands));
    if (s.party == 1) s.label_slot.resize(s.num_slots);
    else              s.eval_slot.resize(s.num_slots);
  }
};

// ===========================================================================
// Pass 2 (garbler, party 1) — produce G ciphertexts per AND, ship in chunks via
// chunk_pipe: compute (this thread) fills the next slot while a pool thread
// drains the previous slot (send + flush). begin() starts the sender; end()
// flushes + joins.
//
// Slot reuse means fabric (XOR/NOT) wire SHARES don't persist from the fused
// pass — so this pass re-propagates them (cheap, deterministic) alongside the
// labels. AND-output shares (λ_γ) and input shares live in permanent slots and
// are read directly.
// ===========================================================================
struct GarblePass {
  using Wire = uint32_t;
  LambdaState& s;
  uint32_t wid;
  int ai = 0;
  static constexpr int kBatch = 1 << 16;
  ThreadPool* pool;
  NetIO* send_io;
  chunk_pipe<LambdaStreamChunk> pipe;
  std::future<void> sender_fut;
  LambdaStreamChunk* cur = nullptr;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  GarblePass(LambdaState& st, NetIO* sio, ThreadPool* p)
      : s(st), wid((uint32_t)st.num_inputs), pool(p), send_io(sio),
        pipe(2, [&st](LambdaStreamChunk& c) {
          int cap = std::min(kBatch, std::max(1, st.num_ands));
          c.G.resize(2 * cap);
          c.b.resize(cap);
        }) {}

  void begin() {
    sender_fut = pool->enqueue([this] {
      while (auto* slot = pipe.consumer_slot()) {
        send_io->send_data(slot->G.data(), (size_t)2 * slot->n * sizeof(block));
        send_io->send_data(slot->b.data(), (size_t)slot->n);
        send_io->flush();
        pipe.consumer_release();
      }
    });
    cur = &pipe.producer_slot();
    cur->n = 0;
  }
  void end() {
    if (cur != nullptr && cur->n > 0) pipe.producer_publish();
    pipe.producer_close();
    sender_fut.get();
  }

  Wire public_bit(bool v) {
    int64_t& c = v ? c1_ : c0_;
    if (c < 0) {
      uint32_t id = wid++;
      s.wslot(id) = AShareBundle{};      // const share is 0
      // c1 acts as NOT(c0): garbler's m_{w,0} for the "1" constant is Δ to flip
      // the eval-label parity when Λ_w = 1; eval-side label is set to 0 by the
      // matching evaluate pass (no message needed — both sides synthesize).
      s.lbl(id) = v ? s.Delta : zero_block;
      c = (int64_t)id;
    }
    return (Wire)c;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    AShareBundle sh;
    sh.mac = s.wslot(i0).mac ^ s.wslot(i1).mac;
    sh.key = s.wslot(i0).key ^ s.wslot(i1).key;
    block lb = s.lbl(i0) ^ s.lbl(i1);
    s.wslot(id) = sh;
    s.lbl(id) = lb;
    return id;
  }
  Wire not_gate(Wire i) {
    uint32_t id = wid++;
    AShareBundle sh = s.wslot(i);
    block lb = s.lbl(i) ^ s.Delta;
    s.wslot(id) = sh;
    s.lbl(id) = lb;
    return id;
  }
  Wire and_gate(Wire in0, Wire in1) {
    uint32_t id = wid++;
    int my_ai = ai++;

    block ml_a0 = s.lbl(in0), ml_a1 = ml_a0 ^ s.Delta;
    block ml_b0 = s.lbl(in1), ml_b1 = ml_b0 ^ s.Delta;
    block buf[4] = {ml_a0, ml_a1, ml_b0, ml_b1};
    s.mitc.template hash_cir<1, 4>(buf);

    const AShareBundle& wb_in0 = s.wslot(in0);
    const AShareBundle& wb_in1 = s.wslot(in1);
    const AShareBundle& wb_out = s.wslot(id);
    const AShareBundle& sb     = s.sigma[my_ai];

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
    return id;
  }
};

// ===========================================================================
// Pass 2 (evaluator, party 2) — consume G chunks, derive output labels, and
// build the c_gamma witness. begin() starts the receiver; end() releases + joins.
// ===========================================================================
struct EvaluatePass {
  using Wire = uint32_t;
  LambdaState& s;
  uint32_t wid;
  int ai = 0;
  static constexpr int kBatch = 1 << 16;
  ThreadPool* pool;
  NetIO* recv_io;
  chunk_pipe<LambdaStreamChunk> pipe;
  std::future<void> recv_fut;
  LambdaStreamChunk* cur = nullptr;
  int loc = 0;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  EvaluatePass(LambdaState& st, NetIO* rio, ThreadPool* p)
      : s(st), wid((uint32_t)st.num_inputs), pool(p), recv_io(rio),
        pipe(2, [&st](LambdaStreamChunk& c) {
          int cap = std::min(kBatch, std::max(1, st.num_ands));
          c.G.resize(2 * cap);
          c.b.resize(cap);
        }) {}

  void begin() {
    recv_fut = pool->enqueue([this] {
      int recv_base = 0;
      while (recv_base < s.num_ands) {
        LambdaStreamChunk& slot = pipe.producer_slot();
        slot.n = std::min(kBatch, s.num_ands - recv_base);
        recv_io->recv_data(slot.G.data(), (size_t)2 * slot.n * sizeof(block));
        recv_io->recv_data(slot.b.data(), (size_t)slot.n);
        pipe.producer_publish();
        recv_base += slot.n;
      }
      pipe.producer_close();
    });
  }
  void end() {
    if (cur != nullptr) pipe.consumer_release();
    recv_fut.get();
  }

  // Re-propagate fabric shares alongside evaluator labels and masks.
  Wire public_bit(bool v) {
    int64_t& c = v ? c1_ : c0_;
    if (c < 0) {
      uint32_t id = wid++;
      s.wslot(id) = AShareBundle{};  // const share is 0
      s.evl(id) = zero_block;        // evaluator's label for both 0 and 1 is 0
      s.minp(id) = v ? 1 : 0;        // const's opened mask = its public bit
      c = (int64_t)id;
    }
    return (Wire)c;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    AShareBundle sh;
    sh.mac = s.wslot(i0).mac ^ s.wslot(i1).mac;
    sh.key = s.wslot(i0).key ^ s.wslot(i1).key;
    block ev = s.evl(i0) ^ s.evl(i1);
    unsigned char mi = s.minp(i0) ^ s.minp(i1);
    s.wslot(id) = sh;
    s.evl(id) = ev;
    s.minp(id) = mi;
    return id;
  }
  Wire not_gate(Wire i) {
    uint32_t id = wid++;
    AShareBundle sh = s.wslot(i);
    block ev = s.evl(i);
    unsigned char mi = s.minp(i) ^ 1;
    s.wslot(id) = sh;
    s.evl(id) = ev;
    s.minp(id) = mi;
    return id;
  }
  Wire and_gate(Wire in0, Wire in1) {
    uint32_t id = wid++;
    int my_ai = ai++;
    if (cur == nullptr || loc == cur->n) {
      if (cur != nullptr) pipe.consumer_release();
      cur = pipe.consumer_slot();
      loc = 0;
    }
    bool La = s.minp(in0), Lb = s.minp(in1);
    const AShareBundle& wb_in0 = s.wslot(in0);
    const AShareBundle& wb_in1 = s.wslot(in1);
    const AShareBundle& wb_out = s.wslot(id);
    const AShareBundle& sb     = s.sigma[my_ai];

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
    return id;
  }
};

// ===========================================================================
// Pass 3 (garbler, party 1 only) — after receiving Lambda_AND from the
// evaluator, re-propagate masks and recompute M1_t for the c_gamma check.
// ===========================================================================
struct PostCheckPass {
  using Wire = uint32_t;
  LambdaState& s;
  uint32_t wid;
  int ai = 0;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  explicit PostCheckPass(LambdaState& st) : s(st), wid((uint32_t)st.num_inputs) {}

  Wire public_bit(bool v) {
    int64_t& c = v ? c1_ : c0_;
    if (c < 0) {
      uint32_t id = wid++;
      s.wslot(id) = AShareBundle{};  // const share is 0
      s.minp(id) = v ? 1 : 0;        // const's opened mask = its public bit
      c = (int64_t)id;
    }
    return (Wire)c;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    AShareBundle sh;
    sh.mac = s.wslot(i0).mac ^ s.wslot(i1).mac;
    sh.key = s.wslot(i0).key ^ s.wslot(i1).key;
    unsigned char mi = s.minp(i0) ^ s.minp(i1);
    s.wslot(id) = sh;
    s.minp(id) = mi;
    return id;
  }
  Wire not_gate(Wire i) {
    uint32_t id = wid++;
    AShareBundle sh = s.wslot(i);
    unsigned char mi = s.minp(i) ^ 1;
    s.wslot(id) = sh;
    s.minp(id) = mi;
    return id;
  }
  Wire and_gate(Wire in0, Wire in1) {
    uint32_t id = wid++;
    int my_ai = ai++;
    s.minp(id) = s.Lambda_AND[my_ai];
    bool La = s.minp(in0), Lb = s.minp(in1);
    block m = s.sigma[my_ai].mac ^ s.wslot(id).mac;
    m = m ^ (select_mask[La] & s.wslot(in1).mac);
    m = m ^ (select_mask[Lb] & s.wslot(in0).mac);
    s.M1_t[my_ai] = m;
    return id;
  }
};

}  // namespace emp
#endif  // EMP_AG2PC_PASSES_H__
