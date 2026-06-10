#ifndef EMP_AG2PC_PASS_CTX_H__
#define EMP_AG2PC_PASS_CTX_H__

// The AG2PC authenticated-garbling protocol as a sequence of PASSES, each a C++20
// emp::BooleanContext over one shared AG2PCRunState (run_state.h). A pass declares
// only its per-gate behavior (public_bit/and_gate/xor_gate/not_gate, value-return)
// plus optional begin()/end(); the engine (engine.h) sequences them and the
// inter-pass crypto. Because a pass is a BooleanContext, the SAME pass drives any
// source (stored BooleanProgram or a live-replayed body) and yields the identical
// gate stream, hence identical transcripts.
//
// Party asymmetry: the garbler (party 1) runs Liveness -> SlotMask -> Garble ->
// GammaCheck; the evaluator (party 2) runs Liveness -> SlotMask -> Evaluate.

#include "emp-tool/runtime/runtime.h"                  // block, MITCCRH, select_mask, ThreadPool, RO, Hash
#include "emp-ag2pc/backend/secure_wires.h"     // AShareBundle / AShareBundleVec / SecureWires
#include "emp-ag2pc/backend/triple_pool.h"      // TriplePool
#include "emp-ag2pc/backend/helper.h"           // chunk_pipe, LSB, LSB1
#include "emp-ag2pc/backend/run_state.h"        // AG2PCRunState, AG2PCStreamChunk
#include <algorithm>
#include <cstdint>
#include <future>
#include <vector>

namespace emp {

// ===========================================================================
// Pass 0 — liveness. last_use / persist over the gate stream; AND outputs
// persist, linear/const wires are recyclable; circuit outputs are pinned by
// commit(). Pure analysis: no crypto, no IO.
// ===========================================================================
struct AG2PCLivenessPass {
  using Wire = uint32_t;
  AG2PCRunState& s;
  uint32_t wid;
  int gi = 0;                       // gate index over AND/XOR/NOT
  int ai = 0;                       // AND count (committed so SlotMask can reserve)
  std::vector<int> last_use;
  std::vector<char> persist;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  explicit AG2PCLivenessPass(AG2PCRunState& st) : s(st), wid((uint32_t)st.num_inputs) {
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
    last_use[i0] = gi; last_use[i1] = gi; ++gi; ++ai;
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
    s.num_ands  = ai;   // exact; lets SlotMask reserve rep_a/rep_b up front
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
struct AG2PCSlotMaskPass {
  using Wire = uint32_t;
  AG2PCRunState& s;
  TriplePool* fpre;
  uint32_t wid;
  int ai = 0;
  int gi = 0;                       // gate index over AND/XOR/NOT
  std::vector<int> freelist;        // recycled fabric slots
  AShareBundleVec lg_buf;
  int lg_off = 0;
  static constexpr int kLgBatch = 1 << 14;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  AG2PCSlotMaskPass(AG2PCRunState& st, TriplePool* f)
      : s(st), fpre(f), wid((uint32_t)st.num_inputs) {
    s.rep_a.clear();
    s.rep_b.clear();
    // num_ands is known from the liveness pass; reserving up front keeps the
    // two operand-share streams (32 B per AND each) from realloc-copying as
    // they grow across the chunk.
    s.rep_a.reserve((size_t)st.num_ands);
    s.rep_b.reserve((size_t)st.num_ands);
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
struct AG2PCGarblePass {
  using Wire = uint32_t;
  AG2PCRunState& s;
  uint32_t wid;
  int ai = 0;
  static constexpr int kBatch = 1 << 16;
  ThreadPool* pool;
  NetIO* send_io;
  chunk_pipe<AG2PCStreamChunk> pipe;
  std::future<void> sender_fut;
  AG2PCStreamChunk* cur = nullptr;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  AG2PCGarblePass(AG2PCRunState& st, NetIO* sio, ThreadPool* p)
      : s(st), wid((uint32_t)st.num_inputs), pool(p), send_io(sio),
        pipe(2, [&st](AG2PCStreamChunk& c) {
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
struct AG2PCEvaluatePass {
  using Wire = uint32_t;
  AG2PCRunState& s;
  uint32_t wid;
  int ai = 0;
  static constexpr int kBatch = 1 << 16;
  ThreadPool* pool;
  NetIO* recv_io;
  chunk_pipe<AG2PCStreamChunk> pipe;
  std::future<void> recv_fut;
  AG2PCStreamChunk* cur = nullptr;
  int loc = 0;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  AG2PCEvaluatePass(AG2PCRunState& st, NetIO* rio, ThreadPool* p)
      : s(st), wid((uint32_t)st.num_inputs), pool(p), recv_io(rio),
        pipe(2, [&st](AG2PCStreamChunk& c) {
          int cap = std::min(kBatch, std::max(1, st.num_ands));
          c.G.resize(2 * cap);
          c.b.resize(cap);
        }) {}

  void begin() {
    recv_fut = pool->enqueue([this] {
      int recv_base = 0;
      while (recv_base < s.num_ands) {
        AG2PCStreamChunk& slot = pipe.producer_slot();
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
struct AG2PCGammaCheckPass {
  using Wire = uint32_t;
  AG2PCRunState& s;
  uint32_t wid;
  int ai = 0;
  int64_t c0_ = -1, c1_ = -1;       // dedup the two constant wires

  explicit AG2PCGammaCheckPass(AG2PCRunState& st) : s(st), wid((uint32_t)st.num_inputs) {}

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
#endif  // EMP_AG2PC_PASS_CTX_H__
