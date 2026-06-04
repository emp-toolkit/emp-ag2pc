#ifndef EMP_AG2PC_ENGINE_H__
#define EMP_AG2PC_ENGINE_H__

#include "emp-tool/emp-tool.h"
#include "emp-tool/frontend/executor.h"   // frontend::run — the pure-circuit calling contract
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

// Lambda-mode wire carrier: a bare int id with NO refcount hook. The user's
// lambda is replayed multiple times (once per phase); each replay emits the
// same sequence of gates, so wire ids come out identical and the per-wire /
// per-AND state arrays — grown during the first pass — can be indexed by id
// directly across phases. No flat gate vector is materialized.
//
// LambdaWire stays distinct from the recorder's AG2PCWire so lambda mode pays
// zero per-Bit overhead (no singleton check on ctor/dtor). The empty user dtor
// keeps the type non-trivially-copyable — without any runtime cost (empty body
// inlines to nothing) — so the build's -Werror=class-memaccess flag still
// catches any memcpy of Bit_T<LambdaWire>.
struct LambdaWire {
  int id = -1;
  LambdaWire() = default;
  explicit LambdaWire(int i) noexcept : id(i) {}
  // Empty user dtor — non-trivially-copyable, but zero runtime cost.
  ~LambdaWire() {}
};

// Per-run shared state. Storage is linear in #AND gates + the circuit's live
// width, NOT #wires: a liveness pre-pass (LivenessBackend) computes last_use +
// persist, the fused pass assigns each wire a physical SLOT (phys[]) — inputs,
// AND-outputs and circuit-outputs get permanent slots, XOR/NOT "fabric" wires
// share a recycled pool freed at last read — and the heavy per-wire arrays size
// to num_slots. The per-wire accessors below hide the phys[] indirection from
// the crypto.
struct LambdaState {
  int party = 0;
  block Delta = zero_block;
  int num_inputs = 0;
  int num_ands = 0;
  int num_wires = 0;     // logical wire ids (inputs + emitted), from liveness pass
  int num_slots = 0;     // physical slots (size of the per-wire arrays)

  // Slot map + liveness (size = num_wires), filled by the liveness pass / fused
  // pass. phys[w] = physical slot of logical wire w.
  std::vector<int> phys;
  std::vector<int> last_use;        // last gate index reading w (-1 if never)
  std::vector<char> persist;        // 1 if w holds a permanent slot

  // Per-SLOT (size = num_slots). Indexed via the accessors below, never by raw
  // wire id, since fabric wires share slots.
  AShareBundleVec wire_slot;
  std::vector<unsigned char> mask_input;
  BlockVec label_slot;                 // garbler only
  BlockVec eval_slot;                  // evaluator only
  // Per-AND (size = num_ands), indexed by AND index (not slotted).
  AShareBundleVec rep_a, rep_b;
  AShareBundleVec sigma;
  // c_γ check state — filled inline by EvaluateBackend (P2 evaluator) or by
  // PostRecvCheckBackend (P1 garbler, after receiving Lambda_AND).
  BlockVec M1_t;
  std::vector<unsigned char> Lambda_AND;

  MITCCRH<8> mitc;

  // Per-wire accessors: map a logical wire id through phys[] to its slot. The
  // garble / evaluate / post-check phases address state ONLY through these.
  AShareBundle&  wslot(int w) { return wire_slot[phys[w]]; }
  unsigned char& minp(int w)  { return mask_input[phys[w]]; }
  block&         lbl(int w)   { return label_slot[phys[w]]; }
  block&         evl(int w)   { return eval_slot[phys[w]]; }
};

// ===========================================================================
// Phase backend base: shared wire_bytes + error-out for feed/reveal.
// ===========================================================================
class PhaseBackend : public Backend {
 public:
  explicit PhaseBackend(int p) : Backend(p) {}
  size_t wire_bytes() const override { return sizeof(LambdaWire); }
  // PUBLIC feeds are public constants — dispatch to public_label per bit.
  // Non-PUBLIC feeds are forbidden inside the lambda; the user must hand
  // SecureWires to run_circuit instead.
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

// ===========================================================================
// Phase 0 — liveness pre-pass. A single value-free walk that records, per
// logical wire, the last gate index that reads it (last_use) and whether it
// must hold a permanent slot (persist = inputs / AND-outputs / circuit-outputs).
// It is a streaming slot-assignment scan — no gate list is materialized; the
// body is just replayed. It runs before the fused pass so the fused pass can
// recycle XOR/NOT fabric slots inline.
//
// Wire ids match the other phases exactly (wid starts at num_inputs, ++ per
// public_label / and / xor / not), and the gate index gi advances only on
// and/xor/not — so last_use is meaningful to the fused pass's free decisions.
// ===========================================================================
class LivenessBackend : public PhaseBackend {
 public:
  LambdaState &s;
  int wid;
  int gi = 0;   // gate index over and/xor/not only (matches the other phases)
  std::vector<int> last_use;
  std::vector<char> persist;

  explicit LivenessBackend(LambdaState &st)
      : PhaseBackend(st.party), s(st), wid(st.num_inputs) {
    last_use.assign(st.num_inputs, -1);
    persist.assign(st.num_inputs, 1);   // inputs hold permanent slots
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
    emit_(out, /*persist=*/true);          // AND outputs hold fresh randomness
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

// ===========================================================================
// Phase 1 (fused) — single walk that assigns physical slots (phys[]) AND runs
// the share-prop sweep. Slots: persistent wires (inputs / AND-outputs / outputs,
// per the liveness pass) get a permanent slot; XOR/NOT fabric wires draw from a
// freelist and are returned at their last read. The per-slot arrays grow only
// when a fresh slot is minted, so peak storage is the live-set width + #ANDs.
//
// λ_γ availability: XOR/NOT downstream of an AND need wire_slot[γ] set to the
// AND's fresh output mask at the moment they read it. Drawing λ_γ in one big
// batch up front would require knowing num_ands first (the eliminated pass).
// Instead, λ_γ is drawn LAZILY in batches of kLgBatch from the open COT
// session — refill happens when the buffer empties. At ~16K shares per refill,
// per-batch round-trip overhead amortizes to negligible per AND; the only
// "waste" is up to kLgBatch − 1 shares left unused at the tail of the last
// batch (≤ 0.02% of total COTs for 100M-AND runs).
// ===========================================================================
class FusedSizeCollectMasksBackend : public PhaseBackend {
 public:
  LambdaState &s;
  TriplePool *fpre;
  int wid;
  int ai = 0;
  int gi = 0;                  // gate index (and/xor/not), matches LivenessBackend
  std::vector<int> freelist;   // recycled fabric slots
  AShareBundleVec lg_buf;
  int lg_off = 0;
  static constexpr int kLgBatch = 1 << 14;

  FusedSizeCollectMasksBackend(LambdaState &st, TriplePool *f)
      : PhaseBackend(st.party), s(st), fpre(f), wid(st.num_inputs) {
    s.rep_a.clear();
    s.rep_b.clear();
    // wire_slot / mask_input were sized to num_inputs and loaded with input
    // shares by the runner at slots [0,num_inputs); s.num_slots == num_inputs.
    // We mint / recycle slots for emitted wires from here, growing the arrays
    // only when a fresh slot is needed.
  }

  AShareBundle next_lambda_gamma() {
    if (lg_off >= (int)lg_buf.size()) {
      lg_buf.clear();
      fpre->draw(kLgBatch, lg_buf);
      lg_off = 0;
    }
    return lg_buf[lg_off++];
  }

  // Assign a physical slot to logical wire `id` (called in emission order, so
  // the slot stream matches across phases). Persistent wires get a fresh
  // permanent slot; fabric wires reuse a freed slot when one is available.
  // Growing the slot count grows the per-slot arrays in lockstep.
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
  // Return a wire's slot to the freelist once its last read has happened.
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

  // Commit final sizes to state. num_ands / num_wires came from the liveness
  // pass; here we size the per-AND sigma and the garbler/evaluator label arrays
  // to num_slots (resize, not assign — input slots [0,num_inputs) already hold
  // the loaded input labels). (Named commit_sizes rather than finalize() to
  // avoid shadowing Backend's virtual.)
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
// Phase 2 — evaluate (P2): consumes G chunks from a pipelined recv thread.
// At each AND, decodes ml_g0 → eval_slot[id] and derives mask_input[id] = Lg,
// AND computes the c_γ witness M1_t[ai] + Lambda_AND[ai] inline (this fuses
// the prior CheckCgamma evaluator walk into evaluate). After Phase 2 the
// evaluator only needs to exchange digests with the garbler — no further walk.
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

  // Like garble, this phase re-propagates fabric SHARES (slot-reused, so they
  // don't survive the fused pass) alongside the evaluator's labels and masks.
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

    // Fused c_γ witness: now that La / Lb / Lg are all known, compute M1_t
    // and Lambda_AND for this AND inline. Saves the prior dedicated walk.
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
// Phase 3 (P1 garbler only) — single walk run AFTER receiving Lambda_AND from
// the evaluator. Propagates mask_input through XOR / NOT and, at each AND,
// sets mask_input[id] = Lambda_AND[ai] and computes M1_t[ai]. Replaces the
// prior two-walk CheckCgamma orchestration (first walk dropped — its only
// purpose was to advance wid/ai with mask_input[id]=0 placeholders; the new
// single walk overwrites mask_input[id] before any downstream XOR consumes it,
// which is safe because the lambda emits gates in topological order).
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

// ===========================================================================
// AG2PCInputs — build engine inputs with ordinary EMP-object constructors,
// OUTSIDE the circuit body. Install it (RAII), construct your secret inputs with
// the normal (value, party) constructor, then hand it to AG2PCEngine::run with a
// nullary body that captures them:
//
//   AG2PCInputs inputs(&mpc);
//   UInt32 a(party == ALICE ? x : 0, ALICE);
//   UInt32 b(party == BOB   ? y : 0, BOB);
//   Bit    flag(party == ALICE ? f : false, ALICE);
//   auto c = engine.run(inputs, [&]{
//     return a.select(flag, b) + UInt32(32, 1, PUBLIC);   // gates + consts: in the body
//   });
//   uint32_t z = c.reveal<uint32_t>(PUBLIC);              // object-style reveal on the handle
//
// feed() is DEFERRED: it only records a pending input and hands back deterministic
// wire ids [base, base+width). The actual sharing is BATCHED — ONE process_inputs
// call (grouped by owner) at process()/run time — then scattered back into
// construction (placeholder-id) order, which is exactly the layout run_engine_
// binds. So the captured objects' ids line up with the engine with no change to
// run_engine_.
//
// Lifecycle: only secret feed() is allowed here; public constants, gates, and
// reveal belong inside the run body (they error here). The batch FREEZES at the
// first process()/run — feeding after that is an error. The frozen input bundle
// is REUSABLE: you may run several different bodies over the same AG2PCInputs
// (construct inputs once, run many), each run replaying a fresh circuit over the
// already-shared input wires (the same wire-reuse the recorder relies on across
// chunks). Construct a fresh AG2PCInputs only when you want different inputs.
//
// RAII: installs itself as the global backend in the ctor and restores the
// previous one in the dtor, so it is non-copyable / non-movable (a copy could
// restore the backend pointer early or out of order).
// ===========================================================================
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

  // Deferred: record (owner, bits), assign ids [base, base+n); no protocol yet.
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

  // Batch-share all pending inputs (one process_inputs call, grouped by owner) and
  // scatter the authenticated wires back into placeholder-id order. Idempotent +
  // freezing: the returned bundle's wire i is the input constructed at id i.
  const SecureWires &process() {
    if (frozen_) return bundle_;
    frozen_ = true;

    std::vector<int> owners;                              // distinct owners, sorted
    for (const Entry &e : pending_)
      if (std::find(owners.begin(), owners.end(), e.owner) == owners.end())
        owners.push_back(e.owner);
    std::sort(owners.begin(), owners.end());
    auto owner_index = [&](int o) {
      return (int)(std::find(owners.begin(), owners.end(), o) - owners.begin());
    };

    std::vector<std::vector<bool>> bits(owners.size());   // per-owner concatenated bits
    std::vector<int> ent_oi(pending_.size()), ent_off(pending_.size());
    for (size_t k = 0; k < pending_.size(); ++k) {
      int oi = owner_index(pending_[k].owner);
      ent_oi[k]  = oi;
      ent_off[k] = (int)bits[oi].size();
      bits[oi].insert(bits[oi].end(), pending_[k].bits.begin(), pending_[k].bits.end());
    }

    std::vector<SecureWires> sub;
    if (!owners.empty()) sub = mpc_->process_inputs(owners, bits);  // ONE batched call

    const bool is_eval = (mpc_->party != 1);
    bundle_.Lambda.resize(next_);
    bundle_.wire_bundle.resize(next_);
    if (is_eval) bundle_.eval_label.resize(next_);
    else         bundle_.label0.resize(next_);
    for (size_t k = 0; k < pending_.size(); ++k) {        // scatter to id order
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

// ===========================================================================
// Opened — the result handle returned by AG2PCEngine::run(AG2PCInputs&, body).
// Lets the engine output be opened object-style — `c.reveal<uint32_t>(PUBLIC)` —
// mirroring the direct front-end, while the engine body stays pure (this is a
// POST-run open, not reveal-inside-the-body). It wraps the output SecureWires;
// reveal<T>() decodes to `recipient` and folds the bits LSB-first into a scalar
// (bool / unsigned integer) or returns the raw bits for std::vector<bool>.
//
// NOTE: this is a decode-and-fold convenience, NOT the EMP object's own reveal
// machinery — identical result for scalar / bit-vector outputs. Composite returns
// (a struct/tuple of values) aren't auto-reconstructed: use reveal_bits() + slice.
// Implicitly converts to SecureWires, so `SecureWires out = run(...)` and
// `mpc.reveal(out, party)` keep working unchanged.
// ===========================================================================
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
  operator SecureWires() const { return wires; }   // back-compat with decode/reveal callers
};

// ===========================================================================
// AG2PCEngine: the streaming AG2PC engine. One phase choreography (liveness ->
// size/collect -> garble/evaluate -> c_γ correction -> output), one LambdaState
// + phase Backends, driven by a CIRCUIT SOURCE — a replay callback that emits
// the circuit under the installed phase backend. Every source replays through
// this one engine; there is no second garbling/evaluation path anywhere in
// AG2PC. The sources:
//
//   frontend body      run<Ins...>(inputs, body)
//                      -> frontend::run(body, LambdaWire args)
//   compiled circuit   run_compiled<Ins...>(tc, inputs)
//                      -> frontend::run(tc, LambdaWire args)
//   raw program        run_program(prog, inputs, output_ids)
//                      -> replay a frontend::BooleanProgram directly
//   legacy flat lambda run_circuit(in_wires, n_out, lambda)
//
// The frontend body and compiled circuit are both emp-tool/frontend front-doors:
// a body is the source code; a compiled circuit (frontend::compile -> TypedCircuit)
// is its recorded BooleanProgram. frontend::run walks either against the phase
// backend, issuing identical backend calls — so a compiled circuit needs no
// lowering. The direct AG2PCBackend recorder (ag2pc_backend.h) is an imperative
// adapter that buffers a chunk into a frontend::BooleanProgram and runs it here
// via run_program — same engine, not a separate path.
//
// CONSTANT subtlety: compile() dedupes CONST0/CONST1, so a compiled circuit's
// gate stream — and thus its transcript — can differ from the equivalent body
// replay (a body may emit a public label per use). Both are correct KRRW;
// semantic/oracle equality is the contract, not byte-identical transcripts.
// ===========================================================================
class AG2PCEngine {
 public:
  AG2PCSession *mpc;
  explicit AG2PCEngine(AG2PCSession *m) : mpc(m) {}

  // Run a pure FRONTEND circuit body (emp-tool/frontend): typed circuit-value
  // arguments in, a typed circuit value out. Inputs/outputs stay outside the
  // body (no feed/reveal inside): the caller process_inputs() each argument into
  // a SecureWires bundle (with its owner) and passes the bundles in ARGUMENT
  // ORDER; the returned SecureWires is decode()d by the caller.
  //
  //   auto out = runner.run<UInt32, UInt32>({xa, yb},
  //                  [](auto a, auto b){ return a + b; });
  //
  // The body is wire-generic (a generic / template lambda or templated functor)
  // and is replayed once per phase (2 for the evaluator, 3 for the garbler), so
  // it must be deterministic and side-effect-free — exactly the frontend's pure-
  // circuit contract. Ins... name the argument shapes (so the typed args can be
  // assembled over LambdaWire); each bundle's width must match its argument.
  template <typename... Ins, typename F>
  SecureWires run(const std::vector<SecureWires> &inputs, F body) {
    auto prep = prepare_typed_inputs_<Ins...>(inputs);
    using Tr = emp::frontend::circuit_fn_traits<F, rebind_t<Ins, LambdaWire>...>;
    auto replay = make_frontend_body_replay_<Tr>(body, prep.args);
    return run_engine_(prep.in_wires, replay);
  }

  // Run with inputs built via EMP-object constructors (AG2PCInputs, above): the
  // batch is shared (one process_inputs call, grouped by owner) and FROZEN here, then a
  // NULLARY `body` that captured those input objects emits the circuit. This is
  // the constructor-style front door — no manual process_inputs / bits_of, all
  // inputs batched. `body` returns the output circuit value.
  //
  // Returns an Opened handle so the output can be read object-style —
  // `auto c = run(inputs, body); c.reveal<uint32_t>(PUBLIC);` — while still
  // converting implicitly to SecureWires for mpc.reveal/decode callers.
  //
  // The nullary `body` goes through the SAME frontend contract as run<Ins...>
  // (circuit_fn_traits / circuit_contract): it must be callable with no args and
  // RETURN A CIRCUIT VALUE BY VALUE — a void / reference / non-circuit return is
  // rejected with the contract's precise diagnostic, not a downstream error.
  template <typename F>
  Opened run(AG2PCInputs &inputs, F body) {
    using Tr = emp::frontend::circuit_fn_traits<F>;     // nullary body (empty arg pack)
    const SecureWires &in = inputs.process();           // batched process_inputs; freezes
    auto replay = [&body]() -> std::vector<int> {
      (void)sizeof(emp::frontend::circuit_contract<Tr>);   // the one contract diagnostic
      if constexpr (Tr::ok) return pack_output_ids_(body());
      else return {};                                      // unreachable: contract static_asserted
    };
    return Opened{mpc, run_engine_(in, replay)};
  }

  // Run a COMPILED frontend circuit (frontend::compile<Ins...>(body) ->
  // TypedCircuit) through the SAME streaming engine, replaying the recorded
  // BooleanProgram per phase via frontend::run(tc, args) (see
  // make_compiled_frontend_replay_) instead of re-invoking a body. The compiled
  // source is the canonical frontend circuit — no lowering step. Ins...
  // name the input shapes (as in compile<Ins...>); RetRec is deduced from tc.
  //
  // NOTE: compile() dedupes CONST0/CONST1, so a compiled circuit's gate stream
  // (and transcript) may differ from the equivalent body replay; both are correct
  // KRRW — semantic/oracle equality is the contract, not byte-identical transcript.
  template <typename... Ins, typename RetRec>
  SecureWires run_compiled(const frontend::TypedCircuit<RetRec> &tc,
                           const std::vector<SecureWires> &inputs) {
    auto prep = prepare_typed_inputs_<Ins...>(inputs);
    auto replay = make_compiled_frontend_replay_(tc, prep.args);
    return run_engine_(prep.in_wires, replay);
  }

  // Legacy entry point: a "circuit lambda" with the flat
  //   void lambda(const std::vector<Bit_T<LambdaWire>>& in,
  //                     std::vector<Bit_T<LambdaWire>>& out)
  // convention and an explicit n_out. Thin shim over run_engine_; new code should
  // use run<Ins...> (a frontend body) or run_compiled<Ins...> (a compiled circuit).
  template <typename F>
  SecureWires run_circuit(const SecureWires &in_wires, int n_out, F lambda) {
    auto replay =
        make_flat_lambda_replay_((int)in_wires.size(), n_out, std::move(lambda));
    return run_engine_(in_wires, replay);
  }

  // Raw compiled-program source: replay a frontend::BooleanProgram through the
  // shared engine. Lower-level than run_compiled<Ins...> (no typed args) — for
  // dynamically-shaped programs such as the direct recorder's per-chunk circuits.
  // `inputs` are bound to wire ids [0, inputs.size()) (it must equal the program's
  // input-wire count); `output_ids` names the program wires to return, in order.
  // Reuses run_engine_ — no garble/evaluate logic here.
  //
  // This is a raw entry point: it validates the program's shape up front (input
  // width, in-range gate operands / outputs) so a malformed BooleanProgram aborts
  // via error() instead of indexing out of bounds during replay.
  SecureWires run_program(const frontend::BooleanProgram &prog,
                          const SecureWires &inputs,
                          const std::vector<int> &output_ids) {
    const int num_inputs = (int)inputs.size();
    const int NW = prog.num_wire;
    if (num_inputs != prog.total_input_bits())
      error("run_program: input bundle width != program input-wire count");
    // Inputs are bound POSITIONALLY to wire ids [0, num_inputs): the replay
    // writes buf[0..num_inputs) (which must fit in buf, sized NW) and ignores
    // InputPort::base, so the ports must in fact tile [0, num_inputs) in order.
    if (num_inputs > NW)
      error("run_program: input count exceeds program wire count");
    int expect = 0;
    for (const frontend::InputPort &p : prog.inputs) {
      if (p.n < 0 || p.base != expect)
        error("run_program: input ports must be contiguous from wire 0");
      expect += p.n;
    }
    auto chk = [&](int w) {
      if (w < 0 || w >= NW) error("run_program: wire id out of range");
    };
    for (const frontend::Gate &g : prog.gates) {
      chk(g.out);
      if (!g.is_const())               chk(g.in0);
      if (g.is_and() || g.is_xor())    chk(g.in1);
    }
    for (int o : output_ids) chk(o);

    // Replay the program's gates against the installed phase backend, binding
    // input wires [0,num_inputs) to LambdaWire ids [0,num_inputs). CONST gates
    // dispatch to public_label; AND/XOR/NOT to the matching op. Identical each
    // phase (program is fixed) → deterministic wire ids. (Inlined rather than a
    // helper because run_program is non-template and the helper's deduced return
    // type couldn't be used before its definition.)
    auto replay = [&prog, num_inputs, &output_ids]() -> std::vector<int> {
      std::vector<LambdaWire> buf(prog.num_wire);
      for (int i = 0; i < num_inputs; ++i) buf[i] = LambdaWire(i);
      for (const frontend::Gate &g : prog.gates) {
        switch (g.op) {
          case frontend::Op::CONST0: backend->public_label(&buf[g.out], false); break;
          case frontend::Op::CONST1: backend->public_label(&buf[g.out], true);  break;
          case frontend::Op::AND: backend->and_gate(&buf[g.out], &buf[g.in0], &buf[g.in1]); break;
          case frontend::Op::XOR: backend->xor_gate(&buf[g.out], &buf[g.in0], &buf[g.in1]); break;
          case frontend::Op::NOT: backend->not_gate(&buf[g.out], &buf[g.in0]); break;
        }
      }
      std::vector<int> ids(output_ids.size());
      for (size_t i = 0; i < output_ids.size(); ++i) ids[i] = buf[output_ids[i]].id;
      return ids;
    };
    return run_engine_(inputs, replay);
  }

 private:
  // Append one SecureWires bundle onto another (argument-order concatenation).
  // label0 is the garbler's (P1) per-wire field, eval_label the evaluator's
  // (P2); each is populated only for the owning role, so the .empty() guards
  // copy whichever this party actually carries.
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

  // ===========================================================================
  // Circuit SOURCES. A source is a callback that, each time it is invoked, emits
  // the same circuit under whatever phase backend run_engine_ has installed, and
  // returns the packed output wire ids (flattened frontend output order). Three
  // sources share the one phase engine:
  //   - make_frontend_body_replay_  : a pure frontend body  (run<Ins...>)
  //   - make_compiled_frontend_replay_ : a compiled circuit (run_compiled<Ins...>)
  //   - make_flat_lambda_replay_    : the legacy (in_bits,out_bits) lambda
  // ===========================================================================

  template <typename... Ins>
  struct Prepared {
    SecureWires in_wires;                            // bundles concatenated, [0,num_in)
    std::tuple<rebind_t<Ins, LambdaWire>...> args;   // typed args over ids [0,num_in)
  };

  // Validate the bundle count + fixed-width shapes, concatenate the per-argument
  // bundles into one ordered input bundle (wires [0,num_in)), and build the typed
  // LambdaWire argument tuple (ids [0,num_in); reused across replays, so wire ids
  // stay fixed while gate ids are reassigned deterministically each pass).
  template <typename... Ins>
  Prepared<Ins...> prepare_typed_inputs_(const std::vector<SecureWires> &inputs) {
    if (sizeof...(Ins) != inputs.size())
      error("AG2PCEngine: input bundle count != argument type count");
    // A fixed-width type (UInt32/Bit/Float) pins its width; a runtime-width type
    // (BitVec/UnsignedInt) default-constructs to pack_size 0 and is sized by its
    // bundle. Mirrors frontend::compile<Ins...>'s shape derivation.
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

  // Pack a returned circuit value into flattened output wire ids.
  template <typename T>
  static std::vector<int> pack_output_ids_(const T &out_val) {
    auto ow = pack_wires(out_val);   // std::vector<LambdaWire>
    std::vector<int> ids(ow.size());
    for (size_t i = 0; i < ow.size(); ++i) ids[i] = ow[i].id;
    return ids;
  }

  // Frontend BODY source. Delegates to frontend::run so the pure-circuit calling
  // contract is reused (prvalue args, return-by-value; lvalue-ref / reference- /
  // void- / non-circuit-return bodies rejected). The contract trait is
  // instantiated ONCE here (its single precise diagnostic), and output packing is
  // guarded by `if constexpr (Tr::ok)` so a violation does NOT also emit a
  // pack_wires(invalid_circuit_fn) error. body/args are run<>'s locals, alive for
  // the synchronous run_engine_ call.
  template <typename Tr, typename F, typename ArgsTuple>
  static auto make_frontend_body_replay_(F &body, ArgsTuple &args) {
    return [&body, &args]() -> std::vector<int> {
      (void)sizeof(emp::frontend::circuit_contract<Tr>);   // the one contract diagnostic
      if constexpr (Tr::ok) {
        auto out = std::apply(
            [&](auto &...a) { return emp::frontend::run(body, a...); }, args);
        return pack_output_ids_(out);
      } else {
        return {};   // unreachable: the contract above already static_asserted
      }
    };
  }

  // Compiled-circuit source: replay the recorded BooleanProgram through the
  // installed phase backend. frontend::run(tc, ...) routes to the circuit-replay
  // overload (is_typed_circuit disables the live-body overload), which walks the
  // program in topological order issuing the same backend calls a body would
  // (public_label for CONST gates, and/xor/not). A compiled circuit always
  // returns a valid circuit value, so no contract guard is needed.
  template <typename RetRec, typename ArgsTuple>
  static auto make_compiled_frontend_replay_(const frontend::TypedCircuit<RetRec> &tc,
                                             ArgsTuple &args) {
    return [&tc, &args]() -> std::vector<int> {
      auto out = std::apply(
          [&](auto &...a) { return emp::frontend::run(tc, a...); }, args);
      return pack_output_ids_(out);
    };
  }

  // Legacy flat-lambda source: owns the Bit_T<LambdaWire> input/output vectors in
  // the closure (so they persist across phase replays). Inputs are pre-bound to
  // ids [0,num_in); outputs are read back by id after each replay.
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

  // The streaming crypto engine. replay() emits the circuit against the
  // currently-installed phase backend and returns the output wire ids; it is
  // called once per phase. The protocol between/after replays is identical
  // regardless of how the circuit is expressed (frontend body or legacy lambda).
  //
  // Walk count (per run):
  //   evaluator (P2): 3 walks  — liveness + fused_size_collect + evaluate(+c_γ)
  //   garbler   (P1): 4 walks  — liveness + fused_size_collect + garble + c_γ
  // The extra liveness walk is value-free (no crypto / IO); it buys storage
  // linear in #ANDs + live width instead of #wires.
  template <typename Replay>
  SecureWires run_engine_(const SecureWires &in_wires, Replay replay) {
    Backend *saved = backend;
    int num_in = (int)in_wires.size();

    LambdaState st;
    st.party = mpc->party;
    st.Delta = mpc->Delta;
    st.num_inputs = num_in;

#ifdef AG2PC_PROFILE
    // AG2PC_PHASE expands `io_count(send_io, recv_io)` and `party` literally, so
    // expose them here; markers below print one [ag2pc] line per phase per call
    // (at the garbler, party 1). AG2PC_TP sub-phase lines come from triple_pool.
    NetIO *send_io = mpc->send_io, *recv_io = mpc->recv_io;
    int party = st.party;
#endif
    AG2PC_PHASE_BEGIN();

    // ---------- Phase 0 (liveness): last_use + persist + circuit outputs ----------
    std::vector<int> out_ids;
    {
      LivenessBackend lb(st);
      backend = &lb;
      out_ids = replay();
      lb.commit(out_ids);     // sets st.num_wires / num_ands / last_use / persist
    }
    const int n_out = (int)out_ids.size();

    // ---------- Slot map: inputs occupy permanent slots [0,num_in) ----------
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

    // ---------- Phase 1 (fused): assign fabric/AND slots + collect_masks ----------
    {
      FusedSizeCollectMasksBackend fb(st, mpc->fpre);
      backend = &fb;
      replay();
      fb.commit_sizes();
    }
    AG2PC_PHASE("fused[size+collect_masks]");

    // M1_t / Lambda_AND for the c_γ witness — filled inline below.
    st.M1_t.resize(std::max(1, st.num_ands));
    st.Lambda_AND.assign(std::max(1, st.num_ands), 0);

    // ---------- compute_inplace (no replay; pure protocol over arrays) ----------
    mpc->fpre->compute_inplace(st.rep_a, st.rep_b, st.num_ands, st.sigma);
    AG2PC_PHASE("inplace_triples[step5b]");

    // MITC start point — drawn fresh from the FS transcript (identical on both
    // parties via get_digest's canonical d_AB‖d_BA; advances every reactive
    // round so the gid-derived gate tweaks never repeat).
    st.mitc.setS(RO("AG2PC half-gate", zero_block)
                     .absorb(mpc->io->get_digest())
                     .absorb(mpc->sib->get_digest())
                     .squeeze_block());

    // ---------- Phase 2: garble OR evaluate (evaluator fuses c_γ inline) ----------
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

    // ---------- c_γ exchange ----------
    // Evaluator already has M1_t + Lambda_AND populated by the fused evaluate
    // pass. Garbler must receive Lambda_AND then run a single walk to compute
    // M1_t.
    if (st.num_ands > 0) {
      if (st.party != 1) {                              // evaluator
        mpc->io->send_bool((const bool *)st.Lambda_AND.data(), st.num_ands);
        mpc->io->flush();
        char D1[Hash::DIGEST_SIZE], D2[Hash::DIGEST_SIZE];
        Hash::hash_once(D1, st.M1_t.data(),
                        (size_t)st.num_ands * sizeof(block));
        mpc->io->recv_data(D2, Hash::DIGEST_SIZE);
        if (memcmp(D1, D2, Hash::DIGEST_SIZE) != 0)
          error("lambda c_gamma check failed");
      } else {                                          // garbler
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

    // ---------- COT subspace-VOLE check ----------
    mpc->fpre->maybe_flush_cot_check();
    AG2PC_PHASE("cot_check");

    // ---------- Gather outputs ----------
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

// Compatibility alias: LambdaRunner was the old name for the engine, back when
// it only ran flat lambdas. It now executes every circuit source.
using LambdaRunner = AG2PCEngine;

}  // namespace emp
#endif  // EMP_AG2PC_ENGINE_H__
