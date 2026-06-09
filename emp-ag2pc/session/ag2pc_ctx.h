#ifndef EMP_AG2PC_SESSION_CTX_H__
#define EMP_AG2PC_SESSION_CTX_H__

// AG2PCCtx — the AG2PC gate recorder (AG2PCSession::Ctx). It is a C++20
// BooleanContext: gate ops record into the current chunk as bare recorder ids. It
// owns ONLY the pending-recording substrate — no crypto, no carried/authenticated
// state, no I/O. The Session (ag2pc_session.h) owns the carried materialized state
// and the protocol, and drives every flush; operand stale-detection is deferred to
// that flush (plan_flush over the Session's carried_), so the gate path stays a
// pure recorder with no per-gate carried lookup.

#include "emp-tool/ir/program.h"           // circuit::Gate, Op
#include "emp-tool/context/concept.h"      // BooleanContext
#include "emp-tool/core/utils.h"           // error()
#include <cstddef>
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace emp {

class AG2PCCtx {
public:
  using Wire = uint32_t;   // bare recorder id (no refcount); std::regular
  AG2PCCtx() = default;

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
  Wire and_gate(Wire a, Wire b) { require_allocated_(a); require_allocated_(b); return record_(a, b, circuit::Op::And); }
  Wire xor_gate(Wire a, Wire b) { require_allocated_(a); require_allocated_(b); return record_(a, b, circuit::Op::Xor); }
  Wire not_gate(Wire a)         { require_allocated_(a); return record_(a, 0, circuit::Op::Not); }

  // ---- recorder substrate the owning Session drives (not user-facing) ----
  // Allocate n fresh ids for a materialized bundle the Session is about to fill.
  std::vector<uint32_t> reserve_ids(std::size_t n) {
    std::vector<uint32_t> ids(n);
    for (std::size_t i = 0; i < n; ++i) ids[i] = alloc_id_();
    return ids;
  }
  bool is_pending(uint32_t id) const { return pending_.count(id) != 0; }
  const std::vector<circuit::Gate>& chunk_gates() const { return chunk_gates_; }
  void drop_chunk() {
    chunk_gates_.clear();
    pending_.clear();
    const_wire_[0] = const_wire_[1] = -1;
  }

private:
  uint32_t next_id_ = 0;                       // monotonic recorder id (never reset)
  std::vector<circuit::Gate> chunk_gates_;     // current chunk (recorder ids)
  std::unordered_set<uint32_t> pending_;       // ids produced in the current chunk
  int64_t const_wire_[2] = {-1, -1};           // per-chunk Const0/Const1 dedup

  uint32_t alloc_id_() {
    if (next_id_ == UINT32_MAX) error("AG2PCCtx: recorder wire id overflow");
    return next_id_++;
  }
  // A non-pending operand is presumed materialized (a carried id the Session holds);
  // the cheap check here only catches a never-allocated garbage id. Stale-vs-
  // materialized is decided later, at the Session's flush.
  void require_allocated_(Wire a) const {
    if (a >= next_id_) error("AG2PCCtx: operand id was never allocated (corrupt wire)");
  }
  Wire record_(Wire a, Wire b, circuit::Op op) {
    uint32_t o = alloc_id_();
    chunk_gates_.push_back({a, b, o, op});
    pending_.insert(o);
    return o;
  }
};

static_assert(BooleanContext<AG2PCCtx>);

}  // namespace emp
#endif  // EMP_AG2PC_SESSION_CTX_H__
