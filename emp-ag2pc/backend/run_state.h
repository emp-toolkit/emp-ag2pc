#ifndef EMP_AG2PC_RUN_STATE_H__
#define EMP_AG2PC_RUN_STATE_H__

// Per-run scratch for one AG2PC execution: AG2PCRunState (slot map + liveness +
// wire shares + garbler/evaluator labels + the c_gamma check state) and
// AG2PCStreamChunk (per-chunk garble/evaluate staging). One fresh AG2PCRunState
// is constructed per run inside the engine; cross-call durable state lives in
// AG2PCSession::carried_, not here.

#include "emp-tool/runtime/runtime.h"                  // block, MITCCRH
#include "emp-ag2pc/backend/secure_wires.h"     // AShareBundle / AShareBundleVec
#include <cstdint>
#include <vector>

namespace emp {

// ===========================================================================
// Shared per-run state. Logical wire ids map to physical slots; XOR/NOT scratch
// wires can reuse slots after their last read. Indexed by logical wire id.
// ===========================================================================
struct AG2PCRunState {
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
struct AG2PCStreamChunk {
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

}  // namespace emp
#endif  // EMP_AG2PC_RUN_STATE_H__
