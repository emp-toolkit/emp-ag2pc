#ifndef EMP_AG2PC_CANONICAL_H__
#define EMP_AG2PC_CANONICAL_H__

// Precondition check on a stored BooleanProgram before any pass runs: it must be
// RecordContext-canonical (gate.out == num_inputs + i; at most one Const0/Const1),
// which is what makes the slot layout match the record-order numbering. This
// validates IR shape, so it lives here rather than in a pass context.

#include "emp-tool/ir/program.h"     // BooleanProgram, Op
#include "emp-tool/ir/validate.h"   // validate_program

namespace emp {

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


}  // namespace emp
#endif  // EMP_AG2PC_CANONICAL_H__
