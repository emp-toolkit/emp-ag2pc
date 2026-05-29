#ifndef EMP_AG2PC_WIRE_GRAPH_H__
#define EMP_AG2PC_WIRE_GRAPH_H__
#include "emp-tool/core/constants.h"   // GateType { AND_GATE=0, XOR_GATE=1, NOT_GATE=2 }
#include <vector>

namespace emp {

// Purpose-built circuit IR for the ag2pc frontend (and, later, GMW). Unlike a
// BristolFormat, it states inputs / outputs explicitly rather than by position:
//   - inputs occupy wire ids [0, num_in) and are grouped per owner, so a
//     recording frontend batches all owners into one process_inputs call;
//   - outputs are an explicit (wire-id, recipient) list — no "last n3" tail
//     convention and no synthesized routing gates;
//   - public constants are realized as ordinary gates by the producer (e.g. the
//     recorder synthesizes c=0 via XOR(w,w)), so there is nothing special here;
//   - last_use is optional neutral liveness metadata (Stage C): last_use[w] =
//     largest gate index reading w as an input, -1 if never read, INT_MAX-style
//     "pinned" left to the consumer. Each backend overlays its own pin policy
//     (ag2pc pins AND-incident/outputs; GMW pins per level).
//
// A gate's single `op` field encodes both kind and AND index: op >= 0 marks an
// AND gate whose value IS its index into the protocol's per-AND arrays; the two
// negative tags mark the linear (free) gates. One field, so there is no
// kind/index pair that can disagree, and no per-pass AND counter to keep in sync.
struct Gate {
  int in0, in1;     // in1 == in0 (unused) for NOT
  int out;
  int op;           // >= 0: AND gate, op IS its and_index; XOR_TAG / NOT_TAG: linear
  static constexpr int XOR_TAG = -1, NOT_TAG = -2, AND_PENDING = -3;
  bool is_and()    const { return op >= 0; }
  bool is_not()    const { return op == NOT_TAG; }
  int  and_index() const { return op; }   // valid iff is_and()
};

struct WireGraph {
  int num_wire = 0;                 // total wire ids (inputs + gate outputs)
  int num_ands = 0;                 // count of AND gates (== count of is_and())
  std::vector<Gate> gates;          // topological order

  struct InGroup { int owner; int base; int n; };  // wires [base, base+n)
  std::vector<InGroup> inputs;      // grouped per owner; together cover [0,num_in)

  std::vector<int> output_ids;      // wire id of each revealed output
  std::vector<int> output_to;       // recipient party for each output (parallel)

  std::vector<int> last_use;        // Stage C; empty until then

  int num_gate() const { return (int)gates.size(); }
  int num_in() const {
    int n = 0;
    for (const auto& g : inputs) n += g.n;
    return n;
  }
};

}  // namespace emp
#endif  // EMP_AG2PC_WIRE_GRAPH_H__
