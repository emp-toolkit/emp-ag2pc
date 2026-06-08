// Non-network unit test of the direct-chunk flush planner (ag2pc_detail::plan_flush):
// DCE, RecordCtx-canonical compaction, and stale-operand detection. Pure graph
// logic — no protocol, no sockets — so the trickiest direct-chunk code is covered
// directly (the two-party tests can only exercise it indirectly, and the stale-id
// guard's error() -> exit(1) can't be death-tested in a live two-party run).
#include "emp-ag2pc/emp-ag2pc.h"
#include <cstdio>
#include <vector>
using namespace emp;
using emp::circuit::Gate;
using emp::circuit::Op;

int main() {
  bool ok = true;

  // 1) Basic compaction: ids 0,1 materialized; gate 2 = AND(0,1) kept.
  {
    std::vector<Gate> chunk = {{0, 1, 2, Op::And}};
    auto p = ag2pc_detail::plan_flush(chunk, {2}, [](uint32_t id) { return id == 0 || id == 1; });
    bool good = p.ok && p.prog.num_inputs == 2 && p.prog.gates.size() == 1 &&
                p.prog.gates[0].out == 2 &&            // canonical: num_inputs + 0
                p.input_ids.size() == 2 && p.output_ids.size() == 1 &&
                p.output_ids[0] == 2 && p.prog.outputs.size() == 1;
    printf("  basic compaction: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  // 2) DCE: ids 0,1,2 materialized; gate 3=AND(0,1) kept, gate 4=AND(0,2) dead.
  //    The dead gate and its private operand (2) are dropped.
  {
    std::vector<Gate> chunk = {{0, 1, 3, Op::And}, {0, 2, 4, Op::And}};
    auto p = ag2pc_detail::plan_flush(chunk, {3}, [](uint32_t id) { return id <= 2; });
    bool good = p.ok && p.prog.gates.size() == 1 && p.output_ids.size() == 1 &&
                p.output_ids[0] == 3 && p.input_ids.size() == 2;   // inputs 0,1 only
    printf("  dead-code elimination: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  // 3) Stale operand: gate references id 9, neither chunk-local nor materialized.
  {
    std::vector<Gate> chunk = {{0, 9, 2, Op::And}};
    auto p = ag2pc_detail::plan_flush(chunk, {2}, [](uint32_t id) { return id == 0; });
    bool good = !p.ok;
    printf("  stale-operand detection: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  // 4) Const-only program: a kept Const1 with no inputs.
  {
    std::vector<Gate> chunk = {{0, 0, 5, Op::Const1}};
    auto p = ag2pc_detail::plan_flush(chunk, {5}, [](uint32_t) { return false; });
    bool good = p.ok && p.prog.num_inputs == 0 && p.prog.gates.size() == 1 &&
                p.prog.outputs.size() == 1 && p.output_ids.size() == 1;
    printf("  const-only program: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  printf("test_flush_plan: %s\n", ok ? "GOOD!" : "BAD!");
  return ok ? 0 : 1;
}
