// Compiled frontend circuit on AG2PC: write a pure emp-tool frontend function,
// frontend::compile() it once, then run it through LambdaRunner::run_compiled —
// which replays the recorded BooleanProgram per phase via frontend::run(tc, args)
// over the shared streaming engine (no WireGraph / lowering). The compiled
// circuit is the canonical frontend::Circuit; "compiled" = recorded once, run
// many. Includes a public-constant case (inc32), which exercises the CONST-gate
// dedup that compile() performs.
//
// Inputs/outputs stay OUTSIDE the circuit: the caller process_inputs() each
// argument (with its owner) into a SecureWires bundle, passes the bundles in
// argument order, and decode()s the output. SPMD: every party supplies its own
// real bits and a dummy for inputs it does not own (dummies are ignored).
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-ag2pc/lambda_runner.h"
#include "emp-tool/frontend/frontend.h"
EMP_USE_CIRCUIT_TYPES_ALL(block)
#include "net_setup.h"
#include <cstdio>
using namespace std;
using namespace emp;

static std::vector<bool> bits_of(uint32_t v, int n = 32) {
  std::vector<bool> b(n);
  for (int i = 0; i < n; ++i) b[i] = (v >> i) & 1u;
  return b;
}
static uint32_t u32_of(const std::vector<bool> &b) {
  uint32_t v = 0;
  for (size_t i = 0; i < b.size() && i < 32; ++i) if (b[i]) v |= (1u << i);
  return v;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();
  LambdaRunner runner(&mpc);

  // Pure circuit bodies, compiled once (RecordBackend; party-independent).
  auto add = [](auto a, auto b) { return a + b; };
  auto inc = [](auto a) { return a + decltype(a)(32, 1, PUBLIC); };  // public const
  auto c_add = frontend::compile<UInt32, UInt32>(add);
  auto c_inc = frontend::compile<UInt32>(inc);

  bool all_ok = true;

  // ---- Test 1: 32-bit add. x owned by P1, y by P2, decode to P1. ----
  {
    const uint32_t xa = 1234567u, yb = 7654321u;
    auto in = mpc.process_inputs(/*owners=*/{1, 2},
                                 {bits_of(party == 1 ? xa : 0u),
                                  bits_of(party == 2 ? yb : 0u)});
    SecureWires outw = runner.run_compiled<UInt32, UInt32>(c_add, {in[0], in[1]});
    std::vector<bool> res = mpc.decode(outw, /*recipient=*/1);
    if (party == 1) {
      uint32_t got = u32_of(res), ref = xa + yb;
      printf("compiled add32: stats num_wire=%d num_and=%lld depth=%d\n",
             c_add.circuit.count.num_wire, (long long)c_add.circuit.count.num_and,
             c_add.circuit.schedule.levels.depth);
      printf("compiled add32 = %u (expected %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      all_ok &= (got == ref);
    }
  }

  // ---- Test 2: single input + public constant (exercises CONST dedup). ----
  {
    const uint32_t xa = 4242u;
    auto in = mpc.process_inputs(/*owners=*/{1}, {bits_of(party == 1 ? xa : 0u)});
    SecureWires outw = runner.run_compiled<UInt32>(c_inc, {in[0]});
    std::vector<bool> res = mpc.decode(outw, /*recipient=*/1);
    if (party == 1) {
      uint32_t got = u32_of(res), ref = xa + 1u;
      printf("compiled inc32 (const) = %u (expected %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      all_ok &= (got == ref);
    }
  }

  return (party == 1 && !all_ok) ? 1 : 0;
}
