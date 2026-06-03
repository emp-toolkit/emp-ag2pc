// Frontend API surface on AG2PC — small, fast circuits exercising every way a
// caller hands a circuit to the one protocol executor (LambdaRunner /
// run_engine_). All run on a single C2PC connection, sequentially:
//
//   * run<Ins...>            — a pure wire-generic body replayed live per phase
//   * run_compiled<Ins...>   — the same body frontend::compile'd once, replayed
//   * chaining               — one run's SecureWires output feeds the next run
//   * C++20 template lambda   — explicit shape UInt32_T<W>, wire W deduced
//   * public constants        — a compiled circuit with a PUBLIC constant (the
//                               CONST-gate dedup compile() performs)
//   * run_program            — a raw frontend::BooleanProgram replayed directly
//
// Inputs/outputs stay OUTSIDE the circuit: the caller process_inputs() each
// argument (with its owner) into a SecureWires bundle and decode()s the result.
// SPMD: every party supplies its own real bits and a dummy for inputs it does
// not own. Compiled as C++20 (add_test_case_with_run_cxx20) for the template
// lambda; the rest of the project stays C++17.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"     // exposes LambdaRunner
#include "emp-tool/frontend/frontend.h"
EMP_USE_CIRCUIT_TYPES_ALL(block)
#include "test_common.h"
#include <cstdio>
using namespace std;
using namespace emp;
using namespace ag2pc_test;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();
  LambdaRunner runner(&mpc);

  bool ok = true;
  auto add = [](auto a, auto b) { return a + b; };

  // ---- add32 — live body vs the same body compiled. x owned by P1, y by P2. --
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb;
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires outL = runner.run<UInt32, UInt32>({in[0], in[1]}, add);
    auto c = frontend::compile<UInt32, UInt32>(add);
    SecureWires outC = runner.run_compiled<UInt32, UInt32>(c, {in[0], in[1]});
    uint32_t gl = u32_of(mpc.decode(outL, 1)), gc = u32_of(mpc.decode(outC, 1));
    if (party == 1) {
      printf("add32: live=%u compiled=%u (expected %u)  %s\n", gl, gc, ref,
             (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // ---- chaining — w = 2*(x+y): one run's output bundle is the next run's input,
  //      done both live (run -> run) and over two compiled circuits. ----------
  {
    const uint32_t xa = 3333333u, yb = 12345u, ref = 2u * (xa + yb);
    auto dbl = [](auto v) { return v + v; };
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires z = runner.run<UInt32, UInt32>({in[0], in[1]}, add);
    SecureWires w = runner.run<UInt32>({z}, dbl);
    auto c_add = frontend::compile<UInt32, UInt32>(add);
    auto c_dbl = frontend::compile<UInt32>(dbl);
    SecureWires z2 = runner.run_compiled<UInt32, UInt32>(c_add, {in[0], in[1]});
    SecureWires w2 = runner.run_compiled<UInt32>(c_dbl, {z2});
    uint32_t gl = u32_of(mpc.decode(w, 1)), gc = u32_of(mpc.decode(w2, 1));
    if (party == 1) {
      printf("chain 2*(x+y): live=%u compiled=%u (expected %u)  %s\n", gl, gc, ref,
             (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // ---- C++20 template lambda body (explicit UInt32_T<W>, W deduced) — live +
  //      compiled. ------------------------------------------------------------
  {
    const uint32_t xa = 111111u, yb = 222222u, ref = xa + yb;
    auto add_tl = []<class W>(UInt32_T<W> a, UInt32_T<W> b) { return a + b; };
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires outL = runner.run<UInt32, UInt32>({in[0], in[1]}, add_tl);
    auto c = frontend::compile<UInt32, UInt32>(add_tl);
    SecureWires outC = runner.run_compiled<UInt32, UInt32>(c, {in[0], in[1]});
    uint32_t gl = u32_of(mpc.decode(outL, 1)), gc = u32_of(mpc.decode(outC, 1));
    if (party == 1) {
      printf("typed lambda add32: live=%u compiled=%u (expected %u)  %s\n", gl, gc,
             ref, (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // ---- public constant — compiled inc32 (x + 1). compile() dedupes CONST0/
  //      CONST1; the engine realizes them as CONST gates. ---------------------
  {
    const uint32_t xa = 4242u, ref = xa + 1u;
    auto inc = [](auto a) { return a + decltype(a)(32, 1, PUBLIC); };
    auto c_inc = frontend::compile<UInt32>(inc);
    auto in = mpc.process_inputs({1}, {bits_of(party == 1 ? xa : 0u)});
    SecureWires outw = runner.run_compiled<UInt32>(c_inc, {in[0]});
    uint32_t got = u32_of(mpc.decode(outw, 1));
    if (party == 1) {
      printf("compiled inc32 (public const) = %u (expected %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      ok &= (got == ref);
    }
  }

  // ---- raw BooleanProgram — compile (x + y + 1) to a frontend::BooleanProgram,
  //      then replay it directly via run_program (no typed args). This is the
  //      lower-level entry the direct recorder uses for its per-chunk circuits. -
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb + 1u;
    auto body = [](auto a, auto b) { return a + b + decltype(a)(32, 1, PUBLIC); };
    auto c = frontend::compile<UInt32, UInt32>(body);
    const auto &prog = c.circuit.prog;        // inputs [0,64), output = sum bits
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires inputs = concat(in, party);   // 64 wires bound to prog ids [0,64)
    SecureWires ow = runner.run_program(prog, inputs, prog.outputs);
    uint32_t got = u32_of(mpc.decode(ow, 1));
    if (party == 1) {
      printf("run_program (x+y+1) = %u (expected %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      ok &= (got == ref);
    }
  }

  return (party == 1 && !ok) ? 1 : 0;
}
