// Compiled / stored-program replay through the AG2PC passes:
//   1) a compiled UInt32 adder via ctx.run(circuit, ...);
//   2) a hand-authored RecordCtx a+b BooleanProgram via ctx.run_program<UInt32>;
//   3) a compiled fp32 adder (exercises the float .empbc builtin) via ctx.run.
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include <cstdint>
#include <cstdio>
#include <span>
using namespace std;
using namespace emp;
namespace cf = emp::frontend;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCCtx ctx(io, &pool, party);
  io->flush();

  using UInt32 = UInt_T<AG2PCCtx, 32>;
  using Float32 = Float_T<AG2PCCtx, 32>;
  bool ok = true;

  // 1) compiled UInt32 adder, replayed standalone.
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb;
    auto c = cf::compile<rec::UInt<32>, rec::UInt<32>>([](auto x, auto y) { return x + y; });
    auto a = ctx.input<UInt32>(ALICE, party == ALICE ? xa : 0);
    auto b = ctx.input<UInt32>(BOB,   party == BOB   ? yb : 0);
    uint32_t got = (uint32_t)ctx.reveal(ctx.run(c, a, b), PUBLIC).value_or(0);
    if (party == ALICE) {
      ok &= (got == ref);
      printf("  compiled run UInt32 a+b = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
    }
  }

  // 2) hand-authored RecordCtx a+b program, run via the typed raw-program path.
  {
    RecordCtx rc;
    uint32_t base = rc.external_input(64);
    uint32_t aw[32], bw[32];
    for (int i = 0; i < 32; ++i) { aw[i] = base + i; bw[i] = base + 32 + i; }
    auto rs = UInt_T<RecordCtx, 32>::from_wires(rc, aw) +
              UInt_T<RecordCtx, 32>::from_wires(rc, bw);
    uint32_t outw[32]; rs.pack_wires(outw);
    circuit::BooleanProgram prog = rc.finish(std::span<const uint32_t>(outw, 32));

    const uint32_t xa = 1000u, yb = 2000u, ref = xa + yb;
    auto a = ctx.input<UInt32>(ALICE, party == ALICE ? xa : 0);
    auto b = ctx.input<UInt32>(BOB,   party == BOB   ? yb : 0);
    uint32_t got = (uint32_t)ctx.reveal(ctx.run_program<UInt32>(prog, a, b), PUBLIC).value_or(0);
    if (party == ALICE) {
      ok &= (got == ref);
      printf("  run_program hand-authored a+b = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
    }
  }

  // 3) compiled fp32 adder (float builtin): 1.5 + 2.25 = 3.75.
  {
    auto cfp = cf::compile<rec::Float<32>, rec::Float<32>>([](auto a, auto b) { return a + b; });
    auto a = ctx.input<Float32>(ALICE, party == ALICE ? 1.5f : 0.0f);
    auto b = ctx.input<Float32>(BOB,   party == BOB   ? 2.25f : 0.0f);
    float got = ctx.reveal(ctx.run(cfp, a, b), PUBLIC).value_or(0.0f);
    if (party == ALICE) {
      ok &= (got == 3.75f);
      printf("  compiled run Float32 1.5+2.25 = %g (exp 3.75)  %s\n", got,
             got == 3.75f ? "GOOD!" : "BAD!");
    }
  }

  if (party == ALICE)
    printf("test_program_replay: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == ALICE && !ok) ? 1 : 0;
}
