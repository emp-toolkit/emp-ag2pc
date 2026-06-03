// Protocol-neutral frontend (emp-tool/frontend) over the live AG2PC backend.
// A circuit is a PURE function: inputs are arguments, output is the return
// value. The inputs are fed in direct mode (OUTSIDE the circuit), the circuit
// (add) is compiled once and replayed through the global backend, and the live
// result is revealed OUTSIDE. SPMD: every party feeds its own real input and a
// dummy for the input it does not own.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-ag2pc/ag2pc_circuit_types.h"   // Bit / UInt32 / ... = *_T<AG2PCWire>
#include "emp-tool/frontend/frontend.h"
#include "net_setup.h"
using namespace std;
using namespace emp;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);     // installs global backend = AG2PCBackend
  io->flush();

  const uint32_t xa = 1234567u, yb = 7654321u;
  const uint32_t ref = xa + yb;

  bool ok = false;
  {
    // Inputs fed in direct mode, OUTSIDE the circuit (x owned by P1, y by P2).
    UInt32 x(32, (party == 1) ? xa : 0u, 1);
    UInt32 y(32, (party == 2) ? yb : 0u, 2);

    // The circuit is a pure function: args in, value out (no feed/reveal).
    auto add = [](auto a, auto b) { return a + b; };

    // Compile once (with stats), then replay through the live backend.
    auto   c = frontend::compile<UInt32, UInt32>(add);
    UInt32 z = frontend::run(c, x, y);

    // Reveal OUTSIDE the circuit (one bulk reveal of all 32 bits to party 1).
    AG2PCWire wbuf[32];
    for (int i = 0; i < 32; ++i) wbuf[i] = z[i].bit;
    bool obuf[32] = {false};
    backend->reveal(obuf, 1, wbuf, 32);

    if (party == 1) {
      uint32_t sum = 0;
      for (int i = 0; i < 32; ++i) if (obuf[i]) sum |= (1u << i);
      cout << "test_frontend stats: num_wire=" << c.circuit.count.num_wire
           << " num_and=" << c.circuit.count.num_and
           << " and_depth=" << c.circuit.schedule.levels.depth << endl;
      cout << "test_frontend add32 (revealed outside) = " << sum
           << " (expected " << ref << ")  " << (sum == ref ? "GOOD!" : "BAD!") << endl;
      ok = (sum == ref);
    }
  }  // x, y, z die here, before finalize tears down the backend

  finalize_ag2pc();
  return (party == 1 && !ok) ? 1 : 0;
}
