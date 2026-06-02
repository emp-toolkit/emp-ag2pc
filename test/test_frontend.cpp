// Protocol-neutral frontend (emp-tool/frontend) over the live AG2PC backend.
// setup_ag2pc installs the global backend; the frontend records ordinary Bit
// code into a BooleanProgram and replays it THROUGH that backend pointer — it
// never touches C2PC directly. Replayed outputs are live AG2PCWire wires, so we
// reveal them OUTSIDE the run() call with ordinary Bit reveal. SPMD: every
// party runs identical code, passing its own real input and a dummy otherwise.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-ag2pc/ag2pc_circuit_types.h"   // Bit / Integer / ... = *_T<AG2PCWire>
#include "emp-tool/frontend/frontend.h"       // Bit_rec / UInt32_rec = *_T<RecWire> + Runner
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

  frontend::Runner<AG2PCWire> fe;

  // Body in RecWire types. Produces a live 32-bit output via keep() — it does
  // NOT reveal inside. a = x owned by P1, b = y owned by P2.
  const uint32_t xa = 1234567u, yb = 7654321u;
  auto body = [party, xa, yb] {
    using U = UInt32_rec;
    U x(32, (party == 1) ? xa : 0u, 1);
    U y(32, (party == 2) ? yb : 0u, 2);
    U z = x + y;
    frontend::keep(z);     // hand z back live; reveal outside
  };

  // Compile once (with stats), then replay through the live backend.
  frontend::Circuit c = frontend::compile(body);
  bool ok_sum = false;
  {
    std::vector<Bit> outs = fe.run(c);   // Bit = Bit_T<AG2PCWire>, live wires

    // Reveal OUTSIDE the run() call. Bulk-reveal all 32 bits in one backend
    // reveal (one protocol round) to party 1.
    AG2PCWire wbuf[32];
    for (int i = 0; i < 32; ++i) wbuf[i] = outs[i].bit;
    bool obuf[32];
    backend->reveal(obuf, 1, wbuf, 32);

    if (party == 1) {
      uint32_t sum = 0;
      for (int i = 0; i < 32; ++i) if (obuf[i]) sum |= (1u << i);
      uint32_t ref = xa + yb;
      cout << "test_frontend stats: num_wire=" << c.count.num_wire
           << " num_and=" << c.count.num_and
           << " num_xor=" << c.count.num_xor
           << " and_depth=" << c.schedule.levels.depth << endl;
      cout << "test_frontend add32 (revealed outside run) = " << sum
           << " (expected " << ref << ")  "
           << (sum == ref ? "GOOD!" : "BAD!") << endl;
      ok_sum = (sum == ref);
    }
  }  // outs dies here, before finalize tears down the backend

  finalize_ag2pc();
  (void)ok_sum;
  return 0;
}
