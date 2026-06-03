// Chaining generic-lambda circuits with EMP objects in/out over the live AG2PC
// backend, two ways:
//   LIVE:     frontend::run(body, args...) invokes a wire-generic body against
//             the installed backend and returns its typed result (live Integer).
//   COMPILED: frontend::compile(body, samples...) records the body once (with
//             stats) as a TypedCircuit; frontend::run(circuit, args...) replays
//             it, binding live inputs to External ports and reconstructing the
//             typed Integer result.
// Either way one run's output feeds straight into the next (chaining) and we
// reveal only at the end, outside the run() calls. SPMD.
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
  setup_ag2pc(io, &pool, party);
  io->flush();

  const uint32_t xa = 1000000u, yb = 2345678u;
  const uint32_t ref = 2u * (xa + yb);   // both chains compute 2*(x+y)

  auto reveal32 = [&](UInt32 &v) -> uint32_t {
    AG2PCWire wb[32];
    for (int i = 0; i < 32; ++i) wb[i] = v[i].bit;
    bool ob[32] = {false};
    backend->reveal(ob, 1, wb, 32);
    uint32_t r = 0;
    if (party == 1) for (int i = 0; i < 32; ++i) if (ob[i]) r |= (1u << i);
    return r;
  };

  uint32_t got_live = 0, got_comp = 0;
  size_t comp_ands = 0, comp_depth = 0;
  {
    UInt32 x(32, (party == 1) ? xa : 0u, 1);
    UInt32 y(32, (party == 2) ? yb : 0u, 2);

    auto add = [](auto a, auto b) { return a + b; };
    auto dbl = [](auto a)         { return a + a; };

    // --- LIVE chain: w = dbl(add(x,y)) = 2*(x+y) ---
    UInt32 z = frontend::run(add, x, y);
    UInt32 w = frontend::run(dbl, z);
    got_live = reveal32(w);

    // --- COMPILED typed chain: compile once, replay, chain on the result ---
    auto cadd = frontend::compile(add, x, y);   // TypedCircuit, sample shapes from x,y
    auto cdbl = frontend::compile(dbl, x);      // sample shape only
    comp_ands  = cadd.circuit.count.num_and;
    comp_depth = cadd.circuit.schedule.levels.depth;
    UInt32 z2 = frontend::run(cadd, x, y);      // z2 = x + y
    UInt32 w2 = frontend::run(cdbl, z2);        // w2 = z2 + z2, chains on z2
    got_comp = reveal32(w2);
  }
  finalize_ag2pc();

  bool ok = (got_live == ref && got_comp == ref);
  if (party == 1) {
    cout << "test_frontend_chain  live=" << got_live << "  compiled=" << got_comp
         << " (expected " << ref << ")  " << (ok ? "GOOD!" : "BAD!") << endl;
    cout << "test_frontend_chain  compiled add stats: num_and=" << comp_ands
         << " add_depth=" << comp_depth << endl;
    return ok ? 0 : 1;
  }
  return 0;
}
