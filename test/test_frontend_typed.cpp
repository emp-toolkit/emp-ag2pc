// Frontend body written as a C++20 template lambda: explicit shape (UInt32_T<W>)
// with the wire W deduced, instead of a generic `auto` lambda or a templated
// functor. Compiled as C++20 via add_test_case_with_run_cxx20 in CMake; the rest
// of the project stays C++17. Runs the body live and compiled, chaining the
// typed Integer result and revealing outside the run() calls. SPMD.
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

  const uint32_t xa = 111111u, yb = 222222u;
  const uint32_t ref = xa + yb;

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
  {
    UInt32 x(32, (party == 1) ? xa : 0u, 1);
    UInt32 y(32, (party == 2) ? yb : 0u, 2);

    // C++20 template lambda: shape is explicit (UInt32_T<W>), wire W deduced.
    auto add = []<class W>(UInt32_T<W> a, UInt32_T<W> b) { return a + b; };

    UInt32 z  = frontend::run(add, x, y);          // live, typed
    got_live  = reveal32(z);

    auto   c  = frontend::compile(add, x, y);       // compile once (+ stats)
    UInt32 z2 = frontend::run(c, x, y);             // replay, typed
    got_comp  = reveal32(z2);
  }
  finalize_ag2pc();

  bool ok = (got_live == ref && got_comp == ref);
  if (party == 1) {
    cout << "test_frontend_typed  live=" << got_live << "  compiled=" << got_comp
         << " (expected " << ref << ")  " << (ok ? "GOOD!" : "BAD!") << endl;
    return ok ? 0 : 1;
  }
  return 0;
}
