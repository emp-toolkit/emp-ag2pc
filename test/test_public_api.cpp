// Public AG2PC direct API — SH2PC-style smoke test. This file is the direct-mode
// self-sufficiency proof: it includes ONLY <emp-ag2pc/direct.h> (plus the test
// transport) and writes ordinary EMP circuit code — `setup_ag2pc`, EMP
// objects (UInt32 / Bit, the public AG2PCWire aliases), normal operators,
// `.reveal<T>()`, `finalize_ag2pc`. No AG2PCSession / AG2PCEngine / SecureWires /
// process_inputs / decode anywhere — those are internals, not user surface.
//
// One session, several operations and reveals (the recorder carries state across
// reveals). SPMD: each party supplies its own real input and a dummy for the
// input it does not own. Party 1 = ALICE, party 2 = BOB.
#include "emp-ag2pc/direct.h"
#include "net_setup.h"
#include <cstdio>
using namespace std;
using namespace emp;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);

  const uint32_t X = 1234567u, Y = 7654321u;
  bool ok = true;

  // ---- add: a (ALICE) + b (BOB), revealed to everyone ----
  UInt32 a(party == ALICE ? X : 0, ALICE);
  UInt32 b(party == BOB   ? Y : 0, BOB);
  UInt32 sum = a + b;
  uint32_t got_sum = sum.reveal<uint32_t>(PUBLIC);

  // ---- public constant + multiply: (a + b) * 3 + 1 ----
  UInt32 expr = sum * UInt32(3, PUBLIC) + UInt32(1, PUBLIC);
  uint32_t got_expr = expr.reveal<uint32_t>(PUBLIC);

  // ---- a Bit comparison, revealed only to ALICE ----
  Bit a_lt_b = a < b;
  bool got_lt = a_lt_b.reveal<bool>(ALICE);

  finalize_ag2pc();

  if (party == ALICE) {
    uint32_t ref_sum = X + Y, ref_expr = (X + Y) * 3u + 1u;
    bool ref_lt = X < Y;
    ok = (got_sum == ref_sum) && (got_expr == ref_expr) && (got_lt == ref_lt);
    printf("public_api: a+b=%u (exp %u), (a+b)*3+1=%u (exp %u), a<b=%d (exp %d)  %s\n",
           got_sum, ref_sum, got_expr, ref_expr, got_lt, ref_lt,
           ok ? "GOOD!" : "BAD!");
  }
  return (party == ALICE && !ok) ? 1 : 0;
}
