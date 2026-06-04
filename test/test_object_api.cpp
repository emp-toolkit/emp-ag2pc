// Object-mode smoke test using only <emp-ag2pc/emp-ag2pc.h>.
#include "emp-ag2pc/emp-ag2pc.h"
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

  // ALICE-owned and BOB-owned inputs.
  UInt32 a(party == ALICE ? X : 0, ALICE);
  UInt32 b(party == BOB   ? Y : 0, BOB);
  UInt32 sum = a + b;
  uint32_t got_sum = sum.reveal<uint32_t>(PUBLIC);

  UInt32 expr = sum * UInt32(3, PUBLIC) + UInt32(1, PUBLIC);
  uint32_t got_expr = expr.reveal<uint32_t>(PUBLIC);

  Bit a_lt_b = a < b;
  bool got_lt = a_lt_b.reveal<bool>(ALICE);

  finalize_ag2pc();

  if (party == ALICE) {
    uint32_t ref_sum = X + Y, ref_expr = (X + Y) * 3u + 1u;
    bool ref_lt = X < Y;
    ok = (got_sum == ref_sum) && (got_expr == ref_expr) && (got_lt == ref_lt);
    printf("object_api: a+b=%u (exp %u), (a+b)*3+1=%u (exp %u), a<b=%d (exp %d)  %s\n",
           got_sum, ref_sum, got_expr, ref_expr, got_lt, ref_lt,
           ok ? "GOOD!" : "BAD!");
  }
  return (party == ALICE && !ok) ? 1 : 0;
}
