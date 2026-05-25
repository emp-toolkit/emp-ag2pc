// Stage B: author a WRK circuit in emp-tool's native Bit frontend, run it
// through WRKBackend (record -> WireGraph -> CMPC), no Bristol. SPMD: every
// party runs identical code, passing its own real input and a dummy for
// inputs it does not own.
#include "emp-tool/emp-tool.h"
#include "emp-agmpc/emp-agmpc.h"
#include "emp-agmpc/wrk_backend.h"
using namespace std;
using namespace emp;
EMP_USE_CIRCUIT_TYPES_ALL(block);  // Bit / Integer / ... = *_T<block>

const static int nP = 3;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(2 * (nP - 1) + 2);
  setup_wrk_backend<nP>(&io, &pool, party);
  io.flush();

  // Inputs: a owned by party 1, b owned by party 2 (a=b=1).
  bool ina = (party == 1);
  bool inb = (party == 2);
  Bit A(ina, 1);
  Bit B(inb, 2);
  Bit r = ((A & B) ^ (!A)) ^ Bit(false, PUBLIC);  // (a&b)^(!a) ^ 0
  bool res = r.reveal<bool>(1);                    // reveal to party 1

  finalize_wrk_backend();

  if (party == 1) {
    bool ref = ((true & true) ^ (!true)) ^ false;  // = 1
    cout << "wrk_recording out = " << res << " (expected " << ref << ")  "
         << (res == ref ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
