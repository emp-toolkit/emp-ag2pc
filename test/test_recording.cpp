// Author an ag2pc circuit in emp-tool's native Bit frontend, run it
// through AG2PCBackend (record -> WireGraph -> C2PC), no Bristol. SPMD: every
// party runs identical code, passing its own real input and a dummy for
// inputs it does not own.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include "emp-ag2pc/ag2pc_backend.h"
using namespace std;
using namespace emp;
EMP_USE_CIRCUIT_TYPES_ALL(block);  // Bit / Integer / ... = *_T<block>


int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);
  io->flush();

  // Inputs: a owned by party 1, b owned by party 2 (a=b=1).
  bool ina = (party == 1);
  bool inb = (party == 2);
  Bit A(ina, 1);
  Bit B(inb, 2);
  Bit r = ((A & B) ^ (!A)) ^ Bit(false, PUBLIC);  // (a&b)^(!a) ^ 0
  bool res = r.reveal<bool>(1);                    // reveal to party 1

  finalize_ag2pc();

  if (party == 1) {
    bool ref = ((true & true) ^ (!true)) ^ false;  // = 1
    cout << "test_recording out = " << res << " (expected " << ref << ")  "
         << (res == ref ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
