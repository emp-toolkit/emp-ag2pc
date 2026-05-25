// Stage 1 of the cut-and-choose leaky-AND (FKOS-lean): verify the OT
// multiplication produces correct UNAUTHENTICATED product shares
// ⊕_p z^p = (⊕_p a^p) ∧ (⊕_p b^p), checked by opening a,b,z to party 1.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
using namespace std;
using namespace emp;

const static int nP = 2;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > nP) return 0;

  NetIO *io1, *io2; make_io2pc(party, port, io1, io2);
  ThreadPool pool(2 * (nP - 1) + 2);
  TriplePool<nP> tp(io1, io2, &pool, party);
  io1->flush(); io2->flush();

  tp.cutchoose_mult_selftest(1024);
  tp.cutchoose_triple_selftest(1024);
  tp.cutchoose_sacrifice_selftest(256, 4, /*tamper=*/-1);  // honest: ALL PASS
  tp.cutchoose_sacrifice_selftest(256, 4, /*tamper=*/7);   // cheat: DETECTED
  return 0;
}
