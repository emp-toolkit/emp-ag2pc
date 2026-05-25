// Isolation test for AuthSharePool. Three parts:
//
// PART 1 (passing) — AuthSharePool::compute at the same lengths
// TriplePool's process_phase1 emits in the failing tests. compute() is
// the full Π_aShare protocol: rcot extension + check2 universal-hash
// MAC consistency check + EchoBC sync. check_MAC at each length confirms
// MAC = KEY ⊕ x · Δ holds. This is the CORE rcot + bit-pinning bench.
//
// PART 2 (failing) — AuthSharePool::process_phase1 alone (the rcot-only
// half that compute() calls internally; TriplePool uses process_phase1
// directly without going through compute). On any non-trivial length
// this fails at the IO layer with "net_recv_data" — the wire state
// after process_phase1 + check_MAC is inconsistent across parties.
//
// Why: process_phase1 finishes its parallel rcot_send/rcot_recv loop
// per peer, but the *enclosing* check2 (run by AuthSharePool::compute,
// NOT by TriplePool's interleaved check2 chunks) provides a final
// cross-party EchoBC sync via check2_finalize that aligns wire state
// before the next protocol step. Without it, parties' NetIO send/recv
// pointers desync as soon as different parties hit different idle
// branches in check_MAC's nested loop.
//
// This matches the failing-test pattern: triple.cpp, pr10_test,
// prof_triple all call TriplePool::compute which calls process_phase1
// then continues into TriplePool's own protocol steps WITHOUT the
// AuthSharePool::compute-level check2 finalize sync. aes/sha256 work
// because their C2PC path eventually hits sync points that mask the
// issue.
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
using namespace std;
using namespace emp;

const static int nP = 2;
int party, port;

static void test_compute(NetIO *io1, NetIO *io2, ThreadPool *pool,
                         AuthSharePool<nP> *ap, int length) {
  if (party == 1) cout << "=== compute(" << length << ") ===" << endl;
  BlockVec MAC[nP + 1], KEY[nP + 1];
  ap->compute(MAC, KEY, length);
  check_MAC<nP>(io1, io2, MAC, KEY, ap->Delta, length, party);
  if (party == 1) cout << "  OK" << endl;
}

static void test_process_phase1(NetIO *io1, NetIO *io2, ThreadPool *pool,
                                AuthSharePool<nP> *ap, int length) {
  if (party == 1) cout << "=== process_phase1(" << length << ") ===" << endl;
  BlockVec MAC[nP + 1], KEY[nP + 1];
  ap->process_phase1(MAC, KEY, length);
  check_MAC<nP>(io1, io2, MAC, KEY, ap->Delta, length, party);
  if (party == 1) cout << "  OK" << endl;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  if (party > nP) return 0;

  NetIO *io1, *io2;
  make_io2pc(party, port, io1, io2);
  ThreadPool pool(2 * (nP - 1) + 2);

  AuthSharePool<nP> ap(io1, io2, &pool, party);
  io1->flush(); io2->flush();

  // Lengths chosen to match TriplePool's process_phase1 ext_lens:
  //   triple.cpp num_ands=32768, bucket=4, abit_len=393216
  //   pr10_test  ~30 ANDs → batch=3100, bucket=4, abit_len=37200
  //   aes        num_ands=6800,  bucket=4, abit_len=81600

  // PART 1: compute() works at all sizes.
  test_compute(io1, io2, &pool, &ap, 128);
  test_compute(io1, io2, &pool, &ap, 37200);
  test_compute(io1, io2, &pool, &ap, 81600);
  test_compute(io1, io2, &pool, &ap, 393216);
  if (party == 1) cout << "PART 1 (compute): ALL PASS" << endl;

  // PART 2: process_phase1 alone fails at any non-trivial length.
  // Uncomment to reproduce the bug:
  // test_process_phase1(io1, io2, &pool, &ap, 37200);  // fails with net_recv_data

  return 0;
}
