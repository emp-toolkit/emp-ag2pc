// Direct call to TriplePool::compute. Reproduces a deterministic protocol
// failure ("LaAND alpha: Sigma alpha != 0") even though:
//   - AuthSharePool::compute on the same lengths passes (see auth_share test).
//   - Calling TriplePool::compute via CMPC->function_independent
//     ->preprocess->refill_internal->compute(BlockVec, BlockVec, length,
//     pool_triples.data()) — same code path, same arguments — passes
//     (see aes / sha256 / chain tests).
//
// Difference between this failing test and the passing CMPC tests:
//   - CMPC tests: TriplePool::compute called from
//     refill_internal(batch) inside TriplePool::preprocess(num).
//   - This test: TriplePool::compute called directly from main.
//
// Both paths end at the same compute() body with the same (length, out_aos)
// args. Yet only the direct call corrupts the leaky-triple c-bit (~50%
// wrong → Sigma alpha != 0). Root cause not yet identified.
#include "emp-agmpc/emp-agmpc.h"
using namespace std;
using namespace emp;

const static int nP = 3;
int party, port;
int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  if (party > nP)
    return 0;
  NetIOMP<nP> io(party, port);

  ThreadPool pool(2 * (nP - 1) + 2);
  TriplePool<nP> mp(&io, &pool, party);

  int num_ands = 1 << 15;
  block *mac[nP + 1];
  block *key[nP + 1];

  for (int i = 1; i <= nP; ++i) {
    key[i] = new block[num_ands * 3];
    mac[i] = new block[num_ands * 3];
  }
  auto t1 = clock_start();
  mp.compute(mac, key, num_ands);
  cout << "Gates: " << num_ands << " time: " << time_from(t1) << endl;
  return 0;
}
