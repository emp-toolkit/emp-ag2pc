#include "emp-ag2pc/emp-ag2pc.h"
#include <chrono>
#include <thread>
using namespace std;
using namespace emp;

const static int nP = 3;
int party, port;
int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(2 * (nP - 1) + 2);
  TriplePool<nP> mp(&io, &pool, party);

  int num_ands = 280000;
  block *mac[nP + 1];
  block *key[nP + 1];
  for (int i = 1; i <= nP; ++i) {
    key[i] = new block[num_ands * 3];
    mac[i] = new block[num_ands * 3];
  }

  // Warm up.
  mp.compute(mac, key, num_ands);

  // Steady-state: 50 iterations for sampler attach (~3 sec at 280K each).
  auto t1 = clock_start();
  for (int i = 0; i < 50; ++i)
    mp.compute(mac, key, num_ands);
  if (party == 1)
    cout << "Gates(x50): " << num_ands << " time_total: " << time_from(t1) << endl;
  return 0;
}
