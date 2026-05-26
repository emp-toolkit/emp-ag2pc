#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include <chrono>
#include <thread>
using namespace std;
using namespace emp;

int party, port;
int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io1, *io2; make_io2pc(party, port, io1, io2);
  ThreadPool pool(4);
  TriplePool mp(io1, io2, &pool, party);

  int num_ands = 280000;
  block *mac = new block[num_ands * 3];
  block *key = new block[num_ands * 3];

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
