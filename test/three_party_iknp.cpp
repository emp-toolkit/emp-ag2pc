// Minimal reproducer: 3-party concurrent pairwise IKNP.
//
// Strips out everything from auth_share_pool except the IKNP setup +
// bulk-rcot loop. Each party constructs 2*(nP-1) IKNP instances (one
// sender + one receiver against each peer). Under the post-refactor
// emp-ot/IKNP, setup is lazy: the base-OT exchange now happens inside
// the first rcot_send / rcot_recv call (setup_done flips on first
// use), so what we exercise here is the per-pair base-OT-then-extend
// pipeline running concurrently across all (party, peer) pairs. If
// this fires "OT Extension check failed" or hangs, the bug is in
// upstream emp-ot/IKNP itself, not in any emp-agmpc protocol code.
//
// Knobs:
//   nP   — number of parties (default 3, the regression boundary)
//   LEN  — random COTs per pair (default 1<<14 = 16K, big enough to
//          exercise the malicious-check chi-fold over many chunks)

#include "emp-agmpc/emp-agmpc.h"
#include <future>
#include <memory>
using namespace std;
using namespace emp;

const int nP = 3;
const int LEN = 1 << 14;

int main(int argc, char **argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(2 * (nP - 1) + 2);

  // New IKNP has no default ctor — store unique_ptrs and construct
  // per-peer once the IO channel is known.
  std::unique_ptr<IKNP> abit1[nP + 1];
  std::unique_ptr<IKNP> abit2[nP + 1];

  bool delta[128];
  PRG prg;
  prg.random_bool(delta, 128);
  delta[0] = true;  // bit-0(Δ)=1 invariant

  // Wire IO + role at construction. Mirrors auth_share_pool.h.
  for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
    bool me_smaller = party < peer;
    abit1[peer] = std::make_unique<IKNP>(
        ALICE, io.get(peer, me_smaller ? false : true));
    abit2[peer] = std::make_unique<IKNP>(
        BOB, io.get(peer, me_smaller ? true : false));
  }

  // Install Δ_me on every sender. The base-OT round-trip is now
  // deferred to the first rcot_send/recv below — no explicit
  // setup_send/setup_recv parallel loop.
  for (int peer = 1; peer <= nP; ++peer) if (peer != party)
    abit1[peer]->set_delta(delta);
  cout << "P" << party << " set_delta done\n" << flush;

  // Shared choice seed across all abit2[peer] receivers
  block choice_seed;
  prg.random_block(&choice_seed, 1);
  for (int peer = 1; peer <= nP; ++peer) if (peer != party)
    abit2[peer]->choice_prg.reseed(&choice_seed);

  // Bulk RCOT phase: parallel across peers. First call on each
  // instance triggers the lazy base-OT bootstrap; subsequent
  // chunks within the same rcot_send call stream the extension.
  BlockVec K[nP + 1], M[nP + 1];
  for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
    K[peer].resize(LEN);
    M[peer].resize(LEN);
  }

  {
    vector<future<void>> res;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
      res.push_back(pool.enqueue([&, peer]() {
        bool me_smaller = party < peer;
        cout << "P" << party << " rcot_send -> " << peer << " begin\n" << flush;
        abit1[peer]->rcot(K[peer].data(), LEN);
        io.get(peer, me_smaller ? false : true)->flush();
        cout << "P" << party << " rcot_send -> " << peer << " end\n" << flush;
      }));
      res.push_back(pool.enqueue([&, peer]() {
        bool me_smaller = party < peer;
        cout << "P" << party << " rcot_recv <- " << peer << " begin\n" << flush;
        abit2[peer]->rcot(M[peer].data(), LEN);
        io.get(peer, me_smaller ? true : false)->flush();
        cout << "P" << party << " rcot_recv <- " << peer << " end\n" << flush;
      }));
    }
    for (auto &f : res) f.get();
  }
  cout << "P" << party << " rcot phase done — OK\n" << flush;
  return 0;
}
