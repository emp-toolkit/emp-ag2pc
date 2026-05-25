// Stage B round check: many same-owner input Integers must be processed with a
// SINGLE process_input (one input-processing round), not one per Integer. This
// is the regression the deferred + per-owner-batched feed exists to prevent.
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
  auto *b = setup_wrk_backend<nP>(&io, &pool, party);
  io.flush();

  // K+1 input feeds, ALL owned by party 1 and ALL fed before any gate. Eager
  // feed would do K+1 process_inputs; batched-per-owner does exactly 1.
  // (Include an AND so the circuit is non-linear — pure-XOR hits a separate
  // 0-AND edge case.)
  const int K = 32;
  Bit acc(false, PUBLIC);          // public constant before any input (sentinel)
  std::vector<Bit> xs;
  for (int i = 0; i <= K; ++i)
    xs.emplace_back((party == 1) ? ((i & 1) != 0) : false, 1);  // owner 1
  for (int i = 0; i < K; ++i) acc = acc ^ xs[i];
  Bit bit0b = acc & xs[K];         // one AND gate
  bool bit0 = bit0b.reveal<bool>(1);  // single (n=1) terminal reveal

  int calls = b->process_input_calls;
  finalize_wrk_backend();

  if (party == 1) {
    // Expected XOR of low bits of 1..10 = low bit parity; just report.
    cout << "wrk_rounds: K=" << K << " same-owner Integers -> process_input_calls="
         << calls << "  " << (calls == 1 ? "GOOD! (batched)" : "BAD! (per-input)")
         << "  (out bit0=" << bit0 << ")" << endl;
  }
  return 0;
}
