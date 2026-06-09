// Transcript equivalence: a circuit run as a LIVE body (sess.run) must produce
// the BYTE-IDENTICAL protocol transcript as the SAME circuit compiled to a
// BooleanProgram and run (sess.run). Both drive the same passes over the same gate
// stream, so this is guaranteed by design — and is the regression gate for the pass
// framework. Determinism comes from set_test_mode (single seed stream); the io
// digest is the transcript fingerprint.
//
// The const edge cases (repeated constant, constant as output, constant used both
// before and after an AND) are exactly where const-dedup / wire-id alignment bugs
// would surface as a body-vs-compiled mismatch.
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-tool/core/test_mode.h"
#include "net_setup.h"
#include <cstdio>
using namespace std;
using namespace emp;
namespace cf = emp::frontend;
using UInt32 = AG2PCSession::UInt<32>;

struct Result { block digest; uint32_t out; bool have; };

// Fingerprint BOTH channels: AG2PC uses io and sib (the MITCCRH seed absorbs both),
// so a divergence on the sibling channel must not slip through. Captured after the
// circuit (before reveal) so it fingerprints input + garbling.
static block fingerprint(AG2PCSession &sess) {
  return RO("ag2pc-equiv", zero_block)
      .absorb(sess.protocol().io->get_digest())
      .absorb(sess.protocol().sib->get_digest())
      .squeeze_block();
}

// Run a 2-arg UInt32 body as a LIVE body (run_body).
template <class Body>
static Result run_body(int party, int port, Body body, uint32_t av, uint32_t bv) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);
  io->flush();
  auto a = sess.input<UInt32>(ALICE, party == ALICE ? av : 0);
  auto b = sess.input<UInt32>(BOB,   party == BOB   ? bv : 0);
  auto z = sess.run(body, a, b);
  block d = fingerprint(sess);
  auto r = sess.reveal(z, ALICE);
  return Result{d, (uint32_t)(r.value_or(0u) & 0xffffffffu), r.has_value()};
}

// Run the SAME body compiled to a BooleanProgram (run).
template <class Body>
static Result run_comp(int party, int port, Body body, uint32_t av, uint32_t bv) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);
  io->flush();
  auto c = cf::compile<rec::UInt<32>, rec::UInt<32>>(body);
  auto a = sess.input<UInt32>(ALICE, party == ALICE ? av : 0);
  auto b = sess.input<UInt32>(BOB,   party == BOB   ? bv : 0);
  auto z = sess.run(c, a, b);
  block d = fingerprint(sess);
  auto r = sess.reveal(z, ALICE);
  return Result{d, (uint32_t)(r.value_or(0u) & 0xffffffffu), r.has_value()};
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;
  set_test_mode(true);   // deterministic randomness (single-threaded seed stream)

  const uint32_t A = 1234567u, B = 7654321u;
  bool ok = true;
  auto eqd = [](block a, block b) { return cmpBlock(&a, &b, 1); };

  // A plain adder and three const-stressing bodies.
  auto plain  = [](auto a, auto b) { return a + b; };
  auto rep_k  = [](auto a, auto b) { auto k = a.constant(5); return a + k + b + k; };   // const reused
  auto out_k  = [](auto a, auto b) { (void)a; return b.constant(0xABCDu); };            // const is the output
  auto around = [](auto a, auto b) { auto k = a.constant(1); auto p = a * b; return p + k; }; // const before+after AND

  int slot = 0;   // advanced identically on both parties

  auto check = [&](const char *name, auto body) {
    Result body_a = run_body(party, port + slot++, body, A, B);
    Result body_b = run_body(party, port + slot++, body, A, B);   // determinism
    Result comp   = run_comp(party, port + slot++, body, A, B);
    if (party == ALICE) {
      bool det  = eqd(body_a.digest, body_b.digest);
      bool byte = eqd(body_a.digest, comp.digest);
      bool sem  = body_a.have && comp.have && body_a.out == comp.out;
      bool good = det && byte && sem;
      printf("equiv[%-10s] det=%d  BYTE body==compiled=%d  semantic=%d  %s\n",
             name, (int)det, (int)byte, (int)sem, good ? "GOOD!" : "BAD!");
      ok &= good;
    }
  };

  check("add",       plain);
  check("rep_const", rep_k);
  check("const_out", out_k);
  check("around_and", around);

  if (party == ALICE)
    printf("test_body_replay_equiv: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == ALICE && !ok) ? 1 : 0;
}
