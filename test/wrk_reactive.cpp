// Reactive test: mid-circuit reveal-to-all, host branch on the value, a new
// input after the reveal, and an auto-flush (new secret input after a gate with
// no explicit reveal/checkpoint). Same SPMD program runs under WRK and under the
// plaintext clear backend; results must match and be identical across parties.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include "emp-ag2pc/wrk_backend.h"
using namespace std;
using namespace emp;

const static int nP = 2;

// a from party 1, b from party 2, d from party 1. Returns {v, r, ru}.
template <typename Wire>
static void reactive(bool a_in, bool b_in, bool d_in, bool *out3) {
  using B = Bit_T<Wire>;
  B a(a_in, 1), b(b_in, 2);
  B c = a & b;
  bool v = c.template reveal<bool>(PUBLIC);     // reveal to ALL; host branches on it
  B result;
  if (v) {
    B d(d_in, 1);                       // new secret input AFTER a reveal
    result = d ^ a;                     // `a` is still live across the reveal
  } else {
    result = a;
  }
  bool r = result.template reveal<bool>(PUBLIC);

  // Auto-flush: a new secret input mid-computation (after a gate), no reveal.
  B x(a_in, 1);
  B t = x & x;                          // a gate
  B y(b_in, 2);                         // mid-computation input -> auto-flush
  B u = t ^ y;
  bool ru = u.template reveal<bool>(PUBLIC);

  out3[0] = v; out3[1] = r; out3[2] = ru;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > nP) return 0;

  // Each party supplies its own real bit; dummies for inputs it doesn't own.
  bool A = true, Bv = true, D = true;             // logical values
  bool a_in = (party == 1) ? A : false;
  bool b_in = (party == 2) ? Bv : false;
  bool d_in = (party == 1) ? D : false;

  NetIO *io1, *io2; make_io2pc(party, port, io1, io2);
  ThreadPool pool(2 * (nP - 1) + 2);
  setup_wrk_backend<nP>(io1, io2, &pool, party);
  io1->flush(); io2->flush();
  bool got[3];
  reactive<block>(a_in, b_in, d_in, got);   // all parties branch on revealed v
  finalize_wrk_backend();

  // Every party should hold identical revealed values (decode-to-all).
  cout << "P" << party << ": v=" << got[0] << " r=" << got[1]
       << " ru=" << got[2] << endl;

  if (party == 1) {
    setup_clear_backend("");
    bool ref[3];
    reactive<block>(A, Bv, D, ref);           // plaintext oracle, real values
    finalize_clear_backend();
    bool ok = got[0] == ref[0] && got[1] == ref[1] && got[2] == ref[2];
    cout << "wrk_reactive vs plaintext: " << (ok ? "GOOD!" : "BAD!")
         << "  (ref v=" << ref[0] << " r=" << ref[1] << " ru=" << ref[2] << ")"
         << endl;
  }
  return 0;
}
