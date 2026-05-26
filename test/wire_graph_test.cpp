// Stage A: validate C2PC::compute(WireGraph) on a hand-built tiny graph, with
// no recorder and no Bristol. Exercises: per-owner input bundles laid into
// [0,num_in), gates referencing inputs, a constant-via-XOR(w,w) wire, an
// explicit (non-tail) output id, and decode to a chosen recipient.
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
using namespace std;
using namespace emp;


int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io1, *io2; make_io2pc(party, port, io1, io2);
  ThreadPool pool(4);
  C2PC mpc(io1, io2, &pool, party);
  io1->flush(); io2->flush();

  // Inputs: a from ALICE (party 1) at wire 0, b from BOB (party 2) at wire 1.
  // Each party supplies its own real bit; non-owners pass a dummy (ignored).
  bool a = (party == 1);   // ALICE's input = 1
  bool b = (party == 2);   // BOB's input   = 1
  SecureWires ba = mpc.process_input(&a, 1, /*owner=*/1);
  SecureWires bb = mpc.process_input(&b, 1, /*owner=*/2);

  // Hand-built circuit over wires [0,7):
  //   w2 = XOR(w0,w0) = 0          (constant-0 synthesized as a gate)
  //   w3 = AND(w0,w1) = a & b
  //   w4 = NOT(w0)    = !a
  //   w5 = XOR(w3,w4) = (a&b) ^ (!a)
  //   w6 = XOR(w5,w2) = w5 ^ 0     (uses the constant wire)
  // output: w6 -> party 1.
  WireGraph g;
  g.num_wire = 7;
  g.inputs = {{1, 0, 1}, {2, 1, 1}};            // owner1: wire0; owner2: wire1
  int ai = 0;  // AND gates carry their index in op; linear gates carry a tag.
  auto push = [&](int i0, int i1, int o, int t) {
    int op = (t == AND_GATE)   ? ai++
             : (t == NOT_GATE) ? Gate::NOT_TAG
                               : Gate::XOR_TAG;
    g.gates.push_back({i0, i1, o, op});
  };
  push(0, 0, 2, XOR_GATE);
  push(0, 1, 3, AND_GATE);
  push(0, 0, 4, NOT_GATE);   // NOT: in1 ignored
  push(3, 4, 5, XOR_GATE);
  push(5, 2, 6, XOR_GATE);
  g.num_ands = ai;
  g.output_ids = {6};
  g.output_to = {1};

  SecureWires outw = mpc.compute(g, {ba, bb});
  vector<bool> res = mpc.decode(outw, /*recipient=*/1);

  if (party == 1) {
    bool ref = ((true & true) ^ (!true)) ^ false;   // (a&b)^(!a) ^ 0, with a=b=1
    cout << "WireGraph out = " << res[0] << " (expected " << ref << ")  "
         << (res[0] == ref ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
