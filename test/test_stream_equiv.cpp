// Transcript equivalence for stream sources under deterministic test mode.
// Compiled replay is checked semantically because constant deduplication can
// change the gate stream.
#include "emp-ag2pc/stream.h"
#include "emp-tool/frontend/frontend.h"
#include "net_setup.h"
#include <cstdio>
using namespace std;
using namespace emp;

// Wire-generic AES-128 body.
struct AesFn {
  template <class W>
  BitVec_T<W> operator()(BitVec_T<W> key, BitVec_T<W> pt) const {
    Bit_T<W> k[128], p[128], expanded[1408], ct[128];
    for (int i = 0; i < 128; ++i) k[i] = key[i];
    for (int i = 0; i < 128; ++i) p[i] = pt[i];
    AES_Calculator_T<W> aes;
    aes.key_schedule(k, expanded);
    aes.encrypt(p, expanded, ct);
    BitVec_T<W> o(128);
    for (int i = 0; i < 128; ++i) o[i] = ct[i];
    return o;
  }
};

static void make_bpo(int party, const bool kb[128], const bool pb[128],
                     std::vector<std::vector<bool>> &bpo) {
  bpo.assign(2, std::vector<bool>(128, false));
  if (party == 1) for (int i = 0; i < 128; ++i) bpo[0][i] = kb[i];
  if (party == 2) for (int i = 0; i < 128; ++i) bpo[1][i] = pb[i];
}

static BitVec input_bits(int party, int owner, const bool *bits, int n) {
  BitVec v(n);
  for (int i = 0; i < n; ++i)
    v[i] = Bit(party == owner ? bits[i] : false, owner);
  return v;
}

struct Result { block digest; std::vector<bool> out; };

// Stream body.
static Result run_stream_body(int party, int port, const bool kb[128], const bool pb[128]) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession mpc(io, &pool, party);
  io->flush();
  AG2PCEngine runner(&mpc);
  AG2PCInputs inputs(&mpc);
  BitVec key = input_bits(party, 1, kb, 128);
  BitVec pt = input_bits(party, 2, pb, 128);
  std::vector<bool> res = runner.run(inputs, [&] { return AesFn{}(key, pt); })
                              .reveal_bits(1);
  return {mpc.io->get_digest(), res};
}

// Flat bit-vector source.
static Result run_flat(int party, int port, const bool kb[128], const bool pb[128]) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession mpc(io, &pool, party);
  io->flush();
  std::vector<std::vector<bool>> bpo; make_bpo(party, kb, pb, bpo);
  auto in = mpc.process_inputs({1, 2}, bpo);
  SecureWires in_wires;
  for (int k = 0; k < 2; ++k) {
    auto &s = in[k];
    in_wires.Lambda.insert(in_wires.Lambda.end(), s.Lambda.begin(), s.Lambda.end());
    in_wires.wire_bundle.insert(in_wires.wire_bundle.end(), s.wire_bundle.begin(),
                                s.wire_bundle.end());
    if (party == 1) in_wires.label0.insert(in_wires.label0.end(), s.label0.begin(), s.label0.end());
    else in_wires.eval_label.insert(in_wires.eval_label.end(), s.eval_label.begin(), s.eval_label.end());
  }
  AG2PCEngine runner(&mpc);
  SecureWires out = runner.run_circuit(
      in_wires, 128, [](const std::vector<Bit> &bin, std::vector<Bit> &bout) {
        Bit key[128], pt[128], expanded[1408], ct[128];
        for (int i = 0; i < 128; ++i) key[i] = bin[i];
        for (int i = 0; i < 128; ++i) pt[i] = bin[128 + i];
        AES_Calculator_T<LambdaWire> aes;
        aes.key_schedule(key, expanded);
        aes.encrypt(pt, expanded, ct);
        for (int i = 0; i < 128; ++i) bout[i] = ct[i];
      });
  std::vector<bool> res = mpc.decode(out, 1);
  return {mpc.io->get_digest(), res};
}

// Compiled circuit.
static Result run_compiled(int party, int port, const bool kb[128], const bool pb[128]) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession mpc(io, &pool, party);
  io->flush();
  auto c = frontend::compile(AesFn{}, BitVec(128), BitVec(128));
  AG2PCEngine runner(&mpc);
  AG2PCInputs inputs(&mpc);
  BitVec key = input_bits(party, 1, kb, 128);
  BitVec pt = input_bits(party, 2, pb, 128);
  std::vector<bool> res = runner.run(inputs, [&] { return frontend::run(c, key, pt); })
                              .reveal_bits(1);
  return {mpc.io->get_digest(), res};
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;
  set_test_mode(true);   // deterministic randomness (single-threaded seed stream)

  bool kb[128], pb[128];
  for (int i = 0; i < 128; ++i) {
    kb[i] = ((i * 7 + 3) % 5) == 0;
    pb[i] = ((i * 3 + 1) % 4) == 0;
  }

  Result flat1 = run_flat(party, port + 0, kb, pb);
  Result flat2 = run_flat(party, port + 1, kb, pb);
  Result body = run_stream_body(party, port + 2, kb, pb);
  Result comp = run_compiled(party, port + 3, kb, pb);

  if (party == 1) {
    auto eqd = [](block a, block b) { return cmpBlock(&a, &b, 1); };
    bool det = eqd(flat1.digest, flat2.digest);
    bool stream_eq = eqd(flat1.digest, body.digest);
    bool compiled_eq = (comp.out == body.out && !comp.out.empty());

    printf("stream-equiv: flat-source determinism                       %s\n",
           det ? "GOOD!" : "BAD! (non-deterministic; comparison invalid)");
    printf("stream-equiv: BYTE     flat source == stream body           %s\n",
           stream_eq ? "GOOD!" : "BAD!");
    printf("stream-equiv: SEMANTIC compiled == body output  (oracle)    %s\n",
           compiled_eq ? "GOOD!" : "BAD!");
    bool ok = det && stream_eq && compiled_eq;
    printf("stream-equiv: %s\n", ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
