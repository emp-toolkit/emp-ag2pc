// Equivalence guard across the frontend execution paths on AG2PC.
//
// The protocol keeps a running transcript hash per channel (NetIO::get_digest(),
// used internally for the Fiat-Shamir half-gate seed). Under EMP_TEST_MODE all
// randomness is deterministic, so two runs of the SAME circuit produce a
// byte-identical transcript iff they drive the crypto identically.
//
// Two kinds of equivalence are checked, because the paths are not all the same:
//
//   * BYTE equivalence — the two STREAMING front-doors share one run_engine and
//     emit the identical gate stream for AES, so their transcripts must match
//     exactly:
//        legacy   — LambdaRunner::run_circuit (flat (in_bits,out_bits) lambda)
//        frontend — LambdaRunner::run<Ins...>  (pure frontend body)
//     (plus a legacy-twice determinism self-check).
//
//   * SEMANTIC equivalence — a COMPILED circuit replayed via
//     LambdaRunner::run_compiled goes through the SAME engine but its gate stream
//     may differ from the body replay, because frontend::compile dedupes
//     CONST0/CONST1 while a body may emit a public label per use. So we require
//     the compiled path to produce the SAME ciphertext (oracle equality), NOT a
//     byte-identical transcript.
//
// (The direct recorder runs on this SAME engine — it emits BooleanProgram chunks
// into run_program — and is covered by test_direct_recorder / test_direct_crypto.
// Its transcript is not compared here: its gate stream depends on chunk
// boundaries, not just the circuit, so byte-equivalence is not expected.)
//
// Each run gets its own connection (so a channel's cumulative digest covers
// exactly one run) and resets the deterministic seed counter first.
// INTERNAL test: drives function mode directly (AG2PCSession + AG2PCEngine +
// SecureWires), so it uses the function-mode header and NOT <emp-ag2pc/direct.h>.
#include "emp-ag2pc/function.h"
#include "emp-tool/frontend/frontend.h"
#include "net_setup.h"
#include <cstdio>
using namespace std;
using namespace emp;

// One AES-128 circuit body, wire-generic — shared by the body and compiled paths.
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

struct Result { block digest; std::vector<bool> out; };   // out: party-1 ciphertext

// --- streaming (frontend body) ------------------------------------------------
static Result run_frontend(int party, int port, const bool kb[128], const bool pb[128]) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();
  std::vector<std::vector<bool>> bpo; make_bpo(party, kb, pb, bpo);
  auto in = mpc.process_inputs({1, 2}, bpo);
  LambdaRunner runner(&mpc);
  SecureWires out = runner.run<BitVec, BitVec>({in[0], in[1]}, AesFn{});
  std::vector<bool> res = mpc.decode(out, 1);
  return {mpc.io->get_digest(), res};
}

// --- streaming (legacy flat lambda) ------------------------------------------
static Result run_legacy(int party, int port, const bool kb[128], const bool pb[128]) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
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
  LambdaRunner runner(&mpc);
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

// --- compiled circuit replayed through the streaming engine ------------------
static Result run_compiled(int party, int port, const bool kb[128], const bool pb[128]) {
  reset_test_seed_counter();
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();
  auto c = frontend::compile(AesFn{}, BitVec(128), BitVec(128));
  std::vector<std::vector<bool>> bpo; make_bpo(party, kb, pb, bpo);
  auto in = mpc.process_inputs({1, 2}, bpo);
  LambdaRunner runner(&mpc);
  SecureWires out = runner.run_compiled<BitVec, BitVec>(c, {in[0], in[1]});
  std::vector<bool> res = mpc.decode(out, 1);
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

  Result leg1 = run_legacy(party, port + 0, kb, pb);
  Result leg2 = run_legacy(party, port + 1, kb, pb);   // determinism self-check
  Result few  = run_frontend(party, port + 2, kb, pb);
  Result comp = run_compiled(party, port + 3, kb, pb);

  if (party == 1) {
    auto eqd = [](block a, block b) { return cmpBlock(&a, &b, 1); };
    bool det        = eqd(leg1.digest, leg2.digest);          // test-mode determinism
    bool stream_eq  = eqd(leg1.digest, few.digest);           // BYTE: both streaming front-doors
    bool compiled_eq = (comp.out == few.out && !comp.out.empty());  // SEMANTIC: same ciphertext

    printf("wire-equiv: legacy determinism self-check                 %s\n",
           det ? "GOOD!" : "BAD! (non-deterministic; comparison invalid)");
    printf("wire-equiv: BYTE     legacy == frontend body  (streaming) %s\n",
           stream_eq ? "GOOD!" : "BAD!");
    printf("wire-equiv: SEMANTIC compiled == body output  (oracle)    %s\n",
           compiled_eq ? "GOOD!" : "BAD!");
    bool ok = det && stream_eq && compiled_eq;
    printf("wire-equiv: %s\n", ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
