// AES-128 in lambda mode vs record mode, back-to-back in the same binary.
// Both modes process the same inputs through the same protocol layer; the
// lambda-mode runner replays the AES circuit 3-4 times across phase-specific
// backends (no flat gate vector materialized), the record-mode AG2PCBackend
// records all gates into chunk_gates_ and runs run_chunk_ at reveal.
// We compare ciphertext (correctness) and wall time (cost delta).
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-ag2pc/lambda_runner.h"
// File-scope Bit alias is for LambdaWire (lambda mode's zero-overhead carrier).
// The record-mode helper below is templated on Wire and uses Bit_T<Wire>
// directly, so it doesn't depend on the file-scope alias.
#include "emp-ag2pc/lambda_circuit_types.h"     // installs Bit/Integer/... = *_T<LambdaWire>
#include "net_setup.h"

#include <chrono>

using namespace std;
using namespace emp;

// Record-mode AES via the existing AG2PCBackend (= test_aes's shape).
template <typename Wire>
static void aes_record(const bool key_bits[128], const bool pt_bits[128],
                       int key_owner, int pt_owner, bool *ct_out) {
  using BW = Bit_T<Wire>;
  BW key[128], pt[128], expanded[1408], ct[128];
  for (int i = 0; i < 128; ++i) key[i] = BW(key_bits[i], key_owner);
  for (int i = 0; i < 128; ++i) pt[i]  = BW(pt_bits[i], pt_owner);
  AES_Calculator_T<Wire> aes;
  aes.key_schedule(key, expanded);
  aes.encrypt(pt, expanded, ct);
  Wire buf[128];
  for (int i = 0; i < 128; ++i) buf[i] = ct[i].bit;
  backend->reveal(ct_out, 1, buf, 128);
}

// Lambda-mode AES — same circuit, driven through LambdaRunner.
static void aes_lambda(C2PC *mpc, const bool key_bits[128],
                       const bool pt_bits[128], bool *ct_out) {
  std::vector<std::vector<bool>> bits_per_owner(2);
  bits_per_owner[0].assign(key_bits, key_bits + 128);   // owner 1: key
  bits_per_owner[1].assign(pt_bits, pt_bits + 128);     // owner 2: plaintext
  auto in_per_owner = mpc->process_inputs({1, 2}, bits_per_owner);
  SecureWires in_wires;
  // Concat both owners' SecureWires into one ordered bundle: key then pt.
  for (int k = 0; k < 2; ++k) {
    auto &s = in_per_owner[k];
    in_wires.Lambda.insert(in_wires.Lambda.end(), s.Lambda.begin(), s.Lambda.end());
    in_wires.wire_bundle.insert(in_wires.wire_bundle.end(),
                                s.wire_bundle.begin(), s.wire_bundle.end());
    if (mpc->party == 1)
      in_wires.label0.insert(in_wires.label0.end(), s.label0.begin(), s.label0.end());
    else
      in_wires.eval_label.insert(in_wires.eval_label.end(),
                                 s.eval_label.begin(), s.eval_label.end());
  }

  LambdaRunner runner(mpc);
  SecureWires out_wires = runner.run_circuit(
      in_wires, /*n_out=*/128,
      [](const std::vector<Bit> &in, std::vector<Bit> &out) {
        Bit key[128], pt[128], expanded[1408], ct[128];
        for (int i = 0; i < 128; ++i) key[i] = in[i];
        for (int i = 0; i < 128; ++i) pt[i]  = in[128 + i];
        AES_Calculator_T<LambdaWire> aes;
        aes.key_schedule(key, expanded);
        aes.encrypt(pt, expanded, ct);
        for (int i = 0; i < 128; ++i) out[i] = ct[i];
      });

  std::vector<bool> result = mpc->decode(out_wires, /*to=*/1);
  if (mpc->party == 1)
    for (int i = 0; i < 128; ++i) ct_out[i] = result[i];
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  bool key_bits[128], pt_bits[128];
  for (int i = 0; i < 128; ++i) {
    key_bits[i] = ((i * 7 + 3) % 5) == 0;
    pt_bits[i]  = ((i * 3 + 1) % 4) == 0;
  }
  bool ka[128], pb[128];
  for (int i = 0; i < 128; ++i) {
    ka[i] = (party == 1) ? key_bits[i] : false;
    pb[i] = (party == 2) ? pt_bits[i] : false;
  }

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);

  // ------------------------------------------------------------------
  // Record mode: AG2PCBackend records the circuit and runs at reveal.
  // ------------------------------------------------------------------
  setup_ag2pc(io, &pool, party);
  io->flush();
  bool ct_record[128] = {};
  auto t0r = std::chrono::steady_clock::now();
  aes_record<AG2PCWire>(ka, pb, /*key_owner=*/1, /*pt_owner=*/2, ct_record);
  auto t1r = std::chrono::steady_clock::now();
  double record_ms =
      std::chrono::duration<double, std::milli>(t1r - t0r).count();
  finalize_ag2pc();

  // ------------------------------------------------------------------
  // Lambda mode: construct a fresh C2PC; the circuit body lives in a
  // lambda that the runner replays per phase. No flat gate vector.
  // ------------------------------------------------------------------
  C2PC mpc_obj(io, &pool, party);
  io->flush();
  bool ct_lambda[128] = {};
  auto t0l = std::chrono::steady_clock::now();
  aes_lambda(&mpc_obj, ka, pb, ct_lambda);
  auto t1l = std::chrono::steady_clock::now();
  double lambda_ms =
      std::chrono::duration<double, std::milli>(t1l - t0l).count();

  if (party == 1) {
    // Plaintext oracle for correctness.
    setup_clear_backend("");
    bool ct_ref[128];
    aes_record<block>(key_bits, pt_bits, PUBLIC, PUBLIC, ct_ref);
    finalize_clear_backend();
    bool ok_r = true, ok_l = true;
    for (int i = 0; i < 128; ++i) {
      if (ct_record[i] != ct_ref[i]) ok_r = false;
      if (ct_lambda[i] != ct_ref[i]) ok_l = false;
    }
    cout << "test_lambda_aes record vs plaintext: " << (ok_r ? "GOOD!" : "BAD!")
         << "   wall = " << record_ms << " ms\n";
    cout << "test_lambda_aes lambda vs plaintext: " << (ok_l ? "GOOD!" : "BAD!")
         << "   wall = " << lambda_ms << " ms\n";
    cout << "lambda / record ratio: " << (lambda_ms / record_ms) << endl;
    return (ok_r && ok_l) ? 0 : 1;
  }
  return 0;
}
