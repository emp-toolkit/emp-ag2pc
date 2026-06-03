// Frontend crypto-sized circuits on AG2PC — AES-128 and SHA-256 driven through
// the shared streaming engine (LambdaRunner / run_engine_), one representative
// circuit per circuit source, all on a single C2PC connection:
//
//   * AES-128 via run<Ins...>        — a pure wire-generic body, replayed live
//   * AES-128 via run_compiled<Ins...> — the same body frontend::compile'd once
//   * SHA-256 via run_circuit        — the legacy flat (in_bits,out_bits) lambda
//
// Each is checked against a plaintext oracle (emp-tool's AES_Calculator /
// sha256_compress on the clear backend). Inputs/outputs stay outside the
// circuit; SPMD: every party supplies its own real bits and dummies for inputs
// it does not own. (Small/fast API behavior — add, chaining, constants, raw
// BooleanProgram — lives in test_frontend_api.)
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/lambda_circuit_types.h"   // Bit / BitVec / ... = *_T<LambdaWire>
#include "emp-tool/frontend/frontend.h"
#include "test_common.h"
#include <cstdio>
using namespace std;
using namespace emp;
using namespace ag2pc_test;

// One AES-128 body, wire-generic — shared by the live and compiled paths.
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

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();
  LambdaRunner runner(&mpc);

  bool ok = true;

  // ============================ AES-128 ====================================
  // key owned by P1, plaintext by P2. The live and compiled runs share one
  // input bundle and one plaintext-oracle ciphertext.
  {
    bool key_bits[128], pt_bits[128];
    aes_test_bits(key_bits, pt_bits);
    std::vector<std::vector<bool>> bpo(2, std::vector<bool>(128, false));
    if (party == 1) for (int i = 0; i < 128; ++i) bpo[0][i] = key_bits[i];
    if (party == 2) for (int i = 0; i < 128; ++i) bpo[1][i] = pt_bits[i];
    auto in = mpc.process_inputs({1, 2}, bpo);

    SecureWires outL = runner.run<BitVec, BitVec>({in[0], in[1]}, AesFn{});
    std::vector<bool> resL = mpc.decode(outL, 1);

    auto c_aes = frontend::compile(AesFn{}, BitVec(128), BitVec(128));
    SecureWires outC = runner.run_compiled<BitVec, BitVec>(c_aes, {in[0], in[1]});
    std::vector<bool> resC = mpc.decode(outC, 1);

    if (party == 1) {
      setup_clear_backend("");
      bool ct_ref[128];
      aes_clear<block>(key_bits, pt_bits, ct_ref);
      finalize_clear_backend();
      auto matches = [&](const std::vector<bool> &r) {
        if (r.size() != 128) return false;
        for (int i = 0; i < 128; ++i) if (r[i] != ct_ref[i]) return false;
        return true;
      };
      bool aes_ok = matches(resL) && matches(resC);
      printf("AES-128: live + compiled vs plaintext  %s\n", aes_ok ? "GOOD!" : "BAD!");
      ok &= aes_ok;
    }
  }

  // ============================ SHA-256 ====================================
  // N independent compressions through the flat-lambda source (run_circuit).
  // Party 2 owns the message blocks; the IV (H0) is a public constant created
  // inside the lambda. SHA_BLOCKS overrides N (default 4 — a correctness check;
  // the AND-dominated bucket regime is covered by test_direct_crypto at N=50).
  {
    const char *env = getenv("SHA_BLOCKS");
    const int N = env ? atoi(env) : 4;
    vector<array<uint32_t, 16>> blk(N);
    for (int n = 0; n < N; ++n)
      for (int j = 0; j < 16; ++j)
        blk[n][j] = 0x9e3779b9u * (uint32_t)(j + 1) + 0x01000193u * (uint32_t)n;

    std::vector<bool> msg_bits(512 * N);
    for (int n = 0; n < N; ++n)
      for (int j = 0; j < 16; ++j)
        for (int b = 0; b < 32; ++b)
          msg_bits[n * 512 + j * 32 + b] =
              (party == 2) ? (((blk[n][j] >> b) & 1u) != 0) : false;
    auto in = mpc.process_inputs({/*owner=*/2}, {msg_bits});

    SecureWires outw = runner.run_circuit(
        in[0], /*n_out=*/256 * N,
        [N](const std::vector<Bit> &bin, std::vector<Bit> &bout) {
          using U = UnsignedInt_T<LambdaWire, 32>;
          for (int n = 0; n < N; ++n) {
            U state[8], m[16];
            for (int i = 0; i < 8; ++i) state[i] = U(sha256_detail::H0[i], PUBLIC);
            for (int j = 0; j < 16; ++j)
              for (int b = 0; b < 32; ++b)
                m[j].bits[b] = bin[n * 512 + j * 32 + b];
            sha256_compress<LambdaWire>(state, m);
            for (int i = 0; i < 8; ++i)
              for (int b = 0; b < 32; ++b)
                bout[n * 256 + i * 32 + b] = state[i].bits[b];
          }
        });
    std::vector<bool> res = mpc.decode(outw, 1);

    if (party == 1) {
      setup_clear_backend("");
      using CU = UnsignedInt_T<block, 32>;
      bool sha_ok = (res.size() == (size_t)256 * N);
      for (int n = 0; n < N && sha_ok; ++n) {
        CU state[8], cmsg[16];
        for (int i = 0; i < 8; ++i) state[i] = CU(sha256_detail::H0[i], PUBLIC);
        for (int j = 0; j < 16; ++j) cmsg[j] = CU(blk[n][j], PUBLIC);
        sha256_compress<block>(state, cmsg);
        block rbuf[256];
        for (int i = 0; i < 8; ++i)
          for (int b = 0; b < 32; ++b) rbuf[i * 32 + b] = state[i].bits[b].bit;
        bool out_ref[256];
        backend->reveal(out_ref, 1, rbuf, 256);
        for (int b = 0; b < 256; ++b)
          sha_ok = sha_ok && (res[n * 256 + b] == out_ref[b]);
      }
      finalize_clear_backend();
      printf("SHA-256 x %d via run_circuit vs plaintext  %s\n", N,
             sha_ok ? "GOOD!" : "BAD!");
      ok &= sha_ok;
    }
  }

  return (party == 1 && !ok) ? 1 : 0;
}
