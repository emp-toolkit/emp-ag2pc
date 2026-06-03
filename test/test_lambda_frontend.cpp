// Streaming executor driven by an emp-tool FRONTEND body (the "LIVE" mode on
// AG2PC). LambdaRunner::run<Ins...> replays a pure wire-generic circuit function
// (typed args in, typed value out) across the per-phase backends — no flat gate
// vector / IR is materialized. Inputs/outputs stay outside the body: the caller
// process_inputs() each argument and decode()s the result.
//
// Two circuits: a 32-bit adder (UInt32 args) and AES-128 (BitVec args), each
// checked against a plaintext oracle. SPMD: every party supplies its own real
// bits and a dummy for inputs it does not own.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-ag2pc/lambda_runner.h"
#include "emp-ag2pc/lambda_circuit_types.h"   // Bit / UInt32 / BitVec = *_T<LambdaWire>
#include "net_setup.h"
#include <cstdio>
using namespace std;
using namespace emp;

static std::vector<bool> bits_of(uint32_t v, int n = 32) {
  std::vector<bool> b(n);
  for (int i = 0; i < n; ++i) b[i] = (v >> i) & 1u;
  return b;
}
static uint32_t u32_of(const std::vector<bool> &b) {
  uint32_t v = 0;
  for (size_t i = 0; i < b.size() && i < 32; ++i) if (b[i]) v |= (1u << i);
  return v;
}

// Plaintext AES oracle via the clear backend (same shape as test_lambda_aes).
template <typename Wire>
static void aes_clear(const bool key_bits[128], const bool pt_bits[128],
                      bool *ct_out) {
  using BW = Bit_T<Wire>;
  BW key[128], pt[128], expanded[1408], ct[128];
  for (int i = 0; i < 128; ++i) key[i] = BW(key_bits[i], PUBLIC);
  for (int i = 0; i < 128; ++i) pt[i]  = BW(pt_bits[i], PUBLIC);
  AES_Calculator_T<Wire> aes;
  aes.key_schedule(key, expanded);
  aes.encrypt(pt, expanded, ct);
  Wire buf[128];
  for (int i = 0; i < 128; ++i) buf[i] = ct[i].bit;
  backend->reveal(ct_out, 1, buf, 128);
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();
  LambdaRunner runner(&mpc);

  bool all_ok = true;

  // ---- Circuit 1: 32-bit add (UInt32 args), x owned by P1, y by P2. ----
  {
    const uint32_t xa = 1234567u, yb = 7654321u;
    auto in = mpc.process_inputs(/*owners=*/{1, 2},
                                 {bits_of(party == 1 ? xa : 0u),
                                  bits_of(party == 2 ? yb : 0u)});
    auto add_body = [](auto a, auto b) { return a + b; };
    SecureWires outw = runner.run<UInt32, UInt32>({in[0], in[1]}, add_body);
    std::vector<bool> res = mpc.decode(outw, /*recipient=*/1);
    if (party == 1) {
      uint32_t got = u32_of(res), ref = xa + yb;
      printf("streaming add32 = %u (expected %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      all_ok &= (got == ref);
    }
  }

  // ---- Circuit 2: AES-128 (BitVec args), key owned by P1, pt by P2. ----
  bool key_bits[128], pt_bits[128];
  for (int i = 0; i < 128; ++i) {
    key_bits[i] = ((i * 7 + 3) % 5) == 0;
    pt_bits[i]  = ((i * 3 + 1) % 4) == 0;
  }
  {
    std::vector<std::vector<bool>> bpo(2);
    bpo[0].assign(128, false);
    bpo[1].assign(128, false);
    if (party == 1) for (int i = 0; i < 128; ++i) bpo[0][i] = key_bits[i];
    if (party == 2) for (int i = 0; i < 128; ++i) bpo[1][i] = pt_bits[i];
    auto in = mpc.process_inputs(/*owners=*/{1, 2}, bpo);

    // Pure frontend body: two 128-bit BitVec args -> 128-bit BitVec ciphertext.
    auto aes_body = [](auto key, auto pt) {
      using W = emp::wire_t<decltype(key)>;
      Bit_T<W> k[128], p[128], expanded[1408], ct[128];
      for (int i = 0; i < 128; ++i) k[i] = key[i];
      for (int i = 0; i < 128; ++i) p[i] = pt[i];
      AES_Calculator_T<W> aes;
      aes.key_schedule(k, expanded);
      aes.encrypt(p, expanded, ct);
      BitVec_T<W> out(128);
      for (int i = 0; i < 128; ++i) out[i] = ct[i];
      return out;
    };
    SecureWires outw = runner.run<BitVec, BitVec>({in[0], in[1]}, aes_body);
    std::vector<bool> res = mpc.decode(outw, /*recipient=*/1);

    if (party == 1) {
      setup_clear_backend("");
      bool ct_ref[128];
      aes_clear<block>(key_bits, pt_bits, ct_ref);
      finalize_clear_backend();
      bool ok = (res.size() == 128);
      for (int i = 0; i < 128 && ok; ++i) ok = (res[i] == ct_ref[i]);
      printf("streaming AES-128 vs plaintext  %s\n", ok ? "GOOD!" : "BAD!");
      all_ok &= ok;
    }
  }

  return (party == 1 && !all_ok) ? 1 : 0;
}
