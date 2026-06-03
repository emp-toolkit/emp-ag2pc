// A COMPILED frontend circuit (frontend::compile -> TypedCircuit) run through the
// streaming engine via LambdaRunner::run_compiled<Ins...>, which uses
// frontend::run(circuit, args) as the per-phase replay source (walks the recorded
// BooleanProgram, no WireGraph / lowering) — the chosen compiled-execution path.
// Two circuits — 32-bit add (UInt32) and AES-128 (BitVec, runtime width via
// samples) — checked vs a plaintext oracle.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-ag2pc/lambda_runner.h"
#include "emp-ag2pc/lambda_circuit_types.h"   // Bit / UInt32 / BitVec = *_T<LambdaWire>
#include "emp-tool/frontend/frontend.h"
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

template <typename Wire>
static void aes_clear(const bool key_bits[128], const bool pt_bits[128], bool *ct_out) {
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

  // Compile once (party-independent). add: fixed-width UInt32; aes: runtime-width
  // BitVec, so shapes come from samples.
  auto c_add = frontend::compile<UInt32, UInt32>([](auto a, auto b) { return a + b; });
  auto c_aes = frontend::compile(AesFn{}, BitVec(128), BitVec(128));

  bool all_ok = true;

  // ---- add32 via compiled-circuit replay ----
  {
    const uint32_t xa = 1234567u, yb = 7654321u;
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires outw = runner.run_compiled<UInt32, UInt32>(c_add, {in[0], in[1]});
    std::vector<bool> res = mpc.decode(outw, 1);
    if (party == 1) {
      uint32_t got = u32_of(res), ref = xa + yb;
      printf("compiled add32 = %u (expected %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      all_ok &= (got == ref);
    }
  }

  // ---- AES-128 via compiled-circuit replay ----
  bool key_bits[128], pt_bits[128];
  for (int i = 0; i < 128; ++i) {
    key_bits[i] = ((i * 7 + 3) % 5) == 0;
    pt_bits[i]  = ((i * 3 + 1) % 4) == 0;
  }
  {
    std::vector<std::vector<bool>> bpo(2);
    bpo[0].assign(128, false); bpo[1].assign(128, false);
    if (party == 1) for (int i = 0; i < 128; ++i) bpo[0][i] = key_bits[i];
    if (party == 2) for (int i = 0; i < 128; ++i) bpo[1][i] = pt_bits[i];
    auto in = mpc.process_inputs({1, 2}, bpo);
    SecureWires outw = runner.run_compiled<BitVec, BitVec>(c_aes, {in[0], in[1]});
    std::vector<bool> res = mpc.decode(outw, 1);
    if (party == 1) {
      setup_clear_backend("");
      bool ct_ref[128];
      aes_clear<block>(key_bits, pt_bits, ct_ref);
      finalize_clear_backend();
      bool ok = (res.size() == 128);
      for (int i = 0; i < 128 && ok; ++i) ok = (res[i] == ct_ref[i]);
      printf("compiled AES-128 vs plaintext  %s\n", ok ? "GOOD!" : "BAD!");
      all_ok &= ok;
    }
  }

  return (party == 1 && !all_ok) ? 1 : 0;
}
