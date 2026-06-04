// INTERNAL / EXPERT test — the low-level engine surface, NOT the public API.
//
// Normal users write SH2PC-style code (see test_public_api / test_direct_*).
// This file drives function mode directly: AG2PCSession (session crypto) +
// AG2PCEngine (the one executor) replaying every circuit SOURCE, with inputs and
// outputs handled explicitly via process_inputs / decode / SecureWires. Because
// it uses those internals and the expert LambdaWire circuit-type aliases, it
// includes <emp-ag2pc/function.h> and MUST NOT include <emp-ag2pc/direct.h>
// (whose AG2PCWire aliases would collide).
//
// Sources covered (all on one AG2PCSession connection):
//   * run<Ins...>            — pure wire-generic body, live per phase
//   * run_compiled<Ins...>   — the same body frontend::compile'd once
//   * run_program            — a raw frontend::BooleanProgram
//   * run_circuit            — the legacy flat (in_bits,out_bits) lambda
//   plus chaining, a C++20 template-lambda body, a public-constant compiled
//   circuit, and crypto-sized AES / SHA-256 vs a plaintext oracle.
// Built as C++20 (for the template-lambda body).
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/function.h"          // AG2PCSession + AG2PCEngine + LambdaWire aliases
#include "emp-tool/frontend/frontend.h"  // frontend::compile
#include "test_common.h"
#include <cstdio>
using namespace std;
using namespace emp;
using namespace ag2pc_test;

// SecureWires concat — an engine-input helper (backend type), so it lives here
// with the internal test rather than in the mode-header-free test_common.h.
static SecureWires concat(const std::vector<SecureWires> &in, int party) {
  SecureWires w;
  for (const auto &s : in) {
    w.Lambda.insert(w.Lambda.end(), s.Lambda.begin(), s.Lambda.end());
    w.wire_bundle.insert(w.wire_bundle.end(), s.wire_bundle.begin(), s.wire_bundle.end());
    if (party == 1) w.label0.insert(w.label0.end(), s.label0.begin(), s.label0.end());
    else            w.eval_label.insert(w.eval_label.end(), s.eval_label.begin(), s.eval_label.end());
  }
  return w;
}

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
  AG2PCSession mpc(io, &pool, party);
  io->flush();
  AG2PCEngine runner(&mpc);

  bool ok = true;
  auto add = [](auto a, auto b) { return a + b; };

  // ---- add32: run<> (live) vs run_compiled<>; x owned by P1, y by P2 ----
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb;
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires outL = runner.run<UInt32, UInt32>({in[0], in[1]}, add);
    auto c = frontend::compile<UInt32, UInt32>(add);
    SecureWires outC = runner.run_compiled<UInt32, UInt32>(c, {in[0], in[1]});
    uint32_t gl = u32_of(mpc.decode(outL, 1)), gc = u32_of(mpc.decode(outC, 1));
    if (party == 1) {
      printf("engine add32: live=%u compiled=%u (exp %u)  %s\n", gl, gc, ref,
             (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // ---- chaining w = 2*(x+y): live run->run and compiled->compiled ----
  {
    const uint32_t xa = 3333333u, yb = 12345u, ref = 2u * (xa + yb);
    auto dbl = [](auto v) { return v + v; };
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires z = runner.run<UInt32, UInt32>({in[0], in[1]}, add);
    SecureWires w = runner.run<UInt32>({z}, dbl);
    auto c_add = frontend::compile<UInt32, UInt32>(add);
    auto c_dbl = frontend::compile<UInt32>(dbl);
    SecureWires z2 = runner.run_compiled<UInt32, UInt32>(c_add, {in[0], in[1]});
    SecureWires w2 = runner.run_compiled<UInt32>(c_dbl, {z2});
    uint32_t gl = u32_of(mpc.decode(w, 1)), gc = u32_of(mpc.decode(w2, 1));
    if (party == 1) {
      printf("engine chain 2*(x+y): live=%u compiled=%u (exp %u)  %s\n", gl, gc,
             ref, (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // ---- C++20 template-lambda body (explicit UInt32_T<W>, W deduced) ----
  {
    const uint32_t xa = 111111u, yb = 222222u, ref = xa + yb;
    auto add_tl = []<class W>(UInt32_T<W> a, UInt32_T<W> b) { return a + b; };
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires outL = runner.run<UInt32, UInt32>({in[0], in[1]}, add_tl);
    auto c = frontend::compile<UInt32, UInt32>(add_tl);
    SecureWires outC = runner.run_compiled<UInt32, UInt32>(c, {in[0], in[1]});
    uint32_t gl = u32_of(mpc.decode(outL, 1)), gc = u32_of(mpc.decode(outC, 1));
    if (party == 1) {
      printf("engine typed add32: live=%u compiled=%u (exp %u)  %s\n", gl, gc, ref,
             (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // ---- public constant: compiled inc32 (x + 1) ----
  {
    const uint32_t xa = 4242u, ref = xa + 1u;
    auto inc = [](auto a) { return a + decltype(a)(32, 1, PUBLIC); };
    auto c_inc = frontend::compile<UInt32>(inc);
    auto in = mpc.process_inputs({1}, {bits_of(party == 1 ? xa : 0u)});
    SecureWires outw = runner.run_compiled<UInt32>(c_inc, {in[0]});
    uint32_t got = u32_of(mpc.decode(outw, 1));
    if (party == 1) {
      printf("engine compiled inc32 (const) = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      ok &= (got == ref);
    }
  }

  // ---- raw BooleanProgram via run_program: (x + y + 1) ----
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb + 1u;
    auto body = [](auto a, auto b) { return a + b + decltype(a)(32, 1, PUBLIC); };
    auto c = frontend::compile<UInt32, UInt32>(body);
    const auto &prog = c.circuit.prog;
    auto in = mpc.process_inputs({1, 2}, {bits_of(party == 1 ? xa : 0u),
                                          bits_of(party == 2 ? yb : 0u)});
    SecureWires inputs = concat(in, party);
    SecureWires ow = runner.run_program(prog, inputs, prog.outputs);
    uint32_t got = u32_of(mpc.decode(ow, 1));
    if (party == 1) {
      printf("engine run_program (x+y+1) = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      ok &= (got == ref);
    }
  }

  // ---- AES-128: run<> (live) + run_compiled<>, vs plaintext oracle ----
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
      auto match = [&](const std::vector<bool> &r) {
        if (r.size() != 128) return false;
        for (int i = 0; i < 128; ++i) if (r[i] != ct_ref[i]) return false;
        return true;
      };
      bool aes_ok = match(resL) && match(resC);
      printf("engine AES-128: live + compiled vs plaintext  %s\n",
             aes_ok ? "GOOD!" : "BAD!");
      ok &= aes_ok;
    }
  }

  // ---- SHA-256 x N via the flat-lambda source (run_circuit), vs oracle ----
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
      printf("engine SHA-256 x %d via run_circuit vs plaintext  %s\n", N,
             sha_ok ? "GOOD!" : "BAD!");
      ok &= sha_ok;
    }
  }

  // ---- AG2PCInputs: inputs built with EMP-object constructors OUTSIDE the body,
  //      batched into one process_inputs; all compute inside run(inputs, body). --
  {
    const uint32_t X = 1234567u, Y = 7654321u;
    const bool F = true;
    AG2PCInputs inputs(&mpc);
    UInt32 a(party == ALICE ? X : 0, ALICE);     // each ctor: deferred, recorded
    UInt32 b(party == BOB   ? Y : 0, BOB);
    Bit    flag(party == ALICE ? F : false, ALICE);
    auto c = runner.run(inputs, [&] {
      return a.select(flag, b) + UInt32(32, 1, PUBLIC);   // (flag? b : a) + 1
    });
    uint32_t got = c.reveal<uint32_t>(1);                 // object-style reveal on the handle
    // Reuse: a second body over the SAME frozen AG2PCInputs (construct once, run many).
    auto c2 = runner.run(inputs, [&] { return a + b; });
    uint32_t got2 = c2.reveal<uint32_t>(1);
    if (party == 1) {
      uint32_t ref = (F ? Y : X) + 1u, ref2 = X + Y;
      bool aok = (got == ref) && (got2 == ref2);
      printf("engine AG2PCInputs (ctor inputs, batched; reused) = %u, %u "
             "(exp %u, %u)  %s\n", got, got2, ref, ref2, aok ? "GOOD!" : "BAD!");
      ok &= aok;
    }
  }

  return (party == 1 && !ok) ? 1 : 0;
}
