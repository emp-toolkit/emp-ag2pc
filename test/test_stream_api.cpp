// Stream-mode API coverage: live body, compiled circuit, raw program,
// flat bit-vector source, chaining, AG2PCInputs, AES, and SHA-256.
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/stream.h"
#include "emp-tool/frontend/frontend.h"
#include "test_common.h"
#include <cstdio>
using namespace std;
using namespace emp;
using namespace ag2pc_test;

static UInt32 input_u32(int party, int owner, uint32_t value) {
  return UInt32(party == owner ? value : 0u, owner);
}

static BitVec input_bits(int party, int owner, const bool *bits, int n) {
  BitVec v(n);
  for (int i = 0; i < n; ++i)
    v[i] = Bit(party == owner ? bits[i] : false, owner);
  return v;
}

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

  // Constructor-style stream I/O.
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb;
    auto c = frontend::compile<UInt32, UInt32>(add);
    uint32_t gl, gc_body, gc_engine;
    {
      AG2PCInputs inputs(&mpc);
      UInt32 a = input_u32(party, ALICE, xa);
      UInt32 b = input_u32(party, BOB, yb);
      gl = runner.run(inputs, [&] { return add(a, b); }).reveal<uint32_t>(1);
      gc_body = runner.run(inputs, [&] { return frontend::run(c, a, b); })
                    .reveal<uint32_t>(1);
      const SecureWires &in = inputs.process();
      SecureWires out = runner.run_compiled<UInt32, UInt32>(
          c, {in.slice(0, 32), in.slice(32, 64)});
      gc_engine = u32_of(mpc.decode(out, 1));
    }
    if (party == 1) {
      printf("stream ctor add32: live=%u compiled-body=%u run_compiled=%u "
             "(exp %u)  %s\n", gl, gc_body, gc_engine, ref,
             (gl == ref && gc_body == ref && gc_engine == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc_body == ref && gc_engine == ref);
    }
  }

  // Chained stream runs.
  {
    const uint32_t xa = 3333333u, yb = 12345u, ref = 2u * (xa + yb);
    auto dbl = [](auto v) { return v + v; };
    auto c_add = frontend::compile<UInt32, UInt32>(add);
    auto c_dbl = frontend::compile<UInt32>(dbl);
    uint32_t gl, gc;
    {
      AG2PCInputs inputs(&mpc);
      UInt32 a = input_u32(party, ALICE, xa);
      UInt32 b = input_u32(party, BOB, yb);
      SecureWires z = runner.run(inputs, [&] { return add(a, b); });
      SecureWires w = runner.run<UInt32>({z}, dbl);
      SecureWires z2 = runner.run(inputs, [&] { return frontend::run(c_add, a, b); });
      SecureWires w2 = runner.run_compiled<UInt32>(c_dbl, {z2});
      gl = u32_of(mpc.decode(w, 1));
      gc = u32_of(mpc.decode(w2, 1));
    }
    if (party == 1) {
      printf("stream ctor chain 2*(x+y): live=%u compiled=%u (exp %u)  %s\n", gl, gc,
             ref, (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // C++20 template-lambda body with constructor-style stream I/O.
  {
    const uint32_t xa = 111111u, yb = 222222u, ref = xa + yb;
    auto add_tl = []<class W>(UInt32_T<W> a, UInt32_T<W> b) { return a + b; };
    auto c = frontend::compile<UInt32, UInt32>(add_tl);
    uint32_t gl, gc;
    {
      AG2PCInputs inputs(&mpc);
      UInt32 a = input_u32(party, ALICE, xa);
      UInt32 b = input_u32(party, BOB, yb);
      gl = runner.run(inputs, [&] { return add_tl(a, b); }).reveal<uint32_t>(1);
      gc = runner.run(inputs, [&] { return frontend::run(c, a, b); })
               .reveal<uint32_t>(1);
    }
    if (party == 1) {
      printf("stream ctor typed add32: live=%u compiled=%u (exp %u)  %s\n", gl, gc, ref,
             (gl == ref && gc == ref) ? "GOOD!" : "BAD!");
      ok &= (gl == ref && gc == ref);
    }
  }

  // Public constant in a compiled body with constructor-style stream I/O.
  {
    const uint32_t xa = 4242u, ref = xa + 1u;
    auto inc = [](auto a) { return a + decltype(a)(32, 1, PUBLIC); };
    auto c_inc = frontend::compile<UInt32>(inc);
    uint32_t got;
    {
      AG2PCInputs inputs(&mpc);
      UInt32 a = input_u32(party, ALICE, xa);
      got = runner.run(inputs, [&] { return frontend::run(c_inc, a); })
                .reveal<uint32_t>(1);
    }
    if (party == 1) {
      printf("stream ctor compiled inc32 (const) = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      ok &= (got == ref);
    }
  }

  // Raw BooleanProgram via run_program.
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb + 1u;
    auto body = [](auto a, auto b) { return a + b + decltype(a)(32, 1, PUBLIC); };
    auto c = frontend::compile<UInt32, UInt32>(body);
    const auto &prog = c.circuit.prog;
    uint32_t got;
    {
      AG2PCInputs inputs(&mpc);
      UInt32 a = input_u32(party, ALICE, xa);
      UInt32 b = input_u32(party, BOB, yb);
      const SecureWires &in = inputs.process();
      SecureWires ow = runner.run_program(prog, in, prog.outputs);
      got = u32_of(mpc.decode(ow, 1));
    }
    if (party == 1) {
      printf("stream ctor run_program (x+y+1) = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
      ok &= (got == ref);
    }
  }

  // AES-128 with constructor-style stream I/O.
  {
    bool key_bits[128], pt_bits[128];
    aes_test_bits(key_bits, pt_bits);
    auto c_aes = frontend::compile(AesFn{}, BitVec(128), BitVec(128));
    std::vector<bool> resL, resC;
    {
      AG2PCInputs inputs(&mpc);
      BitVec key = input_bits(party, ALICE, key_bits, 128);
      BitVec pt = input_bits(party, BOB, pt_bits, 128);
      resL = runner.run(inputs, [&] { return AesFn{}(key, pt); }).reveal_bits(1);
      resC = runner.run(inputs, [&] { return frontend::run(c_aes, key, pt); })
                 .reveal_bits(1);
    }
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
      printf("stream ctor AES-128: live + compiled vs plaintext  %s\n",
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

  // Reuse constructor-style stream inputs across multiple runs.
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
      printf("stream AG2PCInputs (ctor inputs, batched; reused) = %u, %u "
             "(exp %u, %u)  %s\n", got, got2, ref, ref2, aok ? "GOOD!" : "BAD!");
      ok &= aok;
    }
  }

  return (party == 1 && !ok) ? 1 : 0;
}
