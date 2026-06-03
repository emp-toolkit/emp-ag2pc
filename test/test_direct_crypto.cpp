// Direct recorder (AG2PCBackend) on real, crypto-sized circuits: native AES-128
// and SHA-256 authored in the imperative Bit/Integer frontend, recorded into
// frontend::BooleanProgram chunks and run on the shared engine
// (LambdaRunner::run_program -> run_engine_). Each is verified against the SAME
// circuit run in the clear (setup_clear_backend), so the bit-convention cancels
// and we directly check ag2pc == plaintext. Recorder semantics (reveal,
// checkpoint, reactive, liveness) are in test_direct_recorder; this file is the
// at-scale correctness + bucket-regime check. Each circuit runs in its own
// setup/finalize cycle on its own connection (port + k).
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "test_common.h"
using namespace std;
using namespace emp;
using namespace ag2pc_test;

// AES-128 with per-owner inputs (recorder side: key_owner=1, pt_owner=2; oracle:
// PUBLIC, PUBLIC). Bulk-reveal all 128 ciphertext wires to P1 in one call.
template <typename Wire>
static void aes_ct(const bool key_bits[128], const bool pt_bits[128],
                   int key_owner, int pt_owner, bool *ct_out) {
  using B = Bit_T<Wire>;
  B key[128], pt[128], expanded[1408], ct[128];
  for (int i = 0; i < 128; ++i) key[i] = B(key_bits[i], key_owner);
  for (int i = 0; i < 128; ++i) pt[i]  = B(pt_bits[i], pt_owner);
  AES_Calculator_T<Wire> aes;
  aes.key_schedule(key, expanded);
  aes.encrypt(pt, expanded, ct);
  Wire buf[128];
  for (int i = 0; i < 128; ++i) buf[i] = ct[i].bit;
  backend->reveal(ct_out, 1, buf, 128);
}

// ---- AES-128 through the direct recorder vs plaintext -----------------------
static bool aes_direct(int party, int port) {
  bool key_bits[128], pt_bits[128];
  aes_test_bits(key_bits, pt_bits);

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);
  io->flush();

  // key owned by P1, plaintext by P2; each party feeds its own real bits.
  bool ka[128], pb[128];
  for (int i = 0; i < 128; ++i) {
    ka[i] = (party == 1) ? key_bits[i] : false;
    pb[i] = (party == 2) ? pt_bits[i] : false;
  }
  bool ct_ag2pc[128];
  aes_ct<AG2PCWire>(ka, pb, /*key_owner=*/1, /*pt_owner=*/2, ct_ag2pc);
  finalize_ag2pc();
  if (party != 1) return true;

  setup_clear_backend("");
  bool ct_ref[128];
  aes_ct<block>(key_bits, pt_bits, PUBLIC, PUBLIC, ct_ref);
  finalize_clear_backend();
  bool ok = true;
  for (int i = 0; i < 128; ++i) if (ct_ag2pc[i] != ct_ref[i]) ok = false;
  printf("  AES-128 via direct recorder vs plaintext  %s\n", ok ? "GOOD!" : "BAD!");
  return ok;
}

// Compress one pre-fed message into 256 output wire-carriers. The public IV is
// created here (public constants record CONST gates and never flush). Templated
// for both the ag2pc backend (Wire=AG2PCWire) and the clear backend (Wire=block).
template <typename Wire>
static void sha_compress(const UnsignedInt_T<Wire, 32> msg[16], Wire buf[256]) {
  using U = UnsignedInt_T<Wire, 32>;
  U state[8], m[16];
  for (int i = 0; i < 8; ++i) state[i] = U(sha256_detail::H0[i], PUBLIC);  // IV
  for (int j = 0; j < 16; ++j) m[j] = msg[j];
  sha256_compress<Wire>(state, m);
  for (int i = 0; i < 8; ++i)
    for (int b = 0; b < 32; ++b)
      buf[i * 32 + b] = state[i].bits[b].bit;
}

// ---- SHA-256 through the direct recorder vs plaintext -----------------------
// SHA_BLOCKS (env, default 50) independent compressions form ONE circuit; the
// default puts the COT count above 2^20 so the bucket sizer picks B=3 at ssp=40
// (the AND-dominated regime). SHA_CHECKPOINT=K>0 checkpoints every K compressions
// so peak gate-list memory stays at one chunk's worth (`msg` is scoped to die
// before each checkpoint, so keep_all drops it and only `buf` survives).
static bool sha_direct(int party, int port) {
  const char *env = getenv("SHA_BLOCKS");
  const int N = env ? atoi(env) : 50;
  const char *cenv = getenv("SHA_CHECKPOINT");
  const int K = cenv ? atoi(cenv) : 0;

  vector<array<uint32_t, 16>> blk(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j)
      blk[n][j] = 0x9e3779b9u * (uint32_t)(j + 1) + 0x01000193u * (uint32_t)n;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);
  io->flush();

  using AU = UnsignedInt_T<AG2PCWire, 32>;
  vector<AG2PCWire> buf(256 * N);
  if (K <= 0) {
    // Feed ALL secret inputs first, then record all N compressions (single chunk).
    vector<array<AU, 16>> msg(N);
    for (int n = 0; n < N; ++n)
      for (int j = 0; j < 16; ++j)
        msg[n][j] = AU((party == 2) ? blk[n][j] : 0, /*owner=*/2);
    for (int n = 0; n < N; ++n)
      sha_compress<AG2PCWire>(msg[n].data(), buf.data() + n * 256);
  } else {
    for (int c = 0; c < N; c += K) {
      int hi = (c + K < N) ? c + K : N;
      {
        vector<array<AU, 16>> msg(hi - c);
        for (int n = c; n < hi; ++n)
          for (int j = 0; j < 16; ++j)
            msg[n - c][j] = AU((party == 2) ? blk[n][j] : 0, /*owner=*/2);
        for (int n = c; n < hi; ++n)
          sha_compress<AG2PCWire>(msg[n - c].data(), buf.data() + n * 256);
      }  // msg out of scope -> its wires drop at the next checkpoint.
      checkpoint_ag2pc_keep_all();
    }
  }

  vector<bool> out_ag2pc(256 * N);
  {
    bool *o = new bool[256 * N];
    backend->reveal(o, 1, buf.data(), 256 * N);
    for (int i = 0; i < 256 * N; ++i) out_ag2pc[i] = o[i];
    delete[] o;
  }
  finalize_ag2pc();
  if (party != 1) return true;

  setup_clear_backend("");
  using CU = UnsignedInt_T<block, 32>;
  bool ok = true;
  for (int n = 0; n < N; ++n) {
    CU cmsg[16];
    for (int j = 0; j < 16; ++j) cmsg[j] = CU(blk[n][j], PUBLIC);
    block rbuf[256];
    sha_compress<block>(cmsg, rbuf);
    bool out_ref[256];
    backend->reveal(out_ref, 1, rbuf, 256);
    for (int b = 0; b < 256; ++b)
      ok = ok && (out_ag2pc[n * 256 + b] == out_ref[b]);
  }
  finalize_clear_backend();
  printf("  SHA-256 x %d via direct recorder (K=%d) vs plaintext  %s\n", N, K,
         ok ? "GOOD!" : "BAD!");
  return ok;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  bool ok = true;
  ok &= aes_direct(party, port + 0);
  ok &= sha_direct(party, port + 1);

  if (party == 1)
    printf("test_direct_crypto: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
