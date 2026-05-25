// Native SHA-256 compression (emp::sha256_compress<Wire>) authored in the Bit
// frontend and run through WRKBackend (record -> WireGraph -> C2PC). A larger
// circuit than AES (~24.7k ANDs). The 512-bit message block is a secret input
// of party 2; the IV (H0) is public, matching real SHA-256. Oracle: the same
// compression under setup_clear_backend(""), so we verify WRK == plaintext.
//
// SHA_BLOCKS (env var, default 1) compressions form ONE circuit of
// SHA_BLOCKS * ~24.7k ANDs — a knob for the AND-dominated regime. All secret
// inputs are fed up front and a single reveal closes the circuit: a secret feed
// after the first gate, or a mid-circuit reveal, forces a chunk boundary
// (flush_keep_all) that would carry every prior wire forward (O(N^2)).
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/wrk_backend.h"
using namespace std;
using namespace emp;

const static int nP = 3;
using U = UnsignedInt_T<block, 32>;

// Compress one pre-fed message into 256 output wire-carriers. The public IV is
// created here (public constants record no gates and never flush).
static void sha_compress(const U msg[16], block buf[256]) {
  U state[8], m[16];
  for (int i = 0; i < 8; ++i) state[i] = U(sha256_detail::H0[i], PUBLIC);  // IV
  for (int j = 0; j < 16; ++j) m[j] = msg[j];
  sha256_compress<block>(state, m);
  for (int i = 0; i < 8; ++i)
    for (int b = 0; b < 32; ++b)
      memcpy(&buf[i * 32 + b], &state[i].bits[b], sizeof(block));
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > nP) return 0;

  const char *env = getenv("SHA_BLOCKS");
  const int N = env ? atoi(env) : 1;

  // N distinct blocks so each compression is independent (no trivial reuse).
  vector<array<uint32_t, 16>> blk(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j)
      blk[n][j] = 0x9e3779b9u * (uint32_t)(j + 1) + 0x01000193u * (uint32_t)n;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(2 * (nP - 1) + 2);
  setup_wrk_backend<nP>(&io, &pool, party);
  io.flush();

  // Feed ALL secret inputs first (party 2 owns the messages; others feed dummies),
  // then record all N compressions, then reveal every output bit in ONE call.
  vector<array<U, 16>> msg(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j)
      msg[n][j] = U((party == 2) ? blk[n][j] : 0, /*owner=*/2);

  vector<block> buf(256 * N);
  for (int n = 0; n < N; ++n) sha_compress(msg[n].data(), buf.data() + n * 256);

  vector<bool> out_wrk(256 * N);
  {
    bool *o = new bool[256 * N];
    backend->reveal(o, 1, buf.data(), 256 * N);
    for (int i = 0; i < 256 * N; ++i) out_wrk[i] = o[i];
    delete[] o;
  }
  finalize_wrk_backend();

  if (party == 1) {
    setup_clear_backend("");
    bool ok = true;
    for (int n = 0; n < N; ++n) {
      U cmsg[16];
      for (int j = 0; j < 16; ++j) cmsg[j] = U(blk[n][j], PUBLIC);
      block rbuf[256];
      sha_compress(cmsg, rbuf);
      bool out_ref[256];
      backend->reveal(out_ref, 1, rbuf, 256);
      for (int b = 0; b < 256; ++b)
        ok = ok && (out_wrk[n * 256 + b] == out_ref[b]);
    }
    finalize_clear_backend();
    cout << "wrk_sha256 (" << N << " compression" << (N == 1 ? "" : "s")
         << ") vs plaintext: " << (ok ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
