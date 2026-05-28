// Native SHA-256 compression (emp::sha256_compress<Wire>) authored in the Bit
// frontend and run through AG2PCBackend (record -> WireGraph -> C2PC). A larger
// circuit than AES (~24.7k ANDs). The 512-bit message block is a secret input
// of party 2; the IV (H0) is public, matching real SHA-256. Oracle: the same
// compression under setup_clear_backend(""), so we verify ag2pc == plaintext.
//
// SHA_BLOCKS (env var, default 50) compressions form ONE circuit of
// SHA_BLOCKS * ~24.7k ANDs — a knob for the AND-dominated regime. The default
// 50 puts L above 2^20 so the bucket sizer picks B=3 at the default ssp=40
// (any N ≥ 43 suffices; 50 leaves a small margin). All secret inputs are fed
// up front and a single reveal closes the circuit: a secret feed after the
// first gate, or a mid-circuit reveal, forces a chunk boundary that would
// carry every alive wire forward (O(N^2) if msg is still in scope).
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include "emp-ag2pc/ag2pc_backend.h"
using namespace std;
using namespace emp;

// Compress one pre-fed message into 256 output wire-carriers. The public IV is
// created here (public constants record no gates and never flush). Templated
// so the same helper compiles for both the ag2pc backend (Wire=AG2PCWire) and
// the clear backend (Wire=block).
template <typename Wire>
static void sha_compress(const UnsignedInt_T<Wire, 32> msg[16], Wire buf[256]) {
  using U = UnsignedInt_T<Wire, 32>;
  U state[8], m[16];
  for (int i = 0; i < 8; ++i) state[i] = U(sha256_detail::H0[i], PUBLIC);  // IV
  for (int j = 0; j < 16; ++j) m[j] = msg[j];
  sha256_compress<Wire>(state, m);
  // Copy each output Bit's wire-carrier (the .bit member) into buf via
  // assignment — for AG2PCWire that's a refcount-aware copy.
  for (int i = 0; i < 8; ++i)
    for (int b = 0; b < 32; ++b)
      buf[i * 32 + b] = state[i].bits[b].bit;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  const char *env = getenv("SHA_BLOCKS");
  const int N = env ? atoi(env) : 50;

  // N distinct blocks so each compression is independent (no trivial reuse).
  vector<array<uint32_t, 16>> blk(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j)
      blk[n][j] = 0x9e3779b9u * (uint32_t)(j + 1) + 0x01000193u * (uint32_t)n;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);
  io->flush();

  // SHA_CHECKPOINT=K (env, default 0=off): checkpoint every K compressions so
  // peak gate-list memory stays at one chunk's worth. `msg` is scoped to die
  // before the checkpoint so checkpoint_keep_all drops its wires automatically
  // — only `buf` (and any other still-pinned Bits) survives.
  const char *cenv = getenv("SHA_CHECKPOINT");
  const int K = cenv ? atoi(cenv) : 0;

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
    // Per-chunk: feed [c,hi) inputs, record their compressions, checkpoint
    // keeping every Bit still in scope (= buf's wires; msg dies first).
    for (int c = 0; c < N; c += K) {
      int hi = (c + K < N) ? c + K : N;
      {
        vector<array<AU, 16>> msg(hi - c);
        for (int n = c; n < hi; ++n)
          for (int j = 0; j < 16; ++j)
            msg[n - c][j] = AU((party == 2) ? blk[n][j] : 0, /*owner=*/2);
        for (int n = c; n < hi; ++n)
          sha_compress<AG2PCWire>(msg[n - c].data(), buf.data() + n * 256);
      }  // msg out of scope → its wires drop at the next checkpoint.
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
  // SHA_TRACE=1: dump the primary channel's per-direction transcript digest and
  // byte/round/flush counters (counters are randomness-invariant; digest is only
  // reproducible under EMP_TEST_MODE + single-thread). For wire-equivalence diffs.
  if (getenv("SHA_TRACE")) {
    auto hex = [](block b) { unsigned char c[16]; memcpy(c, &b, 16);
      std::string s; char t[3];
      for (int i = 0; i < 16; ++i) { snprintf(t, 3, "%02x", c[i]); s += t; }
      return s; };
    printf("[trace] party=%d send=%s recv=%s sent=%llu recv=%llu rounds=%llu "
           "flushes=%llu\n", party, hex(io->get_send_digest()).c_str(),
           hex(io->get_recv_digest()).c_str(),
           (unsigned long long)io->send_counter, (unsigned long long)io->recv_counter,
           (unsigned long long)io->rounds, (unsigned long long)io->flushes_count);
  }
  finalize_ag2pc();

  if (party == 1) {
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
    cout << "test_sha256 (" << N << " compression" << (N == 1 ? "" : "s")
         << ") vs plaintext: " << (ok ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
