// SHA-256 in lambda mode. Mirrors test_sha256.cpp's shape: N independent
// compressions, optionally split into chunks of K via SHA_CHUNK env. Each
// chunk becomes one run_circuit call; the chunks themselves are independent
// (no state carry), so chunking just bounds per-call memory.
//
// Inputs: party 2 owns the message blocks (512 bits / compression). Public IV
// (H0) is synthesized inside the lambda via Bit(value, PUBLIC). Outputs:
// 256-bit compressed hash per compression, accumulated and decoded at the end.
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/lambda_runner.h"
#include "emp-ag2pc/lambda_circuit_types.h"   // installs Bit/Integer/... = *_T<LambdaWire>
#include "net_setup.h"

#include <chrono>
#include <sys/resource.h>

using namespace std;
using namespace emp;

// Get current peak resident set size in KiB (matching AG2PC_PROFILE's units).
static long peak_rss_kib() {
  rusage r;
  if (getrusage(RUSAGE_SELF, &r) != 0) return 0;
#ifdef __APPLE__
  return r.ru_maxrss / 1024;  // bytes on Darwin
#else
  return r.ru_maxrss;          // KiB on Linux
#endif
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  const char *env = getenv("SHA_BLOCKS");
  const int N = env ? atoi(env) : 50;
  const char *cenv = getenv("SHA_CHUNK");
  int K = cenv ? atoi(cenv) : N;
  if (K <= 0 || K > N) K = N;
  const int num_chunks = (N + K - 1) / K;

  // N distinct blocks so each compression is independent (no trivial reuse).
  vector<array<uint32_t, 16>> blk(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j)
      blk[n][j] = 0x9e3779b9u * (uint32_t)(j + 1) + 0x01000193u * (uint32_t)n;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();

  auto t0 = std::chrono::steady_clock::now();
  uint64_t bytes0 = (uint64_t)io->send_counter + io->recv_counter;

  // Accumulating output: 256 bits per compression, N compressions total.
  // We concatenate each chunk's output bundle and decode the whole thing once.
  SecureWires all_out;
  all_out.Lambda.reserve(256 * N);
  all_out.wire_bundle.reserve(256 * N);
  if (party == 1) all_out.label0.reserve(256 * N);
  else            all_out.eval_label.reserve(256 * N);

  for (int c = 0; c < N; c += K) {
    int hi = (c + K < N) ? c + K : N;
    int M = hi - c;                       // compressions this chunk

    // Pack 512*M bits for party 2's message inputs.
    std::vector<bool> msg_bits(512 * M);
    for (int n = c; n < hi; ++n)
      for (int j = 0; j < 16; ++j)
        for (int b = 0; b < 32; ++b)
          msg_bits[(n - c) * 512 + j * 32 + b] =
              (party == 2) ? (((blk[n][j] >> b) & 1u) != 0) : false;

    auto in_per_owner = mpc.process_inputs({/*owner=*/2}, {msg_bits});
    SecureWires &in_wires = in_per_owner[0];

    LambdaRunner runner(&mpc);
    SecureWires chunk_out = runner.run_circuit(
        in_wires, /*n_out=*/256 * M,
        [M](const std::vector<Bit> &in, std::vector<Bit> &out) {
          using U = UnsignedInt_T<LambdaWire, 32>;
          for (int n = 0; n < M; ++n) {
            U state[8], m[16];
            // IV — public constants synthesized fresh each compression.
            for (int i = 0; i < 8; ++i) state[i] = U(sha256_detail::H0[i], PUBLIC);
            // Pack input message bits into 16 x 32-bit message words.
            for (int j = 0; j < 16; ++j)
              for (int b = 0; b < 32; ++b)
                m[j].bits[b] = in[n * 512 + j * 32 + b];
            sha256_compress<LambdaWire>(state, m);
            for (int i = 0; i < 8; ++i)
              for (int b = 0; b < 32; ++b)
                out[n * 256 + i * 32 + b] = state[i].bits[b];
          }
        });

    // Concatenate this chunk's output into all_out.
    all_out.Lambda.insert(all_out.Lambda.end(),
                          chunk_out.Lambda.begin(), chunk_out.Lambda.end());
    all_out.wire_bundle.insert(all_out.wire_bundle.end(),
                               chunk_out.wire_bundle.begin(),
                               chunk_out.wire_bundle.end());
    if (party == 1)
      all_out.label0.insert(all_out.label0.end(),
                            chunk_out.label0.begin(), chunk_out.label0.end());
    else
      all_out.eval_label.insert(all_out.eval_label.end(),
                                chunk_out.eval_label.begin(),
                                chunk_out.eval_label.end());
  }

  // Decode the full 256*N output once.
  std::vector<bool> out_ag2pc = mpc.decode(all_out, /*to=*/1);

  auto t1 = std::chrono::steady_clock::now();
  double wall_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  uint64_t bytes1 = (uint64_t)io->send_counter + io->recv_counter;
  uint64_t bytes = bytes1 - bytes0;
  long peak = peak_rss_kib();

  if (party == 1) {
    setup_clear_backend("");
    using CU = UnsignedInt_T<block, 32>;
    bool ok = true;
    for (int n = 0; n < N; ++n) {
      CU cmsg[16];
      for (int j = 0; j < 16; ++j) cmsg[j] = CU(blk[n][j], PUBLIC);
      using CB = Bit_T<block>;
      CU state[8];
      for (int i = 0; i < 8; ++i) state[i] = CU(sha256_detail::H0[i], PUBLIC);
      sha256_compress<block>(state, cmsg);
      block rbuf[256];
      for (int i = 0; i < 8; ++i)
        for (int b = 0; b < 32; ++b)
          rbuf[i * 32 + b] = state[i].bits[b].bit;
      bool out_ref[256];
      backend->reveal(out_ref, 1, rbuf, 256);
      for (int b = 0; b < 256; ++b)
        ok = ok && (out_ag2pc[n * 256 + b] == out_ref[b]);
    }
    finalize_clear_backend();
    printf("[lambda] N=%d K=%d chunks=%d  wall=%.1f ms  bytes=%.2f MB  peakRSS=%ld KiB  %s\n",
           N, K, num_chunks, wall_ms, bytes / 1048576.0, peak,
           ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  } else {
    printf("[lambda P2] N=%d K=%d chunks=%d  wall=%.1f ms  bytes=%.2f MB  peakRSS=%ld KiB\n",
           N, K, num_chunks, wall_ms, bytes / 1048576.0, peak);
  }
  return 0;
}
