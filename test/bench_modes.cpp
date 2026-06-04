// Benchmark: the SAME SHA-256 x N circuit run three ways, timing wall + bytes
// (+ peak RSS), to compare the two FRONTEND front-doors (compiled / live) against
// the DIRECT recorder. All three run on the one streaming engine (run_engine_):
// the direct recorder is just an imperative adapter that buffers each chunk into
// a frontend::BooleanProgram and replays it via run_program. Mirrors test_sha256's
// shape and knobs.
//
// Inputs are processed ONCE, up front; there is no per-compression (fine-grained)
// chunking. A coarse chunk level is USER-SPECIFIED via SHA_CHECKPOINT=K, exactly
// like test_sha256:
//   K = 0 (default): one-shot — the whole N-block circuit in a single chunk
//                    (direct recorder) / single run_engine_ call (frontend), one reveal.
// ALL inputs are processed ONCE, at the very beginning, in every mode — K only
// segments the COMPUTATION, never the input processing:
//   K > 0:           checkpoint/flush every K compressions.
//                    - direct-chunked: all inputs fed up front (held live), then
//                      checkpoint_keep_all() every K compressions.
//                    - frontend: one process_inputs for all N up front, then the
//                      input bundle is SLICED into K-block pieces, one run per
//                      slice, decoded once. No per-chunk input processing.
//
// Modes (BENCH_MODE; default "all"): direct-chunked, frontend-compiled, frontend-live.
//
// RSS NOTE: getrusage ru_maxrss is the PROCESS-lifetime peak, meaningful per-mode
// only when each mode runs in its OWN process — set BENCH_MODE to a single mode
// for clean memory numbers. BENCH_MODE=all is cumulative/order-dependent (flagged).
//
// 2-party: party 1 server; party 2 dials AG2PC_PEER (or 127.0.0.1). Same plaintext
// inputs + oracle as test_sha256. Env: SHA_BLOCKS (N, default 50), SHA_CHECKPOINT
// (K, default 0), BENCH_MODE.
// This benchmark spans the direct backend AND the function engine, so it uses
// internal headers + its own `block` circuit-type binding — NOT direct.h or
// function.h (whose mode aliases would collide with block here).
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/frontend/ag2pc.h"        // setup_ag2pc + direct AG2PCBackend (pulls session + engine)
#include "emp-tool/frontend/frontend.h"
EMP_USE_CIRCUIT_TYPES_ALL(block)              // bench's own binding (expert; not the public set)
#include "net_setup.h"
#include <chrono>
#include <string>
#include <sys/resource.h>
using namespace std;
using namespace emp;

static long peak_rss_kib() {
  rusage r;
  if (getrusage(RUSAGE_SELF, &r) != 0) return 0;
#ifdef __APPLE__
  return r.ru_maxrss / 1024;
#else
  return r.ru_maxrss;
#endif
}
using clk = std::chrono::steady_clock;
static double ms_since(clk::time_point t0) {
  return std::chrono::duration<double, std::milli>(clk::now() - t0).count();
}
static uint64_t io_bytes(NetIO *io) { return (uint64_t)io->send_counter + io->recv_counter; }

// Wire-generic SHA-256 x M body: 512*M-bit message in, 256*M-bit hash out.
struct ShaFn {
  int M;
  template <class W>
  BitVec_T<W> operator()(BitVec_T<W> msg) const {
    using U = UnsignedInt_T<W, 32>;
    BitVec_T<W> out(256 * M);
    for (int n = 0; n < M; ++n) {
      U state[8], m[16];
      for (int i = 0; i < 8; ++i) state[i] = U(sha256_detail::H0[i], PUBLIC);
      for (int j = 0; j < 16; ++j)
        for (int b = 0; b < 32; ++b) m[j].bits[b] = msg[n * 512 + j * 32 + b];
      sha256_compress<W>(state, m);
      for (int i = 0; i < 8; ++i)
        for (int b = 0; b < 32; ++b) out[n * 256 + i * 32 + b] = state[i].bits[b];
    }
    return out;
  }
};

// Message bits for blocks [lo, lo+cnt): party 2's real bits, 0 for party 1.
static std::vector<bool> block_bits(int party, const vector<array<uint32_t, 16>> &blk,
                                    int lo, int cnt) {
  std::vector<bool> v(512 * cnt, false);
  if (party == 2)
    for (int k = 0; k < cnt; ++k)
      for (int j = 0; j < 16; ++j)
        for (int b = 0; b < 32; ++b)
          v[k * 512 + j * 32 + b] = ((blk[lo + k][j] >> b) & 1u) != 0;
  return v;
}
static void append_bundle(SecureWires &dst, const SecureWires &s, int party) {
  dst.Lambda.insert(dst.Lambda.end(), s.Lambda.begin(), s.Lambda.end());
  dst.wire_bundle.insert(dst.wire_bundle.end(), s.wire_bundle.begin(), s.wire_bundle.end());
  if (party == 1) dst.label0.insert(dst.label0.end(), s.label0.begin(), s.label0.end());
  else dst.eval_label.insert(dst.eval_label.end(), s.eval_label.begin(), s.eval_label.end());
}

struct Row { double wall_ms = 0, mb = 0, compile_ms = 0; long rss = 0; std::vector<bool> out; };

// ---- direct-chunked: the direct recorder. ALL inputs fed at the very beginning (held
//      live), then checkpoint_keep_all() every K compressions (K<=0 = one chunk)
//      — chunking segments only the computation, matching the frontend. One
//      reveal at the end. ----
static Row run_backend(int party, int port, const vector<array<uint32_t, 16>> &blk, int N, int K) {
  Row r;
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);
  io->flush();
  using U = UnsignedInt_T<AG2PCWire, 32>;
  uint64_t b0 = io_bytes(io);
  auto t0 = clk::now();
  // All secret inputs up front (held live for the whole run).
  vector<array<U, 16>> msg(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j) msg[n][j] = U((party == 2) ? blk[n][j] : 0u, 2);
  std::vector<AG2PCWire> buf(256 * N);
  for (int n = 0; n < N; ++n) {
    U state[8], m[16];
    for (int i = 0; i < 8; ++i) state[i] = U(sha256_detail::H0[i], PUBLIC);
    for (int j = 0; j < 16; ++j) m[j] = msg[n][j];
    sha256_compress<AG2PCWire>(state, m);
    for (int i = 0; i < 8; ++i)
      for (int b = 0; b < 32; ++b) buf[n * 256 + i * 32 + b] = state[i].bits[b].bit;
    if (K > 0 && (n + 1) % K == 0 && n + 1 < N) checkpoint_ag2pc_keep_all();
  }
  bool *obuf = new bool[256 * N]();
  backend->reveal(obuf, 1, buf.data(), 256 * N);
  r.wall_ms = ms_since(t0);
  r.mb = (io_bytes(io) - b0) / 1048576.0;
  r.rss = peak_rss_kib();
  if (party == 1) r.out.assign(obuf, obuf + 256 * N);
  delete[] obuf;
  finalize_ag2pc();
  return r;
}

// ---- frontend: ONE process_inputs for all N up front, then slice the bundle
//      into K-block pieces and run each (K<=0 = one run), decode once. Inputs are
//      processed once at the very beginning; chunking segments only compute. ----
template <bool COMPILED>
static Row run_frontend(int party, int port, const vector<array<uint32_t, 16>> &blk, int N, int K) {
  Row r;
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  C2PC mpc(io, &pool, party);
  io->flush();
  LambdaRunner runner(&mpc);
  const int step = (K > 0) ? K : N;
  const int tail = N % step;                     // size of a final partial chunk (0 if none)

  // Compile the per-chunk circuit(s) ONCE, excluded from the crypto wall.
  using RC = frontend::TypedCircuit<BitVec_T<frontend::RecWire>>;
  RC c_full{}, c_tail{};
  if (COMPILED) {
    auto ct = clk::now();
    c_full = frontend::compile(ShaFn{step}, BitVec(512 * step));
    if (tail) c_tail = frontend::compile(ShaFn{tail}, BitVec(512 * tail));
    r.compile_ms = ms_since(ct);
  }

  uint64_t b0 = io_bytes(io);
  auto t0 = clk::now();
  auto in = mpc.process_inputs({2}, {block_bits(party, blk, 0, N)});  // all inputs, once
  const SecureWires &full = in[0];
  SecureWires all_out;
  for (int c = 0; c < N; c += step) {
    int M = std::min(step, N - c);
    SecureWires sub = full.slice((size_t)c * 512, (size_t)(c + M) * 512);  // no re-process
    SecureWires ow;
    if (COMPILED) ow = runner.run_compiled<BitVec>(M == step ? c_full : c_tail, {sub});
    else          ow = runner.run<BitVec>({sub}, ShaFn{M});
    append_bundle(all_out, ow, party);
  }
  std::vector<bool> out = mpc.decode(all_out, 1);                    // single decode
  r.wall_ms = ms_since(t0);
  r.mb = (io_bytes(io) - b0) / 1048576.0;
  r.rss = peak_rss_kib();
  if (party == 1) r.out = std::move(out);
  return r;
}

static std::vector<bool> sha_oracle(const vector<array<uint32_t, 16>> &blk, int N) {
  setup_clear_backend("");
  std::vector<bool> ref(256 * N);
  using CU = UnsignedInt_T<block, 32>;
  for (int n = 0; n < N; ++n) {
    CU state[8], m[16];
    for (int i = 0; i < 8; ++i) state[i] = CU(sha256_detail::H0[i], PUBLIC);
    for (int j = 0; j < 16; ++j) m[j] = CU(blk[n][j], PUBLIC);
    sha256_compress<block>(state, m);
    block rbuf[256];
    for (int i = 0; i < 8; ++i)
      for (int b = 0; b < 32; ++b) rbuf[i * 32 + b] = state[i].bits[b].bit;
    bool obuf[256];
    backend->reveal(obuf, 1, rbuf, 256);
    for (int b = 0; b < 256; ++b) ref[n * 256 + b] = obuf[b];
  }
  finalize_clear_backend();
  return ref;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;
  const int N = getenv("SHA_BLOCKS") ? atoi(getenv("SHA_BLOCKS")) : 50;
  const int K = getenv("SHA_CHECKPOINT") ? atoi(getenv("SHA_CHECKPOINT")) : 0;
  const std::string sel = getenv("BENCH_MODE") ? getenv("BENCH_MODE") : "all";

  vector<array<uint32_t, 16>> blk(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j)
      blk[n][j] = 0x9e3779b9u * (uint32_t)(j + 1) + 0x01000193u * (uint32_t)n;

  struct Named { const char *name; Row row; };
  std::vector<Named> out;
  int off = 0;
  auto maybe = [&](const char *name, auto fn) {
    if (sel != "all" && sel != name) return;
    out.push_back({name, fn(party, port + off, blk, N, K)});
    ++off;
  };
  maybe("direct-chunked",    run_backend);
  maybe("frontend-compiled", run_frontend<true>);
  maybe("frontend-live",     run_frontend<false>);

  if (party != 1) return 0;
  if (out.empty()) { printf("bench_modes: unknown BENCH_MODE=%s\n", sel.c_str()); return 1; }

  std::vector<bool> ref = sha_oracle(blk, N);
  bool all_ok = true;
  printf("bench_modes SHA-256 x %d  (BENCH_MODE=%s, SHA_CHECKPOINT=%d%s)\n",
         N, sel.c_str(), K, K <= 0 ? " [one-shot]" : "");
  for (auto &m : out) {
    bool ok = (m.row.out == ref);
    all_ok &= ok;
    printf("  %-18s wall=%9.1f ms  bytes=%8.2f MB  peakRSS=%8ld KiB  %s\n",
           m.name, m.row.wall_ms, m.row.mb, m.row.rss, ok ? "OK" : "BAD");
    if (m.row.compile_ms > 0)
      printf("  %-18s   (compile: %.1f ms, excluded from wall above)\n", "", m.row.compile_ms);
  }
  if (sel == "all")
    printf("  NOTE: peakRSS is process-cumulative here (BENCH_MODE=all); rerun a\n"
           "        single BENCH_MODE per process for a clean per-mode memory number.\n");
  return all_ok ? 0 : 1;
}
