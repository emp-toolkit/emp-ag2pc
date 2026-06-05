#ifndef AG2PC_BENCH_SHA_COMMON_H__
#define AG2PC_BENCH_SHA_COMMON_H__

// Shared SHA benchmark machinery. SHA_CHECKPOINT chunks computation only; all
// modes process the input bundle once up front.
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/sha256_circuit.h"
#include "emp-ag2pc/frontend/ag2pc.h"
#include "emp-tool/frontend/frontend.h"
EMP_CIRCUIT_TYPES_ALL(block)
#include "net_setup.h"
#include <chrono>
#include <string>
#include <sys/resource.h>
using namespace std;
using namespace emp;

// Worker-thread count for the protocol's ThreadPool. Override with BENCH_THREADS
// (default 4) to study thread scaling.
static int bench_threads() {
  const char *e = getenv("BENCH_THREADS");
  return e ? atoi(e) : 4;
}

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

// Wire-generic SHA-256 x M body.
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

// stream-compiled-reuse compiles one SHA compression and replays it inside each chunk.
template <class W>
static BitVec_T<W> run_compiled_sha_blocks(
    const frontend::TypedCircuit<BitVec_T<frontend::RecWire>> &sha_block,
    BitVec_T<W> msg, int M) {
  BitVec_T<W> out(256 * M);
  for (int n = 0; n < M; ++n) {
    BitVec_T<W> h = frontend::run(sha_block, msg.slice(n * 512, (n + 1) * 512));
    for (int i = 0; i < 256; ++i) out[n * 256 + i] = h[i];
  }
  return out;
}

// Message bits for blocks [lo, lo+cnt).
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

// Object mode.
static Row run_object(int party, int port, const vector<array<uint32_t, 16>> &blk, int N, int K) {
  Row r;
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(bench_threads());
  setup_ag2pc(io, &pool, party);
  io->flush();
  using U = UnsignedInt_T<AG2PCWire, 32>;
  uint64_t b0 = io_bytes(io);
  auto t0 = clk::now();
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

enum class BenchStreamMode { Live, Compiled, CompiledReuse };

// Stream mode.
template <BenchStreamMode MODE>
static Row run_stream(int party, int port, const vector<array<uint32_t, 16>> &blk, int N, int K) {
  Row r;
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(bench_threads());
  AG2PCSession mpc(io, &pool, party);
  io->flush();
  AG2PCEngine runner(&mpc);
  const int step = (K > 0) ? K : N;

  using RC = frontend::TypedCircuit<BitVec_T<frontend::RecWire>>;
  RC c_full{}, c_tail{}, c_block{};
  if constexpr (MODE == BenchStreamMode::Compiled) {
    const int tail = N % step;
    auto ct = clk::now();
    c_full = frontend::compile(ShaFn{step}, BitVec(512 * step));
    if (tail) c_tail = frontend::compile(ShaFn{tail}, BitVec(512 * tail));
    r.compile_ms = ms_since(ct);
  } else if constexpr (MODE == BenchStreamMode::CompiledReuse) {
    auto ct = clk::now();
    c_block = frontend::compile(ShaFn{1}, BitVec(512));
    r.compile_ms = ms_since(ct);
  }

  uint64_t b0 = io_bytes(io);
  auto t0 = clk::now();
  auto in = mpc.process_inputs({2}, {block_bits(party, blk, 0, N)});
  const SecureWires &full = in[0];
  SecureWires all_out;
  for (int c = 0; c < N; c += step) {
    int M = std::min(step, N - c);
    SecureWires sub = full.slice((size_t)c * 512, (size_t)(c + M) * 512);
    SecureWires ow;
    if constexpr (MODE == BenchStreamMode::Compiled) {
      ow = runner.run_compiled<BitVec>(M == step ? c_full : c_tail, {sub});
    } else if constexpr (MODE == BenchStreamMode::CompiledReuse) {
      ow = runner.run<BitVec>(
          {sub}, [&c_block, M](auto msg) {
            return run_compiled_sha_blocks(c_block, msg, M);
          });
    } else {
      ow = runner.run<BitVec>({sub}, ShaFn{M});
    }
    append_bundle(all_out, ow, party);
  }
  std::vector<bool> out = mpc.decode(all_out, 1);
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

static vector<array<uint32_t, 16>> make_sha_blocks(int N) {
  vector<array<uint32_t, 16>> blk(N);
  for (int n = 0; n < N; ++n)
    for (int j = 0; j < 16; ++j)
      blk[n][j] = 0x9e3779b9u * (uint32_t)(j + 1) + 0x01000193u * (uint32_t)n;
  return blk;
}

static bool is_bench_mode(const std::string &mode) {
  return mode == "object" || mode == "stream-live" || mode == "stream-compiled" ||
         mode == "stream-compiled-reuse";
}

static Row run_bench_mode(const std::string &mode, int party, int port,
                          const vector<array<uint32_t, 16>> &blk, int N, int K) {
  if (mode == "object") return run_object(party, port, blk, N, K);
  if (mode == "stream-live") return run_stream<BenchStreamMode::Live>(party, port, blk, N, K);
  if (mode == "stream-compiled") return run_stream<BenchStreamMode::Compiled>(party, port, blk, N, K);
  if (mode == "stream-compiled-reuse")
    return run_stream<BenchStreamMode::CompiledReuse>(party, port, blk, N, K);
  error("unknown bench mode");
  return {};
}

#endif  // AG2PC_BENCH_SHA_COMMON_H__
