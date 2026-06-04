// Small SHA-256 benchmark/example for comparing object and stream modes.
//
// Env:
//   BENCH_MODE      all | object | stream-live | stream-compiled |
//                   stream-compiled-reuse                         (default all)
//   SHA_BLOCKS      number of independent SHA-256 compressions     (default 50)
//   SHA_CHECKPOINT  checkpoint/run every K compressions, 0 = one-shot (default 10)
#include "bench_sha_common.h"

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  const int N = getenv("SHA_BLOCKS") ? atoi(getenv("SHA_BLOCKS")) : 50;
  const int K = getenv("SHA_CHECKPOINT") ? atoi(getenv("SHA_CHECKPOINT")) : 10;
  const std::string sel = getenv("BENCH_MODE") ? getenv("BENCH_MODE") : "all";
  auto blk = make_sha_blocks(N);

  struct Named { const char *name; Row row; };
  std::vector<Named> out;
  int off = 0;
  auto maybe = [&](const char *name) {
    if (sel != "all" && sel != name) return;
    out.push_back({name, run_bench_mode(name, party, port + off, blk, N, K)});
    ++off;
  };
  maybe("object");
  maybe("stream-live");
  maybe("stream-compiled");
  maybe("stream-compiled-reuse");

  if (party != 1) return 0;
  if (out.empty()) {
    printf("bench_example: unknown BENCH_MODE=%s\n", sel.c_str());
    return 1;
  }

  std::vector<bool> ref = sha_oracle(blk, N);
  bool all_ok = true;
  printf("bench_example SHA-256 x %d  (BENCH_MODE=%s, SHA_CHECKPOINT=%d%s)\n",
         N, sel.c_str(), K, K <= 0 ? " [one-shot]" : "");
  for (auto &m : out) {
    bool ok = (m.row.out == ref);
    all_ok &= ok;
    printf("  %-16s wall=%9.1f ms  bytes=%8.2f MB  peakRSS=%8ld KiB  %s\n",
           m.name, m.row.wall_ms, m.row.mb, m.row.rss, ok ? "OK" : "BAD");
    if (m.row.compile_ms > 0)
      printf("  %-16s   (compile: %.1f ms, excluded from wall above)\n", "", m.row.compile_ms);
  }
  if (sel == "all")
    printf("  NOTE: peakRSS is cumulative across modes; use bench_100m for per-mode RSS.\n");
  return all_ok ? 0 : 1;
}
