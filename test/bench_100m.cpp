// Large SHA-256 benchmark harness with one mode per process.
//
// Env:
//   BENCH_MODE      object | stream-live | stream-compiled |
//                   stream-compiled-reuse                         (required)
//   SHA_BLOCKS      number of independent SHA-256 compressions      (default 4040)
//   SHA_CHECKPOINT  checkpoint/run every K compressions             (default 404)
//
// Output is CSV-ish and stable:
//   mode,sha_blocks,checkpoint,wall_ms,bytes_mb,peak_rss_kib,compile_ms,ok
#include "bench_sha_common.h"

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  const char *mode_env = getenv("BENCH_MODE");
  const std::string mode = mode_env ? mode_env : "";
  if (!is_bench_mode(mode)) {
    if (party == 1)
      printf("bench_100m: set BENCH_MODE=object|stream-live|stream-compiled|stream-compiled-reuse\n");
    return 1;
  }

  const int N = getenv("SHA_BLOCKS") ? atoi(getenv("SHA_BLOCKS")) : 4040;
  const int K = getenv("SHA_CHECKPOINT") ? atoi(getenv("SHA_CHECKPOINT")) : 404;
  auto blk = make_sha_blocks(N);

  Row row = run_bench_mode(mode, party, port, blk, N, K);
  if (party != 1) return 0;

  std::vector<bool> ref = sha_oracle(blk, N);
  bool ok = (row.out == ref);
  printf("mode,sha_blocks,checkpoint,wall_ms,bytes_mb,peak_rss_kib,compile_ms,ok\n");
  printf("%s,%d,%d,%.1f,%.2f,%ld,%.1f,%d\n",
         mode.c_str(), N, K, row.wall_ms, row.mb, row.rss, row.compile_ms,
         ok ? 1 : 0);
  return ok ? 0 : 1;
}
