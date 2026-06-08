# Performance — 100M-AND SHA-256 Chain

`bench_100m` is the current final-state AG2PC benchmark. It uses one
`AG2PCCtx`, the `Bits_T` value layer, and the stored `sha256_256` BooleanProgram
replayed through chunked live body sources.

## Workload

- Initial message: 32 zero bytes.
- Input ownership: bits `[0,128)` are authenticated from ALICE; bits `[128,256)`
  are authenticated from BOB in the same `input_batch()` phase.
- Circuit: repeat the `sha256_256` builtin until the requested AND target is met.
  The default run uses 404 SHA applications per protocol chunk, carrying only the
  256-bit digest into the next chunk.
- Correctness: ALICE compares the final digest with OpenSSL SHA-256 iterated the
  same number of times.

By default the benchmark targets at least 100,000,000 authenticated AND gates.
Override with:

```bash
SHA_ITERS=<iterations>     # exact number of SHA-256 applications
TARGET_ANDS=<and-count>    # used when SHA_ITERS is unset
SHA_CHUNK_ITERS=<iters>    # iterations per protocol chunk, default 404
BENCH_THREADS=<threads>    # protocol worker threads, default 4
```

## Build And Run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DEMP_AG2PC_BUILD_BENCHES=ON
cmake --build build --target bench_100m -j

# Full benchmark: defaults to TARGET_ANDS=100000000.
BENCH_THREADS=4 ./run ./build/bin/bench_100m

# Smoke test.
SHA_ITERS=1 SHA_CHUNK_ITERS=1 ./run ./build/bin/bench_100m
```

The benchmark prints the SHA iteration count, planned gate/AND counts, input
phase count, protocol chunk count, actual garbled AND count, wall-clock time,
throughput, total communication over both AG2PC sockets, peak RSS, and the OpenSSL
comparison.
