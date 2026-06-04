# Performance — 100-million-gate maliciously-secure 2PC

A detailed, reproducible benchmark of emp-ag2pc on a ~100 M-AND-gate circuit, with
a stage-by-stage cost breakdown so each bottleneck is attributable.

- **What it is:** maliciously-secure two-party computation via authenticated
  garbling (WRK17 + the KRRW18 optimizations). No semi-honest assumption, no
  trusted setup; the consistency check gates every output reveal.
- **Workload:** SHA-256 compressed **4,040×** = **99,966,560 AND gates** (~100 M)
  plus ~470 M free XOR/NOT gates. Verified against a cleartext SHA-256 oracle.
- **Headline:** **~2.0–2.3 M authenticated AND gates/sec** between two cloud
  machines using **2 worker threads**, **~113 bytes/AND** of communication, and a
  resident set that **fits in 8 GB** (chunk-size–tunable).

Two machine configurations were measured:

| Config | Instances | vCPU | RAM | Worker threads |
|---|---|--:|--:|--:|
| **A** | 2× AWS `m8a.8xlarge` (AMD EPYC) | 32 | 123 GB | 4 |
| **B** | 2× AWS `m8a.large` (AMD EPYC)   | 2  | 8 GB  | 2 |

Two parties on separate machines, same VPC/subnet (private-IP link), us-east-1.

---

## 1. Results

All runs: `SHA_BLOCKS=4040`, `SHA_CHECKPOINT=404` (10 chunks) unless noted; bytes
are the primary channel's send+recv at party 1; RSS is `getrusage` peak (GiB =
KiB/2²⁰); throughput = 99,966,560 / wall.

### Config A — 32 vCPU, 4 threads (123 GB box)

| Mode | Wall | Throughput | Comm | Peak RSS | Compile |
|---|--:|--:|--:|--:|--:|
| `object`                 | 93.5 s | 1.07 M AND/s | 10.8 GiB | 6.16 GiB | — |
| `stream-live`            | 53.3 s | 1.88 M AND/s | 10.8 GiB | **3.58 GiB** | — |
| `stream-compiled`        | 55.8 s | 1.79 M AND/s | 10.8 GiB | 7.49 GiB | 3.0 s |
| `stream-compiled-reuse`  | **49.2 s** | **2.03 M AND/s** | 10.8 GiB | 3.60 GiB | 6.5 ms |

### Config B — 2 vCPU, 2 threads (8 GB box)

| Mode | Wall | Throughput | Peak RSS | Fits 8 GB? | Compile |
|---|--:|--:|--:|---|--:|
| `object`                 | 86.3 s | 1.16 M AND/s | 6.16 GiB | ✓ | — |
| `stream-live`            | **44.9 s** | **2.23 M AND/s** | 3.58 GiB | ✓ | — |
| `stream-compiled` (K=404)| —      | —            | ~7.2 GiB | ✗ **OOM-killed** | — |
| `stream-compiled` (K=202)| 47.2 s | 2.12 M AND/s | 3.90 GiB | ✓ | 1.5 s |
| `stream-compiled-reuse`  | 44.1 s | 2.27 M AND/s | 3.60 GiB | ✓ | 6.5 ms |

Two findings, expanded in §3:

1. **~2 threads is the effective parallelism.** Config B (2 threads / 2 cores) is
   *as fast or faster* than Config A (4 threads / 32 cores) — the extra
   threads/cores buy nothing; the small box just has a higher per-core clock and
   no cross-core contention.
2. **100 M gates fit in 8 GB**, and the chunk size (`SHA_CHECKPOINT`) is the
   memory dial: the lean modes fit at the default; `stream-compiled` needs
   K≈202 (20 chunks) instead of 404.

---

## 2. The four modes

All four express the *same* SHA circuit and run the *same* protocol over the one
engine (`run_engine_`); they differ only in how the circuit is fed to it.

| Mode | Front-end | What it does |
|---|---|---|
| `object` | imperative (`AG2PCBackend`) | Write straight-line EMP-object code; it records gates, dead-code-eliminates + chunks them into a `BooleanProgram`, and runs each chunk on the engine. |
| `stream-live` | engine, live body | A pure wire-generic body replayed per phase, per chunk. No gate list materialized. |
| `stream-compiled` | engine, compiled chunk | `frontend::compile` the whole K-compression chunk once, replay the recorded program. |
| `stream-compiled-reuse` | engine, compiled unit | Compile **one** SHA compression once, replay it K× inside each chunk. |

---

## 3. Where the time goes (bottleneck analysis)

Per-stage engine timings, **summed over the 10 chunks**, for Config A (the most
detailed run). ns/AND is over 99,966,560 ANDs. Stage names are the `[ag2pc]`
profiling markers.

| Stage (engine phase) | `object` | `stream-live` | `stream-compiled` | `reuse` |
|---|--:|--:|--:|--:|
| process_inputs | 0.17 s | 0.19 s | 0.20 s | 0.18 s |
| liveness + load_inputs | 4.24 s · 42 | 3.79 s · 38 | 4.37 s · 44 | 3.71 s · 37 |
| fused (slot assign + collect masks) | 12.64 s · 126 | 12.20 s · 122 | 12.28 s · 123 | 12.20 s · 122 |
| **inplace_triples (leaky-AND)** | **26.11 s · 261** | **26.31 s · 263** | **26.51 s · 265** | **22.74 s · 228** |
| garble / evaluate (steps 6–10) | 7.51 s · 75 | 6.95 s · 70 | 8.21 s · 82 | 6.76 s · 68 |
| check c_γ (KRRW Fig.3) | 3.63 s · 36 | 3.15 s · 32 | 3.63 s · 36 | 2.99 s · 30 |
| cot_check / gather / decode | <0.07 s | <0.05 s | <0.04 s | <0.05 s |
| **engine total** | **54.4 s** | **52.6 s** | **55.2 s** | **48.6 s** |

(`·N` = ns/AND.) The engine profile is near-identical across modes — confirming
one shared executor. The **leaky-AND triple generation is ~half the time**; its
sub-phases (`[ag2pc-tp]`, summed over chunks, Config A):

| Leaky-AND sub-phase | `object` | `stream-live` | `stream-compiled` | `reuse` |
|---|--:|--:|--:|--:|
| half-gate join (MITCCRH H(·)) | 12.55 s · 126 | 12.50 s · 125 | 12.82 s · 128 | **9.32 s · 93** |
| COT extend (SoftSpoken⟨4⟩) | 6.20 s · 62 | 6.22 s · 62 | 6.19 s · 62 | 6.21 s · 62 |
| F_eq (batched check) | 2.20 s · 22 | 2.20 s · 22 | 2.21 s · 22 | 2.18 s · 22 |
| bucket layers (cyclic-shift) | 1.17 s · 12 | 1.20 s · 12 | 1.18 s · 12 | 1.18 s · 12 |
| s-open + combine | 0.90 s · 9 | 0.94 s · 9 | 0.94 s · 9 | 0.75 s · 8 |

### What bounds each part

- **`inplace_triples` (~261 ns/AND, ~50% of the engine) — the malicious-security
  core.** Generating an authenticated AND triple per gate. Two sub-costs lead:
  - **half-gate join (~125 ns/AND): compute-bound** on the MITCCRH hash (fixed-key
    AES) used by the function-dependent leaky-AND. This is the single largest line.
  - **COT extend (~62 ns/AND): bandwidth/compute-bound** on SoftSpoken⟨4⟩ correlated
    OT (≈7 COTs/AND ⇒ the bulk of the wire traffic).
  - F_eq, bucketing, s-open are minor (~22/12/9 ns/AND).
- **`fused` (~123 ns/AND, ~23%) — memory-bound.** One sweep that assigns each wire
  a physical slot (recycling XOR/NOT scratch) and materializes per-AND input masks;
  dominated by streaming the share bundles, not crypto.
- **`garble/evaluate` (~70–82 ns/AND, ~14%) — the online half-gate tables** (2
  ciphertexts/AND, streamed). The garbler (party 1) view shown; slightly higher in
  `stream-compiled` (extra program-walk indirection).
- **`liveness + load_inputs` (~40 ns/AND, ~8%)** — a value-free pre-pass that
  computes wire lifetimes so per-wire state stays linear in live width, not #wires.
- **`check c_γ` (~33 ns/AND, ~7%)** — the KRRW Fig.3 correctness check (one round +
  digest per chunk) that gates output.
- process_inputs / decode / cot_check are negligible (<2 ns/AND each).

### Cross-mode differences (everything outside the engine)

- **`object` wall (93.5 s) − engine (54.4 s) ≈ 39 s of recording**: building and
  dead-code-eliminating the `BooleanProgram` chunks in memory. This is pure
  bookkeeping outside the protocol — the entire gap between `object` and the stream
  modes. (It is also why `object` is the slowest despite identical crypto.)
- **`stream-live` adds ≈0**: wall 53.3 s ≈ engine 52.6 s — replaying a pure body is
  essentially free.
- **`stream-compiled` adds a one-time compile** (3.0 s for a 404-compression chunk)
  and the most memory (holds that compiled program resident).
- **`stream-compiled-reuse` is the fastest** (engine 48.6 s): compiling one tiny
  compression and replaying it shrinks the resident gate stream, and the
  **half-gate join drops to ~93 ns/AND (from ~125)** — an i-cache/d-cache locality
  win from hashing over a small, hot program instead of a 100 M-gate stream.

### Communication (~113 bytes/AND)

Total primary-channel traffic is **~10.8 GiB** for all modes (same circuit, same
protocol). By stage, traffic concentrates almost entirely in:
- **triple generation** (COT extension + garbled-table-independent material + bucket
  d-opens) — ~80% of bytes,
- **online garble/evaluate** (2 ciphertexts/AND) — ~17%,
- everything else (inputs, c_γ check, decode) — <1% combined.

(The per-stage byte counters in the raw profile count both duplex channels and a
cumulative COT counter, so they overcount vs the 10.8 GiB primary-channel figure;
the proportions above are the reliable takeaway.)

### Memory (set by chunk size, not threads)

Peak RSS is identical across the 4-thread and 2-thread runs — it is a function of
the **chunk** (`SHA_CHECKPOINT=K`), not the machine:

- `stream-live` / `reuse`: ~3.6 GiB at K=404 — the engine's per-chunk slot-reused
  wire/AND state for one ~10 M-AND chunk. No gate list resident.
- `object`: ~6.2 GiB — the engine chunk state **plus** the recorder's per-chunk gate
  log + per-wire metadata.
- `stream-compiled`: ~7.5 GiB at K=404 — engine chunk state **plus** the resident
  compiled `BooleanProgram` for the whole 404-compression chunk. This is what OOMs
  an 8 GB box; halving K (K=202, 20 chunks) roughly halves both terms → 3.9 GiB.

**Rule of thumb:** peak RSS scales ~linearly with K. Pick K so the per-chunk
resident set fits your RAM budget; a 100 M-gate circuit fits 8 GB at K≤~200
(compiled) or the default K=404 (live/reuse/object).

---

## 4. Thread scaling — only ~2 threads are used

Comparing the same modes across Config A (4 threads / 32 cores) and Config B (2
threads / 2 cores):

| Mode | A: 4 thr / 32 vCPU | B: 2 thr / 2 vCPU |
|---|--:|--:|
| `object` | 93.5 s | **86.3 s** |
| `stream-live` | 53.3 s | **44.9 s** |
| `stream-compiled-reuse` | 49.2 s | **44.1 s** |
| engine `inplace_triples` | ~26 s | **~20–21 s** |

The 2-thread box is **faster**, not slower. The protocol's effective parallelism is
the **duplex send/recv pair (~2 threads)**; beyond that, extra `ThreadPool` workers
and extra cores don't help this workload, and on the 32-vCPU box add a little
cross-core contention. Practical takeaway: **2 fast cores per party suffice.**

---

## 5. Reproducing

### 5.1 Build

emp-ag2pc is header-only; build emp-tool and emp-ot (≥1.0) first. To get the
per-stage `[ag2pc]` / `[ag2pc-tp]` numbers, configure the bench with
`-DAG2PC_PROFILE` (zero-cost when off; <1% overhead when on).

```bash
PREFIX=$HOME/inst
# emp-tool, emp-ot -> install to $PREFIX
cmake -S emp-tool -B emp-tool/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX
cmake --build emp-tool/build --target install -j
cmake -S emp-ot   -B emp-ot/build   -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX -DCMAKE_PREFIX_PATH=$PREFIX
cmake --build emp-ot/build --target install -j
# emp-ag2pc benchmarks, profiled
cmake -S emp-ag2pc -B emp-ag2pc/build_prof -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_PREFIX_PATH=$PREFIX -DEMP_AG2PC_BUILD_BENCHES=ON \
      -DCMAKE_CXX_FLAGS=-DAG2PC_PROFILE
cmake --build emp-ag2pc/build_prof --target bench_100m -j
```

For clean wall-clock numbers (no profiling), drop `-DCMAKE_CXX_FLAGS=-DAG2PC_PROFILE`.

### 5.2 The benchmark

`test/bench_100m.cpp` (built as `bench_100m`). Each binary takes `<party> <port>`.

| Env var | Default | Meaning |
|---|--:|---|
| `BENCH_MODE` | (required) | `object` \| `stream-live` \| `stream-compiled` \| `stream-compiled-reuse` |
| `SHA_BLOCKS` | 4040 | number of SHA-256 compressions (4040 ≈ 100 M ANDs) |
| `SHA_CHECKPOINT` | 404 | chunk every K compressions (memory dial) |
| `BENCH_THREADS` | 4 | protocol `ThreadPool` worker threads |

It prints one CSV line: `mode,sha_blocks,checkpoint,wall_ms,bytes_mb,peak_rss_kib,compile_ms,ok`.

### 5.3 Run (two machines)

Party 1 listens; party 2 dials party 1's (private) IP via `AG2PC_PEER`. Identical
env on both. Example, `stream-live`, 2 threads:

```bash
# party 1 (host A):
BENCH_THREADS=2 SHA_BLOCKS=4040 SHA_CHECKPOINT=404 BENCH_MODE=stream-live \
    ./build_prof/bin/bench_100m 1 12345
# party 2 (host B):
BENCH_THREADS=2 SHA_BLOCKS=4040 SHA_CHECKPOINT=404 BENCH_MODE=stream-live \
    AG2PC_PEER=<host-A-private-ip> ./build_prof/bin/bench_100m 2 12345
```

The CSV (`wall_ms,bytes_mb,peak_rss_kib,…`) prints at party 1. With `-DAG2PC_PROFILE`,
party 1 also emits `[ag2pc] <stage> <ms> ms <bytes> B peakRSS <rss> KiB` per chunk
and `[ag2pc-tp] <subphase> <ms> ms` for the leaky-AND. Sum each stage's `ms` across
the K chunks (e.g. `awk '/^\[ag2pc\]/{t[$2]+=$3} END{for(k in t)print k,t[k]}'`) to
reproduce the tables in §3; divide by the AND count for ns/AND.

### 5.4 Environment used here

- AWS, us-east-1, Ubuntu 22.04 (amd64) AMI `ami-02013f5b15758f4d4`, GCC 11.4,
  CMake 4.3.3, OpenSSL 3.x. Config A: 2× `m8a.8xlarge`. Config B: 2× `m8a.large`,
  same subnet. emp-ag2pc development branch (one shared engine; object + stream
  surfaces).

---

## Caveats

- Numbers are single representative runs with profiling enabled (<1% overhead);
  the profiled and clean wall times agreed within ~1% in spot checks.
- All four modes are interchangeable for correctness and share the same protocol,
  communication, and security guarantees — they differ only in ergonomics and
  memory/latency trade-offs.
- This is an actively developed, **not-yet-audited** rewrite. Do not deploy without
  your own review.
