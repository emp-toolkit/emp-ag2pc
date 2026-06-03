# 100M-gate profiling — in-place leaky-AND, two AWS boxes, 10 checkpoints

Run date: 2026-05-27.

## Setup

- **Circuit:** SHA-256 × 4040 compressions = **99,966,560 AND gates** (≈100 M),
  ~571 M total gates (the rest free XOR/NOT). `test_test_sha256`.
- **Checkpointing:** `SHA_BLOCKS=4040 SHA_CHECKPOINT=404` → 10 chunks of 404
  compressions (~10 M ANDs each). Only one chunk is resident at a time, so the
  100 M-gate circuit fits a 16 GB box.
- **Machines:** two `c8a.2xlarge` (8 vCPU, **16 GB**, AMD), us-east-1, different
  AZs (cross-AZ private-IP link). Party 1 listener, party 2 dials.
- **Protocol:** function-dependent in-place leaky-AND (KRRW §5.2 bucket-saving),
  bucket size **B=3** (chunks ≥280 K ANDs), SoftSpoken<4> COT, 8-gate-pipelined G,
  `ThreadPool(4)`.
- **Result: GOOD** (verified vs the plaintext SHA oracle).
- Build flag: `-DAG2PC_PROFILE` (the single consolidated profiling flag).

> Convention note: this run predates the party-1-is-garbler rename. The phase
> markers `p1_evaluate[step10]` and `garble/recv[step6-7]` correspond to today's
> `evaluate[step10]` and `garble[step6-7]`. Numbers below were measured at the
> party that was the evaluator at the time (party 1 in the pre-rename codebase,
> = party 2 under today's convention).

## Time — ns per AND gate (summed over the 10 chunks)

| step | ns/AND | note |
|---|--:|---|
| **inplace_triples** | **226** | the leaky-AND triple generation |
|  ├ half-gate join | 76.8 | MITCCRH H(K)/H(M); G streamed 8-by-8 |
|  ├ COT extend | 71.6 | SoftSpoken<4>, (3B−2)·n = 7n COTs |
|  ├ reconcile + acc-setup | ~34 | a-side Beaver open + rep-mask memcpy |
|  ├ F_eq | 22.6 | 30 checks (B=3 layers × 10 chunks) |
|  ├ bucket layers | 12.4 | B−1 circular-shift combines |
|  └ s-open + combine | 8.1 | |
| evaluate (online eval) | 60.3 | |
| check c_γ (KRRW Fig.3) | 43.3 | per-chunk round + digest |
| collect_masks (share-prop + rep) | 27.5 | |
| draw λ_γ (AND-output masks) | 17.5 | |
| process_input | 1.6 | |
| load_inputs / gather / decode | 1.3 | |
| **secure-compute total** | **≈ 377** | **= 2.65 M AND/s** |
| recording (Bit→BooleanProgram) | ~193 | benchmark artifact, outside the protocol |
| **wall total** | **≈ 570** | = 1.75 M AND/s incl. recording |

Cross-machine the half-gate (76.8) slightly edges out COT (71.6) as the #1 cost,
and the round-trip-bound steps grow vs loopback (check c_γ 43, F_eq 23).

## Communication — bytes per AND gate

| step | B/AND |
|---|--:|
| inplace_triples (COT + G + F_eq + bucket d-opens) | 152 |
| evaluate (online garbled tables, 2 ct/AND) | 33 |
| process_input | 0.55 |
| check c_γ + decode | 0.14 |
| **total** | **≈ 186** (18.6 GB over 100 M) |

## Memory — bytes per AND gate

- **Peak RSS 5.84 GB** at one resident chunk (~10 M ANDs) ⇒ **≈ 584 B/AND resident**.
- Split per resident AND:
  - **~288 B/AND transient** — the B=3 triple layers (acc + 2 sacrifices, freed each chunk).
  - **~296 B/AND persistent** — circuit.gates 91, rep_a+rep_b 64, wire_slot 36,
    λ_γ 32, σ 32, phys 23, circuit.last_use 23, eval/label 18, mask_input 6.
- **Checkpointing is what fits 16 GB:** only ~10 M of the 100 M ANDs are resident.
  A single-chunk (monolithic) 100 M run would need ~584 B/AND × 100 M ≈ **58 GB**;
  the 10 checkpoints hold it to **5.84 GB**.

## Absolute totals (reference)

- Wall ≈ 57 s (garbler view, party 2 in the pre-rename convention = party 1 today) ;
  secure-compute phases ≈ 37.7 s ; recording ≈ 19 s.
- Total communication ≈ 18.6 GB ; peak RSS 5.84 GB.

## Reproduce

```
# build both parties with the single profiling flag
cmake -B build_prof -DCMAKE_CXX_FLAGS=-DAG2PC_PROFILE \
      -Demp-tool_DIR=$PREFIX/lib/cmake/emp-tool -Demp-ot_DIR=$PREFIX/lib/cmake/emp-ot
cmake --build build_prof --target test_test_sha256 -j

# party 1 (listener) and party 2 (dials party-1 private IP) on two 16 GB boxes:
SHA_BLOCKS=4040 SHA_CHECKPOINT=404 build_prof/bin/test_test_sha256 1 12345
SHA_BLOCKS=4040 SHA_CHECKPOINT=404 AG2PC_PEER=<p1-priv-ip> \
                                   build_prof/bin/test_test_sha256 2 12345
```

## Notes / findings

- **x86 SIGFPE fix:** the checkpoint path issues an AND-free tail chunk
  (`num_ands=0`); `rk = raw % L` with `L=0` traps as `SIGFPE` on x86 (silent on
  ARM, which is why local runs never caught it). Guarded `num_ands==0` in both
  triple-gen entry points (`compute_inplace`, `compute_halfgate`).
- The in-place change's win (vs generic) is the ~22% COT reduction (7n vs 9n
  COTs); see the local A/B. Here COT is ~71.6 ns/AND of the 377 ns/AND.
