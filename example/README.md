# emp-ag2pc Examples

These examples are a small curriculum. Start at `1_basics.cpp`; each file adds
one idea and keeps the protocol setup boring on purpose.

Build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DEMP_AG2PC_BUILD_EXAMPLES=ON
cmake --build build -j
```

Run one example locally:

```bash
./run ./build/bin/example_1_basics
```

Run across two machines by starting party 1 on the server and setting
`AG2PC_PEER=<party-1-ip>` for party 2:

```bash
# party 1
./build/bin/example_1_basics 1 12345

# party 2
AG2PC_PEER=10.0.0.5 ./build/bin/example_1_basics 2 12345
```

Examples:

| File | Idea |
|---|---|
| `1_basics.cpp` | Private inputs, ordinary operators, reveal. |
| `2_reveal_and_continue.cpp` | Reveal a small decision, branch publicly, keep computing. |
| `3_reusable_circuit.cpp` | Compile one pure circuit and run it more than once. |
| `4_bit_strings.cpp` | Use `BitVec` for fixed-width bit strings and packet-style layout. |
| `5_chunking.cpp` | Use `checkpoint` so long computations keep only the state they need. |
| `6_raw_program.cpp` | Advanced: `sess.run_artifact` over a stored AES/SHA-style `BooleanProgram` (`BitVec` I/O). |
