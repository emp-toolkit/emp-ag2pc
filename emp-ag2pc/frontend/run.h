#ifndef EMP_AG2PC_RUN_H__
#define EMP_AG2PC_RUN_H__

// Friendly aliases for Bit_T / Integer_T / ... bound to LambdaWire — the
// wire carrier used inside lambdas passed to AG2PCEngine::run_circuit.
// LambdaWire has no refcount hook (zero per-Bit overhead) but is kept
// non-trivially-copyable via an empty user dtor so -Werror=class-memaccess
// still catches memcpy regressions on Bit_T<LambdaWire>.
//
// Prefer including <emp-ag2pc/function.h> from user code. Do not include this
// implementation header together with direct.h / circuit_types.h in the same TU:
// both mode bindings expand to the same `Bit`/`Integer`/... names with different
// wire types and will conflict.

#include "emp-tool/circuits/circuit.h"
#include "emp-ag2pc/backend/engine.h"

EMP_USE_CIRCUIT_TYPES_ALL(LambdaWire)

#endif  // EMP_AG2PC_RUN_H__
