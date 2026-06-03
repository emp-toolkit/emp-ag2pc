#ifndef EMP_AG2PC_LAMBDA_CIRCUIT_TYPES_H__
#define EMP_AG2PC_LAMBDA_CIRCUIT_TYPES_H__

// Friendly aliases for Bit_T / Integer_T / ... bound to LambdaWire — the
// wire carrier used inside lambdas passed to LambdaRunner::run_circuit.
// LambdaWire has no refcount hook (zero per-Bit overhead) but is kept
// non-trivially-copyable via an empty user dtor so -Werror=class-memaccess
// still catches memcpy regressions on Bit_T<LambdaWire>.
//
// Don't include this together with ag2pc_circuit_types.h in the same TU —
// both macros expand to the same `Bit`/`Integer`/... names with different
// wire types and will conflict.

#include "emp-tool/circuits/circuit.h"
#include "emp-ag2pc/lambda_runner.h"

EMP_USE_CIRCUIT_TYPES_ALL(LambdaWire)

#endif  // EMP_AG2PC_LAMBDA_CIRCUIT_TYPES_H__
