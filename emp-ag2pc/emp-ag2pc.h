#ifndef EMP_AG2PC_H__
#define EMP_AG2PC_H__
#include <thread>

// Pulls in everything from emp-tool: io / core / crypto / group / circuits
// (BristolFormat parser, Bit_T<block>) / execution (Backend, half_gate, ...).
#include "emp-tool/emp-tool.h"

// emp-ag2pc layer (header-only). triple_pool.h pulls in the OT-extension
// backends (IKNP / SoftSpoken / Ferret) for the merged COT mesh.
#include "emp-ag2pc/triple_pool.h"
#include "emp-ag2pc/helper.h"
#include "emp-ag2pc/share_bundle.h"
#include "emp-ag2pc/2pc.h"

// Frontend execution surface: LambdaRunner drives a circuit SOURCE (a pure
// frontend body via run<Ins...>, a compiled frontend::TypedCircuit via
// run_compiled<Ins...>, or a raw frontend::BooleanProgram via run_program)
// through the one streaming engine (run_engine_). The direct recorder
// (ag2pc_backend.h) is a separate buffering/chunking adapter that emits
// BooleanProgram chunks and runs them on this same engine; tests that want it
// include ag2pc_backend.h (or ag2pc_circuit_types.h) directly.
//
// Intentionally NOT included: lambda_circuit_types.h. Its
// EMP_USE_CIRCUIT_TYPES_ALL(LambdaWire) aliases (Bit/UInt32/...) collide with
// ag2pc_circuit_types.h's AG2PCWire aliases, so the wire-binding header is a
// per-translation-unit choice the user makes, not an umbrella default.
#include "emp-ag2pc/lambda_runner.h"
#endif // EMP_AG2PC_H__
