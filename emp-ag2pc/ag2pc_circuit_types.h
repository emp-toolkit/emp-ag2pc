#ifndef EMP_AG2PC_CIRCUIT_TYPES_H__
#define EMP_AG2PC_CIRCUIT_TYPES_H__

// Opt-in batteries-included binding of emp-tool's circuit layer to ag2pc's
// 4-byte wire carrier (AG2PCWire). Mirrors emp-tool/circuits/circuit_block.h
// but for the ag2pc backend — nothing in emp-tool includes this automatically.
// Include it in ag2pc test / app code that wants the friendly `Bit`, `Integer`
// etc. aliases backed by the ag2pc backend; otherwise spell `Bit_T<AG2PCWire>`
// directly.

#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-tool/circuits/circuit.h"

// All friendly aliases for the ag2pc wire. The macro opens namespace emp itself.
EMP_USE_CIRCUIT_TYPES_ALL(AG2PCWire)

#endif  // EMP_AG2PC_CIRCUIT_TYPES_H__
