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
#include "emp-ag2pc/circuit_layout.h"
#include "emp-ag2pc/2pc.h"
#endif // EMP_AG2PC_H__
