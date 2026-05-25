#ifndef EMP_AG2PC_H__
#define EMP_AG2PC_H__
#include <thread>

// Pulls in everything from emp-tool: io / core / crypto / group / circuits
// (BristolFormat parser, Bit_T<block>) / execution (Backend, half_gate, ...).
#include "emp-tool/emp-tool.h"

// Upstream OT (IKNP, COT base) consumed by AuthSharePool.
#include "emp-ot/ot_extension/iknp.h"

// emp-ag2pc layer (header-only).
#include "emp-ag2pc/auth_share_pool.h"
#include "emp-ag2pc/triple_pool.h"
#include "emp-ag2pc/helper.h"
#include "emp-ag2pc/secure_wires.h"
#include "emp-ag2pc/circuit_layout.h"
#include "emp-ag2pc/2pc.h"
#include "emp-ag2pc/netmp.h"
#endif // EMP_AG2PC_H__
