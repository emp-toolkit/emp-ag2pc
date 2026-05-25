#ifndef CIRCUIT_LAYOUT_H__
#define CIRCUIT_LAYOUT_H__
#include "emp-ag2pc/wire_graph.h"   // Gate
#include <utility>
#include <vector>
using namespace emp;

// Read-only view of a circuit's gate stream for the protocol engine: a
// non-owning pointer into a WireGraph's typed gates plus the counts it needs.
struct CircuitView {
  int num_wire;
  int num_gate;
  int num_ands;
  const Gate *gates;
  // Optional recorder-supplied liveness: last_use[w] = largest gate index
  // reading w as an input (-1 if never read). When non-null, the layout uses
  // it instead of re-scanning — the savings are computed once in the frontend.
  const int *last_use = nullptr;
};

// Slot-minimal wire numbering: storage linear in #ANDs + live set, not #wires.
// Only three classes of wire hold state that must persist across the protocol's
// garble / evaluate / cheat-check phases: circuit inputs, AND-gate outputs
// (fresh randomness), and circuit outputs (extracted at the end). Every other
// wire is "XOR fabric" — a linear (free-XOR) function of those, recomputed on
// demand per phase and recycled at its last read. phys[w] maps a logical wire
// to a physical slot: persistent wires get a permanent slot; fabric wires share
// a small recycled pool bounded by the circuit's live-set width.
//
// Pure circuit analysis — no crypto. Uses cf.last_use when present, else scans.
struct WireLayout {
  std::vector<int> phys;   // logical wire id -> physical slot (-1 if unused)
  int num_slots;           // size of the per-wire scratch arrays
};

inline WireLayout compute_wire_layout(const CircuitView &cf, int num_in,
                                      const std::vector<int> &output_ids) {
  const int W = cf.num_wire;
  std::vector<char> persist(W, 0);
  for (int w = 0; w < num_in; ++w) persist[w] = 1;
  for (int id : output_ids) persist[id] = 1;  // outputs pinned (extracted at end)
  // Liveness (last_rd): use the recorder-supplied array if present, else scan.
  // The AND-output persist marking (WRK's pin policy) is always applied here.
  std::vector<int> last_rd_storage;
  const int *last_rd;
  if (cf.last_use) {
    last_rd = cf.last_use;
    for (int gi = 0; gi < cf.num_gate; ++gi)
      if (cf.gates[gi].is_and()) persist[cf.gates[gi].out] = 1;
  } else {
    last_rd_storage.assign(W, -1);
    for (int gi = 0; gi < cf.num_gate; ++gi) {
      const Gate &g = cf.gates[gi];
      last_rd_storage[g.in0] = gi;
      last_rd_storage[g.in1] = gi;
      if (g.is_and()) persist[g.out] = 1;  // AND outputs: fresh randomness
    }
    last_rd = last_rd_storage.data();
  }
  std::vector<int> phys(W, -1);
  int next_slot = 0;
  for (int w = 0; w < num_in; ++w) phys[w] = next_slot++;  // inputs: slots [0,num_in)
  std::vector<int> freelist;
  for (int gi = 0; gi < cf.num_gate; ++gi) {
    int a = cf.gates[gi].in0, b = cf.gates[gi].in1;
    int out = cf.gates[gi].out;
    if (phys[out] == -1) {
      if (persist[out]) phys[out] = next_slot++;  // permanent
      else if (!freelist.empty()) { phys[out] = freelist.back(); freelist.pop_back(); }
      else phys[out] = next_slot++;
    }
    for (int k = 0; k < 2; ++k) {
      int w = (k == 0) ? a : b;
      if (k == 1 && b == a) continue;  // avoid double-free when in0 == in1
      if (!persist[w] && last_rd[w] == gi) freelist.push_back(phys[w]);
    }
  }
  return {std::move(phys), next_slot};
}

#endif // CIRCUIT_LAYOUT_H__
