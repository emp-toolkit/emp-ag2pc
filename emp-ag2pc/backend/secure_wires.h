#ifndef SHARE_BUNDLE_H__
#define SHARE_BUNDLE_H__
#include "emp-tool/runtime/core/block.h"
#include <vector>

namespace emp {

// Per-wire authenticated-share state.
//   mac = M_peer[x] = K_peer[x] ⊕ x·Δ_peer   (bit0 carries the share bit x)
//   key = K_me[x_peer]                        (local key for the peer's bit)
struct AShareBundle {
  block mac;
  block key;
};

// Skip zero/value-init for trivial bundles.
using AShareBundleVec =
    std::vector<AShareBundle, default_init_allocator<AShareBundle>>;

// Per-wire authenticated-share + half-gate state (the bundle the protocol carries
// per wire). Notation (Pi = local):
//   wire_bundle[w]   = (M_j[λ_w^i], K_i[λ_w^j]) for the single peer j ≠ i, in the
//                      bundle's .mac / .key fields.
//   λ_w^i            = LSB(wire_bundle[w].mac) — implicit (bit0(M)=x, bit0(K)=0).
//   Lambda[w]        = Λ_w           (publicly opened mask; set at every party
//                                     after process_inputs or compute)
//   label0[w]        = m_{w,0}^1     only at the garbler P1; empty at the evaluator P2
//   eval_label[w]    = m_{w,Λ_w}^1   only at the evaluator P2; empty at the garbler P1
// MAC relation: M_j[λ_w^i] = K_j[λ_w^i] ⊕ λ_w^i · Δ_j.
struct SecureWires {
  std::vector<unsigned char> Lambda;
  AShareBundleVec wire_bundle;
  BlockVec label0;
  BlockVec eval_label;   // m_{w,Λ_w}^1 at the evaluator P2; empty at the garbler P1

  size_t size() const { return Lambda.size(); }

  // Extract wires [lo, hi) into a fresh bundle. label0 / eval_label are sliced
  // only when populated (mirroring the process_inputs / compute layout invariant).
  SecureWires slice(size_t lo, size_t hi) const {
    SecureWires r;
    r.Lambda.assign(Lambda.begin() + lo, Lambda.begin() + hi);
    if (!wire_bundle.empty())
      r.wire_bundle.assign(wire_bundle.begin() + lo, wire_bundle.begin() + hi);
    if (!eval_label.empty())
      r.eval_label.assign(eval_label.begin() + lo, eval_label.begin() + hi);
    if (!label0.empty())
      r.label0.assign(label0.begin() + lo, label0.begin() + hi);
    return r;
  }
};

}  // namespace emp
#endif // SHARE_BUNDLE_H__
