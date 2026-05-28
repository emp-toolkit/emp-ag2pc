#ifndef SHARE_BUNDLE_H__
#define SHARE_BUNDLE_H__
#include "emp-tool/core/block.h"
#include <vector>

namespace emp {

// Per-wire authenticated-share state for one wire: with a single peer it is
// just (mac, key) = 32B, half a cache line. Kept as a struct (rather than
// parallel mac[]/key[] arrays) so the frontend can carry per-wire state as an
// AShareBundleVec and memcpy whole wires around.
//   mac = M_peer[x] = K_peer[x] ⊕ x·Δ_peer   (bit0 carries the share bit x)
//   key = K_me[x_peer]                        (local key for the peer's bit)
struct AShareBundle {
  block mac;
  block key;
};

// Skip zero/value-init for trivial bundles in resize / vector(N), matching
// the BlockVec convention.
using AShareBundleVec =
    std::vector<AShareBundle, default_init_allocator<AShareBundle>>;

// AoS-by-triple packing: three AShareBundles back-to-back, one per share-slot
// of an AND triple, laid out contiguously per triple so a consumer reading
// slot 2 / 1 / 0 of the same triple walks sequential memory (good for HW
// prefetch).
struct TripleBundle {
  AShareBundle b[3];
};

using TripleBundleVec =
    std::vector<TripleBundle, default_init_allocator<TripleBundle>>;

// Per-wire authenticated-share + half-gate state (the bundle the protocol carries
// per wire). Notation (Pi = local):
//   wire_bundle[w]   = (M_j[λ_w^i], K_i[λ_w^j]) for the single peer j ≠ i, in the
//                      bundle's .mac / .key fields.
//   λ_w^i            = LSB(wire_bundle[w].mac) — implicit (bit0(M)=x, bit0(K)=0).
//   Lambda[w]        = Λ_w           (publicly opened mask; set at every party
//                                     after process_input or compute)
//   label0[w]        = m_{w,0}^2     only at the garbler P2; empty at P1
//   eval_label[w]    = m_{w,Λ_w}^2   only at P1; empty at P2
// MAC relation: M_j[λ_w^i] = K_j[λ_w^i] ⊕ λ_w^i · Δ_j.
struct SecureWires {
  std::vector<unsigned char> Lambda;
  AShareBundleVec wire_bundle;
  BlockVec label0;
  BlockVec eval_label;   // m_{w,Λ_w}^2 at P1; empty at the garbler P2

  size_t size() const { return Lambda.size(); }

  // Extract wires [lo, hi) into a fresh bundle. label0 / eval_label are sliced
  // only when populated (mirroring the process_input / compute layout invariant).
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

  // In-place concatenation (no copy of *this).
  void append(const SecureWires &b) {
    Lambda.insert(Lambda.end(), b.Lambda.begin(), b.Lambda.end());
    wire_bundle.insert(wire_bundle.end(), b.wire_bundle.begin(),
                       b.wire_bundle.end());
    eval_label.insert(eval_label.end(), b.eval_label.begin(),
                      b.eval_label.end());
    label0.insert(label0.end(), b.label0.begin(), b.label0.end());
  }
};

}  // namespace emp
#endif // SHARE_BUNDLE_H__
