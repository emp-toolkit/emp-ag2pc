#ifndef SECURE_WIRES_H__
#define SECURE_WIRES_H__
#include "emp-ag2pc/share_bundle.h"
#include <vector>
using namespace emp;

// Per-wire authenticated-share + half-gate state. Notation (Pi = local):
//   wire_bundle[w]   = (M_j[λ_w^i], K_i[λ_w^j]) for the single peer j ≠ i,
//                      in the bundle's .mac / .key fields.
//   λ_w^i            = LSB(wire_bundle[w].mac)  — implicit, since the bit-0
//                      invariant pins bit0(M)=x and bit0(K)=0.
//   Lambda[w]        = Λ_w             (publicly opened mask; populated
//                                       at every party after process_input
//                                       or compute)
//   label0[w]        = m_{w, 0}^2      only at the garbler P2; empty at P1
//   eval_label[w]    = m_{w, Λ_w}^2    only at P1; empty at P2
//
// MAC relation: M_j[λ_w^i] = K_j[λ_w^i] ⊕ λ_w^i · Δ_j; on Pi the LHS is in
// bundle.mac and on Pj the RHS-key is in (Pj's local) bundle.key.
struct SecureWires {
  std::vector<unsigned char> Lambda;
  AShareBundleVec wire_bundle;
  BlockVec label0;
  BlockVec eval_label;   // m_{w,Λ_w}^2 at P1; empty at the garbler P2

  size_t size() const { return Lambda.size(); }

  // Extract wires [lo, hi) into a fresh bundle. eval_label is sliced when
  // populated (P1) and left empty otherwise, mirroring the layout invariant
  // from process_input / compute.
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

  // In-place concatenation. Mirrors C2PC::concat without allocating a copy
  // of `*this`.
  void append(const SecureWires &b) {
    Lambda.insert(Lambda.end(), b.Lambda.begin(), b.Lambda.end());
    wire_bundle.insert(wire_bundle.end(), b.wire_bundle.begin(),
                       b.wire_bundle.end());
    eval_label.insert(eval_label.end(), b.eval_label.begin(),
                      b.eval_label.end());
    label0.insert(label0.end(), b.label0.begin(), b.label0.end());
  }
};

#endif // SECURE_WIRES_H__
