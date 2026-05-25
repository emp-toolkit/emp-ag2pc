#ifndef SECURE_WIRES_H__
#define SECURE_WIRES_H__
#include "emp-agmpc/share_bundle.h"
#include <vector>
using namespace emp;

// Per-wire authenticated-share + half-gate state. Notation (Pi = local):
//   wire_bundle[w]   = (M_j[λ_w^i], K_i[λ_w^j]) for j ≠ i, AoS-by-wire.
//                      Slot k = peer_slot(party, j) maps peer-id j → slot.
//                      mac(k) / key(k) accessors hide the layout. At nP=3
//                      one bundle = 64B = 1 cache line, so per-wire access
//                      from a topological garble loop hits a single line.
//   λ_w^i            = LSB(wire_bundle[w].mac(0))  — implicit, since the
//                      bit-0 invariant pins bit0(M)=x and bit0(K)=0 across
//                      all peer slots.
//   Lambda[w]        = Λ_w             (publicly opened mask; populated
//                                       at every party after process_input
//                                       or compute)
//   label0[w]        = m_{w, 0}^i      only at Pi (i ≥ 2); empty at P1
//   eval_label[j][w] = m_{w, Λ_w}^j    for j ≥ 2, only at P1; empty at Pi (i ≥ 2)
//
// MAC relation: M_j[λ_w^i] = K_j[λ_w^i] ⊕ λ_w^i · Δ_j; on Pi the LHS is
// in bundle.mac(slot of j) and on Pj the RHS-key is in (Pj's local)
// bundle.key(slot of i).
template <int nP> struct SecureWires {
  std::vector<unsigned char> Lambda;
  AShareBundleVec<nP> wire_bundle;
  BlockVec label0;
  BlockVec eval_label[nP + 1];

  size_t size() const { return Lambda.size(); }

  // Extract wires [lo, hi) into a fresh bundle. Per-party label vectors
  // (eval_label) are sliced when populated and left empty otherwise,
  // mirroring the layout invariant from process_input / compute.
  SecureWires<nP> slice(size_t lo, size_t hi) const {
    SecureWires<nP> r;
    r.Lambda.assign(Lambda.begin() + lo, Lambda.begin() + hi);
    if (!wire_bundle.empty())
      r.wire_bundle.assign(wire_bundle.begin() + lo, wire_bundle.begin() + hi);
    for (int j = 1; j <= nP; ++j) {
      if (!eval_label[j].empty())
        r.eval_label[j].assign(eval_label[j].begin() + lo,
                               eval_label[j].begin() + hi);
    }
    if (!label0.empty())
      r.label0.assign(label0.begin() + lo, label0.begin() + hi);
    return r;
  }

  // In-place concatenation. Mirrors CMPC::concat without allocating a copy
  // of `*this`.
  void append(const SecureWires<nP> &b) {
    Lambda.insert(Lambda.end(), b.Lambda.begin(), b.Lambda.end());
    wire_bundle.insert(wire_bundle.end(), b.wire_bundle.begin(),
                       b.wire_bundle.end());
    for (int j = 1; j <= nP; ++j) {
      eval_label[j].insert(eval_label[j].end(), b.eval_label[j].begin(),
                           b.eval_label[j].end());
    }
    label0.insert(label0.end(), b.label0.begin(), b.label0.end());
  }
};

#endif // SECURE_WIRES_H__
