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

}  // namespace emp
#endif // SHARE_BUNDLE_H__
