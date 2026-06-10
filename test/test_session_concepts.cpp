// Compile-time gate: AG2PCSession models the emp-tool session concepts, its gate
// context is a pure BooleanContext recorder, and run() is well-formed over both a
// compiled Circuit and a live body. No network — the test IS that this translation
// unit compiles; main() only confirms the binary links and runs.
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-tool/ir/session/session_io.h"
#include <cstdio>
#include <optional>
#include <type_traits>
using namespace emp;

// The session models the three emp-tool session concepts (also asserted inside the
// header; restated here so this TU is the standalone concept gate).
static_assert(Session<AG2PCSession>);
static_assert(DirectSession<AG2PCSession>);
static_assert(SessionIO<AG2PCSession, UInt_T<AG2PCSession::DirectCtx, 32>>);
static_assert(SessionIO<AG2PCSession, Int_T<AG2PCSession::DirectCtx, 32>>);
static_assert(SessionIO<AG2PCSession, BitVec_T<AG2PCSession::DirectCtx, 128>>);
static_assert(CheckpointingSession<AG2PCSession>);

// Ctx is the pure gate recorder; the value layer is built over it.
static_assert(std::is_same_v<AG2PCSession::DirectCtx, AG2PCCtx>);
static_assert(BooleanContext<AG2PCCtx>);
static_assert(std::is_same_v<UInt_T<AG2PCSession::DirectCtx, 32>, UInt_T<AG2PCCtx, 32>>);

// AG2PC reveal is recipient-only: reveal_t<V> is std::optional<V::clear_t>.
static_assert(std::is_same_v<
    AG2PCSession::reveal_t<UInt_T<AG2PCSession::DirectCtx, 32>>,
    std::optional<UInt_T<AG2PCSession::DirectCtx, 32>::clear_t>>);

// run() is well-formed over a compiled Circuit and over a live body, and a
// checkpointed (materialized) value is an acceptable run() argument. These are
// decltype-only probes — nothing is evaluated, so no session/network is built.
using UInt32 = UInt_T<AG2PCSession::DirectCtx, 32>;
using Adder  = frontend::Circuit<rec::UInt<32>, rec::UInt<32>, rec::UInt<32>>;

template <class S>
using run_compiled_t =
    decltype(std::declval<S&>().run(std::declval<const Adder&>(),
                                    std::declval<const UInt32&>(),
                                    std::declval<const UInt32&>()));
template <class S>
using run_body_t =
    decltype(std::declval<S&>().run([](auto x, auto y) { return x + y; },
                                    std::declval<const UInt32&>(),
                                    std::declval<const UInt32&>()));

static_assert(std::is_same_v<run_compiled_t<AG2PCSession>, UInt32>);
static_assert(std::is_same_v<run_body_t<AG2PCSession>, UInt32>);

int main() {
  std::printf("test_session_concepts: GOOD!\n");
  return 0;
}
