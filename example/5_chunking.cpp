// Checkpoints keep long computations from carrying every intermediate value.
// Here only `state` survives each round; temporary inputs and gates are pruned.

#include "common.h"

using namespace emp;

int main(int argc, char** argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  if (party > BOB) return 0;

  NetIO* io = nullptr;
  ag2pc_example::make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCCtx ctx(io, &pool, party);

  using UInt32 = UInt_T<AG2PCCtx, 32>;

  const uint32_t seed = 1000;
  auto state = ctx.input<UInt32>(ALICE, party == ALICE ? seed : 0);

  uint32_t expected = seed;
  for (uint32_t round = 1; round <= 16; ++round) {
    auto x = ctx.input<UInt32>(BOB, party == BOB ? round : 0);
    state = state + (x * x);
    ctx.checkpoint(state);
    expected += round * round;
  }

  uint32_t opened = (uint32_t)ctx.reveal(state, PUBLIC).value_or(0);
  if (ag2pc_example::is_alice(party)) {
    bool ok = opened == expected;
    std::printf("5_chunking: state after 16 rounds=%u  %s\n",
                opened, ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
