// MPC programs do not have to be one giant circuit. You may reveal a small public
// decision, branch in ordinary C++, then feed more private inputs and continue.

#include "common.h"

using namespace emp;

int main(int argc, char** argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  if (party > BOB) return 0;

  NetIO* io = nullptr;
  ag2pc_example::make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);

  using UInt32 = UInt_T<AG2PCSession::ctx_t, 32>;
  const uint32_t alice_budget = 100;
  const uint32_t bob_price = 73;

  auto budget = sess.input<UInt32>(ALICE, party == ALICE ? alice_budget : 0);
  auto price = sess.input<UInt32>(BOB, party == BOB ? bob_price : 0);

  bool affordable = sess.reveal(price <= budget, PUBLIC).value_or(false);
  if (!affordable) {
    if (ag2pc_example::is_alice(party))
      std::printf("2_reveal_and_continue: item is not affordable  BAD!\n");
    return ag2pc_example::is_alice(party) ? 1 : 0;
  }

  const uint32_t alice_tax = 5;
  const uint32_t bob_shipping = 8;
  auto tax = sess.input<UInt32>(ALICE, party == ALICE ? alice_tax : 0);
  auto shipping = sess.input<UInt32>(BOB, party == BOB ? bob_shipping : 0);
  auto final_total = price + tax + shipping;

  uint32_t opened = (uint32_t)sess.reveal(final_total, PUBLIC).value_or(0);
  if (ag2pc_example::is_alice(party)) {
    uint32_t expected = bob_price + alice_tax + bob_shipping;
    bool ok = opened == expected;
    std::printf("2_reveal_and_continue: affordable=true, final total=%u  %s\n",
                opened, ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
