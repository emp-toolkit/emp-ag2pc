// The smallest useful emp-ag2pc program:
//   1. ALICE contributes one private number.
//   2. BOB contributes one private number.
//   3. Both parties compute with normal C++ operators.
//   4. The result is opened to both parties.

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
  const uint32_t alice_value = 123;
  const uint32_t bob_value = 456;

  auto a = sess.input<UInt32>(ALICE, party == ALICE ? alice_value : 0);
  auto b = sess.input<UInt32>(BOB, party == BOB ? bob_value : 0);

  auto sum = a + b;
  auto bigger_than_500 = sum > sum.constant(500);

  uint32_t opened_sum = (uint32_t)sess.reveal(sum, PUBLIC, bigger_than_500).value_or(0);
  bool opened_cmp = sess.reveal(bigger_than_500, PUBLIC).value_or(false);

  if (ag2pc_example::is_alice(party)) {
    bool ok = opened_sum == alice_value + bob_value && opened_cmp;
    std::printf("1_basics: %u + %u = %u, >500=%s  %s\n",
                alice_value, bob_value, opened_sum,
                opened_cmp ? "true" : "false", ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
