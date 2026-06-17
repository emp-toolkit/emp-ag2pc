// A reusable circuit is written as a pure function and compiled once. The same
// compiled circuit can then run on private inputs as many times as you like.

#include "common.h"

using namespace emp;
namespace cf = emp::frontend;

int main(int argc, char** argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  if (party > BOB) return 0;

  NetIO* io = nullptr;
  ag2pc_example::make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);

  using UInt32 = UInt_T<AG2PCSession::ctx_t, 32>;

  auto score_circuit = cf::compile<rec::UInt<32>, rec::UInt<32>>(
      [](auto x, auto y) {
        auto mixed = (x + y) * (x.constant(3) + y.constant(5));
        return mixed ^ (mixed >> 7);
      });

  const uint32_t ax1 = 10, by1 = 20;
  const uint32_t ax2 = 7, by2 = 35;

  auto a1 = sess.input<UInt32>(ALICE, party == ALICE ? ax1 : 0);
  auto b1 = sess.input<UInt32>(BOB, party == BOB ? by1 : 0);
  auto a2 = sess.input<UInt32>(ALICE, party == ALICE ? ax2 : 0);
  auto b2 = sess.input<UInt32>(BOB, party == BOB ? by2 : 0);

  uint32_t out1 = (uint32_t)sess.reveal(sess.run(score_circuit, a1, b1), PUBLIC).value_or(0);
  uint32_t out2 = (uint32_t)sess.reveal(sess.run(score_circuit, a2, b2), PUBLIC).value_or(0);

  auto clear_score = [](uint32_t x, uint32_t y) {
    uint32_t mixed = (x + y) * (3 + 5);
    return mixed ^ (mixed >> 7);
  };

  if (ag2pc_example::is_alice(party)) {
    bool ok = out1 == clear_score(ax1, by1) && out2 == clear_score(ax2, by2);
    std::printf("3_reusable_circuit: outputs=(%u,%u)  %s\n",
                out1, out2, ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
