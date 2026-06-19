// Advanced: run a stored BooleanProgram directly. This is useful for large
// pre-recorded circuits such as AES or SHA, where the natural input/output type
// is BitVec_T rather than UInt_T.

#include "common.h"
#include "emp-tool/ir/builtins.h"

using namespace emp;

int main(int argc, char** argv) {
  int party;
  party = parse_party(argv);
  if (party > BOB) return 0;

  auto io = (party == ALICE) ? NetIO::listen(peer_port()) : NetIO::connect(peer_ip(), peer_port());
  ThreadPool pool(4);
  AG2PCSession sess(io.get(), &pool, party);

  using Bits128 = BitVec_T<AG2PCSession::ctx_t, 128>;
  using Bits256 = BitVec_T<AG2PCSession::ctx_t, 256>;

  const circuit::BooleanProgram& sha = circuit::builtin_circuit("sha256_256");
  std::array<bool, 128> alice_half{};
  std::array<bool, 128> bob_half{};
  for (int i = 0; i < 128; ++i) {
    alice_half[(size_t)i] = (i % 11) == 0;
    bob_half[(size_t)i] = (i % 7) == 3;
  }

  auto batch = sess.input_batch();
  auto low = batch.add<Bits128>(ALICE, party == ALICE ? alice_half : std::array<bool, 128>{});
  auto high = batch.add<Bits128>(BOB, party == BOB ? bob_half : std::array<bool, 128>{});
  batch.finish();

  Bits256 message = low.concat(high);
  auto digest = sess.run_artifact<Bits256>(sha, message);
  auto opened = sess.reveal(digest, ALICE);

  if (ag2pc_example::is_alice(party)) {
    std::vector<uint8_t> clear_input(256);
    for (int i = 0; i < 128; ++i) {
      clear_input[(size_t)i] = alice_half[(size_t)i];
      clear_input[(size_t)128 + i] = bob_half[(size_t)i];
    }
    std::vector<uint8_t> oracle = ag2pc_example::clear_eval(sha, clear_input);
    bool ok = opened.has_value();
    for (int i = 0; i < 256 && ok; ++i) ok = opened.value()[(size_t)i] == oracle[(size_t)i];

    std::array<bool, 64> first_bits{};
    if (opened.has_value())
      for (int i = 0; i < 64; ++i) first_bits[(size_t)i] = opened.value()[(size_t)i];
    uint64_t first_word = ag2pc_example::u64_from_bits(first_bits);
    std::printf("6_raw_program: sha256_256 first 64 output bits=0x%016llx  %s\n",
                (unsigned long long)first_word, ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
