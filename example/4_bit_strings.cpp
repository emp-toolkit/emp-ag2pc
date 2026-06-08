// Use BitVec_T when the value is a fixed-width string of bits rather than a number:
// keys, hashes, packets, or any layout where slice/concat matter.

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

  using Bits16 = BitVec_T<AG2PCCtx, 16>;
  using Bits32 = BitVec_T<AG2PCCtx, 32>;

  const uint16_t alice_tag = 0xbeef;
  const uint16_t bob_nonce = 0x1234;

  auto tag = ctx.input<Bits16>(ALICE,
      party == ALICE ? ag2pc_example::bits_from_u64<16>(alice_tag) : std::array<bool, 16>{});
  auto nonce = ctx.input<Bits16>(BOB,
      party == BOB ? ag2pc_example::bits_from_u64<16>(bob_nonce) : std::array<bool, 16>{});

  Bits32 packet = tag.concat(nonce);       // bits [0,16) = tag, [16,32) = nonce
  auto recovered_tag = packet.slice<0, 16>();
  auto recovered_nonce = packet.slice<16, 32>();

  uint64_t tag_out = ag2pc_example::u64_from_bits(
      ctx.reveal(recovered_tag, PUBLIC, recovered_nonce).value_or(std::array<bool, 16>{}));
  uint64_t nonce_out = ag2pc_example::u64_from_bits(
      ctx.reveal(recovered_nonce, PUBLIC).value_or(std::array<bool, 16>{}));

  if (ag2pc_example::is_alice(party)) {
    bool ok = tag_out == alice_tag && nonce_out == bob_nonce;
    std::printf("4_bit_strings: tag=0x%04llx nonce=0x%04llx  %s\n",
                (unsigned long long)tag_out, (unsigned long long)nonce_out,
                ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;
  }
  return 0;
}
