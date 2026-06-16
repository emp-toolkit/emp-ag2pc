// Builtin crypto via stored .empbc programs replayed over AG2PC, checked against a
// ClearCtx oracle on the SAME program. I/O is BitVec_T (the fixed-width bit-vector
// value) — never a UInt_T clear codec beyond 64 bits. BOB owns all inputs.
//   aes128:     256 in (128 pt ‖ 128 key) -> 128 out
//   sha256_256: 256 in                    -> 256 out
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-tool/ir/builtins.h"   // circuit::builtin_circuit
#include "test_common.h"
#include <array>
#include <cstdio>
#include <vector>
using namespace std;
using namespace emp;
using namespace ag2pc_test;

// Replay an N_in -> N_out builtin with BOB-owned inputs; compare to the ClearCtx
// oracle at ALICE. Returns true on the non-checking party.
template <int N_in, int N_out>
static bool check_builtin(AG2PCSession &sess, int party, const char *name) {
  const circuit::BooleanProgram &prog = circuit::builtin_circuit(name);
  if ((int)prog.num_inputs != N_in || (int)prog.outputs.size() != N_out)
    error("test_aes_sha_builtin: builtin dimensions != expected");

  std::array<bool, N_in> in_bits{};
  for (int i = 0; i < N_in; ++i) in_bits[i] = ((i * 7 + 3) % 5) == 0;

  auto in = sess.input<BitVec_T<AG2PCSession::DirectCtx, N_in>>(
      BOB, party == BOB ? in_bits : std::array<bool, N_in>{});
  auto out = sess.reveal(sess.run_artifact<BitVec_T<AG2PCSession::DirectCtx, N_out>>(prog, in), ALICE);

  if (party != ALICE) return true;
  std::vector<uint8_t> oracle = clear_eval(prog, std::vector<uint8_t>(in_bits.begin(), in_bits.end()));
  bool ok = out.has_value() && (int)oracle.size() == N_out;
  for (int i = 0; i < N_out && ok; ++i) ok = (out.value()[i] == oracle[i]);
  printf("  builtin %-10s (run_artifact over BitVec) vs ClearCtx oracle  %s\n",
         name, ok ? "GOOD!" : "BAD!");
  return ok;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);
  io->flush();

  bool ok = true;
  ok &= check_builtin<256, 128>(sess, party, "aes128");
  ok &= check_builtin<256, 256>(sess, party, "sha256_256");

  if (party == ALICE)
    printf("test_aes_sha_builtin: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == ALICE && !ok) ? 1 : 0;
}
