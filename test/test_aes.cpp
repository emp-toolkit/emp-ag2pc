// Stage B: native AES-128 (emp-tool's AES_Calculator) authored in the Bit
// frontend and run through AG2PCBackend (record -> WireGraph -> C2PC). Oracle:
// the SAME AES_Calculator run in plaintext via setup_clear_backend(""), so the
// AES bit-convention cancels and we directly verify ag2pc == plaintext AES.
// Exercises many ANDs/XORs + many public constants (Rcon / SBox), no Bristol.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "net_setup.h"
using namespace std;
using namespace emp;


template <typename Wire>
static void aes_ct(const bool key_bits[128], const bool pt_bits[128],
                   int key_owner, int pt_owner, bool *ct_out /*128*/) {
  using B = Bit_T<Wire>;
  B key[128], pt[128], expanded[1408], ct[128];
  for (int i = 0; i < 128; ++i) key[i] = B(key_bits[i], key_owner);
  for (int i = 0; i < 128; ++i) pt[i] = B(pt_bits[i], pt_owner);
  AES_Calculator_T<Wire> aes;
  aes.key_schedule(key, expanded);
  aes.encrypt(pt, expanded, ct);
  // Bulk reveal all 128 ciphertext wires to party 1 in ONE backend call.
  block buf[128];
  for (int i = 0; i < 128; ++i) memcpy(&buf[i], &ct[i], sizeof(block));
  backend->reveal(ct_out, 1, buf, 128);
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  // Fixed (arbitrary) test bits; same values used by ag2pc and the clear oracle.
  bool key_bits[128], pt_bits[128];
  for (int i = 0; i < 128; ++i) {
    key_bits[i] = ((i * 7 + 3) % 5) == 0;
    pt_bits[i] = ((i * 3 + 1) % 4) == 0;
  }

  NetIO *io1, *io2;
  make_io2pc(party, port, io1, io2);
  ThreadPool pool(4);
  setup_ag2pc(io1, io2, &pool, party);
  io1->flush(); io2->flush();

  // key owned by party 1, plaintext by party 2; each party feeds its own real
  // bits, dummies for the other (Bit ctor uses the value only at the owner).
  bool ka[128], pb[128];
  for (int i = 0; i < 128; ++i) {
    ka[i] = (party == 1) ? key_bits[i] : false;
    pb[i] = (party == 2) ? pt_bits[i] : false;
  }
  bool ct_ag2pc[128];
  aes_ct<block>(ka, pb, /*key_owner=*/1, /*pt_owner=*/2, ct_ag2pc);
  finalize_ag2pc();

  if (party == 1) {
    // Plaintext oracle: same AES_Calculator, clear backend, real values.
    setup_clear_backend("");
    bool ct_ref[128];
    aes_ct<block>(key_bits, pt_bits, PUBLIC, PUBLIC, ct_ref);
    finalize_clear_backend();
    bool ok = true;
    for (int i = 0; i < 128; ++i) if (ct_ag2pc[i] != ct_ref[i]) ok = false;
    cout << "test_aes vs plaintext AES: " << (ok ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
