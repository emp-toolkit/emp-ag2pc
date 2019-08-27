#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"

using namespace emp;
using namespace std;

void hmac(int bitsize, input a, input b) {
  // Integer sa(bitsize, a, ALICE);
  // Integer sb(bitsize, b, BOB);

  // sa = sa + sb;

  // for (int i = 0; i < bitsize; i++) {
  //   cout << sa[i].reveal();    
  // }
  // cout << endl;
}

int main (int argc, char** argv) {
  setup_plain_prot(true, "hmac.circuit.txt");
  // add_2(8, "1", "2");
  int keyBitLen = 256;
  string key = "key";
  string message = "The quick brown fox jumps over the lazy dog";
  // expected output (bytes): f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
  hmac();
  finalize_plain_prot();
}