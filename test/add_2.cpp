#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"

using namespace emp;
using namespace std;

void add_2(int bitsize, string a, string b) {
  Integer sa(bitsize, a, ALICE);
  Integer sb(bitsize, b, BOB);

  sa = sa + sb;

  for (int i = 0; i < bitsize; i++) {
    cout << sa[i].reveal();    
  }
  cout << endl;
}

int main (int argc, char** argv) {
  setup_plain_prot(true, "add_2.circuit.txt");
  add_2(8, "1", "2");
  finalize_plain_prot();
}