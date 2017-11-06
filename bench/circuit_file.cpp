#include <emp-tool/emp-tool.h>
#include <emp-sh2pc/emp-sh2pc.h>
#include "c2pc_config.h"
using namespace emp;
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

#define NETWORK
int main(int argc, char** argv) {
	int port, party;
	string file = string(argv[3])+"_"+string(argv[4])+"_"+string(argv[5]) +"_"+string(argv[6]);
	file = "circuits/"+file;

	//string file = circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
//	string file = circuit_file_location+"/sha-256.txt";//AES-non-expanded.txt";//adder_32bit.txt";


	CircuitFile cf(file.c_str());

	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE?nullptr:IP, port);
	io->set_nodelay();
	io->sync();
	setup_semi_honest(io, party);
	double t1 = timeStamp();
	Integer a(cf.n1, 2, ALICE);
	Integer b(cf.n2, 3, BOB);
	Integer c(cf.n3, 1, PUBLIC);
	cf.compute((block*)c.bits, (block*)a.bits, (block*)b.bits);
	string s = c.reveal<string>();
	cout << file<<"\t"<<timeStamp() - t1<<endl;
	return 0;
}
