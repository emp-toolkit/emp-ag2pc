#include <emp-tool/emp-tool.h>
#include "2pc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	string file = "ands.txt";//circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
	file = circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
	cout << file<<endl;
//	file = circuit_file_location+"/sha-1.txt";

	CircuitFile cf(file.c_str());
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	auto t1 = clock_start();
//	double t1 = timeStamp();
	C2PC twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;
	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;


	bool *in = new bool[max(cf.n1, cf.n2)];
	bool * out = new bool[cf.n3];
	t1 = clock_start();
	twopc.online(in, out);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;
	delete io;
	return 0;
}
