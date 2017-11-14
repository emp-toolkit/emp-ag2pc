#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
void test(int party, NetIO* io, string name, string check_output = "") {
	string file = circuit_file_location + name;
	CircuitFile cf(file.c_str());
	auto t1 = clock_start();
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
	memset(in, false, max(cf.n1, cf.n2));
	memset(out, false, cf.n3);
	t1 = clock_start();
	twopc.online(in, out);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;
	if(party == BOB and check_output.size() > 0){
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}
	delete[] in;
	delete[] out;
}

