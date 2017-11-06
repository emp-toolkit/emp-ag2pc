#include <emp-tool/emp-tool.h>
#include "fpre.h"
#include "c2pc_config.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	int size = atoi(argv[3]);
	Fpre fpre(io, party, size);
	auto t1 = clock_start();
	fpre.refill();
	cout << size<<"\t"<<time_from(t1)<<endl;
	delete io;
	return 0;
}
