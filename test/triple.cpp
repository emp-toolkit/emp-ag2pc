#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/fpre.h"
#include<thread>
using namespace std;
using namespace emp;

int N = 1<<20;
int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	HighSpeedNetIO *io;
	io = new HighSpeedNetIO(party==ALICE ? nullptr:IP, port, port+1);
	Fpre<HighSpeedNetIO> * fpre = new Fpre<HighSpeedNetIO>(io, party, N);
	auto tt1 = clock_start();
	fpre->refill();
	//fpre->refill();
	cout << time_from(tt1)/(N)*1000<<endl;
	cout << fpre->bandwidth()<<endl;	

	fpre->check_correctness(fpre->MAC_res, fpre->KEY_res, fpre->batch_size);	

	delete io;
	return 0;
}
