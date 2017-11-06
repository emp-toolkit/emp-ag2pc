#ifndef FEQ_H__
#define FEQ_H__
#include <emp-tool/emp-tool.h>
namespace emp {

class Feq { public:
	Hash h;
	NetIO* io = nullptr;
	int party;
	Feq(NetIO* io, int party) {
		this->io = io;
		this->party = party;
	}
	void add(void * data, int length) {
		h.put(data, length);
	}
	bool compare() {
		char dgst[21];
		char dgst2[20];
		char dgst3[20];
		char dgst4[20];
		dgst[20] = 0x0;
		h.digest(dgst);
		dgst[20] = party&0xF;
		Hash::hash_once(dgst2, dgst, 21);
		dgst[20] = (ALICE+BOB-party)&0xF;
		Hash::hash_once(dgst3, dgst, 21);
		if (party == ALICE) {
			io->send_data(dgst2, 20);
			io->recv_data(dgst4, 20);
		} else {
			io->recv_data(dgst4, 20);
			io->send_data(dgst2, 20);
			io->flush();
		}
		return strncmp(dgst3, dgst4, 20) == 0;
	}
};

}
#endif// FEQ_H__
