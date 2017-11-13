#ifndef FPRE_H__
#define FPRE_H__
#include <emp-tool/emp-tool.h>
#include <bitset>
#include <thread>
#include "abit.h"
#include "feq.h"
#include "c2pc_config.h"
namespace emp {
//#define __debug
inline uint8_t LSB(block & b) {
	return _mm_extract_epi8(b, 0) & 0x1;
}
void abit_setup(ABit * abit, NetIO * io, bool send){
	io->flush();
	if(send) {
		abit->setup_send();
	} else {
		abit->setup_recv();
	}
	io->flush();
}
void abit_run(ABit * abit, NetIO * io, bool send, block * blocks, bool * bools, int length) {
	io->flush();
	if(send) {
		abit->send(blocks, length);
	} else {
		abit->recv(blocks, bools, length);
	}
	io->flush();
}

class Fpre;
void combine_merge(Fpre * fpre, int start, int length, int I, bool * data, bool* data2, block * MAC2, block * KEY2, bool *r2, int * location);
void generate_and_check(Fpre* fpre, int start, int length, int I);

class Fpre {public:
	ThreadPool *pool;
	const static int THDS = fpre_threads;
	int batch_size = 0, bucket_size = 0;
	int size = 0;
	int party;
	block * keys = nullptr;
	bool * values = nullptr;
	PRG prg;
	PRP prp;
	PRP *prps;
	NetIO *io[THDS];
	NetIO *io2[THDS];
	ABit *abit1[THDS], *abit2[THDS];
	block Delta;
	Feq *eq[THDS];
	block * MAC = nullptr, *KEY = nullptr;
	bool * r = nullptr;
	Fpre(NetIO * in_io, int party, int bsize = 1000) {
		pool = new ThreadPool(THDS*2);
		prps = new PRP[THDS];
		for(int i = 0; i < THDS; ++i) {
			io[i] = new NetIO(in_io->is_server?nullptr:in_io->addr.c_str(), in_io->port+2*i+1, true);
			io2[i] = new NetIO(in_io->is_server?nullptr:in_io->addr.c_str(), in_io->port+2*i+2, true);
			io[i]->set_nodelay();	
			io2[i]->set_nodelay();	

			eq[i] = new Feq(io[i], party);
		}
		this->party = party;
		abit1[0] = new ABit(io[0]);
		abit2[0] = new ABit(io2[0]);

		vector<future<void>> res;
		if(party == ALICE) {
			res.push_back(pool->enqueue(&abit_setup, abit1[0], io[0], true));
			res.push_back(pool->enqueue(&abit_setup, abit2[0], io2[0], false));
			res[0].get();
			res[1].get();
			for(int i = 1; i < THDS; ++i) {
				abit1[i] = abit1[0]->clone(io[i], true);
				abit2[i] = abit2[0]->clone(io2[i], false);
			}
			Delta = abit1[0]->Delta;
		} else {
			res.push_back(pool->enqueue(&abit_setup, abit1[0], io[0], false));
			res.push_back(pool->enqueue(&abit_setup, abit2[0], io2[0], true));
			res[0].get();
			res[1].get();
			for(int i = 1; i < THDS; ++i) {
				abit1[i] = abit1[0]->clone(io[i], false);
				abit2[i] = abit2[0]->clone(io2[i], true);
			}
			Delta = abit2[0]->Delta;
		}
		set_batch_size(bsize);
	}
	void set_batch_size(int size) {
		size = std::max(size, 320);
		batch_size = ((size+THDS-1)/THDS)*THDS;
		if(batch_size >= 280*1000)
			bucket_size = 3;
		else if(batch_size >= 3100)
			bucket_size = 4;
		else bucket_size = 5;
		if (MAC != nullptr) {
			delete[] MAC;
			delete[] KEY;
			delete[] r;
		}
		MAC = aalloc<block>(batch_size * bucket_size * 3);
		KEY = aalloc<block>(batch_size * bucket_size * 3);
		r = new bool[batch_size * bucket_size * 3];
	}
	~Fpre() {
		if(MAC != nullptr) {
		free(MAC);
		free(KEY);
		delete[] r;}
		delete[] prps;
		delete pool;
		for(int i = 0; i < THDS; ++i) {
			delete abit1[i];
			delete abit2[i];
			delete io[i];
			delete io2[i];
			delete eq[i];
		}
	}
	void refill() {
		prg.random_bool(r, batch_size * 3 * bucket_size);
#ifdef __debug
		double t1 = timeStamp();
#endif
		vector<future<void>> res;
		for(int i = 0; i < THDS; ++i)
			res.push_back(pool->enqueue(generate_and_check, this, i*batch_size/THDS, batch_size/THDS, i));

		for(int i = 0; i < THDS; ++i)
			res[i].get();
#ifdef __debug
		double t2 = timeStamp();
		cout << "\t Fpre: Generate N Check:\t"<< t2-t1<<endl;
		check_correctness(MAC, KEY, r, batch_size*bucket_size);
		t1 = timeStamp();
#endif
		combine(MAC, KEY, r, batch_size, bucket_size);
#ifdef __debug
		t2 = timeStamp();
		cout << "\t Fpre: Permute N Combine:\t"<< t2-t1<<endl;

		check_correctness(MAC, KEY, r, batch_size);
#endif
		//		cout << eq->compare()<<endl<<flush;
	}
	void generate(block * MAC, block * KEY, bool * r, int length, int I) {
		if (party == ALICE) {
			if(I%2 == 1) {
				future<void> res = pool->enqueue(
						abit_run, abit1[I], io[I], true, KEY, nullptr, length*3);
				abit_run(abit2[I], io2[I], false, MAC, r, length*3);
				res.get();
			} else {
				future<void> res = pool->enqueue(
						abit_run, abit1[I], io[I], true, KEY, nullptr, length*3);
				abit_run(abit2[I], io2[I], false, MAC, r, length*3);
				res.get();
			}
			uint8_t * data = new uint8_t[length];
			for(int i = 0; i < length; ++i) {
				block tmp[4], tmp2[4];
				tmp[0] = KEY[3*i];
				tmp[1] = xorBlocks(tmp[0], Delta);
				tmp[2] = KEY[3*i+1];
				tmp[3] = xorBlocks(tmp[2], Delta);
				prps[I].H<4>(tmp, tmp, 4*i);

				tmp2[0] = xorBlocks(tmp[0], tmp[2]);
				tmp2[1] = xorBlocks(tmp[1], tmp[2]);
				tmp2[2] = xorBlocks(tmp[0], tmp[3]);
				tmp2[3] = xorBlocks(tmp[1], tmp[3]);

				data[i] = LSB(tmp2[0]);
				data[i] |= (LSB(tmp2[1])<<1);
				data[i] |= (LSB(tmp2[2])<<2);
				data[i] |= (LSB(tmp2[3])<<3);
				if ( ((false != r[3*i] ) && (false != r[3*i+1])) != r[3*i+2] )
					data[i] = data[i] ^ 0x1;
				if ( ((true != r[3*i] ) && (false != r[3*i+1])) != r[3*i+2] )
					data[i] = data[i] ^ 0x2;
				if ( ((false != r[3*i] ) && (true != r[3*i+1])) != r[3*i+2] )
					data[i] = data[i] ^ 0x4;
				if ( ((true != r[3*i] ) && (true != r[3*i+1])) != r[3*i+2] )
					data[i] = data[i] ^ 0x8;

				io[I]->send_data(&data[i], 1);
			}
			bool * bb = new bool[length];
			recv_bool(io[I], bb, length);
			for(int i = 0; i < length; ++i) {
				if(bb[i]) KEY[3*i+2] = xorBlocks(KEY[3*i+2], Delta);
			}
			delete[] bb;
			delete[] data;
		} else {
			if(I%2 == 1) {
				future<void> res = pool->enqueue(
						abit_run, abit1[I], io2[I], false, MAC, r, length*3);
				abit_run(abit2[I], io[I], true, KEY, nullptr, length*3);
				res.get();
			} else {
				future<void> res = pool->enqueue(
						abit_run, abit1[I], io2[I], false, MAC, r, length*3);
				abit_run( abit2[I], io[I], true, KEY, nullptr, length*3);
				res.get();
			}
			uint8_t tmp;
			bool *d = new bool[length];
			for(int i = 0; i < length; ++i) {
				io[I]->recv_data(&tmp, 1);
				block H = xorBlocks(prps[I].H(MAC[3*i], 4*i + r[3*i]), prps[I].H(MAC[3*i+1], 4*i + 2 + r[3*i+1]));

				uint8_t res = LSB(H);
				tmp >>= (r[3*i+1]*2+r[3*i]);
				d[i] = r[3*i+2] != ((tmp&0x1) != (res&0x1));
				r[3*i+2] = (!(tmp&0x1) != !(res&0x1));
			}
			send_bool(io[I], d, length);
			delete[] d;
		}
	}
	void check(const block * MAC, const block * KEY, const bool * r, bool checker, int length, NetIO * local_io, int I) {
local_io->flush();
		block * T = new block[length]; 
		if(checker) {
			for(int i = 0; i < length; ++i) {
				block tmp[2], tmp2[2], tmp3[2];
				tmp[0] = double_block(KEY[3*i]);
				tmp[1] = double_block(xorBlocks(KEY[3*i], Delta));

				tmp2[0] = KEY[3*i+2];
				if(r[3*i+2]) tmp2[0] = xorBlocks(tmp2[0], Delta);

				tmp2[1] = xorBlocks(KEY[3*i+1], KEY[3*i+2]);
				if(r[3*i+2] != r[3*i+1]) tmp2[1] = xorBlocks(tmp2[1], Delta);

				tmp2[0] = double_block( double_block (tmp2[0]));
				tmp2[1] = double_block( double_block (tmp2[1]));

				tmp3[0] = xorBlocks(tmp[r[3*i]], tmp2[0]);
				tmp3[1] = xorBlocks(tmp[!r[3*i]], tmp2[1]);

				prps[I].H<2>(tmp, tmp3, 2*i);

				T[i] = tmp[r[3*i]];
				tmp[1] = xorBlocks(tmp[0], tmp[1]);
				local_io->send_block(&tmp[1], 1);
			}
			for(int i = 0; i < length; ++i) {
				block W = xorBlocks(T[i], prps[I].H(MAC[3*i], 2*i+r[3*i])), tmp;

				local_io->recv_block(&tmp, 1);
				if(r[3*i]) W = xorBlocks(W, tmp);

				eq[I]->add(&W, sizeof(block));
			}
		} else {
			for(int i = 0; i < length; ++i) {
				block V[2], tmp2[2];
				V[0] = double_block(MAC[3*i]);
				V[1] = double_block(MAC[3*i]);
				tmp2[0] = double_block(double_block(MAC[3*i+2]));
				tmp2[1] = double_block(double_block(xorBlocks(MAC[3*i+2], MAC[3*i+1])));
				xorBlocks_arr(V, V, tmp2, 2);
				prps[I].H<2>(V, V, 2*i);

				block U;
				local_io->recv_block(&U, 1);

				tmp2[0] = KEY[3*i];
				tmp2[1] = xorBlocks(KEY[3*i], Delta);
				prps[I].H<2>(tmp2, tmp2, 2*i);
				T[i] = xorBlocks(tmp2[0], tmp2[1]);
				T[i] = xorBlocks(T[i], V[0]);
				T[i] = xorBlocks(T[i], V[1]);

				block T2 = xorBlocks(tmp2[0], V[r[3*i]]);
				if(r[3*i])
					T2 = xorBlocks(T2, U);
				eq[I]->add(&T2, sizeof(block));
			}
			local_io->send_block(T, length);
		}
local_io->flush();
		delete[] T;
	}
	void check_correctness(block * MAC, block * KEY, bool * r, int length) {
		if (party == ALICE) {
			io[0]->send_data(r, length*3);
			io[0]->send_block(&Delta, 1);
			io[0]->send_block(KEY, length*3);
			block DD;io[0]->recv_block(&DD, 1);

			for(int i = 0; i < length*3; ++i) {
				block tmp;io[0]->recv_block(&tmp, 1);
				if(r[i]) tmp = xorBlocks(tmp, DD);
				if (!block_cmp(&tmp, &MAC[i], 1))
					cout <<i<<"\tWRONG ABIT!"<<endl<<flush;
			}

		} else {
			bool tmp[3];
			for(int i = 0; i < length; ++i) {
				io[0]->recv_data(tmp, 3);
				bool res = ((tmp[0] != r[3*i] ) && (tmp[1] != r[3*i+1]));
				if(res != (tmp[2] != r[3*i+2]) ) {
					cout <<i<<"\tWRONG!"<<endl<<flush;
				}
			}
			block DD;io[0]->recv_block(&DD, 1);

			for(int i = 0; i < length*3; ++i) {
				block tmp;io[0]->recv_block(&tmp, 1);
				if(r[i]) tmp = xorBlocks(tmp, DD);
				if (!block_cmp(&tmp, &MAC[i], 1))
					cout <<i<<"\tWRONG ABIT!"<<endl<<flush;
			}

			io[0]->send_block(&Delta, 1);
			io[0]->send_block(KEY, length*3);
		}
	}

	void combine(block * MAC, block * KEY, bool * r, int length, int bucket_size) {
		block S, HS, S2, HS2; prg.random_block(&S, 1);
		HS = S;
		prp.permute_block(&HS, 1);
		if (party == ALICE) {
			io[0]->send_block(&HS, 1);
			io[0]->recv_block(&HS2, 1);
			io[0]->recv_block(&S2, 1);
			io[0]->send_block(&S, 1);
		} else {
			io[0]->recv_block(&HS2, 1);
			io[0]->send_block(&HS, 1);
			io[0]->send_block(&S, 1);
			io[0]->recv_block(&S2, 1);
		}
		S = xorBlocks(S, S2);
		HS = S2;
		prp.permute_block(&HS, 1);
		if (!block_cmp(&HS, &HS2, 1)) {
			cout <<"cheat!"<<endl;
		}
		int * ind = new int[length*bucket_size];
		int *location = new int[length*bucket_size];
		for(int i = 0; i < length*bucket_size; ++i) location[i] = i;
		PRG prg(&S);
		prg.random_data(ind, length*bucket_size*4);
		for(int i = length*bucket_size-1; i>=0; --i) {
			int index = ind[i]%(i+1);
			index = index>0? index:(-1*index);
			int tmp = location[i];
			location[i] = location[index];
			location[index] = tmp;
		}
		delete[] ind;

		bool *data = new bool[length*bucket_size];	
		bool *data2 = new bool[length*bucket_size];
		block * MAC2 = new block[length*3];
		block * KEY2 = new block[length*3];
		bool * r2 = new bool[length*3];
		vector<future<void>> res;
		for(int i = 0; i < THDS; ++i)
			res.push_back(pool->enqueue(combine_merge, this, length/THDS*i, length/THDS, i, data, data2, MAC2, KEY2, r2, location));
		for(int i = 0; i < THDS; ++i)
			res[i].get();
		memcpy(MAC, MAC2, sizeof(block)*3*length);
		memcpy(KEY, KEY2, sizeof(block)*3*length);
		memcpy(r, r2, sizeof(bool)*3*length);
		delete[] data;
		delete[] location;
		delete[] data2;
		delete[] MAC2;
		delete[] KEY2;
		delete[] r2;
	}
};
void combine_merge(Fpre * fpre, int start, int length, int I, bool * data, bool* data2, block * MAC2, block * KEY2, bool *r2, int * location) {
	fpre->io[I]->flush();
	int bucket_size = fpre->bucket_size;
	for(int i = start; i < start+length; ++i) {
		for(int j = 1; j < bucket_size; ++j) {
			data[i*bucket_size+j] = (fpre->r[location[i*bucket_size]*3+1]!=fpre->r[location[i*bucket_size+j]*3+1]);
		}
	}
	if(fpre->party == ALICE) {
		send_bool(fpre->io[I], data + start * bucket_size, length*bucket_size);
		recv_bool(fpre->io[I], data2 + start*bucket_size, length*bucket_size);
	} else {
		recv_bool(fpre->io[I], data2 + start*bucket_size, length*bucket_size);
		send_bool(fpre->io[I], data + start * bucket_size, length*bucket_size);
	}
	for(int i = start; i < start+length; ++i) {
		for(int j = 1; j < bucket_size; ++j) {
			data[i*bucket_size+j] = (data[i*bucket_size+j] != data2[i*bucket_size+j]);
		}
	}
	for(int i = start; i < start+length; ++i) {
		for(int j = 0; j < 3; ++j) {
			MAC2[i*3+j] = fpre->MAC[location[i*bucket_size]*3+j];
			KEY2[i*3+j] = fpre->KEY[location[i*bucket_size]*3+j];
			r2[i*3+j] = fpre->r[location[i*bucket_size]*3+j];
		}
		for(int j = 1; j < bucket_size; ++j) {
			MAC2[3*i] = xorBlocks(MAC2[3*i], fpre->MAC[location[i*bucket_size+j]*3]);
			KEY2[3*i] = xorBlocks(KEY2[3*i], fpre->KEY[location[i*bucket_size+j]*3]);
			r2[3*i] = (r2[3*i] != fpre->r[location[i*bucket_size+j]*3]);

			MAC2[i*3+2] = xorBlocks(MAC2[i*3+2], fpre->MAC[location[i*bucket_size+j]*3+2]);
			KEY2[i*3+2] = xorBlocks(KEY2[i*3+2], fpre->KEY[location[i*bucket_size+j]*3+2]);
			r2[i*3+2] = (r2[i*3+2] != fpre->r[location[i*bucket_size+j]*3+2]);

			if(data[i*bucket_size+j]) {
				KEY2[i*3+2] = xorBlocks(KEY2[i*3+2], fpre->KEY[location[i*bucket_size+j]*3]);
				MAC2[i*3+2] = xorBlocks(MAC2[i*3+2], fpre->MAC[location[i*bucket_size+j]*3]);
				r2[i*3+2] = (r2[i*3+2] != fpre->r[location[i*bucket_size+j]*3]);
			}
		}
	}
	fpre->io[I]->flush();
}
void generate_and_check(Fpre* fpre, int start, int length, int I) {
	fpre->io[I]->flush();
	fpre->io2[I]->flush();
	fpre->generate(fpre->MAC + start * fpre->bucket_size*3, fpre->KEY + start * fpre->bucket_size*3, fpre->r + start * fpre->bucket_size*3, length * fpre->bucket_size, I);

	future<void> res = fpre->pool->enqueue(
	&Fpre::check, fpre,   fpre->MAC + start * fpre->bucket_size*3, fpre->KEY + start * fpre->bucket_size*3, fpre->r + start * fpre->bucket_size*3, fpre->party==ALICE, length * fpre->bucket_size, fpre->io[I], I);
	fpre->check(   fpre->MAC + start * fpre->bucket_size*3, fpre->KEY + start * fpre->bucket_size*3, fpre->r + start * fpre->bucket_size*3, fpre->party==BOB, length * fpre->bucket_size, fpre->io2[I], I);
	res.get();
}
}
#endif// FPRE_H__
