#ifndef EMP_AG2PC_FPRE_H__
#define EMP_AG2PC_FPRE_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <thread>
#include "emp-ag2pc/feq.h"
#include "emp-ag2pc/helper.h"
#include "emp-ag2pc/leaky_deltaot.h"
#include "emp-ag2pc/config.h"

namespace emp {
//#define __debug

template<typename T>
class Fpre {
	public:
		ThreadPool *pool;
		const static int THDS = fpre_threads;
		int batch_size = 0, bucket_size = 0, size = 0;
		int party;
		block * keys = nullptr;
		bool * values = nullptr;
		PRG prg;
		PRP prp;
		PRP *prps;
		T *io[THDS];
		T *io2[THDS];
		int bandwidth() {
			int sum = 0;
			for(int i = 0; i < THDS; ++i) {
				sum+=io[i]->counter;
				sum+=io2[i]->counter;
			}
			return sum;
		}
		LeakyDeltaOT<T> *abit1[THDS], *abit2[THDS];
		block Delta;
		block ZDelta;
		block one;
		Feq<T> *eq[THDS*2];
		block * MAC = nullptr, *KEY = nullptr;
		block * MAC_res = nullptr, *KEY_res = nullptr;
		block * pretable = nullptr;
		Fpre(T * in_io, int in_party, int bsize = 1000) {
			pool = new ThreadPool(THDS*2);
			prps = new PRP[THDS*2];
			this->party = in_party;
			for(int i = 0; i < THDS; ++i) {
				usleep(1000);
				io[i] = new T(in_io->is_server?nullptr:in_io->addr.c_str(), in_io->port, true);
				usleep(1000);
				io2[i] = new T(in_io->is_server?nullptr:in_io->addr.c_str(), in_io->port, true);
				eq[i] = new Feq<T>(io[i], party);
				eq[THDS+i] = new Feq<T>(io2[i], party);
			}

			abit1[0] = new LeakyDeltaOT<T>(io[0]);
			abit2[0] = new LeakyDeltaOT<T>(io2[0]);

			bool tmp_s[128];
			prg.random_bool(tmp_s, 128);
			tmp_s[0] = true;
			if(party == ALICE) {
				tmp_s[1] = true;
				abit1[0]->setup_send(tmp_s);
				io[0]->flush();
				abit2[0]->setup_recv();
			} else {
				tmp_s[1] = false;
				abit1[0]->setup_recv();
				io[0]->flush();
				abit2[0]->setup_send(tmp_s);
			}
			io2[0]->flush();
			for(int i = 1; i < THDS; ++i) {
				abit1[i] = new LeakyDeltaOT<T>(io[i]);
				abit2[i] = new LeakyDeltaOT<T>(io2[i]);
				if(party == ALICE) { 
					abit1[i]->setup_send(tmp_s, abit1[0]->k0);
					abit2[i]->setup_recv(abit2[0]->k0, abit2[0]->k1);
				} else {
					abit2[i]->setup_send(tmp_s, abit2[0]->k0);
					abit1[i]->setup_recv(abit1[0]->k0, abit1[0]->k1);
				}
			}

			if(party == ALICE) Delta = abit1[0]->Delta;
			else Delta = abit2[0]->Delta;
			one = makeBlock(0, 1);
			ZDelta =  Delta  & makeBlock(0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFE);
			set_batch_size(bsize);
		}
		int permute_batch_size;
		void set_batch_size(int size) {
			size = std::max(size, 320);
			batch_size = ((size+THDS*2-1)/(2*THDS))*THDS*2;
			if(batch_size >= 280*1000) {
				bucket_size = 3;
				permute_batch_size = 280000;
			}
			else if(batch_size >= 3100) {
				bucket_size = 4;
				permute_batch_size = 3100;
			}
			else bucket_size = 5;
			
			delete[] MAC;
			delete[] KEY;
	      
			MAC = new block[batch_size * bucket_size * 3];
			KEY = new block[batch_size * bucket_size * 3];
			MAC_res = new block[batch_size * 3];
			KEY_res = new block[batch_size * 3];
//			cout << size<<"\t"<<batch_size<<"\n";
		}
		~Fpre() {

			delete[] MAC;
		        delete[] KEY;
			delete[] MAC_res;
			delete[] KEY_res;
			delete[] prps;
			delete pool;
			for(int i = 0; i < THDS; ++i) {
				delete abit1[i];
				delete abit2[i];
				delete io[i];
				delete io2[i];
				delete eq[i];
                                delete eq[THDS + i];
			}
		}
		void refill() {
			auto start_time = clock_start();
			vector<future<void>> res;
			for(int i = 0; i < THDS; ++i) {
				int start = i*(batch_size/THDS);
				int length = batch_size/THDS;
				res.push_back(pool->enqueue([this, start, length, i](){
					generate(MAC + start * bucket_size*3, KEY + start * bucket_size*3, length * bucket_size, i);
				}));
			}
			joinNclean(res);

			if(party == ALICE) {
				cout <<"ABIT\t"<<time_from(start_time)<<"\n";
				start_time = clock_start();
			}

		int T2U = THDS*2;
			for(int i = 0; i < T2U; ++i) {
				int start = i*(batch_size/T2U);
				int length = batch_size/T2U;
				res.push_back(pool->enqueue([this, start, length, i](){
					check(MAC + start * bucket_size*3, KEY + start * bucket_size*3, length * bucket_size, i);
				}));
			}
			joinNclean(res);
			if(party == ALICE) {
				cout <<"check\t"<<time_from(start_time)<<"\n";
				start_time = clock_start();
			}

#ifdef __debug
			check_correctness(MAC, KEY, batch_size);
#endif
			block S = coin_tossing(prg, io[0], party);
			if(bucket_size > 4) {
				combine(S, 0, MAC, KEY, batch_size, bucket_size, MAC_res, KEY_res);
			} else {
				int width = min((batch_size+THDS-1)/THDS, permute_batch_size);
				for(int i = 0; i < THDS; ++i) {
					int start = i*width;
					int length = min( (i+1)*width, batch_size) - i*width;
					res.push_back(pool->enqueue([this, start, length, i, S](){
						combine(S, i, MAC+start*bucket_size*3, KEY+start*bucket_size*3, length, bucket_size, MAC_res+start*3, KEY_res+start*3);
					}));
				}
				joinNclean(res);
			}
			if(party == ALICE) {
				cout <<"permute\t"<<time_from(start_time)<<"\n";
				start_time = clock_start();
			}

#ifdef __debug
			check_correctness(MAC, KEY, batch_size);
#endif
			char dgst[Hash::DIGEST_SIZE];
			for(int i = 1; i < 2*THDS; ++i) {
				eq[i]->dgst(dgst);
				eq[0]->add_data(dgst, Hash::DIGEST_SIZE);
			}
			if(!eq[0]->compare()) {
				error("FEQ error\n");
			}
		}

		void generate(block * MAC, block * KEY, int length, int I) {
			if (party == ALICE) {
				future<void> fut = pool->enqueue([this, length, KEY, I](){
					abit1[I]->send_dot(KEY, length*3);
				});
				abit2[I]->recv_dot(MAC, length*3);
				fut.get();
			} else {
				future<void> fut = pool->enqueue([this, length, KEY, I](){
					abit2[I]->send_dot(KEY, length*3);
				});
				abit1[I]->recv_dot(MAC, length*3);
				fut.get();
			}
		}
		
		void check(block * MAC, block * KEY, int length, int I) {
			T * local_io = (I%2==0) ? io[I/2]: io2[I/2];

			block * G = new block[length];
			block * C = new block[length];
			block * GR = new block[length];
			bool * d = new bool[length];
			bool * dR = new bool[length];
	
			for (int i = 0; i < length; ++i) {
				C[i] = KEY[3*i+1] ^ MAC[3*i+1];
				C[i] = C[i] ^ (select_mask[getLSB(MAC[3*i+1])] & Delta);
				G[i] = H2D(KEY[3*i], Delta, I);
				G[i] = G[i] ^ C[i];
			}
			if(party == ALICE) {
				local_io->send_data(G, sizeof(block)*length);
				local_io->recv_data(GR, sizeof(block)*length);
			} else {
				local_io->recv_data(GR, sizeof(block)*length);
				local_io->send_data(G, sizeof(block)*length);
			}
			local_io->flush();
			for(int i = 0; i < length; ++i) {
				block S = H2(MAC[3*i], KEY[3*i], I);
				S = S ^ MAC[3*i+2] ^ KEY[3*i+2];
				S = S ^ (select_mask[getLSB(MAC[3*i])] & (GR[i] ^ C[i]));
				G[i] = S ^ (select_mask[getLSB(MAC[3*i+2])] & Delta);
				d[i] = getL2SB(G[i]);
			}

			if(party == ALICE) {
				local_io->send_bool(d, length);
				local_io->recv_bool(dR,length);
			} else {
				local_io->recv_bool(dR, length);
				local_io->send_bool(d, length);
			}
			local_io->flush();
			for(int i = 0; i < length; ++i) {
				d[i] = d[i] != dR[i];
				if (d[i]) {
					if(party == ALICE) 
						MAC[3*i+2] = MAC[3*i+2] ^ one;
					else 
						KEY[3*i+2] = KEY[3*i+2] ^ ZDelta;
					
					G[i] = G[i] ^ Delta;
				}
				eq[I]->add_block(G[i]);
			}
			delete[] G;
			delete[] GR;
			delete[] C;
			delete[] d;
			delete[] dR;
		}
		block H2D(block a, block b, int I) {
			block d[2];
			d[0] = a;
			d[1] = a ^ b;
			prps[I].permute_block(d, 2);
			d[0] = d[0] ^ d[1];
			return d[0] ^ b;
		}

		block H2(block a, block b, int I) {
			block d[2];
			d[0] = a;
			d[1] = b;
			prps[I].permute_block(d, 2);
			d[0] = d[0] ^ d[1];
			d[0] = d[0] ^ a;
			return d[0] ^ b;
		}

		bool getL2SB(block b) {
			unsigned char x = *((unsigned char*)&b);
			return ((x >> 1) & 0x1) == 1;
		}

		void combine(block S, int I, block * MAC, block * KEY, int length, int bucket_size, block * MAC_res, block * KEY_res) {
			int *location = new int[length*bucket_size];
			for(int i = 0; i < length*bucket_size; ++i) location[i] = i;
			PRG prg(&S, I); 
			int * ind = new int[length*bucket_size];
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
			for(int i = 0; i < length; ++i) {
				for(int j = 1; j < bucket_size; ++j) {
					data[i*bucket_size+j] = getLSB(MAC[location[i*bucket_size]*3+1] ^ MAC[location[i*bucket_size+j]*3+1]);
				}
			}
			if(party == ALICE) {
				io[I]->send_bool(data, length*bucket_size);
				io[I]->recv_bool(data2, length*bucket_size);
			} else {
				io[I]->recv_bool(data2, length*bucket_size);
				io[I]->send_bool(data, length*bucket_size);
			}
			io[I]->flush();
			for(int i = 0; i < length; ++i) {
				for(int j = 1; j < bucket_size; ++j) {
					data[i*bucket_size+j] = (data[i*bucket_size+j] != data2[i*bucket_size+j]);
				}
			}
			for(int i = 0; i < length; ++i) {
				for(int j = 0; j < 3; ++j) {
					MAC_res[i*3+j] = MAC[location[i*bucket_size]*3+j];
					KEY_res[i*3+j] = KEY[location[i*bucket_size]*3+j];
				}
				for(int j = 1; j < bucket_size; ++j) {
					MAC_res[3*i] = MAC_res[3*i] ^ MAC[location[i*bucket_size+j]*3];
					KEY_res[3*i] = KEY_res[3*i] ^ KEY[location[i*bucket_size+j]*3];

					MAC_res[i*3+2] = MAC_res[i*3+2] ^ MAC[location[i*bucket_size+j]*3+2];
					KEY_res[i*3+2] = KEY_res[i*3+2] ^ KEY[location[i*bucket_size+j]*3+2];

					if(data[i*bucket_size+j]) {
						KEY_res[i*3+2] = KEY_res[i*3+2] ^ KEY[location[i*bucket_size+j]*3];
						MAC_res[i*3+2] = MAC_res[i*3+2] ^ MAC[location[i*bucket_size+j]*3];
					}
				}
			}

			delete[] data;
			delete[] location;
			delete[] data2;
		}

//for debug
		void check_correctness(block * MAC, block * KEY, int length) {
			if (party == ALICE) {
				for(int i = 0; i < length*3; ++i) {
					bool tmp = getLSB(MAC[i]);
					io[0]->send_data(&tmp, 1);
				}
				io[0]->send_block(&Delta, 1);
				io[0]->send_block(KEY, length*3);
				block DD;io[0]->recv_block(&DD, 1);

				for(int i = 0; i < length*3; ++i) {
					block tmp;io[0]->recv_block(&tmp, 1);
					if(getLSB(MAC[i])) tmp = tmp ^ DD;
					if (!cmpBlock(&tmp, &MAC[i], 1))
						cout <<i<<"\tWRONG ABIT2!\n";
				}

			} else {
				bool tmp[3];
				for(int i = 0; i < length; ++i) {
					io[0]->recv_data(tmp, 3);
					bool res = ((tmp[0] != getLSB(MAC[3*i]) ) && (tmp[1] != getLSB(MAC[3*i+1])));
					if(res != (tmp[2] != getLSB(MAC[3*i+2])) ) {
						cout <<i<<"\tWRONG!\t";
					}
				}
				block DD;io[0]->recv_block(&DD, 1);

				for(int i = 0; i < length*3; ++i) {
					block tmp;io[0]->recv_block(&tmp, 1);
					if(getLSB(MAC[i])) tmp = tmp ^ DD;
					if (!cmpBlock(&tmp, &MAC[i], 1))
						cout <<i<<"\tWRONG ABIT2!\n";
				}

				io[0]->send_block(&Delta, 1);
				io[0]->send_block(KEY, length*3);
			}
			io[0]->flush();
		}
};
}
#endif// FPRE_H__
