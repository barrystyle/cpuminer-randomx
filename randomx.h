#include "uint256.h"

extern "C" {
void randomx_init(int thr_id);
}

void randomx_initseed();
void randomx_initcache(int thr_id);
void randomx_initdataset(int thr_id);
void randomx_initvm(int thr_id);
void randomx_shutoff(int thr_id);
void seedNow(int nHeight);
void seedHash(uint256 &seed, char *seedStr, int nHeight);
void randomxhash(const char* input, char* output, int len);
