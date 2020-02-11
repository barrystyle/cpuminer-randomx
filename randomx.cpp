#include "RandomX/src/bytecode_machine.hpp"
#include "RandomX/src/dataset.hpp"
#include "RandomX/src/blake2/endian.h"
#include "RandomX/src/blake2/blake2.h"
#include "RandomX/src/blake2_generator.hpp"
#include "RandomX/src/superscalar.hpp"
#include "RandomX/src/reciprocal.h"
#include "RandomX/src/intrin_portable.h"
#include "RandomX/src/jit_compiler.hpp"
#include "RandomX/src/aes_hash.hpp"
#include "RandomX/src/randomx.h"
#include <openssl/sha.h>
#include <miner.h>
#include "uint256.h"
#include "randomx.h"

#include <cassert>

//! barrystyle 03032020
uint256 oldCache;
char keyCache[32];
unsigned int seedHeight;

//! vector to hold thread obj
std::vector<randomx_flags> vecFlag;
std::vector<randomx_cache*> vecCache;
std::vector<randomx_dataset*> vecDataset;
std::vector<randomx_vm*> vecVm;

extern "C" {
void randomx_init(int thr_id)
{
    randomx_initseed();
    for (int i=0; i<thr_id; i++) {
       randomx_initcache(i);
       randomx_initdataset(i);
       randomx_initvm(i);
    }
}
}

void randomx_initseed()
{
    seedHash(oldCache,keyCache,1);
}

void randomx_initcache(int thr_id)
{
    printf("%s - instance %d\n", __func__, thr_id);
    randomx_flags flags = randomx_get_flags();
    vecFlag.push_back(flags);
    randomx_cache *cache = randomx_alloc_cache(vecFlag.at(thr_id) | RANDOMX_FLAG_LARGE_PAGES);
    if (!cache)
        cache = randomx_alloc_cache(flags);
    randomx_init_cache(cache, &keyCache, 32);
    vecCache.push_back(cache);
}

void randomx_initdataset(int thr_id)
{
    printf("%s - instance %d\n", __func__, thr_id);
    randomx_dataset *dataset = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
    if (!dataset)
        dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
    randomx_init_dataset(dataset, vecCache.at(thr_id), 0, randomx_dataset_item_count());
    vecDataset.push_back(dataset);
}

void randomx_initvm(int thr_id)
{
    printf("%s - instance %d\n", __func__, thr_id);
    randomx_vm *vm = randomx_create_vm(vecFlag.at(thr_id), vecCache.at(thr_id), vecDataset.at(thr_id));
    vecVm.push_back(vm);
}

void seedNow(int nHeight)
{
    uint256 tempCache;
    char tempStr[64];
    seedHash(tempCache, tempStr, nHeight);
    if (!memcmp(&tempCache,keyCache,32)) {
        printf("* changed seed at height %d\n", nHeight);
        memcpy(keyCache,&tempCache,32);
    }
}

void seedHash(uint256 &seed, char *seedStr, int nHeight)
{
    char seedHalf[32] = {0};
    int seedInt = (((nHeight+99)/100)+100);
    sprintf(seedHalf,"%d",seedInt);
    SHA256((const unsigned char*)seedHalf,32,(unsigned char*)seedHalf);
    memcpy(&seed,seedHalf,32);
    for (unsigned int i=0; i<32; i++)
        sprintf(seedStr+(i*2),"%02hhx", seedHalf[i]);
}

void randomxhash(const char* input, char* output, unsigned int len, int thr_id)
{
    char hash[32] = {0};
    randomx_calculate_hash(vecVm.at(thr_id), input, len, hash);
    memcpy(output, hash, 32);
}

extern "C" {

    int scanhash_randomx(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done) {

        uint32_t _ALIGN(128) hash[8];
        uint32_t _ALIGN(128) endiandata[36];
        for(unsigned int i=0; i<36; i++)
            endiandata[i] = 0;
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19];
        uint32_t n = first_nonce;

        bool has_roots = false;
        for(int i=0; i < 36; i++) {
            be32enc(&endiandata[i], pdata[i]);
            if(i >= 20 && pdata[i]) has_roots = true;
        }
        unsigned int hashlen = has_roots ? 144 : 80;

        do {

            be32enc(&endiandata[19], n);
            randomxhash((const char*)endiandata, (char*)hash, hashlen, thr_id);

            if(hash[7] < Htarg) {
                printf("DEBUG %08x\n", hash[7]);
                *hashes_done = n - first_nonce + 1;
                pdata[19] = n;
                return 1;
            }
            n++;

        } while(n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;

        return 0;
    }

}
