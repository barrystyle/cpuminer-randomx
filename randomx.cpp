#include <string.h>
#include "miner.h"
#include "uint256.h"
#include "RandomX/src/randomx.h"

// barrystyle 08072020

bool is_init = false;
char randomx_seed[32]={0};

randomx_flags flags;
randomx_vm* rx_vm = nullptr;
randomx_cache* cache = nullptr;

void seed_set(uint256 newseed)
{
//  printf("%s\n", __func__);
    if (!newseed)
        memset(randomx_seed,0,32);
    else
        memcpy(randomx_seed,&newseed,32);
}

bool seed_changed(uint256 newseed)
{
    bool changed = false;
    if (memcmp(&newseed,randomx_seed,32)==0) {
        seed_set(newseed);
        changed = true;
    }
    printf("%s returning %s\n", __func__, changed ? "true" : "false");
    return changed;
}

void randomx_init()
{
//  printf("%s\n", __func__);

    seed_set(0);

    if (!cache) {
        flags = randomx_get_flags();
        cache = randomx_alloc_cache(flags);
        randomx_init_cache(cache, &randomx_seed, 32);
    }

    if (!rx_vm)
        rx_vm = randomx_create_vm(flags, cache, nullptr);

    is_init = true;
}

void randomx_reinit()
{
    printf("%s\n", __func__);

    randomx_destroy_vm(rx_vm);
    randomx_release_cache(cache);

    cache = randomx_alloc_cache(flags);
    randomx_init_cache(cache, randomx_seed, 32);
    rx_vm = randomx_create_vm(flags, cache, nullptr);
}

void rx_slow_hash(const char* data, char* hash, int length, uint256 seedhash)
{
//  printf("%s\n", __func__);

    if (!is_init)
        randomx_init();

    if (seed_changed(seedhash))
        randomx_reinit();

    randomx_calculate_hash(rx_vm, data, length, hash);
}

#ifdef __cplusplus
extern "C" {
#endif

int scanhash_randomx(int thr_id, struct work* work, const char* seedhash, uint32_t max_nonce, uint64_t* hashes_done)
{
    uint32_t  hash[8];
    uint32_t  endiandata[36];
    uint32_t* pdata = work->data;
    uint32_t* ptarget = work->target;

    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;

    bool has_roots = false;
    for (int i=0; i < 36; i++) {
       be32enc(&endiandata[i], pdata[i]);
       if (i >= 20 && pdata[i]) has_roots = true;
    }

//  for (int i=0; i<32; i++)
//     printf("%02hhx", seedhash[i]);
//  printf("\n");

    do {

        be32enc(&endiandata[19], n);
        rx_slow_hash((const char*)endiandata, (char*) hash, 144, *seedhash);

        if (hash[7] < Htarg) {
            printf("DEBUG %08x\n", hash[7]);
            *hashes_done = n - first_nonce + 1;
            pdata[19] = n;
            return 1;
        }
        n++;

    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - first_nonce + 1;
    pdata[19] = n;

    return 0;
}


#ifdef __cplusplus
}
#endif

