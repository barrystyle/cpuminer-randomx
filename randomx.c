#include <miner.h>
#include <openssl/sha.h>
#include <rxhash/rx-slow-hash.h>

static bool has_roots;

int scanhash_randomx(int thr_id, struct work* work, const char* seedhash, uint32_t max_nonce, uint64_t* hashes_done)
{
    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) endiandata[36];
    uint32_t* pdata = work->data;
    uint32_t* ptarget = work->target;

    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;

    if (opt_benchmark) {
        ptarget[7] = 0x00ff;
    }

    has_roots = false;
    for (int i=0; i < 36; i++) {
	be32enc(&endiandata[i], pdata[i]);
	if (i >= 20 && pdata[i]) has_roots = true;
    }

//  for (int i=0; i<32; i++)
//     printf("%02hhx", seedhash[i]);
//  printf("\n");

    do {

        be32enc(&endiandata[19], n);
        rx_slow_hash(0, 0, (const char*)seedhash, (const char*)endiandata, 144, (char*)hash, 0, 0);

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
