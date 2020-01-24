#include "miner.h"
#include "algo-gate-api.h"
#include "balloon.h"

int scanhash_balloon(struct work* work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        uint32_t _ALIGN(64) hash64[8];
        uint32_t _ALIGN(64) endiandata[20];
	int thr_id = mythr->id;

        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19];
        uint32_t n = first_nonce;

        for (int i=0; i < 19; i++)
                be32enc(&endiandata[i], pdata[i]);

        do {
                be32enc(&endiandata[19], n);
                balloon(endiandata, hash64);
                if (hash64[7] < Htarg && fulltest(hash64, ptarget)) {
                        submit_solution(work, hash64, mythr);
                        *hashes_done = n - first_nonce + 1;
                        pdata[19] = n;
                }
                n++;

        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;

        return 0;
}

bool register_balloon_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
    gate->scanhash = (void*)&scanhash_balloon;
    gate->hash     = (void*)&balloon;
    return true;
};

