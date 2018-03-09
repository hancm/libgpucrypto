#include "cuda_mem_pool.hh"

#include <cuda_runtime.h>
//#include <cutil_inline.h>

#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

//#include "common.hh"

static uint64_t get_usec()
{
        struct timeval tv;
        assert(gettimeofday(&tv, NULL) == 0);
        return tv.tv_sec * 1000000 + tv.tv_usec;
}

cuda_mem_pool::~cuda_mem_pool()
{
        if(mem_)
        {
                /*cutilSafeCall*/(cudaFree(mem_));
                mem_ = 0;
        }
}

bool cuda_mem_pool::init(unsigned long maxsize)
{
        uint64_t startTime = get_usec();
        maxsize_ = maxsize;
        /*cutilSafeCall*/(cudaMalloc((void**)&mem_, maxsize));
        uint64_t endTime = get_usec();
        printf("cudaMalloc time: %d, size: %d.\n", endTime - startTime, maxsize);

        return true;
}


void cuda_mem_pool::destroy()
{
	if (mem_) {
        /*cutilSafeCall*/(cudaFree(mem_));
		mem_ = NULL;
	}
}
