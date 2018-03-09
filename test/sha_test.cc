#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <fstream>

#include <sys/time.h>
#include <typeinfo>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>

#include <openssl/hmac.h>

#include <cuda_runtime.h>

#include "sha1.hh"
#include "sha_context.hh"
#include "device_context.hh"
#include "pinned_mem_pool.hh"
#include "cuda_mem_pool.hh"
#include "common.hh"

#define HMAC_SHA1_HASH_SIZE 20
#define MAX_FLOW_LEN (1024 * 1024 * 100)//16384
#define MAX_FLOW_NUM (1024 * 256)

#define TOTAL_THREAD_NUM (32 * 1024)

#define max(a,b) ((a >= b)?(a):(b))

typedef struct hmac_sha1_param
{
	uint8_t         *memory_start;
	unsigned long   pkt_offset_pos;
	unsigned long   in_pos;
	unsigned long   key_pos;
	unsigned long   length_pos;
	unsigned        total_size;
	unsigned        num_flows;
	uint8_t         *out;
} hmac_sha1_param_t;


void gen_hmac_sha1_data(operation_batch_t *ops,
			unsigned          num_flows,
			unsigned          flow_len)
{
	assert(flow_len  > 0 && flow_len  <= MAX_FLOW_LEN);
    assert(num_flows > 0 && num_flows <= MAX_FLOW_NUM);
	assert(ops != NULL);

	//prepare buffer for data generation
	ops->resize(num_flows);

	//generate random data
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		(*i).destroy();

		//input data
		(*i).in_len  = flow_len;
		(*i).in      = (uint8_t*)malloc(flow_len);
		assert((*i).in != NULL);
//        set_random((*i).in, flow_len);
        memset((*i).in, 0, flow_len);

		//output data
		(*i).out_len = HMAC_SHA1_HASH_SIZE;
		(*i).out     = (uint8_t*)malloc(HMAC_SHA1_HASH_SIZE);
		assert((*i).out != NULL);
//        set_random((*i).out, HMAC_SHA1_HASH_SIZE);
        memset((*i).out, 0, HMAC_SHA1_HASH_SIZE);

		//key
		(*i).key_len = MAX_KEY_SIZE;
		(*i).key     = (uint8_t*)malloc(MAX_KEY_SIZE);
		assert((*i).key != NULL);
//        set_random((*i).key, MAX_KEY_SIZE);
        memset((*i).key, 0, MAX_KEY_SIZE);

		(*i).op = HMAC_SHA1;
	}

}

void hmac_sha1_prepare(operation_batch_t *ops,
		       hmac_sha1_param_t *param,
		       pinned_mem_pool   *pool)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);
	assert(pool != NULL);

	uint32_t *pkt_offset;
	uint8_t  *in;
    /*uint16_t*/uint32_t *lengths;
	uint8_t  *keys;
	uint8_t  *out;

	unsigned tot_in_size = 0; /* total size of input text */

	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		tot_in_size += (*i).in_len;
	}

	unsigned long num_flows = ops->size();

	//allocate memory
	pkt_offset = (uint32_t *)pool->alloc(sizeof(uint32_t) * (num_flows));
	keys       = (uint8_t  *)pool->alloc(num_flows * MAX_KEY_SIZE);
	in         = (uint8_t  *)pool->alloc(tot_in_size);
    lengths     = (/*uint16_t*/uint32_t *)pool->alloc(sizeof(/*uint16_t*/uint32_t) * num_flows);
	out        = (uint8_t  *)pool->alloc(HMAC_SHA1_HASH_SIZE * num_flows);

	assert(pkt_offset != NULL);
	assert(keys       != NULL);
	assert(in         != NULL);
	assert(lengths    != NULL);
	assert(out        != NULL);

	//copy data into pinned memory and set metadata
	unsigned cnt = 0;
	unsigned sum_input = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		pkt_offset[cnt] = sum_input;
		lengths[cnt]    = (*i).in_len;

		memcpy(keys + cnt * MAX_KEY_SIZE, (*i).key,  MAX_KEY_SIZE);
		memcpy(in + sum_input,  (*i).in,   (*i).in_len);

		cnt++;
		sum_input += (*i).in_len;
	}

	//set param for sha_context api
	param->memory_start   = (uint8_t*)pkt_offset;
	param->pkt_offset_pos = (unsigned long)((uint8_t *)pkt_offset -
						param->memory_start);
	param->in_pos         = (unsigned long)(in      - param->memory_start);
	param->key_pos        = (unsigned long)(keys    - param->memory_start);
	param->length_pos     = (unsigned long)((uint8_t *)lengths
						- param->memory_start);
	param->total_size     = (unsigned long)(out     - param->memory_start);

	param->out            = out;
	param->num_flows      = num_flows;
}

void hmac_file_sha1_prepare(const char *file_path, unsigned tot_in_size,
                            operation_batch_t *ops,
                            hmac_sha1_param_t *param,
                            pinned_mem_pool   *pool)
{
    assert(param != NULL);
    assert(pool != NULL);

    uint32_t *pkt_offset;
    uint8_t  *in;
    uint32_t *lengths;
    uint8_t  *keys;
    uint8_t  *out;

//    unsigned tot_in_size = 0; /* total size of input text */
//    struct stat buf;
//    stat(file_path, &buf);
//    tot_in_size = buf.st_size;
//    printf("file size: %d\n", tot_in_size);
//    assert(tot_in_size > 0);

//    for (operation_batch_t::iterator i = ops->begin();
//         i != ops->end(); i++) {
//        assert((*i).in_len > 0);
//        tot_in_size += (*i).in_len;
//    }

    unsigned long num_flows = TOTAL_THREAD_NUM;

    int threadDataLen = tot_in_size / (num_flows - 1);
    int threadDataFree = tot_in_size % (num_flows - 1);
    if (0 == threadDataFree) {
        threadDataLen = (tot_in_size - 1) / (num_flows - 1);
        threadDataFree = tot_in_size % threadDataLen;
    }

    if (0 == tot_in_size % num_flows) {
        threadDataLen = tot_in_size / num_flows;
        threadDataFree = 0;
    }
    printf("dataLen: %d, dataFree: %d.\n", threadDataLen, threadDataFree);

    //allocate memory
    pkt_offset = (uint32_t *)pool->alloc(sizeof(uint32_t) * (num_flows));
    keys       = (uint8_t  *)pool->alloc(num_flows * MAX_KEY_SIZE);
    in         = (uint8_t  *)pool->alloc(tot_in_size);
    lengths     = (uint32_t *)pool->alloc(sizeof(uint32_t) * num_flows);
    out        = (uint8_t  *)pool->alloc(HMAC_SHA1_HASH_SIZE * num_flows);

    assert(pkt_offset != NULL);
    assert(keys       != NULL);
    assert(in         != NULL);
    assert(lengths    != NULL);
    assert(out        != NULL);

    // 生成数据
    // memcpy(keys + cnt * MAX_KEY_SIZE, (*i).key,  MAX_KEY_SIZE);
//    memcpy(in + sum_input,  (*i).in,   (*i).in_len);
    std::ifstream inFile(file_path, std::ifstream::binary);
    if (!inFile) {
        printf("Failed to open.\n");
        return;
    }

    inFile.read((char*)in, tot_in_size);
    if (!inFile) {
        printf("Failed to write.\n");
        return;
    }
    inFile.close();

    // 生成数据偏移和长度
    for (int i = 0; i < num_flows; i++) {
        pkt_offset[i] = threadDataLen * i;
        lengths[i]    = threadDataLen;
    }

    if (0 != threadDataFree) {
        lengths[num_flows - 1] = threadDataFree;
    }

//    printf("ops size: %d, num flows: %d.\n", ops->size(), num_flows);
//    for (int i = 0; i < ops->size() - 1 && i < num_flows - 1; ++i) {
//        memcpy((*ops)[i].in, in + pkt_offset[i], lengths[i]);
//        (*ops)[i].in_len = lengths[i];
//    }

    //copy data into pinned memory and set metadata
//    unsigned cnt = 0;
//    unsigned sum_input = 0;
//    for (operation_batch_t::iterator i = ops->begin();
//         i != ops->end(); i++) {
//        pkt_offset[cnt] = sum_input;
//        lengths[cnt]    = (*i).in_len;
//
//        memcpy(keys + cnt * MAX_KEY_SIZE, (*i).key,  MAX_KEY_SIZE);
//        memcpy(in + sum_input,  (*i).in,   (*i).in_len);
//
//        cnt++;
//        sum_input += (*i).in_len;
//    }

    //set param for sha_context api
    param->memory_start   = (uint8_t*)pkt_offset;                                           // pool中param开始地址
    param->pkt_offset_pos = (unsigned long)((uint8_t *)pkt_offset - param->memory_start);   // 每个分片数据块的偏移量位置
    param->key_pos        = (unsigned long)(keys    - param->memory_start);                 // 密钥位置
    param->in_pos         = (unsigned long)(in      - param->memory_start);                 // 输入数据位置
    param->length_pos     = (unsigned long)((uint8_t *)lengths - param->memory_start);      // 各个分片数据块长度
    param->total_size     = (unsigned long)(out     - param->memory_start);                 // pool分配的总的数据长度

    param->out            = out;                                                            // 输出的hash地址
    param->num_flows      = num_flows;                                                      // 输入数据分块数目
}

void hmac_file_stream_sha1_prepare(std::ifstream &inFile, int file_pos,
                            int tot_in_size,
                            operation_batch_t *ops,
                            hmac_sha1_param_t *param,
                            pinned_mem_pool   *pool)
{
    assert(param != NULL);
    assert(pool != NULL);

    uint32_t *pkt_offset;
    uint8_t  *in;
    uint32_t *lengths;
    uint8_t  *keys;
    uint8_t  *out;

    unsigned long num_flows = TOTAL_THREAD_NUM;

    int threadDataLen = tot_in_size / (num_flows - 1);
    int threadDataFree = tot_in_size % (num_flows - 1);
    if (0 == threadDataFree) {
        threadDataLen = (tot_in_size - 1) / (num_flows - 1);
        threadDataFree = tot_in_size % threadDataLen;
    }

    if (0 == tot_in_size % num_flows) {
        threadDataLen = tot_in_size / num_flows;
        threadDataFree = 0;
    }
    printf("dataLen: %d, dataFree: %d.\n", threadDataLen, threadDataFree);

    //allocate memory
    pkt_offset = (uint32_t *)pool->alloc(sizeof(uint32_t) * (num_flows));
    keys       = (uint8_t  *)pool->alloc(num_flows * MAX_KEY_SIZE);
    in         = (uint8_t  *)pool->alloc(tot_in_size);
    lengths     = (uint32_t *)pool->alloc(sizeof(uint32_t) * num_flows);
    out        = (uint8_t  *)pool->alloc(HMAC_SHA1_HASH_SIZE * num_flows);

    assert(pkt_offset != NULL);
    assert(keys       != NULL);
    assert(in         != NULL);
    assert(lengths    != NULL);
    assert(out        != NULL);

    // 生成数据
    // memcpy(keys + cnt * MAX_KEY_SIZE, (*i).key,  MAX_KEY_SIZE);
//    memcpy(in + sum_input,  (*i).in,   (*i).in_len);

    inFile.seekg(file_pos * tot_in_size, std::ios::beg);
    inFile.read((char*)in, tot_in_size);
    if (!inFile) {
        printf("Failed to write.\n");
        return;
    }

    // 生成数据偏移和长度
    for (int i = 0; i < num_flows; i++) {
        pkt_offset[i] = threadDataLen * i;
        lengths[i]    = threadDataLen;
    }

    if (0 != threadDataFree) {
        lengths[num_flows - 1] = threadDataFree;
    }

//    printf("ops size: %d, num flows: %d.\n", ops->size(), num_flows);
//    for (int i = 0; i < ops->size() - 1 && i < num_flows - 1; ++i) {
//        memcpy((*ops)[i].in, in + pkt_offset[i], lengths[i]);
//        (*ops)[i].in_len = lengths[i];
//    }

    //set param for sha_context api
    param->memory_start   = (uint8_t*)pkt_offset;
    param->pkt_offset_pos = (unsigned long)((uint8_t *)pkt_offset - param->memory_start);
    param->in_pos         = (unsigned long)(in      - param->memory_start);
    param->key_pos        = (unsigned long)(keys    - param->memory_start);
    param->length_pos     = (unsigned long)((uint8_t *)lengths - param->memory_start);
    param->total_size     = (unsigned long)(out     - param->memory_start);

    param->out            = out;
    param->num_flows      = num_flows;
}

void hmac_sha1_post(operation_batch_t *ops,
		    hmac_sha1_param_t   *param)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);

	unsigned sum_outsize = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
        (*i).out_len = 20;
//        assert((*i).in_len > 0);
        memcpy((*i).out, param->out + sum_outsize,   (*i).out_len);
		sum_outsize += (*i).out_len;
	}
}


bool verify_hmac_sha1(operation_batch_t *ops)
{
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		uint8_t out_temp[HMAC_SHA1_HASH_SIZE];

		unsigned len;
		HMAC(EVP_sha1(),
		     (*i).key,
		     (*i).key_len,
		     (*i).in,
		     (*i).in_len,
		     out_temp,
		     &len);
		assert(len == HMAC_SHA1_HASH_SIZE);

		if (memcmp(out_temp, (*i).out, (*i).out_len) != 0) {
			return false;
		}
	}
	return true;
}


static bool test_correctness_hmac_sha1(unsigned  num_flows, unsigned flow_len)
{
	device_context dev_ctx;
	dev_ctx.init(104857600, 0);
	sha_context sha_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(104857600);

	operation_batch_t ops;
	hmac_sha1_param_t param;

	gen_hmac_sha1_data(&ops, num_flows, flow_len);
	hmac_sha1_prepare(&ops, &param, pool);

	sha_ctx.hmac_sha1((void*)param.memory_start,
			  param.in_pos,
			  param.key_pos,
			  param.pkt_offset_pos,
			  param.length_pos,
			  param.total_size,
			  param.out,
			  param.num_flows,
			  0);

	sha_ctx.sync(0);

	hmac_sha1_post(&ops, &param);

	delete pool;

	return verify_hmac_sha1(&ops);
}

static void test_latency_hmac_sha1(unsigned num_flows, unsigned flow_len)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * max(flow_len, 512) * 2.2, 0);
	sha_context sha_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * max(flow_len, 512) * 2.2);

	operation_batch_t ops;
	hmac_sha1_param_t param;

	gen_hmac_sha1_data(&ops, num_flows, flow_len);
	hmac_sha1_prepare(&ops, &param, pool);

	sha_ctx.hmac_sha1((void*)param.memory_start,
			  param.in_pos,
			  param.key_pos,
			  param.pkt_offset_pos,
			  param.length_pos,
			  param.total_size,
			  param.out,
			  param.num_flows,
			  0);

	sha_ctx.sync(0);

	hmac_sha1_post(&ops, &param);

	unsigned rounds = 100;
	uint64_t begin_usec = get_usec();
	for (unsigned i = 0; i < rounds; i++) {
		sha_ctx.hmac_sha1((void*)param.memory_start,
				  param.in_pos,
				  param.key_pos,
				  param.pkt_offset_pos,
				  param.length_pos,
				  param.total_size,
				  param.out,
				  param.num_flows,
				  0);

		sha_ctx.sync(0);
	}
	uint64_t end_usec = get_usec();
	uint64_t total = end_usec - begin_usec;
	uint64_t avg = total / rounds;

	delete pool;

	printf("%4d %13ld %13ld\n",
	       num_flows, avg, num_flows * flow_len * 8 / avg);
}

static void test_latency_stream_hmac_sha1(unsigned num_flows,
					  unsigned flow_len,
					  unsigned num_stream)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * max(flow_len, 512) * 2, num_stream);
	sha_context sha_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * max(flow_len, 512) * 2 * num_stream);

	operation_batch_t ops[MAX_STREAM + 1];
	hmac_sha1_param_t param[MAX_STREAM + 1];

	//warmup
	for (unsigned i = 1; i <= num_stream; i++) {
		gen_hmac_sha1_data(&ops[i], num_flows, flow_len);
		hmac_sha1_prepare(&ops[i], &param[i], pool);
		sha_ctx.hmac_sha1((void*)param[i].memory_start,
				  param[i].in_pos,
				  param[i].key_pos,
				  param[i].pkt_offset_pos,
				  param[i].length_pos,
				  param[i].total_size,
				  param[i].out,
				  param[i].num_flows,
				  i);
		sha_ctx.sync(i, true);
	}

	unsigned count = 0;
	unsigned rounds = 100;
	uint64_t begin_usec = get_usec();
	do {
		int stream = 0;
		for (unsigned i = 1; i <= num_stream; i++) {
			if (dev_ctx.get_state(i) == READY) {
				stream = i;
				break;
			} else {
				if (sha_ctx.sync(i, false)) {
					count++;
					if (count == num_stream )
						begin_usec = get_usec();
				}
			}
		}
		if (stream != 0) {
			sha_ctx.hmac_sha1((void*)param[stream].memory_start,
					  param[stream].in_pos,
					  param[stream].key_pos,
					  param[stream].pkt_offset_pos,
					  param[stream].length_pos,
					  param[stream].total_size,
					  param[stream].out,
					  param[stream].num_flows,
					  stream);

		} else {
		}
	} while (count < rounds + num_stream);
	uint64_t end_usec = get_usec();

	for (unsigned i = 1; i < num_stream; i++) {
		sha_ctx.sync(i, true);
	}
	uint64_t total = end_usec - begin_usec;
	uint64_t avg = total / rounds;

	delete pool;
	printf("%4d %7d %13ld %13ld\n",
	       num_flows, num_stream,
	       avg,
	       num_flows * flow_len * 8 / avg);
}

void test_hmac_sha1(int size)
{
	printf("------------------------------------------\n");
	printf("HMAC_SHA1, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg latency(usec) thruput(Mbps)\n");
	for (unsigned i = 1 ; i <= 4096 ;i = i * 2)
		test_latency_hmac_sha1(i, size);

	printf("Correctness check (batch, random): ");
	bool result = true;
	for (unsigned i = 1 ; i <= 4096 ;i = i * 2)
		result = result && test_correctness_hmac_sha1(i, size);

	if (!result)
		printf("FAIL\n");
	else
		printf("OK\n");

}

void test_hmac_sha1_stream(int size, int num_stream)
{
	printf("------------------------------------------\n");
	printf("HMAC_SHA1, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg #stream latency(usec) thruput(Mbps)\n");
	for (unsigned i = 1 ; i <= 4096 ;i = i * 2)
		test_latency_stream_hmac_sha1(i, size, num_stream);
}


static char usage[] = "%s "
	"[-s number of stream] "
	"[-l length of message in bytes (multiples of 16)]\n";

static void test_file_hmac_sha1(unsigned num_flows, unsigned flow_len)
{
    printf("num_flows: %d, flow_len:%d.\n", num_flows, flow_len);

    uint64_t startTime = get_usec();

    device_context dev_ctx;
    dev_ctx.init(num_flows * max(flow_len, 512) * 1.1, 0);
    sha_context sha_ctx(&dev_ctx);

    pinned_mem_pool *pool;
    pool = new pinned_mem_pool();
    pool->init(num_flows * max(flow_len, 512) * 1.1);

    operation_batch_t ops;
    hmac_sha1_param_t param;

    gen_hmac_sha1_data(&ops, num_flows, flow_len);
    hmac_sha1_prepare(&ops, &param, pool);

    uint64_t dataTime = get_usec();
    printf("dataTime: %d.\n", dataTime - startTime);

    sha_ctx.hmac_sha1((void*)param.memory_start,
              param.in_pos,
              param.key_pos,
              param.pkt_offset_pos,
              param.length_pos,
              param.total_size,
              param.out,
              param.num_flows,
              0);

    sha_ctx.sync(0);
    hmac_sha1_post(&ops, &param);

    uint64_t endTime = get_usec();
    std::cout << "sha1Time: " << endTime - dataTime << " us" << std::endl;

    int iRet = verify_hmac_sha1(&ops);
    uint64_t hmacTime = get_usec();
    printf("Verify ret: %d, time: %d.\n", iRet, hmacTime - endTime);

    for (int j = 0; j < 20; ++j) {
        printf("%X", (char)ops[0].out[j] & 0xFF);
    }
    std::cout << std::endl;

//    printf("Start output param out, batch size: %d, num_flows: %d.", ops.size(), param.num_flows);
//    for (int j = 0; j < param.num_flows * 20; ++j) {
//        if (j % 20 == 0) {
//            printf("\n");
//        }
//        printf("%X", (char)param.out[j] & 0xFF);
//    }
//    printf("\nEnd output param out.\n");
//
//    for (int i = 0; i < ops.size(); ++i) {
//        for (int j = 0; j < ops[i].out_len; ++j) {
//            printf("%X", (char)ops[i].out[j] & 0xFF);
//        }
//        std::cout << std::endl;
//    }

    delete pool;
}

static void test_file_stream_hmac_sha1(unsigned num_flows,
                      unsigned flow_len,
                      unsigned num_stream)
{
    uint64_t startTime = get_usec();

    device_context dev_ctx;
    dev_ctx.init(num_flows * max(flow_len, 512) * 1.1, num_stream);
    sha_context sha_ctx(&dev_ctx);

    pinned_mem_pool *pool;
    pool = new pinned_mem_pool();
    pool->init(num_flows * max(flow_len, 512) * 1.1 * num_stream);

    operation_batch_t ops[MAX_STREAM + 1];
    hmac_sha1_param_t param[MAX_STREAM + 1];

    for (unsigned i = 1; i <= num_stream; i++) {
        gen_hmac_sha1_data(&ops[i], num_flows, flow_len);
        hmac_sha1_prepare(&ops[i], &param[i], pool);
    }

    uint64_t dataTime = get_usec();
    std::cout << "dataTime: " << dataTime - startTime << std::endl;

    //warmup
    for (unsigned i = 1; i <= num_stream; i++) {
//        gen_hmac_sha1_data(&ops[i], num_flows, flow_len);
//        hmac_sha1_prepare(&ops[i], &param[i], pool);
        sha_ctx.hmac_sha1((void*)param[i].memory_start,
                  param[i].in_pos,
                  param[i].key_pos,
                  param[i].pkt_offset_pos,
                  param[i].length_pos,
                  param[i].total_size,
                  param[i].out,
                  param[i].num_flows,
                  i);
//        sha_ctx.sync(i, true);
    }

    for (unsigned i = 1; i <= num_stream; i++) {
        sha_ctx.sync(i, true);
    }

    uint64_t endTime = get_usec();
    std::cout << "sha1Time: " << endTime - dataTime << " us" << std::endl;

    for (unsigned i = 1; i <= num_stream; i++) {
        hmac_sha1_post(&ops[i], &param[i]);
    }

    uint64_t postTime = get_usec();
    std::cout << "postTime: " <<  postTime - endTime << " us" << std::endl;

    for (unsigned i = 1; i <= num_stream; i++) {
        int iRet = verify_hmac_sha1(&ops[i]);
        printf("Verify ret: %d\n", iRet);
    }

    uint64_t hmacTime = get_usec();
    printf("Verify time: %d.\n", hmacTime - postTime);

    for (unsigned i = 1; i <= num_stream; i++) {
        for (int j = 0; j < 20; ++j) {
            printf("%X", (char)ops[i][0].out[j] & 0xFF);
        }
        std::cout << std::endl;
    }

    delete pool;

//    unsigned count = 0;
//    unsigned rounds = 100;
//    uint64_t begin_usec = get_usec();
//    do {
//        int stream = 0;
//        for (unsigned i = 1; i <= num_stream; i++) {
//            if (dev_ctx.get_state(i) == READY) {
//                stream = i;
//                break;
//            } else {
//                if (sha_ctx.sync(i, false)) {
//                    count++;
//                    if (count == num_stream )
//                        begin_usec = get_usec();
//                }
//            }
//        }
//        if (stream != 0) {
//            sha_ctx.hmac_sha1((void*)param[stream].memory_start,
//                      param[stream].in_pos,
//                      param[stream].key_pos,
//                      param[stream].pkt_offset_pos,
//                      param[stream].length_pos,
//                      param[stream].total_size,
//                      param[stream].out,
//                      param[stream].num_flows,
//                      stream);
//
//        } else {
//        }
//    } while (count < rounds + num_stream);
//    uint64_t end_usec = get_usec();
//
//    for (unsigned i = 1; i < num_stream; i++) {
//        sha_ctx.sync(i, true);
//    }
//    uint64_t total = end_usec - begin_usec;
//    uint64_t avg = total / rounds;
//
//    delete pool;
//    printf("%4d %7d %13ld %13ld\n",
//           num_flows, num_stream,
//           avg,
//           num_flows * flow_len * 8 / avg);
}


static void test_file_split_hmac_sha1(const char *file_path)
{
    uint64_t startTime = get_usec();

    unsigned tot_in_size = 0; /* total size of input text */
    struct stat buf;
    stat(file_path, &buf);
    tot_in_size = buf.st_size;
//    printf("file size: %d\n", tot_in_size);
    assert(tot_in_size > 0);

    uint64_t fileSize = get_usec();
    printf("fileSizeTime: %d.\n", fileSize - startTime);

//    int num_flows = 1024;
//    int flow_len = 1024 * 1024;

    device_context dev_ctx;

    // 初始化设备内存 cudaMalloc 耗时,当前设备至少500ms，与初始大小关系不大
    dev_ctx.init(tot_in_size + 3 * 1024 * 1024, 0);//(num_flows * max(flow_len, 512) * 1.8, 0);
    uint64_t devInitTime = get_usec();
    printf("devInitTime: %d.\n", devInitTime - fileSize);

    sha_context sha_ctx(&dev_ctx);

    uint64_t devTime = get_usec();
    printf("sha context time: %d.\n", devTime - devInitTime);

    // 比较耗时
    pinned_mem_pool *pool;
    pool = new pinned_mem_pool();
    pool->init(tot_in_size + 3 * 1024 * 1024);//(num_flows * max(flow_len, 512) * 1.8);

    uint64_t poolTime = get_usec();
    printf("poolTime: %d.\n", poolTime - devTime);

//    operation_batch_t ops;
    hmac_sha1_param_t param;

//    operation_batch_t ops;
//    gen_hmac_sha1_data(&ops, TOTAL_THREAD_NUM, 1024);

    hmac_file_sha1_prepare(file_path, tot_in_size, NULL, /*&ops,*/ &param, pool);

    uint64_t dataTime = get_usec();
    printf("dataTime: %d.\n", dataTime - poolTime);

    sha_ctx.hmac_sha1((void*)param.memory_start,
              param.in_pos,
              param.key_pos,
              param.pkt_offset_pos,
              param.length_pos,
              param.total_size,
              param.out,
              param.num_flows,
              0);

    sha_ctx.sync(0);

    uint64_t endTime = get_usec();
    std::cout << "sha1Time: " << endTime - dataTime << " us" << std::endl;

//    printf("num_flows: %d\n", param.num_flows);

    printf("data sha1 time: %d, total time: %d.\n", endTime - poolTime, endTime - startTime);

//    hmac_sha1_post(&ops, &param);
//
//    int iRet = -1;
//    for (int i = 0; i < ops.size() - 1; i++) {
//        uint8_t out_temp[HMAC_SHA1_HASH_SIZE];
//
//        unsigned len;
//        HMAC(EVP_sha1(),
//             (ops[i]).key,
//             (ops[i]).key_len,
//             (ops[i]).in,
//             (ops[i]).in_len,
//             out_temp,
//             &len);
//        assert(len == HMAC_SHA1_HASH_SIZE);
//
//        if (memcmp(out_temp, (ops[i]).out, (ops[i]).out_len) != 0) {
//            iRet = -1;
//        } else {
//            iRet = 0;
//        }
//    }
//
//    uint64_t hmacTime = get_usec();
//    printf("Verify ret: %d, time: %d.\n", iRet, hmacTime - endTime);


//    for (int i = 0; i < ops.size(); ++i) {
//        for (int j = 0; j < 20; ++j) {
//            printf("%X", (char)ops[i].out[j] & 0xFF);
//        }
//        std::cout << std::endl;
//    }

    delete pool;
}

static void test_file_split_stream_hmac_sha1(const char *file_path, unsigned num_stream)
{
    uint64_t startTime = get_usec();

    int num_flows = 1024;
    int flow_len = 1024 * 1024;

    device_context dev_ctx;
    dev_ctx.init(num_flows * max(flow_len, 512) * 0.8, num_stream);
    sha_context sha_ctx(&dev_ctx);
    uint64_t devInitTime = get_usec();
    printf("DevinitTime: %d.\n", devInitTime - startTime);

    pinned_mem_pool *pool;
    pool = new pinned_mem_pool();
    pool->init(num_flows * max(flow_len, 512) * 1.8);

    operation_batch_t ops[MAX_STREAM + 1];
    hmac_sha1_param_t param[MAX_STREAM + 1];

    uint64_t poolTime = get_usec();
    printf("Pooltime: %d.\n", poolTime - devInitTime);

    unsigned tot_in_size = 0; /* total size of input text */
    struct stat buf;
    stat(file_path, &buf);
    tot_in_size = buf.st_size / num_stream;
    printf("file size: %d\n", tot_in_size);
    assert(tot_in_size > 0);

    std::ifstream inFile(file_path, std::ifstream::binary);
    if (!inFile) {
        printf("Failed to open.\n");
        return;
    }

    for (unsigned i = 1; i <= num_stream; i++) {
        hmac_file_stream_sha1_prepare(inFile, i -1 , tot_in_size, &ops[i], &param[i], pool);
    }
    inFile.close();

    uint64_t dataTime = get_usec();
    std::cout << "fileTime: " << dataTime - poolTime << std::endl;

    //warmup
    for (unsigned i = 1; i <= num_stream; i++) {
//        uint64_t datastreamTime = get_usec();
//        hmac_file_stream_sha1_prepare(inFile, i -1 , tot_in_size, &ops[i], &param[i], pool);
        uint64_t endDatastreamtime = get_usec();
//        printf("stream: %d, datatime: %d.\n", i, endDatastreamtime - datastreamTime);

        sha_ctx.hmac_sha1((void*)param[i].memory_start,
                  param[i].in_pos,
                  param[i].key_pos,
                  param[i].pkt_offset_pos,
                  param[i].length_pos,
                  param[i].total_size,
                  param[i].out,
                  param[i].num_flows,
                  i);
        uint64_t hmacsha1Time = get_usec();
        printf("stream: %d, hmac sha1 time: %d.\n", i, hmacsha1Time - endDatastreamtime);
    }

    uint64_t hmacsha1timestart = get_usec();
    printf("no sync time: %d.\n", hmacsha1timestart - dataTime);
//    inFile.close();


    for (unsigned i = 1; i <= num_stream; i++) {
        uint64_t startSyncTime = get_usec();
        sha_ctx.sync(i, true);
        uint64_t endSyncTime = get_usec();
        printf("stream: %d, sync: %d.\n", i, endSyncTime - startSyncTime);
    }

    uint64_t endTime = get_usec();
    std::cout << "sha1Time: " << endTime - dataTime << " us" << std::endl;

    printf("data sha1 time: %d, Total time: %d.\n", endTime - poolTime, endTime - startTime);

//    for (unsigned i = 1; i <= num_stream; i++) {
//        hmac_sha1_post(&ops[i], &param[i]);
//    }

//    uint64_t postTime = get_usec();
//    std::cout << "postTime: " <<  postTime - endTime << " us" << std::endl;

//    for (unsigned i = 1; i <= num_stream; i++) {
//        int iRet = verify_hmac_sha1(&ops[i]);
//        printf("Verify ret: %d\n", iRet);
//    }
//
//    uint64_t hmacTime = get_usec();
//    printf("Verify time: %d.\n", hmacTime - postTime);
//
//    for (unsigned i = 1; i <= num_stream; i++) {
//        for (int j = 0; j < 20; ++j) {
//            printf("%X", (char)ops[i][0].out[j] & 0xFF);
//        }
//        std::cout << std::endl;
//    }

    delete pool;
}

int main(int argc, char *argv[])
{
    srand(time(NULL));

  int size = 16384;
  int num_stream = 0;

  int i = 1;
  while (i < argc) {
      if (strcmp(argv[i], "-s") == 0) {
          i++;
          if (i == argc)
              goto parse_error;
          num_stream = atoi(argv[i]);
          if (num_stream > 16 || num_stream < 0)
              goto parse_error;
      } else if (strcmp(argv[i], "-l") == 0) {
          i++;
          if (i == argc)
              goto parse_error;
          size = atoi(argv[i]);
          if (size <= 0 || size > 16384 || size % 16 != 0)
              goto parse_error;
        } else if (strcmp(argv[i], "-f") == 0) {
            // 文件摘要
            test_file_hmac_sha1(atoi(argv[2]), atoi(argv[3]));
            return 0;
        } else if (strcmp(argv[i], "-fs") == 0) {
            test_file_stream_hmac_sha1(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
            return 0;
        } else if (strcmp(argv[i], "-file") == 0) {
            test_file_split_hmac_sha1(argv[2]);
            return 0;
        } else if (strcmp(argv[i], "-sfile") == 0) {
            test_file_split_stream_hmac_sha1(argv[2], atoi(argv[3]));
            return 0;
        }
        else {
          goto parse_error;
        }
      i++;
  }

  if (num_stream == 0)
      test_hmac_sha1(size);
  else
      test_hmac_sha1_stream(size, num_stream);

  return 0;

 parse_error:
  printf(usage, argv[0]);
  return -1;
}

//int main(int argc, char *argv[])
//{
//    srand(time(NULL));
//
//    int buf_size = 1024 * 1024 * 64;
//
//    // ./a.out buf_size split_num
//
//    uint64_t AllocTime = get_usec();
//    char *host_buf = NULL;
//    cudaHostAlloc(&host_buf, buf_size, cudaHostAllocPortable);
//    assert(NULL != host_buf);
//    uint64_t allocEndTime = get_usec();
//    std::cout << "HostAlloc time: " << allocEndTime - AllocTime << std::endl;
//
////    set_random((unsigned char*)host_buf, buf_size);
//    uint64_t randomTime = get_usec();
//    std::cout << "RandomTime: " << randomTime - allocEndTime << std::endl;
//
//    char *dev_buf = NULL;
//    cudaMalloc(&dev_buf, buf_size);
//    assert(NULL != dev_buf);
//
//    uint64_t mallocTime = get_usec();
//    std::cout << "mallocTime: " << mallocTime - randomTime << std::endl;
//
//    cudaMemcpy(dev_buf, host_buf, buf_size, cudaMemcpyHostToDevice);
//    uint64_t memcpyTime = get_usec();
//    std::cout << "memcpyTime: " << memcpyTime - mallocTime << std::endl;
////    cudaFreeHost(host_buf);
////    host_buf = NULL;
//
//    int threads = 512;
//
//    int N = 32 * threads;
//
//    int off_size = buf_size / N;
//
//    std::vector<char> keys(N * 64);
//
//    std::vector<uint32_t> offsets(N);
//    for (size_t i = 0; i < offsets.size(); ++i) {
//        offsets[i] = off_size * i;
//    }
//
//    std::vector<uint32_t> lengths(N, off_size);
//
//    std::vector<uint32_t> outputs(N * 5);
//
//    std::vector<uint8_t> checkbits(N);
//
//    uint64_t dataTime = get_usec();
//    std::cout << "dataTime: " << dataTime - memcpyTime << std::endl;
//
//    hmac_sha1_gpu(dev_buf,
//                  &keys[0],
//                  &offsets[0],
//                  &lengths[0],
//                  &outputs[0],
//                  N,
//                  &checkbits[0],
//                  threads,
//                  0);
//    uint64_t gpuTime = get_usec();
//    std::cout << "gpuTime: " << gpuTime - dataTime << std::endl;
//
//    cudaFree(dev_buf);
//    dev_buf = NULL;
//    uint64_t freeTime = get_usec();
//    std::cout << "freeTime: " << freeTime - gpuTime << std::endl;
//
//    std::cout << "Total time: " << freeTime - AllocTime << std::endl;
//
//    unsigned char out_temp[HMAC_SHA1_HASH_SIZE];
//
//    unsigned int len;
//    HMAC(EVP_sha1(),
//         &keys[0],
//         64,
//         (unsigned char*)host_buf,
//         lengths[0],
//         (unsigned char*)out_temp,
//         &len);
//    assert(len == HMAC_SHA1_HASH_SIZE);
//
//    if (memcmp(out_temp, &outputs[0], 20) != 0) {
//        std::cout << "Verify failed." << std::endl;
//    }
//
//    uint64_t hmacTime = get_usec();
//    printf("Verify time: %d.\n", hmacTime - freeTime);
//
//    for (int i = 0; i < len; ++i) {
//        printf("%X", out_temp[i] & 0xFF);
//    }
//
//    std::cout << std::endl;
//
//    char tmp[20] = {0};
//    memcpy(tmp, &outputs[0], 20);
//    for (int i = 0; i < 20; ++i) {
//        printf("%X", tmp[i] & 0xFF);
//    }
//
//    return 0;
//}
