#ifndef __TEST_COMMON_HH__
#define __TEST_COMMON_HH__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define CUDA_SAFE_CALL(call) {                                               \
    cudaError err = call;                                                    \
    if (cudaSuccess != err) {                                                \
        fprintf(stderr, "Cuda error in file '%s' in line %i : %s.\n",        \
                __FILE__, __LINE__, cudaGetErrorString( err) );              \
        exit(EXIT_FAILURE);                                                  \
    } }

typedef enum {RSA_PRIV_DEC, AES_ENC, AES_DEC, HMAC_SHA1} opcode_t;

typedef struct operation
{
	operation() {
		memset(this, 0, sizeof(*this));
	};

	~operation() {
		destroy();
	};

	void destroy() {
		if (in)
			free(in);
		in = NULL;

		if (out)
			free(out);
		out = NULL;

		if (key)
			free(key);
		key = NULL;

		if (iv)
			free(iv);
		iv = NULL;
	};

	opcode_t     op;
	uint8_t      *in;
	uint32_t     in_len;
	uint8_t      *out;
	uint32_t     out_len;
	uint8_t      *key; //RSA key is preloaded and this field should be null
	uint32_t     key_len;
	uint8_t      *iv;  //Used for AES only
	uint32_t     iv_len;
} operation_t;

typedef std::vector<operation_t> operation_batch_t;

typedef enum {CPU, MP, RNS} RSA_MODE;

uint64_t get_usec();
void set_random(unsigned char *buf, int len);

#endif /* __TEST_COMMON_HH__*/
