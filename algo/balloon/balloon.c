/*
 * Copyright (c) 2015-2016, Henry Corrigan-Gibbs (https://github.com/henrycg/balloon)
 * Copyright (c) 2018-2019, barrystyle (https://github.com/barrystyle/balloon)
 *
 * balloon² - improving on the original balloon hashing pow algorithm
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <miner.h>
#include "balloon.h"

typedef struct {
	aes_key ks;
	block128_f block;
} evp_aes_key;

struct balloon_evp_cipher_st;
struct balloon_evp_cipher_ctx_st;
typedef struct balloon_evp_cipher_st balloon_evp_cipher;
typedef struct balloon_evp_cipher_ctx_st balloon_evp_cipher_ctx;

struct balloon_evp_cipher_st {
	int nid;
	int block_size;
	int key_len;
	int iv_len;
	unsigned long flags;
	int (*init)(balloon_evp_cipher_ctx* ctx, const unsigned char* key, const unsigned char* iv, int enc);
	int (*do_cipher)(balloon_evp_cipher_ctx* ctx, unsigned char* out, const unsigned char* in, size_t inl);
	int (*cleanup)(balloon_evp_cipher_ctx*);
	int ctx_size;
	int (*ctrl)(balloon_evp_cipher_ctx*, int type, int arg, void* ptr);
	void* app_data;
};

struct balloon_evp_cipher_ctx_st {
	const balloon_evp_cipher* cipher;
	int encrypt;
	int buf_len;
	unsigned char oiv[16];
	unsigned char iv[16];
	unsigned char buf[32];
	int num;
	void* app_data;
	int key_len;
	unsigned long flags;
	void* cipher_data;
	int final_used;
	int block_mask;
	unsigned char final[32];
};

struct bitstream {
	uint8_t* zeros;
	balloon_evp_cipher_ctx ctx;
};

struct hash_state {
	uint64_t counter;
	uint8_t* buffer;
	struct bitstream bstream;
};

static void aes_encrypt(const unsigned char* in, unsigned char* out, const aes_key* key)
{
	const uint32_t* rk;
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
	rk = key->rd_key;
	s0 = GETU32(in) ^ rk[0];
	s1 = GETU32(in + 4) ^ rk[1];
	s2 = GETU32(in + 8) ^ rk[2];
	s3 = GETU32(in + 12) ^ rk[3];
	t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ rk[4];
	t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ rk[5];
	t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ rk[6];
	t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ rk[7];
	s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >> 8) & 0xff] ^ te3[t3 & 0xff] ^ rk[8];
	s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >> 8) & 0xff] ^ te3[t0 & 0xff] ^ rk[9];
	s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >> 8) & 0xff] ^ te3[t1 & 0xff] ^ rk[10];
	s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >> 8) & 0xff] ^ te3[t2 & 0xff] ^ rk[11];
	t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ rk[12];
	t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ rk[13];
	t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ rk[14];
	t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ rk[15];
	s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >> 8) & 0xff] ^ te3[t3 & 0xff] ^ rk[16];
	s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >> 8) & 0xff] ^ te3[t0 & 0xff] ^ rk[17];
	s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >> 8) & 0xff] ^ te3[t1 & 0xff] ^ rk[18];
	s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >> 8) & 0xff] ^ te3[t2 & 0xff] ^ rk[19];
	t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ rk[20];
	t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ rk[21];
	t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ rk[22];
	t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ rk[23];
	s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >> 8) & 0xff] ^ te3[t3 & 0xff] ^ rk[24];
	s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >> 8) & 0xff] ^ te3[t0 & 0xff] ^ rk[25];
	s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >> 8) & 0xff] ^ te3[t1 & 0xff] ^ rk[26];
	s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >> 8) & 0xff] ^ te3[t2 & 0xff] ^ rk[27];
	t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ rk[28];
	t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ rk[29];
	t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ rk[30];
	t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ rk[31];
	s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >> 8) & 0xff] ^ te3[t3 & 0xff] ^ rk[32];
	s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >> 8) & 0xff] ^ te3[t0 & 0xff] ^ rk[33];
	s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >> 8) & 0xff] ^ te3[t1 & 0xff] ^ rk[34];
	s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >> 8) & 0xff] ^ te3[t2 & 0xff] ^ rk[35];
	t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ rk[36];
	t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ rk[37];
	t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ rk[38];
	t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ rk[39];
	rk += key->rounds << 2;
	s0 = (te2[(t0 >> 24)] & 0xff000000) ^ (te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (te1[(t3)&0xff] & 0x000000ff) ^ rk[0];
	PUTU32(out, s0);
	s1 = (te2[(t1 >> 24)] & 0xff000000) ^ (te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (te1[(t0)&0xff] & 0x000000ff) ^ rk[1];
	PUTU32(out + 4, s1);
	s2 = (te2[(t2 >> 24)] & 0xff000000) ^ (te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (te1[(t1)&0xff] & 0x000000ff) ^ rk[2];
	PUTU32(out + 8, s2);
	s3 = (te2[(t3 >> 24)] & 0xff000000) ^ (te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (te1[(t2)&0xff] & 0x000000ff) ^ rk[3];
	PUTU32(out + 12, s3);
}

static int aes_set_encrypt_key(const unsigned char* userKey, const int bits, aes_key* key)
{
	uint32_t* rk;
	int i = 0;
	uint32_t temp;
	rk = key->rd_key;
	key->rounds = 10;
	rk[0] = GETU32(userKey);
	rk[1] = GETU32(userKey + 4);
	rk[2] = GETU32(userKey + 8);
	rk[3] = GETU32(userKey + 12);
	while (1) {
		temp = rk[3];
		rk[4] = rk[0] ^ (te2[(temp >> 16) & 0xff] & 0xff000000) ^ (te3[(temp >> 8) & 0xff] & 0xff0000) ^ (te0[(temp)&0xff] & 0xff00) ^ (te1[(temp >> 24)] & 0xff) ^ rcon[i];
		rk[5] = rk[1] ^ rk[4];
		rk[6] = rk[2] ^ rk[5];
		rk[7] = rk[3] ^ rk[6];
		if (++i == 10)
			return 0;
		rk += 4;
	}
}

static void aes_init_key(balloon_evp_cipher_ctx* ctx, const unsigned char* key)
{
	evp_aes_key* dat = (evp_aes_key*)ctx->cipher_data;
	aes_set_encrypt_key(key, ctx->key_len * 8, &dat->ks);
	dat->block = (block128_f)aes_encrypt;
}

static void ctr128_inc(unsigned char* counter)
{
	uint32_t n = 16;
	uint8_t c;
	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c)
			return;
	} while (n);
}

static void aes_ctr128_encrypt(const unsigned char* in, unsigned char* out, size_t len, const void* key, unsigned char ivec[16], unsigned char ecount_buf[16], unsigned int* num, block128_f block)
{
	unsigned int n;
	n = *num;
	while (1) {
		while (n && len) {
			*(out++) = *(in++) ^ ecount_buf[n];
			--len;
			n = (n + 1) % 16;
		}
		if (len) {
			(*block)(ivec, ecount_buf, key);
			ctr128_inc(ivec);
			while (len--) {
				out[n] = in[n] ^ ecount_buf[n];
				++n;
			}
		}
		*num = n;
		return;
	}
}

static int aes_ctr_cipher(balloon_evp_cipher_ctx* ctx, unsigned char* out, const unsigned char* in, size_t len)
{
	unsigned int num = ctx->num;
	evp_aes_key* dat = (evp_aes_key*)ctx->cipher_data;
	aes_ctr128_encrypt(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num, dat->block);
	ctx->num = (size_t)num;
}

balloon_evp_cipher aes_128_ctr = { 904, 1, 16, 16, 0x5, aes_init_key, aes_ctr_cipher, NULL, 264, NULL, NULL };
balloon_evp_cipher* balloon_evp_aes_128_ctr(void) { return &aes_128_ctr; }

void sha256(const void* input, void* output, int len)
{
        SHA256_CTX c;
        SHA256_Init(&c);
        SHA256_Update(&c, input, len);
        SHA256_Final(output, &c);
}

void balloon_hash(const void* input, void* output, const int buflen)
{
	const int exprounds = buflen / 32;
	struct hash_state s;
	s.counter = 0;
	s.buffer = (uint8_t*)malloc(buflen);
	s.bstream.zeros = (uint8_t*)malloc(512);
	memset(s.bstream.zeros, 0, 512);
	uint8_t iv[16] = {0};
	uint8_t buf[8] = {0};
	uint8_t hashmix[168] = {0};
	uint8_t key_bytes[32] = {0};
	uint8_t blkpadding[12] = {0};
	memset(blkpadding, 0x80, 1);
	memset(blkpadding+8, 0x04, 1);
	memset(&s.bstream.ctx, 0, 160);
	memcpy(&hashmix[0], input+48, 32);
	memcpy(&hashmix[32], blkpadding, 12);
	sha256(hashmix, key_bytes, 44);
	s.bstream.ctx.cipher = balloon_evp_aes_128_ctr();
	s.bstream.ctx.cipher_data = malloc(264);
	s.bstream.ctx.key_len = 16;
	s.bstream.ctx.cipher->init(&s.bstream.ctx, (const unsigned char*)&key_bytes, (const unsigned char*)&iv, 1);
	memcpy(&hashmix[0], &s.counter, 8);
	memcpy(&hashmix[8], input+48, 32);
	memcpy(&hashmix[40], input, 80);
	memcpy(&hashmix[120], blkpadding, 12);
	sha256(hashmix, s.buffer, 132);
	s.counter++;
	uint8_t* blocks[1] = { s.buffer };
	uint8_t* cur = s.buffer + 32;
	for (int i = 1; i < exprounds; i++) {
		memcpy(&hashmix[0], &s.counter, 8);
		memcpy(&hashmix[8], blocks[0], 32);
		sha256(hashmix, cur, 40);
		s.counter++;
		blocks[0] += 32;
		cur += 32;
	}
	uint64_t neighbor = 0;
	for (int offset = 0; offset < 2; offset++) {
		for (int i = offset; i < exprounds; i+=2) {
			uint8_t* cur_block = s.buffer + (32 * i);
			uint8_t* prev_block = i ? cur_block - 32 : s.buffer + (buflen - 32);
			blocks[0] = prev_block;
			blocks[1] = cur_block;
			s.bstream.ctx.cipher->do_cipher(&s.bstream.ctx, buf, s.bstream.zeros, 8);
			neighbor = (buf[2] << 16) | (buf[1] << 8) | buf[0];
			blocks[2] = s.buffer + (32 * (neighbor % exprounds));
			s.bstream.ctx.cipher->do_cipher(&s.bstream.ctx, buf, s.bstream.zeros, 8);
			neighbor = (buf[2] << 16) | (buf[1] << 8) | buf[0];
			blocks[3] = s.buffer + (32 * (neighbor % exprounds));
			s.bstream.ctx.cipher->do_cipher(&s.bstream.ctx, buf, s.bstream.zeros, 8);
			neighbor = (buf[2] << 16) | (buf[1] << 8) | buf[0];
			blocks[4] = s.buffer + (32 * (neighbor % exprounds));
			memcpy(&hashmix[0], &s.counter, 8);
			memcpy(&hashmix[8], blocks[0], 32);
			memcpy(&hashmix[40], blocks[1], 32);
			memcpy(&hashmix[72], blocks[2], 32);
			memcpy(&hashmix[104], blocks[3], 32);
			memcpy(&hashmix[136], blocks[4], 32);
			sha256(hashmix, cur_block, 168);
			s.counter += 1;
		}
	}
	memcpy((char*)output, (const char*)s.buffer + (buflen - 32), 32);
	if (s.bstream.ctx.cipher_data) free(s.bstream.ctx.cipher_data);
	memset(&s.bstream.ctx, 0, sizeof(balloon_evp_cipher_ctx));
	free(s.bstream.zeros);
	free(s.buffer);
}

void balloon(const void* input, void* output) {
	balloon_hash(input, output, 8192);
}


