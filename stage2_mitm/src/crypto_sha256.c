#include "crypto_sha256.h"

#include <string.h>

static uint32_t rotr32(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32U - n));
}

static uint32_t be32_load(const uint8_t b[4]) {
	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static void be32_store(uint8_t out[4], uint32_t v) {
	out[0] = (uint8_t)(v >> 24);
	out[1] = (uint8_t)(v >> 16);
	out[2] = (uint8_t)(v >> 8);
	out[3] = (uint8_t)v;
}

static void be64_store(uint8_t out[8], uint64_t v) {
	out[0] = (uint8_t)(v >> 56);
	out[1] = (uint8_t)(v >> 48);
	out[2] = (uint8_t)(v >> 40);
	out[3] = (uint8_t)(v >> 32);
	out[4] = (uint8_t)(v >> 24);
	out[5] = (uint8_t)(v >> 16);
	out[6] = (uint8_t)(v >> 8);
	out[7] = (uint8_t)v;
}

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
	static const uint32_t k[64] = {
		0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
		0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
		0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
		0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
		0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
		0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
		0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
		0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
		0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
		0xc67178f2U,
	};

	uint32_t w[64];
	for (uint32_t i = 0; i < 16; i++) {
		w[i] = be32_load(&block[i * 4U]);
	}
	for (uint32_t i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t f = state[5];
	uint32_t g = state[6];
	uint32_t h = state[7];

	for (uint32_t i = 0; i < 64; i++) {
		uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + s1 + ch + k[i] + w[i];
		uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

void crypto_sha256(uint8_t out[32], const uint8_t *data, size_t len) {
	uint32_t state[8] = {
		0x6a09e667U,
		0xbb67ae85U,
		0x3c6ef372U,
		0xa54ff53aU,
		0x510e527fU,
		0x9b05688cU,
		0x1f83d9abU,
		0x5be0cd19U,
	};

	uint8_t block[64];
	uint64_t total_bits = (uint64_t)len * 8U;

	while (len >= 64) {
		sha256_compress(state, data);
		data += 64;
		len -= 64;
	}

	memset(block, 0, sizeof(block));
	if (len > 0) {
		memcpy(block, data, len);
	}
	block[len] = 0x80;

	if (len >= 56) {
		sha256_compress(state, block);
		memset(block, 0, sizeof(block));
	}
	be64_store(&block[56], total_bits);
	sha256_compress(state, block);

	for (uint32_t i = 0; i < 8; i++) {
		be32_store(&out[i * 4U], state[i]);
	}
}

