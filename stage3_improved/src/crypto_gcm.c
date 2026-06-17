#include "crypto_gcm.h"

#include "crypto_aes256.h"

#include <string.h>

static void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
	for (int i = 0; i < 16; i++) {
		out[i] = (uint8_t)(a[i] ^ b[i]);
	}
}

static void inc32(uint8_t x[16]) {
	for (int i = 15; i >= 12; i--) {
		x[i] = (uint8_t)(x[i] + 1);
		if (x[i] != 0) {
			break;
		}
	}
}

static void gf_mul(uint8_t out[16], const uint8_t x[16], const uint8_t y[16]) {
	uint8_t z[16] = {0};
	uint8_t v[16];
	memcpy(v, y, 16);

	for (int i = 0; i < 128; i++) {
		int xi = (x[i / 8] >> (7 - (i % 8))) & 1;
		if (xi) {
			for (int j = 0; j < 16; j++) {
				z[j] ^= v[j];
			}
		}

		int lsb = v[15] & 1;
		for (int j = 15; j > 0; j--) {
			v[j] = (uint8_t)((v[j] >> 1) | ((v[j - 1] & 1) << 7));
		}
		v[0] >>= 1;
		if (lsb) {
			v[0] ^= 0xe1;
		}
	}

	memcpy(out, z, 16);
}

static void ghash(uint8_t out[16], const uint8_t h[16], const uint8_t *aad, size_t aad_len, const uint8_t *ct,
				  size_t ct_len) {
	size_t aad_total = aad_len;
	size_t ct_total = ct_len;
	uint8_t y[16] = {0};
	uint8_t blk[16];

	while (aad_len >= 16) {
		xor_block(y, y, aad);
		gf_mul(y, y, h);
		aad += 16;
		aad_len -= 16;
	}
	if (aad_len > 0) {
		memset(blk, 0, 16);
		memcpy(blk, aad, aad_len);
		xor_block(y, y, blk);
		gf_mul(y, y, h);
	}

	while (ct_len >= 16) {
		xor_block(y, y, ct);
		gf_mul(y, y, h);
		ct += 16;
		ct_len -= 16;
	}
	if (ct_len > 0) {
		memset(blk, 0, 16);
		memcpy(blk, ct, ct_len);
		xor_block(y, y, blk);
		gf_mul(y, y, h);
	}

	uint64_t aad_bits = (uint64_t)aad_total * 8U;
	uint64_t ct_bits = (uint64_t)ct_total * 8U;
	uint8_t len_blk[16] = {0};
	for (int i = 0; i < 8; i++) {
		len_blk[7 - i] = (uint8_t)(aad_bits >> (i * 8));
		len_blk[15 - i] = (uint8_t)(ct_bits >> (i * 8));
	}
	xor_block(y, y, len_blk);
	gf_mul(y, y, h);

	memcpy(out, y, 16);
}

static void gcm_tag(uint8_t out_tag[16], const struct crypto_aes256_ctx *aes, const uint8_t j0[16], const uint8_t h[16],
					const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len) {
	uint8_t s[16];
	ghash(s, h, aad, aad_len, ct, ct_len);

	uint8_t e0[16];
	crypto_aes256_encrypt_block(aes, j0, e0);

	for (int i = 0; i < 16; i++) {
		out_tag[i] = (uint8_t)(e0[i] ^ s[i]);
	}
}

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
	uint8_t r = 0;
	for (size_t i = 0; i < n; i++) {
		r |= (uint8_t)(a[i] ^ b[i]);
	}
	return r;
}

int crypto_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
							 const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t tag[16]) {
	struct crypto_aes256_ctx aes;
	crypto_aes256_init(&aes, key);

	uint8_t h[16] = {0};
	crypto_aes256_encrypt_block(&aes, h, h);

	uint8_t j0[16] = {0};
	memcpy(j0, iv, 12);
	j0[15] = 1;

	uint8_t ctr[16];
	memcpy(ctr, j0, 16);

	size_t off = 0;
	while (off < pt_len) {
		inc32(ctr);
		uint8_t stream[16];
		crypto_aes256_encrypt_block(&aes, ctr, stream);
		size_t n = pt_len - off;
		if (n > 16) {
			n = 16;
		}
		for (size_t i = 0; i < n; i++) {
			ct[off + i] = (uint8_t)(pt[off + i] ^ stream[i]);
		}
		off += n;
	}

	gcm_tag(tag, &aes, j0, h, aad, aad_len, ct, pt_len);
	return 0;
}

int crypto_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
							 const uint8_t *ct, size_t ct_len, const uint8_t tag[16], uint8_t *pt) {
	struct crypto_aes256_ctx aes;
	crypto_aes256_init(&aes, key);

	uint8_t h[16] = {0};
	crypto_aes256_encrypt_block(&aes, h, h);

	uint8_t j0[16] = {0};
	memcpy(j0, iv, 12);
	j0[15] = 1;

	uint8_t expected[16];
	gcm_tag(expected, &aes, j0, h, aad, aad_len, ct, ct_len);
	if (ct_memcmp(expected, tag, 16) != 0) {
		return -1;
	}

	uint8_t ctr[16];
	memcpy(ctr, j0, 16);

	size_t off = 0;
	while (off < ct_len) {
		inc32(ctr);
		uint8_t stream[16];
		crypto_aes256_encrypt_block(&aes, ctr, stream);
		size_t n = ct_len - off;
		if (n > 16) {
			n = 16;
		}
		for (size_t i = 0; i < n; i++) {
			pt[off + i] = (uint8_t)(ct[off + i] ^ stream[i]);
		}
		off += n;
	}

	return 0;
}

