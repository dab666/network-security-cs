#pragma once

#include <stdint.h>

struct crypto_aes256_ctx {
	uint32_t rk[60];
};

void crypto_aes256_init(struct crypto_aes256_ctx *ctx, const uint8_t key[32]);
void crypto_aes256_encrypt_block(const struct crypto_aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

