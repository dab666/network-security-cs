#pragma once

#include <stddef.h>
#include <stdint.h>

int crypto_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
							 const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t tag[16]);
int crypto_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
							 const uint8_t *ct, size_t ct_len, const uint8_t tag[16], uint8_t *pt);

