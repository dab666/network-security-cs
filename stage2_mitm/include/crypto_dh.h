#pragma once

#include <stdint.h>

int crypto_dh_keypair(uint8_t priv[32], uint8_t pub[32]);
void crypto_dh_pub_from_priv(uint8_t pub[32], const uint8_t priv[32]);
int crypto_dh_shared(uint8_t out_shared[32], const uint8_t priv[32], const uint8_t peer_pub[32]);
