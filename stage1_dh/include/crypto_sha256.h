#pragma once

#include <stddef.h>
#include <stdint.h>

void crypto_sha256(uint8_t out[32], const uint8_t *data, size_t len);

