#pragma once

#include <stdint.h>

int util_parse_u16(const char *s, uint16_t *out);
int util_parse_u32(const char *s, uint32_t *out);
int util_random_bytes(void *buf, uint32_t len);
int util_read_file_exact(const char *path, void *buf, uint32_t len);
int util_write_file(const char *path, const void *buf, uint32_t len);
