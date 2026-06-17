#pragma once

#include <stdint.h>

int util_parse_u16(const char *s, uint16_t *out);
int util_parse_u32(const char *s, uint32_t *out);
int util_daemonize(void);
