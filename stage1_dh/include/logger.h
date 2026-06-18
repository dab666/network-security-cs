#pragma once

#include <stddef.h>
#include <stdint.h>

int logger_init(const char *path, const char *role);
void logger_close(void);
void logger_log(const char *fmt, ...);
void logger_hex(const char *label, const uint8_t *buf, size_t len);

