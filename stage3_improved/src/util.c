#include "util.h"

#include <errno.h>
#include <stdlib.h>

int util_parse_u16(const char *s, uint16_t *out) {
	char *end = NULL;
	errno = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0' || v > 65535UL) {
		return -1;
	}
	*out = (uint16_t)v;
	return 0;
}
