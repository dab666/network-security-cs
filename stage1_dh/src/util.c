#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

int util_parse_u32(const char *s, uint32_t *out) {
	char *end = NULL;
	errno = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0' || v > 0xFFFFFFFFUL) {
		return -1;
	}
	*out = (uint32_t)v;
	return 0;
}

int util_daemonize(void) {
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0) {
		_exit(0);
	}
	if (setsid() < 0) {
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0) {
		_exit(0);
	}
	umask(0);
	chdir("/");
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);
	return 0;
}

int util_random_bytes(void *buf, uint32_t len) {
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	uint8_t *p = (uint8_t *)buf;
	uint32_t off = 0;
	while (off < len) {
		ssize_t n = read(fd, p + off, (size_t)(len - off));
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			close(fd);
			return -1;
		}
		if (n == 0) {
			close(fd);
			return -1;
		}
		off += (uint32_t)n;
	}
	close(fd);
	return 0;
}
