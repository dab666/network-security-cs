#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int resolve_addr(const char *host, uint16_t port, int family, int socktype, struct addrinfo **out) {
	struct addrinfo hints;
	char port_str[16];
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_PASSIVE;
	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
	return getaddrinfo(host, port_str, &hints, out);
}

int net_set_reuseaddr(int fd) {
	int yes = 1;
	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

int net_set_nodelay(int fd) {
	int yes = 1;
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
}

int net_listen_tcp(const char *host, uint16_t port, int backlog) {
	struct addrinfo *ai = NULL;
	int rc = resolve_addr(host, port, AF_UNSPEC, SOCK_STREAM, &ai);
	if (rc != 0) {
		return -1;
	}

	int listen_fd = -1;
	for (struct addrinfo *p = ai; p; p = p->ai_next) {
		int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) {
			continue;
		}
		net_set_reuseaddr(fd);

		if (bind(fd, p->ai_addr, p->ai_addrlen) == 0) {
			if (listen(fd, backlog) == 0) {
				listen_fd = fd;
				break;
			}
		}
		close(fd);
	}

	freeaddrinfo(ai);
	return listen_fd;
}

int net_accept(int listen_fd) {
	return accept(listen_fd, NULL, NULL);
}

int net_connect_tcp(const char *host, uint16_t port) {
	struct addrinfo *ai = NULL;
	int rc = resolve_addr(host, port, AF_UNSPEC, SOCK_STREAM, &ai);
	if (rc != 0) {
		return -1;
	}

	int out_fd = -1;
	for (struct addrinfo *p = ai; p; p = p->ai_next) {
		int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) {
			continue;
		}
		if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
			out_fd = fd;
			break;
		}
		close(fd);
	}

	freeaddrinfo(ai);
	return out_fd;
}

int net_send_all(int fd, const void *buf, uint32_t len) {
	const uint8_t *p = (const uint8_t *)buf;
	uint32_t off = 0;
	while (off < len) {
		size_t remain = (size_t)(len - off);
		ssize_t n = send(fd, p + off, remain, 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		off += (uint32_t)n;
	}
	return 0;
}

int net_recv_all(int fd, void *buf, uint32_t len) {
	uint8_t *p = (uint8_t *)buf;
	uint32_t off = 0;
	while (off < len) {
		size_t remain = (size_t)(len - off);
		ssize_t n = recv(fd, p + off, remain, 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		off += (uint32_t)n;
	}
	return 0;
}

int net_send_frame(int fd, const void *buf, uint32_t len) {
	uint32_t be_len = htonl(len);
	if (net_send_all(fd, &be_len, sizeof(be_len)) != 0) {
		return -1;
	}
	if (len == 0) {
		return 0;
	}
	return net_send_all(fd, buf, len);
}

int net_recv_frame(int fd, void **out_buf, uint32_t *out_len) {
	uint32_t be_len = 0;
	if (net_recv_all(fd, &be_len, sizeof(be_len)) != 0) {
		return -1;
	}
	uint32_t len = ntohl(be_len);
	void *buf = NULL;
	if (len > 0) {
		buf = malloc(len);
		if (!buf) {
			return -1;
		}
		if (net_recv_all(fd, buf, len) != 0) {
			free(buf);
			return -1;
		}
	}
	*out_buf = buf;
	*out_len = len;
	return 0;
}

void net_free_frame(void *buf) {
	free(buf);
}
