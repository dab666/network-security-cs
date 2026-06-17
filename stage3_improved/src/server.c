#include "crypto_dh.h"
#include "net.h"
#include "sc.h"
#include "util.h"

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint8_t g_static_priv[32];
static uint8_t g_static_pub[32];

struct worker_args {
	int fd;
};

static void *worker_main(void *arg) {
	struct worker_args *wa = (struct worker_args *)arg;
	int fd = wa->fd;
	free(wa);

	struct sc_session s;
	memset(&s, 0, sizeof(s));
	memcpy(s.server_static_priv, g_static_priv, 32);
	memcpy(s.server_static_pub, g_static_pub, 32);
	s.has_static_priv = 1;
	if (sc_server_handshake(fd, &s) != 0) {
		close(fd);
		return NULL;
	}

	for (;;) {
		uint8_t *pt = NULL;
		uint32_t pt_len = 0;
		if (sc_recv_data(fd, &s, &pt, &pt_len) != 0) {
			break;
		}
		if (sc_send_data(fd, &s, pt, pt_len) != 0) {
			free(pt);
			break;
		}
		free(pt);
	}

	close(fd);
	return NULL;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s --host <ip> --port <port> [--static-key <path>]\n", prog);
}

int main(int argc, char **argv) {
	const char *host = "0.0.0.0";
	uint16_t port = 9000;
	const char *static_key = "server_static.key";

	static struct option opts[] = {
		{"host", required_argument, 0, 'h'},
		{"port", required_argument, 0, 'p'},
		{"static-key", required_argument, 0, 'k'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "h:p:k:", opts, NULL);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'h':
			host = optarg;
			break;
		case 'p':
			if (util_parse_u16(optarg, &port) != 0) {
				usage(argv[0]);
				return 2;
			}
			break;
		case 'k':
			static_key = optarg;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	if (util_read_file_exact(static_key, g_static_priv, 32) != 0) {
		fprintf(stderr, "Failed to read static key: %s\n", static_key);
		return 1;
	}
	crypto_dh_pub_from_priv(g_static_pub, g_static_priv);

	int listen_fd = net_listen_tcp(host, port, 128);
	if (listen_fd < 0) {
		perror("listen");
		return 1;
	}

	for (;;) {
		int fd = net_accept(listen_fd);
		if (fd < 0) {
			continue;
		}
		struct worker_args *wa = (struct worker_args *)calloc(1, sizeof(*wa));
		if (!wa) {
			close(fd);
			continue;
		}
		wa->fd = fd;
		pthread_t th;
		if (pthread_create(&th, NULL, worker_main, wa) != 0) {
			close(fd);
			free(wa);
			continue;
		}
		pthread_detach(th);
	}

	return 0;
}
