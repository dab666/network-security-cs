#include "net.h"
#include "util.h"

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct worker_args {
	int fd;
};

static void *worker_main(void *arg) {
	struct worker_args *wa = (struct worker_args *)arg;
	int fd = wa->fd;
	free(wa);

	for (;;) {
		void *buf = NULL;
		uint32_t len = 0;
		if (net_recv_frame(fd, &buf, &len) != 0) {
			break;
		}
		if (net_send_frame(fd, buf, len) != 0) {
			net_free_frame(buf);
			break;
		}
		net_free_frame(buf);
	}

	close(fd);
	return NULL;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s --host <ip> --port <port> [--daemon]\n", prog);
}

int main(int argc, char **argv) {
	const char *host = "0.0.0.0";
	uint16_t port = 9000;
	int daemon_flag = 0;

	static struct option opts[] = {
		{"host", required_argument, 0, 'h'},
		{"port", required_argument, 0, 'p'},
		{"daemon", no_argument, 0, 'd'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "h:p:d", opts, NULL);
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
		case 'd':
			daemon_flag = 1;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	signal(SIGPIPE, SIG_IGN);
	if (daemon_flag) {
		if (util_daemonize() != 0) {
			return 1;
		}
	}

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
