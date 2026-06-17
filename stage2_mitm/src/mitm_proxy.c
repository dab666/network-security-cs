#include "net.h"
#include "util.h"

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct relay_args {
	int in_fd;
	int out_fd;
};

static void *relay_main(void *arg) {
	struct relay_args *ra = (struct relay_args *)arg;
	for (;;) {
		void *buf = NULL;
		uint32_t len = 0;
		if (net_recv_frame(ra->in_fd, &buf, &len) != 0) {
			break;
		}
		if (net_send_frame(ra->out_fd, buf, len) != 0) {
			net_free_frame(buf);
			break;
		}
		net_free_frame(buf);
	}
	shutdown(ra->in_fd, SHUT_RDWR);
	shutdown(ra->out_fd, SHUT_RDWR);
	return NULL;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s --listen <ip> --lport <port> --target <ip> --tport <port>\n", prog);
}

int main(int argc, char **argv) {
	const char *listen_host = "127.0.0.1";
	uint16_t listen_port = 9001;
	const char *target_host = "127.0.0.1";
	uint16_t target_port = 9000;

	static struct option opts[] = {
		{"listen", required_argument, 0, 'l'},
		{"lport", required_argument, 0, 'L'},
		{"target", required_argument, 0, 't'},
		{"tport", required_argument, 0, 'T'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "l:L:t:T:", opts, NULL);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'l':
			listen_host = optarg;
			break;
		case 'L':
			if (util_parse_u16(optarg, &listen_port) != 0) {
				usage(argv[0]);
				return 2;
			}
			break;
		case 't':
			target_host = optarg;
			break;
		case 'T':
			if (util_parse_u16(optarg, &target_port) != 0) {
				usage(argv[0]);
				return 2;
			}
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	int listen_fd = net_listen_tcp(listen_host, listen_port, 128);
	if (listen_fd < 0) {
		perror("listen");
		return 1;
	}

	for (;;) {
		int client_fd = net_accept(listen_fd);
		if (client_fd < 0) {
			continue;
		}

		int server_fd = net_connect_tcp(target_host, target_port);
		if (server_fd < 0) {
			close(client_fd);
			continue;
		}

		struct relay_args c2s = {.in_fd = client_fd, .out_fd = server_fd};
		struct relay_args s2c = {.in_fd = server_fd, .out_fd = client_fd};

		pthread_t th1, th2;
		pthread_create(&th1, NULL, relay_main, &c2s);
		pthread_create(&th2, NULL, relay_main, &s2c);

		pthread_join(th1, NULL);
		pthread_join(th2, NULL);

		close(client_fd);
		close(server_fd);
	}

	return 0;
}
