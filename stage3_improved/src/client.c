#include "net.h"
#include "util.h"

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s --host <ip> --port <port> --message <msg>\n", prog);
}

int main(int argc, char **argv) {
	const char *host = "127.0.0.1";
	uint16_t port = 9000;
	const char *message = NULL;

	static struct option opts[] = {
		{"host", required_argument, 0, 'h'},
		{"port", required_argument, 0, 'p'},
		{"message", required_argument, 0, 'm'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "h:p:m:", opts, NULL);
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
		case 'm':
			message = optarg;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (!message) {
		usage(argv[0]);
		return 2;
	}

	int fd = net_connect_tcp(host, port);
	if (fd < 0) {
		perror("connect");
		return 1;
	}

	uint32_t len = (uint32_t)strlen(message);
	if (net_send_frame(fd, message, len) != 0) {
		perror("send");
		close(fd);
		return 1;
	}

	void *resp = NULL;
	uint32_t resp_len = 0;
	if (net_recv_frame(fd, &resp, &resp_len) != 0) {
		perror("recv");
		close(fd);
		return 1;
	}

	fwrite(resp, 1, resp_len, stdout);
	fputc('\n', stdout);
	net_free_frame(resp);
	close(fd);
	return 0;
}
