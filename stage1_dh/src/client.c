#include "logger.h"
#include "net.h"
#include "sc.h"
#include "util.h"

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog) {
	fprintf(stderr,
			"Usage: %s --host <ip> --port <port> --message <msg> [--count N] [--rekey-every N] [--log-file <path>]\n",
			prog);
}

int main(int argc, char **argv) {
	const char *host = "127.0.0.1";
	uint16_t port = 9000;
	const char *message = NULL;
	const char *log_file = "client_protocol.log";
	uint32_t count = 1;
	uint32_t rekey_every = 5;

	static struct option opts[] = {
		{"host", required_argument, 0, 'h'},
		{"port", required_argument, 0, 'p'},
		{"message", required_argument, 0, 'm'},
		{"count", required_argument, 0, 'c'},
		{"rekey-every", required_argument, 0, 'r'},
		{"log-file", required_argument, 0, 'l'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "h:p:m:c:r:l:", opts, NULL);
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
		case 'c':
			if (util_parse_u32(optarg, &count) != 0 || count == 0) {
				usage(argv[0]);
				return 2;
			}
			break;
		case 'r':
			if (util_parse_u32(optarg, &rekey_every) != 0) {
				usage(argv[0]);
				return 2;
			}
			break;
		case 'l':
			log_file = optarg;
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

	if (logger_init(log_file, "stage1-client") != 0) {
		fprintf(stderr, "Failed to open log file: %s\n", log_file);
		return 1;
	}
	logger_log("client process start: host=%s port=%u count=%u rekey_every=%u", host, port, count, rekey_every);

	int fd = net_connect_tcp(host, port);
	if (fd < 0) {
		perror("connect");
		logger_log("connect failed");
		logger_close();
		return 1;
	}
	logger_log("tcp connect success");

	struct sc_session s;
	memset(&s, 0, sizeof(s));
	s.rekey_every = rekey_every;
	if (sc_client_handshake(fd, &s) != 0) {
		close(fd);
		logger_log("client handshake failed");
		logger_close();
		return 1;
	}

	for (uint32_t i = 0; i < count; i++) {
		uint32_t len = (uint32_t)strlen(message);
		logger_log("sending application message index=%u", i + 1);
		if (sc_send_data(fd, &s, (const uint8_t *)message, len) != 0) {
			close(fd);
			logger_log("sc_send_data failed");
			logger_close();
			return 1;
		}

		uint8_t *resp = NULL;
		uint32_t resp_len = 0;
		if (sc_recv_data(fd, &s, &resp, &resp_len) != 0) {
			close(fd);
			logger_log("sc_recv_data failed");
			logger_close();
			return 1;
		}
		fwrite(resp, 1, resp_len, stdout);
		fputc('\n', stdout);
		logger_hex("application response plaintext", resp, resp_len);
		free(resp);
	}

	close(fd);
	logger_log("client process finished normally");
	logger_close();
	return 0;
}
