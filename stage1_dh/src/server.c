#include "logger.h"
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

struct worker_args {
	int fd;
};

static void *worker_main(void *arg) {
	struct worker_args *wa = (struct worker_args *)arg;
	int fd = wa->fd;
	free(wa);
	logger_log("worker thread started: fd=%d", fd);

	struct sc_session s;
	memset(&s, 0, sizeof(s));
	if (sc_server_handshake(fd, &s) != 0) {
		logger_log("server handshake failed: fd=%d", fd);
		close(fd);
		return NULL;
	}

	for (;;) {
		uint8_t *pt = NULL;
		uint32_t pt_len = 0;
		if (sc_recv_data(fd, &s, &pt, &pt_len) != 0) {
			logger_log("sc_recv_data failed: fd=%d", fd);
			break;
		}
		if (sc_send_data(fd, &s, pt, pt_len) != 0) {
			free(pt);
			logger_log("sc_send_data failed: fd=%d", fd);
			break;
		}
		free(pt);
	}

	close(fd);
	logger_log("worker thread finished: fd=%d", fd);
	return NULL;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s --host <ip> --port <port> [--daemon] [--log-file <path>]\n", prog);
}

int main(int argc, char **argv) {
	const char *host = "0.0.0.0";
	uint16_t port = 9000;
	int daemon_flag = 0;
	const char *log_file = "server_protocol.log";

	static struct option opts[] = {
		{"host", required_argument, 0, 'h'},
		{"port", required_argument, 0, 'p'},
		{"daemon", no_argument, 0, 'd'},
		{"log-file", required_argument, 0, 'l'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "h:p:dl:", opts, NULL);
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
		case 'l':
			log_file = optarg;
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
	if (logger_init(log_file, "stage1-server") != 0) {
		fprintf(stderr, "Failed to open log file: %s\n", log_file);
		return 1;
	}
	logger_log("server process start: host=%s port=%u daemon=%d", host, port, daemon_flag);

	int listen_fd = net_listen_tcp(host, port, 128);
	if (listen_fd < 0) {
		perror("listen");
		logger_log("listen failed");
		logger_close();
		return 1;
	}
	logger_log("listen success: fd=%d", listen_fd);

	for (;;) {
		int fd = net_accept(listen_fd);
		if (fd < 0) {
			logger_log("accept failed, retrying");
			continue;
		}
		logger_log("accepted connection: fd=%d", fd);
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
