#include "crypto_dh.h"
#include "util.h"

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s [--priv <path>] [--pub <path>]\n", prog);
}

int main(int argc, char **argv) {
	const char *priv_path = "server_static.key";
	const char *pub_path = "server_static.pub";

	static struct option opts[] = {
		{"priv", required_argument, 0, 'k'},
		{"pub", required_argument, 0, 'p'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "k:p:", opts, NULL);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'k':
			priv_path = optarg;
			break;
		case 'p':
			pub_path = optarg;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	uint8_t priv[32];
	if (util_random_bytes(priv, sizeof(priv)) != 0) {
		return 1;
	}
	int all_zero = 1;
	for (int i = 0; i < 32; i++) {
		if (priv[i] != 0) {
			all_zero = 0;
			break;
		}
	}
	if (all_zero) {
		priv[31] = 1;
	}

	uint8_t pub[32];
	crypto_dh_pub_from_priv(pub, priv);

	if (util_write_file(priv_path, priv, sizeof(priv)) != 0) {
		return 1;
	}
	if (util_write_file(pub_path, pub, sizeof(pub)) != 0) {
		return 1;
	}

	fprintf(stdout, "Wrote %s (32 bytes)\n", priv_path);
	fprintf(stdout, "Wrote %s (32 bytes)\n", pub_path);
	return 0;
}

