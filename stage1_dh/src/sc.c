#include "sc.h"

#include "crypto_dh.h"
#include "crypto_gcm.h"
#include "crypto_sha256.h"
#include "net.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

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
	uint32_t s = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | (uint32_t)h[3];
	return s;
}

static void make_iv(uint8_t iv[12], uint32_t salt, uint64_t seq) {
	iv[0] = (uint8_t)(salt >> 24);
	iv[1] = (uint8_t)(salt >> 16);
	iv[2] = (uint8_t)(salt >> 8);
	iv[3] = (uint8_t)salt;
	u64_be_store(&iv[4], seq);
}

static int send_encrypted(int fd, struct sc_session *s, uint8_t type, const uint8_t *pt, uint32_t pt_len) {
	uint8_t iv[12];
	make_iv(iv, s->salt, s->send_seq);

	uint8_t aad[1 + 8];
	aad[0] = type;
	u64_be_store(&aad[1], s->send_seq);

	uint8_t *ct = NULL;
	if (pt_len > 0) {
		ct = (uint8_t *)malloc(pt_len);
		if (!ct) {
			return -1;
		}
	}

	uint8_t tag[16];
	if (crypto_aes256_gcm_encrypt(s->key, iv, aad, sizeof(aad), pt, pt_len, ct, tag) != 0) {
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
	u64_be_store(&frame[off], s->send_seq);
	off += 8;
	memcpy(&frame[off], iv, 12);
	off += 12;
	memcpy(&frame[off], tag, 16);
	off += 16;
	if (pt_len > 0) {
		memcpy(&frame[off], ct, pt_len);
	}

	int rc = net_send_frame(fd, frame, frame_len);
	free(ct);
	free(frame);
	if (rc != 0) {
		return -1;
	}

	s->send_seq++;
	return 0;
}

static int recv_decrypted(int fd, struct sc_session *s, uint8_t *out_type, uint8_t **out_pt, uint32_t *out_pt_len,
						  uint64_t *out_seq) {
	void *buf = NULL;
	uint32_t len = 0;
	if (net_recv_frame(fd, &buf, &len) != 0) {
		return -1;
	}
	if (len < 1 + 8 + 12 + 16) {
		net_free_frame(buf);
		return -1;
	}

	uint8_t *p = (uint8_t *)buf;
	uint8_t type = p[0];
	uint64_t seq = u64_be_load(&p[1]);
	const uint8_t *iv = &p[1 + 8];
	const uint8_t *tag = &p[1 + 8 + 12];
	const uint8_t *ct = &p[1 + 8 + 12 + 16];
	uint32_t ct_len = len - (1 + 8 + 12 + 16);

	uint8_t aad[1 + 8];
	aad[0] = type;
	u64_be_store(&aad[1], seq);

	uint8_t *pt = NULL;
	if (ct_len > 0) {
		pt = (uint8_t *)malloc(ct_len);
		if (!pt) {
			net_free_frame(buf);
			return -1;
		}
	}

	if (crypto_aes256_gcm_decrypt(s->key, iv, aad, sizeof(aad), ct, ct_len, tag, pt) != 0) {
		free(pt);
		net_free_frame(buf);
		return -1;
	}

	net_free_frame(buf);
	*out_type = type;
	*out_pt = pt;
	*out_pt_len = ct_len;
	*out_seq = seq;
	return 0;
}

static int do_rekey_client(int fd, struct sc_session *s) {
	uint8_t priv2[32];
	uint8_t pub2[32];
	if (crypto_dh_keypair(priv2, pub2) != 0) {
		return -1;
	}

	uint8_t n_c[16];
	if (util_random_bytes(n_c, sizeof(n_c)) != 0) {
		return -1;
	}

	uint8_t ctrl[1 + 16 + 32];
	ctrl[0] = CTRL_REKEY_INIT;
	memcpy(&ctrl[1], n_c, 16);
	memcpy(&ctrl[1 + 16], pub2, 32);

	if (send_encrypted(fd, s, MSG_CTRL, ctrl, sizeof(ctrl)) != 0) {
		return -1;
	}

	for (;;) {
		uint8_t type = 0;
		uint8_t *pt = NULL;
		uint32_t pt_len = 0;
		uint64_t seq = 0;
		if (recv_decrypted(fd, s, &type, &pt, &pt_len, &seq) != 0) {
			return -1;
		}
		if (type != MSG_CTRL || pt_len != (1 + 16 + 32) || pt[0] != CTRL_REKEY_REPLY) {
			free(pt);
			return -1;
		}

		uint8_t n_s[16];
		uint8_t pub_s2[32];
		memcpy(n_s, &pt[1], 16);
		memcpy(pub_s2, &pt[1 + 16], 32);
		free(pt);

		uint8_t shared2[32];
		crypto_dh_shared(shared2, priv2, pub_s2);
		uint8_t new_key[32];
		kdf_key(new_key, shared2, n_c, n_s);
		memcpy(s->key, new_key, 32);
		s->salt = derive_salt(n_c, n_s);
		s->send_seq = 0;
		s->recv_seq = 0;
		s->sent_since_rekey = 0;
		return 0;
	}
}

static int handle_rekey_server(int fd, struct sc_session *s, const uint8_t *pt, uint32_t pt_len) {
	if (pt_len != (1 + 16 + 32) || pt[0] != CTRL_REKEY_INIT) {
		return -1;
	}

	uint8_t n_c[16];
	uint8_t pub_c2[32];
	memcpy(n_c, &pt[1], 16);
	memcpy(pub_c2, &pt[1 + 16], 32);

	uint8_t priv2[32];
	uint8_t pub2[32];
	if (crypto_dh_keypair(priv2, pub2) != 0) {
		return -1;
	}
	uint8_t n_s[16];
	if (util_random_bytes(n_s, sizeof(n_s)) != 0) {
		return -1;
	}

	uint8_t shared2[32];
	crypto_dh_shared(shared2, priv2, pub_c2);
	uint8_t new_key[32];
	kdf_key(new_key, shared2, n_c, n_s);

	uint8_t reply[1 + 16 + 32];
	reply[0] = CTRL_REKEY_REPLY;
	memcpy(&reply[1], n_s, 16);
	memcpy(&reply[1 + 16], pub2, 32);

	if (send_encrypted(fd, s, MSG_CTRL, reply, sizeof(reply)) != 0) {
		return -1;
	}

	memcpy(s->key, new_key, 32);
	s->salt = derive_salt(n_c, n_s);
	s->send_seq = 0;
	s->recv_seq = 0;
	return 0;
}

int sc_client_handshake(int fd, struct sc_session *s) {
	uint8_t priv[32];
	uint8_t pub[32];
	if (crypto_dh_keypair(priv, pub) != 0) {
		return -1;
	}

	uint8_t n_c[16];
	if (util_random_bytes(n_c, sizeof(n_c)) != 0) {
		return -1;
	}

	uint8_t hello[1 + 16 + 32];
	hello[0] = MSG_CLIENT_HELLO;
	memcpy(&hello[1], n_c, 16);
	memcpy(&hello[1 + 16], pub, 32);
	if (net_send_frame(fd, hello, sizeof(hello)) != 0) {
		return -1;
	}

	void *buf = NULL;
	uint32_t len = 0;
	if (net_recv_frame(fd, &buf, &len) != 0) {
		return -1;
	}
	if (len != (1 + 16 + 32)) {
		net_free_frame(buf);
		return -1;
	}

	uint8_t *p = (uint8_t *)buf;
	if (p[0] != MSG_SERVER_HELLO) {
		net_free_frame(buf);
		return -1;
	}
	uint8_t n_s[16];
	uint8_t pub_s[32];
	memcpy(n_s, &p[1], 16);
	memcpy(pub_s, &p[1 + 16], 32);
	net_free_frame(buf);

	uint8_t shared[32];
	crypto_dh_shared(shared, priv, pub_s);

	kdf_key(s->key, shared, n_c, n_s);
	s->salt = derive_salt(n_c, n_s);
	s->send_seq = 0;
	s->recv_seq = 0;
	s->sent_since_rekey = 0;
	return 0;
}

int sc_server_handshake(int fd, struct sc_session *s) {
	void *buf = NULL;
	uint32_t len = 0;
	if (net_recv_frame(fd, &buf, &len) != 0) {
		return -1;
	}
	if (len != (1 + 16 + 32)) {
		net_free_frame(buf);
		return -1;
	}

	uint8_t *p = (uint8_t *)buf;
	if (p[0] != MSG_CLIENT_HELLO) {
		net_free_frame(buf);
		return -1;
	}
	uint8_t n_c[16];
	uint8_t pub_c[32];
	memcpy(n_c, &p[1], 16);
	memcpy(pub_c, &p[1 + 16], 32);
	net_free_frame(buf);

	uint8_t priv[32];
	uint8_t pub_s[32];
	if (crypto_dh_keypair(priv, pub_s) != 0) {
		return -1;
	}

	uint8_t n_s[16];
	if (util_random_bytes(n_s, sizeof(n_s)) != 0) {
		return -1;
	}

	uint8_t hello[1 + 16 + 32];
	hello[0] = MSG_SERVER_HELLO;
	memcpy(&hello[1], n_s, 16);
	memcpy(&hello[1 + 16], pub_s, 32);
	if (net_send_frame(fd, hello, sizeof(hello)) != 0) {
		return -1;
	}

	uint8_t shared[32];
	crypto_dh_shared(shared, priv, pub_c);

	kdf_key(s->key, shared, n_c, n_s);
	s->salt = derive_salt(n_c, n_s);
	s->send_seq = 0;
	s->recv_seq = 0;
	s->sent_since_rekey = 0;
	return 0;
}

int sc_send_data(int fd, struct sc_session *s, const uint8_t *pt, uint32_t pt_len) {
	if (s->rekey_every > 0 && s->sent_since_rekey >= s->rekey_every) {
		if (do_rekey_client(fd, s) != 0) {
			return -1;
		}
	}
	if (send_encrypted(fd, s, MSG_DATA, pt, pt_len) != 0) {
		return -1;
	}
	s->sent_since_rekey++;
	return 0;
}

int sc_recv_data(int fd, struct sc_session *s, uint8_t **out_pt, uint32_t *out_len) {
	for (;;) {
		uint8_t type = 0;
		uint8_t *pt = NULL;
		uint32_t pt_len = 0;
		uint64_t seq = 0;
		if (recv_decrypted(fd, s, &type, &pt, &pt_len, &seq) != 0) {
			return -1;
		}
		(void)seq;

		if (type == MSG_DATA) {
			*out_pt = pt;
			*out_len = pt_len;
			return 0;
		}
		if (type == MSG_CTRL) {
			int rc = handle_rekey_server(fd, s, pt, pt_len);
			free(pt);
			if (rc != 0) {
				return -1;
			}
			continue;
		}

		free(pt);
		return -1;
	}
}
