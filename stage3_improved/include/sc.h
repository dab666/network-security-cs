#pragma once

#include <stdint.h>

struct sc_session {
	uint8_t key[32];
	uint32_t salt;
	uint64_t send_seq;
	uint64_t recv_seq;
	uint32_t rekey_every;
	uint32_t sent_since_rekey;

	uint8_t server_static_pub[32];
	uint8_t server_static_priv[32];
	int has_static_priv;
};

int sc_client_handshake(int fd, struct sc_session *s);
int sc_server_handshake(int fd, struct sc_session *s);

int sc_send_data(int fd, struct sc_session *s, const uint8_t *pt, uint32_t pt_len);
int sc_recv_data(int fd, struct sc_session *s, uint8_t **out_pt, uint32_t *out_len);

