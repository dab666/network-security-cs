#pragma once

#include <stdint.h>

int net_listen_tcp(const char *host, uint16_t port, int backlog);
int net_accept(int listen_fd);
int net_connect_tcp(const char *host, uint16_t port);
int net_set_reuseaddr(int fd);
int net_set_nodelay(int fd);
int net_send_all(int fd, const void *buf, uint32_t len);
int net_recv_all(int fd, void *buf, uint32_t len);

int net_send_frame(int fd, const void *buf, uint32_t len);
int net_recv_frame(int fd, void **out_buf, uint32_t *out_len);
void net_free_frame(void *buf);
