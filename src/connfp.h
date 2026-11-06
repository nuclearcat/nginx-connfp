/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef CONNFP_H
#define CONNFP_H
#include <stddef.h>
#include <stdint.h>

#define CONNFP_TLS_SIZE 50
#define CONNFP_SYN_SIZE 256
/* Includes the four-byte TLS handshake header, but no record header. */
int connfp_tls(const uint8_t *hello, size_t len, char out[CONNFP_TLS_SIZE]);
/* Starts at the IP header, as returned by Linux TCP_SAVED_SYN. */
int connfp_syn(const uint8_t *packet, size_t len, char out[CONNFP_SYN_SIZE]);
#endif
