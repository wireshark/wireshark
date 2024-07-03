/* packet-tls.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TLS_H__
#define __PACKET_TLS_H__

#include "ws_symbol_export.h"
#include <epan/packet.h>

struct tlsinfo {
        uint32_t seq; /* The sequence number within the TLS stream. */
        bool is_reassembled;
        bool end_of_stream; /* TCP FIN, close_notify, etc. */
        /* The app handle for the session, set by heuristic dissectors
         * to be called in the future. */
        dissector_handle_t *app_handle;
};

WS_DLL_PUBLIC void ssl_dissector_add(unsigned port, dissector_handle_t handle);
WS_DLL_PUBLIC void ssl_dissector_delete(unsigned port, dissector_handle_t handle);

WS_DLL_PUBLIC void ssl_set_master_secret(uint32_t frame_num, address *addr_srv, address *addr_cli,
                                  port_type ptype, uint32_t port_srv, uint32_t port_cli,
                                  uint32_t version, int cipher, const unsigned char *_master_secret,
                                  const unsigned char *_client_random, const unsigned char *_server_random,
                                  uint32_t client_seq, uint32_t server_seq);
/**
 * Retrieves Libgcrypt identifiers for the current TLS cipher. Only valid after
 * the Server Hello has been processed and if the current conversation has TLS.
 * Alternatively, this conversation lookup can be skipped if the current cipher
 * ('cipher_suite') is provided (non-zero).
 */
extern bool
tls_get_cipher_info(packet_info *pinfo, uint16_t cipher_suite, int *cipher_algo, int *cipher_mode, int *hash_algo);

/**
 * Computes the TLS 1.3 "TLS-Exporter(label, context_value, key_length)" value.
 * On success, the secret is in "out" (free with "wmem_free(NULL, out)").
 */
bool
tls13_exporter(packet_info *pinfo, bool is_early,
               const char *label, uint8_t *context,
               unsigned context_length, unsigned key_length, unsigned char **out);

int
tls13_get_quic_secret(packet_info *pinfo, bool is_from_server, int type, unsigned secret_min_len, unsigned secret_max_len, uint8_t *secret_out);

/**
 * Returns the application-layer protocol name (ALPN) for the current TLS
 * session, or NULL if unavailable.
 */
const char *
tls_get_alpn(packet_info *pinfo);

/**
 * Returns the application-layer protocol name (ALPN) that the client wanted for
 * the current TLS session, or NULL if unavailable.
 */
const char *
tls_get_client_alpn(packet_info *pinfo);

#endif  /* __PACKET_TLS_H__ */
