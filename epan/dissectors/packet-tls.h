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

/* Opaque structure; the details are defined in packet-tls-utils.h */
typedef struct _SslDecryptSession SslDecryptSession;

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
 * Returns a SslDecryptSession pointer that can be used to retrieve info
 * about the current TLS session for a packet. This function is used by the
 * TLS dissector itself or by dissectors like QUIC that use a TLS handshake
 * but whose later packets are not inside a TLS record layer.
 *
 * This returns NULL if a session does not exist. Use ssl_get_session to
 * create a new session if one does not exist.
 *
 * @note At the very end of a packet dissection (e.g., when Follow Stream
 * functions are called), the TLS nested proto depth should be reset to
 * zero and this will return the first TLS session, if any.
 */
extern SslDecryptSession *
tls_get_current_session(packet_info *pinfo);

/**
 * Returns a SslDecryptSession pointer that can be used to retrieve info
 * about the TLS session of the TLS record layer that just called the
 * current dissector. This is use by subdissectors whose PDUs are inside
 * a TLS record layer.
 *
 * This returns NULL if there was not a previous TLS record layer.
 *
 * @note At the very end of a packet dissection, the TLS nested proto
 * depth should be reset to zero and this will return NULL.
 */
extern SslDecryptSession *
tls_get_parent_session(packet_info *pinfo);

/**
 * Retrieves Libgcrypt identifiers for the current TLS cipher. Only valid after
 * the Server Hello has been processed and if the current conversation has TLS.
 * Alternatively, this conversation lookup can be skipped if the current cipher
 * ('cipher_suite') is provided (non-zero).
 */
extern bool
tls_get_cipher_info(SslDecryptSession *tls_session, uint16_t cipher_suite, int *cipher_algo, int *cipher_mode, int *hash_algo);

/**
 * Computes the TLS 1.3 "TLS-Exporter(label, context_value, key_length)" value.
 * On success, the secret is in "out" (free with "wmem_free(NULL, out)").
 */
bool
tls13_exporter(SslDecryptSession *tls_session, bool is_early,
               const char *label, uint8_t *context,
               unsigned context_length, unsigned key_length, unsigned char **out);

int
tls13_get_quic_secret(packet_info *pinfo, bool is_from_server, int type, unsigned secret_min_len, unsigned secret_max_len, uint8_t *secret_out);

/**
 * Returns the application-layer protocol name (ALPN) for a TLS session,
 * or NULL if unavailable.
 *
 * @note The TLS dissector itself and the QUIC dissector call this with the
 * result of tls_get_current_session. Dissectors called by TLS can call
 * this with the session returned by tls_get_parent_session or check
 * pinfo->match_string instead.
 */
const char *
tls_get_alpn(SslDecryptSession *tls_session);

/**
 * Returns the application-layer protocol name (ALPN) that the client wanted for
 * a TLS session, or NULL if unavailable.
 *
 * @note The TLS dissector itself and the QUIC dissector call this with the
 * result of tls_get_current_session. Dissectors called by TLS can call
 * this with the session from tls_get_parent_session.
 */
const char *
tls_get_client_alpn(SslDecryptSession *tls_session);

extern uint32_t
tls_increment_stream_count(void);

#endif  /* __PACKET_TLS_H__ */
