/** @file
 *
 * The interface between the platform-independent part of the process
 * lookup and its platform backends. Not installed.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_PROCESS_LOOKUP_INT_H__
#define __WSUTIL_PROCESS_LOOKUP_INT_H__

#include "process_lookup.h"

/**
 * A socket as found in the operating system's tables, in a form that can
 * be hashed: addresses in network byte order, zero-padded; ports in host
 * byte order. Always initialize it with ws_process_lookup_key_init(), which
 * normalizes it: ip_version 0 means the socket is bound to any address (so
 * it matches both IP versions), and a zero remote address and port mean the
 * socket is not connected.
 */
typedef struct {
    uint8_t  protocol;
    uint8_t  ip_version;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t  local_addr[16];
    uint8_t  remote_addr[16];
} ws_process_lookup_socket_key_t;

/**
 * Initialize a socket key. remote_addr may be NULL. An IPv4 address seen
 * through an IPv6 socket (::ffff:a.b.c.d) becomes an IPv4 key.
 */
void
ws_process_lookup_key_init(ws_process_lookup_socket_key_t *key,
                           uint8_t protocol, uint8_t ip_version,
                           const uint8_t *local_addr, uint16_t local_port,
                           const uint8_t *remote_addr, uint16_t remote_port);

/**
 * Called by a backend for each process that has a socket open. It may be
 * called for several processes with the same socket, and more than once
 * for the same process and socket.
 */
typedef void (*ws_process_lookup_add_socket_func)(void *ctx,
                                                  const ws_process_lookup_socket_key_t *key,
                                                  uint32_t pid);

/**
 * A platform backend. err_msg arguments are never NULL; a message stored
 * there must be g_malloc()ed.
 */
typedef struct {
    /** Whether this platform is supported at all. */
    bool supported;

    /** Set up the per-context state; NULL, with *err_msg set, on failure. */
    void *(*create)(char **err_msg);

    /** Free the per-context state. */
    void (*destroy)(void *state);

    /** Report every socket that has an owning process, through add(). */
    bool (*refresh)(void *state, ws_process_lookup_add_socket_func add,
                    void *ctx, char **err_msg);

    /**
     * Fill in what is known about a process; info->pid is set on entry and
     * the rest is zero. The strings must be g_malloc()ed. With
     * WS_PROCESS_DETAIL_BASIC only the name and the start time are filled
     * in, and the rest is not read. Returns false if there is no such
     * process.
     */
    bool (*describe)(void *state, uint32_t pid, ws_process_detail_t detail,
                     ws_process_info_t *info);
} ws_process_lookup_backend_t;

/** The backend for this platform. */
extern const ws_process_lookup_backend_t ws_process_lookup_backend;

#endif /* __WSUTIL_PROCESS_LOOKUP_INT_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
