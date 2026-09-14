/** @file
 *
 * Look up the processes that have a network socket open, from the
 * operating system's socket tables, and describe them.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_PROCESS_LOOKUP_H__
#define __WSUTIL_PROCESS_LOOKUP_H__

#include <wireshark.h>
#include <wsutil/inet_addr.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief What the operating system knows about a process.
 *
 * Whatever the operating system does not provide, or does not let the
 * calling user see, is NULL (strings), 0 (the start time) or flagged as
 * absent. Strings are UTF-8.
 */
typedef struct ws_process_info {
    uint32_t  pid;            /**< The process ID. */
    bool      has_ppid;       /**< Whether ppid is known. */
    uint32_t  ppid;           /**< The ID of the parent process. */
    bool      has_uid;        /**< Whether uid is known (systems with numeric user IDs). */
    uint32_t  uid;            /**< The numeric ID of the user the process runs as. */
    char     *name;           /**< The short name of the process, typically its executable's file name, or NULL. */
    char     *path;           /**< The full path of the executable image, or NULL. */
    char     *user;           /**< The name of the user the process runs as, e.g. "alice" or "DOMAIN\\alice", or NULL. */
    uint8_t  *cmdline;        /**< The command line, its arguments separated by NULs (none after the last), or NULL. */
    size_t    cmdline_len;    /**< The length of cmdline, in bytes. */
    uint64_t  start_time_ns;  /**< When the process started, in nanoseconds since the Epoch, or 0 if unknown. */
} ws_process_info_t;

/**
 * @brief The transport protocols of the sockets that can be looked up.
 *
 * The values are the IP protocol numbers, so the protocol field of an IP
 * header can be passed as is.
 */
typedef enum {
    WS_PROCESS_LOOKUP_TCP = 6,
    WS_PROCESS_LOOKUP_UDP = 17
} ws_process_lookup_protocol_t;

/**
 * @brief One end of a socket: an IPv4 or IPv6 address and a port.
 */
typedef struct ws_socket_endpoint {
    uint8_t  ip_version;      /**< 4 or 6. */
    union {
        ws_in4_addr ipv4;     /**< The IPv4 address, in network byte order. */
        ws_in6_addr ipv6;     /**< The IPv6 address. */
    } addr;
    uint16_t port;            /**< The port, in host byte order. */
} ws_socket_endpoint_t;

/**
 * @brief A lookup context.
 *
 * It holds a snapshot of the operating system's socket tables, refreshed
 * on demand but not more often than a configurable interval, and a cache
 * of what is known about the processes found. It is not thread-safe.
 */
typedef struct ws_process_lookup ws_process_lookup_t;

/**
 * @brief Whether the operating system's socket tables can be read on this platform.
 *
 * @return true if ws_process_lookup_new() can succeed here.
 */
WS_DLL_PUBLIC bool
ws_process_lookup_supported(void);

/**
 * @brief Create a lookup context.
 *
 * @param err_msg Set to a g_malloc()ed message on failure, if not NULL.
 * @return The context, to be freed with ws_process_lookup_free(), or NULL
 * if the platform is not supported or the socket tables cannot be read.
 */
WS_DLL_PUBLIC ws_process_lookup_t *
ws_process_lookup_new(char **err_msg);

/**
 * @brief Free a lookup context and every ws_process_info_t it returned.
 *
 * @param lookup The context; NULL is allowed.
 */
WS_DLL_PUBLIC void
ws_process_lookup_free(ws_process_lookup_t *lookup);

/**
 * @brief Set how soon the socket tables may be read again after a miss.
 *
 * A socket that is not in the snapshot triggers a refresh only if the
 * previous refresh is at least this old, which bounds the cost of packets
 * that belong to no local socket. The default is 250 ms.
 *
 * @param lookup The context.
 * @param interval_ms The minimum interval between refreshes, in milliseconds.
 * Whatever it is, refreshes are also kept at least ten times as far apart as
 * the last one took, so that a host with very many sockets, where reading
 * the tables is slow, still gets most of the caller's time.
 */
WS_DLL_PUBLIC void
ws_process_lookup_set_refresh_interval(ws_process_lookup_t *lookup, unsigned interval_ms);

/**
 * @brief Read the operating system's socket tables again now.
 *
 * @param lookup The context.
 * @param err_msg Set to a g_malloc()ed message on failure, if not NULL.
 * @return true on success.
 */
WS_DLL_PUBLIC bool
ws_process_lookup_refresh(ws_process_lookup_t *lookup, char **err_msg);

/**
 * @brief Find the processes that have a socket open.
 *
 * The socket is identified by its local end and, for a connected socket,
 * its remote end. If no socket matches both, a socket bound to the local
 * end alone (listening, or an unconnected UDP socket) is looked for, and
 * then one bound to the local port on any address, of either IP version.
 * Every process that has a matching socket open is reported: a socket can
 * be inherited across fork() or passed between processes, and several
 * sockets can match, e.g. with SO_REUSEPORT. On Windows the system reports
 * one process per socket, the one that bound it.
 *
 * @param lookup The context.
 * @param protocol The transport protocol.
 * @param local The end of the socket on this host.
 * @param remote The other end, or NULL if the socket is not connected or
 * the other end is unknown.
 * @param processes Array to which what is known about each process is
 * appended, as const ws_process_info_t pointers valid until the context
 * is freed, the process that has had the socket open longest first,
 * normally the one that created it.
 * @return The number of processes appended: 0 if no socket matches or
 * none can be attributed to a process.
 */
WS_DLL_PUBLIC unsigned
ws_process_lookup_socket(ws_process_lookup_t *lookup,
                         ws_process_lookup_protocol_t protocol,
                         const ws_socket_endpoint_t *local,
                         const ws_socket_endpoint_t *remote,
                         GPtrArray *processes);

/**
 * @brief Describe a process by its ID.
 *
 * @param lookup The context.
 * @param pid The process ID.
 * @return What is known about the process, valid until the context is
 * freed, or NULL if there is no such process.
 */
WS_DLL_PUBLIC const ws_process_info_t *
ws_process_lookup_pid(ws_process_lookup_t *lookup, uint32_t pid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_PROCESS_LOOKUP_H__ */

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
