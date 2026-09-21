/** @file
 *
 * Attribute captured packets to the processes on this host that sent or
 * received them, by looking their sockets up while capturing.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CAPTURE_PROCESS_INFO_H__
#define __CAPTURE_PROCESS_INFO_H__

#include <wireshark.h>
#include <wsutil/process_lookup.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct capture_process_info capture_process_info_t;

/**
 * A function that lists the capture interfaces, with their addresses, as
 * capture_options.get_iface_list does.
 */
typedef GList *(*capture_process_info_iface_list_func)(int *err, char **err_str);

/**
 * @brief Set up to attribute packets to processes.
 *
 * @param get_iface_list Lists this host's interfaces; their addresses say
 * which end of a packet is on this host.
 * @param detail How much to find out about the processes.
 * @param err_msg Set to a g_malloc()ed message if this fails.
 * @return The context, or NULL if process information is not available.
 */
extern capture_process_info_t *
capture_process_info_new(capture_process_info_iface_list_func get_iface_list,
                         ws_process_detail_t detail, char **err_msg);

extern void
capture_process_info_free(capture_process_info_t *cpi);

/**
 * @brief Whether packets with a link-layer header type can be attributed.
 *
 * @param linktype The LINKTYPE_ value of the interface.
 */
extern bool
capture_process_info_linktype_supported(int linktype);

/**
 * @brief Find the processes that sent or received a packet.
 *
 * They are the processes that have a socket matching the end of the packet
 * that is on this host: one of its addresses or, for the destination, a
 * broadcast or multicast address. Both ends of a loopback packet are.
 *
 * @param cpi The context.
 * @param linktype The LINKTYPE_ value of the packet.
 * @param data The packet data.
 * @param len The number of bytes captured.
 * @param processes What is known about each process is appended, as const
 * ws_process_info_t pointers valid until the context is freed.
 * @return The number of processes appended.
 */
extern unsigned
capture_process_info_lookup(capture_process_info_t *cpi, int linktype,
                            const uint8_t *data, size_t len,
                            GPtrArray *processes);

/**
 * @brief Forget which processes the output file already describes.
 *
 * Call when starting a new output file.
 */
extern void
capture_process_info_new_file(capture_process_info_t *cpi);

/**
 * @brief Whether a process still has to be described in the output file.
 *
 * @return true the first time it is called for a process since the file
 * was started; the process then counts as described.
 */
extern bool
capture_process_info_needs_description(capture_process_info_t *cpi,
                                       const ws_process_info_t *process);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_PROCESS_INFO_H__ */
