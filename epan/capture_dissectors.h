/* capture_dissectors.h
 * Routines for handling capture dissectors
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CAPTURE_DISSECTORS_H__
#define __CAPTURE_DISSECTORS_H__

#include "ws_symbol_export.h"
#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 */

/** Table of counts of packets of various types. */
typedef struct {
    GHashTable*       counts_hash; /* packet counters keyed by proto */
    int               other;       /* Packets not counted in the hash total */
    int               total;       /* Cache of total packets */
} packet_counts;

typedef struct _capture_packet_info {
    GHashTable *counts;
} capture_packet_info_t;

typedef struct capture_dissector_handle* capture_dissector_handle_t;

/** callback function definition for capture dissectors */
typedef bool (*capture_dissector_t)(const uint8_t *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

/* a protocol uses the function to register a capture sub-dissector table
 * @param[in] name Name of capture sub-dissector table.
 * @param[in] ui_name Name string used when referring to capture sub-dissector table in UI.
 */
WS_DLL_PUBLIC void register_capture_dissector_table(const char *name, const char *ui_name);

/* Create an anonymous handle for a capture dissector
 * @param[in] dissector capture dissector function.
 * @param[in] proto Protocol associated with capture dissector function.
 * @return  Handle created for capture dissector
 */
WS_DLL_PUBLIC capture_dissector_handle_t create_capture_dissector_handle(capture_dissector_t dissector, const int proto);

/* Find a dissector by name
 * @param[in] name Name of capture dissector
 * @return  Handle for capture dissector if found, NULL otherwise
 */
WS_DLL_PUBLIC capture_dissector_handle_t find_capture_dissector(const char *name);

/* Register a new capture dissector
 * @param[in] name Name of capture dissector function.
 * @param[in] dissector capture dissector function.
 * @param[in] proto Protocol associated with capture dissector function.
 * @return  Handle created for capture dissector
 */
WS_DLL_PUBLIC capture_dissector_handle_t register_capture_dissector(const char *name, capture_dissector_t dissector, int proto);

/* Add an entry to a uint capture dissector table
 * @param[in] name Name of capture dissector table
 * @param[in] pattern Numerical value associated with capture dissector
 * @param[in] handle Handle to capture dissector
 */
WS_DLL_PUBLIC void capture_dissector_add_uint(const char *name, const uint32_t pattern, capture_dissector_handle_t handle);

/* Look for a given value in a given uint capture dissector table and, if found,
 * call the dissector with the arguments supplied, and return true,
 * otherwise return false
 * @param[in] name Name of capture dissector table
 * @param[in] pattern Numerical value associated with capture dissector
 * @param[in] pd Data buffer of captured bytes
 * @param[in] offset Current offset into pd
 * @param[in] len Length of pd
 * @param[in] cpinfo Capture statistics
 * @param[in] pseudo_header Wiretap pseudo header information
 */
WS_DLL_PUBLIC bool try_capture_dissector(const char* name, const uint32_t pattern, const uint8_t *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

/* Call a capture dissector through a handle. If handle is value return true,
 * otherwise return false
 * @param[in] handle Capture dissector handle
 * @param[in] pd Data buffer of captured bytes
 * @param[in] offset Current offset into pd
 * @param[in] len Length of pd
 * @param[in] cpinfo Capture statistics
 * @param[in] pseudo_header Wiretap pseudo header information
 */
WS_DLL_PUBLIC bool call_capture_dissector(capture_dissector_handle_t handle, const uint8_t *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

/* Get current capture packet count for a particular protocol
 * @param[in] counts Packet count structure
 * @param[in] proto Protocol to retrieve packet count from
 * @return Number of packets captured for a particular protocol
 */
WS_DLL_PUBLIC uint32_t capture_dissector_get_count(packet_counts* counts, const int proto);

/* Increment packet capture count by 1 for a particular protocol.
 * @param[in] cpinfo Capture statistics
 * @param[in] proto Protocol to increment packet count
 */
WS_DLL_PUBLIC void capture_dissector_increment_count(capture_packet_info_t *cpinfo, const int proto);

extern void capture_dissector_init(void);
extern void capture_dissector_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture_dissectors.h */
