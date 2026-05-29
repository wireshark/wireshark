/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_PROTO_HIER_STATS_H__
#define __UI_PROTO_HIER_STATS_H__

#include <epan/proto.h>
#include <epan/cfile.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Protocol Hierarchy Statistics
 */

/**
 * @brief Accumulates per-protocol packet and byte statistics for a single node in the protocol hierarchy tree.
 */
typedef struct {
    const header_field_info *hfinfo;         /**< Pointer to the header field descriptor identifying this protocol or field. */
    unsigned                 num_pkts_total; /**< Total number of packets containing this protocol across the entire capture. */
    unsigned                 num_pdus_total; /**< Total number of PDUs attributed to this protocol across the entire capture. */
    unsigned                 num_pkts_last;  /**< Number of packets containing this protocol in the most recent statistics interval. */
    unsigned                 num_bytes_total;/**< Total number of bytes attributed to this protocol across the entire capture. */
    unsigned                 num_bytes_last; /**< Number of bytes attributed to this protocol in the most recent statistics interval. */
    unsigned                 last_pkt;       /**< Frame number of the most recent packet containing this protocol. */
} ph_stats_node_t;

/**
 * @brief Holds aggregate protocol hierarchy statistics for a complete capture or filtered set of packets.
 */
typedef struct {
    unsigned tot_packets; /**< Total number of packets included in these statistics. */
    unsigned tot_bytes;   /**< Total number of bytes included in these statistics. */
    GNode   *stats_tree;  /**< Root of the protocol hierarchy statistics tree; each node is a @ref ph_stats_node_t. */
    double   first_time;  /**< Timestamp in seconds (millisecond resolution) of the first packet in the set. */
    double   last_time;   /**< Timestamp in seconds (millisecond resolution) of the last packet in the set. */
} ph_stats_t;

/**
 * @brief Create a new protocol hierarchy statistics object.
 *
 * @param cf Pointer to the capture file structure.
 * @return ph_stats_t* Pointer to the newly created protocol hierarchy statistics object, or NULL if an error occurred.
 */
ph_stats_t *ph_stats_new(capture_file *cf);

/**
 * @brief Frees memory allocated for a protocol hierarchy statistics structure.
 *
 * This function releases all resources associated with the given protocol
 * hierarchy statistics structure, including its tree and any dynamically
 * allocated data.
 *
 * @param ps Pointer to the protocol hierarchy statistics structure to be freed.
 */
void ph_stats_free(ph_stats_t *ps);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_PROTO_HIER_STATS_H__ */
