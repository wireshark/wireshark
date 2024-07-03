/* packet-udp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_UDP_H__
#define __PACKET_UDP_H__

#include "ws_symbol_export.h"

#include <epan/conversation.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* UDP structs and definitions */
typedef struct _e_udphdr {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint32_t uh_ulen;
    uint32_t uh_sum_cov;
    uint16_t uh_sum;
    uint32_t uh_stream; /* this stream index field is included to help differentiate when address/port pairs are reused */
    address ip_src;
    address ip_dst;
} e_udphdr;

/* Conversation and process structures originally copied from packet-tcp.c */
typedef struct _udp_flow_t {
    /* Process info, currently discovered via IPFIX */
    uint32_t process_uid;    /* UID of local process */
    uint32_t process_pid;    /* PID of local process */
    char *username;        /* Username of the local process */
    char *command;         /* Local process name + path + args */
} udp_flow_t;

struct udp_analysis {
    /* These two structs are managed based on comparing the source
     * and destination addresses and, if they're equal, comparing
     * the source and destination ports.
     *
     * If the source is greater than the destination, then stuff
     * sent from src is in ual1.
     *
     * If the source is less than the destination, then stuff
     * sent from src is in ual2.
     *
     * XXX - if the addresses and ports are equal, we don't guarantee
     * the behavior.
     */
    udp_flow_t  flow1;
    udp_flow_t  flow2;

    /* These pointers are set by get_udp_conversation_data()
     * fwd point in the same direction as the current packet
     * and rev in the reverse direction
     */
    udp_flow_t  *fwd;
    udp_flow_t  *rev;

    /* Keep track of udp stream numbers instead of using the conversation
     * index (as how it was done before). This prevents gaps in the
     * stream index numbering
     */
    uint32_t    stream;

    /* Keep track of packet number within the UDP stream */
    uint32_t    pnum;

    /* Remember the timestamp of the first frame seen in this udp
     * conversation to be able to calculate a relative time compared
     * to the start of this conversation
     */
    nstime_t    ts_first;

    /* Remember the timestamp of the frame that was last seen in this
     * udp conversation to be able to calculate a delta time compared
     * to previous frame in this conversation
     */
    nstime_t    ts_prev;
};

/** Associate process information with a given flow
 *
 * @param frame_num The frame number
 * @param local_addr The local IPv4 or IPv6 address of the process
 * @param remote_addr The remote IPv4 or IPv6 address of the process
 * @param local_port The local TCP port of the process
 * @param remote_port The remote TCP port of the process
 * @param uid The numeric user ID of the process
 * @param pid The numeric PID of the process
 * @param username Ephemeral string containing the full or partial process name
 * @param command Ephemeral string containing the full or partial process name
 */
extern void
add_udp_process_info(uint32_t frame_num, address *local_addr, address *remote_addr,
                     uint16_t local_port, uint16_t remote_port,
                     uint32_t uid, uint32_t pid,
                     char *username, char *command);

/** Get the current number of UDP streams
 *
 * @return The number of UDP streams
 */
WS_DLL_PUBLIC uint32_t
get_udp_stream_count(void);

WS_DLL_PUBLIC void
decode_udp_ports(tvbuff_t *, int, packet_info *, proto_tree *, int, int, int);

WS_DLL_PUBLIC struct udp_analysis *
get_udp_conversation_data(conversation_t *, packet_info *);

/*
 * Loop for dissecting PDUs within a UDP packet; Similar to tcp_dissect_pdus,
 * but doesn't have stream support. Assumes that a PDU consists of a
 * fixed-length chunk of data that contains enough information
 * to determine the length of the PDU, followed by rest of the PDU.
 *
 * @param tvb the tvbuff with the (remaining) packet data passed to dissector
 * @param pinfo the packet info of this packet (additional info) passed to dissector
 * @param tree the protocol tree to be build or NULL passed to dissector
 * @param fixed_len is the length of the fixed-length part of the PDU.
 * @param heuristic_check is the optional routine called to see if dissection
 * should be done; it's passed "pinfo", "tvb", "offset" and "dissector_data".
 * @param get_pdu_len is a routine called to get the length of the PDU from
 * the fixed-length part of the PDU; it's passed "pinfo", "tvb", "offset" and
 * "dissector_data".
 * @param dissect_pdu the sub-dissector to be called
 * @param dissector_data parameter to pass to subdissector
 */
WS_DLL_PUBLIC int
udp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 unsigned fixed_len,
                 bool (*heuristic_check)(packet_info *, tvbuff_t *, int, void*),
                 unsigned (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
                 dissector_t dissect_pdu, void* dissector_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
