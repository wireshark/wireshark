/* packet-darwin-droptap-msg.h
 * Decoding of Darwin droptap message code.
 *
 * Copyright (c) 2024-2025 Apple Inc. All rights reserved.
 * Licensed under the terms of the MIT License.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef PACKET_DARWIN_DROPTAP_MSG_H
#define PACKET_DARWIN_DROPTAP_MSG_H

#include <stdint.h>

/*
 * Drop Reason is a 32-bit encoding of drop code, domain, and component.
 *
 *    Drop Reason
 *    +----+----+--------+----------------+
 *    | 4  | 4  |    8   |      16        |
 *    +----+----+--------+----------------+
 *      ^    ^      ^           ^
 *      |    |      |           Drop Code
 *      |    |      Domain
 *      |    Component
 *      Reserved
 *
 * [ 15:0] Drop Code: Specific reason why the drop happened (e.g. AQM full)
 * [23:16] Domain   : Which domain the drop happened (e.g. Flowswitch, TCP, IP)
 * [27:24] Component: Which component the drop happened (e.g. Skywalk, BSD, driver)
 * [31:28] Reserved : Reserved for future use
 *
 * This code is structured similarly to the implementation in the Darwin xnu kernel
 * to allow easier updates as the Darwin codebase evolves.
 */

#define DROP_COMPONENT_MASK   0x0f000000
#define DROP_COMPONENT_OFFSET 24
#define DROP_COMPONENT_MAX    0x0f
#define DROP_DOMAIN_MASK      0x00ff0000
#define DROP_DOMAIN_OFFSET    16
#define DROP_DOMAIN_MAX       0xff
#define DROP_CODE_MASK        0x0000ffff
#define DROP_CODE_OFFSET      0
#define DROP_CODE_MAX         0xffff

/* 32-bit Drop Reason */
#define DROP_REASON(component, domain, code) \
	(((unsigned)((component) & DROP_COMPONENT_MAX) << DROP_COMPONENT_OFFSET) | \
	 ((unsigned)((domain)    & DROP_DOMAIN_MAX)    << DROP_DOMAIN_OFFSET)    | \
	 ((unsigned)((code)      & DROP_CODE_MAX)      << DROP_CODE_OFFSET))

/* All components */
#define DROPTAP_SKYWALK 1       /**< User-space networking */
#define DROPTAP_BSD     2       /**< Kernel-space networking */

/* All domains for the Skywalk (user-space networking) component */
#define DROPTAP_FSW     1       /**< Flow Switch */
#define DROPTAP_NETIF   2       /**< Network Interface */
#define _DROPTAP_PAD_3  3       /**< Not used */
#define _DROPTAP_PAD_4  4       /**< Not used */
#define DROPTAP_AQM     5       /**< AQM (Active Queue Management) */

/* All domains for the BSD component */
#define DROPTAP_TCP     1       /**< TCP */
#define DROPTAP_UDP     2       /**< UDP */
#define DROPTAP_IP      3       /**< IPv4 */
#define DROPTAP_SOCK    4       /**< Sockets */
#define DROPTAP_DLIL    5       /**< Data-Link Interface Layer */
#define DROPTAP_IPSEC   6       /**< IPSec */
#define DROPTAP_IP6     7       /**< IPv6 */
#define DROPTAP_MPTCP   8       /**< MPTCP */
#define DROPTAP_PF      9       /**< Packet Filter */
#define DROPTAP_BRIDGE  10      /**< Bridge */

#define DROPTAP_UNSPEC  0       /**< Unspecified component */


#define DARWIN_DROP_REASON_LIST(X)                                                                                                   \
	X(DROP_REASON_UNSPECIFIED,                  DROPTAP_UNSPEC,  DROPTAP_UNSPEC, DROPTAP_UNSPEC, "Drop reason not specified")    \
	/* Skywalk component */                                                                                                      \
	X(DROP_REASON_FSW_PP_ALLOC_FAILED,          DROPTAP_SKYWALK, DROPTAP_FSW,  1,  "Flowswitch packet alloc failed")             \
	X(DROP_REASON_RX_DST_RING_FULL,             DROPTAP_SKYWALK, DROPTAP_FSW,  2,  "Flowswitch Rx destination ring full")        \
	X(DROP_REASON_FSW_QUIESCED,                 DROPTAP_SKYWALK, DROPTAP_FSW,  3,  "Flowswitch detached")                        \
	X(DROP_REASON_FSW_IFNET_NOT_ATTACHED,       DROPTAP_SKYWALK, DROPTAP_FSW,  4,  "Flowswitch ifnet not attached")              \
	X(DROP_REASON_FSW_DEMUX_FAILED,             DROPTAP_SKYWALK, DROPTAP_FSW,  5,  "Flowswitch demux error")                     \
	X(DROP_REASON_FSW_TX_DEVPORT_NOT_ATTACHED,  DROPTAP_SKYWALK, DROPTAP_FSW,  6,  "Flowswitch destination nexus port inactive") \
	X(DROP_REASON_FSW_TX_FLOW_EXTRACT_FAILED,   DROPTAP_SKYWALK, DROPTAP_FSW,  7,  "Flowswitch flow extract error")              \
	X(DROP_REASON_FSW_TX_FRAG_BAD_CONT,         DROPTAP_SKYWALK, DROPTAP_FSW,  8,  "Flowswitch invalid continuation fragment")   \
	X(DROP_REASON_FSW_TX_FLOW_NOT_FOUND,        DROPTAP_SKYWALK, DROPTAP_FSW,  9,  "Flowswitch flow lookup failed")              \
	X(DROP_REASON_FSW_TX_RESOLV_PENDING,        DROPTAP_SKYWALK, DROPTAP_FSW,  10, "Flowswitch resolution pending")              \
	X(DROP_REASON_FSW_TX_RESOLV_FAILED,         DROPTAP_SKYWALK, DROPTAP_FSW,  11, "Flowswitch resolution failed")               \
	X(DROP_REASON_FSW_FLOW_NONVIABLE,           DROPTAP_SKYWALK, DROPTAP_FSW,  12, "Flowswitch flow not viable")                 \
	X(DROP_REASON_FSW_RX_RING_NOT_FOUND,        DROPTAP_SKYWALK, DROPTAP_FSW,  13, "Flowswitch Rx ring not found")               \
	X(DROP_REASON_FSW_RX_PKT_NOT_FINALIZED,     DROPTAP_SKYWALK, DROPTAP_FSW,  14, "Flowswitch packet not finalized")            \
	X(DROP_REASON_FSW_FLOW_TRACK_ERR,           DROPTAP_SKYWALK, DROPTAP_FSW,  15, "Flowswitch flow tracker error")              \
	X(DROP_REASON_FSW_PKT_COPY_FAILED,          DROPTAP_SKYWALK, DROPTAP_FSW,  16, "Flowswitch packet copy failed")              \
	X(DROP_REASON_FSW_GSO_FAILED,               DROPTAP_SKYWALK, DROPTAP_FSW,  17, "Flowswitch GSO failed")                      \
	X(DROP_REASON_FSW_GSO_NOMEM_PKT,            DROPTAP_SKYWALK, DROPTAP_FSW,  18, "Flowswitch GSO not enough packet memory")    \
	X(DROP_REASON_FSW_GSO_NOMEM_MBUF,           DROPTAP_SKYWALK, DROPTAP_FSW,  19, "Flowswitch GSO not enough mbuf memory")      \
	X(DROP_REASON_FSW_DST_NXPORT_INVALID,       DROPTAP_SKYWALK, DROPTAP_FSW,  20, "Flowswitch dst nexus port invalid")          \
	X(DROP_REASON_AQM_FULL,                     DROPTAP_SKYWALK, DROPTAP_AQM,  1,  "AQM full")                                   \
	X(DROP_REASON_AQM_COMPRESSED,               DROPTAP_SKYWALK, DROPTAP_AQM,  2,  "AQM compressed")                             \
	X(DROP_REASON_AQM_BK_SYS_THROTTLED,         DROPTAP_SKYWALK, DROPTAP_AQM,  3,  "AQM BK_SYS throttled")                       \
	X(DROP_REASON_AQM_PURGE_FLOW,               DROPTAP_SKYWALK, DROPTAP_AQM,  4,  "AQM purge flow")                             \
	X(DROP_REASON_AQM_DROP,                     DROPTAP_SKYWALK, DROPTAP_AQM,  5,  "AQM drop")                                   \
	X(DROP_REASON_AQM_HIGH_DELAY,               DROPTAP_SKYWALK, DROPTAP_AQM,  6,  "AQM drop due to high delay")                 \
	/* Socket */                                                                                                                 \
	X(DROP_REASON_FULL_SOCK_RCVBUF,             DROPTAP_BSD,     DROPTAP_SOCK, 1,  "Socket receive buffer full")                 \
	/* DLIL */                                                                                                                   \
	X(DROP_REASON_DLIL_BURST_LIMIT,             DROPTAP_BSD,     DROPTAP_DLIL, 1,  "DLIL burst limit exceeded")                  \
	X(DROP_REASON_DLIL_ENQUEUE_INVALID,         DROPTAP_BSD,     DROPTAP_DLIL, 2,  "DLIL enqueue invalid")                       \
	X(DROP_REASON_DLIL_ENQUEUE_IF_NOT_ATTACHED, DROPTAP_BSD,     DROPTAP_DLIL, 3,  "DLIL enqueue interface not fully attached")  \
	X(DROP_REASON_DLIL_ENQUEUE_IF_NOT_UP,       DROPTAP_BSD,     DROPTAP_DLIL, 4,  "DLIL enqueue interface not up")              \
	X(DROP_REASON_DLIL_IF_FILTER,               DROPTAP_BSD,     DROPTAP_DLIL, 5,  "DLIL interface filter")                      \
	X(DROP_REASON_DLIL_IF_DATAMOV_BEGIN,        DROPTAP_BSD,     DROPTAP_DLIL, 6,  "DLIL interface datamove begin")              \
	X(DROP_REASON_DLIL_CLAT64,                  DROPTAP_BSD,     DROPTAP_DLIL, 7,  "DLIL CLAT46")                                \
	X(DROP_REASON_DLIL_PROMISC,                 DROPTAP_BSD,     DROPTAP_DLIL, 8,  "DLIL promiscuous")                           \
	X(DROP_REASON_DLIL_NO_PROTO,                DROPTAP_BSD,     DROPTAP_DLIL, 9,  "DLIL no protocol")                           \
	X(DROP_REASON_DLIL_PRE_OUTPUT,              DROPTAP_BSD,     DROPTAP_DLIL, 10, "DLIL pre output")                            \
	X(DROP_REASON_DLIL_IF_FRAMER,               DROPTAP_BSD,     DROPTAP_DLIL, 11, "DLIL interface framer")                      \
	X(DROP_REASON_DLIL_TSO_NOT_OK,              DROPTAP_BSD,     DROPTAP_DLIL, 12, "DLIL interface TSO not OK")                  \
	/* MPTCP */                                                                                                                  \
	X(DROP_REASON_MPTCP_INPUT_MALFORMED,        DROPTAP_BSD,     DROPTAP_MPTCP,1,  "MPTCP input packet malformed")               \
	X(DROP_REASON_MPTCP_REASSEMBLY_ALLOC,       DROPTAP_BSD,     DROPTAP_MPTCP,2,  "MPTCP reassembly allocation")                \
	/* PF */                                                                                                                     \
	X(DROP_REASON_PF_UNSPECIFIED,               DROPTAP_BSD,     DROPTAP_PF,   1,  "PF unspecified reason")                      \
	X(DROP_REASON_PF_UNDERSIZED,                DROPTAP_BSD,     DROPTAP_PF,   2,  "PF undersized")                              \
	X(DROP_REASON_PF_NO_ROUTE,                  DROPTAP_BSD,     DROPTAP_PF,   3,  "PF no route")                                \
	X(DROP_REASON_PF_NULL_IFP,                  DROPTAP_BSD,     DROPTAP_PF,   4,  "PF NULL ifp")                                \
	X(DROP_REASON_PF_NO_TSO,                    DROPTAP_BSD,     DROPTAP_PF,   5,  "PF No TSO?")                                 \
	X(DROP_REASON_PF_CANNOT_FRAGMENT,           DROPTAP_BSD,     DROPTAP_PF,   6,  "PF Cannot fragment")                         \
	X(DROP_REASON_PF_OVERLAPPING_FRAGMENT,      DROPTAP_BSD,     DROPTAP_PF,   7,  "PF overlapping fragment")                    \
	X(DROP_REASON_PF_BAD_FRAGMENT,              DROPTAP_BSD,     DROPTAP_PF,   8,  "PF overlapping fragment")                    \
	X(DROP_REASON_PF_MEM_ALLOC,                 DROPTAP_BSD,     DROPTAP_PF,   9,  "PF memory allocation")                       \
	X(DROP_REASON_PF_DROP,                      DROPTAP_BSD,     DROPTAP_PF,   10, "PF drop")                                    \
	/* BRIDGE */                                                                                                                 \
	X(DROP_REASON_BRIDGE_UNSPECIFIED,           DROPTAP_BSD,     DROPTAP_BRIDGE,   1,  "Bridge unspecified reason")              \
	X(DROP_REASON_BRIDGE_CHECKSUM,              DROPTAP_BSD,     DROPTAP_BRIDGE,   2,  "Bridge checksum")                        \
	X(DROP_REASON_BRIDGE_NOT_RUNNING,           DROPTAP_BSD,     DROPTAP_BRIDGE,   3,  "Bridge not running")                     \
	X(DROP_REASON_BRIDGE_PRIVATE_SEGMENT,       DROPTAP_BSD,     DROPTAP_BRIDGE,   4,  "Bridge private segment")                 \
	X(DROP_REASON_BRIDGE_NO_PROTO,              DROPTAP_BSD,     DROPTAP_BRIDGE,   5,  "Bridge unknown protocol")                \
	X(DROP_REASON_BRIDGE_BAD_PROTO,             DROPTAP_BSD,     DROPTAP_BRIDGE,   6,  "Bridge bad protocol")                    \
	X(DROP_REASON_BRIDGE_MAC_NAT_FAILURE,       DROPTAP_BSD,     DROPTAP_BRIDGE,   7,  "Bridge NAT failure")                     \
	X(DROP_REASON_BRIDGE_HOST_FILTER,           DROPTAP_BSD,     DROPTAP_BRIDGE,   8,  "Bridge host filter")                     \
	X(DROP_REASON_BRIDGE_HWASSIST,              DROPTAP_BSD,     DROPTAP_BRIDGE,   9,  "Bridge HW assisst")                      \
	X(DROP_REASON_BRIDGE_NOREF,                 DROPTAP_BSD,     DROPTAP_BRIDGE,   10, "Bridge noref")                           \
	X(DROP_REASON_BRIDGE_PF,                    DROPTAP_BSD,     DROPTAP_BRIDGE,   11, "Bridge PF")                              \
	X(DROP_REASON_BRIDGE_LOOP,                  DROPTAP_BSD,     DROPTAP_BRIDGE,   12, "Bridge loop")                            \
	X(DROP_REASON_BRIDGE_NOT_A_MEMBER,          DROPTAP_BSD,     DROPTAP_BRIDGE,   13, "Bridge not a member")                    \
	/* TCP */                                                                                                                    \
	X(DROP_REASON_TCP_RST,                      DROPTAP_BSD,     DROPTAP_TCP,  1,  "TCP connection reset")                       \
	X(DROP_REASON_TCP_REASSEMBLY_ALLOC,         DROPTAP_BSD,     DROPTAP_TCP,  2,  "TCP reassembly allocation")                  \
	X(DROP_REASON_TCP_NECP,                     DROPTAP_BSD,     DROPTAP_TCP,  3,  "TCP NECP not allowed")                       \
	X(DROP_REASON_TCP_PKT_UNSENT,               DROPTAP_BSD,     DROPTAP_TCP,  4,  "TCP unsent packet")                          \
	X(DROP_REASON_TCP_SRC_ADDR_NOT_AVAIL,       DROPTAP_BSD,     DROPTAP_TCP,  5,  "TCP source address not available")           \
	X(DROP_REASON_TCP_REASS_OVERFLOW,           DROPTAP_BSD,     DROPTAP_TCP,  6,  "TCP reassembly queue overflow")              \
	X(DROP_REASON_TCP_CHECKSUM_INCORRECT,       DROPTAP_BSD,     DROPTAP_TCP,  7,  "TCP checksum incorrect")                     \
	X(DROP_REASON_TCP_SRC_ADDR_UNSPECIFIED,     DROPTAP_BSD,     DROPTAP_TCP,  8,  "TCP source address unspecified")             \
	X(DROP_REASON_TCP_OFFSET_INCORRECT,         DROPTAP_BSD,     DROPTAP_TCP,  9,  "TCP offset incorrect")                       \
	X(DROP_REASON_TCP_SYN_FIN,                  DROPTAP_BSD,     DROPTAP_TCP,  10, "TCP SYN with FIN")                           \
	X(DROP_REASON_TCP_NO_SOCK,                  DROPTAP_BSD,     DROPTAP_TCP,  11, "TCP no socket")                              \
	X(DROP_REASON_TCP_PCB_MISMATCH,             DROPTAP_BSD,     DROPTAP_TCP,  12, "TCP protocol control block mismatch")        \
	X(DROP_REASON_TCP_NO_PCB,                   DROPTAP_BSD,     DROPTAP_TCP,  13, "TCP no protocol control block")              \
	X(DROP_REASON_TCP_CLOSED,                   DROPTAP_BSD,     DROPTAP_TCP,  14, "TCP state CLOSED")                           \
	X(DROP_REASON_TCP_FLAGS_INCORRECT,          DROPTAP_BSD,     DROPTAP_TCP,  15, "TCP flags incorrect")                        \
	X(DROP_REASON_TCP_LISTENER_CLOSING,         DROPTAP_BSD,     DROPTAP_TCP,  16, "TCP listener closing")                       \
	X(DROP_REASON_TCP_SYN_RST,                  DROPTAP_BSD,     DROPTAP_TCP,  17, "TCP SYN with RST")                           \
	X(DROP_REASON_TCP_SYN_ACK_LISTENER,         DROPTAP_BSD,     DROPTAP_TCP,  18, "TCP SYN with ACK for listener")              \
	X(DROP_REASON_TCP_LISTENER_NO_SYN,          DROPTAP_BSD,     DROPTAP_TCP,  19, "TCP no SYN for listener")                    \
	X(DROP_REASON_TCP_SAME_PORT,                DROPTAP_BSD,     DROPTAP_TCP,  20, "TCP same source and destination ports")      \
	X(DROP_REASON_TCP_BCAST_MCAST,              DROPTAP_BSD,     DROPTAP_TCP,  21, "TCP address not unicast")                    \
	X(DROP_REASON_TCP_DEPRECATED_ADDR,          DROPTAP_BSD,     DROPTAP_TCP,  22, "TCP address deprecated")                     \
	X(DROP_REASON_TCP_LISTENER_DROP,            DROPTAP_BSD,     DROPTAP_TCP,  23, "TCP listener drop")                          \
	X(DROP_REASON_TCP_PCB_HASH_FAILED,          DROPTAP_BSD,     DROPTAP_TCP,  24, "TCP protocol control block hash")            \
	X(DROP_REASON_TCP_CONTENT_FILTER_ATTACH,    DROPTAP_BSD,     DROPTAP_TCP,  25, "TCP control filter attach")                  \
	X(DROP_REASON_TCP_BIND_IN_PROGRESS,         DROPTAP_BSD,     DROPTAP_TCP,  26, "TCP bind in progress")                       \
	X(DROP_REASON_TCP_MEM_ALLOC,                DROPTAP_BSD,     DROPTAP_TCP,  27, "TCP memory allocation")                      \
	X(DROP_REASON_TCP_PCB_CONNECT,              DROPTAP_BSD,     DROPTAP_TCP,  28, "TCP protocol control block connect")         \
	X(DROP_REASON_TCP_SYN_RECEIVED_BAD_ACK,     DROPTAP_BSD,     DROPTAP_TCP,  29, "TCP SYN_RECEIVED bad ACK")                   \
	X(DROP_REASON_TCP_SYN_SENT_BAD_ACK,         DROPTAP_BSD,     DROPTAP_TCP,  30, "TCP SYN_SENT bad ACK")                       \
	X(DROP_REASON_TCP_SYN_SENT_NO_SYN,          DROPTAP_BSD,     DROPTAP_TCP,  31, "TCP SYN_SENT no SYN")                        \
	X(DROP_REASON_TCP_ACK_TOOMUCH,              DROPTAP_BSD,     DROPTAP_TCP,  32, "TCP ACK rate limit")                         \
	X(DROP_REASON_TCP_OLD_ACK,                  DROPTAP_BSD,     DROPTAP_TCP,  33, "TCP challenge ACK")                          \
	X(DROP_REASON_TCP_SYN_DATA_INVALID,         DROPTAP_BSD,     DROPTAP_TCP,  34, "TCP SYN data invalid")                       \
	X(DROP_REASON_TCP_SYN_RECEIVED_BAD_SEQ,     DROPTAP_BSD,     DROPTAP_TCP,  35, "TCP SYN_RECEIVED bad sequence number")       \
	X(DROP_REASON_TCP_RECV_AFTER_CLOSE,         DROPTAP_BSD,     DROPTAP_TCP,  36, "TCP receive after close")                    \
	X(DROP_REASON_TCP_BAD_ACK,                  DROPTAP_BSD,     DROPTAP_TCP,  37, "TCP bad ACK")                                \
	X(DROP_REASON_TCP_BAD_RST,                  DROPTAP_BSD,     DROPTAP_TCP,  38, "TCP bad RST")                                \
	X(DROP_REASON_TCP_PAWS,                     DROPTAP_BSD,     DROPTAP_TCP,  39, "TCP PAWS")                                   \
	X(DROP_REASON_TCP_REASS_MEMORY_PRESSURE,    DROPTAP_BSD,     DROPTAP_TCP,  40, "TCP reassembly queue memory pressure")       \
	X(DROP_REASON_TCP_CREATE_SERVER_SOCKET,     DROPTAP_BSD,     DROPTAP_TCP,  41, "TCP create server socket failed")            \
	X(DROP_REASON_TCP_INSEQ_MEMORY_PRESSURE,    DROPTAP_BSD,     DROPTAP_TCP,  42, "TCP in-seq input under memory pressure")     \
	/* IP */                                                                                                                     \
	X(DROP_REASON_IP_UNKNOWN_MULTICAST_GROUP,   DROPTAP_BSD,     DROPTAP_IP,   2, "IP unknown multicast group join")             \
	X(DROP_REASON_IP_INVALID_ADDR,              DROPTAP_BSD,     DROPTAP_IP,   3, "Invalid IP address")                          \
	X(DROP_REASON_IP_TOO_SHORT,                 DROPTAP_BSD,     DROPTAP_IP,   4, "IP packet too short")                         \
	X(DROP_REASON_IP_TOO_SMALL,                 DROPTAP_BSD,     DROPTAP_IP,   5, "IP header too small")                         \
	X(DROP_REASON_IP_RCV_IF_NO_MATCH,           DROPTAP_BSD,     DROPTAP_IP,   6, "IP receive interface no match")               \
	X(DROP_REASON_IP_CANNOT_FORWARD,            DROPTAP_BSD,     DROPTAP_IP,   7, "IP cannot forward")                           \
	X(DROP_REASON_IP_BAD_VERSION,               DROPTAP_BSD,     DROPTAP_IP,   8, "IP bad version")                              \
	X(DROP_REASON_IP_BAD_CHECKSUM,              DROPTAP_BSD,     DROPTAP_IP,   9, "IP bad checksum")                             \
	X(DROP_REASON_IP_BAD_HDR_LENGTH,            DROPTAP_BSD,     DROPTAP_IP,   10, "IP bad header length")                       \
	X(DROP_REASON_IP_BAD_LENGTH,                DROPTAP_BSD,     DROPTAP_IP,   11, "IP bad length")                              \
	X(DROP_REASON_IP_BAD_TTL,                   DROPTAP_BSD,     DROPTAP_IP,   12, "IP bad TTL")                                 \
	X(DROP_REASON_IP_NO_PROTO,                  DROPTAP_BSD,     DROPTAP_IP,   13, "IP unknown protocol")                        \
	X(DROP_REASON_IP_FRAG_NOT_ACCEPTED,         DROPTAP_BSD,     DROPTAP_IP,   14, "IP fragment not accepted")                   \
	X(DROP_REASON_IP_FRAG_DROPPED,              DROPTAP_BSD,     DROPTAP_IP,   15, "IP fragment dropped")                        \
	X(DROP_REASON_IP_FRAG_TIMEOUT,              DROPTAP_BSD,     DROPTAP_IP,   16, "IP fragment timeout")                        \
	X(DROP_REASON_IP_FRAG_TOO_MANY,             DROPTAP_BSD,     DROPTAP_IP,   17, "IP fragment too many")                       \
	X(DROP_REASON_IP_FRAG_TOO_LONG,             DROPTAP_BSD,     DROPTAP_IP,   18, "IP fragment too long")                       \
	X(DROP_REASON_IP_FRAG_DRAINED,              DROPTAP_BSD,     DROPTAP_IP,   19, "IP fragment drained")                        \
	X(DROP_REASON_IP_FILTER_DROP,               DROPTAP_BSD,     DROPTAP_IP,   20, "IP filter drop")                             \
	X(DROP_REASON_IP_FRAG_TOO_SMALL,            DROPTAP_BSD,     DROPTAP_IP,   21, "IP too small to fragment")                   \
	X(DROP_REASON_IP_FRAG_NO_MEM,               DROPTAP_BSD,     DROPTAP_IP,   22, "IP no memory for fragmentation")             \
	X(DROP_REASON_IP_CANNOT_FRAGMENT,           DROPTAP_BSD,     DROPTAP_IP,   23, "IP cannot fragment")                         \
	X(DROP_REASON_IP_OUTBOUND_IPSEC_POLICY,     DROPTAP_BSD,     DROPTAP_IP,   24, "IP outbound IPsec policy")                   \
	X(DROP_REASON_IP_ZERO_NET,                  DROPTAP_BSD,     DROPTAP_IP,   25, "IP to network zero")                         \
	X(DROP_REASON_IP_SRC_ADDR_NO_AVAIL,         DROPTAP_BSD,     DROPTAP_IP,   26, "IP source address not available")            \
	X(DROP_REASON_IP_DST_ADDR_NO_AVAIL,         DROPTAP_BSD,     DROPTAP_IP,   27, "IP destination address not available")       \
	X(DROP_REASON_IP_TO_RESTRICTED_IF,          DROPTAP_BSD,     DROPTAP_IP,   28, "IP packet to a restricted interface")        \
	X(DROP_REASON_IP_NO_ROUTE,                  DROPTAP_BSD,     DROPTAP_IP,   29, "IP no route")                                \
	X(DROP_REASON_IP_IF_CANNOT_MULTICAST,       DROPTAP_BSD,     DROPTAP_IP,   30, "IP multicast not supported by interface")    \
	X(DROP_REASON_IP_SRC_ADDR_ANY,              DROPTAP_BSD,     DROPTAP_IP,   31, "IP source address any")                      \
	X(DROP_REASON_IP_IF_CANNOT_BROADCAST,       DROPTAP_BSD,     DROPTAP_IP,   32, "IP broadcast not supported by interface")    \
	X(DROP_REASON_IP_BROADCAST_NOT_ALLOWED,     DROPTAP_BSD,     DROPTAP_IP,   33, "IP broadcast not allowed")                   \
	X(DROP_REASON_IP_BROADCAST_TOO_BIG,         DROPTAP_BSD,     DROPTAP_IP,   34, "IP broadcast too big for MTU")               \
	X(DROP_REASON_IP_FILTER_TSO,                DROPTAP_BSD,     DROPTAP_IP,   35, "TSO packet to IP filter")                    \
	X(DROP_REASON_IP_NECP_POLICY_NO_ALLOW_IF,   DROPTAP_BSD,     DROPTAP_IP,   36, "NECP not allowed on interface")              \
	X(DROP_REASON_IP_NECP_POLICY_DROP,          DROPTAP_BSD,     DROPTAP_IP,   37, "NECP drop")                                  \
	X(DROP_REASON_IP_NECP_POLICY_SOCKET_DIVERT, DROPTAP_BSD,     DROPTAP_IP,   38, "NECP socket divert")                         \
	X(DROP_REASON_IP_NECP_POLICY_TUN_NO_ALLOW_IF, DROPTAP_BSD,   DROPTAP_IP,   39, "NECP tunnel not allowed on interface")       \
	X(DROP_REASON_IP_NECP_POLICY_TUN_REBIND_NO_ALLOW_IF, DROPTAP_BSD,     DROPTAP_IP,   40, "NECP rebind not allowed on interface") \
	X(DROP_REASON_IP_NECP_POLICY_TUN_NO_REBIND_IF, DROPTAP_BSD,  DROPTAP_IP,   41, "NECP rebind not allowed on interface")       \
	X(DROP_REASON_IP_NECP_NO_ALLOW_IF,          DROPTAP_BSD,     DROPTAP_IP,   42, "NECP packet not allowed on interface")       \
	X(DROP_REASON_IP_ENOBUFS,                   DROPTAP_BSD,     DROPTAP_IP,   43, "IP No buffer space available")               \
	X(DROP_REASON_IP_ILLEGAL_PORT,              DROPTAP_BSD,     DROPTAP_IP,   44, "IP Illegal port")                            \
	X(DROP_REASON_IP_UNREACHABLE_PORT,          DROPTAP_BSD,     DROPTAP_IP,   45, "IP Unreachable port")                        \
	X(DROP_REASON_IP_MULTICAST_NO_PORT,         DROPTAP_BSD,     DROPTAP_IP,   46, "IP Multicast no port")                       \
	X(DROP_REASON_IP_EISCONN,                   DROPTAP_BSD,     DROPTAP_IP,   47, "IP Socket is already connected")             \
	X(DROP_REASON_IP_EAFNOSUPPORT,              DROPTAP_BSD,     DROPTAP_IP,   48, "IP Address family not supported by protocol family") \
	X(DROP_REASON_IP_NO_SOCK,                   DROPTAP_BSD,     DROPTAP_IP,   49, "IP No matching sock")                         \
	/* IPsec */                                                                                                                  \
	X(DROP_REASON_IPSEC_REJECT,                 DROPTAP_BSD,     DROPTAP_IPSEC,1,  "IPsec reject")                               \
	/* IPv6 */                                                                                                                   \
	X(DROP_REASON_IP6_OPT_DISCARD,              DROPTAP_BSD,     DROPTAP_IP6,  1, "IPv6 discard option")                         \
	X(DROP_REASON_IP6_IF_IPV6_DISABLED,         DROPTAP_BSD,     DROPTAP_IP6,  2, "IPv6 is disabled on the interface")           \
	X(DROP_REASON_IP6_BAD_SCOPE,                DROPTAP_BSD,     DROPTAP_IP6,  3, "IPv6 bad scope")                              \
	X(DROP_REASON_IP6_UNPROXIED_NS,             DROPTAP_BSD,     DROPTAP_IP6,  4, "IPv6 unproxied mistargeted Neighbor Solicitation") \
	X(DROP_REASON_IP6_BAD_OPTION,               DROPTAP_BSD,     DROPTAP_IP6,  5, "IPv6 bad option")                             \
	X(DROP_REASON_IP6_TOO_MANY_OPTIONS,         DROPTAP_BSD,     DROPTAP_IP6,  6, "IPv6 too many header options")                \
	X(DROP_REASON_IP6_BAD_PATH_MTU,             DROPTAP_BSD,     DROPTAP_IP6,  7, "IPv6 bad path MTU")                           \
	X(DROP_REASON_IP6_NO_PREFERRED_SRC_ADDR,    DROPTAP_BSD,     DROPTAP_IP6,  8, "IPv6 no preferred source address")            \
	X(DROP_REASON_IP6_BAD_HLIM,                 DROPTAP_BSD,     DROPTAP_IP6,  9, "IPv6 bad HLIM")                               \
	X(DROP_REASON_IP6_BAD_DAD,                  DROPTAP_BSD,     DROPTAP_IP6,  10, "IPv6 bad DAD")                               \
	X(DROP_REASON_IP6_NO_ND6ALT_IF,             DROPTAP_BSD,     DROPTAP_IP6,  11, "IPv6 no ND6ALT interface")                   \
	X(DROP_REASON_IP6_BAD_ND_STATE,             DROPTAP_BSD,     DROPTAP_IP6,  12, "IPv6 Bad ND state")                          \
	X(DROP_REASON_IP6_ONLY,                     DROPTAP_BSD,     DROPTAP_IP6,  13, "IPv6 Only")                                  \
	X(DROP_REASON_IP6_ADDR_UNSPECIFIED,         DROPTAP_BSD,     DROPTAP_IP6,  14, "IPv6 Address is unspecified")                \
	X(DROP_REASON_IP6_FRAG_OVERLAPPING,         DROPTAP_BSD,     DROPTAP_IP6,  15, "IPv6 Fragment overlaping")                   \
	X(DROP_REASON_IP6_FRAG_MIXED_CE,            DROPTAP_BSD,     DROPTAP_IP6,  16, "IPv6 Fragment mixed CE bits")                \
	X(DROP_REASON_IP6_RA_NOT_LL,                DROPTAP_BSD,     DROPTAP_IP6,  17, "IPv6 RA src is not LL")                      \
	X(DROP_REASON_IP6_RA_BAD_LLADDR_LEN,        DROPTAP_BSD,     DROPTAP_IP6,  18, "IPv6 RA bad LL length")                      \
	X(DROP_REASON_IP6_RS_BAD_LLADDR_LEN,        DROPTAP_BSD,     DROPTAP_IP6,  19, "IPv6 RS bad LL length")                      \
	X(DROP_REASON_IP6_MEM_ALLOC,                DROPTAP_BSD,     DROPTAP_IP6,  20, "IPv6 memory allocation")                     \
	X(DROP_REASON_IP6_TOO_BIG,                  DROPTAP_BSD,     DROPTAP_IP6,  21, "IPv6 too big for MTU")                       \
	X(DROP_REASON_IP6_POSSIBLE_LOOP,            DROPTAP_BSD,     DROPTAP_IP6,  22, "IPv6 possible loop")                         \
	X(DROP_REASON_IP6_ICMP_DROP,                DROPTAP_BSD,     DROPTAP_IP6,  23, "IPv6 ICMPv6 drop")                           \
	X(DROP_REASON_IP6_BAD_NI,                   DROPTAP_BSD,     DROPTAP_IP6,  24, "IPv6 bad NI")                                \
	X(DROP_REASON_IP6_NS_FROM_NON_NEIGHBOR,     DROPTAP_BSD,     DROPTAP_IP6,  25, "IPv6 NS from non-neighbor")                  \
	X(DROP_REASON_IP6_NS_TO_MULTICAST,          DROPTAP_BSD,     DROPTAP_IP6,  26, "IPv6 NS targeting multicast")                \
	X(DROP_REASON_IP6_NS_BAD_ND_OPT,            DROPTAP_BSD,     DROPTAP_IP6,  27, "IPv6 NS with invalid ND opt")                \
	X(DROP_REASON_IP6_NS_BAD_LLADDR_LEN,        DROPTAP_BSD,     DROPTAP_IP6,  28, "IPv6 NS bad LL length")                      \
	X(DROP_REASON_IP6_NS_DUPLICATE_ADDRESS,     DROPTAP_BSD,     DROPTAP_IP6,  29, "IPv6 NS duplicate address")                  \
	X(DROP_REASON_IP6_NS_INVALID_TARGET,        DROPTAP_BSD,     DROPTAP_IP6,  30, "IPv6 NS invalid target")                     \
	X(DROP_REASON_IP6_NA_INVALID_TARGET,        DROPTAP_BSD,     DROPTAP_IP6,  31, "IPv6 NA invalid target")                     \
	X(DROP_REASON_IP6_NA_DST_MULTICAST,         DROPTAP_BSD,     DROPTAP_IP6,  32, "IPv6 NA destination is multicast")           \
	X(DROP_REASON_IP6_NA_UNKNOWN_SRC_ADDR,      DROPTAP_BSD,     DROPTAP_IP6,  33, "IPv6 NA destination is multicast")           \
	X(DROP_REASON_IP6_NA_BAD_LLADDR_LEN,        DROPTAP_BSD,     DROPTAP_IP6,  34, "IPv6 NA bad LL length")                      \
	X(DROP_REASON_IP6_NA_NOT_CACHED_SCOPED,     DROPTAP_BSD,     DROPTAP_IP6,  35, "IPv6 NA not cached scoped ")                 \
	X(DROP_REASON_IP6_NA_NOT_CACHED,            DROPTAP_BSD,     DROPTAP_IP6,  36, "IPv6 NA not cached")                         \
	X(DROP_REASON_IP6_NA_MISSING_LLADDR_OPT,    DROPTAP_BSD,     DROPTAP_IP6,  37, "IPv6 NA missing lladdr opt")                 \
	X(DROP_REASON_IP6_NA_MISSING_ROUTE,         DROPTAP_BSD,     DROPTAP_IP6,  38, "IPv6 NA missing route info")                 \
	X(DROP_REASON_IP6_BAD_UDP_CHECKSUM,         DROPTAP_BSD,     DROPTAP_IP6,  39, "IPv6 invalid UDP checksum")                  \
	X(DROP_REASON_IP6_ILLEGAL_PORT,             DROPTAP_BSD,     DROPTAP_IP6,  40, "IPv6 Illegal port")                          \
	/* UDP */                                                                                                                    \
	X(DROP_REASON_UDP_SET_PORT_FAILURE,         DROPTAP_BSD,     DROPTAP_UDP,  1, "UDP failed to set ephemeral port ")           \
	X(DROP_REASON_UDP_DST_PORT_ZERO,            DROPTAP_BSD,     DROPTAP_UDP,  2, "UDP destination port zero")                   \
	X(DROP_REASON_UDP_BAD_LENGTH,               DROPTAP_BSD,     DROPTAP_UDP,  3, "UDP bad length")                              \
	X(DROP_REASON_UDP_BAD_CHECKSUM,             DROPTAP_BSD,     DROPTAP_UDP,  4, "UDP bad checksum")                            \
	X(DROP_REASON_UDP_PORT_UNREACHEABLE,        DROPTAP_BSD,     DROPTAP_UDP,  5, "UDP port unreachable")                        \
	X(DROP_REASON_UDP_SOCKET_CLOSING,           DROPTAP_BSD,     DROPTAP_UDP,  6, "UDP socket closing")                          \
	X(DROP_REASON_UDP_NECP,                     DROPTAP_BSD,     DROPTAP_UDP,  7, "UDP denied by NECP")                          \
	X(DROP_REASON_UDP_CANNOT_SAVE_CONTROL,      DROPTAP_BSD,     DROPTAP_UDP,  8, "UDP cannot save control mbufs")               \
	X(DROP_REASON_UDP_IPSEC,                    DROPTAP_BSD,     DROPTAP_UDP,  9, "UDP IPsec")                                   \
	X(DROP_REASON_UDP_PACKET_SHORTER_THAN_HEADER, DROPTAP_BSD,   DROPTAP_UDP,  10, "UDP packet shorter than header")             \
	X(DROP_REASON_UDP_NAT_KEEPALIVE,            DROPTAP_BSD,     DROPTAP_UDP,  11, "UDP NAT keepalive")                          \
	X(DROP_REASON_UDP_PCB_GARBAGE_COLLECTED,    DROPTAP_BSD,     DROPTAP_UDP,  12, "UDP PCB garbage collected")                  \


#endif /* PACKET_DARWIN_DROPTAP_MSG_H */
