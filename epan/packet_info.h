/* packet_info.h
 * Definitions for packet info structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_INFO_H__
#define __PACKET_INFO_H__

#include "frame_data.h"
#include "address.h"

struct conversation_element;

/** @file
 * Dissected packet data and metadata.
 */

/** @defgroup packetinfo Packet Data and Metadata
 *
 * @{
 */

/* Also defined in wiretap/wtap.h */
#define P2P_DIR_UNKNOWN -1
#define P2P_DIR_SENT    0
#define P2P_DIR_RECV    1

/* Link direction */
#define LINK_DIR_UNKNOWN    -1
#define P2P_DIR_UL  0
#define P2P_DIR_DL  1

/*
 * Presence flags.
 */
#define PINFO_HAS_TS            0x00000001  /**< time stamp */

typedef struct _packet_info {
  const char *current_proto;                          /**< Name of protocol currently being dissected */
  struct epan_column_info *cinfo;                     /**< Column formatting information */
  uint32_t presence_flags;                            /**< Presence flags for some items */
  uint32_t num;                                       /**< Frame number */
  nstime_t abs_ts;                                    /**< Packet absolute timestamp */
  nstime_t rel_ts;                                    /**< Relative timestamp (can be negative) */
  nstime_t rel_cap_ts;                                /**< Relative timestamp from capture start (may be negative for broken files) */
  bool rel_cap_ts_present;                            /**< True if relative capture timestamp is valid */

  frame_data *fd;                                     /**< Frame metadata and indexing information */
  union wtap_pseudo_header *pseudo_header;            /**< Capture-specific pseudo header (e.g., Ethernet, 802.11) */
  wtap_rec *rec;                                      /**< Record metadata */
  GSList *data_src;                                   /**< Frame data sources */

  address dl_src;                                     /**< Link-layer source address */
  address dl_dst;                                     /**< Link-layer destination address */
  address net_src;                                    /**< Network-layer source address */
  address net_dst;                                    /**< Network-layer destination address */
  address src;                                        /**< Source address (network if present, else DL) */
  address dst;                                        /**< Destination address (network if present, else DL) */

  uint32_t vlan_id;                                   /**< First encountered VLAN ID if present, else 0 */
  const char *noreassembly_reason;                    /**< Reason why reassembly was not performed, if any */
  bool fragmented;                                    /**< True if the protocol is a fragment */

  struct {
      uint32_t in_error_pkt : 1;                      /**< True if inside an error packet (e.g., ICMP, CLNP) */
      uint32_t in_gre_pkt   : 1;                      /**< True if encapsulated inside a GRE packet */
  } flags;

  uint32_t expert_severity;                           /**< Highest expert severity level */
  port_type ptype;                                    /**< Type of the srcport and destport */
  uint32_t srcport;                                   /**< Source port */
  uint32_t destport;                                  /**< Destination port */

  uint32_t match_uint;                                /**< Matched uint for calling subdissector from a table */
  const char *match_string;                           /**< Matched string for calling subdissector from a table */

  bool use_conv_addr_port_endpoints;                  /**< True if address/port endpoints should be used for conversations */
  struct conversation_addr_port_endpoints *conv_addr_port_endpoints; /**< Address+port conversation data, including wildcarding */
  struct conversation_element *conv_elements;         /**< Arbitrary conversation identifier (cannot be wildcarded) */

  uint16_t can_desegment;                             /**< >0 if this segment could be desegmented.
                                                          A dissector that can offer this API (e.g.
                                                          TCP) sets can_desegment=2, then
                                                          can_desegment is decremented by 1 each time
                                                          we pass to the next subdissector. Thus only
                                                          the dissector immediately above the
                                                          protocol which sets the flag can use it*/

  uint16_t saved_can_desegment;                       /**< Value of can_desegment before current
                                                          dissector was called.  Supplied so that
                                                          dissectors for proxy protocols such as
                                                          SOCKS can restore it, allowing the
                                                          dissectors that they call to use the
                                                          TCP dissector's desegmentation (SOCKS
                                                          just retransmits TCP segments once it's
                                                          finished setting things up, so the TCP
                                                          desegmentor can desegment its payload). */

  int desegment_offset;                               /**< Offset to data needing desegmentation */

#define DESEGMENT_ONE_MORE_SEGMENT 0x0fffffff
#define DESEGMENT_UNTIL_FIN        0x0ffffffe
  uint32_t desegment_len;            /**< requested desegmentation additional length
                                       or
                                       DESEGMENT_ONE_MORE_SEGMENT:
                                         Desegment one more full segment
                                         (warning! only partially implemented)
                                       DESEGMENT_UNTIL_FIN:
                                         Desegment all data for this tcp session
                                         until the FIN segment.
                                    */
  uint16_t want_pdu_tracking;    /**< >0 if the subdissector has specified
                                   a value in 'bytes_until_next_pdu'.
                                   When a dissector detects that the next PDU
                                   will start beyond the start of the next
                                   segment, it can set this value to 2
                                   and 'bytes_until_next_pdu' to the number of
                                   bytes beyond the next segment where the
                                   next PDU starts.

                                   If the protocol dissector below this
                                   one is capable of PDU tracking it can
                                   use this hint to detect PDUs that starts
                                   unaligned to the segment boundaries.
                                   The TCP dissector is using this hint from
                                   (some) protocols to detect when a new PDU
                                   starts in the middle of a tcp segment.

                                   There is intelligence in the glue between
                                   dissector layers to make sure that this
                                   request is only passed down to the protocol
                                   immediately below the current one and not
                                   any further.
                                */
  uint32_t bytes_until_next_pdu;                         /**< Number of bytes until the next PDU starts beyond the next segment */

  int     p2p_dir;              /**< Packet was captured as an
                                       outbound (P2P_DIR_SENT)
                                       inbound (P2P_DIR_RECV)
                                       unknown (P2P_DIR_UNKNOWN) */

  GHashTable *private_table;                           /**< Hash table passed between dissectors */
  wmem_list_t *layers;                                 /**< List of protocol layers */
  wmem_map_t *proto_layers;                            /**< Map from proto_id to curr_proto_layer_num */
  uint8_t curr_layer_num;                              /**< Current "depth" or layer number in the current frame */
  uint8_t curr_proto_layer_num;                        /**< Current "depth" or layer number for this dissector in the current frame */
  uint16_t link_number;                                /**< Link-layer interface index */

  uint16_t clnp_srcref;                                /**< CLNP/COTP source reference (cannot use srcport to avoid confusion with TPKT) */
  uint16_t clnp_dstref;                                /**< CLNP/COTP destination reference (cannot use dstport to avoid confusion with TPKT) */

  int link_dir;                                        /**< Link direction (e.g., 3GPP uplink or downlink) */
  int16_t src_win_scale;                               /**< Rcv.Wind.Shift src applies when sending segments; -1 unknown; -2 disabled */
  int16_t dst_win_scale;                               /**< Rcv.Wind.Shift dst applies when sending segments; -1 unknown; -2 disabled */

  GSList *proto_data;                                  /**< Per-packet protocol data */
  GSList *frame_end_routines;                          /**< List of routines to execute after frame dissection */

  wmem_allocator_t *pool;                              /**< Memory pool scoped to this pinfo */
  struct epan_session *epan;                           /**< Pointer to the current epan session context */

  const char *heur_list_name;                          /**< Name of heuristic list if packet is being heuristically dissected */
  int dissection_depth;                                /**< Current "depth" or layer number in the current frame */

  uint32_t stream_id;                                  /**< Conversation stream ID of the highest protocol */
  uint32_t track_ctype;                                /**< Tracks the conversation type for these protocols
                                                            subscribing to an error packet follow-up.
                                                            Typically transport protocols such as UDP or TCP
                                                            are likely to be followed up by ICMP. */
} packet_info;

/** @} */

#endif /* __PACKET_INFO_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
