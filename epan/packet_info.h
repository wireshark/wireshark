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
#include "tvbuff.h"
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
  const char *current_proto;        /**< name of protocol currently being dissected */
  struct epan_column_info *cinfo;   /**< Column formatting information */
  uint32_t presence_flags;           /**< Presence flags for some items */
  uint32_t num;                      /**< Frame number */
  nstime_t abs_ts;                  /**< Packet absolute time stamp */
  nstime_t rel_ts;                  /**< Relative timestamp (yes, it can be negative) */
  nstime_t rel_cap_ts;              /**< Relative timestamp from capture start (might be negative for broken files) */
  bool rel_cap_ts_present;      /**< Relative timestamp from capture start valid */
  frame_data *fd;
  union wtap_pseudo_header *pseudo_header;
  wtap_rec *rec;                    /**< Record metadata */
  GSList *data_src;                 /**< Frame data sources */
  address dl_src;                   /**< link-layer source address */
  address dl_dst;                   /**< link-layer destination address */
  address net_src;                  /**< network-layer source address */
  address net_dst;                  /**< network-layer destination address */
  address src;                      /**< source address (net if present, DL otherwise )*/
  address dst;                      /**< destination address (net if present, DL otherwise )*/
  uint32_t vlan_id;                  /**< First encountered VLAN Id if present otherwise 0 */
  const char *noreassembly_reason;  /**< reason why reassembly wasn't done, if any */
  bool fragmented;              /**< true if the protocol is only a fragment */
  struct {
    uint32_t in_error_pkt:1;         /**< true if we're inside an {ICMP,CLNP,...} error packet */
    uint32_t in_gre_pkt:1;           /**< true if we're encapsulated inside a GRE packet */
  } flags;
  port_type ptype;                  /**< type of the following two port numbers */
  uint32_t srcport;                  /**< source port */
  uint32_t destport;                 /**< destination port */
  uint32_t match_uint;               /**< matched uint for calling subdissector from table */
  const char *match_string;         /**< matched string for calling subdissector from table */
  bool use_conv_addr_port_endpoints; /**< true if address/port endpoints member should be used for conversations */
  struct conversation_addr_port_endpoints* conv_addr_port_endpoints; /**< Data that can be used for address+port conversations, including wildcarding */
  struct conversation_element *conv_elements; /**< Arbitrary conversation identifier; can't be wildcarded */
  uint16_t can_desegment;            /**< >0 if this segment could be desegmented.
                                         A dissector that can offer this API (e.g.
                                         TCP) sets can_desegment=2, then
                                         can_desegment is decremented by 1 each time
                                         we pass to the next subdissector. Thus only
                                         the dissector immediately above the
                                         protocol which sets the flag can use it*/
  uint16_t saved_can_desegment;      /**< Value of can_desegment before current
                                         dissector was called.  Supplied so that
                                         dissectors for proxy protocols such as
                                         SOCKS can restore it, allowing the
                                         dissectors that they call to use the
                                         TCP dissector's desegmentation (SOCKS
                                         just retransmits TCP segments once it's
                                         finished setting things up, so the TCP
                                         desegmentor can desegment its payload). */
  int desegment_offset;             /**< offset to stuff needing desegmentation */
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
  uint32_t bytes_until_next_pdu;

  int     p2p_dir;              /**< Packet was captured as an
                                       outbound (P2P_DIR_SENT)
                                       inbound (P2P_DIR_RECV)
                                       unknown (P2P_DIR_UNKNOWN) */

  GHashTable *private_table;    /**< a hash table passed from one dissector to another */

  wmem_list_t *layers;          /**< layers of each protocol */
  wmem_map_t *proto_layers;     /** map of proto_id to curr_proto_layer_num. */
  uint8_t curr_layer_num;        /**< The current "depth" or layer number in the current frame */
  uint8_t curr_proto_layer_num;  /**< The current "depth" or layer number for this dissector in the current frame */
  uint16_t link_number;

  uint16_t clnp_srcref;          /**< clnp/cotp source reference (can't use srcport, this would confuse tpkt) */
  uint16_t clnp_dstref;          /**< clnp/cotp destination reference (can't use dstport, this would confuse tpkt) */

  int link_dir;                 /**< 3GPP messages are sometime different UP link(UL) or Downlink(DL) */

  int16_t src_win_scale;        /**< Rcv.Wind.Shift src applies when sending segments; -1 unknown; -2 disabled */
  int16_t dst_win_scale;        /**< Rcv.Wind.Shift dst applies when sending segments; -1 unknown; -2 disabled */

  GSList* proto_data;          /**< Per packet proto data */

  GSList* frame_end_routines;

  wmem_allocator_t *pool;      /**< Memory pool scoped to the pinfo struct */
  struct epan_session *epan;
  const char *heur_list_name;    /**< name of heur list if this packet is being heuristically dissected */
  int dissection_depth;         /**< The current "depth" or layer number in the current frame */

  uint32_t stream_id;            /**< Conversation Stream ID of the highest protocol */
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
