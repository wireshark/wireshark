/* packet_info.h
 * Definitions for packet info structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_INFO_H__
#define __PACKET_INFO_H__

#include "frame_data.h"
#include "tvbuff.h"
#include "address.h"

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

typedef struct _packet_info {
  const char *current_proto;        /**< name of protocol currently being dissected */
  struct epan_column_info *cinfo;   /**< Column formatting information */
  frame_data *fd;
  union wtap_pseudo_header *pseudo_header;
  int file_type_subtype;            /**< Capture file type/subtype */
  struct wtap_pkthdr *phdr;         /**< Record metadata */
  GSList *data_src;                 /**< Frame data sources */
  address dl_src;                   /**< link-layer source address */
  address dl_dst;                   /**< link-layer destination address */
  address net_src;                  /**< network-layer source address */
  address net_dst;                  /**< network-layer destination address */
  address src;                      /**< source address (net if present, DL otherwise )*/
  address dst;                      /**< destination address (net if present, DL otherwise )*/
  guint32 ipproto;                  /**< IP protocol, if this is an IP packet */
  circuit_type ctype;               /**< type of circuit, for protocols with a VC identifier */
  guint32 circuit_id;               /**< circuit ID, for protocols with a VC identifier */
  const char *noreassembly_reason;  /**< reason why reassembly wasn't done, if any */
  gboolean fragmented;              /**< TRUE if the protocol is only a fragment */
  struct {
    guint32 in_error_pkt:1;         /**< TRUE if we're inside an {ICMP,CLNP,...} error packet */
    guint32 in_gre_pkt:1;           /**< TRUE if we're encapsulated inside a GRE packet */
  } flags;
  port_type ptype;                  /**< type of the following two port numbers */
  guint32 srcport;                  /**< source port */
  guint32 destport;                 /**< destination port */
  guint32 match_uint;               /**< matched uint for calling subdissector from table */
  const char *match_string;         /**< matched string for calling subdissector from table */
  guint16 can_desegment;            /**< >0 if this segment could be desegmented.
                                         A dissector that can offer this API (e.g.
                                         TCP) sets can_desegment=2, then
                                         can_desegment is decremented by 1 each time
                                         we pass to the next subdissector. Thus only
                                         the dissector immediately above the
                                         protocol which sets the flag can use it*/
  guint16 saved_can_desegment;      /**< Value of can_desegment before current
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
  guint32 desegment_len;            /**< requested desegmentation additional length
                                       or
                                       DESEGMENT_ONE_MORE_SEGMENT:
                                         Desegment one more full segment
                                         (warning! only partially implemented)
                                       DESEGMENT_UNTIL_FIN:
                                         Desgment all data for this tcp session
                                         until the FIN segment.
                                    */
  guint16 want_pdu_tracking;    /**< >0 if the subdissector has specified
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
  guint32 bytes_until_next_pdu;

  int     p2p_dir;              /**< Packet was captured as an
                                       outbound (P2P_DIR_SENT)
                                       inbound (P2P_DIR_RECV)
                                       unknown (P2P_DIR_UNKNOWN) */

  /**< Extra data for handling of decryption of GSSAPI wrapped tvbuffs.
     Caller sets decrypt_gssapi_tvb if this service is requested.
     If gssapi_encrypted_tvb is NULL, then the rest of the tvb data following
     the gssapi blob itself is decrypted othervise the gssapi_encrypted_tvb
     tvb will be decrypted (DCERPC has the data before the gssapi blob)
     If, on return, gssapi_data_encrypted is FALSE, the wrapped tvbuff
     was signed (i.e., an encrypted signature was present, to check
     whether the data was modified by a man in the middle) but not sealed
     (i.e., the data itself wasn't encrypted).
  */
#define DECRYPT_GSSAPI_NORMAL   1
#define DECRYPT_GSSAPI_DCE  2
  guint16 decrypt_gssapi_tvb;
  tvbuff_t *gssapi_wrap_tvb;
  tvbuff_t *gssapi_encrypted_tvb;
  tvbuff_t *gssapi_decrypted_tvb;
  gboolean gssapi_data_encrypted;

  void    *private_data;        /**< pointer to data passed from one dissector to another */
  GHashTable *private_table;    /**< a hash table passed from one dissector to another */

  wmem_list_t *layers;      /**< layers of each protocol */
  guint8 curr_layer_num;       /**< The current "depth" or layer number in the current frame */
  guint16 link_number;
  guint8  annex_a_used;         /**< used in packet-mtp2.c
                                 * defined in wtap.h
                                 * MTP2_ANNEX_A_NOT_USED      0
                                 * MTP2_ANNEX_A_USED          1
                                 * MTP2_ANNEX_A_USED_UNKNOWN  2
                                 */
  guint16 profinet_type;        /**< the type of PROFINET packet (0: not a PROFINET packet) */

  struct _sccp_msg_info_t* sccp_info;
  guint16 clnp_srcref;          /**< clnp/cotp source reference (can't use srcport, this would confuse tpkt) */
  guint16 clnp_dstref;          /**< clnp/cotp destination reference (can't use dstport, this would confuse tpkt) */

  int link_dir;                 /**< 3GPP messages are sometime different UP link(UL) or Downlink(DL) */

  GSList* proto_data;          /**< Per packet proto data */

  GSList* dependent_frames;     /**< A list of frames which this one depends on */

  GSList* frame_end_routines;

  wmem_allocator_t *pool;      /**< Memory pool scoped to the pinfo struct */
  struct epan_session *epan;
  nstime_t     rel_ts;       /**< Relative timestamp (yes, it can be negative) */
  const gchar  *pkt_comment; /**< NULL if not available */
  const gchar *heur_list_name;    /**< name of heur list if this packet is being heuristically dissected */
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
