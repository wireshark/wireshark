/* packet_info.h
 * Definitions for packet info structures and routines
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_INFO_H__
#define __PACKET_INFO_H__

#include "frame_data.h"
#include "tvbuff.h"
#include "address.h"

#define P2P_DIR_UNKNOWN	-1
#define P2P_DIR_SENT	0
#define P2P_DIR_RECV	1

#define MTP2_ANNEX_A_USED_UNKNOWN -1
#define MTP2_ANNEX_A_NOT_USED      0
#define MTP2_ANNEX_A_USED          1

#define PINFO_SOF_FIRST_FRAME   0x1
#define PINFO_SOF_SOFF          0x2
#define PINFO_EOF_LAST_FRAME    0x80
#define PINFO_EOF_INVALID       0x40
#define MAX_NUMBER_OF_PPIDS     2

typedef struct _packet_info {
  const char *current_proto;	/* name of protocol currently being dissected */
  column_info *cinfo;		/* Column formatting information */
  frame_data *fd;
  union wtap_pseudo_header *pseudo_header;
  GSList *data_src;		/* Frame data sources */
  address dl_src;		/* link-layer source address */
  address dl_dst;		/* link-layer destination address */
  address net_src;		/* network-layer source address */
  address net_dst;		/* network-layer destination address */
  address src;			/* source address (net if present, DL otherwise )*/
  address dst;			/* destination address (net if present, DL otherwise )*/
  guint32 ethertype;		/* Ethernet Type Code, if this is an Ethernet packet */
  guint32 ipproto;		/* IP protocol, if this is an IP packet */
  guint32 ipxptype;		/* IPX packet type, if this is an IPX packet */
  circuit_type ctype;		/* type of circuit, for protocols with a VC identifier */
  guint32 circuit_id;		/* circuit ID, for protocols with a VC identifier */
  const char *noreassembly_reason;  /* reason why reassembly wasn't done, if any */
  gboolean fragmented;		/* TRUE if the protocol is only a fragment */
  gboolean in_error_pkt;	/* TRUE if we're inside an {ICMP,CLNP,...} error packet */
  port_type ptype;		/* type of the following two port numbers */
  guint32 srcport;		/* source port */
  guint32 destport;		/* destination port */
  guint32 match_port;
  const char *match_string;	/* Subdissectors with string dissector tables use this */
  guint16 can_desegment;	/* >0 if this segment could be desegmented.
				   A dissector that can offer this API (e.g.
				   TCP) sets can_desegment=2, then
				   can_desegment is decremented by 1 each time
				   we pass to the next subdissector. Thus only
				   the dissector immediately above the
				   protocol which sets the flag can use it*/
  guint16 saved_can_desegment;	/* Value of can_desegment before current
				   dissector was called.  Supplied so that
				   dissectors for proxy protocols such as
				   SOCKS can restore it, allowing the
				   dissectors that they call to use the
				   TCP dissector's desegmentation (SOCKS
				   just retransmits TCP segments once it's
				   finished setting things up, so the TCP
				   desegmentor can desegment its payload). */
  int desegment_offset;		/* offset to stuff needing desegmentation */
#define DESEGMENT_ONE_MORE_SEGMENT 0x0fffffff
#define DESEGMENT_UNTIL_FIN        0x0ffffffe
  guint32 desegment_len;	/* requested desegmentation additional length
				   or 
				   DESEGMENT_ONE_MORE_SEGMENT:
				     Desegment one more full segment 
				     (warning! only partially implemented)
				   DESEGMENT_UNTIL_FIN:
				     Desgment all data for this tcp session 
				     until the FIN segment.
				*/
  guint16 want_pdu_tracking;	/* >0 if the subdissector has specified
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


  int     iplen;
  int     iphdrlen;
  int	  p2p_dir;              /* Packet was captured as an 
                                       outbound (P2P_DIR_SENT) 
                                       inbound (P2P_DIR_RECV) 
                                       unknown (P2P_DIR_UNKNOWN) */
  guint16 oxid;                 /* next 2 fields reqd to identify fibre */
  guint16 rxid;                 /* channel conversations */
  guint8  r_ctl;                /* R_CTL field in Fibre Channel Protocol */
  guint8  sof_eof;              /* FC's SOF/EOF encoding passed to FC decoder
                                 * Bit 7 set if Last frame in sequence
                                 * Bit 6 set if invalid frame content
                                 * Bit 2 set if SOFf
                                 * Bit 1 set if first frame in sequence
                                 */
  guint16 src_idx;              /* Source port index (Cisco MDS-specific) */
  guint16 dst_idx;              /* Dest port index (Cisco MDS-specific) */
  guint16 vsan;                 /* Fibre channel/Cisco MDS-specific */

  /* Extra data for DCERPC handling and tracking of context ids */
  guint16 dcectxid;             /* Context ID (DCERPC-specific) */
  int     dcetransporttype;     /* Transport type
                                 * Value -1 means "not a DCERPC packet"
                                 */
  guint16 dcetransportsalt;	/* fid: if transporttype==DCE_CN_TRANSPORT_SMBPIPE */

  /* Extra data for handling of decryption of GSSAPI wrapped tvbuffs.
     Caller sets decrypt_gssapi_tvb if this service is requested.
     If gssapi_encrypted_tvb is NULL, then the rest of the tvb data following
     the gssapi blob itself is decrypted othervise the gssapi_encrypted_tvb
     tvb will be decrypted (DCERPC has the data before the gssapi blob)
     If, on return, gssapi_data_encrypted is FALSE, the wrapped tvbuff
     was signed (i.e., an encrypted signature was present, to check
     whether the data was modified by a man in the middle) but not sealed
     (i.e., the data itself wasn't encrypted).
  */
#define DECRYPT_GSSAPI_NORMAL	1
#define DECRYPT_GSSAPI_DCE	2
  guint16 decrypt_gssapi_tvb;
  tvbuff_t *gssapi_wrap_tvb;
  tvbuff_t *gssapi_encrypted_tvb;
  tvbuff_t *gssapi_decrypted_tvb;
  gboolean gssapi_data_encrypted;
 
  guint32 ppid[MAX_NUMBER_OF_PPIDS]; /* The first NUMBER_OF_PPIDS PPIDS which are present
                                      * in the SCTP packet
                                      */
  void    *private_data;	/* pointer to data passed from one dissector to another */
  GString *layer_names; 	/* layers of each protocol */
  guint16 link_number;
  gchar   annex_a_used;
  guint16 profinet_type; 	/* the type of PROFINET packet (0: not a PROFINET packet) */
  void *usb_conv_info;
  void *tcp_tree;		/* proto_tree for the tcp layer */
} packet_info;

#endif /* __PACKET_INFO_H__ */
