/* packet_info.h
 * Definitions for packet info structures and routines
 *
 * $Id: packet_info.h,v 1.36 2003/12/08 21:36:53 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

/* Types of addresses Ethereal knows about. */
typedef enum {
  AT_NONE,		/* no link-layer address */
  AT_ETHER,		/* MAC (Ethernet, 802.x, FDDI) address */
  AT_IPv4,		/* IPv4 */
  AT_IPv6,		/* IPv6 */
  AT_IPX,		/* IPX */
  AT_SNA,		/* SNA */
  AT_ATALK,		/* Appletalk DDP */
  AT_VINES,		/* Banyan Vines */
  AT_OSI,		/* OSI NSAP */
  AT_ARCNET,		/* ARCNET */
  AT_FC,                /* Fibre Channel */
  AT_SS7PC              /* SS7 Point Code */
} address_type;

typedef struct _address {
  address_type  type;		/* type of address */
  int           len;		/* length of address, in bytes */
  const guint8 *data;		/* bytes that constitute address */
} address;

#define	SET_ADDRESS(addr, addr_type, addr_len, addr_data) { \
	(addr)->type = (addr_type); \
	(addr)->len = (addr_len); \
	(addr)->data = (addr_data); \
	}

/*
 * Given two addresses, return
 *  0 if the addresses are equal,
 *  a positive number if addr1>addr2 in some nondefined metric,
 *  a negative number if addr1<addr2 in some nondefined metric
 */
#define CMP_ADDRESS(addr1, addr2) \
	(	((addr1)->type > (addr2)->type)?1:	\
		((addr1)->type < (addr2)->type)?-1:	\
		((addr1)->len  > (addr2)->len) ?1:	\
		((addr1)->len  < (addr2)->len) ?-1:	\
		memcmp((addr1)->data, (addr2)->data, (addr1)->len)\
	)

/*
 * Given two addresses, return "true" if they're equal, "false" otherwise.
 * Addresses are equal only if they have the same type; if the type is
 * AT_NONE, they are then equal, otherwise they must have the same
 * amount of data and the data must be the same.
 */
#define ADDRESSES_EQUAL(addr1, addr2)					\
	(								\
	 (addr1)->type == (addr2)->type &&				\
	 (								\
	  (addr1)->type == AT_NONE ||					\
	  (								\
	   (addr1)->len == (addr2)->len &&				\
	   memcmp((addr1)->data, (addr2)->data, (addr1)->len) == 0	\
	  )								\
	 )								\
	)

/*
 * Copy an address, allocating a new buffer for the address data.
 */
#define COPY_ADDRESS(to, from) { \
	guint8 *COPY_ADDRESS_data; \
	(to)->type = (from)->type; \
	(to)->len = (from)->len; \
	COPY_ADDRESS_data = g_malloc((from)->len); \
	memcpy(COPY_ADDRESS_data, (from)->data, (from)->len); \
	(to)->data = COPY_ADDRESS_data; \
	}

/* Types of port numbers Ethereal knows about. */
typedef enum {
  PT_NONE,		/* no port number */
  PT_SCTP,		/* SCTP */
  PT_TCP,		/* TCP */
  PT_UDP,		/* UDP */
  PT_IPX,		/* IPX sockets */
  PT_NCP,		/* NCP connection */
  PT_EXCHG,     /* Fibre Channel exchange */
  PT_DDP,               /* DDP AppleTalk connection */
  PT_SBCCS              /* FICON */
} port_type;

/* Types of circuit IDs Ethereal knows about. */
typedef enum {
  CT_NONE,		/* no port number */
  CT_DLCI,		/* Frame Relay DLCI */
  CT_ISDN,		/* ISDN channel number */
  CT_X25		/* X.25 logical channel number */
  /* Could also have ATM VPI/VCI pairs */
} circuit_type;

#define P2P_DIR_UNKNOWN	-1
#define P2P_DIR_SENT	0
#define P2P_DIR_RECV	1

#define PINFO_SOF_FIRST_FRAME   0x1
#define PINFO_SOF_SOFF          0x2
#define PINFO_EOF_LAST_FRAME    0x80
#define PINFO_EOF_INVALID       0x40

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
  char   *noreassembly_reason;  /* reason why reassembly wasn't done, if any */
  gboolean fragmented;		/* TRUE if the protocol is only a fragment */
  gboolean in_error_pkt;	/* TRUE if we're inside an {ICMP,CLNP,...} error packet */
  port_type ptype;		/* type of the following two port numbers */
  guint32 srcport;		/* source port */
  guint32 destport;		/* destination port */
  guint32 match_port;
  const char *match_string;	/* Subdissectors with string dissector tables use this */
  guint16 can_desegment;	/* >0 if this segment could be desegmented.
				   A dissector that can offer this API (e.g. TCP)
				   sets can_desegment=2, then can_desegment is
				   decremented by 1 each time we pass to the next
				   subdissector. Thus only the dissector immediately
				   above the protocol which sets the flag can use it*/
  int desegment_offset;		/* offset to stuff needing desegmentation */
  guint32 desegment_len;	/* requested desegmentation additional length */
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
  int	  p2p_dir;
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
  void    *private_data;	/* pointer to data passed from one dissector to another */
} packet_info;

#endif /* __PACKET_INFO_H__ */
