/* packet_info.h
 * Definitions for packet info structures and routines
 *
 * $Id: packet_info.h,v 1.12 2001/11/29 09:05:25 guy Exp $
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
  AT_DLCI               /* Frame Relay DLCI */
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
 * Given two addresses, return "true" if they're equal, "false" otherwise.
 */
#define ADDRESSES_EQUAL(addr1, addr2) \
	((addr1)->type == (addr2)->type && \
	 (addr1)->len == (addr2)->len && \
	 memcmp((addr1)->data, (addr2)->data, (addr1)->len) == 0)

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
  PT_SCTP,              /* SCTP */
  PT_TCP,		/* TCP */
  PT_UDP,		/* UDP */
  PT_NCP		/* NCP connection */
} port_type;

#define P2P_DIR_UNKNOWN	-1
#define P2P_DIR_SENT	0
#define P2P_DIR_RECV	1

typedef struct _packet_info {
  const char *current_proto;	/* name of protocol currently being dissected */
  frame_data *fd;
  union wtap_pseudo_header *pseudo_header;
  address dl_src;		/* link-layer source address */
  address dl_dst;		/* link-layer destination address */
  address net_src;		/* network-layer source address */
  address net_dst;		/* network-layer destination address */
  address src;			/* source address (net if present, DL otherwise )*/
  address dst;			/* destination address (net if present, DL otherwise )*/
  guint32 ethertype;		/* Ethernet Type Code, if this is an Ethernet packet */
  guint32 ipproto;		/* IP protocol, if this is an IP packet */
  guint32 ipxptype;		/* IPX packet type, if this is an IPX packet */
  gboolean fragmented;		/* TRUE if the protocol is only a fragment */
  gboolean in_error_pkt;	/* TRUE if we're inside an {ICMP,CLNP,...} error packet */
  port_type ptype;		/* type of the following two port numbers */
  guint32 srcport;		/* source port */
  guint32 destport;		/* destination port */
  guint32 match_port;
  guint16 can_desegment;	/* >0 if this segment could be desegmented.
				   A dissector that can offer this API (e.g. TCP)
				   sets can_desegment=2, then can_desegment is
				   decremented by 1 each time we pass to the next
				   subdissector. Thus only the dissector immediately
				   above the protocol which sets the flag can use it*/
  int desegment_offset;		/* offset of stuff needing desegmentation */
  guint32 desegment_len;	/* requested desegmentation additional length */
  int     iplen;
  int     iphdrlen;
  int	  p2p_dir;
  void    *private_data;	/* pointer to data passed from one dissector to another */
} packet_info;

#endif /* __PACKET_INFO_H__ */
