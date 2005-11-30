/* address.h
 * Definitions for structures storing addresses, and for the type of
 * variables holding port-type values
 *
 * $Id$
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

#ifndef __ADDRESS_H__
#define __ADDRESS_H__

/* Types of addresses Ethereal knows about. */
/* If a new address type is added here, a string representation procedure should */
/* also be included in address_to_str_buf defined in to_str.c, for presentation purposes */

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
  AT_ARCNET,	/* ARCNET */
  AT_FC,		/* Fibre Channel */
  AT_SS7PC,		/* SS7 Point Code */
  AT_STRINGZ,	/* null-terminated string */
  AT_EUI64,		/* IEEE EUI-64 */
  AT_URI		/* URI/URL/URN */
} address_type;

typedef struct _address {
  address_type  type;		/* type of address */
  int           len;		/* length of address, in bytes */
  const guint8 *data;		/* bytes that constitute address */
} address;

#define	SET_ADDRESS(addr, addr_type, addr_len, addr_data) { \
	(addr)->type = (addr_type); \
	(addr)->len = (addr_len); \
	(addr)->data = (void *)(addr_data); \
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
  PT_DCCP,		/* DCCP */
  PT_IPX,		/* IPX sockets */
  PT_NCP,		/* NCP connection */
  PT_EXCHG,		/* Fibre Channel exchange */
  PT_DDP,		/* DDP AppleTalk connection */
  PT_SBCCS,		/* FICON */
  PT_IDP		/* XNS IDP sockets */
} port_type;

/* Types of circuit IDs Ethereal knows about. */
typedef enum {
  CT_NONE,		/* no circuit type */
  CT_DLCI,		/* Frame Relay DLCI */
  CT_ISDN,		/* ISDN channel number */
  CT_X25,		/* X.25 logical channel number */
  CT_ISUP,		/* ISDN User Part CIC */
  CT_IAX2,		/* IAX2 call id */
  CT_H223,		/* H.223 logical channel number */
  CT_BICC		/* BICC Circuit identifier */
  /* Could also have ATM VPI/VCI pairs */
} circuit_type;

#endif /* __ADDRESS_H__ */

