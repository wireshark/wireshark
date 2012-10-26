/* address.h
 * Definitions for structures storing addresses, and for the type of
 * variables holding port-type values
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __ADDRESS_H__
#define __ADDRESS_H__

#include <string.h>     /* for memcmp */
#include "emem.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Types of addresses Wireshark knows about. */
/* If a new address type is added here, a string representation procedure should */
/* also be included in address_to_str_buf defined in to_str.c, for presentation purposes */

typedef enum {
  AT_NONE,               /* no link-layer address */
  AT_ETHER,              /* MAC (Ethernet, 802.x, FDDI) address */
  AT_IPv4,               /* IPv4 */
  AT_IPv6,               /* IPv6 */
  AT_IPX,                /* IPX */
  AT_SNA,                /* SNA */
  AT_ATALK,              /* Appletalk DDP */
  AT_VINES,              /* Banyan Vines */
  AT_OSI,                /* OSI NSAP */
  AT_ARCNET,             /* ARCNET */
  AT_FC,                 /* Fibre Channel */
  AT_SS7PC,              /* SS7 Point Code */
  AT_STRINGZ,            /* null-terminated string */
  AT_EUI64,              /* IEEE EUI-64 */
  AT_URI,                /* URI/URL/URN */
  AT_TIPC,               /* TIPC Address Zone,Subnetwork,Processor */
  AT_IB,                 /* Infiniband GID/LID */
  AT_USB,                /* USB Device address
                          * (0xffffffff represents the host) */
  AT_AX25,               /* AX.25 */
  AT_IEEE_802_15_4_SHORT /* IEEE 802.15.4 16-bit short address */
                         /* (the long addresses are EUI-64's */
} address_type;

typedef struct _address {
  address_type  type;		/* type of address */
  int           hf;		/* the specific field that this addr is */
  int           len;		/* length of address, in bytes */
  const void	*data;		/* pointer to address data */
} address;

#define	SET_ADDRESS(addr, addr_type, addr_len, addr_data) { \
	(addr)->type = (addr_type); \
	(addr)->hf   = -1;          \
	(addr)->len  = (addr_len);  \
	(addr)->data = (addr_data); \
	}

#define	SET_ADDRESS_HF(addr, addr_type, addr_len, addr_data, addr_hf) { \
	(addr)->type = (addr_type); \
	(addr)->hf   = (addr_hf);   \
	(addr)->len  = (addr_len);  \
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

#define SE_COPY_ADDRESS(to, from) { \
	guint8 *SE_COPY_ADDRESS_data; \
	(to)->type = (from)->type; \
	(to)->len = (from)->len; \
	SE_COPY_ADDRESS_data = se_alloc((from)->len); \
	memcpy(SE_COPY_ADDRESS_data, (from)->data, (from)->len); \
	(to)->data = SE_COPY_ADDRESS_data; \
	}

/*
 * Hash an address into a hash value (which must already have been set).
 */
#define ADD_ADDRESS_TO_HASH(hash_val, addr) { \
	const guint8 *ADD_ADDRESS_TO_HASH_data; \
	int ADD_ADDRESS_TO_HASH_index; \
	ADD_ADDRESS_TO_HASH_data = (addr)->data; \
	for (ADD_ADDRESS_TO_HASH_index = 0; \
	     ADD_ADDRESS_TO_HASH_index < (addr)->len; \
	     ADD_ADDRESS_TO_HASH_index++) \
	     hash_val += ADD_ADDRESS_TO_HASH_data[ADD_ADDRESS_TO_HASH_index]; \
	}

/* Types of port numbers Wireshark knows about. */
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
  PT_IDP,		/* XNS IDP sockets */
  PT_TIPC,		/* TIPC PORT */
  PT_USB,		/* USB endpoint 0xffff means the host */
  PT_I2C,
  PT_IBQP		/* Infiniband QP number */
} port_type;

/* Types of circuit IDs Wireshark knows about. */
typedef enum {
  CT_NONE,		/* no circuit type */
  CT_DLCI,		/* Frame Relay DLCI */
  CT_ISDN,		/* ISDN channel number */
  CT_X25,		/* X.25 logical channel number */
  CT_ISUP,		/* ISDN User Part CIC */
  CT_IAX2,		/* IAX2 call id */
  CT_H223,		/* H.223 logical channel number */
  CT_BICC,		/* BICC Circuit identifier */
  CT_DVBCI		/* DVB-CI session number */
  /* Could also have ATM VPI/VCI pairs */
} circuit_type;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ADDRESS_H__ */
