/* addr_resolv.h
 * Definitions for network object lookup
 *
 * $Id$
 *
 * Laurent Deniel <laurent.deniel@free.fr>
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
/* The buffers returned by these functions are all allocated with a 
 * packet lifetime and does not have have to be freed. 
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an se_alloc() buffer.
 */

#ifndef __RESOLV_H__
#define __RESOLV_H__

#include <epan/address.h>

#ifndef MAXNAMELEN
#define MAXNAMELEN  	64	/* max name length (hostname and port name) */
#endif

/*
 * Flag controlling what names to resolve.
 */
ETH_VAR_IMPORT guint32 g_resolv_flags;

/* 32 types are sufficient (as are 640k of RAM) */
/* FIXME: Maybe MANUF/m, IP/i, IP6/6, IPX/x, UDP+TCP/t etc would be
   more useful/consistent */
#define RESOLV_NONE		0x0
#define RESOLV_MAC		0x1
#define RESOLV_NETWORK		0x2
#define RESOLV_TRANSPORT	0x4
#define RESOLV_CONCURRENT	0x8

#define RESOLV_ALL_ADDRS	(RESOLV_MAC|RESOLV_NETWORK|RESOLV_TRANSPORT)
#define RESOLV_ALL		0xFFFFFFFF

/* global variables */

extern gchar *g_ethers_path;
extern gchar *g_ipxnets_path;
extern gchar *g_pethers_path;
extern gchar *g_pipxnets_path;

/* Functions in resolv.c */

/* Set the flags controlling what names to resolve */
extern void resolv_set_flags(guint32 flags);

/*
 * get_udp_port() returns the port name corresponding to that UDP port,
 * or the port number as a string if not found.
 */
extern gchar *get_udp_port(guint port);

/*
 * get_tcp_port() returns the port name corresponding to that TCP port,
 * or the port number as a string if not found.
 */
extern gchar *get_tcp_port(guint port);

/*
 * get_sctp_port() returns the port name corresponding to that SCTP port,
 * or the port number as a string if not found.
 */
extern gchar *get_sctp_port(guint port);

/* get_addr_name takes as input an "address", as defined in address.h */
/* it returns a string that contains: */
/*  - if the address is of a type that can be translated into a name, and the user */
/*    has activated name resolution, the translated name */
/*  - if the address is of type AT_NONE, a pointer to the string "NONE" */
/*  - if the address is of any other type, the result of address_to_str on the argument, */
/*    which should be a string representation for the answer -e.g. "10.10.10.10" for IPv4 */
/*    address 10.10.10.10 */

const gchar *get_addr_name(address *addr);

/* get_addr_name_buf solves an address in the same way as get_addr_name above */
/* The difference is that get_addr_name_buf takes as input a buffer, in which it puts */
/* the result, and a maximum string length -size-. the buffer should be large enough to */
/* contain size characters plus the terminator */

void get_addr_name_buf(address *addr, gchar *buf, guint size);


/*
 * Asynchronous host name lookup initialization, processing, and cleanup
 */

/* host_name_lookup_init fires up an ADNS socket if we're using ADNS */
extern void host_name_lookup_init(void);

/* host_name_lookup_process does ADNS processing in GTK+ timeouts in Ethereal,
   and before processing each packet in Tethereal, if we're using ADNS */
extern gint host_name_lookup_process(gpointer data);

/* host_name_lookup_cleanup cleans up an ADNS socket if we're using ADNS */
extern void host_name_lookup_cleanup(void);

/* get_hostname returns the host name or "%d.%d.%d.%d" if not found */
extern gchar *get_hostname(guint addr);

/* get_hostname6 returns the host name, or numeric addr if not found */
struct e_in6_addr;
const gchar* get_hostname6(struct e_in6_addr *ad);

/* get_ether_name returns the logical name if found in ethers files else
   "<vendor>_%02x:%02x:%02x" if the vendor code is known else
   "%02x:%02x:%02x:%02x:%02x:%02x" */
extern gchar *get_ether_name(const guint8 *addr);

/* get_ether_name returns the logical name if found in ethers files else NULL */
extern gchar *get_ether_name_if_known(const guint8 *addr);

/* get_manuf_name returns the vendor name or "%02x:%02x:%02x" if not known */
extern const gchar *get_manuf_name(const guint8 *addr);

/* get_manuf_name returns the vendor name or NULL if not known */
extern const gchar *get_manuf_name_if_known(const guint8 *addr);

/* get_ipxnet_name returns the logical name if found in an ipxnets file,
 * or a string formatted with "%X" if not */
extern const gchar *get_ipxnet_name(const guint32 addr);

/* returns the ethernet address corresponding to name or NULL if not known */
extern guint8 *get_ether_addr(const gchar *name);

/* returns the ipx network corresponding to name. If name is unknown,
 * 0 is returned and 'known' is set to FALSE. On success, 'known'
 * is set to TRUE. */
guint32 get_ipxnet_addr(const gchar *name, gboolean *known);

/* adds a hostname/IPv4 in the hash table */
extern void add_ipv4_name(guint addr, const gchar *name);

/* adds a hostname/IPv6 in the hash table */
extern void add_ipv6_name(struct e_in6_addr *addr, const gchar *name);

/* add ethernet address / name corresponding to IP address  */
extern void add_ether_byip(guint ip, const guint8 *eth);

/* Translates a string representing the hostname or dotted-decimal IP address
 * into a numeric IP address value, returning TRUE if it succeeds and
 * FALSE if it fails. */
gboolean get_host_ipaddr(const char *host, guint32 *addrp);

/*
 * Translate IPv6 numeric address or FQDN hostname, into binary IPv6 address.
 * Return TRUE if we succeed and set "*addrp" to that numeric IP address;
 * return FALSE if we fail.
 */
gboolean get_host_ipaddr6(const char *host, struct e_in6_addr *addrp);

/*
 * Find out whether a hostname resolves to an ip or ipv6 address
 * Return "ip6" if it is IPv6, "ip" otherwise (including the case
 * that we don't know)
 */
const char* host_ip_af(const char *host);

#endif /* __RESOLV_H__ */
