/* resolv.h
 * Definitions for network object lookup
 *
 * $Id: resolv.h,v 1.1 2000/09/28 03:28:54 gram Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __RESOLV_H__
#define __RESOLV_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define EPATH_ETHERS 		"/etc/ethers"
#define EPATH_IPXNETS 		"/etc/ipxnets"
#define EPATH_MANUF  		DATAFILE_DIR "/manuf"
#define EPATH_PERSONAL_ETHERS 	".ethereal/ethers"  /* with "$HOME/" prefix */
#define EPATH_PERSONAL_IPXNETS 	".ethereal/ipxnets" /* with "$HOME/" prefix */

#ifndef MAXNAMELEN
#define MAXNAMELEN  	64	/* max name length (hostname and port name) */
#endif

/* global variables */

extern gchar *g_ethers_path;
extern gchar *g_ipxnets_path;
extern gchar *g_manuf_path;
extern gchar *g_pethers_path;
extern gchar *g_pipxnets_path;

/* Functions in resolv.c */

/* get_tcp_port returns the UDP port name or "%u" if not found */
extern u_char *get_udp_port(u_int port);

/* get_tcp_port returns the TCP port name or "%u" if not found */
extern u_char *get_tcp_port(u_int port);

/* get_sctp_port returns the SCTP port name or "%u" if not found */
extern u_char *get_sctp_port(u_int port);

/* get_hostname returns the host name or "%d.%d.%d.%d" if not found */
extern u_char *get_hostname(u_int addr);

/* get_hostname returns the host name, or numeric addr if not found */
struct e_in6_addr;
gchar* get_hostname6(struct e_in6_addr *ad);

/* get_ether_name returns the logical name if found in ethers files else
   "<vendor>_%02x:%02x:%02x" if the vendor code is known else
   "%02x:%02x:%02x:%02x:%02x:%02x" */
extern u_char *get_ether_name(const u_char *addr);

/* get_ether_name returns the logical name if found in ethers files else NULL */
extern u_char *get_ether_name_if_known(const u_char *addr);

/* get_manuf_name returns the vendor name or "%02x:%02x:%02x" if not known */
extern u_char *get_manuf_name(u_char *addr);

/* get_ipxnet_name returns the logical name if found in an ipxnets file,
 * or a string formatted with "%X" if not */
extern u_char *get_ipxnet_name(const guint32 addr);

/* returns the ethernet address corresponding to name or NULL if not known */
extern u_char *get_ether_addr(u_char *name);

/* returns the ipx network corresponding to name. If name is unknown,
 * 0 is returned and 'known' is set to TRUE. */
guint32 get_ipxnet_addr(u_char *name, gboolean *known);

/* adds a hostname/IP in the hash table */
extern void add_host_name(u_int addr, u_char *name);

/* add ethernet address / name corresponding to IP address  */
extern void add_ether_byip(u_int ip, const u_char *eth);

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

#endif /* __RESOLV_H__ */
