/* resolv.h
 * Definitions for network object lookup
 *
 * $Id: resolv.h,v 1.6 1999/09/26 14:39:12 deniel Exp $
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
#define EPATH_MANUF  		DATAFILE_DIR "/manuf"
#define EPATH_PERSONAL_ETHERS 	".ethereal/ethers" /* with "$HOME/" prefix */

/* global variables */

extern gchar *g_ethers_path;
extern gchar *g_manuf_path;
extern gchar *g_pethers_path;

/* Functions in resolv.c */

/* get_tcp_port returns the UDP port name or "%d" if not found */
extern u_char *get_udp_port(u_int port);

/* get_tcp_port returns the TCP port name or "%d" if not found */
extern u_char *get_tcp_port(u_int port);

/* get_hostname returns the host name or "%d.%d.%d.%d" if not found */
extern u_char *get_hostname(u_int addr);

/* get_hostname returns the host name, or numeric addr if not found */
struct e_in6_addr;
gchar* get_hostname6(struct e_in6_addr *ad);

/* get_ether_name returns the logical name if found in ethers files else
   "<vendor>_%02x:%02x:%02x" if the vendor code is known else
   "%02x:%02x:%02x:%02x:%02x:%02x" */
extern u_char *get_ether_name(u_char *addr);

/* get_manuf_name returns the vendor name or "%02x:%02x:%02x" if not known */
extern u_char *get_manuf_name(u_char *addr);

/* returns the ethernet address corresponding to name or NULL if not known */
extern u_char *get_ether_addr(u_char *name);

/* adds a hostname/IP in the hash table */
extern void add_host_name(u_int addr, u_char *name);

/* Returns IP address for a string representing the hostname or dotted-decial IP address */
unsigned long get_host_ipaddr(const char *host);

#endif /* __RESOLV_H__ */
