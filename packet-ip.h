/* packet-ip.h
 * Definitions for IP packet disassembly structures and routines
 *
 * $Id: packet-ip.h,v 1.2 1999/03/28 18:31:59 gram Exp $
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


#ifndef __PACKET_IP_H__
#define __PACKET_IP_H__

#define IP_PROTO_ICMP  1
#define IP_PROTO_IGMP  2
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP  17
#define IP_PROTO_OSPF 89

#define IP_PROTO_IP		0		/* dummy for IP */
#define IP_PROTO_HOPOPTS	0		/* IP6 hop-by-hop options */
#define IP_PROTO_ICMP		1		/* control message protocol */
#define IP_PROTO_IGMP		2		/* group mgmt protocol */
#define IP_PROTO_GGP		3		/* gateway^2 (deprecated) */
#define IP_PROTO_IPIP		4		/* IP inside IP */
#define IP_PROTO_IPV4		4		/* IP header */
#define IP_PROTO_TCP		6		/* tcp */
#define IP_PROTO_EGP		8		/* exterior gateway protocol */
#define IP_PROTO_PUP		12		/* pup */
#define IP_PROTO_UDP		17		/* user datagram protocol */
#define IP_PROTO_IDP		22		/* xns idp */
#define IP_PROTO_TP		29 		/* tp-4 w/ class negotiation */
#define IP_PROTO_IPV6		41		/* IP6 header */
#define IP_PROTO_ROUTING	43		/* IP6 routing header */
#define IP_PROTO_FRAGMENT	44		/* IP6 fragmentation header */
#define IP_PROTO_ESP		50		/* ESP */
#define IP_PROTO_AH		51		/* AH */
#define IP_PROTO_ICMPV6		58		/* ICMP6 */
#define IP_PROTO_NONE		59		/* IP6 no next header */
#define IP_PROTO_DSTOPTS	60		/* IP6 no next header */
#define IP_PROTO_EON		80		/* ISO cnlp */
#define IP_PROTO_OSPF		89
#define IP_PROTO_ENCAP		98		/* encapsulation header */
#define IP_PROTO_PIM		103		/* Protocol Independent Mcast */

typedef enum {
  NO_LENGTH,		/* option has no data, hence no length */
  FIXED_LENGTH,		/* option always has the same length */
  VARIABLE_LENGTH	/* option is variable-length - optlen is minimum */
} opt_len_type;

/* Member of table of IP or TCP options. */
typedef struct {
  int   optcode;	/* code for option */
  char *name;		/* name of option */
  opt_len_type len_type; /* type of option length field */
  int	optlen;		/* value length should be (minimum if VARIABLE) */
  void	(*dissect)(proto_tree *, const char *, const u_char *, int, guint);
			/* routine to dissect option */
} ip_tcp_opt;

/* Routine to dissect IP or TCP options. */
void       dissect_ip_tcp_options(proto_tree *, const u_char *, int, guint,
    ip_tcp_opt *, int, int);

#endif
