/* packet-ip.h
 * Definitions for IP packet disassembly structures and routines
 *
 * $Id: packet-ip.h,v 1.1 1999/03/23 03:14:38 gram Exp $
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
