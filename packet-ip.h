/* packet-ip.h
 * Definitions for IP packet disassembly structures and routines
 *
 * $Id: packet-ip.h,v 1.19 2001/04/23 17:51:33 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

void capture_ip(const u_char *, int, packet_counts *);

typedef enum {
  NO_LENGTH,		/* option has no data, hence no length */
  FIXED_LENGTH,		/* option always has the same length */
  VARIABLE_LENGTH	/* option is variable-length - optlen is minimum */
} opt_len_type;

/* Member of table of IP or TCP options. */
typedef struct ip_tcp_opt {
  int   optcode;	/* code for option */
  char  *name;		/* name of option */
  int   *subtree_index;	/* pointer to subtree index for option */
  opt_len_type len_type; /* type of option length field */
  int	optlen;		/* value length should be (minimum if VARIABLE) */
  void	(*dissect)(const struct ip_tcp_opt *, tvbuff_t *, int, guint,
  		   frame_data *, proto_tree *);
			/* routine to dissect option */
} ip_tcp_opt;

/* Routine to dissect IP or TCP options. */
void       dissect_ip_tcp_options(tvbuff_t *, int, guint,
    const ip_tcp_opt *, int, int, frame_data *, proto_tree *);

/* Dissector table for "ip.proto"; used by IPv6 as well as IPv4 */
extern dissector_table_t ip_dissector_table;

#endif
