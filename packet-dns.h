/* packet-dns.h
 * Definitions for packet disassembly structures and routines used both by
 * DNS and NBNS.
 *
 * $Id: packet-dns.h,v 1.11 2001/07/02 07:17:29 guy Exp $
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


#ifndef __PACKET_DNS_H__
#define __PACKET_DNS_H__

char *dns_class_name(int class);

int get_dns_name(tvbuff_t *, int, int, char *, int);

#define MAXDNAME        1025            /* maximum domain name length */

proto_tree *
add_rr_to_tree(proto_item *, int, tvbuff_t *, int, const char *,
  int, const char *, const char *, u_int, u_short);

#endif /* packet-dns.h */
