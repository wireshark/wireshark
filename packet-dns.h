/* packet-dns.h
 * Definitions for packet disassembly structures and routines used both by
 * DNS and NBNS.
 *
 * $Id: packet-dns.h,v 1.5 2000/02/15 21:02:06 gram Exp $
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


#ifndef __PACKET_DNS_H__
#define __PACKET_DNS_H__

char *dns_class_name(int class);

int get_dns_name(const u_char *pd, int offset, int dns_data_offset,
    char *name, int maxname);

#define MAXDNAME        1025            /* maximum domain name length */

proto_tree *
add_rr_to_tree(proto_item *trr, int rr_type, int offset, const char *name,
  int namelen, const char *type_name, const char *class_name, u_int ttl,
  u_short data_len);

void dissect_dns(const u_char *, int, frame_data *, proto_tree *);

#endif /* packet-dns.h */
