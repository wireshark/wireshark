/* packet-dns.h
 * Definitions for packet disassembly structures and routines used both by
 * DNS and NBNS.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __PACKET_DNS_H__
#define __PACKET_DNS_H__

extern const value_string dns_classes[];

/* Just like expand_dns_name, but pretty-prints empty names. */
int get_dns_name(tvbuff_t *, int, int, int, const gchar **, gint*);

#define MAX_DNAME_LEN   255             /* maximum domain name length */

#endif /* packet-dns.h */
