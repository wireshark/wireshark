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

/*
 * Expands DNS name from TVB into a byte string.
 *
 * Returns int: byte size of DNS data.
 * Returns char *name: a dot (.) separated raw string of DNS domain name labels.
 * This string is null terminated. Labels are copied directly from raw packet
 * data without any validation for a string encoding. This is the callers responsibility.
 * Return int name_len: byte length of "name".
 */
int get_dns_name(tvbuff_t *tvb, int offset, int max_len, int dns_data_offset,
    const char **name, int* name_len);

#define MAX_DNAME_LEN   255             /* maximum domain name length */

#endif /* packet-dns.h */
