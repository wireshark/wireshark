/* packet-netbios.h
 * Declarations of public routines for NetBIOS protocol packet disassembly
 * Jeff Foster <foste@woodward.com>
 * Copyright 1999 Jeffrey C. Foster
 *
 * derived from the packet-nbns.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NETBIOS_H__
#define __PACKET_NETBIOS_H__

/* Length of NetBIOS names */
#define NETBIOS_NAME_LEN	16

extern int process_netbios_name(const unsigned char *name_ptr, char *name_ret, int name_ret_len);
extern int get_netbios_name(tvbuff_t *tvb, int offset,
    char *name_ret, int name_ret_len);
extern const char *netbios_name_type_descr(int name_type);
extern void netbios_add_name( const char* label, tvbuff_t *tvb, int offset,
    proto_tree *tree);

#endif
