/* packet-bgp.h
 * Routines for BGP packet disassembly
 * (c) Copyright Ebben Aries <exa@fb.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_BGP_H__
#define __PACKET_BGP_H__

const char*
decode_bgp_rd(wmem_allocator_t *pool, tvbuff_t *tvb, int offset);

void
dissect_bgp_path_attr(proto_tree *subtree, tvbuff_t *tvb, uint16_t path_attr_len, unsigned tvb_off, packet_info *pinfo);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
