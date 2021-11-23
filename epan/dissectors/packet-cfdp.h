/* packet-cfdp.c
 * Routines for CCSDS File Delivery Protocol (CFDP) dissection
 * Copyright 2013, Juan Antonio Montesinos juan.mondl@gmail.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Slightly updated to allow more in-depth decoding when called
 * with the 'dissect_as_subtree' method and to leverage some
 * of the bitfield display operations: Keith Scott
 * <kscott@mitre.org>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_CFDP_H
#define PACKET_CFDP_H

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>

#ifdef __cplusplus
extern "C" {
#endif

void dissect_cfdp_as_subtree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_CFDP_H */

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
