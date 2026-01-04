/* packet-amp.h
 * Routines for Asynchronous management Protocol dissection
 * Copyright 2018, Krishnamurthy Mayya (krishnamurthymayya@gmail.com)
 * Updated to CBOR encoding: Keith Scott, 2019 (kscott@mitre.org)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_AMP_H
#define PACKET_AMP_H

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>

#ifdef __cplusplus
extern "C" {
#endif

void dissect_amp_as_subtree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_AMP_H */

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
