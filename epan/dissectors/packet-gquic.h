/* packet-gquic.h
 * Routines for (Google) Quick UDP Internet Connections dissection
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GQUIC_H__
#define __PACKET_GQUIC_H__

int
dissect_gquic_ietf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gquic_tree, guint offset, guint32 version);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
