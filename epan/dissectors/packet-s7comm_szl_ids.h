/* packet-s7comm_szl_ids.h
 *
 * Author:      Thomas Wiens, 2014 (th.wiens@gmx.de)
 * Description: Wireshark dissector for S7-Communication
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_S7COMM_SZL_IDS_H__
#define __PACKET_S7COMM_SZL_IDS_H__

guint32 s7comm_decode_ud_cpu_szl_subfunc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *data_tree, guint8 type, guint8 ret_val, guint32 dlength, guint32 offset);
void s7comm_register_szl_types(int proto);

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
