/* packet-s7comm_szl_ids.h
 *
 * Author:      Thomas Wiens, 2014 (th.wiens@gmx.de)
 * Description: Wireshark dissector for S7-Communication
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_S7COMM_SZL_IDS_H__
#define __PACKET_S7COMM_SZL_IDS_H__

guint32 s7comm_decode_ud_cpu_szl_subfunc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *data_tree, guint8 type, guint8 ret_val, guint16 len, guint16 dlength, guint8 data_unit_ref, guint8 last_data_unit, guint32 offset);
void s7comm_register_szl_types(int proto);

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
