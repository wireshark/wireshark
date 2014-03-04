/* packet_list_record.cpp
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

#include "packet_list_record.h"

PacketListRecord::PacketListRecord(frame_data *frameData) :
    //col_text_(NULL),
    //col_text_len_(NULL),
    fdata_(frameData)
{
}

QVariant PacketListRecord::data(int col_num, column_info *cinfo) const
{
    g_assert(fdata_);

    if (!cinfo)
        return QVariant();

    if (col_based_on_frame_data(cinfo, col_num))
        col_fill_in_frame_data(fdata_, cinfo, col_num, FALSE);

    return cinfo->col_data[col_num];
}

frame_data *PacketListRecord::getFdata() {
    return fdata_;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
