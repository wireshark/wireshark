/* packet_list_record.cpp
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "packet_list_record.h"

PacketListRecord::PacketListRecord(frame_data *frameData)
{
    fdata = frameData;
}

QVariant PacketListRecord::data(int col_num, column_info *cinfo) const
{
    g_assert(fdata);

    if (!cinfo)
        return QVariant();

    if (col_based_on_frame_data(cinfo, col_num)) //{
        col_fill_in_frame_data(fdata, cinfo, col_num, FALSE);
        return cinfo->col_data[col_num];
//    } else {
//        QString unknown;
//        return unknown.sprintf("Unknown: frame %d col %d", fdata->num, col_num);
//    }
}

frame_data *PacketListRecord::getFdata() {
    return fdata;
}
