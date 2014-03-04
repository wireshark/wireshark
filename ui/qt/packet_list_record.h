/* packet_list_record.h
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

#ifndef PACKET_LIST_RECORD_H
#define PACKET_LIST_RECORD_H

#include "config.h"

#include <glib.h>

#include <epan/column-info.h>
#include <epan/packet.h>

#include <QList>
#include <QVariant>

class PacketListRecord
{
public:
    PacketListRecord(frame_data *frameData);
    QVariant data(int col_num, column_info *cinfo) const;
    frame_data *getFdata();

private:
    /** The column text for some columns */
    //gchar **col_text_;
    /**< The length of the column text strings in 'col_text' */
    //guint *col_text_len_;

    frame_data *fdata_;

    /** Has this record been columnized? */
    //gboolean columnized_;
    /** Has this record been colorized? */
    //gboolean colorized_;

    /* admin stuff used by the custom list model */
    /** position within the physical array */
    //guint physical_pos_;
    /** position within the visible array */
    //gint visible_pos_;

};

#endif // PACKET_LIST_RECORD_H

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
