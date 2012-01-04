/* packet_list_record.h
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

#ifndef PACKET_LIST_RECORD_H
#define PACKET_LIST_RECORD_H

#include "config.h"

#include <glib.h>

#include <epan/column_info.h>
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
    gchar **col_text;
    /**< The length of the column text strings in 'col_text' */
    guint *col_text_len;

    frame_data *fdata;

    /** Has this record been columnized? */
    gboolean columnized;
    /** Has this record been colorized? */
    gboolean colorized;

    /* admin stuff used by the custom list model */
    /** position within the physical array */
    guint physical_pos;
    /** position within the visible array */
    gint visible_pos;

};

#endif // PACKET_LIST_RECORD_H
