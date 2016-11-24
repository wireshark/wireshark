/* conversation_colorize_action.cpp
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

#include <config.h>

#include <glib.h>
#include <epan/packet_info.h>
#include <epan/proto_data.h>
#include <epan/packet.h>
#include <wsutil/utf8_entities.h>
#include "export_object_action.h"

#include <QMenu>

#include "qt_ui_utils.h"

ExportObjectAction::ExportObjectAction(QObject *parent, register_eo_t *eo) :
    QAction(parent),
    eo_(eo)
{
    if (eo_) {
          setText( QString("%1%2").arg(proto_get_protocol_short_name(find_protocol_by_id(get_eo_proto_id(eo)))).arg(UTF8_HORIZONTAL_ELLIPSIS));
    }
}

void ExportObjectAction::captureFileOpened()
{
    setEnabled(true);
}

void ExportObjectAction::captureFileClosed()
{
    setEnabled(false);
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
