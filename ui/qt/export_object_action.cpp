/* conversation_colorize_action.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet_info.h>
#include <epan/proto_data.h>
#include <epan/packet.h>
#include <wsutil/utf8_entities.h>
#include "export_object_action.h"

#include <QMenu>

#include <ui/qt/utils/qt_ui_utils.h>

ExportObjectAction::ExportObjectAction(QObject *parent, register_eo_t *eo) :
    QAction(parent),
    eo_(eo)
{
    if (eo_) {
          setText(QString("%1%2").arg(proto_get_protocol_short_name(find_protocol_by_id(get_eo_proto_id(eo)))).arg(UTF8_HORIZONTAL_ELLIPSIS));
    }
}

void ExportObjectAction::captureFileEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::File)
    {
        if (e.eventType() == CaptureEvent::Opened)
            setEnabled(true);
        else if (e.eventType() == CaptureEvent::Closed)
            setEnabled(false);
    }
}
