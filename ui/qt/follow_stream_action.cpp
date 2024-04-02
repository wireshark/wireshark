/* follow_stream_action.cpp
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
#include "follow_stream_action.h"

#include <QMenu>

#include <ui/qt/utils/qt_ui_utils.h>

FollowStreamAction::FollowStreamAction(QObject *parent, register_follow_t *follow) :
    QAction(parent),
    follow_(follow)
{
    if (follow_) {
          setText(QString(tr("%1 Stream").arg(proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follow))))));
    }
}
