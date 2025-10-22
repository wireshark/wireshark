/* stratoshark_follow_stream_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "stratoshark_follow_stream_dialog.h"
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>


StratosharkFollowStreamDialog::StratosharkFollowStreamDialog(QWidget &parent, CaptureFile &cf, int proto_id) :
    FollowStreamDialog(parent, cf, proto_id)
{
}

StratosharkFollowStreamDialog::~StratosharkFollowStreamDialog()
{
}

QString StratosharkFollowStreamDialog::labelHint(int pkt)
{
    QString hint;

    if (pkt > 0) {
        hint = tr("Event %1. ").arg(pkt);
    }

    hint += tr("%Ln <span style=\"color: %1; background-color:%2\">reads</span>, ", "", client_packet_count())
        .arg(ColorUtils::fromColorT(prefs.st_client_fg).name(),
            ColorUtils::fromColorT(prefs.st_client_bg).name())
        + tr("%Ln <span style=\"color: %1; background-color:%2\">writes</span>, ", "", server_packet_count())
        .arg(ColorUtils::fromColorT(prefs.st_server_fg).name(),
            ColorUtils::fromColorT(prefs.st_server_bg).name())
        + tr("%Ln turn(s).", "", turns());

    return hint;
}

QString StratosharkFollowStreamDialog::serverToClientString() const
{
    return tr("Read activity(%6)")
        .arg(gchar_free_to_qstring(format_size(
            followInfo().bytes_written[0],
            FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));

}

QString StratosharkFollowStreamDialog::clientToServerString() const
{
    return tr("Write activity(%6)")
        .arg(gchar_free_to_qstring(format_size(
            followInfo().bytes_written[1],
            FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));

}

QString StratosharkFollowStreamDialog::bothDirectionsString() const
{
    return tr("Entire I/O activity (%1)")
        .arg(gchar_free_to_qstring(format_size(
            followInfo().bytes_written[0] + followInfo().bytes_written[1],
            FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));

}
