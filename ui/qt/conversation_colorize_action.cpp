/* conversation_colorize_action.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "conversation_colorize_action.h"

#include <config.h>

#include <glib.h>

#include "epan/conversation_filter.h"

#include <QMenu>

#include <ui/qt/utils/qt_ui_utils.h>

ConversationAction::ConversationAction(QObject *parent, conversation_filter_s *conv_filter) :
    QAction(parent),
    color_number_(-1)
{
    conv_filter_ = conv_filter;
    if (conv_filter_) {
        setText(conv_filter_->display_name);
    }
}

void ConversationAction::setPacketInfo(struct _packet_info *pinfo)
{
    bool enable = false;
    if (conv_filter_ && pinfo) {
        enable = conv_filter_->is_filter_valid(pinfo);
        if (enable) {
            filter_ba_ = gchar_free_to_qbytearray(conv_filter_->build_filter_string(pinfo));
        }
    }
    setEnabled(enable);

    // If we're the "New Coloring Rule" item, enable or disable our parent menu.
    QMenu *parent_submenu = qobject_cast<QMenu *>(parentWidget());
    if (color_number_ < 0 || !parent_submenu) return;
    parent_submenu->setEnabled(enable);
}

void ConversationAction::setFieldFilter(const QByteArray field_filter)
{
    filter_ba_ = field_filter;
    setEnabled(!filter_ba_.isEmpty());
}

bool ConversationAction::isFilterValid(struct _packet_info *pinfo)
{
    bool valid = false;
    if (conv_filter_ && pinfo) {
        valid = conv_filter_->is_filter_valid(pinfo);
    }
    return valid;
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
