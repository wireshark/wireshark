/* conversation_tree_widget.h
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

#ifndef CONVERSATION_TREE_WIDGET_H
#define CONVERSATION_TREE_WIDGET_H

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/tap.h>

#include "ui/conversation_hash.h"

#include "filter_action.h"

#include <QMenu>
#include <QTreeWidget>

Q_DECLARE_METATYPE(conv_item_t *)

class ConversationTreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    explicit ConversationTreeWidget(QWidget *parent, conversation_type_e conv_type);
    ~ConversationTreeWidget();

    static void tapReset(void *conv_tree_ptr);
    static int tapPacket(void *conv_tree_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *vip);
    static void tapDraw(void *conv_tree_ptr);

    // String, int, or double data for each column in a row.
    // Passing -1 returns titles.
    QList<QVariant> rowData(int row);

    conversation_type_e conversationType() { return conv_type_; }
    // Title string plus optional count
    const QString &conversationTitle() { return title_; }

signals:
    void titleChanged(QWidget *tree, const QString &text);
    void filterAction(QString& filter, FilterAction::Action action, FilterAction::ActionType type);

public slots:
    void setNameResolutionEnabled(bool enable);

protected:
    void contextMenuEvent(QContextMenuEvent *event);

private:
    conversation_type_e conv_type_;
    QString title_;
    conv_hash_t hash_;
    bool resolve_names_;
    QMenu ctx_menu_;

    void initDirectionMap();
    int tapEthernetPacket(packet_info *pinfo, const void *vip);
    int tapFibreChannelPacket(packet_info *pinfo, const void *vip);
    int tapFddiPacket(packet_info *pinfo, const void *vip);
    int tapIPv4Packet(packet_info *pinfo, const void *vip);
    int tapIPv6Packet(packet_info *pinfo, const void *vip);
    int tapIpxPacket(packet_info *pinfo, const void *vip);
    int tapJxtaPacket(packet_info *pinfo, const void *vip);
    int tapNcpPacket(packet_info *pinfo, const void *vip);
    int tapRsvpPacket(packet_info *pinfo, const void *vip);
    int tapSctpPacket(packet_info *pinfo, const void *vip);
    int tapTcpPacket(packet_info *pinfo, const void *vip);
    int tapTokenRingPacket(packet_info *pinfo, const void *vip);
    int tapUdpPacket(packet_info *pinfo, const void *vip);
    int tapUsbPacket(packet_info *pinfo, const void *vip);
    int tapWlanPacket(packet_info *pinfo, const void *vip);

private slots:
    void updateItems();
    void filterActionTriggered();
};

#endif // CONVERSATION_TREE_WIDGET_H

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
