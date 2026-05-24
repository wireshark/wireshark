/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IN_PACKET_FIND_DELEGATE_H
#define IN_PACKET_FIND_DELEGATE_H

#include <QStyledItemDelegate>

class InPacketFindBar;

class InPacketFindDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit InPacketFindDelegate(InPacketFindBar *find_bar, QObject *parent = nullptr);

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

private:
    InPacketFindBar *find_bar_;
};

#endif // IN_PACKET_FIND_DELEGATE_H
