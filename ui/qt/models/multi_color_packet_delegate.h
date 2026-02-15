/** @file
 *
 * Header file defining the MultiColorPacketDelegate class
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MULTI_COLOR_PACKET_DELEGATE_H
#define MULTI_COLOR_PACKET_DELEGATE_H

#include <config.h>
#include <QStyledItemDelegate>

class QPainter;

class MultiColorPacketDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    MultiColorPacketDelegate(QWidget *parent = 0);

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

private:
    /** Calculate appropriate foreground color for readability */
    QColor calculateForeground(const QList<QColor> &backgrounds) const;

    /** Draw multi-color striped background (full row) */
    void drawStripedBackground(QPainter *painter, const QStyleOptionViewItem &option,
                               const QList<QColor> &colors) const;

    /** Draw shift-right background (primary 85%, stripes 15%) */
    void drawShiftRightBackground(QPainter *painter, const QStyleOptionViewItem &option,
                                  const QList<QColor> &colors) const;
};

#endif // MULTI_COLOR_PACKET_DELEGATE_H
