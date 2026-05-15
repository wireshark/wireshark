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

/**
 * @brief A delegate for rendering multi-colored packet items in a view.
 */
class MultiColorPacketDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new MultiColorPacketDelegate.
     * @param parent The parent widget, defaults to 0.
     */
    MultiColorPacketDelegate(QWidget *parent = 0);

protected:
    /**
     * @brief Renders the item using the given painter and style option.
     * @param painter The painter used to draw the item.
     * @param option The style option specifying how the item should be drawn.
     * @param index The model index of the item to be drawn.
     */
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

private:
    /**
     * @brief Calculate appropriate foreground color for readability.
     * @param backgrounds The list of background colors to contrast against.
     * @return The calculated foreground QColor.
     */
    QColor calculateForeground(const QList<QColor> &backgrounds) const;

    /**
     * @brief Draw multi-color striped background (full row).
     * @param painter The painter used to draw the background.
     * @param option The style option defining the drawing area.
     * @param colors The list of colors to use for the stripes.
     */
    void drawStripedBackground(QPainter *painter, const QStyleOptionViewItem &option,
                               const QList<QColor> &colors) const;

    /**
     * @brief Draw shift-right background (primary 85%, stripes 15%).
     * @param painter The painter used to draw the background.
     * @param option The style option defining the drawing area.
     * @param colors The list of colors to use for the background and stripes.
     */
    void drawShiftRightBackground(QPainter *painter, const QStyleOptionViewItem &option,
                                  const QList<QColor> &colors) const;
};

#endif // MULTI_COLOR_PACKET_DELEGATE_H
