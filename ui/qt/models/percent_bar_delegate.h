/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PERCENTBARDELEGATE_H
#define PERCENTBARDELEGATE_H

/*
 * @file Percent bar delegate.
 *
 * QStyledItemDelegate subclass that will draw a percentage value and a
 * single-item bar chart for the specified value.
 *
 * This is intended to be used in QTreeWidgets to show percentage values.
 * To use it, first call setItemDelegate:
 *
 *   myTreeWidget()->setItemDelegateForColumn(col_pct_, new PercentBarDelegate());
 *
 * Then, for each QTreeWidgetItem, set a double value using setData:
 *
 *   setData(col_pct_, Qt::UserRole, QVariant::fromValue<double>(packets_ * 100.0 / num_packets));
 *
 * If the item data cannot be converted to a valid double value or if its
 * text string is non-empty then it will be rendered normally (i.e. the
 * percent text and bar will not be drawn). This lets you mix normal and
 * percent bar rendering between rows.
 */

#include <QStyledItemDelegate>

/**
 * @brief Delegate for drawing a percentage bar in an item view.
 */
class PercentBarDelegate : public QStyledItemDelegate
{
public:
    /**
     * @brief Constructs a PercentBarDelegate.
     * @param parent The parent widget.
     */
    PercentBarDelegate(QWidget *parent = 0) : QStyledItemDelegate(parent) { }

    /**
     * @brief Return empty string to ensure QStyledItemDelegate::paint doesn't draw any text.
     * @return An empty string.
     */
    virtual QString displayText(const QVariant &, const QLocale &) const override { return QString(); }

protected:
    /**
     * @brief Renders the percentage bar using the given painter and style option.
     * @param painter The painter to use.
     * @param option The style options for the item.
     * @param index The model index of the item to paint.
     */
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

    /**
     * @brief Returns the size hint for the percentage bar item.
     * @param option The style options for the item.
     * @param index The model index of the item.
     * @return The recommended size.
     */
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override;

};

#endif // PERCENTBARDELEGATE_H
