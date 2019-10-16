/* percent_bar_delegate.h
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

class PercentBarDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    PercentBarDelegate(QWidget *parent = 0) : QStyledItemDelegate(parent) { }

    // Make sure QStyledItemDelegate::paint doesn't draw any text.
    virtual QString displayText(const QVariant &, const QLocale &) const { return QString(); }

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const;

};

#endif // PERCENTBARDELEGATE_H

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
