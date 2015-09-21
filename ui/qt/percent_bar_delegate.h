/* percent_bar_delegate.h
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
