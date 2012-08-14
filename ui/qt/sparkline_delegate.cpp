/* sparkline_delegate.cpp
 *
 * $Id$
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

#include "sparkline_delegate.h"

#include <QPainter>
#include <QApplication>

#define MIN_WIDTH 10

// XXX - Should we use a style sheet for this?
#define SL_MARGIN 2

void SparkLineDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{
    QList<int> *points = qvariant_cast<QList<int> *>(index.data(Qt::UserRole));
    int max = 1;
    int content_w = option.rect.width() - (SL_MARGIN * 2);
    int content_h = option.rect.height() - (SL_MARGIN * 2);
    int val;
    qreal idx = 0.0;
    QVector<QPointF> fpoints;

    QStyledItemDelegate::paint(painter, option, index);

    if (!points || points->isEmpty() || content_w <= 0 || content_h <= 0) {
        return;
    }

    while(points->length() > content_w) {
        points->removeFirst();
    }

    foreach (val, *points) {
        if (val > max) max = val;
    }

    foreach (val, *points) {
        fpoints.append(QPointF(idx, (qreal) content_h - (val * content_h / max) ));
        idx = idx + 1;
    }

    QStyleOptionViewItemV4 optv4 = option;
    QStyledItemDelegate::initStyleOption(&optv4, index);

    painter->save();

    if (QApplication::style()->objectName().contains("vista")) {
        // QWindowsVistaStyle::drawControl does this internally. Unfortunately there
        // doesn't appear to be a more general way to do this.
        optv4.palette.setColor(QPalette::All, QPalette::HighlightedText, optv4.palette.color(QPalette::Active, QPalette::Text));
    }

    QPalette::ColorGroup cg = optv4.state & QStyle::State_Enabled
                              ? QPalette::Normal : QPalette::Disabled;
    if (cg == QPalette::Normal && !(optv4.state & QStyle::State_Active))
        cg = QPalette::Inactive;
    if (optv4.state & QStyle::State_Selected) {
        painter->setPen(optv4.palette.color(cg, QPalette::HighlightedText));
    } else {
        painter->setPen(optv4.palette.color(cg, QPalette::Text));
    }

    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->translate(option.rect.x() + SL_MARGIN + 0.5, option.rect.y() + SL_MARGIN + 0.5);
    painter->drawPolyline(QPolygonF(fpoints));

//    painter->setPen(Qt::NoPen);
//    painter->setBrush(option.palette.foreground());
//    painter->drawEllipse(fpoints.first(), 2, 2);

//    painter->setBrush(Qt::red);
//    painter->drawEllipse(fpoints.last(), 2, 2);

    painter->restore();
}

QSize SparkLineDelegate::sizeHint(const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const {
    return QSize(MIN_WIDTH, QStyledItemDelegate::sizeHint(option, index).height());
}
