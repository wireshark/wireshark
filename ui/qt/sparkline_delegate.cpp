/* sparkline_delegate.cpp
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

#define SPARKLINE_MIN_EM_WIDTH 10

void SparkLineDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{
    QList<int> *points = qvariant_cast<QList<int> *>(index.data(Qt::UserRole));
    int max = 1;
    int em_w = option.fontMetrics.height();
    int content_w = option.rect.width() - (em_w / 4);
    int content_h = option.fontMetrics.ascent() - 1;
    int val;
    qreal idx = 0.0;
    qreal step_w = em_w / 10.0;
    qreal steps = content_w / step_w;
    QVector<QPointF> fpoints;

    QStyledItemDelegate::paint(painter, option, index);

    if (!points || points->isEmpty() || steps < 1.0 || content_h <= 0) {
        return;
    }

    while((qreal) points->length() > steps) {
        points->removeFirst();
    }

    foreach (val, *points) {
        if (val > max) max = val;
    }

    foreach (val, *points) {
        fpoints.append(QPointF(idx, (qreal) content_h - (val * content_h / max) ));
        idx = idx + step_w;
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
    painter->translate(
                option.rect.x() + (em_w / 8) + 0.5,
                option.rect.y() + ((option.rect.height() - option.fontMetrics.height()) / 2) + 1 + 0.5);
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
    return QSize(option.fontMetrics.height() * SPARKLINE_MIN_EM_WIDTH, QStyledItemDelegate::sizeHint(option, index).height());
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
