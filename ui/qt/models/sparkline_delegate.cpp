/* sparkline_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/sparkline_delegate.h>

#include <QPainter>
#include <QApplication>

#define SPARKLINE_MIN_EM_WIDTH 10

void SparkLineDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{
    QList<int> points = qvariant_cast<QList<int> >(index.data(Qt::UserRole));
    int max = 1;
    // We typically draw a sparkline alongside some text. Size our
    // drawing area based on an Em width. and a bit of eyballing on
    // Linux, macOS, and Windows.
    int em_w = option.fontMetrics.height();
    int content_w = option.rect.width() - (em_w / 4);
    int content_h = option.fontMetrics.ascent() - 1;
    int val;
    qreal idx = 0.0;
    qreal step_w = em_w / 10.0;
    qreal steps = content_w / step_w;
    QVector<QPointF> fpoints;

    QStyledItemDelegate::paint(painter, option, index);

    if (points.isEmpty() || steps < 1.0 || content_h <= 0) {
        return;
    }

    while ((qreal) points.length() > steps) {
        points.removeFirst();
    }

    foreach (val, points) {
        if (val > max) max = val;
    }

    foreach (val, points) {
        fpoints.append(QPointF(idx, (qreal) content_h - (val * content_h / max)));
        idx = idx + step_w;
    }

    QStyleOptionViewItem option_vi = option;
    QStyledItemDelegate::initStyleOption(&option_vi, index);

    painter->save();

    if (QApplication::style()->objectName().contains("vista")) {
        // QWindowsVistaStyle::drawControl does this internally. Unfortunately there
        // doesn't appear to be a more general way to do this.
        option_vi.palette.setColor(QPalette::All, QPalette::HighlightedText, option_vi.palette.color(QPalette::Active, QPalette::Text));
    }

    QPalette::ColorGroup cg = option_vi.state & QStyle::State_Enabled
                              ? QPalette::Normal : QPalette::Disabled;
    if (cg == QPalette::Normal && !(option_vi.state & QStyle::State_Active))
        cg = QPalette::Inactive;
#if defined(Q_OS_WIN)
    if (option_vi.state & QStyle::State_Selected) {
#else
    if ((option_vi.state & QStyle::State_Selected) && !(option_vi.state & QStyle::State_MouseOver)) {
#endif
        painter->setPen(option_vi.palette.color(cg, QPalette::HighlightedText));
    } else {
        painter->setPen(option_vi.palette.color(cg, QPalette::Text));
    }

    // As a general rule, aliased painting renders to pixels and
    // antialiased painting renders to mathematical coordinates:
    // https://doc.qt.io/qt-5/coordsys.html
    // Shift our coordinates by 0.5 pixels, otherwise our lines end
    // up blurry.
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->translate(
                option.rect.x() + (em_w / 8) + 0.5,
                option.rect.y() + ((option.rect.height() - option.fontMetrics.height()) / 2) + 1 + 0.5);
    painter->drawPolyline(QPolygonF(fpoints));

    // Some sparklines are decorated with dots at the beginning and end.
    // Ours look better without in my (gcc) opinion.
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

QWidget *SparkLineDelegate::createEditor(QWidget *, const QStyleOptionViewItem &, const QModelIndex &) const
{
    return NULL;
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
