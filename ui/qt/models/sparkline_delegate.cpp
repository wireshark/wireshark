/* sparkline_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/sparkline_delegate.h>

#include <ui/qt/utils/theme_manager.h>

#include <QApplication>
#include <QPainter>
#include <QPen>

#define SPARKLINE_MIN_EM_WIDTH 10

namespace {
// Builds the polyline segments for one spark series. A negative entry is a gap
// marker: it ends the current segment and records a bridge line from the point
// before the gap to the first point after it (so the caller can draw a dashed
// bridge rather than a solid line across an unsampled interval).
void buildSparkSegments(const QList<int> &series, qreal step_w, qreal gap_w, qreal content_h, int max,
                        QVector<QPolygonF> &segments, QVector<QLineF> &bridges)
{
    qreal x = 0.0;
    QPolygonF current;
    QPointF beforeGap;
    bool gapOpen = false;
    bool haveBeforeGap = false;

    for (int val : series) {
        if (val < 0) { // gap marker — render wider than one step so it reads as a gap
            if (!current.isEmpty()) {
                beforeGap = current.last();
                haveBeforeGap = true;
                segments.append(current);
                current.clear();
            }
            gapOpen = true;
            x += gap_w;
            continue;
        }

        const QPointF p(x, content_h - (qreal(val) * content_h / max));
        if (gapOpen && haveBeforeGap) {
            bridges.append(QLineF(beforeGap, p));
            gapOpen = false;
        }
        current.append(p);
        x += step_w;
    }
    if (!current.isEmpty())
        segments.append(current);
}
} // namespace

void SparkLineDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{
    QList<int> points = qvariant_cast<QList<int> >(index.data(Qt::UserRole));
    QList<int> dropped = qvariant_cast<QList<int> >(index.data(SecondaryPointsRole));
    int max = 1;
    // We typically draw a sparkline alongside some text. Size our
    // drawing area based on an Em width. and a bit of eyeballing on
    // Linux, macOS, and Windows.
    int em_w = option.fontMetrics.height();
    int content_w = option.rect.width() - (em_w / 4);
    int content_h = option.fontMetrics.ascent() - 1;
    qreal step_w = em_w / 10.0;
    qreal steps = content_w / step_w;
    // An unsampled gap is drawn several steps wide (and at least ~half an em) so
    // the dashed bridge is clearly readable as a gap rather than a single notch.
    qreal gap_w = qMax(qreal(em_w) * 0.6, step_w * 4.0);

    QStyledItemDelegate::paint(painter, option, index);

    if (points.isEmpty() || steps < 1.0 || content_h <= 0) {
        return;
    }

    // Trim from the front; keep the optional second series aligned in lockstep.
    while ((qreal) points.length() > steps) {
        points.removeFirst();
        if (!dropped.isEmpty())
            dropped.removeFirst();
    }

    // Shared scale across both series; gap markers (negative) don't count.
    // Also note whether any actual drops are visible: the dropped line is only
    // worth drawing when there is at least one non-zero drop in view.
    bool dropsPresent = false;
    for (int val : points)
        if (val > max) max = val;
    for (int val : dropped) {
        if (val > max) max = val;
        if (val > 0) dropsPresent = true;
    }

    QVector<QPolygonF> primarySegments;
    QVector<QLineF> primaryBridges;
    buildSparkSegments(points, step_w, gap_w, content_h, max, primarySegments, primaryBridges);

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

    QColor lineColor;
#if defined(Q_OS_WIN)
    const bool useHighlight = (option_vi.state & QStyle::State_Selected);
#else
    const bool useHighlight = (option_vi.state & QStyle::State_Selected)
                              && !(option_vi.state & QStyle::State_MouseOver);
#endif
    lineColor = useHighlight ? option_vi.palette.color(cg, QPalette::HighlightedText)
                             : option_vi.palette.color(cg, QPalette::Text);

    // As a general rule, aliased painting renders to pixels and
    // antialiased painting renders to mathematical coordinates:
    // https://doc.qt.io/qt-5/coordsys.html
    // Shift our coordinates by 0.5 pixels, otherwise our lines end
    // up blurry.
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->translate(
                option.rect.x() + (em_w / 8) + 0.5,
                option.rect.y() + ((option.rect.height() - option.fontMetrics.height()) / 2) + 1 + 0.5);

    // Dashed bridges spanning unsampled gaps, in a muted theme color, under the
    // lines so the data lines read on top.
    if (!primaryBridges.isEmpty()) {
        // On a highlighted row a muted grey bridge reads as stray dots against
        // the selection color, so match the (highlight) line color there; keep
        // the muted theme color for normal rows.
        QColor gapColor = useHighlight ? lineColor
                                       : ThemeManager::instance()->color(ThemeManager::PaletteMid);
        QPen gapPen(gapColor);
        gapPen.setStyle(Qt::DashLine);
        painter->setPen(gapPen);
        for (const QLineF &bridge : primaryBridges)
            painter->drawLine(bridge);
    }

    // Primary (received) line, in the cell's text color.
    painter->setPen(lineColor);
    for (const QPolygonF &segment : primarySegments)
        painter->drawPolyline(segment);

    // Optional secondary (dropped) line: drawn only when drops are actually
    // present in view, so an interface that never drops shows just the received
    // line. Same scale, distinct theme color, broken at gaps but without a
    // bridge (a baseline drop line bridging would be meaningless).
    if (dropsPresent) {
        QVector<QPolygonF> dropSegments;
        QVector<QLineF> dropBridges; // collected but not drawn
        buildSparkSegments(dropped, step_w, gap_w, content_h, max, dropSegments, dropBridges);
        painter->setPen(ThemeManager::instance()->color(ThemeManager::AccentWarning));
        for (const QPolygonF &segment : dropSegments)
            painter->drawPolyline(segment);
    }

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
