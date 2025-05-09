/** @file
 *
 * QCustomPlot QCPAbstractLegendItem subclass representing an empty space.
 * This is used to separate elements in QCPLegend.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/qcustomplot.h>
#include <ui/qt/widgets/qcp_spacer_legend_item.h>

QCPSpacerLegendItem::QCPSpacerLegendItem(QCPLegend* pParent, int size, bool horizontal)
    : QCPAbstractLegendItem(pParent),
    m_size(size),
    m_horiz(horizontal)
{
}

QSize QCPSpacerLegendItem::minimumOuterSizeHint() const
{
    int w = mMargins.left() + mMargins.right();
    int h = mMargins.top() + mMargins.bottom();
    if (m_horiz) {
        w += m_size;
    }
    else {
        h += m_size;
    }
    return QSize(w, h);
}
