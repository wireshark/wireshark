/** @file
 *
 * QCustomPlot QCPAbstractLegendItem subclass containing a string.
 * This is used to add a title to a QCPLegend.
 *
 * This file is from https://www.qcustomplot.com/index.php/support/forum/443
 * where the author David said "I thought I would share in case any one else
 * is needing the same functionality." Accordingly, this file is in the
 * public domain.
 */

#include <ui/qt/widgets/qcp_string_legend_item.h>

QCPStringLegendItem::QCPStringLegendItem(QCPLegend *pParent, const QString& strText)
    : QCPAbstractLegendItem(pParent)
    , m_strText(strText)
{
}

QString QCPStringLegendItem::text() const
{
    return m_strText;
}

void QCPStringLegendItem::setText(const QString& strText)
{
    m_strText = strText;
}

void QCPStringLegendItem::draw(QCPPainter *pPainter)
{
    pPainter->setFont(mFont);
    pPainter->setPen(QPen(mTextColor));
    QRectF textRect = pPainter->fontMetrics().boundingRect(0, 0, 0, 0, Qt::TextDontClip, m_strText);
    pPainter->drawText(mRect.x() + mMargins.left(), mRect.y(), textRect.width(), textRect.height(), Qt::TextDontClip | Qt::AlignHCenter, m_strText);
}

QSize QCPStringLegendItem::minimumOuterSizeHint() const
{
    QSize cSize(0, 0);
    QFontMetrics fontMetrics(mFont);
    QRect textRect = fontMetrics.boundingRect(0, 0, 0, 0, Qt::TextDontClip, m_strText);
    cSize.setWidth(textRect.width() + mMargins.left() + mMargins.right());
    cSize.setHeight(textRect.height() + mMargins.top() + mMargins.bottom());
    return cSize;
}
