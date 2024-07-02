/** @file
 *
 * QCustomPlot QCPAxisTickerText subclass that elides labels to the
 * width of the parent QCPAxis's QCPAxisRect's margin for the appropriate
 * side, for use when the margin is fixed.
 *
 * Copyright 2024 John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/qcp_axis_ticker_elided.h>

#include <QFontMetrics>

QCPAxisTickerElided::QCPAxisTickerElided(QCPAxis *parent) :
    mParent(parent)
{
}

QCP::MarginSide QCPAxisTickerElided::axisTypeToMarginSide(const QCPAxis::AxisType axis)
{
    switch (axis) {
    case QCPAxis::atLeft:
        return QCP::msLeft;
    case QCPAxis::atRight:
        return QCP::msRight;
    case QCPAxis::atTop:
        return QCP::msTop;
    case QCPAxis::atBottom:
        return QCP::msBottom;
    }
    return QCP::msNone;
}

QString QCPAxisTickerElided::elidedText(const QString& text)
{
    QCP::MarginSides autoMargins = mParent->axisRect()->autoMargins();
    if (autoMargins & axisTypeToMarginSide(mParent->axisType())) {
        return text;
    }
    int elide_w;
    QMargins margins = mParent->axisRect()->margins();
    switch (mParent->axisType()) {
    case QCPAxis::atLeft:
        elide_w = margins.left();
        break;
    case QCPAxis::atRight:
        elide_w = margins.right();
        break;
    case QCPAxis::atTop:
        elide_w = margins.top();
        break;
    case QCPAxis::atBottom:
        elide_w = margins.bottom();
        break;
    default:
        // ??
        elide_w = margins.left();
    }

    return QFontMetrics(mParent->tickLabelFont()).elidedText(text,
                                                             Qt::ElideRight,
                                                             elide_w);
}

QString QCPAxisTickerElided::getTickLabel(double tick, const QLocale& , QChar , int)
{
    return elidedText(mTicks.value(tick));
}
