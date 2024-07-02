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

#ifndef QCP_AXIS_TICKER_ELIDED_H
#define QCP_AXIS_TICKER_ELIDED_H

#include <ui/qt/widgets/qcustomplot.h>

class QCPAxisTickerElided : public QCPAxisTickerText
{
public:
    explicit QCPAxisTickerElided(QCPAxis *parent);

    // QCP has marginSideToAxisType but not the inverse
    static QCP::MarginSide axisTypeToMarginSide(const QCPAxis::AxisType);

    QString elidedText(const QString& text);

protected:
    virtual QString getTickLabel(double tick, const QLocale &locale, QChar formatChar, int precision) override;

private:
    QCPAxis *mParent;
};

#endif
