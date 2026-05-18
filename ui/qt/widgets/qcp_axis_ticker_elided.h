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

/**
 * @brief QCPAxisTickerText specialisation that elides tick labels to fit
 *        within the available axis space, preventing text overflow on
 *        crowded or narrow axes.
 */
class QCPAxisTickerElided : public QCPAxisTickerText
{
public:
    /**
     * @brief Constructs a QCPAxisTickerElided bound to the given axis.
     * @param parent The QCPAxis whose tick labels this ticker will generate and elide.
     */
    explicit QCPAxisTickerElided(QCPAxis *parent);

    /**
     * @brief Converts a QCPAxis AxisType to its corresponding QCP::MarginSide.
     *
     * QCustomPlot provides QCP::marginSideToAxisType() but not the inverse;
     * this utility fills that gap.
     *
     * @param axisType The axis type to convert (Left, Right, Top, or Bottom).
     * @return The QCP::MarginSide that corresponds to @p axisType.
     */
    static QCP::MarginSide axisTypeToMarginSide(const QCPAxis::AxisType axisType);

    /**
     * @brief Returns @p text elided to fit within the available tick-label width
     *        of the parent axis, appending an ellipsis if truncation is needed.
     * @param text The full label string to elide.
     * @return The elided string, or @p text unchanged if it already fits.
     */
    QString elidedText(const QString &text);

protected:
    /**
     * @brief Returns the (possibly elided) label string for the tick at @p tick.
     *
     * Overrides QCPAxisTickerText to apply elision before the label is rendered.
     *
     * @param tick       Axis coordinate of the tick being labelled.
     * @param locale     Locale used for number formatting.
     * @param formatChar printf-style format character for numeric ticks.
     * @param precision  Number of decimal places for numeric tick labels.
     * @return Elided tick label string.
     */
    virtual QString getTickLabel(double tick, const QLocale &locale, QChar formatChar, int precision) override;

private:
    QCPAxis *mParent; /**< The axis this ticker is attached to; used to determine available label width. */
};

#endif
