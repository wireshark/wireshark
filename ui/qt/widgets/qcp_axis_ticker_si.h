/** @file
 *
 * QCustomPlot QCPAxisTicker subclass that creates human-readable
 * SI unit labels, optionally supporting log scale.
 *
 * Copyright 2024 John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QCP_AXIS_TICKER_SI_H
#define QCP_AXIS_TICKER_SI_H

#include <ui/qt/widgets/qcustomplot.h>

#include <wsutil/str_util.h>

/**
 * @brief QCPAxisTickerLog specialisation that formats tick labels using SI
 *        (metric) prefixes and Wireshark size/packet units, with optional
 *        logarithmic tick placement.
 */
class QCPAxisTickerSi : public QCPAxisTickerLog
{
public:
    /**
     * @brief Constructs a QCPAxisTickerSi.
     * @param unit       The unit system to use for label formatting (default: packets).
     * @param customUnit Optional custom unit suffix string; used when @p unit is
     *                   FORMAT_SIZE_UNIT_CUSTOM.
     * @param log        @c true to use logarithmic tick spacing; @c false for linear.
     */
    explicit QCPAxisTickerSi(format_size_units_e unit = FORMAT_SIZE_UNIT_PACKETS, QString customUnit = QString(), bool log = false);

    /**
     * @brief Returns the current unit system used for label formatting.
     * @return The active format_size_units_e value.
     */
    format_size_units_e getUnit() const { return mUnit; }

    /**
     * @brief Sets the unit system used for label formatting and invalidates cached ticks.
     * @param unit The format_size_units_e value to apply.
     */
    void setUnit(format_size_units_e unit);

    /**
     * @brief Sets a custom unit suffix used when the unit is FORMAT_SIZE_UNIT_CUSTOM.
     * @param unit Custom unit string to append to tick labels.
     */
    void setCustomUnit(QString unit);

    /**
     * @brief Enables or disables logarithmic tick spacing.
     * @param log @c true for logarithmic spacing; @c false for linear spacing.
     */
    void setLog(bool log);

protected:
    /**
     * @brief Returns the SI-prefixed, unit-annotated label for the tick at @p tick.
     * @param tick       Axis coordinate of the tick to label.
     * @param locale     Locale used for number formatting.
     * @param formatChar printf-style format character for numeric values.
     * @param precision  Number of significant digits for the formatted value.
     * @return Formatted tick label string (e.g. "1.2 MB", "500 pkts").
     */
    virtual QString getTickLabel(double tick, const QLocale &locale, QChar formatChar, int precision) override;

    /**
     * @brief Returns the number of sub-ticks to place between two major ticks.
     *
     * Adjusts sub-tick count based on whether logarithmic or linear spacing
     * is active and the magnitude of @p tickStep.
     *
     * @param tickStep Distance between two adjacent major ticks in axis coordinates.
     * @return Number of sub-tick intervals between each pair of major ticks.
     */
    virtual int getSubTickCount(double tickStep) override;

    /**
     * @brief Generates the vector of major tick positions for the given range.
     *
     * Delegates to the logarithmic or linear strategy depending on @c mLog,
     * then rounds positions to clean SI-prefix boundaries where possible.
     *
     * @param tickStep Ideal distance between ticks as computed by the base class.
     * @param range    Visible axis range for which ticks are needed.
     * @return Ordered vector of major tick positions in axis coordinates.
     */
    virtual QVector<double> createTickVector(double tickStep, const QCPRange &range) override;

    format_size_units_e mUnit;       /**< Unit system applied to tick label formatting. */
    QString             mCustomUnit; /**< Custom unit suffix, active when mUnit is FORMAT_SIZE_UNIT_CUSTOM. */
    bool                mLog;        /**< @c true when logarithmic tick spacing is enabled. */
};

#endif
