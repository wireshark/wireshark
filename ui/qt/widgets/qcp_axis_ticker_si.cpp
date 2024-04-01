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

#include <cmath>

#include <ui/qt/widgets/qcp_axis_ticker_si.h>
#include <ui/qt/utils/qt_ui_utils.h>

#include <wsutil/str_util.h>

QCPAxisTickerSi::QCPAxisTickerSi(format_size_units_e unit, QString customUnit, bool log) :
    mUnit(unit), mCustomUnit(customUnit), mLog(log)
{
}

QString QCPAxisTickerSi::getTickLabel(double tick, const QLocale& , QChar , int precision)
{
    QString label = gchar_free_to_qstring(format_units(nullptr, tick, mUnit, FORMAT_SIZE_PREFIX_SI, precision));

    // XXX - format_units isn't consistent about whether we need to
    // add a space or not
    if (mUnit == FORMAT_SIZE_UNIT_NONE && !mCustomUnit.isEmpty()) {
        label += mCustomUnit;
    }
    // XXX - "Beautiful typeset powers" for exponentials is handled by QCPAxis,
    // not QCPAxisTicker and its subclasses, and its detection of exponentials
    // doesn't handle having a unit or other suffix, so that won't work.
    // In practical use we'll be within our prefix range, though.
    return label;
}

int QCPAxisTickerSi::getSubTickCount(double tickStep)
{
    if (mLog) {
        return QCPAxisTickerLog::getSubTickCount(tickStep);
    } else {
        return QCPAxisTicker::getSubTickCount(tickStep);
    }
}

QVector<double> QCPAxisTickerSi::createTickVector(double tickStep, const QCPRange &range)
{
    if (mLog) {
        return QCPAxisTickerLog::createTickVector(tickStep, range);
    } else {
        return QCPAxisTicker::createTickVector(tickStep, range);
    }
}

void QCPAxisTickerSi::setUnit(format_size_units_e unit)
{
    mUnit = unit;
}

void QCPAxisTickerSi::setCustomUnit(QString unit)
{
    mCustomUnit = unit;
}

void QCPAxisTickerSi::setLog(bool log)
{
    mLog = log;
}
