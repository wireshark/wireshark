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

class QCPAxisTickerSi : public QCPAxisTickerLog
{
public:
    explicit QCPAxisTickerSi(format_size_units_e unit = FORMAT_SIZE_UNIT_PACKETS, QString customUnit = QString(), bool log = false);

    format_size_units_e getUnit() const { return mUnit; }
    void setUnit(format_size_units_e unit);
    void setCustomUnit(QString unit);
    void setLog(bool log);

protected:
    virtual QString getTickLabel(double tick, const QLocale &locale, QChar formatChar, int precision) override;
    virtual int getSubTickCount(double tickStep) override;
    virtual QVector<double> createTickVector(double tickStep, const QCPRange &range) override;

    format_size_units_e mUnit;
    QString mCustomUnit;
    bool mLog;
};

#endif
