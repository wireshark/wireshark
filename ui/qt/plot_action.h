/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Plots feature by Giovanni Musto <giovanni.musto@partner.italdesign.it>
 * Copyright (c) 2025
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLOT_ACTION_H
#define PLOT_ACTION_H

#include <ui/qt/utils/field_information.h>

#include <QAction>

class PlotAction : public QAction
{
    Q_OBJECT
public:
    explicit PlotAction(QObject* parent, const QString& y_field, bool filtered);
    static QMenu* createMenu(const FieldInformation::HeaderInfo& headerinfo, QWidget* parent);

signals:
    void openPlotDialog(const QString&, bool);

private:
    QString y_field_;
};

#endif // PLOT_ACTION_H
