/* @file
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

#include "plot_action.h"

#include <ui/qt/main_application.h>
#include <ui/qt/main_window.h>

#include <QMenu>

PlotAction::PlotAction(QObject* parent, const QString& y_field, bool filtered) :
    QAction(parent),
    y_field_(y_field)
{
    if (filtered) {
        setText(tr("Plot %1 with current filter").arg(y_field_));
    }
    else {
        setText(tr("Plot %1").arg(y_field_));
    }
    connect(this, &QAction::triggered, [&]() { emit openPlotDialog(y_field_, filtered); });
}

QMenu* PlotAction::createMenu(const FieldInformation::HeaderInfo& headerinfo, QWidget* parent)
{
    MainWindow* mw(nullptr);
    if (mainApp) mw = mainApp->mainWindow();

    QString title("Plot");
    QMenu* submenu = new QMenu(title, parent);

    int one_em = submenu->fontMetrics().height();
    QString prep_text = QStringLiteral("%1: %2").arg(title).arg(headerinfo.abbreviation);
    prep_text = submenu->fontMetrics().elidedText(prep_text, Qt::ElideRight, one_em * 40);
    QAction* comment = submenu->addAction(prep_text);
    comment->setEnabled(false);
    submenu->addSeparator();

    /* Without filter */
    PlotAction* graphAction = new PlotAction(submenu, headerinfo.abbreviation, false);
    if (mw) connect(graphAction, &PlotAction::openPlotDialog, mw, &MainWindow::showPlotDialog);
    submenu->addAction(graphAction);

    /* With filter */
    /* XXX - It would be nice here to add the option to the menu only if a filter is
     * actually applied. df_combo_box_ is a protected member, though.
     */
    graphAction = new PlotAction(submenu, headerinfo.abbreviation, true);
    if (mw) connect(graphAction, &PlotAction::openPlotDialog, mw, &MainWindow::showPlotDialog);
    submenu->addAction(graphAction);

    return submenu;
}
