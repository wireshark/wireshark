/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Plots feature by Giovanni Musto <giovanni.musto@italdesign.it>
 * Copyright (c) 2025-2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLOT_ACTION_H
#define PLOT_ACTION_H

#include <ui/qt/utils/field_information.h>

#include <QAction>

/**
 * @brief An action for triggering a plot generation based on a specific field.
 */
class PlotAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new PlotAction object.
     * @param parent The parent object.
     * @param y_field The Y-axis field to plot.
     * @param filtered True if the plot should use filtered data, false otherwise.
     */
    explicit PlotAction(QObject* parent, const QString& y_field, bool filtered);

    /**
     * @brief Creates a menu containing plot actions for a given field.
     * @param headerinfo The header information of the field.
     * @param parent The parent widget for the menu.
     * @return A pointer to the created QMenu.
     */
    static QMenu* createMenu(const FieldInformation::HeaderInfo& headerinfo, QWidget* parent);

signals:
    /**
     * @brief Signal emitted to open the plot dialog.
     * @param y_field The Y-axis field to plot.
     * @param filtered True if the plot should use filtered data.
     */
    void openPlotDialog(const QString& y_field, bool filtered);

private:
    /** @brief The Y-axis field to be plotted. */
    QString y_field_;

    /** @brief Flag indicating whether the plot is filtered. */
    bool    filtered_;
};

#endif // PLOT_ACTION_H
