/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLOT_THEME_H
#define PLOT_THEME_H

#include <functional>

#include <QColor>

class QCustomPlot;
class QCPAxis;

/**
 * @brief Applies the active theme's palette to a QCustomPlot.
 *
 * QCustomPlot defaults to a white background with black axes, which is
 * unreadable in dark themes.  This helper recolors the background, axes,
 * grids, legend and titles from the theme tokens and keeps them current
 * across theme switches.
 */
class PlotTheme
{
public:
    /**
     * @brief Recolor a plot from the current theme.
     *
     * Pen widths and styles are preserved. Does not replot.
     *
     * @param plot The plot to recolor.
     */
    static void apply(QCustomPlot *plot);

    /**
     * @brief Recolor one axis from the current theme.
     *
     * Recolors the axis' pens, labels, grid, sub-grid and zero line. Use it
     * for axes created after apply() or track() ran. Pen widths and styles
     * are preserved. Null-safe. Does not replot.
     *
     * @param axis The axis to recolor.
     */
    static void applyToAxis(QCPAxis *axis);

    /**
     * @brief Apply the theme now and again whenever the theme changes.
     *
     * Calls apply(), then @p afterApply, then replots, immediately and on
     * every ThemeManager::themeChanged. The connection is bound to the
     * plot's lifetime.
     *
     * @param plot The plot to track.
     * @param afterApply Optional hook for plot-specific colors that must
     *        be reapplied after the generic recoloring.
     */
    static void track(QCustomPlot *plot, std::function<void()> afterApply = nullptr);

    /**
     * @brief The theme's primary text color for plot elements.
     * @return The PaletteText token color.
     */
    static QColor textColor();
};

#endif // PLOT_THEME_H
