/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_PLOT_DIALOG_H
#define STRATOSHARK_PLOT_DIALOG_H

#include <config.h>
#include "plot_dialog.h"

/**
 * @brief Stratoshark-specific plot dialog that provides system-call-aware defaults for plot fields, axis labels, and hint text.
 */
class StratosharkPlotDialog : public PlotDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the StratosharkPlotDialog.
     * @param parent The parent widget.
     * @param cf The capture file whose data is to be plotted.
     */
    explicit StratosharkPlotDialog(QWidget& parent, CaptureFile& cf);

    /**
     * @brief Destroys the StratosharkPlotDialog.
     */
    virtual ~StratosharkPlotDialog();

    /**
     * @brief Initializes the dialog, optionally populating it with a default plot using Stratoshark-specific event fields.
     * @param parent The parent widget.
     * @param show_default If true, adds a default plot on initialization.
     */
    void initialize(QWidget& parent, bool show_default = true);

protected:
    /**
     * @brief Returns the display filter field name used to identify filtered items.
     * @return The filtered item field name string.
     */
    virtual QString getFilteredName() const override;

    /**
     * @brief Returns the label string for the Y axis.
     * @return The Y axis name.
     */
    virtual QString getYAxisName() const override;

    /**
     * @brief Returns a contextual hint string describing the number of plotted items.
     * @param num_items The number of items currently in the plot.
     * @return A human-readable hint string.
     */
    virtual QString getHintText(unsigned num_items) const override;

    /**
     * @brief Adds the default plot entry for Stratoshark with the given visibility and filter state.
     * @param enabled If true, the plot is enabled/visible.
     * @param filtered If true, the plot applies the current display filter.
     */
    virtual void addDefaultPlot(bool enabled, bool filtered) override;
};

#endif // STRATOSHARK_PLOT_DIALOG_H
