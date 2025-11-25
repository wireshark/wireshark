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

class StratosharkPlotDialog : public PlotDialog
{
    Q_OBJECT

public:
    explicit StratosharkPlotDialog(QWidget& parent, CaptureFile& cf);
    virtual ~StratosharkPlotDialog();

    // Overloaded to provide default plot_event_fields.
    void initialize(QWidget& parent, bool show_default = true);

protected:
    virtual QString getFilteredName() const override;
    virtual QString getYAxisName() const override;
    virtual QString getHintText(unsigned num_items) const override;
    virtual void addDefaultPlot(bool enabled, bool filtered) override;
};

#endif // STRATOSHARK_PLOT_DIALOG_H
