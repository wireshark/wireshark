/* stratoshark_plot_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include "stratoshark_plot_dialog.h"
#include <ui/qt/utils/color_utils.h>
#include <ui/plot_graph_uat.h>

static uat_field_t plot_event_fields[] = {
    UAT_FLD_BOOL(plot, enabled, "Enabled", "Graph visibility"),
    UAT_FLD_DEC(plot, group, "Group #", "Which group the plot belongs to"),
    UAT_FLD_CSTRING(plot, name, "Plot Name", "The name of the plot"),
    UAT_FLD_DISPLAY_FILTER(plot, dfilter, "Display Filter", "Plot events matching this display filter"),
    UAT_FLD_COLOR(plot, color, "Color", "Plot color (#RRGGBB)"),
    UAT_FLD_VS(plot, style, "Style", plot_graph_style_vs, "Plot style"),
    UAT_FLD_PROTO_FIELD(plot, yfield, "Y Field", "Field to plot"),
    UAT_FLD_DBL(plot, y_axis_factor, "Y Axis Factor", "Y Axis Factor"),

    UAT_END_FIELDS
};

StratosharkPlotDialog::StratosharkPlotDialog(QWidget& parent, CaptureFile& cf) :
    PlotDialog(parent, cf)
{
}

StratosharkPlotDialog::~StratosharkPlotDialog()
{
}

void StratosharkPlotDialog::initialize(QWidget& parent, bool show_default)
{
    PlotDialog::initialize(parent, plot_event_fields, show_default);
}

QString StratosharkPlotDialog::getFilteredName() const
{
    return tr("Filtered events");
}

QString StratosharkPlotDialog::getYAxisName() const
{
    return tr("All events");
}

QString StratosharkPlotDialog::getHintText(unsigned num_items) const
{
    return QStringLiteral("%1 %2")
        .arg(!file_closed_ ? tr("Click to select event") : tr("Event"))
        .arg(num_items);

}

void StratosharkPlotDialog::addDefaultPlot(bool enabled, bool filtered)
{
    if (filtered) {
        addPlot(enabled, tr("Event latency"), "evt.type == \"read\"", ColorUtils::graphColor(0), Graph::psDotStepLine, "evt.latency");
    }
    else {
        addPlot(enabled, tr("Frame num."), QString(), ColorUtils::graphColor(4), Graph::psLine, "frame.number");
    }
}
