/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "stratoshark_io_graph_dialog.h"
#include "epan/uat.h"
#include "epan/uat-int.h"
#include "ui/io_graph_uat.h"
#include <ui/qt/io_graph.h>
#include <ui/qt/utils/color_utils.h>

UAT_VS_DEF(io_graph, yaxis, io_graph_settings_t, uint32_t, 0, "Events")

static uat_field_t io_graph_event_fields[] = {
    UAT_FLD_BOOL_ENABLE(io_graph, enabled, "Enabled", "Graph visibility"),
    UAT_FLD_CSTRING(io_graph, name, "Graph Name", "The name of the graph"),
    UAT_FLD_DISPLAY_FILTER(io_graph, dfilter, "Display Filter", "Graph packets matching this display filter"),
    UAT_FLD_COLOR(io_graph, color, "Color", "Graph color (#RRGGBB)"),
    UAT_FLD_VS(io_graph, style, "Style", io_graph_style_vs, "Graph style (Line, Bars, etc.)"),
    UAT_FLD_VS(io_graph, yaxis, "Y Axis", y_axis_event_vs, "Y Axis units"),
    UAT_FLD_PROTO_FIELD(io_graph, yfield, "Y Field", "Apply calculations to this field"),
    UAT_FLD_SMA_PERIOD(io_graph, sma_period, "SMA Period", moving_avg_vs, "Simple moving average period"),
    UAT_FLD_DBL(io_graph, y_axis_factor, "Y Axis Factor", "Y Axis Factor"),
    UAT_FLD_BOOL_ENABLE(io_graph, asAOT, "asAOT", "asAOT"),

    UAT_END_FIELDS
};

StratosharkIOGraphDialog::StratosharkIOGraphDialog(QWidget &parent, CaptureFile &cf) :
    IOGraphDialog(parent, cf, "Events")
{
}

StratosharkIOGraphDialog::~StratosharkIOGraphDialog()
{
}

void StratosharkIOGraphDialog::initialize(QWidget& parent, QString displayFilter, io_graph_item_unit_t value_units, QString yfield, bool is_sibling_dialog, const QVector<QString> convFilters)
{
    IOGraphDialog::initialize(parent, io_graph_event_fields, displayFilter, value_units, yfield, is_sibling_dialog, convFilters);
}

void StratosharkIOGraphDialog::addDefaultGraph(bool enabled, int idx)
{
    switch (idx % 2) {
    case 0:
        addGraph(enabled, false, tr("All Events"), QString(), ColorUtils::graphColor(idx),
            IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
        break;
    default:
        addGraph(enabled, false, tr("All Execs"), "evt.type == \"execve\"", ColorUtils::graphColor(4), // 4 = red
            IOGraph::psDot, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
        break;
    }
}

QString StratosharkIOGraphDialog::getFilteredName() const
{
    return tr("Filtered events");
}

QString StratosharkIOGraphDialog::getXAxisName() const
{
    return tr("All events");
}

const char* StratosharkIOGraphDialog::getYAxisName(io_graph_item_unit_t value_units) const
{
    return val_to_str_const(value_units, y_axis_event_vs, "Events");
}

QString StratosharkIOGraphDialog::getYFieldName(io_graph_item_unit_t value_units, const QString& yfield) const
{
    return QString(val_to_str_const(value_units, y_axis_event_vs, "Unknown")).replace("Y Field", yfield);
}

int StratosharkIOGraphDialog::getYAxisValue(const QString& data)
{
    return (int)str_to_val(qUtf8Printable(data), y_axis_event_vs, IOG_ITEM_UNIT_PACKETS);
}

QString StratosharkIOGraphDialog::getNoDataHint() const
{
    return tr("No events in interval");
}

QString StratosharkIOGraphDialog::getHintText(unsigned num_items) const
{
    return QStringLiteral("%1 %2")
        .arg(!file_closed_ ? tr("Click to select event") : tr("Event"))
        .arg(num_items);
}
