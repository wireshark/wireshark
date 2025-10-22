/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IO_GRAPH_H
#define IO_GRAPH_H

#include <config.h>

#include "graph.h"

#include <wsutil/str_util.h>
#include <ui/io_graph_item.h>

#include "wireshark_dialog.h"

#include <vector>

class QCPBars;
class QCPGraph;
class QCustomPlot;

// Scale factor to convert the units the interval is stored in to seconds.
// Must match what get_io_graph_index() in io_graph_item expects.
// Increase this in order to make smaller intervals possible.
const int SCALE = 1000000;
const double SCALE_F = (double)SCALE;

static const value_string y_axis_packet_vs[] = {
    { IOG_ITEM_UNIT_PACKETS, "Packets" },
    { IOG_ITEM_UNIT_BYTES, "Bytes" },
    { IOG_ITEM_UNIT_BITS, "Bits" },
    { IOG_ITEM_UNIT_CALC_SUM, "SUM(Y Field)" },
    { IOG_ITEM_UNIT_CALC_FRAMES, "COUNT FRAMES(Y Field)" },
    { IOG_ITEM_UNIT_CALC_FIELDS, "COUNT FIELDS(Y Field)" },
    { IOG_ITEM_UNIT_CALC_MAX, "MAX(Y Field)" },
    { IOG_ITEM_UNIT_CALC_MIN, "MIN(Y Field)" },
    { IOG_ITEM_UNIT_CALC_AVERAGE, "AVG(Y Field)" },
    { IOG_ITEM_UNIT_CALC_THROUGHPUT, "THROUGHPUT(Y Field)" },
    { IOG_ITEM_UNIT_CALC_LOAD, "LOAD(Y Field)" },
    { 0, NULL }
};

static const value_string y_axis_event_vs[] = {
    { IOG_ITEM_UNIT_PACKETS, "Events" },
    y_axis_packet_vs[1],
    y_axis_packet_vs[2],
    y_axis_packet_vs[3],
    y_axis_packet_vs[4],
    y_axis_packet_vs[5],
    y_axis_packet_vs[6],
    y_axis_packet_vs[7],
    y_axis_packet_vs[8],
    y_axis_packet_vs[9],
    { 0, NULL }
};

class IOGraph : public Graph {
    Q_OBJECT
public:
    explicit IOGraph(QCustomPlot* parent, const char* type_unit_name);
    ~IOGraph();
    QString configError() const { return config_err_; }
    void setAOT(bool asAOT);
    bool getAOT() const { return asAOT_; }
    QString filter() const { return filter_; }
    bool setFilter(const QString& filter);
    void setVisible(bool visible);
    bool needRetap() const { return need_retap_; }
    void setNeedRetap(bool retap);
    void setPlotStyle(PlotStyles style);
    QString valueUnitLabel() const;
    format_size_units_e formatUnits() const;
    io_graph_item_unit_t valueUnits() const { return val_units_; }
    void setValueUnits(int val_units);
    QString valueUnitField() const { return vu_field_; }
    void setValueUnitField(const QString& vu_field);
    nstime_t startTime() const;
    unsigned int movingAveragePeriod() const { return moving_avg_period_; }
    void setInterval(int interval);
    int packetFromTime(double ts) const;
    bool hasItemToShow(int idx, double value) const;
    double getItemValue(int idx, const capture_file* cap_file) const;
    int maxInterval() const { return cur_idx_; }

    void clearAllData();

    unsigned int moving_avg_period_;

public slots:
    void recalcGraphData(capture_file* cap_file);
    void captureEvent(const CaptureEvent& e);
    void reloadValueUnitField();

signals:
    void requestReplot();
    void requestRecalc();
    void requestRetap();

private:
    // Callbacks for register_tap_listener
    static void tapReset(void* iog_ptr);
    static tap_packet_status tapPacket(void* iog_ptr, packet_info* pinfo, epan_dissect_t* edt, const void* data, tap_flags_t flags);
    static void tapDraw(void* iog_ptr);

    void removeTapListener();

    bool showsZero() const;
    double startOffset() const;

    template<class DataMap> double maxValueFromGraphData(const DataMap& map);
    template<class DataMap> void scaleGraphData(DataMap& map, int scalar);

    QString config_err_;
    bool tap_registered_;
    bool need_retap_;
    QString filter_;
    QString full_filter_; // Includes vu_field_ if used
    io_graph_item_unit_t val_units_;
    QString vu_field_;
    nstime_t start_time_;
    int hf_index_;
    int interval_;
    bool asAOT_; // Average Over Time interpretation
    const char* type_unit_name_;

    // Cached data. We should be able to change the Y axis without retapping as
    // much as is feasible.
    std::vector<io_graph_item_t> items_;
    int cur_idx_;
};

#endif // IO_GRAPH_H
