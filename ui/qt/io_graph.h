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

/**
 * @brief Represents an individual input/output graph, handling tapping, packet processing, and data scaling.
 */
class IOGraph : public Graph {
    Q_OBJECT
public:
    /**
     * @brief Constructs a new IOGraph.
     * @param parent The parent QCustomPlot widget.
     * @param type_unit_name The name string representing the graph's unit type.
     */
    explicit IOGraph(QCustomPlot* parent, const char* type_unit_name);

    /**
     * @brief Destroys the IOGraph.
     */
    ~IOGraph();

    /**
     * @brief Retrieves the current configuration error string, if any.
     * @return The configuration error string.
     */
    QString configError() const { return config_err_; }

    /**
     * @brief Sets whether the graph displays values as an Average Over Time (AOT).
     * @param asAOT True to enable AOT interpretation.
     */
    void setAOT(bool asAOT);

    /**
     * @brief Checks if the graph displays values as an Average Over Time (AOT).
     * @return True if AOT is enabled, false otherwise.
     */
    bool getAOT() const { return asAOT_; }

    /**
     * @brief Retrieves the active filter string for this graph.
     * @return The filter string.
     */
    QString filter() const { return filter_; }

    /**
     * @brief Sets the filter string for this graph.
     * @param filter The new filter string.
     * @return True if the filter was successfully applied.
     */
    bool setFilter(const QString& filter);

    /**
     * @brief Sets the visibility of the graph.
     * @param visible True to show the graph, false to hide it.
     */
    void setVisible(bool visible);

    /**
     * @brief Checks if changing the graph configuration requires a packet retap.
     * @return True if a retap is needed, false otherwise.
     */
    bool needRetap() const { return need_retap_; }

    /**
     * @brief Manually flags whether a retap is required.
     * @param retap True to flag for a retap.
     */
    void setNeedRetap(bool retap);

    /**
     * @brief Sets the visual plotting style for this specific IO graph.
     * @param style The desired PlotStyles value.
     */
    void setPlotStyle(PlotStyles style);

    /**
     * @brief Generates the label for the value (Y-axis) units.
     * @return The unit label string.
     */
    QString valueUnitLabel() const;

    /**
     * @brief Retrieves the size formatting enumerator for the Y-axis units.
     * @return The format_size_units_e value.
     */
    format_size_units_e formatUnits() const;

    /**
     * @brief Retrieves the core IO graph item unit type.
     * @return The io_graph_item_unit_t value.
     */
    io_graph_item_unit_t valueUnits() const { return val_units_; }

    /**
     * @brief Sets the core IO graph item unit type.
     * @param val_units The new io_graph_item_unit_t integer value.
     */
    void setValueUnits(int val_units);

    /**
     * @brief Retrieves the field used to calculate the value units (e.g., specific protocol field).
     * @return The value unit field string.
     */
    QString valueUnitField() const { return vu_field_; }

    /**
     * @brief Sets the field used to calculate the value units.
     * @param vu_field The new value unit field string.
     */
    void setValueUnitField(const QString& vu_field);

    /**
     * @brief Retrieves the starting time of the graph data.
     * @return The nstime_t structure representing the start time.
     */
    nstime_t startTime() const;

    /**
     * @brief Retrieves the period used for moving average calculations.
     * @return The moving average period integer.
     */
    unsigned int movingAveragePeriod() const { return moving_avg_period_; }

    /**
     * @brief Sets the time interval for data bucketing.
     * @param interval The interval in milliseconds.
     */
    void setInterval(int interval);

    /**
     * @brief Determines the packet number closest to a specific timestamp.
     * @param ts The timestamp to search for.
     * @return The closest packet number.
     */
    int packetFromTime(double ts) const;

    /**
     * @brief Checks if a specific data item index has a valid value to display.
     * @param idx The item index.
     * @param value The value associated with the index.
     * @return True if it should be shown, false otherwise.
     */
    bool hasItemToShow(int idx, double value) const;

    /**
     * @brief Calculates or retrieves the formatted value for a specific data item index.
     * @param idx The item index.
     * @param cap_file The capture file context.
     * @return The calculated double value.
     */
    double getItemValue(int idx, const capture_file* cap_file) const;

    /**
     * @brief Retrieves the maximum populated interval index.
     * @return The maximum interval index.
     */
    int maxInterval() const { return cur_idx_; }

    /**
     * @brief Clears all cached plotting and tap data.
     */
    void clearAllData();

    /** The active moving average period. */
    unsigned int moving_avg_period_;

public slots:
    /**
     * @brief Recalculates the graph plotting data based on cached tap data.
     * @param cap_file The capture file context.
     */
    void recalcGraphData(capture_file* cap_file);

    /**
     * @brief Handles system capture events.
     * @param e The capture event.
     */
    void captureEvent(const CaptureEvent& e);

    /**
     * @brief Reloads and re-evaluates the value unit field setting.
     */
    void reloadValueUnitField();

signals:
    /**
     * @brief Signal emitted to request a UI redraw of the parent plot.
     */
    void requestReplot();

    /**
     * @brief Signal emitted to request a recalculation of the graph data.
     */
    void requestRecalc();

    /**
     * @brief Signal emitted to request a full retap of the packet data.
     */
    void requestRetap();

private:
    // Callbacks for register_tap_listener
    /**
     * @brief Callback used by register_tap_listener to reset the graph state.
     * @param iog_ptr Pointer to the IOGraph instance.
     */
    static void tapReset(void* iog_ptr);

    /**
     * @brief Callback used by register_tap_listener when a packet is processed.
     * @param iog_ptr Pointer to the IOGraph instance.
     * @param pinfo Pointer to the packet info structure.
     * @param edt Pointer to the epan dissection structure.
     * @param data Pointer to the custom tap data.
     * @param flags Tap flags.
     * @return The status of the tap packet processing.
     */
    static tap_packet_status tapPacket(void* iog_ptr, packet_info* pinfo, epan_dissect_t* edt, const void* data, tap_flags_t flags);

    /**
     * @brief Callback used by register_tap_listener to trigger drawing updates.
     * @param iog_ptr Pointer to the IOGraph instance.
     */
    static void tapDraw(void* iog_ptr);

    /**
     * @brief Unregisters and removes the current tap listener.
     */
    void removeTapListener();

    /**
     * @brief Checks if zero values should be plotted or ignored.
     * @return True if zero values are shown, false otherwise.
     */
    bool showsZero() const;

    /**
     * @brief Calculates the starting offset for the graph timeline.
     * @return The offset as a double.
     */
    double startOffset() const;

    /**
     * @brief Template function to find the maximum value within a mapped data set.
     * @param map The map containing graph data.
     * @return The maximum double value.
     */
    template<class DataMap> double maxValueFromGraphData(const DataMap& map);

    /**
     * @brief Template function to scale values within a mapped data set.
     * @param map The map containing graph data.
     * @param scalar The integer scalar to multiply/divide by.
     */
    template<class DataMap> void scaleGraphData(DataMap& map, int scalar);

    /** Configuration error string. */
    QString config_err_;

    /** Flag indicating if the tap listener is currently registered. */
    bool tap_registered_;

    /** Flag indicating if the graph data needs to be retapped from the capture file. */
    bool need_retap_;

    /** The base filter string. */
    QString filter_;

    /** The complete filter string, incorporating the value unit field if necessary. */
    QString full_filter_; // Includes vu_field_ if used

    /** The unit type mapped to the Y-axis. */
    io_graph_item_unit_t val_units_;

    /** The specific protocol field used to calculate the Y-axis values. */
    QString vu_field_;

    /** The time of the first packet in the stream. */
    nstime_t start_time_;

    /** The header field index associated with the vu_field_. */
    int hf_index_;

    /** The data bucketing interval. */
    int interval_;

    /** Flag indicating if values are interpreted as an average over time. */
    bool asAOT_; // Average Over Time interpretation

    /** The name of the value unit type for display purposes. */
    const char* type_unit_name_;

    /**
     * Cached tap data items. We should be able to change the Y axis without retapping as
     * much as is feasible.
     */
    std::vector<io_graph_item_t> items_;

    /** The highest interval index currently populated with data. */
    int cur_idx_;
};

#endif // IO_GRAPH_H
