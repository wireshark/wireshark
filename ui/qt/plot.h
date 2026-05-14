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

#ifndef PLOT_H
#define PLOT_H

#include <config.h>

#include "graph.h"

#include <vector>

typedef struct _plot_item_t {
    double      frame_ts;   /* Absolute timestamp of the packet */
    double      rel_cap_ts; /* Time relative from capture start */
    uint32_t    frame_num;  /* Packet number */
    unsigned    idx;        /* Istance of the field in the packet */
    double      value;      /* Value of the field (always converted to double) */
} plot_item_t;

class QCPRange;

/**
 * @brief A single tap-driven data series rendered on a QCustomPlot axis pair.
 */
class Plot : public Graph {
    Q_OBJECT

public:
    /**
     * @brief Construct a Plot.
     * @param parent    The QCustomPlot that owns this graph.
     * @param keyAxis   The X axis to plot against, or nullptr for the default.
     * @param valueAxis The Y axis to plot against, or nullptr for the default.
     */
    explicit Plot(QCustomPlot *parent, QCPAxis *keyAxis = nullptr, QCPAxis *valueAxis = nullptr);

    /**
     * @brief Destroy the Plot.
     */
    ~Plot();

    /**
     * @brief Set the display filter and Y-axis field for this plot.
     * @param filter The display filter expression (may be empty).
     * @param field  The header field abbreviation whose value is plotted on the Y axis.
     */
    void setFilterField(const QString &filter, const QString &field);

    /**
     * @brief Set the visual plot style for this series.
     * @param style The desired plot style.
     */
    void setPlotStyle(PlotStyles style);

    /**
     * @brief Show or hide this plot on the graph.
     * @param visible true to show and activate the tap; false to hide and
     *                deactivate it.
     */
    void setVisible(bool visible);

    /**
     * @brief Return any configuration error set by setFilterField().
     * @return The configuration error string, or an empty string if none.
     */
    QString configError() const { return config_err_; }

    /**
     * @brief Return the capture timestamp of the first packet seen by this plot.
     * @return The timestamp of the first packet in seconds, or 0.0 if no
     *         packets have been received yet.
     */
    double startTime() const;

    /**
     * @brief Set the shared plot start time used for relative-time calculations.
     * @param start_time The common time origin in seconds.
     */
    void setPlotStartTime(double start_time);

    /**
     * @brief Return whether this plot uses absolute (wall-clock) time on the X axis.
     * @return true if the X axis shows absolute timestamps; false for elapsed time.
     */
    bool absoluteTime() const { return abs_time_; }

    /**
     * @brief Set the X-axis time display mode.
     * @param abs_time true to display absolute (wall-clock) timestamps;
     *                 false to display elapsed time relative to @c plot_start_time_.
     */
    void setAbsoluteTime(bool abs_time);

    /**
     * @brief Set a multiplier applied to all Y-axis values before plotting.
     * @param y_axis_factor The scale factor; 1.0 means no scaling.
     */
    void setYAxisFactor(double y_axis_factor);

    /**
     * @brief Return the resolved header field index for the Y-axis field.
     * @return The @c hf_index for the field set by setFilterField(), or -1 if
     *         no valid field has been resolved.
     */
    int hfIndex() const { return hf_index_; }

    /**
     * @brief Return read-only access to the collected plot items.
     * @return A const reference to the vector of @c plot_item_t values
     *         accumulated by the tap callbacks.
     */
    const std::vector<plot_item_t> &getItems() const { return items_; }

    /**
     * @brief Remove this plot's tap listener, if one is registered.
     */
    void removeTapListener();

    /**
     * @brief Compare two plot items by absolute capture timestamp.
     * @param a The first plot item.
     * @param b The second plot item.
     * @return true if @p a occurred before @p b.
     */
    static bool itemCompare(const plot_item_t &a, const plot_item_t &b);

    /**
     * @brief Compare two plot items by relative capture timestamp.
     * @param a The first plot item.
     * @param b The second plot item.
     * @return true if @p a has an earlier relative capture time than @p b.
     */
    static bool itemRelCapCompare(const plot_item_t &a, const plot_item_t &b);

    /**
     * @brief Set the pen colour of all visual components of a QCPAxis.
     * @param axis The axis to recolour.
     * @param pen  The pen (colour and width) to apply.
     */
    static void setAxisColor(QCPAxis *axis, const QPen &pen);

    /**
     * @brief Return the frame number of the packet closest to a given timestamp.
     * @param ts The target timestamp in seconds.
     * @return The 1-based frame number of the nearest packet, or 0 if
     *         @c items_ is empty.
     */
    uint32_t packetFromTime(double ts) const;

    /**
     * @brief Write all plot items as CSV rows to @p stream.
     * @param stream The text stream to write to.
     */
    void makeCsv(QTextStream &stream) const;

    /**
     * @brief Return the key (X-axis) range covering the most recent @p count items.
     * @param count The number of most-recent data points to include in the range.
     * @return A QCPRange spanning the timestamps of the last @p count items,
     *         or an empty range if @c items_ has fewer than @p count entries.
     */
    QCPRange recentDrawnDataRange(int count) const;

public slots:
    /**
     * @brief React to a capture lifecycle event.
     * @param e The capture event describing the state transition.
     */
    void captureEvent(const CaptureEvent &e);


signals:
    /** @brief Emitted to request a lightweight QCustomPlot replot without recalculation. */
    void requestReplot();

    /** @brief Emitted to request a medium-weight value recalculation followed by replot. */
    void requestRecalc();

    /** @brief Emitted to request a full retap of the capture file. */
    void requestRetap();

private:
    // Static trampoline callbacks passed to register_tap_listener.
    /** @brief Tap reset trampoline — delegates to tapReset(). */
    static void tap_reset(void *plot_ptr);
    /** @brief Tap packet trampoline — delegates to tapPacket(). */
    static tap_packet_status tap_packet(void *plot_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *data, tap_flags_t flags);
    /** @brief Tap draw trampoline — delegates to tapDraw(). */
    static void tap_draw(void *plot_ptr);

    /** @brief Clear @c items_ and reset per-pass state before a retap. */
    void tapReset();
    /**
     * @brief Process one dissected packet and append a plot_item_t to @c items_.
     * @param pinfo Packet metadata.
     * @param edt   The epan dissect context carrying field values.
     * @param data  Tap-specific data (unused).
     * @param flags Tap flags (unused).
     * @return TAP_PACKET_REDRAW if the display should refresh, otherwise
     *         TAP_PACKET_DONT_REDRAW.
     */
    tap_packet_status tapPacket(packet_info *pinfo, epan_dissect_t *edt, const void *data _U_, tap_flags_t flags _U_);
    /** @brief Push accumulated items into QCPGraph data and emit requestReplot(). */
    void tapDraw();

    nstime_t first_packet_;   /**< Absolute timestamp of the first tapped packet. */
    double plot_start_time_;  /**< Shared time origin for relative-time X-axis display. */
    bool abs_time_;           /**< true = absolute time X axis; false = relative time. */
    bool tap_registered_;     /**< true if a tap listener is currently registered. */
    bool retap_needed_;       /**< Used to delay calling requestRetap() when the plot is not visible. */
    int hf_index_;            /**< Resolved hf_index for the Y-axis field, or -1. */
    QString full_filter_;     /**< Combined "filter && field" tap filter string. */
    QString config_err_;      /**< Non-empty if setFilterField() failed to resolve the field. */

    std::vector<plot_item_t> items_; /**< Per-packet (timestamp, value) data points. */
};

#endif // PLOT_H
