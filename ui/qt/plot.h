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

class Plot : public Graph {
    Q_OBJECT

public:
    explicit Plot(QCustomPlot* parent, QCPAxis* keyAxis = nullptr, QCPAxis* valueAxis = nullptr);
    ~Plot();
    void setFilterField(const QString& filter, const QString& field);
    void setPlotStyle(PlotStyles style);
    void setVisible(bool visible);
    QString configError() const { return config_err_; }
    /* Returns the timestamp of the first packet, so that relative times can be calculated. */
    double startTime() const;
    void setPlotStartTime(double start_time);
    bool absoluteTime() const { return abs_time_; }
    void setAbsoluteTime(bool abs_time);
    int hfIndex() const { return hf_index_; }
    const std::vector<plot_item_t>& getItems() const { return items_; }

    void removeTapListener();

    static bool itemCompare(const plot_item_t& a, const plot_item_t& b);
    static bool itemRelCapCompare(const plot_item_t& a, const plot_item_t& b);
    uint32_t packetFromTime(double ts) const;

    void makeCsv(QTextStream& stream) const;

public slots:
    void captureEvent(const CaptureEvent& e);

signals:
    void requestReplot();
    void requestRecalc();
    void requestRetap();

private:
    // Callbacks for register_tap_listener
    static void tap_reset(void* plot_ptr);
    static tap_packet_status tap_packet(void* plot_ptr, packet_info* pinfo, epan_dissect_t* edt, const void* data, tap_flags_t flags);
    static void tap_draw(void* plot_ptr);
    // Actual non-static functions called by the callbacks above
    void tapReset();
    tap_packet_status tapPacket(packet_info* pinfo, epan_dissect_t* edt, const void* data _U_, tap_flags_t flags _U_);
    void tapDraw();

    nstime_t first_packet_;
    double plot_start_time_;
    bool abs_time_;
    bool tap_registered_;
    bool retap_needed_; // Used to delay calling requestRetap() when the plot is not visible
    int hf_index_;
    QString full_filter_;
    QString config_err_;

    std::vector<plot_item_t> items_;
};

#endif // PLOT_H
