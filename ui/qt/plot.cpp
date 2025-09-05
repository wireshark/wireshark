/* plot.cpp
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

#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include "plot.h"

#include <epan/epan_dissect.h>
#include <ui/qt/widgets/qcustomplot.h>

Plot::Plot(QCustomPlot* parent, QCPAxis* keyAxis, QCPAxis* valueAxis) :
    Graph(parent, keyAxis, valueAxis),
    first_packet_(NSTIME_INIT_UNSET),
    plot_start_time_(qQNaN()),
    abs_time_(false),
    retap_needed_(false),
    hf_index_(-1)
{
    GString* error_string = register_tap_listener("frame",
        this,
        "",
        TL_REQUIRES_PROTO_TREE,
        tap_reset,
        tap_packet,
        tap_draw,
        NULL);
    if (error_string) {
        //        QMessageBox::critical(this, tr("%1 failed to register tap listener").arg(name_),
        //                             error_string->str);
        //        config_err_ = error_string->str;
        g_string_free(error_string, true);
        tap_registered_ = false;
    }
    else {
        tap_registered_ = true;
    }
}

Plot::~Plot() {
    removeTapListener();
}

void Plot::captureEvent(const CaptureEvent& e)
{
    if ((e.captureContext() == CaptureEvent::File) &&
        (e.eventType() == CaptureEvent::Closing))
    {
        removeTapListener();
    }
}

void Plot::removeTapListener()
{
    if (tap_registered_) {
        remove_tap_listener(this);
        tap_registered_ = false;
    }
}

void Plot::setFilterField(const QString& filter, const QString& field)
{
    QString new_filter(filter.trimmed());
    QString new_field(field.trimmed());
    QString filter_, field_, full_filter;
    dfilter_t* dfilter;
    df_error_t* df_err;
    bool status;

    config_err_.clear();
    hf_index_ = -1;

    if (!new_filter.isEmpty()) {    /* Make sure the filter is valid. */
        dfilter = NULL;
        df_err = NULL;
        status = dfilter_compile(new_filter.toUtf8().constData(), &dfilter, &df_err);
        dfilter_free(dfilter);
        if (!status) {
            config_err_ = QString::fromUtf8(df_err->msg);
            df_error_free(&df_err);
            return;
        }
        else {
            filter_ = new_filter;
        }
    }

    if (!new_field.isEmpty()) { /* Make sure the field is a valid filter too. */
        dfilter = NULL;
        df_err = NULL;
        status = dfilter_compile(new_field.toUtf8().constData(), &dfilter, &df_err);
        dfilter_free(dfilter);
        if (!status) {
            config_err_ = QString::fromUtf8(df_err->msg);
            df_error_free(&df_err);
            return;
        }
        else {
            field_ = new_field;
            const header_field_info* hfi = proto_registrar_get_byname(field_.toUtf8().constData());
            if (hfi) {
                hf_index_ = hfi->id;
            }
        }
    }

    if (field_.isEmpty()) { /* We must have a field */
        config_err_ = tr("Field cannot be empty!");
        return;
    }

    if (filter_.isEmpty()) {
        full_filter = field_;
    }
    else {
        full_filter = QStringLiteral("(%1) && (%2)").arg(filter_).arg(field_);
    }

    if (full_filter_.compare(full_filter)) {
        GString* error_string = set_tap_dfilter(this, full_filter.toUtf8().constData());
        if (!error_string) {
            full_filter_ = full_filter;
            if (visible_) {
                retap_needed_ = false;
                emit requestRetap();
            }
            else {
                retap_needed_ = true;
            }
            return;
        }
        else {
            config_err_ = error_string->str;
            g_string_free(error_string, true);
        }
    }

    return;
}

void Plot::setPlotStyle(PlotStyles style)
{
    switch (style) {
    case psLine:
    case psDotLine:
    case psStepLine:
    case psDotStepLine:
    case psImpulse:
    case psDot:
    case psSquare:
    case psDiamond:
    case psCross:
    case psPlus:
    case psCircle:
        Graph::setPlotStyle(style);
        if (visible_) emit requestReplot();
        break;
    case psBar:
    case psStackedBar:
    default:
        /* Not allowed */
        break;
    }
}

void Plot::setVisible(bool visible)
{
    bool old_visibility = visible_;
    Graph::setVisible(visible);
    if (old_visibility != visible_) {
        if (visible_ && retap_needed_) {
            retap_needed_ = false;
            emit requestRetap();
        }
        else {
            // When disabling a plot, we need to update plot_start_time_
            emit requestRecalc();
        }
    }
}

double Plot::startTime() const
{
    if (abs_time_) {
        /* If we are using absolute times (i.e. time relative to capture
         * start), we don't need to subtract any offset, since the data
         * point is already absolute.
         */
        return 0.0;
    }
    if (!nstime_is_unset(&first_packet_)) {
        return nstime_to_sec(&first_packet_);
    }
    return qQNaN();
}

void Plot::setPlotStartTime(double start_time)
{
    if (qIsFinite(start_time) && start_time != plot_start_time_) {
        plot_start_time_ = start_time;
        tapDraw();  // We need to re-draw the plot
    }
}

void Plot::setAbsoluteTime(bool abs_time)
{
    if (abs_time != abs_time_) {
        abs_time_ = abs_time;
        if (visible_) emit requestRecalc(); // Start time changed.
    }
}

void Plot::setYAxisFactor(double y_axis_factor)
{
    if (y_axis_factor != y_axis_factor_) {
        Graph::setYAxisFactor(y_axis_factor);
        tapDraw();
    }
}

bool Plot::itemCompare(const plot_item_t& a, const plot_item_t& b)
{
    double res = a.frame_ts - b.frame_ts;
    if (res == 0) {
        if (a.frame_num == b.frame_num) {
            return a.idx < b.idx;
        }
        return a.frame_num < b.frame_num;
    }
    return res < 0;
}

bool Plot::itemRelCapCompare(const plot_item_t& a, const plot_item_t& b)
{
    double res = a.rel_cap_ts - b.rel_cap_ts;
    if (res == 0) {
        if (a.frame_num == b.frame_num) {
            return a.idx < b.idx;
        }
        return a.frame_num < b.frame_num;
    }
    return res < 0;
}

uint32_t Plot::packetFromTime(double ts) const
{
    plot_item_t search_item;
    if (abs_time_) {
        search_item = { 0.0, ts, 0, 0, 0.0 };
    }
    else {
        search_item = { ts, 0.0, 0, 0, 0.0 };
    }
    auto it = std::lower_bound(items_.begin(), items_.end(), search_item, abs_time_ ? itemRelCapCompare : itemCompare);
    if (it != items_.end()) {
        return it->frame_num;
    }

    return 0;
}

void Plot::setAxisColor(QCPAxis* axis, const QPen& pen)
{
    axis->setBasePen(pen);
    axis->setTickPen(pen);
    axis->setSubTickPen(pen);
    axis->setTickLabelColor(pen.color());
}

void Plot::tap_reset(void* plot_ptr)
{
    Plot* plot = static_cast<Plot*>(plot_ptr);
    if (!plot) return;

    plot->tapReset();
}

void Plot::tapReset()
{
    clearAllData();
    items_.clear();
    plot_start_time_ = qQNaN();
    first_packet_ = NSTIME_INIT_UNSET;
    retap_needed_ = false;
}

tap_packet_status Plot::tap_packet(void* plot_ptr, packet_info* pinfo, epan_dissect_t* edt, const void* data, tap_flags_t flags)
{
    Plot* plot = static_cast<Plot*>(plot_ptr);
    if (!plot) return TAP_PACKET_FAILED;

    return plot->tapPacket(pinfo, edt, data, flags);
}

tap_packet_status Plot::tapPacket(packet_info* pinfo, epan_dissect_t* edt, const void* data _U_, tap_flags_t flags _U_)
{
    if (!pinfo || !edt || !pinfo->rec || !(pinfo->rec->presence_flags & WTAP_HAS_TS) || hf_index_ < 0) {
        return TAP_PACKET_DONT_REDRAW;
    }

    GPtrArray* gp = proto_get_finfo_ptr_array(edt->tree, hf_index_);
    if (!gp) return TAP_PACKET_DONT_REDRAW;

    // XXX - QCPGraph can't show more than one value per key, so effectively,
    // if a value is present multiple times at the same timestamp, either
    // because two packets share the exact same TS, or because the field is
    // repeated in the dissection tree, only the last one will be shown.
    // Should we just ignore this case and get the last (first?) occurrence
    // of the field in the packet? At the moment we are wasting memory storing
    // the index of the occurrence.
    // As an alternative, QCPCurve supports multiple values at the same key
    // (see https://www.qcustomplot.com/documentation/classQCPCurve.html), but
    // do we really need it?
    bool one_valid = false;
    for (unsigned i = 0; i < gp->len; i++) {
        double value;
        const field_info* fip = static_cast<field_info*>(gp->pdata[i]);
        if (fip && fvalue_to_double(fip->value, &value) == FT_OK) {
            one_valid = true;
            double abs_ts = nstime_to_sec(&pinfo->abs_ts);
            double rel_cap_ts = pinfo->rel_cap_ts_present ? nstime_to_sec(&pinfo->rel_cap_ts) : qQNaN();
            if (nstime_is_unset(&first_packet_) || nstime_cmp(&pinfo->abs_ts, &first_packet_) < 0) {
                nstime_copy(&first_packet_, &pinfo->abs_ts);
                emit requestRecalc();
            }
            if (!qIsFinite(plot_start_time_) || abs_ts < plot_start_time_) {
                plot_start_time_ = abs_ts;
            }
            plot_item_t new_item = { abs_ts, rel_cap_ts, pinfo->num, i, value };
            items_.insert(std::upper_bound(items_.begin(), items_.end(), new_item, itemCompare), new_item);
        }
    }

    return one_valid ? TAP_PACKET_REDRAW : TAP_PACKET_DONT_REDRAW;
}

void Plot::tap_draw(void* plot_ptr)
{
    Plot* plot = static_cast<Plot*>(plot_ptr);
    if (!plot) return;

    plot->tapDraw();
}

void Plot::tapDraw()
{
    if (!graph_) return;

    clearAllData();

    for (auto it = items_.begin(); it != items_.end(); it++) {
        double ts = abs_time_ ? it->rel_cap_ts : (it->frame_ts - plot_start_time_);
        if (qIsFinite(ts)) {
            graph_->addData(ts, it->value * y_axis_factor_);
        }
    }

    emit requestReplot();
}

void Plot::makeCsv(QTextStream& stream) const
{
    QString name = name_.toUtf8();
    name = QStringLiteral("\"%1\"").arg(name.replace("\"", "\"\""));  // RFC 4180
    stream << "\"Time (s)\",\"Time from capture start (s)\",\"Packet number\"," << name << '\n';
    for (auto it = items_.begin(); it != items_.end(); it++) {
        double ts = it->frame_ts;
        if (qIsFinite(plot_start_time_)) ts -= plot_start_time_;
        stream << QString::number(ts, 'f', 9);
        stream << ",";
        if (qIsFinite(it->rel_cap_ts)) stream << QString::number(it->rel_cap_ts, 'f', 9);
        stream << ",";
        stream << QString::number(it->frame_num);
        stream << ",";
        stream << QString::number(it->value, 'g', QLocale::FloatingPointShortest);
        stream << '\n';
    }
}

QCPRange Plot::recentDrawnDataRange(int count) const
{
    QCPRange result;
    if (visible() && graph() && !graph()->data()->isEmpty()) {
        const QSharedPointer<QCPGraphDataContainer>& dataContainer = graph()->data();
        const int totalSize = dataContainer->size();
        int index = totalSize > count ? totalSize - count : 0;
        result.lower = dataContainer.data()->at(index)->key;
        result.upper = dataContainer.data()->at(totalSize - 1)->key;
    }
    return result;
}
