/* io_graph.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include "io_graph.h"

#include <wsutil/application_flavor.h>
#include <wsutil/ws_assert.h>

#include <ui/qt/widgets/qcustomplot.h>

//#include <QMessageBox>

#include <new> // std::bad_alloc

// GTK+ set this to 100000 (NUM_IO_ITEMS) before raising it to unlimited
// in commit 524583298beb671f43e972476693866754d38a38.
// This is the maximum index returned from get_io_graph_index that will
// be added to the graph. Thus, for a minimum interval size of 1 μs no
// more than 33.55 s.
// Each io_graph_item_t is 88 bytes on a system with 64 bit time_t, so
// the max size we'll attempt to allocate for the array of items is 2.75 GiB
// (plus a tiny amount extra for the std::vector bookkeeping.)
// 2^25 = 16777216
const int max_io_items_ = 1 << 25;

IOGraph::IOGraph(QCustomPlot* parent) :
    Graph(parent),
    moving_avg_period_(0),
    tap_registered_(true),
    need_retap_(false),
    val_units_(IOG_ITEM_UNIT_FIRST),
    hf_index_(-1),
    interval_(0),
    asAOT_(false),
    cur_idx_(-1)
{
    GString* error_string;
    error_string = register_tap_listener("frame",
        this,
        "",
        TL_REQUIRES_PROTO_TREE,
        tapReset,
        tapPacket,
        tapDraw,
        NULL);
    if (error_string) {
        //        QMessageBox::critical(this, tr("%1 failed to register tap listener").arg(name_),
        //                             error_string->str);
        //        config_err_ = error_string->str;
        g_string_free(error_string, true);
        tap_registered_ = false;
    }
}

IOGraph::~IOGraph() {
    removeTapListener();
}

void IOGraph::removeTapListener()
{
    if (tap_registered_) {
        remove_tap_listener(this);
        tap_registered_ = false;
    }
}

// Construct a full filter string from the display filter and value unit / Y axis.
// Check for errors and sets config_err_ and returns false if any are found.
bool IOGraph::setFilter(const QString& filter)
{
    GString* error_string;
    QString full_filter(filter.trimmed());

    config_err_.clear();

    // Make sure we have a good display filter
    if (!full_filter.isEmpty()) {
        dfilter_t* dfilter;
        bool status;
        df_error_t* df_err = NULL;
        status = dfilter_compile(full_filter.toUtf8().constData(), &dfilter, &df_err);
        dfilter_free(dfilter);
        if (!status) {
            config_err_ = QString::fromUtf8(df_err->msg);
            df_error_free(&df_err);
            filter_ = full_filter;
            return false;
        }
    }

    // Check our value unit + field combo.
    error_string = check_field_unit(vu_field_.toUtf8().constData(), NULL, val_units_);
    if (error_string) {
        config_err_ = error_string->str;
        g_string_free(error_string, true);
        return false;
    }

    // Make sure vu_field_ survives edt tree pruning by adding it to our filter
    // expression.
    if (val_units_ >= IOG_ITEM_UNIT_CALC_SUM && !vu_field_.isEmpty() && hf_index_ >= 0) {
        if (full_filter.isEmpty()) {
            full_filter = vu_field_;
        }
        else {
            full_filter += QStringLiteral(" && (%1)").arg(vu_field_);
        }
    }

    if (full_filter_.compare(full_filter)) {
        error_string = set_tap_dfilter(this, full_filter.toUtf8().constData());
        if (error_string) {
            config_err_ = error_string->str;
            g_string_free(error_string, true);
            return false;
        }

        filter_ = filter;
        full_filter_ = full_filter;
        /* If we changed the tap filter the graph is visible, we need to
         * retap.
         * Note that setting the tap dfilter will mark the tap as needing a
         * redraw, which will cause a recalculation (via tapDraw) via the
         * (fairly long) main application timer.
         */
         /* XXX - When changing from an advanced graph to one that doesn't
          * use the field, we don't actually need to retap if filter and
          * full_filter produce the same results. (We do have to retap
          * regardless if changing _to_ an advanced graph, because the
          * extra fields in the io_graph_item_t aren't filled in from the
          * edt for the basic graph.)
          * Checking that in full generality would require more optimization
          * in the dfilter engine plus functions to compare filters, but
          * we could test the simple case where filter and vu_field are
          * the same string.
          */
        setNeedRetap(true);
    }
    return true;
}

// Sets the Average Over Time value.
// Mostly C/P of setVisible(), Refer to this method for comments.
void IOGraph::setAOT(bool asAOT)
{
    bool old_val = asAOT_;
    asAOT_ = asAOT;
    if (old_val != asAOT) {
        if (visible_ && need_retap_) {
            need_retap_ = false;
            emit requestRetap();
        }
        else {
            emit requestRecalc();
        }
    }
}

void IOGraph::setVisible(bool visible)
{
    bool old_visibility = visible_;
    Graph::setVisible(visible);
    if (old_visibility != visible_) {
        if (visible_ && need_retap_) {
            need_retap_ = false;
            emit requestRetap();
        }
        else {
            // XXX - If the number of enabled graphs changed to or from 1, we
            // need to recalculate to possibly change the rescaling. (This is
            // why QCP recommends doing scaling in the axis ticker instead.)
            // If we can't determine the number of enabled graphs here, always
            // request a recalculation instead of a replot. (At least until we
            // change the scaling to be done in the ticker.)
            //emit requestReplot();
            emit requestRecalc();
        }
    }
}

void IOGraph::setNeedRetap(bool retap)
{
    if (visible_ && retap) {
        emit requestRetap();
    }
    else {
        need_retap_ = retap;
    }
}

void IOGraph::setPlotStyle(PlotStyles style)
{
    bool shows_zero = showsZero();
    bool recalc = Graph::setPlotStyle(style);

    if (bars_ && interval_) {
        bars_->setWidth(interval_ / SCALE_F);
    }
    setValueUnits(val_units_);

    if (shows_zero != showsZero()) {
        // recalculate if whether zero is added changed
        recalc = true;
    }

    if (recalc) {
        // switching the plottable requires recalculation to add the data
        emit requestRecalc();
    }
}

QString IOGraph::valueUnitLabel() const
{
    if (application_flavor_is_wireshark()) {
        return val_to_str_const(val_units_, y_axis_packet_vs, "Unknown");
    }
    return val_to_str_const(val_units_, y_axis_event_vs, "Unknown");
}

void IOGraph::setValueUnits(int val_units)
{
    if (val_units >= IOG_ITEM_UNIT_FIRST && val_units <= IOG_ITEM_UNIT_LAST) {
        int old_val_units = val_units_;
        val_units_ = (io_graph_item_unit_t)val_units;

        if (old_val_units != val_units) {
            // If val_units changed, switching between a type that doesn't
            // use the vu_field/hfi/edt to one of the advanced graphs that
            // does requires a retap. setFilter will handle that, because
            // the full filter strings will be different.
            if (setFilter(filter_)) { // Check config & prime vu field
                if (val_units == IOG_ITEM_UNIT_CALC_LOAD ||
                    old_val_units == IOG_ITEM_UNIT_CALC_LOAD) {
                    // LOAD graphs fill in the io_graph_item_t differently
                    // than other advanced graphs, so we have to retap even
                    // if the filter is the same. (update_io_graph_item could
                    // instead calculate and store LOAD information for any
                    // advanced graph type, but the tradeoff might not be
                    // worth it.)
                    setNeedRetap(true);
                }
            }
        }
    }
}

void IOGraph::setValueUnitField(const QString& vu_field)
{
    int old_hf_index = hf_index_;

    vu_field_ = vu_field.trimmed();
    hf_index_ = -1;

    const header_field_info* hfi = proto_registrar_get_byname(vu_field_.toUtf8().constData());
    if (hfi) {
        hf_index_ = hfi->id;
    }

    if (old_hf_index != hf_index_) {
        // If the field changed, and val_units is a type that uses it,
        // we need to retap. setFilter will handle that.
        setFilter(filter_); // Check config & prime vu field
    }
}

int IOGraph::packetFromTime(double ts) const
{
    int idx = ts * SCALE_F / interval_;
    if (idx >= 0 && idx <= cur_idx_) {
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_MAX:
            return items_[idx].max_frame_in_invl;
        case IOG_ITEM_UNIT_CALC_MIN:
            return items_[idx].min_frame_in_invl;
        default:
            return items_[idx].last_frame_in_invl;
        }
    }
    return -1;
}

void IOGraph::clearAllData()
{
    cur_idx_ = -1;
    if (items_.size()) {
        reset_io_graph_items(&items_[0], items_.size(), hf_index_);
    }
    Graph::clearAllData();
}

void IOGraph::recalcGraphData(capture_file* cap_file)
{
    /* Moving average variables */
    unsigned int mavg_in_average_count = 0, mavg_left = 0;
    unsigned int mavg_to_remove = 0, mavg_to_add = 0;
    double mavg_cumulated = 0;

    if (graph_) {
        graph_->data()->clear();
    }
    if (bars_) {
        bars_->data()->clear();
    }

    if (moving_avg_period_ > 0 && cur_idx_ >= 0) {
        /* "Warm-up phase" - calculate average on some data not displayed;
         * just to make sure average on leftmost and rightmost displayed
         * values is as reliable as possible
         */
        unsigned warmup_interval = 0;

        mavg_cumulated += getItemValue((int)warmup_interval, cap_file);
        mavg_in_average_count++;
        for (warmup_interval = 1;
            (warmup_interval < moving_avg_period_ / 2) &&
            (warmup_interval <= (unsigned)cur_idx_);
            warmup_interval += 1) {

            mavg_cumulated += getItemValue((int)warmup_interval, cap_file);
            mavg_in_average_count++;
        }
        mavg_to_add = warmup_interval;
    }

    double ts_offset = startOffset();
    for (int i = 0; i <= cur_idx_; i++) {
        double ts = (double)i * interval_ / SCALE_F + ts_offset;
        double val = getItemValue(i, cap_file);

        if (moving_avg_period_ > 0) {
            if (i != 0) {
                mavg_left++;
                if (mavg_left > moving_avg_period_ / 2) {
                    mavg_left--;
                    mavg_in_average_count--;
                    mavg_cumulated -= getItemValue(mavg_to_remove, cap_file);
                    mavg_to_remove += 1;
                }
                if (mavg_to_add <= (unsigned int)cur_idx_) {
                    mavg_in_average_count++;
                    mavg_cumulated += getItemValue(mavg_to_add, cap_file);
                    mavg_to_add += 1;
                }
            }
            if (mavg_in_average_count > 0) {
                val = mavg_cumulated / mavg_in_average_count;
            }
        }

        val *= y_axis_factor_;

        if (hasItemToShow(i, val))
        {
            if (graph_) {
                graph_->addData(ts, val);
            }
            if (bars_) {
                bars_->addData(ts, val);
            }
        }
    }

    emit requestReplot();
}

format_size_units_e IOGraph::formatUnits() const
{
    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
    case IOG_ITEM_UNIT_CALC_FRAMES:
        if (application_flavor_is_wireshark()) {
            return FORMAT_SIZE_UNIT_PACKETS;
        }
        return FORMAT_SIZE_UNIT_EVENTS;
    case IOG_ITEM_UNIT_BYTES:
        return FORMAT_SIZE_UNIT_BYTES;
    case IOG_ITEM_UNIT_BITS:
        return FORMAT_SIZE_UNIT_BITS;
    case IOG_ITEM_UNIT_CALC_LOAD:
        return FORMAT_SIZE_UNIT_ERLANGS;
    case IOG_ITEM_UNIT_CALC_FIELDS:
        return FORMAT_SIZE_UNIT_FIELDS;
    case IOG_ITEM_UNIT_CALC_SUM:
    case IOG_ITEM_UNIT_CALC_MAX:
    case IOG_ITEM_UNIT_CALC_MIN:
    case IOG_ITEM_UNIT_CALC_AVERAGE:
        // Unit is not yet known, continue detecting it.
        if (hf_index_ > 0) {
            if (proto_registrar_get_ftype(hf_index_) == FT_RELATIVE_TIME) {
                return FORMAT_SIZE_UNIT_SECONDS;
            }
            // Could we look if it's BASE_UNIT_STRING and use that?
            // One complication is that prefixes shouldn't be combined,
            // and some unit strings are already prefixed units.
        }
        return FORMAT_SIZE_UNIT_NONE;
    case IOG_ITEM_UNIT_CALC_THROUGHPUT:
        return FORMAT_SIZE_UNIT_BITS_S;
    default:
        return FORMAT_SIZE_UNIT_NONE;
    }
}

template<class DataMap>
double IOGraph::maxValueFromGraphData(const DataMap& map)
{
    double maxValue = 0;
    typename DataMap::const_iterator it = map.constBegin();
    while (it != map.constEnd()) {
        maxValue = MAX(fabs((*it).value), maxValue);
        ++it;
    }
    return maxValue;
}

template<class DataMap>
void IOGraph::scaleGraphData(DataMap& map, int scalar)
{
    if (scalar != 1) {
        typename DataMap::iterator it = map.begin();
        while (it != map.end()) {
            (*it).value *= scalar;
            ++it;
        }
    }
}

void IOGraph::captureEvent(const CaptureEvent& e)
{
    if ((e.captureContext() == CaptureEvent::File) &&
        (e.eventType() == CaptureEvent::Closing))
    {
        removeTapListener();
    }
}

void IOGraph::reloadValueUnitField()
{
    if (vu_field_.length() > 0) {
        setValueUnitField(vu_field_);
    }
}

// returns true if the current plot style shows zero values,
// false if null values are omitted.
bool IOGraph::showsZero() const
{
    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
    case IOG_ITEM_UNIT_BYTES:
    case IOG_ITEM_UNIT_BITS:
    case IOG_ITEM_UNIT_CALC_FRAMES:
    case IOG_ITEM_UNIT_CALC_FIELDS:
        if (graph_ && graph_->lineStyle() == QCPGraph::lsNone) {
            return false;
        }
        else {
            return true;
        }
    case IOG_ITEM_UNIT_CALC_SUM:
    case IOG_ITEM_UNIT_CALC_MAX:
    case IOG_ITEM_UNIT_CALC_MIN:
    case IOG_ITEM_UNIT_CALC_AVERAGE:
    case IOG_ITEM_UNIT_CALC_LOAD:
    case IOG_ITEM_UNIT_CALC_THROUGHPUT:
        // These are not the same sort of "omitted zeros" as above,
        // but changing val_units_ always results in a recalculation
        // so it doesn't matter (see modelDataChanged)
        return false;

    default:
        return true;
    }
}

// Check if a packet is available at the given interval (idx).
bool IOGraph::hasItemToShow(int idx, double value) const
{
    ws_assert(idx < max_io_items_);

    bool result = false;

    const io_graph_item_t* item = &items_[idx];

    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
    case IOG_ITEM_UNIT_BYTES:
    case IOG_ITEM_UNIT_BITS:
    case IOG_ITEM_UNIT_CALC_FRAMES:
    case IOG_ITEM_UNIT_CALC_FIELDS:
        if (value == 0.0 && (graph_ && graph_->lineStyle() == QCPGraph::lsNone)) {
            result = false;
        }
        else {
            result = true;
        }
        break;

    case IOG_ITEM_UNIT_CALC_SUM:
    case IOG_ITEM_UNIT_CALC_MAX:
    case IOG_ITEM_UNIT_CALC_MIN:
    case IOG_ITEM_UNIT_CALC_AVERAGE:
    case IOG_ITEM_UNIT_CALC_LOAD:
    case IOG_ITEM_UNIT_CALC_THROUGHPUT:
        if (item->fields) {
            result = true;
        }
        break;

    default:
        result = true;
        break;
    }

    return result;
}

void IOGraph::setInterval(int interval)
{
    interval_ = interval;
    if (bars_) {
        bars_->setWidth(interval_ / SCALE_F);
    }
}

// Get the value at the given interval (idx) for the current value unit.
double IOGraph::getItemValue(int idx, const capture_file* cap_file) const
{
    ws_assert(idx < max_io_items_);

    return get_io_graph_item(&items_[0], val_units_, idx, hf_index_, cap_file, interval_, cur_idx_, asAOT_);
}

// "tap_reset" callback for register_tap_listener
void IOGraph::tapReset(void* iog_ptr)
{
    IOGraph* iog = static_cast<IOGraph*>(iog_ptr);
    if (!iog) return;

    //    qDebug() << "=tapReset" << iog->name_;
    iog->clearAllData();
}

// "tap_packet" callback for register_tap_listener
tap_packet_status IOGraph::tapPacket(void* iog_ptr, packet_info* pinfo, epan_dissect_t* edt, const void*, tap_flags_t)
{
    IOGraph* iog = static_cast<IOGraph*>(iog_ptr);
    if (!pinfo || !iog) {
        return TAP_PACKET_DONT_REDRAW;
    }

    int64_t tmp_idx = get_io_graph_index(pinfo, iog->interval_);
    bool recalc = false;

    /* some sanity checks */
    if ((tmp_idx < 0) || (tmp_idx >= max_io_items_)) {
        iog->cur_idx_ = (int)iog->items_.size() - 1;
        return TAP_PACKET_DONT_REDRAW;
    }

    int idx = (int)tmp_idx;
    /* If the graph isn't visible, don't do the work or redraw, but mark
     * the graph in need of a retap if it is ever enabled. The alternative
     * is to do the work, but clear pending retaps when the taps are reset
     * (which indicates something else triggered a retap.) The tradeoff would
     * be more calculation and memory usage when a graph is disabled in
     * exchange for fewer scenarios that involve retaps when toggling the
     * enabled/disabled taps.
     */
    if (!iog->visible()) {
        if (idx > iog->cur_idx_) {
            iog->need_retap_ = true;
        }
        return TAP_PACKET_DONT_REDRAW;
    }

    if ((size_t)idx >= iog->items_.size()) {
        const size_t old_size = iog->items_.size();
        size_t new_size;
        if (old_size == 0) {
            new_size = 1024;
        }
        else {
            new_size = MIN((old_size * 3) / 2, max_io_items_);
        }
        new_size = MAX(new_size, (size_t)idx + 1);
        try {
            iog->items_.resize(new_size);
        }
        catch (std::bad_alloc&) {
            // std::vector.resize() has strong exception safety
            ws_warning("Failed memory allocation!");
            return TAP_PACKET_DONT_REDRAW;
        }
        // resize zero-initializes new items, which is what we want
        //reset_io_graph_items(&iog->items_[old_size], new_size - old_size);
    }

    /* update num_items */
    if (idx > iog->cur_idx_) {
        iog->cur_idx_ = idx;
        recalc = true;
    }

    /* set start time */
    if (nstime_is_zero(&iog->start_time_)) {
        nstime_delta(&iog->start_time_, &pinfo->abs_ts, &pinfo->rel_ts);
    }

    epan_dissect_t* adv_edt = NULL;
    /* For ADVANCED mode we need to keep track of some more stuff than just frame and byte counts */
    if (iog->val_units_ >= IOG_ITEM_UNIT_CALC_SUM) {
        adv_edt = edt;
    }

    if (!update_io_graph_item(&iog->items_[0], idx, pinfo, adv_edt, iog->hf_index_, iog->val_units_, iog->interval_)) {
        return TAP_PACKET_DONT_REDRAW;
    }

    //    qDebug() << "=tapPacket" << iog->name_ << idx << iog->hf_index_ << iog->val_units_ << iog->num_items_;

    if (recalc) {
        emit iog->requestRecalc();
    }
    return TAP_PACKET_REDRAW;
}

// "tap_draw" callback for register_tap_listener
void IOGraph::tapDraw(void* iog_ptr)
{
    IOGraph* iog = static_cast<IOGraph*>(iog_ptr);
    if (!iog) return;
    emit iog->requestRecalc();

    if (iog->graph_) {
        //        qDebug() << "=tapDraw g" << iog->name_ << iog->graph_->data()->keys().size();
    }
    if (iog->bars_) {
        //        qDebug() << "=tapDraw b" << iog->name_ << iog->bars_->data()->keys().size();
    }
}
