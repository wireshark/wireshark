/* response_time_delay_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "response_time_delay_dialog.h"

#include "file.h"

#include "epan/proto.h"
#include "epan/rtd_table.h"

#include <QTreeWidget>

#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"

static QHash<const QString, register_rtd_t *> cfg_str_to_rtd_;

extern "C" {
static bool
rtd_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    if (args_l.length() > 1) {
        QString rtd = QStringLiteral("%1,%2").arg(args_l[0]).arg(args_l[1]);
        QString filter;
        if (args_l.length() > 2) {
            filter = QStringList(args_l.mid(2)).join(",");
        }
        mainApp->emitTapParameterSignal(rtd, filter, NULL);
    }

    return true;
}
}

bool register_response_time_delay_tables(const void *, void *value, void*)
{
    register_rtd_t *rtd = (register_rtd_t*)value;
    const char* short_name = proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd)));
    char *cfg_abbr = rtd_table_get_tap_string(rtd);

    cfg_str_to_rtd_[cfg_abbr] = rtd;
    TapParameterDialog::registerDialog(
                short_name,
                cfg_abbr,
                REGISTER_STAT_GROUP_RESPONSE_TIME,
                rtd_init,
                ResponseTimeDelayDialog::createRtdDialog);
    g_free(cfg_abbr);
    return false;
}

enum {
    col_type_,
    col_messages_,
    col_min_srt_,
    col_max_srt_,
    col_avg_srt_,
    col_min_frame_,
    col_max_frame_,
    col_open_requests,
    col_discarded_responses_,
    col_repeated_requests_,
    col_repeated_responses_
};

enum {
    rtd_table_type_ = 1000,
    rtd_time_stat_type_
};

class RtdTimeStatTreeWidgetItem : public QTreeWidgetItem
{
public:
    RtdTimeStatTreeWidgetItem(QTreeWidget *parent, const QString type, const rtd_timestat *rtd_timestat, unsigned timestat_idx = 0) :
        QTreeWidgetItem (parent, rtd_time_stat_type_),
        type_(type),
        rtd_timestat_(rtd_timestat)
    {
        Q_ASSERT(timestat_idx < rtd_timestat->num_timestat);
        timestat_ = &rtd_timestat->rtd[timestat_idx];
        setText(col_type_, type_);
        setHidden(true);
    }
    void draw() {
        setText(col_messages_, QString::number(timestat_->num));
        setText(col_min_srt_, QString::number(nstime_to_sec(&timestat_->min), 'f', 6));
        setText(col_max_srt_, QString::number(nstime_to_sec(&timestat_->max), 'f', 6));
        setText(col_avg_srt_, QString::number(get_average(&timestat_->tot, timestat_->num) / 1000.0, 'f', 6));
        setText(col_min_frame_, QString::number(timestat_->min_num));
        setText(col_max_frame_, QString::number(timestat_->max_num));
        setText(col_open_requests, QString::number(rtd_timestat_->open_req_num));
        setText(col_discarded_responses_, QString::number(rtd_timestat_->disc_rsp_num));
        setText(col_repeated_requests_, QString::number(rtd_timestat_->req_dup_num));
        setText(col_repeated_responses_, QString::number(rtd_timestat_->rsp_dup_num));

        setHidden(timestat_->num < 1);
    }
    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != rtd_time_stat_type_) return QTreeWidgetItem::operator< (other);
        const RtdTimeStatTreeWidgetItem *other_row = static_cast<const RtdTimeStatTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case col_messages_:
            return timestat_->num < other_row->timestat_->num;
        case col_min_srt_:
            return nstime_cmp(&timestat_->min, &other_row->timestat_->min) < 0;
        case col_max_srt_:
            return nstime_cmp(&timestat_->max, &other_row->timestat_->max) < 0;
        case col_avg_srt_:
        {
            double our_avg = get_average(&timestat_->tot, timestat_->num);
            double other_avg = get_average(&other_row->timestat_->tot, other_row->timestat_->num);
            return our_avg < other_avg;
        }
        case col_min_frame_:
            return timestat_->min_num < other_row->timestat_->min_num;
        case col_max_frame_:
            return timestat_->max_num < other_row->timestat_->max_num;
        case col_open_requests:
            return rtd_timestat_->open_req_num < other_row->rtd_timestat_->open_req_num;
        case col_discarded_responses_:
            return rtd_timestat_->disc_rsp_num < other_row->rtd_timestat_->disc_rsp_num;
        case col_repeated_requests_:
            return rtd_timestat_->req_dup_num < other_row->rtd_timestat_->req_dup_num;
        case col_repeated_responses_:
            return rtd_timestat_->rsp_dup_num < other_row->rtd_timestat_->rsp_dup_num;
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }
    QList<QVariant> rowData() {
        return QList<QVariant>() << type_ << timestat_->num
                                 << nstime_to_sec(&timestat_->min) << nstime_to_sec(&timestat_->max)
                                 << get_average(&timestat_->tot, timestat_->num) / 1000.0
                                 << timestat_->min_num << timestat_->max_num
                                 << rtd_timestat_->open_req_num << rtd_timestat_->disc_rsp_num
                                 << rtd_timestat_->req_dup_num << rtd_timestat_->rsp_dup_num;
    }

private:
    const QString type_;
    const rtd_timestat *rtd_timestat_;
    const timestat_t *timestat_;
};

ResponseTimeDelayDialog::ResponseTimeDelayDialog(QWidget &parent, CaptureFile &cf, register_rtd *rtd, const QString filter, int help_topic) :
    TapParameterDialog(parent, cf, help_topic),
    rtd_(rtd)
{
    QString subtitle = tr("%1 Response Time Delay Statistics")
            .arg(proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd))));
    setWindowSubtitle(subtitle);
    loadGeometry(0, 0, "ResponseTimeDelayDialog");

    QStringList header_names = QStringList()
            << tr("Type") << tr("Messages")
            << tr("Min SRT") << tr("Max SRT") << tr("Avg SRT")
            << tr("Min in Frame") << tr("Max in Frame")
            << tr("Open Requests") << tr("Discarded Responses")
            << tr("Repeated Requests") << tr("Repeated Responses");

    statsTreeWidget()->setHeaderLabels(header_names);

    for (int col = 0; col < statsTreeWidget()->columnCount(); col++) {
        if (col == col_type_) continue;
        statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
    }

    if (!filter.isEmpty()) {
        setDisplayFilter(filter);
    }
}

TapParameterDialog *ResponseTimeDelayDialog::createRtdDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf)
{
    if (!cfg_str_to_rtd_.contains(cfg_str)) {
        // XXX MessageBox?
        return NULL;
    }

    register_rtd_t *rtd = cfg_str_to_rtd_[cfg_str];

    return new ResponseTimeDelayDialog(parent, cf, rtd, filter);
}

void ResponseTimeDelayDialog::addRtdTable(const _rtd_stat_table *rtd_table)
{
    // There are two types of rtd_stat_tables - those with num_rtds == 1 and
    // num_timestat > 1 on that rtd_timestat, and those with num_rtds > 1 and
    // num_timestat == 1 on each rtd_timestat.
    //
    // XXX - Both MEGACO and MGCP have one row that is a total for all types,
    // so it might make sense for that row to be the parent of the others.
    // But in MGCP the "Overall" type has index 0, whereas in MEGACO the
    // "ALL" types has the last index, 10. They should both be the first or
    // the last.
    if (rtd_table->num_rtds == 1) {
        for (unsigned i = 0; i < rtd_table->time_stats[0].num_timestat; i++) {
            const QString type = val_to_qstring(i, get_rtd_value_string(rtd_), "Other (%d)");
            new RtdTimeStatTreeWidgetItem(statsTreeWidget(), type, &rtd_table->time_stats[0], i);
        }
    } else {
        for (unsigned i = 0; i < rtd_table->num_rtds; i++) {
            const QString type = val_to_qstring(i, get_rtd_value_string(rtd_), "Other (%d)");
            new RtdTimeStatTreeWidgetItem(statsTreeWidget(), type, &rtd_table->time_stats[i]);
        }
    }
}

void ResponseTimeDelayDialog::tapReset(void *rtdd_ptr)
{
    rtd_data_t *rtdd = (rtd_data_t*) rtdd_ptr;
    ResponseTimeDelayDialog *rtd_dlg = static_cast<ResponseTimeDelayDialog *>(rtdd->user_data);
    if (!rtd_dlg) return;

    reset_rtd_table(&rtdd->stat_table);
    rtd_dlg->statsTreeWidget()->clear();
    rtd_dlg->addRtdTable(&rtdd->stat_table);
}

void ResponseTimeDelayDialog::tapDraw(void *rtdd_ptr)
{
    rtd_data_t *rtdd = (rtd_data_t*) rtdd_ptr;
    ResponseTimeDelayDialog *rtd_dlg = static_cast<ResponseTimeDelayDialog *>(rtdd->user_data);
    if (!rtd_dlg || !rtd_dlg->statsTreeWidget()) return;

    QTreeWidgetItemIterator it(rtd_dlg->statsTreeWidget());
    while (*it) {
        if ((*it)->type() == rtd_time_stat_type_) {
            RtdTimeStatTreeWidgetItem *rtd_ts_ti = static_cast<RtdTimeStatTreeWidgetItem *>((*it));
            rtd_ts_ti->draw();
        }
        ++it;
    }

    for (int i = 0; i < rtd_dlg->statsTreeWidget()->columnCount() - 1; i++) {
        rtd_dlg->statsTreeWidget()->resizeColumnToContents(i);
    }
}

void ResponseTimeDelayDialog::fillTree()
{
    rtd_data_t rtd_data;
    memset (&rtd_data, 0, sizeof(rtd_data));
    rtd_table_dissector_init(rtd_, &rtd_data.stat_table, NULL, NULL);
    rtd_data.user_data = this;

    QByteArray display_filter = displayFilter().toUtf8();
    if (!registerTapListener(get_rtd_tap_listener_name(rtd_),
                          &rtd_data,
                          display_filter.constData(),
                          0,
                          tapReset,
                          get_rtd_packet_func(rtd_),
                          tapDraw)) {
        free_rtd_table(&rtd_data.stat_table);
        reject(); // XXX Stay open instead?
        return;
    }

    statsTreeWidget()->setSortingEnabled(false);

    cap_file_.retapPackets();

    tapDraw(&rtd_data);

    statsTreeWidget()->sortItems(col_type_, Qt::AscendingOrder);
    statsTreeWidget()->setSortingEnabled(true);

    removeTapListeners();
    free_rtd_table(&rtd_data.stat_table);
}

QList<QVariant> ResponseTimeDelayDialog::treeItemData(QTreeWidgetItem *ti) const
{
    QList<QVariant> tid;
    if (ti->type() == rtd_time_stat_type_) {
        RtdTimeStatTreeWidgetItem *rtd_ts_ti = static_cast<RtdTimeStatTreeWidgetItem *>(ti);
        tid << rtd_ts_ti->rowData();
    }
    return tid;
}
