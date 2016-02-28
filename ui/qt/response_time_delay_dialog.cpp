/* response_time_delay_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "response_time_delay_dialog.h"

#include "file.h"

#include "epan/proto.h"
#include "epan/rtd_table.h"

#include <QTreeWidget>

#include "qt_ui_utils.h"
#include "wireshark_application.h"

static QHash<const QString, register_rtd_t *> cfg_str_to_rtd_;

extern "C" {
static void
rtd_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    if (args_l.length() > 1) {
        QString rtd = QString("%1,%2").arg(args_l[0]).arg(args_l[1]);
        QString filter;
        if (args_l.length() > 2) {
            filter = QStringList(args_l.mid(2)).join(",");
        }
        wsApp->emitTapParameterSignal(rtd, filter, NULL);
    }
}
}

void register_response_time_delay_tables(gpointer data, gpointer)
{
    register_rtd_t *rtd = (register_rtd_t*)data;
    const char* short_name = proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd)));
    const char *cfg_abbr = rtd_table_get_tap_string(rtd);

    cfg_str_to_rtd_[cfg_abbr] = rtd;
    TapParameterDialog::registerDialog(
                short_name,
                cfg_abbr,
                REGISTER_STAT_GROUP_RESPONSE_TIME,
                rtd_init,
                ResponseTimeDelayDialog::createRtdDialog);
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
    col_discarded_reponses_,
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
    RtdTimeStatTreeWidgetItem(QTreeWidget *parent, const QString type, const rtd_timestat *timestat) :
        QTreeWidgetItem (parent, rtd_time_stat_type_),
        type_(type),
        timestat_(timestat)
    {
        setText(col_type_, type_);
        setHidden(true);
    }
    void draw() {
        setText(col_messages_, QString::number(timestat_->rtd->num));
        setText(col_min_srt_, QString::number(nstime_to_sec(&timestat_->rtd->min), 'f', 6));
        setText(col_max_srt_, QString::number(nstime_to_sec(&timestat_->rtd->max), 'f', 6));
        setText(col_avg_srt_, QString::number(get_average(&timestat_->rtd->tot, timestat_->rtd->num) / 1000.0, 'f', 6));
        setText(col_min_frame_, QString::number(timestat_->rtd->min_num));
        setText(col_max_frame_, QString::number(timestat_->rtd->max_num));
        setText(col_open_requests, QString::number(timestat_->open_req_num));
        setText(col_discarded_reponses_, QString::number(timestat_->disc_rsp_num));
        setText(col_repeated_requests_, QString::number(timestat_->req_dup_num));
        setText(col_repeated_responses_, QString::number(timestat_->rsp_dup_num));

        setHidden(timestat_->rtd->num < 1);
    }
    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != rtd_time_stat_type_) return QTreeWidgetItem::operator< (other);
        const RtdTimeStatTreeWidgetItem *other_row = static_cast<const RtdTimeStatTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case col_messages_:
            return timestat_->rtd->num < other_row->timestat_->rtd->num;
        case col_min_srt_:
            return nstime_cmp(&timestat_->rtd->min, &other_row->timestat_->rtd->min) < 0;
        case col_max_srt_:
            return nstime_cmp(&timestat_->rtd->max, &other_row->timestat_->rtd->max) < 0;
        case col_avg_srt_:
        {
            double our_avg = get_average(&timestat_->rtd->tot, timestat_->rtd->num);
            double other_avg = get_average(&other_row->timestat_->rtd->tot, other_row->timestat_->rtd->num);
            return our_avg < other_avg;
        }
        case col_min_frame_:
            return timestat_->rtd->min_num < other_row->timestat_->rtd->min_num;
        case col_max_frame_:
            return timestat_->rtd->max_num < other_row->timestat_->rtd->max_num;
        case col_open_requests:
            return timestat_->open_req_num < other_row->timestat_->open_req_num;
        case col_discarded_reponses_:
            return timestat_->disc_rsp_num < other_row->timestat_->disc_rsp_num;
        case col_repeated_requests_:
            return timestat_->req_dup_num < other_row->timestat_->req_dup_num;
        case col_repeated_responses_:
            return timestat_->rsp_dup_num < other_row->timestat_->rsp_dup_num;
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }
    QList<QVariant> rowData() {
        return QList<QVariant>() << type_ << timestat_->rtd->num
                                 << nstime_to_sec(&timestat_->rtd->min) << nstime_to_sec(&timestat_->rtd->max)
                                 << get_average(&timestat_->rtd->tot, timestat_->rtd->num) / 1000.0
                                 << timestat_->rtd->min_num << timestat_->rtd->max_num
                                 << timestat_->open_req_num << timestat_->disc_rsp_num
                                 << timestat_->req_dup_num << timestat_->rsp_dup_num;
    }

private:
    const QString type_;
    const rtd_timestat *timestat_;
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
    for (unsigned i = 0; i < rtd_table->num_rtds; i++) {
        const QString type = val_to_qstring(i, get_rtd_value_string(rtd_), "Other (%d)");
        new RtdTimeStatTreeWidgetItem(statsTreeWidget(), type, &rtd_table->time_stats[i]);
    }
}

void ResponseTimeDelayDialog::tapReset(void *rtdd_ptr)
{
    rtd_data_t *rtdd = (rtd_data_t*) rtdd_ptr;
    ResponseTimeDelayDialog *rtd_dlg = static_cast<ResponseTimeDelayDialog *>(rtdd->user_data);
    if (!rtd_dlg) return;

    reset_rtd_table(&rtdd->stat_table, NULL, NULL);
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
        free_rtd_table(&rtd_data.stat_table, NULL, NULL);
        reject(); // XXX Stay open instead?
        return;
    }

    statsTreeWidget()->setSortingEnabled(false);

    cap_file_.retapPackets();

    tapDraw(&rtd_data);

    statsTreeWidget()->sortItems(col_type_, Qt::AscendingOrder);
    statsTreeWidget()->setSortingEnabled(true);

    removeTapListeners();
    free_rtd_table(&rtd_data.stat_table, NULL, NULL);
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
