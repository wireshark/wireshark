/* multicast_statistics_dialog.cpp
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

#include "multicast_statistics_dialog.h"

#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>

#include "qt_ui_utils.h"
#include "syntax_line_edit.h"
#include "wireshark_application.h"

enum {
    col_src_addr_,
    col_src_port_,
    col_dst_addr_,
    col_dst_port_,
    col_packets_,
    col_packets_s_,
    col_avg_bw_,
    col_max_bw_,
    col_max_burst_,
    col_burst_alarms_,
    col_max_buffers_,
    col_buffer_alarms_
};

enum {
    mcast_table_type_ = 1000
};

class MulticastStatTreeWidgetItem : public QTreeWidgetItem
{
public:
    MulticastStatTreeWidgetItem(QTreeWidget *parent) :
        QTreeWidgetItem (parent, mcast_table_type_)
    {
        clear_address(&src_addr_);
        clear_address(&dst_addr_);
        src_port_ = 0;
        dst_port_ = 0;
        num_packets_ = 0;
        avg_pps_ = 0;
        avg_bw_ = 0;
        max_bw_ = 0;
        top_burst_size_ = 0;
        num_bursts_ = 0;
        top_buff_usage_ = 0;
        num_buff_alarms_ = 0;
    }

    void updateStreamInfo(const mcast_stream_info_t *stream_info) {
        copy_address(&src_addr_, &stream_info->src_addr);
        src_port_ = stream_info->src_port;
        copy_address(&dst_addr_, &stream_info->dest_addr);
        dst_port_ = stream_info->dest_port;
        num_packets_ = stream_info->npackets;
        avg_pps_ = stream_info->apackets;
        avg_bw_ = stream_info->average_bw;
        max_bw_ = stream_info->element.maxbw;
        top_burst_size_ = stream_info->element.topburstsize;
        num_bursts_ = stream_info->element.numbursts;
        top_buff_usage_ = stream_info->element.topbuffusage;
        num_buff_alarms_ = stream_info->element.numbuffalarms;

        draw();
    }

    void draw() {
        setText(col_src_addr_, address_to_qstring(&src_addr_));
        setText(col_src_port_, QString::number(src_port_));
        setText(col_dst_addr_, address_to_qstring(&dst_addr_));
        setText(col_dst_port_, QString::number(dst_port_));
        setText(col_packets_, QString::number(num_packets_));
        setText(col_packets_s_, QString::number(avg_pps_, 'f', 2));
        setText(col_avg_bw_, bits_s_to_qstring(avg_bw_));
        setText(col_max_bw_, bits_s_to_qstring(max_bw_));
        setText(col_max_burst_, QString("%1 / %2ms").arg(top_burst_size_).arg(mcast_stream_burstint));
        setText(col_burst_alarms_, QString::number(num_bursts_));
        setText(col_max_buffers_, bits_s_to_qstring(top_buff_usage_));
        setText(col_buffer_alarms_, QString::number(num_buff_alarms_));
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != mcast_table_type_) return QTreeWidgetItem::operator< (other);
        const MulticastStatTreeWidgetItem *other_row = static_cast<const MulticastStatTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case col_src_addr_:
            return cmp_address(&src_addr_, &other_row->src_addr_) < 0;
        case col_src_port_:
            return src_port_ < other_row->src_port_;
        case col_dst_addr_:
            return cmp_address(&dst_addr_, &other_row->dst_addr_) < 0;
        case col_dst_port_:
            return dst_port_ < other_row->dst_port_;
        case col_packets_:
            return num_packets_ < other_row->num_packets_;
        case col_packets_s_:
            return avg_pps_ < other_row->avg_pps_;
        case col_avg_bw_:
            return avg_bw_ < other_row->avg_bw_;
        case col_max_bw_:
            return max_bw_ < other_row->max_bw_;
        case col_max_burst_:
            return top_burst_size_ < other_row->top_burst_size_;
        case col_burst_alarms_:
            return num_bursts_ < other_row->num_bursts_;
        case col_max_buffers_:
            return top_buff_usage_ < other_row->top_buff_usage_;
        case col_buffer_alarms_:
            return num_buff_alarms_ < other_row->num_buff_alarms_;
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }
    QList<QVariant> rowData() {
        return QList<QVariant>()
                << address_to_qstring(&src_addr_) << src_port_
                << address_to_qstring(&dst_addr_) << dst_port_
                << num_packets_ << avg_pps_
                << avg_bw_ << max_bw_
                << top_burst_size_ << num_bursts_
                << top_buff_usage_ << num_buff_alarms_;
    }
    const QString filterExpression() {
        QString ip_version;

        if (src_addr_.type == AT_IPv6) ip_version = "v6";

        const QString filter_expr = QString("(ip%1.src==%2 && udp.srcport==%3 && ip%1.dst==%4 && udp.dstport==%5)")
                .arg(ip_version)
                .arg(address_to_qstring(&src_addr_))
                .arg(src_port_)
                .arg(address_to_qstring(&dst_addr_))
                .arg(dst_port_);
        return filter_expr;
    }

private:
    address src_addr_;
    guint16 src_port_;
    address dst_addr_;
    guint16 dst_port_;
    unsigned num_packets_;
    double avg_pps_;
    double avg_bw_;
    double max_bw_;
    int top_burst_size_;
    int num_bursts_;
    int top_buff_usage_;
    int num_buff_alarms_;
};

MulticastStatisticsDialog::MulticastStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter) :
    TapParameterDialog(parent, cf)
{
    setWindowSubtitle(tr("UDP Multicast Streams"));
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4, "MulticastStatisticsDialog");

    tapinfo_ = new mcaststream_tapinfo_t();
    tapinfo_->user_data = this;
    tapinfo_->tap_reset = tapReset;
    tapinfo_->tap_draw = tapDraw;

    QStringList header_names = QStringList()
            << tr("Source Address") << tr("Source Port")
            << tr("Destination Address") << tr("Destination Port")
            << tr("Packets") << tr("Packets/s")
            << tr("Avg BW (bps)") << tr("Max BW (bps)")
            << tr("Max Burst") << tr("Burst Alarms")
            << tr("Max Buffers (B)") << tr("Buffer Alarms");

    statsTreeWidget()->setHeaderLabels(header_names);

    for (int col = 0; col < statsTreeWidget()->columnCount(); col++) {
        if (col == col_src_addr_ || col == col_dst_addr_) continue;
        statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
    }

    burst_measurement_interval_le_ = new SyntaxLineEdit(this);
    burst_alarm_threshold_le_ = new SyntaxLineEdit(this);
    buffer_alarm_threshold_le_ = new SyntaxLineEdit(this);
    stream_empty_speed_le_ = new SyntaxLineEdit(this);
    total_empty_speed_le_ = new SyntaxLineEdit(this);

    int filter_layout_idx = verticalLayout()->indexOf(filterLayout()->widget());
    QGridLayout *param_grid = new QGridLayout();
    int one_em = fontMetrics().height();
    verticalLayout()->insertLayout(filter_layout_idx, param_grid);

    // Label | LineEdit | | Label | LineEdit | | Label | LineEdit
    // 0       1         2  3       4         5  6       7
    param_grid->setColumnMinimumWidth(2, one_em * 2);
    param_grid->setColumnStretch(2, 1);
    param_grid->setColumnMinimumWidth(5, one_em * 2);
    param_grid->setColumnStretch(5, 1);
    param_grid->addWidget(new QLabel(tr("Burst measurement interval (ms):")), 0, 0, Qt::AlignRight);
    param_grid->addWidget(burst_measurement_interval_le_, 0, 1);
    param_grid->addWidget(new QLabel(tr("Burst alarm threshold (packets):")), 0, 3, Qt::AlignRight);
    param_grid->addWidget(burst_alarm_threshold_le_, 0, 4);
    param_grid->addWidget(new QLabel(tr("Buffer alarm threshold (B):")), 0, 6, Qt::AlignRight);
    param_grid->addWidget(buffer_alarm_threshold_le_, 0, 7);

    param_grid->addWidget(new QLabel(tr("Stream empty speed (Kb/s):")), 1, 0, Qt::AlignRight);
    param_grid->addWidget(stream_empty_speed_le_, 1, 1);
    param_grid->addWidget(new QLabel(tr("Total empty speed (Kb/s):")), 1, 3, Qt::AlignRight);
    param_grid->addWidget(total_empty_speed_le_, 1, 4);

    burst_measurement_interval_le_->setText(QString::number(mcast_stream_burstint));
    burst_alarm_threshold_le_->setText(QString::number(mcast_stream_trigger));
    buffer_alarm_threshold_le_->setText(QString::number(mcast_stream_bufferalarm));
    stream_empty_speed_le_->setText(QString::number(mcast_stream_emptyspeed));
    total_empty_speed_le_->setText(QString::number(mcast_stream_cumulemptyspeed));

    line_edits_ = QList<QWidget *>()
            << burst_measurement_interval_le_ << burst_alarm_threshold_le_
            << buffer_alarm_threshold_le_ << stream_empty_speed_le_
            << total_empty_speed_le_;

    foreach (QWidget *line_edit, line_edits_) {
        line_edit->setMinimumWidth(one_em * 5);
        connect(line_edit, SIGNAL(textEdited(QString)), this, SLOT(updateWidgets()));
    }

    addFilterActions();

    if (filter) {
        setDisplayFilter(filter);
    }

    connect(this, SIGNAL(updateFilter(QString)),
            this, SLOT(updateMulticastParameters()));

    connect(&cap_file_, SIGNAL(captureFileClosing()),
            this, SLOT(captureFileClosing()));

    /* Register the tap listener */
    register_tap_listener_mcast_stream(tapinfo_);

    updateWidgets();
}

MulticastStatisticsDialog::~MulticastStatisticsDialog()
{
    /* Remove the stream tap listener */
    remove_tap_listener_mcast_stream(tapinfo_);

    /* Clean up memory used by stream tap */
    mcaststream_reset(tapinfo_);

    delete tapinfo_;
}

void MulticastStatisticsDialog::tapReset(mcaststream_tapinfo_t *tapinfo)
{
    MulticastStatisticsDialog *ms_dlg = dynamic_cast<MulticastStatisticsDialog *>((MulticastStatisticsDialog*)tapinfo->user_data);
    if (!ms_dlg || !ms_dlg->statsTreeWidget()) return;

    ms_dlg->statsTreeWidget()->clear();
}

void MulticastStatisticsDialog::tapDraw(mcaststream_tapinfo_t *tapinfo)
{
    MulticastStatisticsDialog *ms_dlg = dynamic_cast<MulticastStatisticsDialog *>((MulticastStatisticsDialog*)tapinfo->user_data);
    if (!ms_dlg || !ms_dlg->statsTreeWidget()) return;

    // Add missing rows and update stats
    int cur_row = 0;
    for (GList *cur = g_list_first(tapinfo->strinfo_list); cur; cur = g_list_next(cur)) {
        mcast_stream_info_t *stream_info = (mcast_stream_info_t *) cur->data;
        if (!stream_info) continue;

        MulticastStatTreeWidgetItem *ms_ti;
        QTreeWidgetItem *ti = ms_dlg->statsTreeWidget()->topLevelItem(cur_row);
        if (!ti) {
            ms_ti = new MulticastStatTreeWidgetItem(ms_dlg->statsTreeWidget());
            for (int col = 0; col < ms_dlg->statsTreeWidget()->columnCount(); col++) {
                if (col == col_src_addr_ || col == col_dst_addr_) continue;
                ms_ti->setTextAlignment(col, Qt::AlignRight);
            }
        } else {
            ms_ti = static_cast<MulticastStatTreeWidgetItem *>(ti);
        }

        ms_ti->updateStreamInfo(stream_info);
        cur_row++;
    }
}

const QString MulticastStatisticsDialog::filterExpression()
{
    QString filter_expr;
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];

        MulticastStatTreeWidgetItem *ms_ti = static_cast<MulticastStatTreeWidgetItem *>(ti);
        filter_expr = ms_ti->filterExpression();
    }
    return filter_expr;
}

void MulticastStatisticsDialog::updateWidgets()
{
    QString hint;
    bool enable_apply = true;
    bool enable_edits = cap_file_.isValid();
    bool ok = false;
    int param;

    param = burst_measurement_interval_le_->text().toUInt(&ok);
    if (!ok || param < 1 || param > 1000) {
        hint += tr("The burst interval must be between 1 and 1000. ");
        enable_apply = false;
        burst_measurement_interval_le_->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        burst_measurement_interval_le_->setSyntaxState(SyntaxLineEdit::Valid);
    }

    param = burst_alarm_threshold_le_->text().toInt(&ok);
    if (!ok || param < 1) {
        hint += tr("The burst alarm threshold isn't valid. ");
        enable_apply = false;
        burst_alarm_threshold_le_->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        burst_alarm_threshold_le_->setSyntaxState(SyntaxLineEdit::Valid);
    }

    param = buffer_alarm_threshold_le_->text().toInt(&ok);
    if (!ok || param < 1) {
        hint += tr("The buffer alarm threshold isn't valid. ");
        enable_apply = false;
        buffer_alarm_threshold_le_->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        buffer_alarm_threshold_le_->setSyntaxState(SyntaxLineEdit::Valid);
    }

    param = stream_empty_speed_le_->text().toInt(&ok);
    if (!ok || param < 1 || param > 10000000) {
        hint += tr("The stream empty speed should be between 1 and 10000000. ");
        enable_apply = false;
        stream_empty_speed_le_->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        stream_empty_speed_le_->setSyntaxState(SyntaxLineEdit::Valid);
    }

    param = total_empty_speed_le_->text().toInt(&ok);
    if (!ok || param < 1 || param > 10000000) {
        hint += tr("The total empty speed should be between 1 and 10000000. ");
        enable_apply = false;
        total_empty_speed_le_->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        total_empty_speed_le_->setSyntaxState(SyntaxLineEdit::Valid);
    }

    foreach (QWidget *line_edit, line_edits_) {
        line_edit->setEnabled(enable_edits);
    }

    applyFilterButton()->setEnabled(enable_apply);

    if (hint.isEmpty() && tapinfo_->allstreams) {
        const QString stats = tr("%1 streams, avg bw: %2bps, max bw: %3bps, max burst: %4 / %5ms, max buffer: %6B")
                .arg(statsTreeWidget()->topLevelItemCount())
                .arg(bits_s_to_qstring(tapinfo_->allstreams->average_bw))
                .arg(bits_s_to_qstring(tapinfo_->allstreams->element.maxbw))
                .arg(tapinfo_->allstreams->element.topburstsize)
                .arg(mcast_stream_burstint)
                .arg(bits_s_to_qstring(tapinfo_->allstreams->element.topbuffusage));
        hint.append(stats);
    }
    hint.prepend("<small><i>");
    hint.append("</i></small>");
    setHint(hint);
    TapParameterDialog::updateWidgets();
}

void MulticastStatisticsDialog::updateMulticastParameters()
{
    bool ok = false;
    int param;

    param = burst_measurement_interval_le_->text().toUInt(&ok);
    if (ok && param > 0 && param <= 1000) {
        mcast_stream_burstint = (guint16) param;
    }

    param = burst_alarm_threshold_le_->text().toInt(&ok);
    if (ok) {
        mcast_stream_trigger = param;
    }

    param = buffer_alarm_threshold_le_->text().toInt(&ok);
    if (ok && param > 0) {
        mcast_stream_bufferalarm = param;
    }

    param = stream_empty_speed_le_->text().toInt(&ok);
    if (ok && param > 0 && param <= 10000000) {
        mcast_stream_emptyspeed = param;
    }

    param = total_empty_speed_le_->text().toInt(&ok);
    if (ok && param > 0 && param <= 10000000) {
        mcast_stream_cumulemptyspeed = param;
    }
}

void MulticastStatisticsDialog::fillTree()
{
    QList<QWidget *> disable_widgets = QList<QWidget *>()
            << line_edits_ << displayFilterLineEdit() << applyFilterButton();

    foreach (QWidget *w, disable_widgets) w->setEnabled(false);

    /* Scan for Mcast streams (redissect all packets) */
    mcaststream_scan(tapinfo_, cap_file_.capFile());
    tapDraw(tapinfo_);

    foreach (QWidget *w, disable_widgets) w->setEnabled(true);
    for (int col = 0; col < statsTreeWidget()->columnCount() - 1; col++) {
        statsTreeWidget()->resizeColumnToContents(col);
    }
    updateWidgets();
}

void MulticastStatisticsDialog::captureFileClosing()
{
    /* Remove the stream tap listener */
    remove_tap_listener_mcast_stream(tapinfo_);

    updateWidgets();
    WiresharkDialog::captureFileClosing();
}

// Stat command + args

static void
multicast_statistics_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    QByteArray filter;
    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    wsApp->emitStatCommandSignal("MulticastStatistics", filter.constData(), NULL);
}

static stat_tap_ui multicast_statistics_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "multicast,stat",
    multicast_statistics_init,
    0,
    NULL
};

extern "C" {
void
register_tap_listener_qt_multicast_statistics(void)
{
    register_stat_tap_ui(&multicast_statistics_ui, NULL);
}
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
