/* rtp_stream_dialog.cpp
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

#include "rtp_stream_dialog.h"
#include <ui_rtp_stream_dialog.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include <epan/rtp_pt.h>

#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"
#include "rtp_analysis_dialog.h"
#include "wireshark_application.h"

#include <QAction>
#include <QClipboard>
#include <QFileDialog>
#include <QKeyEvent>
#include <QPushButton>
#include <QTextStream>
#include <QTreeWidgetItem>
#include <QTreeWidgetItemIterator>

#include "tango_colors.h"

/*
 * @file RTP stream dialog
 *
 * Displays a list of RTP streams with the following information:
 * - UDP 4-tuple
 * - SSRC
 * - Payload type
 * - Stats: Packets, lost, max delta, max jitter, mean jitter
 * - Problems
 *
 * Finds reverse streams
 * "Save As" rtpdump
 * Mark packets
 * Go to the setup frame
 * Prepare filter
 * Copy As CSV and YAML
 * Analyze
 */

// To do:
// - Add more statistics to the hint text (e.g. lost packets).
// - Add more statistics to the main list (e.g. stream duration)

const int src_addr_col_    =  0;
const int src_port_col_    =  1;
const int dst_addr_col_    =  2;
const int dst_port_col_    =  3;
const int ssrc_col_        =  4;
const int payload_col_     =  5;
const int packets_col_     =  6;
const int lost_col_        =  7;
const int max_delta_col_   =  8;
const int max_jitter_col_  =  9;
const int mean_jitter_col_ = 10;
const int status_col_      = 11;

enum { rtp_stream_type_ = 1000 };

class RtpStreamTreeWidgetItem : public QTreeWidgetItem
{
public:
    RtpStreamTreeWidgetItem(QTreeWidget *tree, rtp_stream_info_t *stream_info) :
        QTreeWidgetItem(tree, rtp_stream_type_),
        stream_info_(stream_info)
    {
        drawData();
    }

    rtp_stream_info_t *streamInfo() const { return stream_info_; }

    void drawData() {
        if (!stream_info_) {
            return;
        }
        setText(src_addr_col_, address_to_display_qstring(&stream_info_->src_addr));
        setText(src_port_col_, QString::number(stream_info_->src_port));
        setText(dst_addr_col_, address_to_display_qstring(&stream_info_->dest_addr));
        setText(dst_port_col_, QString::number(stream_info_->dest_port));
        setText(ssrc_col_, QString("0x%1").arg(stream_info_->ssrc, 0, 16));

        if (stream_info_->payload_type_name != NULL) {
            setText(payload_col_, stream_info_->payload_type_name);
        } else {
            setText(payload_col_, val_ext_to_qstring(stream_info_->payload_type,
                                                 &rtp_payload_type_short_vals_ext,
                                                 "Unknown (%u)"));
        }

        setText(packets_col_, QString::number(stream_info_->packet_count));

        guint32 expected;
        double pct_loss;
        expected = (stream_info_->rtp_stats.stop_seq_nr + stream_info_->rtp_stats.cycles*65536)
            - stream_info_->rtp_stats.start_seq_nr + 1;
        lost_ = expected - stream_info_->rtp_stats.total_nr;
        if (expected) {
            pct_loss = (double)(lost_*100.0)/(double)expected;
        } else {
            pct_loss = 0;
        }

        setText(lost_col_, QObject::tr("%1 (%L2%)").arg(lost_).arg(QString::number(pct_loss, 'f', 1)));
        setText(max_delta_col_, QString::number(stream_info_->rtp_stats.max_delta, 'f', 3)); // This is RTP. Do we need nanoseconds?
        setText(max_jitter_col_, QString::number(stream_info_->rtp_stats.max_jitter, 'f', 3));
        setText(mean_jitter_col_, QString::number(stream_info_->rtp_stats.mean_jitter, 'f', 3));

        if (stream_info_->problem) {
            setText(status_col_, UTF8_BULLET);
            setTextAlignment(status_col_, Qt::AlignCenter);
            for (int i = 0; i < columnCount(); i++) {
                setBackgroundColor(i, ws_css_warn_background);
                setTextColor(i, ws_css_warn_text);
            }
        }
    }
    // Return a QString, int, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col) const {
        if (!stream_info_) {
            return QVariant();
        }

        switch(col) {
        case src_addr_col_:
        case dst_addr_col_:
        case payload_col_: // XXX Return numeric value?
            return text(col);
        case src_port_col_:
            return stream_info_->src_port;
        case dst_port_col_:
            return stream_info_->dest_port;
        case ssrc_col_:
            return stream_info_->ssrc;
        case packets_col_:
            return stream_info_->packet_count;
        case lost_col_:
            return lost_;
        case max_delta_col_:
            return stream_info_->rtp_stats.max_delta;
        case max_jitter_col_:
            return stream_info_->rtp_stats.max_jitter;
        case mean_jitter_col_:
            return stream_info_->rtp_stats.mean_jitter;
        case status_col_:
            return stream_info_->problem ? "Problem" : "";
        default:
            break;
        }
        return QVariant();
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != rtp_stream_type_) return QTreeWidgetItem::operator <(other);
        const RtpStreamTreeWidgetItem &other_rstwi = dynamic_cast<const RtpStreamTreeWidgetItem&>(other);

        switch (treeWidget()->sortColumn()) {
        case src_addr_col_:
            return cmp_address(&(stream_info_->src_addr), &(other_rstwi.stream_info_->src_addr)) < 0;
        case src_port_col_:
            return stream_info_->src_port < other_rstwi.stream_info_->src_port;
        case dst_addr_col_:
            return cmp_address(&(stream_info_->dest_addr), &(other_rstwi.stream_info_->dest_addr)) < 0;
        case dst_port_col_:
            return stream_info_->dest_port < other_rstwi.stream_info_->dest_port;
        case ssrc_col_:
            return stream_info_->ssrc < other_rstwi.stream_info_->ssrc;
        case payload_col_:
            return stream_info_->payload_type < other_rstwi.stream_info_->payload_type; // XXX Compare payload_type_name instead?
        case packets_col_:
            return stream_info_->packet_count < other_rstwi.stream_info_->packet_count;
        case lost_col_:
            return lost_ < other_rstwi.lost_;
        case max_delta_col_:
            return stream_info_->rtp_stats.max_delta < other_rstwi.stream_info_->rtp_stats.max_delta;
        case max_jitter_col_:
            return stream_info_->rtp_stats.max_jitter < other_rstwi.stream_info_->rtp_stats.max_jitter;
        case mean_jitter_col_:
            return stream_info_->rtp_stats.mean_jitter < other_rstwi.stream_info_->rtp_stats.mean_jitter;
        default:
            break;
        }

        // Fall back to string comparison
        return QTreeWidgetItem::operator <(other);
    }

private:
    rtp_stream_info_t *stream_info_;
    guint32 lost_;
};

RtpStreamDialog::RtpStreamDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::RtpStreamDialog),
    need_redraw_(false)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);
    setWindowSubtitle(tr("RTP Streams"));
    ui->streamTreeWidget->installEventFilter(this);

    ctx_menu_.addAction(ui->actionSelectNone);
    ctx_menu_.addAction(ui->actionFindReverse);
    ctx_menu_.addAction(ui->actionGoToSetup);
    ctx_menu_.addAction(ui->actionMarkPackets);
    ctx_menu_.addAction(ui->actionPrepareFilter);
    ctx_menu_.addAction(ui->actionExportAsRtpDump);
    ctx_menu_.addAction(ui->actionCopyAsCsv);
    ctx_menu_.addAction(ui->actionCopyAsYaml);
    ctx_menu_.addAction(ui->actionAnalyze);
    ui->streamTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->streamTreeWidget->header()->setSortIndicator(0, Qt::AscendingOrder);
    connect(ui->streamTreeWidget, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showStreamMenu(QPoint)));

    // Some GTK+ buttons have been left out intentionally in order to
    // reduce clutter. Do you have a strong and informed opinion about
    // this? Perhaps you should volunteer to maintain this code!
    find_reverse_button_ = ui->buttonBox->addButton(ui->actionFindReverse->text(), QDialogButtonBox::ApplyRole);
    find_reverse_button_->setToolTip(ui->actionFindReverse->toolTip());
    prepare_button_ = ui->buttonBox->addButton(ui->actionPrepareFilter->text(), QDialogButtonBox::ApplyRole);
    prepare_button_->setToolTip(ui->actionPrepareFilter->toolTip());
    export_button_ = ui->buttonBox->addButton(tr("Export" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ApplyRole);
    export_button_->setToolTip(ui->actionExportAsRtpDump->toolTip());
    copy_button_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ApplyRole);
    analyze_button_ = ui->buttonBox->addButton(ui->actionAnalyze->text(), QDialogButtonBox::ApplyRole);
    analyze_button_->setToolTip(ui->actionAnalyze->toolTip());

    QMenu *copy_menu = new QMenu();
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(ui->actionCopyAsCsv->toolTip());
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyAsCsv_triggered()));
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(ui->actionCopyAsYaml->toolTip());
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyAsYaml_triggered()));
    copy_button_->setMenu(copy_menu);

    /* Register the tap listener */
    memset(&tapinfo_, 0, sizeof(rtpstream_tapinfo_t));
    tapinfo_.tap_reset = tapReset;
    tapinfo_.tap_draw = tapDraw;
    tapinfo_.tap_mark_packet = tapMarkPacket;
    tapinfo_.tap_data = this;
    tapinfo_.mode = TAP_ANALYSE;

    register_tap_listener_rtp_stream(&tapinfo_, NULL);
    /* Scan for RTP streams (redissect all packets) */
    rtpstream_scan(&tapinfo_, cf.capFile(), NULL);

    updateWidgets();
}

RtpStreamDialog::~RtpStreamDialog()
{
    delete ui;
    remove_tap_listener_rtp_stream(&tapinfo_);
}

bool RtpStreamDialog::eventFilter(QObject *, QEvent *event)
{
    if (ui->streamTreeWidget->hasFocus() && event->type() == QEvent::KeyPress) {
        QKeyEvent &keyEvent = static_cast<QKeyEvent&>(*event);
        switch(keyEvent.key()) {
        case Qt::Key_G:
            on_actionGoToSetup_triggered();
            return true;
        case Qt::Key_M:
            on_actionMarkPackets_triggered();
            return true;
        case Qt::Key_P:
            on_actionPrepareFilter_triggered();
            return true;
        case Qt::Key_R:
            on_actionFindReverse_triggered();
            return true;
        case Qt::Key_A:
            // XXX "Shift+Ctrl+A" is a fairly standard shortcut for "select none".
            // However, the main window uses this for displaying the profile dialog.
//            if (keyEvent.modifiers() == (Qt::ControlModifier | Qt::ShiftModifier))
//                on_actionSelectNone_triggered();
//            return true;
            break;
        default:
            break;
        }
    }
    return false;
}

void RtpStreamDialog::tapReset(rtpstream_tapinfo_t *tapinfo)
{
    RtpStreamDialog *rtp_stream_dialog = dynamic_cast<RtpStreamDialog *>((RtpStreamDialog *)tapinfo->tap_data);
    if (rtp_stream_dialog) {
        /* invalidate items which refer to old strinfo_list items. */
        rtp_stream_dialog->ui->streamTreeWidget->clear();
    }
}

void RtpStreamDialog::tapDraw(rtpstream_tapinfo_t *tapinfo)
{
    RtpStreamDialog *rtp_stream_dialog = dynamic_cast<RtpStreamDialog *>((RtpStreamDialog *)tapinfo->tap_data);
    if (rtp_stream_dialog) {
        rtp_stream_dialog->updateStreams();
    }
}

void RtpStreamDialog::tapMarkPacket(rtpstream_tapinfo_t *tapinfo, frame_data *fd)
{
    if (!tapinfo) return;

    RtpStreamDialog *rtp_stream_dialog = dynamic_cast<RtpStreamDialog *>((RtpStreamDialog *)tapinfo->tap_data);
    if (rtp_stream_dialog) {
        cf_mark_frame(rtp_stream_dialog->cap_file_.capFile(), fd);
        rtp_stream_dialog->need_redraw_ = true;
    }
}

void RtpStreamDialog::updateStreams()
{
    GList *cur_stream = g_list_nth(tapinfo_.strinfo_list, ui->streamTreeWidget->topLevelItemCount());

    // Add any missing items
    while (cur_stream && cur_stream->data) {
        rtp_stream_info_t *stream_info = (rtp_stream_info_t*) cur_stream->data;
        new RtpStreamTreeWidgetItem(ui->streamTreeWidget, stream_info);
        cur_stream = g_list_next(cur_stream);
    }

    // Recalculate values
    QTreeWidgetItemIterator iter(ui->streamTreeWidget);
    while (*iter) {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(*iter);
        rsti->drawData();
        ++iter;
    }

    // Resize columns
    for (int i = 0; i < ui->streamTreeWidget->columnCount(); i++) {
        ui->streamTreeWidget->resizeColumnToContents(i);
    }

    ui->streamTreeWidget->setSortingEnabled(true);

    updateWidgets();

    if (need_redraw_) {
        emit packetsMarked();
        need_redraw_ = false;
    }
}

void RtpStreamDialog::updateWidgets()
{
    bool selected = ui->streamTreeWidget->selectedItems().count() > 0;

    QString hint = "<small><i>";
    hint += tr("%1 streams").arg(ui->streamTreeWidget->topLevelItemCount());

    if (selected) {
        int tot_packets = 0;
        foreach(QTreeWidgetItem *ti, ui->streamTreeWidget->selectedItems()) {
            RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
            if (rsti->streamInfo()) {
                tot_packets += rsti->streamInfo()->packet_count;
            }
        }
        hint += tr(", %1 selected, %2 total packets")
                .arg(ui->streamTreeWidget->selectedItems().count())
                .arg(tot_packets);
    }

    hint += ". Right-click for more options.";
    hint += "</i></small>";
    ui->hintLabel->setText(hint);

    bool enable = selected && !file_closed_;
    bool has_data = ui->streamTreeWidget->topLevelItemCount() > 0;

    find_reverse_button_->setEnabled(enable);
    prepare_button_->setEnabled(enable);
    export_button_->setEnabled(enable);
    copy_button_->setEnabled(has_data);
    analyze_button_->setEnabled(selected);

    ui->actionFindReverse->setEnabled(enable);
    ui->actionGoToSetup->setEnabled(enable);
    ui->actionMarkPackets->setEnabled(enable);
    ui->actionPrepareFilter->setEnabled(enable);
    ui->actionExportAsRtpDump->setEnabled(enable);
    ui->actionCopyAsCsv->setEnabled(has_data);
    ui->actionCopyAsYaml->setEnabled(has_data);
    ui->actionAnalyze->setEnabled(selected);

    WiresharkDialog::updateWidgets();
}

QList<QVariant> RtpStreamDialog::streamRowData(int row) const
{
    QList<QVariant> row_data;

    if (row >= ui->streamTreeWidget->topLevelItemCount()) {
        return row_data;
    }

    for (int col = 0; col < ui->streamTreeWidget->columnCount(); col++) {
        if (row < 0) {
            row_data << ui->streamTreeWidget->headerItem()->text(col);
        } else {
            RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(row));
            if (rsti) {
                row_data << rsti->colData(col);
            }
        }
    }
    return row_data;
}

void RtpStreamDialog::captureFileClosing()
{
    remove_tap_listener_rtp_stream(&tapinfo_);
    WiresharkDialog::captureFileClosing();
}

void RtpStreamDialog::showStreamMenu(QPoint pos)
{
    ctx_menu_.popup(ui->streamTreeWidget->viewport()->mapToGlobal(pos));
}

void RtpStreamDialog::on_actionAnalyze_triggered()
{
    rtp_stream_info_t *stream_a, *stream_b = NULL;

    QTreeWidgetItem *ti = ui->streamTreeWidget->selectedItems()[0];
    RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
    stream_a = rsti->streamInfo();
    if (ui->streamTreeWidget->selectedItems().count() > 1) {
        ti = ui->streamTreeWidget->selectedItems()[1];
        rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
        stream_b = rsti->streamInfo();
    }

    if (stream_a == NULL && stream_b == NULL) return;

    RtpAnalysisDialog rtp_analysis_dialog(*this, cap_file_, stream_a, stream_b);
    rtp_analysis_dialog.exec();
}

void RtpStreamDialog::on_actionCopyAsCsv_triggered()
{
    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    for (int row = -1; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QStringList rdsl;
        foreach (QVariant v, streamRowData(row)) {
            if (!v.isValid()) {
                rdsl << "\"\"";
            } else if ((int) v.type() == (int) QMetaType::QString) {
                rdsl << QString("\"%1\"").arg(v.toString());
            } else {
                rdsl << v.toString();
            }
        }
        stream << rdsl.join(",") << endl;
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void RtpStreamDialog::on_actionCopyAsYaml_triggered()
{
    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    stream << "---" << endl;
    for (int row = -1; row < ui->streamTreeWidget->topLevelItemCount(); row ++) {
        stream << "-" << endl;
        foreach (QVariant v, streamRowData(row)) {
            stream << " - " << v.toString() << endl;
        }
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void RtpStreamDialog::on_actionExportAsRtpDump_triggered()
{
    if (file_closed_ || ui->streamTreeWidget->selectedItems().count() < 1) return;

    // XXX If the user selected multiple frames is this the one we actually want?
    QTreeWidgetItem *ti = ui->streamTreeWidget->selectedItems()[0];
    RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
    rtp_stream_info_t *stream_info = rsti->streamInfo();
    if (stream_info) {
        QString file_name;
        QDir path(wsApp->lastOpenDir());
        QString save_file = path.canonicalPath() + "/" + cap_file_.fileTitle();
        QString extension;
        file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save RTPDump As" UTF8_HORIZONTAL_ELLIPSIS)),
                                                 save_file, "RTPDump Format (*.rtpdump)", &extension);

        if (file_name.length() > 0) {
            gchar *dest_file = qstring_strdup(file_name);
            gboolean save_ok = rtpstream_save(&tapinfo_, cap_file_.capFile(), stream_info, dest_file);
            g_free(dest_file);
            // else error dialog?
            if (save_ok) {
                path = QDir(file_name);
                wsApp->setLastOpenDir(path.canonicalPath().toUtf8().constData());
            }
        }

    }
}

void RtpStreamDialog::on_actionFindReverse_triggered()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    // Gather up our selected streams...
    QList<rtp_stream_info_t *> selected_streams;
    foreach(QTreeWidgetItem *ti, ui->streamTreeWidget->selectedItems()) {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
        rtp_stream_info_t *stream_info = rsti->streamInfo();
        if (stream_info) {
            selected_streams << stream_info;
        }
    }

    // ...and compare them to our unselected streams.
    QTreeWidgetItemIterator iter(ui->streamTreeWidget, QTreeWidgetItemIterator::Unselected);
    while (*iter) {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(*iter);
        rtp_stream_info_t *stream_info = rsti->streamInfo();
        if (stream_info) {
            foreach (rtp_stream_info_t *fwd_stream, selected_streams) {
                if (rtp_stream_info_is_reverse(fwd_stream, stream_info)) {
                    (*iter)->setSelected(true);
                }
            }
        }
        ++iter;
    }
}

void RtpStreamDialog::on_actionGoToSetup_triggered()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;
    // XXX If the user selected multiple frames is this the one we actually want?
    QTreeWidgetItem *ti = ui->streamTreeWidget->selectedItems()[0];
    RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
    rtp_stream_info_t *stream_info = rsti->streamInfo();
    if (stream_info) {
        emit goToPacket(stream_info->setup_frame_number);
    }
}

void RtpStreamDialog::on_actionMarkPackets_triggered()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;
    rtp_stream_info_t *stream_a, *stream_b = NULL;

    QTreeWidgetItem *ti = ui->streamTreeWidget->selectedItems()[0];
    RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
    stream_a = rsti->streamInfo();
    if (ui->streamTreeWidget->selectedItems().count() > 1) {
        ti = ui->streamTreeWidget->selectedItems()[1];
        rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
        stream_b = rsti->streamInfo();
    }

    if (stream_a == NULL && stream_b == NULL) return;

    // XXX Mark the setup frame as well?
    need_redraw_ = false;
    rtpstream_mark(&tapinfo_, cap_file_.capFile(), stream_a, stream_b);
    updateWidgets();
}

void RtpStreamDialog::on_actionPrepareFilter_triggered()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    // Gather up our selected streams...
    QStringList stream_filters;
    foreach(QTreeWidgetItem *ti, ui->streamTreeWidget->selectedItems()) {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
        rtp_stream_info_t *stream_info = rsti->streamInfo();
        if (stream_info) {
            QString ip_proto = stream_info->src_addr.type == AT_IPv6 ? "ipv6" : "ip";
            stream_filters << QString("(%1.src==%2 && udp.srcport==%3 && %1.dst==%4 && udp.dstport==%5 && rtp.ssrc==0x%6)")
                             .arg(ip_proto) // %1
                             .arg(address_to_qstring(&stream_info->src_addr)) // %2
                             .arg(stream_info->src_port) // %3
                             .arg(address_to_qstring(&stream_info->dest_addr)) // %4
                             .arg(stream_info->dest_port) // %5
                             .arg(stream_info->ssrc, 0, 16);
        }
    }
    if (stream_filters.length() > 0) {
        QString filter = stream_filters.join(" || ");
        remove_tap_listener_rtp_stream(&tapinfo_);
        emit updateFilter(filter);
    }
}

void RtpStreamDialog::on_actionSelectNone_triggered()
{
    ui->streamTreeWidget->clearSelection();
}

void RtpStreamDialog::on_streamTreeWidget_itemSelectionChanged()
{
    updateWidgets();
}

void RtpStreamDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == prepare_button_) {
        on_actionPrepareFilter_triggered();
    } else if (button == export_button_) {
        on_actionExportAsRtpDump_triggered();
    } else if (button == analyze_button_) {
        on_actionAnalyze_triggered();
    }
}

void RtpStreamDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_RTP_ANALYSIS_DIALOG);
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
