/* rtp_analysis_dialog.cpp
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

#include "rtp_analysis_dialog.h"
#include <ui_rtp_analysis_dialog.h>

#include "file.h"
#include "frame_tvbuff.h"

#include "epan/epan_dissect.h"
#include "epan/rtp_pt.h"

#include "epan/dfilter/dfilter.h"

#include "epan/dissectors/packet-rtp.h"

#include "ui/help_url.h"
#include <wsutil/utf8_entities.h>

#include <wsutil/g711.h>
#include <wsutil/pint.h>

#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QTemporaryFile>

#include "color_utils.h"
#include "qt_ui_utils.h"
#include "rtp_player_dialog.h"
#include "stock_icon.h"
#include "wireshark_application.h"

/*
 * @file RTP stream analysis dialog
 *
 * Displays forward and reverse RTP streams and graphs each stream
 */

// To do:
// - Progress bar for tapping and saving.
// - Add a refresh button and/or action.
// - Fixup output file names.
// - Add a graph title and legend when saving?

enum {
    packet_col_,
    sequence_col_,
    delta_col_,
    jitter_col_,
    skew_col_,
    bandwidth_col_,
    marker_col_,
    status_col_
};

static const QRgb color_cn_ = 0xbfbfff;
static const QRgb color_rtp_warn_ = 0xffdbbf;
static const QRgb color_pt_event_ = 0xefffff;

enum { rtp_analysis_type_ = 1000 };
class RtpAnalysisTreeWidgetItem : public QTreeWidgetItem
{
public:
    RtpAnalysisTreeWidgetItem(QTreeWidget *tree, tap_rtp_stat_t *statinfo, packet_info *pinfo, const struct _rtp_info *rtpinfo) :
        QTreeWidgetItem(tree, rtp_analysis_type_)
    {
        frame_num_ = pinfo->num;
        sequence_num_ = rtpinfo->info_seq_num;
        pkt_len_ = pinfo->fd->pkt_len;
        flags_ = statinfo->flags;
        if (flags_ & STAT_FLAG_FIRST) {
            delta_ = 0.0;
            jitter_ = 0.0;
            skew_ = 0.0;
        } else {
            delta_ = statinfo->delta;
            jitter_ = statinfo->jitter;
            skew_ = statinfo->skew;
        }
        bandwidth_ = statinfo->bandwidth;
        marker_ = rtpinfo->info_marker_set ? true : false;
        ok_ = false;

        QColor bg_color = QColor();
        QString status;

        if (statinfo->pt == PT_CN) {
            status = "Comfort noise (PT=13, RFC 3389)";
            bg_color = color_cn_;
        } else if (statinfo->pt == PT_CN_OLD) {
            status = "Comfort noise (PT=19, reserved)";
            bg_color = color_cn_;
        } else if (statinfo->flags & STAT_FLAG_WRONG_SEQ) {
            status = "Wrong sequence number";
            bg_color = ColorUtils::expert_color_error;
        } else if (statinfo->flags & STAT_FLAG_DUP_PKT) {
            status = "Suspected duplicate (MAC address) only delta time calculated";
            bg_color = color_rtp_warn_;
        } else if (statinfo->flags & STAT_FLAG_REG_PT_CHANGE) {
            status = QString("Payload changed to PT=%1").arg(statinfo->pt);
            if (statinfo->flags & STAT_FLAG_PT_T_EVENT) {
                status.append(" telephone/event");
            }
            bg_color = color_rtp_warn_;
        } else if (statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP) {
            status = "Incorrect timestamp";
            /* color = COLOR_WARNING; */
            bg_color = color_rtp_warn_;
        } else if ((statinfo->flags & STAT_FLAG_PT_CHANGE)
            &&  !(statinfo->flags & STAT_FLAG_FIRST)
            &&  !(statinfo->flags & STAT_FLAG_PT_CN)
            &&  (statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)
            &&  !(statinfo->flags & STAT_FLAG_MARKER)) {
            status = "Marker missing?";
            bg_color = color_rtp_warn_;
        } else if (statinfo->flags & STAT_FLAG_PT_T_EVENT) {
            status = QString("PT=%1 telephone/event").arg(statinfo->pt);
            /* XXX add color? */
            bg_color = color_pt_event_;
        } else {
            if (statinfo->flags & STAT_FLAG_MARKER) {
                bg_color = color_rtp_warn_;
            }
        }

        if (status.isEmpty()) {
            ok_ = true;
            status = UTF8_CHECK_MARK;
        }

        setText(packet_col_, QString::number(frame_num_));
        setText(sequence_col_, QString::number(sequence_num_));
        setText(delta_col_, QString::number(delta_, 'f', 2));
        setText(jitter_col_, QString::number(jitter_, 'f', 2));
        setText(skew_col_, QString::number(skew_, 'f', 2));
        setText(bandwidth_col_, QString::number(bandwidth_, 'f', 2));
        if (marker_) {
            setText(marker_col_, UTF8_BULLET);
        }
        setText(status_col_, status);

        setTextAlignment(packet_col_, Qt::AlignRight);
        setTextAlignment(sequence_col_, Qt::AlignRight);
        setTextAlignment(delta_col_, Qt::AlignRight);
        setTextAlignment(jitter_col_, Qt::AlignRight);
        setTextAlignment(skew_col_, Qt::AlignRight);
        setTextAlignment(bandwidth_col_, Qt::AlignRight);
        setTextAlignment(marker_col_, Qt::AlignCenter);

        if (bg_color.isValid()) {
            for (int col = 0; col < columnCount(); col++) {
                setBackground(col, bg_color);
                setForeground(col, ColorUtils::expert_color_foreground);
            }
        }
    }

    guint32 frameNum() { return frame_num_; }
    bool frameStatus() { return ok_; }

    QList<QVariant> rowData() {
        QString marker_str;
        QString status_str = ok_ ? "OK" : text(status_col_);

        if (marker_) marker_str = "SET";

        return QList<QVariant>()
                << frame_num_ << sequence_num_ << delta_ << jitter_ << skew_ << bandwidth_
                << marker_str << status_str;
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != rtp_analysis_type_) return QTreeWidgetItem::operator< (other);
        const RtpAnalysisTreeWidgetItem *other_row = static_cast<const RtpAnalysisTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case (packet_col_):
            return frame_num_ < other_row->frame_num_;
            break;
        case (sequence_col_):
            return sequence_num_ < other_row->sequence_num_;
            break;
        case (delta_col_):
            return delta_ < other_row->delta_;
            break;
        case (jitter_col_):
            return jitter_ < other_row->jitter_;
            break;
        case (skew_col_):
            return skew_ < other_row->skew_;
            break;
        case (bandwidth_col_):
            return bandwidth_ < other_row->bandwidth_;
            break;
        default:
            break;
        }

        // Fall back to string comparison
        return QTreeWidgetItem::operator <(other);
    }
private:
    guint32 frame_num_;
    guint32 sequence_num_;
    guint32 pkt_len_;
    guint32 flags_;
    double delta_;
    double jitter_;
    double skew_;
    double bandwidth_;
    bool marker_;
    bool ok_;
};

enum {
    fwd_jitter_graph_,
    fwd_diff_graph_,
    fwd_delta_graph_,
    rev_jitter_graph_,
    rev_diff_graph_,
    rev_delta_graph_,
    num_graphs_
};

RtpAnalysisDialog::RtpAnalysisDialog(QWidget &parent, CaptureFile &cf, struct _rtp_stream_info *stream_fwd, struct _rtp_stream_info *stream_rev) :
    WiresharkDialog(parent, cf),
    ui(new Ui::RtpAnalysisDialog),
    port_src_fwd_(0),
    port_dst_fwd_(0),
    ssrc_fwd_(0),
    packet_count_fwd_(0),
    setup_frame_number_fwd_(0),
    port_src_rev_(0),
    port_dst_rev_(0),
    ssrc_rev_(0),
    packet_count_rev_(0),
    setup_frame_number_rev_(0),
    num_streams_(0),
    save_payload_error_(TAP_RTP_NO_ERROR)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);
    setWindowSubtitle(tr("RTP Stream Analysis"));

    ui->progressFrame->hide();

    player_button_ = RtpPlayerDialog::addPlayerButton(ui->buttonBox);

    stream_ctx_menu_.addAction(ui->actionGoToPacket);
    stream_ctx_menu_.addAction(ui->actionNextProblem);
    stream_ctx_menu_.addSeparator();
    stream_ctx_menu_.addAction(ui->actionSaveAudio);
    stream_ctx_menu_.addAction(ui->actionSaveForwardAudio);
    stream_ctx_menu_.addAction(ui->actionSaveReverseAudio);
    stream_ctx_menu_.addSeparator();
    stream_ctx_menu_.addAction(ui->actionSaveCsv);
    stream_ctx_menu_.addAction(ui->actionSaveForwardCsv);
    stream_ctx_menu_.addAction(ui->actionSaveReverseCsv);
    stream_ctx_menu_.addSeparator();
    stream_ctx_menu_.addAction(ui->actionSaveGraph);
    ui->forwardTreeWidget->installEventFilter(this);
    ui->forwardTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->forwardTreeWidget->header()->setSortIndicator(0, Qt::AscendingOrder);
    connect(ui->forwardTreeWidget, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showStreamMenu(QPoint)));
    ui->reverseTreeWidget->installEventFilter(this);
    ui->reverseTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->reverseTreeWidget->header()->setSortIndicator(0, Qt::AscendingOrder);
    connect(ui->reverseTreeWidget, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showStreamMenu(QPoint)));
    connect(ui->streamGraph, SIGNAL(mousePress(QMouseEvent*)),
            this, SLOT(graphClicked(QMouseEvent*)));

    graph_ctx_menu_.addAction(ui->actionSaveGraph);

    QStringList header_labels;
    for (int i = 0; i < ui->forwardTreeWidget->columnCount(); i++) {
        header_labels << ui->forwardTreeWidget->headerItem()->text(i);
    }
    ui->reverseTreeWidget->setHeaderLabels(header_labels);

    memset(&src_fwd_, 0, sizeof(address));
    memset(&dst_fwd_, 0, sizeof(address));
    memset(&src_rev_, 0, sizeof(address));
    memset(&dst_rev_, 0, sizeof(address));
    nstime_set_zero(&start_rel_time_fwd_);
    nstime_set_zero(&start_rel_time_rev_);

    QList<QCheckBox *> graph_cbs = QList<QCheckBox *>()
            << ui->fJitterCheckBox << ui->fDiffCheckBox << ui->fDeltaCheckBox
            << ui->rJitterCheckBox << ui->rDiffCheckBox << ui->rDeltaCheckBox;

    for (int i = 0; i < num_graphs_; i++) {
        QCPGraph *graph = ui->streamGraph->addGraph();
        graph->setPen(QPen(ColorUtils::graphColor(i)));
        graph->setName(graph_cbs[i]->text());
        graphs_ << graph;
        graph_cbs[i]->setChecked(true);
        graph_cbs[i]->setIcon(StockIcon::colorIcon(ColorUtils::graphColor(i), QPalette::Text));
    }
    ui->streamGraph->xAxis->setLabel("Arrival Time");
    ui->streamGraph->yAxis->setLabel("Value (ms)");

    // We keep our temp files open for the lifetime of the dialog. The GTK+
    // UI opens and closes at various points.
    QString tempname = QString("%1/wireshark_rtp_f").arg(QDir::tempPath());
    fwd_tempfile_ = new QTemporaryFile(tempname, this);
    fwd_tempfile_->open();
    tempname = QString("%1/wireshark_rtp_r").arg(QDir::tempPath());
    rev_tempfile_ = new QTemporaryFile(tempname, this);
    rev_tempfile_->open();

    if (fwd_tempfile_->error() != QFile::NoError || rev_tempfile_->error() != QFile::NoError) {
        err_str_ = tr("Unable to save RTP data.");
        ui->actionSaveAudio->setEnabled(false);
        ui->actionSaveForwardAudio->setEnabled(false);
        ui->actionSaveReverseAudio->setEnabled(false);
    }

    QMenu *save_menu = new QMenu();
    save_menu->addAction(ui->actionSaveAudio);
    save_menu->addAction(ui->actionSaveForwardAudio);
    save_menu->addAction(ui->actionSaveReverseAudio);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveCsv);
    save_menu->addAction(ui->actionSaveForwardCsv);
    save_menu->addAction(ui->actionSaveReverseCsv);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveGraph);
    ui->buttonBox->button(QDialogButtonBox::Save)->setMenu(save_menu);

    if (stream_fwd) { // XXX What if stream_fwd == 0 && stream_rev != 0?
        copy_address(&src_fwd_, &(stream_fwd->src_addr));
        port_src_fwd_ = stream_fwd->src_port;
        copy_address(&dst_fwd_, &(stream_fwd->dest_addr));
        port_dst_fwd_ = stream_fwd->dest_port;
        ssrc_fwd_ = stream_fwd->ssrc;
        packet_count_fwd_ = stream_fwd->packet_count;
        setup_frame_number_fwd_ = stream_fwd->setup_frame_number;
        nstime_copy(&start_rel_time_fwd_, &stream_fwd->start_rel_time);
        num_streams_++;
        if (stream_rev) {
            copy_address(&src_rev_, &(stream_rev->src_addr));
            port_src_rev_ = stream_rev->src_port;
            copy_address(&dst_rev_, &(stream_rev->dest_addr));
            port_dst_rev_ = stream_rev->dest_port;
            ssrc_rev_ = stream_rev->ssrc;
            packet_count_rev_ = stream_rev->packet_count;
            setup_frame_number_rev_ = stream_rev->setup_frame_number;
            nstime_copy(&start_rel_time_rev_, &stream_rev->start_rel_time);
            num_streams_++;
        }
    } else {
        findStreams();
    }

    if (err_str_.isEmpty() && num_streams_ < 1) {
        err_str_ = tr("No streams found.");
    }

    registerTapListener("rtp", this, NULL, 0, tapReset, tapPacket, tapDraw);
    cap_file_.retapPackets();
    removeTapListeners();

    connect(ui->tabWidget, SIGNAL(currentChanged(int)),
            this, SLOT(updateWidgets()));
    connect(ui->forwardTreeWidget, SIGNAL(itemSelectionChanged()),
            this, SLOT(updateWidgets()));
    connect(ui->reverseTreeWidget, SIGNAL(itemSelectionChanged()),
            this, SLOT(updateWidgets()));
    connect(&cap_file_, SIGNAL(captureFileClosing()),
            this, SLOT(updateWidgets()));
    updateWidgets();

    updateStatistics();
}

RtpAnalysisDialog::~RtpAnalysisDialog()
{
    delete ui;
//    remove_tap_listener_rtp_stream(&tapinfo_);
    delete fwd_tempfile_;
    delete rev_tempfile_;
}

void RtpAnalysisDialog::updateWidgets()
{
    bool enable_tab = false;
    QString hint = err_str_;

    if (hint.isEmpty()) {
        enable_tab = true;
        hint = tr("%1 streams found.").arg(num_streams_);
    } else if (save_payload_error_ != TAP_RTP_NO_ERROR) {
        /* We cannot save the payload but can still display the widget
           or save CSV data */
        enable_tab = true;
    }

    bool enable_nav = false;
    if (!file_closed_
            && ((ui->tabWidget->currentWidget() == ui->forwardTreeWidget
                 && ui->forwardTreeWidget->selectedItems().length() > 0)
                || (ui->tabWidget->currentWidget() == ui->reverseTreeWidget
                    && ui->reverseTreeWidget->selectedItems().length() > 0))) {
        enable_nav = true;
    }
    ui->actionGoToPacket->setEnabled(enable_nav);
    ui->actionNextProblem->setEnabled(enable_nav);

    if (enable_nav) {
        hint.append(tr(" G: Go to packet, N: Next problem packet"));
    }

    bool enable_save_fwd_audio = fwd_tempfile_->isOpen() && (save_payload_error_ == TAP_RTP_NO_ERROR);
    bool enable_save_rev_audio = rev_tempfile_->isOpen() && (save_payload_error_ == TAP_RTP_NO_ERROR);
    ui->actionSaveAudio->setEnabled(enable_save_fwd_audio && enable_save_rev_audio);
    ui->actionSaveForwardAudio->setEnabled(enable_save_fwd_audio);
    ui->actionSaveReverseAudio->setEnabled(enable_save_rev_audio);

    bool enable_save_fwd_csv = ui->forwardTreeWidget->topLevelItemCount() > 0;
    bool enable_save_rev_csv = ui->reverseTreeWidget->topLevelItemCount() > 0;
    ui->actionSaveCsv->setEnabled(enable_save_fwd_csv && enable_save_rev_csv);
    ui->actionSaveForwardCsv->setEnabled(enable_save_fwd_csv);
    ui->actionSaveReverseCsv->setEnabled(enable_save_rev_csv);

#if defined(QT_MULTIMEDIA_LIB)
    player_button_->setEnabled(num_streams_ > 0);
#else
    player_button_->setEnabled(false);
    player_button_->setText(tr("No Audio"));
#endif

    ui->tabWidget->setEnabled(enable_tab);
    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);

    WiresharkDialog::updateWidgets();
}

void RtpAnalysisDialog::on_actionGoToPacket_triggered()
{
    if (file_closed_) return;
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->tabWidget->currentWidget());
    if (!cur_tree || cur_tree->selectedItems().length() < 1) return;

    QTreeWidgetItem *ti = cur_tree->selectedItems()[0];
    if (ti->type() != rtp_analysis_type_) return;

    RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)ti);
    emit goToPacket(ra_ti->frameNum());
}

void RtpAnalysisDialog::on_actionNextProblem_triggered()
{
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->tabWidget->currentWidget());
    if (!cur_tree || cur_tree->topLevelItemCount() < 2) return;

    // Choose convenience over correctness.
    if (cur_tree->selectedItems().length() < 1) {
        cur_tree->setCurrentItem(cur_tree->topLevelItem(0));
    }

    QTreeWidgetItem *sel_ti = cur_tree->selectedItems()[0];
    if (sel_ti->type() != rtp_analysis_type_) return;
    QTreeWidgetItem *test_ti = cur_tree->itemBelow(sel_ti);
    while (test_ti != sel_ti) {
        if (!test_ti) test_ti = cur_tree->topLevelItem(0);
        RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)test_ti);
        if (!ra_ti->frameStatus()) {
            cur_tree->setCurrentItem(ra_ti);
            break;
        }

        test_ti = cur_tree->itemBelow(test_ti);
    }
}

void RtpAnalysisDialog::on_fJitterCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(fwd_jitter_graph_)->setVisible(checked);
    updateGraph();
}

void RtpAnalysisDialog::on_fDiffCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(fwd_diff_graph_)->setVisible(checked);
    updateGraph();
}

void RtpAnalysisDialog::on_fDeltaCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(fwd_delta_graph_)->setVisible(checked);
    updateGraph();
}

void RtpAnalysisDialog::on_rJitterCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(rev_jitter_graph_)->setVisible(checked);
    updateGraph();
}

void RtpAnalysisDialog::on_rDiffCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(rev_diff_graph_)->setVisible(checked);
    updateGraph();
}

void RtpAnalysisDialog::on_rDeltaCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(rev_delta_graph_)->setVisible(checked);
    updateGraph();
}

void RtpAnalysisDialog::on_actionSaveAudio_triggered()
{
    saveAudio(dir_both_);
}

void RtpAnalysisDialog::on_actionSaveForwardAudio_triggered()
{
    saveAudio(dir_forward_);
}

void RtpAnalysisDialog::on_actionSaveReverseAudio_triggered()
{
    saveAudio(dir_reverse_);
}

void RtpAnalysisDialog::on_actionSaveCsv_triggered()
{
    saveCsv(dir_both_);
}

void RtpAnalysisDialog::on_actionSaveForwardCsv_triggered()
{
    saveCsv(dir_forward_);
}

void RtpAnalysisDialog::on_actionSaveReverseCsv_triggered()
{
    saveCsv(dir_reverse_);
}

void RtpAnalysisDialog::on_actionSaveGraph_triggered()
{
    ui->tabWidget->setCurrentWidget(ui->graphTab);

    QString file_name, extension;
    QDir path(wsApp->lastOpenDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString filter = QString("%1;;%2;;%3;;%4")
            .arg(pdf_filter)
            .arg(png_filter)
            .arg(bmp_filter)
            .arg(jpeg_filter);

    QString save_file = path.canonicalPath();
    if (!file_closed_) {
        save_file += QString("/%1").arg(cap_file_.fileTitle());
    }
    file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Graph As" UTF8_HORIZONTAL_ELLIPSIS)),
                                             save_file, filter, &extension);

    if (!file_name.isEmpty()) {
        bool save_ok = false;
        // http://www.qcustomplot.com/index.php/support/forum/63
//        ui->streamGraph->legend->setVisible(true);
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->streamGraph->savePdf(file_name);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = ui->streamGraph->savePng(file_name);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->streamGraph->saveBmp(file_name);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->streamGraph->saveJpg(file_name);
        }
//        ui->streamGraph->legend->setVisible(false);
        // else error dialog?
        if (save_ok) {
            path = QDir(file_name);
            wsApp->setLastOpenDir(path.canonicalPath().toUtf8().constData());
        }
    }
}

void RtpAnalysisDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == player_button_) {
        showPlayer();
    }
}

void RtpAnalysisDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_RTP_ANALYSIS_DIALOG);
}

void RtpAnalysisDialog::tapReset(void *tapinfo_ptr)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return;

    rtp_analysis_dialog->resetStatistics();
}

gboolean RtpAnalysisDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return FALSE;

    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)rtpinfo_ptr;
    if (!rtpinfo) return FALSE;

    /* we ignore packets that are not displayed */
    if (pinfo->fd->flags.passed_dfilter == 0)
        return FALSE;
    /* also ignore RTP Version != 2 */
    else if (rtpinfo->info_version != 2)
        return FALSE;
    /* is it the forward direction?  */
    else if (rtp_analysis_dialog->ssrc_fwd_ == rtpinfo->info_sync_src
         && (cmp_address(&(rtp_analysis_dialog->src_fwd_), &(pinfo->src)) == 0)
         && (rtp_analysis_dialog->port_src_fwd_ == pinfo->srcport)
         && (cmp_address(&(rtp_analysis_dialog->dst_fwd_), &(pinfo->dst)) == 0)
         && (rtp_analysis_dialog->port_dst_fwd_ == pinfo->destport))  {

        rtp_analysis_dialog->addPacket(true, pinfo, rtpinfo);
    }
    /* is it the reversed direction? */
    else if (rtp_analysis_dialog->ssrc_rev_ == rtpinfo->info_sync_src
         && (cmp_address(&(rtp_analysis_dialog->src_rev_), &(pinfo->src)) == 0)
         && (rtp_analysis_dialog->port_src_rev_ == pinfo->srcport)
         && (cmp_address(&(rtp_analysis_dialog->dst_rev_), &(pinfo->dst)) == 0)
         && (rtp_analysis_dialog->port_dst_rev_ == pinfo->destport))  {

        rtp_analysis_dialog->addPacket(false, pinfo, rtpinfo);
    }
    return FALSE;
}

void RtpAnalysisDialog::tapDraw(void *tapinfo_ptr)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return;
    rtp_analysis_dialog->updateStatistics();
}

void RtpAnalysisDialog::resetStatistics()
{
    memset(&fwd_statinfo_, 0, sizeof(tap_rtp_stat_t));
    memset(&rev_statinfo_, 0, sizeof(tap_rtp_stat_t));

    fwd_statinfo_.first_packet = TRUE;
    rev_statinfo_.first_packet = TRUE;
    fwd_statinfo_.reg_pt = PT_UNDEFINED;
    rev_statinfo_.reg_pt = PT_UNDEFINED;

    ui->forwardTreeWidget->clear();
    ui->reverseTreeWidget->clear();

    for (int i = 0; i < ui->streamGraph->graphCount(); i++) {
        ui->streamGraph->graph(i)->clearData();
    }

    fwd_time_vals_.clear();
    fwd_jitter_vals_.clear();
    fwd_diff_vals_.clear();
    fwd_delta_vals_.clear();
    rev_time_vals_.clear();
    rev_jitter_vals_.clear();
    rev_diff_vals_.clear();
    rev_delta_vals_.clear();

    fwd_tempfile_->resize(0);
    rev_tempfile_->resize(0);
}

void RtpAnalysisDialog::addPacket(bool forward, packet_info *pinfo, const _rtp_info *rtpinfo)
{
    /* add this RTP for future listening using the RTP Player*/
//    add_rtp_packet(rtpinfo, pinfo);

    if (forward) {
        rtp_packet_analyse(&fwd_statinfo_, pinfo, rtpinfo);
        new RtpAnalysisTreeWidgetItem(ui->forwardTreeWidget, &fwd_statinfo_, pinfo, rtpinfo);

        fwd_time_vals_.append(fwd_statinfo_.time / 1000);
        fwd_jitter_vals_.append(fwd_statinfo_.jitter);
        fwd_diff_vals_.append(fwd_statinfo_.diff);
        fwd_delta_vals_.append(fwd_statinfo_.delta);

        savePayload(fwd_tempfile_, &fwd_statinfo_, pinfo, rtpinfo);
    } else {
        rtp_packet_analyse(&rev_statinfo_, pinfo, rtpinfo);
        new RtpAnalysisTreeWidgetItem(ui->reverseTreeWidget, &rev_statinfo_, pinfo, rtpinfo);

        rev_time_vals_.append(rev_statinfo_.time / 1000);
        rev_jitter_vals_.append(rev_statinfo_.jitter);
        rev_diff_vals_.append(rev_statinfo_.diff);
        rev_delta_vals_.append(rev_statinfo_.delta);

        savePayload(rev_tempfile_, &rev_statinfo_, pinfo, rtpinfo);
    }

}

// rtp_analysis.c:rtp_packet_save_payload
const unsigned int max_silence_ticks_ = 1000000;
const guint8 silence_pcmu_ = 0xff;
const guint8 silence_pcma_ = 0x55;
void RtpAnalysisDialog::savePayload(QTemporaryFile *tmpfile, tap_rtp_stat_t *statinfo, packet_info *pinfo, const _rtp_info *rtpinfo)
{
    /* Is this the first packet we got in this direction? */
//    if (statinfo->flags & STAT_FLAG_FIRST) {
//        if (saveinfo->fp == NULL) {
//            saveinfo->saved = FALSE;
//            saveinfo->error_type = TAP_RTP_FILE_OPEN_ERROR;
//        } else {
//            saveinfo->saved = TRUE;
//        }
//    }

    /* Save the voice information */

    /* If there was already an error, we quit */
    if (!tmpfile->isOpen() || tmpfile->error() != QFile::NoError)
        return;

    /* Quit if the captured length and packet length aren't equal or
     * if the RTP dissector thinks there is some information missing
     */
    if ((pinfo->fd->pkt_len != pinfo->fd->cap_len) &&
        (!rtpinfo->info_all_data_present))
    {
        tmpfile->close();
        err_str_ = tr("Can't save in a file: Wrong length of captured packets.");
        save_payload_error_ = TAP_RTP_WRONG_LENGTH;
        return;
    }

    /* If padding bit is set but the padding count is bigger
     * then the whole RTP data - error with padding count
     */
    if ((rtpinfo->info_padding_set != FALSE) &&
        (rtpinfo->info_padding_count > rtpinfo->info_payload_len))
    {
        tmpfile->close();
        err_str_ = tr("Can't save in a file: RTP data with padding.");
        save_payload_error_ = TAP_RTP_PADDING_ERROR;
        return;
    }

    /* Do we need to insert some silence? */
    if ((rtpinfo->info_marker_set) &&
        !(statinfo->flags & STAT_FLAG_FIRST) &&
        !(statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP) &&
        (statinfo->delta_timestamp > (rtpinfo->info_payload_len - rtpinfo->info_padding_count)))
    {
        /* the amount of silence should be the difference between
        * the last timestamp and the current one minus x
        * x should equal the amount of information in the last frame
        * XXX not done yet */
        for (unsigned int i = 0;
             (i < (statinfo->delta_timestamp - rtpinfo->info_payload_len - rtpinfo->info_padding_count))
                 && (i < max_silence_ticks_);
             i++) {
            guint8 tmp;
            size_t nchars;

            switch (statinfo->reg_pt) {
            case PT_PCMU:
                tmp = silence_pcmu_;
                break;
            case PT_PCMA:
                tmp = silence_pcma_;
                break;
            default:
                tmp = 0;
                break;
            }
            nchars = tmpfile->write((char *)&tmp, 1);
            if (nchars != 1) {
                /* Write error or short write */
                tmpfile->close();
                err_str_ = tr("Can't save in a file: File I/O problem.");
                save_payload_error_ = TAP_RTP_FILE_IO_ERROR;
                return;
            }
        }
    }


    if ((rtpinfo->info_payload_type == PT_CN) ||
        (rtpinfo->info_payload_type == PT_CN_OLD)) {
    } else { /* All other payloads */
        const char *data;
        size_t nchars;

        if (!rtpinfo->info_all_data_present) {
            /* Not all the data was captured. */
            tmpfile->close();
            err_str_ = tr("Can't save in a file: Not all data in all packets was captured.");
            save_payload_error_ = TAP_RTP_WRONG_LENGTH;
            return;
        }

        /* We put the pointer at the beginning of the RTP
         * payload, that is, at the beginning of the RTP data
         * plus the offset of the payload from the beginning
         * of the RTP data */
        data   = (const char *) rtpinfo->info_data + rtpinfo->info_payload_offset;
        nchars = tmpfile->write(data, rtpinfo->info_payload_len - rtpinfo->info_padding_count);
        if (nchars != (rtpinfo->info_payload_len - rtpinfo->info_padding_count)) {
            /* Write error or short write */
            err_str_ = tr("Can't save in a file: File I/O problem.");
            save_payload_error_ = TAP_RTP_FILE_IO_ERROR;
            tmpfile->close();
            return;
        }
        return;
    }
    return;
}

void RtpAnalysisDialog::updateStatistics()
{
    unsigned int f_clock_rate = fwd_statinfo_.clock_rate;
    unsigned int r_clock_rate = rev_statinfo_.clock_rate;
    unsigned int f_expected = (fwd_statinfo_.stop_seq_nr + fwd_statinfo_.cycles*65536)
            - fwd_statinfo_.start_seq_nr + 1;
    unsigned int r_expected = (rev_statinfo_.stop_seq_nr + rev_statinfo_.cycles*65536)
            - rev_statinfo_.start_seq_nr + 1;
    unsigned int f_total_nr = fwd_statinfo_.total_nr;
    unsigned int r_total_nr = rev_statinfo_.total_nr;
    int f_lost = f_expected - f_total_nr;
    int r_lost = r_expected - r_total_nr;
    double f_sumt = fwd_statinfo_.sumt;
    double f_sumTS = fwd_statinfo_.sumTS;
    double f_sumt2 = fwd_statinfo_.sumt2;
    double f_sumtTS = fwd_statinfo_.sumtTS;
    double r_sumt = rev_statinfo_.sumt;
    double r_sumTS = rev_statinfo_.sumTS;
    double r_sumt2 = rev_statinfo_.sumt2;
    double r_sumtTS = rev_statinfo_.sumtTS;
    double f_perc, r_perc;
    double f_clock_drift = 1.0;
    double r_clock_drift = 1.0;
    double f_duration = fwd_statinfo_.time - fwd_statinfo_.start_time;
    double r_duration = rev_statinfo_.time - rev_statinfo_.start_time;

    if (f_clock_rate == 0) {
        f_clock_rate = 1;
    }

    if (r_clock_rate == 0) {
        r_clock_rate = 1;
    }

    if (f_expected) {
        f_perc = (double)(f_lost*100)/(double)f_expected;
    } else {
        f_perc = 0;
    }
    if (r_expected) {
        r_perc = (double)(r_lost*100)/(double)r_expected;
    } else {
        r_perc = 0;
    }

    if ((f_total_nr >0) && (f_sumt2 > 0)) {
        f_clock_drift = (f_total_nr * f_sumtTS - f_sumt * f_sumTS) / (f_total_nr * f_sumt2 - f_sumt * f_sumt);
    }
    if ((r_total_nr >0) && (r_sumt2 > 0)) {
        r_clock_drift = (r_total_nr * r_sumtTS - r_sumt * r_sumTS) / (r_total_nr * r_sumt2 - r_sumt * r_sumt);
    }

    QString stats_tables = "<html><head></head><body>\n";
    stats_tables += QString("<p>%1:%2 " UTF8_LEFT_RIGHT_ARROW)
            .arg(address_to_qstring(&src_fwd_, true))
            .arg(port_src_fwd_);
    stats_tables += QString("<br>%1:%2</p>\n")
            .arg(address_to_qstring(&dst_fwd_, true))
            .arg(port_dst_fwd_);
    stats_tables += "<h4>Forward</h4>\n";
    stats_tables += "<p><table>\n";
    stats_tables += QString("<tr><th align=\"left\">SSRC</th><td>%1</tr>")
            .arg(int_to_qstring(ssrc_fwd_, 8, 16));
    stats_tables += QString("<tr><th align=\"left\">Max Delta</th><td>%1 ms @ %2</td></tr>")
            .arg(fwd_statinfo_.max_delta, 0, 'f', 2)
            .arg(fwd_statinfo_.max_nr);
    stats_tables += QString("<tr><th align=\"left\">Max Jitter</th><td>%1 ms</tr>")
            .arg(fwd_statinfo_.max_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Mean Jitter</th><td>%1 ms</tr>")
            .arg(fwd_statinfo_.mean_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Max Skew</th><td>%1 ms</tr>")
            .arg(fwd_statinfo_.max_skew, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">RTP Packets</th><td>%1</tr>")
            .arg(f_total_nr);
    stats_tables += QString("<tr><th align=\"left\">Expected</th><td>%1</tr>")
            .arg(f_expected);
    stats_tables += QString("<tr><th align=\"left\">Lost</th><td>%1 (%2 %)</tr>")
            .arg(f_lost).arg(f_perc, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Seq Errs</th><td>%1</tr>")
            .arg(fwd_statinfo_.sequence);
    stats_tables += QString("<tr><th align=\"left\">Duration</th><td>%1 s</tr>")
            .arg(f_duration / 1000.0, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Clock Drift</th><td>%1 ms</tr>")
            .arg(f_duration * (f_clock_drift - 1.0), 0, 'f', 0);
    stats_tables += QString("<tr><th align=\"left\">Freq Drift</th><td>%1 Hz (%2 %)</tr>") // XXX Terminology?
            .arg(f_clock_drift * f_clock_rate, 0, 'f', 0).arg(100.0 * (f_clock_drift - 1.0), 0, 'f', 2);
    stats_tables += "</table></p>\n";

    stats_tables += "<h4>Reverse</h4>\n";
    stats_tables += "<p><table>\n";
    stats_tables += QString("<tr><th align=\"left\">SSRC</th><td>%1</tr>")
            .arg(int_to_qstring(ssrc_fwd_, 8, 16));
    stats_tables += QString("<tr><th align=\"left\">Max Delta</th><td>%1 ms @ %2</td></tr>")
            .arg(rev_statinfo_.max_delta, 0, 'f', 2)
            .arg(rev_statinfo_.max_nr);
    stats_tables += QString("<tr><th align=\"left\">Max Jitter</th><td>%1 ms</tr>")
            .arg(rev_statinfo_.max_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Mean Jitter</th><td>%1 ms</tr>")
            .arg(rev_statinfo_.mean_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Max Skew</th><td>%1 ms</tr>")
            .arg(rev_statinfo_.max_skew, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">RTP Packets</th><td>%1</tr>")
            .arg(r_total_nr);
    stats_tables += QString("<tr><th align=\"left\">Expected</th><td>%1</tr>")
            .arg(r_expected);
    stats_tables += QString("<tr><th align=\"left\">Lost</th><td>%1 (%2 %)</tr>")
            .arg(r_lost).arg(r_perc, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Seq Errs</th><td>%1</tr>")
            .arg(rev_statinfo_.sequence);
    stats_tables += QString("<tr><th align=\"left\">Duration</th><td>%1 s</tr>")
            .arg(r_duration / 1000.0, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Clock Drift</th><td>%1 ms</tr>")
            .arg(r_duration * (r_clock_drift - 1.0), 0, 'f', 0);
    stats_tables += QString("<tr><th align=\"left\">Freq Drift</th><td>%1 Hz (%2 %)</tr>") // XXX Terminology?
            .arg(r_clock_drift * r_clock_rate, 0, 'f', 0).arg(100.0 * (r_clock_drift - 1.0), 0, 'f', 2);
    stats_tables += "</table></p></body>\n";

    ui->statisticsLabel->setText(stats_tables);

    for (int col = 0; col < ui->forwardTreeWidget->columnCount() - 1; col++) {
        ui->forwardTreeWidget->resizeColumnToContents(col);
        ui->reverseTreeWidget->resizeColumnToContents(col);
    }

    graphs_[fwd_jitter_graph_]->setData(fwd_time_vals_, fwd_jitter_vals_);
    graphs_[fwd_diff_graph_]->setData(fwd_time_vals_, fwd_diff_vals_);
    graphs_[fwd_delta_graph_]->setData(fwd_time_vals_, fwd_delta_vals_);
    graphs_[rev_jitter_graph_]->setData(rev_time_vals_, rev_jitter_vals_);
    graphs_[rev_diff_graph_]->setData(rev_time_vals_, rev_diff_vals_);
    graphs_[rev_delta_graph_]->setData(rev_time_vals_, rev_delta_vals_);

    updateGraph();

    updateWidgets();
}

void RtpAnalysisDialog::updateGraph()
{
    for (int i = 0; i < ui->streamGraph->graphCount(); i++) {
        if (ui->streamGraph->graph(i)->visible()) {
            ui->streamGraph->graph(i)->rescaleAxes(i > 0);
        }
    }
    ui->streamGraph->replot();
}

void RtpAnalysisDialog::showPlayer()
{
#ifdef QT_MULTIMEDIA_LIB
    if (num_streams_ < 1) return;

    RtpPlayerDialog rtp_player_dialog(*this, cap_file_);
    rtp_stream_info_t stream_info;

    // XXX We might want to create an "rtp_stream_id_t" struct with only
    // addresses, ports & SSRC.
    memset(&stream_info, 0, sizeof(stream_info));
    copy_address(&(stream_info.src_addr), &src_fwd_);
    stream_info.src_port = port_src_fwd_;
    copy_address(&(stream_info.dest_addr), &dst_fwd_);
    stream_info.dest_port = port_dst_fwd_;
    stream_info.ssrc = ssrc_fwd_;
    stream_info.packet_count = packet_count_fwd_;
    stream_info.setup_frame_number = setup_frame_number_fwd_;
    nstime_copy(&stream_info.start_rel_time, &start_rel_time_fwd_);

    rtp_player_dialog.addRtpStream(&stream_info);
    if (num_streams_ > 1) {
        copy_address(&(stream_info.src_addr), &src_rev_);
        stream_info.src_port = port_src_rev_;
        copy_address(&(stream_info.dest_addr), &dst_rev_);
        stream_info.dest_port = port_dst_rev_;
        stream_info.ssrc = ssrc_rev_;
        stream_info.packet_count = packet_count_rev_;
        stream_info.setup_frame_number = setup_frame_number_rev_;
        rtp_player_dialog.addRtpStream(&stream_info);
        nstime_copy(&stream_info.start_rel_time, &start_rel_time_rev_);
    }

    connect(&rtp_player_dialog, SIGNAL(goToPacket(int)), this, SIGNAL(goToPacket(int)));

    rtp_player_dialog.exec();
#endif // QT_MULTIMEDIA_LIB
}

// rtp_analysis.c:copy_file
enum { save_audio_none_, save_audio_au_, save_audio_raw_ };
void RtpAnalysisDialog::saveAudio(RtpAnalysisDialog::StreamDirection direction)
{
    if (!fwd_tempfile_->isOpen() || !rev_tempfile_->isOpen()) return;

    QString caption;

    switch (direction) {
    case dir_forward_:
        caption = tr("Save forward stream audio");
        break;
    case dir_reverse_:
        caption = tr("Save reverse stream audio");
        break;
    case dir_both_:
    default:
        caption = tr("Save audio");
        break;
    }

    QString ext_filter = tr("Sun Audio (*.au)");
    if (direction != dir_both_) {
        ext_filter.append(tr(";;Raw (*.raw)"));
    }
    QString sel_filter;
    QString file_path = QFileDialog::getSaveFileName(
                this, caption, wsApp->lastOpenDir().absoluteFilePath("Saved RTP Audio.au"),
                ext_filter, &sel_filter);

    if (file_path.isEmpty()) return;

    int save_format = save_audio_none_;
    if (file_path.endsWith(".au")) {
        save_format = save_audio_au_;
    } else if (file_path.endsWith(".raw")) {
        save_format = save_audio_raw_;
    }

    if (save_format == save_audio_none_) {
        QMessageBox::warning(this, tr("Warning"), tr("Unable to save in that format"));
        return;
    }

    if (save_format == save_audio_au_) {
        if ((((direction == dir_forward_) || (direction == dir_both_)) &&
             (fwd_statinfo_.pt != PT_PCMU) && (fwd_statinfo_.pt != PT_PCMA)) ||
             (((direction == dir_reverse_) || (direction == dir_both_)) &&
             (rev_statinfo_.pt != PT_PCMU) && (rev_statinfo_.pt != PT_PCMA))) {
            QMessageBox::warning(this, tr("Warning"), tr("Can't save in a file: saving in au format supported only for alaw/ulaw streams"));
            return;
        }
    }

    QFile      save_file(file_path);
    gint16     sample;
    gchar      pd[4];
    gboolean   stop_flag = FALSE;
    size_t     nchars;

    save_file.open(QIODevice::WriteOnly);
    fwd_tempfile_->seek(0);
    rev_tempfile_->seek(0);

    if (save_file.error() != QFile::NoError) {
        QMessageBox::warning(this, tr("Warning"), tr("Unable to save %1").arg(save_file.fileName()));
        return;
    }

    ui->hintLabel->setText(tr("Saving %1" UTF8_HORIZONTAL_ELLIPSIS).arg(save_file.fileName()));
    ui->progressFrame->showProgress(true, true, &stop_flag);

    if	(save_format == save_audio_au_) { /* au format */
        /* First we write the .au header. XXX Hope this is endian independent */
        /* the magic word 0x2e736e64 == .snd */
        phton32(pd, 0x2e736e64);
        nchars = save_file.write((const char *)pd, 4);
        if (nchars != 4)
            goto copy_file_err;
        /* header offset == 24 bytes */
        phton32(pd, 24);
        nchars = save_file.write((const char *)pd, 4);
        if (nchars != 4)
            goto copy_file_err;
        /* total length; it is permitted to set this to 0xffffffff */
        phton32(pd, 0xffffffff);
        nchars = save_file.write((const char *)pd, 4);
        if (nchars != 4)
            goto copy_file_err;
        /* encoding format == 16-bit linear PCM */
        phton32(pd, 3);
        nchars = save_file.write((const char *)pd, 4);
        if (nchars != 4)
            goto copy_file_err;
        /* sample rate == 8000 Hz */
        phton32(pd, 8000);
        nchars = save_file.write((const char *)pd, 4);
        if (nchars != 4)
            goto copy_file_err;
        /* channels == 1 */
        phton32(pd, 1);
        nchars = save_file.write((const char *)pd, 4);
        if (nchars != 4)
            goto copy_file_err;

        switch (direction) {
        /* Only forward direction */
        case dir_forward_:
        {
            char f_rawvalue;
            while (fwd_tempfile_->getChar(&f_rawvalue)) {
                if (stop_flag) {
                    break;
                }
                ui->progressFrame->setValue(fwd_tempfile_->pos() * 100 / fwd_tempfile_->size());

                if (fwd_statinfo_.pt == PT_PCMU) {
                    sample = ulaw2linear((unsigned char)f_rawvalue);
                    phton16(pd, sample);
                } else if (fwd_statinfo_.pt == PT_PCMA) {
                    sample = alaw2linear((unsigned char)f_rawvalue);
                    phton16(pd, sample);
                } else {
                    goto copy_file_err;
                }

                nchars = save_file.write((const char *)pd, 2);
                if (nchars < 2) {
                    goto copy_file_err;
                }
            }
            break;
        }
            /* Only reverse direction */
        case dir_reverse_:
        {
            char r_rawvalue;
            while (rev_tempfile_->getChar(&r_rawvalue)) {
                if (stop_flag) {
                    break;
                }
                ui->progressFrame->setValue(rev_tempfile_->pos() * 100 / rev_tempfile_->size());

                if (rev_statinfo_.pt == PT_PCMU) {
                    sample = ulaw2linear((unsigned char)r_rawvalue);
                    phton16(pd, sample);
                } else if (rev_statinfo_.pt == PT_PCMA) {
                    sample = alaw2linear((unsigned char)r_rawvalue);
                    phton16(pd, sample);
                } else {
                    goto copy_file_err;
                }

                nchars = save_file.write((const char *)pd, 2);
                if (nchars < 2) {
                    goto copy_file_err;
                }
            }
            break;
        }
            /* Both directions */
        case dir_both_:
        {
            char f_rawvalue, r_rawvalue;
            guint32 f_write_silence = 0;
            guint32 r_write_silence = 0;
            /* since conversation in one way can start later than in the other one,
                 * we have to write some silence information for one channel */
            if (fwd_statinfo_.start_time > rev_statinfo_.start_time) {
                f_write_silence = (guint32)
                        ((fwd_statinfo_.start_time - rev_statinfo_.start_time)
                         * (8000/1000));
            } else if (fwd_statinfo_.start_time < rev_statinfo_.start_time) {
                r_write_silence = (guint32)
                        ((rev_statinfo_.start_time - fwd_statinfo_.start_time)
                         * (8000/1000));
            }
            for (;;) {
                if (stop_flag) {
                    break;
                }
                int fwd_pct = (fwd_tempfile_->size() > 0 ? fwd_tempfile_->pos() * 100 / fwd_tempfile_->size() : 0);
                int rev_pct = (rev_tempfile_->size() > 0 ? rev_tempfile_->pos() * 100 / rev_tempfile_->size() : 0);
                ui->progressFrame->setValue(qMin(fwd_pct, rev_pct));

                if (f_write_silence > 0) {
                    rev_tempfile_->getChar(&r_rawvalue);
                    switch (fwd_statinfo_.reg_pt) {
                    case PT_PCMU:
                        f_rawvalue = silence_pcmu_;
                        break;
                    case PT_PCMA:
                        f_rawvalue = silence_pcma_;
                        break;
                    default:
                        f_rawvalue = 0;
                        break;
                    }
                    f_write_silence--;
                } else if (r_write_silence > 0) {
                    fwd_tempfile_->getChar(&f_rawvalue);
                    switch (rev_statinfo_.reg_pt) {
                    case PT_PCMU:
                        r_rawvalue = silence_pcmu_;
                        break;
                    case PT_PCMA:
                        r_rawvalue = silence_pcma_;
                        break;
                    default:
                        r_rawvalue = 0;
                        break;
                    }
                    r_write_silence--;
                } else {
                    fwd_tempfile_->getChar(&f_rawvalue);
                    rev_tempfile_->getChar(&r_rawvalue);
                }
                if (fwd_tempfile_->atEnd() && rev_tempfile_->atEnd())
                    break;
                if ((fwd_statinfo_.pt == PT_PCMU)
                        && (rev_statinfo_.pt == PT_PCMU)) {
                    sample = (ulaw2linear((unsigned char)r_rawvalue)
                              + ulaw2linear((unsigned char)f_rawvalue)) / 2;
                    phton16(pd, sample);
                }
                else if ((fwd_statinfo_.pt == PT_PCMA)
                         && (rev_statinfo_.pt == PT_PCMA)) {
                    sample = (alaw2linear((unsigned char)r_rawvalue)
                              + alaw2linear((unsigned char)f_rawvalue)) / 2;
                    phton16(pd, sample);
                } else {
                    goto copy_file_err;
                }

                nchars = save_file.write((const char *)pd, 2);
                if (nchars < 2) {
                    goto copy_file_err;
                }
            }
        }
        }
    } else if (save_format == save_audio_raw_) { /* raw format */
        QFile *tempfile;
        int progress_pct;

        switch (direction) {
        /* Only forward direction */
        case dir_forward_: {
            progress_pct = fwd_tempfile_->pos() * 100 / fwd_tempfile_->size();
            tempfile = fwd_tempfile_;
            break;
        }
            /* only reversed direction */
        case dir_reverse_: {
            progress_pct = rev_tempfile_->pos() * 100 / rev_tempfile_->size();
            tempfile = rev_tempfile_;
            break;
        }
        default: {
            goto copy_file_err;
        }
        }

        int chunk_size = 65536;
        /* XXX how do you just copy the file? */
        while (chunk_size > 0) {
            if (stop_flag)
                break;
            QByteArray bytes = tempfile->read(chunk_size);
            ui->progressFrame->setValue(progress_pct);

            if (!save_file.write(bytes)) {
                goto copy_file_err;
            }
            chunk_size = bytes.length();
        }
    }

copy_file_err:
    ui->progressFrame->hide();
    updateWidgets();
    return;
}

// XXX The GTK+ UI saves the length and timestamp.
void RtpAnalysisDialog::saveCsv(RtpAnalysisDialog::StreamDirection direction)
{
    QString caption;

    switch (direction) {
    case dir_forward_:
        caption = tr("Save forward stream CSV");
        break;
    case dir_reverse_:
        caption = tr("Save reverse stream CSV");
        break;
    case dir_both_:
    default:
        caption = tr("Save CSV");
        break;
    }

    QString file_path = QFileDialog::getSaveFileName(
                this, caption, wsApp->lastOpenDir().absoluteFilePath("RTP Packet Data.csv"),
                tr("Comma-separated values (*.csv)"));

    if (file_path.isEmpty()) return;

    QFile save_file(file_path);
    save_file.open(QFile::WriteOnly);

    if (direction == dir_forward_ || direction == dir_both_) {
        save_file.write("Forward\n");

        for (int row = 0; row < ui->forwardTreeWidget->topLevelItemCount(); row++) {
            QTreeWidgetItem *ti = ui->forwardTreeWidget->topLevelItem(row);
            if (ti->type() != rtp_analysis_type_) continue;
            RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)ti);
            QStringList values;
            foreach (QVariant v, ra_ti->rowData()) {
                if (!v.isValid()) {
                    values << "\"\"";
                } else if ((int) v.type() == (int) QMetaType::QString) {
                    values << QString("\"%1\"").arg(v.toString());
                } else {
                    values << v.toString();
                }
            }
            save_file.write(values.join(",").toUtf8());
            save_file.write("\n");
        }
    }
    if (direction == dir_both_) {
        save_file.write("\n");
    }
    if (direction == dir_reverse_ || direction == dir_both_) {
        save_file.write("Reverse\n");

        for (int row = 0; row < ui->forwardTreeWidget->topLevelItemCount(); row++) {
            QTreeWidgetItem *ti = ui->forwardTreeWidget->topLevelItem(row);
            if (ti->type() != rtp_analysis_type_) continue;
            RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)ti);
            QStringList values;
            foreach (QVariant v, ra_ti->rowData()) {
                if (!v.isValid()) {
                    values << "\"\"";
                } else if ((int) v.type() == (int) QMetaType::QString) {
                    values << QString("\"%1\"").arg(v.toString());
                } else {
                    values << v.toString();
                }
            }
            save_file.write(values.join(",").toUtf8());
            save_file.write("\n");
        }
    }
}

bool RtpAnalysisDialog::eventFilter(QObject *, QEvent *event)
{
    if (event->type() != QEvent::KeyPress) return false;

    QKeyEvent *kevt = static_cast<QKeyEvent *>(event);

    switch(kevt->key()) {
    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        return true;
    case Qt::Key_N:
        on_actionNextProblem_triggered();
        return true;
    default:
        break;
    }
    return false;
}

void RtpAnalysisDialog::graphClicked(QMouseEvent *event)
{
    updateWidgets();
    if (event->button() == Qt::RightButton) {
        graph_ctx_menu_.exec(event->globalPos());
    }
}

void RtpAnalysisDialog::findStreams()
{
    const gchar filter_text[] = "rtp && rtp.version == 2 && rtp.ssrc && (ip || ipv6)";
    dfilter_t *sfcode;
    gchar *err_msg;

    /* Try to get the hfid for "rtp.ssrc". */
    int hfid_rtp_ssrc = proto_registrar_get_id_byname("rtp.ssrc");
    if (hfid_rtp_ssrc == -1) {
        err_str_ = tr("There is no \"rtp.ssrc\" field in this version of Wireshark.");
        updateWidgets();
        return;
    }

    /* Try to compile the filter. */
    if (!dfilter_compile(filter_text, &sfcode, &err_msg)) {
        err_str_ = QString(err_msg);
        g_free(err_msg);
        updateWidgets();
        return;
    }

    if (!cap_file_.capFile() || !cap_file_.capFile()->current_frame) close();

    frame_data *fdata = cap_file_.capFile()->current_frame;

    if (!cf_read_record(cap_file_.capFile(), fdata)) close();

    epan_dissect_t edt;

    epan_dissect_init(&edt, cap_file_.capFile()->epan, TRUE, FALSE);
    epan_dissect_prime_dfilter(&edt, sfcode);
    epan_dissect_prime_hfid(&edt, hfid_rtp_ssrc);
    epan_dissect_run(&edt, cap_file_.capFile()->cd_t, &cap_file_.capFile()->phdr,
                     frame_tvbuff_new_buffer(fdata, &cap_file_.capFile()->buf), fdata, NULL);

    /*
     * Packet must be an RTPv2 packet with an SSRC; we use the filter to
     * check.
     */
    if (!dfilter_apply_edt(sfcode, &edt)) {
        epan_dissect_cleanup(&edt);
        dfilter_free(sfcode);
        err_str_ = tr("Please select an RTPv2 packet with an SSRC value");
        updateWidgets();
        return;
    }

    dfilter_free(sfcode);

    /* OK, it is an RTP frame. Let's get the IP and port values */
    copy_address(&(src_fwd_), &(edt.pi.src));
    copy_address(&(dst_fwd_), &(edt.pi.dst));
    port_src_fwd_ = edt.pi.srcport;
    port_dst_fwd_ = edt.pi.destport;

    /* assume the inverse ip/port combination for the reverse direction */
    copy_address(&(src_rev_), &(edt.pi.dst));
    copy_address(&(dst_rev_), &(edt.pi.src));
    port_src_rev_ = edt.pi.destport;
    port_dst_rev_ = edt.pi.srcport;

    /* now we need the SSRC value of the current frame */
    GPtrArray *gp = proto_get_finfo_ptr_array(edt.tree, hfid_rtp_ssrc);
    if (gp == NULL || gp->len == 0) {
        /* XXX - should not happen, as the filter includes rtp.ssrc */
        epan_dissect_cleanup(&edt);
        err_str_ = tr("SSRC value not found.");
        updateWidgets();
        return;
    }
    ssrc_fwd_ = fvalue_get_uinteger(&((field_info *)gp->pdata[0])->value);

    /* Register the tap listener */
    memset(&tapinfo_, 0, sizeof(rtpstream_tapinfo_t));
    tapinfo_.tap_data = this;
    tapinfo_.mode = TAP_ANALYSE;

//    register_tap_listener_rtp_stream(&tapinfo_, NULL);
    /* Scan for RTP streams (redissect all packets) */
    rtpstream_scan(&tapinfo_, cap_file_.capFile(), NULL);

    for (GList *strinfo_list = g_list_first(tapinfo_.strinfo_list); strinfo_list; strinfo_list = g_list_next(strinfo_list)) {
        rtp_stream_info_t * strinfo = (rtp_stream_info_t*)(strinfo_list->data);
        if (addresses_equal(&(strinfo->src_addr), &(src_fwd_))
            && (strinfo->src_port == port_src_fwd_)
            && (addresses_equal(&(strinfo->dest_addr), &(dst_fwd_)))
            && (strinfo->dest_port == port_dst_fwd_))
        {
            packet_count_fwd_ = strinfo->packet_count;
            setup_frame_number_fwd_ = strinfo->setup_frame_number;
            nstime_copy(&start_rel_time_fwd_, &strinfo->start_rel_time);
            num_streams_++;
        }

        if (addresses_equal(&(strinfo->src_addr), &(src_rev_))
            && (strinfo->src_port == port_src_rev_)
            && (addresses_equal(&(strinfo->dest_addr), &(dst_rev_)))
            && (strinfo->dest_port == port_dst_rev_))
        {
            packet_count_rev_ = strinfo->packet_count;
            setup_frame_number_rev_ = strinfo->setup_frame_number;
            nstime_copy(&start_rel_time_rev_, &strinfo->start_rel_time);
            num_streams_++;
            if (ssrc_rev_ == 0) {
                ssrc_rev_ = strinfo->ssrc;
            }
        }
    }
}

void RtpAnalysisDialog::showStreamMenu(QPoint pos)
{
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->tabWidget->currentWidget());
    if (!cur_tree) return;

    updateWidgets();
    stream_ctx_menu_.popup(cur_tree->viewport()->mapToGlobal(pos));
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
