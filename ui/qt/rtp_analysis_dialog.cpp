/* rtp_analysis_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_analysis_dialog.h"
#include <ui_rtp_analysis_dialog.h>

#include "file.h"
#include "frame_tvbuff.h"

#include "epan/epan_dissect.h"
#include "epan/rtp_pt.h"

#include "epan/dfilter/dfilter.h"

#include "epan/dissectors/packet-rtp.h"

#include <ui/rtp_media.h>

#include "ui/help_url.h"
#include "ui/simple_dialog.h"
#include <wsutil/utf8_entities.h>

#include <wsutil/g711.h>
#include <wsutil/pint.h>

#include <QMessageBox>
#include <QPushButton>
#include <QTemporaryFile>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "rtp_player_dialog.h"
#include <ui/qt/utils/stock_icon.h>
#include "wireshark_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

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

    uint32_t frameNum() { return frame_num_; }
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
    uint32_t frame_num_;
    uint32_t sequence_num_;
    uint32_t pkt_len_;
    uint32_t flags_;
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

RtpAnalysisDialog::RtpAnalysisDialog(QWidget &parent, CaptureFile &cf, rtpstream_info_t *stream_fwd, rtpstream_info_t *stream_rev) :
    WiresharkDialog(parent, cf),
    ui(new Ui::RtpAnalysisDialog),
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
    stream_ctx_menu_.addAction(ui->actionSaveAudioUnsync);
    stream_ctx_menu_.addAction(ui->actionSaveForwardAudioUnsync);
    stream_ctx_menu_.addAction(ui->actionSaveReverseAudioUnsync);
    stream_ctx_menu_.addSeparator();
    stream_ctx_menu_.addAction(ui->actionSaveAudioSyncStream);
    stream_ctx_menu_.addAction(ui->actionSaveForwardAudioSyncStream);
    stream_ctx_menu_.addAction(ui->actionSaveReverseAudioSyncStream);
    stream_ctx_menu_.addSeparator();
    stream_ctx_menu_.addAction(ui->actionSaveAudioSyncFile);
    stream_ctx_menu_.addAction(ui->actionSaveForwardAudioSyncFile);
    stream_ctx_menu_.addAction(ui->actionSaveReverseAudioSyncFile);
    stream_ctx_menu_.addSeparator();
    stream_ctx_menu_.addAction(ui->actionSaveCsv);
    stream_ctx_menu_.addAction(ui->actionSaveForwardCsv);
    stream_ctx_menu_.addAction(ui->actionSaveReverseCsv);
    stream_ctx_menu_.addSeparator();
    stream_ctx_menu_.addAction(ui->actionSaveGraph);
    set_action_shortcuts_visible_in_context_menu(stream_ctx_menu_.actions());

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

    memset(&fwd_statinfo_, 0, sizeof(fwd_statinfo_));
    memset(&rev_statinfo_, 0, sizeof(rev_statinfo_));

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
        ui->actionSaveAudioUnsync->setEnabled(false);
        ui->actionSaveForwardAudioUnsync->setEnabled(false);
        ui->actionSaveReverseAudioUnsync->setEnabled(false);
        ui->actionSaveAudioSyncStream->setEnabled(false);
        ui->actionSaveForwardAudioSyncStream->setEnabled(false);
        ui->actionSaveReverseAudioSyncStream->setEnabled(false);
        ui->actionSaveAudioSyncFile->setEnabled(false);
        ui->actionSaveForwardAudioSyncFile->setEnabled(false);
        ui->actionSaveReverseAudioSyncFile->setEnabled(false);
    }

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    QMenu *save_menu = new QMenu(save_bt);
    save_menu->addAction(ui->actionSaveAudioUnsync);
    save_menu->addAction(ui->actionSaveForwardAudioUnsync);
    save_menu->addAction(ui->actionSaveReverseAudioUnsync);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveAudioSyncStream);
    save_menu->addAction(ui->actionSaveForwardAudioSyncStream);
    save_menu->addAction(ui->actionSaveReverseAudioSyncStream);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveAudioSyncFile);
    save_menu->addAction(ui->actionSaveForwardAudioSyncFile);
    save_menu->addAction(ui->actionSaveReverseAudioSyncFile);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveCsv);
    save_menu->addAction(ui->actionSaveForwardCsv);
    save_menu->addAction(ui->actionSaveReverseCsv);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveGraph);
    save_bt->setMenu(save_menu);

    if (stream_fwd) { // XXX What if stream_fwd == 0 && stream_rev != 0?
        rtpstream_info_copy_deep(&fwd_statinfo_, stream_fwd);
        num_streams_=1;
        if (stream_rev) {
            rtpstream_info_copy_deep(&rev_statinfo_, stream_rev);
            num_streams_=2;
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
//    remove_tap_listener_rtpstream(&tapinfo_);
    rtpstream_info_free_data(&fwd_statinfo_);
    rtpstream_info_free_data(&rev_statinfo_);
    delete fwd_tempfile_;
    delete rev_tempfile_;
}

void RtpAnalysisDialog::captureFileClosing()
{
    updateWidgets();
    WiresharkDialog::captureFileClosing();
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

    bool enable_save_fwd_audio = fwd_statinfo_.rtp_stats.total_nr && (save_payload_error_ == TAP_RTP_NO_ERROR);
    bool enable_save_rev_audio = rev_statinfo_.rtp_stats.total_nr && (save_payload_error_ == TAP_RTP_NO_ERROR);
    ui->actionSaveAudioUnsync->setEnabled(enable_save_fwd_audio && enable_save_rev_audio);
    ui->actionSaveForwardAudioUnsync->setEnabled(enable_save_fwd_audio);
    ui->actionSaveReverseAudioUnsync->setEnabled(enable_save_rev_audio);
    ui->actionSaveAudioSyncStream->setEnabled(enable_save_fwd_audio && enable_save_rev_audio);
    ui->actionSaveForwardAudioSyncStream->setEnabled(enable_save_fwd_audio && enable_save_rev_audio);
    ui->actionSaveReverseAudioSyncStream->setEnabled(enable_save_fwd_audio && enable_save_rev_audio);
    ui->actionSaveAudioSyncFile->setEnabled(enable_save_fwd_audio && enable_save_rev_audio);
    ui->actionSaveForwardAudioSyncFile->setEnabled(enable_save_fwd_audio);
    ui->actionSaveReverseAudioSyncFile->setEnabled(enable_save_rev_audio);

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
    if (!test_ti) test_ti = cur_tree->topLevelItem(0);
    while (test_ti != sel_ti) {
        RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)test_ti);
        if (!ra_ti->frameStatus()) {
            cur_tree->setCurrentItem(ra_ti);
            break;
        }

        test_ti = cur_tree->itemBelow(test_ti);
        if (!test_ti) test_ti = cur_tree->topLevelItem(0);
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

void RtpAnalysisDialog::on_actionSaveAudioUnsync_triggered()
{
    saveAudio(dir_both_, sync_unsync_);
}

void RtpAnalysisDialog::on_actionSaveForwardAudioUnsync_triggered()
{
    saveAudio(dir_forward_, sync_unsync_);
}

void RtpAnalysisDialog::on_actionSaveReverseAudioUnsync_triggered()
{
    saveAudio(dir_reverse_, sync_unsync_);
}

void RtpAnalysisDialog::on_actionSaveAudioSyncStream_triggered()
{
    saveAudio(dir_both_, sync_sync_stream_);
}

void RtpAnalysisDialog::on_actionSaveForwardAudioSyncStream_triggered()
{
    saveAudio(dir_forward_, sync_sync_stream_);
}

void RtpAnalysisDialog::on_actionSaveReverseAudioSyncStream_triggered()
{
    saveAudio(dir_reverse_, sync_sync_stream_);
}

void RtpAnalysisDialog::on_actionSaveAudioSyncFile_triggered()
{
    saveAudio(dir_both_, sync_sync_file_);
}

void RtpAnalysisDialog::on_actionSaveForwardAudioSyncFile_triggered()
{
    saveAudio(dir_forward_, sync_sync_file_);
}

void RtpAnalysisDialog::on_actionSaveReverseAudioSyncFile_triggered()
{
    saveAudio(dir_reverse_, sync_sync_file_);
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
        save_file += QString("/%1").arg(cap_file_.fileBaseName());
    }
    file_name = WiresharkFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Graph As" UTF8_HORIZONTAL_ELLIPSIS)),
                                             save_file, filter, &extension);

    if (!file_name.isEmpty()) {
        bool save_ok = false;
        // https://www.qcustomplot.com/index.php/support/forum/63
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

tap_packet_status RtpAnalysisDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return TAP_PACKET_DONT_REDRAW;

    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)rtpinfo_ptr;
    if (!rtpinfo) return TAP_PACKET_DONT_REDRAW;

    /* we ignore packets that are not displayed */
    if (pinfo->fd->passed_dfilter == 0)
        return TAP_PACKET_DONT_REDRAW;
    /* also ignore RTP Version != 2 */
    else if (rtpinfo->info_version != 2)
        return TAP_PACKET_DONT_REDRAW;
    /* is it the forward direction?  */
    else if (rtpstream_id_equal_pinfo_rtp_info(&(rtp_analysis_dialog->fwd_statinfo_.id),pinfo,rtpinfo))  {

        rtp_analysis_dialog->addPacket(true, pinfo, rtpinfo);
    }
    /* is it the reversed direction? */
    else if (rtpstream_id_equal_pinfo_rtp_info(&(rtp_analysis_dialog->rev_statinfo_.id),pinfo,rtpinfo))  {

        rtp_analysis_dialog->addPacket(false, pinfo, rtpinfo);
    }
    return TAP_PACKET_DONT_REDRAW;
}

void RtpAnalysisDialog::tapDraw(void *tapinfo_ptr)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return;
    rtp_analysis_dialog->updateStatistics();
}

void RtpAnalysisDialog::resetStatistics()
{
    memset(&fwd_statinfo_.rtp_stats, 0, sizeof(fwd_statinfo_.rtp_stats));
    memset(&rev_statinfo_.rtp_stats, 0, sizeof(rev_statinfo_.rtp_stats));

    fwd_statinfo_.rtp_stats.first_packet = true;
    rev_statinfo_.rtp_stats.first_packet = true;
    fwd_statinfo_.rtp_stats.reg_pt = PT_UNDEFINED;
    rev_statinfo_.rtp_stats.reg_pt = PT_UNDEFINED;

    ui->forwardTreeWidget->clear();
    ui->reverseTreeWidget->clear();

    for (int i = 0; i < ui->streamGraph->graphCount(); i++) {
        ui->streamGraph->graph(i)->data()->clear();
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
        rtppacket_analyse(&fwd_statinfo_.rtp_stats, pinfo, rtpinfo);
        new RtpAnalysisTreeWidgetItem(ui->forwardTreeWidget, &fwd_statinfo_.rtp_stats, pinfo, rtpinfo);

        fwd_time_vals_.append(fwd_statinfo_.rtp_stats.time / 1000);
        fwd_jitter_vals_.append(fwd_statinfo_.rtp_stats.jitter);
        fwd_diff_vals_.append(fwd_statinfo_.rtp_stats.diff);
        fwd_delta_vals_.append(fwd_statinfo_.rtp_stats.delta);

        savePayload(fwd_tempfile_, &fwd_statinfo_.rtp_stats, pinfo, rtpinfo);
    } else {
        rtppacket_analyse(&rev_statinfo_.rtp_stats, pinfo, rtpinfo);
        new RtpAnalysisTreeWidgetItem(ui->reverseTreeWidget, &rev_statinfo_.rtp_stats, pinfo, rtpinfo);

        rev_time_vals_.append(rev_statinfo_.rtp_stats.time / 1000);
        rev_jitter_vals_.append(rev_statinfo_.rtp_stats.jitter);
        rev_diff_vals_.append(rev_statinfo_.rtp_stats.diff);
        rev_delta_vals_.append(rev_statinfo_.rtp_stats.delta);

        savePayload(rev_tempfile_, &rev_statinfo_.rtp_stats, pinfo, rtpinfo);
    }

}

void RtpAnalysisDialog::savePayload(QTemporaryFile *tmpfile, tap_rtp_stat_t *statinfo, packet_info *pinfo, const _rtp_info *rtpinfo)
{
    /* Is this the first packet we got in this direction? */
//    if (statinfo->flags & STAT_FLAG_FIRST) {
//        if (saveinfo->fp == NULL) {
//            saveinfo->saved = false;
//            saveinfo->error_type = TAP_RTP_FILE_OPEN_ERROR;
//        } else {
//            saveinfo->saved = true;
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
    if ((rtpinfo->info_padding_set != false) &&
        (rtpinfo->info_padding_count > rtpinfo->info_payload_len))
    {
        tmpfile->close();
        err_str_ = tr("Can't save in a file: RTP data with padding.");
        save_payload_error_ = TAP_RTP_PADDING_ERROR;
        return;
    }

    if ((rtpinfo->info_payload_type == PT_CN) ||
        (rtpinfo->info_payload_type == PT_CN_OLD)) {
    } else { /* All other payloads */
        const char *data;
        int64_t nchars;
        tap_rtp_save_data_t save_data;

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
        data = (const char *) rtpinfo->info_data + rtpinfo->info_payload_offset;

        /* Store information about timestamp, payload_type and payload in file */
        save_data.timestamp = statinfo->timestamp;
        save_data.payload_type = rtpinfo->info_payload_type;
        save_data.payload_len = rtpinfo->info_payload_len - rtpinfo->info_padding_count;
        nchars = tmpfile->write((char *)&save_data, sizeof(save_data));
        if (nchars != sizeof(save_data)) {
                /* Write error or short write */
                err_str_ = tr("Can't save in a file: File I/O problem.");
                save_payload_error_ = TAP_RTP_FILE_WRITE_ERROR;
                tmpfile->close();
                return;
        }
        if (save_data.payload_len > 0) {
            nchars = tmpfile->write(data, save_data.payload_len);
            if ((size_t)nchars != save_data.payload_len) {
                /* Write error or short write */
                err_str_ = tr("Can't save in a file: File I/O problem.");
                save_payload_error_ = TAP_RTP_FILE_WRITE_ERROR;
                tmpfile->close();
                return;
            }
        }
        return;
    }
    return;
}

void RtpAnalysisDialog::updateStatistics()
{
    unsigned int f_clock_rate = fwd_statinfo_.rtp_stats.clock_rate;
    unsigned int r_clock_rate = rev_statinfo_.rtp_stats.clock_rate;
    unsigned int f_expected = (fwd_statinfo_.rtp_stats.stop_seq_nr + fwd_statinfo_.rtp_stats.cycles*65536)
            - fwd_statinfo_.rtp_stats.start_seq_nr + 1;
    unsigned int r_expected = (rev_statinfo_.rtp_stats.stop_seq_nr + rev_statinfo_.rtp_stats.cycles*65536)
            - rev_statinfo_.rtp_stats.start_seq_nr + 1;
    unsigned int f_total_nr = fwd_statinfo_.rtp_stats.total_nr;
    unsigned int r_total_nr = rev_statinfo_.rtp_stats.total_nr;
    int f_lost = f_expected - f_total_nr;
    int r_lost = r_expected - r_total_nr;
    double f_sumt = fwd_statinfo_.rtp_stats.sumt;
    double f_sumTS = fwd_statinfo_.rtp_stats.sumTS;
    double f_sumt2 = fwd_statinfo_.rtp_stats.sumt2;
    double f_sumtTS = fwd_statinfo_.rtp_stats.sumtTS;
    double r_sumt = rev_statinfo_.rtp_stats.sumt;
    double r_sumTS = rev_statinfo_.rtp_stats.sumTS;
    double r_sumt2 = rev_statinfo_.rtp_stats.sumt2;
    double r_sumtTS = rev_statinfo_.rtp_stats.sumtTS;
    double f_perc, r_perc;
    double f_clock_drift = 1.0;
    double r_clock_drift = 1.0;
    double f_duration = fwd_statinfo_.rtp_stats.time - fwd_statinfo_.rtp_stats.start_time;
    double r_duration = rev_statinfo_.rtp_stats.time - rev_statinfo_.rtp_stats.start_time;

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

    QString stats_tables = "<html><head><style>td{vertical-align:bottom;}</style></head><body>\n";
    stats_tables += "<h4>Forward</h4>\n";
    stats_tables += QString("<p>%1:%2 " UTF8_RIGHTWARDS_ARROW)
            .arg(address_to_qstring(&fwd_statinfo_.id.src_addr, true))
            .arg(fwd_statinfo_.id.src_port);
    stats_tables += QString("<br>%1:%2</p>\n")
            .arg(address_to_qstring(&fwd_statinfo_.id.dst_addr, true))
            .arg(fwd_statinfo_.id.dst_port);
    stats_tables += "<p><table>\n";
    stats_tables += QString("<tr><th align=\"left\">SSRC</th><td>%1</td></tr>")
            .arg(int_to_qstring(fwd_statinfo_.id.ssrc, 8, 16));
    stats_tables += QString("<tr><th align=\"left\">Max Delta</th><td>%1 ms @ %2</td></tr>")
            .arg(fwd_statinfo_.rtp_stats.max_delta, 0, 'f', 2)
            .arg(fwd_statinfo_.rtp_stats.max_nr);
    stats_tables += QString("<tr><th align=\"left\">Max Jitter</th><td>%1 ms</td></tr>")
            .arg(fwd_statinfo_.rtp_stats.max_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Mean Jitter</th><td>%1 ms</td></tr>")
            .arg(fwd_statinfo_.rtp_stats.mean_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Max Skew</th><td>%1 ms</td></tr>")
            .arg(fwd_statinfo_.rtp_stats.max_skew, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">RTP Packets</th><td>%1</td></tr>")
            .arg(f_total_nr);
    stats_tables += QString("<tr><th align=\"left\">Expected</th><td>%1</td></tr>")
            .arg(f_expected);
    stats_tables += QString("<tr><th align=\"left\">Lost</th><td>%1 (%2 %)</td></tr>")
            .arg(f_lost).arg(f_perc, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Seq Errs</th><td>%1</td></tr>")
            .arg(fwd_statinfo_.rtp_stats.sequence);
    stats_tables += QString("<tr><th align=\"left\">Start at</th><td>%1 s @ %2</td></tr>")
            .arg(fwd_statinfo_.rtp_stats.start_time / 1000.0, 0, 'f', 6)
            .arg(fwd_statinfo_.rtp_stats.first_packet_num);
    stats_tables += QString("<tr><th align=\"left\">Duration</th><td>%1 s</td></tr>")
            .arg(f_duration / 1000.0, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Clock Drift</th><td>%1 ms</td></tr>")
            .arg(f_duration * (f_clock_drift - 1.0), 0, 'f', 0);
    stats_tables += QString("<tr><th align=\"left\">Freq Drift</th><td>%1 Hz (%2 %)</td></tr>") // XXX Terminology?
            .arg(f_clock_drift * f_clock_rate, 0, 'f', 0).arg(100.0 * (f_clock_drift - 1.0), 0, 'f', 2);
    stats_tables += "</table></p>\n";

    stats_tables += "<h4>Reverse</h4>\n";
    stats_tables += QString("<p>%1:%2 " UTF8_RIGHTWARDS_ARROW)
            .arg(address_to_qstring(&rev_statinfo_.id.src_addr, true))
            .arg(rev_statinfo_.id.src_port);
    stats_tables += QString("<br>%1:%2</p>\n")
            .arg(address_to_qstring(&rev_statinfo_.id.dst_addr, true))
            .arg(rev_statinfo_.id.dst_port);
    stats_tables += "<p><table>\n";
    stats_tables += QString("<tr><th align=\"left\">SSRC</th><td>%1</td></tr>")
            .arg(int_to_qstring(rev_statinfo_.id.ssrc, 8, 16));
    stats_tables += QString("<tr><th align=\"left\">Max Delta</th><td>%1 ms @ %2</td></tr>")
            .arg(rev_statinfo_.rtp_stats.max_delta, 0, 'f', 2)
            .arg(rev_statinfo_.rtp_stats.max_nr);
    stats_tables += QString("<tr><th align=\"left\">Max Jitter</th><td>%1 ms</td></tr>")
            .arg(rev_statinfo_.rtp_stats.max_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Mean Jitter</th><td>%1 ms</td></tr>")
            .arg(rev_statinfo_.rtp_stats.mean_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Max Skew</th><td>%1 ms</td></tr>")
            .arg(rev_statinfo_.rtp_stats.max_skew, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">RTP Packets</th><td>%1</td></tr>")
            .arg(r_total_nr);
    stats_tables += QString("<tr><th align=\"left\">Expected</th><td>%1</td></tr>")
            .arg(r_expected);
    stats_tables += QString("<tr><th align=\"left\">Lost</th><td>%1 (%2 %)</td></tr>")
            .arg(r_lost).arg(r_perc, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Seq Errs</th><td>%1</td></tr>")
            .arg(rev_statinfo_.rtp_stats.sequence);
    stats_tables += QString("<tr><th align=\"left\">Start at</th><td>%1 s @ %2</td></tr>")
            .arg(rev_statinfo_.rtp_stats.start_time / 1000.0, 0, 'f', 6)
            .arg(rev_statinfo_.rtp_stats.first_packet_num);
    stats_tables += QString("<tr><th align=\"left\">Duration</th><td>%1 s</td></tr>")
            .arg(r_duration / 1000.0, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Clock Drift</th><td>%1 ms</td></tr>")
            .arg(r_duration * (r_clock_drift - 1.0), 0, 'f', 0);
    stats_tables += QString("<tr><th align=\"left\">Freq Drift</th><td>%1 Hz (%2 %)</td></tr>") // XXX Terminology?
            .arg(r_clock_drift * r_clock_rate, 0, 'f', 0).arg(100.0 * (r_clock_drift - 1.0), 0, 'f', 2);
    stats_tables += "</table></p>";
    if (rev_statinfo_.rtp_stats.total_nr) {
        stats_tables += QString("<h4>Forward to reverse<br/>start diff %1 s @ %2</h4>")
            .arg((rev_statinfo_.rtp_stats.start_time - fwd_statinfo_.rtp_stats.start_time) / 1000.0, 0, 'f', 6)
            .arg((int64_t)rev_statinfo_.rtp_stats.first_packet_num - (int64_t)fwd_statinfo_.rtp_stats.first_packet_num);
    }
    stats_tables += "</body></html>\n";

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

    RtpPlayerDialog *rtp_player_dialog = new RtpPlayerDialog(*this, cap_file_);
    rtpstream_info_t stream_info;

    // XXX We might want to create an "rtp_stream_id_t" struct with only
    // addresses, ports & SSRC.
    rtpstream_info_init(&stream_info);
    rtpstream_id_copy(&fwd_statinfo_.id, &stream_info.id);
    stream_info.packet_count = fwd_statinfo_.packet_count;
    stream_info.setup_frame_number = fwd_statinfo_.setup_frame_number;
    nstime_copy(&stream_info.start_rel_time, &fwd_statinfo_.start_rel_time);
    nstime_copy(&stream_info.stop_rel_time, &fwd_statinfo_.stop_rel_time);
    nstime_copy(&stream_info.start_abs_time, &fwd_statinfo_.start_abs_time);
    rtp_player_dialog->addRtpStream(&stream_info);

    if (num_streams_ > 1) {
        rtpstream_info_init(&stream_info);
        rtpstream_id_copy(&rev_statinfo_.id, &stream_info.id);
        stream_info.packet_count = rev_statinfo_.packet_count;
        stream_info.setup_frame_number = rev_statinfo_.setup_frame_number;
        nstime_copy(&stream_info.start_rel_time, &rev_statinfo_.start_rel_time);
        nstime_copy(&stream_info.stop_rel_time, &rev_statinfo_.stop_rel_time);
        nstime_copy(&stream_info.start_abs_time, &rev_statinfo_.start_abs_time);
        rtp_player_dialog->addRtpStream(&stream_info);
    }

    connect(rtp_player_dialog, SIGNAL(goToPacket(int)), this, SIGNAL(goToPacket(int)));

    rtp_player_dialog->setWindowModality(Qt::ApplicationModal);
    rtp_player_dialog->setAttribute(Qt::WA_DeleteOnClose);
    rtp_player_dialog->setMarkers();
    rtp_player_dialog->show();
#endif // QT_MULTIMEDIA_LIB
}

/* Convert one packet payload to samples in row */
/* It supports G.711 now, but can be extended to any other codecs */
size_t RtpAnalysisDialog::convert_payload_to_samples(unsigned int payload_type, const gchar *payload_type_names[256], QTemporaryFile *tempfile, uint8_t *pd_out, size_t payload_len, struct _GHashTable *decoders_hash)
{
    unsigned int channels = 0;
    unsigned int sample_rate = 0;
    /* Payload data are in bytes */
    uint8_t payload_data[2*4000];
    size_t decoded_bytes;
    /* Decoded audio is in samples (2 bytes) */
    SAMPLE *decode_buff = Q_NULLPTR;
    size_t decoded_samples;
    const gchar *payload_type_str = Q_NULLPTR;

    tempfile->read((char *)payload_data, payload_len);
    if (PT_UNDF_123 == payload_type) {
        /* 123 is payload used as silence in ED-137 */
        return 0;
    }

    if (payload_type_names[payload_type] != NULL) {
        payload_type_str = payload_type_names[payload_type];
    }

    /* Decoder returns count of bytes, but data are samples */
    decoded_bytes = decode_rtp_packet_payload(payload_type, payload_type_str, payload_data, payload_len, &decode_buff, decoders_hash, &channels, &sample_rate);
    decoded_samples = decoded_bytes/2;

    if (decoded_samples > 0) {
        if (sample_rate == 8000) {
            /* Change byte order to network order */
            for(size_t i = 0; i < decoded_samples; i++) {
                SAMPLE sample;
                uint8_t pd[4];

                sample = decode_buff[i];
                phton16(pd, sample);
                pd_out[2*i] = pd[0];
                pd_out[2*i+1] = pd[1];
            }
        } else {
            sae_unsupported_rate_ = true;
            decoded_samples = 0;
        }
    } else {
        sae_unsupported_codec_ = true;
        decoded_samples = 0;
    }
    g_free(decode_buff);

    return decoded_samples;
}

bool RtpAnalysisDialog::saveAudioAUSilence(size_t total_len, QFile *save_file, gboolean *stop_flag)
{
    int64_t nchars;
    uint8_t pd_out[2*4000];
    int16_t silence;
    uint8_t pd[4];

    silence = 0x0000;
    phton16(pd, silence);
    pd_out[0] = pd[0];
    pd_out[1] = pd[1];
    /* Fill whole file with silence */
    for (size_t i=0; i<total_len; i++) {
        if (*stop_flag) {
            sae_stopped_ = true;
            return false;
        }
        nchars = save_file->write((const char *)pd_out, 2);
        if (nchars < 2) {
            sae_file_error_ = true;
            return false;
        }
    }

    return true;
}

bool RtpAnalysisDialog::saveAudioAUUnidir(tap_rtp_stat_t &statinfo, const gchar *payload_type_names[256], QTemporaryFile *tempfile, QFile *save_file, int64_t header_end, gboolean *stop_flag, gboolean interleave, size_t prefix_silence)
{
    int64_t nchars;
    uint8_t pd_out[2*4000];
    uint8_t pd[4];
    tap_rtp_save_data_t save_data;
    struct _GHashTable *decoders_hash = rtp_decoder_hash_table_new();

    while (sizeof(save_data) == tempfile->read((char *)&save_data,sizeof(save_data))) {
        size_t sample_count;

        if (*stop_flag) {
            sae_stopped_ = true;
            return false;
        }

        ui->progressFrame->setValue(int(tempfile->pos() * 100 / tempfile->size()));

        sample_count=convert_payload_to_samples(save_data.payload_type, payload_type_names, tempfile, pd_out, save_data.payload_len, decoders_hash);

        if (!isSAEOK()) {
            return false;
        }
        if (sample_count > 0 ) {
            nchars = 0;
            /* Save payload samples with optional interleaving */
            for (size_t i = 0; i < sample_count; i++) {
                pd[0] = pd_out[ 2 * i ];
                pd[1] = pd_out[ 2 * i + 1 ];
                if (interleave) {
                    save_file->seek(header_end+(prefix_silence + (guint32_wraparound_diff(save_data.timestamp, statinfo.first_timestamp) + i)) * 4);
                } else {
                    save_file->seek(header_end+(prefix_silence + (guint32_wraparound_diff(save_data.timestamp, statinfo.first_timestamp) + i)) * 2);
                }
                nchars += save_file->write((const char *)pd, 2);
            }
            if ((size_t)nchars < sample_count*2) {
                sae_file_error_ = true;
                return false;
            }
        }
    }
    g_hash_table_destroy(decoders_hash);

    return true;
}

bool RtpAnalysisDialog::saveAudioAUBidir(tap_rtp_stat_t &fwd_statinfo, tap_rtp_stat_t &rev_statinfo, const gchar *fwd_payload_type_names[256], const gchar *rev_payload_type_names[256], QTemporaryFile *fwd_tempfile, QTemporaryFile *rev_tempfile, QFile *save_file, int64_t header_end, gboolean *stop_flag, size_t prefix_silence_fwd, size_t prefix_silence_rev)
{
    if (!saveAudioAUUnidir(fwd_statinfo, fwd_payload_type_names, fwd_tempfile, save_file, header_end, stop_flag, true, prefix_silence_fwd)) {
        return false;
    }

    if (!saveAudioAUUnidir(rev_statinfo, rev_payload_type_names, rev_tempfile, save_file, header_end+2, stop_flag, true, prefix_silence_rev)) {
        return false;
    }

    return true;
}

bool RtpAnalysisDialog::saveAudioAU(StreamDirection direction, QFile *save_file, gboolean *stop_flag, RtpAnalysisDialog::SyncType sync)
{
    uint8_t pd[4];
    int64_t nchars;
    int64_t header_end;
    size_t fwd_total_len;
    size_t rev_total_len;
    size_t total_len;

    /* https://pubs.opengroup.org/external/auformat.html */
    /* First we write the .au header.  All values in the header are
     * 4-byte big-endian values, so we use pntoh32() to copy them
     * to a 4-byte buffer, in big-endian order, and then write out
     * the buffer. */

    /* the magic word 0x2e736e64 == .snd */
    phton32(pd, 0x2e736e64);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        sae_file_error_ = true;
        return false;
    }
    /* header offset == 24 bytes */
    phton32(pd, 24);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        sae_file_error_ = true;
        return false;
    }
    /* total length; it is permitted to set this to 0xffffffff */
    phton32(pd, 0xffffffff);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        sae_file_error_ = true;
        return false;
    }
    /* encoding format == 16-bit linear PCM */
    phton32(pd, 3);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        sae_file_error_ = true;
        return false;
    }
    /* sample rate == 8000 Hz */
    phton32(pd, 8000);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        sae_file_error_ = true;
        return false;
    }
    /* channels == 1 or == 2 */
    switch (direction) {
        case dir_forward_: {
            phton32(pd, 1);
            break;
        }
        case dir_reverse_: {
            phton32(pd, 1);
            break;
        }
        case dir_both_: {
            phton32(pd, 2);
            break;
        }
    }
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        sae_file_error_ = true;
        return false;
    }

    header_end=save_file->pos();

    bool two_channels = rev_statinfo_.rtp_stats.total_nr && (save_payload_error_ == TAP_RTP_NO_ERROR);
    double t_min = MIN(fwd_statinfo_.rtp_stats.start_time, rev_statinfo_.rtp_stats.start_time);
    double t_fwd_diff = fwd_statinfo_.rtp_stats.start_time - t_min;
    double t_rev_diff = rev_statinfo_.rtp_stats.start_time - t_min;
    size_t fwd_samples_diff = 0;
    size_t rev_samples_diff = 0;
    size_t bidir_samples_diff = 0;

    switch (sync) {
        case sync_unsync_: {
            fwd_samples_diff = 0;
            rev_samples_diff = 0;
            bidir_samples_diff = 0;
            break;
        }
        case sync_sync_stream_: {
            if (! two_channels) {
                /* Only forward channel */
                /* This branch should not be reached ever */
                QMessageBox::warning(this, tr("Warning"), tr("Can't synchronize when only one channel is selected"));
                sae_other_error_ = true;
                return false;
            } else {
                /* Two channels */
                fwd_samples_diff = t_fwd_diff*8000/1000;
                rev_samples_diff = t_rev_diff*8000/1000;
                bidir_samples_diff = 0;
            }
            break;
        }
        case sync_sync_file_: {
            if (! two_channels) {
                /* Only forward channel */
                fwd_samples_diff = t_fwd_diff*8000/1000;
                rev_samples_diff = 0;
                bidir_samples_diff = fwd_samples_diff;
            } else {
                /* Two channels */
                fwd_samples_diff = t_fwd_diff*8000/1000;
                rev_samples_diff = t_rev_diff*8000/1000;
                bidir_samples_diff = t_min*8000/1000;
            }
            break;
        }
    }

    switch (direction) {
        /* Only forward direction */
        case dir_forward_: {
            fwd_total_len = guint32_wraparound_diff(fwd_statinfo_.rtp_stats.timestamp, fwd_statinfo_.rtp_stats.first_timestamp) + fwd_statinfo_.rtp_stats.last_payload_len;
            if (!saveAudioAUSilence(fwd_total_len + fwd_samples_diff + bidir_samples_diff, save_file, stop_flag)) {
                return false;
            }
            if (!saveAudioAUUnidir(fwd_statinfo_.rtp_stats, fwd_statinfo_.payload_type_names, fwd_tempfile_, save_file, header_end, stop_flag, false, fwd_samples_diff + bidir_samples_diff)) {
                return false;
            }
            break;
        }
        /* Only reverse direction */
        case dir_reverse_: {
            rev_total_len = guint32_wraparound_diff(rev_statinfo_.rtp_stats.timestamp, rev_statinfo_.rtp_stats.first_timestamp) + rev_statinfo_.rtp_stats.last_payload_len;
            if (!saveAudioAUSilence(rev_total_len + rev_samples_diff + bidir_samples_diff, save_file, stop_flag)) {
                return false;
            }

            if (!saveAudioAUUnidir(rev_statinfo_.rtp_stats, rev_statinfo_.payload_type_names, rev_tempfile_, save_file, header_end, stop_flag, false, rev_samples_diff + bidir_samples_diff)) {
                return false;
            }
            break;
        }
        /* Both directions */
        case dir_both_: {
            fwd_total_len = guint32_wraparound_diff(fwd_statinfo_.rtp_stats.timestamp, fwd_statinfo_.rtp_stats.first_timestamp) + fwd_statinfo_.rtp_stats.last_payload_len;
            rev_total_len = guint32_wraparound_diff(rev_statinfo_.rtp_stats.timestamp, rev_statinfo_.rtp_stats.first_timestamp) + rev_statinfo_.rtp_stats.last_payload_len;
            total_len = MAX(fwd_total_len + fwd_samples_diff, rev_total_len + rev_samples_diff);
            if (!saveAudioAUSilence((total_len + bidir_samples_diff) * 2, save_file, stop_flag)) {
                return false;
            }
            if (!saveAudioAUBidir(fwd_statinfo_.rtp_stats, rev_statinfo_.rtp_stats, fwd_statinfo_.payload_type_names, rev_statinfo_.payload_type_names, fwd_tempfile_, rev_tempfile_, save_file, header_end, stop_flag, fwd_samples_diff + bidir_samples_diff, rev_samples_diff + bidir_samples_diff)) {
                return false;
            }
        }
    }

    return true;
}

bool RtpAnalysisDialog::saveAudioRAW(StreamDirection direction, QFile *save_file, gboolean *stop_flag)
{
    QFile *tempfile;
    tap_rtp_save_data_t save_data;

    switch (direction) {
        /* Only forward direction */
        case dir_forward_: {
            tempfile = fwd_tempfile_;
            break;
        }
        /* Only reversed direction */
        case dir_reverse_: {
            tempfile = rev_tempfile_;
            break;
        }
        default: {
            QMessageBox::warning(this, tr("Warning"), tr("None of channels was selected"));
            sae_other_error_ = true;
            return false;
        }
    }

    /* Copy just payload */
    while (sizeof(save_data) == tempfile->read((char *)&save_data,sizeof(save_data))) {
        char f_rawvalue;

        if (*stop_flag) {
            sae_stopped_ = true;
            return false;
        }

        ui->progressFrame->setValue(int(tempfile->pos() * 100 / fwd_tempfile_->size()));

        if (save_data.payload_len > 0) {
            for (size_t i = 0; i < save_data.payload_len; i++) {
                if (sizeof(f_rawvalue) != tempfile->read((char *)&f_rawvalue, sizeof(f_rawvalue))) {
                    sae_file_error_ = true;
                    return false;
                }
                if (sizeof(f_rawvalue) != save_file->write((char *)&f_rawvalue, sizeof(f_rawvalue))) {
                    sae_file_error_ = true;
                    return false;
                }
            }
        }
    }

    return true;
}

// rtp_analysis.c:copy_file
enum { save_audio_none_, save_audio_au_, save_audio_raw_ };
void RtpAnalysisDialog::saveAudio(RtpAnalysisDialog::StreamDirection direction, RtpAnalysisDialog::SyncType sync)
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
        caption = tr("Save forward and reverse stream audio");
        break;
    }

    QString ext_filter = "";
    QString ext_filter_au = tr("Sun Audio (*.au)");
    QString ext_filter_raw = tr("Raw (*.raw)");
    ext_filter.append(ext_filter_au);
    if (direction != dir_both_) {
        ext_filter.append(";;");
        ext_filter.append(ext_filter_raw);
    }
    QString sel_filter;
    QString file_path = WiresharkFileDialog::getSaveFileName(
                this, caption, wsApp->lastOpenDir().absoluteFilePath("Saved RTP Audio.au"),
                ext_filter, &sel_filter);

    if (file_path.isEmpty()) return;

    int save_format = save_audio_none_;
    if (0 == QString::compare(sel_filter, ext_filter_au)) {
        save_format = save_audio_au_;
    } else if (0 == QString::compare(sel_filter, ext_filter_raw)) {
        save_format = save_audio_raw_;
    }

    if (save_format == save_audio_none_) {
        QMessageBox::warning(this, tr("Warning"), tr("Unable to save in that format"));
        return;
    }

    QFile      save_file(file_path);
    gboolean   stop_flag = false;

    save_file.open(QIODevice::WriteOnly);
    fwd_tempfile_->seek(0);
    rev_tempfile_->seek(0);

    if (save_file.error() != QFile::NoError) {
        QMessageBox::warning(this, tr("Warning"), tr("Unable to save %1").arg(save_file.fileName()));
        return;
    }

    ui->hintLabel->setText(tr("Saving %1" UTF8_HORIZONTAL_ELLIPSIS).arg(save_file.fileName()));
    ui->progressFrame->showProgress(tr("Analyzing RTP"), true, true, &stop_flag);

    clearSAEErrors();
    if (save_format == save_audio_au_) { /* au format */

        if (!saveAudioAU(direction, &save_file, &stop_flag, sync)) {
        }
    } else if (save_format == save_audio_raw_) { /* raw format */
        if (!saveAudioRAW(direction, &save_file, &stop_flag)) {
        }
    }
    if (!isSAEOK()) {
      // Other error was already handled
        if (!sae_other_error_) {
            if (sae_stopped_) {
                QMessageBox::warning(this, tr("Information"), tr("Save was interrupted"));
            }
            else if (sae_file_error_) {
                QMessageBox::warning(this, tr("Error"), tr("Save or read of file was failed during saving"));
            }
            else if (sae_unsupported_codec_) {
                QMessageBox::warning(this, tr("Warning"), tr("Codec is not supported, file is incomplete"));
            }
            else if (sae_unsupported_rate_) {
                QMessageBox::warning(this, tr("Warning"), tr("Codec rate is not supported, file is incomplete"));
            }
            else {
                QMessageBox::warning(this, tr("Warning"), tr("Unknown error occured"));
            }
        }
    }

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

    QString file_path = WiresharkFileDialog::getSaveFileName(
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

        for (int row = 0; row < ui->reverseTreeWidget->topLevelItemCount(); row++) {
            QTreeWidgetItem *ti = ui->reverseTreeWidget->topLevelItem(row);
            if (ti->type() != rtp_analysis_type_) continue;
            RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)ti);
            QStringList values;
            foreach (QVariant v, ra_ti->rowData()) {
                if (!v.isValid()) {
                    values << "\"\"";
                } else if (v.type() == QVariant::String) {
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
        graph_ctx_menu_.popup(event->globalPos());
    }
}

void RtpAnalysisDialog::clearSAEErrors()
{ sae_stopped_ = false;
  sae_file_error_ = false;
  sae_unsupported_codec_ = false;
  sae_unsupported_rate_ = false;
  sae_other_error_ = false;
}

bool RtpAnalysisDialog::isSAEOK()
{ return !(sae_stopped_ ||
           sae_file_error_ ||
           sae_unsupported_codec_ ||
           sae_unsupported_rate_ ||
           sae_other_error_
         )
  ;
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

    if (!cf_read_current_record(cap_file_.capFile())) close();

    frame_data *fdata = cap_file_.capFile()->current_frame;

    epan_dissect_t edt;

    epan_dissect_init(&edt, cap_file_.capFile()->epan, true, false);
    epan_dissect_prime_with_dfilter(&edt, sfcode);
    epan_dissect_prime_with_hfid(&edt, hfid_rtp_ssrc);
    epan_dissect_run(&edt, cap_file_.capFile()->cd_t, &cap_file_.capFile()->rec,
                     frame_tvbuff_new_buffer(&cap_file_.capFile()->provider, fdata, &cap_file_.capFile()->buf),
                     fdata, NULL);

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
    rtpstream_id_copy_pinfo(&(edt.pi),&(fwd_statinfo_.id),false);

    /* assume the inverse ip/port combination for the reverse direction */
    rtpstream_id_copy_pinfo(&(edt.pi),&(rev_statinfo_.id),true);

    /* now we need the SSRC value of the current frame */
    GPtrArray *gp = proto_get_finfo_ptr_array(edt.tree, hfid_rtp_ssrc);
    if (gp == NULL || gp->len == 0) {
        /* XXX - should not happen, as the filter includes rtp.ssrc */
        epan_dissect_cleanup(&edt);
        err_str_ = tr("SSRC value not found.");
        updateWidgets();
        return;
    }
    fwd_statinfo_.id.ssrc = fvalue_get_uinteger(&((field_info *)gp->pdata[0])->value);

    epan_dissect_cleanup(&edt);

    /* Register the tap listener */
    memset(&tapinfo_, 0, sizeof(rtpstream_tapinfo_t));
    tapinfo_.tap_data = this;
    tapinfo_.mode = TAP_ANALYSE;

//    register_tap_listener_rtpstream(&tapinfo_, NULL);
    /* Scan for RTP streams (redissect all packets) */
    rtpstream_scan(&tapinfo_, cap_file_.capFile(), Q_NULLPTR);

    for (GList *strinfo_list = g_list_first(tapinfo_.strinfo_list); strinfo_list; strinfo_list = gxx_list_next(strinfo_list)) {
        rtpstream_info_t * strinfo = gxx_list_data(rtpstream_info_t*, strinfo_list);
        if (rtpstream_id_equal(&(strinfo->id), &(fwd_statinfo_.id),RTPSTREAM_ID_EQUAL_NONE))
        {
            fwd_statinfo_.packet_count = strinfo->packet_count;
            fwd_statinfo_.setup_frame_number = strinfo->setup_frame_number;
            nstime_copy(&fwd_statinfo_.start_rel_time, &strinfo->start_rel_time);
            nstime_copy(&fwd_statinfo_.stop_rel_time, &strinfo->stop_rel_time);
            nstime_copy(&fwd_statinfo_.start_abs_time, &strinfo->start_abs_time);
            num_streams_++;
        }

        if (rtpstream_id_equal(&(strinfo->id), &(rev_statinfo_.id),RTPSTREAM_ID_EQUAL_NONE))
        {
            rev_statinfo_.packet_count = strinfo->packet_count;
            rev_statinfo_.setup_frame_number = strinfo->setup_frame_number;
            nstime_copy(&rev_statinfo_.start_rel_time, &strinfo->start_rel_time);
            nstime_copy(&rev_statinfo_.stop_rel_time, &strinfo->stop_rel_time);
            nstime_copy(&rev_statinfo_.start_abs_time, &strinfo->start_abs_time);
            num_streams_++;
            if (rev_statinfo_.id.ssrc == 0) {
                rev_statinfo_.id.ssrc = strinfo->id.ssrc;
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
