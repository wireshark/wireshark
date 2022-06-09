/* iax2_analysis_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "iax2_analysis_dialog.h"
#include <ui_iax2_analysis_dialog.h>

#include "file.h"
#include "frame_tvbuff.h"

#include <epan/epan_dissect.h>
#include <epan/rtp_pt.h>

#include <epan/dfilter/dfilter.h>

#include <epan/dissectors/packet-iax2.h>

#include "ui/help_url.h"
#ifdef IAX2_RTP_STREAM_CHECK
#include "ui/rtp_stream.h"
#endif
#include <wsutil/utf8_entities.h>

#include <wsutil/g711.h>
#include <wsutil/pint.h>

#include <QMessageBox>
#include <QPushButton>
#include <QTemporaryFile>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/stock_icon.h>
#include "main_application.h"
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
    delta_col_,
    jitter_col_,
    bandwidth_col_,
    status_col_,
    length_col_
};

static const QRgb color_rtp_warn_ = 0xffdbbf;

enum { iax2_analysis_type_ = 1000 };
class Iax2AnalysisTreeWidgetItem : public QTreeWidgetItem
{
public:
    Iax2AnalysisTreeWidgetItem(QTreeWidget *tree, tap_iax2_stat_t *statinfo, packet_info *pinfo) :
        QTreeWidgetItem(tree, iax2_analysis_type_),
        frame_num_(pinfo->num),
        pkt_len_(pinfo->fd->pkt_len),
        flags_(statinfo->flags),
        bandwidth_(statinfo->bandwidth),
        ok_(false)
    {
        if (flags_ & STAT_FLAG_FIRST) {
            delta_ = 0.0;
            jitter_ = 0.0;
        } else {
            delta_ = statinfo->delta;
            jitter_ = statinfo->jitter;
        }

        QColor bg_color = QColor();
        QString status;

        if (statinfo->flags & STAT_FLAG_WRONG_SEQ) {
            status = QObject::tr("Wrong sequence number");
            bg_color = ColorUtils::expert_color_error;
        } else if (statinfo->flags & STAT_FLAG_REG_PT_CHANGE) {
            status = QObject::tr("Payload changed to PT=%1").arg(statinfo->pt);
            bg_color = color_rtp_warn_;
        } else if (statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP) {
            status = QObject::tr("Incorrect timestamp");
            /* color = COLOR_WARNING; */
            bg_color = color_rtp_warn_;
        } else if ((statinfo->flags & STAT_FLAG_PT_CHANGE)
            &&  !(statinfo->flags & STAT_FLAG_FIRST)
            &&  !(statinfo->flags & STAT_FLAG_PT_CN)
            &&  (statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)
            &&  !(statinfo->flags & STAT_FLAG_MARKER)) {
            status = QObject::tr("Marker missing?");
            bg_color = color_rtp_warn_;
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
        setText(delta_col_, QString::number(delta_, 'f', 2));
        setText(jitter_col_, QString::number(jitter_, 'f', 2));
        setText(bandwidth_col_, QString::number(bandwidth_, 'f', 2));
        setText(status_col_, status);
        setText(length_col_, QString::number(pkt_len_));

        setTextAlignment(packet_col_, Qt::AlignRight);
        setTextAlignment(delta_col_, Qt::AlignRight);
        setTextAlignment(jitter_col_, Qt::AlignRight);
        setTextAlignment(bandwidth_col_, Qt::AlignRight);
        setTextAlignment(length_col_, Qt::AlignRight);

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
        QString status_str = ok_ ? "OK" : text(status_col_);

        return QList<QVariant>()
                << frame_num_ << delta_ << jitter_ << bandwidth_
                << status_str << pkt_len_;
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != iax2_analysis_type_) return QTreeWidgetItem::operator< (other);
        const Iax2AnalysisTreeWidgetItem *other_row = static_cast<const Iax2AnalysisTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case (packet_col_):
            return frame_num_ < other_row->frame_num_;
            break;
        case (delta_col_):
            return delta_ < other_row->delta_;
            break;
        case (jitter_col_):
            return jitter_ < other_row->jitter_;
            break;
        case (bandwidth_col_):
            return bandwidth_ < other_row->bandwidth_;
            break;
        case (length_col_):
            return pkt_len_ < other_row->pkt_len_;
            break;
        default:
            break;
        }

        // Fall back to string comparison
        return QTreeWidgetItem::operator <(other);
    }
private:
    guint32 frame_num_;
    guint32 pkt_len_;
    guint32 flags_;
    double delta_;
    double jitter_;
    double bandwidth_;
    bool ok_;
};

enum {
    fwd_jitter_graph_,
    fwd_diff_graph_,
    rev_jitter_graph_,
    rev_diff_graph_,
    num_graphs_
};

Iax2AnalysisDialog::Iax2AnalysisDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::Iax2AnalysisDialog),
    save_payload_error_(TAP_IAX2_NO_ERROR)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);
    setWindowSubtitle(tr("IAX2 Stream Analysis"));

    ui->progressFrame->hide();

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
    set_action_shortcuts_visible_in_context_menu(stream_ctx_menu_.actions());

    ui->forwardTreeWidget->installEventFilter(this);
    ui->forwardTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->forwardTreeWidget, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showStreamMenu(QPoint)));
    ui->reverseTreeWidget->installEventFilter(this);
    ui->reverseTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
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

    memset(&fwd_id_, 0, sizeof(fwd_id_));
    memset(&rev_id_, 0, sizeof(rev_id_));

    QList<QCheckBox *> graph_cbs = QList<QCheckBox *>()
            << ui->fJitterCheckBox << ui->fDiffCheckBox
            << ui->rJitterCheckBox << ui->rDiffCheckBox;

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
    QString tempname = QString("%1/wireshark_iax2_f").arg(QDir::tempPath());
    fwd_tempfile_ = new QTemporaryFile(tempname, this);
    fwd_tempfile_->open();
    tempname = QString("%1/wireshark_iax2_r").arg(QDir::tempPath());
    rev_tempfile_ = new QTemporaryFile(tempname, this);
    rev_tempfile_->open();

    if (fwd_tempfile_->error() != QFile::NoError || rev_tempfile_->error() != QFile::NoError) {
        err_str_ = tr("Unable to save RTP data.");
        ui->actionSaveAudio->setEnabled(false);
        ui->actionSaveForwardAudio->setEnabled(false);
        ui->actionSaveReverseAudio->setEnabled(false);
    }

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    QMenu *save_menu = new QMenu(save_bt);
    save_menu->addAction(ui->actionSaveAudio);
    save_menu->addAction(ui->actionSaveForwardAudio);
    save_menu->addAction(ui->actionSaveReverseAudio);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveCsv);
    save_menu->addAction(ui->actionSaveForwardCsv);
    save_menu->addAction(ui->actionSaveReverseCsv);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveGraph);
    save_bt->setMenu(save_menu);

    ui->buttonBox->button(QDialogButtonBox::Close)->setDefault(true);

    resetStatistics();
    updateStatistics(); // Initialize stats if an error occurs

#if 0
    /* Only accept Voice or MiniPacket packets */
    const gchar filter_text[] = "iax2.call && (ip || ipv6)";
#else
    const gchar filter_text[] = "iax2 && (ip || ipv6)";
#endif
    dfilter_t *sfcode;
    gchar *err_msg;

    /* Try to compile the filter. */
    if (!dfilter_compile(filter_text, &sfcode, &err_msg)) {
        err_str_ = QString(err_msg);
        g_free(err_msg);
        updateWidgets();
        return;
    }

    if (!cap_file_.capFile() || !cap_file_.capFile()->current_frame) {
        err_str_ = tr("Please select an IAX2 packet.");
        save_payload_error_ = TAP_IAX2_NO_PACKET_SELECTED;
        updateWidgets();
        return;
    }

    if (!cf_read_current_record(cap_file_.capFile())) close();

    frame_data *fdata = cap_file_.capFile()->current_frame;

    epan_dissect_t edt;

    epan_dissect_init(&edt, cap_file_.capFile()->epan, TRUE, FALSE);
    epan_dissect_prime_with_dfilter(&edt, sfcode);
    epan_dissect_run(&edt, cap_file_.capFile()->cd_t, &cap_file_.capFile()->rec,
                     frame_tvbuff_new_buffer(&cap_file_.capFile()->provider, fdata, &cap_file_.capFile()->buf),
                     fdata, NULL);

    // This shouldn't happen (the menu item should be disabled) but check anyway
    if (!dfilter_apply_edt(sfcode, &edt)) {
        epan_dissect_cleanup(&edt);
        dfilter_free(sfcode);
        err_str_ = tr("Please select an IAX2 packet.");
        save_payload_error_ = TAP_IAX2_NO_PACKET_SELECTED;
        updateWidgets();
        return;
    }

    dfilter_free(sfcode);

    /* ok, it is a IAX2 frame, so let's get the ip and port values */
    rtpstream_id_copy_pinfo(&(edt.pi),&(fwd_id_),FALSE);

    /* assume the inverse ip/port combination for the reverse direction */
    rtpstream_id_copy_pinfo(&(edt.pi),&(rev_id_),TRUE);

    epan_dissect_cleanup(&edt);

#ifdef IAX2_RTP_STREAM_CHECK
    rtpstream_tapinfo_t tapinfo;

    /* Register the tap listener */
    rtpstream_info_init(&tapinfo);

    tapinfo.tap_data = this;
    tapinfo.mode = TAP_ANALYSE;

//    register_tap_listener_rtpstream(&tapinfo, NULL);
    /* Scan for RTP streams (redissect all packets) */
    rtpstream_scan(&tapinfo, cap_file_.capFile(), Q_NULLPTR);

    int num_streams = 0;
    // TODO: Not used
    //GList *filtered_list = NULL;
    for (GList *strinfo_list = g_list_first(tapinfo.strinfo_list); strinfo_list; strinfo_list = gxx_list_next(strinfo_list)) {
        rtpstream_info_t * strinfo = gxx_list_data(rtpstream_info_t*, strinfo_list);
        if (rtpstream_id_equal(&(strinfo->id), &(fwd_id_),RTPSTREAM_ID_EQUAL_NONE))
        {
            ++num_streams;
            // TODO: Not used
            //filtered_list = g_list_prepend(filtered_list, strinfo);
        }

        if (rtpstream_id_equal(&(strinfo->id), &(rev_id_),RTPSTREAM_ID_EQUAL_NONE))
        {
            ++num_streams;
            // TODO: Not used
            //filtered_list = g_list_append(filtered_list, strinfo);
        }

        rtpstream_info_free_data(strinfo);
        g_free(list->data);
    }
    g_list_free(tapinfo->strinfo_list);

    if (num_streams > 1) {
        // Open the RTP streams dialog.
    }
#endif

    connect(ui->tabWidget, SIGNAL(currentChanged(int)),
            this, SLOT(updateWidgets()));
    connect(ui->forwardTreeWidget, SIGNAL(itemSelectionChanged()),
            this, SLOT(updateWidgets()));
    connect(ui->reverseTreeWidget, SIGNAL(itemSelectionChanged()),
            this, SLOT(updateWidgets()));
    updateWidgets();

    registerTapListener("IAX2", this, Q_NULLPTR, 0, tapReset, tapPacket, tapDraw);
    cap_file_.retapPackets();
    removeTapListeners();

    updateStatistics();
}

Iax2AnalysisDialog::~Iax2AnalysisDialog()
{
    delete ui;
//    remove_tap_listener_rtpstream(&tapinfo);
    delete fwd_tempfile_;
    delete rev_tempfile_;
}

void Iax2AnalysisDialog::updateWidgets()
{
    bool enable_tab = false;
    QString hint = err_str_;

    if (hint.isEmpty() || save_payload_error_ != TAP_IAX2_NO_ERROR) {
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

    bool enable_save_fwd_audio = fwd_tempfile_->isOpen() && (save_payload_error_ == TAP_IAX2_NO_ERROR);
    bool enable_save_rev_audio = rev_tempfile_->isOpen() && (save_payload_error_ == TAP_IAX2_NO_ERROR);
    ui->actionSaveAudio->setEnabled(enable_save_fwd_audio && enable_save_rev_audio);
    ui->actionSaveForwardAudio->setEnabled(enable_save_fwd_audio);
    ui->actionSaveReverseAudio->setEnabled(enable_save_rev_audio);

    bool enable_save_fwd_csv = ui->forwardTreeWidget->topLevelItemCount() > 0;
    bool enable_save_rev_csv = ui->reverseTreeWidget->topLevelItemCount() > 0;
    ui->actionSaveCsv->setEnabled(enable_save_fwd_csv && enable_save_rev_csv);
    ui->actionSaveForwardCsv->setEnabled(enable_save_fwd_csv);
    ui->actionSaveReverseCsv->setEnabled(enable_save_rev_csv);

    ui->tabWidget->setEnabled(enable_tab);
    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);

    WiresharkDialog::updateWidgets();
}

void Iax2AnalysisDialog::on_actionGoToPacket_triggered()
{
    if (file_closed_) return;
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->tabWidget->currentWidget());
    if (!cur_tree || cur_tree->selectedItems().length() < 1) return;

    QTreeWidgetItem *ti = cur_tree->selectedItems()[0];
    if (ti->type() != iax2_analysis_type_) return;

    Iax2AnalysisTreeWidgetItem *ra_ti = dynamic_cast<Iax2AnalysisTreeWidgetItem *>((Iax2AnalysisTreeWidgetItem *)ti);
    emit goToPacket(ra_ti->frameNum());
}

void Iax2AnalysisDialog::on_actionNextProblem_triggered()
{
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->tabWidget->currentWidget());
    if (!cur_tree || cur_tree->topLevelItemCount() < 2) return;

    // Choose convenience over correctness.
    if (cur_tree->selectedItems().length() < 1) {
        cur_tree->setCurrentItem(cur_tree->topLevelItem(0));
    }

    QTreeWidgetItem *sel_ti = cur_tree->selectedItems()[0];
    if (sel_ti->type() != iax2_analysis_type_) return;
    QTreeWidgetItem *test_ti = cur_tree->itemBelow(sel_ti);
    while (test_ti != sel_ti) {
        if (!test_ti) test_ti = cur_tree->topLevelItem(0);
        Iax2AnalysisTreeWidgetItem *ra_ti = dynamic_cast<Iax2AnalysisTreeWidgetItem *>((Iax2AnalysisTreeWidgetItem *)test_ti);
        if (!ra_ti->frameStatus()) {
            cur_tree->setCurrentItem(ra_ti);
            break;
        }

        test_ti = cur_tree->itemBelow(test_ti);
    }
}

void Iax2AnalysisDialog::on_fJitterCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(fwd_jitter_graph_)->setVisible(checked);
    updateGraph();
}

void Iax2AnalysisDialog::on_fDiffCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(fwd_diff_graph_)->setVisible(checked);
    updateGraph();
}

void Iax2AnalysisDialog::on_rJitterCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(rev_jitter_graph_)->setVisible(checked);
    updateGraph();
}

void Iax2AnalysisDialog::on_rDiffCheckBox_toggled(bool checked)
{
    ui->streamGraph->graph(rev_diff_graph_)->setVisible(checked);
    updateGraph();
}

void Iax2AnalysisDialog::on_actionSaveAudio_triggered()
{
    saveAudio(dir_both_);
}

void Iax2AnalysisDialog::on_actionSaveForwardAudio_triggered()
{
    saveAudio(dir_forward_);
}

void Iax2AnalysisDialog::on_actionSaveReverseAudio_triggered()
{
    saveAudio(dir_reverse_);
}

void Iax2AnalysisDialog::on_actionSaveCsv_triggered()
{
    saveCsv(dir_both_);
}

void Iax2AnalysisDialog::on_actionSaveForwardCsv_triggered()
{
    saveCsv(dir_forward_);
}

void Iax2AnalysisDialog::on_actionSaveReverseCsv_triggered()
{
    saveCsv(dir_reverse_);
}

void Iax2AnalysisDialog::on_actionSaveGraph_triggered()
{
    ui->tabWidget->setCurrentWidget(ui->graphTab);

    QString file_name, extension;
    QDir path(mainApp->lastOpenDir());
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
    file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Graph As…")),
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
            mainApp->setLastOpenDirFromFilename(file_name);
        }
    }
}

void Iax2AnalysisDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_IAX2_ANALYSIS_DIALOG);
}

void Iax2AnalysisDialog::tapReset(void *tapinfoptr)
{
    Iax2AnalysisDialog *iax2_analysis_dialog = dynamic_cast<Iax2AnalysisDialog *>((Iax2AnalysisDialog*)tapinfoptr);
    if (!iax2_analysis_dialog) return;

    iax2_analysis_dialog->resetStatistics();
}

tap_packet_status Iax2AnalysisDialog::tapPacket(void *tapinfoptr, packet_info *pinfo, struct epan_dissect *, const void *iax2info_ptr, tap_flags_t)
{
    Iax2AnalysisDialog *iax2_analysis_dialog = dynamic_cast<Iax2AnalysisDialog *>((Iax2AnalysisDialog*)tapinfoptr);
    if (!iax2_analysis_dialog) return TAP_PACKET_DONT_REDRAW;

    const iax2_info_t *iax2info = (const iax2_info_t *)iax2info_ptr;
    if (!iax2info) return TAP_PACKET_DONT_REDRAW;

    /* we ignore packets that are not displayed */
    if (pinfo->fd->passed_dfilter == 0)
        return TAP_PACKET_DONT_REDRAW;

    /* we ignore packets that carry no data */
    if (iax2info->payload_len < 1)
        return TAP_PACKET_DONT_REDRAW;

    /* is it the forward direction?  */
    else if ((cmp_address(&(iax2_analysis_dialog->fwd_id_.src_addr), &(pinfo->src)) == 0)
         && (iax2_analysis_dialog->fwd_id_.src_port == pinfo->srcport)
         && (cmp_address(&(iax2_analysis_dialog->fwd_id_.dst_addr), &(pinfo->dst)) == 0)
         && (iax2_analysis_dialog->fwd_id_.dst_port == pinfo->destport))  {

        iax2_analysis_dialog->addPacket(true, pinfo, iax2info);
    }
    /* is it the reversed direction? */
    else if ((cmp_address(&(iax2_analysis_dialog->rev_id_.src_addr), &(pinfo->src)) == 0)
         && (iax2_analysis_dialog->rev_id_.src_port == pinfo->srcport)
         && (cmp_address(&(iax2_analysis_dialog->rev_id_.dst_addr), &(pinfo->dst)) == 0)
         && (iax2_analysis_dialog->rev_id_.dst_port == pinfo->destport))  {

        iax2_analysis_dialog->addPacket(false, pinfo, iax2info);
    }
    return TAP_PACKET_DONT_REDRAW;
}

void Iax2AnalysisDialog::tapDraw(void *tapinfoptr)
{
    Iax2AnalysisDialog *iax2_analysis_dialog = dynamic_cast<Iax2AnalysisDialog *>((Iax2AnalysisDialog*)tapinfoptr);
    if (!iax2_analysis_dialog) return;
    iax2_analysis_dialog->updateStatistics();
}

void Iax2AnalysisDialog::resetStatistics()
{
    memset(&fwd_statinfo_, 0, sizeof(fwd_statinfo_));
    memset(&rev_statinfo_, 0, sizeof(rev_statinfo_));

    fwd_statinfo_.first_packet = TRUE;
    rev_statinfo_.first_packet = TRUE;
    fwd_statinfo_.reg_pt = PT_UNDEFINED;
    rev_statinfo_.reg_pt = PT_UNDEFINED;

    ui->forwardTreeWidget->clear();
    ui->reverseTreeWidget->clear();

    for (int i = 0; i < ui->streamGraph->graphCount(); i++) {
        ui->streamGraph->graph(i)->data()->clear();
    }

    fwd_time_vals_.clear();
    fwd_jitter_vals_.clear();
    fwd_diff_vals_.clear();
    rev_time_vals_.clear();
    rev_jitter_vals_.clear();
    rev_diff_vals_.clear();

    fwd_tempfile_->resize(0);
    rev_tempfile_->resize(0);
}

void Iax2AnalysisDialog::addPacket(bool forward, packet_info *pinfo, const struct _iax2_info_t *iax2info)
{
    /* add this RTP for future listening using the RTP Player*/
//    add_rtp_packet(rtpinfo, pinfo);

    if (forward) {
        iax2_packet_analyse(&fwd_statinfo_, pinfo, iax2info);
        new Iax2AnalysisTreeWidgetItem(ui->forwardTreeWidget, &fwd_statinfo_, pinfo);

        fwd_time_vals_.append((fwd_statinfo_.time));
        fwd_jitter_vals_.append(fwd_statinfo_.jitter * 1000);
        fwd_diff_vals_.append(fwd_statinfo_.diff * 1000);

        savePayload(fwd_tempfile_, pinfo, iax2info);
    } else {
        iax2_packet_analyse(&rev_statinfo_, pinfo, iax2info);
        new Iax2AnalysisTreeWidgetItem(ui->reverseTreeWidget, &rev_statinfo_, pinfo);

        rev_time_vals_.append((rev_statinfo_.time));
        rev_jitter_vals_.append(rev_statinfo_.jitter * 1000);
        rev_diff_vals_.append(rev_statinfo_.diff * 1000);

        savePayload(rev_tempfile_, pinfo, iax2info);
    }

}

// iax2_analysis.c:rtp_packet_save_payload
const guint8 silence_pcmu_ = 0xff;
const guint8 silence_pcma_ = 0x55;
void Iax2AnalysisDialog::savePayload(QTemporaryFile *tmpfile, packet_info *pinfo, const struct _iax2_info_t *iax2info)
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
    if (!tmpfile->isOpen() || tmpfile->error() != QFile::NoError) return;

    /* Quit if the captured length and packet length aren't equal.
     */
    if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
        tmpfile->close();
        err_str_ = tr("Can't save in a file: Wrong length of captured packets.");
        save_payload_error_ = TAP_IAX2_WRONG_LENGTH;
        return;
    }

    if (iax2info->payload_len > 0) {
        const char *data = (const char *) iax2info->payload_data;
        qint64 nchars;

        nchars = tmpfile->write(data, iax2info->payload_len);
        if (nchars != (iax2info->payload_len)) {
            /* Write error or short write */
            err_str_ = tr("Can't save in a file: File I/O problem.");
            save_payload_error_ = TAP_IAX2_FILE_IO_ERROR;
            tmpfile->close();
            return;
        }
        return;
    }
    return;
}

void Iax2AnalysisDialog::updateStatistics()
{
    double f_duration = fwd_statinfo_.time - fwd_statinfo_.start_time; // s
    double r_duration = rev_statinfo_.time - rev_statinfo_.start_time;
#if 0 // Marked as "TODO" in tap-iax2-analysis.c:128
    unsigned int f_expected = fwd_statinfo_.stop_seq_nr - fwd_statinfo_.start_seq_nr + 1;
    unsigned int r_expected = rev_statinfo_.stop_seq_nr - rev_statinfo_.start_seq_nr + 1;
    int f_lost = f_expected - fwd_statinfo_.total_nr;
    int r_lost = r_expected - rev_statinfo_.total_nr;
    double f_perc, r_perc;

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
#endif

    QString stats_tables = "<html><head></head><body>\n";
    stats_tables += QString("<p>%1:%2 " UTF8_LEFT_RIGHT_ARROW)
            .arg(address_to_qstring(&fwd_id_.src_addr, true))
            .arg(fwd_id_.src_port);
    stats_tables += QString("<br>%1:%2</p>\n")
            .arg(address_to_qstring(&fwd_id_.dst_addr, true))
            .arg(fwd_id_.dst_port);
    stats_tables += "<h4>Forward</h4>\n";
    stats_tables += "<p><table>\n";
    stats_tables += QString("<tr><th align=\"left\">Max Delta</th><td>%1 ms @ %2</td></tr>")
            .arg(fwd_statinfo_.max_delta, 0, 'f', 2)
            .arg(fwd_statinfo_.max_nr);
    stats_tables += QString("<tr><th align=\"left\">Max Jitter</th><td>%1 ms</tr>")
            .arg(fwd_statinfo_.max_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Mean Jitter</th><td>%1 ms</tr>")
            .arg(fwd_statinfo_.mean_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">IAX2 Packets</th><td>%1</tr>")
            .arg(fwd_statinfo_.total_nr);
#if 0
    stats_tables += QString("<tr><th align=\"left\">Expected</th><td>%1</tr>")
            .arg(f_expected);
    stats_tables += QString("<tr><th align=\"left\">Lost</th><td>%1 (%2 %)</tr>")
            .arg(f_lost).arg(f_perc, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Seq Errs</th><td>%1</tr>")
            .arg(fwd_statinfo_.sequence);
#endif
    stats_tables += QString("<tr><th align=\"left\">Duration</th><td>%1 s</tr>")
            .arg(f_duration, 0, 'f', 2);
    stats_tables += "</table></p>\n";

    stats_tables += "<h4>Reverse</h4>\n";
    stats_tables += "<p><table>\n";
    stats_tables += QString("<tr><th align=\"left\">Max Delta</th><td>%1 ms @ %2</td></tr>")
            .arg(rev_statinfo_.max_delta, 0, 'f', 2)
            .arg(rev_statinfo_.max_nr);
    stats_tables += QString("<tr><th align=\"left\">Max Jitter</th><td>%1 ms</tr>")
            .arg(rev_statinfo_.max_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Mean Jitter</th><td>%1 ms</tr>")
            .arg(rev_statinfo_.mean_jitter, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">IAX2 Packets</th><td>%1</tr>")
            .arg(rev_statinfo_.total_nr);
#if 0
    stats_tables += QString("<tr><th align=\"left\">Expected</th><td>%1</tr>")
            .arg(r_expected);
    stats_tables += QString("<tr><th align=\"left\">Lost</th><td>%1 (%2 %)</tr>")
            .arg(r_lost).arg(r_perc, 0, 'f', 2);
    stats_tables += QString("<tr><th align=\"left\">Seq Errs</th><td>%1</tr>")
            .arg(rev_statinfo_.sequence);
#endif
    stats_tables += QString("<tr><th align=\"left\">Duration</th><td>%1 s</tr>")
            .arg(r_duration, 0, 'f', 2);
    stats_tables += "</table></p></body>\n";

    ui->statisticsLabel->setText(stats_tables);

    for (int col = 0; col < ui->forwardTreeWidget->columnCount() - 1; col++) {
        ui->forwardTreeWidget->resizeColumnToContents(col);
        ui->reverseTreeWidget->resizeColumnToContents(col);
    }

    graphs_[fwd_jitter_graph_]->setData(fwd_time_vals_, fwd_jitter_vals_);
    graphs_[fwd_diff_graph_]->setData(fwd_time_vals_, fwd_diff_vals_);
    graphs_[rev_jitter_graph_]->setData(rev_time_vals_, rev_jitter_vals_);
    graphs_[rev_diff_graph_]->setData(rev_time_vals_, rev_diff_vals_);

    updateGraph();

    updateWidgets();
}

void Iax2AnalysisDialog::updateGraph()
{
    for (int i = 0; i < ui->streamGraph->graphCount(); i++) {
        if (ui->streamGraph->graph(i)->visible()) {
            ui->streamGraph->graph(i)->rescaleAxes(i > 0);
        }
    }
    ui->streamGraph->replot();
}

// iax2_analysis.c:copy_file
enum { save_audio_none_, save_audio_au_, save_audio_raw_ };
void Iax2AnalysisDialog::saveAudio(Iax2AnalysisDialog::StreamDirection direction)
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
    QString file_path = WiresharkFileDialog::getSaveFileName(
                this, caption, mainApp->lastOpenDir().absoluteFilePath("Saved RTP Audio.au"),
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

    QFile      save_file(file_path);
    gint16     sample;
    guint8     pd[4];
    gboolean   stop_flag = FALSE;
    qint64     nchars;

    save_file.open(QIODevice::WriteOnly);
    fwd_tempfile_->seek(0);
    rev_tempfile_->seek(0);

    if (save_file.error() != QFile::NoError) {
        QMessageBox::warning(this, tr("Warning"), tr("Unable to save %1").arg(save_file.fileName()));
        return;
    }

    ui->hintLabel->setText(tr("Saving %1…").arg(save_file.fileName()));
    ui->progressFrame->showProgress(tr("Analyzing IAX2"), true, true, &stop_flag);

    if	(save_format == save_audio_au_) { /* au format; https://pubs.opengroup.org/external/auformat.html */
        /* First we write the .au header.  All values in the header are
         * 4-byte big-endian values, so we use pntoh32() to copy them
         * to a 4-byte buffer, in big-endian order, and then write out
         * the buffer. */

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
                ui->progressFrame->setValue(int(fwd_tempfile_->pos() * 100 / fwd_tempfile_->size()));

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
                ui->progressFrame->setValue(int(rev_tempfile_->pos() * 100 / rev_tempfile_->size()));

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
                int fwd_pct = int(fwd_tempfile_->pos() * 100 / fwd_tempfile_->size());
                int rev_pct = int(rev_tempfile_->pos() * 100 / rev_tempfile_->size());
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
            progress_pct = int(fwd_tempfile_->pos() * 100 / fwd_tempfile_->size());
            tempfile = fwd_tempfile_;
            break;
        }
            /* only reversed direction */
        case dir_reverse_: {
            progress_pct = int(rev_tempfile_->pos() * 100 / rev_tempfile_->size());
            tempfile = rev_tempfile_;
            break;
        }
        default: {
            goto copy_file_err;
        }
        }

        qsizetype chunk_size = 65536;
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
void Iax2AnalysisDialog::saveCsv(Iax2AnalysisDialog::StreamDirection direction)
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
                this, caption, mainApp->lastOpenDir().absoluteFilePath("RTP Packet Data.csv"),
                tr("Comma-separated values (*.csv)"));

    if (file_path.isEmpty()) return;

    QFile save_file(file_path);
    save_file.open(QFile::WriteOnly);

    if (direction == dir_forward_ || direction == dir_both_) {
        save_file.write("Forward\n");

        for (int row = 0; row < ui->forwardTreeWidget->topLevelItemCount(); row++) {
            QTreeWidgetItem *ti = ui->forwardTreeWidget->topLevelItem(row);
            if (ti->type() != iax2_analysis_type_) continue;
            Iax2AnalysisTreeWidgetItem *ra_ti = dynamic_cast<Iax2AnalysisTreeWidgetItem *>((Iax2AnalysisTreeWidgetItem *)ti);
            QStringList values;
            foreach (QVariant v, ra_ti->rowData()) {
                if (!v.isValid()) {
                    values << "\"\"";
                } else if (v.userType() == QMetaType::QString) {
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
            if (ti->type() != iax2_analysis_type_) continue;
            Iax2AnalysisTreeWidgetItem *ra_ti = dynamic_cast<Iax2AnalysisTreeWidgetItem *>((Iax2AnalysisTreeWidgetItem *)ti);
            QStringList values;
            foreach (QVariant v, ra_ti->rowData()) {
                if (!v.isValid()) {
                    values << "\"\"";
                } else if (v.userType() == QMetaType::QString) {
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

bool Iax2AnalysisDialog::eventFilter(QObject *, QEvent *event)
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

void Iax2AnalysisDialog::graphClicked(QMouseEvent *event)
{
    updateWidgets();
    if (event->button() == Qt::RightButton) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        graph_ctx_menu_.exec(event->globalPosition().toPoint());
#else
        graph_ctx_menu_.exec(event->globalPos());
#endif
    }
}

void Iax2AnalysisDialog::showStreamMenu(QPoint pos)
{
    QTreeWidget *cur_tree = qobject_cast<QTreeWidget *>(ui->tabWidget->currentWidget());
    if (!cur_tree) return;

    updateWidgets();
    stream_ctx_menu_.popup(cur_tree->viewport()->mapToGlobal(pos));
}
