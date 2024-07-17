/* rtp_stream_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_stream_dialog.h"
#include <ui_rtp_stream_dialog.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include <epan/rtp_pt.h>

#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "rtp_analysis_dialog.h"
#include "progress_frame.h"
#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QAction>
#include <QClipboard>
#include <QKeyEvent>
#include <QPushButton>
#include <QTextStream>
#include <QTreeWidgetItem>
#include <QTreeWidgetItemIterator>
#include <QDateTime>

#include <ui/qt/utils/color_utils.h>

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
const int start_time_col_  =  5;
const int duration_col_    =  6;
const int payload_col_     =  7;
const int packets_col_     =  8;
const int lost_col_        =  9;
const int min_delta_col_   = 10;
const int mean_delta_col_  = 11;
const int max_delta_col_   = 12;
const int min_jitter_col_  = 13;
const int mean_jitter_col_ = 14;
const int max_jitter_col_  = 15;
const int status_col_      = 16;
const int ssrc_fmt_col_    = 17;
const int lost_perc_col_   = 18;

enum { rtp_stream_type_ = 1000 };

bool operator==(rtpstream_id_t const& a, rtpstream_id_t const& b);

class RtpStreamTreeWidgetItem : public QTreeWidgetItem
{
public:
    RtpStreamTreeWidgetItem(QTreeWidget *tree, rtpstream_info_t *stream_info) :
        QTreeWidgetItem(tree, rtp_stream_type_),
        stream_info_(stream_info),
        tod_(0)
    {
        drawData();
    }

    rtpstream_info_t *streamInfo() const { return stream_info_; }

    void drawData() {
        rtpstream_info_calc_t calc;

        if (!stream_info_) {
            return;
        }
        rtpstream_info_calculate(stream_info_, &calc);

        setText(src_addr_col_, calc.src_addr_str);
        setText(src_port_col_, QString::number(calc.src_port));
        setText(dst_addr_col_, calc.dst_addr_str);
        setText(dst_port_col_, QString::number(calc.dst_port));
        setText(ssrc_col_, QString("0x%1").arg(calc.ssrc, 0, 16));
        if (tod_) {
            QDateTime abs_dt = QDateTime::fromMSecsSinceEpoch(nstime_to_msec(&stream_info_->start_fd->abs_ts));
            setText(start_time_col_, QString("%1")
                .arg(abs_dt.toString("yyyy-MM-dd hh:mm:ss.zzz")));
        } else {
          setText(start_time_col_, QString::number(calc.start_time_ms, 'f', 6));
        }
        setText(duration_col_, QString::number(calc.duration_ms, 'f', prefs.gui_decimal_places1));
        setText(payload_col_, calc.all_payload_type_names);
        setText(packets_col_, QString::number(calc.packet_count));
        setText(lost_col_, QObject::tr("%1 (%L2%)").arg(calc.lost_num).arg(QString::number(calc.lost_perc, 'f', 1)));
        setText(min_delta_col_, QString::number(calc.min_delta, 'f', prefs.gui_decimal_places3)); // This is RTP. Do we need nanoseconds?
        setText(mean_delta_col_, QString::number(calc.mean_delta, 'f', prefs.gui_decimal_places3)); // This is RTP. Do we need nanoseconds?
        setText(max_delta_col_, QString::number(calc.max_delta, 'f', prefs.gui_decimal_places3)); // This is RTP. Do we need nanoseconds?
        setText(min_jitter_col_, QString::number(calc.min_jitter, 'f', prefs.gui_decimal_places3));
        setText(mean_jitter_col_, QString::number(calc.mean_jitter, 'f', prefs.gui_decimal_places3));
        setText(max_jitter_col_, QString::number(calc.max_jitter, 'f', prefs.gui_decimal_places3));

        if (calc.problem) {
            setText(status_col_, UTF8_BULLET);
            setTextAlignment(status_col_, Qt::AlignCenter);
            QColor bgColor(ColorUtils::warningBackground());
            QColor textColor(QApplication::palette().text().color());
            for (int i = 0; i < columnCount(); i++) {
                QBrush bgBrush = background(i);
                bgBrush.setColor(bgColor);
                bgBrush.setStyle(Qt::SolidPattern);
                setBackground(i, bgBrush);
                QBrush fgBrush = foreground(i);
                fgBrush.setColor(textColor);
                fgBrush.setStyle(Qt::SolidPattern);
                setForeground(i, fgBrush);
            }
        }

        rtpstream_info_calc_free(&calc);
    }
    // Return a QString, int, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col) const {
        rtpstream_info_calc_t calc;
        if (!stream_info_) {
            return QVariant();
        }

        QVariant ret;
        rtpstream_info_calculate(stream_info_, &calc);

        switch(col) {
        case src_addr_col_:
            ret = QVariant(text(col));
            break;
        case src_port_col_:
            ret = calc.src_port;
            break;
        case dst_addr_col_:
            ret = text(col);
            break;
        case dst_port_col_:
            ret = calc.dst_port;
            break;
        case ssrc_col_:
            ret = calc.ssrc;
            break;
        case start_time_col_:
            ret = calc.start_time_ms;
            break;
        case duration_col_:
            ret = calc.duration_ms;
            break;
        case payload_col_:
            ret = text(col);
            break;
        case packets_col_:
            ret = calc.packet_count;
            break;
        case lost_col_:
            ret = calc.lost_num;
            break;
        case min_delta_col_:
            ret = calc.min_delta;
            break;
        case mean_delta_col_:
            ret = calc.mean_delta;
            break;
        case max_delta_col_:
            ret = calc.max_delta;
            break;
        case min_jitter_col_:
            ret = calc.min_jitter;
            break;
        case mean_jitter_col_:
            ret = calc.mean_jitter;
            break;
        case max_jitter_col_:
            ret = calc.max_jitter;
            break;
        case status_col_:
            ret = calc.problem ? "Problem" : "";
            break;
        case ssrc_fmt_col_:
            ret = QString("0x%1").arg(calc.ssrc, 0, 16);
            break;
        case lost_perc_col_:
            ret = QString::number(calc.lost_perc, 'f', prefs.gui_decimal_places1);
            break;
        default:
            ret = QVariant();
            break;
        }
        rtpstream_info_calc_free(&calc);
        return ret;
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        rtpstream_info_calc_t calc1;
        rtpstream_info_calc_t calc2;
        bool ret;

        if (other.type() != rtp_stream_type_) return QTreeWidgetItem::operator <(other);
        const RtpStreamTreeWidgetItem &other_rstwi = dynamic_cast<const RtpStreamTreeWidgetItem&>(other);

        switch (treeWidget()->sortColumn()) {
        case src_addr_col_:
            return cmp_address(&(stream_info_->id.src_addr), &(other_rstwi.stream_info_->id.src_addr)) < 0;
        case src_port_col_:
            return stream_info_->id.src_port < other_rstwi.stream_info_->id.src_port;
        case dst_addr_col_:
            return cmp_address(&(stream_info_->id.dst_addr), &(other_rstwi.stream_info_->id.dst_addr)) < 0;
        case dst_port_col_:
            return stream_info_->id.dst_port < other_rstwi.stream_info_->id.dst_port;
        case ssrc_col_:
            return stream_info_->id.ssrc < other_rstwi.stream_info_->id.ssrc;
        case start_time_col_:
            rtpstream_info_calculate(stream_info_, &calc1);
            rtpstream_info_calculate(other_rstwi.stream_info_, &calc2);
            ret = calc1.start_time_ms < calc2.start_time_ms;
            rtpstream_info_calc_free(&calc1);
            rtpstream_info_calc_free(&calc2);
            return ret;
        case duration_col_:
            rtpstream_info_calculate(stream_info_, &calc1);
            rtpstream_info_calculate(other_rstwi.stream_info_, &calc2);
            ret = calc1.duration_ms < calc2.duration_ms;
            rtpstream_info_calc_free(&calc1);
            rtpstream_info_calc_free(&calc2);
            return ret;
        case payload_col_:
            return g_strcmp0(stream_info_->all_payload_type_names, other_rstwi.stream_info_->all_payload_type_names);
        case packets_col_:
            return stream_info_->packet_count < other_rstwi.stream_info_->packet_count;
        case lost_col_:
            rtpstream_info_calculate(stream_info_, &calc1);
            rtpstream_info_calculate(other_rstwi.stream_info_, &calc2);
            /* XXX: Should this sort on the total number or the percentage?
             * lost_num is displayed first and lost_perc in parenthesis,
             * so let's use the total number.
             */
            ret = calc1.lost_num < calc2.lost_num;
            rtpstream_info_calc_free(&calc1);
            rtpstream_info_calc_free(&calc2);
            return ret;
        case min_delta_col_:
            return stream_info_->rtp_stats.min_delta < other_rstwi.stream_info_->rtp_stats.min_delta;
        case mean_delta_col_:
            return stream_info_->rtp_stats.mean_delta < other_rstwi.stream_info_->rtp_stats.mean_delta;
        case max_delta_col_:
            return stream_info_->rtp_stats.max_delta < other_rstwi.stream_info_->rtp_stats.max_delta;
        case min_jitter_col_:
            return stream_info_->rtp_stats.min_jitter < other_rstwi.stream_info_->rtp_stats.min_jitter;
        case mean_jitter_col_:
            return stream_info_->rtp_stats.mean_jitter < other_rstwi.stream_info_->rtp_stats.mean_jitter;
        case max_jitter_col_:
            return stream_info_->rtp_stats.max_jitter < other_rstwi.stream_info_->rtp_stats.max_jitter;
        default:
            break;
        }

        // Fall back to string comparison
        return QTreeWidgetItem::operator <(other);
    }

    void setTOD(bool tod)
    {
      tod_ = tod;
    }

private:
    rtpstream_info_t *stream_info_;
    bool tod_;
};


RtpStreamDialog *RtpStreamDialog::pinstance_{nullptr};
std::mutex RtpStreamDialog::mutex_;

RtpStreamDialog *RtpStreamDialog::openRtpStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pinstance_ == nullptr)
    {
        pinstance_ = new RtpStreamDialog(parent, cf);
        connect(pinstance_, SIGNAL(packetsMarked()),
                packet_list, SLOT(redrawVisiblePackets()));
        connect(pinstance_, SIGNAL(goToPacket(int)),
                packet_list, SLOT(goToPacket(int)));
    }
    return pinstance_;
}

RtpStreamDialog::RtpStreamDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::RtpStreamDialog),
    need_redraw_(false)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);
    setWindowSubtitle(tr("RTP Streams"));
    ui->streamTreeWidget->installEventFilter(this);

    ctx_menu_.addMenu(ui->menuSelect);
    ctx_menu_.addMenu(ui->menuFindReverse);
    ctx_menu_.addAction(ui->actionGoToSetup);
    ctx_menu_.addAction(ui->actionMarkPackets);
    ctx_menu_.addAction(ui->actionPrepareFilter);
    ctx_menu_.addAction(ui->actionExportAsRtpDump);
    ctx_menu_.addAction(ui->actionCopyAsCsv);
    ctx_menu_.addAction(ui->actionCopyAsYaml);
    ctx_menu_.addAction(ui->actionAnalyze);
    set_action_shortcuts_visible_in_context_menu(ctx_menu_.actions());

    ui->streamTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->streamTreeWidget->header()->setSortIndicator(0, Qt::AscendingOrder);
    connect(ui->streamTreeWidget, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showStreamMenu(QPoint)));

    find_reverse_button_ = new QToolButton();
    ui->buttonBox->addButton(find_reverse_button_, QDialogButtonBox::ActionRole);
    find_reverse_button_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    find_reverse_button_->setPopupMode(QToolButton::MenuButtonPopup);

    connect(ui->actionFindReverse, &QAction::triggered, this, &RtpStreamDialog::on_actionFindReverseNormal_triggered);
    find_reverse_button_->setDefaultAction(ui->actionFindReverse);
    // Overrides text striping of shortcut undercode in QAction
    find_reverse_button_->setText(ui->actionFindReverseNormal->text());
    find_reverse_button_->setMenu(ui->menuFindReverse);

    analyze_button_ = RtpAnalysisDialog::addAnalyzeButton(ui->buttonBox, this);
    prepare_button_ = ui->buttonBox->addButton(ui->actionPrepareFilter->text(), QDialogButtonBox::ActionRole);
    prepare_button_->setToolTip(ui->actionPrepareFilter->toolTip());
    connect(prepare_button_, &QPushButton::pressed, this, &RtpStreamDialog::on_actionPrepareFilter_triggered);
    player_button_ = RtpPlayerDialog::addPlayerButton(ui->buttonBox, this);
    copy_button_ = ui->buttonBox->addButton(ui->actionCopyButton->text(), QDialogButtonBox::ActionRole);
    copy_button_->setToolTip(ui->actionCopyButton->toolTip());
    export_button_ = ui->buttonBox->addButton(ui->actionExportAsRtpDump->text(), QDialogButtonBox::ActionRole);
    export_button_->setToolTip(ui->actionExportAsRtpDump->toolTip());
    connect(export_button_, &QPushButton::pressed, this, &RtpStreamDialog::on_actionExportAsRtpDump_triggered);

    QMenu *copy_menu = new QMenu(copy_button_);
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(ui->actionCopyAsCsv->toolTip());
    connect(ca, &QAction::triggered, this, &RtpStreamDialog::on_actionCopyAsCsv_triggered);
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(ui->actionCopyAsYaml->toolTip());
    connect(ca, &QAction::triggered, this, &RtpStreamDialog::on_actionCopyAsYaml_triggered);
    copy_button_->setMenu(copy_menu);
    connect(&cap_file_, SIGNAL(captureEvent(CaptureEvent)),
            this, SLOT(captureEvent(CaptureEvent)));

    /* Register the tap listener */
    memset(&tapinfo_, 0, sizeof(rtpstream_tapinfo_t));
    tapinfo_.tap_reset = tapReset;
    tapinfo_.tap_draw = tapDraw;
    tapinfo_.tap_mark_packet = tapMarkPacket;
    tapinfo_.tap_data = this;
    tapinfo_.mode = TAP_ANALYSE;

    register_tap_listener_rtpstream(&tapinfo_, NULL, show_tap_registration_error);
    if (cap_file_.isValid() && cap_file_.capFile()->dfilter) {
        // Activate display filter checking
        tapinfo_.apply_display_filter = true;
        ui->displayFilterCheckBox->setChecked(true);
    }

    connect(ui->displayFilterCheckBox, &QCheckBox::toggled,
            this, &RtpStreamDialog::displayFilterCheckBoxToggled);
    connect(this, SIGNAL(updateFilter(QString, bool)),
            &parent, SLOT(filterPackets(QString, bool)));
    connect(&parent, SIGNAL(displayFilterSuccess(bool)),
            this, SLOT(displayFilterSuccess(bool)));
    connect(this, SIGNAL(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)));

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    updateWidgets();

    if (cap_file_.isValid()) {
        cap_file_.delayedRetapPackets();
    }
}

RtpStreamDialog::~RtpStreamDialog()
{
    std::lock_guard<std::mutex> lock(mutex_);
    freeLastSelected();
    delete ui;
    rtpstream_reset(&tapinfo_);
    remove_tap_listener_rtpstream(&tapinfo_);
    pinstance_ = nullptr;
}

void RtpStreamDialog::setRtpStreamSelection(rtpstream_id_t *id, bool state)
{
    QTreeWidgetItemIterator iter(ui->streamTreeWidget);
    while (*iter) {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(*iter);
        rtpstream_info_t *stream_info = rsti->streamInfo();
        if (stream_info) {
            if (rtpstream_id_equal(id,&stream_info->id,RTPSTREAM_ID_EQUAL_SSRC)) {
                (*iter)->setSelected(state);
            }
        }
        ++iter;
    }
}

void RtpStreamDialog::selectRtpStream(QVector<rtpstream_id_t *> stream_ids)
{
    std::lock_guard<std::mutex> lock(mutex_);
    foreach(rtpstream_id_t *id, stream_ids) {
        setRtpStreamSelection(id, true);
    }
}

void RtpStreamDialog::deselectRtpStream(QVector<rtpstream_id_t *> stream_ids)
{
    std::lock_guard<std::mutex> lock(mutex_);
    foreach(rtpstream_id_t *id, stream_ids) {
        setRtpStreamSelection(id, false);
    }
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
                if (keyEvent.modifiers() == Qt::ShiftModifier) {
                    on_actionFindReversePair_triggered();
                } else if (keyEvent.modifiers() == Qt::ControlModifier) {
                    on_actionFindReverseSingle_triggered();
                } else {
                    on_actionFindReverseNormal_triggered();
                }
                return true;
            case Qt::Key_I:
                if (keyEvent.modifiers() == Qt::ControlModifier) {
                    // Ctrl+I
                    on_actionSelectInvert_triggered();
                    return true;
                }
                break;
            case Qt::Key_A:
                if (keyEvent.modifiers() == Qt::ControlModifier) {
                    // Ctrl+A
                    on_actionSelectAll_triggered();
                    return true;
                } else if (keyEvent.modifiers() == (Qt::ShiftModifier | Qt::ControlModifier)) {
                    // Ctrl+Shift+A
                    on_actionSelectNone_triggered();
                    return true;
                } else if (keyEvent.modifiers() == Qt::NoModifier) {
                    on_actionAnalyze_triggered();
                }
                break;
            default:
                break;
        }
    }
    return false;
}

void RtpStreamDialog::captureEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::Retap)
    {
        switch (e.eventType())
        {
        case CaptureEvent::Started:
            ui->displayFilterCheckBox->setEnabled(false);
            break;
        case CaptureEvent::Finished:
            ui->displayFilterCheckBox->setEnabled(true);
            break;
        default:
            break;
        }
    }

}

void RtpStreamDialog::tapReset(rtpstream_tapinfo_t *tapinfo)
{
    RtpStreamDialog *rtp_stream_dialog = dynamic_cast<RtpStreamDialog *>((RtpStreamDialog *)tapinfo->tap_data);
    if (rtp_stream_dialog) {
        rtp_stream_dialog->freeLastSelected();
        /* Copy currently selected rtpstream_ids */
        QTreeWidgetItemIterator iter(rtp_stream_dialog->ui->streamTreeWidget);
        rtpstream_id_t selected_id;
        while (*iter) {
            RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(*iter);
            rtpstream_info_t *stream_info = rsti->streamInfo();
            if ((*iter)->isSelected()) {
                /* QList.append() does a member by member copy, so allocate new
                 * addresses. rtpstream_id_copy() overwrites all struct members.
                 */
                rtpstream_id_copy(&stream_info->id, &selected_id);
                rtp_stream_dialog->last_selected_.append(selected_id);
            }
            ++iter;
        }
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

/* Operator == for rtpstream_id_t */
bool operator==(rtpstream_id_t const& a, rtpstream_id_t const& b)
{
    return rtpstream_id_equal(&a, &b, RTPSTREAM_ID_EQUAL_SSRC);
}

void RtpStreamDialog::updateStreams()
{
    // string_list is reverse ordered, so we must add
    // just first "to_insert_count" of streams
    GList *cur_stream = g_list_first(tapinfo_.strinfo_list);
    unsigned tap_len = g_list_length(tapinfo_.strinfo_list);
    unsigned tree_len = static_cast<unsigned>(ui->streamTreeWidget->topLevelItemCount());
    unsigned to_insert_count = tap_len - tree_len;

    // Add any missing items
    while (cur_stream && cur_stream->data && to_insert_count) {
        rtpstream_info_t *stream_info = gxx_list_data(rtpstream_info_t*, cur_stream);
        RtpStreamTreeWidgetItem *rsti = new RtpStreamTreeWidgetItem(ui->streamTreeWidget, stream_info);
        cur_stream = gxx_list_next(cur_stream);
        to_insert_count--;

        // Check if item was selected last time. If so, select it
        if (-1 != last_selected_.indexOf(stream_info->id)) {
           rsti->setSelected(true);
        }
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

    find_reverse_button_->setEnabled(has_data);
    prepare_button_->setEnabled(enable);
    export_button_->setEnabled(enable);
    copy_button_->setEnabled(has_data);
    analyze_button_->setEnabled(enable);

    ui->actionFindReverseNormal->setEnabled(enable);
    ui->actionFindReversePair->setEnabled(has_data);
    ui->actionFindReverseSingle->setEnabled(has_data);
    ui->actionGoToSetup->setEnabled(enable);
    ui->actionMarkPackets->setEnabled(enable);
    ui->actionPrepareFilter->setEnabled(enable);
    ui->actionExportAsRtpDump->setEnabled(enable);
    ui->actionCopyAsCsv->setEnabled(has_data);
    ui->actionCopyAsYaml->setEnabled(has_data);
    ui->actionAnalyze->setEnabled(enable);

#if defined(QT_MULTIMEDIA_LIB)
    player_button_->setEnabled(enable);
#endif

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

    // Add additional columns to export
    if (row < 0) {
        row_data << QString("SSRC formatted");
        row_data << QString("Lost percentage");
    } else {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(row));
        if (rsti) {
            row_data << rsti->colData(ssrc_fmt_col_);
            row_data << rsti->colData(lost_perc_col_);
        }
    }
    return row_data;
}

void RtpStreamDialog::freeLastSelected()
{
    /* Free old IDs */
    for(int i=0; i<last_selected_.length(); i++) {
        rtpstream_id_t id = last_selected_.at(i);
        rtpstream_id_free(&id);
    }
    /* Clear list and reuse it */
    last_selected_.clear();
}

void RtpStreamDialog::captureFileClosing()
{
    remove_tap_listener_rtpstream(&tapinfo_);

    WiresharkDialog::captureFileClosing();
}

void RtpStreamDialog::captureFileClosed()
{
    ui->todCheckBox->setEnabled(false);
    ui->displayFilterCheckBox->setEnabled(false);

    WiresharkDialog::captureFileClosed();
}

void RtpStreamDialog::showStreamMenu(QPoint pos)
{
    ui->actionGoToSetup->setEnabled(!file_closed_);
    ui->actionMarkPackets->setEnabled(!file_closed_);
    ui->actionPrepareFilter->setEnabled(!file_closed_);
    ui->actionExportAsRtpDump->setEnabled(!file_closed_);
    ui->actionAnalyze->setEnabled(!file_closed_);
    ctx_menu_.popup(ui->streamTreeWidget->viewport()->mapToGlobal(pos));
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
            } else if (v.userType() == QMetaType::QString) {
                rdsl << QString("\"%1\"").arg(v.toString());
            } else {
                rdsl << v.toString();
            }
        }
        stream << rdsl.join(",") << '\n';
    }
    mainApp->clipboard()->setText(stream.readAll());
}

void RtpStreamDialog::on_actionCopyAsYaml_triggered()
{
    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    stream << "---" << '\n';
    for (int row = -1; row < ui->streamTreeWidget->topLevelItemCount(); row ++) {
        stream << "-" << '\n';
        foreach (QVariant v, streamRowData(row)) {
            stream << " - " << v.toString() << '\n';
        }
    }
    mainApp->clipboard()->setText(stream.readAll());
}

void RtpStreamDialog::on_actionExportAsRtpDump_triggered()
{
    if (file_closed_ || ui->streamTreeWidget->selectedItems().count() < 1) return;

    // XXX If the user selected multiple frames is this the one we actually want?
    QTreeWidgetItem *ti = ui->streamTreeWidget->selectedItems()[0];
    RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
    rtpstream_info_t *stream_info = rsti->streamInfo();
    if (stream_info) {
        QString file_name;
        QDir path(mainApp->openDialogInitialDir());
        QString save_file = path.canonicalPath() + "/" + cap_file_.fileBaseName();
        QString extension;
        file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save RTPDump As…")),
                                                 save_file, "RTPDump Format (*.rtp)", &extension);

        if (file_name.length() > 0) {
            char *dest_file = qstring_strdup(file_name);
            bool save_ok = rtpstream_save(&tapinfo_, cap_file_.capFile(), stream_info, dest_file);
            g_free(dest_file);
            // else error dialog?
            if (save_ok) {
                mainApp->setLastOpenDirFromFilename(file_name);
            }
        }

    }
}

// Search for reverse stream of every selected stream
void RtpStreamDialog::on_actionFindReverseNormal_triggered()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    ui->streamTreeWidget->blockSignals(true);

    // Traverse all items and if stream is selected, search reverse from
    // current position till last item (NxN/2)
    for (int fwd_row = 0; fwd_row < ui->streamTreeWidget->topLevelItemCount(); fwd_row++) {
        RtpStreamTreeWidgetItem *fwd_rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(fwd_row));
        rtpstream_info_t *fwd_stream = fwd_rsti->streamInfo();
        if (fwd_stream && fwd_rsti->isSelected()) {
            for (int rev_row = fwd_row + 1; rev_row < ui->streamTreeWidget->topLevelItemCount(); rev_row++) {
                RtpStreamTreeWidgetItem *rev_rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(rev_row));
                rtpstream_info_t *rev_stream = rev_rsti->streamInfo();
                if (rev_stream && rtpstream_info_is_reverse(fwd_stream, rev_stream)) {
                    rev_rsti->setSelected(true);
                    break;
                }
            }
        }
    }
    ui->streamTreeWidget->blockSignals(false);
    updateWidgets();
}

// Select all pairs of forward/reverse streams
void RtpStreamDialog::on_actionFindReversePair_triggered()
{
    ui->streamTreeWidget->blockSignals(true);
    ui->streamTreeWidget->clearSelection();

    // Traverse all items and search reverse from current position till last
    // item (NxN/2)
    for (int fwd_row = 0; fwd_row < ui->streamTreeWidget->topLevelItemCount(); fwd_row++) {
        RtpStreamTreeWidgetItem *fwd_rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(fwd_row));
        rtpstream_info_t *fwd_stream = fwd_rsti->streamInfo();
        if (fwd_stream) {
            for (int rev_row = fwd_row + 1; rev_row < ui->streamTreeWidget->topLevelItemCount(); rev_row++) {
                RtpStreamTreeWidgetItem *rev_rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(rev_row));
                rtpstream_info_t *rev_stream = rev_rsti->streamInfo();
                if (rev_stream && rtpstream_info_is_reverse(fwd_stream, rev_stream)) {
                    fwd_rsti->setSelected(true);
                    rev_rsti->setSelected(true);
                    break;
                }
            }
        }
    }
    ui->streamTreeWidget->blockSignals(false);
    updateWidgets();
}

// Select all streams which don't have reverse stream
void RtpStreamDialog::on_actionFindReverseSingle_triggered()
{
    ui->streamTreeWidget->blockSignals(true);
    ui->streamTreeWidget->selectAll();

    // Traverse all items and search reverse from current position till last
    // item (NxN/2)
    for (int fwd_row = 0; fwd_row < ui->streamTreeWidget->topLevelItemCount(); fwd_row++) {
        RtpStreamTreeWidgetItem *fwd_rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(fwd_row));
        rtpstream_info_t *fwd_stream = fwd_rsti->streamInfo();
        if (fwd_stream) {
            for (int rev_row = fwd_row + 1; rev_row < ui->streamTreeWidget->topLevelItemCount(); rev_row++) {
                RtpStreamTreeWidgetItem *rev_rsti = static_cast<RtpStreamTreeWidgetItem*>(ui->streamTreeWidget->topLevelItem(rev_row));
                rtpstream_info_t *rev_stream = rev_rsti->streamInfo();
                if (rev_stream && rtpstream_info_is_reverse(fwd_stream, rev_stream)) {
                    fwd_rsti->setSelected(false);
                    rev_rsti->setSelected(false);
                    break;
                }
            }
        }
    }
    ui->streamTreeWidget->blockSignals(false);
    updateWidgets();
}

void RtpStreamDialog::on_actionGoToSetup_triggered()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;
    // XXX If the user selected multiple frames is this the one we actually want?
    QTreeWidgetItem *ti = ui->streamTreeWidget->selectedItems()[0];
    RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
    rtpstream_info_t *stream_info = rsti->streamInfo();
    if (stream_info) {
        emit goToPacket(stream_info->setup_frame_number);
    }
}

void RtpStreamDialog::on_actionMarkPackets_triggered()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;
    rtpstream_info_t *stream_a, *stream_b = NULL;

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
    QVector<rtpstream_id_t *> ids = getSelectedRtpIds();
    QString filter = make_filter_based_on_rtpstream_id(ids);
    if (filter.length() > 0) {
        remove_tap_listener_rtpstream(&tapinfo_);
        emit updateFilter(filter);
    }
}

void RtpStreamDialog::on_streamTreeWidget_itemSelectionChanged()
{
    updateWidgets();
}

void RtpStreamDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_TELEPHONY_RTP_STREAMS_DIALOG);
}

void RtpStreamDialog::displayFilterCheckBoxToggled(bool checked)
{
    if (!cap_file_.isValid()) {
        return;
    }

    tapinfo_.apply_display_filter = checked;

    cap_file_.retapPackets();
}

void RtpStreamDialog::on_todCheckBox_toggled(bool checked)
{
    QTreeWidgetItemIterator iter(ui->streamTreeWidget);
    while (*iter) {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(*iter);
        rsti->setTOD(checked);
        rsti->drawData();
        ++iter;
    }
    ui->streamTreeWidget->resizeColumnToContents(start_time_col_);
}

void RtpStreamDialog::on_actionSelectAll_triggered()
{
    ui->streamTreeWidget->selectAll();
}

void RtpStreamDialog::on_actionSelectInvert_triggered()
{
    invertSelection();
}

void RtpStreamDialog::on_actionSelectNone_triggered()
{
    ui->streamTreeWidget->clearSelection();
}

QVector<rtpstream_id_t *>RtpStreamDialog::getSelectedRtpIds()
{
    // Gather up our selected streams...
    QVector<rtpstream_id_t *> stream_ids;
    foreach(QTreeWidgetItem *ti, ui->streamTreeWidget->selectedItems()) {
        RtpStreamTreeWidgetItem *rsti = static_cast<RtpStreamTreeWidgetItem*>(ti);
        rtpstream_info_t *selected_stream = rsti->streamInfo();
        if (selected_stream) {
            stream_ids << &(selected_stream->id);
        }
    }

    return stream_ids;
}

void RtpStreamDialog::rtpPlayerReplace()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpPlayerDialogReplaceRtpStreams(getSelectedRtpIds());
}

void RtpStreamDialog::rtpPlayerAdd()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpPlayerDialogAddRtpStreams(getSelectedRtpIds());
}

void RtpStreamDialog::rtpPlayerRemove()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpPlayerDialogRemoveRtpStreams(getSelectedRtpIds());
}

void RtpStreamDialog::rtpAnalysisReplace()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpAnalysisDialogReplaceRtpStreams(getSelectedRtpIds());
}

void RtpStreamDialog::rtpAnalysisAdd()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpAnalysisDialogAddRtpStreams(getSelectedRtpIds());
}

void RtpStreamDialog::rtpAnalysisRemove()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpAnalysisDialogRemoveRtpStreams(getSelectedRtpIds());
}

void RtpStreamDialog::displayFilterSuccess(bool success)
{
    if (success && ui->displayFilterCheckBox->isChecked()) {
        cap_file_.retapPackets();
    }
}

void RtpStreamDialog::invertSelection()
{
    ui->streamTreeWidget->blockSignals(true);
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        ti->setSelected(!ti->isSelected());
    }
    ui->streamTreeWidget->blockSignals(false);
    updateWidgets();
}

void RtpStreamDialog::on_actionAnalyze_triggered()
{
    RtpStreamDialog::rtpAnalysisAdd();
}

