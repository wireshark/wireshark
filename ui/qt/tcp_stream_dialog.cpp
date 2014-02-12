/* tcp_stream_dialog.cpp
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

#include "tcp_stream_dialog.h"
#include "ui_tcp_stream_dialog.h"

#include "epan/to_str.h"

#include "wsutil/str_util.h"

#include "ui/utf8_entities.h"

#include "tango_colors.h"
#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QCursor>
#include <QDir>
#include <QFileDialog>
#include <QIcon>
#include <QPushButton>

#include <QDebug>

// To do:
// - Show a message or disable the graph if we don't have any data.
// - Add a bytes in flight graph
// - Make the crosshairs tracer a vertical band?
// - Implement File->Copy
// - Add UDP graphs
// - Add horizontal- and vertical-only zoom via modifier keys?
// - Make the first throughput MA period a dotted/dashed line?
// - Add range scroll bars?
// - ACK & RWIN segment ticks in tcptrace graph
// - Add missing elements (retrans, URG, SACK, etc) to tcptrace. It probably makes
//   sense to subclass QCPGraph for this.

// The GTK+ version computes a 20 (or 21!) segment moving average. Comment
// out the line below to use that. By default we use a 1 second MA.
#define MA_1_SECOND

#ifndef MA_1_SECOND
const int moving_avg_period_ = 20;
#endif

const QRgb graph_color_1 = tango_sky_blue_5;
const QRgb graph_color_2 = tango_butter_6;
const QRgb graph_color_3 = tango_chameleon_5;
//const QRgb graph_color_4 = tango_aluminium_6;

// Size of selectable packet points in the base graph
const double pkt_point_size_ = 3.0;

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const QString average_throughput_label_ = QObject::tr("Avgerage Througput (bits/s)");
const QString round_trip_time_ms_label_ = QObject::tr("Round Trip Time (ms)");
const QString segment_length_label_ = QObject::tr("Segment Length (B)");
const QString sequence_number_label_ = QObject::tr("Sequence Number (B)");
const QString time_s_label_ = QObject::tr("Time (s)");
const QString window_size_label_ = QObject::tr("Window Size (B)");

TCPStreamDialog::TCPStreamDialog(QWidget *parent, capture_file *cf, tcp_graph_type graph_type) :
    QDialog(parent),
    ui(new Ui::TCPStreamDialog),
    cap_file_(cf),
    ts_origin_conn_(true),
    seq_origin_zero_(true),
    mouse_drags_(true),
    rubber_band_(NULL),
    num_dsegs_(-1),
    num_acks_(-1),
    num_sack_ranges_(-1)
{
    struct segment current;
    int graph_idx = -1;

    ui->setupUi(this);

    struct tcpheader *header = select_tcpip_session(cap_file_, &current);
    if (!header) {
        done(QDialog::Rejected);
        return;
    }

//#ifdef Q_OS_MAC
//    ui->hintLabel->setAttribute(Qt::WA_MacSmallSize, true);
//#endif

    QComboBox *gtcb = ui->graphTypeComboBox;
    gtcb->setUpdatesEnabled(false);
    gtcb->addItem(ui->actionRoundTripTime->text(), GRAPH_RTT);
    if (graph_type == GRAPH_RTT) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionThroughput->text(), GRAPH_THROUGHPUT);
    if (graph_type == GRAPH_THROUGHPUT) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionStevens->text(), GRAPH_TSEQ_STEVENS);
    if (graph_type == GRAPH_TSEQ_STEVENS) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionTcptrace->text(), GRAPH_TSEQ_TCPTRACE);
    if (graph_type == GRAPH_TSEQ_TCPTRACE) graph_idx = gtcb->count() - 1;
    gtcb->addItem(ui->actionWindowScaling->text(), GRAPH_WSCALE);
    if (graph_type == GRAPH_WSCALE) graph_idx = gtcb->count() - 1;
    gtcb->setUpdatesEnabled(true);

    ui->dragRadioButton->setChecked(mouse_drags_);

    ctx_menu_.addAction(ui->actionZoomIn);
    ctx_menu_.addAction(ui->actionZoomOut);
    ctx_menu_.addAction(ui->actionReset);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionMoveRight10);
    ctx_menu_.addAction(ui->actionMoveLeft10);
    ctx_menu_.addAction(ui->actionMoveUp10);
    ctx_menu_.addAction(ui->actionMoveDown10);
    ctx_menu_.addAction(ui->actionMoveRight1);
    ctx_menu_.addAction(ui->actionMoveLeft1);
    ctx_menu_.addAction(ui->actionMoveUp1);
    ctx_menu_.addAction(ui->actionMoveDown1);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionNextStream);
    ctx_menu_.addAction(ui->actionPreviousStream);
    ctx_menu_.addAction(ui->actionSwitchDirection);
    ctx_menu_.addAction(ui->actionGoToPacket);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionDragZoom);
    ctx_menu_.addAction(ui->actionToggleSequenceNumbers);
    ctx_menu_.addAction(ui->actionToggleTimeOrigin);
    ctx_menu_.addAction(ui->actionCrosshairs);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionRoundTripTime);
    ctx_menu_.addAction(ui->actionThroughput);
    ctx_menu_.addAction(ui->actionStevens);
    ctx_menu_.addAction(ui->actionTcptrace);
    ctx_menu_.addAction(ui->actionWindowScaling);

    memset (&graph_, 0, sizeof(graph_));
    graph_.type = graph_type;
    copy_address(&graph_.src_address, &current.ip_src);
    graph_.src_port = current.th_sport;
    copy_address(&graph_.dst_address, &current.ip_dst);
    graph_.dst_port = current.th_dport;
    graph_.stream = header->th_stream;
    findStream();

    ui->streamNumberSpinBox->blockSignals(true);
    ui->streamNumberSpinBox->setValue(graph_.stream);
    ui->streamNumberSpinBox->setMaximum(get_tcp_stream_count() - 1);
    ui->streamNumberSpinBox->blockSignals(false);

    QCustomPlot *sp = ui->streamPlot;
    QCPPlotTitle *file_title = new QCPPlotTitle(sp, cf_get_display_name(cap_file_));
    file_title->setFont(sp->xAxis->labelFont());
    title_ = new QCPPlotTitle(sp);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, file_title);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, title_);

    base_graph_ = sp->addGraph(); // All: Selectable segments
    base_graph_->setPen(QPen(QBrush(graph_color_1), 0.25));
    tput_graph_ = sp->addGraph(sp->xAxis, sp->yAxis2); // Throughput: Moving average
    tput_graph_->setPen(QPen(QBrush(graph_color_2), 0.5));
    tput_graph_->setLineStyle(QCPGraph::lsLine);
    seg_graph_ = sp->addGraph(); // tcptrace: fwd segments
    seg_graph_->setErrorType(QCPGraph::etValue);
    seg_graph_->setLineStyle(QCPGraph::lsNone);
    seg_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0));
    seg_graph_->setErrorPen(QPen(QBrush(graph_color_1), 0.5));
    seg_graph_->setErrorBarSize(pkt_point_size_);
    ack_graph_ = sp->addGraph(); // tcptrace: rev ACKs
    ack_graph_->setPen(QPen(QBrush(graph_color_2), 0.5));
    ack_graph_->setLineStyle(QCPGraph::lsStepLeft);
    rwin_graph_ = sp->addGraph(); // tcptrace: rev RWIN
    rwin_graph_->setPen(QPen(QBrush(graph_color_3), 0.5));
    rwin_graph_->setLineStyle(QCPGraph::lsStepLeft);

    tracer_ = new QCPItemTracer(sp);
    sp->addItem(tracer_);

    // Triggers fillGraph().
    ui->graphTypeComboBox->setCurrentIndex(graph_idx);

    sp->setMouseTracking(true);

    sp->yAxis->setLabelColor(QColor(graph_color_1));
    sp->yAxis->setTickLabelColor(QColor(graph_color_1));

    tracer_->setVisible(false);
    toggleTracerStyle(true);

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As..."));

    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    connect(sp, SIGNAL(axisClick(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)),
            this, SLOT(axisClicked(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(transformYRange(QCPRange)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}

TCPStreamDialog::~TCPStreamDialog()
{
    delete ui;
}

void TCPStreamDialog::showEvent(QShowEvent *event)
{
    Q_UNUSED(event);
    resetAxes();
}

void TCPStreamDialog::keyPressEvent(QKeyEvent *event)
{
    int pan_pixels = event->modifiers() & Qt::ShiftModifier ? 1 : 10;

    // XXX - This differs from the main window but matches other applications (e.g. Mozilla and Safari)
    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
    case Qt::Key_O:             // GTK+
        zoomAxes(false);
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
    case Qt::Key_I:             // GTK+
        zoomAxes(true);
        break;

    case Qt::Key_Right:
    case Qt::Key_L:
        panAxes(pan_pixels, 0);
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        panAxes(-1 * pan_pixels, 0);
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        panAxes(0, pan_pixels);
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        panAxes(0, -1 * pan_pixels);
        break;

    case Qt::Key_Space:
        toggleTracerStyle();
        break;

    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_R:
    case Qt::Key_Home:
        resetAxes();
        break;

    case Qt::Key_PageUp:
        on_actionNextStream_triggered();
        break;
    case Qt::Key_PageDown:
        on_actionPreviousStream_triggered();
        break;

    case Qt::Key_D:
        on_actionSwitchDirection_triggered();
        break;
    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        break;
    case Qt::Key_S:
        on_actionToggleSequenceNumbers_triggered();
        break;
    case Qt::Key_T:
        on_actionToggleTimeOrigin_triggered();
        break;
    case Qt::Key_Z:
        on_actionDragZoom_triggered();
        break;

    case Qt::Key_1:
        on_actionRoundTripTime_triggered();
        break;
    case Qt::Key_2:
        on_actionThroughput_triggered();
        break;
    case Qt::Key_3:
        on_actionStevens_triggered();
        break;
    case Qt::Key_4:
        on_actionTcptrace_triggered();
        break;
    case Qt::Key_5:
        on_actionWindowScaling_triggered();
        break;
        // Alas, there is no Blade Runner-style Qt::Key_Enhance
    }

    QDialog::keyPressEvent(event);
}

void TCPStreamDialog::mouseReleaseEvent(QMouseEvent *event)
{
    mouseReleased(event);
}

void TCPStreamDialog::findStream()
{
    graph_segment_list_free(&graph_);
    graph_segment_list_get(cap_file_, &graph_, TRUE);
}

void TCPStreamDialog::fillGraph()
{
    QCustomPlot *sp = ui->streamPlot;

    if (sp->graphCount() < 1) return;

    base_graph_->setLineStyle(QCPGraph::lsNone);
    tracer_->setGraph(NULL);

    // base_graph_ is always visible.
    for (int i = 0; i < sp->graphCount(); i++) {
        sp->graph(i)->clearData();
        sp->graph(i)->setVisible(i == 0 ? true : false);
    }

    base_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));

    sp->xAxis->setLabel(time_s_label_);
    sp->xAxis->setNumberFormat("gb");
    sp->xAxis->setNumberPrecision(6);
    sp->yAxis->setNumberFormat("f");
    sp->yAxis->setNumberPrecision(0);
    sp->yAxis2->setVisible(false);
    sp->yAxis2->setLabel(QString());

    if (!cap_file_) {
        QString dlg_title = QString(tr("No Capture Data"));
        setWindowTitle(dlg_title);
        title_->setText(dlg_title);
        sp->setEnabled(false);
        sp->yAxis->setLabel(QString());
        sp->replot();
        return;
    }

    ts_offset_ = 0;
    seq_offset_ = 0;
    bool first = true;
    guint64 bytes_fwd = 0;
    guint64 bytes_rev = 0;
    int pkts_fwd = 0;
    int pkts_rev = 0;

    time_stamp_map_.clear();
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            bytes_rev += seg->th_seglen;
            pkts_rev++;
            continue;
        }
        bytes_fwd += seg->th_seglen;
        pkts_fwd++;
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;
        if (first) {
            if (ts_origin_conn_) ts_offset_ = ts;
            if (seq_origin_zero_) seq_offset_ = seg->th_seq;
            first = false;
        }
        time_stamp_map_.insertMulti(ts - ts_offset_, seg);
    }

    switch (graph_.type) {
    case GRAPH_TSEQ_STEVENS:
        fillStevens();
        break;
    case GRAPH_TSEQ_TCPTRACE:
        fillTcptrace();
        break;
    case GRAPH_THROUGHPUT:
        fillThroughput();
        break;
    case GRAPH_RTT:
        fillRoundTripTime();
        break;
    case GRAPH_WSCALE:
        fillWindowScale();
        break;
    default:
        break;
    }
    sp->setEnabled(true);

    stream_desc_ = tr("%1 %2 pkts, %3 %4 %5 pkts, %6 ")
            .arg(UTF8_RIGHTWARDS_ARROW)
            .arg(gchar_free_to_qstring(format_size(pkts_fwd, format_size_unit_none|format_size_prefix_si)))
            .arg(gchar_free_to_qstring(format_size(bytes_fwd, format_size_unit_bytes|format_size_prefix_si)))
            .arg(UTF8_LEFTWARDS_ARROW)
            .arg(gchar_free_to_qstring(format_size(pkts_rev, format_size_unit_none|format_size_prefix_si)))
            .arg(gchar_free_to_qstring(format_size(bytes_rev, format_size_unit_bytes|format_size_prefix_si)));
    mouseMoved(NULL);
    resetAxes();
    tracer_->setGraph(base_graph_);

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();
}

void TCPStreamDialog::zoomAxes(bool in)
{
    QCustomPlot *sp = ui->streamPlot;
    double h_factor = sp->axisRect()->rangeZoomFactor(Qt::Horizontal);
    double v_factor = sp->axisRect()->rangeZoomFactor(Qt::Vertical);

    if (!in) {
        h_factor = pow(h_factor, -1);
        v_factor = pow(v_factor, -1);
    }

    sp->xAxis->scaleRange(h_factor, sp->xAxis->range().center());
    sp->yAxis->scaleRange(v_factor, sp->yAxis->range().center());
    sp->replot();
}

void TCPStreamDialog::panAxes(int x_pixels, int y_pixels)
{
    QCustomPlot *sp = ui->streamPlot;
    double h_pan = 0.0;
    double v_pan = 0.0;

    h_pan = sp->xAxis->range().size() * x_pixels / sp->xAxis->axisRect()->width();
    v_pan = sp->yAxis->range().size() * y_pixels / sp->yAxis->axisRect()->height();
    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan) {
        sp->xAxis->moveRange(h_pan);
        sp->replot();
    }
    if (v_pan) {
        sp->yAxis->moveRange(v_pan);
        sp->replot();
    }
}

void TCPStreamDialog::resetAxes()
{
    QCustomPlot *sp = ui->streamPlot;

    y_axis_xfrm_.reset();
    double pixel_pad = 10.0; // per side

    sp->rescaleAxes(true);
    tput_graph_->rescaleValueAxis(false, true);
//    base_graph_->rescaleAxes(false, true);
//    for (int i = 0; i < sp->graphCount(); i++) {
//        sp->graph(i)->rescaleValueAxis(false, true);
//    }

    double axis_pixels = sp->xAxis->axisRect()->width();
    sp->xAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, sp->xAxis->range().center());

    if (sp->yAxis2->visible()) {
        double ratio = sp->yAxis2->range().size() / sp->yAxis->range().size();
        y_axis_xfrm_.translate(0.0, sp->yAxis2->range().lower - (sp->yAxis->range().lower * ratio));
        y_axis_xfrm_.scale(1.0, ratio);
    }

    axis_pixels = sp->yAxis->axisRect()->height();
    sp->yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, sp->yAxis->range().center());

    sp->replot();
}

void TCPStreamDialog::fillStevens()
{
    QString dlg_title = QString(tr("Sequence Numbers (Stevens)")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->yAxis->setLabel(sequence_number_label_);

    // True Stevens-style graphs don't have lines but I like them - gcc
    base_graph_->setLineStyle(QCPGraph::lsStepLeft);

    QVector<double> rel_time, seq;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }

        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;
        rel_time.append(ts - ts_offset_);
        seq.append(seg->th_seq - seq_offset_);
    }
    base_graph_->setData(rel_time, seq);
}

void TCPStreamDialog::fillTcptrace()
{
    QString dlg_title = QString(tr("Sequence Numbers (tcptrace)")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->yAxis->setLabel(sequence_number_label_);

    base_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot));

    seg_graph_->setVisible(true);
    ack_graph_->setVisible(true);
    rwin_graph_->setVisible(true);

    QVector<double> seq_time, seq, sb_time, sb_center, sb_span, ackrwin_time, ack, rwin;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        double ts = (seg->rel_secs + seg->rel_usecs / 1000000.0) - ts_offset_;
        if (compareHeaders(seg)) {
            // Forward direction: seq + data
            seq_time.append(ts);
            seq.append(seg->th_seq - seq_offset_);

            // QCP doesn't have a segment graph type. For now, fake
            // it with error bars.
            if (seg->th_seglen > 0) {
                double half = seg->th_seglen / 2.0;
                sb_time.append(ts);
                sb_center.append(seg->th_seq - seq_offset_ + half);
                sb_span.append(half);
            }
        } else {
            // Reverse direction: ACK + RWIN
            if (! (seg->th_flags & TH_ACK)) {
                // SYNs and RSTs do not necessarily have ACKs
                continue;
            }
            double ackno = seg->th_ack - seq_offset_;
            ackrwin_time.append(ts);
            ack.append(ackno);
            rwin.append(ackno + seg->th_win);
        }
    }
    base_graph_->setData(seq_time, seq);
    seg_graph_->setDataValueError(sb_time, sb_center, sb_span);
    ack_graph_->setData(ackrwin_time, ack);
    rwin_graph_->setData(ackrwin_time, rwin);
}

void TCPStreamDialog::fillThroughput()
{
    QString dlg_title = QString(tr("Throughput")) + streamDescription();
#ifdef MA_1_SECOND
    dlg_title.append(tr(" (1s MA)"));
#else
    dlg_title.append(QString(tr(" (%1 Segment MA)")).arg(moving_avg_period_));
#endif
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->yAxis->setLabel(segment_length_label_);
    sp->yAxis2->setLabel(average_throughput_label_);
    sp->yAxis2->setLabelColor(QColor(graph_color_2));
    sp->yAxis2->setTickLabelColor(QColor(graph_color_2));
    sp->yAxis2->setVisible(true);

    tput_graph_->setVisible(true);

    if (!graph_.segments || !graph_.segments->next) {
        dlg_title.append(tr(" [not enough data]"));
        return;
    }

    QVector<double> rel_time, seg_len, tput_time, tput;
    int oldest = 0;
    int sum = 0;
    // Financial charts don't show MA data until a full period has elapsed.
    // The Rosetta Code MA examples start spitting out values immediately.
    // For now use not-really-correct initial values just to keep our vector
    // lengths the same.
    for (struct segment *seg = graph_.segments->next; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }

        double ts = (seg->rel_secs + seg->rel_usecs / 1000000.0) - ts_offset_;

        rel_time.append(ts);
        seg_len.append(seg->th_seglen);

#ifdef MA_1_SECOND
        while (ts - rel_time[oldest] > 1.0 && oldest < rel_time.size()) {
            sum -= seg_len[oldest];
            oldest++;
        }
#else
        if (seg_len.size() > moving_avg_period_) {
            sum -= seg_len[oldest];
            oldest++;
        }
#endif

        double dtime = ts - rel_time[oldest];
        double av_tput;
        sum += seg->th_seglen;
        if (dtime > 0.0) {
            av_tput = sum * 8.0 / dtime;
        } else {
            av_tput = 0.0;
        }

        // Add a data point only if our time window has advanced. Otherwise
        // update the most recent point. (We might want to show a warning
        // for out-of-order packets.)
        if (tput_time.size() > 0 && ts <= tput_time.last()) {
            tput[tput.size() - 1] = av_tput;
        } else {
            tput.append(av_tput);
            tput_time.append(ts);
        }
    }
    base_graph_->setData(rel_time, seg_len);
    tput_graph_->setData(tput_time, tput);
}

void TCPStreamDialog::fillRoundTripTime()
{
    QString dlg_title = QString(tr("Round Trip Time")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);
    sequence_num_map_.clear();

    QCustomPlot *sp = ui->streamPlot;
    sp->xAxis->setLabel(sequence_number_label_);
    sp->xAxis->setNumberFormat("f");
    sp->xAxis->setNumberPrecision(0);
    sp->yAxis->setLabel(round_trip_time_ms_label_);

    base_graph_->setLineStyle(QCPGraph::lsLine);

    QVector<double> seq_no, rtt;
    guint32 seq_base = 0;
    struct unack *unack = NULL, *u = NULL;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (compareHeaders(seg)) {
            seq_base = seg->th_seq;
            break;
        }
    }
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (compareHeaders(seg)) {
            guint32 seqno = seg->th_seq - seq_base;
            if (seg->th_seglen && !rtt_is_retrans(unack, seqno)) {
                double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
                u = rtt_get_new_unack(rt_val, seqno);
                if (!u) return;
                rtt_put_unack_on_list(&unack, u);
            }
        } else {
            guint32 ack_no = seg->th_ack - seq_base;
            double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
            struct unack *v;

            for (u = unack; u; u = v) {
                if (ack_no > u->seqno) {
                    seq_no.append(u->seqno);
                    rtt.append((rt_val - u->time) * 1000.0);
                    sequence_num_map_.insert(u->seqno, seg);
                    v = u->next;
                    rtt_delete_unack_from_list(&unack, u);
                } else {
                    v = u->next;
                }
            }
        }
    }
    base_graph_->setData(seq_no, rtt);
}

void TCPStreamDialog::fillWindowScale()
{
    QString dlg_title = QString(tr("Window Scaling")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    base_graph_->setLineStyle(QCPGraph::lsLine);

    QVector<double> rel_time, win_size;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }

        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;
        guint16 flags = seg->th_flags;

        if ( (flags & (TH_SYN|TH_RST)) == 0 ) {
            rel_time.append(ts - ts_offset_);
            win_size.append(seg->th_win);
        }
    }
    base_graph_->setData(rel_time, win_size);
    sp->yAxis->setLabel(window_size_label_);
}

QString TCPStreamDialog::streamDescription()
{
    return QString(tr(" for %1:%2 %3 %4:%5"))
            .arg(ep_address_to_str(&graph_.src_address))
            .arg(graph_.src_port)
            .arg(UTF8_RIGHTWARDS_ARROW)
            .arg(ep_address_to_str(&graph_.dst_address))
            .arg(graph_.dst_port);
}

bool TCPStreamDialog::compareHeaders(segment *seg)
{
    return (compare_headers(&graph_.src_address, &graph_.dst_address,
                         graph_.src_port, graph_.dst_port,
                         &seg->ip_src, &seg->ip_dst,
                         seg->th_sport, seg->th_dport,
                            COMPARE_CURR_DIR));
}

void TCPStreamDialog::toggleTracerStyle(bool force_default)
{
    if (!tracer_->visible() && !force_default) return;

    QPen sp_pen = ui->streamPlot->graph(0)->pen();
    QCPItemTracer::TracerStyle tstyle = QCPItemTracer::tsCrosshair;
    QPen tr_pen = QPen(tracer_->pen());
    QColor tr_color = sp_pen.color();

    if (force_default || tracer_->style() != QCPItemTracer::tsCircle) {
        tstyle = QCPItemTracer::tsCircle;
        tr_color.setAlphaF(1.0);
        tr_pen.setWidthF(1.5);
    } else {
        tr_color.setAlphaF(0.5);
        tr_pen.setWidthF(1.0);
    }

    tracer_->setStyle(tstyle);
    tr_pen.setColor(tr_color);
    tracer_->setPen(tr_pen);
    ui->streamPlot->replot();
}

QRectF TCPStreamDialog::getZoomRanges(QRect zoom_rect)
{
    QRectF zoom_ranges = QRectF();

    if (zoom_rect.width() < min_zoom_pixels_ && zoom_rect.height() < min_zoom_pixels_) {
        return zoom_ranges;
    }

    QCustomPlot *sp = ui->streamPlot;
    QRect zr = zoom_rect.normalized();
    QRect ar = sp->axisRect()->rect();
    if (ar.intersects(zr)) {
        QRect zsr = ar.intersected(zr);
        zoom_ranges.setX(sp->xAxis->range().lower
                         + sp->xAxis->range().size() * (zsr.left() - ar.left()) / ar.width());
        zoom_ranges.setWidth(sp->xAxis->range().size() * zsr.width() / ar.width());

        // QRects grow down
        zoom_ranges.setY(sp->yAxis->range().lower
                         + sp->yAxis->range().size() * (ar.bottom() - zsr.bottom()) / ar.height());
        zoom_ranges.setHeight(sp->yAxis->range().size() * zsr.height() / ar.height());
    }
    return zoom_ranges;
}

void TCPStreamDialog::graphClicked(QMouseEvent *event)
{
    QCustomPlot *sp = ui->streamPlot;

    if (event->button() == Qt::RightButton) {
        // XXX We should find some way to get streamPlot to handle a
        // contextMenuEvent instead.
        ctx_menu_.exec(event->globalPos());
    } else  if (mouse_drags_) {
        if (sp->axisRect()->rect().contains(event->pos())) {
            sp->setCursor(QCursor(Qt::ClosedHandCursor));
        }
        on_actionGoToPacket_triggered();
    } else {
        if (!rubber_band_) {
            rubber_band_ = new QRubberBand(QRubberBand::Rectangle, sp);
        }
        rb_origin_ = event->pos();
        rubber_band_->setGeometry(QRect(rb_origin_, QSize()));
        rubber_band_->show();
    }
}

void TCPStreamDialog::axisClicked(QCPAxis *axis, QCPAxis::SelectablePart part, QMouseEvent *event)
{
    Q_UNUSED(part)
    Q_UNUSED(event)
    QCustomPlot *sp = ui->streamPlot;

    if (axis == sp->xAxis) {
        switch (graph_.type) {
        case GRAPH_THROUGHPUT:
        case GRAPH_TSEQ_STEVENS:
        case GRAPH_TSEQ_TCPTRACE:
        case GRAPH_WSCALE:
            ts_origin_conn_ = ts_origin_conn_ ? false : true;
            fillGraph();
            break;
        case GRAPH_RTT:
            seq_origin_zero_ = seq_origin_zero_ ? false : true;
            fillGraph();
            break;
        default:
            break;
        }
    } else if (axis == sp->yAxis) {
        switch (graph_.type) {
        case GRAPH_TSEQ_STEVENS:
        case GRAPH_TSEQ_TCPTRACE:
            seq_origin_zero_ = seq_origin_zero_ ? false : true;
            fillGraph();
            break;
        default:
            break;
        }
    }
}

// Setting mouseTracking on our streamPlot may not be as reliable
// as we need. If it's not we might want to poll the mouse position
// using a QTimer instead.
void TCPStreamDialog::mouseMoved(QMouseEvent *event)
{
    QCustomPlot *sp = ui->streamPlot;
    Qt::CursorShape shape = Qt::ArrowCursor;
    if (event) {
        if (event->buttons().testFlag(Qt::LeftButton)) {
            if (mouse_drags_) {
                shape = Qt::ClosedHandCursor;
            } else {
                shape = Qt::CrossCursor;
            }
        } else {
            if (sp->axisRect()->rect().contains(event->pos())) {
                if (mouse_drags_) {
                    shape = Qt::OpenHandCursor;
                } else {
                    shape = Qt::CrossCursor;
                }
            }
        }
    }
    sp->setCursor(QCursor(shape));

    QString hint = "<small><i>";
    if (mouse_drags_) {
        double tr_key = tracer_->position->key();
        struct segment *packet_seg = NULL;
        packet_num_ = 0;

        // XXX If we have multiple packets with the same timestamp tr_key
        // may not return the packet we want. It might be possible to fudge
        // unique keys using nextafter().
        if (event && tracer_->graph() && tracer_->position->axisRect()->rect().contains(event->pos())) {
            switch (graph_.type) {
            case GRAPH_TSEQ_STEVENS:
            case GRAPH_TSEQ_TCPTRACE:
            case GRAPH_THROUGHPUT:
            case GRAPH_WSCALE:
                packet_seg = time_stamp_map_.value(tr_key, NULL);
                break;
            case GRAPH_RTT:
                packet_seg = sequence_num_map_.value(tr_key, NULL);
            default:
                break;
            }
        }

        if (!packet_seg) {
            tracer_->setVisible(false);
            hint += "Hover over the graph for details. " + stream_desc_ + "</i></small>";
            ui->hintLabel->setText(hint);
            ui->streamPlot->replot();
            return;
        }

        tracer_->setVisible(true);
        packet_num_ = packet_seg->num;
        hint += tr("%1 %2 (%3s len %4 seq %5 ack %6 win %7)")
                .arg(cap_file_ ? tr("Click to select packet") : tr("Packet"))
                .arg(packet_num_)
                .arg(QString::number(packet_seg->rel_secs + packet_seg->rel_usecs / 1000000.0, 'g', 4))
                .arg(packet_seg->th_seglen)
                .arg(packet_seg->th_seq)
                .arg(packet_seg->th_ack)
                .arg(packet_seg->th_win);
        tracer_->setGraphKey(ui->streamPlot->xAxis->pixelToCoord(event->pos().x()));
        sp->replot();
    } else {
        if (rubber_band_ && rubber_band_->isVisible() && event) {
            rubber_band_->setGeometry(QRect(rb_origin_, event->pos()).normalized());
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
                hint += tr("Release to zoom, x = %1 to %2, y = %3 to %4")
                        .arg(zoom_ranges.x())
                        .arg(zoom_ranges.x() + zoom_ranges.width())
                        .arg(zoom_ranges.y())
                        .arg(zoom_ranges.y() + zoom_ranges.height());
            } else {
                hint += tr("Unable to select range.");
            }
        } else {
            hint += tr("Click to select a portion of the graph.");
        }
    }
    hint += " " + stream_desc_ + "</i></small>";
    ui->hintLabel->setText(hint);
}

void TCPStreamDialog::mouseReleased(QMouseEvent *event)
{
    if (rubber_band_) {
        rubber_band_->hide();
        if (!mouse_drags_) {
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
                QCustomPlot *sp = ui->streamPlot;
                sp->xAxis->setRangeLower(zoom_ranges.x());
                sp->xAxis->setRangeUpper(zoom_ranges.x() + zoom_ranges.width());
                sp->yAxis->setRangeLower(zoom_ranges.y());
                sp->yAxis->setRangeUpper(zoom_ranges.y() + zoom_ranges.height());
                sp->replot();
            }
        }
    } else if (ui->streamPlot->cursor().shape() == Qt::ClosedHandCursor) {
        ui->streamPlot->setCursor(QCursor(Qt::OpenHandCursor));
    }
}

void TCPStreamDialog::transformYRange(const QCPRange &y_range1)
{
    if (y_axis_xfrm_.isIdentity()) return;

    QCustomPlot *sp = ui->streamPlot;
    QLineF yp1 = QLineF(1.0, y_range1.lower, 1.0, y_range1.upper);
    QLineF yp2 = y_axis_xfrm_.map(yp1);

    sp->yAxis2->setRangeUpper(yp2.y2());
    sp->yAxis2->setRangeLower(yp2.y1());
}

void TCPStreamDialog::on_buttonBox_accepted()
{
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

    file_name = QFileDialog::getSaveFileName(this, tr("Wireshark: Save Graph As..."),
                                             path.canonicalPath(), filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->streamPlot->savePdf(file_name);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = ui->streamPlot->savePng(file_name);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->streamPlot->saveBmp(file_name);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->streamPlot->saveJpg(file_name);
        }
        // else error dialog?
        if (save_ok) {
            path = QDir(file_name);
            wsApp->setLastOpenDir(path.canonicalPath().toUtf8().constData());
        }
    }
}

void TCPStreamDialog::on_graphTypeComboBox_currentIndexChanged(int index)
{
    if (index < 0) return;
    graph_.type = static_cast<tcp_graph_type>(ui->graphTypeComboBox->itemData(index).toInt());
    fillGraph();
}

void TCPStreamDialog::on_resetButton_clicked()
{
    resetAxes();
}

void TCPStreamDialog::setCaptureFile(capture_file *cf)
{
    if (!cf) { // We only want to know when the file closes.
        cap_file_ = NULL;
    }
}

void TCPStreamDialog::on_streamNumberSpinBox_valueChanged(int new_stream)
{
    if (new_stream >= 0 && new_stream < int(get_tcp_stream_count())) {
        graph_.stream = new_stream;
        graph_.src_address.type = AT_NONE;
        graph_.dst_address.type = AT_NONE;
        findStream();
        fillGraph();
    }
}

void TCPStreamDialog::on_otherDirectionButton_clicked()
{
    on_actionSwitchDirection_triggered();
}

void TCPStreamDialog::on_dragRadioButton_toggled(bool checked)
{
    if (checked) mouse_drags_ = true;
    ui->streamPlot->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom
                );
}

void TCPStreamDialog::on_zoomRadioButton_toggled(bool checked)
{
    if (checked) mouse_drags_ = false;
    ui->streamPlot->setInteractions(0);
}

void TCPStreamDialog::on_actionZoomIn_triggered()
{
    zoomAxes(true);
}

void TCPStreamDialog::on_actionZoomOut_triggered()
{
    zoomAxes(false);
}

void TCPStreamDialog::on_actionReset_triggered()
{
    on_resetButton_clicked();
}

void TCPStreamDialog::on_actionMoveRight10_triggered()
{
    panAxes(10, 0);
}

void TCPStreamDialog::on_actionMoveLeft10_triggered()
{
    panAxes(-10, 0);
}

void TCPStreamDialog::on_actionMoveUp10_triggered()
{
    panAxes(0, 10);
}

void TCPStreamDialog::on_actionMoveDown10_triggered()
{
    panAxes(0, -10);
}

void TCPStreamDialog::on_actionMoveRight1_triggered()
{
    panAxes(1, 0);
}

void TCPStreamDialog::on_actionMoveLeft1_triggered()
{
    panAxes(-1, 0);
}

void TCPStreamDialog::on_actionMoveUp1_triggered()
{
    panAxes(0, 1);
}

void TCPStreamDialog::on_actionMoveDown1_triggered()
{
    panAxes(0, -1);
}

void TCPStreamDialog::on_actionNextStream_triggered()
{
    if (int(graph_.stream) < int(get_tcp_stream_count()) - 1) {
        ui->streamNumberSpinBox->setValue(graph_.stream + 1);
    }
}

void TCPStreamDialog::on_actionPreviousStream_triggered()
{
    if (graph_.stream > 0) {
        ui->streamNumberSpinBox->setValue(graph_.stream - 1);
    }
}

void TCPStreamDialog::on_actionSwitchDirection_triggered()
{
    address tmp_addr;
    guint16 tmp_port;

    copy_address(&tmp_addr, &graph_.src_address);
    tmp_port = graph_.src_port;
    copy_address(&graph_.src_address, &graph_.dst_address);
    graph_.src_port = graph_.dst_port;
    copy_address(&graph_.dst_address, &tmp_addr);
    graph_.dst_port = tmp_port;

    fillGraph();
}

void TCPStreamDialog::on_actionGoToPacket_triggered()
{
    if (tracer_->visible() && cap_file_ && packet_num_ > 0) {
        emit goToPacket(packet_num_);
    }
}

void TCPStreamDialog::on_actionDragZoom_triggered()
{
    if (mouse_drags_) {
        ui->zoomRadioButton->toggle();
    } else {
        ui->dragRadioButton->toggle();
    }
}

void TCPStreamDialog::on_actionToggleSequenceNumbers_triggered()
{
    seq_origin_zero_ = seq_origin_zero_ ? false : true;
    fillGraph();
}

void TCPStreamDialog::on_actionToggleTimeOrigin_triggered()
{
    ts_origin_conn_ = ts_origin_conn_ ? false : true;
    fillGraph();
}

void TCPStreamDialog::on_actionRoundTripTime_triggered()
{
    ui->graphTypeComboBox->setCurrentIndex(ui->graphTypeComboBox->findData(GRAPH_RTT));
}

void TCPStreamDialog::on_actionThroughput_triggered()
{
    ui->graphTypeComboBox->setCurrentIndex(ui->graphTypeComboBox->findData(GRAPH_THROUGHPUT));
}

void TCPStreamDialog::on_actionStevens_triggered()
{
    ui->graphTypeComboBox->setCurrentIndex(ui->graphTypeComboBox->findData(GRAPH_TSEQ_STEVENS));
}

void TCPStreamDialog::on_actionTcptrace_triggered()
{
    ui->graphTypeComboBox->setCurrentIndex(ui->graphTypeComboBox->findData(GRAPH_TSEQ_TCPTRACE));
}

void TCPStreamDialog::on_actionWindowScaling_triggered()
{
    ui->graphTypeComboBox->setCurrentIndex(ui->graphTypeComboBox->findData(GRAPH_WSCALE));
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
