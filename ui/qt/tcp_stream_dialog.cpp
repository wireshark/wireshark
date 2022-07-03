/* tcp_stream_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tcp_stream_dialog.h"
#include <ui_tcp_stream_dialog.h>

#include <algorithm> // for std::sort
#include <utility> // for std::pair
#include <vector>

#include "epan/to_str.h"

#include "wsutil/str_util.h"

#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/tango_colors.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "progress_frame.h"
#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QCursor>
#include <QDir>
#include <QIcon>
#include <QPushButton>

#include <QDebug>

// To do:
// - Make the Help button work.
// - Show a message or disable the graph if we don't have any data.
// - Add a bytes in flight graph
// - Make the crosshairs tracer a vertical band?
// - Implement File->Copy
// - Add UDP graphs
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
const QRgb graph_color_4 = tango_scarlet_red_4;
const QRgb graph_color_5 = tango_scarlet_red_6;

// Size of selectable packet points in the base graph
const double pkt_point_size_ = 3.0;

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const QString average_throughput_label_ = QObject::tr("Average Throughput (bits/s)");
const QString round_trip_time_ms_label_ = QObject::tr("Round Trip Time (ms)");
const QString segment_length_label_ = QObject::tr("Segment Length (B)");
const QString sequence_number_label_ = QObject::tr("Sequence Number (B)");
const QString time_s_label_ = QObject::tr("Time (s)");
const QString window_size_label_ = QObject::tr("Window Size (B)");

QCPErrorBarsNotSelectable::QCPErrorBarsNotSelectable(QCPAxis *keyAxis, QCPAxis *valueAxis) :
    QCPErrorBars(keyAxis, valueAxis)
{
}

QCPErrorBarsNotSelectable::~QCPErrorBarsNotSelectable()
{
}

double QCPErrorBarsNotSelectable::selectTest(const QPointF &pos, bool onlySelectable, QVariant *details) const
{
    Q_UNUSED(pos);
    Q_UNUSED(onlySelectable);
    Q_UNUSED(details);
    return -1.0;
}

TCPStreamDialog::TCPStreamDialog(QWidget *parent, capture_file *cf, tcp_graph_type graph_type) :
    GeometryStateDialog(parent),
    ui(new Ui::TCPStreamDialog),
    cap_file_(cf),
    ts_offset_(0),
    ts_origin_conn_(true),
    seq_offset_(0),
    seq_origin_zero_(true),
    title_(nullptr),
    base_graph_(nullptr),
    tput_graph_(nullptr),
    goodput_graph_(nullptr),
    seg_graph_(nullptr),
    seg_eb_(nullptr),
    ack_graph_(nullptr),
    sack_graph_(nullptr),
    sack_eb_(nullptr),
    sack2_graph_(nullptr),
    sack2_eb_(nullptr),
    rwin_graph_(nullptr),
    dup_ack_graph_(nullptr),
    zero_win_graph_(nullptr),
    tracer_(nullptr),
    packet_num_(0),
    mouse_drags_(true),
    rubber_band_(nullptr),
    graph_updater_(this),
    num_dsegs_(-1),
    num_acks_(-1),
    num_sack_ranges_(-1),
    ma_window_size_(1.0)
{
    int graph_idx = -1;

    memset(&graph_, 0, sizeof(graph_));

    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 4 / 5);
    setAttribute(Qt::WA_DeleteOnClose, true);

    guint32 th_stream = select_tcpip_session(cap_file_);
    if (th_stream == G_MAXUINT32) {
        done(QDialog::Rejected);
        return;
    }

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
    ctx_menu_.addAction(ui->actionZoomInX);
    ctx_menu_.addAction(ui->actionZoomInY);
    ctx_menu_.addAction(ui->actionZoomOut);
    ctx_menu_.addAction(ui->actionZoomOutX);
    ctx_menu_.addAction(ui->actionZoomOutY);
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
    set_action_shortcuts_visible_in_context_menu(ctx_menu_.actions());

    graph_.type = graph_type;
    graph_.stream = th_stream;
    findStream();

    showWidgetsForGraphType();

    ui->streamNumberSpinBox->blockSignals(true);
    ui->streamNumberSpinBox->setMaximum(get_tcp_stream_count() - 1);
    ui->streamNumberSpinBox->setValue(graph_.stream);
    ui->streamNumberSpinBox->blockSignals(false);

#ifdef MA_1_SECOND
    ui->maWindowSizeSpinBox->blockSignals(true);
    ui->maWindowSizeSpinBox->setDecimals(6);
    ui->maWindowSizeSpinBox->setMinimum(0.000001);
    ui->maWindowSizeSpinBox->setValue(ma_window_size_);
    ui->maWindowSizeSpinBox->blockSignals(false);
#endif

    // set which Throughput graphs are displayed by default
    ui->showSegLengthCheckBox->blockSignals(true);
    ui->showSegLengthCheckBox->setChecked(true);
    ui->showSegLengthCheckBox->blockSignals(false);

    ui->showThroughputCheckBox->blockSignals(true);
    ui->showThroughputCheckBox->setChecked(true);
    ui->showThroughputCheckBox->blockSignals(false);

    // set which WScale graphs are displayed by default
    ui->showRcvWinCheckBox->blockSignals(true);
    ui->showRcvWinCheckBox->setChecked(true);
    ui->showRcvWinCheckBox->blockSignals(false);

    ui->showBytesOutCheckBox->blockSignals(true);
    ui->showBytesOutCheckBox->setChecked(true);
    ui->showBytesOutCheckBox->blockSignals(false);

    QCustomPlot *sp = ui->streamPlot;
    QCPTextElement *file_title = new QCPTextElement(sp, gchar_free_to_qstring(cf_get_display_name(cap_file_)));
    file_title->setFont(sp->xAxis->labelFont());
    title_ = new QCPTextElement(sp);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, file_title);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, title_);

    qreal pen_width = 0.5;
    // Base Graph - enables selecting segments (both data and SACKs)
    base_graph_ = sp->addGraph();
    base_graph_->setPen(QPen(QBrush(graph_color_1), pen_width));

    // Throughput Graph - rate of sent bytes
    tput_graph_ = sp->addGraph(sp->xAxis, sp->yAxis2);
    tput_graph_->setPen(QPen(QBrush(graph_color_2), pen_width));
    tput_graph_->setLineStyle(QCPGraph::lsStepLeft);

    // Goodput Graph - rate of ACKed bytes
    goodput_graph_ = sp->addGraph(sp->xAxis, sp->yAxis2);
    goodput_graph_->setPen(QPen(QBrush(graph_color_3), pen_width));
    goodput_graph_->setLineStyle(QCPGraph::lsStepLeft);

    // Seg Graph - displays forward data segments on tcptrace graph
    seg_graph_ = sp->addGraph();
    seg_graph_->setLineStyle(QCPGraph::lsNone);
    seg_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0));
    seg_eb_ = new QCPErrorBarsNotSelectable(sp->xAxis, sp->yAxis);
    seg_eb_->setErrorType(QCPErrorBars::etValueError);
    seg_eb_->setPen(QPen(QBrush(graph_color_1), pen_width));
    seg_eb_->setSymbolGap(0.0); // draw error spine as single line
    seg_eb_->setWhiskerWidth(pkt_point_size_);
    seg_eb_->removeFromLegend();
    seg_eb_->setDataPlottable(seg_graph_);

    // Ack Graph - displays ack numbers from reverse packets
    ack_graph_ = sp->addGraph();
    ack_graph_->setPen(QPen(QBrush(graph_color_2), pen_width));
    ack_graph_->setLineStyle(QCPGraph::lsStepLeft);

    // Sack Graph - displays highest number (most recent) SACK block
    sack_graph_ = sp->addGraph();
    sack_graph_->setLineStyle(QCPGraph::lsNone);
    sack_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0));
    sack_eb_ = new QCPErrorBarsNotSelectable(sp->xAxis, sp->yAxis);
    sack_eb_->setErrorType(QCPErrorBars::etValueError);
    sack_eb_->setPen(QPen(QBrush(graph_color_4), pen_width));
    sack_eb_->setSymbolGap(0.0); // draw error spine as single line
    sack_eb_->setWhiskerWidth(0.0);
    sack_eb_->removeFromLegend();
    sack_eb_->setDataPlottable(sack_graph_);

    // Sack Graph 2 - displays subsequent SACK blocks
    sack2_graph_ = sp->addGraph();
    sack2_graph_->setLineStyle(QCPGraph::lsNone);
    sack2_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot, Qt::transparent, 0));
    sack2_eb_ = new QCPErrorBarsNotSelectable(sp->xAxis, sp->yAxis);
    sack2_eb_->setErrorType(QCPErrorBars::etValueError);
    sack2_eb_->setPen(QPen(QBrush(graph_color_5), pen_width));
    sack2_eb_->setSymbolGap(0.0); // draw error spine as single line
    sack2_eb_->setWhiskerWidth(0.0);
    sack2_eb_->removeFromLegend();
    sack2_eb_->setDataPlottable(sack2_graph_);

    // RWin graph - displays upper extent of RWIN advertised on reverse packets
    rwin_graph_ = sp->addGraph();
    rwin_graph_->setPen(QPen(QBrush(graph_color_3), pen_width));
    rwin_graph_->setLineStyle(QCPGraph::lsStepLeft);

    // Duplicate ACK Graph - displays duplicate ack ticks
    // QCustomPlot doesn't have QCPScatterStyle::ssTick so we have to make our own.
    int tick_len = 3;
    tick_len *= devicePixelRatio();
    QPixmap da_tick_pm = QPixmap(1, tick_len * 2);
    da_tick_pm.fill(Qt::transparent);
    QPainter painter(&da_tick_pm);
    QPen da_tick_pen;
    da_tick_pen.setColor(graph_color_2);
    da_tick_pen.setWidthF(pen_width);
    painter.setPen(da_tick_pen);
    painter.drawLine(0, tick_len, 0, tick_len * 2);
    dup_ack_graph_ = sp->addGraph();
    dup_ack_graph_->setLineStyle(QCPGraph::lsNone);
    QCPScatterStyle da_ss = QCPScatterStyle(QCPScatterStyle::ssPixmap, graph_color_2, 0);
    da_ss.setPixmap(da_tick_pm);
    dup_ack_graph_->setScatterStyle(da_ss);

    // Zero Window Graph - displays zero window crosses (x)
    zero_win_graph_ = sp->addGraph();
    zero_win_graph_->setLineStyle(QCPGraph::lsNone);
    zero_win_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCross, graph_color_1, 5));

    tracer_ = new QCPItemTracer(sp);

    // Triggers fillGraph() [ UNLESS the index is already graph_idx!! ]
    if (graph_idx != ui->graphTypeComboBox->currentIndex())
        // changing the current index will call fillGraph
        ui->graphTypeComboBox->setCurrentIndex(graph_idx);
    else
        // the current index is what we want - so fillGraph() manually
        fillGraph();

    sp->setMouseTracking(true);

    sp->yAxis->setLabelColor(QColor(graph_color_1));
    sp->yAxis->setTickLabelColor(QColor(graph_color_1));

    tracer_->setVisible(false);
    toggleTracerStyle(true);

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As…"));

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    ProgressFrame::addToButtonBox(ui->buttonBox, parent);

    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    connect(sp, SIGNAL(axisClick(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)),
            this, SLOT(axisClicked(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(transformYRange(QCPRange)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    this->setResult(QDialog::Accepted);
}

TCPStreamDialog::~TCPStreamDialog()
{
    graph_segment_list_free(&graph_);

    delete ui;
}

void TCPStreamDialog::showEvent(QShowEvent *)
{
    resetAxes();
}

void TCPStreamDialog::keyPressEvent(QKeyEvent *event)
{
    int pan_pixels = event->modifiers() & Qt::ShiftModifier ? 1 : 10;

    QWidget* focusWidget = QApplication::focusWidget();

    // Block propagation of "Enter" key when focus is not default (e.g. SpinBox)
    //  [ Note that if focus was on, e.g. Close button, event would never reach
    //      here ]
    if ((event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) &&
        focusWidget !=NULL && focusWidget != ui->streamPlot) {

        // reset focus to default, and accept event
        ui->streamPlot->setFocus();
        event->accept();
        return;
    }

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
    case Qt::Key_X:             // Zoom X axis only
        if (event->modifiers() & Qt::ShiftModifier) {
            zoomXAxis(false);   // upper case X -> Zoom out
        } else {
            zoomXAxis(true);    // lower case x -> Zoom in
        }
        break;
    case Qt::Key_Y:             // Zoom Y axis only
        if (event->modifiers() & Qt::ShiftModifier) {
            zoomYAxis(false);   // upper case Y -> Zoom out
        } else {
            zoomYAxis(true);    // lower case y -> Zoom in
        }
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

void TCPStreamDialog::mousePressEvent(QMouseEvent *event)
{
    // if no-one else wants the event, then this is a click on blank space.
    //   Use this opportunity to set focus back to default, and accept event.
    ui->streamPlot->setFocus();
    event->accept();
}

void TCPStreamDialog::mouseReleaseEvent(QMouseEvent *event)
{
    mouseReleased(event);
}

void TCPStreamDialog::findStream()
{
    QCustomPlot *sp = ui->streamPlot;

    disconnect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    // if streamNumberSpinBox has focus -
    //   first clear focus, then disable/enable, then restore focus
    bool spin_box_focused = ui->streamNumberSpinBox->hasFocus();
    if (spin_box_focused)
        ui->streamNumberSpinBox->clearFocus();
    ui->streamNumberSpinBox->setEnabled(false);
    graph_segment_list_free(&graph_);
    graph_segment_list_get(cap_file_, &graph_);
    ui->streamNumberSpinBox->setEnabled(true);
    if (spin_box_focused)
        ui->streamNumberSpinBox->setFocus();

    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
}

void TCPStreamDialog::fillGraph(bool reset_axes, bool set_focus)
{
    QCustomPlot *sp = ui->streamPlot;

    if (sp->graphCount() < 1) return;

    base_graph_->setLineStyle(QCPGraph::lsNone);
    tracer_->setGraph(NULL);

    // base_graph_ is always visible.
    for (int i = 0; i < sp->graphCount(); i++) {
        sp->graph(i)->data()->clear();
        sp->graph(i)->setVisible(i == 0 ? true : false);
    }
    // also clear and hide ErrorBars plottables
    seg_eb_->setVisible(false);
    seg_eb_->data()->clear();
    sack_eb_->setVisible(false);
    sack_eb_->data()->clear();
    sack2_eb_->setVisible(false);
    sack2_eb_->data()->clear();

    base_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));

    sp->xAxis->setLabel(time_s_label_);
    sp->xAxis->setNumberFormat("gb");
    // Use enough precision to mark microseconds
    //    when zooming in on a <100s capture
    sp->xAxis->setNumberPrecision(8);
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
        // NOTE - adding both forward and reverse packets to time_stamp_map_
        //   so that both data and acks are selectable
        //   (this is important especially in selecting particular SACK pkts)
        bool insert = true;
        if (!compareHeaders(seg)) {
            bytes_rev += seg->th_seglen;
            pkts_rev++;
            // only insert reverse packets if SACK present
            insert = (seg->num_sack_ranges != 0);
        } else {
            bytes_fwd += seg->th_seglen;
            pkts_fwd++;
        }
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;
        if (first) {
            if (ts_origin_conn_) ts_offset_ = ts;
            if (seq_origin_zero_) {
                if (compareHeaders(seg))
                    seq_offset_ = seg->th_seq;
                else
                    seq_offset_ = seg->th_ack;
            }
            first = false;
        }
        if (insert) {
            time_stamp_map_.insert(ts - ts_offset_, seg);
        }
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
            .arg(gchar_free_to_qstring(format_size(pkts_fwd, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI)))
            .arg(gchar_free_to_qstring(format_size(bytes_fwd, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)))
            .arg(UTF8_LEFTWARDS_ARROW)
            .arg(gchar_free_to_qstring(format_size(pkts_rev, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI)))
            .arg(gchar_free_to_qstring(format_size(bytes_rev, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));
    mouseMoved(NULL);
    if (reset_axes)
        resetAxes();
    else
        sp->replot();
    // Throughput and Window Scale graphs can hide base_graph_
    if (base_graph_->visible())
        tracer_->setGraph(base_graph_);

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    if (set_focus)
        sp->setFocus();
}

void TCPStreamDialog::showWidgetsForGraphType()
{
    if (graph_.type == GRAPH_RTT) {
        ui->bySeqNumberCheckBox->setVisible(true);
    } else {
        ui->bySeqNumberCheckBox->setVisible(false);
    }
    if (graph_.type == GRAPH_THROUGHPUT) {
#ifdef MA_1_SECOND
        ui->maWindowSizeLabel->setVisible(true);
        ui->maWindowSizeSpinBox->setVisible(true);
#else
        ui->maWindowSizeLabel->setVisible(false);
        ui->maWindowSizeSpinBox->setVisible(false);
#endif
        ui->showSegLengthCheckBox->setVisible(true);
        ui->showThroughputCheckBox->setVisible(true);
        ui->showGoodputCheckBox->setVisible(true);
    } else {
        ui->maWindowSizeLabel->setVisible(false);
        ui->maWindowSizeSpinBox->setVisible(false);
        ui->showSegLengthCheckBox->setVisible(false);
        ui->showThroughputCheckBox->setVisible(false);
        ui->showGoodputCheckBox->setVisible(false);
    }

    if (graph_.type == GRAPH_TSEQ_TCPTRACE) {
        ui->selectSACKsCheckBox->setVisible(true);
    } else {
        ui->selectSACKsCheckBox->setVisible(false);
    }

    if (graph_.type == GRAPH_WSCALE) {
        ui->showRcvWinCheckBox->setVisible(true);
        ui->showBytesOutCheckBox->setVisible(true);
    } else {
        ui->showRcvWinCheckBox->setVisible(false);
        ui->showBytesOutCheckBox->setVisible(false);
    }
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

void TCPStreamDialog::zoomXAxis(bool in)
{
    QCustomPlot *sp = ui->streamPlot;
    double h_factor = sp->axisRect()->rangeZoomFactor(Qt::Horizontal);

    if (!in) {
        h_factor = pow(h_factor, -1);
    }

    sp->xAxis->scaleRange(h_factor, sp->xAxis->range().center());
    sp->replot();
}

void TCPStreamDialog::zoomYAxis(bool in)
{
    QCustomPlot *sp = ui->streamPlot;
    double v_factor = sp->axisRect()->rangeZoomFactor(Qt::Vertical);

    if (!in) {
        v_factor = pow(v_factor, -1);
    }

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
//    tput_graph_->rescaleValueAxis(false, true);
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

    bool allow_sack_select = ui->selectSACKsCheckBox->isChecked();

    QCustomPlot *sp = ui->streamPlot;
    sp->yAxis->setLabel(sequence_number_label_);

    base_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDot));

    seg_graph_->setVisible(true);
    seg_eb_->setVisible(true);
    ack_graph_->setVisible(true);
    sack_graph_->setVisible(true);
    sack_eb_->setVisible(true);
    sack2_graph_->setVisible(true);
    sack2_eb_->setVisible(true);
    rwin_graph_->setVisible(true);
    dup_ack_graph_->setVisible(true);
    zero_win_graph_->setVisible(true);

    QVector<double> pkt_time, pkt_seqnums;
    QVector<double> sb_time, sb_center, sb_span;
    QVector<double> ackrwin_time, ack, rwin;
    QVector<double> sack_time, sack_center, sack_span;
    QVector<double> sack2_time, sack2_center, sack2_span;
    QVector<double> dup_ack_time, dup_ack;
    QVector<double> zero_win_time, zero_win;

    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        double ts = (seg->rel_secs + seg->rel_usecs / 1000000.0) - ts_offset_;
        if (compareHeaders(seg)) {
            double half = seg->th_seglen / 2.0;
            double center = seg->th_seq - seq_offset_ + half;

            // Add forward direction to base_graph_ (to select data packets)
            // Forward direction: seq + data
            pkt_time.append(ts);
            pkt_seqnums.append(center);

            // QCP doesn't have a segment graph type. For now, fake
            // it with error bars.
            if (seg->th_seglen > 0) {
                sb_time.append(ts);
                sb_center.append(center);
                sb_span.append(half);
            }

            // Look for zero window sizes.
            // Should match the TCP_A_ZERO_WINDOW test in packet-tcp.c.
            if (seg->th_win == 0 && (seg->th_flags & (TH_RST|TH_FIN|TH_SYN)) == 0) {
                zero_win_time.append(ts);
                zero_win.append(center);
            }
        } else {
            // Reverse direction: ACK + RWIN
            if (! (seg->th_flags & TH_ACK)) {
                // SYNs and RSTs do not necessarily have ACKs
                continue;
            }
            double ackno = seg->th_ack - seq_offset_;
            // add SACK segments to sack, sack2, and selectable packet graph
            for (int i = 0; i < seg->num_sack_ranges; ++i) {
                double half = seg->sack_right_edge[i] - seg->sack_left_edge[i];
                half = half/2.0;
                double center = seg->sack_left_edge[i] - seq_offset_ + half;
                if (i == 0) {
                    sack_time.append(ts);
                    sack_center.append(center);
                    sack_span.append(half);
                    if (allow_sack_select) {
                        pkt_time.append(ts);
                        pkt_seqnums.append(center);
                    }
                } else {
                    sack2_time.append(ts);
                    sack2_center.append(center);
                    sack2_span.append(half);
                }
            }
            // If ackno is the same as our last one mark it as a duplicate.
            //   (but don't mark window updates as duplicate acks)
            if (ack.size() > 0 && ack.last() == ackno
                  && rwin.last() == ackno + seg->th_win) {
                dup_ack_time.append(ts);
                dup_ack.append(ackno);
            }
            // Also add reverse packets to the ack_graph_
            ackrwin_time.append(ts);
            ack.append(ackno);
            rwin.append(ackno + seg->th_win);
        }
    }
    base_graph_->setData(pkt_time, pkt_seqnums, true);
    ack_graph_->setData(ackrwin_time, ack, true);
    seg_graph_->setData(sb_time, sb_center, true);
    seg_eb_->setData(sb_span);
    sack_graph_->setData(sack_time, sack_center, true);
    sack_eb_->setData(sack_span);
    sack2_graph_->setData(sack2_time, sack2_center, true);
    sack2_eb_->setData(sack2_span);
    rwin_graph_->setData(ackrwin_time, rwin, true);
    dup_ack_graph_->setData(dup_ack_time, dup_ack, true);
    zero_win_graph_->setData(zero_win_time, zero_win, true);
}

// If the current implementation of incorporating SACKs in goodput calc
//   is slow, comment out the following line to ignore SACKs in goodput calc.
#define USE_SACKS_IN_GOODPUT_CALC

#ifdef USE_SACKS_IN_GOODPUT_CALC
// to incorporate SACKED segments into goodput calculation,
//   need to keep track of all the SACK blocks we haven't yet
//   fully ACKed.
// I expect this to be _relatively_ small, so using vector to store
//   them.  If this performs badly, it can be refactored with std::list
//   or std::map.
typedef std::pair<guint32, guint32> sack_t;
typedef std::vector<sack_t> sack_list_t;
static inline bool compare_sack(const sack_t& s1, const sack_t& s2) {
    return tcp_seq_before(s1.first, s2.first);
}

// Helper function to adjust an acked seglen for goodput:
//   - removes previously sacked ranges from seglen (and from old_sacks),
//   - adds newly sacked ranges to seglen (and to old_sacks)
static void
goodput_adjust_for_sacks(guint32 *seglen, guint32 last_ack,
                         sack_list_t& new_sacks, guint8 num_sack_ranges,
                         sack_list_t& old_sacks) {

    // Step 1 - For any old_sacks acked by last_ack,
    //   delete their acked length from seglen,
    //   and remove the sack block (or portion)
    //   from (sorted) old_sacks.
    sack_list_t::iterator unacked = old_sacks.begin();
    while (unacked != old_sacks.end()) {
        // break on first sack not fully acked
        if (tcp_seq_before(last_ack, unacked->second)) {
            if (tcp_seq_after(last_ack, unacked->first)) {
                // partially acked - modify to remove acked part
                *seglen -= (last_ack - unacked->first);
                unacked->first = last_ack;
            }
            break;
        }
        // remove fully acked sacks from seglen and move on
        //   (we'll actually remove from the list when loop is done)
        *seglen -= (unacked->second - unacked->first);
        ++unacked;
    }
    // actually remove all fully acked sacks from old_sacks list
    if (unacked != old_sacks.begin())
        old_sacks.erase(old_sacks.begin(), unacked);

    // Step 2 - for any new_sacks that precede last_ack,
    //   ignore them. (These would generally be SACKed dup-acks of
    //   a retransmitted seg).
    //   [ in the unlikely case that any new SACK straddles last_ack,
    //       the sack block will be modified to remove the acked portion ]
    int next_new_idx = 0;
    while (next_new_idx < num_sack_ranges) {
        if (tcp_seq_before(last_ack, new_sacks[next_new_idx].second)) {
            // if a new SACK block is unacked by its own packet, then it's
            //   likely fully unacked, but let's check for partial ack anyway,
            //   and truncate the SACK so that it's fully unacked:
            if (tcp_seq_before(new_sacks[next_new_idx].first, last_ack))
                new_sacks[next_new_idx].first = last_ack;
            break;
        }
        ++next_new_idx;
    }

    // Step 3 - for any byte ranges in remaining new_sacks
    //   that don't already exist in old_sacks, add
    //   their length to seglen
    //   and add that range (by extension, if possible) to
    //   the list of old_sacks.

    sack_list_t::iterator next_old = old_sacks.begin();

    while (next_new_idx < num_sack_ranges &&
           next_old != old_sacks.end()) {
        sack_t* next_new = &new_sacks[next_new_idx];

        // Assumptions / Invariants:
        //  - new and old lists are sorted
        //  - span of leftmost to rightmost endpt. is less than half uint32 range
        //      [ensures transitivity - e.g. before(a,b) and before(b,c) ==> before(a,c)]
        //  - all SACKs are non-empty (sack.left before sack.right)
        //  - adjacent SACKs in list always have a gap between them
        //      (sack.right before next_sack.left)

        // Given these assumptions, and noting that there are only three
        //   possible comparisons for a pair of points (before/equal/after),
        //   there are only a few possible relative configurations
        //   of next_old and next_new:
        // next_new:
        //                         [-------------)
        // next_old:
        //  1.             [---)
        //  2.             [-------)
        //  3.             [----------------)
        //  4.             [---------------------)
        //  5.             [----------------------------)
        //  6.                     [--------)
        //  7.                     [-------------)
        //  8.                     [--------------------)
        //  9.                          [---)
        // 10.                          [--------)
        // 11.                          [---------------)
        // 12.                                   [------)
        // 13.                                       [--)

        // Case 1: end of next_old is before beginning of next_new
        // next_new:
        //                         [-------------) ... <end>
        // next_old:
        //  1.             [---) ... <end>
        if (tcp_seq_before(next_old->second, next_new->first)) {
            // Actions:
            //   advance to the next sack in old_sacks
            ++next_old;
            //   retry from the top
            continue;
        }

        // Case 13: end of next_new is before beginning of next_old
        // next_new:
        //                         [-------------)   ... <end>
        // next_old:
        // 13.                                       [--) ... <end>
        if (tcp_seq_before(next_new->second, next_old->first)) {
            // Actions:
            //   add then entire length of next_new into seglen
            *seglen += (next_new->second - next_new->first);
            //   insert next_new before next_old in old_sacks
            // (be sure to save and restore next_old iterator around insert!)
            int next_old_idx = int(next_old - old_sacks.begin());
            old_sacks.insert(next_old, *next_new);
            next_old = old_sacks.begin() + next_old_idx + 1;
            //   advance to the next remaining sack in new_sacks
            ++next_new_idx;
            //   retry from the top
            continue;
        }

        // Remaining possible configurations:
        // next_new:
        //                         [-------------)
        // next_old:
        //  2.             [-------)
        //  3.             [----------------)
        //  4.             [---------------------)
        //  5.             [----------------------------)
        //  6.                     [--------)
        //  7.                     [-------------)
        //  8.                     [--------------------)
        //  9.                          [---)
        // 10.                          [--------)
        // 11.                          [---------------)
        // 12.                                   [------)

        // Cases 2,3,6,9: end of next_old is before end of next_new
        // next_new:
        //                         [-------------)
        // next_old:
        //  2.             [-------)
        //  3.             [----------------)
        //  6.                     [--------)
        //  9.                          [---)
        // Actions:
        //   until end of next_old is equal or after end of next_new,
        //     repeatedly extend next_old, coalescing with next_next_old
        //     if necessary.  (and add extended bytes to seglen)
        while (tcp_seq_before(next_old->second, next_new->second)) {
            // if end of next_new doesn't collide with start of next_next_old,
            if (((next_old+1) == old_sacks.end()) ||
                tcp_seq_before(next_new->second, (next_old + 1)->first)) {
                // extend end of next_old up to end of next_new,
                // adding extended bytes to seglen
                *seglen += (next_new->second - next_old->second);
                next_old->second = next_new->second;
            }
            // otherwise, coalesce next_old with next_next_old
            else {
                // add bytes to close gap between sacks to seglen
                *seglen += ((next_old + 1)->first - next_old->second);
                // coalesce next_next_old into next_old
                next_old->second = (next_old + 1)->second;
                old_sacks.erase(next_old + 1);
            }
        }
        // This operation turns:
        //   Cases 2 and 3 into Case 4 or 5
        //   Case 6 into Case 7
        //   Case 9 into Case 10
        // Leaving:

        // Remaining possible configurations:
        // next_new:
        //                         [-------------)
        // next_old:
        //  4.             [---------------------)
        //  5.             [----------------------------)
        //  7.                     [-------------)
        //  8.                     [--------------------)
        // 10.                          [--------)
        // 11.                          [---------------)
        // 12.                                   [------)

        // Cases 10,11,12: start of next_new is before start of next_old
        // next_new:
        //                         [-------------)
        // next_old:
        // 10.                          [--------)
        // 11.                          [---------------)
        // 12.                                   [------)
        if (tcp_seq_before(next_new->first, next_old->first)) {
            // Actions:
            //   add the unaccounted bytes in next_new to seglen
            *seglen += (next_old->first - next_new->first);
            //   then pull the start of next_old back to the start of next_new
            next_old->first = next_new->first;
        }
        // This operation turns:
        //   Case 10 into Case 7
        //   Cases 11 and 12 into Case 8
        // Leaving:

        // Remaining possible configurations:
        // next_new:
        //                         [-------------)
        // next_old:
        //  4.             [---------------------)
        //  5.             [----------------------------)
        //  7.                     [-------------)
        //  8.                     [--------------------)

        // In these cases, the bytes in next_new are fully accounted
        //   by the bytes in next_old, so we can move on to look at
        //   the next sack block in new_sacks
        ++next_new_idx;
    }
    // Conditions for leaving loop:
    //   - we processed all remaining new_sacks - nothing left to do
    //     (next_new_idx == num_sack_ranges)
    //  OR
    //   - all remaining new_sacks start at least one byte after
    //       the rightmost edge of the last old_sack
    //     (meaning we can just add the remaining new_sacks to old_sacks list,
    //      and add them directly to the goodput seglen)
    while (next_new_idx < num_sack_ranges) {
        sack_t* next_new = &new_sacks[next_new_idx];
        *seglen += (next_new->second - next_new->first);
        old_sacks.push_back(*next_new);
        ++next_new_idx;
    }
}
#endif // USE_SACKS_IN_GOODPUT_CALC

void TCPStreamDialog::fillThroughput()
{
    QString dlg_title = QString(tr("Throughput")) + streamDescription();
#ifdef MA_1_SECOND
    dlg_title.append(tr(" (MA)"));
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

    base_graph_->setVisible(ui->showSegLengthCheckBox->isChecked());
    tput_graph_->setVisible(ui->showThroughputCheckBox->isChecked());
    goodput_graph_->setVisible(ui->showGoodputCheckBox->isChecked());

#ifdef MA_1_SECOND
    if (!graph_.segments) {
#else
    if (!graph_.segments || !graph_.segments->next) {
#endif
        dlg_title.append(tr(" [not enough data]"));
        return;
    }

    QVector<double> seg_rel_times, ack_rel_times;
    QVector<double> seg_lens, ack_lens;
    QVector<double> tput_times, gput_times;
    QVector<double> tputs, gputs;
    int oldest_seg = 0, oldest_ack = 0;
    guint64 seg_sum = 0, ack_sum = 0;
    guint32 seglen = 0;

#ifdef USE_SACKS_IN_GOODPUT_CALC
    // to incorporate SACKED segments into goodput calculation,
    //   need to keep track of all the SACK blocks we haven't yet
    //   fully ACKed.
    sack_list_t old_sacks, new_sacks;
    new_sacks.reserve(MAX_TCP_SACK_RANGES);
    // statically allocate current_sacks vector
    //   [ std::array might be better, but that is C++11 ]
    for (int i = 0; i < MAX_TCP_SACK_RANGES; ++i) {
        new_sacks.push_back(sack_t(0,0));
    }
    old_sacks.reserve(2*MAX_TCP_SACK_RANGES);
#endif // USE_SACKS_IN_GOODPUT_CALC

    // need first acked sequence number to jump-start
    //    computation of acked bytes per packet
    guint32 last_ack = 0;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        // first reverse packet with ACK flag tells us first acked sequence #
        if (!compareHeaders(seg) && (seg->th_flags & TH_ACK)) {
            last_ack = seg->th_ack;
            break;
        }
    }
    // Financial charts don't show MA data until a full period has elapsed.
    //  [ NOTE - this is because they assume that there's old data that they
    //      don't have access to - but in our case we know that there's NO
    //      data prior to the first packet in the stream - so it's fine to
    //      spit out the MA immediately... ]
    // The Rosetta Code MA examples start spitting out values immediately.
    // For now use not-really-correct initial values just to keep our vector
    // lengths the same.
#ifdef MA_1_SECOND
    // NOTE that for the time-based MA case, you certainly can start with the
    //  first segment!
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
#else
    for (struct segment *seg = graph_.segments->next; seg != NULL; seg = seg->next) {
#endif
        bool is_forward_seg = compareHeaders(seg);
        QVector<double>& r_pkt_times = is_forward_seg ? seg_rel_times : ack_rel_times;
        QVector<double>& r_lens = is_forward_seg ? seg_lens : ack_lens;
        QVector<double>& r_Xput_times = is_forward_seg ? tput_times : gput_times;
        QVector<double>& r_Xputs = is_forward_seg ? tputs : gputs;
        int& r_oldest = is_forward_seg ? oldest_seg : oldest_ack;
        guint64& r_sum = is_forward_seg ? seg_sum : ack_sum;

        double ts = (seg->rel_secs + seg->rel_usecs / 1000000.0) - ts_offset_;

        if (is_forward_seg) {
            seglen = seg->th_seglen;
        } else {
            if ((seg->th_flags & TH_ACK) &&
                tcp_seq_eq_or_after(seg->th_ack, last_ack)) {
                seglen = seg->th_ack - last_ack;
                last_ack = seg->th_ack;
#ifdef USE_SACKS_IN_GOODPUT_CALC
                // copy any sack_ranges into new_sacks, and sort.
                for (int i = 0; i < seg->num_sack_ranges; ++i) {
                    new_sacks[i].first = seg->sack_left_edge[i];
                    new_sacks[i].second = seg->sack_right_edge[i];
                }
                std::sort(new_sacks.begin(),
                          new_sacks.begin() + seg->num_sack_ranges,
                          compare_sack);

                // adjust the seglen based on new and old sacks,
                //   and update the old_sacks list
                goodput_adjust_for_sacks(&seglen, last_ack,
                                         new_sacks, seg->num_sack_ranges,
                                         old_sacks);
#endif // USE_SACKS_IN_GOODPUT_CALC
            } else {
                seglen = 0;
            }
        }

        r_pkt_times.append(ts);
        r_lens.append(seglen);

#ifdef MA_1_SECOND
        while (r_oldest < r_pkt_times.size() && ts - r_pkt_times[r_oldest] > ma_window_size_) {
            r_sum -= r_lens[r_oldest];
            // append points where a packet LEAVES the MA window
            //   (as well as, below, where they ENTER the MA window)
            r_Xputs.append(r_sum * 8.0 / ma_window_size_);
            r_Xput_times.append(r_pkt_times[r_oldest] + ma_window_size_);
            r_oldest++;
        }
#else
        if (r_lens.size() > moving_avg_period_) {
            r_sum -= r_lens[r_oldest];
            r_oldest++;
        }
#endif

        // av_Xput computes Xput, i.e.:
        //    throughput for forward packets
        //    goodput for reverse packets
        double av_Xput;
        r_sum += seglen;
#ifdef MA_1_SECOND
        // for time-based MA, delta_t is constant
        av_Xput = r_sum * 8.0 / ma_window_size_;
#else
        double dtime = 0.0;
        if (r_oldest > 0)
            dtime = ts - r_pkt_times[r_oldest-1];
        if (dtime > 0.0) {
            av_Xput = r_sum * 8.0 / dtime;
        } else {
            av_Xput = 0.0;
        }
#endif

        // Add a data point only if our time window has advanced. Otherwise
        // update the most recent point. (We might want to show a warning
        // for out-of-order packets.)
        if (r_Xput_times.size() > 0 && ts <= r_Xput_times.last()) {
            r_Xputs[r_Xputs.size() - 1] = av_Xput;
        } else {
            r_Xputs.append(av_Xput);
            r_Xput_times.append(ts);
        }
    }
    base_graph_->setData(seg_rel_times, seg_lens);
    tput_graph_->setData(tput_times, tputs);
    goodput_graph_->setData(gput_times, gputs);
}

// rtt_selectively_ack_range:
//    "Helper" function for fillRoundTripTime
//    given an rtt_unack list, two pointers to a range of segments in the list,
//    and the [left,right) edges of a SACK block, selectively ACKs the range
//    from "begin" to "end" - possibly splitting one segment in the range
//    into two (and relinking the new segment in order after the first)
//
// Assumptions:
//    "begin must be non-NULL
//    "begin" must precede "end" (or "end" must be NULL)
//    [ there are minor optimizations that could be added if
//        the range from "begin" to "end" are in sequence number order.
//        (this function would preserve that as an invariant). ]
static struct rtt_unack *
rtt_selectively_ack_range(QVector<double>& x_vals, bool bySeqNumber,
                    QVector<double>& rtt,
                    struct rtt_unack **list,
                    struct rtt_unack *begin, struct rtt_unack *end,
                    unsigned int left, unsigned int right, double rt_val) {
    struct rtt_unack *cur, *next;
    // sanity check:
    if (tcp_seq_eq_or_after(left, right))
        return begin;
    // real work:
    for (cur = begin; cur != end; cur = next) {
        next = cur->next;
        // check #1: does [left,right) intersect current unack at all?
        //   (if not, we can just move on to the next unack)
        if (tcp_seq_eq_or_after(cur->seqno, right) ||
            tcp_seq_eq_or_after(left, cur->end_seqno)) {
            // no intersection - just skip this.
            continue;
        }
        // yes, we intersect!
        int left_end_acked = tcp_seq_eq_or_after(cur->seqno, left);
        int right_end_acked = tcp_seq_eq_or_after(right, cur->end_seqno);
        // check #2 - did we fully ack the current unack?
        //   (if so, we can delete it and move on)
        if (left_end_acked && right_end_acked) {
            // ACK the whole segment
            if (bySeqNumber) {
                x_vals.append(cur->seqno);
            } else {
                x_vals.append(cur->time);
            }
            rtt.append((rt_val - cur->time) * 1000.0);
            // in this case, we will delete current unack
            // [ update "begin" if necessary - we will return it to the
            //     caller to let them know we deleted it ]
            if (cur == begin)
                begin = next;
             rtt_delete_unack_from_list(list, cur);
             continue;
        }
        // check #3 - did we ACK the left-hand side of the current unack?
        //   (if so, we can just modify it and move on)
        if (left_end_acked) { // and right_end_not_acked
            // ACK the left end
            if (bySeqNumber) {
                x_vals.append(cur->seqno);
            } else {
                x_vals.append(cur->time);
            }
            rtt.append((rt_val - cur->time) * 1000.0);
            // in this case, "right" marks the start of remaining bytes
            cur->seqno = right;
            continue;
        }
        // check #4 - did we ACK the right-hand side of the current unack?
        //   (if so, we can just modify it and move on)
        if (right_end_acked) { // and left_end_not_acked
            // ACK the right end
            if (bySeqNumber) {
                x_vals.append(left);
            } else {
                x_vals.append(cur->time);
            }
            rtt.append((rt_val - cur->time) * 1000.0);
            // in this case, "left" is just beyond the remaining bytes
            cur->end_seqno = left;
            continue;
        }
        // at this point, we know:
        //   - the SACK block does intersect this unack, but
        //   - it does not intersect the left or right endpoints
        // Therefore, it must intersect the middle, so we must split the unack
        //   into left and right unacked segments:
        // ACK the SACK block
        if (bySeqNumber) {
            x_vals.append(left);
        } else {
            x_vals.append(cur->time);
        }
        rtt.append((rt_val - cur->time) * 1000.0);
        // then split cur into two unacked segments
        //   (linking the right-hand unack after the left)
        cur->next = rtt_get_new_unack(cur->time, right, cur->end_seqno - right);
        cur->next->next = next;
        cur->end_seqno = left;
    }
    return begin;
}

void TCPStreamDialog::fillRoundTripTime()
{
    QString dlg_title = QString(tr("Round Trip Time")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    bool bySeqNumber = ui->bySeqNumberCheckBox->isChecked();

    if (bySeqNumber) {
        sequence_num_map_.clear();
        sp->xAxis->setLabel(sequence_number_label_);
        sp->xAxis->setNumberFormat("f");
        sp->xAxis->setNumberPrecision(0);
    }
    sp->yAxis->setLabel(round_trip_time_ms_label_);
    sp->yAxis->setNumberFormat("gb");
    sp->yAxis->setNumberPrecision(3);

    base_graph_->setLineStyle(QCPGraph::lsLine);

    QVector<double> x_vals, rtt;
    guint32 seq_base = 0;
    struct rtt_unack *unack_list = NULL, *u = NULL;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (compareHeaders(seg)) {
            seq_base = seg->th_seq;
            break;
        }
    }
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (compareHeaders(seg)) {
            guint32 seqno = seg->th_seq - seq_base;
            if (seg->th_seglen && !rtt_is_retrans(unack_list, seqno)) {
                double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
                rt_val -= ts_offset_;
                u = rtt_get_new_unack(rt_val, seqno, seg->th_seglen);
                if (!u) {
                    // make sure to free list before returning!
                    rtt_destroy_unack_list(&unack_list);
                    return;
                }
                rtt_put_unack_on_list(&unack_list, u);
            }
        } else {
            guint32 ack_no = seg->th_ack - seq_base;
            double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
            rt_val -= ts_offset_;
            struct rtt_unack *v;

            for (u = unack_list; u; u = v) {
                if (tcp_seq_after(ack_no, u->seqno)) {
                    // full or partial ack of seg by ack_no
                    if (bySeqNumber) {
                        x_vals.append(u->seqno);
                        sequence_num_map_.insert(u->seqno, seg);
                    } else {
                        x_vals.append(u->time);
                    }
                    rtt.append((rt_val - u->time) * 1000.0);
                    if (tcp_seq_eq_or_after(ack_no, u->end_seqno)) {
                        // fully acked segment - nothing more to see here
                        v = u->next;
                        rtt_delete_unack_from_list(&unack_list, u);
                        // no need to compare SACK blocks for fully ACKed seg
                        continue;
                    } else {
                        // partial ack of GSO seg
                        u->seqno = ack_no;
                        // (keep going - still need to compare SACK blocks...)
                    }
                }
                v = u->next;
                // selectively acking u more than once
                //   can shatter it into multiple intervals.
                //   If we link those back into the list between u and v,
                //   then each subsequent SACK selectively ACKs that range.
                for (int i = 0; i < seg->num_sack_ranges; ++i) {
                    guint32 left = seg->sack_left_edge[i] - seq_base;
                    guint32 right = seg->sack_right_edge[i] - seq_base;
                    u = rtt_selectively_ack_range(x_vals, bySeqNumber, rtt,
                                                  &unack_list, u, v,
                                                  left, right, rt_val);
                    // if range is empty after selective ack, we can
                    //   skip the rest of the SACK blocks
                    if (u == v) break;
                }
            }
        }
    }
    // it's possible there's still unacked segs - so be sure to free list!
    rtt_destroy_unack_list(&unack_list);
    base_graph_->setData(x_vals, rtt);
}

void TCPStreamDialog::fillWindowScale()
{
    QString dlg_title = QString(tr("Window Scaling")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    // use base_graph_ to represent unacked window size
    //  (estimate of congestion window)
    base_graph_->setLineStyle(QCPGraph::lsStepLeft);
    // use rwin_graph_ here to show rwin window scale
    //  (derived from ACK packets)
    base_graph_->setVisible(ui->showBytesOutCheckBox->isChecked());
    rwin_graph_->setVisible(ui->showRcvWinCheckBox->isChecked());

    QVector<double> rel_time, win_size;
    QVector<double> cwnd_time, cwnd_size;
    guint32 last_ack = 0;
    bool found_first_ack = false;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;

        // The receive window that applies to this flow comes
        //   from packets in the opposite direction
        if (compareHeaders(seg)) {
            // compute bytes_in_flight for cwnd graph
            guint32 end_seq = seg->th_seq + seg->th_seglen;
            if (found_first_ack &&
                tcp_seq_eq_or_after(end_seq, last_ack)) {
                cwnd_time.append(ts - ts_offset_);
                cwnd_size.append((double)(end_seq - last_ack));
            }
        } else {
            // packet in opposite direction - has advertised rwin
            guint16 flags = seg->th_flags;

            if ((flags & (TH_SYN|TH_RST)) == 0) {
                rel_time.append(ts - ts_offset_);
                win_size.append(seg->th_win);
            }
            if ((flags & (TH_ACK)) != 0) {
                // use this to update last_ack
                if (!found_first_ack ||
                    tcp_seq_eq_or_after(seg->th_ack, last_ack)) {
                    last_ack = seg->th_ack;
                    found_first_ack = true;
                }
            }
        }
    }
    base_graph_->setData(cwnd_time, cwnd_size);
    rwin_graph_->setData(rel_time, win_size);
    sp->yAxis->setLabel(window_size_label_);
}

QString TCPStreamDialog::streamDescription()
{
    QString description(tr(" for %1:%2 %3 %4:%5")
            .arg(address_to_qstring(&graph_.src_address))
            .arg(graph_.src_port)
            .arg(UTF8_RIGHTWARDS_ARROW)
            .arg(address_to_qstring(&graph_.dst_address))
            .arg(graph_.dst_port));
    return description;
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

    QCustomPlot *sp = ui->streamPlot;
    QRect zr = zoom_rect.normalized();

    if (zr.width() < min_zoom_pixels_ && zr.height() < min_zoom_pixels_) {
        return zoom_ranges;
    }

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

    // mouse press on graph should reset focus to graph
    sp->setFocus();

    if (event->button() == Qt::RightButton) {
        // XXX We should find some way to get streamPlot to handle a
        // contextMenuEvent instead.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        ctx_menu_.popup(event->globalPosition().toPoint());
#else
        ctx_menu_.popup(event->globalPos());
#endif
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

void TCPStreamDialog::axisClicked(QCPAxis *axis, QCPAxis::SelectablePart, QMouseEvent *)
{
    QCustomPlot *sp = ui->streamPlot;

    if (axis == sp->xAxis) {
        switch (graph_.type) {
        case GRAPH_THROUGHPUT:
        case GRAPH_TSEQ_STEVENS:
        case GRAPH_TSEQ_TCPTRACE:
        case GRAPH_WSCALE:
        case GRAPH_RTT:
            ts_origin_conn_ = ts_origin_conn_ ? false : true;
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
                if (ui->bySeqNumberCheckBox->isChecked())
                    packet_seg = sequence_num_map_.value(tr_key, NULL);
                else
                    packet_seg = time_stamp_map_.value(tr_key, NULL);
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
    if (rubber_band_ && rubber_band_->isVisible()) {
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

// XXX - We have similar code in io_graph_dialog and packet_diagram. Should this be a common routine?
void TCPStreamDialog::on_buttonBox_accepted()
{
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

    file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Graph As…")),
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
            mainApp->setLastOpenDirFromFilename(file_name);
        }
    }
}

void TCPStreamDialog::on_graphTypeComboBox_currentIndexChanged(int index)
{
    if (index < 0) return;
    graph_.type = static_cast<tcp_graph_type>(ui->graphTypeComboBox->itemData(index).toInt());
    showWidgetsForGraphType();

    fillGraph(/*reset_axes=*/true, /*set_focus=*/false);
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

void TCPStreamDialog::updateGraph()
{
    graph_updater_.doUpdate();
}

void TCPStreamDialog::on_streamNumberSpinBox_valueChanged(int new_stream)
{
    if (new_stream >= 0 && new_stream < int(get_tcp_stream_count())) {
        graph_updater_.triggerUpdate(1000, /*reset_axes =*/true);
    }
}

void TCPStreamDialog::on_streamNumberSpinBox_editingFinished()
{
    updateGraph();
}

void TCPStreamDialog::on_maWindowSizeSpinBox_valueChanged(double new_ma_size)
{
    if (new_ma_size > 0.0) {
        ma_window_size_ = new_ma_size;
        graph_updater_.triggerUpdate(1000, /*reset_axes =*/false);
    }
}

void TCPStreamDialog::on_maWindowSizeSpinBox_editingFinished()
{
    updateGraph();
}

void TCPStreamDialog::on_selectSACKsCheckBox_stateChanged(int /* state */)
{
    fillGraph(/*reset_axes=*/false, /*set_focus=*/false);
}

void TCPStreamDialog::on_otherDirectionButton_clicked()
{
    on_actionSwitchDirection_triggered();
}

void TCPStreamDialog::on_dragRadioButton_toggled(bool checked)
{
    if (checked) {
        mouse_drags_ = true;
        if (rubber_band_ && rubber_band_->isVisible())
            rubber_band_->hide();
        ui->streamPlot->setInteractions(
                    QCP::iRangeDrag |
                    QCP::iRangeZoom
                    );
    }
}

void TCPStreamDialog::on_zoomRadioButton_toggled(bool checked)
{
    if (checked) {
        mouse_drags_ = false;
        ui->streamPlot->setInteractions(QCP::Interactions());
    }
}

void TCPStreamDialog::on_bySeqNumberCheckBox_stateChanged(int /* state */)
{
    fillGraph(/*reset_axes=*/true, /*set_focus=*/false);
}

void TCPStreamDialog::on_showSegLengthCheckBox_stateChanged(int state)
{
    bool visible = (state != 0);
    if (graph_.type == GRAPH_THROUGHPUT && base_graph_ != NULL) {
        base_graph_->setVisible(visible);
        tracer_->setGraph(visible ? base_graph_ : NULL);
        ui->streamPlot->replot();
    }
}

void TCPStreamDialog::on_showThroughputCheckBox_stateChanged(int state)
{
    bool visible = (state != 0);
    if (graph_.type == GRAPH_THROUGHPUT && tput_graph_ != NULL) {
        tput_graph_->setVisible(visible);
        ui->streamPlot->replot();
    }
}

void TCPStreamDialog::on_showGoodputCheckBox_stateChanged(int state)
{
    bool visible = (state != 0);
    if (graph_.type == GRAPH_THROUGHPUT && goodput_graph_ != NULL) {
        goodput_graph_->setVisible(visible);
        ui->streamPlot->replot();
    }
}

void TCPStreamDialog::on_showRcvWinCheckBox_stateChanged(int state)
{
    bool visible = (state != 0);
    if (graph_.type == GRAPH_WSCALE && rwin_graph_ != NULL) {
        rwin_graph_->setVisible(visible);
        ui->streamPlot->replot();
    }
}

void TCPStreamDialog::on_showBytesOutCheckBox_stateChanged(int state)
{
    bool visible = (state != 0);
    if (graph_.type == GRAPH_WSCALE && base_graph_ != NULL) {
        base_graph_->setVisible(visible);
        tracer_->setGraph(visible ? base_graph_ : NULL);
        ui->streamPlot->replot();
    }
}

void TCPStreamDialog::on_actionZoomIn_triggered()
{
    zoomAxes(true);
}

void TCPStreamDialog::on_actionZoomInX_triggered()
{
    zoomXAxis(true);
}

void TCPStreamDialog::on_actionZoomInY_triggered()
{
    zoomYAxis(true);
}

void TCPStreamDialog::on_actionZoomOut_triggered()
{
    zoomAxes(false);
}

void TCPStreamDialog::on_actionZoomOutX_triggered()
{
    zoomXAxis(false);
}

void TCPStreamDialog::on_actionZoomOutY_triggered()
{
    zoomYAxis(false);
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
        updateGraph();
    }
}

void TCPStreamDialog::on_actionPreviousStream_triggered()
{
    if (graph_.stream > 0) {
        ui->streamNumberSpinBox->setValue(graph_.stream - 1);
        updateGraph();
    }
}

void TCPStreamDialog::on_actionSwitchDirection_triggered()
{
    address tmp_addr;
    guint16 tmp_port;

    copy_address(&tmp_addr, &graph_.src_address);
    tmp_port = graph_.src_port;
    free_address(&graph_.src_address);
    copy_address(&graph_.src_address, &graph_.dst_address);
    graph_.src_port = graph_.dst_port;
    free_address(&graph_.dst_address);
    copy_address(&graph_.dst_address, &tmp_addr);
    graph_.dst_port = tmp_port;
    free_address(&tmp_addr);

    fillGraph(/*reset_axes=*/true, /*set_focus=*/false);
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

void TCPStreamDialog::GraphUpdater::triggerUpdate(int timeout, bool reset_axes)
{
    if (!hasPendingUpdate()) {
        graph_update_timer_ = new QTimer(dialog_);
        graph_update_timer_->setSingleShot(true);
        dialog_->connect(graph_update_timer_, SIGNAL(timeout()), dialog_, SLOT(updateGraph()));
    }
    reset_axes_ = (reset_axes_ || reset_axes);
    graph_update_timer_->start(timeout);
}

void TCPStreamDialog::GraphUpdater::clearPendingUpdate()
{
    if (hasPendingUpdate()) {
        if (graph_update_timer_->isActive())
            graph_update_timer_->stop();
        delete graph_update_timer_;
        graph_update_timer_ = NULL;
        reset_axes_ = false;
    }
}

void TCPStreamDialog::GraphUpdater::doUpdate()
{
    if (hasPendingUpdate()) {
        bool reset_axes = reset_axes_;
        clearPendingUpdate();
        // if the stream has changed, update the data here
        int new_stream = dialog_->ui->streamNumberSpinBox->value();
        if ((int(dialog_->graph_.stream) != new_stream) &&
            (new_stream >= 0 && new_stream < int(get_tcp_stream_count()))) {
            dialog_->graph_.stream = new_stream;
            dialog_->findStream();
        }
        dialog_->fillGraph(reset_axes, /*set_focus =*/false);
    }
}

void TCPStreamDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_TCP_STREAM_GRAPHS_DIALOG);
}
