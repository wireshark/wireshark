/* tcp_stream_dialog.cpp
 *
 * $Id$
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

#include "ui/utf8_entities.h"

#include "wireshark_application.h"
#include "tango_colors.h"

#include <QCursor>
#include <QDir>
#include <QFileDialog>
#include <QIcon>
#include <QPushButton>

#include <QDebug>

// The GTK+ version computes a 20 (or 21!) segment moving average. Comment
// out the line below to use that. By default we use a 1 second MA.
#define MA_1_SECOND

#ifndef MA_1_SECOND
const int moving_avg_period_ = 20;
#endif
const QRgb graph_color_1 = tango_sky_blue_5;
const QRgb graph_color_2 = tango_butter_6;

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const QString average_throughput_label_ = QObject::tr("Avgerage Througput (bits/s)");
const QString round_trip_time_ms_label_ = QObject::tr("Round Trip Time (ms)");
const QString segment_length_label_ = QObject::tr("Segment Length (B)");
const QString sequence_number_label_ = QObject::tr("Sequence Number (B)");
const QString time_s_label_ = QObject::tr("Time (s)");
const QString window_size_label_ = QObject::tr("Window Size (B)");

Q_DECLARE_METATYPE(tcp_graph_type)

TCPStreamDialog::TCPStreamDialog(QWidget *parent, capture_file *cf, tcp_graph_type graph_type) :
    QDialog(parent),
    ui(new Ui::TCPStreamDialog),
    cap_file_(cf),
    ts_origin_conn_(true),
    seq_origin_zero_(true),
    tracer_(NULL),
    mouse_drags_(true),
    rubber_band_(NULL),
    num_dsegs_(-1),
    num_acks_(-1),
    num_sack_ranges_(-1)
{
    struct segment current;

    ui->setupUi(this);

    struct tcpheader *header = select_tcpip_session(cap_file_, &current);
    if (!header) {
        done(QDialog::Rejected);
    }

//#ifdef Q_OS_MAC
//    ui->hintLabel->setAttribute(Qt::WA_MacSmallSize, true);
//#endif

    ui->graphTypeComboBox->setUpdatesEnabled(false);
    ui->graphTypeComboBox->addItem(tr("Time / Sequence (Stevens)"), qVariantFromValue(GRAPH_TSEQ_STEVENS));
    ui->graphTypeComboBox->addItem(tr("Throughput"), qVariantFromValue(GRAPH_THROUGHPUT));
    ui->graphTypeComboBox->addItem(tr("Round Trip Time"), qVariantFromValue(GRAPH_RTT));
    ui->graphTypeComboBox->addItem(tr("Window Scaling"), qVariantFromValue(GRAPH_WSCALE));
    ui->graphTypeComboBox->setCurrentIndex(-1);
    ui->graphTypeComboBox->setUpdatesEnabled(true);

    ui->mouseHorizontalLayout->setContentsMargins(0, 0, 0, 0);
    ui->dragToolButton->setChecked(mouse_drags_);

    memset (&graph_, 0, sizeof(graph_));
    graph_.type = graph_type;
    COPY_ADDRESS(&graph_.src_address, &current.ip_src);
    graph_.src_port = current.th_sport;
    COPY_ADDRESS(&graph_.dst_address, &current.ip_dst);
    graph_.dst_port = current.th_dport;
    graph_.stream = header->th_stream;

    QCustomPlot *sp = ui->streamPlot;
    QCPPlotTitle *file_title = new QCPPlotTitle(sp, cf_get_display_name(cap_file_));
    file_title->setFont(sp->xAxis->labelFont());
    title_ = new QCPPlotTitle(sp);
    tracer_ = new QCPItemTracer(sp);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, file_title);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, title_);
    sp->addGraph(); // 0 - All: Selectable segments
    sp->addGraph(sp->xAxis, sp->yAxis2); // 1 - Throughput: Moving average
    sp->addItem(tracer_);

    // Fills the graph
    ui->graphTypeComboBox->setCurrentIndex(ui->graphTypeComboBox->findData(qVariantFromValue(graph_type)));

    sp->setMouseTracking(true);
    sp->graph(0)->setPen(QPen(QBrush(graph_color_1), 0.25));
    sp->graph(0)->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, 5));

    sp->yAxis->setLabelColor(QColor(graph_color_1));
    sp->yAxis->setTickLabelColor(QColor(graph_color_1));

    tracer_->setVisible(false);
    toggleTracerStyle(true);

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As..."));

    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    connect(sp, SIGNAL(axisClick(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)),
            this, SLOT(axisClicked(QCPAxis*,QCPAxis::SelectablePart,QMouseEvent*)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(transformYRange(QCPRange)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));

    mouseMoved(NULL);
}

TCPStreamDialog::~TCPStreamDialog()
{
    delete ui;
}

void TCPStreamDialog::showEvent(QShowEvent *event)
{
    Q_UNUSED(event)
    resetAxes();
}

void TCPStreamDialog::keyPressEvent(QKeyEvent *event)
{
    QCustomPlot *sp = ui->streamPlot;
    double h_factor = sp->axisRect()->rangeZoomFactor(Qt::Horizontal);
    double v_factor = sp->axisRect()->rangeZoomFactor(Qt::Vertical);
    bool scale_range = false;

    double h_pan = 0.0;
    double v_pan = 0.0;

    // XXX - This differs from the main window but matches other applications (e.g. Mozilla and Safari)
    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
    case Qt::Key_O:             // GTK+
        h_factor = pow(h_factor, -1);
        v_factor = pow(v_factor, -1);
        scale_range = true;
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
    case Qt::Key_I:             // GTK+
        scale_range = true;
        break;

    // XXX Use pixel sizes instead
    case Qt::Key_Right:
    case Qt::Key_L:
        h_pan = sp->xAxis->range().size() * 10.0 / sp->xAxis->axisRect()->width();
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        h_pan = sp->xAxis->range().size() * -10.0 / sp->xAxis->axisRect()->width();
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        v_pan = sp->yAxis->range().size() * 10.0 / sp->yAxis->axisRect()->height();
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        v_pan = sp->yAxis->range().size() * -10.0 / sp->yAxis->axisRect()->height();
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

    case Qt::Key_D:
        on_otherDirectionButton_clicked();
        break;
    case Qt::Key_G:
        if (tracer_->visible() && cap_file_ && packet_num_ > 0) {
            emit goToPacket(packet_num_);
        }
        break;
    case Qt::Key_S:
        seq_origin_zero_ = seq_origin_zero_ ? false : true;
        fillGraph();
        break;
    case Qt::Key_T:
        ts_origin_conn_ = ts_origin_conn_ ? false : true;
        fillGraph();
        break;
    case Qt::Key_Z:
        if (mouse_drags_) {
            ui->selectToolButton->toggle();
        } else {
            ui->dragToolButton->toggle();
        }
        break;

        // Alas, there is no Blade Runner-style Qt::Key_Enhance
    }

    if (scale_range) {
        sp->xAxis->scaleRange(h_factor, sp->xAxis->range().center());
        sp->yAxis->scaleRange(v_factor, sp->yAxis->range().center());
        sp->replot();
    }

    double pan_mul = event->modifiers() & Qt::ShiftModifier ? 0.1 : 1.0;

    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan) {
        sp->xAxis->moveRange(h_pan * pan_mul);
        sp->replot();
    }
    if (v_pan) {
        sp->yAxis->moveRange(v_pan * pan_mul);
        sp->replot();
    }
    QDialog::keyPressEvent(event);

    // GTK+ Shortcuts:
    // Left Mouse Button	selects segment under cursor in Wiresharks packet list
    // can also drag to zoom in on a rectangular region
    // Middle Mouse Button	zooms in (towards area under cursor)
    // <Shift>-Middle Mouse Button	zooms out

    // Right Mouse Button	moves the graph (if zoomed in)
    // <Ctrl>-Right Mouse Button	displays a portion of graph under cursor magnified

    // 1	display Round Trip Time Graph
    // 2	display Throughput Graph
    // 3	display Time/Sequence Graph (Stevens)
    // 4	display Time/Sequence Graph (tcptrace)
    // 5	display Window Scaling Graph

    // <Space bar>	toggles crosshairs on/off

    // i or +	zoom in (towards area under mouse pointer)
    // o or -	zoom out
    // r or <Home>	restore graph to initial state (zoom out max)
    // s	toggles relative/absolute sequence numbers
    // t	toggles time origin
    // g	go to frame under cursor in Wiresharks packet list (if possible)

    // <Left>	move view left by 100 pixels (if zoomed in)
    // <Right>	move view right 100 pixels (if zoomed in)
    // <Up>	move view up by 100 pixels (if zoomed in)
    // <Down>	move view down by 100 pixels (if zoomed in)

    // <Shift><Left>	move view left by 10 pixels (if zoomed in)
    // <Shift><Right>	move view right 10 pixels (if zoomed in)
    // <Shift><Up>	move view up by 10 pixels (if zoomed in)
    // <Shift><Down>	move view down by 10 pixels (if zoomed in)

    // <Ctrl><Left>	move view left by 1 pixel (if zoomed in)
    // <Ctrl><Right>	move view right 1 pixel (if zoomed in)
    // <Ctrl><Up>	move view up by 1 pixel (if zoomed in)
    // <Ctrl><Down>	move view down by 1 pixel (if zoomed in)

}

void TCPStreamDialog::mouseReleaseEvent(QMouseEvent *event)
{
    mouseReleased(event);
}

void TCPStreamDialog::fillGraph()
{
    QCustomPlot *sp = ui->streamPlot;

    if (sp->graphCount() < 1) return;

    time_stamp_map_.clear();
    sequence_num_map_.clear();
    graph_segment_list_free(&graph_);
    tracer_->setGraph(NULL);
    // We need at least one graph, so don't bother deleting the first one.
    for (int i = 0; i < sp->graphCount(); i++) {
        sp->graph(i)->clearData();
        sp->graph(i)->setVisible(i == 0 ? true : false);
    }

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

    // XXX graph_segment_list_get returns a different list for throughput
    // graphs. If the throughput list used the same list we could call this
    // above in our ctor.
    graph_segment_list_get(cap_file_, &graph_, TRUE);
    ts_offset_ = 0;
    seq_offset_ = 0;
    bool first = true;

    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }
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

    resetAxes();
    tracer_->setGraph(sp->graph(0));
}

void TCPStreamDialog::resetAxes()
{
    QCustomPlot *sp = ui->streamPlot;

    y_axis_xfrm_.reset();
    double pixel_pad = 10.0; // per side

    sp->graph(0)->rescaleAxes(false, true);
    for (int i = 1; i < sp->graphCount(); i++) {
        sp->graph(i)->rescaleValueAxis(false, true);
    }

    double axis_pixels = sp->xAxis->axisRect()->width();
    sp->xAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, sp->xAxis->range().center());

    axis_pixels = sp->yAxis->axisRect()->height();
    sp->yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, sp->yAxis->range().center());

    if (sp->graph(1)->visible()) {
        axis_pixels = sp->yAxis2->axisRect()->height();
        sp->yAxis2->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, sp->yAxis2->range().center());

        double ratio = sp->yAxis2->range().size() / sp->yAxis->range().size();
        y_axis_xfrm_.translate(0.0, sp->yAxis2->range().lower - (sp->yAxis->range().lower * ratio));
        y_axis_xfrm_.scale(1.0, ratio);
    }

    sp->replot();
}

void TCPStreamDialog::fillStevens()
{
    QString dlg_title = QString(tr("Sequence Numbers")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->yAxis->setLabel(sequence_number_label_);

    // True Stevens-style graphs don't have lines but I like them - gcc
    sp->graph(0)->setLineStyle(QCPGraph::lsStepLeft);

    QVector<double> rel_time, seq;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }

        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;
        rel_time.append(ts - ts_offset_);
        seq.append(seg->th_seq - seq_offset_);
    }
    sp->graph(0)->setData(rel_time, seq);
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

    sp->graph(0)->setLineStyle(QCPGraph::lsNone);
    sp->graph(1)->setVisible(true);
    sp->graph(1)->setPen(QPen(QBrush(graph_color_2), 0.5));
    sp->graph(1)->setLineStyle(QCPGraph::lsLine);

    if (!graph_.segments || !graph_.segments->next) {
        dlg_title.append(tr(" [not enough data]"));
        return;
    }

    QVector<double> rel_time, seg_len, tput_time, tput;
    struct segment *oldest_seg = graph_.segments;
#ifndef MA_1_SECOND
    int i = 1;
#endif
    int sum = 0;
    // Financial charts don't show MA data until a full period has elapsed.
    // The Rosetta Code MA examples start spitting out values immediately.
    // For now use not-really-correct initial values just to keep our vector
    // lengths the same.
    for (struct segment *seg = graph_.segments->next; seg != NULL; seg = seg->next) {
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;

#ifdef MA_1_SECOND
        while (ts - (oldest_seg->rel_secs + oldest_seg->rel_usecs / 1000000.0) > 1.0) {
            oldest_seg = oldest_seg->next;
            sum -= oldest_seg->th_seglen;
        }
#else
        if (i > moving_avg_period_) {
            oldest_seg = oldest_seg->next;
            sum -= oldest_seg->th_seglen;
        }
        i++;
#endif

        double dtime = ts - (oldest_seg->rel_secs + oldest_seg->rel_usecs / 1000000.0);
        double av_tput;
        sum += seg->th_seglen;
        if (dtime > 0.0) {
            av_tput = sum * 8.0 / dtime;
        } else {
            av_tput = 0.0;
        }

        rel_time.append(ts - ts_offset_);
        seg_len.append(seg->th_seglen);

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
    sp->graph(0)->setData(rel_time, seg_len);
    sp->graph(1)->setData(tput_time, tput);
}

void TCPStreamDialog::fillRoundTripTime()
{
    QString dlg_title = QString(tr("Round Trip Time")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->xAxis->setLabel(sequence_number_label_);
    sp->xAxis->setNumberFormat("f");
    sp->xAxis->setNumberPrecision(0);
    sp->yAxis->setLabel(round_trip_time_ms_label_);

    sp->graph(0)->setLineStyle(QCPGraph::lsLine);

    QVector<double> seq_no, rtt;
    guint32 seq_base = 0;
    struct unack *unack = NULL, *u;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (seg == graph_.segments) {
            seq_base = seg->th_seq;
        }
        if (compareHeaders(seg)) {
            if (seg->th_seglen && !rtt_is_retrans(unack, seg->th_seq)) {
                double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
                rtt_put_unack_on_list(&unack, rtt_get_new_unack(rt_val, seg->th_seq));
            }
        } else {
            guint32 ack_no = seg->th_ack - seq_base;
            double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
            struct unack *v;

            for (u = unack; u; u = v) {
                if (ack_no > u->seqno) {
                    seq_no.append(u->seqno - seq_offset_);
                    rtt.append((rt_val - u->time) * 1000.0);
                    sequence_num_map_.insert(u->seqno, seg);
                    rtt_delete_unack_from_list(&unack, u);
                }
                v = u->next;
            }
        }
    }
    sp->graph(0)->setData(seq_no, rtt);
}

void TCPStreamDialog::fillWindowScale()
{
    QString dlg_title = QString(tr("Window Scaling")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->graph(0)->setLineStyle(QCPGraph::lsLine);

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
    sp->graph(0)->setData(rel_time, win_size);
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
    Q_UNUSED(event)

    if (mouse_drags_) {
        if (tracer_->visible() && cap_file_ && packet_num_ > 0) {
            emit goToPacket(packet_num_);
        }
    } else {
        if (!rubber_band_) {
            rubber_band_ = new QRubberBand(QRubberBand::Rectangle, ui->streamPlot);
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
    if (mouse_drags_) {
        double tr_key = tracer_->position->key();
        struct segment *packet_seg = NULL;
        packet_num_ = 0;

        if (event && tracer_->graph() && tracer_->position->axisRect()->rect().contains(event->pos())) {
            switch (graph_.type) {
            case GRAPH_TSEQ_STEVENS:
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
            ui->hintLabel->setText(tr("<small><i>Hover over the graph for details.</i></small>"));
            ui->streamPlot->replot();
            return;
        }

        tracer_->setVisible(true);
        packet_num_ = packet_seg->num;
        QString hint = QString(tr("<small><i>%1 %2 (%3s len %4 seq %5 ack %6 win %7)</i></small>"))
                .arg(cap_file_ ? tr("Click to select packet") : tr("Packet"))
                .arg(packet_num_)
                .arg(QString::number(packet_seg->rel_secs + packet_seg->rel_usecs / 1000000.0, 'g', 4))
                .arg(packet_seg->th_seglen)
                .arg(packet_seg->th_seq)
                .arg(packet_seg->th_ack)
                .arg(packet_seg->th_win);
        ui->hintLabel->setText(hint);
        tracer_->setGraphKey(ui->streamPlot->xAxis->pixelToCoord(event->pos().x()));
        ui->streamPlot->replot();
    } else {
        QString hint = QString(tr("<small>Click to select a portion of the graph</small>"));
        if (rubber_band_) {
            rubber_band_->setGeometry(QRect(rb_origin_, event->pos()).normalized());
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
                hint = QString(tr("<small>Release to zoom, x = %1 to %2, y = %3 to %4</small>"))
                        .arg(zoom_ranges.x())
                        .arg(zoom_ranges.x() + zoom_ranges.width())
                        .arg(zoom_ranges.y())
                        .arg(zoom_ranges.y() + zoom_ranges.height());
            } else {
                hint = QString(tr("<small>Unable to select range</small>"));
            }
        }
        ui->hintLabel->setText(hint);
    }
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
    graph_.type = ui->graphTypeComboBox->itemData(index).value<tcp_graph_type>();
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

void TCPStreamDialog::on_otherDirectionButton_clicked()
{
    address tmp_addr;
    guint16 tmp_port;

    COPY_ADDRESS(&tmp_addr, &graph_.src_address);
    tmp_port = graph_.src_port;
    COPY_ADDRESS(&graph_.src_address, &graph_.dst_address);
    graph_.src_port = graph_.dst_port;
    COPY_ADDRESS(&graph_.dst_address, &tmp_addr);
    graph_.dst_port = tmp_port;

    fillGraph();
}

void TCPStreamDialog::on_dragToolButton_toggled(bool checked)
{
    if (checked) mouse_drags_ = true;
    ui->streamPlot->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom
                );
    ui->streamPlot->setCursor(QCursor(Qt::OpenHandCursor));
}

void TCPStreamDialog::on_selectToolButton_toggled(bool checked)
{
    if (checked) mouse_drags_ = false;
    ui->streamPlot->setInteractions(0);
    ui->streamPlot->setCursor(QCursor(Qt::CrossCursor));
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
