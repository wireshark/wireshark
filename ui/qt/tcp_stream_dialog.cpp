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

#include <QDir>
#include <QFileDialog>
#include <QPushButton>

#include <QDebug>

const int moving_avg_period_ = 20;
const QRgb graph_color_1 = tango_sky_blue_5;
const QRgb graph_color_2 = tango_butter_6;

Q_DECLARE_METATYPE(tcp_graph_type)

TCPStreamDialog::TCPStreamDialog(QWidget *parent, capture_file *cf, tcp_graph_type graph_type) :
    QDialog(parent),
    ui(new Ui::TCPStreamDialog),
    cap_file_(cf),
    tracer_(NULL),
    num_dsegs_(-1),
    num_acks_(-1),
    num_sack_ranges_(-1)
{
    struct segment current;

    ui->setupUi(this);

    if (!select_tcpip_session(cap_file_, &current)) {
        done(QDialog::Rejected);
    }

//#ifdef Q_OS_MAC
//    ui->hintLabel->setAttribute(Qt::WA_MacSmallSize, true);
//#endif

    ui->graphTypeComboBox->setUpdatesEnabled(false);
    ui->graphTypeComboBox->addItem(tr("Time / Sequence (Stevens)"), qVariantFromValue(GRAPH_TSEQ_STEVENS));
    ui->graphTypeComboBox->addItem(tr("Throughput"), qVariantFromValue(GRAPH_THROUGHPUT));
    ui->graphTypeComboBox->setCurrentIndex(-1);
    ui->graphTypeComboBox->setUpdatesEnabled(true);

    memset (&graph_, 0, sizeof(graph_));
    graph_.type = graph_type;

    QCustomPlot *sp = ui->streamPlot;
    title_ = new QCPPlotTitle(sp);
    tracer_ = new QCPItemTracer(sp);
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, title_);
    sp->addGraph(); // 0 - All: Selectable segments
    sp->addGraph(sp->xAxis, sp->yAxis2); // 1 - Throughput: Moving average
    sp->addItem(tracer_);

    // Fills the graph
    ui->graphTypeComboBox->setCurrentIndex(ui->graphTypeComboBox->findData(qVariantFromValue(graph_type)));

    sp->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom
                );
    sp->setMouseTracking(true);
    sp->graph(0)->setPen(QPen(QBrush(graph_color_1), 0.25));
    sp->graph(0)->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, 5));

    sp->xAxis->setLabel(tr("Time (s)"));
    sp->yAxis->setTickLabelColor(QColor(graph_color_1));

    tracer_->setVisible(false);
    toggleTracerStyle(true);

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As..."));

    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(translateYRange(QCPRange)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));

    mouseMoved(NULL);
}

TCPStreamDialog::~TCPStreamDialog()
{
    delete ui;
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

    case Qt::Key_Right:
    case Qt::Key_L:
        h_pan = sp->xAxis->range().size() * 0.1;
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        h_pan = sp->xAxis->range().size() * -0.1;
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        v_pan = sp->yAxis->range().size() * 0.1;
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        v_pan = sp->yAxis->range().size() * -0.1;
        break;

    case Qt::Key_Space:
        toggleTracerStyle();
        break;

        // Reset
    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_R:
    case Qt::Key_Home:
        resetAxes();
        break;
    // Alas, there is no Blade Runner-style Qt::Key_Ehance
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
}

void TCPStreamDialog::fillGraph()
{
    QCustomPlot *sp = ui->streamPlot;

    if (sp->graphCount() < 1) return;

    segment_map_.clear();
    graph_segment_list_free(&graph_);
    graph_segment_list_get(cap_file_, &graph_, FALSE);

    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }
        double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
        segment_map_.insertMulti(rt_val, seg);
    }

    tracer_->setGraph(NULL);
    // We need at least one graph, so don't bother deleting the first one.
    for (int i = 0; i < sp->graphCount(); i++) {
        sp->graph(i)->clearData();
        sp->graph(i)->setVisible(i == 0 ? true : false);
    }
    sp->yAxis2->setVisible(false);
    sp->yAxis2->setLabel(QString());

    if (!cap_file_) {
        QString dlg_title = QString(tr("No capture file"));
        setWindowTitle(dlg_title);
        title_->setText(dlg_title);
        sp->setEnabled(false);
    } else {
        switch (graph_.type) {
        case GRAPH_TSEQ_STEVENS:
            initializeStevens();
            break;
        case GRAPH_THROUGHPUT:
            initializeThroughput();
            break;
        default:
            break;
        }
        sp->setEnabled(true);
    }
    resetAxes();
    tracer_->setGraph(sp->graph(0));
}

void TCPStreamDialog::resetAxes()
{
    QCustomPlot *sp = ui->streamPlot;

    y_translate_mul_ = 0.0;

    sp->graph(0)->rescaleAxes(false, true);
    for (int i = 1; i < sp->graphCount(); i++) {
        sp->graph(i)->rescaleValueAxis(false, true);
    }

    double range_pad = (sp->xAxis->range().upper - sp->xAxis->range().lower) * 0.05;
    sp->xAxis->setRange(sp->xAxis->range().lower - range_pad,
                        sp->xAxis->range().upper + range_pad);

    range_pad = (sp->yAxis->range().upper - sp->yAxis->range().lower) * 0.05;
    sp->yAxis->setRange(sp->yAxis->range().lower - range_pad,
                        sp->yAxis->range().upper + range_pad);

    range_pad = (sp->yAxis2->range().upper - sp->yAxis2->range().lower) * 0.05;
    sp->yAxis2->setRange(sp->yAxis2->range().lower - range_pad,
                         sp->yAxis2->range().upper + range_pad);

    y_translate_mul_ = (sp->yAxis2->range().upper - sp->yAxis2->range().lower)
            / (sp->yAxis->range().upper - sp->yAxis->range().lower);

    sp->replot();
}

void TCPStreamDialog::initializeStevens()
{
    QString dlg_title = QString(tr("TCP Graph ")) + streamDescription();
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    // True Stevens-style graphs don't have lines but I like them - gcc
    sp->graph(0)->setLineStyle(QCPGraph::lsStepLeft);

    QVector<double> rel_time, seq;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }

        double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;
        rel_time.append(rt_val);
        seq.append(seg->th_seq);
    }
    sp->graph(0)->setData(rel_time, seq);
    sp->yAxis->setLabel(tr("Sequence number (B)"));
}

void TCPStreamDialog::initializeThroughput()
{
    QString dlg_title = QString(tr("Throughput "))
            + streamDescription()
            + QString(tr(" (%1 segment MA)")).arg(moving_avg_period_);
    setWindowTitle(dlg_title);
    title_->setText(dlg_title);

    QCustomPlot *sp = ui->streamPlot;
    sp->graph(0)->setLineStyle(QCPGraph::lsNone);
    sp->graph(1)->setVisible(true);
    sp->graph(1)->setPen(QPen(QBrush(graph_color_2), 0.5));
    sp->graph(1)->setLineStyle(QCPGraph::lsLine);

    if (!graph_.segments || !graph_.segments->next) {
        dlg_title.append(tr(" [not enough data]"));
        return;
    }

    QVector<double> rel_time, seg_len, tput;
    struct segment *oldest_seg = graph_.segments;
    int i = 1, sum = 0;
    // Financial charts don't show MA data until a full period has elapsed.
    // The Rosetta Code MA examples start spitting out values immediately.
    // For now use not-really-correct initial values just to keep our vector
    // lengths the same.
    for (struct segment *seg = graph_.segments->next; seg != NULL; seg = seg->next) {
        double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;

        if (i > moving_avg_period_) {
            oldest_seg = oldest_seg->next;
            sum -= oldest_seg->th_seglen;
        }
        i++;

        double dtime = rt_val - (oldest_seg->rel_secs + oldest_seg->rel_usecs / 1000000.0);
        double av_tput;
        sum += seg->th_seglen;
        if (dtime > 0.0) {
            av_tput = sum * 8.0 / dtime;
        } else {
            av_tput = 0.0;
        }

        rel_time.append(rt_val);
        seg_len.append(seg->th_seglen);
        tput.append(av_tput);
    }
    sp->graph(0)->setData(rel_time, seg_len);
    sp->graph(1)->setData(rel_time, tput);

    sp->yAxis->setLabel(tr("Segment length (B)"));

    sp->yAxis2->setLabel(tr("Avg througput (bits/s)"));
    sp->yAxis2->setTickLabelColor(QColor(graph_color_2));
    sp->yAxis2->setVisible(true);
}

QString TCPStreamDialog::streamDescription()
{
    return QString(tr("%1 %2:%3 %4 %5:%6"))
            .arg(cf_get_display_name(cap_file_))
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
        tr_pen.color().setAlphaF(1.0);
    } else {
        tr_color.setAlphaF(0.5);
        tr_pen.setWidthF(1.0);
    }

    tracer_->setStyle(tstyle);
    tr_pen.setColor(tr_color);
    tracer_->setPen(tr_pen);
    ui->streamPlot->replot();
}

void TCPStreamDialog::graphClicked(QMouseEvent *event)
{
    Q_UNUSED(event)
//    QRect spr = ui->streamPlot->axisRect()->rect();

    if (tracer_->visible() && packet_num_ > 0) {
        emit goToPacket(packet_num_);
    }
}

// Setting mouseTracking on our streamPlot may not be as reliable
// as we need. If it's not we might want to poll the mouse position
// using a QTimer instead.
void TCPStreamDialog::mouseMoved(QMouseEvent *event)
{
    struct segment *packet_seg = NULL;
    packet_num_ = 0;

    if (event && tracer_->graph() && tracer_->position->axisRect()->rect().contains(event->pos())) {
        double ts = tracer_->position->key();
        packet_seg = segment_map_.value(ts, NULL);
    }

    if (!packet_seg) {
        tracer_->setVisible(false);
        ui->hintLabel->setText(tr("<small><i>Hover over the graph for details.</i></small>"));
        ui->streamPlot->replot();
        return;
    }

    tracer_->setVisible(true);
    packet_num_ = packet_seg->num;
    QString hint = QString(tr("<small><i>Click to select packet %1 (len %2 seq %3 ack %4 win %5)</i></small>"))
            .arg(packet_num_)
            .arg(packet_seg->th_seglen)
            .arg(packet_seg->th_seq)
            .arg(packet_seg->th_ack)
            .arg(packet_seg->th_win);
    ui->hintLabel->setText(hint);
    tracer_->setGraphKey(ui->streamPlot->xAxis->pixelToCoord(event->pos().x()));
    ui->streamPlot->replot();
}

void TCPStreamDialog::translateYRange(const QCPRange &y_range1)
{
    if (y_translate_mul_ <= 0.0) return;

    QCustomPlot *sp = ui->streamPlot;

    sp->yAxis2->setRangeUpper(y_range1.upper * y_translate_mul_);
    sp->yAxis2->setRangeLower(y_range1.lower * y_translate_mul_);
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

void TCPStreamDialog::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    fillGraph();
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
