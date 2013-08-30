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

TCPStreamDialog::TCPStreamDialog(QWidget *parent, capture_file *cf, tcp_graph_type graph_type) :
    QDialog(parent),
    ui(new Ui::TCPStreamDialog),
    cap_file_(cf),
    tracer_(NULL)
{
    struct segment current;

    ui->setupUi(this);

    if (!select_tcpip_session(cap_file_, &current)) {
        done(QDialog::Rejected);
    }

//#ifdef Q_OS_MAC
//    ui->hintLabel->setAttribute(Qt::WA_MacSmallSize, true);
//#endif

    memset (&graph_, 0, sizeof(graph_));
    graph_.type = graph_type;
    graph_segment_list_get(cap_file_, &graph_, FALSE);

    QString dlg_title = QString(tr("TCP Graph %1 %2:%3 %4 %5:%6"))
            .arg(cf_get_display_name(cap_file_))
            .arg(ep_address_to_str(&graph_.src_address))
            .arg(graph_.src_port)
            .arg(UTF8_RIGHTWARDS_ARROW)
            .arg(ep_address_to_str(&graph_.dst_address))
            .arg(graph_.dst_port);
    setWindowTitle(dlg_title);

    QVector<double> rel_time, seq;
    double rel_time_min = QCPRange::maxRange, rel_time_max = QCPRange::minRange;
    double seq_min = QCPRange::maxRange, seq_max = QCPRange::minRange;
    for (struct segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }

        double rt_val = seg->rel_secs + seg->rel_usecs / 1000000.0;

        rel_time.append(rt_val);
        if (rel_time_min > rt_val) rel_time_min = rt_val;
        if (rel_time_max < rt_val) rel_time_max = rt_val;

        seq.append(seg->th_seq);
        if (seq_min > seg->th_seq) seq_min = seg->th_seq;
        if (seq_max < seg->th_seq) seq_max = seg->th_seq;

        segment_map_.insertMulti(rt_val, seg);
    }

    QCustomPlot *sp = ui->streamPlot;
    sp->plotLayout()->insertRow(0);
    sp->plotLayout()->addElement(0, 0, new QCPPlotTitle(sp, dlg_title));
    sp->addGraph();
    sp->graph(0)->setData(rel_time, seq);
    sp->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom
                );
    sp->setMouseTracking(true);
    // True Stevens-style graphs don't have lines but I like them - gcc
    sp->graph(0)->setPen(QPen(QBrush(tango_sky_blue_5), 0.25));
    sp->graph(0)->setLineStyle(QCPGraph::lsStepLeft);
    sp->graph(0)->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, 5));

    sp->xAxis->setLabel(tr("Time (s)"));
    double range_pad = (rel_time_max - rel_time_min) * 0.05;
    data_range_.setLeft(rel_time_min - range_pad);
    data_range_.setRight(rel_time_max + range_pad);
    sp->xAxis->setRange(data_range_.left(), data_range_.right());
    sp->yAxis->setLabel(tr("Sequence number (B)"));
    range_pad = (seq_max - seq_min) * 0.05;
    data_range_.setBottom(seq_min - range_pad);
    data_range_.setTop(seq_max + range_pad);
    sp->yAxis->setRange(data_range_.bottom(), data_range_.top());

    tracer_ = new QCPItemTracer(sp);
    tracer_->setVisible(false);
    tracer_->setGraph(sp->graph(0));
    tracer_->setInterpolating(false);
    sp->addItem(tracer_);
    toggleTracerStyle(true);

    // XXX - QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As..."));

    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
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
        sp->xAxis->setRange(data_range_.left(), data_range_.right());
        sp->yAxis->setRange(data_range_.bottom(), data_range_.top());
        sp->replot();
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
    QRect spr = ui->streamPlot->axisRect()->rect();
    struct segment *packet_seg = NULL;
    packet_num_ = 0;

    if (spr.contains(event->pos())) {
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
