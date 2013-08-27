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

#include "tango_colors.h"

#include <QDebug>

TCPStreamDialog::TCPStreamDialog(QWidget *parent, capture_file *cf, tcp_graph_type graph_type) :
    QDialog(parent),
    ui(new Ui::TCPStreamDialog),
    cap_file_(cf)
{
    struct segment current;

    ui->setupUi(this);

    if (!select_tcpip_session(cap_file_, &current)) {
        done(QDialog::Rejected);
    }

    memset (&graph_, 0, sizeof(graph_));
    graph_.type = graph_type;
    graph_segment_list_get(cap_file_, &graph_, FALSE);
    ui->streamPlot->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom |
                QCP::iSelectPlottables
                );

    QVector<double> rel_time, seq;
    double rel_time_min = QCPRange::maxRange, rel_time_max = QCPRange::minRange;
    double seq_min = QCPRange::maxRange, seq_max = QCPRange::minRange;
    for (struct segment *cur = graph_.segments; cur != NULL; cur = cur->next) {
        if (!compare_headers(&graph_.src_address, &graph_.dst_address,
                             graph_.src_port, graph_.dst_port,
                             &cur->ip_src, &cur->ip_dst,
                             cur->th_sport, cur->th_dport,
                             COMPARE_CURR_DIR)) {
            continue;
        }

        double rt_val = cur->rel_secs + cur->rel_usecs / 1000000.0;

        rel_time.append(rt_val);
        if (rel_time_min > rt_val) rel_time_min = rt_val;
        if (rel_time_max < rt_val) rel_time_max = rt_val;

        seq.append(cur->th_seq);
        if (seq_min > cur->th_seq) seq_min = cur->th_seq;
        if (seq_max < cur->th_seq) seq_max = cur->th_seq;
    }

    ui->streamPlot->addGraph();
    ui->streamPlot->graph(0)->setData(rel_time, seq);
    // True Stevens-style graphs don't have lines but I like them - gcc
    ui->streamPlot->graph(0)->setPen(QPen(QBrush(tango_sky_blue_5), 0.25));
    ui->streamPlot->graph(0)->setLineStyle(QCPGraph::lsStepLeft);
    ui->streamPlot->graph(0)->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, 5));

    ui->streamPlot->xAxis->setLabel(tr("Time (s)"));
    double range_pad = (rel_time_max - rel_time_min) * 0.05;
    data_range_.setLeft(rel_time_min - range_pad);
    data_range_.setRight(rel_time_max + range_pad);
    ui->streamPlot->xAxis->setRange(data_range_.left(), data_range_.right());
    ui->streamPlot->yAxis->setLabel(tr("Sequence number (B)"));
    range_pad = (seq_max - seq_min) * 0.05;
    data_range_.setBottom(seq_min - range_pad);
    data_range_.setTop(seq_max + range_pad);
    ui->streamPlot->yAxis->setRange(data_range_.bottom(), data_range_.top());
    ui->streamPlot->setFocus();
}

TCPStreamDialog::~TCPStreamDialog()
{
    delete ui;
}

void TCPStreamDialog::keyPressEvent(QKeyEvent *event)
{
    double h_factor = ui->streamPlot->axisRect()->rangeZoomFactor(Qt::Horizontal);
    double v_factor = ui->streamPlot->axisRect()->rangeZoomFactor(Qt::Vertical);
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
        h_pan = ui->streamPlot->xAxis->range().size() * 0.1;
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        h_pan = ui->streamPlot->xAxis->range().size() * -0.1;
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        v_pan = ui->streamPlot->yAxis->range().size() * 0.1;
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        v_pan = ui->streamPlot->yAxis->range().size() * -0.1;
        break;

    // Reset
    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_R:
    case Qt::Key_Home:
        ui->streamPlot->xAxis->setRange(data_range_.left(), data_range_.right());
        ui->streamPlot->yAxis->setRange(data_range_.bottom(), data_range_.top());
        ui->streamPlot->replot();
        break;
    }

    if (scale_range) {
        ui->streamPlot->xAxis->scaleRange(h_factor, ui->streamPlot->xAxis->range().center());
        ui->streamPlot->yAxis->scaleRange(v_factor, ui->streamPlot->yAxis->range().center());
        ui->streamPlot->replot();
    }

    double pan_mul = event->modifiers() & Qt::ShiftModifier ? 0.1 : 1.0;

    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan) {
        ui->streamPlot->xAxis->moveRange(h_pan * pan_mul);
        ui->streamPlot->replot();
    }
    if (v_pan) {
        ui->streamPlot->yAxis->moveRange(v_pan * pan_mul);
        ui->streamPlot->replot();
    }
    QDialog::keyPressEvent(event);
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
