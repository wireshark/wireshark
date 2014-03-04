/* sctp_graph_arwnd_dialog.cpp
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

#include "sctp_graph_arwnd_dialog.h"
#include "ui_sctp_graph_arwnd_dialog.h"
#include "sctp_assoc_analyse_dialog.h"

#include "sctp_graph_dialog.h"

SCTPGraphArwndDialog::SCTPGraphArwndDialog(QWidget *parent, sctp_assoc_info_t *assoc, capture_file *cf, int dir) :
    QDialog(parent),
    ui(new Ui::SCTPGraphArwndDialog),
    selected_assoc(assoc),
    cap_file_(cf),
    direction(dir)
{
    ui->setupUi(this);
    if (!selected_assoc) {
        selected_assoc = SCTPAssocAnalyseDialog::findAssocForPacket(cap_file_);
    }
    this->setWindowTitle(QString(tr("SCTP Data and Adv. Rec. Window over Time: %1 Port1 %2 Port2 %3")).arg(cf_get_display_name(cap_file_)).arg(selected_assoc->port1).arg(selected_assoc->port2));
    if ((direction == 1 && selected_assoc->n_array_tsn1 == 0) || (direction == 2 && selected_assoc->n_array_tsn2 == 0)) {
        QMessageBox msgBox;
        msgBox.setText(tr("No Data Chunks sent"));
        msgBox.exec();
        return;
    } else {
        drawGraph();
    }
}

SCTPGraphArwndDialog::~SCTPGraphArwndDialog()
{
    delete ui;
}

void SCTPGraphArwndDialog::drawArwndGraph()
{
    GList *listSACK = NULL, *tlist;
    struct sack_chunk_header *sack_header;
    struct nr_sack_chunk_header *nr_sack_header;
    tsn_t *tsn;
    guint8 type;
    guint32 arwnd=0;

    if (direction == 1) {
        listSACK = g_list_last(selected_assoc->sack1);
        startArwnd = selected_assoc->arwnd1;
    } else {
        listSACK = g_list_last(selected_assoc->sack2);
        startArwnd = selected_assoc->arwnd2;
    }
    while (listSACK) {
        tsn = (tsn_t*) (listSACK->data);
        tlist = g_list_first(tsn->tsns);
        while (tlist) {
            type = ((struct chunk_header *)tlist->data)->type;
            if (type == SCTP_SACK_CHUNK_ID) {
                sack_header =(struct sack_chunk_header *)tlist->data;
                arwnd = g_ntohl(sack_header->a_rwnd);
            } else if (type == SCTP_NR_SACK_CHUNK_ID) {
                nr_sack_header =(struct nr_sack_chunk_header *)tlist->data;
                arwnd = g_ntohl(nr_sack_header->a_rwnd);
            }
            ya.append(arwnd);
            xa.append(tsn->secs + tsn->usecs/1000000.0);
            fa.append(tsn->frame_number);
            tlist = g_list_next(tlist);
        }
        listSACK = g_list_previous(listSACK);
    }

    QCPScatterStyle myScatter;
    myScatter.setShape(QCPScatterStyle::ssCircle);
    myScatter.setSize(3);

    // create graph and assign data to it:

    // Add Arwnd graph
    if (xa.size() > 0) {
        QCPGraph *gr = ui->sctpPlot->addGraph(ui->sctpPlot->xAxis, ui->sctpPlot->yAxis);
        gr->setName(QString(tr("Arwnd")));
        myScatter.setPen(QPen(Qt::red));
        myScatter.setBrush(Qt::red);
        ui->sctpPlot->graph(0)->setScatterStyle(myScatter);
        ui->sctpPlot->graph(0)->setLineStyle(QCPGraph::lsNone);
        ui->sctpPlot->graph(0)->setData(xa, ya);
    }

    ui->sctpPlot->xAxis->setLabel(tr("time [secs]"));
    ui->sctpPlot->yAxis->setLabel(tr("Advertised Receiver Window [Bytes]"));

    // set axes ranges, so we see all data:
    QCPRange myXArwndRange(0, (selected_assoc->max_secs+1));
   // QCPRange myXArwndRange(0, 1);
    QCPRange myYArwndRange(0, startArwnd);
    ui->sctpPlot->xAxis->setRange(myXArwndRange);
    ui->sctpPlot->yAxis->setRange(myYArwndRange);
}


void SCTPGraphArwndDialog::drawGraph()
{
    ui->sctpPlot->clearGraphs();
    drawArwndGraph();
    ui->sctpPlot->setInteractions(QCP::iRangeZoom | QCP::iRangeDrag | QCP::iSelectPlottables);
    ui->sctpPlot->axisRect(0)->setRangeZoomAxes(ui->sctpPlot->xAxis, ui->sctpPlot->yAxis);
    ui->sctpPlot->axisRect(0)->setRangeZoom(Qt::Horizontal);
    connect(ui->sctpPlot, SIGNAL(plottableClick(QCPAbstractPlottable*,QMouseEvent*)), this, SLOT(graphClicked(QCPAbstractPlottable*, QMouseEvent*)));
    ui->sctpPlot->replot();
}


void SCTPGraphArwndDialog::on_pushButton_4_clicked()
{
    ui->sctpPlot->xAxis->setRange(selected_assoc->min_secs+selected_assoc->min_usecs/1000000.0, selected_assoc->max_secs+selected_assoc->max_usecs/1000000.0);
    ui->sctpPlot->yAxis->setRange(0, startArwnd);
    ui->sctpPlot->replot();
}

void SCTPGraphArwndDialog::graphClicked(QCPAbstractPlottable* plottable, QMouseEvent* event)
{
    if (plottable->name().contains("Arwnd", Qt::CaseInsensitive)) {
        double times = ui->sctpPlot->xAxis->pixelToCoord(event->pos().x());
        int i=0;
        for (i = 0; i < xa.size(); i++) {
            if (times <= xa.value(i)) {
                frame_num = fa.at(i);
                break;
            }
        }
        if (cap_file_ && frame_num > 0) {
            cf_goto_frame(cap_file_, frame_num);
        }

        ui->hintLabel->setText(QString(tr("<small><i>Graph %1: a_rwnd=%2 Time=%3 secs </i></small>"))
                               .arg(plottable->name())
                               .arg(ya.value(i))
                               .arg(xa.value(i)));
    }
}


void SCTPGraphArwndDialog::on_saveButton_clicked()
{
    SCTPGraphDialog::save_graph(this, ui->sctpPlot);
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
