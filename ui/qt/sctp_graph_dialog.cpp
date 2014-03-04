/* sctp_graph_dialog.cpp
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

#include "sctp_graph_dialog.h"
#include "ui_sctp_graph_dialog.h"
#include "sctp_assoc_analyse_dialog.h"

#include "wireshark_application.h"

SCTPGraphDialog::SCTPGraphDialog(QWidget *parent, sctp_assoc_info_t *assoc, capture_file *cf, int dir) :
    QDialog(parent),
    ui(new Ui::SCTPGraphDialog),
    selected_assoc(assoc),
    cap_file_(cf),
    direction(dir)
{
    ui->setupUi(this);
    if (!selected_assoc) {
        selected_assoc = SCTPAssocAnalyseDialog::findAssocForPacket(cap_file_);
    }
    this->setWindowTitle(QString(tr("SCTP TSNs and SACKs over Time: %1 Port1 %2 Port2 %3")).arg(cf_get_display_name(cap_file_)).arg(selected_assoc->port1).arg(selected_assoc->port2));
    if ((direction == 1 && selected_assoc->n_array_tsn1 == 0) || (direction == 2 && selected_assoc->n_array_tsn2 == 0)) {
        QMessageBox msgBox;
        msgBox.setText(tr("No Data Chunks sent"));
        msgBox.exec();
        return;
    } else {
        drawGraph(3);
    }
}

SCTPGraphDialog::~SCTPGraphDialog()
{
    delete ui;
}

void SCTPGraphDialog::drawNRSACKGraph()
{
    tsn_t *sack;
    GList *list=NULL, *tlist;
    guint16 gap_start=0, gap_end=0, i, numberOf_gaps, numberOf_nr_gaps;
    guint8 type;
    guint32 tsnumber, j, min_tsn;
    struct nr_sack_chunk_header *nr_sack_header;
    struct gaps *nr_gap;
    /* This holds the sum of gap acks and nr gap acks */
    guint16 total_gaps = 0;

    if (direction == 1) {
        list = g_list_last(selected_assoc->sack1);
        min_tsn = selected_assoc->min_tsn1;
    } else {
        list = g_list_last(selected_assoc->sack1);
        min_tsn = selected_assoc->min_tsn1;
    }
    while (list) {
        sack = (tsn_t*) (list->data);
        tlist = g_list_first(sack->tsns);
        while (tlist) {
            type = ((struct chunk_header *)tlist->data)->type;
            if (type == SCTP_NR_SACK_CHUNK_ID) {
                gIsNRSackChunkPresent = 1;
                nr_sack_header =(struct nr_sack_chunk_header *)tlist->data;
                numberOf_nr_gaps=g_ntohs(nr_sack_header->nr_of_nr_gaps);
                numberOf_gaps=g_ntohs(nr_sack_header->nr_of_gaps);
                tsnumber = g_ntohl(nr_sack_header->cum_tsn_ack);
                total_gaps = numberOf_gaps + numberOf_nr_gaps;
                /* If the number of nr_gaps is greater than 0 */
                if ( total_gaps > 0 ) {
                    nr_gap = &nr_sack_header->gaps[0];
                    for (i = 0; i < total_gaps; i++) {
                        gap_start = g_ntohs(nr_gap->start);
                        gap_end = g_ntohs(nr_gap->end);
                        for ( j = gap_start; j <= gap_end; j++) {
                            if (i >= numberOf_gaps) {
                                yn.append(j + tsnumber);
                                xn.append(sack->secs + sack->usecs/1000000.0);
                                fn.append(sack->frame_number);
                            } else {
                                yg.append(j + tsnumber);
                                xg.append(sack->secs + sack->usecs/1000000.0);
                                fg.append(sack->frame_number);
                            }
                        }
                        if (i < total_gaps-1)
                            nr_gap++;
                    }

                    if (tsnumber>=min_tsn) {
                        ys.append(j + tsnumber);
                        xs.append(sack->secs + sack->usecs/1000000.0);
                        fs.append(sack->frame_number);
                    }
                }
            }
            tlist = g_list_next(tlist);
        }
        list = g_list_previous(list);
    }
}

void SCTPGraphDialog::drawSACKGraph()
{
    GList *listSACK = NULL, *tlist;
    guint16 gap_start=0, gap_end=0, nr, dup_nr;
    struct sack_chunk_header *sack_header;
    struct gaps *gap;
    tsn_t *tsn;
    guint8 type;
    guint32 tsnumber=0;
    guint32 minTSN;
    guint32 *dup_list;
    int i, j;

    if (direction == 1) {
        minTSN = selected_assoc->min_tsn1;
        listSACK = g_list_last(selected_assoc->sack1);
    } else {
        minTSN = selected_assoc->min_tsn2;
        listSACK = g_list_last(selected_assoc->sack2);
    }
    while (listSACK) {
        tsn = (tsn_t*) (listSACK->data);
        tlist = g_list_first(tsn->tsns);
        while (tlist) {
            type = ((struct chunk_header *)tlist->data)->type;
            if (type == SCTP_SACK_CHUNK_ID) {
                gIsSackChunkPresent = 1;
                sack_header =(struct sack_chunk_header *)tlist->data;
                nr=g_ntohs(sack_header->nr_of_gaps);
                tsnumber = g_ntohl(sack_header->cum_tsn_ack);
                dup_nr=g_ntohs(sack_header->nr_of_dups);
                if (nr>0) {  // Gap Reports green
                    gap = &sack_header->gaps[0];
                    for(i=0;i<nr; i++) {
                        gap_start=g_ntohs(gap->start);
                        gap_end = g_ntohs(gap->end);
                        for (j=gap_start; j<=gap_end; j++) {
                            yg.append(j+tsnumber);
                            xg.append(tsn->secs + tsn->usecs/1000000.0);
                            fg.append(tsn->frame_number);
                        }
                        if (i < nr-1)
                            gap++;
                    }
                }
                if (tsnumber>=minTSN) { // CumTSNAck red
                    ys.append(tsnumber);
                    xs.append(tsn->secs + tsn->usecs/1000000.0);
                    fs.append(tsn->frame_number);
                }
                if (dup_nr > 0) { // Duplicates cyan
                    dup_list = &sack_header->a_rwnd + 2 + nr;
                    for (i = 0; i < dup_nr; i++) {
                        tsnumber = g_ntohl(dup_list[i]);
                        if (tsnumber >= minTSN) {
                            yd.append(tsnumber);
                            xd.append(tsn->secs + tsn->usecs/1000000.0);
                            fd.append(tsn->frame_number);
                        }
                    }
                }
            }
            tlist = g_list_next(tlist);
        }
        listSACK = g_list_previous(listSACK);
    }

    QCPScatterStyle myScatter;
    myScatter.setShape(QCPScatterStyle::ssCircle);
    myScatter.setSize(3);

    int graphcount = ui->sctpPlot->graphCount();
    // create graph and assign data to it:

    // Add SACK graph
    if (xs.size() > 0) {
        QCPGraph *gr = ui->sctpPlot->addGraph();
        gr->setName(QString("SACK"));
        myScatter.setPen(QPen(Qt::red));
        myScatter.setBrush(Qt::red);
        ui->sctpPlot->graph(graphcount)->setScatterStyle(myScatter);
        ui->sctpPlot->graph(graphcount)->setLineStyle(QCPGraph::lsNone);
        ui->sctpPlot->graph(graphcount)->setData(xs, ys);
        typeStrings.insert(graphcount, QString(tr("CumTSNAck")));
        graphcount++;
    }

    // Add Gap Acks
    if (xg.size() > 0) {
        QCPGraph *gr = ui->sctpPlot->addGraph();
        gr->setName(QString("GAP"));
        myScatter.setPen(QPen(Qt::green));
        myScatter.setBrush(Qt::green);
        ui->sctpPlot->graph(graphcount)->setScatterStyle(myScatter);
        ui->sctpPlot->graph(graphcount)->setLineStyle(QCPGraph::lsNone);
        ui->sctpPlot->graph(graphcount)->setData(xg, yg);
        typeStrings.insert(graphcount, QString(tr("Gap Ack")));
        graphcount++;
    }

    // Add NR Gap Acks
    if (xn.size() > 0) {
        QCPGraph *gr = ui->sctpPlot->addGraph();
        gr->setName(QString("NR_GAP"));
        myScatter.setPen(QPen(Qt::blue));
        myScatter.setBrush(Qt::blue);
        ui->sctpPlot->graph(graphcount)->setScatterStyle(myScatter);
        ui->sctpPlot->graph(graphcount)->setLineStyle(QCPGraph::lsNone);
        ui->sctpPlot->graph(graphcount)->setData(xg, yg);
        typeStrings.insert(graphcount, QString(tr("NR Gap Ack")));
        graphcount++;
    }

    // Add Duplicates
    if (xd.size() > 0) {
        QCPGraph *gr = ui->sctpPlot->addGraph();
        gr->setName(QString("DUP"));
        myScatter.setPen(QPen(Qt::cyan));
        myScatter.setBrush(Qt::cyan);
        ui->sctpPlot->graph(graphcount)->setScatterStyle(myScatter);
        ui->sctpPlot->graph(graphcount)->setLineStyle(QCPGraph::lsNone);
        ui->sctpPlot->graph(graphcount)->setData(xd, yd);
        typeStrings.insert(graphcount, QString(tr("Duplicate Ack")));
    }
}

void SCTPGraphDialog::drawTSNGraph()
{
    GList *listTSN = NULL,*tlist;
    tsn_t *tsn;
    guint8 type;
    guint32 tsnumber=0;

    if (direction == 1) {
        listTSN = g_list_last(selected_assoc->tsn1);
    } else {
        listTSN = g_list_last(selected_assoc->tsn2);
    }

    while (listTSN) {
        tsn = (tsn_t*) (listTSN->data);
        tlist = g_list_first(tsn->tsns);
        while (tlist)
        {
            type = ((struct chunk_header *)tlist->data)->type;
            if (type == SCTP_DATA_CHUNK_ID || type == SCTP_FORWARD_TSN_CHUNK_ID) {
                tsnumber = g_ntohl(((struct data_chunk_header *)tlist->data)->tsn);
                yt.append(tsnumber);
                xt.append(tsn->secs + tsn->usecs/1000000.0);
                ft.append(tsn->frame_number);
            }
            tlist = g_list_next(tlist);
        }
        listTSN = g_list_previous(listTSN);
    }

    QCPScatterStyle myScatter;
    myScatter.setShape(QCPScatterStyle::ssCircle);
    myScatter.setSize(3);

    int graphcount = ui->sctpPlot->graphCount();
    // create graph and assign data to it:

    // Add TSN graph
    if (xt.size() > 0) {
        QCPGraph *gr = ui->sctpPlot->addGraph();
        gr->setName(QString("TSN"));
        myScatter.setPen(QPen(Qt::black));
        myScatter.setBrush(Qt::black);
        ui->sctpPlot->graph(graphcount)->setScatterStyle(myScatter);
        ui->sctpPlot->graph(graphcount)->setLineStyle(QCPGraph::lsNone);
        ui->sctpPlot->graph(graphcount)->setData(xt, yt);
        typeStrings.insert(graphcount, QString(tr("TSN")));
    }
}

void SCTPGraphDialog::drawGraph(int which)
{
    guint32 maxTSN, minTSN;

    gIsSackChunkPresent = false;
    gIsNRSackChunkPresent = false;

    if (direction == 1) {
        maxTSN = selected_assoc->max_tsn1;
        minTSN = selected_assoc->min_tsn1;
    } else {
        maxTSN = selected_assoc->max_tsn2;
        minTSN = selected_assoc->min_tsn2;
    }
    ui->sctpPlot->clearGraphs();
    switch (which) {
    case 1: drawSACKGraph();
        drawNRSACKGraph();
        break;
    case 2: drawTSNGraph();
        break;
    case 3: drawTSNGraph();
        drawSACKGraph();
        drawNRSACKGraph();
        break;
    default: drawTSNGraph();
        drawSACKGraph();
        drawNRSACKGraph();
    }

    // give the axes some labels:
    ui->sctpPlot->xAxis->setLabel(tr("time [secs]"));
    ui->sctpPlot->yAxis->setLabel(tr("TSNs"));
    ui->sctpPlot->setInteractions(QCP::iRangeZoom | QCP::iRangeDrag | QCP::iSelectPlottables);
    connect(ui->sctpPlot, SIGNAL(plottableClick(QCPAbstractPlottable*,QMouseEvent*)), this, SLOT(graphClicked(QCPAbstractPlottable*, QMouseEvent*)));
    // set axes ranges, so we see all data:
    QCPRange myXRange(selected_assoc->min_secs, (selected_assoc->max_secs+1));
    QCPRange myYRange(minTSN, maxTSN);
    ui->sctpPlot->xAxis->setRange(myXRange);
    ui->sctpPlot->yAxis->setRange(myYRange);
    ui->sctpPlot->replot();
}

void SCTPGraphDialog::on_pushButton_clicked()
{
    drawGraph(1);
}

void SCTPGraphDialog::on_pushButton_2_clicked()
{
    drawGraph(2);
}

void SCTPGraphDialog::on_pushButton_3_clicked()
{
    drawGraph(3);
}

void SCTPGraphDialog::on_pushButton_4_clicked()
{
    ui->sctpPlot->xAxis->setRange(selected_assoc->min_secs, selected_assoc->max_secs+1);
    if (direction == 1) {
        ui->sctpPlot->yAxis->setRange(selected_assoc->min_tsn1, selected_assoc->max_tsn1);
    } else {
        ui->sctpPlot->yAxis->setRange(selected_assoc->min_tsn2, selected_assoc->max_tsn2);
    }
    ui->sctpPlot->replot();
}

void SCTPGraphDialog::graphClicked(QCPAbstractPlottable* plottable, QMouseEvent* event)
{
    frame_num = 0;
    int i=0;
    double times = ui->sctpPlot->xAxis->pixelToCoord(event->pos().x());
    if (plottable->name().contains("TSN", Qt::CaseInsensitive)) {
        for (i = 0; i < xt.size(); i++) {
            if (times <= xt.value(i)) {
                frame_num = ft.at(i);
                break;
            }
        }
    } else if (plottable->name().contains("SACK", Qt::CaseInsensitive)) {
        for (i = 0; i < xs.size(); i++) {
            if (times <= xs.value(i)) {
                frame_num = fs.at(i);
                break;
            }
        }
    } else if (plottable->name().contains("DUP", Qt::CaseInsensitive)) {
        for (i = 0; i < xd.size(); i++) {
            if (times <= xd.value(i)) {
                frame_num = fd.at(i);
                break;
            }
        }
    } else if (plottable->name().contains("NR_GAP", Qt::CaseInsensitive)) {
        for (i = 0; i < xn.size(); i++) {
            if (times <= xn.value(i)) {
                frame_num = fn.at(i);
                break;
            }
        }
    } else if (plottable->name().contains("GAP", Qt::CaseInsensitive)) {
        for (i = 0; i < xs.size(); i++) {
            if (times <= xs.value(i)) {
                frame_num = fs.at(i);
                break;
            }
        }
    }
    if (cap_file_ && frame_num > 0) {
        cf_goto_frame(cap_file_, frame_num);
    }
    ui->hintLabel->setText(QString(tr("<small><i>%1: %2 Time: %3 secs </i></small>"))
                           .arg(plottable->name())
                           .arg(floor(ui->sctpPlot->yAxis->pixelToCoord(event->pos().y()) + 0.5))
                           .arg(ui->sctpPlot->xAxis->pixelToCoord(event->pos().x())));
}

void SCTPGraphDialog::save_graph(QDialog *dlg, QCustomPlot *plot)
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

    file_name = QFileDialog::getSaveFileName(dlg, tr("Wireshark: Save Graph As..."),
                                             path.canonicalPath(), filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        if (extension.compare(pdf_filter) == 0) {
            save_ok = plot->savePdf(file_name);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = plot->savePng(file_name);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = plot->saveBmp(file_name);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = plot->saveJpg(file_name);
        }
        // else error dialog?
        if (save_ok) {
            path = QDir(file_name);
            wsApp->setLastOpenDir(path.canonicalPath().toUtf8().constData());
        }
    }
}


void SCTPGraphDialog::on_saveButton_clicked()
{
    save_graph(this, ui->sctpPlot);
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
