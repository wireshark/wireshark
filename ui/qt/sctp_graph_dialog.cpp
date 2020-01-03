/* sctp_graph_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wsutil/utf8_entities.h>

#include "sctp_graph_dialog.h"
#include <ui_sctp_graph_dialog.h>
#include "sctp_assoc_analyse_dialog.h"

#include <file.h>
#include <math.h>
#include <epan/dissectors/packet-sctp.h>
#include "epan/packet.h"

#include "ui/tap-sctp-analysis.h"

#include <QMessageBox>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/qcustomplot.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include "wireshark_application.h"

SCTPGraphDialog::SCTPGraphDialog(QWidget *parent, const sctp_assoc_info_t *assoc,
        capture_file *cf, int dir) :
    QDialog(parent),
    ui(new Ui::SCTPGraphDialog),
    cap_file_(cf),
    frame_num(0),
    direction(dir),
    relative(false),
    type(1)
{
    Q_ASSERT(assoc);
    selected_assoc_id = assoc->assoc_id;

    ui->setupUi(this);
    Qt::WindowFlags flags = Qt::Window | Qt::WindowSystemMenuHint
            | Qt::WindowMinimizeButtonHint
            | Qt::WindowMaximizeButtonHint
            | Qt::WindowCloseButtonHint;
    this->setWindowFlags(flags);
    this->setWindowTitle(QString(tr("SCTP TSNs and SACKs over Time: %1 Port1 %2 Port2 %3"))
            .arg(gchar_free_to_qstring(cf_get_display_name(cap_file_))).arg(assoc->port1).arg(assoc->port2));
    if ((direction == 1 && assoc->n_array_tsn1 == 0) || (direction == 2 && assoc->n_array_tsn2 == 0)) {
        QMessageBox msgBox;
        msgBox.setText(tr("No Data Chunks sent"));
        msgBox.exec();
        return;
    } else {
        drawGraph(assoc);
    }
}

SCTPGraphDialog::~SCTPGraphDialog()
{
    delete ui;
}

void SCTPGraphDialog::drawNRSACKGraph(const sctp_assoc_info_t* selected_assoc)
{
    tsn_t *sack = Q_NULLPTR;
    GList *list = Q_NULLPTR, *tlist = Q_NULLPTR;
    guint16 gap_start=0, gap_end=0, i, numberOf_gaps, numberOf_nr_gaps;
    guint8 type;
    guint32 tsnumber, j = 0, min_tsn, rel = 0;
    struct nr_sack_chunk_header *nr_sack_header = Q_NULLPTR;
    struct gaps *nr_gap = Q_NULLPTR;
    /* This holds the sum of gap acks and nr gap acks */
    guint16 total_gaps = 0;

    if (direction == 1) {
        list = g_list_last(selected_assoc->sack1);
        min_tsn = selected_assoc->min_tsn1;
    } else {
        list = g_list_last(selected_assoc->sack2);
        min_tsn = selected_assoc->min_tsn2;
    }
    if (relative) {
        rel = min_tsn;
    }
    while (list) {
        sack = gxx_list_data(tsn_t*, list);
        tlist = g_list_first(sack->tsns);
        while (tlist) {
            type = gxx_list_data(struct chunk_header *, tlist)->type;
            if (type == SCTP_NR_SACK_CHUNK_ID) {
                nr_sack_header = gxx_list_data(struct nr_sack_chunk_header *, tlist);
                numberOf_nr_gaps=g_ntohs(nr_sack_header->nr_of_nr_gaps);
                numberOf_gaps=g_ntohs(nr_sack_header->nr_of_gaps);
                tsnumber = g_ntohl(nr_sack_header->cum_tsn_ack);
                total_gaps = numberOf_gaps + numberOf_nr_gaps;
                /* If the number of nr_gaps is greater than 0 */
                if (total_gaps > 0) {
                    nr_gap = &nr_sack_header->gaps[0];
                    for (i = 0; i < total_gaps; i++) {
                        gap_start = g_ntohs(nr_gap->start);
                        gap_end = g_ntohs(nr_gap->end);
                        for (j = gap_start; j <= gap_end; j++) {
                            if (i >= numberOf_gaps) {
                                yn.append(j + tsnumber - rel);
                                xn.append(sack->secs + sack->usecs/1000000.0);
                                fn.append(sack->frame_number);
                            } else {
                                yg.append(j + tsnumber - rel);
                                xg.append(sack->secs + sack->usecs/1000000.0);
                                fg.append(sack->frame_number);
                            }
                        }
                        if (i < total_gaps-1)
                            nr_gap++;
                    }

                    if (tsnumber>=min_tsn) {
                        ys.append(j + tsnumber - rel);
                        xs.append(sack->secs + sack->usecs/1000000.0);
                        fs.append(sack->frame_number);
                    }
                }
            }
            tlist = gxx_list_next(tlist);
        }
        list = gxx_list_previous(list);
    }
}

void SCTPGraphDialog::drawSACKGraph(const sctp_assoc_info_t* selected_assoc)
{
    GList *listSACK = Q_NULLPTR, *tlist = Q_NULLPTR;
    guint16 gap_start=0, gap_end=0, nr, dup_nr;
    struct sack_chunk_header *sack_header = Q_NULLPTR;
    struct gaps *gap = Q_NULLPTR;
    tsn_t *tsn = Q_NULLPTR;
    guint8 type;
    guint32 tsnumber=0, rel = 0;
    guint32 minTSN;
    guint32 *dup_list = Q_NULLPTR;
    int i, j;

    if (direction == 1) {
        minTSN = selected_assoc->min_tsn1;
        listSACK = g_list_last(selected_assoc->sack1);
    } else {
        minTSN = selected_assoc->min_tsn2;
        listSACK = g_list_last(selected_assoc->sack2);
    }
    if (relative) {
        rel = minTSN;
    }
    while (listSACK) {
        tsn = gxx_list_data(tsn_t*, listSACK);
        tlist = g_list_first(tsn->tsns);
        while (tlist) {
            type = gxx_list_data(struct chunk_header *, tlist)->type;
            if (type == SCTP_SACK_CHUNK_ID) {
                sack_header = gxx_list_data(struct sack_chunk_header *, tlist);
                nr=g_ntohs(sack_header->nr_of_gaps);
                tsnumber = g_ntohl(sack_header->cum_tsn_ack);
                dup_nr=g_ntohs(sack_header->nr_of_dups);
                if (nr>0) {  // Gap Reports green
                    gap = &sack_header->gaps[0];
                    for (i=0;i<nr; i++) {
                        gap_start=g_ntohs(gap->start);
                        gap_end = g_ntohs(gap->end);
                        for (j=gap_start; j<=gap_end; j++) {
                            yg.append(j + tsnumber - rel);
                            xg.append(tsn->secs + tsn->usecs/1000000.0);
                            fg.append(tsn->frame_number);
                        }
                        if (i < nr-1)
                            gap++;
                    }
                }
                if (tsnumber>=minTSN) { // CumTSNAck red
                    ys.append(tsnumber - rel);
                    xs.append(tsn->secs + tsn->usecs/1000000.0);
                    fs.append(tsn->frame_number);
                }
                if (dup_nr > 0) { // Duplicates cyan
                    dup_list = &sack_header->a_rwnd + 2 + nr;
                    for (i = 0; i < dup_nr; i++) {
                        tsnumber = g_ntohl(dup_list[i]);
                        if (tsnumber >= minTSN) {
                            yd.append(tsnumber - rel);
                            xd.append(tsn->secs + tsn->usecs/1000000.0);
                            fd.append(tsn->frame_number);
                        }
                    }
                }
            }
            tlist = gxx_list_next(tlist);
        }
        listSACK = gxx_list_previous(listSACK);
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
        ui->sctpPlot->graph(graphcount)->setData(xn, yn);
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

void SCTPGraphDialog::drawTSNGraph(const sctp_assoc_info_t* selected_assoc)
{
    GList *listTSN = Q_NULLPTR,*tlist = Q_NULLPTR;
    tsn_t *tsn = Q_NULLPTR;
    guint8 type;
    guint32 tsnumber=0, rel = 0, minTSN;

    if (direction == 1) {
        listTSN = g_list_last(selected_assoc->tsn1);
         minTSN = selected_assoc->min_tsn1;
    } else {
        listTSN = g_list_last(selected_assoc->tsn2);
         minTSN = selected_assoc->min_tsn2;
    }

    if (relative) {
        rel = minTSN;
     }

    while (listTSN) {
        tsn = gxx_list_data(tsn_t*, listTSN);
        tlist = g_list_first(tsn->tsns);
        while (tlist)
        {
            type = gxx_list_data(struct chunk_header *, tlist)->type;
            if (type == SCTP_DATA_CHUNK_ID || type == SCTP_I_DATA_CHUNK_ID || type == SCTP_FORWARD_TSN_CHUNK_ID) {
                tsnumber = g_ntohl(gxx_list_data(struct data_chunk_header *, tlist)->tsn);
                yt.append(tsnumber - rel);
                xt.append(tsn->secs + tsn->usecs/1000000.0);
                ft.append(tsn->frame_number);
            }
            tlist = gxx_list_next(tlist);
        }
        listTSN = gxx_list_previous(listTSN);
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

void SCTPGraphDialog::drawGraph(const sctp_assoc_info_t* selected_assoc)
{
    if (!selected_assoc) {
        selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
        if (!selected_assoc) return;
    }

    guint32 maxTSN, minTSN;

    if (direction == 1) {
        maxTSN = selected_assoc->max_tsn1;
        minTSN = selected_assoc->min_tsn1;
    } else {
        maxTSN = selected_assoc->max_tsn2;
        minTSN = selected_assoc->min_tsn2;
    }
    ui->sctpPlot->clearGraphs();
    xt.clear();
    yt.clear();
    xs.clear();
    ys.clear();
    xg.clear();
    yg.clear();
    xd.clear();
    yd.clear();
    xn.clear();
    yn.clear();
    ft.clear();
    fs.clear();
    fg.clear();
    fd.clear();
    fn.clear();
    typeStrings.clear();
    switch (type) {
    case 1:
        drawSACKGraph(selected_assoc);
        drawNRSACKGraph(selected_assoc);
        break;
    case 2:
        drawTSNGraph(selected_assoc);
        break;
    case 3:
        drawTSNGraph(selected_assoc);
        drawSACKGraph(selected_assoc);
        drawNRSACKGraph(selected_assoc);
        break;
    default:
        drawTSNGraph(selected_assoc);
        drawSACKGraph(selected_assoc);
        drawNRSACKGraph(selected_assoc);
        break;
    }

    // give the axes some labels:
    ui->sctpPlot->xAxis->setLabel(tr("time [secs]"));
    ui->sctpPlot->yAxis->setLabel(tr("TSNs"));
    ui->sctpPlot->setInteractions(QCP::iRangeZoom | QCP::iRangeDrag | QCP::iSelectPlottables);
    connect(ui->sctpPlot, SIGNAL(plottableClick(QCPAbstractPlottable*,QMouseEvent*)), this, SLOT(graphClicked(QCPAbstractPlottable*, QMouseEvent*)));
    // set axes ranges, so we see all data:
    QCPRange myXRange(selected_assoc->min_secs, (selected_assoc->max_secs+1));
    if (relative) {
        QCPRange myYRange(0, maxTSN - minTSN + 1);
        ui->sctpPlot->yAxis->setRange(myYRange);
    } else {
        QCPRange myYRange(minTSN, maxTSN + 1);
        ui->sctpPlot->yAxis->setRange(myYRange);
    }
    ui->sctpPlot->xAxis->setRange(myXRange);
    ui->sctpPlot->replot();
}

void SCTPGraphDialog::on_pushButton_clicked()
{
    type = 1;
    drawGraph();
}

void SCTPGraphDialog::on_pushButton_2_clicked()
{
    type = 2;
    drawGraph();
}

void SCTPGraphDialog::on_pushButton_3_clicked()
{
    type = 3;
    drawGraph();
}

void SCTPGraphDialog::on_pushButton_4_clicked()
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    ui->sctpPlot->xAxis->setRange(selected_assoc->min_secs, selected_assoc->max_secs+1);
    if (relative) {
        if (direction == 1) {
            ui->sctpPlot->yAxis->setRange(0, selected_assoc->max_tsn1 - selected_assoc->min_tsn1);
        } else {
            ui->sctpPlot->yAxis->setRange(0, selected_assoc->max_tsn2 - selected_assoc->min_tsn2);
        }
   } else {
        if (direction == 1) {
            ui->sctpPlot->yAxis->setRange(selected_assoc->min_tsn1, selected_assoc->max_tsn1);
        } else {
            ui->sctpPlot->yAxis->setRange(selected_assoc->min_tsn2, selected_assoc->max_tsn2);
        }
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

    file_name = WiresharkFileDialog::getSaveFileName(dlg, wsApp->windowTitleString(tr("Save Graph As" UTF8_HORIZONTAL_ELLIPSIS)),
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

void SCTPGraphDialog::on_relativeTsn_stateChanged(int arg1)
{
    relative = arg1;
    drawGraph();
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
