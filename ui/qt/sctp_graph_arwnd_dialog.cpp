/* sctp_graph_arwnd_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sctp_graph_arwnd_dialog.h"
#include <ui_sctp_graph_arwnd_dialog.h>
#include "sctp_assoc_analyse_dialog.h"

#include <file.h>
#include <math.h>
#include <epan/dissectors/packet-sctp.h>
#include "epan/packet.h"

#include "ui/tap-sctp-analysis.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/qcustomplot.h>
#include "sctp_graph_dialog.h"

SCTPGraphArwndDialog::SCTPGraphArwndDialog(QWidget *parent, const sctp_assoc_info_t *assoc,
        _capture_file *cf, int dir) :
    QDialog(parent),
    ui(new Ui::SCTPGraphArwndDialog),
    cap_file_(cf),
    frame_num(0),
    direction(dir),
    startArwnd(0)
{
    Q_ASSERT(assoc);
    selected_assoc_id = assoc->assoc_id;

    ui->setupUi(this);
    Qt::WindowFlags flags = Qt::Window | Qt::WindowSystemMenuHint
            | Qt::WindowMinimizeButtonHint
            | Qt::WindowMaximizeButtonHint
            | Qt::WindowCloseButtonHint;
    this->setWindowFlags(flags);
    this->setWindowTitle(QString(tr("SCTP Data and Adv. Rec. Window over Time: %1 Port1 %2 Port2 %3"))
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

SCTPGraphArwndDialog::~SCTPGraphArwndDialog()
{
    delete ui;
}

void SCTPGraphArwndDialog::drawArwndGraph(const sctp_assoc_info_t *selected_assoc)
{
    GList *listSACK = Q_NULLPTR, *tlist;
    struct sack_chunk_header *sack_header;
    struct nr_sack_chunk_header *nr_sack_header;
    tsn_t *tsn;
    guint8 type;
    guint32 arwnd=0;

    if (direction == 1) {
        listSACK = g_list_last(selected_assoc->sack1);
        startArwnd = selected_assoc->arwnd2;
    } else {
        listSACK = g_list_last(selected_assoc->sack2);
        startArwnd = selected_assoc->arwnd1;
    }
    bool detect_max_arwnd = (startArwnd == 0) ? true : false;

    while (listSACK) {
        tsn = gxx_list_data(tsn_t*, listSACK);
        tlist = g_list_first(tsn->tsns);
        while (tlist) {
            type = gxx_list_data(struct chunk_header *, tlist)->type;
            if (type == SCTP_SACK_CHUNK_ID) {
                sack_header = gxx_list_data(struct sack_chunk_header *, tlist);
                arwnd = g_ntohl(sack_header->a_rwnd);
            } else if (type == SCTP_NR_SACK_CHUNK_ID) {
                nr_sack_header = gxx_list_data(struct nr_sack_chunk_header *, tlist);
                arwnd = g_ntohl(nr_sack_header->a_rwnd);
            }
            if (detect_max_arwnd && startArwnd < arwnd) {
                startArwnd = arwnd;
            }
            ya.append(arwnd);
            xa.append(tsn->secs + tsn->usecs/1000000.0);
            fa.append(tsn->frame_number);
            tlist = gxx_list_next(tlist);
        }
        listSACK = gxx_list_previous(listSACK);
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


void SCTPGraphArwndDialog::drawGraph(const sctp_assoc_info_t *selected_assoc)
{
    ui->sctpPlot->clearGraphs();
    drawArwndGraph(selected_assoc);
    ui->sctpPlot->setInteractions(QCP::iRangeZoom | QCP::iRangeDrag | QCP::iSelectPlottables);
    ui->sctpPlot->axisRect(0)->setRangeZoomAxes(ui->sctpPlot->xAxis, ui->sctpPlot->yAxis);
    ui->sctpPlot->axisRect(0)->setRangeZoom(Qt::Horizontal);
    connect(ui->sctpPlot, SIGNAL(plottableClick(QCPAbstractPlottable*,QMouseEvent*)), this, SLOT(graphClicked(QCPAbstractPlottable*, QMouseEvent*)));
    ui->sctpPlot->replot();
}


void SCTPGraphArwndDialog::on_pushButton_4_clicked()
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

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
