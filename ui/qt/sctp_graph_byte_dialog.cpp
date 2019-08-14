/* sctp_graph_byte_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sctp_graph_byte_dialog.h"
#include <ui_sctp_graph_byte_dialog.h>

#include <file.h>
#include <math.h>
#include <epan/dissectors/packet-sctp.h>
#include "epan/packet.h"

#include "ui/tap-sctp-analysis.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/qcustomplot.h>
#include "sctp_graph_dialog.h"
#include "sctp_assoc_analyse_dialog.h"

SCTPGraphByteDialog::SCTPGraphByteDialog(QWidget *parent, const sctp_assoc_info_t *assoc,
        capture_file *cf, int dir) :
    QDialog(parent),
    ui(new Ui::SCTPGraphByteDialog),
    cap_file_(cf),
    frame_num(0),
    direction(dir)
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
        drawGraph();
    }
}

SCTPGraphByteDialog::~SCTPGraphByteDialog()
{
    delete ui;
}


void SCTPGraphByteDialog::drawBytesGraph(const sctp_assoc_info_t *selected_assoc)
{
    GList *listTSN = Q_NULLPTR, *tlist = Q_NULLPTR;
    tsn_t *tsn = Q_NULLPTR;
    guint8 type;
    guint32 maxBytes;
    guint64 sumBytes = 0;

    if (direction == 1) {
        maxBytes = selected_assoc->n_data_bytes_ep1;
        listTSN = g_list_last(selected_assoc->tsn1);
    } else {
        maxBytes = selected_assoc->n_data_bytes_ep2;
        listTSN = g_list_last(selected_assoc->tsn2);
    }


    while (listTSN) {
        tsn = gxx_list_data(tsn_t*, listTSN);
        tlist = g_list_first(tsn->tsns);
        guint16 length;
        while (tlist)
        {
            type = gxx_list_data(struct chunk_header *, tlist)->type;
            if (type == SCTP_DATA_CHUNK_ID || type == SCTP_I_DATA_CHUNK_ID) {
                length = g_ntohs(gxx_list_data(struct data_chunk_header *, tlist)->length);
                if (type == SCTP_DATA_CHUNK_ID)
                    length -= DATA_CHUNK_HEADER_LENGTH;
                else
                    length -= I_DATA_CHUNK_HEADER_LENGTH;
                sumBytes += length;
                yb.append(sumBytes);
                xb.append(tsn->secs + tsn->usecs/1000000.0);
                fb.append(tsn->frame_number);
            }
            tlist = gxx_list_next(tlist);
        }
        listTSN = gxx_list_previous(listTSN);
    }


    QCPScatterStyle myScatter;
    myScatter.setShape(QCPScatterStyle::ssCircle);
    myScatter.setSize(3);

    // create graph and assign data to it:

    // Add Bytes graph
    if (xb.size() > 0) {
        QCPGraph *gr = ui->sctpPlot->addGraph(ui->sctpPlot->xAxis, ui->sctpPlot->yAxis);
        gr->setName(QString(tr("Bytes")));
        myScatter.setPen(QPen(Qt::red));
        myScatter.setBrush(Qt::red);
        ui->sctpPlot->graph(0)->setScatterStyle(myScatter);
        ui->sctpPlot->graph(0)->setLineStyle(QCPGraph::lsNone);
        ui->sctpPlot->graph(0)->setData(xb, yb);
    }
    ui->sctpPlot->xAxis->setLabel(tr("time [secs]"));
    ui->sctpPlot->yAxis->setLabel(tr("Received Bytes"));

    // set axes ranges, so we see all data:
    QCPRange myXByteRange(0, (selected_assoc->max_secs+1));
    QCPRange myYByteRange(0, maxBytes);
    ui->sctpPlot->xAxis->setRange(myXByteRange);
    ui->sctpPlot->yAxis->setRange(myYByteRange);
}


void SCTPGraphByteDialog::drawGraph()
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    ui->sctpPlot->clearGraphs();
    drawBytesGraph(selected_assoc);
    ui->sctpPlot->setInteractions(QCP::iRangeZoom | QCP::iRangeDrag | QCP::iSelectPlottables);
    connect(ui->sctpPlot, SIGNAL(plottableClick(QCPAbstractPlottable*,QMouseEvent*)), this, SLOT(graphClicked(QCPAbstractPlottable*, QMouseEvent*)));
    ui->sctpPlot->replot();
}


void SCTPGraphByteDialog::on_pushButton_4_clicked()
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    ui->sctpPlot->xAxis->setRange(selected_assoc->min_secs+selected_assoc->min_usecs/1000000.0, selected_assoc->max_secs+selected_assoc->max_usecs/1000000.0);
    if (direction == 1) {
        ui->sctpPlot->yAxis->setRange(0, selected_assoc->n_data_bytes_ep1);
    } else {
        ui->sctpPlot->yAxis->setRange(0, selected_assoc->n_data_bytes_ep2);
    }
    ui->sctpPlot->replot();
}

void SCTPGraphByteDialog::graphClicked(QCPAbstractPlottable* plottable, QMouseEvent* event)
{
    if (plottable->name().contains(tr("Bytes"), Qt::CaseInsensitive)) {
        double bytes = ui->sctpPlot->yAxis->pixelToCoord(event->pos().y());
        int i;
        for (i = 0; i < yb.size(); i++) {
            if (bytes <= yb.value(i)) {
                frame_num = fb.at(i);
                break;
            }
        }
        if (cap_file_ && frame_num > 0) {
            cf_goto_frame(cap_file_, frame_num);
        }

        ui->hintLabel->setText(QString(tr("<small><i>Graph %1: Received bytes=%2 Time=%3 secs </i></small>"))
                               .arg(plottable->name())
                               .arg(yb.value(i))
                               .arg(xb.value(i)));
    }
}


void SCTPGraphByteDialog::on_saveButton_clicked()
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
