/* sctp_assoc_analyse_dialog.cpp
 *
 * Copyright 2021 Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "epan/to_str.h"

#include "sctp_assoc_analyse_dialog.h"
#include <ui_sctp_assoc_analyse_dialog.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "sctp_graph_dialog.h"
#include "sctp_graph_arwnd_dialog.h"
#include "sctp_graph_byte_dialog.h"
#include "sctp_chunk_statistics_dialog.h"

SCTPAssocAnalyseDialog::SCTPAssocAnalyseDialog(QWidget *parent, const sctp_assoc_info_t *assoc,
        capture_file *cf) :
    QDialog(parent),
    ui(new Ui::SCTPAssocAnalyseDialog),
    cap_file_(cf)
{
    Q_ASSERT(assoc);
    selected_assoc_id = assoc->assoc_id;

    ui->setupUi(this);
    ui->SCTPAssocAnalyseTab->setCurrentWidget(ui->Statistics);
    Qt::WindowFlags flags = Qt::Window | Qt::WindowSystemMenuHint
            | Qt::WindowMinimizeButtonHint
            | Qt::WindowCloseButtonHint;
    this->setWindowFlags(flags);

    this->setWindowTitle(QString(tr("SCTP Analyse Association: %1 Port1 %2 Port2 %3"))
            .arg(gchar_free_to_qstring(cf_get_display_name(cap_file_))).arg(assoc->port1).arg(assoc->port2));
    fillTabs(assoc);
}

SCTPAssocAnalyseDialog::~SCTPAssocAnalyseDialog()
{
    delete ui;
}

const sctp_assoc_info_t* SCTPAssocAnalyseDialog::findAssocForPacket(capture_file* cf)
{
    frame_data     *fdata;
    GList          *list, *framelist;
    const sctp_assoc_info_t *assoc;
    bool           frame_found = false;

    fdata = cf->current_frame;
    if (sctp_stat_get_info()->is_registered == false) {
        register_tap_listener_sctp_stat();
        /*  (redissect all packets) */
        cf_retap_packets(cf);
    }
    list = g_list_first(sctp_stat_get_info()->assoc_info_list);

    while (list) {
        assoc = gxx_list_data(const sctp_assoc_info_t*, list);

        framelist = g_list_first(assoc->frame_numbers);
        uint32_t fn;
        while (framelist) {
            fn = GPOINTER_TO_UINT(framelist->data);
            if (fn == fdata->num) {
                frame_found = true;
                break;
            }
            framelist = gxx_list_next(framelist);
        }
        if (frame_found) {
            return assoc;
        } else {
            list = gxx_list_next(list);
        }
    }

    if (!frame_found) {
        QMessageBox msgBox;
        msgBox.setText(tr("No Association found for this packet."));
        msgBox.exec();
    }
    return Q_NULLPTR;
}

const _sctp_assoc_info* SCTPAssocAnalyseDialog::findAssoc(QWidget *parent, uint16_t assoc_id)
{
    const sctp_assoc_info_t* result = get_sctp_assoc_info(assoc_id);
    if (result) return result;

    QMessageBox::warning(parent, tr("Warning"), tr("Could not find SCTP Association with id: %1")
            .arg(assoc_id));
    return NULL;
}

void SCTPAssocAnalyseDialog::fillTabs(const sctp_assoc_info_t* selected_assoc)
{
    Q_ASSERT(selected_assoc);

    /* Statistics Tab */

    ui->checksumLabel->setText(selected_assoc->checksum_type);
    ui->data12Label->setText(QString("%1").arg(selected_assoc->n_data_chunks_ep1));
    ui->bytes12Label->setText(QString("%1").arg(selected_assoc->n_data_bytes_ep1));
    ui->data21Label->setText(QString("%1").arg(selected_assoc->n_data_chunks_ep2));
    ui->bytes21Label->setText(QString("%1").arg(selected_assoc->n_data_bytes_ep2));

    /* Tab Endpoint 1 */

    if (selected_assoc->init)
            ui->labelEP1->setText(QString(tr("Complete list of IP addresses from INIT Chunk:")));
        else if ((selected_assoc->initack) && (selected_assoc->initack_dir == 1))
            ui->labelEP1->setText(QString(tr("Complete list of IP addresses from INIT_ACK Chunk:")));
        else
            ui->labelEP1->setText(QString(tr("List of Used IP Addresses")));

    if (selected_assoc->addr1 != Q_NULLPTR) {
        GList *list;

        list = g_list_first(selected_assoc->addr1);
        while (list) {
            address *store;

            store = gxx_list_data(address *, list);
            if (store->type != AT_NONE) {
                if ((store->type == AT_IPv4) || (store->type == AT_IPv6)) {
                    ui->listWidgetEP1->addItem(address_to_qstring(store));
                }
            }
            list = gxx_list_next(list);
        }
    } else {
        return;
    }

    ui->label_221->setText(QString("%1").arg(selected_assoc->port1));
    ui->label_222->setText(QString("0x%1").arg(selected_assoc->verification_tag1, 0, 16));

    if ((selected_assoc->init) ||
        ((selected_assoc->initack) && (selected_assoc->initack_dir == 1))) {
        ui->label_213->setText(QString(tr("Requested Number of Inbound Streams:")));
        ui->label_223->setText(QString("%1").arg(selected_assoc->instream1));
        ui->label_214->setText(QString(tr("Minimum Number of Inbound Streams:")));
        ui->label_224->setText(QString("%1").arg(((selected_assoc->instream1 > selected_assoc->outstream2) ?
                                               selected_assoc->outstream2 : selected_assoc->instream1)));
        ui->label_215->setText(QString(tr("Provided Number of Outbound Streams:")));
        ui->label_225->setText(QString("%1").arg(selected_assoc->outstream1));
        ui->label_216->setText(QString(tr("Minimum Number of Outbound Streams:")));
        ui->label_226->setText(QString("%1").arg(((selected_assoc->outstream1 > selected_assoc->instream2) ?
                                                      selected_assoc->instream2 : selected_assoc->outstream1)));
    } else {
        ui->label_213->setText(QString(tr("Used Number of Inbound Streams:")));
        ui->label_223->setText(QString("%1").arg(selected_assoc->instream1));
        ui->label_214->setText(QString(tr("Used Number of Outbound Streams:")));
        ui->label_224->setText(QString("%1").arg(selected_assoc->outstream1));
        ui->label_215->setText(QString(""));
        ui->label_225->setText(QString(""));
        ui->label_216->setText(QString(""));
        ui->label_226->setText(QString(""));
    }

    /* Tab Endpoint 2 */

    if ((selected_assoc->initack) && (selected_assoc->initack_dir == 2))
        ui->labelEP2->setText(QString(tr("Complete list of IP addresses from INIT_ACK Chunk:")));
    else
        ui->labelEP2->setText(QString(tr("List of Used IP Addresses")));

    if (selected_assoc->addr2 != Q_NULLPTR) {
        GList *list;

        list = g_list_first(selected_assoc->addr2);
        while (list) {
            address     *store;

            store = gxx_list_data(address *, list);
            if (store->type != AT_NONE) {
                if ((store->type == AT_IPv4) || (store->type == AT_IPv6)) {
                    ui->listWidgetEP2->addItem(address_to_qstring(store));
                }
            }
            list = gxx_list_next(list);
        }
    } else {
        return;
    }

    ui->label_321->setText(QString("%1").arg(selected_assoc->port2));
    ui->label_322->setText(QString("0x%1").arg(selected_assoc->verification_tag2, 0, 16));

    if (selected_assoc->initack) {
        ui->label_313->setText(QString(tr("Requested Number of Inbound Streams:")));
        ui->label_323->setText(QString("%1").arg(selected_assoc->instream2));
        ui->label_314->setText(QString(tr("Minimum Number of Inbound Streams:")));
        ui->label_324->setText(QString("%1").arg(((selected_assoc->instream2 > selected_assoc->outstream1) ?
                                               selected_assoc->outstream1 : selected_assoc->instream2)));
        ui->label_315->setText(QString(tr("Provided Number of Outbound Streams:")));
        ui->label_325->setText(QString("%1").arg(selected_assoc->outstream2));
        ui->label_316->setText(QString(tr("Minimum Number of Outbound Streams:")));
        ui->label_326->setText(QString("%1").arg(((selected_assoc->outstream2 > selected_assoc->instream1) ?
                                                      selected_assoc->instream1 : selected_assoc->outstream2)));
    } else {
        ui->label_313->setText(QString(tr("Used Number of Inbound Streams:")));
        ui->label_323->setText(QString("%1").arg(selected_assoc->instream2));
        ui->label_314->setText(QString(tr("Used Number of Outbound Streams:")));
        ui->label_324->setText(QString("%1").arg(selected_assoc->outstream2));
        ui->label_315->setText(QString(""));
        ui->label_325->setText(QString(""));
        ui->label_316->setText(QString(""));
        ui->label_326->setText(QString(""));
    }
}

void SCTPAssocAnalyseDialog::openGraphDialog(int direction)
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    SCTPGraphDialog *sctp_dialog = new SCTPGraphDialog(this, selected_assoc, cap_file_, direction);

    if (sctp_dialog->isMinimized() == true) {
        sctp_dialog->showNormal();
    } else {
        sctp_dialog->show();
    }

    sctp_dialog->raise();
    sctp_dialog->activateWindow();
}

void SCTPAssocAnalyseDialog::on_GraphTSN_2_clicked()
{
    openGraphDialog(2);
}

void SCTPAssocAnalyseDialog::on_GraphTSN_1_clicked()
{
    openGraphDialog(1);
}

void SCTPAssocAnalyseDialog::on_chunkStatisticsButton_clicked()
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    SCTPChunkStatisticsDialog *sctp_dialog = new SCTPChunkStatisticsDialog(this, selected_assoc, cap_file_);

    if (sctp_dialog->isMinimized() == true) {
        sctp_dialog->showNormal();
    } else {
        sctp_dialog->show();
    }

    sctp_dialog->raise();
    sctp_dialog->activateWindow();
}

void SCTPAssocAnalyseDialog::on_setFilterButton_clicked()
{
    QString newFilter = QString("sctp.assoc_index==%1").arg(selected_assoc_id);
    emit filterPackets(newFilter, false);
}

void SCTPAssocAnalyseDialog::openGraphByteDialog(int direction)
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    SCTPGraphByteDialog *sctp_dialog = new SCTPGraphByteDialog(this, selected_assoc, cap_file_, direction);

    if (sctp_dialog->isMinimized() == true) {
        sctp_dialog->showNormal();
    } else {
        sctp_dialog->show();
    }

    sctp_dialog->raise();
    sctp_dialog->activateWindow();
}

void SCTPAssocAnalyseDialog::on_GraphBytes_1_clicked()
{
    openGraphByteDialog(1);
}

void SCTPAssocAnalyseDialog::on_GraphBytes_2_clicked()
{
    openGraphByteDialog(2);
}

void SCTPAssocAnalyseDialog::openGraphArwndDialog(int direction)
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    SCTPGraphArwndDialog *sctp_dialog = new SCTPGraphArwndDialog(this, selected_assoc, cap_file_, direction);

    if (sctp_dialog->isMinimized() == true) {
        sctp_dialog->showNormal();
    } else {
        sctp_dialog->show();
    }

    sctp_dialog->raise();
    sctp_dialog->activateWindow();
}

void SCTPAssocAnalyseDialog::on_GraphArwnd_1_clicked()
{
    openGraphArwndDialog(1);
}

void SCTPAssocAnalyseDialog::on_GraphArwnd_2_clicked()
{
    openGraphArwndDialog(2);
}
