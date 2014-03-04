/* sctp_assoc_analyse_dialog.cpp
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

#include "epan/to_str.h"

#include "sctp_assoc_analyse_dialog.h"
#include "ui_sctp_assoc_analyse_dialog.h"
#include "sctp_graph_dialog.h"
#include "sctp_graph_arwnd_dialog.h"
#include "sctp_graph_byte_dialog.h"
#include "sctp_chunk_statistics_dialog.h"


SCTPAssocAnalyseDialog::SCTPAssocAnalyseDialog(QWidget *parent, sctp_assoc_info_t *assoc, capture_file *cf, SCTPAllAssocsDialog* caller) :
    QDialog(parent),
    ui(new Ui::SCTPAssocAnalyseDialog),
    selected_assoc(assoc),
    cap_file_(cf),
    caller_(caller)
{
    ui->setupUi(this);
    ui->SCTPAssocAnalyseTab->setCurrentWidget(ui->Statistics);
    if (!selected_assoc) {
        if (sctp_stat_get_info()->is_registered == FALSE) {
            register_tap_listener_sctp_stat();
        }
        /*  (redissect all packets) */
        cf_retap_packets(cap_file_);
        selected_assoc = findAssocForPacket(cap_file_);
    }
    this->setWindowTitle(QString(tr("SCTP Analyse Association: %1 Port1 %2 Port2 %3")).arg(cf_get_display_name(cap_file_)).arg(selected_assoc->port1).arg(selected_assoc->port2));
    fillTabs();
}

SCTPAssocAnalyseDialog::~SCTPAssocAnalyseDialog()
{
    delete ui;
}

sctp_assoc_info_t* SCTPAssocAnalyseDialog::findAssocForPacket(capture_file* cf)
{
    frame_data     *fdata;
    GList          *list, *framelist;
    sctp_assoc_info_t *assoc;
    bool           frame_found = false;

    fdata = cf->current_frame;
    if (sctp_stat_get_info()->is_registered == FALSE) {
        register_tap_listener_sctp_stat();
        /*  (redissect all packets) */
        cf_retap_packets(cf);
    }
    list = g_list_first(sctp_stat_get_info()->assoc_info_list);

    while (list) {
        assoc = (sctp_assoc_info_t*)(list->data);

        framelist = g_list_first(assoc->frame_numbers);
        while (framelist) {
            guint32 *fn;
            fn = (guint32 *)framelist->data;
            if (*fn == fdata->num) {
                frame_found = TRUE;
                break;
            }
            framelist = g_list_next(framelist);
        }
        if (frame_found) {
            return assoc;
        } else {
            list = g_list_next(list);
        }
    }

    if (!frame_found) {
        QMessageBox msgBox;
        msgBox.setText(tr("No Association found for this packet."));
        msgBox.exec();
    }
    return NULL;
}

void SCTPAssocAnalyseDialog::fillTabs()
{
    /* Statistics Tab */

    ui->checksumLabel->setText(selected_assoc->checksum_type);
    ui->data12Label->setText(QString("%1").arg(selected_assoc->n_data_chunks_ep1));
    ui->bytes12Label->setText(QString("%1").arg(selected_assoc->n_data_bytes_ep1));
    ui->data21Label->setText(QString("%1").arg(selected_assoc->n_data_chunks_ep2));
    ui->bytes21Label->setText(QString("%1").arg(selected_assoc->n_data_bytes_ep2));

    /* Tab Endpoint 1 */

    if (selected_assoc->init)
            ui->labelEP1->setText(QString(tr("Complete list of IP-Addresses as provided in the INIT-Chunk")));
        else if ((selected_assoc->initack) && (selected_assoc->initack_dir == 1))
            ui->labelEP1->setText(QString(tr("Complete list of IP-Addresses as provided in the INITACK-Chunk")));
        else
            ui->labelEP1->setText(QString(tr("List of used IP-Addresses")));

    if (selected_assoc->addr1 != NULL) {
        GList *list;

        list = g_list_first(selected_assoc->addr1);
        while (list) {
            address *store;

            store = (address *)(list->data);
            if (store->type != AT_NONE) {
                if (store->type == AT_IPv4) {
                    ui->listWidgetEP1->addItem(QString("%1").arg(ip_to_str((const guint8 *)(store->data))));
                } else if (store->type == AT_IPv6) {
                    ui->listWidgetEP1->addItem(QString("%1").arg(ip6_to_str((const struct e_in6_addr *)(store->data))));
                }
            }
            list = g_list_next(list);
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
        ui->labelEP2->setText(QString(tr("Complete list of IP-Addresses as provided in the INITACK-Chunk")));
    else
        ui->labelEP2->setText(QString(tr("List of used IP-Addresses")));

    if (selected_assoc->addr2 != NULL) {
        GList *list;

        list = g_list_first(selected_assoc->addr2);
        while (list) {
            address     *store;

            store = (address *)(list->data);
            if (store->type != AT_NONE) {
                if (store->type == AT_IPv4) {
                    ui->listWidgetEP2->addItem(QString("%1").arg(ip_to_str((const guint8 *)(store->data))));
                } else if (store->type == AT_IPv6) {
                    ui->listWidgetEP2->addItem(QString("%1").arg(ip6_to_str((const struct e_in6_addr *)(store->data))));
                }
            }
            list = g_list_next(list);
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
    if (caller_ && !selected_assoc) {
        selected_assoc = caller_->findSelectedAssoc();
    } else if (!caller_ && !selected_assoc) {
        selected_assoc = findAssocForPacket(cap_file_);
    }
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
    QString newFilter = QString("sctp.assoc_index==%1").arg(selected_assoc->assoc_id);
    selected_assoc = NULL;
    emit filterPackets(newFilter, false);
}

void SCTPAssocAnalyseDialog::openGraphByteDialog(int direction)
{
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
