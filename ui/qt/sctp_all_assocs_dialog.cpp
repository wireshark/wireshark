/* sctp_all_assocs_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sctp_all_assocs_dialog.h"
#include <ui_sctp_all_assocs_dialog.h>
#include "sctp_assoc_analyse_dialog.h"

#include <ui/qt/utils/qt_ui_utils.h>
//#include "wireshark_application.h"
#include "file.h"
#include "ui/qt/main_window.h"

#include <QWidget>
#include <QDir>
#include <QPushButton>

//#include <QDebug>

SCTPAllAssocsDialog::SCTPAllAssocsDialog(QWidget *parent, capture_file *cf) :
    QDialog(parent),
    ui(new Ui::SCTPAllAssocsDialog),
    cap_file_(cf)
{
    ui->setupUi(this);
    Qt::WindowFlags flags = Qt::Window | Qt::WindowSystemMenuHint
            | Qt::WindowMinimizeButtonHint
            | Qt::WindowMaximizeButtonHint
            | Qt::WindowCloseButtonHint;
    this->setWindowFlags(flags);
    fillTable();
}

SCTPAllAssocsDialog::~SCTPAllAssocsDialog()
{
    delete ui;
}

void SCTPAllAssocsDialog::fillTable()
{
    const sctp_allassocs_info_t *sctp_assocs;
    GList *list;
    const sctp_assoc_info_t* assinfo;
    int numAssocs;

    ui->assocList->setColumnHidden(0, true);
    ui->assocList->setColumnWidth(1,  85);
    ui->assocList->setColumnWidth(2,  85);
    ui->assocList->setColumnWidth(3,  150);
    ui->assocList->setColumnWidth(4,  150);

    sctp_assocs = sctp_stat_get_info();
    if (sctp_assocs->is_registered == FALSE) {
        register_tap_listener_sctp_stat();
        /*  (redissect all packets) */
        cf_retap_packets(cap_file_);
    }
    numAssocs = 0;
    ui->assocList->setRowCount(static_cast<int>(g_list_length(sctp_assocs->assoc_info_list)));

    list = g_list_first(sctp_assocs->assoc_info_list);

    while (list) {
        assinfo = gxx_list_data(const sctp_assoc_info_t*, list);
        ui->assocList->setItem(numAssocs, 0, new QTableWidgetItem(QString("%1").arg(assinfo->assoc_id)));
        ui->assocList->setItem(numAssocs, 1, new QTableWidgetItem(QString("%1").arg(assinfo->port1)));
        ui->assocList->setItem(numAssocs, 2, new QTableWidgetItem(QString("%1").arg(assinfo->port2)));
        ui->assocList->setItem(numAssocs, 3, new QTableWidgetItem(QString("%1").arg(assinfo->n_packets)));
        ui->assocList->setItem(numAssocs, 4, new QTableWidgetItem(QString("%1").arg(assinfo->n_data_chunks)));
        ui->assocList->setItem(numAssocs, 5, new QTableWidgetItem(QString("%1").arg(assinfo->n_data_bytes)));
        list = gxx_list_next(list);
        numAssocs++;
    }
    ui->analyseButton->setEnabled(false);
    ui->setFilterButton->setEnabled(false);
    connect(ui->assocList, SIGNAL(itemSelectionChanged()), this, SLOT(getSelectedItem()));
 }

void SCTPAllAssocsDialog::getSelectedItem()
{
    ui->analyseButton->setEnabled(true);
    ui->setFilterButton->setEnabled(true);
    ui->analyseButton->setFocus(Qt::OtherFocusReason);
    selected_assoc_id = ui->assocList->item(ui->assocList->selectedItems().at(0)->row(), 0)->data(0).toInt();
}

void SCTPAllAssocsDialog::on_analyseButton_clicked()
{
    const sctp_assoc_info_t* selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
    if (!selected_assoc) return;

    SCTPAssocAnalyseDialog *sctp_analyse = new SCTPAssocAnalyseDialog(this, selected_assoc, cap_file_);
    connect(sctp_analyse, SIGNAL(filterPackets(QString&,bool)),
            parent(), SLOT(filterPackets(QString&,bool)));

    if (sctp_analyse->isMinimized() == true)
    {
        sctp_analyse->showNormal();
    }
    else
    {
        sctp_analyse->show();
    }

    sctp_analyse->raise();
    sctp_analyse->activateWindow();
}

void SCTPAllAssocsDialog::on_setFilterButton_clicked()
{
    QString newFilter = QString("sctp.assoc_index==%1").arg(selected_assoc_id);
    emit filterPackets(newFilter, false);
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
