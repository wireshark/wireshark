/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_ASSOC_ANALYSE_DIALOG_H
#define SCTP_ASSOC_ANALYSE_DIALOG_H

#include <config.h>

#include <file.h>

#include <epan/dissectors/packet-sctp.h>

#include "sctp_all_assocs_dialog.h"

#include <QDialog>
#include <QTabWidget>
#include <QObject>
#include <QGridLayout>
#include <QMessageBox>


namespace Ui {
class SCTPAssocAnalyseDialog;
}

struct _sctp_assoc_info;

class SCTPAssocAnalyseDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCTPAssocAnalyseDialog(QWidget *parent = 0, const _sctp_assoc_info *assoc = NULL,
            capture_file *cf = NULL);
    ~SCTPAssocAnalyseDialog();

    void fillTabs(const _sctp_assoc_info* selected_assoc);
    static const _sctp_assoc_info* findAssocForPacket(capture_file* cf);
    static const _sctp_assoc_info* findAssoc(QWidget *parent, uint16_t assoc_id);

public slots:
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    void on_GraphTSN_2_clicked();
    void on_GraphTSN_1_clicked();
    void on_chunkStatisticsButton_clicked();
    void on_setFilterButton_clicked();

    void on_GraphBytes_1_clicked();
    void on_GraphBytes_2_clicked();

    void on_GraphArwnd_1_clicked();
    void on_GraphArwnd_2_clicked();

private:
    Ui::SCTPAssocAnalyseDialog *ui;
    uint16_t selected_assoc_id;
    capture_file *cap_file_;
    void openGraphDialog(int direction);
    void openGraphByteDialog(int direction);
    void openGraphArwndDialog(int direction);


signals:
    void filterPackets(QString new_filter, bool force);
};

#endif // SCTP_ASSOC_ANALYSE_DIALOG_H
