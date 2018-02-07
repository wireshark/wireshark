/* sctp_assoc_analyse_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#ifndef SCTP_ASSOC_ANALYSE_DIALOG_H
#define SCTP_ASSOC_ANALYSE_DIALOG_H

#include <config.h>

#include <glib.h>

#include <file.h>

#include <epan/dissectors/packet-sctp.h>

#include "ui/tap-sctp-analysis.h"
#include "sctp_all_assocs_dialog.h"

#include <QDialog>
#include <QTabWidget>
#include <QObject>
#include <QGridLayout>
#include <QMessageBox>


namespace Ui {
class SCTPAssocAnalyseDialog;
}

class SCTPAssocAnalyseDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCTPAssocAnalyseDialog(QWidget *parent = 0, sctp_assoc_info_t *assoc = NULL, capture_file *cf = NULL, SCTPAllAssocsDialog *caller = NULL);
    ~SCTPAssocAnalyseDialog();

    void fillTabs();
    static sctp_assoc_info_t* findAssocForPacket(capture_file* cf);

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
    sctp_assoc_info_t     *selected_assoc;
    capture_file *cap_file_;
    SCTPAllAssocsDialog *caller_;
    void openGraphDialog(int direction);
    void openGraphByteDialog(int direction);
    void openGraphArwndDialog(int direction);


signals:
    void filterPackets(QString new_filter, bool force);
};

#endif // SCTP_ASSOC_ANALYSE_DIALOG_H

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
