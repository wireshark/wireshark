/* sctp_all_assocs_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_ALL_ASSOCS_DIALOG_H
#define SCTP_ALL_ASSOCS_DIALOG_H

#include <config.h>

#include <glib.h>

#include <file.h>

#include <epan/dissectors/packet-sctp.h>

#include "ui/tap-sctp-analysis.h"

#include <QDialog>
#include <QObject>

namespace Ui {
class SCTPAllAssocsDialog;
}

class SCTPAllAssocsDialog : public QDialog
{
     Q_OBJECT

public:
    explicit SCTPAllAssocsDialog(QWidget *parent = 0, capture_file *cf = NULL);
    ~SCTPAllAssocsDialog();

    void fillTable();

public slots:
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    void on_analyseButton_clicked();
    void on_setFilterButton_clicked();
    void getSelectedItem();

private:
    Ui::SCTPAllAssocsDialog *ui;
    capture_file *cap_file_;
    guint16 selected_assoc_id;


signals:
    void filterPackets(QString new_filter, bool force);
};

#endif // SCTP_ALL_ASSOCS_DIALOG_H

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
