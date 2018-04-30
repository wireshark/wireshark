/* export_pdu_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_PDU_DIALOG_H
#define EXPORT_PDU_DIALOG_H

#include <QDialog>
#include <QDebug>

namespace Ui {
class ExportPDUDialog;
}

class ExportPDUDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ExportPDUDialog(QWidget *parent = 0);
    ~ExportPDUDialog();

private:
    Ui::ExportPDUDialog *ui;

private slots:
    void on_buttonBox_accepted();
};

#endif // EXPORT_PDU_DIALOG_H

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
