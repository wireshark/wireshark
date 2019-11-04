/* funnel_string_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "funnel_string_dialog.h"
#include <ui_funnel_string_dialog.h>

#include <QLabel>
#include <QLineEdit>

#include <ui/qt/utils/qt_ui_utils.h>
#include "wireshark_application.h"

// Helper object used for sending close signal to open dialogs from a C function
static FunnelStringDialogHelper dialogHelper;

const int min_edit_width_ = 20; // em widths
FunnelStringDialog::FunnelStringDialog(const QString title, const QStringList field_name_list, funnel_dlg_cb_t dialog_cb, void *dialog_cb_data,
    funnel_dlg_cb_data_free_t dialog_data_free_cb) :
    QDialog(NULL),
    ui(new Ui::FunnelStringDialog),
    dialog_cb_(dialog_cb),
    dialog_cb_data_(dialog_cb_data),
    dialog_cb_data_free_(dialog_data_free_cb)
{
    ui->setupUi(this);
    setWindowTitle(wsApp->windowTitleString(title));
    int one_em = fontMetrics().height();

    int row = 0;
    foreach (QString field_name, field_name_list) {
        QLabel *field_label = new QLabel(field_name, this);
        ui->stringGridLayout->addWidget(field_label, row, 0);
        QLineEdit *field_edit = new QLineEdit(this);
        field_edit->setMinimumWidth(one_em * min_edit_width_);
        field_edits_ << field_edit;
        ui->stringGridLayout->addWidget(field_edit, row, 1);
        row++;
    }
}

FunnelStringDialog::~FunnelStringDialog()
{
    if (dialog_cb_data_free_) {
        dialog_cb_data_free_(dialog_cb_data_);
    }

    delete ui;
}

void FunnelStringDialog::accept()
{
    QDialog::accept();

    disconnect();
    deleteLater();
}

void FunnelStringDialog::reject()
{
    QDialog::reject();

    disconnect();
    deleteLater();
}

void FunnelStringDialog::on_buttonBox_accepted()
{
    if (!dialog_cb_) return;

    GPtrArray* returns = g_ptr_array_new();

    foreach (QLineEdit *field_edit, field_edits_) {
        g_ptr_array_add(returns, qstring_strdup(field_edit->text()));
    }
    g_ptr_array_add(returns, NULL);

    gchar **user_input = (gchar **)g_ptr_array_free(returns, FALSE);
    dialog_cb_(user_input, dialog_cb_data_);
}

void FunnelStringDialog::stringDialogNew(const QString title, const QStringList field_name_list, funnel_dlg_cb_t dialog_cb, void *dialog_cb_data, funnel_dlg_cb_data_free_t dialog_cb_data_free)
{
    FunnelStringDialog *fsd = new FunnelStringDialog(title, field_name_list, dialog_cb, dialog_cb_data, dialog_cb_data_free);
    connect(&dialogHelper, SIGNAL(closeDialogs()), fsd, SLOT(close()));
    fsd->show();
}

void FunnelStringDialogHelper::emitCloseDialogs()
{
    emit closeDialogs();
}

void string_dialog_new(const gchar *title, const gchar **fieldnames, funnel_dlg_cb_t dialog_cb, void *dialog_cb_data, funnel_dlg_cb_data_free_t dialog_cb_data_free)
{
    QStringList field_name_list;
    for (int i = 0; fieldnames[i]; i++) {
        field_name_list << fieldnames[i];
    }
    FunnelStringDialog::stringDialogNew(title, field_name_list, dialog_cb, dialog_cb_data, dialog_cb_data_free);
}

void string_dialogs_close(void)
{
    dialogHelper.emitCloseDialogs();
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
