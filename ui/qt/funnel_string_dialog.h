/* funnel_string_dialog.h
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

#ifndef FUNNEL_STRING_DIALOG_H
#define FUNNEL_STRING_DIALOG_H

#include <glib.h>

#include "epan/funnel.h"

#include <QDialog>

class QLineEdit;

namespace Ui {
class FunnelStringDialog;
class FunnelStringDialogHelper;
}

class FunnelStringDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FunnelStringDialog(const QString title, const QStringList field_name_list, funnel_dlg_cb_t dialog_cb, void *dialog_cb_data);
    ~FunnelStringDialog();

    // Funnel ops
    static void stringDialogNew(const QString title, const QStringList field_name_list, funnel_dlg_cb_t dialog_cb, void* dialog_cb_data);

    void accept();
    void reject();

private slots:
    void on_buttonBox_accepted();

private:
    Ui::FunnelStringDialog *ui;
    funnel_dlg_cb_t dialog_cb_;
    void *dialog_cb_data_;
    QList<QLineEdit *> field_edits_;
};

class FunnelStringDialogHelper : public QObject
{
    Q_OBJECT

public slots:
    void emitCloseDialogs();

signals:
    void closeDialogs();
};

extern "C" {
void string_dialog_new(const gchar* title, const gchar** fieldnames, funnel_dlg_cb_t dialog_cb, void* dialog_cb_data);
void string_dialogs_close(void);
}

#endif // FUNNEL_STRING_DIALOG_H

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
