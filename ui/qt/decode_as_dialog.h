/* stats_tree_dialog.h
 *
 * $Id$
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

#ifndef DECODE_AS_DIALOG_H
#define DECODE_AS_DIALOG_H

#include "config.h"

#include <glib.h>

#include "cfile.h"

#include <QDialog>

namespace Ui {
class DecodeAsDialog;
}

class DecodeAsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DecodeAsDialog(QWidget *parent = 0, capture_file *cf = NULL);
    ~DecodeAsDialog();

public slots:
    void setCaptureFile(capture_file *cf);

private:
    Ui::DecodeAsDialog *ui;

    capture_file *cap_file_;

    static void buildChangedList(const gchar *table_name, ftenum_t selector_type,
                          gpointer key, gpointer value, gpointer user_data);
    static void buildDceRpcChangedList(gpointer data, gpointer user_data);

private slots:
    void fillTable();
};

#endif // DECODE_AS_DIALOG_H

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
