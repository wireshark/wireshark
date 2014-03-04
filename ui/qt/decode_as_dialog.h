/* decode_as_dialog.h
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

#include <QComboBox>
#include <QDialog>
#include <QMap>
#include <QTreeWidgetItem>

namespace Ui {
class DecodeAsDialog;
}

class DecodeAsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DecodeAsDialog(QWidget *parent = 0, capture_file *cf = NULL, bool create_new = false);
    ~DecodeAsDialog();

public slots:
    void setCaptureFile(capture_file *cf);

private:
    Ui::DecodeAsDialog *ui;

    capture_file *cap_file_;
    QComboBox *table_names_combo_box_;
    QComboBox *selector_combo_box_;
    QComboBox *cur_proto_combo_box_;
    QMap<QString, const char *> ui_name_to_name_;

    QString entryString(const gchar *table_name, gpointer value);
    static void buildChangedList(const gchar *table_name, ftenum_t selector_type,
                          gpointer key, gpointer value, gpointer user_data);
    static void buildDceRpcChangedList(gpointer data, gpointer user_data);
    static void decodeAddProtocol(const gchar *table_name, const gchar *proto_name, gpointer value, gpointer user_data);
    void addRecord(bool copy_from_current = false);
    void fillTypeColumn(QTreeWidgetItem *item);

private slots:
    void fillTable();
    void activateLastItem();

    void on_decodeAsTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_decodeAsTreeWidget_itemActivated(QTreeWidgetItem *item, int column = 0);
    void on_decodeAsTreeWidget_itemSelectionChanged();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();

    void tableNamesDestroyed();
    void tableNamesCurrentIndexChanged(const QString & text);
    void selectorDestroyed();
    void selectorEditTextChanged(const QString & text);
    void curProtoCurrentIndexChanged(const QString & text);
    void curProtoDestroyed();
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();
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
