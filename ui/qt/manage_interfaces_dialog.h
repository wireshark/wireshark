/* manage_interfaces_dialog.h
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

#ifndef MANAGE_INTERFACES_DIALOG_H
#define MANAGE_INTERFACES_DIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QTableWidget>
#include <QStyledItemDelegate>

enum
{
    HIDE = 0,
    FRIENDLY,
    LOCAL_NAME,
    COMMENT,
    NUM_LOCAL_COLUMNS
};


class NewFileDelegate : public QStyledItemDelegate
{
    Q_OBJECT

private:
    QTableWidget* table;

public:
    NewFileDelegate(QObject *parent = 0);
    ~NewFileDelegate();

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    void setTable(QTableWidget* tb) { table = tb; };

private slots:
    void browse_button_clicked();
    void setTextField(const QString &text);
    void stopEditor();
};


namespace Ui {
class ManageInterfacesDialog;
}

class ManageInterfacesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ManageInterfacesDialog(QWidget *parent = 0);
    ~ManageInterfacesDialog();

private:
    Ui::ManageInterfacesDialog *ui;
    NewFileDelegate new_pipe_item_delegate_;

    void showPipes();
    void showLocalInterfaces();
    void saveLocalHideChanges(QTableWidgetItem *item);
    void saveLocalCommentChanges(QTableWidgetItem *item);
    void checkBoxChanged(QTableWidgetItem *item);

signals:
    void ifsChanged();

private slots:
    void on_addButton_clicked();
    void on_buttonBox_accepted();
    void on_delButton_clicked();
    void on_localButtonBox_accepted();
};

#endif // MANAGE_INTERFACES_DIALOG_H

//
// Editor modelines  -  http://www.wireshark.org/tools/modelines.html
//
// Local variables:
// c-basic-offset: 4
// tab-width: 4
// indent-tabs-mode: nil
// End:
//
// vi: set shiftwidth=4 tabstop=4 expandtab:
// :indentSize=4:tabSize=4:noTabs=true:
//
