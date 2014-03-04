/* uat_dialog.h
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

#ifndef UAT_DIALOG_H
#define UAT_DIALOG_H

#include "config.h"

#include <glib.h>

#include "epan/uat-int.h"

#include "syntax_line_edit.h"

#include <QComboBox>
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidgetItem>

namespace Ui {
class UatDialog;
}

class UatDialog : public QDialog
{
    Q_OBJECT

public:
    explicit UatDialog(QWidget *parent = 0, uat_t *uat = NULL);
    ~UatDialog();

    void setUat(uat_t *uat = NULL);

protected:
    void keyPressEvent(QKeyEvent *evt);

private slots:
    void on_uatTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_uatTreeWidget_itemActivated(QTreeWidgetItem *item, int column);
    void on_uatTreeWidget_itemSelectionChanged();
    void lineEditPrefDestroyed();
    void enumPrefDestroyed();
    void enumPrefCurrentIndexChanged(int index);
    void stringPrefTextChanged(const QString & text);
    void stringPrefEditingFinished();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_buttonBox_helpRequested();

private:
    Ui::UatDialog *ui;
    QPushButton *ok_button_;
    QPushButton *help_button_;
    uat_t *uat_;
    int cur_column_;
    SyntaxLineEdit *cur_line_edit_;
    QString saved_string_pref_;
    QComboBox *cur_combo_box_;
    int saved_combo_idx_;

    QString fieldString(guint row, guint column);
    void updateItem(QTreeWidgetItem &item);
    void updateItems();
    void activateLastItem();
    void applyChanges();
    void addRecord(bool copy_from_current = false);
};

#endif // UAT_DIALOG_H
