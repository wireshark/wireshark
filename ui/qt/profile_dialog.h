/* profile_dialog.h
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

#ifndef PROFILE_DIALOG_H
#define PROFILE_DIALOG_H

#include <QDialog>
#include <QTreeWidgetItem>
#include <QPushButton>

namespace Ui {
class ProfileDialog;
}

class ProfileDialog : public QDialog
{
    Q_OBJECT

public:
    enum ProfileAction { ShowProfiles, NewProfile, EditCurrentProfile, DeleteCurrentProfile };

    explicit ProfileDialog(QWidget *parent = 0);
    ~ProfileDialog();
    int execAction(ProfileAction profile_action);


private:
    void updateWidgets();
    Ui::ProfileDialog *pd_ui_;
    QPushButton *ok_button_;

private slots:
    void on_profileTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();
    void editingFinished();
};

#endif // PROFILE_DIALOG_H
