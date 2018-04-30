/* profile_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_DIALOG_H
#define PROFILE_DIALOG_H

#include "geometry_state_dialog.h"

class QPushButton;
class QTreeWidgetItem;

namespace Ui {
class ProfileDialog;
}

class ProfileDialog : public GeometryStateDialog
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
