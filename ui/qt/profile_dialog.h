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

#include "config.h"

#include <ui/qt/geometry_state_dialog.h>
#include <ui/qt/models/profile_model.h>
#include <ui/qt/widgets/profile_tree_view.h>

#include <QPushButton>
#include <QTreeWidgetItem>

namespace Ui {
class ProfileDialog;
}

class ProfileDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    enum ProfileAction {
        ShowProfiles, NewProfile, ImportZipProfile, ImportDirProfile,
        ExportSingleProfile, ExportAllProfiles, EditCurrentProfile, DeleteCurrentProfile
    };

    explicit ProfileDialog(QWidget *parent = Q_NULLPTR);
    ~ProfileDialog();
    int execAction(ProfileAction profile_action);

    /**
     * @brief Select the profile with the given name.
     *
     * If the profile name is empty, the currently selected profile will be choosen instead.
     * If the choosen profile is invalid, the first row will be choosen.
     *
     * @param profile the name of the profile to be selected
     */
    void selectProfile(QString profile = QString());

protected:
    virtual void keyPressEvent(QKeyEvent *event);

private:
    Ui::ProfileDialog *pd_ui_;
    QPushButton *ok_button_;
    QPushButton *import_button_;
#ifdef HAVE_MINIZIP
    QPushButton *export_button_;
    QAction *export_selected_entry_;
#endif
    ProfileModel *model_;
    ProfileSortModel *sort_model_;

    void updateWidgets();
    void resetTreeView();

    QString lastOpenDir();
    void storeLastDir(QString dir);
    void finishImport(QFileInfo fi, int count, int skipped, QStringList import);

private slots:
    void currentItemChanged(const QModelIndex & c = QModelIndex(), const QModelIndex & p = QModelIndex());
#ifdef HAVE_MINIZIP
    void exportProfiles(bool exportAllPersonalProfiles = false);
    void importFromZip();
#endif
    void importFromDirectory();

    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_buttonBox_helpRequested();
    void dataChanged(const QModelIndex &);

    void filterChanged(const QString &);

    void selectionChanged();
    QModelIndexList selectedProfiles();

    // QWidget interface

};

#endif // PROFILE_DIALOG_H
