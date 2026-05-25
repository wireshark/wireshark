/** @file
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
#include <QLabel>

namespace Ui {
class ProfileDialog;
}

/**
 * @brief Dialog for managing Wireshark configuration profiles.
 */
class ProfileDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Actions that can be performed on profiles.
     */
    enum ProfileAction {
        ShowProfiles,         /**< Show the profiles dialog. */
        NewProfile,           /**< Create a new profile. */
        ImportZipProfile,     /**< Import a profile from a ZIP archive. */
        ImportDirProfile,     /**< Import a profile from a directory. */
        ExportSingleProfile,  /**< Export a single profile. */
        ExportAllProfiles,    /**< Export all profiles. */
        EditCurrentProfile,   /**< Edit the current profile. */
        DeleteCurrentProfile  /**< Delete the current profile. */
    };

    /**
     * @brief Constructs a ProfileDialog.
     * @param parent The parent widget.
     */
    explicit ProfileDialog(QWidget *parent = Q_NULLPTR);

    /**
     * @brief Destroys the ProfileDialog.
     */
    virtual ~ProfileDialog();

    /**
     * @brief Executes a specific profile action.
     * @param profile_action The action to execute.
     * @return The result code of the action.
     */
    int execAction(ProfileAction profile_action);

    /**
     * @brief Select the profile with the given name.
     *
     * If the profile name is empty, the currently selected profile will be chosen instead.
     * If the chosen profile is invalid, the first row will be chosen.
     *
     * @param profile the name of the profile to be selected
     */
    void selectProfile(QString profile = QString());

protected:
    /**
     * @brief Handles key press events within the dialog.
     * @param event The key press event.
     */
    virtual void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Gets the auto switch limit label UI element.
     * @return Pointer to the QLabel.
     */
    QLabel* autoSwitchLimitLabel() const;

private:
    Ui::ProfileDialog *pd_ui_; /**< Pointer to the user interface form elements. */
    QPushButton *ok_button_; /**< The OK button. */
    QPushButton *import_button_; /**< The import button. */
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    QPushButton *export_button_; /**< The export button. */
    QAction *export_selected_entry_; /**< The action for exporting a selected entry. */
#endif
    ProfileModel *model_; /**< Pointer to the profile data model. */
    ProfileSortModel *sort_model_; /**< Pointer to the profile sorting model. */

    /**
     * @brief Finishes the import process.
     * @param fi The file info of the imported target.
     * @param skipped The number of items skipped during import.
     * @param importedProfiles List of successfully imported profile names.
     */
    void finishImport(QFileInfo fi, int skipped, const QStringList& importedProfiles);

    /**
     * @brief Helper function to remove filter before adding/copying profiles.
     */
    void clearFilter();

private slots:
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    /**
     * @brief Exports profiles to an archive.
     * @param exportAllPersonalProfiles True to export all personal profiles, false otherwise.
     */
    void exportProfiles(bool exportAllPersonalProfiles = false);

    /**
     * @brief Initiates import of profiles from a ZIP archive.
     */
    void importFromZip();
#endif
    /**
     * @brief Initiates import of profiles from a directory.
     */
    void importFromDirectory();

    /**
     * @brief Handles clicks on the new tool button.
     */
    void newToolButtonClicked();

    /**
     * @brief Handles clicks on the delete tool button.
     */
    void deleteToolButtonClicked();

    /**
     * @brief Handles clicks on the copy tool button.
     */
    void copyToolButtonClicked();

    /**
     * @brief Handles the acceptance (OK) of the dialog button box.
     */
    void buttonBoxAccepted();

    /**
     * @brief Handles help requests from the dialog button box.
     */
    void buttonBoxHelpRequested();

    /**
     * @brief Handles data changes within the profile model.
     */
    void dataChanged(const QModelIndex &);

    /**
     * @brief Handles changes to the profile search/filter text.
     * @param text The new filter string.
     */
    void filterChanged(const QString &text);

    /**
     * @brief Handles changes to the selected profiles in the view.
     */
    void selectionChanged();

    /**
     * @brief Retrieves a list of the currently selected profile indexes.
     * @return The list of selected model indexes.
     */
    QModelIndexList selectedProfiles();

    // QWidget interface

};

#endif // PROFILE_DIALOG_H
