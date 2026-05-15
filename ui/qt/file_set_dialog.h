/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILE_SET_DIALOG_H
#define FILE_SET_DIALOG_H

#include <config.h>

#include "file.h"
#include "fileset.h"

#include "geometry_state_dialog.h"

#include <QItemSelection>

namespace Ui {
class FileSetDialog;
}

class FilesetEntryModel;

/**
 * @brief A dialog for managing and displaying capture file sets.
 */
class FileSetDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FileSetDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit FileSetDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the FileSetDialog.
     */
    ~FileSetDialog();

    /**
     * @brief Handles the event when a capture file in the set is opened.
     * @param cf Pointer to the opened capture file.
     */
    void fileOpened(const capture_file *cf);

    /**
     * @brief Handles the event when the capture file is closed.
     */
    void fileClosed();

    /**
     * @brief Adds a file entry to the file set dialog.
     * @param entry Pointer to the file set entry to add, defaults to NULL.
     */
    void addFile(fileset_entry *entry = NULL);

    /**
     * @brief Prepares the dialog to begin adding a new file.
     */
    void beginAddFile();

    /**
     * @brief Finalizes the process of adding a new file to the dialog.
     */
    void endAddFile();

signals:
    /**
     * @brief Signal emitted to open a specific capture file from the set.
     * @param filePath The path of the capture file to open.
     */
    void fileSetOpenCaptureFile(QString filePath);

private slots:
    /**
     * @brief Slot triggered when the selected item in the file set changes.
     * @param selected The newly selected items.
     */
    void selectionChanged(const QItemSelection &selected, const QItemSelection &);

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

private:
    /** Pointer to the generated UI elements. */
    Ui::FileSetDialog *fs_ui_;

    /** Model managing the file set entry data. */
    FilesetEntryModel *fileset_entry_model_;

    /** Pointer to the close button in the dialog. */
    QPushButton *close_button_;

    /** The index of the currently active file in the set. */
    int cur_idx_;
};

#endif // FILE_SET_DIALOG_H
