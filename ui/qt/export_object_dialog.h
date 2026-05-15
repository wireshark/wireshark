/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_OBJECT_DIALOG_H
#define EXPORT_OBJECT_DIALOG_H

#include <config.h>

#include <file.h>

#include <ui/qt/models/export_objects_model.h>
#include <ui/qt/widgets/export_objects_view.h>

#include "wireshark_dialog.h"

#include <QKeyEvent>

class QTreeWidgetItem;
class QAbstractButton;
class QToolButton;

namespace Ui {
class ExportObjectDialog;
}

/**
 * @brief A dialog window for exporting specific types of objects from a capture file.
 */
class ExportObjectDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ExportObjectDialog.
     * @param parent The parent widget.
     * @param cf The capture file containing the objects.
     * @param eo Pointer to the registered export object type.
     */
    explicit ExportObjectDialog(QWidget &parent, CaptureFile &cf, register_eo_t* eo);

    /**
     * @brief Destroys the ExportObjectDialog.
     */
    ~ExportObjectDialog();

public slots:
    /**
     * @brief Displays the export object dialog.
     */
    void show();

protected:
    /**
     * @brief Marks the beginning of a retap operation for packets.
     */
    void beginRetapPackets() override;

    /**
     * @brief Finishes retap by cleaning up resources.
     */
    void endRetapPackets() override;

    /**
     * @brief Handles key press events for the dialog.
     * @param evt The key event to handle.
     */
    virtual void keyPressEvent(QKeyEvent *evt) override;

private slots:
    /**
     * @brief Slot triggered to accept the dialog.
     */
    void accept() override;

    /**
     * @brief Slot triggered to handle capture events.
     * @param e The capture event.
     */
    void captureEvent(CaptureEvent e);

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Slot triggered when a button in the button box is clicked.
     * @param button The button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * @brief Slot triggered when the selected content type changes.
     * @param index The index of the newly selected content type.
     */
    void on_cmbContentType_currentIndexChanged(int index);
    void uniqueToggled(bool checked);

    /**
     * @brief Slot triggered when data in the model changes.
     * @param topLeft The top left index of the changed data.
     * @param from The starting row index.
     * @param to The ending row index.
     */
    void modelDataChanged(const QModelIndex &topLeft, int from, int to);

    /**
     * @brief Slot triggered when the model's rows are reset.
     */
    void modelRowsReset();

    /**
     * @brief Slot triggered when the current item changes.
     * @param current The newly current model index.
     */
    void currentHasChanged(const QModelIndex &current);

    /**
     * @brief Slot triggered when the selection changes.
     */
    void selectionHasChanged(const QItemSelection&);

private:
    /**
     * @brief Determines if a specific MIME type can be previewed.
     * @param mime_type The MIME type string to check.
     * @return True if previewable, false otherwise.
     */
    bool mimeTypeIsPreviewable(QString mime_type);

    /**
     * @brief Saves a specific entry to a file.
     * @param proxyIndex The proxy model index of the entry.
     * @param tempFile Optional pointer to store the temporary file path.
     */
    void saveEntry(const QModelIndex &proxyIndex, QString *tempFile = nullptr);

    /**
     * @brief Saves multiple entries to a directory.
     * @param proxyIndices The list of proxy model indices to save.
     */
    void saveEntries(const QModelIndexList &proxyIndices);

    /**
     * @brief Saves the currently selected entry.
     * @param tempFile Optional pointer to store the temporary file path.
     */
    void saveCurrentEntry(QString *tempFile = Q_NULLPTR);

    /**
     * @brief Saves all currently selected entries.
     */
    void saveSelectedEntries();

    /**
     * @brief Saves all currently displayed (filtered) entries.
     */
    void saveDisplayedEntries();

    /**
     * @brief Saves all entries in the model.
     */
    void saveAllEntries();

    /** Pointer to the generated UI elements. */
    Ui::ExportObjectDialog *eo_ui_;

    /** Pointer to the save button. */
    QPushButton *save_bt_;

    /** Pointer to the save all tool button. */
    QToolButton *save_all_bt_;

    /** The underlying model managing export objects. */
    ExportObjectModel model_;

    /** The proxy model used for sorting and filtering objects. */
    ExportObjectProxyModel proxyModel_;

    /** A list of available content types for filtering. */
    QStringList contentTypes;

    /**
     * @brief Updates the list of available content types based on the current items.
     */
    void updateContentTypes();
};

#endif // EXPORT_OBJECT_DIALOG_H
