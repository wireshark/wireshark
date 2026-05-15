/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KEYBOARD_SHORTCUTS_DIALOG_H
#define KEYBOARD_SHORTCUTS_DIALOG_H

#include "geometry_state_dialog.h"

#include <ui/qt/models/astringlist_list_model.h>

#include <QPersistentModelIndex>
#include <QPoint>
#include <QString>

class QShowEvent;

namespace Ui {
class KeyboardShortcutsDialog;
}

/**
 * @brief A model managing the list of keyboard shortcuts for UI display.
 */
class ShortcutListModel : public AStringListListModel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ShortcutListModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit ShortcutListModel(QObject *parent = Q_NULLPTR);

protected:
    /**
     * @brief Retrieves the header column titles for the model.
     * @return A list of header column strings.
     */
    QStringList headerColumns() const override;
};

/**
 * @brief A dialog window that displays the available keyboard shortcuts.
 */
class KeyboardShortcutsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new KeyboardShortcutsDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit KeyboardShortcutsDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the KeyboardShortcutsDialog.
     */
    ~KeyboardShortcutsDialog();

protected:
    /**
     * @brief Handles the event when the dialog is shown.
     * @param event The show event.
     */
    void showEvent(QShowEvent *event) override;

private slots:
    /**
     * @brief Displays the context menu for copying shortcut data.
     * @param pos The position to display the menu at.
     */
    void showCopyMenu(const QPoint &pos);

    /**
     * @brief Copies the currently selected column text to the clipboard.
     */
    void copyColumnSelection();

    /**
     * @brief Copies the currently selected row text to the clipboard.
     */
    void copyRowSelection();

    /**
     * @brief Opens a print dialog to print the list of keyboard shortcuts.
     */
    void printShortcuts();

private:
    /**
     * @brief Helper function to perform the copy operation.
     * @param copy_row True to copy the entire row, false to copy just the selected column.
     */
    void copySelection(bool copy_row);

    /**
     * @brief Builds an HTML formatted string containing all keyboard shortcuts.
     * @return The formatted HTML string.
     */
    QString buildShortcutsHtml() const;

    /**
     * @brief Generates a label containing the application version information.
     * @return The formatted version string.
     */
    QString applicationVersionLabel() const;

    /** Pointer to the generated UI elements. */
    Ui::KeyboardShortcutsDialog *ui;

    /** Model holding the raw shortcut data. */
    ShortcutListModel *shortcut_model_;

    /** Proxy model managing the sorting and filtering of shortcuts. */
    AStringListListSortFilterProxyModel *shortcut_proxy_model_;

    /** The index at which the context menu was triggered. */
    QPersistentModelIndex context_menu_index_;
};

#endif // KEYBOARD_SHORTCUTS_DIALOG_H
