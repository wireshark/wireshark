/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MANUF_DIALOG_H
#define MANUF_DIALOG_H

#include <wireshark_dialog.h>
#include <models/manuf_table_model.h>

namespace Ui {
class ManufDialog;
}

/**
 * @brief Dialog for querying MAC address manufacturer (OUI) information.
 */
class ManufDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ManufDialog.
     * @param parent The parent widget.
     * @param cf The associated capture file.
     */
    explicit ManufDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the ManufDialog.
     */
    ~ManufDialog();

private slots:
    /**
     * @brief Slot triggered when the search mode is toggled.
     */
    void on_searchToggled(void);

    /**
     * @brief Slot triggered when editing of the search input is finished.
     */
    void on_editingFinished(void);

    /**
     * @brief Slot triggered when the short name checkbox state changes.
     * @param state The new state of the checkbox.
     */
#if QT_VERSION >= QT_VERSION_CHECK(6, 7, 0)
    void shortNameStateChanged(Qt::CheckState state);
#else
    void shortNameStateChanged(int state);
#endif

    /**
     * @brief Copies the currently selected entry to the clipboard.
     */
    void copyToClipboard(void);

    /**
     * @brief Clears the active search filter.
     */
    void clearFilter(void);

private:
    /**
     * @brief Searches the table by MAC address prefix.
     * @param text The MAC prefix string to search for.
     */
    void searchPrefix(QString &text);

    /**
     * @brief Searches the table by manufacturer/vendor name.
     * @param text The vendor name string to search for.
     */
    void searchVendor(QString &text);

    /** Pointer to the UI elements. */
    Ui::ManufDialog *ui;

    /** Pointer to the manufacturer table model. */
    ManufTableModel *model_;

    /** Pointer to the sorting and filtering proxy model. */
    ManufSortFilterProxyModel *proxy_model_;
};

#endif // MANUF_DIALOG_H
