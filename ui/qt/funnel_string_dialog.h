/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FUNNEL_STRING_DIALOG_H
#define FUNNEL_STRING_DIALOG_H

#include "epan/funnel.h"

#include <QDialog>

class QLineEdit;

namespace Ui {
class FunnelStringDialog;
class FunnelStringDialogHelper;
}

/**
 * @brief A generic dialog created via the funnel API to prompt the user for string inputs.
 */
class FunnelStringDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FunnelStringDialog.
     * @param parent The parent widget.
     * @param title The title of the dialog window.
     * @param field_list A list of pairs, where each pair defines a label and an initial string value for an input field.
     * @param dialog_cb The callback function executed when the dialog is accepted.
     * @param dialog_cb_data User data passed to the callback function.
     * @param dialog_data_free_cb The callback function used to free the user data.
     */
    explicit FunnelStringDialog(QWidget *parent, const QString title, const QList<QPair<QString, QString>> field_list, funnel_dlg_cb_t dialog_cb, void* dialog_cb_data, funnel_dlg_cb_data_free_t dialog_data_free_cb);

    /**
     * @brief Destroys the FunnelStringDialog.
     */
    ~FunnelStringDialog();

    // Funnel ops

    /**
     * @brief Static helper method to instantiate and show a new FunnelStringDialog.
     * @param parent The parent widget.
     * @param title The title of the dialog window.
     * @param field_list A list of labels and default values for the input fields.
     * @param dialog_cb The acceptance callback.
     * @param dialog_cb_data User data for the callback.
     * @param dialog_cb_data_free The memory freeing callback for the user data.
     */
    static void stringDialogNew(QWidget *parent, const QString title, const QList<QPair<QString, QString>> field_list, funnel_dlg_cb_t dialog_cb, void* dialog_cb_data, funnel_dlg_cb_data_free_t dialog_cb_data_free);

    /**
     * @brief Handles the dialog acceptance, triggering the callback with user inputs.
     */
    void accept();

    /**
     * @brief Handles the dialog rejection, cleaning up associated callback data without execution.
     */
    void reject();

private slots:
    /**
     * @brief Slot triggered when the accepted button is clicked in the button box.
     */
    void on_buttonBox_accepted();

private:
    /** Pointer to the generated UI elements. */
    Ui::FunnelStringDialog *ui;

    /** Callback executed with the entered string data. */
    funnel_dlg_cb_t dialog_cb_;

    /** Data context pointer supplied to the callback. */
    void *dialog_cb_data_;

    /** Callback executed to release the memory of dialog_cb_data_. */
    funnel_dlg_cb_data_free_t dialog_cb_data_free_;

    /** A list tracking the dynamically created QLineEdit input widgets. */
    QList<QLineEdit *> field_edits_;
};

/**
 * @brief A helper class used to broadcast signals for managing open funnel dialogs.
 */
class FunnelStringDialogHelper : public QObject
{
    Q_OBJECT

public slots:
    /**
     * @brief Emits the closeDialogs signal to close all open funnel dialogs.
     */
    void emitCloseDialogs();

signals:
    /**
     * @brief Signal instructing all open funnel string dialogs to close.
     */
    void closeDialogs();
};

extern "C" {

    /**
     * @brief Closes all string dialogs.
     *
     * This function emits a signal to close all dialog windows related to string operations.
     */
    void string_dialogs_close(void);
}

#endif // FUNNEL_STRING_DIALOG_H
