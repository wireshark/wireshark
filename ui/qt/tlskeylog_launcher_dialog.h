/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TLSKEYLOG_DIALOG_H
#define TLSKEYLOG_DIALOG_H

#include <wireshark.h>
#include <QProcess>
#include <QDialog>

#include <epan/prefs.h>

namespace Ui {
class TLSKeylogDialog;
}

/**
 * @brief Dialog for configuring and launching TLS keylog-based decryption,
 *        allowing the user to set the keylog file path, the helper program
 *        used to populate it, and to persist those settings as preferences.
 */
class TLSKeylogDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the TLS Keylog dialog.
     * @param parent Parent widget; used to position the dialog.
     */
    explicit TLSKeylogDialog(QWidget &parent);

    /**
     * @brief Destroys the dialog and releases UI resources.
     */
    ~TLSKeylogDialog();

private slots:
    /**
     * @brief Launches the configured helper program that writes to the TLS keylog file.
     */
    void on_launchActivated();

    /**
     * @brief Saves the current keylog file path and helper program path to
     *        their respective preferences.
     */
    void on_saveActivated();

    /**
     * @brief Resets the keylog file path and helper program path fields to
     *        their stored preference values, discarding any unsaved edits.
     */
    void on_resetActivated();

    /**
     * @brief Opens a file-chooser dialog to select the TLS keylog file path
     *        and populates the corresponding input field.
     */
    void on_browseKeylogPath();

    /**
     * @brief Opens a file-chooser dialog to select the helper program path
     *        and populates the corresponding input field.
     */
    void on_browseProgramPath();

private:
    Ui::TLSKeylogDialog *ui; /**< Qt Designer-generated UI object. */

    module_t *tls_module_;       /**< TLS dissector preferences module. */
    pref_t   *pref_tls_keylog_;  /**< Preference entry for the TLS keylog file path. */

    module_t *gui_module_;             /**< GUI preferences module. */
    pref_t   *pref_tlskeylog_command_; /**< Preference entry for the TLS keylog helper program path. */
};

#endif // TLSKEYLOG_DIALOG_H
