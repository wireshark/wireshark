/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef REMOTE_CAPTURE_DIALOG_H
#define REMOTE_CAPTURE_DIALOG_H

#include <config.h>

#ifdef HAVE_PCAP_REMOTE
#include <QDialog>
#include "ui/capture_opts.h"

namespace Ui {
class RemoteCaptureDialog;
}

/**
 * @brief Dialog for configuring and adding remote capture interfaces.
 */
class RemoteCaptureDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new RemoteCaptureDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit RemoteCaptureDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the RemoteCaptureDialog.
     */
    ~RemoteCaptureDialog();

signals:
    /**
     * @brief Signal emitted when a remote interface is successfully added.
     * @param rlist The list of remote interfaces retrieved.
     * @param roptions The options used to connect to the remote host.
     */
    void remoteAdded(GList *rlist, remote_options *roptions);

private slots:
    /**
     * @brief Slot triggered when password authentication is toggled.
     * @param checked True if password authentication is enabled.
     */
    void on_pwAuth_toggled(bool checked);

    /**
     * @brief Slot triggered when null (no) authentication is toggled.
     * @param checked True if null authentication is enabled.
     */
    void on_nullAuth_toggled(bool checked);

    /**
     * @brief Applies the remote configuration and attempts to connect.
     */
    void apply_remote();

    /**
     * @brief Slot triggered when the host input changes.
     * @param host The new host string.
     */
    void hostChanged(const QString host);

private:
    /** Pointer to the generated UI elements. */
    Ui::RemoteCaptureDialog *ui;

    /**
     * @brief Fills the host combobox with previously used remote hosts.
     */
    void fillComboBox();
};
#endif
#endif // REMOTE_CAPTURE_DIALOG_H
