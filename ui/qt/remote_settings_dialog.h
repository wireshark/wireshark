/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef REMOTE_SETTINGS_DIALOG_H
#define REMOTE_SETTINGS_DIALOG_H

#include <config.h>

#ifdef HAVE_PCAP_REMOTE
#include <QDialog>
#include "ui/capture_opts.h"

namespace Ui {
class RemoteSettingsDialog;
}

/**
 * @brief Dialog for configuring remote interface settings.
 */
class RemoteSettingsDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a RemoteSettingsDialog.
     * @param parent The parent widget.
     * @param iface Pointer to the interface being configured.
     */
    explicit RemoteSettingsDialog(QWidget *parent = 0, interface_t *iface = NULL);

    /**
     * @brief Destroys the RemoteSettingsDialog.
     */
    ~RemoteSettingsDialog();

signals:
    /**
     * @brief Signal emitted when the remote settings for an interface change.
     * @param iface Pointer to the updated interface.
     */
    void remoteSettingsChanged(interface_t *iface);

private slots:
    /**
     * @brief Handles the acceptance (OK) of the dialog button box.
     */
    void on_buttonBox_accepted();

private:
    Ui::RemoteSettingsDialog *ui; /**< Pointer to the user interface form elements. */
    interface_t mydevice; /**< The local copy of the interface device being configured. */
};
#endif
#endif // REMOTE_SETTINGS_DIALOG_H
