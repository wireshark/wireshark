/* remote_settings_dialog.h
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
#include "capture_opts.h"

namespace Ui {
class RemoteSettingsDialog;
}

class RemoteSettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RemoteSettingsDialog(QWidget *parent = 0, interface_t *iface = NULL);
    ~RemoteSettingsDialog();

signals:
    void remoteSettingsChanged(interface_t *iface);

private slots:
    void on_buttonBox_accepted();

private:
    Ui::RemoteSettingsDialog *ui;
    interface_t mydevice;
};
#endif
#endif // REMOTE_SETTINGS_DIALOG_H
