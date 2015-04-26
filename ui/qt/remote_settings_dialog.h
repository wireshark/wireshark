/* remote_settings_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
