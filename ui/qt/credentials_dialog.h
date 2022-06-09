/** @file
 *
 * Copyright 2019 - Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CREDENTIALS_DIALOG_H
#define CREDENTIALS_DIALOG_H

#include "config.h"

#include <wireshark_dialog.h>
#include "packet_list.h"
#include <ui/tap-credentials.h>

class CredentialsModel;

namespace Ui {
class CredentialsDialog;
}

class CredentialsDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit CredentialsDialog(QWidget &parent, CaptureFile &cf, PacketList *packet_list);
    ~CredentialsDialog();

private slots:
    void actionGoToPacket(const QModelIndex&);

private:
    Ui::CredentialsDialog *ui;
    PacketList *packet_list_;
    CredentialsModel * model_;

    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, struct _packet_info *pinfo, struct epan_dissect *edt, const void *data, tap_flags_t flags);
};

#endif // CREDENTIALS_DIALOG_H
