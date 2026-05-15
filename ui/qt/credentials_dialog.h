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
#include <epan/credentials.h>

class CredentialsModel;

namespace Ui {
class CredentialsDialog;
}

/**
 * @brief A dialog for displaying network credentials extracted from the capture file.
 */
class CredentialsDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CredentialsDialog.
     * @param parent The parent widget.
     * @param cf The capture file to extract credentials from.
     * @param packet_list Pointer to the packet list widget.
     */
    explicit CredentialsDialog(QWidget &parent, CaptureFile &cf, PacketList *packet_list);

    /**
     * @brief Destroys the CredentialsDialog.
     */
    ~CredentialsDialog();

private slots:
    /**
     * @brief Slot triggered to navigate to the packet associated with the selected credential.
     * @param idx The model index of the selected credential item.
     */
    void actionGoToPacket(const QModelIndex& idx);

private:
    /** Pointer to the generated UI elements. */
    Ui::CredentialsDialog *ui;

    /** Pointer to the packet list widget for navigation. */
    PacketList *packet_list_;

    /** The model managing the extracted credentials data. */
    CredentialsModel * model_;

    /**
     * @brief Callback function to reset the credentials tap data.
     * @param tapdata Pointer to the tap specific data.
     */
    static void tapReset(void *tapdata);

    /**
     * @brief Callback function for processing packets through the credentials tap.
     * @param tapdata Pointer to the tap specific data.
     * @param pinfo Pointer to the packet information structure.
     * @param edt Pointer to the epan dissection data.
     * @param data Pointer to the protocol-specific tap data.
     * @param flags Tap flags for processing.
     * @return The status of the tap packet processing.
     */
    static tap_packet_status tapPacket(void *tapdata, struct _packet_info *pinfo, struct epan_dissect *edt, const void *data, tap_flags_t flags);
};

#endif // CREDENTIALS_DIALOG_H
