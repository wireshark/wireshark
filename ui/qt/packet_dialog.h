/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_DIALOG_H
#define PACKET_DIALOG_H

#include "wireshark_dialog.h"

#include "epan/epan_dissect.h"
#include "wiretap/wtap.h"
#include "wsutil/buffer.h"

#include <ui/qt/utils/field_information.h>

class DataSourceTab;
class InPacketFindBar;
class ProtoTree;

namespace Ui {
class PacketDialog;
}

/**
 * @brief Dialog for displaying details of a specific packet.
 */
class PacketDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new PacketDialog object.
     * @param parent The parent widget.
     * @param cf The capture file containing the packet.
     * @param fdata The frame data for the packet to display.
     */
    explicit PacketDialog(QWidget &parent, CaptureFile &cf, frame_data *fdata);

    /**
     * @brief Destroys the PacketDialog object.
     */
    ~PacketDialog();

protected:
    /**
     * @brief Handles the event when the capture file is closing.
     */
    void captureFileClosing();

signals:
    /**
     * @brief Signal emitted to show preferences for a protocol.
     * @param module_name The name of the protocol module.
     */
    void showProtocolPreferences(const QString module_name);

    /**
     * @brief Signal emitted to edit a specific protocol preference.
     * @param pref Pointer to the preference to edit.
     * @param module Pointer to the protocol module containing the preference.
     */
    void editProtocolPreference(pref_t *pref, module_t *module);

private slots:
    /**
     * @brief Handles the event when the help button is clicked in the dialog's button box.
     */
    void on_buttonBox_helpRequested();

#if QT_VERSION >= QT_VERSION_CHECK(6, 7, 0)
    /**
     * @brief Handles changes in the view visibility state.
     * @param state The new check state.
     */
    void viewVisibilityStateChanged(Qt::CheckState state);
#else
    /**
     * @brief Handles changes in the view visibility state.
     * @param state The new state value.
     */
    void viewVisibilityStateChanged(int state);
#endif

    /**
     * @brief Handles changes to the dialog's layout.
     */
    void layoutChanged(int);

    /**
     * @brief Sets the hint text in the status bar based on a field.
     * @param finfo Pointer to the field information to display.
     */
    void setHintText(FieldInformation *finfo);

    /**
     * @brief Sets the hint text for the selected field.
     * @param finfo Pointer to the selected field information.
     */
    void setHintTextSelected(FieldInformation *finfo);

private:
    /** @brief Pointer to the user interface object for this dialog. */
    Ui::PacketDialog *ui;

    /** @brief Layout preference for the packet dialog. */
    pref_t *pref_packet_dialog_layout_;

    /** @brief The column information text for the packet. */
    QString col_info_;

    /** @brief Pointer to the protocol tree representation. */
    ProtoTree *proto_tree_;

    /** @brief The in-packet find bar. */
    InPacketFindBar *in_packet_find_bar_;

    /** @brief Pointer to the data source tab widget. */
    DataSourceTab *data_source_tab_;

    /** @brief The wiretap record containing packet data. */
    wtap_rec rec_;

    /** @brief The epan dissection state for the packet. */
    epan_dissect_t edt_;
};

#endif // PACKET_DIALOG_H