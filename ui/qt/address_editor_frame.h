/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ADDRESS_EDITOR_FRAME_H
#define ADDRESS_EDITOR_FRAME_H

#include "accordion_frame.h"

#include "capture_file.h"

#include <ui/qt/utils/field_information.h>
#include <ui/qt/utils/proto_node.h>

namespace Ui {
class AddressEditorFrame;
}

struct epan_column_info;

/**
 * @brief An AccordionFrame for editing user-defined hostname mappings.
 */
class AddressEditorFrame : public AccordionFrame
{
    Q_OBJECT

public:
    /**
     * @brief Construct an AddressEditorFrame.
     * @param parent The parent widget.
     */
    explicit AddressEditorFrame(QWidget *parent = 0);

    /** @brief Destroy the AddressEditorFrame and release its UI resources. */
    ~AddressEditorFrame();

public slots:
    /**
     * @brief Populate the frame with addresses from the selected packet.
     *
     * @param cf     The capture file containing the currently selected packet.
     * @param column Zero-based packet-list column index to pre-select, or
     *               -1 to select the first available address.
     */
    void editAddresses(CaptureFile &cf, int column = -1);

signals:
    /**
     * @brief Emitted when the user clicks the Name Resolution Preferences button.
     * @param module_name The preferences module name to open (e.g. @c "nameres").
     */
    void showNameResolutionPreferences(const QString module_name);

    /**
     * @brief Emitted after a hostname mapping is saved, to trigger a full redissection.
     */
    void redissectPackets();

protected:
    /**
     * @brief Populate widgets with the latest address data when the frame becomes visible.
     * @param event The show event.
     */
    virtual void showEvent(QShowEvent *event) override;

    /**
     * @brief Handle key press events.
     *
     * @param event The key event.
     */
    virtual void keyPressEvent(QKeyEvent *event) override;

private slots:
    /**
     * @brief Restore the previously saved user-defined hostname for the
     * currently selected address into the name line edit.
     */
    void displayPreviousUserDefinedHostname();

    /**
     * @brief Refresh the enabled/disabled state of the button box and
     * other widgets based on the current input.
     */
    void updateWidgets();

    /** @brief Open the Name Resolution preferences page. */
    void on_nameResolutionPreferencesToolButton_clicked();

    /**
     * @brief Update the name line edit when the selected address changes.
     * @param idx The index of the newly selected address in the combo box.
     */
    void on_addressComboBox_currentIndexChanged(int idx);

    /**
     * @brief Refresh widget state when the user edits the hostname field.
     * @param name The current text of the name line edit after the edit.
     */
    void on_nameLineEdit_textEdited(const QString &name);

    /**
     * @brief Save the hostname mapping and emit redissectPackets().
     */
    void on_buttonBox_accepted();

    /** @brief Dismiss the frame without saving any changes. */
    void on_buttonBox_rejected();

private:
    Ui::AddressEditorFrame *ui; /**< Pointer to the UI elements for this frame. */
    capture_file *cap_file_; /**< The capture file whose selected packet supplies addresses. */

    /**
     * @brief Format a FieldInformation address value as a display string.
     * @param finfo The field information containing the address value.
     * @return A human-readable address string (e.g. @c "192.168.1.1").
     */
    static QString addressToString(const FieldInformation &finfo);

    /**
     * @brief Recursively collect all resolvable addresses from a protocol node.
     *
     * @param node      The protocol tree node to inspect.
     * @param addresses The list to which discovered address strings are appended.
     */
    static void addAddresses(const ProtoNode &node, QStringList &addresses);

    /**
     * @brief Test whether a packet-list column contains an address field.
     * @param cinfo  The column information structure for the current packet.
     * @param column Zero-based column index to test.
     * @return true if @p column displays a source or destination address.
     */
    bool isAddressColumn(struct epan_column_info *cinfo, int column);
};

#endif // ADDRESS_EDITOR_FRAME_H
