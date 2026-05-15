/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RANGE_GROUP_BOX_H
#define PACKET_RANGE_GROUP_BOX_H

#include <config.h>

#include <ui/packet_range.h>

#include <ui/qt/widgets/syntax_line_edit.h>
#include <QGroupBox>

namespace Ui {
class PacketRangeGroupBox;
}

/**
 * @brief UI element for controlling a range selection. The range provided in
 * "initRange" is not owned by this class but will be modified.
 */
class PacketRangeGroupBox : public QGroupBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new PacketRangeGroupBox object.
     * @param parent The parent widget.
     */
    explicit PacketRangeGroupBox(QWidget *parent = 0);

    /**
     * @brief Destroys the PacketRangeGroupBox object.
     */
    ~PacketRangeGroupBox();

    /**
     * @brief Initializes the packet range and selection string.
     * @param range Pointer to the packet range structure to modify.
     * @param selRange The initial selection range string.
     */
    void initRange(packet_range_t *range, QString selRange = QString());

    /**
     * @brief Checks if the current range selection is valid.
     * @return True if the range is valid, false otherwise.
     */
    bool isValid();

signals:
    /**
     * @brief Signal emitted when the validity of the range changes.
     * @param is_valid True if the range became valid, false if invalid.
     */
    void validityChanged(bool is_valid);

    /**
     * @brief Signal emitted when the range selection changes.
     */
    void rangeChanged();

private:
    /**
     * @brief Updates the internal packet counts based on the current range.
     */
    void updateCounts();

    /**
     * @brief Processes toggled state for a specific range selection button.
     * @param checked True if the button is checked, false otherwise.
     * @param process The packet range processing mode associated with the button.
     */
    void processButtonToggled(bool checked, packet_range_e process);

    /** @brief Pointer to the user interface object for this group box. */
    Ui::PacketRangeGroupBox *pr_ui_;

    /** @brief Pointer to the packet range structure being modified. */
    packet_range_t *range_;

    /** @brief The current syntax state of the range line edit. */
    SyntaxLineEdit::SyntaxState syntax_state_;

private slots:
    /**
     * @brief Handles the event when the text in the range line edit changes.
     * @param range_str The new range string.
     */
    void on_rangeLineEdit_textChanged(const QString &range_str);

    /**
     * @brief Handles the event when the "All packets" button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_allButton_toggled(bool checked);

    /**
     * @brief Handles the event when the "Selected packet" button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_selectedButton_toggled(bool checked);

    /**
     * @brief Handles the event when the "Marked packets" button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_markedButton_toggled(bool checked);

    /**
     * @brief Handles the event when the "First to last marked" button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_ftlMarkedButton_toggled(bool checked);

    /**
     * @brief Handles the event when the "Specify a packet range" button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_rangeButton_toggled(bool checked);

    /**
     * @brief Handles the event when the "Captured" radio button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_capturedButton_toggled(bool checked);

    /**
     * @brief Handles the event when the "Displayed" radio button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_displayedButton_toggled(bool checked);

    /**
     * @brief Handles the event when the "Ignored packets" check box is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_ignoredCheckBox_toggled(bool checked);

    /**
     * @brief Handles the event when the "Dependent packets" check box is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_dependedCheckBox_toggled(bool checked);
};

#endif // PACKET_RANGE_GROUP_BOX_H
