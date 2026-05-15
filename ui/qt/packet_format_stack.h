/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef PACKET_FORMAT_STACK_H
#define PACKET_FORMAT_STACK_H

#include "file.h"
#include "ui/file_dialog.h"

#include <QStackedWidget>
#include <QMap>

/**
 * @brief A stacked widget that manages and displays different packet formatting UI elements based on export type.
 */
class PacketFormatStack : public QStackedWidget
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new PacketFormatStack.
     * @param parent The parent widget, defaults to 0.
     */
    explicit PacketFormatStack(QWidget *parent = 0);

    /**
     * @brief Destroys the PacketFormatStack.
     */
    ~PacketFormatStack();

    /**
     * @brief Sets the current export type, updating the displayed stack widget accordingly.
     * @param type The export format type to set.
     */
    void setExportType(export_type_e type);

    /**
     * @brief Checks if the currently selected packet format configuration is valid.
     * @return True if valid, false otherwise.
     */
    bool isValid() const;

    /**
     * @brief Updates the provided print arguments with the user's formatting selections.
     * @param print_args Reference to the print_args_t structure to be updated.
     */
    void updatePrintArgs(print_args_t& print_args);

signals:
    /**
     * @brief Signal emitted when the formatting configuration changes.
     */
    void formatChanged();

private:
    /** Map linking export types to their corresponding index in the stacked widget. */
    QMap<export_type_e, int> export_type_map_;

    /** The stack index corresponding to a blank/empty format view. */
    int blank_idx_;
};

#endif // PACKET_FORMAT_STACK_H
