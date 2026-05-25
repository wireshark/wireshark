/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_EXTCAP_ARGUMENT_FILE_H_
#define UI_QT_EXTCAP_ARGUMENT_FILE_H_

#include <QObject>
#include <QWidget>
#include <QLineEdit>

#include <extcap_parser.h>
#include <extcap_argument.h>

/**
 * @brief Represents an extcap argument that provides a file selection UI.
 */
class ExtcapArgumentFileSelection : public ExtcapArgument
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtcapArgumentFileSelection.
     * @param argument Pointer to the core extcap_arg structure.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ExtcapArgumentFileSelection(extcap_arg * argument, QObject * parent = Q_NULLPTR);

    /**
     * @brief Destroys the ExtcapArgumentFileSelection.
     */
    virtual ~ExtcapArgumentFileSelection();

    /**
     * @brief Creates the file selection editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created file selection widget.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Retrieves the selected file path.
     * @return The selected file path string.
     */
    virtual QString value() override;

    /**
     * @brief Checks if the current file selection is valid.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid() override;

    /**
     * @brief Sets the file selection to its default value.
     */
    virtual void setDefaultValue() override;

protected:
    /** The line edit widget displaying the selected file path. */
    QLineEdit * textBox;

private slots:
    /**
     * @brief Opens the file dialog.
     */
    void openFileDialog();

    /**
     * @brief Clears the previously entered filename.
     */
    void clearFilename();
};

#endif /* UI_QT_EXTCAP_ARGUMENT_FILE_H_ */
