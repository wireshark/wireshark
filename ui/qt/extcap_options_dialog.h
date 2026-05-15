/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef EXTCAP_OPTIONS_DIALOG_H
#define EXTCAP_OPTIONS_DIALOG_H

#include <config.h>

#include <QWidget>
#include <QDialog>
#include <QPushButton>
#include <QList>

#include "ui/qt/extcap_argument.h"

#include <extcap.h>
#include <extcap_parser.h>

namespace Ui {
class ExtcapOptionsDialog;
}

typedef QList<ExtcapArgument *> ExtcapArgumentList;

/**
 * @brief A dialog for configuring extcap device options.
 */
class ExtcapOptionsDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Destroys the ExtcapOptionsDialog.
     */
    ~ExtcapOptionsDialog();

    /**
     * @brief Creates an ExtcapOptionsDialog for a specific device.
     * @param device_name The name of the extcap device.
     * @param startCaptureOnClose True to automatically start the capture when the dialog closes.
     * @param parent The parent widget, defaults to 0.
     * @param option_name Optional pointer to a specific option name to configure.
     * @param option_value Optional pointer to a specific option value to configure.
     * @return A pointer to the created ExtcapOptionsDialog.
     */
    static ExtcapOptionsDialog * createForDevice(QString &device_name, bool startCaptureOnClose, QWidget *parent = 0,
        QString *option_name = NULL, QString *option_value = NULL);

    /**
     * @brief Loads a list of available values for a specific argument.
     * @param argNum The argument number.
     * @param call The call string associated with the argument.
     * @param parent The parent hierarchy string (defaults to an empty string).
     * @return A list of loaded ExtcapValue objects.
     */
    ExtcapValueList loadValuesFor(int argNum, QString call, QString parent = "");

private Q_SLOTS:
    /**
     * @brief Slot triggered when a button in the button box is clicked.
     * @param button The button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Updates the states of dialog widgets based on the current configuration.
     */
    void updateWidgets();

    /**
     * @brief Slot triggered when any extcap argument value changes.
     */
    void anyValueChanged();

private:
    /**
     * @brief Constructs an ExtcapOptionsDialog.
     * @param startCaptureOnClose True to automatically start the capture when the dialog closes.
     * @param parent The parent widget, defaults to 0.
     */
    explicit ExtcapOptionsDialog(bool startCaptureOnClose, QWidget *parent = 0);

    /** Pointer to the generated UI elements. */
    Ui::ExtcapOptionsDialog *ui;

    /** The name of the extcap device. */
    QString device_name;

    /** The option name, if using the UI to edit the config of a sub-argument. */
    QString option_name;  // If using the UI to edit the config of a sub-argument

    /** The option value, if using the UI to edit the config of a sub-argument. */
    QString option_value;  // If using the UI to edit the config of a sub-argument

    /** The internal index of the device. */
    unsigned device_idx;

    /** The icon representing a default value. */
    QIcon defaultValueIcon_;

    /** The list of extcap arguments populated in the dialog. */
    ExtcapArgumentList extcapArguments;

    /**
     * @brief Loads the arguments for the current device and populates the dialog.
     */
    void loadArguments();

    /**
     * @brief Saves the configured options into the capture info structure.
     * @return True if successful, false otherwise.
     */
    bool saveOptionToCaptureInfo();

    /**
     * @brief Retrieves the current argument settings.
     * @param useCallsAsKey True to use call strings as hash keys, otherwise use option names.
     * @param includeEmptyValues True to include empty values in the settings.
     * @return A GHashTable containing the configured argument settings.
     */
    GHashTable * getArgumentSettings(bool useCallsAsKey = false, bool includeEmptyValues = true);

    /**
     * @brief Stores the current argument values persistently.
     */
    void storeValues();

    /**
     * @brief Resets all arguments to their default values.
     */
    void resetValues();

};

#endif // EXTCAP_OPTIONS_DIALOG_H
