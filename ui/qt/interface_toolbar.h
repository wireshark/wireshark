/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_TOOLBAR_H
#define INTERFACE_TOOLBAR_H

#include "ui/iface_toolbar.h"
#include "funnel_text_dialog.h"
#include "interface_toolbar_reader.h"

#include <QFrame>
#include <QList>
#include <QMap>
#include <QString>


namespace Ui {
class InterfaceToolbar;
}

/**
 * @brief Holds state and values for a specific capture interface's toolbar.
 */
struct interface_values
{
    /** The thread reading from the interface control pipe. */
    QThread *reader_thread;

    /** File descriptor for writing control messages to the interface. */
    int out_fd;

    /** Map of control numbers to their current byte array values. */
    QMap<int, QByteArray> value;

    /** Map tracking whether a specific control's value has changed. */
    QMap<int, bool> value_changed;

    /** Map of control numbers to a list of byte array options (e.g., for selectors). */
    QMap<int, QList<QByteArray> > list;

    /** Map of control numbers to their respective log dialog windows. */
    QMap<int, FunnelTextDialog *> log_dialog;

    /** Map of control numbers to their accumulated log text. */
    QMap<int, QString> log_text;

    /** Map tracking the disabled state of specific control widgets. */
    QMap<int, bool> widget_disabled;
};

/**
 * @brief A toolbar widget dynamically generated for interface-specific controls.
 */
class InterfaceToolbar : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new InterfaceToolbar.
     * @param parent The parent widget, defaults to 0.
     * @param toolbar Pointer to the core iface_toolbar configuration, defaults to NULL.
     */
    explicit InterfaceToolbar(QWidget *parent = 0, const iface_toolbar *toolbar = NULL);

    /**
     * @brief Destroys the InterfaceToolbar.
     */
    ~InterfaceToolbar();

    /**
     * @brief Initializes and starts the capture controls for the given interfaces.
     * @param ifaces Array of interfaces participating in the capture.
     */
    void startCapture(GArray *ifaces);

    /**
     * @brief Stops the capture and disables active controls.
     */
    void stopCapture();

    /**
     * @brief Checks if this toolbar is managing a specific interface.
     * @param ifname The interface name to check.
     * @return True if the interface is managed here, false otherwise.
     */
    bool hasInterface(QString ifname);

public slots:
    /**
     * @brief Slot triggered when the global list of interfaces changes.
     */
    void interfaceListChanged();

    /**
     * @brief Slot triggered when a control message is received from an interface.
     * @param ifname The name of the interface sending the control.
     * @param num The control number.
     * @param command The command type.
     * @param message The payload message.
     */
    void controlReceived(QString ifname, int num, int command, QByteArray message);

signals:
    /**
     * @brief Signal emitted to request the reader threads to close.
     */
    void closeReader();

private slots:
    /** @brief Subscribes to the window's InterfaceListManager::interfaceListChanged. */
    void connectInterfaceListManager();

    /**
     * @brief Starts the background reader thread for a specific interface.
     * @param ifname The name of the interface.
     * @param control_in Pointer to the input control pipe/handle.
     */
    void startReaderThread(QString ifname, void *control_in);

    /**
     * @brief Updates the states of the toolbar widgets based on current values.
     */
    void updateWidgets();

    /**
     * @brief Slot triggered when a standard control button is clicked.
     */
    void onControlButtonClicked();

    /**
     * @brief Slot triggered when a log button is clicked.
     */
    void onLogButtonClicked();

    /**
     * @brief Slot triggered when the help button is clicked.
     */
    void onHelpButtonClicked();

    /**
     * @brief Slot triggered when the restore defaults button is clicked.
     */
    void onRestoreButtonClicked();

    /**
     * @brief Slot triggered when a checkbox state changes.
     * @param state The new state of the checkbox.
     */
    void onCheckBoxChanged(int state);

    /**
     * @brief Slot triggered when a combo box selection changes.
     * @param idx The new index selected.
     */
    void onComboBoxChanged(int idx);

    /**
     * @brief Slot triggered when text in a line edit changes.
     */
    void onLineEditChanged();

    /**
     * @brief Slot triggered to handle closing a log dialog.
     */
    void closeLog();

    /**
     * @brief Slot triggered when the active interface in the combo box changes.
     * @param ifname The newly selected interface name.
     */
    void on_interfacesComboBox_currentTextChanged(const QString &ifname);

private:
    /**
     * @brief Initializes the UI controls based on the provided configuration.
     * @param toolbar The core iface_toolbar configuration.
     */
    void initializeControls(const iface_toolbar *toolbar);

    /**
     * @brief Sets the default value for a specific control.
     * @param num The control number.
     * @param value The default byte array value.
     */
    void setDefaultValue(int num, const QByteArray &value);

    /**
     * @brief Sends all modified values to the specified interface.
     * @param ifname The interface to send values to.
     */
    void sendChangedValues(QString ifname);

    /**
     * @brief Creates a checkbox widget for a boolean control.
     * @param control The interface toolbar control definition.
     * @return A pointer to the created widget.
     */
    QWidget *createCheckbox(iface_toolbar_control *control);

    /**
     * @brief Creates a push button widget for a trigger control.
     * @param control The interface toolbar control definition.
     * @return A pointer to the created widget.
     */
    QWidget *createButton(iface_toolbar_control *control);

    /**
     * @brief Creates a combo box widget for a selection control.
     * @param control The interface toolbar control definition.
     * @return A pointer to the created widget.
     */
    QWidget *createSelector(iface_toolbar_control *control);

    /**
     * @brief Creates a line edit widget for a string control.
     * @param control The interface toolbar control definition.
     * @return A pointer to the created widget.
     */
    QWidget *createString(iface_toolbar_control *control);

    /**
     * @brief Sends a specific control message to an interface.
     * @param ifname The target interface name.
     * @param num The control number.
     * @param type The control type.
     * @param payload The data to send.
     */
    void controlSend(QString ifname, int num, int type, const QByteArray &payload);

    /**
     * @brief Updates a specific widget's value programmatically.
     * @param widget The widget to update.
     * @param type The control type.
     * @param payload The new value data.
     */
    void setWidgetValue(QWidget *widget, int type, QByteArray payload);

    /**
     * @brief Updates the stored value for an interface control and reflects it in the UI.
     * @param ifname The interface name.
     * @param widget The associated widget.
     * @param num The control number.
     * @param type The control type.
     * @param payload The new value data.
     */
    void setInterfaceValue(QString ifname, QWidget *widget, int num, int type, QByteArray payload);

    /** Pointer to the generated UI elements. */
    Ui::InterfaceToolbar *ui;

    /** Map of interface names to their respective state values. */
    QMap<QString, struct interface_values> interface_;

    /** Map tracking the default values for controls by control number. */
    QMap<int, QByteArray> default_value_;

    /** Map tracking default list options for selector controls by control number. */
    QMap<int, QList<QByteArray> > default_list_;

    /** Map tracking the input widgets instantiated for controls. */
    QMap<int, QWidget *> control_widget_;

    /** Map tracking the label widgets instantiated for controls. */
    QMap<int, QWidget *> label_widget_;

    /** The URL or link for help documentation. */
    QString help_link_;

    /** Flag indicating whether a spacer should be used in the toolbar layout. */
    bool use_spacer_;
};

#endif // INTERFACE_TOOLBAR_H
