/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIRELESS_FRAME_H
#define WIRELESS_FRAME_H

#include <glib.h>

#include <QFrame>

namespace Ui {
class WirelessFrame;
}

/**
 * @brief Toolbar frame that exposes 802.11 wireless interface controls —
 *        channel, channel type, and FCS settings — for the selected capture
 *        interface during a live capture session.
 */
class WirelessFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the WirelessFrame toolbar.
     * @param parent Optional parent widget.
     */
    explicit WirelessFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the frame and releases interface resources.
     */
    ~WirelessFrame();

    /**
     * @brief Updates widget enabled states based on whether a capture is running.
     * @param capture_in_progress @c true while a live capture is active.
     */
    void setCaptureInProgress(bool capture_in_progress);

signals:
    /**
     * @brief Emitted when the user clicks the preferences button, requesting that
     *        the WLAN preferences page be opened.
     * @param wlan_module_name The preferences module name for the WLAN dissector.
     */
    void showWirelessPreferences(const QString wlan_module_name);

protected:
    /**
     * @brief Polls for interface availability when the interface-detection timer fires.
     * @param event The timer event; checked against iface_timer_id_.
     */
    void timerEvent(QTimerEvent *event) override;

public slots:
    /**
     * @brief Responds to a network interface being added, removed, or brought up/down.
     * @param ifname Name of the interface that changed.
     * @param added  Non-zero if the interface was added; zero if removed.
     * @param up     Non-zero if the interface is now up; zero if down.
     */
    void handleInterfaceEvent(const char *ifname, int added, int up);

private:
    /**
     * @brief Starts a repeating timer with the given interval to poll for interface changes.
     * @param interval Timer interval in milliseconds.
     * @return The timer ID returned by QObject::startTimer().
     */
    int startTimer(int interval);

    /**
     * @brief Queries the currently selected interface for its channel, channel type,
     *        and FCS capabilities and updates the corresponding UI widgets.
     */
    void getInterfaceInfo();

    /**
     * @brief Applies the channel, channel type, and FCS settings shown in the UI
     *        to the currently selected interface.
     */
    void setInterfaceInfo();

    /**
     * @brief Rebuilds the interface combo box from the current list of available
     *        wireless capture interfaces.
     */
    void updateInterfaceList();

private slots:
    /**
     * @brief Refreshes the enabled/disabled state of all child widgets based on
     *        the current interface selection and capture state.
     */
    void updateWidgets();

    /**
     * @brief Opens the wireless helper or extcap helper configuration when the
     *        helper tool button is clicked.
     */
    void on_helperToolButton_clicked();

    /**
     * @brief Emits showWirelessPreferences() when the preferences tool button is clicked.
     */
    void on_prefsToolButton_clicked();

    /**
     * @brief Handles selection of a new wireless interface from the combo box.
     */
    void on_interfaceComboBox_activated(int);

    /**
     * @brief Applies the newly selected channel to the active interface.
     */
    void on_channelComboBox_activated(int);

    /**
     * @brief Applies the newly selected channel type (HT20, HT40, etc.) to the
     *        active interface.
     */
    void on_channelTypeComboBox_activated(int);

    /**
     * @brief Applies the newly selected FCS validation mode to the active interface.
     */
    void on_fcsComboBox_activated(int);

    /**
     * @brief Refreshes the channel-type combo box when the selected channel changes.
     */
    void channelComboBoxIndexChanged(int);

    /**
     * @brief Refreshes the channel combo box when the selected frequency band changes.
     */
    void bandComboBoxIndexChanged(int);

private:
    Ui::WirelessFrame *ui;           /**< Qt Designer-generated UI object. */
    GArray            *interfaces_;  /**< Array of available wireless interface descriptors. */
    bool               capture_in_progress_; /**< @c true while a live capture is running. */
    int                iface_timer_id_;      /**< Timer ID for the interface-polling timer; -1 if not active. */
};

#endif // WIRELESS_FRAME_H
