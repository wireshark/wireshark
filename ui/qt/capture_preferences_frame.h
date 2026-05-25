/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_PREFERENCES_FRAME_H
#define CAPTURE_PREFERENCES_FRAME_H

#include <QFrame>

#include <epan/prefs.h>

namespace Ui {
class CapturePreferencesFrame;
}

/**
 * @brief A frame for configuring and managing capture-related preferences.
 */
class CapturePreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CapturePreferencesFrame.
     * @param parent The parent widget, defaults to 0.
     */
    explicit CapturePreferencesFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the CapturePreferencesFrame.
     */
    ~CapturePreferencesFrame();

protected:
    /**
     * @brief Handles the show event for the frame.
     * @param evt The show event object.
     */
    void showEvent(QShowEvent *evt) override;

private slots:
    /**
     * @brief Slot triggered when the text of the default interface combo box is edited.
     * @param new_iface The new interface string.
     */
    void on_defaultInterfaceComboBox_editTextChanged(const QString &new_iface);

    /**
     * @brief Slot triggered when the promiscuous mode checkbox is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_capturePromModeCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the monitor mode checkbox is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_captureMonitorModeCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the pcapng checkbox is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_capturePcapNgCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the real-time capture checkbox is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_captureRealTimeCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the capture update interval line edit text changes.
     * @param new_str The new update interval string.
     */
    void on_captureUpdateIntervalLineEdit_textChanged(const QString &new_str);

    /**
     * @brief Slot triggered when the disable interface loading checkbox is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_captureNoInterfaceLoad_toggled(bool checked);

    /**
     * @brief Slot triggered when the disable extcap checkbox is toggled.
     * @param checked True if checked, false otherwise.
     */
    void on_captureNoExtcapCheckBox_toggled(bool checked);

private:
    /** Pointer to the generated UI elements. */
    Ui::CapturePreferencesFrame *ui;

    /** Preference setting for the default device. */
    pref_t *pref_device_;

    /** Preference setting for promiscuous mode. */
    pref_t *pref_prom_mode_;

    /** Preference setting for monitor mode. */
    pref_t *pref_monitor_mode_;

    /** Preference setting for pcapng format usage. */
    pref_t *pref_pcap_ng_;

    /** Preference setting for real-time capture display. */
    pref_t *pref_real_time_;

    /** Preference setting for the UI update interval during capture. */
    pref_t *pref_update_interval_;

    /** Preference setting to skip interface loading. */
    pref_t *pref_no_interface_load_;

    /** Preference setting to disable extcap interfaces. */
    pref_t *pref_no_extcap_;

    /**
     * @brief Updates the states of the widgets to match the current preferences.
     */
    void updateWidgets();
};

#endif // CAPTURE_PREFERENCES_FRAME_H
