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

class CapturePreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit CapturePreferencesFrame(QWidget *parent = 0);
    ~CapturePreferencesFrame();

protected:
    void showEvent(QShowEvent *evt);

private slots:
    void on_defaultInterfaceComboBox_editTextChanged(const QString &new_iface);
    void on_capturePromModeCheckBox_toggled(bool checked);
    void on_captureMonitorModeCheckBox_toggled(bool checked);
    void on_capturePcapNgCheckBox_toggled(bool checked);
    void on_captureRealTimeCheckBox_toggled(bool checked);
    void on_captureUpdateIntervalLineEdit_textChanged(const QString &new_str);
    void on_captureNoInterfaceLoad_toggled(bool checked);
    void on_captureNoExtcapCheckBox_toggled(bool checked);

private:
    Ui::CapturePreferencesFrame *ui;

    pref_t *pref_device_;
    pref_t *pref_prom_mode_;
    pref_t *pref_monitor_mode_;
    pref_t *pref_pcap_ng_;
    pref_t *pref_real_time_;
    pref_t *pref_update_interval_;
    pref_t *pref_no_interface_load_;
    pref_t *pref_no_extcap_;

    void updateWidgets();
};

#endif // CAPTURE_PREFERENCES_FRAME_H
