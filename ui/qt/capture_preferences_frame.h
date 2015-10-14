/* capture_preferences_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CAPTURE_PREFERENCES_FRAME_H
#define CAPTURE_PREFERENCES_FRAME_H

#include "preferences_dialog.h"

#include <QFrame>

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
    void on_capturePcapNgCheckBox_toggled(bool checked);
    void on_captureRealTimeCheckBox_toggled(bool checked);
    void on_captureAutoScrollCheckBox_toggled(bool checked);

private:
    Ui::CapturePreferencesFrame *ui;

    pref_t *pref_device_;
    pref_t *pref_prom_mode_;
    pref_t *pref_pcap_ng_;
    pref_t *pref_real_time_;
    pref_t *pref_auto_scroll_;

    void updateWidgets();
};

#endif // CAPTURE_PREFERENCES_FRAME_H
