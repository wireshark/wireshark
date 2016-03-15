/* wireless_frame.h
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

#ifndef WIRELESS_FRAME_H
#define WIRELESS_FRAME_H

#include <glib.h>

#include <QFrame>

namespace Ui {
class WirelessFrame;
}

class WirelessFrame : public QFrame
{
    Q_OBJECT

public:
    explicit WirelessFrame(QWidget *parent = 0);
    ~WirelessFrame();

    void setCaptureInProgress(bool capture_in_progress);

signals:
    void pushAdapterStatus(const QString&);
    void showWirelessPreferences(const QString wlan_module_name);

protected:
    void timerEvent(QTimerEvent *event);

private:
    void getInterfaceInfo();
    void setInterfaceInfo();
    int getCenterFrequency(int control_frequency, int bandwidth);
    int getBandwidthFromChanType(int chan_type);

private slots:
    void updateWidgets();

    void on_helperToolButton_clicked();
    void on_prefsToolButton_clicked();
    void on_interfaceComboBox_activated(int);
    void on_channelComboBox_activated(int);
    void on_channelTypeComboBox_activated(int);
    void on_fcsComboBox_activated(int);

private:
    Ui::WirelessFrame *ui;
    GArray *interfaces_;
    bool capture_in_progress_;
    int iface_timer_id_;
};

#endif // WIRELESS_FRAME_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
