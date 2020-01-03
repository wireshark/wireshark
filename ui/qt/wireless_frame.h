/* wireless_frame.h
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

class WirelessFrame : public QFrame
{
    Q_OBJECT

public:
    explicit WirelessFrame(QWidget *parent = 0);
    ~WirelessFrame();

    void setCaptureInProgress(bool capture_in_progress);

signals:
    void showWirelessPreferences(const QString wlan_module_name);

protected:
    void timerEvent(QTimerEvent *event);

public slots:
    void handleInterfaceEvent(const char *ifname, int added, int up);

private:
    int startTimer(int interval);
    void getInterfaceInfo();
    void setInterfaceInfo();
    int getCenterFrequency(int control_frequency, int bandwidth);
    int getBandwidthFromChanType(int chan_type);
    void updateInterfaceList();

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
