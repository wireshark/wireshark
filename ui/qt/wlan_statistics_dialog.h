/* wlan_statistics_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WLANSTATISTICSDIALOG_H
#define WLANSTATISTICSDIALOG_H

#include "tap_parameter_dialog.h"
#include <ui/qt/models/percent_bar_delegate.h>

class QElapsedTimer;

class WlanStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    WlanStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter);
    ~WlanStatisticsDialog();

protected:

private:
    int packet_count_;
    int cur_network_;
    PercentBarDelegate *packets_delegate_, *retry_delegate_;
    QElapsedTimer *add_station_timer_;
    QString displayFilter_;

    // Callbacks for register_tap_listener
    static void tapReset(void *ws_dlg_ptr);
    static tap_packet_status tapPacket(void *ws_dlg_ptr, struct _packet_info *, struct epan_dissect *, const void *wlan_hdr_ptr);
    static void tapDraw(void *ws_dlg_ptr);

    virtual const QString filterExpression();

    // How each item will be exported
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *) const;

private slots:
    virtual void fillTree();
    void addStationTreeItems();
    void updateHeaderLabels();
    void captureFileClosing();
    void filterUpdated(QString filter);
};

#endif // WLANSTATISTICSDIALOG_H

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
