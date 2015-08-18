/* wlan_statistics_dialog.h
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

#ifndef WLANSTATISTICSDIALOG_H
#define WLANSTATISTICSDIALOG_H

#include "tap_parameter_dialog.h"

class WlanStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    WlanStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter);
    ~WlanStatisticsDialog();

protected:

private:
    int packet_count_;

    // Callbacks for register_tap_listener
    static void tapReset(void *ws_dlg_ptr);
    static gboolean tapPacket(void *ws_dlg_ptr, struct _packet_info *, struct epan_dissect *, const void *wlan_hdr_ptr);
    static void tapDraw(void *ws_dlg_ptr);

    virtual const QString filterExpression();

private slots:
    virtual void fillTree();
    void updateHeaderLabels();
    void captureFileClosing();
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
