/* lte_rlc_statistics_dialog.h
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

#ifndef __LTE_RLC_STATISTICS_DIALOG_H__
#define __LTE_RLC_STATISTICS_DIALOG_H__

#include "tap_parameter_dialog.h"

#include <QCheckBox>

class LteRlcStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    LteRlcStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter);
    ~LteRlcStatisticsDialog();

    unsigned getFrameCount() { return packet_count_; }
    void     incFrameCount() { ++packet_count_; }

protected:

signals:
    void launchRLCGraph(bool channelKnown,
                        guint16 ueid, guint8 rlcMode,
                        guint16 channelType, guint16 channelId,
                        guint8 direction);

private:
    // Extra controls needed for this dialog.
    QCheckBox *useRLCFramesFromMacCheckBox_;
    QCheckBox *showSRFilterCheckBox_;
    QCheckBox *showRACHFilterCheckBox_;
    QPushButton *launchULGraph_;
    QPushButton *launchDLGraph_;

    CaptureFile &cf_;
    int packet_count_;

    // Callbacks for register_tap_listener
    static void tapReset(void *ws_dlg_ptr);
    static gboolean tapPacket(void *ws_dlg_ptr, struct _packet_info *, struct epan_dissect *, const void *rlc_lte_tap_info_ptr);
    static void tapDraw(void *ws_dlg_ptr);

    void updateHeaderLabels();

    virtual const QString filterExpression();

private slots:
    virtual void fillTree();
    void updateItemSelectionChanged();

    void captureFileClosing();

    void useRLCFramesFromMacCheckBoxToggled(bool state);
    void launchULGraphButtonClicked();
    void launchDLGraphButtonClicked();
};

#endif // __LTE_RLC_STATISTICS_DIALOG_H__

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
