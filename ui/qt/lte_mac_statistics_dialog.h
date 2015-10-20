/* lte_mac_statistics_dialog.h
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

#ifndef __LTE_MAC_STATISTICS_DIALOG_H__
#define __LTE_MAC_STATISTICS_DIALOG_H__

#include "tap_parameter_dialog.h"

#include <QLabel>
#include <QCheckBox>


// Common channel stats
typedef struct mac_lte_common_stats {
    guint32 all_frames;
    guint32 mib_frames;
    guint32 sib_frames;
    guint32 sib_bytes;
    guint32 pch_frames;
    guint32 pch_bytes;
    guint32 pch_paging_ids;
    guint32 rar_frames;
    guint32 rar_entries;

    guint16  max_ul_ues_in_tti;
    guint16  max_dl_ues_in_tti;
} mac_lte_common_stats;


class LteMacStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    LteMacStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter);
    ~LteMacStatisticsDialog();

protected:

private:
    // Extra controls needed for this dialog.
    QLabel *commonStatsLabel_;
    QCheckBox *showSRFilterCheckBox_;
    QCheckBox *showRACHFilterCheckBox_;

    // Callbacks for register_tap_listener
    static void tapReset(void *ws_dlg_ptr);
    static gboolean tapPacket(void *ws_dlg_ptr, struct _packet_info *, struct epan_dissect *, const void *mac_lte_tap_info_ptr);
    static void tapDraw(void *ws_dlg_ptr);

    virtual const QString filterExpression();

    // Common stats.
    mac_lte_common_stats commonStats_;
    bool commonStatsCurrent_;          // TODO: may not be worth it.
    void updateCommonStats(const struct mac_lte_tap_info *mlt_info);
    void drawCommonStats();
    void clearCommonStats();

    unsigned  getFrameCount();

private slots:
    virtual void fillTree();
    void updateHeaderLabels();
    void captureFileClosing();
};

#endif // __LTE_MAC_STATISTICS_DIALOG_H__

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
