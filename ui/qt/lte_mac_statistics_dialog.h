/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __LTE_MAC_STATISTICS_DIALOG_H__
#define __LTE_MAC_STATISTICS_DIALOG_H__

#include "tap_parameter_dialog.h"

#include <QLabel>
#include <QCheckBox>

#include <ui/qt/models/percent_bar_delegate.h>

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
    void captureFileClosing();

private:
    // Extra controls needed for this dialog.
    QLabel *commonStatsLabel_;
    QCheckBox *showSRFilterCheckBox_;
    QCheckBox *showRACHFilterCheckBox_;
    PercentBarDelegate *ul_delegate_, *dl_delegate_;
    QString   displayFilter_;

    // Callbacks for register_tap_listener
    static void tapReset(void *ws_dlg_ptr);
    static tap_packet_status tapPacket(void *ws_dlg_ptr, struct _packet_info *, struct epan_dissect *, const void *mac_lte_tap_info_ptr, tap_flags_t flags);
    static void tapDraw(void *ws_dlg_ptr);

    virtual const QString filterExpression();

    // Common stats.
    mac_lte_common_stats commonStats_;
    bool commonStatsCurrent_;          // Set when changes have not yet been drawn
    void updateCommonStats(const struct mac_lte_tap_info *mlt_info);
    void drawCommonStats();
    void clearCommonStats();

    unsigned  getFrameCount();

    QList<QVariant> treeItemData(QTreeWidgetItem *item) const;

private slots:
    virtual void fillTree();
    void updateHeaderLabels();
    void filterUpdated(QString filter);
};

#endif // __LTE_MAC_STATISTICS_DIALOG_H__
