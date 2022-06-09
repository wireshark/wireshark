/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    void captureFileClosing();

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
    QString     displayFilter_;

    CaptureFile &cf_;
    int packet_count_;

    // Callbacks for register_tap_listener
    static void tapReset(void *ws_dlg_ptr);
    static tap_packet_status tapPacket(void *ws_dlg_ptr, struct _packet_info *, struct epan_dissect *, const void *rlc_lte_tap_info_ptr, tap_flags_t flags);
    static void tapDraw(void *ws_dlg_ptr);

    void updateHeaderLabels();

    virtual const QString filterExpression();

    QList<QVariant> treeItemData(QTreeWidgetItem *item) const;

private slots:
    virtual void fillTree();
    void updateItemSelectionChanged();

    void useRLCFramesFromMacCheckBoxToggled(bool state);
    void launchULGraphButtonClicked();
    void launchDLGraphButtonClicked();
    void filterUpdated(QString filter);
};

#endif // __LTE_RLC_STATISTICS_DIALOG_H__
