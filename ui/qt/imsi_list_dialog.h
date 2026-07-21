/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IMSI_LIST_DIALOG_H
#define IMSI_LIST_DIALOG_H

#include <config.h>

#include <epan/cfile.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-e212.h>

#include "wireshark_dialog.h"

#include <QAbstractButton>
#include <QPushButton>
#include <QStandardItemModel>

namespace Ui {
class ImsiListDialog;
}

/**
 * @brief Entry for a single IMSI discovered in the capture.
 */
struct ImsiEntry {
    QString imsi;
    uint32_t packet_count;
    uint32_t first_frame;
    uint32_t last_frame;
    QStringList protocols;
    QSet<uint32_t> seen_frames;  /**< Deduplicate: track frames already counted */
};

/**
 * @brief Dialog for displaying all IMSIs in a capture and filtering by IMSI.
 */
class ImsiListDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ImsiListDialog(QWidget &parent, CaptureFile &cf);
    ~ImsiListDialog();

signals:
    void updateFilter(QString filter, bool force = false);
    void goToPacket(int packet_num);

protected:
    void captureFileClosing() override;

private slots:
    void updateWidgets() override;
    void prepareFilter();
    void onImsiDoubleClicked(const QModelIndex &index);
    void on_buttonBox_clicked(QAbstractButton *button);
    void displayFilterCheckBoxToggled(bool checked);

private:
    Ui::ImsiListDialog *ui;
    QWidget &parent_;

    QPushButton *prepare_button_;

    QStandardItemModel *model_;

    /** Per-IMSI entry data, keyed by IMSI string */
    QHash<QString, ImsiEntry*> imsi_entries_;

    // Tap callbacks
    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, packet_info *pinfo,
                                       epan_dissect_t *edt, const void *data,
                                       tap_flags_t flags);
    static void tapDraw(void *tapdata);

    void resetData();
    void updateModel();
};

#endif // IMSI_LIST_DIALOG_H
