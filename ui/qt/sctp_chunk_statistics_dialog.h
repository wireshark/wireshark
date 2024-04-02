/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_CHUNK_STATISTICS_DIALOG_H
#define SCTP_CHUNK_STATISTICS_DIALOG_H

#include <config.h>

#include <file.h>
#include <wsutil/file_util.h>
#include <epan/dissectors/packet-sctp.h>
#include "epan/packet.h"
#include "epan/value_string.h"
#include <epan/prefs.h>
#include <epan/uat-int.h>
#include <epan/prefs-int.h>
#include <wsutil/filesystem.h>
#include "wireshark_application.h"

#include <QTableWidgetItem>
#include <QDialog>
#include <QMenu>
#include <QContextMenuEvent>

namespace Ui {
class SCTPChunkStatisticsDialog;
}

struct _sctp_assoc_info;

class SCTPChunkStatisticsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCTPChunkStatisticsDialog(QWidget *parent = 0, const _sctp_assoc_info *assoc = NULL, capture_file *cf = NULL);
    ~SCTPChunkStatisticsDialog();

public slots:
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
  //  void on_sectionClicked(int row);
 //   void on_sectionMoved(int logicalIndex, int oldVisualIndex, int newVisualIndex);
    void on_pushButton_clicked();
    void on_actionHideChunkType_triggered();
    void on_actionChunkTypePreferences_triggered();
    void contextMenuEvent(QContextMenuEvent * event);

    void on_actionShowAllChunkTypes_triggered();

signals:
   // void sectionClicked(int);
  //  void sectionMoved(int, int, int);

private:
    Ui::SCTPChunkStatisticsDialog *ui;
    uint16_t selected_assoc_id;
    capture_file *cap_file_;
    QMenu ctx_menu_;
    QPoint selected_point;

    struct chunkTypes {
        int row;
        int id;
        int hide;
        char name[30];
    };

    QMap<int, struct chunkTypes> chunks, tempChunks;

    void initializeChunkMap();
    void fillTable(bool all = false, const _sctp_assoc_info *selected_assoc = NULL);
};

#endif // SCTP_CHUNK_STATISTICS_DIALOG_H
