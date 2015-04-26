/* sctp_chunck_statistics_dialog.h
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

#ifndef SCTP_CHUNK_STATISTICS_DIALOG_H
#define SCTP_CHUNK_STATISTICS_DIALOG_H

#include <config.h>
#include <glib.h>

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

#include "ui/tap-sctp-analysis.h"

#include <QTableWidgetItem>
#include <QDialog>
#include <QMenu>
#include <QContextMenuEvent>

namespace Ui {
class SCTPChunkStatisticsDialog;
}

class SCTPChunkStatisticsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCTPChunkStatisticsDialog(QWidget *parent = 0, sctp_assoc_info_t *assoc = NULL, capture_file *cf = NULL);
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
    sctp_assoc_info_t     *selected_assoc;
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
    void fillTable(bool all = false);
};

#endif // SCTP_CHUNK_STATISTICS_DIALOG_H

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
