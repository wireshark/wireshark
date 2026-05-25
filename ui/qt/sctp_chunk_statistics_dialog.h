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
#include <wsutil/value_string.h>
#include <epan/prefs.h>
#include <epan/uat.h>
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

/**
 * @brief A dialog for displaying and managing SCTP chunk statistics.
 */
class SCTPChunkStatisticsDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new SCTPChunkStatisticsDialog.
     * @param parent The parent widget, defaults to 0.
     * @param assoc Pointer to the SCTP association info, defaults to NULL.
     * @param cf Pointer to the capture file, defaults to NULL.
     */
    explicit SCTPChunkStatisticsDialog(QWidget *parent = 0, const _sctp_assoc_info *assoc = NULL, capture_file *cf = NULL);

    /**
     * @brief Destroys the SCTPChunkStatisticsDialog.
     */
    ~SCTPChunkStatisticsDialog();

public slots:
    /**
     * @brief Sets the active capture file for the dialog.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
  //  void on_sectionClicked(int row);
 //   void on_sectionMoved(int logicalIndex, int oldVisualIndex, int newVisualIndex);

    /**
     * @brief Slot triggered when the push button is clicked.
     */
    void on_pushButton_clicked();

    /**
     * @brief Slot triggered to hide a specific chunk type.
     */
    void on_actionHideChunkType_triggered();

    /**
     * @brief Slot triggered to open the chunk type preferences.
     */
    void on_actionChunkTypePreferences_triggered();

    /**
     * @brief Handles context menu events for the dialog.
     * @param event The context menu event details.
     */
    void contextMenuEvent(QContextMenuEvent * event) override;

    /**
     * @brief Slot triggered to show all chunk types in the table.
     */
    void on_actionShowAllChunkTypes_triggered();

signals:
   // void sectionClicked(int);
  //  void sectionMoved(int, int, int);

private:
    /** Pointer to the generated UI elements. */
    Ui::SCTPChunkStatisticsDialog *ui;

    /** The ID of the currently selected association. */
    uint16_t selected_assoc_id;

    /** Pointer to the underlying capture file. */
    capture_file *cap_file_;

    /** Context menu used within the dialog. */
    QMenu ctx_menu_;

    /** The currently selected coordinate point in the UI. */
    QPoint selected_point;

    /**
     * @brief Represents properties of a specific SCTP chunk type.
     */
    struct chunkTypes {
        /** The row index of the chunk type in the table. */
        int row;
        /** The identifier for the chunk type. */
        int id;
        /** Flag indicating whether the chunk type is hidden (non-zero implies hidden). */
        int hide;
        /** The display name of the chunk type. */
        char name[24];
    };

    /** Map of active chunk types by their integer identifier. */
    QMap<int, struct chunkTypes> chunks;

    /** Temporary map of chunk types used during modifications. */
    QMap<int, struct chunkTypes> tempChunks;

    /**
     * @brief Initializes the chunk map with default chunk types.
     */
    void initializeChunkMap();

    /**
     * @brief Fills the statistics table with chunk data.
     * @param all If true, populates the table with all chunks regardless of visibility; defaults to false.
     * @param selected_assoc Pointer to the selected association info, defaults to NULL.
     */
    void fillTable(bool all = false, const _sctp_assoc_info *selected_assoc = NULL);
};

#endif // SCTP_CHUNK_STATISTICS_DIALOG_H
