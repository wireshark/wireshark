/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_ASSOC_ANALYSE_DIALOG_H
#define SCTP_ASSOC_ANALYSE_DIALOG_H

#include <config.h>

#include <file.h>

#include <epan/dissectors/packet-sctp.h>

#include "sctp_all_assocs_dialog.h"

#include <QDialog>
#include <QTabWidget>
#include <QObject>
#include <QGridLayout>
#include <QMessageBox>


namespace Ui {
class SCTPAssocAnalyseDialog;
}

struct _sctp_assoc_info;

/**
 * @brief Dialog that presents a detailed analysis of a single SCTP association,
 *        including TSN graphs, byte-throughput graphs, advertised receiver window
 *        (ARWND) graphs, chunk statistics, and display-filter controls.
 */
class SCTPAssocAnalyseDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the SCTP Association Analysis dialog and populates its tabs.
     * @param parent  Optional parent widget.
     * @param assoc   Pointer to the SCTP association to analyse; @c NULL opens an empty dialog.
     * @param cf      Pointer to the capture file providing packet context; @c NULL if unavailable.
     */
    explicit SCTPAssocAnalyseDialog(QWidget *parent = 0,
                                    const _sctp_assoc_info *assoc = NULL,
                                    capture_file *cf = NULL);

    /**
     * @brief Destroys the dialog and frees all owned resources.
     */
    ~SCTPAssocAnalyseDialog();

    /**
     * @brief Populates all analysis tabs with data from @p selected_assoc.
     * @param selected_assoc Pointer to the association whose data fills the tabs.
     */
    void fillTabs(const _sctp_assoc_info *selected_assoc);

    /**
     * @brief Searches the capture file for the SCTP association that owns the
     *        currently selected packet.
     * @param cf Capture file to search.
     * @return Pointer to the matching _sctp_assoc_info, or @c NULL if not found.
     */
    static const _sctp_assoc_info *findAssocForPacket(capture_file *cf);

    /**
     * @brief Looks up an SCTP association by its numeric identifier, showing an
     *        error dialog via @p parent if the ID is not found.
     * @param parent   Widget used as the parent for any error dialogs shown.
     * @param assoc_id Association identifier to search for.
     * @return Pointer to the matching _sctp_assoc_info, or @c NULL if not found.
     */
    static const _sctp_assoc_info *findAssoc(QWidget *parent, uint16_t assoc_id);

public slots:
    /**
     * @brief Updates the capture file pointer used for packet lookups.
     * @param cf New capture file pointer; may be @c NULL when a file is closed.
     */
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    /**
     * @brief Opens the TSN graph for endpoint 2 (the responding side).
     */
    void on_GraphTSN_2_clicked();

    /**
     * @brief Opens the TSN graph for endpoint 1 (the initiating side).
     */
    void on_GraphTSN_1_clicked();

    /**
     * @brief Opens the chunk statistics sub-dialog for the current association.
     */
    void on_chunkStatisticsButton_clicked();

    /**
     * @brief Applies a display filter that isolates packets belonging to the
     *        current association and emits filterPackets() accordingly.
     */
    void on_setFilterButton_clicked();

    /**
     * @brief Opens the byte-throughput graph for endpoint 1.
     */
    void on_GraphBytes_1_clicked();

    /**
     * @brief Opens the byte-throughput graph for endpoint 2.
     */
    void on_GraphBytes_2_clicked();

    /**
     * @brief Opens the ARWND graph for endpoint 1.
     */
    void on_GraphArwnd_1_clicked();

    /**
     * @brief Opens the ARWND graph for endpoint 2.
     */
    void on_GraphArwnd_2_clicked();

private:
    Ui::SCTPAssocAnalyseDialog *ui;           /**< Qt Designer-generated UI object. */
    uint16_t                    selected_assoc_id; /**< Numeric ID of the currently displayed association. */
    capture_file               *cap_file_;    /**< Capture file used for packet-level lookups. */

    /**
     * @brief Opens a TSN graph dialog for the specified endpoint direction.
     * @param direction Endpoint index (1 = initiator, 2 = responder).
     */
    void openGraphDialog(int direction);

    /**
     * @brief Opens a byte-throughput graph dialog for the specified endpoint direction.
     * @param direction Endpoint index (1 = initiator, 2 = responder).
     */
    void openGraphByteDialog(int direction);

    /**
     * @brief Opens an ARWND graph dialog for the specified endpoint direction.
     * @param direction Endpoint index (1 = initiator, 2 = responder).
     */
    void openGraphArwndDialog(int direction);

signals:
    /**
     * @brief Emitted when the dialog requests a display-filter change.
     * @param new_filter The display filter expression to apply.
     * @param force      If @c true, reapply even if the filter string is unchanged.
     */
    void filterPackets(QString new_filter, bool force);
};

#endif // SCTP_ASSOC_ANALYSE_DIALOG_H
