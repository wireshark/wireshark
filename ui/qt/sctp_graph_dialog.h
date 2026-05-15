/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_GRAPH_DIALOG_H
#define SCTP_GRAPH_DIALOG_H

#include <config.h>

#include <epan/cfile.h>

#include <QDialog>

namespace Ui {
class SCTPGraphDialog;
}

class QCPAbstractPlottable;
class QCustomPlot;

struct _sctp_assoc_info;

/**
 * @brief SCTP chunk header structure.
 */
struct chunk_header {
    /** Type of the chunk. */
    uint8_t type;
    /** Chunk flags. */
    uint8_t flags;
    /** Length of the chunk. */
    uint16_t length;
};

/**
 * @brief SCTP data chunk header structure.
 */
struct data_chunk_header {
    /** Type of the chunk. */
    uint8_t type;
    /** Chunk flags. */
    uint8_t flags;
    /** Length of the chunk. */
    uint16_t length;
    /** Transmission Sequence Number (TSN). */
    uint32_t tsn;
    /** Stream Identifier. */
    uint16_t sid;
    /** Stream Sequence Number. */
    uint16_t ssn;
    /** Payload Protocol Identifier. */
    uint32_t ppi;
};

/**
 * @brief Gap block structure for SACK and NR-SACK chunks.
 */
struct gaps {
    /** Start of the gap block. */
    uint16_t start;
    /** End of the gap block. */
    uint16_t end;
};

/**
 * @brief SCTP SACK chunk header structure.
 */
struct sack_chunk_header {
    /** Type of the chunk. */
    uint8_t type;
    /** Chunk flags. */
    uint8_t flags;
    /** Length of the chunk. */
    uint16_t length;
    /** Cumulative TSN Ack. */
    uint32_t cum_tsn_ack;
    /** Advertised Receiver Window Credit (a_rwnd). */
    uint32_t a_rwnd;
    /** Number of gap blocks. */
    uint16_t nr_of_gaps;
    /** Number of duplicate TSNs. */
    uint16_t nr_of_dups;
    struct gaps gaps[1]; /**< A Flexible Array Member (standard C, not standard C++) */
    /* Another unnamed FAM of uint32_t for the TSN duplicates follows the first one */
};

/**
 * @brief SCTP NR-SACK chunk header structure.
 */
struct nr_sack_chunk_header {
    /** Type of the chunk. */
    uint8_t type;
    /** Chunk flags. */
    uint8_t flags;
    /** Length of the chunk. */
    uint16_t length;
    /** Cumulative TSN Ack. */
    uint32_t cum_tsn_ack;
    /** Advertised Receiver Window Credit (a_rwnd). */
    uint32_t a_rwnd;
    /** Number of gap blocks. */
    uint16_t nr_of_gaps;
    /** Number of Non-Renegable gap blocks. */
    uint16_t nr_of_nr_gaps;
    /** Number of duplicate TSNs. */
    uint16_t nr_of_dups;
    /** Reserved field. */
    uint16_t reserved;
    struct gaps gaps[1]; /**< A Flexible Array Member (standard C, not standard C++) */
};

/**
 * @brief A dialog for displaying and managing SCTP association graphs.
 */
class SCTPGraphDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new SCTPGraphDialog.
     * @param parent The parent widget, defaults to 0.
     * @param assoc Pointer to the SCTP association info, defaults to NULL.
     * @param cf Pointer to the capture file, defaults to NULL.
     * @param dir The direction of the graph, defaults to 0.
     */
    explicit SCTPGraphDialog(QWidget *parent = 0, const _sctp_assoc_info *assoc = NULL,
            capture_file *cf = NULL, int dir = 0);

    /**
     * @brief Destroys the SCTPGraphDialog.
     */
    ~SCTPGraphDialog();

    /**
     * @brief Saves the displayed graph to a file.
     * @param dlg Pointer to the dialog instance.
     * @param plot Pointer to the custom plot to save.
     */
    static void save_graph(QDialog *dlg, QCustomPlot *plot);

public slots:
    /**
     * @brief Sets the active capture file for the dialog.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    /**
     * @brief Slot triggered when push button 1 is clicked.
     */
    void on_pushButton_clicked();

    /**
     * @brief Slot triggered when push button 2 is clicked.
     */
    void on_pushButton_2_clicked();

    /**
     * @brief Slot triggered when push button 3 is clicked.
     */
    void on_pushButton_3_clicked();

    /**
     * @brief Slot triggered when push button 4 is clicked.
     */
    void on_pushButton_4_clicked();

    /**
     * @brief Slot triggered when the graph is clicked.
     * @param plottable The plottable item that was clicked.
     * @param event The mouse event details.
     */
    void graphClicked(QCPAbstractPlottable* plottable, int, QMouseEvent* event);

    /**
     * @brief Slot triggered when the save button is clicked.
     */
    void on_saveButton_clicked();

    /**
     * @brief Slot triggered when the relative TSN checkbox state changes.
     * @param arg1 The new state of the checkbox.
     */
    void on_relativeTsn_stateChanged(int arg1);

private:
    /** Pointer to the generated UI elements. */
    Ui::SCTPGraphDialog *ui;

    /** The ID of the currently selected association. */
    uint16_t selected_assoc_id;

    /** Pointer to the underlying capture file. */
    capture_file *cap_file_;

    /** The current frame number. */
    int frame_num;

    /** The direction of the traffic being graphed. */
    int direction;

    /** Data points for X and Y axes representing TSNs, SACKs, gaps, duplicates, and NR-SACKs. */
    QVector<double> xt, yt, xs, ys, xg, yg, xd, yd, xn, yn;

    /** Frame numbers corresponding to the data points. */
    QVector<uint32_t> ft, fs, fg, fd, fn;

    /** Strings describing the plot types. */
    QVector<QString> typeStrings;

    /** Flag indicating whether to display relative TSNs. */
    bool relative;

    /** The current type of the graph. */
    int type;

    /**
     * @brief Draws the overall SCTP graph.
     * @param selected_assoc Pointer to the selected association info, defaults to NULL.
     */
    void drawGraph(const _sctp_assoc_info* selected_assoc = NULL);

    /**
     * @brief Draws the TSN graph.
     * @param selected_assoc Pointer to the selected association info.
     */
    void drawTSNGraph(const _sctp_assoc_info* selected_assoc);

    /**
     * @brief Draws the SACK graph.
     * @param selected_assoc Pointer to the selected association info.
     */
    void drawSACKGraph(const _sctp_assoc_info* selected_assoc);

    /**
     * @brief Draws the NR-SACK graph.
     * @param selected_assoc Pointer to the selected association info.
     */
    void drawNRSACKGraph(const _sctp_assoc_info* selected_assoc);
};

#endif // SCTP_GRAPH_DIALOG_H
