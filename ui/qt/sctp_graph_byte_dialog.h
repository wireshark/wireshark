/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_GRAPH_BYTE_DIALOG_H
#define SCTP_GRAPH_BYTE_DIALOG_H

#include <config.h>

#include <epan/cfile.h>

#include <QDialog>

namespace Ui {
class SCTPGraphByteDialog;
}

class QCPAbstractPlottable;

struct _sctp_assoc_info;

/**
 * @brief Dialog that plots cumulative bytes sent over time for a single
 *        direction of an SCTP association.
 */
class SCTPGraphByteDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an SCTPGraphByteDialog and renders the initial bytes graph.
     * @param parent Optional parent widget.
     * @param assoc  SCTP association whose byte data is to be plotted; may be @c NULL.
     * @param cf     Capture file containing the association's packets; may be @c NULL.
     * @param dir    Direction index (0 or 1) selecting which endpoint's byte stream to display.
     */
    explicit SCTPGraphByteDialog(QWidget *parent = 0, const _sctp_assoc_info *assoc = NULL,
            capture_file *cf = NULL, int dir = 0);

    /**
     * @brief Destroys the dialog and releases the associated UI resources.
     */
    ~SCTPGraphByteDialog();

public slots:
    /**
     * @brief Updates the capture file pointer, e.g. after a file is closed or reloaded.
     * @param cf New capture file pointer; may be @c NULL.
     */
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    /**
     * @brief Resets the graph axes to their default zoom and redraws the plot.
     */
    void on_pushButton_4_clicked();

    /**
     * @brief Handles a click on a graph plottable, identifying the nearest data
     *        point and navigating the packet list to the corresponding frame.
     * @param plottable The plottable that was clicked.
     * @param index     Data-point index within the plottable (unused).
     * @param event     The originating mouse event.
     */
    void graphClicked(QCPAbstractPlottable *plottable, int index, QMouseEvent *event);

    /**
     * @brief Opens a file-save dialog and exports the current graph as an image.
     */
    void on_saveButton_clicked();

private:
    Ui::SCTPGraphByteDialog *ui; /**< Qt Designer-generated UI object for this dialog. */
    uint16_t      selected_assoc_id; /**< Association ID of the SCTP association being graphed. */
    capture_file *cap_file_;         /**< Capture file containing the association's packets. */
    int           frame_num;         /**< Frame number of the most recently selected data point. */
    int           direction;         /**< Direction index (0 or 1) whose byte stream is displayed. */
    QVector<double>   xb; /**< X-axis (time) coordinates for each byte-count data point. */
    QVector<double>   yb; /**< Y-axis (cumulative byte count) coordinates for each data point. */
    QVector<uint32_t> fb; /**< Frame numbers corresponding to each data point in @c xb / @c yb. */

    /**
     * @brief Clears the plot and triggers a redraw using the currently selected association.
     */
    void drawGraph();

    /**
     * @brief Populates @c xb, @c yb, and @c fb from @p selected_assoc and plots
     *        the cumulative bytes series on the QCustomPlot widget.
     * @param selected_assoc Association whose byte data should be plotted.
     */
    void drawBytesGraph(const _sctp_assoc_info *selected_assoc);
};

#endif // SCTP_GRAPH_DIALOG_H
