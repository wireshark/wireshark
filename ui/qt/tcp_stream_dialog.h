/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TCP_STREAM_DIALOG_H
#define TCP_STREAM_DIALOG_H

#include <config.h>

#include <file.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/follow.h>
#include <wsutil/str_util.h>

#include "ui/tap-tcp-stream.h"

#include "capture_file.h"
#include "geometry_state_dialog.h"

#include <ui/qt/widgets/qcustomplot.h>
#include <QMenu>
#include <QRubberBand>
#include <QTimer>

namespace Ui {
class TCPStreamDialog;
class QCPErrorBarsNotSelectable;
class DupAckGraph;
}

/**
 * @brief Custom QCPErrorBars class that disables selectability.
 */
class QCPErrorBarsNotSelectable : public QCPErrorBars
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new QCPErrorBarsNotSelectable instance.
     * @param keyAxis The key axis.
     * @param valueAxis The value axis.
     */
    explicit QCPErrorBarsNotSelectable(QCPAxis *keyAxis, QCPAxis *valueAxis);

    /**
     * @brief Destroys the QCPErrorBarsNotSelectable instance.
     */
    virtual ~QCPErrorBarsNotSelectable();

    /**
     * @brief Overrides the selectTest to always return -1, disabling selection.
     * @param pos The position to test.
     * @param onlySelectable Flag indicating if only selectable items should be tested.
     * @param details Optional variant for details.
     * @return -1.0 indicating no selection.
     */
    virtual double selectTest(const QPointF &pos, bool onlySelectable, QVariant *details = 0) const Q_DECL_OVERRIDE;

    /**
     * @brief Draws the legend icon for the error bars.
     * @param painter The QCPPainter to draw with.
     * @param rect The rectangle defining the icon bounds.
     */
    virtual void drawLegendIcon(QCPPainter *painter, const QRectF &rect) const override;
};

/**
 * @brief A custom QCPGraph representing Duplicate ACKs.
 */
class DupAckGraph : public QCPGraph
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DupAckGraph.
     * @param keyAxis The key axis.
     * @param valueAxis The value axis.
     */
    explicit DupAckGraph(QCPAxis *keyAxis, QCPAxis *valueAxis);

    /**
     * @brief Destroys the DupAckGraph.
     */
    virtual ~DupAckGraph();

    /**
     * @brief Draws the legend icon specific to Duplicate ACKs.
     * @param painter The QCPPainter to draw with.
     * @param rect The rectangle defining the icon bounds.
     */
    virtual void drawLegendIcon(QCPPainter *painter, const QRectF &rect) const override;
};

/**
 * @brief A dialog providing various graphical analyses of a TCP stream.
 */
class TCPStreamDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new TCPStreamDialog.
     * @param parent The parent widget.
     * @param cf The capture file containing the TCP stream.
     * @param graph_type The initial type of graph to display.
     */
    explicit TCPStreamDialog(QWidget *parent, const CaptureFile &cf, tcp_graph_type graph_type = GRAPH_TSEQ_TCPTRACE);

    /**
     * @brief Destroys the TCPStreamDialog.
     */
    ~TCPStreamDialog();

signals:
    /**
     * @brief Signal emitted to navigate to a specific packet in the main UI.
     * @param packet_num The target packet number.
     */
    void goToPacket(int packet_num);

public slots:
    /**
     * @brief Triggers an update of the graph data and display.
     */
    void updateGraph();

protected:
    /**
     * @brief Handles the show event for the dialog.
     * @param event The show event object.
     */
    void showEvent(QShowEvent *event);

    /**
     * @brief Handles key press events within the dialog (e.g., zooming/panning shortcuts).
     * @param event The key press event object.
     */
    void keyPressEvent(QKeyEvent *event);

    /**
     * @brief Handles mouse press events on the graph.
     * @param event The mouse press event object.
     */
    void mousePressEvent(QMouseEvent *event);

    /**
     * @brief Handles mouse release events on the graph.
     * @param event The mouse release event object.
     */
    void mouseReleaseEvent(QMouseEvent *event);

private:
    /** Pointer to the generated UI elements. */
    Ui::TCPStreamDialog *ui;

    /** Reference to the underlying capture file. */
    const CaptureFile &cap_file_;

    /** Flag indicating if the capture file has been closed. */
    bool file_closed_;

    /** Flag indicating if a tap operation is currently active. */
    bool tapping_;

    /** Multimap sorting TCP segments by timestamp. */
    QMultiMap<double, struct segment *> time_stamp_map_;

    /** Offset applied to timestamps. */
    double ts_offset_;

    /** Flag indicating if the timestamp origin is the connection start. */
    bool ts_origin_conn_;

    /** Map sorting TCP segments by sequence number. */
    QMap<double, struct segment *> sequence_num_map_;

    /** Offset applied to sequence numbers. */
    uint32_t seq_offset_;

    /** Flag indicating if sequence numbers origin at zero. */
    bool seq_origin_zero_;

    /** Flag indicating whether SI units are used. */
    bool si_units_;

    /** Flag indicating if the graph legend is visible. */
    bool legend_visible_;

    /** Core struct holding the TCP graph data. */
    struct tcp_graph graph_;

    /** Function pointer to get the stream count. */
    follow_stream_count_func get_stream_count_;

    /** The title text element of the graph. */
    QCPTextElement *title_;

    /** String description of the current stream. */
    QString stream_desc_;

    /** Base graph containing clickable packet points. */
    QCPGraph *base_graph_;

    /** Graph displaying throughput. */
    QCPGraph *tput_graph_;

    /** Graph displaying goodput. */
    QCPGraph *goodput_graph_;

    /** Graph displaying segment data. */
    QCPGraph *seg_graph_;

    /** Error bars associated with segment data. */
    QCPErrorBars *seg_eb_;

    /** Graph displaying ACK data. */
    QCPGraph *ack_graph_;

    /** Graph displaying SACK data. */
    QCPGraph *sack_graph_;

    /** Error bars associated with SACK data. */
    QCPErrorBars *sack_eb_;

    /** Secondary graph displaying SACK data. */
    QCPGraph *sack2_graph_;

    /** Secondary error bars associated with SACK data. */
    QCPErrorBars *sack2_eb_;

    /** Graph displaying receive window data. */
    QCPGraph *rwin_graph_;

    /** Graph displaying duplicate ACK data. */
    QCPGraph *dup_ack_graph_;

    /** Graph displaying zero window events. */
    QCPGraph *zero_win_graph_;

    /** Item used to trace values on the graph. */
    QCPItemTracer *tracer_;

    /** Bounding rectangle for the axes. */
    QRectF axis_bounds_;

    /** The currently selected packet number. */
    uint32_t packet_num_;

    /** Transformation matrix for the Y-axis. */
    QTransform y_axis_xfrm_;

    /** Flag indicating if the mouse action is currently dragging. */
    bool mouse_drags_;

    /** Rubber band widget used for zooming. */
    QRubberBand *rubber_band_;

    /** The origin point of the rubber band drag. */
    QPoint rb_origin_;

    /** Context menu for the graph. */
    QMenu ctx_menu_;

    /**
     * @brief Helper class to manage delayed graph updates.
     */
    class GraphUpdater {
    public:
        /**
         * @brief Constructs a new GraphUpdater.
         * @param dialog Pointer to the parent dialog.
         */
        GraphUpdater(TCPStreamDialog *dialog) :
            dialog_(dialog),
            graph_update_timer_(NULL),
            reset_axes_(false) {}

        /**
         * @brief Triggers an update after a specified timeout.
         * @param timeout The timeout in milliseconds.
         * @param reset_axes True if the axes should be reset upon update.
         */
        void triggerUpdate(int timeout, bool reset_axes = false);

        /**
         * @brief Clears any pending scheduled updates.
         */
        void clearPendingUpdate();

        /**
         * @brief Immediately executes the update logic.
         * @param get_count Function to get the stream count.
         */
        void doUpdate(follow_stream_count_func get_count);

        /**
         * @brief Checks if there is a pending update.
         * @return True if an update is scheduled, false otherwise.
         */
        bool hasPendingUpdate() { return graph_update_timer_ != NULL; }
    private:
        TCPStreamDialog *dialog_;
        QTimer *graph_update_timer_;
        bool reset_axes_;
    };
    /** @brief Friend class allowing access to private members. */
    friend class GraphUpdater;

    /** Instance managing delayed graph updates. */
    GraphUpdater graph_updater_;

    /** Number of data segments processed. */
    int num_dsegs_;

    /** Number of ACKs processed. */
    int num_acks_;

    /** Number of SACK ranges processed. */
    int num_sack_ranges_;

    /** Window size for the moving average calculation. */
    double ma_window_size_;

    /** @brief Initializes or discovers the stream data. */
    void findStream();

    /**
     * @brief Populates the graph with data.
     * @param reset_axes True to reset the axes bounds.
     * @param set_focus True to set keyboard focus on the plot.
     */
    void fillGraph(bool reset_axes = true, bool set_focus = true);

    /** @brief Adjusts UI widget visibility based on the selected graph type. */
    void showWidgetsForGraphType();

    /**
     * @brief Zooms both axes in or out.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomAxes(bool in);

    /**
     * @brief Zooms the X-axis in or out.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomXAxis(bool in);

    /**
     * @brief Zooms the Y-axis in or out.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomYAxis(bool in);

    /**
     * @brief Sets the formatting units for a given axis.
     * @param axis The axis to configure.
     * @param units The units format to apply.
     */
    void setAxisUnits(QCPAxis *axis, format_size_units_e units);

    /**
     * @brief Pans the axes by a specific pixel offset.
     * @param x_pixels Horizontal pan amount.
     * @param y_pixels Vertical pan amount.
     */
    void panAxes(int x_pixels, int y_pixels);

    /** @brief Resets the axes to their original bounds. */
    void resetAxes();

    /** @brief Populates the legend with active graph items. */
    void fillLegend();

    /** @brief Moves the legend position based on user interaction or state. */
    void moveLegend();

    /** @brief Toggles the visibility of the legend. */
    void toggleLegend();

    /** @brief Calculates and plots the Stevens-style graph. */
    void fillStevens();

    /** @brief Calculates and plots the tcptrace-style graph. */
    void fillTcptrace();

    /** @brief Calculates and plots the throughput graph. */
    void fillThroughput();

    /** @brief Calculates and plots the round trip time graph. */
    void fillRoundTripTime();

    /** @brief Calculates and plots the window scale graph. */
    void fillWindowScale();

    /**
     * @brief Constructs a descriptive string for the stream.
     * @return The description string.
     */
    QString streamDescription();

    /**
     * @brief Compares headers of a segment against expected values.
     * @param seg The segment to check.
     * @return True if headers match, false otherwise.
     */
    bool compareHeaders(struct segment *seg);

    /**
     * @brief Toggles the visual style of the crosshair tracer.
     * @param force_default True to force the default crosshair style.
     */
    void toggleTracerStyle(bool force_default = false);

    /**
     * @brief Calculates the axis range bounds derived from a pixel rectangle.
     * @param zoom_rect The pixel rectangle defining the zoom area.
     * @return The calculated coordinate ranges.
     */
    QRectF getZoomRanges(QRect zoom_rect);

private slots:
    /**
     * @brief Shows the context menu at the specified position.
     * @param pos The position coordinates.
     */
    void showContextMenu(const QPoint &pos);

    /**
     * @brief Slot triggered when the graph is clicked.
     * @param event The mouse event details.
     */
    void graphClicked(QMouseEvent *event);

    /**
     * @brief Slot triggered when an axis is clicked.
     * @param axis The axis that was clicked.
     * @param part The part of the axis clicked.
     * @param event The mouse event details.
     */
    void axisClicked(QCPAxis *axis, QCPAxis::SelectablePart part, QMouseEvent *event);

    /**
     * @brief Slot triggered during mouse movement over the plot.
     * @param event The mouse event details.
     */
    void mouseMoved(QMouseEvent *event);

    /**
     * @brief Slot triggered when the mouse button is released over the plot.
     * @param event The mouse event details.
     */
    void mouseReleased(QMouseEvent *event);

    /**
     * @brief Slot triggered when a capture event occurs (e.g., file closed).
     * @param e The capture event details.
     */
    void captureEvent(CaptureEvent e);

    /**
     * @brief Transforms and syncs the Y-axis ranges.
     * @param y_range1 The new primary Y-axis range.
     */
    void transformYRange(const QCPRange &y_range1);

    /** @brief Toggles between absolute and scaled units. */
    void toggleUnits();

    /** @brief Slot triggered when the dialog is accepted. */
    void on_buttonBox_accepted();

    /** @brief Slot triggered when the graph type selection changes. */
    void on_graphTypeComboBox_currentIndexChanged(int index);

    /** @brief Slot triggered when the reset button is clicked. */
    void on_resetButton_clicked();

    /** @brief Slot triggered when the stream number spinbox value changes. */
    void on_streamNumberSpinBox_valueChanged(int new_stream);

    /** @brief Slot triggered when editing finishes on the stream number spinbox. */
    void on_streamNumberSpinBox_editingFinished();

    /** @brief Slot triggered when the moving average window size spinbox value changes. */
    void on_maWindowSizeSpinBox_valueChanged(double new_ma_size);

    /** @brief Slot triggered when editing finishes on the moving average window size spinbox. */
    void on_maWindowSizeSpinBox_editingFinished();

    /** @brief Slot triggered when the 'Select SACKs' checkbox state changes. */
    void on_selectSACKsCheckBox_stateChanged(int state);

    /** @brief Slot triggered when the 'Switch Direction' button is clicked. */
    void on_otherDirectionButton_clicked();

    /** @brief Slot triggered when the 'Drag' radio button is toggled. */
    void on_dragRadioButton_toggled(bool checked);

    /** @brief Slot triggered when the 'Zoom' radio button is toggled. */
    void on_zoomRadioButton_toggled(bool checked);

    /** @brief Slot triggered when the 'By Sequence Number' checkbox state changes. */
    void on_bySeqNumberCheckBox_stateChanged(int state);

    /** @brief Slot triggered when the sampling method combo box selection changes. */
    void on_samplingMethodComboBox_currentIndexChanged(int index);

    /** @brief Slot triggered when the 'Show Segment Length' checkbox state changes. */
    void on_showSegLengthCheckBox_stateChanged(int state);

    /** @brief Slot triggered when the 'Show Throughput' checkbox state changes. */
    void on_showThroughputCheckBox_stateChanged(int state);

    /** @brief Slot triggered when the 'Show Goodput' checkbox state changes. */
    void on_showGoodputCheckBox_stateChanged(int state);

    /** @brief Slot triggered when the 'Show Receive Window' checkbox state changes. */
    void on_showRcvWinCheckBox_stateChanged(int state);

    /** @brief Slot triggered when the 'Show Bytes Out' checkbox state changes. */
    void on_showBytesOutCheckBox_stateChanged(int state);

    /** @brief Slot triggered via the action to zoom in overall. */
    void on_actionZoomIn_triggered();

    /** @brief Slot triggered via the action to zoom in horizontally. */
    void on_actionZoomInX_triggered();

    /** @brief Slot triggered via the action to zoom in vertically. */
    void on_actionZoomInY_triggered();

    /** @brief Slot triggered via the action to zoom out overall. */
    void on_actionZoomOut_triggered();

    /** @brief Slot triggered via the action to zoom out horizontally. */
    void on_actionZoomOutX_triggered();

    /** @brief Slot triggered via the action to zoom out vertically. */
    void on_actionZoomOutY_triggered();

    /** @brief Slot triggered via the action to reset the view. */
    void on_actionReset_triggered();

    /** @brief Slot triggered via the action to pan right by 10 units. */
    void on_actionMoveRight10_triggered();

    /** @brief Slot triggered via the action to pan left by 10 units. */
    void on_actionMoveLeft10_triggered();

    /** @brief Slot triggered via the action to pan up by 10 units. */
    void on_actionMoveUp10_triggered();

    /** @brief Slot triggered via the action to pan down by 10 units. */
    void on_actionMoveDown10_triggered();

    /** @brief Slot triggered via the action to pan right by 1 unit. */
    void on_actionMoveRight1_triggered();

    /** @brief Slot triggered via the action to pan left by 1 unit. */
    void on_actionMoveLeft1_triggered();

    /** @brief Slot triggered via the action to pan up by 1 unit. */
    void on_actionMoveUp1_triggered();

    /** @brief Slot triggered via the action to pan down by 1 unit. */
    void on_actionMoveDown1_triggered();

    /** @brief Slot triggered via the action to load the next stream. */
    void on_actionNextStream_triggered();

    /** @brief Slot triggered via the action to load the previous stream. */
    void on_actionPreviousStream_triggered();

    /** @brief Slot triggered via the action to switch the stream direction. */
    void on_actionSwitchDirection_triggered();

    /** @brief Slot triggered via the action to go to the selected packet in the main UI. */
    void on_actionGoToPacket_triggered();

    /** @brief Slot triggered via the action to enable drag/zoom interaction. */
    void on_actionDragZoom_triggered();

    /** @brief Slot triggered via the action to toggle sequence number origin. */
    void on_actionToggleSequenceNumbers_triggered();

    /** @brief Slot triggered via the action to toggle time origin. */
    void on_actionToggleTimeOrigin_triggered();

    /** @brief Slot triggered via the action to display the Round Trip Time graph. */
    void on_actionRoundTripTime_triggered();

    /** @brief Slot triggered via the action to display the Throughput graph. */
    void on_actionThroughput_triggered();

    /** @brief Slot triggered via the action to display the Stevens graph. */
    void on_actionStevens_triggered();

    /** @brief Slot triggered via the action to display the Tcptrace graph. */
    void on_actionTcptrace_triggered();

    /** @brief Slot triggered via the action to display the Window Scaling graph. */
    void on_actionWindowScaling_triggered();

    /** @brief Slot triggered when help is requested from the button box. */
    void on_buttonBox_helpRequested();
};

#endif // TCP_STREAM_DIALOG_H

