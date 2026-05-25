/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LTE_RLC_GRAPH_DIALOG_H
#define LTE_RLC_GRAPH_DIALOG_H

#include "wireshark_dialog.h"
#include <ui/tap-rlc-graph.h>

#include <ui/qt/widgets/qcustomplot.h>

class QMenu;
class QRubberBand;

namespace Ui {
class LteRlcGraphDialog;
}

/**
 * @brief Dialog for displaying and interacting with LTE RLC graphs.
 */
class LteRlcGraphDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    // TODO: will need to add another constructor option to give channel explicitly,
    // rather than find in currently selected packet, for when launch graph from
    // RLC statistics dialog.

    /**
     * @brief Constructs a new LteRlcGraphDialog.
     * @param parent The parent widget.
     * @param cf The capture file associated with the dialog.
     * @param channelKnown True if the channel is already known, false to derive from the selected packet.
     */
    explicit LteRlcGraphDialog(QWidget &parent, CaptureFile &cf, bool channelKnown);

    /**
     * @brief Destroys the LteRlcGraphDialog.
     */
    ~LteRlcGraphDialog();

    /**
     * @brief Sets the channel information manually.
     * @param rat The Radio Access Technology identifier.
     * @param ueid The User Equipment identifier.
     * @param rlcMode The RLC mode (e.g., AM, UM).
     * @param channelType The type of the channel.
     * @param channelId The identifier for the channel.
     * @param direction The direction of the channel (uplink/downlink).
     * @param maybe_empty True if the channel might be empty, defaults to false.
     */
    void setChannelInfo(uint8_t rat, uint16_t ueid, uint8_t rlcMode,
                        uint16_t channelType, uint16_t channelId, uint8_t direction,
                        bool maybe_empty=false);

signals:
    /**
     * @brief Signal emitted to navigate to a specific packet in the main window.
     * @param packet_num The frame number of the packet to navigate to.
     */
    void goToPacket(int packet_num);

protected:
    /**
     * @brief Handles the event when the dialog is shown.
     * @param event The show event to handle.
     */
    void showEvent(QShowEvent *event) override;

    /**
     * @brief Handles key press events within the dialog.
     * @param event The key press event.
     */
    void keyPressEvent(QKeyEvent *event) override;

private:
    /** Pointer to the generated UI elements. */
    Ui::LteRlcGraphDialog *ui;

    /** Flag indicating whether a mouse drag operation is in progress. */
    bool mouse_drags_;

    /** Pointer to the rubber band widget used for zoom selection. */
    QRubberBand *rubber_band_;

    /** The origin point of the current rubber band selection. */
    QPoint rb_origin_;

    /** Pointer to the context menu. */
    QMenu *ctx_menu_;

    /** Data gleaned directly from tapping packets. */
    struct rlc_graph graph_;

    // Data
    /** Map of timestamps to RLC segments, used for mapping clicks back to a segment/frame. */
    QMultiMap<double, struct rlc_segment *> time_stamp_map_;

    /** Map of sequence numbers to RLC segments. */
    QMap<double, struct rlc_segment *> sequence_num_map_;

    /** Base graph displaying data sequence numbers (clickable packets). */
    QCPGraph *base_graph_;

    /** Graph displaying resegmentation data. */
    QCPGraph *reseg_graph_;

    /** Graph displaying acknowledgments (ACKs). */
    QCPGraph *acks_graph_;

    /** Graph displaying negative acknowledgments (NACKs). */
    QCPGraph *nacks_graph_;

    /** Crosshair tracer for interacting with graph data points. */
    QCPItemTracer *tracer_;

    /** The currently selected or tracked packet number. */
    uint32_t packet_num_;

    /**
     * @brief Completes the setup of the graph.
     * @param may_be_empty True if the graph is permitted to contain no data, defaults to false.
     */
    void completeGraph(bool may_be_empty=false);

    /**
     * @brief Compares headers for a given RLC segment against expected values.
     * @param seg Pointer to the RLC segment to evaluate.
     * @return True if the headers match, false otherwise.
     */
    bool compareHeaders(rlc_segment *seg);

    /**
     * @brief Attempts to find the RLC channel from the currently selected packet.
     * @param may_fail True if failure to find a channel is acceptable, defaults to false.
     */
    void findChannel(bool may_fail=false);

    /**
     * @brief Fills the graph objects with the processed segment data.
     */
    void fillGraph();

    /**
     * @brief Zooms both X and Y axes in or out.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomAxes(bool in);

    /**
     * @brief Zooms only the X axis in or out.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomXAxis(bool in);

    /**
     * @brief Zooms only the Y axis in or out.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomYAxis(bool in);

    /**
     * @brief Pans the graph axes by a specified number of pixels.
     * @param x_pixels Pixels to pan horizontally.
     * @param y_pixels Pixels to pan vertically.
     */
    void panAxes(int x_pixels, int y_pixels);

    /**
     * @brief Calculates the zoom ranges corresponding to a selected rectangle.
     * @param zoom_rect The rectangle selected for zooming.
     * @return The calculated coordinate ranges as a QRectF.
     */
    QRectF getZoomRanges(QRect zoom_rect);

    /**
     * @brief Toggles the visual style of the item tracer.
     * @param force_default True to force the default tracer style, ignoring current state.
     */
    void toggleTracerStyle(bool force_default);

private slots:
    /**
     * @brief Displays the context menu at the specified position.
     * @param pos The position coordinates for the menu.
     */
    void showContextMenu(const QPoint &pos);

    /**
     * @brief Slot triggered when a mouse click occurs on the graph.
     * @param event The mouse event data.
     */
    void graphClicked(QMouseEvent *event);

    /**
     * @brief Slot triggered when the mouse moves over the graph.
     * @param event The mouse event data.
     */
    void mouseMoved(QMouseEvent *event);

    /**
     * @brief Slot triggered when a mouse button is released over the graph.
     * @param event The mouse event data.
     */
    void mouseReleased(QMouseEvent *event);

    /**
     * @brief Resets the graph axes to their default ranges.
     */
    void resetAxes();

    /**
     * @brief Slot triggered when the drag radio button state changes.
     * @param checked True if the drag radio button is checked.
     */
    void on_dragRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the zoom radio button state changes.
     * @param checked True if the zoom radio button is checked.
     */
    void on_zoomRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the reset view button is clicked.
     */
    void on_resetButton_clicked();

    /**
     * @brief Slot triggered when the other direction button is clicked to switch graph direction.
     */
    void on_otherDirectionButton_clicked();

    /**
     * @brief Slot triggered by the reset action.
     */
    void on_actionReset_triggered();

    /**
     * @brief Slot triggered by the zoom in action.
     */
    void on_actionZoomIn_triggered();

    /**
     * @brief Slot triggered by the zoom out action.
     */
    void on_actionZoomOut_triggered();

    /**
     * @brief Slot triggered by the action to move the view up by 10 units.
     */
    void on_actionMoveUp10_triggered();

    /**
     * @brief Slot triggered by the action to move the view left by 10 units.
     */
    void on_actionMoveLeft10_triggered();

    /**
     * @brief Slot triggered by the action to move the view right by 10 units.
     */
    void on_actionMoveRight10_triggered();

    /**
     * @brief Slot triggered by the action to move the view down by 10 units.
     */
    void on_actionMoveDown10_triggered();

    /**
     * @brief Slot triggered by the action to move the view up by 1 unit.
     */
    void on_actionMoveUp1_triggered();

    /**
     * @brief Slot triggered by the action to move the view left by 1 unit.
     */
    void on_actionMoveLeft1_triggered();

    /**
     * @brief Slot triggered by the action to move the view right by 1 unit.
     */
    void on_actionMoveRight1_triggered();

    /**
     * @brief Slot triggered by the action to move the view down by 1 unit.
     */
    void on_actionMoveDown1_triggered();

    /**
     * @brief Slot triggered by the action to switch to drag-zoom mode.
     */
    void on_actionDragZoom_triggered();

    /**
     * @brief Slot triggered by the action to move the view up by 100 units.
     */
    void on_actionMoveUp100_triggered();

    /**
     * @brief Slot triggered by the action to move the view down by 100 units.
     */
    void on_actionMoveDown100_triggered();

    /**
     * @brief Slot triggered by the action to navigate to the selected packet.
     */
    void on_actionGoToPacket_triggered();

    /**
     * @brief Slot triggered by the action to toggle the crosshairs tool.
     */
    void on_actionCrosshairs_triggered();

    /**
     * @brief Slot triggered by the action to switch between uplink and downlink directions.
     */
    void on_actionSwitchDirection_triggered();

    /**
     * @brief Slot triggered when the standard dialog button box is accepted.
     */
    void on_buttonBox_accepted();
};

#endif // LTE_RLC_GRAPH_DIALOG_H
