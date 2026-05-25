/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SEQUENCE_DIALOG_H
#define SEQUENCE_DIALOG_H

#include <config.h>

#include <epan/cfile.h>

#include "epan/packet.h"
#include "epan/sequence_analysis.h"

#include <ui/qt/widgets/qcustomplot.h>
#include "wireshark_dialog.h"
#include "rtp_stream_dialog.h"

#include <QMenu>

namespace Ui {
class SequenceDialog;
}

class SequenceDiagram;

/**
 * @brief Reference-counted wrapper for sequence analysis information.
 */
class SequenceInfo
{
public:
    /**
     * @brief Constructs a new SequenceInfo object.
     * @param sainfo Pointer to the sequence analysis information.
     */
    SequenceInfo(seq_analysis_info_t *sainfo = NULL);

    /**
     * @brief Retrieves the sequence analysis info structure.
     * @return Pointer to the sequence analysis information.
     */
    seq_analysis_info_t * sainfo() { return sainfo_;}

    /**
     * @brief Increments the reference count.
     */
    void ref() { count_++; }

    /**
     * @brief Decrements the reference count and deletes the object if it reaches zero.
     */
    void unref() { if (--count_ == 0) delete this; }
private:
    /**
     * @brief Destroys the SequenceInfo object.
     */
    ~SequenceInfo();

    /** @brief Pointer to the internal sequence analysis information. */
    seq_analysis_info_t *sainfo_;

    /** @brief Current reference count. */
    unsigned int count_;
};

/**
 * @brief Dialog for displaying and interacting with a sequence diagram (e.g., VoIP call flows).
 */
class SequenceDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new SequenceDialog object.
     * @param parent The parent widget.
     * @param cf The associated capture file.
     * @param info Pointer to the sequence info to display.
     * @param voipFeatures True to enable VoIP-specific features in the dialog.
     */
    explicit SequenceDialog(QWidget &parent, CaptureFile &cf, SequenceInfo *info = NULL, bool voipFeatures = false);

    /**
     * @brief Destroys the SequenceDialog object.
     */
    ~SequenceDialog();

protected:
    /**
     * @brief Handles generic events for the dialog.
     * @param event The event object.
     * @return True if handled, false otherwise.
     */
    bool event(QEvent *event) override;

    /**
     * @brief Handles the show event for the dialog.
     * @param event The show event.
     */
    void showEvent(QShowEvent *event) override;

    /**
     * @brief Handles resize events to adjust diagram layout.
     * @param event The resize event.
     */
    void resizeEvent(QResizeEvent *event) override;

    /**
     * @brief Handles key press events for navigation and zooming.
     * @param event The key press event.
     */
    void keyPressEvent(QKeyEvent *event) override;

signals:
    /**
     * @brief Signal emitted to request selecting specific RTP streams in the stream dialog.
     * @param stream_infos The streams to select.
     */
    void rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *> stream_infos);

    /**
     * @brief Signal emitted to request deselecting specific RTP streams in the stream dialog.
     * @param stream_infos The streams to deselect.
     */
    void rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *> stream_infos);

    /**
     * @brief Signal emitted to request replacing RTP streams in the player dialog.
     * @param stream_ids The streams to replace.
     */
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request adding RTP streams to the player dialog.
     * @param stream_ids The streams to add.
     */
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request removing RTP streams from the player dialog.
     * @param stream_ids The streams to remove.
     */
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);

private slots:
    /**
     * @brief Updates the state and data of the dialog's widgets.
     */
    void updateWidgets() override;

    /**
     * @brief Handles changes to the horizontal scrollbar value.
     * @param value The new scrollbar value.
     */
    void hScrollBarChanged(int value);

    /**
     * @brief Handles changes to the vertical scrollbar value.
     * @param value The new scrollbar value.
     */
    void vScrollBarChanged(int value);

    /**
     * @brief Handles changes to the X-axis range of the diagram.
     * @param range The new axis range.
     */
    void xAxisChanged(QCPRange range);

    /**
     * @brief Handles changes to the Y-axis range of the diagram.
     * @param range The new axis range.
     */
    void yAxisChanged(QCPRange range);

    /**
     * @brief Displays the context menu at the specified position.
     * @param pos The position for the menu.
     */
    void showContextMenu(const QPoint &pos);

    /**
     * @brief Handles clicks within the sequence diagram.
     * @param event The mouse event.
     */
    void diagramClicked(QMouseEvent *event);

    /**
     * @brief Handles double-clicks on the diagram's axes.
     * @param axis The clicked axis.
     * @param part The specific part of the axis clicked.
     * @param event The mouse event.
     */
    void axisDoubleClicked(QCPAxis *axis, QCPAxis::SelectablePart part, QMouseEvent *event);

    /**
     * @brief Handles mouse release events on the diagram.
     * @param event The mouse event.
     */
    void mouseReleased(QMouseEvent *event);

    /**
     * @brief Handles mouse movement over the diagram.
     * @param event The mouse event.
     */
    void mouseMoved(QMouseEvent *event);

    /**
     * @brief Handles mouse wheel events for zooming or scrolling.
     * @param event The wheel event.
     */
    void mouseWheeled(QWheelEvent *event);

    /**
     * @brief Populates the diagram with the sequence analysis data.
     */
    void fillDiagram();

    /**
     * @brief Resets the view of the diagram to its default state.
     */
    void resetView();

    /**
     * @brief Initiates an export of the current diagram diagram to an image or file.
     */
    void exportDiagram();

    /**
     * @brief Calculates and updates the layout of the axis labels.
     */
    void layoutAxisLabels();

    /**
     * @brief Handles changes in the selected address configuration.
     * @param index The new address combo box index.
     */
    void addressChanged(int index);

    /**
     * @brief Handles toggling of the display filter checkbox.
     * @param checked The new checked state.
     */
    void displayFilterCheckBoxToggled(bool checked);

    /**
     * @brief Handles clicks on the main dialog button box.
     * @param button The clicked button.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * @brief Handles the "Go to Packet" action.
     */
    void on_actionGoToPacket_triggered();

    /**
     * @brief Handles navigating to the next packet in the sequence.
     */
    void on_actionGoToNextPacket_triggered() { goToAdjacentPacket(true); }

    /**
     * @brief Handles navigating to the previous packet in the sequence.
     */
    void on_actionGoToPreviousPacket_triggered() { goToAdjacentPacket(false); }

    /**
     * @brief Handles activation of an item in the flow combo box.
     * @param index The index of the activated item.
     */
    void on_flowComboBox_activated(int index);

    /**
     * @brief Handles moving the view right by 10 units.
     */
    void on_actionMoveRight10_triggered();

    /**
     * @brief Handles moving the view left by 10 units.
     */
    void on_actionMoveLeft10_triggered();

    /**
     * @brief Handles moving the view up by 10 units.
     */
    void on_actionMoveUp10_triggered();

    /**
     * @brief Handles moving the view down by 10 units.
     */
    void on_actionMoveDown10_triggered();

    /**
     * @brief Handles moving the view right by 1 unit.
     */
    void on_actionMoveRight1_triggered();

    /**
     * @brief Handles moving the view left by 1 unit.
     */
    void on_actionMoveLeft1_triggered();

    /**
     * @brief Handles moving the view up by 1 unit.
     */
    void on_actionMoveUp1_triggered();

    /**
     * @brief Handles moving the view down by 1 unit.
     */
    void on_actionMoveDown1_triggered();

    /**
     * @brief Handles the "Zoom In" action.
     */
    void on_actionZoomIn_triggered();

    /**
     * @brief Handles the "Zoom Out" action.
     */
    void on_actionZoomOut_triggered();

    /**
     * @brief Handles selecting the related RTP streams.
     */
    void on_actionSelectRtpStreams_triggered();

    /**
     * @brief Handles deselecting the related RTP streams.
     */
    void on_actionDeselectRtpStreams_triggered();

    /**
     * @brief Handles requests for dialog help.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Replaces current RTP streams in the player based on selection.
     */
    void rtpPlayerReplace();

    /**
     * @brief Adds selected RTP streams to the player.
     */
    void rtpPlayerAdd();

    /**
     * @brief Removes selected RTP streams from the player.
     */
    void rtpPlayerRemove();

private:
    /** @brief Pointer to the UI object for this dialog. */
    Ui::SequenceDialog *ui;

    /** @brief The sequence diagram plotting widget. */
    SequenceDiagram *seq_diagram_;

    /** @brief Pointer to the sequence analysis data. */
    SequenceInfo *info_;

    /** @brief Total number of items in the sequence. */
    int num_items_;

    /** @brief Currently selected packet number. */
    uint32_t packet_num_;

    /** @brief The size of one "em" in the current font, used for layout scaling. */
    double one_em_;

    /** @brief The calculated width of the sequence diagram area. */
    int sequence_w_;

    /** @brief Flag indicating if an axis is currently pressed (for panning). */
    bool axis_pressed_;

    /** @brief Button to reset the view. */
    QPushButton *reset_button_;

    /** @brief Button to open or interact with the RTP player. */
    QToolButton *player_button_;

    /** @brief Button to export the diagram. */
    QPushButton *export_button_;

    /** @brief The context menu for the diagram. */
    QMenu ctx_menu_;

    /** @brief Text item displaying the current key/value hovered or selected. */
    QCPItemText *key_text_;

    /** @brief Text item displaying comments. */
    QCPItemText *comment_text_;

    /** @brief Pointer to the currently selected sequence analysis item. */
    seq_analysis_item_t *current_rtp_sai_selected_;     // Used for passing current sai to rtp processing

    /** @brief Pointer to the currently hovered sequence analysis item. */
    seq_analysis_item_t *current_rtp_sai_hovered_;      // Used for passing current sai to rtp processing

    /** @brief Pointer to the RTP stream dialog singleton. */
    QPointer<RtpStreamDialog> rtp_stream_dialog_;       // Singleton pattern used

    /** @brief Flag indicating if VoIP-specific features are enabled. */
    bool voipFeaturesEnabled;

    /**
     * @brief Enables VoIP-specific features in the UI.
     */
    void enableVoIPFeatures();

    /**
     * @brief Zooms the X-axis of the diagram.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomXAxis(bool in);

    /**
     * @brief Pans the axes by the specified pixel amounts.
     * @param x_pixels Pixels to pan horizontally.
     * @param y_pixels Pixels to pan vertically.
     */
    void panAxes(int x_pixels, int y_pixels);

    /**
     * @brief Resets the axes to their default ranges.
     * @param keep_lower True to retain the current lower bound of the Y-axis.
     */
    void resetAxes(bool keep_lower = false);

    /**
     * @brief Navigates to the adjacent packet in the sequence.
     * @param next True to go to the next packet, false for the previous.
     */
    void goToAdjacentPacket(bool next);

    /**
     * @brief Callback function to add a sequence item from the flow analysis.
     * @param key The hash key.
     * @param value The sequence item value.
     * @param userdata User data context.
     * @return True to continue processing, false to stop.
     */
    static bool addFlowSequenceItem(const void *key, void *value, void *userdata);

    /**
     * @brief Processes the RTP stream associated with the current item.
     * @param select True to select the stream, false to deselect.
     */
    void processRtpStream(bool select);

    /**
     * @brief Retrieves the IDs of the currently selected RTP streams.
     * @return A vector of RTP stream IDs.
     */
    QVector<rtpstream_id_t *>getSelectedRtpIds();
};

#endif // SEQUENCE_DIALOG_H
