/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIST_H
#define PACKET_LIST_H

#include "data_source_tab.h"
#include <ui/qt/models/packet_list_model.h>
#include "proto_tree.h"
#include "protocol_preferences_menu.h"
#include <ui/qt/models/related_packet_delegate.h>
#include <ui/qt/models/multi_color_packet_delegate.h>
#include <ui/qt/utils/field_information.h>

#include <QMenu>
#include <QTime>
#include <QTreeView>
#include <QPainter>

class PacketListHeader;
class OverlayScrollBar;
class ProfileSwitcher;

class QAction;
class QTimerEvent;

//
// XXX - Wireshark supports up to 2^32-1 packets in a capture, but
// row numbers in a QAbstractItemModel are ints, not unsigned ints,
// so we can only have 2^31-1 rows on ILP32, LP64, and LLP64 platforms.
// Does that mean we're permanently stuck at a maximum of 2^31-1 packets
// per capture?
//

/**
 * @brief The main packet list view for displaying captured packets.
 */
class PacketList : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new PacketList object.
     * @param parent The parent widget.
     */
    explicit PacketList(QWidget *parent = 0);

    /**
     * @brief Destroys the PacketList object.
     */
    ~PacketList();

    /**
     * @brief Types of formats available for copying packet summaries.
     */
    enum SummaryCopyType {
        /** @brief Copy summary as plain text. */
        CopyAsText,
        /** @brief Copy summary as Comma-Separated Values (CSV). */
        CopyAsCSV,
        /** @brief Copy summary as YAML format. */
        CopyAsYAML,
        /** @brief Copy summary as HTML format. */
        CopyAsHTML
    };
    Q_ENUM(SummaryCopyType)

    /**
     * @brief Scrolls the view to the given index.
     * @param index The model index to scroll to.
     * @param hint The scroll hint to use.
     */
    virtual void scrollTo(const QModelIndex &index, QAbstractItemView::ScrollHint hint = EnsureVisible) override;

    /**
     * @brief Retrieves the conversation menu.
     * @return A pointer to the conversation QMenu.
     */
    QMenu *conversationMenu() { return &conv_menu_; }

    /**
     * @brief Retrieves the colorize menu.
     * @return A pointer to the colorize QMenu.
     */
    QMenu *colorizeMenu() { return &colorize_menu_; }

    /**
     * @brief Sets the protocol tree.
     * @param proto_tree Pointer to the protocol tree.
     */
    void setProtoTree(ProtoTree *proto_tree);

    /**
     * @brief Disable and clear the packet list.
     *
     * @param keep_current_frame If true, keep the selected frame.
     * Disable packet list widget updates, clear the detail and byte views,
     * and disconnect the model.
     * @return True if successfully frozen, false otherwise.
     */
    bool freeze(bool keep_current_frame = false);

    /**
     * @brief Enable and restore the packet list.
     *
     * Enable packet list widget updates and reconnect the model.
     *
     * @param restore_selection If true, redissect the previously selected
     * packet. This includes filling in the detail and byte views.
     * @return True if successfully thawed, false otherwise.
     */
    bool thaw(bool restore_selection = false);

    /**
     * @brief Clears the packet list.
     */
    void clear();

    /**
     * @brief Writes recent configuration to a file.
     * @param rf The file pointer to write to.
     */
    void writeRecent(FILE *rf);

    /**
     * @brief Checks if the context menu is currently active.
     * @return True if active, false otherwise.
     */
    bool contextMenuActive();

    /**
     * @brief Retrieves the filter string based on a given row and column.
     * @param idx The model index indicating the row and column.
     * @return A QString containing the filter.
     */
    QString getFilterFromRowAndColumn(QModelIndex idx);

    /**
     * @brief Resets the colorized state of the packets.
     */
    void resetColorized();

    /**
     * @brief Retrieves the comment for a specific packet.
     * @param c_number The frame number of the packet.
     * @return A QString containing the packet's comment.
     */
    QString getPacketComment(unsigned c_number);

    /**
     * @brief Adds a new comment to the currently selected packet.
     * @param new_comment The comment text to add.
     */
    void addPacketComment(QString new_comment);

    /**
     * @brief Sets the comment for a specific packet.
     * @param c_number The frame number of the packet.
     * @param new_comment The comment text to set.
     */
    void setPacketComment(unsigned c_number, QString new_comment);

    /**
     * @brief Retrieves all packet comments in the capture.
     * @return A QString containing all comments.
     */
    QString allPacketComments();

    /**
     * @brief Deletes comments from the selected packets.
     */
    void deleteCommentsFromPackets();

    /**
     * @brief Deletes all packet comments in the capture.
     */
    void deleteAllPacketComments();

    /**
     * @brief Enables or disables vertical auto-scrolling.
     * @param enabled True to enable auto-scrolling, false to disable.
     */
    void setVerticalAutoScroll(bool enabled = true);

    /**
     * @brief Sets the capture in progress state.
     * @param in_progress True if a capture is running, false otherwise.
     * @param auto_scroll True to enable auto-scrolling during capture.
     */
    void setCaptureInProgress(bool in_progress = false, bool auto_scroll = true) { capture_in_progress_ = in_progress; tail_at_end_ = in_progress && auto_scroll; }

    /**
     * @brief Handles the event when the capture file has finished reading.
     */
    void captureFileReadFinished();

    /**
     * @brief Sets the column delegate for the view.
     */
    void setColumnDelegate();

    /**
     * @brief Resets the columns to their default state.
     */
    void resetColumns();

    /**
     * @brief Checks if there is a next packet in the selection history.
     * @param update_cur True to update the current history pointer.
     * @return True if a next history item exists, false otherwise.
     */
    bool haveNextHistory(bool update_cur = false);

    /**
     * @brief Checks if there is a previous packet in the selection history.
     * @param update_cur True to update the current history pointer.
     * @return True if a previous history item exists, false otherwise.
     */
    bool havePreviousHistory(bool update_cur = false);

    /**
     * @brief Sets the profile switcher for the packet list.
     * @param profile_switcher Pointer to the profile switcher.
     */
    void setProfileSwitcher(ProfileSwitcher *profile_switcher);

    /**
     * @brief Retrieves the frame data for a specific row.
     * @param row The row index.
     * @return Pointer to the frame data.
     */
    frame_data * getFDataForRow(int row) const;

    /**
     * @brief Checks if a single unique selection is currently active.
     * @return True if exactly one item is selected.
     */
    bool uniqueSelectActive();

    /**
     * @brief Checks if multiple selections are currently active.
     * @return True if more than one item is selected.
     */
    bool multiSelectActive();

    /**
     * @brief Retrieves a list of selected row numbers.
     * @param useFrameNum True to return frame numbers instead of row indices.
     * @return A list of integer row or frame numbers.
     */
    QList<int> selectedRows(bool useFrameNum = false);

    /**
     * @brief Creates a summary text for a specific index.
     * @param idx The model index.
     * @param type The format type for the summary.
     * @return A QString containing the formatted summary.
     */
    QString createSummaryText(QModelIndex idx, SummaryCopyType type);

    /**
     * @brief Creates the header summary text.
     * @param type The format type for the summary.
     * @return A QString containing the formatted header.
     */
    QString createHeaderSummaryText(SummaryCopyType type);

    /**
     * @brief Creates string parts for aligned headers.
     * @return A QStringList of header parts.
     */
    QStringList createHeaderPartsForAligned();

    /**
     * @brief Creates alignment parts for formatting.
     * @return A list of alignment sizes.
     */
    QList<int> createAlignmentPartsForAligned();

    /**
     * @brief Creates size parts for aligned formatting.
     * @param useHeader True to include the header in size calculation.
     * @param hdr_parts The header parts.
     * @param rows The list of rows to evaluate.
     * @return A list of sizes.
     */
    QList<int> createSizePartsForAligned(bool useHeader, QStringList hdr_parts, QList<int> rows);

    /**
     * @brief Creates an aligned header summary.
     * @param hdr_parts The header parts.
     * @param align_parts The alignment parts.
     * @param size_parts The size parts.
     * @return A QString containing the aligned header summary.
     */
    QString createHeaderSummaryForAligned(QStringList hdr_parts, QList<int> align_parts, QList<int> size_parts);

    /**
     * @brief Creates an aligned summary for a specific index.
     * @param idx The model index.
     * @param align_parts The alignment parts.
     * @param size_parts The size parts.
     * @return A QString containing the aligned summary.
     */
    QString createSummaryForAligned(QModelIndex idx, QList<int> align_parts, QList<int> size_parts);

    /**
     * @brief Retrieves the default CSS style for HTML summaries.
     * @return A QString containing the style string.
     */
    QString createDefaultStyleForHtml();

    /**
     * @brief Creates the opening tag block for HTML summaries.
     * @return A QString containing HTML opening tags.
     */
    QString createOpeningTagForHtml();

    /**
     * @brief Creates the HTML header summary.
     * @return A QString containing the HTML header row.
     */
    QString createHeaderSummaryForHtml();

    /**
     * @brief Creates an HTML summary for a specific index.
     * @param idx The model index.
     * @return A QString containing the HTML summary row.
     */
    QString createSummaryForHtml(QModelIndex idx);

    /**
     * @brief Creates the closing tag block for HTML summaries.
     * @return A QString containing HTML closing tags.
     */
    QString createClosingTagForHtml();

    /**
     * @brief Resizes all columns to fit their content.
     * @param onlyTimeFormatted True to only resize time-formatted columns.
     */
    void resizeAllColumns(bool onlyTimeFormatted = false);

protected:
    /**
     * @brief Handles selection change events.
     * @param selected The newly selected items.
     * @param deselected The newly deselected items.
     */
    void selectionChanged(const QItemSelection & selected, const QItemSelection & deselected) override;

    /**
     * @brief Handles context menu events.
     * @param event The context menu event.
     */
    virtual void contextMenuEvent(QContextMenuEvent *event) override;

    /**
     * @brief Handles timer events.
     * @param event The timer event.
     */
    void timerEvent(QTimerEvent *event) override;

    /**
     * @brief Handles paint events.
     * @param event The paint event.
     */
    void paintEvent(QPaintEvent *event) override;

    /**
     * @brief Handles mouse press events.
     * @param event The mouse event.
     */
    virtual void mousePressEvent (QMouseEvent *event) override;

    /**
     * @brief Handles mouse release events.
     * @param event The mouse event.
     */
    virtual void mouseReleaseEvent (QMouseEvent *event) override;

    /**
     * @brief Handles mouse move events.
     * @param event The mouse event.
     */
    virtual void mouseMoveEvent (QMouseEvent *event) override;

    /**
     * @brief Handles resize events.
     * @param event The resize event.
     */
    virtual void resizeEvent(QResizeEvent *event) override;

    /**
     * @brief Handles key press events.
     * @param event The key event.
     */
    virtual void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Handles focus in events.
     * @param event The focus event.
     */
    virtual void focusInEvent(QFocusEvent *event) override;

protected slots:
    /**
     * @brief Slot triggered when rows are inserted into the model.
     * @param parent The parent model index.
     * @param start The starting row index.
     * @param end The ending row index.
     */
    void rowsInserted(const QModelIndex &parent, int start, int end) override;

    /**
     * @brief Custom drawing logic for a row.
     * @param painter The painter object.
     * @param option The style option.
     * @param index The model index.
     */
    virtual void drawRow(QPainter *painter, const QStyleOptionViewItem &option,
        const QModelIndex &index) const override;

private:
    /** @brief Pointer to the internal packet list model. */
    PacketListModel *packet_list_model_;

    /** @brief Pointer to the header view of the packet list. */
    PacketListHeader * packet_list_header_;

    /** @brief Pointer to the protocol tree. */
    ProtoTree *proto_tree_;

    /** @brief Pointer to the underlying capture file. */
    capture_file *cap_file_;

    /** @brief The context menu for conversations. */
    QMenu conv_menu_;

    /** @brief The context menu for colorization rules. */
    QMenu colorize_menu_;

    /** @brief Current context column index. */
    int ctx_column_;

    /** @brief Saved column state. */
    QByteArray column_state_;

    /** @brief Pointer to the custom overlay scroll bar. */
    OverlayScrollBar *overlay_sb_;

    /** @brief The timer ID used for overlay operations. */
    int overlay_timer_id_;

    /** @brief Flag for creating near overlays. */
    bool create_near_overlay_;

    /** @brief Flag for creating far overlays. */
    bool create_far_overlay_;

    /** @brief The colors used in the overlay scrollbar. */
    QVector<QRgb> overlay_colors_;

    /** @brief Flag indicating if the profile is currently changing. */
    bool changing_profile_;

    /** @brief Tracks the model index where the mouse was pressed. */
    QModelIndex mouse_pressed_at_;

    /** @brief Delegate responsible for related packet visualization. */
    RelatedPacketDelegate related_packet_delegate_;

    /** @brief Delegate responsible for drawing multi-color packet lines. */
    MultiColorPacketDelegate multi_color_delegate_;

    /** @brief Action to show or hide the column separator. */
    QAction *show_hide_separator_;

    /** @brief List of actions for showing or hiding individual columns. */
    QList<QAction *>show_hide_actions_;

    /** @brief State flag for active packet capture. */
    bool capture_in_progress_;

    /** @brief State flag indicating if auto-scrolling is pinned to the end. */
    bool tail_at_end_;

    /** @brief Flag indicating if columns were changed. */
    bool columns_changed_;

    /** @brief Flag requesting a set column visibility update. */
    bool set_column_visibility_;

    /** @brief Flag requesting a style sheet update. */
    bool set_style_sheet_;

    /** @brief The currently selected row when the list is frozen. */
    QModelIndex frozen_current_row_;

    /** @brief The list of selected rows when the list is frozen. */
    QModelIndexList frozen_selected_rows_;

    /** @brief Array of previously selected row numbers for history navigation. */
    QVector<int> selection_history_;

    /** @brief Current index within the selection history. */
    int cur_history_;

    /** @brief Flag indicating if history traversal is in progress. */
    bool in_history_;

    /** @brief Packet data from the last selected packet entry. */
    GPtrArray *finfo_array;

    /** @brief Pointer to the profile switcher manager. */
    ProfileSwitcher *profile_switcher_;

    /**
     * @brief Sets or unsets a frame as a time reference.
     * @param set True to set as time reference, false to unset.
     * @param fdata Pointer to the frame data.
     */
    void setFrameReftime(bool set, frame_data *fdata);

    /**
     * @brief Updates the visibility of columns.
     */
    void setColumnVisibility();

    /**
     * @brief Applies the recently used width to a specific column.
     * @param column The column index.
     */
    void setRecentColumnWidth(int column);

    /**
     * @brief Forces drawing of the current packet.
     */
    void drawCurrentPacket();

    /**
     * @brief Applies recent widths across all columns.
     */
    void applyRecentColumnWidths();

    /**
     * @brief Handles updates when the scroll view changes.
     * @param at_end True if scrolled to the end of the view.
     */
    void scrollViewChanged(bool at_end);

    /**
     * @brief Joins column parts into a formatted summary row.
     * @param col_parts The list of column text pieces.
     * @param row The row index.
     * @param type The summary format type.
     * @return A QString containing the joined summary.
     */
    QString joinSummaryRow(QStringList col_parts, int row, SummaryCopyType type);

signals:
    /**
     * @brief Signal emitted when packet dissection data changes.
     */
    void packetDissectionChanged();

    /**
     * @brief Signal emitted to show preferences for a specific pane.
     * @param pane_name The name of the preferences pane.
     */
    void showColumnPreferences(QString pane_name);

    /**
     * @brief Signal emitted to trigger editing for a specific column.
     * @param column The column index to edit.
     */
    void editColumn(int column);

    /**
     * @brief Signal emitted when the packet list has been scrolled.
     * @param at_end True if the scroll position is at the very bottom.
     */
    void packetListScrolled(bool at_end);

    /**
     * @brief Signal emitted to show protocol specific preferences.
     * @param module_name The protocol module name.
     */
    void showProtocolPreferences(const QString module_name);

    /**
     * @brief Signal emitted to edit a specific protocol preference.
     * @param pref Pointer to the preference to edit.
     * @param module Pointer to the related module.
     */
    void editProtocolPreference(pref_t *pref, module_t *module);

    /**
     * @brief Signal emitted when multiple frames are selected.
     * @param frames List of selected frame numbers.
     */
    void framesSelected(QList<int> frames);

    /**
     * @brief Signal emitted when a specific field is selected.
     * @param finfo Pointer to the selected field information.
     */
    void fieldSelected(FieldInformation *finfo);

public slots:
    /**
     * @brief Sets the active capture file.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Sets the monospace font used in the list.
     * @param mono_font The chosen monospace font.
     */
    void setMonospaceFont(const QFont &mono_font);

    /**
     * @brief Sets the regular font used in the list.
     * @param regular_font The chosen regular font.
     */
    void setRegularFont(const QFont &regular_font);

    /**
     * @brief Navigates to the next packet.
     */
    void goNextPacket();

    /**
     * @brief Navigates to the previous packet.
     */
    void goPreviousPacket();

    /**
     * @brief Navigates to the very first packet.
     */
    void goFirstPacket();

    /**
     * @brief Navigates to the very last packet.
     */
    void goLastPacket();

    /**
     * @brief Jumps directly to a specific packet number.
     * @param packet The packet number to go to.
     * @param hf_id Optional header field id to highlight.
     */
    void goToPacket(int packet, int hf_id = -1);

    /**
     * @brief Navigates to the next packet in the selection history.
     */
    void goNextHistoryPacket();

    /**
     * @brief Navigates to the previous packet in the selection history.
     */
    void goPreviousHistoryPacket();

    /**
     * @brief Toggles the mark on the currently selected frame.
     */
    void markFrame();

    /**
     * @brief Marks or unmarks all displayed frames.
     * @param set True to mark all, false to unmark all.
     */
    void markAllDisplayedFrames(bool set);

    /**
     * @brief Toggles the ignore status of the currently selected frame.
     */
    void ignoreFrame();

    /**
     * @brief Ignores or un-ignores all displayed frames.
     * @param set True to ignore all, false to un-ignore all.
     */
    void ignoreAllDisplayedFrames(bool set);

    /**
     * @brief Toggles the time reference status on the currently selected frame.
     */
    void setTimeReference();

    /**
     * @brief Unsets all time reference flags on all frames.
     */
    void unsetAllTimeReferences();

    /**
     * @brief Applies a time shift to the capture packets.
     */
    void applyTimeShift();

    /**
     * @brief Recolors the displayed packets based on rules.
     */
    void recolorPackets();

    /**
     * @brief Fully redraws all visible packets.
     */
    void redrawVisiblePackets();

    /**
     * @brief Redraws all visible packets without modifying the current selection.
     */
    void redrawVisiblePacketsDontSelectCurrent();

    /**
     * @brief Slot triggered when global color configurations change.
     */
    void colorsChanged();

    /**
     * @brief Slot triggered when the column configuration changes.
     */
    void columnsChanged();

    /**
     * @brief Slot triggered when global fields configuration changes.
     * @param cf Pointer to the capture file.
     */
    void fieldsChanged(capture_file *cf);

    /**
     * @brief Slot triggered when global preferences have changed.
     */
    void preferencesChanged();

    /**
     * @brief Slot to trigger freezing the packet list state.
     * @param changing_profile True if the freeze is due to a profile change.
     */
    void freezePacketList(bool changing_profile);

private slots:
    /**
     * @brief Slot triggered when a column's visibility action is invoked.
     */
    void columnVisibilityTriggered();

    /**
     * @brief Slot triggered when a header section is resized.
     * @param col The column index.
     * @param new_width The new width.
     */
    void sectionResized(int col, int, int new_width);

    /**
     * @brief Slot triggered when a header section is moved.
     * @param logicalIndex The logical index of the column.
     * @param oldVisualIndex The previous visual index.
     * @param newVisualIndex The new visual index.
     */
    void sectionMoved(int logicalIndex, int oldVisualIndex, int newVisualIndex);

    /**
     * @brief Slot triggered to copy the summary text.
     */
    void copySummary();

    /**
     * @brief Slot triggered by actions on the vertical scroll bar.
     */
    void vScrollBarActionTriggered(int);

    /**
     * @brief Slot to trigger drawing the far overlay.
     */
    void drawFarOverlay();

    /**
     * @brief Slot to trigger drawing the near overlay.
     */
    void drawNearOverlay();

    /**
     * @brief Triggers an update and potential redraw of the packet list.
     * @param redraw True if a full redraw is necessary.
     */
    void updatePackets(bool redraw);

    /**
     * @brief Slot triggered to show the "Decode As" dialog for the context.
     */
    void ctxDecodeAsDialog();
};

#endif // PACKET_LIST_H
