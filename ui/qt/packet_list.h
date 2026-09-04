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
#include <ui/qt/widgets/pinned_column_view.h>
#include <ui/qt/widgets/pinned_row_view.h>
#include <ui/qt/models/pinned_rows_model.h>

#include <QElapsedTimer>
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
     * @brief Updates the visibility of columns, including propagating
     * global column-hidden state to the pinned-column/pinned-row overlay
     * views (which PacketListHeader::columnVisibilityTriggered() needs to
     * do explicitly, since toggling a column's checkbox there only ever
     * hides that section on the real header itself).
     */
    void setColumnVisibility();

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

    /**
     * @brief Pins a packet's row so that it stays visible (stacked with
     * any other pinned rows, ordered to match the active sort) while the
     * view is scrolled vertically. Up to PinnedRowsModel::kMaxPinnedRows
     * packets may be pinned at once; additional pins beyond that are
     * ignored.
     * @param frame_num The frame number of the packet to pin.
     */
    void pinRow(int frame_num);

    /**
     * @brief Unpins a single packet's row, if pinned.
     * @param frame_num The frame number of the packet to unpin.
     */
    void unpinRow(int frame_num);

    // Unpins every currently pinned packet's row.
    void unpinAllRows();

    /**
     * @brief The height of a single row in this view, for sizing the
     * pinned-row strip to exactly N rows (see PinnedRowView::sizeHint()).
     *
     * Deliberately queried from this view rather than from the
     * (separately laid-out) PinnedRowView itself: sizeHintForRow() only
     * returns a real answer once a view has actually laid out that row,
     * and the pinned-row views start hidden and may still have an empty
     * model the first time a row is pinned, whereas this primary view is
     * already showing real rows by the time there's anything to pin at
     * all.
     * @return The row height in pixels, or a small fallback if no rows
     * have been laid out yet.
     */
    int pinnedRowHeight() const;

    /**
     * @brief Freezes the leftmost columns so they stay visible while the
     * view is scrolled horizontally.
     * @param column_count Number of leftmost columns to freeze; 0 clears it.
     */
    void setPinnedColumnBoundary(int column_count);

    /**
     * @brief The current frozen-column boundary (see
     * setPinnedColumnBoundary()), for callers that need the current value
     * rather than reacting to pinnedColumnBoundaryChanged() -- e.g.
     * PacketListPane resyncing its duplicate header pair's frozen/
     * non-frozen column split right before showing it, which may need to
     * reflect a boundary set well before anything was ever pinned.
     * @return Number of leftmost columns currently frozen, or 0.
     */
    int pinnedColumnBoundary() const { return pinned_column_boundary_; }

    /**
     * @brief The single shared definition of "column i is frozen" given a
     * frozen-column boundary, used everywhere that rule needs to be
     * applied (this class and PacketListPane, which splits its duplicate
     * header pair the same way) so the rule itself only has one place to
     * change.
     */
    static bool isColumnFrozen(int column, int boundary) { return column < boundary; }

    /**
     * @brief Supplies the pinned-row-strip overlay views for this view to
     * manage the content/properties of (model, column widths, styles,
     * fonts, delegates, column visibility). The views themselves are
     * owned and positioned by the owning PacketListPane, which
     * constructs them as siblings of this view in a normal layout above
     * it -- QTreeView reserves viewport space for its own header
     * internally and reasserts that reservation on every geometry pass,
     * so this content couldn't be reserved space as overlay children of
     * PacketList itself via setViewportMargins()/setGeometry().
     * @param row_view The overlay view showing pinned rows' non-frozen columns.
     * @param corner_view The overlay view showing pinned rows' frozen columns.
     */
    void setPinnedRowViews(PinnedRowView *row_view, PinnedRowView *corner_view);

    /**
     * @brief Selects/marks a row as if the user had clicked it directly in
     * this view, given a row already resolved by the overlay view's own
     * (always-correct, since it's local) indexAt(). Avoids translating
     * pixel coordinates between two independently laid-out QTreeViews,
     * whose row geometry can drift by a row even when visually aligned.
     * @param row The row index (in this view's current row numbering).
     * @param column The column that was clicked, for consistency with a
     * direct click (used e.g. for context/copy actions).
     * @param buttons The mouse buttons held during the press.
     */
    void selectRowFromOverlay(int row, int column, Qt::MouseButtons buttons);

    /**
     * @brief Same as selectRowFromOverlay(), but given a frame/packet
     * number directly rather than a row in this view's own model.
     *
     * Used by PinnedRowView for a pinned packet that's been filtered out
     * of the primary view entirely: such a packet has no row here at
     * all, so model()->index(row, column) (what selectRowFromOverlay()
     * uses) can never resolve to it. Selection itself is not actually a
     * QModelIndex-level concept underneath -- cf_select_packet() takes a
     * frame_data* directly and works purely against the capture file's
     * own frame array, independent of the display filter -- so this
     * bypasses the model entirely and drives that directly, then emits
     * framesSelected() the same way selectionChanged() normally would.
     * @param frame_num The frame/packet number to select.
     */
    void selectFrameFromOverlay(int frame_num);

    /**
     * @brief Shows this view's context menu for a row already resolved by
     * an overlay view's own indexAt(), rather than translating pixel
     * coordinates across views (see selectRowFromOverlay()).
     * @param row The row index (in this view's current row numbering).
     * @param global_pos Where to actually pop up the menu on screen.
     * @param from_pinned_row_strip Whether this request originated from
     * the pinned-row strip (PinnedRowView) specifically, rather than the
     * frozen-column overlay (PinnedColumnView) or the primary view --
     * used to show "Unpin All Rows" only there.
     */
    void showContextMenuForRow(int row, const QPoint &global_pos, bool from_pinned_row_strip = false);

    /**
     * @brief Same as showContextMenuForRow(), but given a frame/packet
     * number directly for a pinned packet that's been filtered out of
     * the primary view (see selectFrameFromOverlay() for why a row-based
     * lookup can't reach it).
     * @param frame_num The frame/packet number to show the menu for.
     * @param global_pos Where to actually pop up the menu on screen.
     * @param from_pinned_row_strip See showContextMenuForRow(); always
     * true in practice for this overload, since only PinnedRowView (never
     * PinnedColumnView) ever needs the frame-number-based path (see its
     * own comment for why).
     */
    void showContextMenuForFrame(int frame_num, const QPoint &global_pos, bool from_pinned_row_strip = true);

    /**
     * @brief Translates a position local to the pinned column view's own
     * header (PinnedColumnHeader, which never scrolls and always shows
     * frozen columns at their unscrolled logical positions) into the
     * equivalent position in this view's real header's own coordinate
     * space, which does scroll horizontally. Used by PinnedColumnHeader
     * before calling any of the forwardHeader*() methods below, all of
     * which require header_pos already in the real header's space.
     */
    QPoint frozenHeaderPosToReal(const QPoint &frozen_pos) const;

    /**
     * @brief Forwards a header context menu request from the pinned
     * column view's own header.
     * @param event The original context menu event.
     * @param header_pos The equivalent position in this view's header.
     */
    void forwardHeaderContextMenu(QContextMenuEvent *event, const QPoint &header_pos);

    /**
     * @brief Forwards a header mouse press (used for resize dragging) from
     * the pinned column view's own header to this view's real header.
     */
    void forwardHeaderMousePress(QMouseEvent *event, const QPoint &header_pos);

    // Forwards a header mouse move (used for resize dragging).
    void forwardHeaderMouseMove(QMouseEvent *event, const QPoint &header_pos);

    // Forwards a header mouse release (used for resize dragging).
    void forwardHeaderMouseRelease(QMouseEvent *event, const QPoint &header_pos);

    /**
     * @brief Sorts by the given column as if its header section had been
     * clicked directly, toggling order if it's already the sorted column.
     * Used because a plain click on the pinned column view's own header
     * doesn't reliably trigger QHeaderView's built-in click-to-sort
     * machinery once its press/release events are being forwarded here
     * for resize-drag support.
     * @param column The logical column index that was clicked.
     */
    void sortByColumnFromOverlay(int column);

    /**
     * @brief Forwards a wheel scroll event from a pinned overlay view so
     * scrolling stays perfectly in sync with the primary view.
     */
    void forwardWheelEvent(QWheelEvent *event);

    /**
     * @brief Updates which row is considered "hovered" from a pinned
     * overlay view's own mouse-move event, so the hover highlight shows
     * across the whole logical row (both frozen and non-frozen panes)
     * rather than only in whichever pane the mouse happens to be over.
     * @param row The row index (in this view's current row numbering)
     * under the mouse in the overlay view, or -1 if the mouse left it.
     */
    void setHoveredRowFromOverlay(int row);

    /**
     * @brief Same as setHoveredRowFromOverlay(), but given the frame
     * number directly rather than a row to resolve via getFDataForRow().
     *
     * Used by PinnedRowView, whose rows can represent a pinned packet
     * that's been filtered out of the primary view entirely -- such a
     * packet has no row there at all, so a row-based lookup can never
     * resolve to it (getFDataForRow() only searches visible rows), even
     * though the frame number to highlight is already known directly
     * from PinnedRowView's own model index.
     * @param frame_num The frame number to mark as hovered, or -1 for none.
     */
    void setHoveredFrameNum(int frame_num);

    /**
     * @brief The frame number of the row currently tracked as hovered
     * across all panes, or -1 if none. Used by the pinned overlay views'
     * drawRow() overrides to manually paint the hover highlight, since
     * Qt's native per-widget hover state doesn't span separate widgets.
     */
    int hoveredFrameNum() const { return hovered_frame_num_; }

    /**
     * @brief The frame number of the currently selected packet, or -1 if
     * none. Reflects cap_file_->current_frame, which cf_select_packet()
     * keeps correct regardless of whether the selection was made through
     * a normal click (a row in this view's own model) or through
     * selectFrameFromOverlay() (a pinned packet with no row here at all,
     * e.g. filtered out) -- unlike selectedRows(), which can only ever
     * list rows that exist in this view's own model, and so comes back
     * empty for the latter case even though a packet really is selected.
     * Used by PinnedRowView::drawRow() so the pinned strip's own
     * selection highlight tracks the real selection in both cases.
     */
    int currentFrameNum() const;

protected:
    /**
     * @brief Handles window-activation changes.
     *
     * Qt's :active/:!active stylesheet pseudo-states resolve per-widget
     * based on which widget currently has focus, which doesn't track
     * cleanly across the pinned overlay views (separate QTreeView
     * instances). Instead, this view's own window-active state is applied
     * to all of them directly whenever it changes.
     */
    virtual void changeEvent(QEvent *event) override;

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
     * @brief Clears the tracked hover row when the mouse leaves this view
     * (and, by extension, all pinned overlay views showing the same row).
     */
    virtual void leaveEvent(QEvent *event) override;

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
     * @brief Handles key release events.
     * @param event The key event.
     */
    virtual void keyReleaseEvent(QKeyEvent *event) override;

    /**
     * @brief Handles focus in events.
     * @param event The focus event.
     */
    virtual void focusInEvent(QFocusEvent *event) override;

    /**
     * @brief Handles focus out events. Needed to stops turbo mode
     * navigation if we lose focus.
     * @param event The focus event.
     */
    virtual void focusOutEvent(QFocusEvent *event) override;

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

    /** @brief Whether the context menu currently being built was
     * requested from the pinned-row strip specifically (see
     * showContextMenuForRow()'s own comment), so contextMenuEvent() can
     * show "Unpin All Rows" only there. Set just before contextMenuEvent()
     * runs by showContextMenuForRow()/showContextMenuForFrame(); a direct
     * right-click on the primary view bypasses both and goes straight to
     * contextMenuEvent(), so this is reset to false at the top of that
     * function to avoid leaking a stale true from a previous overlay
     * invocation. */
    bool ctx_from_pinned_row_strip_;

    /** @brief Saved column state. */
    QByteArray column_state_;

    /** @brief Pointer to the custom overlay scroll bar. */
    OverlayScrollBar *overlay_sb_;

    /** @brief The timer ID used for overlay operations. */
    int overlay_timer_id_;

    /** @brief The timer ID used for turbo mode autorepeat. */
    int turbo_timer_id_;

    /** @brief The key that turbo mode is repeating (Qt::Key_Down or Qt::Key_Up). */
    Qt::Key turbo_key_;

    /** @brief The Down/Up key currently being held down (via a non-autorepeat press with no release yet), or 0 if neither is held. */
    Qt::Key held_key_;

    /** @brief Time elapsed since held_key_ was first pressed. Used to activate turbo mode. */
    QElapsedTimer key_hold_elapsed_;

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

    /** @brief Proxy model exposing only the pinned packets, in pin order,
     * for the pinned-row overlay views. */
    PinnedRowsModel *pinned_rows_model_;

    // Number of leftmost columns currently frozen/pinned, or 0.
    int pinned_column_boundary_;

    // Overlay view showing the frozen leftmost columns for all rows.
    PinnedColumnView *pinned_column_view_;

    /** @brief pinned_column_view_'s viewport size as of the last
     * layoutPinnedOverlays() call that actually resized it, so a plain
     * column-width change (which alone doesn't change its vertical scroll
     * range) can skip the relayout that setGeometry() alone doesn't need --
     * see layoutPinnedOverlays()'s own comment. */
    QSize pinned_column_view_size_;

    // Overlay view showing the pinned row's non-frozen columns.
    PinnedRowView *pinned_row_view_;

    // Overlay view showing the pinned row's frozen columns (the "corner").
    PinnedRowView *pinned_row_corner_view_;

    // Cached selection stylesheet for the overlay views when this window is active.
    QString overlay_active_flat_style_;

    // Cached selection stylesheet for the overlay views when this window is inactive.
    QString overlay_inactive_flat_style_;

    /**
     * @brief Frame number of the row currently under the mouse, tracked
     * centrally (rather than relying on each view's own native hover
     * detection) so the hover highlight can be forced to show across all
     * pinned overlay panes as well as the primary view. -1 = none.
     */
    int hovered_frame_num_;

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
     * @brief The currently-live pinned overlay views (pinned_column_view_,
     * pinned_row_view_, pinned_row_corner_view_), skipping any that are
     * still null (pinned_row_view_/pinned_row_corner_view_ aren't set until
     * setPinnedRowViews() is called by the owning PacketListPane).
     * @return The live overlay views, as their common QTreeView base.
     */
    QList<QTreeView *> pinnedOverlayViews() const;

    /**
     * @brief Requests a repaint of every live pinned overlay view's
     * viewport. Used wherever this view's own selection or hover state
     * changes: the overlay views draw those highlights themselves (see
     * PinnedRowView::drawRow()/PinnedColumnView::drawRow()) rather than
     * picking up the change automatically, since each is a separate
     * QAbstractItemView with its own viewport.
     */
    void repaintPinnedOverlays();

    /**
     * @brief Mirrors a single header section's width onto every live
     * pinned overlay view.
     * @param column The column (logical index) to mirror.
     * @param width The new width.
     */
    void mirrorSectionWidthToOverlays(int column, int width);

    /**
     * @brief Sets the pinned overlay views' selection stylesheet to match
     * whether this view's window is currently active.
     */
    void applyOverlayActiveState();

    /**
     * @brief Slot connected to QApplication::focusChanged, since
     * isActiveWindow() can lag behind the actual activation state on some
     * platforms until the next event loop iteration.
     */
    void applicationFocusChanged(QWidget *old, QWidget *now);

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
     * @brief Emitted whenever the width needed for the pinned-row strip's
     * "corner" (the frozen-column portion, matching the pinned column
     * boundary) changes, so the owning PacketListPane can resize the
     * corner widget in its layout to match, and whenever whether any rows
     * are pinned at all may have changed, so the pane can show/hide the
     * whole strip. Emitted from layoutPinnedOverlays(), which already
     * runs whenever column widths, the pinned column boundary, or the
     * pinned row set change.
     *
     * have_pinned_rows is passed explicitly rather than left for
     * PacketListPane to infer from the row views' own isVisible(): those
     * views are nested inside the very strip widget this signal controls
     * the visibility of, and QWidget::isVisible() reflects actual
     * on-screen visibility (requiring every ancestor to also be visible),
     * not just a widget's own explicit show/hide flag -- so deriving the
     * strip's visibility from its own (still-hidden) children's
     * isVisible() can never become true.
     * @param corner_width The width, in pixels, of the frozen-column portion.
     * @param have_pinned_rows Whether at least one row is currently pinned.
     */
    void pinnedRowsCornerWidthChanged(int corner_width, bool have_pinned_rows);

    /**
     * @brief Emitted from setColumnVisibility() for every column whenever
     * any column's visibility changes, so PacketListPane can mirror it
     * onto duplicate_header_ (a bare QHeaderView with no setColumnHidden()
     * of its own the way a full QTreeView-based overlay has).
     * @param column The column (logical index) whose visibility changed.
     * @param hidden The column's new hidden state.
     */
    void columnHiddenChanged(int column, bool hidden);

    /**
     * @brief Emitted from setPinnedColumnBoundary() whenever the frozen-
     * column boundary changes, so PacketListPane can split
     * duplicate_header_ into frozen/non-frozen halves the same way
     * pinned_column_view_/pinned_row_view_/pinned_row_corner_view_ already
     * split their own column visibility around pinned_column_boundary_.
     * @param column_count Number of leftmost columns now frozen, or 0.
     */
    void pinnedColumnBoundaryChanged(int column_count);

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

    /**
     * @brief Re-resolves the pinned row's frame number to its current
     * visible row and updates overlay visibility/position accordingly.
     * Connected to the model's modelReset signal.
     */
    void updatePinnedRowVisibility();

    /**
     * @brief Recomputes the geometry of the pinned column overlay
     * (pinned_column_view_) against the current viewport, and emits
     * pinnedRowsCornerWidthChanged() so the owning PacketListPane can keep
     * the pinned-row strip's corner width in sync. The pinned-row strip
     * itself is a sibling widget positioned by PacketListPane's own
     * layout, not by this view, since QTreeView reserves viewport space
     * for its own header internally and reasserts that reservation on
     * every geometry pass -- reserving additional space above the
     * viewport via setViewportMargins() can't coexist with that.
     */
    void layoutPinnedOverlays();
};

#endif // PACKET_LIST_H
