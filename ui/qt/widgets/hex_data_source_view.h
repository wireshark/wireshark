/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <config.h>

#include "ui/recent.h"

#include <QAbstractScrollArea>
#include <QFont>
#include <QColor>
#include <QVector>
#include <QMenu>
#include <QSize>
#include <QString>
#include <QTextLayout>
#include <QVector>

#include <limits>

#include "base_data_source_view.h"

#include <ui/qt/utils/data_printer.h>
#include <ui/qt/utils/idata_printable.h>

// XXX - Is there any reason we shouldn't add ImageDataSourceView, etc?

/**
 * @brief A fully custom-painted hex dump view for a single packet data source.
 */
class HexDataSourceView : public BaseDataSourceView, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:
    /**
     * @brief A user-defined color annotation over a byte range.
     */
    struct ByteViewAnnotation {
        int start;       /**< Zero-based start byte offset within the data. */
        int length;      /**< Number of bytes covered by the annotation. */
        QColor color;    /**< Background color applied to the annotated range. */
        QString comment; /**< User-visible label shown in a tooltip on hover. */
    };

    /**
     * @brief Construct a HexDataSourceView.
     * @param data     The raw packet bytes to display.
     * @param encoding Character encoding used for the ASCII panel;
     *                 @c PACKET_CHAR_ENC_CHAR_ASCII (default) or
     *                 @c PACKET_CHAR_ENC_CHAR_EBCDIC.
     * @param parent   The parent widget; may be nullptr.
     */
    explicit HexDataSourceView(const QByteArray &data,
                                packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII,
                                QWidget *parent = nullptr);

    /** @brief Destroy the view and its @c QTextLayout. */
    ~HexDataSourceView();

    /**
     * @brief Set the numeric base used to render hex-panel byte values.
     * @param format One of the @c bytes_view_type values:
     *               hexadecimal, decimal, octal, or binary.
     */
    void setFormat(bytes_view_type format);

    /**
     * @brief Replace the current set of user annotations.
     * @param annotations The new annotation list.
     */
    void setAnnotations(const QVector<ByteViewAnnotation> &annotations);

    // ── Selection accessors ───────────────────────────────────────────────

    /**
     * @brief Return the current byte selection range.
     * @param[out] start  Set to the first selected byte offset, or -1 if
     *                    there is no selection.
     * @param[out] length Set to the number of selected bytes, or 0.
     * @return true if at least one byte is selected; false otherwise.
     */
    bool selectionRange(int *start, int *length) const;

    /**
     * @brief Return the selection anchor byte offset.
     *
     * The anchor is the byte where a drag or keyboard selection began. It
     * may be greater than @c selectionEnd() for backward selections.
     *
     * @return The anchor byte offset, or -1 if there is no selection.
     */
    int selectionAnchor() const;

    /**
     * @brief Return the byte offset at the end of the current selection.
     * @return The inclusive last selected byte offset, or -1 if none.
     */
    int selectionEnd() const;

    /**
     * @brief Return the byte offset at which the context menu was invoked.
     *
     * Saved in @c contextMenuEvent() so that context-menu action slots know
     * which byte the user right-clicked on, independent of the current
     * keyboard selection.
     *
     * @return The byte offset under the cursor at context-menu open time.
     */
    int contextByteOffset() const;

    /**
     * @brief Return the number of bytes in the data buffer.
     * @return @c data_.size() cast to @c int. Asserts that the size fits.
     */
    int dataSize() const {
        Q_ASSERT(data_.size() <= std::numeric_limits<int>::max());
        return static_cast<int>(data_.size());
    }

    // ── Offset marker accessors ───────────────────────────────────────────

    /**
     * @brief Return the current offset-start marker byte position.
     * @return The byte offset of the start marker, or -1 if not set.
     */
    int offsetStart() const { return offset_start_byte_; }

    /**
     * @brief Return the current offset-end marker byte position.
     * @return The byte offset of the end marker, or -1 if not set.
     */
    int offsetEnd() const { return offset_end_byte_; }

    /**
     * @brief Set the offset-start marker to the given byte.
     * @param byte Zero-based byte offset at which the start marker is placed.
     */
    void setOffsetStart(int byte);

    /**
     * @brief Set the offset-end marker to the given byte.
     * @param byte Zero-based byte offset at which the end marker is placed.
     */
    void setOffsetEnd(int byte);

    /**
     * @brief Clear both offset markers and repaint.
     */
    void clearOffsetMarkers();

    // ── Selected-field metadata accessors ────────────────────────────────

    /** @return Start byte offset of the currently highlighted field. */
    int selectedFieldStart() const { return field_start_; }

    /** @return Byte length of the currently highlighted field. */
    int selectedFieldLength() const { return field_len_; }

    /** @return Start byte offset of the enclosing protocol span. */
    int selectedProtocolStart() const { return proto_start_; }

    /** @return Byte length of the enclosing protocol span. */
    int selectedProtocolLength() const { return proto_len_; }

    /**
     * @brief Return whether the selected field is itself a protocol layer.
     *
     * @return true if the selected item in the packet tree is a protocol node.
     */
    bool selectedFieldIsProtocol() const { return selected_field_is_protocol_; }

    /**
     * @brief Return whether the selected field defines its own byte range.
     * @return true if the field uses its own independent range.
     */
    bool selectedFieldUsesOwnRange() const { return selected_field_use_own_range_; }

    /**
     * @brief Set whether the selected field is a protocol-level item.
     * @param is_protocol true if the item is a protocol node.
     */
    void setSelectedFieldIsProtocol(bool is_protocol) {
        selected_field_is_protocol_ = is_protocol;
    }

    /**
     * @brief Set whether the selected field uses its own independent range.
     * @param use_own_range true to use the field's own range.
     */
    void setSelectedFieldUsesOwnRange(bool use_own_range) {
        selected_field_use_own_range_ = use_own_range;
    }

signals:
    /**
     * @brief Emitted when any byte-view display setting changes.
     *
     * Connected to sibling views so all tabs stay in sync when the user
     * changes the format, encoding, or row-width preference.
     */
    void byteViewSettingsChanged();

    /** @brief Emitted when the user triggers "Add annotation" from the context menu. */
    void addAnnotationRequested();

    /** @brief Emitted when the user triggers "Edit annotation" from the context menu. */
    void editAnnotationRequested();

    /** @brief Emitted when the user triggers "Remove annotation" from the context menu. */
    void removeAnnotationRequested();

    /**
     * @brief Emitted when the user requests a new offset-start marker.
     * @param byte The byte offset under the cursor at the time of the request.
     */
    void offsetStartRequested(int byte);

    /**
     * @brief Emitted when the user requests a new offset-end marker.
     * @param byte The byte offset under the cursor at the time of the request.
     */
    void offsetEndRequested(int byte);

    /** @brief Emitted when the user requests that both offset markers be cleared. */
    void offsetMarkersCleared();

public slots:
    /**
     * @brief Update the monospace font and recalculate layout metrics.
     * @param mono_font The new monospace font.
     */
    void setMonospaceFont(const QFont &mono_font);

    /**
     * @brief Reload byte-view display preferences and repaint.
     */
    void updateByteViewSettings();

    /**
     * @brief Highlight the enclosing protocol layer byte range.
     *
     * @param start  First byte offset of the protocol span.
     * @param length Number of bytes in the protocol span.
     */
    void markProtocol(int start, int length);

    /**
     * @brief Highlight a specific dissected field byte range.
     *
     * @param start     First byte offset of the field.
     * @param length    Number of bytes in the field.
     * @param scroll_to true (default) to scroll the range into view.
     * @param hover     true to apply hover coloring rather than selection.
     */
    void markField(int start, int length, bool scroll_to = true, bool hover = false);

    /**
     * @brief Highlight the appendix (trailing) bytes of the selected field.
     *
     * @param start  First byte offset of the appendix.
     * @param length Number of bytes in the appendix.
     */
    void markAppendix(int start, int length);

    /**
     * @brief Clear field, appendix, and hover highlights.
     */
    void unmarkField();

protected:
    /**
     * @brief Paint all visible rows of the hex dump.
     *
     * @param event Provides the dirty rect used to limit painting.
     */
    virtual void paintEvent(QPaintEvent *event);

    /**
     * @brief Recalculate scrollbar ranges and repaint after a resize.
     * @param event The resize event (unused beyond triggering the update).
     */
    virtual void resizeEvent(QResizeEvent *event);

    /**
     * @brief Ensure the layout is up to date when the widget first becomes visible.
     *
     * @param event The show event.
     */
    virtual void showEvent(QShowEvent *event);

    /**
     * @brief Begin a byte selection or move the cursor on mouse press.
     *
     * @param event The mouse press event.
     */
    virtual void mousePressEvent(QMouseEvent *event);

    /**
     * @brief Extend the selection during a mouse drag.
     *
     * @param event The mouse move event.
     */
    virtual void mouseMoveEvent(QMouseEvent *event);

    /**
     * @brief Finalise a drag selection on mouse release.
     * @param event The mouse release event.
     */
    virtual void mouseReleaseEvent(QMouseEvent *event);

    /**
     * @brief Clear hover highlights when the pointer leaves the widget.
     * @param event The leave event.
     */
    virtual void leaveEvent(QEvent *event);

    /**
     * @brief Show the byte-view context menu.
     *
     * @param event The context menu event.
     */
    virtual void contextMenuEvent(QContextMenuEvent *event);

    /**
     * @brief Handle keyboard navigation and copy commands.
     *
     * @param event The key press event.
     */
    virtual void keyPressEvent(QKeyEvent *event);

private:
    /**
     * @brief Semantic highlight modes used when building @c QTextLayout format ranges.
     */
    typedef enum {
        ModeNormal,       /**< Default foreground/background colors. */
        ModeField,        /**< Selected field highlight color. */
        ModeProtocol,     /**< Enclosing protocol layer highlight color. */
        ModeOffsetNormal, /**< Offset column default color. */
        ModeOffsetField,  /**< Offset column color within the marked offset range. */
        ModeNonPrintable, /**< Dimmed color for bytes with no printable ASCII glyph. */
        ModeHover         /**< Transient hover highlight color. */
    } HighlightMode;

    QTextLayout *layout_; /**< Reused text layout for rendering one row at a time. */

    /**
     * @brief Recompute character widths, line height, and column pixel offsets.
     */
    void updateLayoutMetrics();

    /**
     * @brief Return the pixel width of @p line using the current font metrics.
     * @param line A string whose rendered width is to be measured.
     * @return The width in pixels.
     */
    int stringWidth(const QString &line);

    /**
     * @brief Paint a single row of the hex dump.
     *
     * @param painter The painter targeting the viewport.
     * @param offset  First byte offset of the row.
     * @param row_y   Top-of-row y coordinate in viewport pixels.
     */
    void drawLine(QPainter *painter, const int offset, const int row_y);

    /**
     * @brief Append a semantic highlight range to a format list.
     *
     * @param fmt_list The format range list to modify.
     * @param start    Character start index within the layout string.
     * @param length   Number of characters to cover.
     * @param mode     The highlight mode that determines the color.
     * @return true if a range was appended; false if the range was empty.
     */
    bool addFormatRange(QList<QTextLayout::FormatRange> &fmt_list,
                        int start, int length, HighlightMode mode);

    /**
     * @brief Append a semantic highlight range over the hex panel columns.
     *
     * @param fmt_list    The format range list to modify.
     * @param mark_start  Absolute start byte offset of the mark.
     * @param mark_length Length of the mark in bytes.
     * @param tvb_offset  First byte offset of the current row.
     * @param max_tvb_pos One past the last byte of the current row.
     * @param mode        The highlight mode.
     * @return true if any columns were covered.
     */
    bool addHexFormatRange(QList<QTextLayout::FormatRange> &fmt_list,
                           int mark_start, int mark_length,
                           int tvb_offset, int max_tvb_pos,
                           HighlightMode mode);

    /**
     * @brief Append a semantic highlight range over the ASCII panel columns.
     *
     * @param fmt_list    The format range list to modify.
     * @param mark_start  Absolute start byte offset of the mark.
     * @param mark_length Length of the mark in bytes.
     * @param tvb_offset  First byte offset of the current row.
     * @param max_tvb_pos One past the last byte of the current row.
     * @param mode        The highlight mode.
     * @return true if any columns were covered.
     */
    bool addAsciiFormatRange(QList<QTextLayout::FormatRange> &fmt_list,
                             int mark_start, int mark_length,
                             int tvb_offset, int max_tvb_pos,
                             HighlightMode mode);

    /**
     * @brief Append a custom-color range over the hex panel columns.
     *
     * @param fmt_list    The format range list to modify.
     * @param mark_start  Absolute start byte offset of the annotation.
     * @param mark_length Length of the annotation in bytes.
     * @param tvb_offset  First byte offset of the current row.
     * @param max_tvb_pos One past the last byte of the current row.
     * @param bg          Background color.
     * @param fg          Foreground (text) color.
     * @return true if any columns were covered.
     */
    bool addHexCustomRange(QList<QTextLayout::FormatRange> &fmt_list,
                           int mark_start, int mark_length,
                           int tvb_offset, int max_tvb_pos,
                           const QColor &bg, const QColor &fg);

    /**
     * @brief Append a custom-color range over the ASCII panel columns.
     *
     * @param fmt_list    The format range list to modify.
     * @param mark_start  Absolute start byte offset of the annotation.
     * @param mark_length Length of the annotation in bytes.
     * @param tvb_offset  First byte offset of the current row.
     * @param max_tvb_pos One past the last byte of the current row.
     * @param bg          Background color.
     * @param fg          Foreground (text) color.
     * @return true if any columns were covered.
     */
    bool addAsciiCustomRange(QList<QTextLayout::FormatRange> &fmt_list,
                             int mark_start, int mark_length,
                             int tvb_offset, int max_tvb_pos,
                             const QColor &bg, const QColor &fg);

    /**
     * @brief Return the index of the annotation that covers @p byte_offset.
     * @param byte_offset The byte offset to test.
     * @return The zero-based index into @c annotations_ of the topmost
     *         annotation covering @p byte_offset, or -1 if none.
     */
    int annotationIndexAt(int byte_offset) const;

    /**
     * @brief Return the index of the first annotation intersecting a range.
     * @param start  First byte of the range.
     * @param length Number of bytes in the range.
     * @return The zero-based index of the first intersecting annotation,
     *         or -1 if none.
     */
    int annotationIndexIntersecting(int start, int length) const;

    /**
     * @brief Update the byte selection and optionally notify the packet tree.
     *
     * @param byte_offset The target byte offset.
     * @param extend      true to extend from the existing anchor.
     * @param emit_signal true to emit @c byteSelected().
     */
    void updateSelection(int byte_offset, bool extend, bool emit_signal);

    /**
     * @brief Show or hide a tooltip for the annotation at @p byte_offset.
     *
     * @param byte_offset The byte offset under the cursor.
     * @param global_pos  The cursor position in global screen coordinates.
     */
    void updateAnnotationToolTip(int byte_offset, const QPoint &global_pos);

    /**
     * @brief Scroll the view so that @p byte is visible.
     *
     * @param byte The byte offset to scroll into view.
     */
    void scrollToByte(int byte);

    /**
     * @brief Update scrollbar page steps, ranges, and single-step sizes.
     */
    void updateScrollbars();

    /**
     * @brief Convert a viewport pixel position to a byte offset.
     *
     * @param pos         Position in viewport (widget-local) coordinates.
     * @param allow_fuzzy true to snap to the nearest byte when @p pos is
     *                    between the hex and ASCII panels; false to return
     *                    -1 for positions that do not clearly map to a byte.
     * @return The zero-based byte offset, or -1 if the position is invalid.
     */
    int byteOffsetAtPixel(QPoint pos, bool allow_fuzzy = false);

    /**
     * @brief Build the context menu with all byte-view actions.
     */
    void createContextMenu();

    /**
     * @brief Enable or disable context-menu actions for the current state.
     */
    void updateContextMenu();

    // ── Column layout helpers ─────────────────────────────────────────────

    /**
     * @brief Return the number of characters in the offset column.
     * @param include_pad true to include the trailing space separator.
     * @return Character count for the offset field.
     */
    int offsetChars(bool include_pad = true);

    /** @return Pixel width of the offset column. */
    int offsetPixels();

    /** @return Pixel width of the hex values panel. */
    int hexPixels();

    /** @return Pixel width of the ASCII/EBCDIC text panel. */
    int asciiPixels();

    /** @return Total pixel width of all three panels combined. */
    int totalPixels();

    /**
     * @brief Return the raw data buffer for printing (IDataPrintable).
     * @return A copy of @c data_.
     */
    const QByteArray printableData() { return data_; }

    // ── Constants ─────────────────────────────────────────────────────────

    /** Number of bytes between vertical separator lines in the hex panel. */
    static const int separator_interval_;

    // ── State ─────────────────────────────────────────────────────────────
    bool layout_dirty_; /**< true when font or size has changed and metrics must be recomputed. */

    // Colors
    QColor offset_normal_fg_; /**< Foreground color for offset column text outside the marker range. */
    QColor offset_field_fg_;  /**< Foreground color for offset column text inside the marker range. */

    // Data
    packet_char_enc encoding_; /**< Character encoding for the ASCII panel (ASCII or EBCDIC). */
    QMenu ctx_menu_;           /**< Right-click context menu. */

    // Highlight ranges
    int hovered_byte_offset_; /**< Byte offset currently under the mouse, or -1. */
    int proto_start_;         /**< Start of the protocol layer highlight range. */
    int proto_len_;           /**< Length of the protocol layer highlight range. */
    int field_start_;         /**< Start of the selected field highlight range. */
    int field_len_;           /**< Length of the selected field highlight range. */
    int field_a_start_;       /**< Start of the appendix highlight range. */
    int field_a_len_;         /**< Length of the appendix highlight range. */
    int field_hover_start_;   /**< Start of the transient hover field highlight range. */
    int field_hover_len_;     /**< Length of the transient hover field highlight range. */

    // Display settings
    bool show_offset_;  /**< Whether the offset column is rendered. */
    bool show_hex_;     /**< Whether the hex values panel is rendered. */
    bool show_ascii_;   /**< Whether the ASCII/EBCDIC panel is rendered. */
    int row_width_;     /**< Number of bytes displayed per row. */
    int em_width_;      /**< Width of a single monospace character in pixels; also the text margin. */
    int line_height_;   /**< Vertical distance between row baselines in pixels. */

    /** Outline rectangles drawn around the byte under the cursor. */
    QList<QRect> hover_outlines_;

    bool allow_hover_selection_; /**< When true, moving the mouse also updates the packet-tree hover highlight. */

    QVector<ByteViewAnnotation> annotations_; /**< User-defined color annotations over byte ranges. */

    // Selection state
    int selection_anchor_; /**< Byte offset where the current selection began. */
    int selection_start_;  /**< Smaller of anchor and end; the first selected byte. */
    int selection_end_;    /**< Larger of anchor and end; the last selected byte. */
    bool selecting_;       /**< true while a mouse-drag selection is in progress. */
    int context_byte_offset_;   /**< Byte offset saved at context-menu open time. */
    int cursor_byte_;           /**< Byte offset of the keyboard cursor. */
    int hovered_annotation_index_; /**< Index of the annotation under the cursor, or -1. */
    int offset_start_byte_; /**< Byte offset of the start offset marker, or -1. */
    int offset_end_byte_;   /**< Byte offset of the end offset marker, or -1. */
    bool selected_field_is_protocol_;   /**< true if the packet-tree selection is a protocol node. */
    bool selected_field_use_own_range_; /**< true if the selected field carries its own independent range. */

    /**
     * @brief Maps x pixel positions to column indices within the current row.
     *
     * Built by @c updateLayoutMetrics(). Indexed by x pixel offset from the
     * left edge of the viewport; each entry holds the byte column number
     * (0 … @c row_width_-1) nearest to that pixel, enabling O(1) hit-testing
     * in @c byteOffsetAtPixel().
     */
    QVector<int> x_pos_to_column_;

    // Context menu actions
    QAction *action_allow_hover_selection_; /**< Toggle: update packet tree on mouse hover. */
    QAction *action_add_annotation_;        /**< Add a new annotation at the context byte. */
    QAction *action_edit_annotation_;       /**< Edit the annotation at the context byte. */
    QAction *action_remove_annotation_;     /**< Remove the annotation at the context byte. */
    QAction *action_set_offset_start_;      /**< Set the offset-start marker to the context byte. */
    QAction *action_set_offset_end_;        /**< Set the offset-end marker to the context byte. */
    QAction *action_clear_offset_markers_;  /**< Clear both offset markers. */
    QAction *action_bytes_hex_;             /**< Display byte values in hexadecimal. */
    QAction *action_bytes_dec_;             /**< Display byte values in decimal. */
    QAction *action_bytes_oct_;             /**< Display byte values in octal. */
    QAction *action_bytes_bits_;            /**< Display byte values in binary. */
    QAction *action_bytes_enc_from_packet_; /**< Use the character encoding declared in the packet. */
    QAction *action_bytes_enc_ascii_;       /**< Force ASCII character encoding. */
    QAction *action_bytes_enc_ebcdic_;      /**< Force EBCDIC character encoding. */

private slots:
    /**
     * @brief Copy the current byte selection to the clipboard.
     * @param unused Unused boolean parameter (connected from a @c QAction::triggered signal).
     */
    void copyBytes(bool unused);

    /**
     * @brief Apply the hex-panel display format chosen from the context menu.
     * @param action The triggered action; its data holds the @c bytes_view_type value.
     */
    void setHexDisplayFormat(QAction *action);

    /**
     * @brief Apply the character encoding chosen from the context menu.
     * @param action The triggered action; its data holds the @c packet_char_enc value.
     */
    void setCharacterEncoding(QAction *action);

    /**
     * @brief Enable or disable hover-driven packet-tree updates.
     * @param allowed true to enable hover selection; false to disable it.
     */
    void toggleHoverAllowed(bool allowed);

    /** @brief Emit @c addAnnotationRequested() for the context byte. */
    void requestAddAnnotation();

    /** @brief Emit @c editAnnotationRequested() for the annotation at the context byte. */
    void requestEditAnnotation();

    /** @brief Emit @c removeAnnotationRequested() for the annotation at the context byte. */
    void requestRemoveAnnotation();

    /** @brief Emit @c offsetStartRequested() with the context byte offset. */
    void requestSetOffsetStart();

    /** @brief Emit @c offsetEndRequested() with the context byte offset. */
    void requestSetOffsetEnd();

    /** @brief Emit @c offsetMarkersCleared(). */
    void requestClearOffsetMarkers();
};
