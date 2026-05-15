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

#include "base_data_source_view.h"

#include <ui/qt/utils/field_information.h>

#include <QAbstractScrollArea>
#include <QTextLayout>

class QTextLayout;

struct TextLine {
    QString line;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QList<QTextLayout::FormatRange> fmt_list;
#else
    QVector<QTextLayout::FormatRange> fmt_list;
#endif
    int highlight_start;
    int highlight_length;
    int kv_start;
    int kv_length;
};

struct TextBlock {
    QList<TextLine> text_lines;
};

/**
 * @brief A view for displaying and interacting with JSON formatted data sources.
 */
class JsonDataSourceView : public BaseDataSourceView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new JsonDataSourceView.
     * @param data The raw JSON byte data.
     * @param root_node The root protocol node of the JSON tree.
     * @param parent The parent widget, defaults to nullptr.
     */
    explicit JsonDataSourceView(const QByteArray &data, proto_node *root_node, QWidget *parent = nullptr);

    /**
     * @brief Destroys the JsonDataSourceView.
     */
    ~JsonDataSourceView();

signals:
    /**
     * @brief Signal emitted when a JSON field is selected.
     * @param finfo Pointer to the selected field information.
     */
    void fieldSelected(FieldInformation *finfo);

    /**
     * @brief Signal emitted when a JSON field is hovered or highlighted.
     * @param finfo Pointer to the highlighted field information.
     */
    void fieldHighlight(FieldInformation *finfo);

public slots:
    /**
     * @brief Sets the monospace font used for rendering the JSON text.
     * @param mono_font The monospace font to apply.
     */
    void setMonospaceFont(const QFont &mono_font);

    /**
     * @brief Visually marks a field in the display.
     * @param start The starting byte offset.
     * @param length The length of the field in bytes.
     * @param scroll_to True to automatically scroll the view to the marked field.
     * @param hover True if the field is being marked due to a hover action.
     */
    void markField(int start, int length, bool scroll_to = true, bool hover = false);

    /**
     * @brief Clears the currently marked field.
     */
    void unmarkField();

    /**
     * @brief Marks a protocol in the view (unused for JSON view).
     * @param start The starting byte offset.
     * @param length The length in bytes.
     */
    void markProtocol(int start, int length) {Q_UNUSED(start) Q_UNUSED(length)}

    /**
     * @brief Marks the appendix in the view (unused for JSON view).
     * @param start The starting byte offset.
     * @param length The length in bytes.
     */
    void markAppendix(int start, int length) {Q_UNUSED(start) Q_UNUSED(length)}

protected:
    // virtual bool event(QEvent *event);

    /**
     * @brief Handles paint events to draw the JSON text.
     */
    virtual void paintEvent(QPaintEvent *);

    /**
     * @brief Handles resize events to adjust the text layout.
     */
    virtual void resizeEvent(QResizeEvent *);

    /**
     * @brief Handles show events.
     */
    virtual void showEvent(QShowEvent *);

    /**
     * @brief Handles key press events for navigation.
     */
    virtual void keyPressEvent(QKeyEvent *);

    /**
     * @brief Handles mouse press events for selecting fields.
     * @param event The mouse event.
     */
    virtual void mousePressEvent (QMouseEvent *event);

    /**
     * @brief Handles mouse move events for hovering over fields.
     * @param event The mouse event.
     */
    virtual void mouseMoveEvent (QMouseEvent * event);

    /**
     * @brief Handles leave events to clear hover states.
     * @param event The leave event.
     */
    virtual void leaveEvent(QEvent *event);

private:
    /**
     * @brief Updates the internal text layout metrics based on font and widget size.
     */
    void updateLayoutMetrics();

    /**
     * @brief Calculates the pixel width of a given string line.
     * @param line The string to measure.
     * @return The width in pixels.
     */
    int stringWidth(const QString &line);

    /**
     * @brief Updates the scrollbar ranges and positions.
     */
    void updateScrollbars();

    /**
     * @brief Adds a formatted text line to the current text block.
     * @param text_block The block being populated.
     * @param text_line The text line structure.
     * @param next_line An optional preview of the next line's text.
     */
    void addTextLine(TextBlock &text_block, TextLine &text_line, const QString &next_line = QString());

    /**
     * @brief Parses and pretty-prints plain JSON text.
     * @param in_buf The input buffer.
     * @param out_str The output formatted string.
     * @return True if parsing succeeded, false otherwise.
     */
    bool prettyPrintPlain(const char *in_buf, QString &out_str);

    /**
     * @brief Adds a JSON object block to the display.
     * @return True if the object was added successfully.
     */
    bool addJsonObject();

    /**
     * @brief Gets the horizontal offset in characters.
     * @param include_pad True to include padding characters.
     * @return The offset character count.
     */
    int offsetChars(bool include_pad = true);

    /**
     * @brief Gets the horizontal offset in pixels.
     * @return The pixel offset.
     */
    int offsetPixels();

    /**
     * @brief Finds the text line corresponding to a given vertical line index.
     * @param line The line index.
     * @return Pointer to the found TextLine, or nullptr if not found.
     */
    const TextLine *findTextLine(int line);

    /** The Qt text layout engine for rendering JSON. */
    QTextLayout *layout_;

    /** The list of text blocks representing the JSON data. */
    QList<TextBlock> text_blocks_;

    /** Flag indicating if the text layout needs recalculation. */
    bool layout_dirty_;

    /** Flag indicating whether the byte offset should be shown. */
    bool show_offset_;          // Should we show the byte offset?

    /** The width of a single 'M' character and text margin. */
    int em_width_;              // Single character width and text margin. NOTE: Use fontMetrics::width for multiple characters.

    /** The font line spacing. */
    int line_height_;           // Font line spacing

    /** The maximum line length in characters. */
    qsizetype max_line_length_; // In characters

    /** The root node of the dissected JSON protocol tree. */
    proto_node *root_node_;

    /** The currently selected text line. */
    const TextLine *selected_line_;

    /** The currently hovered text line. */
    const TextLine *hovered_line_;
};
