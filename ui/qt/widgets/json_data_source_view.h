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
    int field_start;
    int field_length;
};

struct TextBlock {
    QList<TextLine> text_lines;
};

class JsonDataSourceView : public BaseDataSourceView
{
    Q_OBJECT
public:
    explicit JsonDataSourceView(const QByteArray &data, proto_node *root_node, QWidget *parent = nullptr);
    ~JsonDataSourceView();

signals:
    void fieldSelected(FieldInformation *);
    void fieldHighlight(FieldInformation *);

public slots:
    void setMonospaceFont(const QFont &mono_font);

    void markField(int start, int length, bool scroll_to = true);
    void unmarkField();
    // We're assuming that we have a 1:1 correspondence between the view and a single protocol.
    void markProtocol(int start, int length) {Q_UNUSED(start) Q_UNUSED(length)}
    void markAppendix(int start, int length) {Q_UNUSED(start) Q_UNUSED(length)}

protected:
    // virtual bool event(QEvent *event);
    virtual void paintEvent(QPaintEvent *);
    virtual void resizeEvent(QResizeEvent *);
    virtual void keyPressEvent(QKeyEvent *event);
    virtual void mousePressEvent (QMouseEvent *event);
    virtual void mouseMoveEvent (QMouseEvent * event);
    virtual void leaveEvent(QEvent *event);

private:
    void updateLayoutMetrics();
    int stringWidth(const QString &line);
    void updateScrollbars();

    void addTextLine(TextBlock &text_block, TextLine &text_line, const QString &next_line = QString());
    bool prettyPrintPlain(const char *in_buf, QString &out_str);
    bool addJsonObject();

    int offsetChars(bool include_pad = true);
    int offsetPixels();
    const TextLine *findTextLine(int line);

    QTextLayout *layout_;
    QList<TextBlock> text_blocks_;

    bool show_offset_;          // Should we show the byte offset?
    int em_width_;              // Single character width and text margin. NOTE: Use fontMetrics::width for multiple characters.
    int line_height_;           // Font line spacing
    qsizetype max_line_length_; // In characters

    proto_node *root_node_;
    const TextLine *selected_line_;
    const TextLine *hovered_line_;
};
