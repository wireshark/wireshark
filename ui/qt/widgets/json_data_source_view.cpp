/* json_data_source_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// To do:
// - Better performance? This works fine with 1 or 2 K of JSON. What
//   about 1 or 2 G?
// - Handle object and array selection. That is, add support for multiline
//   highlighting and selection.
// - Add an RFC 5322 Internet Message Format DataSourceView.
// - The JSON printer could use a review to verify correctness.
// - Add accessibility

#include "json_data_source_view.h"

#include <wsutil/wsjson.h>

#include "main_application.h"

#include "ui/qt/main_window.h"
#include "ui/qt/utils/color_utils.h"
#include "ui/qt/utils/tango_colors.h"

#include <QPainter>
#include <QScrollBar>

JsonDataSourceView::JsonDataSourceView(const QByteArray &data, proto_node *root_node, QWidget *parent) :
    BaseDataSourceView(data, parent),
    layout_(new QTextLayout()),
    show_offset_(false),
    em_width_(0),
    line_height_(0),
    max_line_length_(0),
    // cap_file_(nullptr),
    root_node_(nullptr),
    selected_line_(nullptr),
    hovered_line_(nullptr)
{
    Q_UNUSED(root_node)
    setAccessibleName(tr("Event JSON"));

    layout_->setCacheEnabled(true);

    connect(mainApp, &MainApplication::zoomMonospaceFont, this, &JsonDataSourceView::setMonospaceFont);

    setMouseTracking(true);

#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacShowFocusRect, true);
#endif

    addJsonObject();
}

JsonDataSourceView::~JsonDataSourceView()
{
//    ctx_menu_.clear();
    delete(layout_);
}

void JsonDataSourceView::setMonospaceFont(const QFont &mono_font)
{
    setFont(mono_font);
    viewport()->setFont(mono_font);
    layout_->setFont(mono_font);

    updateLayoutMetrics();

    updateScrollbars();
    viewport()->update();
}

void JsonDataSourceView::markField(int start, int length, bool scroll_to)
{
    selected_line_ = nullptr;
    int row_y = -line_height_;

    for (auto &text_block : text_blocks_) {
        for (auto &text_line : text_block.text_lines) {
            row_y += line_height_;
            int end = start + length;
            int kv_end = text_line.kv_start + text_line.kv_length;
            // Let dissectors provide the offset+length of either the value itself
            // or the key+value
            if (text_line.kv_start <= start && kv_end == end) {
                selected_line_ = &text_line;
                goto sl_found;
            }
        }
    }
sl_found:
    if (scroll_to && selected_line_ && row_y >= 0) {
        if (row_y < verticalScrollBar()->value()) {
            verticalScrollBar()->setValue(row_y);
        } else if (row_y + line_height_ > verticalScrollBar()->value() + viewport()->height()) {
            verticalScrollBar()->setValue(row_y + line_height_ - viewport()->height());
        }
    }

    viewport()->update();
}

void JsonDataSourceView::unmarkField()
{
    selected_line_ = nullptr;
    viewport()->update();
}

void JsonDataSourceView::paintEvent(QPaintEvent *)
{
    updateLayoutMetrics();

    QPainter painter(viewport());
    painter.translate(-horizontalScrollBar()->value(), -verticalScrollBar()->value());

    // Clear the area
    painter.fillRect(viewport()->rect(), palette().base());

    // Offset background. We want the entire height to be filled.
    if (show_offset_) {
        QRect offset_rect = QRect(viewport()->rect());
        offset_rect.setWidth(offsetPixels());
        painter.fillRect(offset_rect, palette().window());
    }

    if (text_blocks_.isEmpty()) {
        return;
    }

    // Pixel offset of this row
    int row_y = 0;
    int draw_top = verticalScrollBar()->value() - line_height_;
    int draw_bottom = verticalScrollBar()->value() + viewport()->height();

    for (auto &text_block : text_blocks_) {
        for (auto &text_line : text_block.text_lines) {
            if (row_y < draw_top) {
                row_y += line_height_;
                continue;
            }
            layout_->clearLayout();
            layout_->clearFormats();
            layout_->setText(text_line.line);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
            QList<QTextLayout::FormatRange> fmt_list(text_line.fmt_list);
#else
            QVector<QTextLayout::FormatRange> fmt_list(text_line.fmt_list);
#endif
            if (selected_line_ == &text_line || hovered_line_ == &text_line) {
                QTextLayout::FormatRange format_range;
                format_range.start = text_line.highlight_start;
                format_range.length = text_line.highlight_length;
                format_range.format.setBackground(
                            hovered_line_ == &text_line ? ColorUtils::hoverBackground() : palette().highlight());
                fmt_list.append(format_range);
            }
            layout_->setFormats(fmt_list);
            layout_->beginLayout();
            QTextLine tl = layout_->createLine();
            tl.setLeadingIncluded(true);
            layout_->endLayout();
            layout_->draw(&painter, QPointF(0.0, row_y));
            if (row_y > draw_bottom) {
                break;
            }
            row_y += line_height_;
        }
    }
}

void JsonDataSourceView::resizeEvent(QResizeEvent *)
{
    updateScrollbars();
}

void JsonDataSourceView::keyPressEvent(QKeyEvent *event)
{
    hovered_line_ = nullptr;
    switch(event->key()) {
    case Qt::Key_Escape:
        markField(0, 0, false);
        break;
    case Qt::Key_Up:
    case Qt::Key_Down:
        // Up:
        //   selected_line_ is null: Last nonzero item
        //   selected_line_ is first nonzero: Nothing
        //   otherwise, previous nonzero
        // Down:
        //   selected_line_ is null: First nonzero item
        //   selected_line_ is last nonzero: Nothing
        //   otherwise, next nonzero
    {
        QList<const TextLine *> selectable_lines;
        qsizetype idx = event->key() == Qt::Key_Up ? INT32_MAX : -1;
        for (const auto &text_block : text_blocks_) {
            for (const auto &text_line : text_block.text_lines) {
                if (text_line.kv_length > 0) {
                    if (selected_line_ && selected_line_->kv_start == text_line.kv_start && selected_line_->kv_length == text_line.kv_length) {
                        idx = selectable_lines.size() + (event->key() == Qt::Key_Up ? -1 : 1);
                    }
                    selectable_lines.append(&text_line);
                }
            }
        }
        if (idx >= selectable_lines.size() && event->key()) {
            idx = selectable_lines.size() - 1;
        } else if (idx < 0 && event->key()) {
            idx = 0;
        }
        if (idx >= 0 && idx < selectable_lines.size()) {
            auto select_line = selectable_lines.at(idx);

            setUpdatesEnabled(false);
            emit byteSelected(select_line->kv_start + select_line->kv_length - 1);
            setUpdatesEnabled(true);

            markField(select_line->kv_start, select_line->kv_length, true);
        }
    }
    break;
    default:
        QAbstractScrollArea::keyPressEvent(event);
        break;
    }
    viewport()->update();
}

const TextLine * JsonDataSourceView::findTextLine(int line)
{
    int cur_line = 0;
    for (auto &text_block : text_blocks_) {
        for (auto &text_line : text_block.text_lines) {
            if (cur_line == line) {
                return &text_line;
            }
            cur_line++;
        }
    }
    return nullptr;
}

void JsonDataSourceView::mousePressEvent(QMouseEvent *event)
{
    int ev_line = (event->pos().y() + verticalScrollBar()->value()) / line_height_;
    auto old_selected_line = selected_line_;
    selected_line_ = findTextLine(ev_line);

    // byteSelected does the following:
    // - Triggers selectedFieldChanged in ProtoTree, which clears the
    //   selection and selects the corresponding (or no) item.
    // - The new tree selection triggers markField.

    if (selected_line_ && selected_line_ != old_selected_line) {
        setUpdatesEnabled(false);
        emit byteSelected(selected_line_->kv_start + selected_line_->kv_length - 1);
        viewport()->update();
        setUpdatesEnabled(true);
    }
}

void JsonDataSourceView::mouseMoveEvent(QMouseEvent *event)
{
    Q_UNUSED(event)
    int ev_line = (event->pos().y() + verticalScrollBar()->value()) / line_height_;
    const TextLine *old_hovered_line = hovered_line_;
    hovered_line_ = findTextLine(ev_line);

    if (hovered_line_ && old_hovered_line != hovered_line_) {
        emit byteHovered(hovered_line_->kv_start);
        viewport()->update();
    }
}

void JsonDataSourceView::leaveEvent(QEvent *event)
{
    hovered_line_ = nullptr;
    emit fieldHighlight((FieldInformation *)nullptr);
    viewport()->update();
    QAbstractScrollArea::leaveEvent(event);
}

void JsonDataSourceView::updateLayoutMetrics()
{
    // We might want to match ProtoTree::rowHeight.
    line_height_ = viewport()->fontMetrics().lineSpacing();
    em_width_  = stringWidth("M");

    verticalScrollBar()->setSingleStep(line_height_);
    horizontalScrollBar()->setSingleStep(em_width_);
}

int JsonDataSourceView::stringWidth(const QString &line)
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
    return viewport()->fontMetrics().horizontalAdvance(line);
#else
    return viewport()->fontMetrics().boundingRect(line).width();
#endif
}

void JsonDataSourceView::updateScrollbars()
{
    qsizetype line_count = 0;
    for (const auto & text_block : text_blocks_) {
        line_count += text_block.text_lines.size();
    }

    int all_lines_px = (static_cast<int>(line_count) * line_height_) - viewport()->height();
    int max_line_px = (static_cast<int>(max_line_length_) * em_width_) - viewport()->width();

    verticalScrollBar()->setPageStep(viewport()->height());
    horizontalScrollBar()->setPageStep(viewport()->width());
    verticalScrollBar()->setRange(0, qMax(0, all_lines_px));
    horizontalScrollBar()->setRange(0, qMax(0, max_line_px));
}

void JsonDataSourceView::addTextLine(TextBlock &text_block, TextLine &text_line, const QString &next_line)
{
    text_block.text_lines.append(text_line);
    text_line.fmt_list.clear();
    text_line.line = next_line;
    text_line.highlight_start = -1;
    text_line.highlight_length = -1;
    text_line.kv_start = 0;
    text_line.kv_length = 0;
}

bool JsonDataSourceView::prettyPrintPlain(const char *in_buf, QString &out_str)
{
    // XXX Add more features, e.g. UTF-8 and a printable character threshold
    size_t idx = 0;
    while (g_ascii_isprint(in_buf[idx])) {
        out_str += in_buf[idx];
    }
    return !out_str.isEmpty();
}

// Lines have the following components:
// - newline+indent
// {, [, value
// ": "
// value, ], }
// ","
bool JsonDataSourceView::addJsonObject()
{
    jsmn_parser parser;
    jsmn_init(&parser);
    int num_tokens = jsmn_parse(&parser, data_.constData(), data_.size(), NULL, 0);
    // XXX Provide some sort of visual indicator on error, e.g. just dump the text and color it "grayed out"?
    switch (num_tokens) {
    case JSMN_ERROR_INVAL:
        return false;
    case JSMN_ERROR_PART:
        return false;
    default:
        break;
    }

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QList<jsmntok_t> tokens;
#else
    QVector<jsmntok_t> tokens;
#endif
    QList<jsmntok_t *> parents;
    bool new_line = false;
    QString indent;

    tokens.resize(num_tokens);
    jsmn_init(&parser);
    jsmn_parse(&parser, data_.constData(), data_.size(), tokens.data(), num_tokens);
    int val_idx = -1;

    TextBlock text_block;
    TextLine text_line;
    text_line.highlight_start = -1;
    text_line.highlight_length = -1;
    text_line.kv_start = 0;
    text_line.kv_length = 0;

    QColor key_color = QColor(ColorUtils::themeIsDark() ? tango_aluminium_3 : tango_aluminium_5);
    QColor str_val_color = QColor(ColorUtils::themeIsDark() ? tango_chameleon_3 : tango_chameleon_5);
    QColor prim_val_color = QColor(ColorUtils::themeIsDark() ? tango_sky_blue_3 : tango_sky_blue_5);

    for (int idx = 0; idx < num_tokens; idx++) {
        jsmntok_t *tok = &tokens[idx];
        QString trailing = "";

        if (new_line) {
            if (text_line.line.size() > max_line_length_) {
                max_line_length_ = text_line.line.size();
            }
            addTextLine(text_block, text_line, indent);
        }
        new_line = true;

        bool is_key = false;
        jsmntok_t *ptok = parents.size() > 0 ? parents.last() : nullptr;
        if (ptok != nullptr) {
            // XXX Is there a more robust way to differentiate keys vs values?
            if (ptok->type == JSMN_OBJECT && ptok->size % 2 == 0) {
                is_key = true;
                trailing = ": ";
                new_line = false;
            } else if (tok->type >= JSMN_STRING && ptok->size > 1) {
                trailing = ",";
            }
            ptok->size--;
        }

        // Dissectors will likely provide the value offset+length, but the key+value
        // offset+length creates a larger target for markField.
        if (is_key && idx < num_tokens - 1) {
            val_idx = idx + 1;
            jsmntok_t *v_tok = &tokens[val_idx];
            // Offsets are from the start of the tvb.
            text_line.kv_start = tok->start - 1;
            if (v_tok->type == JSMN_STRING || v_tok->type == JSMN_PRIMITIVE) {
                // Include preceding and succeeding quotes.
                // text_line.field_start = tok->start;
                text_line.kv_length = v_tok->end - tok->start + (v_tok->type == JSMN_STRING ? 2 : 1);
            }
        }

        switch(tok->type) {
        case JSMN_OBJECT:
            text_line.line.append('{');
            break;
        case JSMN_ARRAY:
            text_line.line.append('[');
            break;
        case JSMN_STRING:
        {
            QTextLayout::FormatRange format_range;
            format_range.start = static_cast<int>(text_line.line.size());
            // Include succeeding quote.
            format_range.length = tok->end - tok->start + 2;
            // Include preceding quote.
            text_line.line += data_.mid(tok->start - 1, format_range.length);

            if (is_key) {
                format_range.format.setForeground(key_color);
                text_line.highlight_start = format_range.start;
            } else {
                format_range.format.setForeground(str_val_color);
                text_line.highlight_length = static_cast<int>(text_line.line.size()) - text_line.highlight_start;
            }
            text_line.fmt_list.append(format_range);
        }
            break;
        case JSMN_PRIMITIVE:
        {
            QTextLayout::FormatRange format_range;
            format_range.start = static_cast<int>(text_line.line.size());
            format_range.length = tok->end - tok->start;
            format_range.format.setForeground(prim_val_color);
            text_line.fmt_list.append(format_range);
            text_line.line += data_.mid(tok->start, format_range.length);
            if (idx == val_idx) {
                text_line.highlight_length = static_cast<int>(text_line.line.size()) - text_line.highlight_start;
            }
        }
            break;
        default:
            break;
        }

        text_line.line.append(trailing);

        if (tok->type == JSMN_OBJECT || tok->type == JSMN_ARRAY) {
            if (tok->type == JSMN_OBJECT) {
                tok->size *= 2; // jsmn counts keys+values as one entity.
            }
            parents << tok;
            indent.fill(' ', parents.size() * 2);
        }

        ptok = parents.size() > 0 ? parents.last() : nullptr;
        while (ptok != nullptr && ptok->size == 0) {
            parents.pop_back();
            indent.fill(' ', parents.size() * 2);
            if (text_line.line.size() > max_line_length_) {
                max_line_length_ = text_line.line.size();
            }
            addTextLine(text_block, text_line, indent);
            text_line.line += ptok->type == JSMN_OBJECT ? "}" : "]";
            ptok = nullptr;
            if (parents.size() > 0) {
                ptok = parents.last();
                if (ptok->size > 1) {
                    text_line.line.append(",");
                }
            }
        }
    }
    addTextLine(text_block, text_line);
    text_blocks_.append(text_block);
    return true;
}

int JsonDataSourceView::offsetChars(bool include_pad)
{
    int padding = include_pad ? 2 : 0;
    if (text_blocks_.size() > 0xffff) {
        return 8 + padding;
    }
    return 4 + padding;
}

int JsonDataSourceView::offsetPixels()
{
    if (show_offset_) {
        // One pad space before and after
        QString zeroes = QString(offsetChars(), '0');
        return stringWidth(zeroes);
    }
    return 0;
}
