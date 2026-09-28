/* tag_column_delegate.cpp
 *
 * Delegate for COL_TAG packet list column
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tag_column_delegate.h"
#include "packet_list_record.h"

#include <epan/tag_rules.h>

#include <QApplication>
#include <QDesktopServices>
#include <QFontInfo>
#include <QFontMetrics>
#include <QMouseEvent>
#include <QPainter>
#include <QStyleOptionViewItem>
#include <QUrl>

// Segment: one matching rule's display text + its URL.
struct TagSeg {
    QString text;
    QString url;
    int     x;      // filled during hit-test
    int     width;
};

// emoji_size applies only to emoji glyphs; text tag labels and the separator
// character always render at the default row font size.
static int emojiPixelSize(const QStyleOptionViewItem &option) {
    tag_prefs_t prefs = tag_rules_get_prefs();
    int pct = (prefs.emoji_size > 0) ? prefs.emoji_size : 100;
    int row_h = option.rect.height() > 0 ? option.rect.height() : 16;
    return qMax(1, row_h * pct / 100);
}

static QFont tagFont(const QStyleOptionViewItem &option) {
    return option.font;
}

static QFont emojiFont(int pixel_size) {
    QFont font("Noto Color Emoji");
    if (!QFontInfo(font).exactMatch())
        font.setFamily("Segoe UI Emoji");
    font.setPixelSize(pixel_size);
    return font;
}

// Emoji codepoints that should always render in the color emoji font.
static bool isEmojiCodepoint(char32_t cp)
{
    return (cp >= 0x1F300 && cp <= 0x1FAFF)
        || (cp >= 0x1F000 && cp <= 0x1F2FF)
        || (cp >= 0x2600  && cp <= 0x27BF)
        || (cp >= 0xFE00  && cp <= 0xFE0F)
        || (cp >= 0x1F1E6 && cp <= 0x1F1FF)
        || cp == 0x200D;
}

// Each run is a consecutive span of emoji or non-emoji characters.
// Emoji always go to the color emoji font; non-emoji use the configured font.
struct TagRun {
    QString text;
    bool    is_emoji;
};

static QList<TagRun> splitRuns(const QString &text)
{
    QList<TagRun> runs;
    if (text.isEmpty())
        return runs;
    QList<uint> ucs4 = text.toUcs4();
    for (uint cp : ucs4) {
        char32_t c32 = static_cast<char32_t>(cp);
        bool emoji = isEmojiCodepoint(c32);
        QString ch = QString::fromUcs4(&c32, 1);
        if (!runs.isEmpty() && runs.last().is_emoji == emoji)
            runs.last().text += ch;
        else
            runs.append({ch, emoji});
    }
    return runs;
}

static QFont fontForRun(const TagRun &run, const QStyleOptionViewItem &option)
{
    if (run.is_emoji)
        return emojiFont(emojiPixelSize(option));
    return tagFont(option);
}

static int measureRuns(const QList<TagRun> &runs, const QStyleOptionViewItem &option,
                       QList<int> *widths_out)
{
    int total = 0;
    for (const TagRun &run : runs) {
        QFontMetrics fm(fontForRun(run, option));
        int w = fm.horizontalAdvance(run.text);
        if (widths_out)
            widths_out->append(w);
        total += w;
    }
    return total;
}

// Unpack the QList<QPair<QString,QString>> stored in Qt::UserRole.
static QList<TagSeg> segmentsFromIndex(const QModelIndex &index)
{
    QList<TagSeg> result;
    QVariant v = index.data(Qt::UserRole);
    if (!v.isValid())
        return result;
    TagSegmentList pairs = v.value<TagSegmentList>();
    for (const auto &p : pairs) {
        if (p.first.isEmpty())
            continue;
        TagSeg s;
        s.text  = p.first;
        s.url   = p.second;
        s.x     = 0;
        s.width = 0;
        result << s;
    }
    return result;
}

TagColumnDelegate::TagColumnDelegate(QWidget *parent)
    : QStyledItemDelegate(parent)
{
}

void TagColumnDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{
    QStyleOptionViewItem bg_option = option;
    initStyleOption(&bg_option, index);
    bg_option.text.clear();
    QApplication::style()->drawControl(QStyle::CE_ItemViewItem, &bg_option, painter,
                                       bg_option.widget);

    paintContent(painter, option, index);
}

void TagColumnDelegate::paintContent(QPainter *painter, const QStyleOptionViewItem &option,
                                     const QModelIndex &index) const
{
    QString text = index.data(Qt::DisplayRole).toString();
    if (text.isEmpty())
        return;

    QList<TagRun> runs = splitRuns(text);
    if (runs.isEmpty())
        return;

    QList<int> run_widths;
    int total_width = measureRuns(runs, option, &run_widths);

    const QRect &drawRect = option.rect;
    int x = drawRect.left() + (drawRect.width() - total_width) / 2;

    painter->save();
    painter->setClipRect(option.rect);
    painter->setPen(Qt::black);
    for (int i = 0; i < runs.size(); i++) {
        QFont f = fontForRun(runs.at(i), option);
        painter->setFont(f);
        // Use Qt's own vertical centering within drawRect so glyph internal
        // leading doesn't push the emoji down from the top of the cell.
        QRect segRect(x, drawRect.top(), run_widths.at(i), drawRect.height());
        painter->drawText(segRect, Qt::AlignVCenter | Qt::AlignLeft, runs.at(i).text);
        x += run_widths.at(i);
    }
    painter->restore();
}

QSize TagColumnDelegate::sizeHint(const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    QSize base = QStyledItemDelegate::sizeHint(option, index);
    QString text = index.data(Qt::DisplayRole).toString();
    if (text.isEmpty())
        return base;

    QList<TagRun> runs = splitRuns(text);
    int w = measureRuns(runs, option, nullptr);
    if (w <= 0) w = base.height();
    return QSize(w + 8, base.height());
}

bool TagColumnDelegate::editorEvent(QEvent *event, QAbstractItemModel *model,
                                    const QStyleOptionViewItem &option,
                                    const QModelIndex &index)
{
    Q_UNUSED(model);

    if (event->type() != QEvent::MouseButtonRelease)
        return false;

    QMouseEvent *me = static_cast<QMouseEvent *>(event);
    if (me->button() != Qt::LeftButton)
        return false;

    tag_prefs_t prefs = tag_rules_get_prefs();
    if (prefs.link_click == TAG_LINK_CLICK_NONE)
        return false;
    if (prefs.link_click == TAG_LINK_CLICK_CTRL) {
        if (!(me->modifiers() & Qt::ControlModifier) || !(me->modifiers() & Qt::ShiftModifier))
            return false;
    }

    QList<TagSeg> segs = segmentsFromIndex(index);
    if (segs.isEmpty())
        return false;

    // Check whether any segment has a URL at all.
    bool has_links = false;
    for (const TagSeg &s : segs)
        if (!s.url.isEmpty()) { has_links = true; break; }
    if (!has_links)
        return false;

    QString full_text = index.data(Qt::DisplayRole).toString();
    int total_width = measureRuns(splitRuns(full_text), option, nullptr);
    int x = option.rect.left() + (option.rect.width() - total_width) / 2;

    QString separator;
    if (prefs.separator != '\0')
        separator = QChar::fromLatin1(prefs.separator);
    int separator_width = separator.isEmpty()
        ? 0
        : measureRuns(splitRuns(separator), option, nullptr);

    bool first = true;
    for (TagSeg &s : segs) {
        if (!first)
            x += separator_width;
        first = false;
        s.x     = x;
        s.width = measureRuns(splitRuns(s.text), option, nullptr);
        x += s.width;
    }

    QPoint mouse_pos = me->pos();

    for (const TagSeg &s : segs) {
        if (s.url.isEmpty())
            continue;
        if (mouse_pos.x() >= s.x && mouse_pos.x() < s.x + s.width
                && option.rect.contains(mouse_pos)) {
            QDesktopServices::openUrl(QUrl(s.url));
            return true;
        }
    }

    return false;
}
