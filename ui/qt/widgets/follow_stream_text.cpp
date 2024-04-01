/* follow_stream_text.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/follow_stream_text.h>

#include "epan/prefs.h"

#include <ui/qt/utils/color_utils.h>

#include <main_application.h>

#include <QMap>
#include <QMouseEvent>
#include <QTextCursor>
#include <QScrollBar>

// To do:
// - Draw text by hand similar to ByteViewText. This would let us add
//   extra information, e.g. a timestamp column and get rid of
//   max_document_length_ in FollowStreamDialog.

FollowStreamText::FollowStreamText(QWidget *parent) :
    QPlainTextEdit(parent), truncated_(false)
{
    setMouseTracking(true);
//    setMaximumBlockCount(1);
    QTextDocument *text_doc = document();
    text_doc->setDefaultFont(mainApp->monospaceFont());

    metainfo_fg_ = ColorUtils::alphaBlend(palette().windowText(), palette().window(), 0.35);
}

const int FollowStreamText::max_document_length_ = 500 * 1000 * 1000; // Just a guess

void FollowStreamText::addTruncated(int cur_pos)
{
    if (truncated_) {
        QTextCharFormat tcf = currentCharFormat();
        tcf.setBackground(palette().base().color());
        tcf.setForeground(metainfo_fg_);
        insertPlainText("\n" + tr("[Stream output truncated]"));
        moveCursor(QTextCursor::End);
    } else {
        verticalScrollBar()->setValue(cur_pos);
    }
}

void FollowStreamText::addText(QString text, bool is_from_server, uint32_t packet_num, bool colorize)
{
    if (truncated_) {
        return;
    }

    int char_count = document()->characterCount();
    if (char_count + text.length() > max_document_length_) {
        text.truncate(max_document_length_ - char_count);
        truncated_ = true;
    }

    setUpdatesEnabled(false);
    int cur_pos = verticalScrollBar()->value();
    moveCursor(QTextCursor::End);

    QTextCharFormat tcf = currentCharFormat();
    if (!colorize) {
        tcf.setBackground(palette().base().color());
        tcf.setForeground(palette().text().color());
    } else if (is_from_server) {
        tcf.setForeground(ColorUtils::fromColorT(prefs.st_server_fg));
        tcf.setBackground(ColorUtils::fromColorT(prefs.st_server_bg));
    } else {
        tcf.setForeground(ColorUtils::fromColorT(prefs.st_client_fg));
        tcf.setBackground(ColorUtils::fromColorT(prefs.st_client_bg));
    }
    setCurrentCharFormat(tcf);

    insertPlainText(text);
    text_pos_to_packet_[textCursor().anchor()] = packet_num;

    addTruncated(cur_pos);
    setUpdatesEnabled(true);
}

void FollowStreamText::addDeltaTime(double delta)
{
    QString delta_str = QString("\n%1s").arg(QString::number(delta, 'f', 6));
    if (truncated_) {
        return;
    }

    if (document()->characterCount() + delta_str.length() > max_document_length_) {
        truncated_ = true;
    }

    setUpdatesEnabled(false);
    int cur_pos = verticalScrollBar()->value();
    moveCursor(QTextCursor::End);

    QTextCharFormat tcf = currentCharFormat();
    tcf.setBackground(palette().base().color());
    tcf.setForeground(metainfo_fg_);
    setCurrentCharFormat(tcf);

    insertPlainText(delta_str);

    addTruncated(cur_pos);
    setUpdatesEnabled(true);
}

void FollowStreamText::mouseMoveEvent(QMouseEvent *event)
{
    emit mouseMovedToPacket(textPosToPacket(cursorForPosition(event->pos()).position()));
    // Don't send the mouseMoveEvents with no buttons pushed to the base
    // class, effectively turning off mouse tracking for the base class.
    // It causes a lot of useless calculations that hurt scroll performance.
    if (event->buttons() != Qt::NoButton) {
        QPlainTextEdit::mouseMoveEvent(event);
    }
}

void FollowStreamText::mousePressEvent(QMouseEvent *event)
{
    emit mouseClickedOnPacket(textPosToPacket(cursorForPosition(event->pos()).position()));
    QPlainTextEdit::mousePressEvent(event);
}

void FollowStreamText::leaveEvent(QEvent *event)
{
    emit mouseMovedToPacket(0);
    QPlainTextEdit::leaveEvent(event);
}

void FollowStreamText::clear()
{
    truncated_ = false;
    text_pos_to_packet_.clear();
    QPlainTextEdit::clear();
}

int FollowStreamText::currentPacket() const
{
    return textPosToPacket(textCursor().position());
}

int FollowStreamText::textPosToPacket(int text_pos) const
{
    int pkt = 0;
    if (text_pos >= 0) {
        QMap<int, uint32_t>::const_iterator it = text_pos_to_packet_.upperBound(text_pos);
        if (it != text_pos_to_packet_.end()) {
            pkt = it.value();
        }
    }

    return pkt;
}
