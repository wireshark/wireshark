/* follow_stream_text.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "follow_stream_text.h"

#include <wireshark_application.h>

#include <QMouseEvent>
#include <QTextCursor>

// To do:
// - Draw text by hand similar to ByteViewText. This would let us add
//   extra information, e.g. a timestamp column and get rid of
//   max_document_length_ in FollowStreamDialog.

FollowStreamText::FollowStreamText(QWidget *parent) :
    QPlainTextEdit(parent)
{
    setMouseTracking(true);
//    setMaximumBlockCount(1);
    QTextDocument *text_doc = document();
    text_doc->setDefaultFont(wsApp->monospaceFont());
}

void FollowStreamText::mouseMoveEvent(QMouseEvent *event)
{
    emit mouseMovedToTextCursorPosition(cursorForPosition(event->pos()).position());
    QPlainTextEdit::mouseMoveEvent(event);
}

void FollowStreamText::mousePressEvent(QMouseEvent *event)
{
    emit mouseClickedOnTextCursorPosition(cursorForPosition(event->pos()).position());
    QPlainTextEdit::mousePressEvent(event);
}

void FollowStreamText::leaveEvent(QEvent *event)
{
    emit mouseMovedToTextCursorPosition(-1);
    QPlainTextEdit::leaveEvent(event);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
