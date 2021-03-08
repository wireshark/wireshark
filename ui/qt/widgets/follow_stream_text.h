/* follow_stream_text.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FOLLOW_STREAM_TEXT_H
#define FOLLOW_STREAM_TEXT_H

#include <QPlainTextEdit>

class FollowStreamText : public QPlainTextEdit
{
    Q_OBJECT
public:
    explicit FollowStreamText(QWidget *parent = 0);

protected:
    void mouseMoveEvent(QMouseEvent *event);
    void mousePressEvent(QMouseEvent *event);
    void leaveEvent(QEvent *event);

signals:
    // Perhaps this is not descriptive enough. We should add more words.
    void mouseMovedToTextCursorPosition(int);
    void mouseClickedOnTextCursorPosition(int);

public slots:

};

#endif // FOLLOW_STREAM_TEXT_H
