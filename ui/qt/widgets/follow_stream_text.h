/** @file
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
    bool isTruncated() const { return truncated_; }
    void addText(QString text, bool is_from_server, uint32_t packet_num, bool colorize);
    void addDeltaTime(double delta);
    int currentPacket() const;

protected:
    void mouseMoveEvent(QMouseEvent *event);
    void mousePressEvent(QMouseEvent *event);
    void leaveEvent(QEvent *event);

signals:
    void mouseMovedToPacket(int);
    void mouseClickedOnPacket(int);

public slots:
    void clear();

private:
    int textPosToPacket(int text_pos) const;
    void addTruncated(int cur_pos);

    static const int        max_document_length_;
    bool                    truncated_;
    QMap<int, uint32_t>     text_pos_to_packet_;
    QColor                  metainfo_fg_;
};

#endif // FOLLOW_STREAM_TEXT_H
