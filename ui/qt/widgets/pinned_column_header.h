/** @file
 *
 * Header file defining the PinnedColumnHeader class
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PINNED_COLUMN_HEADER_H
#define PINNED_COLUMN_HEADER_H

#include <QHeaderView>
#include <QPoint>

class PacketList;

/**
 * @brief The header used by PinnedColumnView.
 *
 * QHeaderView handles interactive resize (and its own click-to-sort
 * detection) directly in its mousePress/Move/ReleaseEvent virtuals rather
 * than through events that reliably pass through an installed event
 * filter (an installEventFilter()-based approach was tried and found not
 * to see any mouse press/release events at all, even though resize itself
 * worked). Overriding those virtuals directly guarantees they're seen, so
 * a plain click (no drag) can be forwarded to the primary view's header to
 * trigger sorting, matching a click on the real header exactly.
 */
class PinnedColumnHeader : public QHeaderView
{
    Q_OBJECT
public:
    /**
     * @param packet_list The primary view mouse/context-menu events on
     * this header are forwarded to; must outlive this header.
     * @param parent The view this header is installed on via setHeader().
     */
    explicit PinnedColumnHeader(PacketList *packet_list, QWidget *parent = nullptr);

protected:
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;

private:
    PacketList *packet_list_;
    int press_section_;
    QPoint press_pos_;
};

#endif // PINNED_COLUMN_HEADER_H
