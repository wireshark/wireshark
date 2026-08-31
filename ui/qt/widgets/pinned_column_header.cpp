/* pinned_column_header.cpp
 *
 * Header view used by PinnedColumnView
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/pinned_column_header.h>

#include <ui/qt/packet_list.h>

#include <QApplication>
#include <QMouseEvent>
#include <QContextMenuEvent>

PinnedColumnHeader::PinnedColumnHeader(PacketList *packet_list, QWidget *parent) :
    QHeaderView(Qt::Horizontal, parent),
    packet_list_(packet_list),
    press_section_(-1)
{
}

void PinnedColumnHeader::mousePressEvent(QMouseEvent *event)
{
    press_section_ = logicalIndexAt(event->pos());
    press_pos_ = event->pos();

    if (packet_list_) {
        packet_list_->forwardHeaderMousePress(event, packet_list_->frozenHeaderPosToReal(event->pos()));
    }

    QHeaderView::mousePressEvent(event);
}

void PinnedColumnHeader::mouseMoveEvent(QMouseEvent *event)
{
    if (packet_list_) {
        packet_list_->forwardHeaderMouseMove(event, packet_list_->frozenHeaderPosToReal(event->pos()));
    }

    QHeaderView::mouseMoveEvent(event);
}

void PinnedColumnHeader::mouseReleaseEvent(QMouseEvent *event)
{
    if (packet_list_) {
        packet_list_->forwardHeaderMouseRelease(event, packet_list_->frozenHeaderPosToReal(event->pos()));

        // A plain click (press and release on the same section, without
        // enough movement to have been a resize drag) sorts by that
        // column, matching a click on the real header.
        int release_section = logicalIndexAt(event->pos());
        if (press_section_ >= 0 && release_section == press_section_
            && (event->pos() - press_pos_).manhattanLength() < QApplication::startDragDistance()) {
            packet_list_->sortByColumnFromOverlay(release_section);
        }
    }
    press_section_ = -1;

    QHeaderView::mouseReleaseEvent(event);
}

void PinnedColumnHeader::contextMenuEvent(QContextMenuEvent *event)
{
    if (packet_list_) {
        packet_list_->forwardHeaderContextMenu(event, packet_list_->frozenHeaderPosToReal(event->pos()));
    }
}
