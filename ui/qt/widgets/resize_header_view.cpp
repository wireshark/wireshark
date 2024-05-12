/** @file
 *
 * Header view with a context menu to resize all sections to contents
 *
 * Copyright 2024 John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "resize_header_view.h"

#include <QMenu>
#include <QContextMenuEvent>

ResizeHeaderView::ResizeHeaderView(Qt::Orientation orientation, QWidget *parent) : QHeaderView(orientation, parent)
{
    setStretchLastSection(true);
    setSectionsMovable(true);
    // setFirstSectionMovable(true) ?
}

/*!
    \fn void ResizeHeaderView::contextMenuEvent(QContextMenuEvent *e)

    Shows a context menu which resizes all sections to their contents.
 */

void ResizeHeaderView::contextMenuEvent(QContextMenuEvent *e)
{
    if (e == nullptr)
        return;

    QMenu *ctxMenu = new QMenu(this);
    ctxMenu->setAttribute(Qt::WA_DeleteOnClose);

    QString text = tr("Resize all %1 to contents").arg((orientation() == Qt::Horizontal) ? "columns" : "rows");
    QAction *act = ctxMenu->addAction(std::move(text));
    connect(act, &QAction::triggered, this, [&]() { resizeSections(QHeaderView::ResizeToContents); });

    ctxMenu->popup(e->globalPos());
}
