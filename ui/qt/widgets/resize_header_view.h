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

#ifndef RESIZE_HEADER_VIEW_H
#define RESIZE_HEADER_VIEW_H

#include <config.h>

#include <ui/qt/widgets/adaptive_header_view.h>

/**
 * @brief QHeaderView subclass that adds a context menu for interactively
 *        resizing or resetting column (or row) widths.
 */
class ResizeHeaderView : public AdaptiveHeaderView
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a ResizeHeaderView.
     * @param orientation Whether this is a horizontal (column) or vertical (row) header.
     * @param parent      Optional parent widget.
     */
    ResizeHeaderView(Qt::Orientation orientation, QWidget *parent = nullptr);

protected:
    /**
     * @brief Presents a context menu at the position of @p e, offering actions
     *        to resize sections to their contents or reset them to default widths.
     * @param e The context menu event carrying the cursor position.
     */
    void contextMenuEvent(QContextMenuEvent *e) override;
};
#endif // RESIZE_HEADER_VIEW_H
