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
#include <QHeaderView>

class ResizeHeaderView : public QHeaderView
{
    Q_OBJECT

public:
    ResizeHeaderView(Qt::Orientation orientation, QWidget *parent = nullptr);

protected:
    void contextMenuEvent(QContextMenuEvent *e) override;

};
#endif // RESIZE_HEADER_VIEW_H
