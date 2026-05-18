/** @file
 *
 * Tree widget with saner tab navigation properties.
 *
 * Copyright 2017 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TABNAV_TREE_WIDGET_H
#define TABNAV_TREE_WIDGET_H

#include <config.h>
#include <QTreeWidget>

/**
 * @brief QTreeWidget subclass that remaps the Tab and Backtab keys to the next row (same column) when
 * pressing Tab while editing, change to the next column (same row).
 */
class TabnavTreeWidget : public QTreeWidget
{
public:
    /**
     * @brief Constructs the TabnavTreeWidget.
     * @param parent Optional parent widget.
     */
    TabnavTreeWidget(QWidget *parent = 0);

    /**
     * @brief Overrides cursor movement so that Tab and Backtab transfer focus
     *        out of the tree rather than selecting the next or previous item.
     * @param cursorAction The requested cursor movement action.
     * @param modifiers    Active keyboard modifiers at the time of the action.
     * @return The model index the cursor should move to, or an invalid index
     *         when focus is handed off to another widget.
     */
    QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers) override;
};
#endif // TABNAV_TREE_WIDGET_H
