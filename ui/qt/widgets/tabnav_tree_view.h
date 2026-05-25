/** @file
 *
 * Tree view with saner tab navigation functionality.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TABNAV_TREE_VIEW_H
#define TABNAV_TREE_VIEW_H

#include <config.h>
#include <QTreeView>

/**
 * @brief A QTreeView variant that advances to the next column (same row) on Tab
 *        instead of the next row (same column), making it suitable for
 *        inline tabular editing workflows.
 */
class TabnavTreeView : public QTreeView
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the tree view with column-wise Tab navigation.
     * @param parent Optional parent widget.
     */
    TabnavTreeView(QWidget *parent = 0);

    /**
     * @brief Returns the index the view should move to for a given cursor action.
     *
     * Overrides the default behaviour so that CursorAction::MoveNext (Tab) and
     * CursorAction::MovePrevious (Shift+Tab) advance through columns within the
     * current row rather than moving to adjacent rows.
     *
     * @param cursorAction The navigation action requested (e.g. MoveNext, MovePrevious).
     * @param modifiers    Active keyboard modifiers at the time of the action.
     * @return The model index that should receive focus.
     */
    QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers) override;

protected slots:
    /**
     * @brief Relays the QAbstractItemView::currentChanged notification as the
     *        currentItemChanged() signal so that external observers can connect
     *        without subclassing.
     * @param current  The newly current model index.
     * @param previous The previously current model index.
     */
    void currentChanged(const QModelIndex &current, const QModelIndex &previous) override;

signals:
    /**
     * @brief Emitted whenever the current item changes.
     * @param current  The newly current model index.
     * @param previous The previously current model index.
     */
    void currentItemChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // TABNAV_TREE_VIEW_H
