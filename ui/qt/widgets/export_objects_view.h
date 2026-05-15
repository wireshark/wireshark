/** @file
 *
 * Tree view of Export object data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_OBJECTS_VIEW_H
#define EXPORT_OBJECTS_VIEW_H

#include <config.h>
#include <QTreeView>

/**
 * @brief A custom tree view for displaying export objects.
 */
class ExportObjectsTreeView : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ExportObjectsTreeView.
     * @param parent The parent widget, defaults to 0.
     */
    ExportObjectsTreeView(QWidget *parent = 0);

signals:
    /**
     * @brief Signal emitted when the current index changes.
     * @param current The newly current model index.
     */
    void currentIndexChanged(const QModelIndex &current);

    /**
     * @brief Signal emitted when the selected items change.
     * @param selected The new item selection.
     */
    void selectedItemsChanged(const QItemSelection &selected);

protected slots:
    /**
     * @brief Handles the event when the current item changes.
     * @param current The newly current model index.
     * @param previous The previously current model index.
     */
    void currentChanged(const QModelIndex &current, const QModelIndex &previous) override;

    /**
     * @brief Handles the event when the item selection changes.
     * @param selected The items that were selected.
     * @param deselected The items that were deselected.
     */
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected) override;
};
#endif // EXPORT_OBJECTS_VIEW_H
