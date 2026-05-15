/** @file
 *
 * Tree view of Dissector Table data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISSECTOR_TABLES_VIEW_H
#define DISSECTOR_TABLES_VIEW_H

#include <config.h>
#include <QTreeView>

/**
 * @brief A tree view widget specifically designed for displaying dissector tables.
 */
class DissectorTablesTreeView : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DissectorTablesTreeView.
     * @param parent The parent widget, defaults to 0.
     */
    DissectorTablesTreeView(QWidget *parent = 0);

protected slots:
    /**
     * @brief Slot triggered when the currently selected item in the view changes.
     * @param current The newly selected model index.
     * @param previous The previously selected model index.
     */
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // DISSECTOR_TABLES_VIEW_H
