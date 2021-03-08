/* dissector_tables_view.cpp
 * Tree view of Dissector Table data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "dissector_tables_view.h"
#include <ui/qt/models/dissector_tables_model.h>

DissectorTablesTreeView::DissectorTablesTreeView(QWidget *parent) : QTreeView(parent)
{
}

void DissectorTablesTreeView::currentChanged(const QModelIndex &current, const QModelIndex &previous)
{
    if (current.isValid())
    {
        ((DissectorTablesProxyModel*)model())->adjustHeader(current);
    }

    QTreeView::currentChanged(current, previous);
}
