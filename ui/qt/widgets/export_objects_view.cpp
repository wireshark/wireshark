/* export_objects_view.cpp
 * Tree view of Export object data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "export_objects_view.h"
#include <ui/qt/models/export_objects_model.h>

ExportObjectsTreeView::ExportObjectsTreeView(QWidget *parent) : QTreeView(parent)
{
}

void ExportObjectsTreeView::currentChanged(const QModelIndex &current, const QModelIndex &previous)
{
    emit currentIndexChanged(current);

    QTreeView::currentChanged(current, previous);
}
