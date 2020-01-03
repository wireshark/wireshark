/* export_objects_view.h
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

class ExportObjectsTreeView : public QTreeView
{
    Q_OBJECT
public:
    ExportObjectsTreeView(QWidget *parent = 0);

signals:
    void currentIndexChanged(const QModelIndex &current);

protected slots:
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // EXPORT_OBJECTS_VIEW_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
