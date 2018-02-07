/* dissector_tables_view.h
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

class DissectorTablesTreeView : public QTreeView
{
    Q_OBJECT
public:
    DissectorTablesTreeView(QWidget *parent = 0);

protected slots:
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // DISSECTOR_TABLES_VIEW_H

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
