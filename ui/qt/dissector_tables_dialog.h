/* dissector_tables_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef DISSECTOR_TABLES_DIALOG_H
#define DISSECTOR_TABLES_DIALOG_H

#include <glib.h>

#include <epan/ftypes/ftypes.h>

#include "geometry_state_dialog.h"

namespace Ui {
class DissectorTablesDialog;
}

class QTreeWidgetItem;

class DissectorTablesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit DissectorTablesDialog(QWidget *parent = 0);
    ~DissectorTablesDialog();

private slots:
    void on_tableTreeWidget_itemSelectionChanged();

private:
    Ui::DissectorTablesDialog *ui;
    QList<QTreeWidgetItem *> string_dissectors_;
    QList<QTreeWidgetItem *> integer_dissectors_;
    QList<QTreeWidgetItem *> custom_dissectors_;
    QList<QTreeWidgetItem *> heuristic_dissectors_;

    static void gatherTableNames(const char *short_name, const char *table_name, gpointer dlg_ptr);
    static void gatherProtocolDecodes(const char *, ftenum_t selector_type, gpointer key, gpointer value, gpointer list_ptr);
    static void gatherHeurTableNames(const char *table_name, struct heur_dissector_list *list, gpointer dlg_ptr);
    static void gatherHeurProtocolDecodes(const char *, struct heur_dtbl_entry *dtbl_entry, gpointer list_ptr);
};

#endif // DISSECTOR_TABLES_DIALOG_H

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
