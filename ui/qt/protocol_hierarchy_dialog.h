/* protocol_hierarchy_dialog.h
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

#ifndef PROTOCOL_HIERARCHY_DIALOG_H
#define PROTOCOL_HIERARCHY_DIALOG_H

#include <QMenu>

#include "filter_action.h"
#include "percent_bar_delegate.h"
#include "wireshark_dialog.h"

class QPushButton;
class QTreeWidgetItem;

namespace Ui {
class ProtocolHierarchyDialog;
}

class ProtocolHierarchyDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ProtocolHierarchyDialog(QWidget &parent, CaptureFile &cf);
    ~ProtocolHierarchyDialog();

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

private slots:
    void showProtoHierMenu(QPoint pos);
    void filterActionTriggered();
    void on_actionCopyAsCsv_triggered();
    void on_actionCopyAsYaml_triggered();
    void on_buttonBox_helpRequested();

private:
    Ui::ProtocolHierarchyDialog *ui;
    QPushButton *copy_button_;
    QMenu ctx_menu_;
    PercentBarDelegate percent_bar_delegate_;
    QString display_filter_;

    // Callback for g_node_children_foreach
    static void addTreeNode(GNode *node, gpointer data);
    void updateWidgets();
    QList<QVariant> protoHierRowData(QTreeWidgetItem *item) const;
};

#endif // PROTOCOL_HIERARCHY_DIALOG_H

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
