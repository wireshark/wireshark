/* manage_interfaces_dialog.h
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

#ifndef MANAGE_INTERFACES_DIALOG_H
#define MANAGE_INTERFACES_DIALOG_H

#include <config.h>

#include <glib.h>
#include "capture_opts.h"

#include "ui/qt/interface_tree_cache_model.h"
#include "ui/qt/interface_sort_filter_model.h"

#include "geometry_state_dialog.h"
#include <QStyledItemDelegate>

class QTreeWidget;
class QTreeWidgetItem;
class QStandardItemModel;

class QLineEdit;


namespace Ui {
class ManageInterfacesDialog;
}

class ManageInterfacesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit ManageInterfacesDialog(QWidget *parent = 0);
    ~ManageInterfacesDialog();

private:
    Ui::ManageInterfacesDialog *ui;

    InterfaceTreeCacheModel * sourceModel;
    InterfaceSortFilterModel * proxyModel;
    InterfaceSortFilterModel * pipeProxyModel;

    void showRemoteInterfaces();

signals:
    void ifsChanged();
#ifdef HAVE_PCAP_REMOTE
    void remoteAdded(GList *rlist, remote_options *roptions);
    void remoteSettingsChanged(interface_t *iface);
#endif

private slots:
    void updateWidgets();

    void on_buttonBox_accepted();

    void on_addPipe_clicked();
    void on_delPipe_clicked();

    void onSelectionChanged(const QItemSelection &sel, const QItemSelection &desel);

#ifdef HAVE_PCAP_REMOTE
    void on_addRemote_clicked();
    void on_delRemote_clicked();
    void remoteAccepted();
    void on_remoteList_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_remoteList_itemClicked(QTreeWidgetItem *item, int column);
    void addRemoteInterfaces(GList *rlist, remote_options *roptions);
    void updateRemoteInterfaceList(GList *rlist, remote_options *roptions);
    void setRemoteSettings(interface_t *iface);
    void remoteSelectionChanged(QTreeWidgetItem* item, int col);
    void on_remoteSettings_clicked();
#endif
    void on_buttonBox_helpRequested();
};

#endif // MANAGE_INTERFACES_DIALOG_H

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
