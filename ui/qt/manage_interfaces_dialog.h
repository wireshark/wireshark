/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MANAGE_INTERFACES_DIALOG_H
#define MANAGE_INTERFACES_DIALOG_H

#include <config.h>

#include "capture_opts.h"

#include <ui/qt/models/interface_tree_cache_model.h>
#include <ui/qt/models/interface_sort_filter_model.h>

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
#ifdef HAVE_PCAP_REMOTE
    void addRemote(const QVariantMap&&);
    void populateExistingRemotes();
#endif

signals:
    void ifsChanged();
#ifdef HAVE_PCAP_REMOTE
    void remoteAdded(GList *rlist, remote_options *roptions);
    void remoteSettingsChanged(interface_t *iface);
#endif

private slots:
    void updateWidgets();

#ifdef HAVE_LIBPCAP
    void on_addPipe_clicked();
    void on_delPipe_clicked();
#endif

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
