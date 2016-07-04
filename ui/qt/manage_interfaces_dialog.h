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

#include "geometry_state_dialog.h"
#include <QStyledItemDelegate>

class QTreeWidget;
class QTreeWidgetItem;
class QStandardItemModel;

class QLineEdit;

class PathChooserDelegate : public QStyledItemDelegate
{
    Q_OBJECT

private:
    QTreeWidget* tree_;
    mutable QTreeWidgetItem *path_item_;
    mutable QWidget *path_editor_;
    mutable QLineEdit *path_le_;

public:
    PathChooserDelegate(QObject *parent = 0);
    ~PathChooserDelegate();

    void setTree(QTreeWidget* tree) { tree_ = tree; }

protected:
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    void updateEditorGeometry (QWidget * editor, const QStyleOptionViewItem & option, const QModelIndex & index) const;

private slots:
    void stopEditor();
    void browse_button_clicked();
};


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
    PathChooserDelegate new_pipe_item_delegate_;

    void showPipes();
    void showLocalInterfaces();
    void showRemoteInterfaces();
    void saveLocalHideChanges(QTreeWidgetItem *item);
    void saveLocalCommentChanges(QTreeWidgetItem *item);
#if 0 // Not needed?
    void checkBoxChanged(QTreeWidgetItem *item);
#endif

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
    void pipeAccepted();
    void on_pipeList_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);

    void localAccepted();
    void localListItemDoubleClicked(QTreeWidgetItem * item, int column);

#ifdef HAVE_PCAP_REMOTE
    void on_addRemote_clicked();
    void on_delRemote_clicked();
    void remoteAccepted();
    void on_remoteList_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_remoteList_itemClicked(QTreeWidgetItem *item, int column);
    void addRemoteInterfaces(GList *rlist, remote_options *roptions);
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
