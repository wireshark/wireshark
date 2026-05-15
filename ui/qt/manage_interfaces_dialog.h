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

#include <ui/capture_opts.h>

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

/**
 * @brief Dialog for managing capture interfaces.
 */
class ManageInterfacesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ManageInterfacesDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit ManageInterfacesDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the ManageInterfacesDialog.
     */
    ~ManageInterfacesDialog();

private:
    /** Pointer to the UI elements. */
    Ui::ManageInterfacesDialog *ui;

    /** Pointer to the source tree cache model for interfaces. */
    InterfaceTreeCacheModel * sourceModel;

    /** Pointer to the proxy model for sorting and filtering interfaces. */
    InterfaceSortFilterModel * proxyModel;

    /** Pointer to the proxy model for sorting and filtering pipe interfaces. */
    InterfaceSortFilterModel * pipeProxyModel;

    /**
     * @brief Shows the remote interfaces view.
     */
    void showRemoteInterfaces();

#ifdef HAVE_PCAP_REMOTE
    /**
     * @brief Adds a remote interface using a variant map.
     * @param unnamed The variant map containing remote configuration data.
     */
    void addRemote(const QVariantMap&&);

    /**
     * @brief Populates the list with existing remote interfaces.
     */
    void populateExistingRemotes();
#endif

signals:
    /**
     * @brief Signal emitted when the list of interfaces has changed.
     */
    void ifsChanged();

#ifdef HAVE_PCAP_REMOTE
    /**
     * @brief Signal emitted when remote interfaces are added.
     * @param rlist The list of remote interfaces.
     * @param roptions The remote options applied.
     */
    void remoteAdded(GList *rlist, remote_options *roptions);

    /**
     * @brief Signal emitted when settings for a remote interface change.
     * @param iface Pointer to the remote interface.
     */
    void remoteSettingsChanged(interface_t *iface);
#endif

private slots:
    /**
     * @brief Updates the state of the UI widgets.
     */
    void updateWidgets();

#ifdef HAVE_LIBPCAP
    /**
     * @brief Slot triggered when the add pipe button is clicked.
     */
    void on_addPipe_clicked();

    /**
     * @brief Slot triggered when the delete pipe button is clicked.
     */
    void on_delPipe_clicked();
#endif

#ifdef HAVE_PCAP_REMOTE
    /**
     * @brief Slot triggered when the add remote button is clicked.
     */
    void on_addRemote_clicked();

    /**
     * @brief Slot triggered when the delete remote button is clicked.
     */
    void on_delRemote_clicked();

    /**
     * @brief Slot triggered when the remote dialog is accepted.
     */
    void remoteAccepted();

    /**
     * @brief Slot triggered when the current item in the remote list changes.
     * @param current The newly selected item.
     * @param previous The previously selected item.
     */
    void on_remoteList_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);

    /**
     * @brief Slot triggered when an item in the remote list is clicked.
     * @param item The clicked item.
     * @param column The clicked column index.
     */
    void on_remoteList_itemClicked(QTreeWidgetItem *item, int column);

    /**
     * @brief Adds remote interfaces from a given list.
     * @param rlist The list of remote interfaces to add.
     * @param roptions The remote options to apply.
     */
    void addRemoteInterfaces(GList *rlist, remote_options *roptions);

    /**
     * @brief Updates the remote interface list with new options.
     * @param capture_opts Pointer to capture options.
     * @param rlist The list of remote interfaces.
     * @param roptions The remote options applied.
     */
    void updateRemoteInterfaceList(capture_options* capture_opts, GList *rlist, remote_options *roptions);

    /**
     * @brief Sets the settings for a specific remote interface.
     * @param iface Pointer to the remote interface.
     */
    void setRemoteSettings(interface_t *iface);

    /**
     * @brief Slot triggered when the selection in the remote list changes.
     * @param item The selected item.
     * @param col The selected column index.
     */
    void remoteSelectionChanged(QTreeWidgetItem* item, int col);

    /**
     * @brief Slot triggered when the remote settings button is clicked.
     */
    void on_remoteSettings_clicked();
#endif

    /**
     * @brief Slot triggered when help is requested via the button box.
     */
    void on_buttonBox_helpRequested();
};

#endif // MANAGE_INTERFACES_DIALOG_H
