/* interface_sort_filter_model.h
 * Proxy model for the display of interface data for the interface tree
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

#ifndef INTERFACE_SORT_FILTER_MODEL_H
#define INTERFACE_SORT_FILTER_MODEL_H

#include <config.h>

#include "ui/qt/interface_tree_model.h"

#include <glib.h>

#include <QSortFilterProxyModel>

class InterfaceSortFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    InterfaceSortFilterModel(QObject *parent);

    void setStoreOnChange(bool storeOnChange);
    void resetAllFilter();

    void setFilterHidden(bool filter);
    bool filterHidden() const;
    int interfacesHidden();
    void toggleFilterHidden();

#ifdef HAVE_PCAP_REMOTE
    void setRemoteDisplay(bool remoteDisplay);
    bool remoteDisplay();
    void toggleRemoteDisplay();
    bool remoteInterfacesExist();
#endif

    void setInterfaceTypeVisible(int ifType, bool visible);
    bool isInterfaceTypeShown(int ifType) const;
    void setFilterByType(bool filter, bool invert = false);
    bool filterByType() const;
    void toggleTypeVisibility(int ifType);

    QList<int> typesDisplayed();

    void setColumns(QList<InterfaceTreeColumns> columns);
    int mapSourceToColumn(InterfaceTreeColumns mdlIndex);

    QModelIndex mapToSource(const QModelIndex &proxyIndex) const;
    QModelIndex mapFromSource(const QModelIndex &sourceIndex) const;

    QString interfaceError();

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex & source_parent) const;
    bool filterAcceptsColumn(int source_column, const QModelIndex & source_parent) const;

private:
    bool _filterHidden;
    bool _filterTypes;
    bool _invertTypeFilter;
    bool _storeOnChange;

#ifdef HAVE_PCAP_REMOTE
    bool _remoteDisplay;
#endif

    QList<int> displayHiddenTypes;

    QList<InterfaceTreeColumns> _columns;

private slots:
    void resetPreferenceData();
};

#endif // INTERFACE_SORT_FILTER_MODEL_H

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
