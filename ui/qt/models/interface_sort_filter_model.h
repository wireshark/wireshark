/** @file
 *
 * Proxy model for the display of interface data for the interface tree
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_SORT_FILTER_MODEL_H
#define INTERFACE_SORT_FILTER_MODEL_H

#include <config.h>

#include <ui/qt/models/interface_tree_model.h>

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

    void setSortByActivity(bool sort);
    bool sortByActivity() const;

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
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

private:
    bool _filterHidden;
    bool _filterTypes;
    bool _invertTypeFilter;
    bool _storeOnChange;
    bool _sortByActivity;

#ifdef HAVE_PCAP_REMOTE
    bool _remoteDisplay;
#endif

    QList<int> displayHiddenTypes;

    QList<InterfaceTreeColumns> _columns;

private slots:
    void resetPreferenceData();
};

#endif // INTERFACE_SORT_FILTER_MODEL_H
