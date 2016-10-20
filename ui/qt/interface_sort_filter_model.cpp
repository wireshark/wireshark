/* interface_sort_filter_model.cpp
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

#include "ui/qt/interface_tree_model.h"
#include "ui/qt/interface_sort_filter_model.h"

#include <glib.h>

#include <epan/prefs.h>
#include <ui/preference_utils.h>
#include <ui/qt/qt_ui_utils.h>

#include "wireshark_application.h"

#include <QAbstractItemModel>

InterfaceSortFilterModel::InterfaceSortFilterModel(QObject *parent) :
        QSortFilterProxyModel(parent)
{
    _filterHidden = true;
    _filterTypes = true;
    _invertTypeFilter = false;

    /* Adding all columns, to have a default setting */
    for ( int col = 0; col < IFTREE_COL_MAX; col++ )
        _columns.append((InterfaceTreeColumns)col);

    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(resetPreferenceData()));

    resetPreferenceData();
}

void InterfaceSortFilterModel::setFilterHidden(bool filter)
{
    _filterHidden = filter;

    invalidate();
}

void InterfaceSortFilterModel::setFilterByType(bool filter, bool invert)
{
    _filterTypes = filter;
    _invertTypeFilter = invert;

    invalidate();
}

void InterfaceSortFilterModel::resetPreferenceData()
{
    displayHiddenTypes.clear();
    QString stored_prefs(prefs.gui_interfaces_hide_types);
    if ( stored_prefs.length() > 0 )
    {
        QStringList ifTypesStored = stored_prefs.split(',');
        QStringList::const_iterator it = ifTypesStored.constBegin();
        while(it != ifTypesStored.constEnd())
        {
            int i_val = (*it).toInt();
            if ( ! displayHiddenTypes.contains(i_val) )
                displayHiddenTypes.append(i_val);
            ++it;
        }
    }

    _filterHidden = ! prefs.gui_interfaces_show_hidden;

    invalidate();
}

bool InterfaceSortFilterModel::filterHidden() const
{
    return _filterHidden;
}

void InterfaceSortFilterModel::toggleFilterHidden()
{
    _filterHidden = ! _filterHidden;

    prefs.gui_interfaces_show_hidden = ! _filterHidden;

    prefs_main_write();

    invalidateFilter();
    invalidate();
}

bool InterfaceSortFilterModel::filterByType() const
{
    return _filterTypes;
}

int InterfaceSortFilterModel::interfacesHidden()
{
#ifdef HAVE_LIBPCAP
    if ( ! global_capture_opts.all_ifaces )
        return 0;
#endif

    return sourceModel()->rowCount() - rowCount();
}

QList<int> InterfaceSortFilterModel::typesDisplayed()
{
    QList<int> shownTypes;

    if ( sourceModel()->rowCount() == 0 )
        return shownTypes;

    for (int idx = 0; idx < sourceModel()->rowCount(); idx++)
    {
        int type = ((InterfaceTreeModel *)sourceModel())->getColumnContent(idx, IFTREE_COL_TYPE).toInt();
        bool hidden = ((InterfaceTreeModel *)sourceModel())->getColumnContent(idx, IFTREE_COL_HIDDEN).toBool();

        if ( ! hidden )
        {
            if ( ! shownTypes.contains(type) )
                shownTypes.append(type);
        }
    }

    return shownTypes;
}

void InterfaceSortFilterModel::setInterfaceTypeVisible(int ifType, bool visible)
{
    if ( visible && displayHiddenTypes.contains(ifType) )
        displayHiddenTypes.removeAll(ifType);
    else if ( ! visible && ! displayHiddenTypes.contains(ifType) )
        displayHiddenTypes.append(ifType);
    else
        /* Nothing should have changed */
        return;

    QString new_pref;
    QList<int>::const_iterator it = displayHiddenTypes.constBegin();
    while( it != displayHiddenTypes.constEnd() )
    {
        new_pref.append(QString("%1,").arg(*it));
        ++it;
    }
    if (new_pref.length() > 0)
        new_pref = new_pref.left(new_pref.length() - 1);

    prefs.gui_interfaces_hide_types = qstring_strdup(new_pref);

    prefs_main_write();

    invalidateFilter();
    invalidate();
}

void InterfaceSortFilterModel::toggleTypeVisibility(int ifType)
{
    bool checked = isInterfaceTypeShown(ifType);

    setInterfaceTypeVisible(ifType, checked ? false : true);
}

bool InterfaceSortFilterModel::isInterfaceTypeShown(int ifType) const
{
    bool result = false;

    if ( displayHiddenTypes.size() == 0 )
        result = true;
    else if ( ! displayHiddenTypes.contains(ifType) )
        result = true;

    return ( ( _invertTypeFilter && ! result ) || ( ! _invertTypeFilter && result ) );
}

bool InterfaceSortFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex & sourceParent) const
{
    QModelIndex realIndex = sourceModel()->index(sourceRow, 0, sourceParent);

    if ( ! realIndex.isValid() )
        return false;

#ifdef HAVE_LIBPCAP
    int idx = realIndex.row();

    /* No data loaded, we do not display anything */
    if ( sourceModel()->rowCount() == 0 )
        return false;

    int type = ((InterfaceTreeModel *)sourceModel())->getColumnContent(idx, IFTREE_COL_TYPE).toInt();
    bool hidden = ((InterfaceTreeModel *)sourceModel())->getColumnContent(idx, IFTREE_COL_HIDDEN, Qt::UserRole).toBool();

    if ( hidden && _filterHidden )
        return false;

    if ( _filterTypes && ! isInterfaceTypeShown(type) )
        return false;
#endif

    return true;
}

bool InterfaceSortFilterModel::filterAcceptsColumn(int sourceColumn, const QModelIndex & sourceParent) const
{
    QModelIndex realIndex = sourceModel()->index(0, sourceColumn, sourceParent);

    if ( ! realIndex.isValid() )
        return false;

    if ( ! _columns.contains((InterfaceTreeColumns)sourceColumn) )
        return false;

    return true;
}

void InterfaceSortFilterModel::setColumns(QList<InterfaceTreeColumns> columns)
{
    _columns.clear();
    _columns.append(columns);
}

int InterfaceSortFilterModel::mapSourceToColumn(InterfaceTreeColumns mdlIndex)
{
    if ( ! _columns.contains(mdlIndex) )
        return -1;

    return _columns.indexOf(mdlIndex, 0);
}

QModelIndex InterfaceSortFilterModel::mapToSource(const QModelIndex &proxyIndex) const
{
    if ( ! proxyIndex.isValid() )
        return QModelIndex();

    QModelIndex baseIndex = QSortFilterProxyModel::mapToSource(proxyIndex);
    QModelIndex newIndex = sourceModel()->index(baseIndex.row(), _columns.at(proxyIndex.column()));

    return newIndex;
}

QModelIndex InterfaceSortFilterModel::mapFromSource(const QModelIndex &sourceIndex) const
{
    if ( ! sourceIndex.isValid() )
        return QModelIndex();
    else if ( ! _columns.contains( (InterfaceTreeColumns) sourceIndex.column() ) )
        return QModelIndex();

    QModelIndex newIndex = QSortFilterProxyModel::mapFromSource(sourceIndex);

    return index(newIndex.row(), _columns.indexOf((InterfaceTreeColumns) sourceIndex.column()));
}

QString InterfaceSortFilterModel::interfaceError()
{
    QString result;

    InterfaceTreeModel * sourceModel = dynamic_cast<InterfaceTreeModel *>(this->sourceModel());
    if ( sourceModel != NULL )
        result = sourceModel->interfaceError();

    if ( result.size() == 0 && rowCount() == 0 )
        result = QString(tr("No interfaces to be displayed. %1 interfaces filtered.")).arg(interfacesHidden());

    return result;
}

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
