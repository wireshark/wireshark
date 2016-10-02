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

#include "interface_tree_model.h"
#include "interface_sort_filter_model.h"

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

    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(resetPreferenceData()));

    resetPreferenceData();
}

void InterfaceSortFilterModel::setFilterHidden(bool filter)
{
    _filterHidden = filter;

    invalidate();
}

void InterfaceSortFilterModel::resetPreferenceData()
{
    displayHiddenTypes.clear();
    QString stored_prefs(prefs.gui_interfaces_hide_types);
    if ( stored_prefs.length() > 0 )
    {
        QStringList ifTypesStored = stored_prefs.split(',');
        foreach(QString val, ifTypesStored)
        {
            int i_val = val.toInt();
            if ( ! displayHiddenTypes.contains(i_val) )
                displayHiddenTypes.append(i_val);
        }
    }

    invalidate();
}

bool InterfaceSortFilterModel::filterHidden() const
{
    return _filterHidden;
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
#ifdef HAVE_LIBPCAP
    if ( ! global_capture_opts.all_ifaces )
        return shownTypes;

    for(unsigned int idx = 0; idx < global_capture_opts.all_ifaces->len; idx++)
    {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);
        if ( ! device.hidden )
        {
            if ( ! shownTypes.contains(device.if_info.type) )
                shownTypes.append(device.if_info.type);
        }
    }
#endif
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
    foreach(int i, displayHiddenTypes)
    {
        new_pref.append(QString("%1,").arg(i));
    }
    if (new_pref.length() > 0)
        new_pref = new_pref.left(new_pref.length() - 1);

    prefs.gui_interfaces_hide_types = qstring_strdup(new_pref);

    prefs_main_write();

    invalidate();
}

bool InterfaceSortFilterModel::isInterfaceTypeShown(int ifType) const
{
    if ( ! displayHiddenTypes.contains(ifType) )
        return true;

    return false;
}

bool InterfaceSortFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex & sourceParent) const
{
    QModelIndex realIndex = sourceModel()->index(sourceRow, 0, sourceParent);

    if ( ! realIndex.isValid() )
        return false;

#ifdef HAVE_LIBPCAP
    int idx = realIndex.row();

    /* No data loaded, we do not display anything */
    if ( ! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len <= (guint) idx )
        return false;

    interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

    if ( device.hidden && _filterHidden )
        return false;

    if ( ! isInterfaceTypeShown(device.if_info.type) )
        return false;
#endif

    return true;
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
