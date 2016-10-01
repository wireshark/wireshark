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

#ifdef HAVE_LIBPCAP
#include "ui/capture_globals.h"
#endif

#include <glib.h>

#include <QSortFilterProxyModel>

class InterfaceSortFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    InterfaceSortFilterModel(QObject *parent);

    void setFilterHidden(bool filter);
    bool filterHidden() const;
    int interfacesHidden();

    void setInterfaceTypeVisible(int ifType, bool visible);
    bool isInterfaceTypeShown(int ifType) const;

    QList<int> typesDisplayed();

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex & source_parent) const;

private:
    bool _filterHidden;

    QList<int> displayHiddenTypes;

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
