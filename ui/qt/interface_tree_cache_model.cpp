/* interface_tree_cache_model.cpp
 * Model caching interface changes before sending them to global storage
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


#include "ui/qt/interface_tree_cache_model.h"

#include "glib.h"

#include "epan/prefs.h"

#include "qt_ui_utils.h"
#include "ui/capture_globals.h"
#include "wireshark_application.h"

InterfaceTreeCacheModel::InterfaceTreeCacheModel(QObject *parent) :
    QIdentityProxyModel(parent)
{
    /* ATTENTION: This cache model is not intended to be used with anything
     * else then InterfaceTreeModel, and will break with anything else
     * leading to unintended results. */
    sourceModel = new InterfaceTreeModel(parent);

    QIdentityProxyModel::setSourceModel(sourceModel);
    storage = new QMap<int, QMap<InterfaceTreeColumns, QVariant> *>();

    checkableColumns << IFTREE_COL_HIDDEN;

    editableColumns << IFTREE_COL_INTERFACE_COMMENT;
}

InterfaceTreeCacheModel::~InterfaceTreeCacheModel()
{
    delete storage;
    delete sourceModel;
}

void InterfaceTreeCacheModel::reset(int row)
{
    if ( row < 0 )
    {
        delete storage;
        storage = new QMap<int, QMap<InterfaceTreeColumns, QVariant> *>();
    }
    else
    {
        if ( storage->count() > row )
            storage->remove(storage->keys().at(row));
    }
}

QVariant InterfaceTreeCacheModel::getColumnContent(int idx, int col, int role)
{
    return InterfaceTreeCacheModel::data(index(idx, col), role);
}

void InterfaceTreeCacheModel::save()
{
    if ( storage->count() == 0 )
        return;

    QStringList hideList;
    QStringList commentList;

    for(unsigned int idx = 0; idx < global_capture_opts.all_ifaces->len; idx++)
    {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);
        if (! device.name )
            continue;

        /* Try to load a saved value row for this index */
        QMap<InterfaceTreeColumns, QVariant> * dataField = storage->value(idx, 0);

        /* Handle the storing of values for this device here */
        if ( dataField )
        {
            QMap<InterfaceTreeColumns, QVariant>::const_iterator it = dataField->constBegin();
            while ( it != dataField->constEnd() )
            {
                InterfaceTreeColumns col = it.key();
                QVariant saveValue = it.value();

                /* Setting the field values for each individual saved value cannot be generic, as the
                 * struct cannot be accessed generically. Therefore below, each individually changed
                 * value has to be handled separately */

                if ( col == IFTREE_COL_HIDDEN )
                {
                    device.hidden = saveValue.toBool();
                }

                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, idx);
                g_array_insert_val(global_capture_opts.all_ifaces, idx, device);

                ++it;
            }
        }

        QVariant content = getColumnContent(idx, IFTREE_COL_HIDDEN, Qt::CheckStateRole);
        if ( content.isValid() && static_cast<Qt::CheckState>(content.toInt()) == Qt::Unchecked )
                hideList << QString(device.name);

        content = getColumnContent(idx, IFTREE_COL_INTERFACE_COMMENT);
        if ( content.isValid() && content.toString().size() > 0 )
            commentList << QString("%1(%2)").arg(device.name).arg(content.toString());
    }

    g_free(prefs.capture_devices_hide);
    prefs.capture_devices_hide = qstring_strdup(hideList.join(","));

    g_free(prefs.capture_devices_descr);
    prefs.capture_devices_descr = qstring_strdup(commentList.join(","));
}

int InterfaceTreeCacheModel::rowCount(const QModelIndex & parent) const
{
    return sourceModel->rowCount(parent);
}

bool InterfaceTreeCacheModel::changeIsAllowed(InterfaceTreeColumns col) const
{
    if ( editableColumns.contains(col) || checkableColumns.contains(col) )
        return true;
    return false;
}

bool InterfaceTreeCacheModel::isAllowedToBeChanged(const QModelIndex &index) const
{
    if ( ! index.isValid() || ! global_capture_opts.all_ifaces )
        return false;

    int idx = index.row();
    if ( (unsigned int) idx >= global_capture_opts.all_ifaces->len )
        return false;

    interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

    InterfaceTreeColumns col = (InterfaceTreeColumns) index.column();
    if ( col == IFTREE_COL_HIDDEN )
    {
        if ( prefs.capture_device )
        {
            if ( ! g_strcmp0(prefs.capture_device, device.display_name) )
                return false;
        }
    }

    return true;
}

Qt::ItemFlags InterfaceTreeCacheModel::flags(const QModelIndex &index) const
{
    if ( ! index.isValid() )
        return 0;

    Qt::ItemFlags flags = Qt::ItemIsEnabled | Qt::ItemIsSelectable;

    InterfaceTreeColumns col = (InterfaceTreeColumns) index.column();

    if ( changeIsAllowed(col) && isAllowedToBeChanged(index) )
    {
        if ( checkableColumns.contains(col) )
        {
            flags = Qt::ItemIsEnabled | Qt::ItemIsUserCheckable;
        }
        else
        {
            flags = Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable;
        }
    }

    return flags;
}

bool InterfaceTreeCacheModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if ( ! index.isValid() )
        return false;

    if ( ! isAllowedToBeChanged(index) )
        return false;

    int row = index.row();
    InterfaceTreeColumns col = (InterfaceTreeColumns)index.column();

    if ( role == Qt::CheckStateRole || role == Qt::EditRole )
    {
        if ( changeIsAllowed( col ) )
        {
            QMap<InterfaceTreeColumns, QVariant> * dataField = 0;
            /* obtain the list of already stored changes for this row. If none exist
             * create a new storage row for this entry */
            if ( ( dataField = storage->value(row, 0) ) == 0 )
            {
                dataField = new QMap<InterfaceTreeColumns, QVariant>();
                storage->insert(row, dataField);
            }

            dataField->insert(col, value);

            return true;
        }
    }

    return false;
}

QVariant InterfaceTreeCacheModel::data(const QModelIndex &index, int role) const
{
    if ( ! index.isValid() )
        return QVariant();

    int row = index.row();
    InterfaceTreeColumns col = (InterfaceTreeColumns)index.column();

    if ( ( role == Qt::DisplayRole && editableColumns.contains(col) ) ||
            ( role == Qt::CheckStateRole && checkableColumns.contains(col) ) )
    {
        QMap<InterfaceTreeColumns, QVariant> * dataField = 0;
        if ( ( dataField = storage->value(row, 0) ) != 0 )
        {
            if ( dataField->contains(col) )
            {
                return dataField->value(col, QVariant());
            }
        }
    }

    return sourceModel->data(index, role);
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

