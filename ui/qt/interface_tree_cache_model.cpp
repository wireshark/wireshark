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

#include "wiretap/wtap.h"

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

    checkableColumns << IFTREE_COL_HIDDEN << IFTREE_COL_PROMISCUOUSMODE << IFTREE_COL_MONITOR_MODE;

    editableColumns << IFTREE_COL_INTERFACE_COMMENT << IFTREE_COL_SNAPLEN;

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    editableColumns << IFTREE_COL_BUFFERLEN;
#endif
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

    QMap<char**, QStringList> prefStorage;

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
                 * value has to be handled separately. Comments are stored only in the preference file
                 * and applied to the data name during loading. Therefore comments are not handled here */

                if ( col == IFTREE_COL_HIDDEN )
                {
                    device.hidden = saveValue.toBool();
                }
#ifdef HAVE_EXTCAP
                else if ( device.if_info.type == IF_EXTCAP )
                {
                    /* extcap interfaces do not have the following columns.
                     * ATTENTION: all generic columns must be added, BEFORE this
                     * if-clause, or they will be ignored for extcap interfaces */
                }
#endif
                else if ( col == IFTREE_COL_PROMISCUOUSMODE )
                {
                    device.pmode = saveValue.toBool();
                }
#ifdef HAVE_PCAP_CREATE
                else if ( col == IFTREE_COL_MONITOR_MODE )
                {
                    device.monitor_mode_enabled = saveValue.toBool();
                }
#endif
                else if ( col == IFTREE_COL_SNAPLEN )
                {
                    int iVal = saveValue.toInt();
                    if ( iVal != WTAP_MAX_PACKET_SIZE )
                    {
                        device.has_snaplen = true;
                        device.snaplen = iVal;
                    }
                    else
                    {
                        device.has_snaplen = false;
                        device.snaplen = WTAP_MAX_PACKET_SIZE;
                    }
                }
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
                else if ( col == IFTREE_COL_BUFFERLEN )
                {
                    device.buffer = saveValue.toInt();
                }
#endif

                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, idx);
                g_array_insert_val(global_capture_opts.all_ifaces, idx, device);

                ++it;
            }
        }

        QVariant content = getColumnContent(idx, IFTREE_COL_HIDDEN, Qt::CheckStateRole);
        if ( content.isValid() && static_cast<Qt::CheckState>(content.toInt()) == Qt::Unchecked )
                prefStorage[&prefs.capture_devices_hide] << QString(device.name);

        content = getColumnContent(idx, IFTREE_COL_INTERFACE_COMMENT);
        if ( content.isValid() && content.toString().size() > 0 )
            prefStorage[&prefs.capture_devices_descr] << QString("%1(%2)").arg(device.name).arg(content.toString());

        bool allowExtendedColumns = true;
#ifdef HAVE_EXTCAP
        if ( device.if_info.type == IF_EXTCAP )
            allowExtendedColumns = false;
#endif
        if ( allowExtendedColumns )
        {
            content = getColumnContent(idx, IFTREE_COL_PROMISCUOUSMODE, Qt::CheckStateRole);
            if ( content.isValid() )
            {
                bool value = static_cast<Qt::CheckState>(content.toInt()) == Qt::Checked;
                prefStorage[&prefs.capture_devices_pmode]  << QString("%1(%2)").arg(device.name).arg(value ? 1 : 0);
            }

#ifdef HAVE_PCAP_CREATE
            content = getColumnContent(idx, IFTREE_COL_MONITOR_MODE, Qt::CheckStateRole);
            if ( content.isValid() && static_cast<Qt::CheckState>(content.toInt()) == Qt::Checked )
                    prefStorage[&prefs.capture_devices_monitor_mode] << QString(device.name);
#endif

            content = getColumnContent(idx, IFTREE_COL_SNAPLEN);
            if ( content.isValid() )
            {
                int value = content.toInt();
                prefStorage[&prefs.capture_devices_snaplen]  <<
                        QString("%1:%2(%3)").arg(device.name).
                        arg(device.has_snaplen ? 1 : 0).
                        arg(device.has_snaplen ? value : WTAP_MAX_PACKET_SIZE);
            }

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
            content = getColumnContent(idx, IFTREE_COL_BUFFERLEN);
            if ( content.isValid() )
            {
                int value = content.toInt();
                if ( value != -1 )
                {
                    prefStorage[&prefs.capture_devices_buffersize]  <<
                            QString("%1(%2)").arg(device.name).
                            arg(value);
                }
            }
#endif
        }
    }

    QMap<char**, QStringList>::const_iterator it = prefStorage.constBegin();
    while ( it != prefStorage.constEnd() )
    {
        char ** key = it.key();

        g_free(*key);
        *key = qstring_strdup(it.value().join(","));

        ++it;
    }
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

/* This checks if the column can be edited for the given index. This differs from
 * isAllowedToBeChanged in such a way, that it is only used in flags and not any
 * other method.*/
bool InterfaceTreeCacheModel::isAllowedToBeEdited(const QModelIndex &index) const
{
    if ( ! index.isValid() || ! global_capture_opts.all_ifaces )
         return false;

     int idx = index.row();
     if ( (unsigned int) idx >= global_capture_opts.all_ifaces->len )
         return false;

     interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

     InterfaceTreeColumns col = (InterfaceTreeColumns) index.column();
#ifdef HAVE_EXTCAP
     if ( device.if_info.type == IF_EXTCAP )
     {
         /* extcap interfaces do not have those settings */
         if ( col == IFTREE_COL_PROMISCUOUSMODE || col == IFTREE_COL_SNAPLEN )
             return false;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
         if ( col == IFTREE_COL_BUFFERLEN )
             return false;
#endif
     }
#endif

     return true;
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

    if ( changeIsAllowed(col) && isAllowedToBeChanged(index) && isAllowedToBeEdited(index) )
    {
        if ( checkableColumns.contains(col) )
        {
            flags |= Qt::ItemIsUserCheckable;
        }
        else
        {
            flags |= Qt::ItemIsEditable;
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
            QVariant saveValue = value;

            QMap<InterfaceTreeColumns, QVariant> * dataField = 0;
            /* obtain the list of already stored changes for this row. If none exist
             * create a new storage row for this entry */
            if ( ( dataField = storage->value(row, 0) ) == 0 )
            {
                dataField = new QMap<InterfaceTreeColumns, QVariant>();
                storage->insert(row, dataField);
            }

            dataField->insert(col, saveValue);

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

    if ( isAllowedToBeEdited(index) )
    {
        if ( ( ( role == Qt::DisplayRole || role == Qt::EditRole ) && editableColumns.contains(col) ) ||
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
    }
    else
    {
        if ( role == Qt::CheckStateRole )
            return QVariant();
        else if ( role == Qt::DisplayRole )
            return QString("-");
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

