/* interface_tree_cache_model.cpp
 * Model caching interface changes before sending them to global storage
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include <ui/qt/models/interface_tree_cache_model.h>

#include "glib.h"

#include "epan/prefs.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include "ui/capture_globals.h"
#include "wsutil/utf8_entities.h"

#include "wiretap/wtap.h"

#include "wireshark_application.h"

#include <QIdentityProxyModel>

InterfaceTreeCacheModel::InterfaceTreeCacheModel(QObject *parent) :
    QIdentityProxyModel(parent)
{
    /* ATTENTION: This cache model is not intended to be used with anything
     * else then InterfaceTreeModel, and will break with anything else
     * leading to unintended results. */
    sourceModel = new InterfaceTreeModel(parent);

    QIdentityProxyModel::setSourceModel(sourceModel);
    storage = new QMap<int, QMap<InterfaceTreeColumns, QVariant> *>();

    checkableColumns << IFTREE_COL_HIDDEN << IFTREE_COL_PROMISCUOUSMODE;
#ifdef HAVE_PCAP_CREATE
    checkableColumns << IFTREE_COL_MONITOR_MODE;
#endif

    editableColumns << IFTREE_COL_COMMENT << IFTREE_COL_SNAPLEN << IFTREE_COL_PIPE_PATH;

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    editableColumns << IFTREE_COL_BUFFERLEN;
#endif
}

InterfaceTreeCacheModel::~InterfaceTreeCacheModel()
{
#ifdef HAVE_LIBPCAP
    /* This list should only exist, if the dialog is closed, without calling save first */
    newDevices.clear();
#endif

    delete storage;
    delete sourceModel;
}

QVariant InterfaceTreeCacheModel::getColumnContent(int idx, int col, int role)
{
    return InterfaceTreeCacheModel::data(index(idx, col), role);
}

#ifdef HAVE_LIBPCAP
void InterfaceTreeCacheModel::reset(int row)
{
    if (row < 0)
    {
        delete storage;
        storage = new QMap<int, QMap<InterfaceTreeColumns, QVariant> *>();
    }
    else
    {
        if (storage->count() > row)
            storage->remove(storage->keys().at(row));
    }
}

void InterfaceTreeCacheModel::saveNewDevices()
{
    QList<interface_t>::const_iterator it = newDevices.constBegin();
    /* idx is used for iterating only over the indices of the new devices. As all new
     * devices are stored with an index higher then sourceModel->rowCount(), we start
     * only with those storage indices.
     * it is just the iterator over the new devices. A new device must not necessarily
     * have storage, which will lead to that device not being stored in global_capture_opts */
    for (int idx = sourceModel->rowCount(); it != newDevices.constEnd(); ++it, idx++)
    {
        interface_t *device = const_cast<interface_t *>(&(*it));
        bool useDevice = false;

        QMap<InterfaceTreeColumns, QVariant> * dataField = storage->value(idx, 0);
        /* When devices are being added, they are added using generic values. So only devices
         * whose data have been changed should be used from here on out. */
        if (dataField != 0)
        {
            if (device->if_info.type != IF_PIPE)
            {
                continue;
            }

            if (device->if_info.type == IF_PIPE)
            {
                QVariant saveValue = dataField->value(IFTREE_COL_PIPE_PATH);
                if (saveValue.isValid())
                {
                    g_free(device->if_info.name);
                    device->if_info.name = qstring_strdup(saveValue.toString());

                    g_free(device->name);
                    device->name = qstring_strdup(saveValue.toString());

                    g_free(device->display_name);
                    device->display_name = qstring_strdup(saveValue.toString());
                    useDevice = true;
                }
            }

            if (useDevice)
                g_array_append_val(global_capture_opts.all_ifaces, *device);

        }

        /* All entries of this new devices have been considered */
        storage->remove(idx);
        delete dataField;
    }

    newDevices.clear();
}

void InterfaceTreeCacheModel::save()
{
    if (storage->count() == 0)
        return;

    QMap<char**, QStringList> prefStorage;

    /* No devices are hidden until checking "Show" state */
    prefStorage[&prefs.capture_devices_hide] = QStringList();

    /* Storing new devices first including their changed values */
    saveNewDevices();


    for (unsigned int idx = 0; idx < global_capture_opts.all_ifaces->len; idx++)
    {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

        if (! device->name)
            continue;

        /* Try to load a saved value row for this index */
        QMap<InterfaceTreeColumns, QVariant> * dataField = storage->value(idx, 0);

        /* Handle the storing of values for this device here */
        if (dataField)
        {
            QMap<InterfaceTreeColumns, QVariant>::const_iterator it = dataField->constBegin();
            while (it != dataField->constEnd())
            {
                InterfaceTreeColumns col = it.key();
                QVariant saveValue = it.value();

                /* Setting the field values for each individual saved value cannot be generic, as the
                 * struct cannot be accessed in a generic way. Therefore below, each individually changed
                 * value has to be handled separately. Comments are stored only in the preference file
                 * and applied to the data name during loading. Therefore comments are not handled here */

                if (col == IFTREE_COL_HIDDEN)
                {
                    device->hidden = saveValue.toBool();
                }
                else if (device->if_info.type == IF_EXTCAP)
                {
                    /* extcap interfaces do not have the following columns.
                     * ATTENTION: all generic columns must be added, BEFORE this
                     * if-clause, or they will be ignored for extcap interfaces */
                }
                else if (col == IFTREE_COL_PROMISCUOUSMODE)
                {
                    device->pmode = saveValue.toBool();
                }
#ifdef HAVE_PCAP_CREATE
                else if (col == IFTREE_COL_MONITOR_MODE)
                {
                    device->monitor_mode_enabled = saveValue.toBool();
                }
#endif
                else if (col == IFTREE_COL_SNAPLEN)
                {
                    int iVal = saveValue.toInt();
                    if (iVal != WTAP_MAX_PACKET_SIZE_STANDARD)
                    {
                        device->has_snaplen = true;
                        device->snaplen = iVal;
                    }
                    else
                    {
                        device->has_snaplen = false;
                        device->snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
                    }
                }
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
                else if (col == IFTREE_COL_BUFFERLEN)
                {
                    device->buffer = saveValue.toInt();
                }
#endif
                ++it;
            }
        }

        QVariant content = getColumnContent(idx, IFTREE_COL_HIDDEN, Qt::CheckStateRole);
        if (content.isValid() && static_cast<Qt::CheckState>(content.toInt()) == Qt::Unchecked)
            prefStorage[&prefs.capture_devices_hide] << QString(device->name);

        content = getColumnContent(idx, IFTREE_COL_COMMENT);
        if (content.isValid() && content.toString().size() > 0)
            prefStorage[&prefs.capture_devices_descr] << QString("%1(%2)").arg(device->name).arg(content.toString());

        bool allowExtendedColumns = true;

        if (device->if_info.type == IF_EXTCAP)
            allowExtendedColumns = false;

        if (allowExtendedColumns)
        {
            content = getColumnContent(idx, IFTREE_COL_PROMISCUOUSMODE, Qt::CheckStateRole);
            if (content.isValid())
            {
                bool value = static_cast<Qt::CheckState>(content.toInt()) == Qt::Checked;
                prefStorage[&prefs.capture_devices_pmode]  << QString("%1(%2)").arg(device->name).arg(value ? 1 : 0);
            }

#ifdef HAVE_PCAP_CREATE
            content = getColumnContent(idx, IFTREE_COL_MONITOR_MODE, Qt::CheckStateRole);
            if (content.isValid() && static_cast<Qt::CheckState>(content.toInt()) == Qt::Checked)
                    prefStorage[&prefs.capture_devices_monitor_mode] << QString(device->name);
#endif

            content = getColumnContent(idx, IFTREE_COL_SNAPLEN);
            if (content.isValid())
            {
                int value = content.toInt();
                prefStorage[&prefs.capture_devices_snaplen]  <<
                        QString("%1:%2(%3)").arg(device->name).
                        arg(device->has_snaplen ? 1 : 0).
                        arg(device->has_snaplen ? value : WTAP_MAX_PACKET_SIZE_STANDARD);
            }

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
            content = getColumnContent(idx, IFTREE_COL_BUFFERLEN);
            if (content.isValid())
            {
                int value = content.toInt();
                if (value != -1)
                {
                    prefStorage[&prefs.capture_devices_buffersize]  <<
                            QString("%1(%2)").arg(device->name).
                            arg(value);
                }
            }
#endif
        }
    }

    QMap<char**, QStringList>::const_iterator it = prefStorage.constBegin();
    while (it != prefStorage.constEnd())
    {
        char ** key = it.key();

        g_free(*key);
        *key = qstring_strdup(it.value().join(","));

        ++it;
    }

    wsApp->emitAppSignal(WiresharkApplication::LocalInterfacesChanged);
}
#endif

int InterfaceTreeCacheModel::rowCount(const QModelIndex & parent) const
{
    int totalCount = sourceModel->rowCount(parent);
#ifdef HAVE_LIBPCAP
    totalCount += newDevices.size();
#endif
    return totalCount;
}

bool InterfaceTreeCacheModel::changeIsAllowed(InterfaceTreeColumns col) const
{
    if (editableColumns.contains(col) || checkableColumns.contains(col))
        return true;
    return false;
}

#ifdef HAVE_LIBPCAP
const interface_t * InterfaceTreeCacheModel::lookup(const QModelIndex &index) const
{
    const interface_t * result = 0;

    if (! index.isValid() || ! global_capture_opts.all_ifaces)
        return result;

    int idx = index.row();

    if ((unsigned int) idx >= global_capture_opts.all_ifaces->len)
    {
        idx = idx - global_capture_opts.all_ifaces->len;
        if (idx < newDevices.size())
            result = &newDevices[idx];
    }
    else
    {
        result = &g_array_index(global_capture_opts.all_ifaces, interface_t, idx);
    }

    return result;
}
#endif

/* This checks if the column can be edited for the given index. This differs from
 * isAvailableField in such a way, that it is only used in flags and not any
 * other method.*/
bool InterfaceTreeCacheModel::isAllowedToBeEdited(const QModelIndex &index) const
{
#ifndef HAVE_LIBPCAP
    Q_UNUSED(index);
#else
    const interface_t * device = lookup(index);
    if (device == 0)
        return false;

    InterfaceTreeColumns col = (InterfaceTreeColumns) index.column();
    if (device->if_info.type == IF_EXTCAP)
    {
        /* extcap interfaces do not have those settings */
        if (col == IFTREE_COL_PROMISCUOUSMODE || col == IFTREE_COL_SNAPLEN)
            return false;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
        if (col == IFTREE_COL_BUFFERLEN)
            return false;
#endif
    }
#endif
    return true;
}

// Whether this field is available for modification and display.
bool InterfaceTreeCacheModel::isAvailableField(const QModelIndex &index) const
{
#ifndef HAVE_LIBPCAP
    Q_UNUSED(index);
#else
    const interface_t * device = lookup(index);

    if (device == 0)
        return false;

    InterfaceTreeColumns col = (InterfaceTreeColumns) index.column();
    if (col == IFTREE_COL_HIDDEN)
    {
        // Do not allow default capture interface to be hidden.
        if (! g_strcmp0(prefs.capture_device, device->display_name))
            return false;
    }
#endif

    return true;
}

Qt::ItemFlags InterfaceTreeCacheModel::flags(const QModelIndex &index) const
{
    if (! index.isValid())
        return Qt::ItemFlags();

    Qt::ItemFlags flags = Qt::ItemIsEnabled | Qt::ItemIsSelectable;

    InterfaceTreeColumns col = (InterfaceTreeColumns) index.column();

    if (changeIsAllowed(col) && isAvailableField(index) && isAllowedToBeEdited(index))
    {
        if (checkableColumns.contains(col))
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
    if (! index.isValid())
        return false;

    if (! isAvailableField(index))
        return false;

    int row = index.row();
    InterfaceTreeColumns col = (InterfaceTreeColumns)index.column();

    if (role == Qt::CheckStateRole || role == Qt::EditRole)
    {
        if (changeIsAllowed(col) )
        {
            QVariant saveValue = value;

            QMap<InterfaceTreeColumns, QVariant> * dataField = 0;
            /* obtain the list of already stored changes for this row. If none exist
             * create a new storage row for this entry */
            if ((dataField = storage->value(row, 0)) == 0)
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
    if (! index.isValid())
        return QVariant();

    int row = index.row();

    InterfaceTreeColumns col = (InterfaceTreeColumns)index.column();

    if (isAvailableField(index) && isAllowedToBeEdited(index))
    {
        if (((role == Qt::DisplayRole || role == Qt::EditRole) && editableColumns.contains(col)) ||
                (role == Qt::CheckStateRole && checkableColumns.contains(col)) )
        {
            QMap<InterfaceTreeColumns, QVariant> * dataField = 0;
            if ((dataField = storage->value(row, 0)) != 0)
            {
                if (dataField->contains(col))
                {
                    return dataField->value(col, QVariant());
                }
            }
        }
    }
    else
    {
        if (role == Qt::CheckStateRole)
            return QVariant();
        else if (role == Qt::DisplayRole)
            return QString(UTF8_EM_DASH);
    }

    if (row < sourceModel->rowCount())
    {
        return sourceModel->data(index, role);
    }
#ifdef HAVE_LIBPCAP
    else
    {
        /* Handle all fields, which will have to be displayed for new devices. Only pipes
         * are supported at the moment, so the information to be displayed is pretty limited.
         * After saving, the devices are stored in global_capture_opts and no longer
         * classify as new devices. */
        const interface_t * device = lookup(index);

        if (device != 0)
        {
            if (role == Qt::DisplayRole || role == Qt::EditRole)
            {
                if (col == IFTREE_COL_PIPE_PATH ||
                        col == IFTREE_COL_NAME ||
                        col == IFTREE_COL_DESCRIPTION)
                {

                    QMap<InterfaceTreeColumns, QVariant> * dataField = 0;
                    if ((dataField = storage->value(row, 0)) != 0 &&
                            dataField->contains(IFTREE_COL_PIPE_PATH))
                    {
                        return dataField->value(IFTREE_COL_PIPE_PATH, QVariant());
                    }
                    else
                        return QString(device->name);
                }
                else if (col == IFTREE_COL_TYPE)
                {
                    return QVariant::fromValue((int)device->if_info.type);
                }
            }
            else if (role == Qt::CheckStateRole)
            {
                if (col == IFTREE_COL_HIDDEN)
                {
                    // Do not allow default capture interface to be hidden.
                    if (! g_strcmp0(prefs.capture_device, device->display_name))
                        return QVariant();

                    /* Hidden is a de-selection, therefore inverted logic here */
                    return device->hidden ? Qt::Unchecked : Qt::Checked;
                }
            }
        }
    }
#endif

    return QVariant();
}

#ifdef HAVE_LIBPCAP
QModelIndex InterfaceTreeCacheModel::index(int row, int column, const QModelIndex &parent) const
{
    if (row >= sourceModel->rowCount() && (row - sourceModel->rowCount()) < newDevices.count())
    {
        return createIndex(row, column, (void *)0);
    }

    return QIdentityProxyModel::index(row, column, parent);
}

void InterfaceTreeCacheModel::addDevice(const interface_t * newDevice)
{
    emit beginInsertRows(QModelIndex(), rowCount(), rowCount());
    newDevices << *newDevice;
    emit endInsertRows();
}

void InterfaceTreeCacheModel::deleteDevice(const QModelIndex &index)
{
    if (! index.isValid())
        return;

    emit beginRemoveRows(QModelIndex(), index.row(), index.row());

    int row = index.row();

    /* device is in newDevices */
    if (row >= sourceModel->rowCount())
    {
        int newDeviceIdx = row - sourceModel->rowCount();

        newDevices.removeAt(newDeviceIdx);
        if (storage->contains(index.row()))
            storage->remove(index.row());

        /* The storage array has to be resorted, if the index, that was removed
         * had been in the middle of the array. Can't start at index.row(), as
         * it may not be contained in storage
         * We must iterate using a list, not an iterator, otherwise the change
         * will fold on itself. */
        QList<int> storageKeys = storage->keys();
        for (int i = 0; i < storageKeys.size(); ++i)
        {
            int key = storageKeys.at(i);
            if (key > index.row())
            {
                storage->insert(key - 1, storage->value(key));
                storage->remove(key);
            }
        }

        emit endRemoveRows();
    }
    else
    {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, row);
        capture_opts_free_interface_t(device);
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, row);
        emit endRemoveRows();
        wsApp->emitAppSignal(WiresharkApplication::LocalInterfacesChanged);
    }
}
#endif

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
