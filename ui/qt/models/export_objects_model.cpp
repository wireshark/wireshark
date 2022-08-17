/* export_objects_model.cpp
 * Data model for Export Objects.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "export_objects_model.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <wsutil/filesystem.h>
#include <epan/prefs.h>

#include <QDir>

extern "C" {

static void
object_list_add_entry(void *gui_data, export_object_entry_t *entry) {
    export_object_list_gui_t *object_list = (export_object_list_gui_t*)gui_data;

    if (object_list && object_list->model)
        object_list->model->addObjectEntry(entry);
}

static export_object_entry_t*
object_list_get_entry(void *gui_data, int row) {
    export_object_list_gui_t *object_list = (export_object_list_gui_t*)gui_data;

    if (object_list && object_list->model)
        return object_list->model->objectEntry(row);

    return NULL;
}

} // extern "C"




ExportObjectModel::ExportObjectModel(register_eo_t* eo, QObject *parent) :
    QAbstractTableModel(parent),
    eo_(eo)
{
    eo_gui_data_.model = this;

    export_object_list_.add_entry = object_list_add_entry;
    export_object_list_.get_entry = object_list_get_entry;
    export_object_list_.gui_data = (void*)&eo_gui_data_;
}

ExportObjectModel::~ExportObjectModel()
{
    foreach (QVariant v, objects_) {
        eo_free_entry(VariantPointer<export_object_entry_t>::asPtr(v));
    }
}

QVariant ExportObjectModel::data(const QModelIndex &index, int role) const
{
    if ((!index.isValid()) || ((role != Qt::DisplayRole) && (role != Qt::UserRole))) {
        return QVariant();
    }

    if (role == Qt::DisplayRole)
    {
        export_object_entry_t *entry = VariantPointer<export_object_entry_t>::asPtr(objects_.value(index.row()));
        if (entry == NULL)
            return QVariant();

        switch(index.column())
        {
        case colPacket:
            return QString::number(entry->pkt_num);
        case colHostname:
            return entry->hostname;
        case colContent:
            return entry->content_type;
        case colSize:
            return file_size_to_qstring(entry->payload_len);
        case colFilename:
            return entry->filename;
        }
    }
    else if (role == Qt::UserRole)
    {
        return objects_.value(index.row());
    }

    return QVariant();
}

QVariant ExportObjectModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    switch (section) {
    case colPacket:
        return tr("Packet");
    case colHostname:
        return tr("Hostname");
    case colContent:
        return tr("Content Type");
    case colSize:
        return tr("Size");
    case colFilename:
        return tr("Filename");
    }

    return QVariant();
}

int ExportObjectModel::rowCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(objects_.count());
}

int ExportObjectModel::columnCount(const QModelIndex&) const
{
    return colExportObjectMax;
}

void ExportObjectModel::addObjectEntry(export_object_entry_t *entry)
{
    if (entry == NULL)
        return;

    int count = static_cast<int>(objects_.count());
    beginInsertRows(QModelIndex(), count, count);
    objects_.append(VariantPointer<export_object_entry_t>::asQVariant(entry));
    endInsertRows();
}

export_object_entry_t* ExportObjectModel::objectEntry(int row)
{
    return VariantPointer<export_object_entry_t>::asPtr(objects_.value(row));
}

bool ExportObjectModel::saveEntry(QModelIndex &index, QString filename)
{
    if (!index.isValid() || filename.isEmpty())
        return false;

    export_object_entry_t *entry = VariantPointer<export_object_entry_t>::asPtr(objects_.value(index.row()));
    if (entry == NULL)
        return false;

    if (filename.length() > 0) {
        write_file_binary_mode(qUtf8Printable(filename), entry->payload_data, entry->payload_len);
    }

    return true;
}

void ExportObjectModel::saveAllEntries(QString path)
{
    if (path.isEmpty())
        return;

    QDir save_dir(path);
    export_object_entry_t *entry;

    for (QList<QVariant>::iterator it = objects_.begin(); it != objects_.end(); ++it)
    {
        entry = VariantPointer<export_object_entry_t>::asPtr(*it);
        if (entry == NULL)
            continue;

        guint count = 0;
        QString filename;

        do {
            GString *safe_filename;

            if (entry->filename)
                safe_filename = eo_massage_str(entry->filename,
                    EXPORT_OBJECT_MAXFILELEN, count);
            else {
                char generic_name[EXPORT_OBJECT_MAXFILELEN+1];
                const char *ext;
                ext = eo_ct2ext(entry->content_type);
                snprintf(generic_name, sizeof(generic_name),
                    "object%u%s%s", entry->pkt_num, ext ? "." : "",
                    ext ? ext : "");
                safe_filename = eo_massage_str(generic_name,
                    EXPORT_OBJECT_MAXFILELEN, count);
            }
            filename = QString::fromUtf8(safe_filename->str);
            g_string_free(safe_filename, TRUE);
        } while (save_dir.exists(filename) && ++count < prefs.gui_max_export_objects);
        write_file_binary_mode(qUtf8Printable(save_dir.filePath(filename)),
                               entry->payload_data, entry->payload_len);
    }
}

void ExportObjectModel::resetObjects()
{
    export_object_gui_reset_cb reset_cb = get_eo_reset_func(eo_);

    beginResetModel();
    objects_.clear();
    endResetModel();

    if (reset_cb)
        reset_cb();
}

// Called by taps
/* Runs at the beginning of tapping only */
void ExportObjectModel::resetTap(void *tapdata)
{
    export_object_list_t *tap_object = (export_object_list_t *)tapdata;
    export_object_list_gui_t *object_list = (export_object_list_gui_t *)tap_object->gui_data;
    if (object_list && object_list->model)
        object_list->model->resetObjects();
}

const char* ExportObjectModel::getTapListenerName()
{
    return get_eo_tap_listener_name(eo_);
}

void* ExportObjectModel::getTapData()
{
    return &export_object_list_;
}

tap_packet_cb ExportObjectModel::getTapPacketFunc()
{
    return get_eo_packet_func(eo_);
}

void ExportObjectModel::removeTap()
{
    eo_gui_data_.model = NULL;
}



ExportObjectProxyModel::ExportObjectProxyModel(QObject * parent)
    : QSortFilterProxyModel(parent)
{

}

bool ExportObjectProxyModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    export_object_entry_t *left_entry = VariantPointer<export_object_entry_t>::asPtr(sourceModel()->data(source_left, Qt::UserRole)),
                          *right_entry = VariantPointer<export_object_entry_t>::asPtr(sourceModel()->data(source_right, Qt::UserRole));

    if ((left_entry != NULL) && (right_entry != NULL))
    {
        switch (source_left.column())
        {
        case ExportObjectModel::colPacket:
            return left_entry->pkt_num < right_entry->pkt_num;
        case ExportObjectModel::colSize:
            return left_entry->payload_len < right_entry->payload_len;
        case ExportObjectModel::colFilename:
            break;
        }
    }

    return QSortFilterProxyModel::lessThan(source_left, source_right);
}

void ExportObjectProxyModel::setContentFilterString(QString filter_)
{
    contentFilter_ = filter_;
    invalidateFilter();
}

void ExportObjectProxyModel::setTextFilterString(QString filter_)
{
    textFilter_ = filter_;
    invalidateFilter();
}

bool ExportObjectProxyModel::filterAcceptsRow(int source_row, const QModelIndex &/*source_parent*/) const
{
    if (contentFilter_.length() > 0)
    {
        QModelIndex idx = sourceModel()->index(source_row, ExportObjectModel::colContent);
        if (!idx.isValid())
            return false;

        if (contentFilter_.compare(idx.data().toString()) != 0)
            return false;
    }

    if (textFilter_.length() > 0)
    {
        QModelIndex hostIdx = sourceModel()->index(source_row, ExportObjectModel::colHostname);
        QModelIndex fileIdx = sourceModel()->index(source_row, ExportObjectModel::colFilename);
        if (!hostIdx.isValid() || !fileIdx.isValid())
            return false;

        QString host = hostIdx.data().toString();
        QString file = fileIdx.data().toString();

        if (!host.contains(textFilter_) && !file.contains(textFilter_))
            return false;
    }

    return true;
}
