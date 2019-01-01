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
#include <ui/export_object_ui.h>

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

    return objects_.count();
}

int ExportObjectModel::columnCount(const QModelIndex&) const
{
    return colExportObjectMax;
}

void ExportObjectModel::addObjectEntry(export_object_entry_t *entry)
{
    if (entry == NULL)
        return;

    int count = objects_.count();
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
        eo_save_entry(filename.toUtf8().constData(), entry);
    }

    return true;
}

void ExportObjectModel::saveAllEntries(QString path)
{
    if (path.isEmpty())
        return;

    export_object_entry_t *entry;

    for (QList<QVariant>::iterator it = objects_.begin(); it != objects_.end(); ++it)
    {
        entry = VariantPointer<export_object_entry_t>::asPtr(*it);
        if (entry == NULL)
            continue;

        int count = 0;
        gchar *save_as_fullpath = NULL;

        do {
            GString *safe_filename;

            g_free(save_as_fullpath);
            if (entry->filename)
                safe_filename = eo_massage_str(entry->filename,
                    EXPORT_OBJECT_MAXFILELEN, count);
            else {
                char generic_name[EXPORT_OBJECT_MAXFILELEN+1];
                const char *ext;
                ext = eo_ct2ext(entry->content_type);
                g_snprintf(generic_name, sizeof(generic_name),
                    "object%u%s%s", entry->pkt_num, ext ? "." : "",
                    ext ? ext : "");
                safe_filename = eo_massage_str(generic_name,
                    EXPORT_OBJECT_MAXFILELEN, count);
            }
            save_as_fullpath = g_build_filename(path.toUtf8().constData(),
                                                safe_filename->str, NULL);
            g_string_free(safe_filename, TRUE);
        } while (g_file_test(save_as_fullpath, G_FILE_TEST_EXISTS) && ++count < 1000);
        eo_save_entry(save_as_fullpath, entry);
        g_free(save_as_fullpath);
        save_as_fullpath = NULL;
    }
}

void ExportObjectModel::resetObjects()
{
    export_object_gui_reset_cb reset_cb = get_eo_reset_func(eo_);

    emit beginResetModel();
    objects_.clear();
    emit endResetModel();

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



/* * Editor modelines
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
