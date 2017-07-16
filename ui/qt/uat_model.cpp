/* uat_model.cpp
 * Data model for UAT records.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
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

#include "uat_model.h"
#include <epan/to_str.h>
#include <QBrush>
#include <QDebug>

UatModel::UatModel(QObject *parent, epan_uat *uat) :
    QAbstractTableModel(parent),
    uat_(uat)
{
    dirty_records.reserve(uat_->raw_data->len);
    // Validate existing data such that they can be marked as invalid if necessary.
    record_errors.reserve(uat_->raw_data->len);
    for (int i = 0; i < (int)uat_->raw_data->len; i++) {
        record_errors.push_back(QMap<int, QString>());
        checkRow(i);
        // Assume that records are initially not modified.
        dirty_records.push_back(false);
    }
}

Qt::ItemFlags UatModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    Qt::ItemFlags flags = QAbstractTableModel::flags(index);
    flags |= Qt::ItemIsEditable;
    return flags;
}

QVariant UatModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return QVariant();
    }

    void *rec = UAT_INDEX_PTR(uat_, index.row());
    uat_field_t *field = &uat_->fields[index.column()];
    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        char *str = NULL;
        guint length = 0;
        field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);

        if (field->mode == PT_TXTMOD_HEXBYTES) {
            char* temp_str = bytes_to_str(NULL, (const guint8 *) str, length);
            g_free(str);
            QString qstr(temp_str);
            wmem_free(NULL, temp_str);
            return qstr;
        } else {
            QString qstr(str);
            g_free(str);
            return qstr;
        }
    }

    if (role == Qt::UserRole) {
        return QVariant::fromValue(static_cast<void *>(field));
    }

    const QMap<int, QString> &errors = record_errors[index.row()];
    // mark fields that fail the validation.
    if (role == Qt::BackgroundRole) {
        if (errors.contains(index.column())) {
            // TODO is it OK to color cells like this? Maybe some other marker is better?
            return QBrush("pink");
        }
        return QVariant();
    }

    // expose error message if any.
    if (role == Qt::UserRole + 1) {
        if (errors.contains(index.column())) {
            return errors[index.column()];
        }
        return QVariant();
    }

    return QVariant();
}

QVariant UatModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal) {
        return QVariant();
    }

    if (role == Qt::ToolTipRole && uat_->fields[section].desc) {
        return uat_->fields[section].desc;
    }

    if (role == Qt::DisplayRole) {
        return uat_->fields[section].title;
    }

    return QVariant();
}

int UatModel::rowCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return uat_->raw_data->len;
}

int UatModel::columnCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return uat_->ncols;
}

bool UatModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (!index.isValid() || role != Qt::EditRole)
        return false;

    if (data(index, role) == value) {
        // Data appears unchanged, do not do additional checks.
        return true;
    }

    const int row = index.row();
    uat_field_t *field = &uat_->fields[index.column()];
    void *rec = UAT_INDEX_PTR(uat_, row);

    //qDebug() << "Changing (" << row << "," << index.column() << ") from " << data(index, Qt::EditRole) << " to " << value;
    const QByteArray &str = value.toString().toUtf8();
    const QByteArray &bytes = field->mode == PT_TXTMOD_HEXBYTES ? QByteArray::fromHex(str) : str;
    field->cb.set(rec, bytes.constData(), (unsigned) bytes.size(), field->cbdata.set, field->fld_data);

    QVector<int> roles;
    roles << role;

    // Check validity of all rows, obtaining a list of columns where the
    // validity status has changed.
    const QList<int> &updated_cols = checkRow(row);
    if (!updated_cols.isEmpty()) {
        roles << Qt::BackgroundRole;
        //qDebug() << "validation status changed:" << updated_cols;
    }

    if (record_errors[row].isEmpty()) {
        // If all fields are valid, invoke the update callback
        if (uat_->update_cb) {
            char *err = NULL;
            if (!uat_->update_cb(rec, &err)) {
                // TODO the error is not exactly on the first column, but we need a way to show the error.
                record_errors[row].insert(0, err);
                g_free(err);
            }
        }
        uat_update_record(uat_, rec, TRUE);
    } else {
        uat_update_record(uat_, rec, FALSE);
    }
    dirty_records[row] = true;
    uat_->changed = TRUE;

    if (updated_cols.size() > updated_cols.count(index.column())) {
        // The validation status for other columns were also affected by
        // changing this field, mark those as dirty!
        emit dataChanged(this->index(row, updated_cols.first()),
                         this->index(row, updated_cols.last())
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
                         , roles
#endif
        );
    } else {

        emit dataChanged(index, index
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
                         , roles
#endif
        );
    }
    return true;
}

bool UatModel::insertRows(int row, int count, const QModelIndex &/*parent*/)
{
    // support insertion of just one item for now.
    if (count != 1 || row < 0 || row > rowCount())
        return false;

    beginInsertRows(QModelIndex(), row, row);

    // Initialize with empty values, caller should use setData to populate it.
    void *record = g_malloc0(uat_->record_size);
    for (int col = 0; col < columnCount(); col++) {
        uat_field_t *field = &uat_->fields[col];
        field->cb.set(record, "", 0, field->cbdata.set, field->fld_data);
    }
    uat_insert_record_idx(uat_, row, record);
    if (uat_->free_cb) {
        uat_->free_cb(record);
    }
    g_free(record);

    record_errors.insert(row, QMap<int, QString>());
    // a new row is created. For the moment all fields are empty, so validation
    // will likely mark everything as invalid. Ideally validation should be
    // postponed until the row (in the view) is not selected anymore
    checkRow(row);
    dirty_records.insert(row, true);
    uat_->changed = TRUE;
    endInsertRows();
    return true;
}

bool UatModel::removeRows(int row, int count, const QModelIndex &/*parent*/)
{
    if (count != 1 || row < 0 || row >= rowCount())
        return false;

    beginRemoveRows(QModelIndex(), row, row);
    uat_remove_record_idx(uat_, row);
    record_errors.removeAt(row);
    dirty_records.removeAt(row);
    uat_->changed = TRUE;
    endRemoveRows();
    return true;
}

bool UatModel::copyRow(int dst_row, int src_row)
{
    if (src_row < 0 || src_row >= rowCount() || dst_row < 0 || dst_row >= rowCount()) {
        return false;
    }

    const void *src_record = UAT_INDEX_PTR(uat_, src_row);
    void *dst_record = UAT_INDEX_PTR(uat_, dst_row);
    // insertRows always initializes the record with empty value. Before copying
    // over the new values, be sure to clear the old fields.
    if (uat_->free_cb) {
        uat_->free_cb(dst_record);
    }
    if (uat_->copy_cb) {
      uat_->copy_cb(dst_record, src_record, uat_->record_size);
    } else {
      /* According to documentation of uat_copy_cb_t memcpy should be used if uat_->copy_cb is NULL */
      memcpy(dst_record, src_record, uat_->record_size);
    }
    gboolean src_valid = g_array_index(uat_->valid_data, gboolean, src_row);
    uat_update_record(uat_, dst_record, src_valid);
    record_errors[dst_row] = record_errors[src_row];
    dirty_records[dst_row] = true;

    QVector<int> roles;
    roles << Qt::EditRole << Qt::BackgroundRole;
    emit dataChanged(index(dst_row, 0), index(dst_row, columnCount())
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
                     , roles
#endif
    );

    return true;
}


bool UatModel::hasErrors() const
{
    for (int i = 0; i < rowCount(); i++) {
        // Ignore errors on unmodified records, these should not prevent the OK
        // button from saving modifications to other entries.
        if (dirty_records[i] && !record_errors[i].isEmpty()) {
            return true;
        }
    }
    return false;
}

bool UatModel::checkField(int row, int col, char **error) const
{
    uat_field_t *field = &uat_->fields[col];
    void *rec = UAT_INDEX_PTR(uat_, row);

    if (!field->cb.chk) {
        return true;
    }

    char *str = NULL;
    guint length;
    field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);

    bool ok = field->cb.chk(rec, str, length, field->cbdata.chk, field->fld_data, error);
    g_free(str);
    return ok;
}

// Validates all fields in the given record, setting error messages as needed.
// Returns the columns that have changed (not the columns with errors).
QList<int> UatModel::checkRow(int row)
{
    Q_ASSERT(0 <= row && row < rowCount());

    QList<int> changed;
    QMap<int, QString> &errors = record_errors[row];
    for (int col = 0; col < columnCount(); col++) {
        char *err;
        bool error_changed = errors.remove(col) > 0;
        if (!checkField(row, col, &err)) {
            errors.insert(col, err);
            g_free(err);
            error_changed = !error_changed;
        }
        if (error_changed) {
            changed << col;
        }
    }
    return changed;
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
