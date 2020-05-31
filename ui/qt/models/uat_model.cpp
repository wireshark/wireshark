/* uat_model.cpp
 * Data model for UAT records.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "uat_model.h"
#include <epan/to_str.h>
#include <QBrush>
#include <QDebug>

UatModel::UatModel(QObject *parent, epan_uat *uat) :
    QAbstractTableModel(parent),
    uat_(0)
{
    loadUat(uat);
}

UatModel::UatModel(QObject * parent, QString tableName) :
    QAbstractTableModel(parent),
    uat_(0)
{
    loadUat(uat_get_table_by_name(tableName.toStdString().c_str()));
}

void UatModel::loadUat(epan_uat * uat)
{
    uat_ = uat;

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

void UatModel::reloadUat()
{
    beginResetModel();
    loadUat(uat_);
    endResetModel();
}

bool UatModel::applyChanges(QString &error)
{
    if (uat_->changed) {
        gchar *err = NULL;

        if (!uat_save(uat_, &err)) {
            error = QString("Error while saving %1: %2").arg(uat_->name).arg(err);
            g_free(err);
        }

        if (uat_->post_update_cb) {
            uat_->post_update_cb();
        }
        return true;
    }

    return false;
}

bool UatModel::revertChanges(QString &error)
{
    // Ideally this model should remember the changes made and try to undo them
    // to avoid calling post_update_cb. Calling uat_clear + uat_load is a lazy
    // option and might fail (e.g. when the UAT file is removed).
    if (uat_->changed) {
        gchar *err = NULL;
        uat_clear(uat_);
        if (!uat_load(uat_, NULL, &err)) {
            error = QString("Error while loading %1: %2").arg(uat_->name).arg(err);
            g_free(err);
        }
        return true;
    }

    return false;
}

Qt::ItemFlags UatModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::ItemFlags();

    uat_field_t *field = &uat_->fields[index.column()];

    Qt::ItemFlags flags = QAbstractTableModel::flags(index);
    if (field->mode == PT_TXTMOD_BOOL)
    {
        flags |= Qt::ItemIsUserCheckable;
    }
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

        switch (field->mode) {
        case PT_TXTMOD_HEXBYTES:
            {
            char* temp_str = bytes_to_str(NULL, (const guint8 *) str, length);
            g_free(str);
            QString qstr(temp_str);
            wmem_free(NULL, temp_str);
            return qstr;
            }
        case PT_TXTMOD_BOOL:
        case PT_TXTMOD_COLOR:
            return QVariant();
        default:
            {
            QString qstr(str);
            g_free(str);
            return qstr;
            }
        }
    }

    if ((role == Qt::CheckStateRole) && (field->mode == PT_TXTMOD_BOOL))
    {
        char *str = NULL;
        guint length = 0;
        enum Qt::CheckState state = Qt::Unchecked;
        field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);
        if ((g_strcmp0(str, "TRUE") == 0) ||
            (g_strcmp0(str, "Enabled") == 0))
            state = Qt::Checked;

        g_free(str);
        return state;
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

    if ((role == Qt::DecorationRole) && (field->mode == PT_TXTMOD_COLOR)) {
        char *str = NULL;
        guint length = 0;
        field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);

        return QColor(QString(str));
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

QModelIndex UatModel::findRowForColumnContent(QVariant columnContent, int columnToCheckAgainst, int role)
{
    if (! columnContent.isValid())
        return QModelIndex();

    for (int i = 0; i < rowCount(); i++)
    {
        QVariant r_expr = data(index(i, columnToCheckAgainst), role);
        if (r_expr == columnContent)
            return index(i, columnToCheckAgainst);
    }

    return QModelIndex();
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
    if (!index.isValid())
        return false;

    uat_field_t *field = &uat_->fields[index.column()];

    if ((role != Qt::EditRole) &&
        ((field->mode == PT_TXTMOD_BOOL) && (role != Qt::CheckStateRole)))
        return false;

    if (data(index, role) == value) {
        // Data appears unchanged, do not do additional checks.
        return true;
    }

    const int row = index.row();
    void *rec = UAT_INDEX_PTR(uat_, row);

    //qDebug() << "Changing (" << row << "," << index.column() << ") from " << data(index, Qt::EditRole) << " to " << value;
    if (field->mode != PT_TXTMOD_BOOL) {
        const QByteArray &str = value.toString().toUtf8();
        const QByteArray &bytes = field->mode == PT_TXTMOD_HEXBYTES ? QByteArray::fromHex(str) : str;
        field->cb.set(rec, bytes.constData(), (unsigned) bytes.size(), field->cbdata.set, field->fld_data);
    } else {
        if (value == Qt::Checked) {
            field->cb.set(rec, "TRUE", 4, field->cbdata.set, field->fld_data);
        } else {
            field->cb.set(rec, "FALSE", 5, field->cbdata.set, field->fld_data);
        }
    }

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
        // If all individual fields are valid, invoke the update callback. This
        // might detect additional issues in either individual fields, or the
        // combination of them.
        if (uat_->update_cb) {
            char *err = NULL;
            if (!uat_->update_cb(rec, &err)) {
                // TODO the error is not exactly on the first column, but we need a way to show the error.
                record_errors[row].insert(0, err);
                g_free(err);
            }
        }
    }
    uat_update_record(uat_, rec, record_errors[row].isEmpty());
    dirty_records[row] = true;
    uat_->changed = TRUE;

    if (updated_cols.size() > updated_cols.count(index.column())) {
        // The validation status for other columns were also affected by
        // changing this field, mark those as dirty!
        emit dataChanged(this->index(row, updated_cols.first()),
                         this->index(row, updated_cols.last()), roles);
    } else {

        emit dataChanged(index, index, roles);
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

void UatModel::clearAll()
{
    if (rowCount() < 1)
        return;

    beginResetModel();
    uat_clear(uat_);
    record_errors.clear();
    dirty_records.clear();
    uat_->changed = TRUE;
    endResetModel();
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
    emit dataChanged(index(dst_row, 0), index(dst_row, columnCount()), roles);

    return true;
}

bool UatModel::moveRow(int src_row, int dst_row)
{
    if (src_row < 0 || src_row >= rowCount() || dst_row < 0 || dst_row >= rowCount())
        return false;

    int dst = src_row < dst_row ? dst_row + 1 : dst_row;

    beginMoveRows(QModelIndex(), src_row, src_row, QModelIndex(), dst);
    uat_move_index(uat_, src_row, dst_row);
    record_errors.move(src_row, dst_row);
    dirty_records.move(src_row, dst_row);
    uat_->changed = TRUE;
    endMoveRows();

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
