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
#include "ui/qt/io_graph_dialog.h"
#include <epan/to_str.h>
#include <epan/uat-int.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/profile_inherit_combo_box.h>
#include <app/application_flavor.h>
#include <QFont>
#include <QSet>
#include <QTimer>
#include <QBrush>
#include <QDebug>

// XXX - The model accesses the uat_t raw data, but if the raw data
// is changed outside the model, e.g. by another model on the same UAT
// or by changing configuration profiles, record_errors and dirty_records
// don't have the proper length, which leads to accessing an illegal list
// index. The preference dialog and configuration profile dialogs are modal,
// which reduces the chance of this, but the I/O Graphs using a UAT invites
// issues.

UatModel::UatModel(QObject *parent, epan_uat *uat) :
    QAbstractTableModel(parent),
    uat_(0),
    applying_(false),
    refresh_pending_(false),
    unannounced_rows_(0)
{
    loadUat(uat);
    followOverridden();
    // The records overridden by own records are shown too
    refreshInherited();
}

UatModel::UatModel(QObject * parent, QString tableName) :
    QAbstractTableModel(parent),
    uat_(0),
    applying_(false),
    refresh_pending_(false),
    unannounced_rows_(0)
{
    loadUat(uat_get_table_by_name(tableName.toStdString().c_str()));
    followOverridden();
    // The records overridden by own records are shown too
    refreshInherited();
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
    // Avoid unnecessarily resetting the model if we're just making
    // what's on disk match what we have.
    if (applying_)
        return;

    beginResetModel();
    record_errors.clear();
    dirty_records.clear();
    loadUat(uat_);
    endResetModel();

    // Records copied from another profile may hide inherited records
    refreshInherited();
}

profile_inherit_e UatModel::inheritMode() const
{
    return uat_get_inherit_mode(uat_);
}

int UatModel::ownRowCount() const
{
    return static_cast<int>(uat_own_count(uat_));
}

bool UatModel::isInherited(int row) const
{
    return row >= 0 && uat_record_is_inherited(uat_, static_cast<unsigned>(row));
}

QString UatModel::sourceProfile(int row) const
{
    return row >= 0 ? QString::fromUtf8(uat_record_source(uat_, static_cast<unsigned>(row))) : QString();
}

bool UatModel::isOverridden(int row) const
{
    return row >= 0 && row < overridden_.count() && overridden_[row];
}

void UatModel::followOverridden()
{
    // The overridden records follow the rows
    auto update = [this]() { updateOverridden(); };
    connect(this, &QAbstractItemModel::rowsInserted, this, update);
    connect(this, &QAbstractItemModel::rowsRemoved, this, update);
    connect(this, &QAbstractItemModel::rowsMoved, this, update);
    connect(this, &QAbstractItemModel::dataChanged, this, update);
    connect(this, &QAbstractItemModel::modelReset, this, update);

    // Changes of the own records, not the inherited records being replaced
    auto changed = [this]() { if (!refreshing_inherited_) own_unsaved_ = true; };
    connect(this, &QAbstractItemModel::rowsInserted, this, changed);
    connect(this, &QAbstractItemModel::rowsRemoved, this, changed);
    connect(this, &QAbstractItemModel::rowsMoved, this, changed);
    connect(this, &QAbstractItemModel::dataChanged, this, changed);
}

void UatModel::updateOverridden()
{
    QSet<QString> keys = ownKeys();
    int own_count = ownRowCount();

    overridden_.fill(false, rowCount());
    for (int row = own_count; row < overridden_.count(); row++) {
        overridden_[row] = keys.contains(gchar_free_to_qstring(uat_record_key_string(uat_, static_cast<unsigned>(row))));
    }
}

void UatModel::ownEdited()
{
    uat_own_records_edited(uat_);
}

bool UatModel::setInheritMode(profile_inherit_e mode, QString &error)
{
    if (mode == inheritMode())
        return true;

    char *err = NULL;
    int own_count = ownRowCount();
    // The edit state of the own records, which stay as they are if they are not read again
    QVector<bool> own_dirty = dirty_records.mid(0, own_count);

    own_unsaved_ = false;
    beginResetModel();
    bool ok = uat_set_inherit_mode(uat_, mode, application_configuration_environment_prefix(), &err);
    record_errors.clear();
    dirty_records.clear();
    loadUat(uat_);
    if (ownRowCount() == own_dirty.count()) {
        for (int row = 0; row < own_dirty.count() && row < dirty_records.count(); row++)
            dirty_records[row] = own_dirty[row];
    }
    // The inherited records were read for the own records now
    refreshed_for_keys_ = ownKeys();
    endResetModel();

    if (!ok) {
        error = QStringLiteral("Error while loading %1: %2").arg(uat_->name).arg(err);
        g_free(err);
    }
    return ok;
}

QSet<QString> UatModel::ownKeys() const
{
    QSet<QString> keys;
    int own_count = ownRowCount();
    for (int row = 0; row < own_count; row++)
        keys << gchar_free_to_qstring(uat_record_key_string(uat_, static_cast<unsigned>(row)));
    return keys;
}

void UatModel::refreshInherited()
{
    if (!uat_->from_profile || inheritMode() == PROFILE_INHERIT_PROFILE_ONLY)
        return;

    // Not while a view is committing an edit; the rows may be replaced
    if (!refresh_pending_) {
        refresh_pending_ = true;
        QTimer::singleShot(0, this, &UatModel::doRefreshInherited);
    }
}

void UatModel::doRefreshInherited()
{
    refresh_pending_ = false;
    if (!uat_->from_profile || inheritMode() == PROFILE_INHERIT_PROFILE_ONLY)
        return;

    // Only the keys of the own records decide which records are inherited
    QSet<QString> keys = ownKeys();
    if (refreshed_for_keys_ && *refreshed_for_keys_ == keys)
        return;
    refreshed_for_keys_ = keys;

    // Replace only the inherited rows after the own rows, so that the
    // current index, the selection and an open editor on own rows stay
    const char *prefix = application_configuration_environment_prefix();
    int own_count = ownRowCount();
    int shown = rowCount() - own_count;
    refreshing_inherited_ = true;
    if (shown > 0) {
        beginRemoveRows(QModelIndex(), own_count, own_count + shown - 1);
        uat_remove_inherited_records(uat_);
        record_errors.remove(own_count, shown);
        dirty_records.remove(own_count, shown);
        endRemoveRows();
    }

    // Only reading the records tells how many are inherited. The model
    // does not count them until the rows to insert are announced.
    char *err = NULL;
    uat_add_inherited_records(uat_, prefix, &err);
    g_free(err);
    int added = static_cast<int>(uat_->raw_data->len) - own_count;
    if (added <= 0) {
        refreshing_inherited_ = false;
        return;
    }

    unannounced_rows_ = added;
    beginInsertRows(QModelIndex(), own_count, own_count + added - 1);
    unannounced_rows_ = 0;
    for (int row = own_count; row < rowCount(); row++) {
        record_errors.push_back(QMap<int, QString>());
        checkRow(row);
        dirty_records.push_back(false);
    }
    endInsertRows();
    refreshing_inherited_ = false;
}

bool UatModel::applyChanges(QString &error)
{
    own_unsaved_ = false;
    if (uat_->changed) {
        char *err = NULL;

        if (!uat_save(uat_, application_configuration_environment_prefix(), &err)) {
            error = QStringLiteral("Error while saving %1: %2").arg(uat_->name).arg(err);
            g_free(err);
        }

        applying_ = true;
        // XXX - Why does this need to call post_update_cb? post_update_cb
        // is for when the uat_t is updated, e.g. after loading a file.
        // Saving makes the information on disk match the table records in
        // memory, but it shouldn't change the uat_t.
        if (uat_->post_update_cb) {
            uat_->post_update_cb();
        }
        applying_ = false;
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
        char *err = NULL;
        uat_clear(uat_);
        if (!uat_load(uat_, NULL, application_configuration_environment_prefix(), &err)) {
            error = QStringLiteral("Error while loading %1: %2").arg(uat_->name).arg(err);
            g_free(err);
        }
        return true;
    }

    return false;
}

Qt::ItemFlags UatModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flags = QAbstractTableModel::flags(index);
    flags |= Qt::ItemIsDropEnabled;

    if (!index.isValid())
        return flags;

    // Inherited records are read-only
    if (isInherited(index.row()))
        return flags & ~Qt::ItemIsDropEnabled;

    uat_field_t *field = &uat_->fields[index.column()];

    /* UAT being multipurpose, we want to handle this specific
     * case for I/O Graphs here.
     * Column indexes are defined there (io_graph_dialog precisely).
     */
    bool isIOGraph = g_strcmp0(uat_->name, "I/O Graphs") == 0;
    if(isIOGraph) {
        UatColumnsIOG ucol = colAOT;
        if(index.column()==colAOT) {
            ucol = colYAxis;
            uat_field_t *field2 = &uat_->fields[ucol];
            void *rec = UAT_INDEX_PTR(uat_, index.row());
            char *str = NULL;
            unsigned length;
            field2->cb.tostr(rec, &str, &length, field2->cbdata.tostr, field2->fld_data);
            bool allowsAOT = (str &&
                         ( (g_strcmp0(str, "Packets") == 0) ||
                         (g_strcmp0(str, "Bytes") == 0) ||
                         (g_strcmp0(str, "Bits") == 0) ));
            g_free(str);

            if ((field->mode == PT_TXTMOD_BOOL) && allowsAOT ) {
                flags |= Qt::ItemIsUserCheckable;
            }
        }
        else {
            if (field->mode == PT_TXTMOD_BOOL) {
                flags |= Qt::ItemIsUserCheckable;
            }
        }

        flags |= Qt::ItemIsEditable | Qt::ItemIsDragEnabled;
    }
    else {
        // default case (non-I/O Graph)
        if (field->mode == PT_TXTMOD_BOOL)
        {
            flags |= Qt::ItemIsUserCheckable;
        }
        flags |= Qt::ItemIsEditable | Qt::ItemIsDragEnabled;
    }

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
        unsigned length = 0;
        field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);

        switch (field->mode) {
        case PT_TXTMOD_HEXBYTES:
            {
            char* temp_str = bytes_to_str(NULL, (const uint8_t *) str, length);
            g_free(str);
            QString qstr(temp_str);
            wmem_free(NULL, temp_str);
            return qstr;
            }
        case PT_TXTMOD_BOOL:
        case PT_TXTMOD_COLOR:
            g_free(str);
            return QVariant();
        default:
            return gchar_free_to_qstring(str);
        }
    }

    // An inherited record shows a lock instead of the check box enabling it
    if (role == Qt::CheckStateRole && index.column() == uat_->enabled_field && isInherited(index.row()))
        return QVariant();

    if ((role == Qt::CheckStateRole) && (field->mode == PT_TXTMOD_BOOL))
    {
        char *str = NULL;
        unsigned length = 0;
        enum Qt::CheckState state = Qt::Unchecked;
        field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);
        // "Enabled" is for backwards compatibility with pre-UAT IO Graphs:
        // (Commit 5b3e3ee58748ac1fd9201d2d3facbed1b9b1e800)
        if (str &&
           ((g_ascii_strcasecmp(str, "true") == 0) ||
            (g_strcmp0(str, "Enabled") == 0)))
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

    bool inherited = isInherited(index.row());

    bool overridden = inherited && isOverridden(index.row());

    if (role == Qt::FontRole) {
        if (inherited || !g_array_index(uat_->valid_data, bool, index.row())) {
            QFont font;
            // Not used: also struck out
            font.setItalic(!font.italic());
            font.setStrikeOut(overridden);
            return font;
        }
        return QVariant();
    }

    if (role == Qt::ForegroundRole && inherited) {
        return ProfileInheritComboBox::inheritedData(role, QString());
    }

    if ((role == Qt::ToolTipRole || role == Qt::AccessibleDescriptionRole) && overridden) {
        return ProfileInheritComboBox::notUsedText(QString::fromUtf8(uat_record_source(uat_, index.row())));
    }

    if ((role == Qt::ToolTipRole || role == Qt::AccessibleDescriptionRole) && inherited) {
        return ProfileInheritComboBox::inheritedData(role, QString::fromUtf8(uat_record_source(uat_, index.row())));
    }

    // A lock marks the inherited records. It replaces the check box of the
    // field enabling a record, as an inherited record is always enabled, or
    // else comes first in the first column. Own records get room for it only
    // when inherited records are shown, so the first column lines up.
    const int lock_column = uat_->enabled_field >= 0 ? uat_->enabled_field : 0;
    if (role == Qt::DecorationRole && index.column() == lock_column && field->mode != PT_TXTMOD_COLOR) {
        if (inherited) {
            return overridden ? ProfileInheritComboBox::overriddenIcon() : ProfileInheritComboBox::inheritedIcon();
        }
        // Inherited records come last
        if (uat_->enabled_field < 0 && isInherited(rowCount() - 1)) {
            return ProfileInheritComboBox::inheritedPlaceholderIcon();
        }
        return QVariant();
    }

    if ((role == Qt::DecorationRole) && (field->mode == PT_TXTMOD_COLOR)) {
        char *str = NULL;
        unsigned length = 0;
        field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);

        return QColor(gchar_free_to_qstring(str));
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

    return static_cast<int>(uat_->raw_data->len) - unannounced_rows_;
}

int UatModel::columnCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return uat_->ncols;
}

QModelIndex UatModel::appendEntry(QVariantList rowData)
{
    // Don't add an empty row, or a row with more entries than we have columns,
    // but a row with fewer can be added, where the remaining entries are empty
    if (rowData.count() == 0 || rowData.count() > columnCount())
        return QModelIndex();

    QModelIndex newIndex;
    if (inheritMode() == PROFILE_INHERIT_PARENT_ONLY)
        return QModelIndex();

    // New records are own records, which come before the inherited records
    int row = ownRowCount();
    emit beginInsertRows(QModelIndex(), row, row);

    // Initialize with given values
    void *record = g_malloc0(uat_->record_size);
    for (int col = 0; col < columnCount(); col++) {
        uat_field_t *field = &uat_->fields[col];

        QString data;
        if (rowData.count() > col) {
            if (field->mode != PT_TXTMOD_BOOL) {
                data = rowData[col].toString();
            } else {
                if (rowData[col].toInt() == Qt::Checked) {
                    data = QStringLiteral("true");
                } else {
                    data = QStringLiteral("false");
                }
            }
        }

        QByteArray bytes = field->mode == PT_TXTMOD_HEXBYTES ? QByteArray::fromHex(data.toUtf8()) : data.toUtf8();
        field->cb.set(record, bytes.constData(), (unsigned) bytes.size(), field->cbdata.set, field->fld_data);
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
    uat_->changed = true;
    ownEdited();

    emit endInsertRows();

    refreshInherited();
    newIndex = index(row, 0, QModelIndex());

    return newIndex;
}

bool UatModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (!index.isValid() || isInherited(index.row()))
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
        // XXX - This converts from string to value before checkRow converts
        // back to a string to check the value. For, e.g., the numeric types,
        // that means that they aren't really checked, just converted to a
        // number if possible. The chk function for those needs to be called
        // earlier (possibly in UatDelegate.)
        field->cb.set(rec, bytes.constData(), (unsigned) bytes.size(), field->cbdata.set, field->fld_data);
    } else {
        if (value.toInt() == Qt::Checked) {
            field->cb.set(rec, "true", 4, field->cbdata.set, field->fld_data);
        } else {
            field->cb.set(rec, "false", 5, field->cbdata.set, field->fld_data);
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
    uat_->changed = true;
    ownEdited();

    if (updated_cols.size() > updated_cols.count(index.column())) {
        // The validation status for other columns were also affected by
        // changing this field, mark those as dirty!
        emit dataChanged(this->index(row, updated_cols.first()),
                         this->index(row, updated_cols.last()), roles);
    } else {

        emit dataChanged(index, index, roles);
    }

    // An own record hides an inherited record with the same key
    refreshInherited();
    return true;
}

bool UatModel::insertRows(int row, int count, const QModelIndex &/*parent*/)
{
    // support insertion of just one item for now.
    if (count != 1 || row < 0 || row > rowCount() || inheritMode() == PROFILE_INHERIT_PARENT_ONLY)
        return false;

    // New records are own records, which come before the inherited records
    row = qMin(row, ownRowCount());

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
    uat_->changed = true;
    ownEdited();
    endInsertRows();
    return true;
}

bool UatModel::removeRows(int row, int count, const QModelIndex &/*parent*/)
{
    // Only own records can be removed
    if (row < 0 || count < 0 || row + count > ownRowCount())
        return false;

    if (count == 0)
        return true;

    beginRemoveRows(QModelIndex(), row, row + count - 1);
    uat_remove_record_range(uat_, row, count);
    record_errors.remove(row, count);
    dirty_records.remove(row, count);
    uat_->changed = true;
    ownEdited();
    endRemoveRows();

    // A removed own record may have hidden an inherited record
    refreshInherited();
    return true;
}

QModelIndex UatModel::copyRow(QModelIndex original)
{
    if (! original.isValid() || inheritMode() == PROFILE_INHERIT_PARENT_ONLY)
        return QModelIndex();

    // The copy is an own record, which comes before the inherited records
    int newRow = ownRowCount();
    int srcRow = original.row() >= newRow ? original.row() + 1 : original.row();

    beginInsertRows(QModelIndex(), newRow, newRow);

    // Initialize with empty values, caller should use setData to populate it.
    void *record = g_malloc0(uat_->record_size);
    for (int col = 0; col < columnCount(); col++) {
        uat_field_t *field = &uat_->fields[col];
        field->cb.set(record, "", 0, field->cbdata.set, field->fld_data);
    }
    uat_insert_record_idx(uat_, newRow, record);
    if (uat_->free_cb) {
        uat_->free_cb(record);
    }
    g_free(record);

    record_errors.insert(newRow, QMap<int, QString>());
    // a new row is created. For the moment all fields are empty, so validation
    // will likely mark everything as invalid. Ideally validation should be
    // postponed until the row (in the view) is not selected anymore
    checkRow(newRow);
    dirty_records.insert(newRow, true);

    // the UAT record has been created, now it is filled with the information
    const void *src_record = UAT_INDEX_PTR(uat_, srcRow);
    void *dst_record = UAT_INDEX_PTR(uat_, newRow);
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
    bool src_valid = g_array_index(uat_->valid_data, bool, srcRow);
    uat_update_record(uat_, dst_record, src_valid);
    record_errors[newRow] = record_errors[srcRow];
    dirty_records[newRow] = true;

    uat_->changed = true;
    ownEdited();

    endInsertRows();

    // A copy of an inherited record hides that record
    refreshInherited();
    return index(newRow, 0, QModelIndex());
}

bool UatModel::moveRowPrivate(int src_row, int dst_row)
{
    if (src_row == dst_row)
        return true;

    uat_move_index(uat_, src_row, dst_row);
    record_errors.move(src_row, dst_row);
    dirty_records.move(src_row, dst_row);
    uat_->changed = true;
    ownEdited();

    return true;
}

bool UatModel::moveRow(int src_row, int dst_row)
{
    return moveRows(QModelIndex(), src_row, 1, QModelIndex(), dst_row);
}

bool UatModel::moveRows(const QModelIndex &, int sourceRow, int count, const QModelIndex &, int destinationChild)
{
    // Records move within the own records only
    int own_count = ownRowCount();
    if (sourceRow < 0 || sourceRow + count > own_count || destinationChild < 0 || destinationChild >= own_count || count < 0)
        return false;

    if (count == 0)
        return true;

    // beginMoveRows checks this
    if (sourceRow <= destinationChild && destinationChild <= sourceRow + count - 1)
        return false;

    if (destinationChild < sourceRow) {
        if (!beginMoveRows(QModelIndex(), sourceRow, sourceRow + count - 1, QModelIndex(), destinationChild)) {
            return false;
        }
        for (int i = 0; i < count; i++) {
            moveRowPrivate(sourceRow + i, destinationChild + i);
        }
    } else {
        if (!beginMoveRows(QModelIndex(), sourceRow, sourceRow + count - 1, QModelIndex(), destinationChild + 1)) {
            return false;
        }
        for (int i = 0; i < count; i++) {
            moveRowPrivate(sourceRow, destinationChild);
        }
    }
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
    unsigned length;
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

Qt::DropActions UatModel::supportedDropActions() const
{
    return Qt::MoveAction;
}

bool UatModel::dropMimeData(const QMimeData *, Qt::DropAction, int, int, const QModelIndex &)
{
    // We could implement MimeData using uat_fld_tostr (or a new function
    // that just gives the entire string) although it would be nice for
    // uat_load_str to be able to load at a specified index, or else have
    // a function to produce a UAT record from a string. Or we could use
    // something else. However, for now we really just want internal moves.
    // Supporting drop actions and rejecting drops still allows our row
    // moving view's InternalMove to work.
    return false;
}
