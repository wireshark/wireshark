/* filter_list_model.cpp
 * Model for all filter types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wsutil/filesystem.h>
#include <wsutil/filter_files.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/models/filter_list_model.h>
#include <ui/qt/models/profile_model.h>
#include <app/application_flavor.h>

#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QDir>

FilterListItem::FilterListItem(const QString &name, const QString &filter, FilterListItem *parent,
                               const QString &source_profile) :
    ModelHelperTreeItem<FilterListItem>(parent),
    name_(name),
    filter_(filter),
    source_profile_(source_profile)
{
}

FilterListItem::FilterListItem(const FilterListItem &item) :
    ModelHelperTreeItem<FilterListItem>(item.parent_),
    name_(item.name_),
    filter_(item.filter_),
    source_profile_(item.source_profile_)
{
}

FilterListModel::FilterListModel(QObject * parent) :
    FilterListModel(FilterListModel::Display, parent)
{
}

FilterListModel::FilterListModel(FilterListModel::FilterListType type, QObject * parent) :
    InheritedRulesModel<FilterListItem>(fileName(type), parent),
    type_(type),
    own_from_globals_(false),
    own_file_exists_(false)
{
    root_ = new FilterListItem(QString(), QString(), nullptr);
    loadOwn();
    initInherited();
}

FilterListModel::~FilterListModel()
{
    qDeleteAll(default_rules_);
}

const char *FilterListModel::fileName(FilterListModel::FilterListType type)
{
    switch (type) {
        case FilterListModel::Capture: return CFILTER_FILE_NAME;
        case FilterListModel::Display: return DFILTER_FILE_NAME;
        case FilterListModel::DisplayMacro: return DMACROS_FILE_NAME;
        default: ws_assert_not_reached();
    }
    return NULL;
}

QList<FilterListModel::FilterListValue> FilterListModel::readFile(const QString &path, bool *ok)
{
    QList<FilterListValue> values;

    if (ok)
        *ok = true;

    QFile file(path);
    if (! file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (ok)
            *ok = false;
        return values;
    }

    QTextStream in(&file);
    QRegularExpression rx("\\s*\\\"\\s*(.*?)\\s*\\\"\\s(.*)");
    while (!in.atEnd())
    {
        QString data = in.readLine().trimmed();
        /* Filter out lines that do not contain content:
        *  - Starting with # is a comment
        *  - Does not start with a quoted string
        */
        if (data.startsWith("#") || ! data.trimmed().startsWith("\""))
            continue;

        QStringList content = data.split(QChar('\n'));
        foreach (QString line, content)
        {
            QRegularExpressionMatch match = rx.match(line);
            if (match.hasMatch()) {
                QString name = match.captured(1).trimmed();
                QString expression = match.captured(2).trimmed();
                if (name.length() > 0 && expression.length() > 0)
                    values << FilterListValue(name, expression);
            }
        }
    }

    return values;
}

QList<FilterListItem *> FilterListModel::readGlobals() const
{
    QList<FilterListItem *> rules;
    QString path = gchar_free_to_qstring(get_datafile_path(fileName(type_), application_configuration_environment_prefix()));
    if (path.length() <= 0 || ! QFileInfo::exists(path))
        return rules;

    for (const FilterListValue &value : readFile(path))
        rules << new FilterListItem(value.name, value.expression, nullptr);
    return rules;
}

void FilterListModel::loadOwn()
{
    QString path = gchar_free_to_qstring(get_persconffile_path(fileName(type_), true, application_configuration_environment_prefix()));
    own_file_exists_ = path.length() > 0 && QFileInfo::exists(path);

    // Without a file, a profile using its own filters only uses the global filters
    own_from_globals_ = inherit_mode_ == PROFILE_INHERIT_PROFILE_ONLY && !own_file_exists_;

    QList<FilterListItem *> rules;
    if (own_file_exists_) {
        for (const FilterListValue &value : readFile(path))
            rules << new FilterListItem(value.name, value.expression, nullptr);
    } else if (own_from_globals_) {
        rules = readGlobals();
    }

    if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY) {
        // The own filters are not in use
        qDeleteAll(rules);
    } else {
        for (FilterListItem *rule : rules) {
            rule->setParentItem(root_);
            root_->appendChild(rule);
        }
    }

    own_edited_ = false;
}

void FilterListModel::reload()
{
    refreshing_inherited_ = true;
    beginResetModel();
    delete root_;
    root_ = new FilterListItem(QString(), QString(), nullptr);
    qDeleteAll(default_rules_);
    default_rules_.clear();
    loadOwn();
    loadInherited();
    endResetModel();
    refreshing_inherited_ = false;

    refreshInherited();
}

void FilterListModel::setFilterType(FilterListModel::FilterListType type)
{
    type_ = type;
    inherit_mode_ = profile_get_inherit(application_configuration_environment_prefix(), NULL, fileName(type_));
    reload();
}

FilterListModel::FilterListType FilterListModel::filterType() const
{
    return type_;
}

/* The data of profile_inherit_read_layers() reading the filters of the parent profiles */
struct FilterListReadLayer {
    QList<FilterListItem *> rules;
};

static bool
filter_list_read_layer(const profile_inherit_layer_t *layer, const char *path, const char *,
                       profile_inherit_seen_t *seen, void *user_data, char **err)
{
    FilterListReadLayer *data = static_cast<FilterListReadLayer *>(user_data);
    bool ok;
    QList<FilterListModel::FilterListValue> values = FilterListModel::readFile(QString::fromUtf8(path), &ok);
    if (!ok) {
        *err = ws_strdup_printf("Could not read \"%s\".", path);
        return false;
    }

    for (const FilterListModel::FilterListValue &value : values) {
        QByteArray name = value.name.toUtf8();
        // A macro is found by its name, a filter also by its expression
        if (profile_inherit_seen_check(seen, name.constData()))
            continue;
        data->rules << new FilterListItem(value.name, value.expression, nullptr, QString::fromUtf8(layer->profile_name));
    }
    return true;
}

QList<FilterListItem *> FilterListModel::readInherited(profile_inherit_e mode)
{
    // The own filters are not seen here: an own filter hides an inherited
    // filter only while it is there, see refreshInherited()
    FilterListReadLayer data;
    profile_inherit_seen_t *seen = profile_inherit_seen_new();
    char *err = NULL;
    if (!profile_inherit_read_layers(application_configuration_environment_prefix(), fileName(type_), NULL, true,
                                     mode, seen, filter_list_read_layer, &data, &err)) {
        g_free(err);
    }
    profile_inherit_seen_free(seen);
    return data.rules;
}

QList<FilterListItem *> FilterListModel::readOwnRows()
{
    QList<FilterListItem *> rules;
    QString path = gchar_free_to_qstring(get_persconffile_path(fileName(type_), true, application_configuration_environment_prefix()));
    if (path.length() > 0 && QFileInfo::exists(path)) {
        for (const FilterListValue &value : readFile(path))
            rules << new FilterListItem(value.name, value.expression, nullptr);
    }
    return rules;
}

void FilterListModel::leavingInheritMode(profile_inherit_e mode)
{
    if (mode == PROFILE_INHERIT_PROFILE_ONLY && own_from_globals_ && !own_edited_) {
        // Unchanged global filters are not the profile's own; inherit instead
        default_rules_ << takeOwnRows();
    }
}

void FilterListModel::enteredInheritMode(profile_inherit_e mode)
{
    if (mode == PROFILE_INHERIT_PROFILE_ONLY && ownRowCount() == 0 && !own_file_exists_) {
        // Without own filters or a file, the profile uses the global filters,
        // as when loading them
        if (default_rules_.isEmpty())
            default_rules_ = readGlobals();
        insertOwnRows(default_rules_);
        own_from_globals_ = true;
        own_edited_ = false;
    }
}

int FilterListModel::columnCount(const QModelIndex &/* parent */) const
{
    return 2;
}

QVariant FilterListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (section >= columnCount() || section < 0 || orientation != Qt::Horizontal)
        return QVariant();

    if (role == Qt::DisplayRole)
    {
        switch (section) {
            case ColumnName:
                if (type_ == DisplayMacro)
                    return tr("Macro Name");
                else
                    return tr("Filter Name");
                break;
            case ColumnExpression:
                if (type_ == DisplayMacro)
                    return tr("Macro Expression");
                else
                    return tr("Filter Expression");
                break;
        }
    }

    return QVariant();
}

QVariant FilterListModel::data(const QModelIndex &index, int role) const
{
    if (! index.isValid() || index.row() >= rowCount())
        return QVariant();

    FilterListItem *row = root_->child(index.row());
    if (row == nullptr)
        return QVariant();

    // The lock, italics and tool tip of an inherited filter
    bool handled;
    QVariant inherited_data = inheritedData(row, index, role, &handled);
    if (handled)
        return inherited_data;

    switch (role) {
    case Qt::DisplayRole:
    case Qt::EditRole:
        switch (index.column()) {
        case FilterListModel::ColumnName:
            return row->name_;
        case FilterListModel::ColumnExpression:
            return row->filter_;
        default:
            break;
        }
        break;
    case Qt::ForegroundRole:
        if (row->isInherited())
            return ProfileInheritComboBox::inheritedData(role, row->source_profile_);
        break;
    case Qt::DecorationRole:
        // Own filters get room for the lock only when inherited filters are
        // shown, so the first column lines up
        if (index.column() == ColumnName && ownRowCount() < rowCount())
            return ProfileInheritComboBox::inheritedPlaceholderIcon();
        break;
    default:
        break;
    }

    return QVariant();
}

bool FilterListModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (! index.isValid() || index.row() >= rowCount() || role != Qt::EditRole)
        return false;

    FilterListItem *row = root_->child(index.row());
    if (row == nullptr || row->isInherited())
        return false;

    switch (index.column()) {
    case FilterListModel::ColumnName:
        if (value.toString().contains("\""))
            return false;
        row->name_ = value.toString();
        break;
    case FilterListModel::ColumnExpression:
        row->filter_ = value.toString();
        break;
    default:
        return false;
    }

    own_edited_ = true;
    emit dataChanged(index, index, QVector<int>() << role);
    return true;
}

Qt::ItemFlags FilterListModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags fl = QAbstractItemModel::flags(index);
    fl |= Qt::ItemIsDropEnabled;

    if (! index.isValid() || index.row() >= rowCount())
        return fl;

    fl |= Qt::ItemIsEditable | Qt::ItemIsDragEnabled;

    // Inherited filters are read-only
    return inheritedFlags(index, fl);
}

QModelIndex FilterListModel::addFilter(QString name, QString expression)
{
    if (name.length() == 0 || expression.length() == 0)
        return QModelIndex();

    // New filters go into the own filters, which are not used with the parent's filters only
    if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY)
        return QModelIndex();

    // After the own filters, before the inherited filters
    int row = ownRowCount();
    beginInsertRows(QModelIndex(), row, row);
    // Don't touch the inherited rows while inserting
    refreshing_inherited_ = true;
    root_->insertChild(row, new FilterListItem(name, expression, root_));
    own_edited_ = true;
    refreshing_inherited_ = false;
    endInsertRows();

    return index(row, 0);
}

QModelIndex FilterListModel::findByName(QString name)
{
    if (name.length() == 0)
        return QModelIndex();

    for (int cnt = 0; cnt < rowCount(); cnt++)
    {
        if (root_->child(cnt)->name_ == name)
            return index(cnt, 0);
    }

    return QModelIndex();
}

QModelIndex FilterListModel::findByExpression(QString expression)
{
    if (expression.length() == 0)
        return QModelIndex();

    for (int cnt = 0; cnt < rowCount(); cnt++)
    {
        if (root_->child(cnt)->filter_ == expression)
            return index(cnt, 0);
    }

    return QModelIndex();
}

void FilterListModel::removeFilter(QModelIndex idx)
{
    if (! idx.isValid() || idx.row() >= rowCount())
        return;

    removeRows(idx.row(), 1);
}

bool FilterListModel::removeRows(int row, int count, const QModelIndex &parent)
{
    // Only own filters can be removed
    int own_count = ownRowCount();
    if (parent.isValid() || row < 0 || row >= own_count)
        return false;
    count = qMin(count, own_count - row);
    if (count <= 0)
        return false;

    beginRemoveRows(parent, row, row + count - 1);
    for (int i = 0; i < count; i++)
        root_->removeChild(row);
    own_edited_ = true;
    endRemoveRows();
    return true;
}

bool FilterListModel::importFile(const QString &path, QString &err)
{
    bool ok;
    QList<FilterListValue> values = readFile(path, &ok);
    if (!ok) {
        err = tr("Could not read \"%1\".").arg(path);
        return false;
    }

    for (const FilterListValue &value : values)
        addFilter(value.name, value.expression);
    return true;
}

QString FilterListModel::ownFilePath() const
{
    //Use the model object to pull the profile information
    ProfileModel model;
    QString profilePath;
    const ProfileItem* currentProfile = model.getCurrentProfile();
    if (currentProfile != Q_NULLPTR)
        profilePath = currentProfile->getProfilePath();
    return QStringLiteral("%1%2%3").arg(profilePath).arg("/").arg(fileName(type_));
}

void FilterListModel::saveList()
{
    // The profile's file is left as it is when only the parent's filters are used
    if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY)
        return;

    QList<FilterListItem *> rules;
    for (int row = 0; row < ownRowCount(); row++)
        rules << root_->child(row);

    QString filename = ownFilePath();

    // A file without filters is written only if the filters it replaces had
    // filters: the file, or the global filters used without a file. A
    // profile without a file keeps using the global or inherited filters.
    if (rules.isEmpty() && !(own_from_globals_ && inherit_mode_ == PROFILE_INHERIT_PROFILE_ONLY)) {
        if (!QFileInfo::exists(filename) || readFile(filename).isEmpty())
            return;
    }

    QFile file(filename);

    if (! file.open(QIODevice::WriteOnly | QIODevice::Text))
        return;

    QTextStream out(&file);
    for (const FilterListItem *rule : rules)
    {
        QString line = QStringLiteral("\"%1\"").arg(rule->name_.trimmed());
        line.append(join_lines(QStringLiteral(" %1").arg(rule->filter_)));

        out << line << Qt::endl;
    }

    file.close();
    own_file_exists_ = true;
    ownSaved();
}

Qt::DropActions FilterListModel::supportedDropActions() const
{
    return Qt::MoveAction;
}
