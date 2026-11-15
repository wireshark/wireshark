/* profile_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>

#include "ui/profile.h"
#include "ui/recent.h"

#include "wsutil/filesystem.h"
#include "app/application_flavor.h"

#include <ui/simple_dialog.h>
#include <ui/qt/models/profile_model.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/unique_name.h>
#include <ui/qt/utils/wireshark_zip_helper.h>

#include <QApplication>
#include <QDataStream>
#include <QDir>
#include <QFont>
#include <QMimeData>
#include <QTemporaryDir>
#include <QRegularExpression>

Q_LOGGING_CATEGORY(profileLogger, "wireshark.profiles")

static const QString profileMimeType = QStringLiteral("application/x-wireshark-profile");


ProfileItem::ProfileItem(profile_def* profile)
 : name_(profile->name),
   status_(StatusType::Existing),
   autoSwitchFilter_(profile->auto_switch_filter ? profile->auto_switch_filter : ""),
   isGlobal_(profile->is_global),
   reference_(profile->name)
{

}

ProfileItem::ProfileItem(QString name, QString reference, StatusType status, bool isGlobal, bool fromGlobal, bool isImport)
 : name_(name),
    status_(status),
    isGlobal_(isGlobal),
    fromGlobal_(fromGlobal),
    isImport_(isImport),
    reference_(reference)
{

}

const QString ProfileItem::getType() const
{
    if (isDefault())
        return QObject::tr("Default");

    if (isGlobal_)
        return QObject::tr("Global");

    return QObject::tr("Personal");
}

bool ProfileItem::isDefault() const
{
    return (!parent_ && name_.compare(DEFAULT_PROFILE) == 0);
}

// NOLINTNEXTLINE(misc-no-recursion)
QString ProfileItem::getName() const
{
    return parent_ ? QStringLiteral("%1/%2").arg(parent_->getName(), name_) : name_;
}

ProfileItem::StatusType ProfileItem::getStatus() const
{
    // A profile is changed when it, or one of its parents, has been renamed or moved
    if (status_ == StatusType::Existing || status_ == StatusType::Changed)
        return (getName().compare(reference_) == 0) ? StatusType::Existing : StatusType::Changed;

    return status_;
}

QString ProfileItem::getProfilePath(QString profileName) const
{
    QString profile_path = gchar_free_to_qstring(get_profile_dir(application_configuration_environment_prefix(), profileName.toUtf8().constData(), isGlobal()));

    return QDir::toNativeSeparators(profile_path);
}

QString ProfileItem::getProfilePath() const
{
    return getProfilePath(getName());
}

void ProfileItem::setName(QString value)
{
    name_ = value;
    setForDeletion_ = false;
}

void ProfileItem::setAutoSwitchFilter(QString value)
{
    autoSwitchFilter_ = value;
    isChanged_ = true;
}



ProfileSortModel::ProfileSortModel(QObject * parent):
    QSortFilterProxyModel (parent),
    ft_(ProfileSortModel::AllProfiles),
    ftext_(QString())
{
    setRecursiveFilteringEnabled(true);
}

bool ProfileSortModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    QModelIndex left = source_left;
    if (source_left.column() != ProfileModel::COL_NAME)
        left = source_left.sibling(source_left.row(), ProfileModel::COL_NAME);

    QModelIndex right = source_right;
    if (source_right.column() != ProfileModel::COL_NAME)
        right = source_right.sibling(source_right.row(), ProfileModel::COL_NAME);

    bool igL = left.data(ProfileModel::DATA_IS_GLOBAL).toBool();
    bool igR = right.data(ProfileModel::DATA_IS_GLOBAL).toBool();

    if (igL && !igR)
        return true;
    if (!igL && igR)
        return false;

    if (!igL && !igR)
    {
        if (left.data(ProfileModel::DATA_IS_DEFAULT).toBool())
            return false;

        if (right.data(ProfileModel::DATA_IS_DEFAULT).toBool())
            return true;
    }

    return (left.data().toString().compare(right.data().toString(), Qt::CaseInsensitive) > 0);
}

void ProfileSortModel::setFilterType(FilterType ft)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
    beginFilterChange();
#endif
    ft_ = ft;
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}

void ProfileSortModel::setFilterString(QString txt)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
    beginFilterChange();
#endif
    ftext_ = ! txt.isEmpty() ? txt : "";
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}

QStringList ProfileSortModel::filterTypes()
{
    QMap<int, QString> filter_types_;
    filter_types_.insert(ProfileSortModel::AllProfiles, tr("All profiles"));
    filter_types_.insert(ProfileSortModel::PersonalProfiles, tr("Personal profiles"));
    filter_types_.insert(ProfileSortModel::GlobalProfiles, tr("Global profiles"));

    return filter_types_.values();
}

bool ProfileSortModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    bool accept = true;
    QModelIndex idx = sourceModel()->index(source_row, ProfileModel::COL_NAME, source_parent);

    if (ft_ != ProfileSortModel::AllProfiles)
    {
        bool gl = idx.data(ProfileModel::DATA_IS_GLOBAL).toBool();
        if (ft_ == ProfileSortModel::PersonalProfiles && gl)
            accept = false;
        else if (ft_ == ProfileSortModel::GlobalProfiles && ! gl)
            accept = false;
    }

    if (ftext_.length() > 0)
    {
        // Match the profile's own name only. Recursive filtering keeps the
        // parents leading to a match, and hides non-matching sub-profiles.
        const ProfileModel *model = qobject_cast<const ProfileModel *>(sourceModel());
        const ProfileItem *item = model ? model->getProfile(idx) : Q_NULLPTR;
        QString name = item ? item->getLeafName() : idx.data().toString();
        if (! name.contains(ftext_, Qt::CaseInsensitive))
            accept = false;
    }

    return accept;
}

ProfileModel::ProfileModel(QObject * parent) :
    QAbstractItemModel(parent)
{
    /* Set filenames for profiles */
    GList *files, *file;
    files = g_hash_table_get_keys(const_cast<GHashTable *>(allowed_profile_filenames()));
    file = g_list_first(files);
    while (file) {
        profile_files_ << static_cast<char *>(file->data);
        file = gxx_list_next(file);
    }
    g_list_free(files);

    fillTable();
}

ProfileModel::~ProfileModel()
{
    foreach(ProfileItem * item, profile_items_)
        delete item;
    profile_items_.clear();
}

void ProfileModel::fillTable()
{
    beginResetModel();

    profile_sync(application_configuration_environment_prefix());

    const char* currentProfile = get_profile_name();

    for (GList* cur = profile_get_list(); cur; cur = cur->next) {
        profile_def* profile = static_cast<profile_def*>(cur->data);
        profile_items_ << new ProfileItem(profile);
    }

    // The list is not sorted, so link the parents before their children
    QList<ProfileItem*> items = profile_items_;
    std::stable_sort(items.begin(), items.end(), [](const ProfileItem* a, const ProfileItem* b) {
        return a->getReference().count('/') < b->getReference().count('/');
    });
    foreach (ProfileItem* item, items)
    {
        linkParent(item, item->getReference());

        // Store current profile
        if ((item->getName().compare(currentProfile) == 0) && !item->isGlobal())
            current_profile_ = item;
    }

    endResetModel();
}

bool ProfileModel::userProfilesExist() const
{
    foreach(ProfileItem* profile, profile_items_)
    {
        if (!profile->isGlobal() && !profile->isDefault())
            return true;
    }

    return false;
}

ProfileItem *ProfileModel::itemAt(const QModelIndex &index) const
{
    return index.isValid() ? static_cast<ProfileItem *>(index.internalPointer()) : Q_NULLPTR;
}

QList<ProfileItem *> ProfileModel::children(const ProfileItem *parent) const
{
    QList<ProfileItem *> result;
    foreach (ProfileItem *item, profile_items_)
    {
        if (item->parent() == parent)
            result << item;
    }
    return result;
}

QModelIndex ProfileModel::indexOf(const ProfileItem *item, int column) const
{
    if (!item)
        return QModelIndex();

    qsizetype row = children(item->parent()).indexOf(item);
    return row < 0 ? QModelIndex() : createIndex(static_cast<int>(row), column, item);
}

// Set the parent from the full profile name. If the parent is not found the
// full name is used as leaf name.
void ProfileModel::linkParent(ProfileItem *item, const QString &name) const
{
    ProfileItem *parent = Q_NULLPTR;
    if (name.contains('/'))
    {
        int row = findByNameAndVisibility(name.section('/', 0, -2), item->isGlobal());
        if (row >= 0)
            parent = profile_items_[row];
    }
    item->setParent(parent);
    item->setName(parent ? name.section('/', -1) : name);
}

void ProfileModel::removeItem(ProfileItem *item)
{
    QModelIndex idx = indexOf(item);
    beginRemoveRows(idx.parent(), idx.row(), idx.row());
    profile_items_.removeOne(item);
    delete item;
    endRemoveRows();
}

int ProfileModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid() && parent.column() != COL_NAME)
        return 0;

    return static_cast<int>(children(itemAt(parent)).count());
}

QModelIndex ProfileModel::index(int row, int column, const QModelIndex &parent) const
{
    if (column < 0 || column >= _LAST_ENTRY || (parent.isValid() && parent.column() != COL_NAME))
        return QModelIndex();

    QList<ProfileItem *> items = children(itemAt(parent));
    if (row < 0 || row >= items.count())
        return QModelIndex();

    return createIndex(row, column, items.at(row));
}

QModelIndex ProfileModel::parent(const QModelIndex &index) const
{
    ProfileItem *item = itemAt(index);
    return item ? indexOf(item->parent()) : QModelIndex();
}

int ProfileModel::columnCount(const QModelIndex &) const
{
    return static_cast<int>(_LAST_ENTRY);
}

QVariant ProfileModel::dataDisplay(const QModelIndex &index) const
{
    ProfileItem* item = itemAt(index);

    switch (index.column())
    {
    case COL_NAME:
        return item->getLeafName();
    case COL_TYPE:
        return item->getType();
    case COL_AUTO_SWITCH_FILTER:
        return item->getAutoSwitchFilter();
    default:
        break;
    }

    return QVariant();
}

QVariant ProfileModel::dataFontRole(const QModelIndex &index) const
{
    ProfileItem* item = itemAt(index);

    QFont font;

    if (item->isGlobal())
        font.setItalic(true);
    else if (item == current_profile_)
        font.setBold(true);

    if (item->isDeleted())
        font.setStrikeOut(true);

    return font;
}

// The profile has a directory, at its reference
static bool onDisk(const ProfileItem* item)
{
    return item->getStatus() == ProfileItem::StatusType::Existing || item->getStatus() == ProfileItem::StatusType::Changed;
}

// Profile names that only differ in case clash on case-insensitive file
// systems. Allow this only for profiles that already exist with such names.
static Qt::CaseSensitivity nameCase(const ProfileItem* a, const ProfileItem* b)
{
    return (onDisk(a) && onDisk(b) && a->getReference().compare(b->getReference(), Qt::CaseInsensitive) == 0) ?
           Qt::CaseSensitive : Qt::CaseInsensitive;
}

bool ProfileModel::isDataValid(QString& err)
{
    err.clear();
    foreach(ProfileItem* item, profile_items_)
    {
        // If the profile is slated for deletion, don't care about valid data
        if (item->isDeleted())
            continue;

        if (!checkNameValidity(item->getLeafName(), err))
            return false;

        foreach(ProfileItem* dup_item, profile_items_)
        {
            // Skip same profiles
            if (item == dup_item)
                continue;

            // Deleted profiles free their names before any new names are used
            if (dup_item->isDeleted())
                continue;

            // Ensure matching "scope"
            if (item->isGlobal() == dup_item->isGlobal())
            {
                // Can't have multiple matching personal profile names
                Qt::CaseSensitivity cs = nameCase(item, dup_item);
                if (item->getName().compare(dup_item->getName(), cs) == 0)
                {
                    err = tr("Duplicate profile name (%1)").arg(item->getName());
                    return false;
                }
            }
        }
    }

    return true;
}

bool ProfileModel::checkDuplicate(const QModelIndex &index, bool isOriginalToDuplicate) const
{
    ProfileItem* item = itemAt(index);
    if (!isOriginalToDuplicate && (item->getStatus() == ProfileItem::StatusType::Existing))
        return false;

    foreach (ProfileItem* dupItem, profile_items_)
    {
        if (dupItem == item || dupItem->isDeleted())
            continue;

        // Ensure matching "scope"
        if (item->isGlobal() == dupItem->isGlobal())
        {
            Qt::CaseSensitivity cs = nameCase(item, dupItem);
            if (item->getName().compare(dupItem->getName(), cs) == 0)
            {
                if (isOriginalToDuplicate)
                {
                    if (dupItem->getStatus() != ProfileItem::StatusType::Existing)
                        return true;
                }
                else
                {
                    return true;
                }
            }
        }
    }

    return false;
}

QVariant ProfileModel::dataBackgroundRole(const QModelIndex &index) const
{
    ProfileItem* item = itemAt(index);

    if (item->isDeleted())
        return ThemeManager::instance()->color(ThemeManager::PacketsInactive);

    if (!item->isDefault() && !item->isGlobal())
    {
        /* Highlights erroneous line */
        QString ignore;
        if (item->isDeleted() || checkDuplicate(index) || !checkNameValidity(item->getLeafName(), ignore))
            return ThemeManager::instance()->color(ThemeManager::FilterInvalid);

        /* Highlights line, which has been duplicated by another index */
        if (checkDuplicate(index, true))
            return ThemeManager::instance()->color(ThemeManager::FilterValid);
    }

    return QVariant();
}

QVariant ProfileModel::dataForegroundRole(const QModelIndex &index) const
{
    ProfileItem* item = itemAt(index);

    if (item->isDeleted())
        return QApplication::palette().color(QPalette::Disabled, QPalette::Text);

    if (item->isGlobal() && index.column() == COL_AUTO_SWITCH_FILTER) {
        return ColorUtils::disabledForeground();
    }

    return QVariant();
}

QVariant ProfileModel::dataToolTipRole(const QModelIndex& index) const
{
    ProfileItem* item = itemAt(index);

    if (item->isGlobal())
        return tr("This is a system provided profile");

    QString ignorePath;
    return dataPath(index, ignorePath);
}

QVariant ProfileModel::dataPath(const QModelIndex &index, QString& profilePath) const
{
    // Presume profile path isn't provided
    profilePath = "";

    if (!index.isValid())
        return QVariant();

    ProfileItem* item = itemAt(index);

    // Renamed and deleted profiles free their names, so only another profile can have it
    if (checkDuplicate(index))
        return tr("A profile already exists with this name");

    if (item->isDeleted())
    {
        if (item->isDefault())
            return tr("Resetting to default");

        QString profileName = item->getName();
        if (item->getReference().compare(item->getName()) == 0)
        {
            profilePath = item->getProfilePath();
        }
        else
        {
            profileName = tr("%1 (originally %2)").arg(item->getName()).arg(item->getReference());
            profilePath = item->getProfilePath(item->getReference());
        }
        return tr("The %1 profile is being deleted").arg(profileName);
    }

    // An imported profile is stored when it is imported, at its reference
    if (item->isImport())
    {
        profilePath = item->getProfilePath(item->getReference());
        return tr("Imported profile");
    }

    if (item->isDefault())
    {
        profilePath = item->getProfilePath();
        return gchar_free_to_qstring(get_persconffile_path("", false, application_configuration_environment_prefix()));
    }

    switch (item->getStatus())
    {
    case ProfileItem::StatusType::Existing:
        {
            profilePath = item->getProfilePath();
            return item->getProfilePath();
        }
    case ProfileItem::StatusType::New:
        {
            QString errMsg;

            if (! checkNameValidity(item->getLeafName(), errMsg))
                return errMsg;

            return tr("Created from default settings");
        }
    case ProfileItem::StatusType::Changed:
        {
            QString msg;
            if (!checkNameValidity(item->getLeafName(), msg))
                return msg;

            if (item->getReference().compare(item->getName()))
            {
                profilePath = item->getProfilePath(item->getReference());
                // Moved with its parent or on its own, keeping its own name
                if (item->getLeafName().compare(item->getReference().section('/', -1)) == 0)
                    return tr("Moved from: %1").arg(item->getReference());
                return tr("Renamed from: %1").arg(item->getReference());
            }

            return QVariant();
        }
    case ProfileItem::StatusType::Copy:
        {
            QString msg = tr("Copied from: %1").arg(item->getReference());
            QString appendix;

            /* A global profile is neither deleted or removed, only system provided is allowed as appendix */
            if (profile_exists(application_configuration_environment_prefix(), item->getReference().toUtf8().constData(), true) && item->isFromGlobal())
            {
                appendix = tr("system provided");
            }
            /* A default model as reference can neither be deleted or renamed, so skip if the reference was one */
            else if (!item->isDefault())
            {
                /* find a non-global, non-default profile which could be referenced by this one. Those are the only
                    * ones which could be renamed or deleted */
                ProfileItem* refItem = Q_NULLPTR;
                // Prefer the copied profile over another one given its name
                foreach (int row, findAllByNameAndVisibility(item->getReference(), false, true))
                {
                    ProfileItem* found = profile_items_[row];
                    bool copied = onDisk(found) && found->getReference().compare(item->getReference()) == 0;
                    if (!refItem || copied)
                        refItem = found;
                    if (copied)
                        break;
                }

                /* The reference is itself a copy of the original, therefore it is not accepted */
                if ((refItem->getStatus() == ProfileItem::StatusType::Copy || refItem->getStatus() == ProfileItem::StatusType::New) && refItem->getName().compare(item->getReference()) != 0)
                    refItem = Q_NULLPTR;

                /* found no other profile, original one had to be deleted */
                if (!refItem || refItem == item || (refItem->isDeleted()))
                {
                    appendix = tr("deleted");
                }
                /* found another profile, so the reference had been renamed, it the status is changed */
                else if (refItem && refItem->getStatus() == ProfileItem::StatusType::Changed)
                {
                    appendix = tr("renamed to %1").arg(refItem->getName());
                }
            }

            if (appendix.length() > 0)
                msg.append(QStringLiteral(" (%1)").arg(appendix));

            return msg;
        }
    default:
        ws_assert_not_reached();
    }

    return QVariant();
}

QVariant ProfileModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    ProfileItem* item = itemAt(index);

    switch (role)
    {
    case Qt::DisplayRole:
        return dataDisplay(index);
    case Qt::FontRole:
        return dataFontRole(index);
    case Qt::BackgroundRole:
        return dataBackgroundRole(index);
    case Qt::ForegroundRole:
        return dataForegroundRole(index);
    case Qt::ToolTipRole:
        return dataToolTipRole(index);
    case ProfileModel::DATA_IS_DEFAULT:
        return QVariant::fromValue(item->isDefault());
    case ProfileModel::DATA_IS_GLOBAL:
        return QVariant::fromValue(item->isGlobal());
    default:
        break;
    }

    return QVariant();
}

QVariant ProfileModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    switch (section)
    {
    case COL_NAME:
        return tr("Profile");
    case COL_TYPE:
        return tr("Type");
    case COL_AUTO_SWITCH_FILTER:
        return tr("Auto Switch Filter");
    default:
        ws_assert_not_reached();
        break;
    }

    return QVariant();
}

Qt::ItemFlags ProfileModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::ItemIsDropEnabled;

    ProfileItem* item = itemAt(index);

    Qt::ItemFlags fl = QAbstractItemModel::flags(index);

    switch(index.column())
    {
    case COL_NAME:
        if (!item->isDefault())
            fl |= Qt::ItemIsEditable;
        if (!item->isDefault() && !item->isGlobal() && !item->isDeleted())
            fl |= Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled;
        break;
    case COL_AUTO_SWITCH_FILTER:
        fl |= Qt::ItemIsEditable;
        break;
    }

    return fl;
}

QModelIndex ProfileModel::findByName(const QString& name)
{
    int row = findByNameAndVisibility(name, false);
    if (row < 0)
        row = findByNameAndVisibility(name, true);

    return row < 0 ? QModelIndex() : indexOf(profile_items_[row]);
}

const ProfileItem* ProfileModel::getPersonalProfile(const QString& name)
{
    int row = findByNameAndVisibility(name, false);
    if (row < 0)
        return Q_NULLPTR;

    return profile_items_[row];
}


int ProfileModel::findByNameAndVisibility(const QString& name, bool isGlobal, bool searchReference, Qt::CaseSensitivity cs) const
{
    // A deleted profile may share its name with another one, prefer the other one
    QList<int> result = findAllByNameAndVisibility(name, isGlobal, searchReference, cs);
    foreach (int row, result)
    {
        if (!profile_items_[row]->isDeleted())
            return row;
    }
    return result.count() == 0 ? -1 : result.at(0);
}

QList<int> ProfileModel::findAllByNameAndVisibility(const QString& name, bool isGlobal, bool searchReference, Qt::CaseSensitivity cs) const
{
    QList<int> result;

    for (int cnt = 0; cnt < profile_items_.count(); cnt++)
    {
        ProfileItem* item = profile_items_[cnt];
        if (item->isGlobal() == isGlobal)
        {
            if (name.compare(item->getName(), cs) == 0 || (searchReference && name.compare(item->getReference(), cs) == 0))
                result << cnt;
        }
    }

    return result;

}

QModelIndex ProfileModel::addNewProfile(QString name)
{
    return addNewProfile(name, name);
}

QModelIndex ProfileModel::addNewProfile(QString name, QString reference, bool isGlobal, bool fromGlobal, bool isImport)
{
    int cnt = 1;
    QString newName = name;
    while (findByNameAndVisibility(newName, false, false, Qt::CaseInsensitive) >= 0)
    {
        newName = QStringLiteral("%1 %2").arg(name, QString::number(cnt));
        cnt++;
    }

    // Imported profiles already exist on disk, so they can be renamed and deleted like existing ones
    ProfileItem* item = new ProfileItem(newName, reference, isImport ? ProfileItem::StatusType::Existing : ProfileItem::StatusType::New,
                                        isGlobal, fromGlobal, isImport);
    linkParent(item, newName);

    int row = static_cast<int>(children(item->parent()).count());
    beginInsertRows(indexOf(item->parent()), row, row);
    profile_items_ << item;
    endInsertRows();

    return indexOf(item);
}


// NOLINTNEXTLINE(misc-no-recursion)
QModelIndex ProfileModel::duplicateEntry(QModelIndex idx, ProfileItem::StatusType new_status, const QString &name)
{
    if (!idx.isValid())
        return QModelIndex();

    ProfileItem* item = itemAt(idx);

    /* this is a copy from a personal profile, check if the original has been a
     * new profile or a preexisting one. In the case of a new profile, restart
     * with the state PROF_STAT_NEW */
    if (item->getStatus() == ProfileItem::StatusType::Copy && !item->isGlobal())
    {
        int row = findByNameAndVisibility(item->getReference(), false);
        ProfileItem* copyItem = (row >= 0) ? profile_items_[row] : Q_NULLPTR;
        if (copyItem && copyItem->getStatus() == ProfileItem::StatusType::New)
        {
            // We recurse here, but our depth is limited
            return duplicateEntry(indexOf(copyItem), ProfileItem::StatusType::New, name);
        }
    }

    /* Rules for figuring out the name to copy from:
     *
     * General, use copy name
     * If status of copy is new or changed => use copy reference
     * If copy is non global and status of copy is != changed, use original parent name
     */
    QString parent = item->getName();
    if ((item->getStatus() == ProfileItem::StatusType::Changed) ||
        (!item->isGlobal() && item->getStatus() != ProfileItem::StatusType::New && item->getStatus() != ProfileItem::StatusType::Changed))
    {
        parent = item->getReference();
    }

    /* parent references the parent profile to be used, parentName is the base for the new name */
    QString parentName = parent;
    /* the user has changed the profile name, therefore this is also the name to be used */
    if (item->getStatus() != ProfileItem::StatusType::Existing)
        parentName = item->getName();

    /* a copy of a global profile is created at the top level */
    if (item->isGlobal())
        parentName = item->getLeafName();

    /* check to ensure we do not end up with (copy) (copy) (copy) ... */
    QRegularExpression rx("\\s+(\\(\\s*" + tr("copy", "noun") + "\\s*\\d*\\))");
    parentName.replace(rx, "");

    /* if copy is global and name has not been used before, use that, else create first copy */
    const QString first_name = (item->isGlobal() && findByNameAndVisibility(parentName, false, false, Qt::CaseInsensitive) < 0)
                                   ? item->getLeafName()
                                   : QStringLiteral("%1 (%2)").arg(parentName, tr("copy", "noun"));
    /* iterate until an unused version is found */
    const QString new_name = !name.isEmpty() ? name : uniqueName(
        [&](int n) {
            return n == 0 ? first_name
                          : QStringLiteral("%1 (%2 %3)").arg(parentName, tr("copy", "noun"), QString::number(n));
        },
        [this](const QString &candidate) { return findByNameAndVisibility(candidate, false, false, Qt::CaseInsensitive) >= 0; });

    /* if this would be a copy, but the original is already a new one, this is a copy as well */
    if (new_status == ProfileItem::StatusType::Copy && item->getStatus() == ProfileItem::StatusType::New)
        new_status = ProfileItem::StatusType::New;

    ProfileItem* newItem = new ProfileItem(new_name, parent, new_status, false, item->isFromGlobal() ? true : item->isGlobal(), item->isImport());
    linkParent(newItem, new_name);

    int row = static_cast<int>(children(newItem->parent()).count());
    beginInsertRows(indexOf(newItem->parent()), row, row);
    profile_items_ << newItem;
    endInsertRows();

    // Copy the sub-profiles as well, except those deleted on their own
    foreach (ProfileItem* child, children(item))
    {
        if (!child->isDeleted() || item->isDeleted())
            duplicateEntry(indexOf(child), ProfileItem::StatusType::Copy, QStringLiteral("%1/%2").arg(newItem->getName(), child->getLeafName()));
    }

    /* return the index of the profile */
    return indexOf(newItem);
}

void ProfileModel::deleteEntries(QModelIndexList idcs)
{
    // Collect the selected personal profiles and all their children
    QList<ProfileItem*> items;
    foreach (QModelIndex idx, withChildren(idcs))
    {
        ProfileItem* item = itemAt(idx);
        if (!item->isGlobal())
            items << item;
    }

    // Handle children before their parents
    std::sort(items.begin(), items.end(), [](const ProfileItem* a, const ProfileItem* b) {
        return a->getName().count('/') > b->getName().count('/');
    });

    foreach (ProfileItem* item, items)
    {
        if ((item->getStatus() == ProfileItem::StatusType::New || item->getStatus() == ProfileItem::StatusType::Copy) &&
            children(item).isEmpty())
        {
            // If it was just created, remove it
            removeItem(item);
            continue;
        }

        // Mark it for deletion
        item->setForDeletion();
        emit dataChanged(indexOf(item, COL_NAME), indexOf(item, columnCount() - 1));
    }
}

bool ProfileModel::restoreEntries(QModelIndexList idcs)
{
    bool restored = false;
    foreach(QModelIndex idx, idcs)
    {
        // Restore deleted parents as well
        for (ProfileItem* item = itemAt(idx); item; item = item->parent())
        {
            if (item->isDeleted())
            {
                // Reset the profile status
                item->setName(item->getLeafName());
                emit dataChanged(indexOf(item, COL_NAME), indexOf(item, columnCount() - 1));
                restored = true;
            }
        }
    }

    return restored;
}

QModelIndex ProfileModel::activeProfile() const
{
    if (current_profile_ == Q_NULLPTR)
        return QModelIndex();

    QList<int> rows = findAllByNameAndVisibility(current_profile_->getName(), false, true);
    foreach(int row, rows)
    {
        ProfileItem* item = profile_items_[row];
        if (item->isGlobal() || checkDuplicate(indexOf(item)))
            return QModelIndex();

        if ((current_profile_->getName().compare(item->getName()) == 0 && (item->getStatus() == ProfileItem::StatusType::Existing || item->isDefault())) ||
            (current_profile_->getName().compare(item->getReference()) == 0 && item->getStatus() == ProfileItem::StatusType::Changed))
            return indexOf(item);
    }

    return QModelIndex();
}

bool ProfileModel::setData(const QModelIndex &cur_index, const QVariant &value, int role)
{
    if (!cur_index.isValid())
        return false;

    if (role != Qt::EditRole)
        return false;

    if (data(cur_index, role) == value) {
        // Data appears unchanged, do not do additional checks.
        return true;
    }

    ProfileItem* item = itemAt(cur_index);

    switch (cur_index.column())
    {
    case COL_NAME:
        if (value.toString().isEmpty())
            return false;

        // There is only one Default profile
        if (!item->parent() && value.toString().compare(DEFAULT_PROFILE, Qt::CaseInsensitive) == 0)
            return false;

        if (!item->isDefault())
        {
            item->setName(value.toString());
            emit dataChanged(cur_index, cur_index);
        }
        break;
    case COL_AUTO_SWITCH_FILTER:
        item->setAutoSwitchFilter(value.toString());
        emit dataChanged(cur_index, cur_index);
        break;
    }

    return true;
}

Qt::DropActions ProfileModel::supportedDropActions() const
{
    return Qt::MoveAction;
}

QStringList ProfileModel::mimeTypes() const
{
    return QStringList() << profileMimeType;
}

QMimeData *ProfileModel::mimeData(const QModelIndexList &indexes) const
{
    QByteArray encoded;
    QDataStream stream(&encoded, QIODevice::WriteOnly);
    foreach (QModelIndex idx, indexes)
    {
        if (idx.column() == COL_NAME)
            stream << reinterpret_cast<quintptr>(itemAt(idx));
    }

    QMimeData *data = new QMimeData();
    data->setData(profileMimeType, encoded);
    return data;
}

// Only accept items from this model
QList<ProfileItem *> ProfileModel::draggedItems(const QMimeData *data) const
{
    QList<ProfileItem *> items;
    QByteArray encoded = data->data(profileMimeType);
    QDataStream stream(&encoded, QIODevice::ReadOnly);
    while (!stream.atEnd())
    {
        quintptr ptr;
        stream >> ptr;
        foreach (ProfileItem *item, profile_items_)
        {
            if (reinterpret_cast<quintptr>(item) == ptr)
                items << item;
        }
    }
    return items;
}

bool ProfileModel::canMove(const ProfileItem *item, const ProfileItem *target) const
{
    if (item->isGlobal() || item->isDefault() || item->isDeleted() || item->parent() == target)
        return false;

    if (target && (target->isGlobal() || target->isDefault() || target->isDeleted()))
        return false;

    // Cannot move a profile into itself or one of its children
    for (const ProfileItem *p = target; p; p = p->parent())
    {
        if (p == item)
            return false;
    }

    // Do not move deeper than the maximum number of levels
    qsizetype levels = 0;
    foreach (QModelIndex idx, withChildren({indexOf(item)}))
        levels = qMax(levels, itemAt(idx)->getName().count('/') - item->getName().count('/') + 1);
    if ((target ? target->getName().count('/') + 1 : 0) + levels > PROFILE_MAX_DEPTH)
        return false;

    // Deleted profiles free their names before any new names are used
    QString name = target ? QStringLiteral("%1/%2").arg(target->getName(), item->getLeafName()) : item->getLeafName();
    int row = findByNameAndVisibility(name, false, false, Qt::CaseInsensitive);
    return row < 0 || profile_items_[row]->isDeleted();
}

// Keep the hierarchy of the dragged profiles: a profile below another
// dragged profile is moved into the nearest one of them.
static ProfileItem *dropParent(const ProfileItem *item, const QList<ProfileItem *> &items, ProfileItem *target)
{
    for (ProfileItem *p = item->parent(); p; p = p->parent())
    {
        if (items.contains(p))
            return p;
    }
    return target;
}

bool ProfileModel::canDropMimeData(const QMimeData *data, Qt::DropAction action, int, int, const QModelIndex &parent) const
{
    if (action != Qt::MoveAction)
        return false;

    // Cannot move profiles into one of themselves
    ProfileItem *target = itemAt(parent);
    QList<ProfileItem *> items = draggedItems(data);
    for (ProfileItem *p = target; p; p = p->parent())
    {
        if (items.contains(p))
            return false;
    }

    // Move all the dragged profiles or none of them
    QStringList names;
    foreach (ProfileItem *item, items)
    {
        ProfileItem *newParent = dropParent(item, items, target);
        if (item->parent() == newParent)
            continue;

        QString name = newParent ? QStringLiteral("%1/%2").arg(newParent->getName(), item->getLeafName()) : item->getLeafName();
        if (!canMove(item, newParent) || names.contains(name, Qt::CaseInsensitive))
            return false;
        names << name;
    }
    return !names.isEmpty();
}

bool ProfileModel::dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent)
{
    if (!canDropMimeData(data, action, row, column, parent))
        return false;

    ProfileItem *target = itemAt(parent);
    QList<ProfileItem *> items = draggedItems(data);
    bool moved = false;

    foreach (ProfileItem *item, items)
    {
        ProfileItem *newParent = dropParent(item, items, target);
        if (!canMove(item, newParent))
            continue;

        QModelIndex idx = indexOf(item);
        int newRow = static_cast<int>(children(newParent).count());
        if (!beginMoveRows(idx.parent(), idx.row(), idx.row(), indexOf(newParent), newRow))
            continue;

        // Moving the item last in the list makes it the last child of the new parent
        profile_items_.move(profile_items_.indexOf(item), profile_items_.count() - 1);
        item->setParent(newParent);
        endMoveRows();

        emit dataChanged(indexOf(item, COL_NAME), indexOf(item, columnCount() - 1));
        moved = true;
    }

    return moved;
}

bool ProfileModel::copyTempToProfile(QString tempPath, QString profilePath, bool& wasEmpty)
{
    wasEmpty = true;

    QDir profileDir(profilePath);
    if (! profileDir.mkpath(profilePath) || ! QFile::exists(tempPath))
        return false;

    QDir tempProfile(tempPath);
    tempProfile.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
    QFileInfoList files = tempProfile.entryInfoList();
    if (files.count() <= 0)
        return true; // An empty profile

    int created = 0;
    foreach (QFileInfo finfo, files)
    {
        QString tempFile = finfo.absoluteFilePath();
        QString profileFile = QStringLiteral("%1/%2").arg(profilePath, finfo.fileName());

        if (! profile_files_.contains(finfo.fileName()))
        {
            wasEmpty = false;
            continue;
        }

        if (! QFile::exists(tempFile) || QFile::exists(profileFile))
            continue;

        if (QFile::copy(tempFile, profileFile))
            created++;
    }

    return (created > 0);
}

QFileInfoList ProfileModel::uniquePaths(QFileInfoList lst)
{
    QStringList files;
    QFileInfoList newLst;

    foreach (QFileInfo entry, lst)
    {
        if (! files.contains(entry.absoluteFilePath()))
        {
            if (entry.exists() && entry.isDir())
            {
                newLst << QFileInfo(entry.absoluteFilePath());
                files << entry.absoluteFilePath();
            }
        }
    }

    return newLst;
}

// NOLINTNEXTLINE(misc-no-recursion)
QFileInfoList ProfileModel::filterProfilePath(QString path, QFileInfoList ent, bool fromZip, bool inProfile)
{
    auto hasConfig = [](const QString &dir) {
        QDir fPath(dir);
        fPath.setFilter(QDir::Files | QDir::NoSymLinks);
        foreach (QFileInfo fEntry, fPath.entryInfoList())
        {
            if (config_file_exists_with_entries(fEntry.absoluteFilePath().toUtf8().constData(), '#'))
                return true;
        }
        return false;
    };

    QFileInfoList result = ent;
    QDir temp(path);
    temp.setSorting(QDir::Name);
    temp.setFilter(QDir::Dirs | QDir::NoSymLinks | QDir::NoDotAndDotDot);
    QFileInfoList entries = temp.entryInfoList();
    if (! fromZip)
        entries << QFileInfo(path);

    // Directories in a zip are exported profiles, and sub-folders of a profile
    // are sub-profiles, also when empty
    bool parentIsProfile = fromZip || inProfile || hasConfig(path);
    foreach (QFileInfo entry, entries)
    {
        bool isProfile = parentIsProfile || hasConfig(entry.absoluteFilePath());
        if (isProfile)
            result.append(entry);

        // Look for nested profiles
        if (!filePathsMatch(path, entry.absoluteFilePath()))
            // We recurse here, but our depth is limited
            result.append(filterProfilePath(entry.absoluteFilePath(), QFileInfoList(), fromZip, isProfile));
    }

    return result;
}

QModelIndexList ProfileModel::withChildren(const QModelIndexList &items) const
{
    QModelIndexList result;
    foreach (ProfileItem* candidate, profile_items_)
    {
        for (ProfileItem* p = candidate; p; p = p->parent())
        {
            if (items.contains(indexOf(p)))
            {
                result << indexOf(candidate);
                break;
            }
        }
    }
    return result;
}

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
bool ProfileModel::isExportable(const QModelIndex &idx) const
{
    const ProfileItem* item = itemAt(idx);
    if (!item || item->isGlobal() || item->isDefault() || item->isDeleted() || item->isImport())
        return false;

    // A profile is stored on disk when the changes are applied
    QString path;
    dataPath(idx, path);
    return !path.isEmpty();
}

QList<QPair<QString, QString>> ProfileModel::exportFileList(QModelIndexList items, QString &err)
{
    QList<QPair<QString, QString>> result;
    QStringList seen;
    QMap<QString, QString> sources;

    QList<const ProfileItem*> exported;
    foreach(QModelIndex idx, items)
        exported << itemAt(idx);

    foreach(const ProfileItem* item, exported)
    {
        QModelIndex idx = indexOf(const_cast<ProfileItem*>(item));
        if (!isExportable(idx))
            continue;

        QString path;
        dataPath(idx, path);

        // Parents are not exported unless they are exported themselves, so
        // the names in the archive start at the topmost exported profile
        const ProfileItem* root = item;
        for (const ProfileItem* p = item->parent(); p; p = p->parent())
        {
            if (exported.contains(p))
                root = p;
        }
        QString prefix = root->getName().left(root->getName().length() - root->getLeafName().length());
        QString zipName = item->getName().mid(prefix.length());

        // Profiles with the same name from different parents would overwrite each other
        if (sources.contains(zipName) && sources.value(zipName).compare(path) != 0)
        {
            err = tr("Several profiles named \"%1\" cannot be exported together. Export them separately.").arg(item->getLeafName());
            return QList<QPair<QString, QString>>();
        }
        sources.insert(zipName, path);

        QDir temp(path);
        temp.setSorting(QDir::Name);
        temp.setFilter(QDir::Files | QDir::NoSymLinks | QDir::NoDotAndDotDot);
        QFileInfoList entries = temp.entryInfoList();
        foreach (QFileInfo fi, entries)
        {
            QString name = zipName + "/" + fi.fileName();
            if (!seen.contains(name))
            {
                seen << name;
                result << qMakePair(fi.absoluteFilePath(), name);
            }
        }

        // Export profiles without files as directories, to keep empty sub-profiles
        if (entries.isEmpty() && !seen.contains(zipName))
        {
            seen << zipName;
            result << qMakePair(path, zipName);
        }
    }

    return result;
}

bool ProfileModel::exportProfiles(QString filename, QModelIndexList items, QString& err)
{
    // Write recent file for current profile before exporting
    write_profile_recent();

    QList<QPair<QString, QString>> files = exportFileList(items, err);
    if (files.count() == 0)
    {
        if (err.isEmpty())
            err.append((tr("No profiles found to export")));
        return false;
    }

    if (WiresharkZipHelper::zip(filename, files))
        return true;

    return false;
}

/* This check runs BEFORE the file has been unzipped! */
bool ProfileModel::acceptFile(QString fileName, uint64_t fileSize)
{
    if (fileName.toLower().endsWith(".zip"))
        return false;

    /* Should we skip entries that are just directories? I don't believe
     * we add them to our archive and it may simplify the logic elsewhere. */

    /* Arbitrary maximum config file size accepted: 256MB */
    if (fileSize > 1024 * 1024 * 256)
        return false;

    return true;
}

QString ProfileModel::cleanName(QString fileName)
{
    QStringList parts = fileName.split("/");
    parts[parts.count() - 1].replace(QRegularExpression(QStringLiteral("[%1]").arg(QRegularExpression::escape(illegalCharacters()))), QStringLiteral("_") );
    return parts.join("/");
}

void ProfileModel::importProfilesFromZip(QString filename, int& skippedCnt, QStringList& importList, const QString& targetParent)
{
    QTemporaryDir dir;

    if (dir.isValid())
    {
        WiresharkZipHelper::unzip(filename, dir.path(), &ProfileModel::acceptFile, &ProfileModel::cleanName);
        importProfilesFromDir(dir.path(), skippedCnt, importList, true, targetParent);
    }
}
#endif

void ProfileModel::importProfilesFromDir(QString dirname, int& skippedCnt, QStringList& importList, bool fromZip, const QString& targetParent)
{
    skippedCnt = 0;
    QDir profileDir(gchar_free_to_qstring(get_profiles_dir(application_configuration_environment_prefix())));
    QDir dir(dirname);

    skippedCnt = 0;

    if (dir.exists())
    {
        QFileInfoList entries = uniquePaths(filterProfilePath(dirname, QFileInfoList(), fromZip));

        // Profile names are relative to the import directory, or to its
        // parent if the import directory is a profile itself.
        QDir baseDir(dir);
        foreach (QFileInfo fentry, entries)
        {
            if (filePathsMatch(fentry.absoluteFilePath(), dir.absolutePath()))
            {
                baseDir.cdUp();
                break;
            }
        }

        foreach (QFileInfo fentry, entries)
        {
            QString name = baseDir.relativeFilePath(fentry.absoluteFilePath());
            if (name.length() <= 0 || name.startsWith(".."))
                continue;

            // Import below the selected profile
            if (!targetParent.isEmpty())
                name = targetParent + "/" + name;

            if (name.count('/') >= PROFILE_MAX_DEPTH)
            {
                skippedCnt++;
                continue;
            }

            bool wasEmpty = true;
            bool success = false;

            QString profilePath = QStringLiteral("%1/%2").arg(profileDir.absolutePath(), name);
            QString tempPath = fentry.absoluteFilePath();

            // Renamed, moved and deleted profiles keep their directories until
            // the changes are applied, so the directory of a parent must
            // belong to the profile the imported profile is added to
            bool otherParent = false;
            for (int depth = 0; depth < name.count('/'); depth++)
            {
                QString parent = name.section('/', 0, depth);
                int row = findByNameAndVisibility(parent);
                const ProfileItem* newParent = row < 0 ? Q_NULLPTR : profile_items_[row];
                const ProfileItem* dirOwner = Q_NULLPTR;
                foreach (int ref, findAllByNameAndVisibility(parent, false, true))
                {
                    if (onDisk(profile_items_[ref]) && profile_items_[ref]->getReference().compare(parent) == 0)
                        dirOwner = profile_items_[ref];
                }
                if (dirOwner ? dirOwner != newParent : newParent && onDisk(newParent))
                    otherParent = true;
            }

            if (name.compare(DEFAULT_PROFILE, Qt::CaseInsensitive) == 0 || QFile::exists(profilePath) || otherParent)
            {
                skippedCnt++;
                continue;
            }

            success = copyTempToProfile(tempPath, profilePath, wasEmpty);
            if (success)
            {
                importList << name;

            }
            else if (! wasEmpty && QFile::exists(profilePath))
            {
                QDir dh(profilePath);
                dh.rmdir(profilePath);
            }
        }

    }

    // Now add the successfully imported profiles, parents first
    importList.sort();
    foreach(QString newProfile, importList)
    {
        // Add parent directories created by the import, and restore deleted
        // parents, as the imported profile would be deleted with them
        for (int depth = 0; depth < newProfile.count('/'); depth++)
        {
            QString parent = newProfile.section('/', 0, depth);
            int row = findByNameAndVisibility(parent);
            if (row < 0)
                addNewProfile(parent, parent, false, false, true);
            else
                restoreEntries(QModelIndexList() << indexOf(profile_items_[row]));
        }
        addNewProfile(newProfile, newProfile, false, false, true);
    }
}

QString ProfileModel::illegalCharacters()
{
#ifdef _WIN32
    return QString::fromLatin1(WS_FILENAME_RESERVED_PRINTABLE_CHARS);
#else
    return QDir::separator();
#endif

}

bool ProfileModel::checkNameValidity(QString name, QString& msg)
{
    bool invalid = false;
    QString msgChars;

    QString invalid_dir_chars = illegalCharacters();

    for (int cnt = 0; cnt < invalid_dir_chars.length() && ! invalid; cnt++)
    {
        msgChars += invalid_dir_chars[cnt];
        msgChars += ' ';
        if (name.contains(invalid_dir_chars[cnt]))
            invalid = true;
    }
#ifdef _WIN32
    if (invalid)
    {
        msg = tr("A profile name cannot contain the following characters: %1").arg(msgChars);
    }

    if (msg.isEmpty() && (name.startsWith('.') || name.endsWith('.')) )
        msg = tr("A profile cannot start or end with a period (.)");
#else
    if (invalid)
        msg = tr("A profile name cannot contain the '/' character");
#endif

    return msg.isEmpty();
}

void ProfileModel::applyChanges()
{
    // Clear any existing profile information
    profile_empty_list();

    char *pf_dir_path, *pf_dir_path2, *pf_filename;
    const char* app_env_var_prefix = application_configuration_environment_prefix();
    const char* app_name = application_flavor_name_proper();
    char* err;
    QList<ProfileItem*> deletedProfiles;

    // Rename and move profiles first. A new name may still be in use by a
    // profile that is moved or deleted later, so first move all of them to
    // temporary names, children before parents, and then the renamed ones to
    // the new names, parents before children. The deleted ones are deleted
    // from the temporary names at the end.
    QList<ProfileItem*> renamedProfiles;
    foreach(ProfileItem* profile, profile_items_)
    {
        if (profile->isDeleted() ? onDisk(profile) && !profile->isDefault() :
                                   profile->getStatus() == ProfileItem::StatusType::Changed)
            renamedProfiles << profile;
    }

    auto renameProfile = [&](const QString &from, const QString &to) {
        if (rename_persconffile_profile(app_env_var_prefix, from.toUtf8().constData(), to.toUtf8().constData(),
            &pf_dir_path, &pf_dir_path2) == -1) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't rename directory\n\"%s\" to\n\"%s\":\n%s.",
                pf_dir_path, pf_dir_path2, g_strerror(errno));

            g_free(pf_dir_path);
            g_free(pf_dir_path2);
            return false;
        }

        // Update the references to the moved directories
        foreach(ProfileItem* other, profile_items_)
        {
            QString ref = other->getReference();
            if (!other->isGlobal() && !other->isFromGlobal() && (ref.compare(from) == 0 || ref.startsWith(from + "/")))
                other->setReference(to + ref.mid(from.length()));
        }
        return true;
    };

    std::sort(renamedProfiles.begin(), renamedProfiles.end(), [](const ProfileItem* a, const ProfileItem* b) {
        return a->getReference().count('/') > b->getReference().count('/');
    });
    int tempCnt = 0;
    QList<ProfileItem*> movedProfiles;
    foreach(ProfileItem* profile, renamedProfiles)
    {
        QString temp;
        do {
            temp = QStringLiteral("moving-%1").arg(tempCnt++);
        } while (profile_exists(app_env_var_prefix, temp.toUtf8().constData(), false) ||
                 findByNameAndVisibility(temp, false, true, Qt::CaseInsensitive) >= 0);

        if (renameProfile(profile->getReference(), temp))
            movedProfiles << profile;
    }

    std::sort(movedProfiles.begin(), movedProfiles.end(), [](const ProfileItem* a, const ProfileItem* b) {
        return a->getName().count('/') < b->getName().count('/');
    });
    foreach(ProfileItem* profile, movedProfiles)
    {
        if (!profile->isDeleted())
            renameProfile(profile->getReference(), profile->getName());
    }

    foreach(ProfileItem* profile, profile_items_)
    {
        // Cache the profile information for the (C-like) UI layer
        QByteArray qN = profile->getName().toUtf8();
        const char* profileName = qN.constData();
        QByteArray qR = profile->getReference().toUtf8();
        const char* profileReference = qR.constData();

        // Ignore any profiles slated for deletion
        // They will be handled in the following for loop, so
        // profiles potentially relying on this can do their actions
        if (profile->isDeleted())
        {
            // Only keep the profile if it's the default; we need to
            // do this now to keep it at the front of the list.
            if (profile->isDefault())
                profile_add_profile(profileName, profileReference, false, "");

            deletedProfiles.push_back(profile);
            continue;
        }

        QByteArray qA = profile->getAutoSwitchFilter().toUtf8();
        const char* profileAutoSwitchFilter = qA.constData();
        switch (profile->getStatus())
        {
        case ProfileItem::StatusType::New:
            // Add the profile
            profile_add_profile(profileName, profileReference, false, profileAutoSwitchFilter);

            // We do not create a directory for the default or imported profile
            if (!profile->isDefault() && !profile->isImport())
            {
                if (create_persconffile_profile(app_env_var_prefix, profileName, &pf_dir_path) == -1) {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't create directory\n\"%s\":\n%s.",
                        pf_dir_path, g_strerror(errno));

                    g_free(pf_dir_path);
                }
            }

            // Save auto switch filter if any
            if (profile->getAutoSwitchFilter().length() > 0)
                if (!profile_save_settings(profileName, app_env_var_prefix, app_name, &err))
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
                    g_free(err);
                }

            break;
        case ProfileItem::StatusType::Copy:
            // Add the profile
            profile_add_profile(profileName, profileReference, profile->isFromGlobal(), profileAutoSwitchFilter);

            if (create_persconffile_profile(app_env_var_prefix, profileName, &pf_dir_path) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't create directory\n\"%s\":\n%s.", pf_dir_path, g_strerror(errno));

                g_free(pf_dir_path);
                break;
            }

            if (copy_persconffile_profile(app_env_var_prefix, profileName, profileReference, profile->isFromGlobal(),
                &pf_filename, &pf_dir_path, &pf_dir_path2) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
                    pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

                g_free(pf_filename);
                g_free(pf_dir_path);
                g_free(pf_dir_path2);
            }

            // Save auto switch filter if any
            if (profile->getAutoSwitchFilter().length() > 0)
                if (!profile_save_settings(profileName, app_env_var_prefix, app_name, &err))
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
                    g_free(err);
                }


            break;
        case ProfileItem::StatusType::Existing:

            // Keep the profile
            profile_add_profile(profileName, profileReference, profile->isGlobal(), profileAutoSwitchFilter);

            // Save auto switch filter
            if (profile->isChanged())
                if (!profile_save_settings(profileName, app_env_var_prefix, app_name, &err))
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
                    g_free(err);
                }



            break;
        case ProfileItem::StatusType::Changed:

            // The rename failed above, keep the old name
            profile_add_profile(profileReference, profileReference, profile->isGlobal(), profileAutoSwitchFilter);

            // Save auto switch filter
            if (profile->isChanged())
                if (!profile_save_settings(profileName, app_env_var_prefix, app_name, &err))
                {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
                    g_free(err);
                }


            break;
        }
    }

    // Now, handle any deletions
    foreach(ProfileItem* profile, deletedProfiles)
    {
        // A new name may be in use by another profile, so only delete
        // profiles with a directory, which is at the reference
        if (!onDisk(profile))
            continue;

        QByteArray qR = profile->getReference().toUtf8();
        if (delete_persconffile_profile(app_env_var_prefix, qR.constData(), &pf_dir_path) == -1) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't delete profile directory\n\"%s\":\n%s.",
                pf_dir_path, g_strerror(errno));

            g_free(pf_dir_path);
        }
    }
}
