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
#include <ui/qt/utils/wireshark_zip_helper.h>

#include <QApplication>
#include <QDir>
#include <QFont>
#include <QTemporaryDir>
#include <QRegularExpression>

Q_LOGGING_CATEGORY(profileLogger, "wireshark.profiles")


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
    return (name_.compare(DEFAULT_PROFILE) == 0);
}

QString ProfileItem::getProfilePath(QString profileName) const
{
    QString profile_path;
    if (isGlobal()) {
        profile_path = gchar_free_to_qstring(get_global_profiles_dir(application_configuration_environment_prefix()));
    }
    else {
        profile_path = gchar_free_to_qstring(get_profiles_dir(application_configuration_environment_prefix()));
    }
    if (profileName.isEmpty())
        profileName = getName();

    profile_path.append("/").append(profileName);
    return QDir::toNativeSeparators(profile_path);
}

void ProfileItem::setName(QString value)
{
    name_ = value;
    setForDeletion_ = false;

    if ((status_ == StatusType::Existing) &&
        (name_.compare(reference_) != 0))
        status_ = StatusType::Changed;

    if ((status_ == StatusType::Changed) &&
        (name_.compare(reference_) == 0))
        status_ = StatusType::Existing;
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
{}

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

bool ProfileSortModel::filterAcceptsRow(int source_row, const QModelIndex &) const
{
    bool accept = true;
    QModelIndex idx = sourceModel()->index(source_row, ProfileModel::COL_NAME);

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
        QString name = idx.data().toString();
        if (! name.contains(ftext_, Qt::CaseInsensitive))
            accept = false;
    }

    return accept;
}

ProfileModel::ProfileModel(QObject * parent) :
    QAbstractTableModel(parent)
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

        ProfileItem* item = new ProfileItem(profile);
        profile_items_ << item;

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

int ProfileModel::rowCount(const QModelIndex &) const
{
    return static_cast<int>(profile_items_.count());
}

int ProfileModel::columnCount(const QModelIndex &) const
{
    return static_cast<int>(_LAST_ENTRY);
}

QVariant ProfileModel::dataDisplay(const QModelIndex &index) const
{
    ProfileItem* item = profile_items_[index.row()];

    switch (index.column())
    {
    case COL_NAME:
        return item->getName();
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
    ProfileItem* item = profile_items_[index.row()];

    QFont font;

    if (item->isGlobal())
        font.setItalic(true);
    else if ((current_profile_ != Q_NULLPTR) && (current_profile_->getName().compare(item->getName()) == 0))
        font.setBold(true);

    if (item->isDeleted())
        font.setStrikeOut(true);

    return font;
}

bool ProfileModel::isDataValid(QString& err)
{
    err.clear();
    foreach(ProfileItem* item, profile_items_)
    {
        // If the profile is slated for deletion, don't care about valid data
        if (item->isDeleted())
            continue;

        if (!checkNameValidity(item->getName(), err))
            return false;

        foreach(ProfileItem* dup_item, profile_items_)
        {
            // Skip same profiles
            if (item == dup_item)
                continue;

            // Ensure matching "scope"
            if (item->isGlobal() == dup_item->isGlobal())
            {
                // Can't have multiple matching personal profile names or
                // renaming a profile to an existing profile's name.
                if ((item->getName().compare(dup_item->getName()) == 0) ||
                    (item->getStatus() == ProfileItem::StatusType::Changed && item->getReference().compare(dup_item->getName()) == 0) ||
                    (dup_item->getStatus() == ProfileItem::StatusType::Changed && item->getName().compare(dup_item->getReference()) == 0))
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
    ProfileItem* item = profile_items_[index.row()];
    if (!isOriginalToDuplicate && (item->getStatus() == ProfileItem::StatusType::Existing))
        return false;

    for (int cnt = 0; cnt < rowCount(); cnt++)
    {
        if (cnt == index.row())
            continue;

        ProfileItem* dupItem = profile_items_[cnt];

        // Ensure matching "scope"
        if (item->isGlobal() == dupItem->isGlobal())
        {
            if ((item->getName().compare(dupItem->getName()) == 0) ||
                (item->getStatus() == ProfileItem::StatusType::Changed && item->getReference().compare(dupItem->getName()) == 0))
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
            else if (dupItem->getStatus() == ProfileItem::StatusType::Changed && item->getName().compare(dupItem->getReference()) == 0)
            {
                return true;
            }
        }
    }

    return false;
}

QVariant ProfileModel::dataBackgroundRole(const QModelIndex &index) const
{
    ProfileItem* item = profile_items_[index.row()];

    if (item->isDeleted())
        return ThemeManager::instance()->color(ThemeManager::PacketsInactive);

    if (!item->isDefault() && !item->isGlobal())
    {
        /* Highlights erroneous line */
        QString ignore;
        if (item->isDeleted() || checkDuplicate(index) || !checkNameValidity(item->getName(), ignore))
            return ThemeManager::instance()->color(ThemeManager::FilterInvalid);

        /* Highlights line, which has been duplicated by another index */
        if (checkDuplicate(index, true))
            return ThemeManager::instance()->color(ThemeManager::FilterValid);
    }

    return QVariant();
}

QVariant ProfileModel::dataForegroundRole(const QModelIndex &index) const
{
    ProfileItem* item = profile_items_[index.row()];

    if (item->isDeleted())
        return QApplication::palette().color(QPalette::Disabled, QPalette::Text);

    if (item->isGlobal() && index.column() == COL_AUTO_SWITCH_FILTER) {
        return ColorUtils::disabledForeground();
    }

    return QVariant();
}

QVariant ProfileModel::dataToolTipRole(const QModelIndex& index) const
{
    ProfileItem* item = profile_items_[index.row()];

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

    ProfileItem* item = profile_items_[index.row()];

    if (checkDuplicate(index))
    {
        // See if one is being renamed to an already existing name.
        for (int dup = 0; dup < profile_items_.count(); dup++)
        {
            if (dup == index.row())
                continue;

            ProfileItem* dup_item = profile_items_[dup];
            if (dup_item && dup_item->getReference().compare(item->getName()) == 0)
                return tr("A profile change for this name is pending (See: %1)").arg(dup_item->getName());
        }

        return tr("A profile already exists with this name");
    }

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

    if (item->isImport())
        return tr("Imported profile");

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

            if (! checkNameValidity(item->getName(), errMsg))
                return errMsg;

            return tr("Created from default settings");
        }
    case ProfileItem::StatusType::Changed:
        {
            QString msg;
            if (!checkNameValidity(item->getName(), msg))
                return msg;

            if (item->getReference().compare(item->getName()))
            {
                profilePath = item->getProfilePath(item->getReference());
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
                int row = findByNameAndVisibility(item->getReference(), false, true);
                if (row >= 0)
                    refItem = profile_items_[row];

                /* The reference is itself a copy of the original, therefore it is not accepted */
                if ((refItem->getStatus() == ProfileItem::StatusType::Copy || refItem->getStatus() == ProfileItem::StatusType::New) && refItem->getName().compare(item->getReference()) != 0)
                    refItem = Q_NULLPTR;

                /* found no other profile, original one had to be deleted */
                if (!refItem || row == index.row() || (refItem->isDeleted()))
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

    ProfileItem* item = profile_items_[index.row()];

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
        return Qt::ItemFlags();

    ProfileItem* item = profile_items_[index.row()];

    Qt::ItemFlags fl = QAbstractTableModel::flags(index);

    switch(index.column())
    {
    case COL_NAME:
        if (!item->isDefault())
            fl |= Qt::ItemIsEditable;
        break;
    case COL_AUTO_SWITCH_FILTER:
        fl |= Qt::ItemIsEditable;
        break;
    }

    return fl;
}

int ProfileModel::findByName(const QString& name)
{
    int row = findByNameAndVisibility(name, false);
    if (row < 0)
        row = findByNameAndVisibility(name, true);

    return row;
}

const ProfileItem* ProfileModel::getPersonalProfile(const QString& name)
{
    int row = findByNameAndVisibility(name, false);
    if (row < 0)
        return Q_NULLPTR;

    return profile_items_[row];
}


int ProfileModel::findByNameAndVisibility(const QString& name, bool isGlobal, bool searchReference) const
{
    QList<int> result = findAllByNameAndVisibility(name, isGlobal, searchReference);
    return result.count() == 0 ? -1 : result.at(0);
}

QList<int> ProfileModel::findAllByNameAndVisibility(const QString& name, bool isGlobal, bool searchReference) const
{
    QList<int> result;

    for (int cnt = 0; cnt < profile_items_.count(); cnt++)
    {
        ProfileItem* item = profile_items_[cnt];
        if (item->isGlobal() == isGlobal)
        {
            if (name.compare(item->getName()) == 0 || (searchReference && name.compare(item->getReference()) == 0))
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
    while (findByNameAndVisibility(newName) >= 0)
    {
        newName = QStringLiteral("%1 %2").arg(name, QString::number(cnt));
        cnt++;
    }

    int row = static_cast<int>(profile_items_.count());
    beginInsertRows(QModelIndex(), row, row);


    ProfileItem* item = new ProfileItem(newName, reference, ProfileItem::StatusType::New, isGlobal, fromGlobal, isImport);
    profile_items_ << item;

    endInsertRows();

    return index(row, COL_NAME);
}


// NOLINTNEXTLINE(misc-no-recursion)
QModelIndex ProfileModel::duplicateEntry(QModelIndex idx, ProfileItem::StatusType new_status)
{
    if (!idx.isValid())
        return QModelIndex();

    ProfileItem* item = profile_items_[idx.row()];

    /* this is a copy from a personal profile, check if the original has been a
     * new profile or a preexisting one. In the case of a new profile, restart
     * with the state PROF_STAT_NEW */
    if (item->getStatus() == ProfileItem::StatusType::Copy && !item->isGlobal())
    {
        int row = findByNameAndVisibility(item->getReference(), false);
        ProfileItem* copyItem = profile_items_[row];
        if (copyItem && copyItem->getStatus() == ProfileItem::StatusType::New)
        {
            // We recurse here, but our depth is limited
            return duplicateEntry(index(row, ProfileModel::COL_NAME), ProfileItem::StatusType::New);
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

    /* check to ensure we do not end up with (copy) (copy) (copy) ... */
    QRegularExpression rx("\\s+(\\(\\s*" + tr("copy", "noun") + "\\s*\\d*\\))");
    parentName.replace(rx, "");

    QString new_name;
    /* if copy is global and name has not been used before, use that, else create first copy */
    if (item->isGlobal() && findByNameAndVisibility(parentName) < 0)
        new_name = QString(item->getName());
    else
        new_name = QStringLiteral("%1 (%2)").arg(parentName, tr("copy", "noun"));

    /* check if copy already exists and iterate, until an unused version is found */
    int cnt = 1;
    while (findByNameAndVisibility(new_name) >= 0)
    {
        new_name = QStringLiteral("%1 (%2 %3)").arg(parentName, tr("copy", "noun"), QString::number(cnt));
        cnt++;
    }

    /* if this would be a copy, but the original is already a new one, this is a copy as well */
    if (new_status == ProfileItem::StatusType::Copy && item->getStatus() == ProfileItem::StatusType::New)
        new_status = ProfileItem::StatusType::New;

    int row = static_cast<int>(profile_items_.count());
    beginInsertRows(QModelIndex(), row, row);

    ProfileItem* newItem = new ProfileItem(new_name, parent, new_status, false, item->isFromGlobal() ? true : item->isGlobal(), item->isImport());
    profile_items_ << newItem;

    endInsertRows();

    /* return the index of the profile */
    return index(row, COL_NAME);
}

void ProfileModel::deleteEntries(QModelIndexList idcs)
{
    if (idcs.count() == 0)
        return;

    QList<int> indeces;
    foreach (QModelIndex idx, idcs)
    {
        // Remove any global profiles from the list
        if (! indeces.contains(idx.row()) && ! idx.data(ProfileModel::DATA_IS_GLOBAL).toBool())
            indeces << idx.row();
    }

    // Security blanket. This ensures, that we start deleting from the end and do not get any issues iterating the list
    std::sort(indeces.begin(), indeces.end(), std::greater<int>());

    int start = indeces.last();
    int end = indeces.first();
    foreach (int row, indeces)
    {
        ProfileItem* item = profile_items_[row];
        if (item->isDefault())
        {
            item->setForDeletion();
        }
        else
        {
            switch (item->getStatus())
            {
            case ProfileItem::StatusType::New:
            case ProfileItem::StatusType::Copy:
            {
                beginRemoveRows(QModelIndex(), start, end);

                // If it was just created, remove it
                delete profile_items_.takeAt(row);
                endRemoveRows();
                break;
            }
            default:
            {
                bool foundDuplicate = false;

                // Check if there is a new duplicate of this profile, so that one can be removed instead of the original one
                for (int duprow = 0; duprow < rowCount(); duprow++)
                {
                    if (duprow == row)
                        continue;

                    ProfileItem* dupItem = profile_items_[duprow];
                    if ((dupItem->getName().compare(item->getName()) == 0) && (dupItem->isGlobal() == item->isGlobal()))
                    {
                        if (dupItem->getStatus() != ProfileItem::StatusType::Existing)
                        {
                            foundDuplicate = true;
                            beginRemoveRows(QModelIndex(), start, end);
                            // If there is a duplicate, remove it
                            delete profile_items_.takeAt(duprow);
                            endRemoveRows();
                            break;
                        }
                    }
                }

                // Mark it for deletion
                if (!foundDuplicate)
                    item->setForDeletion();
                break;
            }
            }

        }
    }

    emit dataChanged(index(start, COL_NAME), index(end, COL_NAME));
}

bool ProfileModel::restoreEntries(QModelIndexList idcs)
{
    bool restored = false;
    foreach(QModelIndex idx, idcs)
    {
        ProfileItem* item = profile_items_[idx.row()];
        if (item->isDeleted())
        {
            // Reset the profile status
            item->setName(item->getName());
            emit dataChanged(index(idx.row(), ProfileModel::COL_NAME), index(idx.row(), columnCount()));
            restored = true;
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
        if (item->isGlobal() || checkDuplicate(index(row, ProfileModel::COL_NAME)))
            return QModelIndex();

        if ((current_profile_->getName().compare(item->getName()) == 0 && (item->getStatus() == ProfileItem::StatusType::Existing || item->isDefault())) ||
            (current_profile_->getName().compare(item->getReference()) == 0 && item->getStatus() == ProfileItem::StatusType::Changed))
            return index(row, ProfileModel::COL_NAME);
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

    ProfileItem* item = profile_items_[cur_index.row()];

    switch (cur_index.column())
    {
    case COL_NAME:
        if (value.toString().isEmpty())
            return false;

        if (!item->isDefault())
        {
            item->setName(value.toString());
            emit dataChanged(index(0, COL_NAME),
                                   index(rowCount()-1, COL_NAME));
        }
        break;
    case COL_AUTO_SWITCH_FILTER:
        item->setAutoSwitchFilter(value.toString());
        emit dataChanged(index(cur_index.row(), COL_AUTO_SWITCH_FILTER),
                         index(cur_index.row(), COL_AUTO_SWITCH_FILTER));
        break;
    }

    return true;
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
        return false;

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
QFileInfoList ProfileModel::filterProfilePath(QString path, QFileInfoList ent, bool fromZip)
{
    QFileInfoList result = ent;
    QDir temp(path);
    temp.setSorting(QDir::Name);
    temp.setFilter(QDir::Dirs | QDir::NoSymLinks | QDir::NoDotAndDotDot);
    QFileInfoList entries = temp.entryInfoList();
    if (! fromZip)
        entries << QFileInfo(path);
    foreach (QFileInfo entry, entries)
    {
        QDir fPath(entry.absoluteFilePath());
        fPath.setSorting(QDir::Name);
        fPath.setFilter(QDir::Files | QDir::NoSymLinks);
        QFileInfoList fEntries = fPath.entryInfoList();
        bool found = false;
        for (int cnt = 0; cnt < fEntries.count() && ! found; cnt++)
        {
            if (config_file_exists_with_entries(fEntries[cnt].absoluteFilePath().toUtf8().constData(), '#'))
                 found = true;
        }

        if (found)
        {
            result.append(entry);
        }
        else
        {
            if (!filePathsMatch(path, entry.absoluteFilePath()))
                // We recurse here, but our depth is limited
                result.append(filterProfilePath(entry.absoluteFilePath(), result, fromZip));
        }
    }

    return result;
}

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
QStringList ProfileModel::exportFileList(QModelIndexList items)
{
    QStringList result;

    foreach(QModelIndex idx, items)
    {
        ProfileItem* item = profile_items_[idx.row()];
        if (item->isGlobal() || item->isDefault() ||
            item->isDeleted() ||
            item->isImport())
            continue;

        QString ignoreProfile;
        QString path = dataPath(idx, ignoreProfile).toString();

        QDir temp(path);
        temp.setSorting(QDir::Name);
        temp.setFilter(QDir::Files | QDir::NoSymLinks | QDir::NoDotAndDotDot);
        QFileInfoList entries = temp.entryInfoList();
        foreach (QFileInfo fi, entries)
            result << fi.absoluteFilePath();
    }

    return result;
}

bool ProfileModel::exportProfiles(QString filename, QModelIndexList items, QString& err)
{
    // Write recent file for current profile before exporting
    write_profile_recent();

    QStringList files = exportFileList(items);
    if (files.count() == 0)
    {
        err.append((tr("No profiles found to export")));
        return false;
    }

    if (WiresharkZipHelper::zip(filename, files, gchar_free_to_qstring(get_profiles_dir(application_configuration_environment_prefix())) + "/") )
        return true;

    return false;
}

/* This check runs BEFORE the file has been unzipped! */
bool ProfileModel::acceptFile(QString fileName, int fileSize)
{
    if (fileName.toLower().endsWith(".zip"))
        return false;

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

void ProfileModel::importProfilesFromZip(QString filename, int& skippedCnt, QStringList& importList)
{
    QTemporaryDir dir;

    if (dir.isValid())
    {
        WiresharkZipHelper::unzip(filename, dir.path(), &ProfileModel::acceptFile, &ProfileModel::cleanName);
        importProfilesFromDir(dir.path(), skippedCnt, importList, true);
    }
}
#endif

void ProfileModel::importProfilesFromDir(QString dirname, int& skippedCnt, QStringList& importList, bool fromZip)
{
    skippedCnt = 0;
    QDir profileDir(gchar_free_to_qstring(get_profiles_dir(application_configuration_environment_prefix())));
    QDir dir(dirname);

    skippedCnt = 0;

    if (dir.exists())
    {
        QFileInfoList entries = uniquePaths(filterProfilePath(dirname, QFileInfoList(), fromZip));

        foreach (QFileInfo fentry, entries)
        {
            if (fentry.fileName().length() <= 0)
                continue;

            bool wasEmpty = true;
            bool success = false;

            QString profilePath = QStringLiteral("%1/%2").arg(profileDir.absolutePath(), fentry.fileName());
            QString tempPath = fentry.absoluteFilePath();

            if (fentry.fileName().compare(DEFAULT_PROFILE, Qt::CaseInsensitive) == 0 || QFile::exists(profilePath))
            {
                skippedCnt++;
                continue;
            }

            success = copyTempToProfile(tempPath, profilePath, wasEmpty);
            if (success)
            {
                importList << fentry.fileName();

            }
            else if (! wasEmpty && QFile::exists(profilePath))
            {
                QDir dh(profilePath);
                dh.rmdir(profilePath);
            }
        }

    }

    // Now add the successfully imported profiles
    foreach(QString newProfile, importList)
        addNewProfile(newProfile, newProfile, false, false, true);
}

QString ProfileModel::illegalCharacters()
{
#ifdef _WIN32
    /* According to https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions */
    return QStringLiteral("<>:\"/\\|?*");
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

            // Add the profile with the new name
            profile_add_profile(profileReference, profileReference, profile->isGlobal(), profileAutoSwitchFilter);

            // Rename old profile directory to new
            if (rename_persconffile_profile(app_env_var_prefix, profileReference, profileName,
                &pf_dir_path, &pf_dir_path2) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't rename directory\n\"%s\" to\n\"%s\":\n%s.",
                    pf_dir_path, pf_dir_path2, g_strerror(errno));

                g_free(pf_dir_path);
                g_free(pf_dir_path2);
            }

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
        QByteArray qN = profile->getName().toUtf8();
        const char* profileName = qN.constData();
        QByteArray qR = profile->getReference().toUtf8();
        const char* profileReference = qR.constData();

        // If it has been renamed, remove the original name
        if (profile->getStatus() == ProfileItem::StatusType::Changed)
            profileName = profileReference;

        if (delete_persconffile_profile(app_env_var_prefix, profileName, &pf_dir_path) == -1) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't delete profile directory\n\"%s\":\n%s.",
                pf_dir_path, g_strerror(errno));

            g_free(pf_dir_path);
        }
    }
}
