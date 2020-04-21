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

#include "glib.h"
#include "ui/profile.h"
#include "ui/recent.h"
#include "wsutil/filesystem.h"
#include "epan/prefs.h"

#include <ui/qt/models/profile_model.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/wireshark_zip_helper.h>

#include <QDir>
#include <QFont>
#include <QTemporaryDir>

Q_LOGGING_CATEGORY(profileLogger, "wireshark.profiles")

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

    if (left.data(ProfileModel::DATA_STATUS).toInt() == PROF_STAT_DEFAULT)
        igL = true;
    if (right.data(ProfileModel::DATA_STATUS).toInt() == PROF_STAT_DEFAULT)
        igR = true;

    if (igL && ! igR)
        return true;
    else if (! igL && igR)
        return false;
    else if (igL && igR)
    {
        if (left.data(ProfileModel::DATA_STATUS) == PROF_STAT_DEFAULT)
            return true;
    }

    if (left.data().toString().compare(right.data().toString()) <= 0)
        return true;

    return false;
}

void ProfileSortModel::setFilterType(FilterType ft)
{
    ft_ = ft;
    invalidateFilter();
}

void ProfileSortModel::setFilterString(QString txt)
{
    ftext_ = ! txt.isEmpty() ? txt : "";
    invalidateFilter();
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
    /* Store preset profile name */
    set_profile_ = get_profile_name();

    reset_default_ = false;
    profiles_imported_ = false;

    last_set_row_ = 0;

    /* Set filenames for profiles */
    GList *files, *file;
    files = g_hash_table_get_keys(const_cast<GHashTable *>(allowed_profile_filenames()));
    file = g_list_first(files);
    while (file) {
        profile_files_ << static_cast<char *>(file->data);
        file = gxx_list_next(file);
    }
    g_list_free(files);

    loadProfiles();
}

void ProfileModel::loadProfiles()
{
    emit beginResetModel();

    bool refresh = profiles_.count() > 0;

     if (refresh)
         profiles_.clear();
     else
         init_profile_list();

    GList *fl_entry = edited_profile_list();
    while (fl_entry && fl_entry->data)
    {
        profiles_ << reinterpret_cast<profile_def *>(fl_entry->data);
        fl_entry = gxx_list_next(fl_entry);
    }

    emit endResetModel();
}

GList * ProfileModel::entry(profile_def *ref) const
{
    GList *fl_entry = edited_profile_list();
    while (fl_entry && fl_entry->data)
    {
        profile_def *profile = reinterpret_cast<profile_def *>(fl_entry->data);
        if (QString(ref->name).compare(profile->name) == 0 &&
             QString(ref->reference).compare(profile->reference) == 0 &&
             ref->is_global == profile->is_global &&
             ref->status == profile->status)
        {
            return fl_entry;
        }

        fl_entry = gxx_list_next(fl_entry);
    }

    return Q_NULLPTR;
}

GList *ProfileModel::at(int row) const
{
    if (row < 0 || row >= profiles_.count())
        return Q_NULLPTR;

    profile_def * prof = profiles_.at(row);
    return entry(prof);
}

bool ProfileModel::changesPending() const
{
    if (reset_default_)
        return true;

    if (g_list_length(edited_profile_list()) != g_list_length(current_profile_list()))
        return true;

    bool pending = false;
    GList *fl_entry = edited_profile_list();
    while (fl_entry && fl_entry->data && ! pending) {
        profile_def *profile = reinterpret_cast<profile_def *>(fl_entry->data);
        pending = (profile->status == PROF_STAT_NEW || profile->status == PROF_STAT_CHANGED || profile->status == PROF_STAT_COPY);
        fl_entry = gxx_list_next(fl_entry);
    }

    return pending;
}

bool ProfileModel::importPending() const
{
    return profiles_imported_;
}

bool ProfileModel::userProfilesExist() const
{
    bool user_exists = false;
    for (int cnt = 0; cnt < rowCount() && ! user_exists; cnt++)
    {
        QModelIndex idx = index(cnt, ProfileModel::COL_NAME);
        if (! idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() && ! idx.data(ProfileModel::DATA_IS_DEFAULT).toBool())
            user_exists = true;
    }

    return user_exists;
}

int ProfileModel::rowCount(const QModelIndex &) const
{
    return profiles_.count();
}

int ProfileModel::columnCount(const QModelIndex &) const
{
    return static_cast<int>(_LAST_ENTRY);
}

profile_def * ProfileModel::guard(const QModelIndex &index) const
{
    if (! index.isValid())
        return Q_NULLPTR;

    return guard(index.row());
}

profile_def * ProfileModel::guard(int row) const
{
    if (row < 0 || profiles_.count() <= row)
        return Q_NULLPTR;

    if (! edited_profile_list())
    {
        static_cast<QList<profile_def *>>(profiles_).clear();
        return Q_NULLPTR;
    }

    return profiles_.value(row, Q_NULLPTR);
}

QVariant ProfileModel::dataDisplay(const QModelIndex &index) const
{
    profile_def * prof = guard(index);
    if (! prof)
        return QVariant();

    switch (index.column())
    {
    case COL_NAME:
        return QString(prof->name);
    case COL_TYPE:
        if (prof->status == PROF_STAT_DEFAULT)
            return tr("Default");
        else if (prof->is_global)
            return tr("Global");
        else
            return tr("Personal");
    default:
        break;
    }

    return QVariant();
}

QVariant ProfileModel::dataFontRole(const QModelIndex &index) const
{
    if (! index.isValid() || profiles_.count() <= index.row())
        return QVariant();

    profile_def * prof = guard(index.row());
    if (! prof)
        return QVariant();

    QFont font;

    if (prof->is_global)
        font.setItalic(true);

    if (! prof->is_global && ! checkDuplicate(index))
    {
        if ((set_profile_.compare(prof->name) == 0 &&  prof->status == PROF_STAT_EXISTS) ||
             (set_profile_.compare(prof->reference) == 0 &&  prof->status == PROF_STAT_CHANGED) )
            font.setBold(true);
    }

    if (prof->status == PROF_STAT_DEFAULT && reset_default_)
        font.setStrikeOut(true);

    return font;
}

bool ProfileModel::checkIfDeleted(int row) const
{
    QModelIndex idx = index(row, ProfileModel::COL_NAME);
    return checkIfDeleted(idx);
}

bool ProfileModel::checkIfDeleted(const QModelIndex &index) const
{
    profile_def * prof = guard(index);
    if (! prof)
        return false;

    QStringList deletedNames;

    GList * current = current_profile_list();

    /* search the current list as long as we have not found anything */
    while (current)
    {
        bool found = false;
        GList * edited = edited_profile_list();
        profile_def * profcurr = static_cast<profile_def *>(current->data);

        if (! profcurr->is_global && profcurr->status != PROF_STAT_DEFAULT)
        {
            while (edited && ! found)
            {
                profile_def * profed = static_cast<profile_def *>(edited->data);
                if (! profed->is_global && profed->status != PROF_STAT_DEFAULT)
                {
                    if (g_strcmp0(profcurr->name, profed->name) == 0 || g_strcmp0(profcurr->name, profed->reference) == 0)
                    {
                        if (profed->status == profcurr->status && prof->status != PROF_STAT_NEW && prof->status != PROF_STAT_COPY)
                            found = true;
                    }
                }

                edited = gxx_list_next(edited);
            }

            /* profile has been deleted, check if it has the name we ask for */
            if (! found)
                deletedNames << profcurr->name;
        }

        if (profcurr->is_global && deletedNames.contains(profcurr->name))
            deletedNames.removeAll(profcurr->name);

        current = gxx_list_next(current);
    }

    if (deletedNames.contains(prof->name))
        return true;

    return false;
}

bool ProfileModel::checkInvalid(const QModelIndex &index) const
{
    profile_def * prof = guard(index);
    if (! prof)
        return false;

    int ref = this->findAsReference(prof->name);
    if (ref == index.row())
        return false;

    profile_def * pg = guard(ref);
    if (pg && pg->status == PROF_STAT_CHANGED && g_strcmp0(pg->name, pg->reference) != 0 && ! prof->is_global)
        return true;

    return false;
}

bool ProfileModel::checkDuplicate(const QModelIndex &index, bool isOriginalToDuplicate) const
{
    profile_def * prof = guard(index);
    if (! prof || (! isOriginalToDuplicate && prof->status == PROF_STAT_EXISTS) )
        return false;

    QList<int> rows = this->findAllByNameAndVisibility(prof->name, prof->is_global, false);
    int found = 0;
    profile_def * check = Q_NULLPTR;
    for (int cnt = 0; cnt < rows.count(); cnt++)
    {
        int row = rows.at(cnt);

        if (row == index.row())
            continue;

        check = guard(row);
        if (! check || (isOriginalToDuplicate && check->status == PROF_STAT_EXISTS) )
            continue;

        found++;
    }

    if (found > 0)
        return true;
    return false;
}

QVariant ProfileModel::dataBackgroundRole(const QModelIndex &index) const
{
    if (! index.isValid() || profiles_.count() <= index.row())
        return QVariant();

    profile_def * prof = guard(index.row());
    if (! prof)
        return QVariant();

    if (prof->status == PROF_STAT_DEFAULT && reset_default_)
        return ColorUtils::fromColorT(&prefs.gui_text_deprecated);

    if (prof->status != PROF_STAT_DEFAULT && ! prof->is_global)
    {
        /* Highlights errorneous line */
        if (checkInvalid(index) || checkIfDeleted(index) || checkDuplicate(index) || ! checkNameValidity(prof->name))
            return ColorUtils::fromColorT(&prefs.gui_text_invalid);

        /* Highlights line, which has been duplicated by another index */
        if (checkDuplicate(index, true))
            return ColorUtils::fromColorT(&prefs.gui_text_valid);
    }

    return QVariant();
}

QVariant ProfileModel::dataToolTipRole(const QModelIndex &idx) const
{
    if (! idx.isValid() || profiles_.count() <= idx.row())
        return QVariant();

    profile_def * prof = guard(idx.row());
    if (! prof)
        return QVariant();

    if (prof->is_global)
        return tr("This is a system provided profile");
    else
        return dataPath(idx);
}

QVariant ProfileModel::dataPath(const QModelIndex &index) const
{
    if (! index.isValid() || profiles_.count() <= index.row())
        return QVariant();

    profile_def * prof = guard(index.row());
    if (! prof)
        return QVariant();

    if (checkInvalid(index))
    {
        int ref = this->findAsReference(prof->name);
        if (ref != index.row() && ref >= 0)
        {
            profile_def * prof = guard(ref);
            QString msg = tr("A profile change for this name is pending");
            if (prof)
                msg.append(tr(" (See: %1)").arg(prof->name));
            return msg;
        }

        return tr("This is an invalid profile definition");
    }

    if ((prof->status == PROF_STAT_NEW || prof->status == PROF_STAT_CHANGED || prof->status == PROF_STAT_COPY) && checkDuplicate(index))
        return tr("A profile already exists with this name");

    if (checkIfDeleted(index))
    {
        return tr("A profile with this name is being deleted");
    }

    if (prof->is_import)
        return tr("Imported profile");

    switch (prof->status)
    {
    case PROF_STAT_DEFAULT:
        if (!reset_default_)
            return gchar_free_to_qstring(get_persconffile_path("", FALSE));
        else
            return tr("Resetting to default");
    case PROF_STAT_EXISTS:
        {
            QString profile_path;
            if (prof->is_global) {
                profile_path = gchar_free_to_qstring(get_global_profiles_dir());
            } else {
                profile_path = gchar_free_to_qstring(get_profiles_dir());
            }
            profile_path.append("/").append(prof->name);
            return profile_path;
        }
    case PROF_STAT_NEW:
        {
            QString errMsg;

            if (! checkNameValidity(prof->name, &errMsg))
                return errMsg;
            else
                return tr("Created from default settings");
        }
    case PROF_STAT_CHANGED:
        {
            QString msg;
            if (! ProfileModel::checkNameValidity(QString(prof->name), &msg))
                return msg;

            if (prof->reference)
                return tr("Renamed from: %1").arg(prof->reference);

            return QVariant();
        }
    case PROF_STAT_COPY:
        {
            QString msg;

            /* this should always be the case, but just as a precaution it is checked */
            if (prof->reference)
            {
                msg = tr("Copied from: %1").arg(prof->reference);
                QString appendix;

                /* A global profile is neither deleted or removed, only system provided is allowed as appendix */
                if (profile_exists(prof->reference, TRUE) && prof->from_global)
                    appendix = tr("system provided");
                /* A default model as reference can neither be deleted or renamed, so skip if the reference was one */
                else  if (! index.data(ProfileModel::DATA_IS_DEFAULT).toBool())
                {
                    /* find a non-global, non-default profile which could be referenced by this one. Those are the only
                     * ones which could be renamed or deleted */
                    int row = this->findByNameAndVisibility(prof->reference, false, true);
                    profile_def * ref = guard(row);

                    /* The reference is itself a copy of the original, therefore it is not accepted */
                    if (ref && (ref->status == PROF_STAT_COPY || ref->status == PROF_STAT_NEW) && QString(ref->name).compare(prof->reference) != 0)
                        ref = Q_NULLPTR;

                    /* found no other profile, original one had to be deleted */
                    if (! ref || row == index.row() || checkIfDeleted(row))
                    {
                        appendix = tr("deleted");
                    }
                    /* found another profile, so the reference had been renamed, it the status is changed */
                    else if (ref && ref->status == PROF_STAT_CHANGED)
                    {
                        appendix = tr("renamed to %1").arg(ref->name);
                    }
                }

                if (appendix.length() > 0)
                    msg.append(QString(" (%1)").arg(appendix));
            }

            return msg;
        }
    }

    return QVariant();
}

QVariant ProfileModel::data(const QModelIndex &index, int role) const
{
    profile_def * prof = guard(index);
    if (! prof)
        return QVariant();

    switch (role)
    {
    case Qt::DisplayRole:
        return dataDisplay(index);
    case Qt::FontRole:
        return dataFontRole(index);
    case Qt::BackgroundRole:
        return dataBackgroundRole(index);
    case Qt::ToolTipRole:
        return dataToolTipRole(index);
    case ProfileModel::DATA_STATUS:
        return QVariant::fromValue(prof->status);
    case ProfileModel::DATA_IS_DEFAULT:
        return QVariant::fromValue(prof->status == PROF_STAT_DEFAULT);
    case ProfileModel::DATA_IS_GLOBAL:
        return QVariant::fromValue(prof->is_global);
    case ProfileModel::DATA_IS_SELECTED:
        {
            QModelIndex selected = activeProfile();
            profile_def * selprof = guard(selected);
            if (selprof)
            {
                if (selprof && selprof->is_global != prof->is_global)
                    return QVariant::fromValue(false);

                if (selprof && strcmp(selprof->name, prof->name) == 0)
                    return QVariant::fromValue(true);
            }
            return QVariant::fromValue(false);
        }
    case ProfileModel::DATA_PATH:
        return dataPath(index);
    case ProfileModel::DATA_INDEX_VALUE_IS_URL:
        if (index.column() <= ProfileModel::COL_TYPE)
            return QVariant::fromValue(false);
        return QVariant::fromValue(true);
    case ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION:
        if (prof->status == PROF_STAT_NEW || prof->status == PROF_STAT_COPY
             || (prof->status == PROF_STAT_DEFAULT && reset_default_)
             || prof->status == PROF_STAT_CHANGED || prof->is_import)
            return QVariant::fromValue(false);
        else
            return QVariant::fromValue(true);

    default:
        break;
    }

    return QVariant();
}

QVariant ProfileModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
    {
        switch (section)
        {
        case COL_NAME:
            return tr("Profile");
        case COL_TYPE:
            return tr("Type");
        default:
            break;
        }
    }

    return QVariant();
}

Qt::ItemFlags ProfileModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags fl = QAbstractTableModel::flags(index);

    profile_def * prof = guard(index);
    if (! prof)
        return fl;

    if (index.column() == ProfileModel::COL_NAME && prof->status != PROF_STAT_DEFAULT  && ! prof->is_global)
        fl |= Qt::ItemIsEditable;

    return fl;
}

int ProfileModel::findByName(QString name)
{
    int row = findByNameAndVisibility(name, false);
    if (row < 0)
        row = findByNameAndVisibility(name, true);

    return row;
}

int ProfileModel::findAsReference(QString reference) const
{
    int found = -1;
    if (reference.length() <= 0)
        return found;

    for (int cnt = 0; cnt < profiles_.count() && found < 0; cnt++)
    {
        profile_def * prof = guard(cnt);
        if (prof && reference.compare(prof->reference) == 0)
            found = cnt;
    }

    return found;
}

int ProfileModel::findByNameAndVisibility(QString name, bool isGlobal, bool searchReference) const
{
    QList<int> result = findAllByNameAndVisibility(name, isGlobal, searchReference);
    return result.count() == 0 ? -1 : result.at(0);
}

QList<int> ProfileModel::findAllByNameAndVisibility(QString name, bool isGlobal, bool searchReference) const
{
    QList<int> result;

    for (int cnt = 0; cnt < profiles_.count(); cnt++)
    {
        profile_def * prof = guard(cnt);
        if (prof && static_cast<bool>(prof->is_global) == isGlobal)
        {
            if (name.compare(prof->name) == 0 || (searchReference && name.compare(prof->reference) == 0) )
                result << cnt;
        }
    }

    return result;

}

QModelIndex ProfileModel::addNewProfile(QString name)
{
    int cnt = 1;
    QString newName = name;
    while (findByNameAndVisibility(newName) >= 0)
    {
        newName = QString("%1 %2").arg(name).arg(QString::number(cnt));
        cnt++;
    }

    add_to_profile_list(newName.toUtf8().constData(), newName.toUtf8().constData(), PROF_STAT_NEW, FALSE, FALSE, FALSE);
    loadProfiles();

    return index(findByName(newName), COL_NAME);
}

QModelIndex ProfileModel::duplicateEntry(QModelIndex idx, int new_status)
{
    profile_def * prof = guard(idx);
    if (! prof)
        return QModelIndex();

    /* only new and copied stati can be set */
    if (new_status != PROF_STAT_NEW && new_status != PROF_STAT_COPY)
        new_status = PROF_STAT_COPY;

    /* this is a copy from a personal profile, check if the original has been a
     * new profile or a preexisting one. In the case of a new profile, restart
     * with the state PROF_STAT_NEW */
    if (prof->status == PROF_STAT_COPY && ! prof->from_global)
    {
        int row = findByNameAndVisibility(prof->reference, false);
        profile_def * copyParent = guard(row);
        if (copyParent && copyParent->status == PROF_STAT_NEW)
            return duplicateEntry(index(row, ProfileModel::COL_NAME), PROF_STAT_NEW);
    }

    /* Rules for figuring out the name to copy from:
     *
     * General, use copy name
     * If status of copy is new or changed => use copy reference
     * If copy is non global and status of copy is != changed, use original parent name
     */
    QString parent = prof->name;
    if (prof->status == PROF_STAT_CHANGED)
        parent = prof->reference;
    else if (! prof->is_global && prof->status != PROF_STAT_NEW && prof->status != PROF_STAT_CHANGED)
        parent = get_profile_parent (prof->name);

    if (parent.length() == 0)
        return QModelIndex();

    /* parent references the parent profile to be used, parentName is the base for the new name */
    QString parentName = parent;
    /* the user has changed the profile name, therefore this is also the name to be used */
    if (prof->status != PROF_STAT_EXISTS)
        parentName = prof->name;

    /* check to ensure we do not end up with (copy) (copy) (copy) ... */
    QRegExp rx("\\s+(\\(\\s*" + tr("copy", "noun") + "\\s*\\d*\\))");
    if (rx.indexIn(parentName) >= 0)
        parentName.replace(rx, "");

    QString new_name;
    /* if copy is global and name has not been used before, use that, else create first copy */
    if (prof->is_global && findByNameAndVisibility(parentName) < 0)
        new_name = QString(prof->name);
    else
        new_name = QString("%1 (%2)").arg(parentName).arg(tr("copy", "noun"));

    /* check if copy already exists and iterate, until an unused version is found */
    int cnt = 1;
    while (findByNameAndVisibility(new_name) >= 0)
    {
        new_name = QString("%1 (%2 %3)").arg(parentName).arg(tr("copy", "noun")).arg(QString::number(cnt));
        cnt++;
    }

    /* if this would be a copy, but the original is already a new one, this is a copy as well */
    if (new_status == PROF_STAT_COPY && prof->status == PROF_STAT_NEW)
        new_status = PROF_STAT_NEW;

    /* add element */
    add_to_profile_list(new_name.toUtf8().constData(), parent.toUtf8().constData(), new_status, FALSE, prof->from_global ? prof->from_global : prof->is_global, FALSE);

    /* reload profile list in model */
    loadProfiles();

    int row = findByNameAndVisibility(new_name, false);
    /* sanity check, if adding the profile went correctly */
    if (row < 0 || row == idx.row())
        return QModelIndex();

    /* return the index of the profile */
    return index(row, COL_NAME);
}

void ProfileModel::deleteEntry(QModelIndex idx)
{
    if (! idx.isValid())
        return;

    QModelIndexList temp;
    temp << idx;
    deleteEntries(temp);
}

void ProfileModel::deleteEntries(QModelIndexList idcs)
{
    bool changes = false;

    QList<int> indeces;
    foreach (QModelIndex idx, idcs)
    {
        if (! indeces.contains(idx.row()) && ! idx.data(ProfileModel::DATA_IS_GLOBAL).toBool())
            indeces << idx.row();
    }
    /* Security blanket. This ensures, that we start deleting from the end and do not get any issues iterating the list */
    std::sort(indeces.begin(), indeces.end(), std::less<int>());

    foreach (int row, indeces)
    {
        profile_def * prof = guard(row);
        if (! prof)
            continue;

        if (prof->is_global)
            continue;

        if (prof->status == PROF_STAT_DEFAULT)
        {
            reset_default_ = ! reset_default_;
        }
        else
        {
            GList * fl_entry = entry(prof);
            if (fl_entry)
            {
                changes = true;
                remove_from_profile_list(fl_entry);
            }
        }
    }

    if (changes)
        loadProfiles();

    if (reset_default_)
    {
        emit layoutAboutToBeChanged();
        emit dataChanged(index(0, 0), index(rowCount(), columnCount()));
        emit layoutChanged();
    }
}

bool ProfileModel::resetDefault() const
{
    return reset_default_;
}

void ProfileModel::doResetModel(bool reset_import)
{
    reset_default_ = false;
    if (reset_import)
        profiles_imported_ = false;

    loadProfiles();
}

QModelIndex ProfileModel::activeProfile() const
{
    QList<int> rows = this->findAllByNameAndVisibility(set_profile_, false, true);
    foreach (int row, rows)
    {
        profile_def * prof = profiles_.at(row);
        if (prof->is_global || checkDuplicate(index(row, ProfileModel::COL_NAME)) )
            return QModelIndex();

        if ((set_profile_.compare(prof->name) == 0 && (prof->status == PROF_STAT_EXISTS || prof->status == PROF_STAT_DEFAULT) ) ||
             (set_profile_.compare(prof->reference) == 0 &&  prof->status == PROF_STAT_CHANGED) )
            return index(row, ProfileModel::COL_NAME);
    }

    return QModelIndex();
}

bool ProfileModel::setData(const QModelIndex &idx, const QVariant &value, int role)
{
    last_set_row_ = -1;

    if (role != Qt::EditRole ||  ! value.isValid() || value.toString().isEmpty())
        return false;

    QString newValue = value.toString();
    profile_def * prof = guard(idx);
    if (! prof || prof->status == PROF_STAT_DEFAULT)
        return false;

    last_set_row_ = idx.row();

    QString current(prof->name);
    if (current.compare(newValue) != 0)
    {
        g_free(prof->name);
        prof->name = qstring_strdup(newValue);

        if (prof->reference && g_strcmp0(prof->name, prof->reference) == 0 && ! (prof->status == PROF_STAT_NEW || prof->status == PROF_STAT_COPY)) {
            prof->status = PROF_STAT_EXISTS;
        } else if (prof->status == PROF_STAT_EXISTS) {
            prof->status = PROF_STAT_CHANGED;
        }
        emit itemChanged(idx);
    }

    loadProfiles();

    return true;
}

int ProfileModel::lastSetRow() const
{
    return last_set_row_;
}

bool ProfileModel::copyTempToProfile(QString tempPath, QString profilePath, bool * wasEmpty)
{
    bool was_empty = true;

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
        QString profileFile = profilePath + "/" + finfo.fileName();

        if (! profile_files_.contains(finfo.fileName()))
        {
            was_empty = false;
            continue;
        }

        if (! QFile::exists(tempFile) || QFile::exists(profileFile))
            continue;

        if (QFile::copy(tempFile, profileFile))
            created++;
    }

    if (wasEmpty)
        *wasEmpty = was_empty;

    if (created > 0)
        return true;

    return false;
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
                newLst << entry.absoluteFilePath();
                files << entry.absoluteFilePath();
            }
        }
    }

    return newLst;
}

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
            if (path.compare(entry.absoluteFilePath()) != 0)
                result.append(filterProfilePath(entry.absoluteFilePath(), result, fromZip));
        }
    }

    return result;
}

#ifdef HAVE_MINIZIP
QStringList ProfileModel::exportFileList(QModelIndexList items)
{
    QStringList result;

    foreach(QModelIndex idx, items)
    {
        profile_def * prof = guard(idx);
        if (! prof || prof->is_global || QString(prof->name).compare(DEFAULT_PROFILE) == 0)
            continue;

        if (! idx.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool())
            continue;

        QString path = idx.data(ProfileModel::DATA_PATH).toString();
        QDir temp(path);
        temp.setSorting(QDir::Name);
        temp.setFilter(QDir::Files | QDir::NoSymLinks | QDir::NoDotAndDotDot);
        QFileInfoList entries = temp.entryInfoList();
        foreach (QFileInfo fi, entries)
            result << fi.absoluteFilePath();
    }

    return result;
}

bool ProfileModel::exportProfiles(QString filename, QModelIndexList items, QString *err)
{
    if (changesPending())
    {
        if (err)
            err->append(tr("Exporting profiles while changes are pending is not allowed"));
        return false;
    }

    /* Write recent file for current profile before exporting */
    write_profile_recent();

    QStringList files = exportFileList(items);
    if (files.count() == 0)
    {
        if (err)
            err->append((tr("No profiles found to export")));
        return false;
    }

    if (WiresharkZipHelper::zip(filename, files, gchar_free_to_qstring(get_profiles_dir()) + "/") )
        return true;

    return false;
}

/* This check runs BEFORE the file has been unzipped! */
bool ProfileModel::acceptFile(QString fileName, int fileSize)
{
    if (fileName.toLower().endsWith(".zip"))
        return false;

    if (fileSize > 1024 * 512)
        return false;

    return true;
}

QString ProfileModel::cleanName(QString fileName)
{
    QStringList parts = fileName.split("/");
    QString temp = parts[parts.count() - 1].replace(QRegExp("[" + QRegExp::escape(illegalCharacters()) + "]"), QString("_") );
    temp = parts.join("/");
    return temp;
}

int ProfileModel::importProfilesFromZip(QString filename, int * skippedCnt, QStringList *result)
{
    QTemporaryDir dir;
#if 0
    dir.setAutoRemove(false);
    g_printerr("Temp dir for unzip: %s\n", dir.path().toUtf8().constData());
#endif

    int cnt = 0;
    if (dir.isValid())
    {
        WiresharkZipHelper::unzip(filename, dir.path(), &ProfileModel::acceptFile, &ProfileModel::cleanName);
        cnt = importProfilesFromDir(dir.path(), skippedCnt, true, result);
    }

    return cnt;
}
#endif

int ProfileModel::importProfilesFromDir(QString dirname, int * skippedCnt, bool fromZip, QStringList *result)
{
    int count = 0;
    int skipped = 0;
    QDir profileDir(gchar_free_to_qstring(get_profiles_dir()));
    QDir dir(dirname);

    if (skippedCnt)
        *skippedCnt = 0;

    if (dir.exists())
    {
        QFileInfoList entries = uniquePaths(filterProfilePath(dirname, QFileInfoList(), fromZip));

        int entryCount = 0;
        foreach (QFileInfo fentry, entries)
        {
            if (fentry.fileName().length() <= 0)
                continue;

            bool wasEmpty = true;
            bool success = false;

            entryCount++;

            QString profilePath = profileDir.absolutePath() + "/" + fentry.fileName();
            QString tempPath = fentry.absoluteFilePath();

            if (fentry.fileName().compare(DEFAULT_PROFILE, Qt::CaseInsensitive) == 0 || QFile::exists(profilePath))
            {
                skipped++;
                continue;
            }

            if (result)
                *result << fentry.fileName();

            success = copyTempToProfile(tempPath, profilePath, &wasEmpty);
            if (success)
            {
                count++;
                add_to_profile_list(fentry.fileName().toUtf8().constData(), fentry.fileName().toUtf8().constData(), PROF_STAT_NEW, FALSE, FALSE, TRUE);
            }
            else if (! wasEmpty && QFile::exists(profilePath))
            {
                QDir dh(profilePath);
                dh.rmdir(profilePath);
            }
        }

    }

    if (count > 0)
    {
        profiles_imported_ = true;
        loadProfiles();
    }

    if (skippedCnt)
        *skippedCnt = skipped;

    return count;
}

void ProfileModel::markAsImported(QStringList importedItems)
{
    if (importedItems.count() <= 0)
        return;

    profiles_imported_ = true;

    foreach (QString item, importedItems)
    {
        int row = findByNameAndVisibility(item, false);
        profile_def * prof = guard(row);
        if (! prof)
            continue;

        prof->is_import = true;
    }
}

bool ProfileModel::clearImported(QString *msg)
{
    QList<int> rows;
    bool result = true;
    for (int cnt = 0; cnt < rowCount(); cnt++)
    {
        profile_def * prof = guard(cnt);
        if (prof && prof->is_import && ! rows.contains(cnt))
            rows << cnt;
    }
    /* Security blanket. This ensures, that we start deleting from the end and do not get any issues iterating the list */
    std::sort(rows.begin(), rows.end(), std::less<int>());

    char * ret_path = Q_NULLPTR;
    for (int cnt = 0; cnt < rows.count() && result; cnt++)
    {
        int row = rows.at(cnt);
        if (delete_persconffile_profile (index(row, ProfileModel::COL_NAME).data().toString().toUtf8().constData(), &ret_path) != 0)
        {
            if (msg)
            {
                QString errmsg = QString("%1\n\"%2\":\n%3").arg(tr("Can't delete profile directory")).arg(ret_path).arg(g_strerror(errno));
                msg->append(errmsg);
            }

            result = false;
        }
    }

    return result;
}

QString ProfileModel::illegalCharacters()
{
#ifdef _WIN32
    /* According to https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions */
    return QString("<>:\"/\\|?*");
#else
    return QDir::separator();
#endif

}

bool ProfileModel::checkNameValidity(QString name, QString *msg)
{
    QString message;
    bool invalid = false;
    QString msgChars;

    QString invalid_dir_chars = illegalCharacters();

    for (int cnt = 0; cnt < invalid_dir_chars.length() && ! invalid; cnt++)
    {
        msgChars += invalid_dir_chars[cnt] + " ";
        if (name.contains(invalid_dir_chars[cnt]))
            invalid = true;
    }
#ifdef _WIN32
    if (invalid)
    {
        message = tr("A profile name cannot contain the following characters: %1").arg(msgChars);
    }

    if (message.isEmpty() && (name.startsWith('.') || name.endsWith('.')) )
        message = tr("A profile cannot start or end with a period (.)");
#else
    if (invalid)
        message = tr("A profile name cannot contain the '/' character");
#endif

    if (! message.isEmpty()) {
        if (msg)
            msg->append(message);
        return false;
    }

    return true;
}

QString ProfileModel::activeProfileName()
{
    ProfileModel model;
    QModelIndex idx = model.activeProfile();
    return idx.data(ProfileModel::COL_NAME).toString();
}

QString ProfileModel::activeProfilePath()
{
    ProfileModel model;
    QModelIndex idx = model.activeProfile();
    return idx.data(ProfileModel::DATA_PATH).toString();
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
