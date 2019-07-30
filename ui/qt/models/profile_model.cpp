/* profile_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "glib.h"
#include "ui/profile.h"
#include "wsutil/filesystem.h"
#include "epan/prefs.h"

#include <ui/qt/models/profile_model.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/wireshark_zip_helper.h>

#include <QDir>
#include <QFont>
#include <QTemporaryDir>

#define gxx_list_next(list) ((list) ? ((reinterpret_cast<GList *>(list))->next) : Q_NULLPTR)

Q_LOGGING_CATEGORY(profileLogger, "wireshark.profiles")

ProfileSortModel::ProfileSortModel(QObject * parent):
    QSortFilterProxyModel (parent),
    ft_(ProfileSortModel::AllProfiles),
    ftext_(QString())
{}

bool ProfileSortModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    QModelIndex left = source_left;
    if ( source_left.column() != ProfileModel::COL_NAME )
        left = source_left.sibling(source_left.row(), ProfileModel::COL_NAME);

    QModelIndex right = source_right;
    if ( source_right.column() != ProfileModel::COL_NAME )
        right = source_right.sibling(source_right.row(), ProfileModel::COL_NAME);

    bool igL = left.data(ProfileModel::DATA_IS_GLOBAL).toBool();
    bool igR = right.data(ProfileModel::DATA_IS_GLOBAL).toBool();

    if (left.data(ProfileModel::DATA_STATUS).toInt() == PROF_STAT_DEFAULT)
        igL = true;
    if (right.data(ProfileModel::DATA_STATUS).toInt() == PROF_STAT_DEFAULT)
        igR = true;

    if ( igL && ! igR )
        return true;
    else if ( ! igL && igR )
        return false;
    else if ( igL && igR )
    {
        if (left.data(ProfileModel::DATA_STATUS) == PROF_STAT_DEFAULT)
            return true;
    }

    if ( left.data().toString().compare(right.data().toString()) <= 0 )
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

bool ProfileSortModel::filterAcceptsRow(int source_row, const QModelIndex &) const
{
    bool accept = true;
    QModelIndex idx = sourceModel()->index(source_row, ProfileModel::COL_NAME);

    if ( ft_ != ProfileSortModel::AllProfiles )
    {
        bool gl = idx.data(ProfileModel::DATA_IS_GLOBAL).toBool();
        if ( ft_ == ProfileSortModel::PersonalProfiles && gl )
            accept = false;
        else if ( ft_ == ProfileSortModel::GlobalProfiles && ! gl )
            accept = false;
    }

    if ( ftext_.length() > 0 )
    {
        QString name = idx.data().toString();
        if ( ! name.contains(ftext_, Qt::CaseInsensitive) )
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

    loadProfiles();
}

void ProfileModel::loadProfiles()
{
    emit beginResetModel();

    bool refresh = profiles_.count() > 0;

     if ( refresh )
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
    while (fl_entry && fl_entry->data) {
        profile_def *profile = reinterpret_cast<profile_def *>(fl_entry->data);
        if (strcmp(ref->name, profile->name) == 0 && ref->is_global == profile->is_global)
        {
            if ( ( ref->reference == Q_NULLPTR && profile->reference == Q_NULLPTR )
                 || ( ( ref->reference != Q_NULLPTR && profile->reference != Q_NULLPTR )
                      && (strcmp(ref->reference, profile->reference) == 0) ) )
                return fl_entry;
        }

        fl_entry = gxx_list_next(fl_entry);
    }

    return Q_NULLPTR;
}

GList *ProfileModel::at(int row) const
{
    if ( row < 0 || row >= profiles_.count() )
        return Q_NULLPTR;

    profile_def * prof = profiles_.at(row);
    return entry(prof);
}

bool ProfileModel::changesPending() const
{
    if ( reset_default_ )
        return true;

    if ( g_list_length(edited_profile_list()) != g_list_length(current_profile_list()) )
        return true;

    bool pending = false;
    GList *fl_entry = edited_profile_list();
    while (fl_entry && fl_entry->data && ! pending) {
        profile_def *profile = reinterpret_cast<profile_def *>(fl_entry->data);
        pending = ( profile->status == PROF_STAT_NEW || profile->status == PROF_STAT_CHANGED || profile->status == PROF_STAT_COPY );
        fl_entry = gxx_list_next(fl_entry);
    }

    return pending;
}

int ProfileModel::rowCount(const QModelIndex &) const
{
    return profiles_.count();
}

int ProfileModel::columnCount(const QModelIndex &) const
{
    return static_cast<int>(_LAST_ENTRY);
}

profile_def * ProfileModel::guard(int row) const
{
    if ( profiles_.count() <= row )
        return Q_NULLPTR;

    if ( ! edited_profile_list() )
    {
        static_cast<QList<profile_def *>>(profiles_).clear();
        return Q_NULLPTR;
    }

    return profiles_.at(row);
}

QVariant ProfileModel::dataDisplay(const QModelIndex &index) const
{
    if ( ! index.isValid() || profiles_.count() <= index.row() )
        return QVariant();

    profile_def * prof = guard(index.row());
    if ( ! prof )
        return QVariant();

    switch (index.column())
    {
    case COL_NAME:
        return QString(prof->name);
    case COL_TYPE:
        if ( prof->status == PROF_STAT_DEFAULT )
            return tr("Default");
        else if ( prof->is_global )
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
    if ( ! index.isValid() || profiles_.count() <= index.row() )
        return QVariant();

    profile_def * prof = guard(index.row());
    if ( ! prof )
        return QVariant();

    QFont font;

        if ( prof->is_global )
        font.setItalic(true);

        if ( set_profile_.compare(prof->name) == 0 && ! prof->is_global )
            font.setBold(true);

    if ( prof->status == PROF_STAT_DEFAULT && reset_default_ )
        font.setStrikeOut(true);

    return font;
}

QVariant ProfileModel::dataBackgroundRole(const QModelIndex &index) const
{
    if ( ! index.isValid() || profiles_.count() <= index.row() )
        return QVariant();

    profile_def * prof = guard(index.row());
    if ( ! prof )
        return QVariant();

    if ( ! ProfileModel::checkNameValidity(QString(prof->name)) )
        return ColorUtils::fromColorT(&prefs.gui_text_invalid);

    if ( prof->status == PROF_STAT_DEFAULT && reset_default_ )
        return ColorUtils::fromColorT(&prefs.gui_text_deprecated);

    QList<int> rows = const_cast<ProfileModel *>(this)->findAllByNameAndVisibility(QString(prof->name), prof->is_global);
    if ( rows.count() > 1 )
        return ColorUtils::fromColorT(&prefs.gui_text_invalid);

    return QVariant();
}

QVariant ProfileModel::dataToolTipRole(const QModelIndex &idx) const
{
    if ( ! idx.isValid() || profiles_.count() <= idx.row() )
        return QVariant();

    profile_def * prof = guard(idx.row());
    if ( ! prof )
        return QVariant();

    QString msg;

    if (prof->is_global)
        return tr("This is a system provided profile.");
    else
        return dataPath(idx);
}

QVariant ProfileModel::dataPath(const QModelIndex &index) const
{
    if ( ! index.isValid() || profiles_.count() <= index.row() )
        return QVariant();

    profile_def * prof = guard(index.row());
    if ( ! prof )
        return QVariant();

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
            profile_path.append(QDir::separator()).append(prof->name);
            return profile_path;
        }
    case PROF_STAT_NEW:
        {
            QList<int> entries = const_cast<ProfileModel *>(this)->findAllByNameAndVisibility(prof->name);
            QString errMsg;

            if ( entries.count() > 1 )
                return tr("A profile already exists with this name.");
            else if ( ! checkNameValidity(prof->name, &errMsg) )
                return errMsg;
            else
                return tr("Created from default settings");
        }
    case PROF_STAT_CHANGED:
        if (prof->reference)
            return QString("%1 %2").arg(tr("Renamed from: ")).arg(prof->reference);
        break;
    case PROF_STAT_COPY:
        if (prof->reference)
        {
            QString msg = QString("%1 %2").arg(tr("Copied from: ")).arg(prof->reference);

            if ( profile_exists(prof->reference, TRUE) && prof->from_global )
                msg.append(QString(" (%1)").arg(tr("system provided")));
            else
            {
                ProfileModel * nthis = const_cast<ProfileModel *>(this);
                int row = nthis->findByNameAndVisibility(prof->reference);
                if ( row < 0 )
                    msg.append(QString(" (%1)").arg(tr("deleted")));
            }

            return msg;
        }
        break;
    }

    return QVariant();
}

QVariant ProfileModel::data(const QModelIndex &index, int role) const
{
    QString msg;

    if ( ! index.isValid() || profiles_.count() <= index.row() )
        return QVariant();

    profile_def * prof = guard(index.row());
    if ( ! prof )
        return QVariant();

    switch ( role )
    {
    case Qt::DisplayRole:
        return dataDisplay(index);
        break;
    case Qt::FontRole:
        return dataFontRole(index);
        break;
    case Qt::BackgroundColorRole:
        return dataBackgroundRole(index);
        break;
    case Qt::ToolTipRole:
        return dataToolTipRole(index);
        break;
    case ProfileModel::DATA_STATUS:
        return qVariantFromValue(prof->status);
    case ProfileModel::DATA_IS_DEFAULT:
        return qVariantFromValue(prof->status == PROF_STAT_DEFAULT);
    case ProfileModel::DATA_IS_GLOBAL:
        return qVariantFromValue(prof->is_global);
    case ProfileModel::DATA_IS_SELECTED:
        {
            QModelIndex selected = activeProfile();
            if ( selected.isValid() && selected.row() < profiles_.count() )
            {
                profile_def * selprof = guard(selected.row());
                if ( selprof && selprof->is_global != prof->is_global )
                    return qVariantFromValue(false);

                if ( selprof && strcmp(selprof->name, prof->name) == 0 )
                    return qVariantFromValue(true);
            }
            return qVariantFromValue(false);
        }
        break;
    case ProfileModel::DATA_PATH:
        return dataPath(index);
        break;

    case ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION:
        if ( prof->status == PROF_STAT_NEW || prof->status == PROF_STAT_COPY
             || ( prof->status == PROF_STAT_DEFAULT && reset_default_ )
             || prof->status == PROF_STAT_CHANGED )
            return qVariantFromValue(false);
        else
            return qVariantFromValue(true);

    default:
        break;
    }

    return QVariant();
}

QVariant ProfileModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if ( orientation == Qt::Horizontal && role == Qt::DisplayRole )
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

    if ( ! index.isValid() || profiles_.count() <= index.row() )
        return fl;

    profile_def * prof = guard(index.row());
    if ( ! prof )
        return fl;

    if ( index.column() == ProfileModel::COL_NAME && prof->status != PROF_STAT_DEFAULT  && ! prof->is_global )
        fl |= Qt::ItemIsEditable;

    return fl;
}

int ProfileModel::findByName(QString name)
{
    int row = findByNameAndVisibility(name, false);
    if ( row < 0 )
        row = findByNameAndVisibility(name, true);

    return row;
}

int ProfileModel::findByNameAndVisibility(QString name, bool isGlobal)
{
    QList<int> result = findAllByNameAndVisibility(name, isGlobal);
    return result.count() == 0 ? -1 : result.at(0);
}

QList<int> ProfileModel::findAllByNameAndVisibility(QString name, bool isGlobal)
{
    QList<int> result;

    for ( int cnt = 0; cnt < profiles_.count(); cnt++ )
    {
        profile_def * prof = guard(cnt);
        if ( prof && static_cast<bool>(prof->is_global) == isGlobal && name.compare(prof->name) == 0 )
            result << cnt;
    }

    return result;

}

QModelIndex ProfileModel::addNewProfile(QString name)
{
    int cnt = 1;
    QString newName = name;
    while(findByNameAndVisibility(newName) >= 0)
    {
        newName = QString("%1 %2").arg(name).arg(QString::number(cnt));
        cnt++;
    }

    add_to_profile_list(newName.toUtf8().constData(), Q_NULLPTR, PROF_STAT_NEW, FALSE, FALSE);
    loadProfiles();

    return index(findByName(newName), COL_NAME);
}

QModelIndex ProfileModel::duplicateEntry(QModelIndex idx)
{
    if ( ! idx.isValid() )
        return QModelIndex();

    profile_def * prof = guard(idx.row());
    if ( ! prof )
        return QModelIndex();

    QString parent = prof->name;
    if ( ! prof->is_global && prof->status != PROF_STAT_CHANGED && prof->status != PROF_STAT_NEW )
        parent = get_profile_parent (prof->name);

    QString new_name;
    if (prof->is_global && ! profile_exists (parent.toUtf8().constData(), FALSE))
        new_name = QString(prof->name);
    else
        new_name = QString("%1 (%2)").arg(parent).arg(tr("copy", "noun"));

    if ( findByNameAndVisibility(new_name) >= 0 )
    {
        int cnt = 1;
        QString copyName = new_name;
        while(findByNameAndVisibility(copyName) >= 0)
        {
            copyName = new_name;
            copyName = copyName.replace(tr("copy", "noun"), tr("copy", "noun").append(" %1").arg(QString::number(cnt)));
            cnt++;
        }
        new_name = copyName;
    }

    if ( new_name.compare(QString(new_name.toUtf8().constData())) != 0 && !prof->is_global )
        return QModelIndex();

    add_to_profile_list(new_name.toUtf8().constData(), parent.toUtf8().constData(), PROF_STAT_COPY, FALSE, prof->from_global);
    loadProfiles();

    int row = findByNameAndVisibility(new_name, false);
    if ( row < 0 || row == idx.row() )
        return QModelIndex();

    return index(row, COL_NAME);
}

void ProfileModel::deleteEntry(QModelIndex idx)
{
    if ( ! idx.isValid() )
        return;

    profile_def * prof = guard(idx.row());
    if ( ! prof )
        return;

    if ( prof->is_global )
        return;

    if ( prof->status == PROF_STAT_DEFAULT )
    {
        emit layoutAboutToBeChanged();
        reset_default_ = ! reset_default_;
        emit dataChanged(index(0, 0), index(rowCount(), columnCount()));
        emit layoutChanged();
    }
    else
    {
        GList * fl_entry = entry(prof);
        if ( fl_entry )
        {
            remove_from_profile_list(fl_entry);
            loadProfiles();
        }
    }
}

bool ProfileModel::resetDefault() const
{
    return reset_default_;
}

void ProfileModel::doResetModel()
{
    reset_default_ = false;
    loadProfiles();
}

QModelIndex ProfileModel::activeProfile() const
{
    ProfileModel * temp = const_cast<ProfileModel *>(this);
    QString sel_profile = get_profile_name();
    int row = temp->findByName(sel_profile);
    if ( row >= 0 )
    {
        profile_def * prof = profiles_.at(row);
        if ( prof->is_global )
            return QModelIndex();

        return index(row, ProfileModel::COL_NAME);
    }

    return QModelIndex();
}

bool ProfileModel::setData(const QModelIndex &idx, const QVariant &value, int role)
{
    if ( role != Qt::EditRole || ! idx.isValid() )
        return false;

    if ( ! value.isValid() || value.toString().isEmpty() )
        return false;

    profile_def * prof = guard(idx.row());
    if ( ! prof || prof->status == PROF_STAT_DEFAULT )
        return false;

    QString current(prof->name);
    if ( current.compare(value.toString()) != 0 )
    {
        g_free(prof->name);
        prof->name = qstring_strdup(value.toString());

        if (prof->reference && strcmp(prof->name, prof->reference) == 0) {
            prof->status = PROF_STAT_EXISTS;
        } else if (prof->status == PROF_STAT_EXISTS) {
            prof->status = PROF_STAT_CHANGED;
        }
    }

    loadProfiles();

    return true;
}

bool ProfileModel::copyTempToProfile(QString tempPath, QString profilePath)
{
    QDir profileDir(profilePath);
    if ( ! profileDir.mkpath(profilePath) || ! QFile::exists(tempPath) )
        return false;

    QDir tempProfile(tempPath);
    tempProfile.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
    QFileInfoList files = tempProfile.entryInfoList();
    if ( files.count() <= 0 )
        return false;

    int created = 0;
    foreach ( QFileInfo finfo, files)
    {
        QString tempFile = finfo.absoluteFilePath();
        QString profileFile = profilePath + QDir::separator() + finfo.fileName();

        if ( ! QFile::exists(tempFile) || QFile::exists(profileFile) )
            continue;

        if ( QFile::copy(tempFile, profileFile) )
            created++;
    }

    if ( created > 0 )
        return true;

    return false;
}

QFileInfoList ProfileModel::filterProfilePath(QString path, QFileInfoList ent, bool fromZip)
{
    QFileInfoList result = ent;

    QDir temp(path);
    temp.setSorting(QDir::Name);
    temp.setFilter(QDir::Dirs | QDir::NoSymLinks | QDir::NoDotAndDotDot);
    QFileInfoList entries = temp.entryInfoList();
    if ( ! fromZip )
        entries << QFileInfo(path);
    foreach ( QFileInfo entry, entries )
    {
        QDir fPath(entry.absoluteFilePath());
        fPath.setSorting(QDir::Name);
        fPath.setFilter(QDir::Files | QDir::NoSymLinks);
        QFileInfoList fEntries = fPath.entryInfoList();
        bool found = false;
        for ( int cnt = 0; cnt < fEntries.count() && ! found; cnt++)
        {
            if ( config_file_exists_with_entries(fEntries[cnt].absoluteFilePath().toUtf8().constData(), '#') )
                 found = true;
        }

        if ( found )
            result.append(entry);
        else
            result.append(filterProfilePath(entry.absoluteFilePath(), result, fromZip));
    }

    return result;
}

#ifdef HAVE_MINIZIP
QStringList ProfileModel::exportFileList(QModelIndexList items)
{
    QStringList result;

    foreach(QModelIndex idx, items)
    {
        profile_def * prof = guard(idx.row());
        if ( prof->is_global || QString(prof->name).compare(DEFAULT_PROFILE) == 0 )
            continue;

        if ( ! idx.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool() )
            continue;

        QString path = idx.data(ProfileModel::DATA_PATH).toString();
        QDir temp(path);
        temp.setSorting(QDir::Name);
        temp.setFilter(QDir::Files | QDir::NoSymLinks | QDir::NoDotAndDotDot);
        QFileInfoList entries = temp.entryInfoList();
        foreach ( QFileInfo fi, entries )
            result << fi.absoluteFilePath();
    }

    return result;
}

bool ProfileModel::exportProfiles(QString filename, QModelIndexList items, QString *err)
{
    if ( changesPending() )
    {
        if ( err )
            err->append(tr("Exporting profiles while changes are pending is not allowed"));
        return false;
    }

    QStringList files = exportFileList(items);
    if ( files.count() == 0 )
    {
        if ( err )
            err->append((tr("No profiles found to export")));
        return false;
    }

    if ( WireSharkZipHelper::zip(filename, files, gchar_free_to_qstring(get_profiles_dir()) + QDir::separator() ) )
        return true;

    return false;
}

/* This check runs BEFORE the file has been unzipped! */
bool ProfileModel::acceptFile(QString fileName, int fileSize)
{
    if ( fileName.contains(".") || fileName.startsWith("_") )
        return false;

    if ( fileSize > 1024 * 512 )
        return false;

    /*  config_file_exists_with_entries cannot be used, due to the fact, that the file has not been extracted yet */

    return true;
}

int ProfileModel::importProfilesFromZip(QString filename, int * skippedCnt)
{
    QTemporaryDir dir;
#if 0
    dir.setAutoRemove(false);
#endif

    int cnt = 0;
    if ( dir.isValid() )
    {
        WireSharkZipHelper::unzip(filename, dir.path(), &ProfileModel::acceptFile);
        cnt = importProfilesFromDir(dir.path(), skippedCnt, true);
    }

    return cnt;
}
#endif

int ProfileModel::importProfilesFromDir(QString dirname, int * skippedCnt, bool fromZip)
{
    int count = 0;
    int skipped = 0;
    QDir profileDir(gchar_free_to_qstring(get_profiles_dir()));
    QDir dir(dirname);
    if ( dir.exists() )
    {
        QFileInfoList entries = filterProfilePath(dirname, QFileInfoList(), fromZip);

        int entryCount = 0;
        foreach ( QFileInfo fentry, entries )
        {
            entryCount++;

            QString profilePath = profileDir.absolutePath() + QDir::separator() + fentry.fileName();
            QString tempPath = fentry.absoluteFilePath();

            if ( fentry.fileName().compare(DEFAULT_PROFILE, Qt::CaseInsensitive) == 0 || QFile::exists(profilePath) )
            {
                skipped++;
                continue;
            }

            if ( copyTempToProfile(tempPath, profilePath) )
            {
                count++;
            }
        }

    }

    if ( count > 0 )
        loadProfiles();

    if ( skippedCnt )
        *skippedCnt = skipped;

    return count;
}

bool ProfileModel::checkNameValidity(QString name, QString *msg)
{
    QString message;
    bool invalid = false;
    QString msgChars;

#ifdef _WIN32
    /* According to https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions */
    QString invalid_dir_chars = "<>:\"/\\|?*";
#else
    QString invalid_dir_chars = QDir::separator();
#endif

    for ( int cnt = 0; cnt < invalid_dir_chars.length() && ! invalid; cnt++ )
    {
        msgChars += invalid_dir_chars[cnt] + " ";
        if ( name.contains(invalid_dir_chars[cnt]) )
            invalid = true;
    }
    if ( invalid )
    {
#ifdef _WIN32
        message = tr("A profile name cannot contain the following characters: %1").arg(msgChars);
#else
        message = tr("A profile name cannot contain the '/' character.");
#endif
    }

    if ( message.isEmpty() && ( name.startsWith('.') || name.endsWith('.') ) )
        message = tr("A profile cannot start or end with a period (.)");

    if (! message.isEmpty()) {
        if (msg)
            msg->append(message);
        return false;
    }

    return true;
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
