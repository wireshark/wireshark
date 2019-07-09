/* profile_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "glib.h"
#include "ui/profile.h"
#include "wsutil/filesystem.h"
#include "epan/prefs.h"

#include <ui/qt/models/profile_model.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>

#include <QDir>
#include <QFont>

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

    if (left.data(ProfileModel::DATA_STATUS) == PROF_STAT_DEFAULT)
        igL = true;
    if (right.data(ProfileModel::DATA_STATUS) == PROF_STAT_DEFAULT)
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
        bool gl = idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() || idx.data(ProfileModel::DATA_IS_DEFAULT).toBool();
        if ( ft_ == ProfileSortModel::UserProfiles && gl )
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
    bool refresh = profiles_.count() > 0;

    if ( refresh )
        profiles_.clear();
    else
        init_profile_list();

    emit beginResetModel();

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
        if (strcmp(ref->reference, profile->reference) == 0 && ref->is_global == profile->is_global)
            return fl_entry;

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

int ProfileModel::rowCount(const QModelIndex &) const
{
    return profiles_.count();
}

int ProfileModel::columnCount(const QModelIndex &) const
{
    return static_cast<int>(_LAST_ENTRY);
}

QVariant ProfileModel::data(const QModelIndex &index, int role) const
{
    if ( ! index.isValid() || profiles_.count() <= index.row() )
        return QVariant();

    profile_def * prof = profiles_.at(index.row());
    if ( ! prof )
        return QVariant();

    switch ( role )
    {
    case Qt::DisplayRole:
        switch (index.column())
        {
        case COL_NAME:
            return QString(prof->name);
        case COL_TYPE:
            if ( prof->is_global || prof->status == PROF_STAT_DEFAULT )
                return tr("Global");
            else
                return tr("User");
        case COL_PATH:
            switch (prof->status)
            {
            case PROF_STAT_DEFAULT:
                if (!reset_default_)
                    return get_persconffile_path("", FALSE);
                else
                    return tr("Resetting to default");
            case PROF_STAT_EXISTS:
                {
                    QString profile_path = prof->is_global ? get_global_profiles_dir() : get_profiles_dir();
                    profile_path.append(QDir::separator()).append(prof->name);
                    return profile_path;
                }
            case PROF_STAT_NEW:
                return tr("Created from default settings");
            case PROF_STAT_COPY:
                if (prof->reference)
                    return QString("%1 %2").arg(tr("Copied from: ")).arg(prof->reference);
                break;
            }
            break;
        default:
            break;
        }
        break;

    case Qt::FontRole:
    {
        QFont font;

        if ( prof->is_global || prof->status == PROF_STAT_DEFAULT )
            font.setItalic(true);

        if ( set_profile_.compare(prof->name) == 0 )
        {
            profile_def * act = profiles_.at(activeProfile().row());
            if ( act->is_global == prof->is_global )
                font.setBold(true);
        }

        if ( prof->status == PROF_STAT_DEFAULT && reset_default_ )
            font.setStrikeOut(true);

        return font;
    }

    case Qt::BackgroundRole:
    {
        QBrush bgBrush;

        if ( ! profile_name_is_valid(prof->name) )
            bgBrush.setColor(ColorUtils::fromColorT(&prefs.gui_text_invalid));

        if ( prof->status == PROF_STAT_DEFAULT && reset_default_ )
            bgBrush.setColor(ColorUtils::fromColorT(&prefs.gui_text_deprecated));


        return bgBrush;
    }

    case Qt::ToolTipRole:
        switch (prof->status)
        {
        case PROF_STAT_DEFAULT:
            if (reset_default_)
                return tr("Will be reset to default values");
            break;
        case PROF_STAT_COPY:
            if (prof->reference) {
                QString reference = prof->reference;
                GList *fl_entry = entry(prof);
                if (fl_entry)
                {
                    profile_def *profile = reinterpret_cast<profile_def *>(fl_entry->data);
                    if (strcmp(prof->reference, profile->reference) == 0) {
                        if (profile->status == PROF_STAT_CHANGED) {
                            // Reference profile was renamed, use the new name
                            reference = profile->name;
                            break;
                        }
                    }
                }

                QString profile_info = tr("Created from %1").arg(reference);
                if (prof->from_global) {
                    profile_info.append(QString(" %1").arg(tr("(system provided)")));
                } else if (!reference.isEmpty()) {
                    profile_info.append(QString(" %1").arg(tr("(deleted)")));
                }
                return profile_info;
            }
            break;
        case PROF_STAT_NEW:
            return tr("Created from default settings");
        case PROF_STAT_CHANGED:
            if ( prof->reference )
                return tr("Renamed from %1").arg(prof->reference);
            break;
        default:
            break;
        }

        if (gchar * err_msg = profile_name_is_valid(prof->name))
        {
            QString msg = gchar_free_to_qstring(err_msg);
            return msg;
        }

        if (prof->is_global)
            return tr("This is a system provided profile.");
        if ( prof->status == PROF_STAT_DEFAULT && reset_default_ )
            return tr("The profile will be reset to default values.");

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
            profile_def * selprof = profiles_.at(selected.row());
            if ( selprof )
            {
                if ( selprof->is_global != prof->is_global )
                    return qVariantFromValue(false);

                if ( strcmp(selprof->name, prof->name) == 0 )
                    return qVariantFromValue(true);
            }
            return qVariantFromValue(false);
        }

    case ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION:
        if ( prof->status == PROF_STAT_NEW || prof->status == PROF_STAT_COPY || ( prof->status == PROF_STAT_DEFAULT && reset_default_ ) )
            return qVariantFromValue(false);
        else
            return qVariantFromValue(true);

    default:
        break;
    }

#if 0
    if (pd_ui_->profileTreeView->topLevelItemCount() > 0) {
        profile_def *profile;
        for (int i = 0; i < pd_ui_->profileTreeView->topLevelItemCount(); i++) {
            item = pd_ui_->profileTreeView->topLevelItem(i);
            profile = (profile_def *) VariantPointer<GList>::asPtr(item->data(0, Qt::UserRole))->data;
            if (current_profile && !current_profile->is_global && profile != current_profile && strcmp(profile->name, current_profile->name) == 0) {
                item->setToolTip(0, tr("A profile already exists with this name."));
                item->setBackground(0, ColorUtils::fromColorT(&prefs.gui_text_invalid));
                if (current_profile->status != PROF_STAT_DEFAULT &&
                    current_profile->status != PROF_STAT_EXISTS)
                {
                    pd_ui_->infoLabel->setText(tr("A profile already exists with this name"));
                }
                enable_ok = false;
            }
        }
    }
#endif

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
        case COL_PATH:
            return tr("Path");
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

    profile_def * prof = profiles_.at(index.row());
    if ( ! prof )
        return fl;

    if ( index.column() == ProfileModel::COL_NAME && prof->status != PROF_STAT_DEFAULT  && ! prof->is_global && set_profile_.compare(prof->name) != 0 )
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
    int row = -1;
    for ( int cnt = 0; cnt < profiles_.count() && row < 0; cnt++ )
    {
        profile_def * prof = profiles_.at(cnt);
        if ( prof && prof->is_global == isGlobal && name.compare(prof->name) == 0 )
            row = cnt;
    }

    return row;
}

QModelIndex ProfileModel::addNewProfile(QString name)
{
    add_to_profile_list(name.toUtf8().data(), "", PROF_STAT_NEW, FALSE, FALSE);
    loadProfiles();

    return index(findByName(name), COL_NAME);
}

QModelIndex ProfileModel::duplicateEntry(QModelIndex idx)
{
    if ( ! idx.isValid() || profiles_.count() <= idx.row() )
        return QModelIndex();

    profile_def * prof = profiles_.at(idx.row());
    if ( ! prof )
        return QModelIndex();

    QString parent = prof->name;
    if (!prof->is_global)
        parent = get_profile_parent (prof->name);

    QString new_name;
    if (prof->is_global && ! profile_exists (parent.toUtf8().constData(), FALSE))
        new_name = QString(prof->name);
    else
        new_name = QString("%1 (%2)").arg(parent).arg(tr("copy"));

    if ( findByNameAndVisibility(new_name) >= 0 )
        return QModelIndex();

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

    profile_def * prof = profiles_.at(idx.row());
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
        emit beginRemoveRows(QModelIndex(), idx.row(), idx.row());
        remove_from_profile_list(fl_entry);
        loadProfiles();
        emit endRemoveRows();
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
        return index(row, ProfileModel::COL_NAME);

    return QModelIndex();
}

bool ProfileModel::setData(const QModelIndex &idx, const QVariant &value, int role)
{
    if ( role != Qt::EditRole || ! idx.isValid() )
        return false;

    if ( ! value.isValid() || value.toString().isEmpty() )
        return false;

    profile_def * prof = profiles_.at(idx.row());
    if ( ! prof || prof->status == PROF_STAT_DEFAULT )
        return false;

    QString current(prof->name);
    if ( current.compare(value.toString()) != 0 )
    {
        g_free(prof->name);
        prof->name = qstring_strdup(value.toString());

        if (strcmp(prof->name, prof->reference) == 0) {
            prof->status = PROF_STAT_EXISTS;
        } else if (prof->status == PROF_STAT_EXISTS) {
            prof->status = PROF_STAT_CHANGED;
        }
    }

    loadProfiles();

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
