/* profile_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_MODEL_H
#define PROFILE_MODEL_H

#include "config.h"
#include "glib.h"

#include <ui/profile.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QLoggingCategory>
#include <QFileInfoList>

Q_DECLARE_LOGGING_CATEGORY(profileLogger)

class ProfileSortModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    ProfileSortModel(QObject *parent = Q_NULLPTR);

    enum FilterType {
        AllProfiles = 0,
        PersonalProfiles,
        GlobalProfiles
    };

    void setFilterType(FilterType ft);
    void setFilterString(QString txt = QString());

    static QStringList filterTypes();

protected:
    virtual bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;

private:
    FilterType ft_;
    QString ftext_;
};

class ProfileModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit ProfileModel(QObject * parent = Q_NULLPTR);

    enum {
        COL_NAME,
        COL_TYPE,
        _LAST_ENTRY
    } columns_;

    enum {
        DATA_STATUS = Qt::UserRole,
        DATA_IS_DEFAULT,
        DATA_IS_GLOBAL,
        DATA_IS_SELECTED,
        DATA_PATH,
        DATA_PATH_IS_NOT_DESCRIPTION,
        DATA_INDEX_VALUE_IS_URL
    } data_values_;

    // QAbstractItemModel interface
    virtual int rowCount(const QModelIndex & parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex & parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex & idx, int role = Qt::DisplayRole) const;
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role);
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const;

    void deleteEntry(QModelIndex idx);
    void deleteEntries(QModelIndexList idcs);

    int findByName(QString name);
    QModelIndex addNewProfile(QString name);
    QModelIndex duplicateEntry(QModelIndex idx, int new_status = PROF_STAT_COPY);

    void doResetModel(bool reset_import = false);
    bool resetDefault() const;

    QModelIndex activeProfile() const;
    static QString activeProfileName();
    static QString activeProfilePath();

    GList * at(int row) const;

    bool changesPending() const;
    bool importPending() const;

    bool userProfilesExist() const;

#ifdef HAVE_MINIZIP
    bool exportProfiles(QString filename, QModelIndexList items, QString * err = Q_NULLPTR);
    int importProfilesFromZip(QString filename, int *skippedCnt = Q_NULLPTR, QStringList *result = Q_NULLPTR);
#endif
    int importProfilesFromDir(QString filename, int *skippedCnt = Q_NULLPTR, bool fromZip = false, QStringList *result = Q_NULLPTR);

    static bool checkNameValidity(QString name, QString *msg = Q_NULLPTR);
    QList<int> findAllByNameAndVisibility(QString name, bool isGlobal = false, bool searchReference = false) const;
    void markAsImported(QStringList importedItems);
    bool clearImported(QString *msg = Q_NULLPTR);

    int lastSetRow() const;

    bool checkInvalid(const QModelIndex &index) const;
    bool checkIfDeleted(const QModelIndex &index) const;
    bool checkIfDeleted(int row) const;
    bool checkDuplicate(const QModelIndex &index, bool isOriginalToDuplicate = false) const;

Q_SIGNALS:
    void itemChanged(const QModelIndex &idx);

protected:
    static QString illegalCharacters();

private:
    QList<profile_def *> profiles_;
    QStringList profile_files_;
    QString set_profile_;
    bool reset_default_;
    bool profiles_imported_;

    int last_set_row_;

    void loadProfiles();
    profile_def * guard(const QModelIndex &index) const;
    profile_def * guard(int row) const;
    GList * entry(profile_def *) const;

    int findByNameAndVisibility(QString name, bool isGlobal = false, bool searchReference = false) const;
    int findAsReference(QString reference) const;

#ifdef HAVE_MINIZIP
    static bool acceptFile(QString fileName, int fileSize);
    static QString cleanName(QString fileName);
#endif

    QVariant dataDisplay(const QModelIndex & idx) const;
    QVariant dataFontRole(const QModelIndex & idx) const;
    QVariant dataBackgroundRole(const QModelIndex & idx) const;
    QVariant dataToolTipRole(const QModelIndex & idx) const;
    QVariant dataPath(const QModelIndex & idx) const;

#ifdef HAVE_MINIZIP
    QStringList exportFileList(QModelIndexList items);
#endif
    bool copyTempToProfile(QString tempPath, QString profilePath, bool *wasEmpty = Q_NULLPTR);
    QFileInfoList filterProfilePath(QString, QFileInfoList ent, bool fromZip);
    QFileInfoList uniquePaths(QFileInfoList lst);

};

#endif

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
