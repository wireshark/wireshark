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

#include "glib.h"

#include <ui/profile.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(profileLogger)

class ProfileSortModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    ProfileSortModel(QObject *parent = Q_NULLPTR);

    enum FilterType {
        AllProfiles = 0,
        GlobalProfiles,
        UserProfiles
    };

    void setFilterType(FilterType ft);
    void setFilterString(QString txt = QString());

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
        COL_PATH,
        _LAST_ENTRY
    } columns_;

    enum {
        DATA_STATUS = Qt::UserRole,
        DATA_IS_DEFAULT,
        DATA_IS_GLOBAL,
        DATA_IS_SELECTED,
        DATA_PATH_IS_NOT_DESCRIPTION
    } data_values_;

    // QAbstractItemModel interface
    virtual int rowCount(const QModelIndex & parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex & parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex & idx, int role = Qt::DisplayRole) const;
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role);
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const;

    void deleteEntry(QModelIndex idx);

    int findByName(QString name);
    QModelIndex addNewProfile(QString name);
    QModelIndex duplicateEntry(QModelIndex idx);

    void doResetModel();
    bool resetDefault() const;

    QModelIndex activeProfile() const;

    GList * at(int row) const;

    static bool checkNameValidity(QString name, QString *msg = Q_NULLPTR);
    QList<int> findAllByNameAndVisibility(QString name, bool isGlobal = false);

private:
    QList<profile_def *> profiles_;
    QString set_profile_;
    bool reset_default_;

    void loadProfiles();
    GList * entry(profile_def *) const;

    int findByNameAndVisibility(QString name, bool isGlobal = false);
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
