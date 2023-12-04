/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ASTRINGLIST_LIST_MODEL_H
#define ASTRINGLIST_LIST_MODEL_H

#include <config.h>

#include <QAbstractTableModel>
#include <QModelIndex>
#include <QList>
#include <QStringList>
#include <QSortFilterProxyModel>
#include <QIdentityProxyModel>

class AStringListListModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit AStringListListModel(QObject * parent = Q_NULLPTR);
    virtual ~AStringListListModel();

    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    //
    // This is not protected because we may need to invoke it from
    // a wmem_map_foreach() callback implemented as an extern "C"
    // static member function of a subclass.  wmem_map_foreach() is
    // passed, as the user data, a pointer to the class instance to
    // which we want to append rows.
    //
    virtual void appendRow(const QStringList &, const QString & row_tooltip = QString(), const QModelIndex &parent = QModelIndex());

protected:
    virtual QStringList headerColumns() const = 0;

private:
    QList<QStringList> display_data_;
    QStringList tooltip_data_;
};

class AStringListListSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:

    enum AStringListListFilterType
    {
        FilterByContains = 0,
        FilterByStart,
        FilterByEquivalent,
        FilterNone
    };
    Q_ENUM(AStringListListFilterType)

    explicit AStringListListSortFilterProxyModel(QObject * parent = Q_NULLPTR);

    virtual bool lessThan(const QModelIndex &left, const QModelIndex &right) const;
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;
    virtual bool filterAcceptsColumn(int column, const QModelIndex &sourceParent) const;

    void setFilterType(AStringListListFilterType type, int column = -1);

    void setColumnToFilter(int);
    void setColumnsToFilter(QList<int>);
    void clearColumnsToFilter();

    void clearHiddenColumns();
    void setColumnToHide(int col);

    void clearNumericColumns();
    void setColumnAsNumeric(int col);

public slots:
    void setFilter(const QString&);

private:
    QString filter_;
    QMap<int, AStringListListFilterType> types_;
    QList<int> columnsToFilter_;
    QList<int> hiddenColumns_;
    QList<int> numericColumns_;
};

class AStringListListUrlProxyModel : public QIdentityProxyModel
{
public:
    explicit AStringListListUrlProxyModel(QObject * parent = Q_NULLPTR);

    void setUrlColumn(int);
    bool isUrlColumn(int) const;

    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

private:
    QList<int> urls_;
};

#endif // ASTRINGLIST_LIST_MODEL_H
