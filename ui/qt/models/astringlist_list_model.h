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

/**
 * @brief A table model backed by a list of string lists.
 *
 * Each row is represented as a @c QStringList.
 */
class AStringListListModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    /** @brief Construct an empty model.
     *  @param parent The parent object. */
    explicit AStringListListModel(QObject * parent = Q_NULLPTR);

    /** @brief Destroy the model. */
    virtual ~AStringListListModel();

    /** @brief Return the number of rows in the model.
     *  @param parent Unused; present for API compatibility.
     *  @return The number of rows. */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /** @brief Return the number of columns in the model.
     *  @param parent Unused; present for API compatibility.
     *  @return The number of columns. */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /** @brief Return data for the given index and role.
     *  @param index The model index to query.
     *  @param role  The data role.
     *  @return The data for the given index and role, or an invalid
     *          @c QVariant if the index or role is unsupported. */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

    /** @brief Return header data for the given section, orientation, and role.
     *  @param section     The section index.
     *  @param orientation The header orientation.
     *  @param role        The data role.
     *  @return The header data, or an invalid @c QVariant if unsupported. */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    /**
     * @brief Append a row to the model.
     *
     * This method is public rather than protected because it may need to be
     * invoked from a wmem_map_foreach() callback implemented as an
     * @c extern @c "C" static member function of a subclass.
     * wmem_map_foreach() is passed, as the user data, a pointer to the
     * class instance to which rows should be appended.
     *
     * @param row         The string list representing the new row's data.
     * @param row_tooltip The tooltip text for the new row.
     * @param parent      Unused; present for API compatibility.
     */
    virtual void appendRow(const QStringList &row, const QString & row_tooltip = QString(), const QModelIndex &parent = QModelIndex());


protected:
    /** @brief Return the list of column header strings.
     *  @return A @c QStringList of column header names. */
    virtual QStringList headerColumns() const = 0;

private:
    QList<QStringList> display_data_;   /**< Row data for display. */
    QStringList tooltip_data_;          /**< Per-row tooltip strings. */
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
