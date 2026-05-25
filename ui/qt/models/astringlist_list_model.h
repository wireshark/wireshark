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
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /** @brief Return the number of columns in the model.
     *  @param parent Unused; present for API compatibility.
     *  @return The number of columns. */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /** @brief Return data for the given index and role.
     *  @param index The model index to query.
     *  @param role  The data role.
     *  @return The data for the given index and role, or an invalid
     *          @c QVariant if the index or role is unsupported. */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /** @brief Return header data for the given section, orientation, and role.
     *  @param section     The section index.
     *  @param orientation The header orientation.
     *  @param role        The data role.
     *  @return The header data, or an invalid @c QVariant if unsupported. */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

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
/**
 * @brief A sort/filter proxy model for AStringListList-based models.
 */
class AStringListListSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    /**
     * @brief Text filter match mode applied to a column.
     */
    enum AStringListListFilterType {
        FilterByContains   = 0, /**< Row is accepted if the column value contains the filter string. */
        FilterByStart,          /**< Row is accepted if the column value starts with the filter string. */
        FilterByEquivalent,     /**< Row is accepted if the column value equals the filter string. */
        FilterNone              /**< No filtering is applied to this column. */
    };
    Q_ENUM(AStringListListFilterType)

    /**
     * @brief Construct an AStringListListSortFilterProxyModel.
     * @param parent The parent QObject.
     */
    explicit AStringListListSortFilterProxyModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Compare two rows for sorting.
     *
     * @param left  Source model index of the left-hand item.
     * @param right Source model index of the right-hand item.
     * @return true if @p left should sort before @p right.
     */
    virtual bool lessThan(const QModelIndex &left, const QModelIndex &right) const override;

    /**
     * @brief Determine whether a source row passes the current filter.
     *
     * @param sourceRow    Row index in the source model.
     * @param sourceParent Parent index in the source model.
     * @return true if the row should be shown.
     */
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

    /**
     * @brief Determine whether a source column should be visible.
     *
     * @param column       Column index in the source model.
     * @param sourceParent Parent index in the source model (unused).
     * @return true if the column should be shown; false if it is hidden.
     */
    virtual bool filterAcceptsColumn(int column, const QModelIndex &sourceParent) const override;

    /**
     * @brief Set the filter match mode for a column.
     * @param type   The match mode to apply.
     * @param column The column to configure, or -1 to apply @p type to all
     *               columns in @c columnsToFilter_.
     */
    void setFilterType(AStringListListFilterType type, int column = -1);

    /**
     * @brief Set a single column to include in filter evaluation.
     *
     * @param column The column index to filter on.
     */
    void setColumnToFilter(int column);

    /**
     * @brief Set multiple columns to include in filter evaluation.
     * @param columns The list of column indices to filter on.
     */
    void setColumnsToFilter(QList<int> columns);

    /**
     * @brief Clear the list of columns included in filter evaluation.
     */
    void clearColumnsToFilter();

    /**
     * @brief Clear the list of hidden columns, making all columns visible.
     */
    void clearHiddenColumns();

    /**
     * @brief Hide a column from the view.
     * @param col The column index to hide.
     */
    void setColumnToHide(int col);

    /**
     * @brief Clear the list of numeric columns, reverting all to string sort.
     */
    void clearNumericColumns();

    /**
     * @brief Mark a column for numeric rather than lexicographic sorting.
     * @param col The column index to treat as numeric.
     */
    void setColumnAsNumeric(int col);

public slots:
    /**
     * @brief Set the filter string and trigger re-evaluation of visible rows.
     * @param filter The text to filter on; an empty string shows all rows.
     */
    void setFilter(const QString &filter);

private:
    QString filter_;                          /**< Current filter string. */
    QMap<int, AStringListListFilterType> types_; /**< Per-column filter match modes. */
    QList<int> columnsToFilter_;              /**< Columns evaluated during filterAcceptsRow(). */
    QList<int> hiddenColumns_;                /**< Columns hidden by filterAcceptsColumn(). */
    QList<int> numericColumns_;               /**< Columns sorted numerically by lessThan(). */
};


/**
 * @brief An identity proxy model that exposes selected columns as clickable URLs.
 */
class AStringListListUrlProxyModel : public QIdentityProxyModel
{
public:
    /**
     * @brief Construct an AStringListListUrlProxyModel.
     * @param parent The parent QObject.
     */
    explicit AStringListListUrlProxyModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Register a column whose values should be treated as URLs.
     * @param column The column index to mark as a URL column.
     */
    void setUrlColumn(int column);

    /**
     * @brief Return whether a column is registered as a URL column.
     * @param column The column index to query.
     * @return true if @p column was registered via setUrlColumn().
     */
    bool isUrlColumn(int column) const;

    /**
     * @brief Return data for @p index, adding URL role data for URL columns.
     *
     * @param index The model index to query.
     * @param role  The data role.
     * @return The requested data, or an invalid QVariant if unavailable.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

private:
    QList<int> urls_; /**< Indices of columns whose values are treated as URLs. */
};

#endif // ASTRINGLIST_LIST_MODEL_H
