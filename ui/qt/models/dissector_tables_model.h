/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISSECTOR_TABLES_MODEL_H
#define DISSECTOR_TABLES_MODEL_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <QSortFilterProxyModel>

/**
 * @brief Represents a single item in the dissector tables model, supporting tree structures.
 */
class DissectorTablesItem : public ModelHelperTreeItem<DissectorTablesItem>
{
public:
    /**
     * @brief Constructs a new DissectorTablesItem.
     * @param tableName The name of the dissector table.
     * @param dissectorDescription The description of the dissector.
     * @param parent The parent item in the tree.
     */
    DissectorTablesItem(QString tableName, QString dissectorDescription, DissectorTablesItem* parent);

    /**
     * @brief Destroys the DissectorTablesItem.
     */
    virtual ~DissectorTablesItem();

    /**
     * @brief Retrieves the table name associated with this item.
     * @return The table name string.
     */
    QString tableName() const {return tableName_;}

    /**
     * @brief Retrieves the dissector description associated with this item.
     * @return The dissector description string.
     */
    QString dissectorDescription() const {return dissectorDescription_;}

    /**
     * @brief Compares this item with another for sorting purposes.
     * @param right The other DissectorTablesItem to compare against.
     * @return True if this item is considered "less than" the right item, false otherwise.
     */
    virtual bool lessThan(DissectorTablesItem &right) const;

protected:
    /** The table name string. */
    QString tableName_;

    /** The dissector description string. */
    QString dissectorDescription_;
};

/**
 * @brief A tree model providing data for the registered dissector tables.
 */
class DissectorTablesModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DissectorTablesModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit DissectorTablesModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Destroys the DissectorTablesModel.
     */
    virtual ~DissectorTablesModel();

    /**
     * @brief Enumeration of the columns available in the model.
     */
    enum DissectorTablesColumn {
        colTableName = 0,           /**< Column for the table name. */
        colDissectorDescription,    /**< Column for the dissector description. */
        colLast                     /**< Maximum column index marker. */
    };

    /**
     * @brief Generates an index for the specified row and column.
     * @param row The row number.
     * @param column The column number.
     * @param parent The parent index (defaults to an invalid QModelIndex).
     * @return The generated model index.
     */
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves the parent index for the given index.
     * @param index The child model index.
     * @return The parent model index.
     */
    QModelIndex parent(const QModelIndex &index) const override;

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The requested data role.
     * @return The data associated with the index and role.
     */
    QVariant data(const QModelIndex &index, int role) const override;

    /**
     * @brief Returns the number of rows under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Populates the model with the currently registered dissector tables.
     */
    void populate();

private:
    /** Pointer to the root item of the model. */
    DissectorTablesItem* root_;
};

/**
 * @brief A proxy model that filters and sorts the DissectorTablesModel.
 */
class DissectorTablesProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DissectorTablesProxyModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit DissectorTablesProxyModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Determines whether a row from the source model should be visible.
     * @param sourceRow The row in the source model.
     * @param sourceParent The parent index in the source model.
     * @return True if the row is accepted by the current filter, false otherwise.
     */
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

    /**
     * @brief Retrieves header data, potentially adjusted dynamically.
     * @param section The column section.
     * @param orientation The header orientation.
     * @param role The requested data role (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    /**
     * @brief Adjusts the header based on the currently selected index.
     * @param currentIndex The active model index.
     */
    void adjustHeader(const QModelIndex &currentIndex);

    /**
     * @brief Sets the filter string used to screen items.
     * @param filter The filter text.
     */
    void setFilter(const QString& filter);

protected:
    /**
     * @brief Compares two source indices to determine their sort order.
     * @param source_left The first source index.
     * @param source_right The second source index.
     * @return True if the left item should appear before the right item.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;

    /**
     * @brief Checks if an individual item is accepted by the filter.
     * @param item The DissectorTablesItem to check.
     * @return True if accepted, false otherwise.
     */
    bool filterAcceptItem(DissectorTablesItem& item) const;

private:

    /** The dynamically determined table name string for header display. */
    QString tableName_;

    /** The dynamically determined description string for header display. */
    QString dissectorDescription_;

    /** The currently active filter string. */
    QString filter_;
};

#endif // DISSECTOR_TABLES_MODEL_H
