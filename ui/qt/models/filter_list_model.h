/** @file
 *
 * Model for all filter types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_LIST_MODEL_h
#define FILTER_LIST_MODEL_h

#include <config.h>

#include <QAbstractListModel>
#include <QList>
#include <QStringList>

/**
 * @brief A list model for managing capture filters, display filters, and display macros.
 */
class FilterListModel : public QAbstractListModel
{
    Q_OBJECT

public:
    /**
     * @brief Defines the type of filter list.
     */
    enum FilterListType {
        Display,       /**< A list of display filters. */
        Capture,       /**< A list of capture filters. */
        DisplayMacro,  /**< A list of display macros. */
    };

    /**
     * @brief Constructs a new FilterListModel with a specific type.
     * @param type The type of filter list (defaults to FilterListModel::Display).
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit FilterListModel(FilterListType type = FilterListModel::Display, QObject * parent = Q_NULLPTR);

    /**
     * @brief Constructs a new FilterListModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit FilterListModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Enumerates the columns for the filter list model.
     */
    enum {
        ColumnName,       /**< The filter name column. */
        ColumnExpression  /**< The filter expression column. */
    };

    /**
     * @brief Represents a single filter entry with a name and an expression.
     */
    struct FilterListValue {
        QString name;       /**< The name of the filter. */
        QString expression; /**< The filter expression string. */

        /**
         * @brief Constructs a new FilterListValue.
         * @param n The name of the filter.
         * @param e The expression of the filter.
         */
        FilterListValue(QString n, QString e) : name(n), expression(e) {}
    };

    /**
     * @brief Sets the filter type for this model.
     * @param type The filter list type to set.
     */
    void setFilterType(FilterListModel::FilterListType type);

    /**
     * @brief Retrieves the current filter type of the model.
     * @return The filter list type.
     */
    FilterListModel::FilterListType filterType() const;

    /**
     * @brief Finds a filter by its name.
     * @param name The name to search for.
     * @return The model index of the found filter, or an invalid index if not found.
     */
    QModelIndex findByName(QString name);

    /**
     * @brief Finds a filter by its expression.
     * @param expression The expression to search for.
     * @return The model index of the found filter, or an invalid index if not found.
     */
    QModelIndex findByExpression(QString expression);

    /**
     * @brief Adds a new filter to the list.
     * @param name The name of the new filter.
     * @param expression The expression string of the new filter.
     * @return The model index of the newly added filter.
     */
    QModelIndex addFilter(QString name, QString expression);

    /**
     * @brief Removes a filter at the specified index.
     * @param idx The model index of the filter to remove.
     */
    void removeFilter(QModelIndex idx);

    /**
     * @brief Saves the current list of filters to persistent storage.
     */
    void saveList();

    /**
     * @brief Returns the number of rows under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Sets data in the model for a given index and role.
     * @param index The model index to update.
     * @param value The value to set.
     * @param role The role being edited.
     * @return True if successful, false otherwise.
     */
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role) override;

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves the item flags for a given index.
     * @param index The model index.
     * @return The item flags.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Retrieves the drop actions supported by the model.
     * @return The supported drop actions.
     */
    virtual Qt::DropActions supportedDropActions() const override;

    /**
     * @brief Retrieves the MIME types supported by the model for drag and drop operations.
     * @return A list of supported MIME types.
     */
    virtual QStringList mimeTypes() const override;

    /**
     * @brief Creates MIME data representing the given model indices.
     * @param indexes The list of model indices to encode.
     * @return A pointer to the created QMimeData.
     */
    virtual QMimeData *mimeData(const QModelIndexList &indexes) const override;

    /**
     * @brief Handles dropped MIME data to insert items into the model.
     * @param data The MIME data dropped.
     * @param action The drop action performed.
     * @param row The row where the drop occurred.
     * @param column The column where the drop occurred.
     * @param parent The parent model index.
     * @return True if the drop was successfully handled, false otherwise.
     */
    virtual bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) override;

private:

    /** The current type of the filter list. */
    FilterListModel::FilterListType type_;

    /** The underlying list storing the filter values. */
    QList<struct FilterListModel::FilterListValue> storage;

    /**
     * @brief Reloads the filter list from persistent storage.
     */
    void reload();
};

#endif // FILTER_LIST_MODEL_h
