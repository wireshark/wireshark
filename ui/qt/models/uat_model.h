/** @file
 *
 * Data model for UAT records.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UAT_MODEL_H
#define UAT_MODEL_H

#include <config.h>

#include <QAbstractItemModel>
#include <QList>
#include <QMap>
#include <epan/uat.h>

/**
 * @brief Table model for representing and managing User Accessible Tables (UAT).
 */
class UatModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new UatModel object using a UAT structure.
     * @param parent The parent object.
     * @param uat Pointer to the UAT structure.
     */
    UatModel(QObject *parent, uat_t *uat = 0);

    /**
     * @brief Constructs a new UatModel object using a UAT table name.
     * @param parent The parent object.
     * @param tableName The name of the UAT table to load.
     */
    UatModel(QObject *parent, QString tableName);

    /**
     * @brief Returns the item flags for a given index.
     * @param index The model index.
     * @return The item flags (e.g., selectable, editable).
     */
    Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Retrieves data for a given index and role.
     * @param index The model index.
     * @param role The requested data role.
     * @return The data as a QVariant.
     */
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves header data for the table.
     * @param section The column or row index.
     * @param orientation The orientation of the header.
     * @param role The requested data role.
     * @return The header data as a QVariant.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    /**
     * @brief Returns the number of rows under a given parent.
     * @param parent The parent model index.
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns under a given parent.
     * @param parent The parent model index.
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Sets the data for a specific index.
     * @param index The model index.
     * @param value The new value to set.
     * @param role The role for the data being set.
     * @return True if successful, false otherwise.
     */
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;

    /**
     * @brief Inserts a specified number of rows into the model.
     * @param row The starting row index.
     * @param count The number of rows to insert.
     * @param parent The parent model index.
     * @return True if successful, false otherwise.
     */
    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;

    /**
     * @brief Removes a specified number of rows from the model.
     * @param row The starting row index.
     * @param count The number of rows to remove.
     * @param parent The parent model index.
     * @return True if successful, false otherwise.
     */
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;

    /**
     * @brief Appends a new entry to the end of the table.
     * @param row A list of variants representing the new row data.
     * @return The model index of the newly appended row.
     */
    QModelIndex appendEntry(QVariantList row);

    /**
     * @brief Copies an existing row and inserts the copy.
     * @param original The model index of the row to copy.
     * @return The model index of the new copied row.
     */
    QModelIndex copyRow(QModelIndex original);

    /**
     * @brief Moves a row from one position to another.
     * @param src_row The source row index.
     * @param dst_row The destination row index.
     * @return True if the move was successful, false otherwise.
     */
    bool moveRow(int src_row, int dst_row);

    /**
     * @brief Moves multiple rows from one position to another.
     * @param sourceParent The source parent index.
     * @param sourceRow The starting source row index.
     * @param count The number of rows to move.
     * @param destinationParent The destination parent index.
     * @param destinationChild The destination row index.
     * @return True if the move was successful, false otherwise.
     */
    bool moveRows(const QModelIndex &sourceParent, int sourceRow, int count, const QModelIndex &destinationParent, int destinationChild) override;

    //Drag & drop functionality
    /**
     * @brief Returns the supported drag and drop actions for the model.
     * @return The supported drop actions.
     */
    Qt::DropActions supportedDropActions() const override;

    /**
     * @brief Handles dropped MIME data to perform drag and drop operations.
     * @param data The dropped MIME data.
     * @param action The drop action requested.
     * @param row The target row.
     * @param column The target column.
     * @param parent The target parent index.
     * @return True if the drop was successfully handled, false otherwise.
     */
    bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) override;

    /**
     * @brief Reloads the UAT data from the underlying structure.
     */
    void reloadUat();

    /**
     * @brief Checks if any records in the model currently have validation errors.
     * @return True if there are errors, false otherwise.
     */
    bool hasErrors() const;

    /**
     * @brief Clears all entries from the model.
     */
    void clearAll();

    /**
     * If the UAT has changed, save the contents to file and invoke the UAT
     * post_update_cb.
     *
     * @param error An error while saving changes, if any.
     * @return true if anything changed, false otherwise.
     */
    bool applyChanges(QString &error);

    /**
     * Undo any changes to the UAT.
     *
     * @param error An error while restoring the original UAT, if any.
     * @return true if anything changed, false otherwise.
     */
    bool revertChanges(QString &error);

    /**
     * @brief Finds the first row containing specific content in a given column.
     * @param columnContent The content to search for.
     * @param columnToCheckAgainst The column index to search within.
     * @param role The data role to compare against.
     * @return The model index of the found row, or an invalid index if not found.
     */
    QModelIndex findRowForColumnContent(QVariant columnContent, int columnToCheckAgainst, int role = Qt::DisplayRole);

private:
    /**
     * @brief Validates the contents of a specific field.
     * @param row The row index.
     * @param col The column index.
     * @param error Pointer to a string to store any validation error message.
     * @return True if the field is valid, false otherwise.
     */
    bool checkField(int row, int col, char **error) const;

    /**
     * @brief Validates an entire row and returns a list of columns with errors.
     * @param row The row index.
     * @return A list of column indices containing validation errors.
     */
    QList<int> checkRow(int row);

    /**
     * @brief Loads data from a UAT structure into the model.
     * @param uat Pointer to the UAT structure.
     */
    void loadUat(uat_t * uat = 0);

    /**
     * @brief Internal helper function to move a row.
     * @param src_row The source row index.
     * @param dst_row The destination row index.
     * @return True if successful.
     */
    bool moveRowPrivate(int src_row, int dst_row);

    /** @brief Pointer to the underlying UAT structure. */
    uat_t *uat_;

    /** @brief Flag indicating if an apply operation is currently in progress. */
    bool applying_;

    /** @brief Vector tracking which records have been modified. */
    QVector<bool> dirty_records;

    /** @brief Vector storing validation error messages per row and column. */
    QVector<QMap<int, QString> > record_errors;
};
#endif // UAT_MODEL_H
