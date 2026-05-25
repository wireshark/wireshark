/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILESET_ENTRY_MODEL_H
#define FILESET_ENTRY_MODEL_H

#include <config.h>

#include <fileset.h>

#include <QAbstractItemModel>
#include <QModelIndex>
#include <QVector>

/**
 * @brief A model managing a list of fileset entries for UI display.
 */
class FilesetEntryModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FilesetEntryModel.
     * @param parent The parent QObject, defaults to 0.
     */
    explicit FilesetEntryModel(QObject * parent = 0);

    /**
     * @brief Generates an index for the given row and column.
     * @param row The row index.
     * @param column The column index.
     * @return The corresponding model index.
     */
    QModelIndex index(int row, int column, const QModelIndex & = QModelIndex()) const override;

    /**
     * @brief Retrieves the parent of a given index. Everything is under the root.
     * @return An invalid QModelIndex since all items are top-level.
     */
    virtual QModelIndex parent(const QModelIndex &) const override { return QModelIndex(); }

    /**
     * @brief Returns the number of rows under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns under a given parent.
     * @return The number of columns.
     */
    virtual int columnCount(const QModelIndex &) const override { return ColumnCount; }

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Appends a new entry to the fileset model.
     * @param entry Pointer to the fileset entry to add.
     */
    virtual void appendEntry(const fileset_entry *entry);

    /**
     * @brief Retrieves the fileset entry at a specific row.
     * @param row The row index.
     * @return Pointer to the fileset entry, or NULL if not found.
     */
    const fileset_entry *getRowEntry(int row) const { return entries_.value(row, NULL); }

    /**
     * @brief Retrieves the total number of entries in the model.
     * @return The entry count.
     */
    int entryCount() const { return static_cast<int>(entries_.count()); }

    /**
     * @brief Calls fileset_delete and clears our model data.
     */
    void clear();

private:
    /** The list of fileset entries managed by the model. */
    QVector<const fileset_entry *> entries_;

    /**
     * @brief Enumerates the columns used in the fileset model.
     */
    enum Column {
        Name,        /**< The name of the file. */
        Created,     /**< The creation time of the file. */
        Modified,    /**< The modification time of the file. */
        Size,        /**< The size of the file. */
        ColumnCount  /**< The total number of columns. */
    };

    /**
     * @brief Extracts and formats a date from a filename string.
     * @param name The filename to parse.
     * @return The formatted date string.
     */
    QString nameToDate(const char *name) const;

    /**
     * @brief Converts a time_t value to a formatted string.
     * @param clock The time value to convert.
     * @return The formatted time string.
     */
    QString time_tToString(time_t clock) const;
};

#endif // FILESET_ENTRY_MODEL_H
