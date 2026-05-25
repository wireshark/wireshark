/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MANUF_TABLE_MODEL_H
#define MANUF_TABLE_MODEL_H

#include <QSortFilterProxyModel>
#include <QAbstractTableModel>
#include <QList>

#include <wireshark.h>
#include <epan/manuf.h>

/**
 * @brief A class representing a single manufacturer entry in the table.
 */
class ManufTableItem
{
public:
    /**
     * @brief Constructs a new ManufTableItem.
     * @param ptr Pointer to the manufacturer structure containing the data.
     */
    ManufTableItem(struct ws_manuf *ptr);

    /**
     * @brief Destroys the ManufTableItem.
     */
    ~ManufTableItem();

    /** The byte block representing the MAC prefix. */
    QByteArray block_bytes_;

    /** The string representation of the MAC prefix block. */
    QString block_name_;

    /** The short name of the manufacturer. */
    QString short_name_;

    /** The long, full vendor name of the manufacturer. */
    QString long_name_;
};

/**
 * @brief A table model for managing and displaying MAC address manufacturer data.
 */
class ManufTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ManufTableModel.
     * @param parent The parent QObject.
     */
    ManufTableModel(QObject *parent);

    /**
     * @brief Destroys the ManufTableModel.
     */
    ~ManufTableModel();

    /**
     * @brief Retrieves the number of rows in the model.
     * @param parent The parent model index, defaults to QModelIndex().
     * @return The number of rows.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves the number of columns in the model.
     * @param parent The parent model index, defaults to QModelIndex().
     * @return The number of columns.
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves the data stored under the given role for the item referred to by the index.
     * @param index The model index.
     * @param role The display role.
     * @return The data as a QVariant.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves the header data for the given section, orientation, and role.
     * @param section The section (column or row) index.
     * @param orientation The orientation (horizontal or vertical).
     * @param role The display role.
     * @return The header data as a QVariant.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Adds a new manufacturer record to the model.
     * @param ptr Pointer to the manufacturer structure to add.
     */
    void addRecord(struct ws_manuf *ptr);

    /**
     * @brief Clears all records from the model.
     */
    void clear();

    /**
     * @brief Enumeration of the columns available in the table.
     */
    enum {
        /** The column displaying the MAC address prefix. */
        COL_MAC_PREFIX,
        /** The column displaying the short name. */
        COL_SHORT_NAME,
        /** The column displaying the full vendor name. */
        COL_VENDOR_NAME,
        /** The total number of columns. */
        NUM_COLS,
    };

private:
    /** List of rows containing manufacturer data items. */
    QList<ManufTableItem *> rows_;
};

/**
 * @brief A proxy model for sorting and filtering manufacturer data.
 */
class ManufSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Enumeration of available filter types.
     */
    enum ManufProxyFilterType
    {
        /** No filter is applied. */
        FilterEmpty = 0,
        /** Filtering by MAC address. */
        FilterByAddress,
        /** Filtering by manufacturer name. */
        FilterByName,
    };
    Q_ENUM(ManufProxyFilterType)

    /**
     * @brief Constructs a new ManufSortFilterProxyModel.
     * @param parent The parent QObject.
     */
    ManufSortFilterProxyModel(QObject *parent);

    /**
     * @brief Determines if a row is accepted by the current filter.
     * @param source_row The index of the row in the source model.
     * @param source_parent The parent index in the source model.
     * @return True if the row is accepted, false otherwise.
     */
    virtual bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override;

public slots:
    /**
     * @brief Sets the filter to match a specific MAC address.
     * @param bytes The byte array representing the MAC address to filter by.
     */
    void setFilterAddress(const QByteArray& bytes);

    /**
     * @brief Sets the filter to match a specific manufacturer name.
     * @param name The regular expression to filter the names by.
     */
    void setFilterName(QRegularExpression& name);

    /**
     * @brief Clears the active filter.
     */
    void clearFilter();

private:
    /** The current active filter type. */
    ManufProxyFilterType filter_type_;

    /** The byte array used for address filtering. */
    QByteArray filter_bytes_;

    /** The regular expression used for name filtering. */
    QRegularExpression filter_name_;

    /**
     * @brief Helper function to determine if a row passes the address filter.
     * @param source_row The index of the row in the source model.
     * @param source_parent The parent index in the source model.
     * @return True if the address filter accepts the row, false otherwise.
     */
    bool filterAddressAcceptsRow(int source_row, const QModelIndex& source_parent) const;

    /**
     * @brief Helper function to determine if a row passes the name filter.
     * @param source_row The index of the row in the source model.
     * @param source_parent The parent index in the source model.
     * @return True if the name filter accepts the row, false otherwise.
     */
    bool filterNameAcceptsRow(int source_row, const QModelIndex& source_parent) const;
};

#endif
