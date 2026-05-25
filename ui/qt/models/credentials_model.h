/** @file
 *
 * Copyright 2019 - Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CREDENTIALS_MODELS_H
#define CREDENTIALS_MODELS_H

#include <QAbstractListModel>
#include <QList>

#include <epan/tap.h>
#include <capture_file.h>
#include <epan/credentials.h>

/**
 * @brief A list model for managing and displaying extracted network credentials.
 */
class CredentialsModel : public QAbstractListModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CredentialsModel.
     * @param parent The parent QObject.
     */
    CredentialsModel(QObject *parent);

    /**
     * @brief Destroys the CredentialsModel.
     */
    ~CredentialsModel();

    /**
     * @brief Returns the number of rows (credentials) under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of credential records.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const  override;

    /**
     * @brief Returns the number of columns (data fields) for a credential.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves data from the model for the given index and role.
     * @param index The model index to retrieve data for.
     * @param role The requested data role (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves header data for the given section, orientation, and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The requested data role (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Adds a new credential record to the model.
     * @param rec Pointer to the core tap credential structure to add.
     */
    void addRecord(const tap_credential_t *rec);

    /**
     * @brief Clears all credential records from the model.
     */
    void clear();

    /**
     * @brief Enumeration of column identifiers in the credentials model.
     */
    enum {
        COL_NUM,       /**< Column for the packet number. */
        COL_PROTO,     /**< Column for the protocol name. */
        COL_USERNAME,  /**< Column for the username. */
        COL_INFO       /**< Column for additional credential information. */
    };

    /**
     * @brief Enumeration of custom roles used in the credentials model.
     */
    enum {
        ColumnHFID = Qt::UserRole + 1 /**< Custom role for retrieving the header field ID. */
    };

private:
    /** Internal list storing pointers to the extracted tap credentials. */
    QList<tap_credential_t*> credentials_;

};

#endif // CREDENTIALS_MODELS_H
