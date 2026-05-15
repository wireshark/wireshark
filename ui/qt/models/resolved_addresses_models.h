/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RESOLVED_ADDRESSES_MODELS_H
#define RESOLVED_ADDRESSES_MODELS_H

#include <ui/qt/models/astringlist_list_model.h>

#include <QAbstractListModel>
#include <QSortFilterProxyModel>

/**
 * @brief A model managing a list of Ethernet addresses for UI display.
 */
class EthernetAddressModel : public AStringListListModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new EthernetAddressModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    EthernetAddressModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Retrieves the filterable values for the model.
     * @return A list of filter strings.
     */
    QStringList filterValues() const;

protected:
    /**
     * @brief Retrieves the header column titles for the model.
     * @return A list of header column strings.
     */
    QStringList headerColumns() const override;

    /**
     * @brief Populates the model with Ethernet address data.
     */
    void populate();

};

/**
 * @brief Defines the column indices for the PortsModel.
 */
enum PortsModelColumns
{
    PORTS_COL_NAME,       /**< The name or service associated with the port. */
    PORTS_COL_PORT,       /**< The port number column. */
    PORTS_COL_PROTOCOL    /**< The protocol used by the port (e.g., TCP or UDP). */
};

/**
 * @brief A model managing a list of network ports for UI display.
 */
class PortsModel : public AStringListListModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new PortsModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    PortsModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Retrieves the filterable values for the model.
     * @return A list of filter strings.
     */
    QStringList filterValues() const;

protected:
    /**
     * @brief Retrieves the header column titles for the model.
     * @return A list of header column strings.
     */
    QStringList headerColumns() const override;

    /**
     * @brief Populates the model with port data.
     */
    void populate();

};

#endif // RESOLVED_ADDRESSES_MODELS_H
