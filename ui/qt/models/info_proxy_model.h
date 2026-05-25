/** @file
 *
 * Proxy model for displaying an info text at the end of any QAbstractListModel
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INFO_PROXY_MODEL_H
#define INFO_PROXY_MODEL_H

#include <config.h>

#include <QStringList>
#include <QIdentityProxyModel>

/**
 * @brief Proxy model that appends additional information rows to a source model.
 */
class InfoProxyModel : public QIdentityProxyModel
{
public:
    /**
     * @brief Constructs an InfoProxyModel.
     * @param parent The parent object.
     */
    explicit InfoProxyModel(QObject * parent = 0);

    /**
     * @brief Destroys the InfoProxyModel.
     */
    ~InfoProxyModel();

    /**
     * @brief Returns the number of rows under the given parent.
     * @param parent The parent model index.
     * @return The row count including the appended information rows.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the data stored under the given role for the item referred to by the index.
     * @param index The model index.
     * @param role The item role.
     * @return The data for the specified role.
     */
    virtual QVariant data (const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Returns the item flags for the given index.
     * @param index The model index.
     * @return The item flags.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Returns the index of the item in the model specified by the given row, column and parent index.
     * @param row The row number.
     * @param column The column number.
     * @param parent The parent model index.
     * @return The created model index.
     */
    virtual QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Maps a proxy index to the corresponding source model index.
     * @param proxyIndex The proxy model index.
     * @return The source model index.
     */
    virtual QModelIndex mapToSource(const QModelIndex &proxyIndex) const override;

    /**
     * @brief Maps a source model index to the corresponding proxy model index.
     * @param fromIndex The source model index.
     * @return The proxy model index.
     */
    virtual QModelIndex mapFromSource(const QModelIndex &fromIndex) const override;

    /**
     * @brief Appends an information string to the model.
     * @param info The information string to append.
     */
    void appendInfo(QString info);

    /**
     * @brief Clears all appended information strings.
     */
    void clearInfos();

    /**
     * @brief Sets the column used for displaying the information.
     * @param column The column index.
     */
    void setColumn(int column);

private:

    int column_; /**< The column index where information is displayed. */

    QStringList infos_; /**< The list of appended information strings. */
};

#endif // INFO_PROXY_MODEL_H
