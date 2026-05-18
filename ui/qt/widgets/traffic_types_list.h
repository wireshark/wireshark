/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRAFFIC_TYPES_LIST_H
#define TRAFFIC_TYPES_LIST_H

#include "config.h"

#include <QTreeView>
#include <QAbstractListModel>
#include <QMap>
#include <QList>
#include <QString>
#include <QSortFilterProxyModel>

/**
 * @brief Data record for a single row in the traffic-types protocol list,
 *        storing a protocol's numeric ID, display name, and selection state.
 */
class TrafficTypesRowData
{
public:
    /**
     * @brief Constructs a row data record for the given protocol.
     * @param protocol Numeric protocol ID.
     * @param name     Human-readable protocol name.
     */
    TrafficTypesRowData(int protocol, QString name);

    /**
     * @brief Returns the numeric protocol ID.
     * @return Protocol ID.
     */
    int protocol() const;

    /**
     * @brief Returns the human-readable protocol name.
     * @return Protocol display name.
     */
    QString name() const;

    /**
     * @brief Returns whether this protocol is currently checked (selected).
     * @return @c true if checked.
     */
    bool checked() const;

    /**
     * @brief Sets the checked (selected) state of this protocol.
     * @param checked @c true to select; @c false to deselect.
     */
    void setChecked(bool checked);

private:
    int     _protocol; /**< Numeric protocol ID. */
    QString _name;     /**< Human-readable protocol name. */
    bool    _checked;  /**< Whether the protocol is currently selected. */
};


/**
 * @brief List model that exposes all registered traffic-tap protocols with
 *        checkable rows, backed by a recent-protocol GList for persistence.
 */
class TrafficTypesModel : public QAbstractListModel
{
    Q_OBJECT

public:
    /**
     * @brief Custom Qt::UserRole values for retrieving protocol data from the model.
     */
    enum {
        TRAFFIC_PROTOCOL   = Qt::UserRole, /**< Returns the numeric protocol ID. */
        TRAFFIC_IS_CHECKED,                /**< Returns the checked state as a bool. */
    } eTrafficUserData;

    /**
     * @brief Column indices for the traffic-types table view.
     */
    enum {
        COL_CHECKED,  /**< Checkbox column indicating whether the protocol is selected. */
        COL_NAME,     /**< Protocol display name column. */
        COL_NUM,      /**< Total number of data columns. */
        COL_PROTOCOL, /**< Numeric protocol ID column (hidden/internal). */
    } eTrafficColumnNames;

    /**
     * @brief Constructs the model from the full set of registered tap protocols.
     * @param recentList Pointer to the recent-protocols GList used to initialise
     *                   checked states and updated when selections change.
     * @param parent     Optional parent QObject.
     */
    TrafficTypesModel(GList **recentList, QObject *parent = nullptr);

    /**
     * @brief Returns the number of protocol rows in the model.
     * @param parent Unused; must be an invalid index for list models.
     * @return Number of rows.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns in the model.
     * @param parent Unused; must be an invalid index for list models.
     * @return Number of columns (COL_NUM).
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns data for the given index and role.
     * @param idx  Model index of the cell to query.
     * @param role Qt item data role (Qt::DisplayRole, Qt::CheckStateRole, UserRole, etc.).
     * @return The requested data, or an invalid QVariant if not applicable.
     */
    virtual QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const override;

    /**
     * @brief Returns header labels for the traffic-types columns.
     * @param section     Column or row index.
     * @param orientation Qt::Horizontal for column headers; Qt::Vertical for row headers.
     * @param role        Qt item data role.
     * @return Header label string, or an invalid QVariant if not applicable.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Sets data for the given index and role, updating the checked state
     *        and emitting protocolsChanged() when the selection changes.
     * @param idx   Model index of the cell to modify.
     * @param value New value to apply.
     * @param role  Qt item data role; only Qt::CheckStateRole is handled.
     * @return @c true if the data was successfully set.
     */
    virtual bool setData(const QModelIndex &idx, const QVariant &value, int role) override;

    /**
     * @brief Returns the item flags for the given index.
     * @param idx Model index to query.
     * @return Flags including Qt::ItemIsUserCheckable for checkable rows.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &idx) const override;

    /**
     * @brief Returns the list of currently checked (selected) protocol IDs.
     * @return List of selected protocol IDs.
     */
    QList<int> protocols() const;

public slots:
    /**
     * @brief Replaces the current selection with the given protocol IDs and emits
     *        protocolsChanged().
     * @param protocols List of protocol IDs to select.
     */
    void selectProtocols(QList<int> protocols);

signals:
    /**
     * @brief Emitted whenever the set of checked protocols changes.
     * @param protocols Updated list of selected protocol IDs.
     */
    void protocolsChanged(QList<int> protocols);

private:
    QList<TrafficTypesRowData> _allTaps;    /**< All available tap protocol rows. */
    GList                    **_recentList; /**< Pointer to the recent-protocols GList for persistence. */
};


/**
 * @brief Sort/filter proxy model for TrafficTypesModel that supports
 *        case-insensitive name filtering and protocol-name–aware sorting.
 */
class TrafficListSortModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the sort/filter proxy model.
     * @param parent Optional parent QObject.
     */
    TrafficListSortModel(QObject *parent = nullptr);

    /**
     * @brief Sets the text filter used to show only protocols whose name contains
     *        the given string (case-insensitive). Pass an empty string to show all.
     * @param filter Filter string; empty clears the filter.
     */
    void setFilter(QString filter = QString());

protected:
    /**
     * @brief Compares two rows for sorting, using protocol name for the name column
     *        and numeric ordering for the protocol-ID column.
     * @param source_left  Index of the left-hand row in the source model.
     * @param source_right Index of the right-hand row in the source model.
     * @return @c true if @p source_left should sort before @p source_right.
     */
    virtual bool lessThan(const QModelIndex &source_left,
                          const QModelIndex &source_right) const override;

    /**
     * @brief Determines whether a source row should be visible given the current filter.
     * @param source_row    Row index in the source model.
     * @param source_parent Parent index in the source model (unused for list models).
     * @return @c true if the row's protocol name contains the filter string.
     */
    virtual bool filterAcceptsRow(int source_row,
                                  const QModelIndex &source_parent) const override;

private:
    QString _filter; /**< Current case-insensitive name filter string. */
};


/**
 * @brief Tree view widget that presents a filterable, sortable, checkable list
 *        of traffic-tap protocols and forwards selection changes to interested parties.
 */
class TrafficTypesList : public QTreeView
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the TrafficTypesList view.
     * @param parent Optional parent widget.
     */
    TrafficTypesList(QWidget *parent = nullptr);

    /**
     * @brief Initialises the underlying model with the given protocol group name
     *        and recent-list pointer, then resets the view.
     * @param name       Display name for this group of protocols (e.g. "Conversations").
     * @param recentList Pointer to the recent-protocols GList for the group.
     */
    void setProtocolInfo(QString name, GList **recentList);

    /**
     * @brief Returns the list of protocol IDs tracked by this view.
     * @param onlySelected @c true to return only checked (selected) protocol IDs;
     *                     @c false to return all protocol IDs.
     * @return List of protocol IDs.
     */
    QList<int> protocols(bool onlySelected = false) const;

public slots:
    /**
     * @brief Checks the given protocol IDs and unchecks all others.
     * @param protocols List of protocol IDs to select.
     */
    void selectProtocols(QList<int> protocols);

    /**
     * @brief Applies a name filter to the visible protocol list.
     * @param filter Filter string; empty string shows all protocols.
     */
    void filterList(QString filter);

signals:
    /**
     * @brief Emitted when the set of checked protocols changes.
     * @param protocols Updated list of selected protocol IDs.
     */
    void protocolsChanged(QList<int> protocols);

    /** @brief Emitted to request that any external filter input be cleared. */
    void clearFilterList();

private:
    QString               _name;       /**< Display name for this protocol group. */
    TrafficTypesModel    *_model;      /**< Source data model for protocol rows. */
    TrafficListSortModel *_sortModel;  /**< Sort/filter proxy applied on top of _model. */
};

#endif // TRAFFIC_TYPES_LIST_H
