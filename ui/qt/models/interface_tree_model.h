/** @file
 *
 * Model for the interface data for display in the interface frame
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_TREE_MODEL_H
#define INTERFACE_TREE_MODEL_H

#include <config.h>
#include <wireshark.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#include "ui/capture_globals.h"
#endif

#include <QAbstractTableModel>
#include <QList>
#include <QMap>
#include <QItemSelection>

typedef QList<int> PointList;

/*
 * When sorting, QSortFilterProxyModel creates its own mapping instead
 * of using the QModelIndex mapping with mapToSource to determine which
 * column in the proxy model maps to which column in the source. Its own
 * mapping is always done in order; this means that it's easier if all
 * the Views of this model keep the columns in the same relative order,
 * but can omit columns. (If you really need to change the order,
 * QHeaderView::swapSections() can be used.)
 */
enum InterfaceTreeColumns
{
    IFTREE_COL_EXTCAP,         // InterfaceFrame interfaceTree
    IFTREE_COL_EXTCAP_PATH,
    IFTREE_COL_HIDDEN,         // ManageInterfaceDialog localView
    IFTREE_COL_DISPLAY_NAME,   // InterfaceFrame interfaceTree
    IFTREE_COL_DESCRIPTION,    // ManageInterfaceDialog localView
    IFTREE_COL_NAME,           // ManageInterfaceDialog localView
    IFTREE_COL_COMMENT,        // ManageInterfaceDialog localView
    IFTREE_COL_STATS,          // InterfaceFrame interfaceTree
    IFTREE_COL_DLT,
    IFTREE_COL_PROMISCUOUSMODE,
    IFTREE_COL_TYPE,
    IFTREE_COL_ACTIVE,
    IFTREE_COL_SNAPLEN,
    IFTREE_COL_BUFFERLEN,
    IFTREE_COL_MONITOR_MODE,
    IFTREE_COL_CAPTURE_FILTER,
    IFTREE_COL_PIPE_PATH,      // ManageInterfaceDialog pipeView
    IFTREE_COL_MAX /* is not being displayed, it is the definition for the maximum numbers of columns */
};

/**
 * @brief A table model representing the system's available capture interfaces.
 */
class InterfaceTreeModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new InterfaceTreeModel.
     * @param parent The parent QObject.
     */
    InterfaceTreeModel(QObject *parent);

    /**
     * @brief Destroys the InterfaceTreeModel.
     */
    ~InterfaceTreeModel();

    /**
     * @brief Returns the number of rows (interfaces) under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns in the table model.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    QVariant data (const QModelIndex &index, int role = Qt::DisplayRole) const;

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested.
     * @return The header data.
     */
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    /**
     * @brief Triggers an update of the statistics (like sparklines) for a specific row.
     * @param row The row index of the interface to update.
     */
    void updateStatistic(unsigned int row);

#ifdef HAVE_LIBPCAP
    /**
     * @brief Sets the statistics cache used to query live interface metrics.
     * @param stat_cache Pointer to the if_stat_cache_t structure.
     */
    void setCache(if_stat_cache_t *stat_cache);

    /**
     * @brief Stops all active statistics gathering and polling for interfaces.
     */
    void stopStatistic();
#endif

    /**
     * @brief Retrieves any current interface-related error messages.
     * @return The error message string.
     */
    QString interfaceError();

    /**
     * @brief Retrieves the currently selected devices as an item selection.
     * @return A QItemSelection representing the selected interfaces.
     */
    QItemSelection selectedDevices();

    /**
     * @brief Updates the internal state of selected devices based on a UI selection.
     * @param sourceSelection The selection from the view.
     * @return True if the selection state changed successfully, false otherwise.
     */
    bool updateSelectedDevices(QItemSelection sourceSelection);

    /**
     * @brief Gets the content for a specific column and row directly.
     * @param idx The row index.
     * @param col The column index.
     * @param role The data role (defaults to Qt::DisplayRole).
     * @return The requested data variant.
     */
    QVariant getColumnContent(int idx, int col, int role = Qt::DisplayRole);

#ifdef HAVE_PCAP_REMOTE
    /**
     * @brief Checks if the interface at the given index is remote.
     * @param idx The row index.
     * @return True if the interface is remote, false otherwise.
     */
    bool isRemote(int idx);
#endif

    /** A default placeholder string for unavailable numeric values. */
    static const QString DefaultNumericValue;

public slots:
    /**
     * @brief Slot triggered when the global list of available interfaces changes.
     */
    void interfaceListChanged();

private:
    /**
     * @brief Generates a tooltip string detailing information about a specific interface.
     * @param idx The row index of the interface.
     * @return The tooltip string variant.
     */
    QVariant toolTipForInterface(int idx) const;

    /** Map storing a list of data points for sparkline generation per interface. */
    QMap<QString, PointList> points;

    /** Map tracking whether an interface is currently considered active for data polling. */
    QMap<QString, bool> active;

#ifdef HAVE_LIBPCAP
    /** Pointer to the core interface statistics cache. */
    if_stat_cache_t *stat_cache_;
#endif // HAVE_LIBPCAP
};

#endif // INTERFACE_TREE_MODEL_H
