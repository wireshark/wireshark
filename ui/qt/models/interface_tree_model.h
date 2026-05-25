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

class InterfaceStatistics;

/**
 * @brief Column indices for the interface tree model shared across interface-related views.
 *
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
    IFTREE_COL_EXTCAP,          /**< Extcap plugin indicator icon — InterfaceFrame interfaceTree */
    IFTREE_COL_EXTCAP_PATH,     /**< Filesystem path to the extcap executable */
    IFTREE_COL_HIDDEN,          /**< Whether the interface is hidden from the capture list — ManageInterfaceDialog localView */
    IFTREE_COL_DISPLAY_NAME,    /**< Human-readable display name for the interface — InterfaceFrame interfaceTree */
    IFTREE_COL_DESCRIPTION,     /**< OS-supplied interface description string — ManageInterfaceDialog localView */
    IFTREE_COL_NAME,            /**< System interface name (e.g. eth0, en0) — ManageInterfaceDialog localView */
    IFTREE_COL_COMMENT,         /**< User-editable free-text comment for the interface — ManageInterfaceDialog localView */
    IFTREE_COL_STATS,           /**< Live packet rate sparkline or traffic statistics — InterfaceFrame interfaceTree */
    IFTREE_COL_DLT,             /**< Selected data link type (DLT) for the interface */
    IFTREE_COL_PROMISCUOUSMODE, /**< Whether promiscuous mode capture is enabled */
    IFTREE_COL_TYPE,            /**< Interface type (e.g. wired, wireless, pipe, extcap) */
    IFTREE_COL_ACTIVE,          /**< Whether the interface is selected for the next capture */
    IFTREE_COL_SNAPLEN,         /**< Snapshot length (in bytes) applied to each captured packet */
    IFTREE_COL_BUFFERLEN,       /**< Kernel capture buffer size in megabytes */
    IFTREE_COL_MONITOR_MODE,    /**< Whether 802.11 monitor mode is enabled (wireless interfaces only) */
    IFTREE_COL_CAPTURE_FILTER,  /**< BPF capture filter string applied to this interface */
    IFTREE_COL_PIPE_PATH,       /**< Filesystem path or URI for a pipe interface — ManageInterfaceDialog pipeView */
    IFTREE_COL_MAX              /**< Sentinel: total number of columns; not displayed */
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
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns in the table model.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    QVariant data (const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested.
     * @return The header data.
     */
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    /**
     * @brief Sets the statistics provider supplying sparkline/activity data.
     *
     * The model does not own it; it reads pointsFor()/isActive() in data() and
     * connects to its update signals to repaint the stats column and re-sort on
     * activity changes. Pass nullptr to detach.
     * @param statistics The interface statistics, or nullptr.
     */
    void setStatistics(InterfaceStatistics *statistics);

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

private slots:
    /**
     * @brief Subscribes to the window's InterfaceListManager::interfaceListChanged.
     *
     * The model has no window reference and may be built either before the window
     * (welcome frame's source model) or after (dialog cache model), so wiring is
     * deferred to appInitialized only when the app is not yet initialized.
     */
    void connectInterfaceListManager();

    /** @brief Repaints the statistics column when a new sample arrives. */
    void onStatisticsUpdated();

    /** @brief Re-sorts (via layoutChanged) when the active interface set changes. */
    void onActivityChanged();

private:
    /**
     * @brief Generates a tooltip string detailing information about a specific interface.
     * @param idx The row index of the interface.
     * @return The tooltip string variant.
     */
    QVariant toolTipForInterface(int idx) const;

    /** Statistics provider (not owned) supplying sparkline/activity data. */
    InterfaceStatistics *interface_stats_;
};

#endif // INTERFACE_TREE_MODEL_H
