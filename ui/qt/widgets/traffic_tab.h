/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRAFFIC_TAB_H
#define TRAFFIC_TAB_H

#include "config.h"

#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/filter_action.h>
#include <ui/qt/widgets/traffic_tree.h>
#include <ui/qt/widgets/detachable_tabwidget.h>
#include <ui/qt/widgets/traffic_types_list.h>

#include <QTabWidget>
#include <QTreeView>
#include <QFile>
#include <QUrl>
#include <QAbstractItemDelegate>
#include <QSortFilterProxyModel>

/**
 * @brief Callback for creating an ATapDataModel
 *
 * @param protoId the protocol id for the callback to use
 * @param filter setting the filter for the tap
 * @return either null, if no model could be created, or an instance
 * of the model itself.
 */
typedef ATapDataModel * (*ATapModelCallback)(int protoId, QString filter);

/**
 * @brief Callback for creating an item delegate
 *
 * @param parent the parent for the delegate to attach to
 * @return either null if no delegate had been created, or an instance for
 * the delegate
 */
typedef QAbstractItemDelegate * (*ATapCreateDelegate)(QWidget * parent);

/**
 * @brief A simple class to store the data for a tab in the traffic tab widget
 */
class TabData
{
public:
    /**
     * @brief Constructs a new empty TabData object.
     */
    TabData();

    /**
     * @brief Copy constructor.
     */
    TabData(const TabData &) = default;

    /**
     * @brief Copy assignment operator.
     */
    TabData &operator=(const TabData &) = default;

    /**
     * @brief Constructs a new TabData object with a specific name and protocol ID.
     * @param name The name of the tab.
     * @param proto The protocol ID associated with the tab.
     */
    TabData(QString name, int proto);

    /**
     * @brief Retrieves the name of the tab.
     * @return A QString containing the name.
     */
    QString name() const;

    /**
     * @brief Retrieves the protocol ID.
     * @return The protocol ID.
     */
    int protoId() const;

private:
    /** @brief The name of the tab. */
    QString _name;

    /** @brief The protocol ID for the tab. */
    int _protoId;
};

Q_DECLARE_METATYPE(TabData)

/**
 * @brief A QTabWidget class, providing tap information
 *
 * This class combines all required information, to display tapped data
 * to the user. Specifically it handles all model data internally, therefore
 * removing the need of the dialog to know how data is being stored or
 * generated.
 */
class TrafficTab : public DetachableTabWidget
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new TrafficTab widget.
     * @param parent The parent widget.
     */
    TrafficTab(QWidget *parent = nullptr);

    /**
     * @brief Destroys the TrafficTab widget.
     */
    virtual ~TrafficTab();

    /**
     * @brief Set the Protocol Info for the traffic tab
     *
     * This has to be called right after instantiating the class. The reason this is not
     * done inside the constructor is such, that the object can be used with Qt Designer
     * without having to removing the predefined object during setup of the UI.
     *
     * @param tableName The name for the table. Used for the protocol selection button
     * @param trafficList an element of traffictypeslist, which handles all profile selections
     * @param recentColumnList a list of columns to be displayed for this traffic type
     * @param createModel A callback, which will create the correct model for the trees
     *
     * @see ATapModelCallback
     */
    void setProtocolInfo(QString tableName, TrafficTypesList * trafficList, GList ** recentList, GList ** recentColumnList, ATapModelCallback createModel);

    /**
     * @brief Set the Delegate object for the tab. It will apply for all
     * models residing in this tab object
     *
     * @param createDelegate the callback for the delegate creation
     *
     * @see ATapCreateDelegate
     */
    void setDelegate(ATapCreateDelegate createDelegate);

    /**
     * @brief Set the filter or remove it by providing an empty filter
     *
     * This differs from filtering the model itself in such a way, that filtering is
     * being done using the epan system. Therefore, once filtered, the only way to get
     * all elements back is to set an empty string.
     *
     * @note Filtering will only work, as long as the capture file remains open. If
     * taps have been disabled and capture has stopped, filtering will no longer work.
     *
     * @param filter the string to be filtered on
     */
    void setFilter(QString filter = QString());

    /**
     * @brief Enable/Disable name resolution for the address column
     *
     * @param checked true to enable name resolution
     */
    void setNameResolution(bool checked);

    /**
     * @brief Disables the taps for this traffic tab.
     *
     * Disables all taps for models used by this traffic tab. They cannot be re-enabled on purpose,
     * as in most cases, disabling them is being done during closing of the original capture file.
     * This also disabled all filter actions, as well as the tap selection button.
     */
    void disableTap();

    /**
     * @brief Create a menu containing clipboard copy entries for this tab
     *
     * It will create all entries, including copying the content of the currently selected tab
     * to CSV, YAML and JSON
     *
     * @param parent the parent object or null
     * @return QMenu* the resulting menu or null
     */
    QMenu * createCopyMenu(QWidget * parent = nullptr);

    /**
     * @brief Checks, wether the given tabpage support name resolution on the address column
     *
     * @param tabIdx the index of the page. If it is out of bounds or < 0, the current index is being used
     * @return true if name resolution is being supported
     * @return false if name resolution is not supported
     */
    bool hasNameResolution(int tabIdx = -1);

#ifdef HAVE_MAXMINDDB
    /**
     * @brief Checks, wether the given tabpage support GeoIP data
     *
     * @param tabIdx the index of the page. If it is out of bounds or < 0, the current index is being used
     * @return true if geoIP data is being supported
     * @return false if geoIP data is not supported
     */
    bool hasGeoIPData(int tabIdx = -1);

    /**
     * @brief Create a map of GeoIP data and write it to a temporary file
     *
     * @param onlyJSON only put the json content into the temporary file
     * @param tabIdx the index of the page. If it is out of bounds or < 0, the current index is being used
     * @return The path to the temporary file for the data
     */
    QUrl createGeoIPMap(bool onlyJSON, int tabIdx = -1);
#endif

    /**
     * @brief Return the itemData for the currently selected index in the currently
     * displayed treeview.
     *
     * @param role the role to be used, defaults to Qt::DisplayRole
     * @return QVariant the resulting value as QVariant type
     */
    QVariant currentItemData(int role = Qt::DisplayRole);

    /**
     * @brief Return the number of currently selected items in the currently
     * displayed treeview.
     *
     * @param role the role to be used, defaults to Qt::DisplayRole
     * @return qlonglong the number of selected items
     */
    qlonglong countSelectedItems(int role = Qt::DisplayRole);

    /**
     * @brief Return a list of IOGraph related data, for the currently selected
     * index or indexes in the currently displayed treeview.
     *
     * @return QList of IOGraph related data expressed in QVariant types
     */
    QList<QList<QVariant> > selectedItemsIOGData();

    /**
     * @brief Use nanosecond timestamps if requested
     *
     * @param useNSTime use nanosecond timestamps if required and requested
     */
    void useNanosecondTimestamps(bool useNSTime);

    /**
     * @brief Retrieves the tap data model for a specific tab index.
     * @param tabIdx The tab index, or current index if -1.
     * @return Pointer to the ATapDataModel.
     */
    ATapDataModel * dataModelForTabIndex(int tabIdx = -1);

public slots:

    /**
     * @brief Use absolute time for the time columns
     *
     * @param absolute true if absolute time should be used
     */
    void useAbsoluteTime(bool absolute);

    /**
     * @brief Limits the displayed data to the active display filter.
     * @param limit True to apply the display filter constraint.
     */
    void limitToDisplayFilter(bool limit);

    /**
     * @brief Configures output presentation to be machine readable.
     * @param machine True to enable machine readable formatting.
     */
    void setMachineReadable(bool machine);

    /**
     * @brief Opens specific protocol tabs based on a list.
     * @param protocols List of protocol IDs to open tabs for.
     */
    void setOpenTabs(QList<int> protocols);

signals:
    /**
     * @brief Signal emitted to trigger a filter action.
     * @param filter The filter string.
     * @param action The specific action to take.
     * @param type The type of the filter action.
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /**
     * @brief Signal emitted when the tab data has changed.
     * @param idx The tab index.
     * @param selcounter The count of selected items.
     */
    void tabDataChanged(int idx, int selcounter);

    /**
     * @brief Signal emitted when a retap operation is required.
     */
    void retapRequired();

    /**
     * @brief Signal emitted to notify that taps are being disabled.
     */
    void disablingTaps();

    /**
     * @brief Signal emitted when the open tabs have changed.
     * @param protocols List of protocol IDs currently open.
     */
    void tabsChanged(QList<int> protocols);

    /**
     * @brief Signal emitted when the column configuration has changed.
     * @param columns List of active columns.
     */
    void columnsHaveChanged(QList<int> columns);

protected slots:

    /**
     * @brief Slot called to detach a tab into its own window.
     * @param idx The index of the tab to detach.
     * @param pos The position to place the new window.
     */
    virtual void detachTab(int idx, QPoint pos) override;

    /**
     * @brief Slot called to reattach a previously detached tab.
     * @param content The widget content to reattach.
     * @param name The name of the tab.
     */
    virtual void attachTab(QWidget * content, QString name) override;

private:
    /** @brief List of all available protocol IDs for this traffic tab. */
    QList<int> _allProtocols;

    /** @brief Map relating physical tab indices to protocol IDs. */
    QMap<int, int> _tabs;

    /** @brief Callback function used to create new data models. */
    ATapModelCallback _createModel;

    /** @brief Callback function used to create new delegates. */
    ATapCreateDelegate _createDelegate;

    /** @brief Pointer to the list of recent traffic types. */
    GList ** _recentList;

    /** @brief Pointer to the list of recent column configurations. */
    GList ** _recentColumnList;

    /** @brief Flag indicating if taps are currently disabled. */
    bool _disableTaps;

    /** @brief Flag indicating if name resolution is active. */
    bool _nameResolution;

    /** @brief Flag indicating if absolute time format should be used. */
    bool _absoluteTime;

    /** @brief Flag indicating if data is limited to the display filter. */
    bool _limitToDisplayFilter;

    /** @brief Flag indicating if nanosecond precision is active. */
    bool _nanoseconds;

    /** @brief Flag indicating if machine readable output format is requested. */
    bool _machineReadable;

    /**
     * @brief Creates the tree view for a specific protocol.
     * @param protoId The protocol ID.
     * @return Pointer to the constructed QTreeView.
     */
    QTreeView * createTree(int protoId);

    /**
     * @brief Retrieves the filter proxy model for a specific tab index.
     * @param tabIdx The tab index.
     * @return Pointer to the TrafficDataFilterProxy.
     */
    TrafficDataFilterProxy * modelForTabIndex(int tabIdx = -1);

    /**
     * @brief Retrieves the filter proxy model for a specific widget.
     * @param widget The target widget.
     * @return Pointer to the TrafficDataFilterProxy.
     */
    TrafficDataFilterProxy * modelForWidget(QWidget * widget);

    /**
     * @brief Retrieves the underlying data model for a specific widget.
     * @param widget The target widget.
     * @return Pointer to the ATapDataModel.
     */
    ATapDataModel * dataModelForWidget(QWidget * widget);

    /**
     * @brief Inserts a new tab for the specified protocol.
     * @param protoId The protocol ID.
     * @param emitSignals True to emit related signals, false otherwise.
     */
    void insertProtoTab(int protoId, bool emitSignals = true);

    /**
     * @brief Removes the tab for the specified protocol.
     * @param protoId The protocol ID.
     * @param emitSignals True to emit related signals, false otherwise.
     */
    void removeProtoTab(int protoId, bool emitSignals = true);

#ifdef HAVE_MAXMINDDB
    /**
     * @brief Writes GeoIP map data to a file.
     * @param fp Pointer to the file to write to.
     * @param json_only True to write only JSON.
     * @param model Pointer to the filter proxy model containing the data.
     * @return True if write was successful.
     */
    bool writeGeoIPMapFile(QFile * fp, bool json_only, TrafficDataFilterProxy * model);
#endif

private slots:
    /**
     * @brief Responds to changes or resets in the active model.
     */
    void modelReset();

    /**
     * @brief Handles updates when the current item index changes.
     * @param cur The new current model index.
     * @param prev The previous model index.
     */
    void doCurrentIndexChange(const QModelIndex & cur, const QModelIndex & prev);

    /**
     * @brief Handles updates when the item selection state changes.
     * @param selected The items newly selected.
     * @param deselected The items newly deselected.
     */
    void doSelectionChange(const QItemSelection &selected, const QItemSelection &deselected);
};

#endif // TRAFFIC_TAB_H
