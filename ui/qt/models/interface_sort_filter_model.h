/** @file
 *
 * Proxy model for the display of interface data for the interface tree
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_SORT_FILTER_MODEL_H
#define INTERFACE_SORT_FILTER_MODEL_H

#include <config.h>

#include <ui/qt/models/interface_tree_model.h>

#include <QSortFilterProxyModel>

/**
 * @brief A proxy model that provides custom sorting and filtering for the list of interfaces.
 */
class InterfaceSortFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new InterfaceSortFilterModel.
     * @param parent The parent QObject.
     */
    InterfaceSortFilterModel(QObject *parent);

    /**
     * @brief Configures whether changes to interface visibility state should be stored persistently.
     * @param storeOnChange True to store changes automatically, false otherwise.
     */
    void setStoreOnChange(bool storeOnChange);

    /**
     * @brief Resets all current filters to their default states.
     */
    void resetAllFilter();

    /**
     * @brief Sets whether hidden interfaces should be filtered out (not displayed).
     * @param filter True to hide interfaces marked as hidden, false to show them.
     */
    void setFilterHidden(bool filter);

    /**
     * @brief Checks if hidden interfaces are currently being filtered out.
     * @return True if filtering hidden interfaces, false otherwise.
     */
    bool filterHidden() const;

    /**
     * @brief Gets the count of interfaces that are currently hidden by the filter.
     * @return The number of hidden interfaces.
     */
    int interfacesHidden();

    /**
     * @brief Toggles the filter state for hidden interfaces.
     */
    void toggleFilterHidden();

    /**
     * @brief Sets whether the interfaces should be dynamically sorted based on network activity.
     * @param sort True to sort by activity, false to use standard sorting.
     */
    void setSortByActivity(bool sort);

    /**
     * @brief Checks if the interfaces are currently being sorted by activity.
     * @return True if sorting by activity, false otherwise.
     */
    bool sortByActivity() const;

#ifdef HAVE_PCAP_REMOTE
    /**
     * @brief Sets whether remote interfaces should be displayed.
     * @param remoteDisplay True to display remote interfaces, false to hide them.
     */
    void setRemoteDisplay(bool remoteDisplay);

    /**
     * @brief Checks if remote interfaces are currently configured to be displayed.
     * @return True if remote interfaces are displayed, false otherwise.
     */
    bool remoteDisplay();

    /**
     * @brief Toggles the display state of remote interfaces.
     */
    void toggleRemoteDisplay();

    /**
     * @brief Checks if there are any remote interfaces present in the underlying data.
     * @return True if remote interfaces exist, false otherwise.
     */
    bool remoteInterfacesExist();
#endif

    /**
     * @brief Sets the visibility for a specific interface type.
     * @param ifType The interface type identifier.
     * @param visible True to make this type visible, false to hide it.
     */
    void setInterfaceTypeVisible(int ifType, bool visible);

    /**
     * @brief Checks if a specific interface type is currently set to be visible.
     * @param ifType The interface type identifier.
     * @return True if visible, false otherwise.
     */
    bool isInterfaceTypeShown(int ifType) const;

    /**
     * @brief Enables or disables filtering by interface type.
     * @param filter True to apply type filtering, false to ignore type visibility settings.
     * @param invert True to invert the logic (show what is usually hidden, hide what is usually shown).
     */
    void setFilterByType(bool filter, bool invert = false);

    /**
     * @brief Checks if filtering by interface type is currently active.
     * @return True if type filtering is active, false otherwise.
     */
    bool filterByType() const;

    /**
     * @brief Toggles the visibility state for a specific interface type.
     * @param ifType The interface type identifier.
     */
    void toggleTypeVisibility(int ifType);

    /**
     * @brief Retrieves a list of interface types that are currently set to be displayed.
     * @return A list of integer type identifiers.
     */
    QList<int> typesDisplayed();

    /**
     * @brief Configures which specific columns from the source model should be displayed.
     * @param columns A list of InterfaceTreeColumns to show.
     */
    void setColumns(QList<InterfaceTreeColumns> columns);

    /**
     * @brief Maps a logical column identifier to its actual display column index.
     * @param mdlIndex The logical column identifier.
     * @return The display column index, or -1 if not found.
     */
    int mapSourceToColumn(InterfaceTreeColumns mdlIndex);

    /**
     * @brief Maps a proxy model index to its corresponding source model index.
     * @param proxyIndex The proxy model index.
     * @return The source model index.
     */
    QModelIndex mapToSource(const QModelIndex &proxyIndex) const override;

    /**
     * @brief Maps a source model index to its corresponding proxy model index.
     * @param sourceIndex The source model index.
     * @return The proxy model index.
     */
    QModelIndex mapFromSource(const QModelIndex &sourceIndex) const override;

    /**
     * @brief Retrieves any current interface-related error messages.
     * @return The error message string, or empty if no errors.
     */
    QString interfaceError();

protected:
    /**
     * @brief Determines whether a row from the source model matches all active filters.
     * @param source_row The row index in the source model.
     * @param source_parent The parent index in the source model.
     * @return True if the row should be displayed, false otherwise.
     */
    bool filterAcceptsRow(int source_row, const QModelIndex & source_parent) const override;

    /**
     * @brief Determines whether a column from the source model matches active column filters.
     * @param source_column The column index in the source model.
     * @param source_parent The parent index in the source model.
     * @return True if the column should be displayed, false otherwise.
     */
    bool filterAcceptsColumn(int source_column, const QModelIndex & source_parent) const override;

    /**
     * @brief Compares two source indices to determine their sort order.
     * @param source_left The first source index.
     * @param source_right The second source index.
     * @return True if the left item should appear before the right item.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;

private:
    /** Flag indicating if hidden interfaces should be filtered out. */
    bool _filterHidden;

    /** Flag indicating if filtering by interface type is active. */
    bool _filterTypes;

    /** Flag indicating if the type filtering logic is inverted. */
    bool _invertTypeFilter;

    /** Flag indicating if configuration changes should be immediately saved to preferences. */
    bool _storeOnChange;

    /** Flag indicating if dynamic sorting by activity is enabled. */
    bool _sortByActivity;

#ifdef HAVE_PCAP_REMOTE
    /** Flag indicating if remote interfaces should be displayed. */
    bool _remoteDisplay;
#endif

    /** List of interface types that are explicitly hidden by the user. */
    QList<int> displayHiddenTypes;

    /** List of columns that are currently configured to be displayed. */
    QList<InterfaceTreeColumns> _columns;

private slots:
    /**
     * @brief Slot triggered to reload filter settings from persistent preferences.
     */
    void resetPreferenceData();
};

#endif // INTERFACE_SORT_FILTER_MODEL_H
