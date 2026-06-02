/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRAFFIC_TREE_H
#define TRAFFIC_TREE_H

#include "config.h"

#include <ui/recent.h>

#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/filter_action.h>
#include <ui/qt/widgets/adaptive_header_view.h>

#include <QTreeView>
#include <QMenu>
#include <QHeaderView>
#include <QSortFilterProxyModel>

#include <QWidgetAction>
#include <QLineEdit>
#include <QActionGroup>

/**
 * @brief Action containing an editable text field for use in menus.
 */
class MenuEditAction : public QWidgetAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new MenuEditAction.
     * @param text The default text for the action.
     * @param hintText The placeholder text to display when empty.
     * @param parent The parent QObject, defaults to nullptr.
     */
    MenuEditAction(QString text, QString hintText, QObject * parent = nullptr);

    /**
     * @brief Retrieves the current text in the line edit.
     * @return The text string.
     */
    QString text() const;

protected:
    /**
     * @brief Creates the custom widget for this action.
     * @param parent The parent widget.
     * @return A pointer to the created QWidget.
     */
    virtual QWidget * createWidget(QWidget *parent);

private:
    /** Placeholder hint text. */
    QString _hintText;

    /** Current text value. */
    QString _text;

    /** Pointer to the line edit widget. */
    QLineEdit * _lineEdit;

private slots:
    /**
     * @brief Slot triggered when the text entry is completed or triggered.
     */
    void triggerEntry();
};


/**
 * @brief Header view for the traffic tree providing column customization and filtering.
 */
class TrafficTreeHeaderView : public AdaptiveHeaderView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new TrafficTreeHeaderView.
     * @param recentColumnList Pointer to a GList of recently visible columns.
     * @param parent The parent widget, defaults to nullptr.
     */
    TrafficTreeHeaderView(GList ** recentColumnList, QWidget * parent = nullptr);

    /**
     * @brief Destroys the TrafficTreeHeaderView.
     */
    ~TrafficTreeHeaderView();

    /**
     * @brief Applies the recently used column settings.
     */
    void applyRecent();

signals:
    /**
     * @brief Signal emitted when the visible columns have changed.
     * @param visible List of visible column indices.
     */
    void columnsHaveChanged(QList<int> visible);

    /**
     * @brief Signal emitted to filter data based on a column's criteria.
     * @param column The column index to filter on.
     * @param filterOn The filter operation type.
     * @param filterText The text value to filter against.
     */
    void filterOnColumn(int column, int filterOn, QString filterText);

private:
    /** Pointer to the GList tracking recent columns. */
    GList ** _recentColumnList;

    /** Action group for header context menu actions. */
    QActionGroup * _actions;

    /** The current filter text. */
    QString _filterText;

private slots:
    /**
     * @brief Displays the context menu for the header.
     * @param pos The position to show the menu.
     */
    void headerContextMenu(const QPoint &pos);

    /**
     * @brief Slot triggered when a column toggle action is selected.
     * @param checked True if the column is checked/visible, false otherwise.
     */
    void columnTriggered(bool checked = false);

    /**
     * @brief Slot triggered when a specific menu action is executed.
     * @param act Pointer to the triggered QAction.
     */
    void menuActionTriggered(QAction * act);

    /**
     * @brief Slot triggered to apply a filter on the column.
     * @param checked True if triggered by a toggle, defaults to false.
     */
    void filterColumn(bool checked = false);
};


/**
 * @brief Proxy model handling sorting, filtering, and column visibility for traffic data.
 */
class TrafficDataFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT
public:

    /** @brief Types of filtering operations available for traffic data. */
    enum {
        /** @brief Filter for values strictly less than the target. */
        TRAFFIC_DATA_LESS,
        /** @brief Filter for values strictly greater than the target. */
        TRAFFIC_DATA_GREATER,
        /** @brief Filter for values equal to the target. */
        TRAFFIC_DATA_EQUAL,
    };

    /**
     * @brief Constructs a new TrafficDataFilterProxy.
     * @param parent The parent QObject, defaults to nullptr.
     */
    TrafficDataFilterProxy(QObject *parent = nullptr);

    /**
     * @brief Sets the visibility for a specific column.
     * @param column The column index.
     * @param visible True to show the column, false to hide it.
     */
    void setColumnVisibility(int column, bool visible);

    /**
     * @brief Checks if a column is currently visible.
     * @param column The column index.
     * @return True if visible, false otherwise.
     */
    bool columnVisible(int column) const;

public slots:
    /**
     * @brief Applies filtering criteria for a specific column.
     * @param column The column index to filter.
     * @param filterOn The filter operation type (e.g., less, greater, equal).
     * @param filterText The text value to filter against.
     */
    void filterForColumn(int column, int filterOn, QString filterText);

protected:
    /**
     * @brief Determines if a row from the source model should be included.
     * @param source_row The source row index.
     * @param source_parent The source parent index.
     * @return True if the row is accepted, false otherwise.
     */
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;

    /**
     * @brief Determines if a column from the source model should be included.
     * @param source_column The source column index.
     * @param source_parent The source parent index.
     * @return True if the column is accepted, false otherwise.
     */
    virtual bool filterAcceptsColumn(int source_column, const QModelIndex &source_parent) const;

    /**
     * @brief Compares two items for sorting.
     * @param source_left The left model index.
     * @param source_right The right model index.
     * @return True if the left item is less than the right item, false otherwise.
     */
    virtual bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

private:
    /** List of column indices that are hidden. */
    QList<int> hideColumns_;

    /** The column currently being filtered. */
    int _filterColumn;

    /** The active filter operation type. */
    int _filterOn;

    /** The active filter text. */
    QString _filterText;

    /**
     * @brief Maps a proxy column index to its source column index.
     * @param proxyColumn The index in the proxy model.
     * @return The corresponding source column index.
     */
    int mapToSourceColumn(int proxyColumn) const;
};


/**
 * @brief Tree view tailored for displaying network traffic conversations and endpoints.
 */
class TrafficTree : public QTreeView
{
    Q_OBJECT

public:
    /**
     * @brief Type for the selection of export
     * @see copyToClipboard
     */
    typedef enum {
        /** @brief export as CSV */
        CLIPBOARD_CSV,
        /** @brief export as YAML */
        CLIPBOARD_YAML,
        /** @brief export as JSON */
        CLIPBOARD_JSON
    } eTrafficTreeClipboard;

    /**
     * @brief Constructs a new TrafficTree.
     * @param baseName The base name identifying the tree context.
     * @param recentColumnList Pointer to a GList tracking recent columns.
     * @param parent The parent widget, defaults to nullptr.
     */
    TrafficTree(QString baseName, GList ** recentColumnList, QWidget *parent = nullptr);

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
     * @brief Applies the recently visible columns configuration.
     */
    void applyRecentColumns();

    /**
     * @brief Increase column width if necessary to fit contents, but don't
     * narrow it.
     *
     * This is used to ensure that the columns are wide enough for newly
     * received data, but to avoid narrowing columns that have been manually
     * widened, especially the Rel Start/Abs Start and Duration columns,
     * since those contain a timeline graph.
     * @param column The column index to widen.
     */
    void widenColumnToContents(int column);

    /**
     * @brief Sets the data model for the tree view.
     * @param model Pointer to the abstract item model.
     */
    virtual void setModel(QAbstractItemModel *model) override;

signals:
    /**
     * @brief Signal emitted to perform a display filter action.
     * @param filter The filter string.
     * @param action The filter action.
     * @param type The filter action type.
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /**
     * @brief Signal emitted when the visible columns have changed.
     * @param columns List of visible column indices.
     */
    void columnsHaveChanged(QList<int> columns);

public slots:
    /**
     * @brief Enables or disables the tap listener.
     * @param enable True to enable, false to disable.
     */
    void tapListenerEnabled(bool enable);

    /**
     * @brief Disables the tap completely.
     */
    void disableTap();

    /**
     * @brief Slot triggered when columns are changed.
     * @param columns List of new visible column indices.
     */
    void columnsChanged(QList<int> columns);

private:
    /** Flag indicating if the tap listener is enabled. */
    bool _tapEnabled;

    /** The role used for exporting data. */
    int _exportRole;

    /** Flag indicating whether to save raw formatting. */
    bool _saveRaw;

    /** The base name for this traffic tree. */
    QString _baseName;

    /** Pointer to the custom header view. */
    TrafficTreeHeaderView * _header;

    /**
     * @brief Retrieves the underlying tap data model.
     * @return Pointer to the ATapDataModel.
     */
    ATapDataModel * dataModel();

    /**
     * @brief Creates a context submenu for filter actions.
     * @param cur_action The base filter action.
     * @param idx The model index for context.
     * @param isConversation True if treating as a conversation, false otherwise.
     * @return Pointer to the generated QMenu.
     */
    QMenu * createActionSubMenu(FilterAction::Action cur_action, QModelIndex idx, bool isConversation);

    /**
     * @brief Copies tree contents to the clipboard in a specific format.
     * @param type The clipboard export format type.
     */
    void copyToClipboard(eTrafficTreeClipboard type);

    /** Grants TrafficTreeHeaderView access to private members. */
    friend class TrafficTreeHeaderView;

private slots:
    /**
     * @brief Shows the custom context menu for the tree.
     * @param pos The position coordinates for the menu.
     */
    void customContextMenu(const QPoint &pos);

    /**
     * @brief Slot to use the selected filter action.
     */
    void useFilterAction();

    /**
     * @brief Slot to trigger a clipboard copy action.
     */
    void clipboardAction();

    /**
     * @brief Slot to trigger a resize action for columns.
     */
    void resizeAction();

    /**
     * @brief Slot to toggle saving raw format.
     */
    void toggleSaveRawAction();

    /**
     * @brief Handles updates when underlying data changes.
     * @param topLeft Top left index of changed data.
     * @param bottomRight Bottom right index of changed data.
     */
    void handleDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight,
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
        const QVector<int>
#else
        const QList<int>
#endif
        );

    /**
     * @brief Handles updates when the model layout changes.
     */
    void handleLayoutChanged(const QList<QPersistentModelIndex>, QAbstractItemModel::LayoutChangeHint);
};

#endif // TRAFFIC_TREE_H
