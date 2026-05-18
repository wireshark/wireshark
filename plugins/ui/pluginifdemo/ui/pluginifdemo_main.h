/* pluginifdemo_main.h
 *
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLUGINIFDEMO_MAIN_H_
#define PLUGINIFDEMO_MAIN_H_

#include <QWidget>
#include <QDialog>
#include <QAbstractButton>
#include <QListWidget>
#include <QAbstractListModel>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>

#include <ui/plugins/include/plugin_if.h>

namespace Ui {
class PluginIFDemo_Main;
}

/**
 * @brief Represents a single toolbar item type with an associated display label.
 */
class PluginIfType
{
public:
    /**
     * @brief Constructs a PluginIfType with the given label and toolbar item type.
     * @param label    Human-readable display label for this item type.
     * @param itemType The underlying toolbar item type constant.
     */
    PluginIfType(const QString &label, const ext_toolbar_item_t &itemType);

    /**
     * @brief Returns the display label for this item type.
     * @return Human-readable label string.
     */
    QString label() const;

    /**
     * @brief Returns the toolbar item type constant for this entry.
     * @return The ext_toolbar_item_t value associated with this item type.
     */
    ext_toolbar_item_t itemType() const;

private:
    QString            m_label;    /**< Display label for this toolbar item type. */
    ext_toolbar_item_t m_itemType; /**< Toolbar item type constant. */
};


/**
 * @brief List model that exposes a collection of PluginIfType entries to Qt views.
 */
class PluginIfTypeModel : public QAbstractListModel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs an empty PluginIfTypeModel.
     * @param parent Optional parent QObject.
     */
    PluginIfTypeModel(QObject *parent = 0);

    /**
     * @brief Appends a PluginIfType entry to the model.
     * @param pluginIfType The entry to append.
     */
    void addPluginIfType(const PluginIfType &pluginIfType);

    /**
     * @brief Returns the number of rows (entries) in the model.
     * @param parent Unused; pass a default QModelIndex for list models.
     * @return Number of PluginIfType entries currently held.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns data for the given index and role.
     * @param idx  Model index of the requested item.
     * @param role Qt item data role (e.g. Qt::DisplayRole).
     * @return QVariant containing the requested data, or an invalid QVariant if unavailable.
     */
    QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const;

private:
    QList<PluginIfType> m_pluginIfTypes; /**< Ordered list of toolbar item type entries. */
};


/**
 * @brief Sort/filter proxy that restricts a PluginIfTypeModel to a single item type.
 */
class PluginIfTypeSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs the proxy model with no active filter.
     * @param parent Optional parent QObject.
     */
    PluginIfTypeSortFilterProxyModel(QObject *parent = 0);

    /**
     * @brief Determines whether the given source row should be included in the filtered view.
     * @param sourceRow    Row index in the source model to evaluate.
     * @param sourceParent Parent index in the source model (unused for list models).
     * @return @c true if the row's item type matches the active filter; @c false otherwise.
     */
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    /**
     * @brief Sets the item type to filter on; only rows matching this type will be shown.
     * @param filterType The ext_toolbar_item_t value to accept.
     */
    void setFilterElement(ext_toolbar_item_t filterType);

private:
    ext_toolbar_item_t m_filterType; /**< The item type currently used as the filter criterion. */
};


/**
 * @brief Main dialog for the Plugin Interface Demo, providing interactive controls
 *        for exercising all ext_toolbar item types.
 */
class PluginIFDemo_Main : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the main demo dialog.
     * @param parent Optional parent widget.
     */
    explicit PluginIFDemo_Main(QWidget *parent = 0);

    /**
     * @brief Destroys the dialog and releases all associated resources.
     */
    ~PluginIFDemo_Main();

    /**
     * @brief Associates an external toolbar with this dialog so that demo
     *        actions can drive toolbar state.
     * @param toolbar Reference to the pointer of the ext_toolbar_t to control.
     */
    void setToolbar(ext_toolbar_t *&toolbar);

private slots:
    /**
     * @brief Handles button-box button clicks (e.g. Close/OK).
     * @param button The button that was activated.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /** @brief Sends the current button label text to the associated toolbar button. */
    void on_btnSendButtonText_clicked();

    /** @brief Sends the current text-field content to the associated toolbar text item. */
    void on_btnSendText_clicked();

    /** @brief Sends an update for the currently selected toolbar item. */
    void on_btnSendUpdateItem_clicked();

    /**
     * @brief Responds to state changes on the test checkbox and forwards the new
     *        state to the associated toolbar checkbox item.
     * @param newState The new Qt::CheckState value.
     */
    void on_chkTestCheckbox_stateChanged(int newState);

    /**
     * @brief Switches the active interface type tab and updates the proxy filter
     *        to show only entries relevant to the newly selected tab.
     * @param newTab Index of the tab that became active.
     */
    void on_tabInterfaceTypes_currentChanged(int newTab);

    /** @brief Adds a new item to the list model and forwards it to the toolbar. */
    void on_btnAddItem_clicked();

    /** @brief Removes the currently selected item from the list model and the toolbar. */
    void on_btnRemoveItem_clicked();

    /** @brief Sends the current list model contents to the associated toolbar list item. */
    void on_btnSendList_clicked();

    /**
     * @brief Responds to combo-box text changes and updates the toolbar selector accordingly.
     * @param newText The newly selected or entered text.
     */
    void on_cmbElements_currentTextChanged(const QString &newText);

    /**
     * @brief Handles item selection in the list view and reflects the selection
     *        in associated controls.
     * @param idx Model index of the clicked item.
     */
    void on_lstItems_clicked(const QModelIndex &idx);

    /** @brief Enables the currently selected toolbar item. */
    void on_btnEnable_clicked();

    /** @brief Disables the currently selected toolbar item. */
    void on_btnDisable_clicked();

    /**
     * @brief Appends @p message to the dialog's log output area.
     * @param message The log message to display.
     */
    void logChanged(QString message);

    /** @brief Closes the dialog in response to an external signal (e.g. toolbar teardown). */
    void closeDialog();

private:
    Ui::PluginIFDemo_Main *ui; /**< Qt Designer-generated UI object for this dialog. */

    PluginIfTypeModel              *sourceModel; /**< Source model holding all available toolbar item types. */
    PluginIfTypeSortFilterProxyModel *proxyModel; /**< Proxy model filtering sourceModel by the active tab's item type. */
    QStandardItemModel             *listModel;   /**< Model backing the list-item editor. */
    QStandardItemModel             *indexModel;  /**< Model backing the index/selector editor. */

    ext_toolbar_t *_toolbar; /**< Pointer to the external toolbar being exercised by this dialog. */
};


#endif /* PLUGINIFDEMO_MAIN_H_ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
