/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_
#define UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_

#include <QObject>
#include <QWidget>
#include <QStandardItem>
#include <QTreeView>
#include <QAbstractItemModel>
#include <QItemSelection>
#include <QLineEdit>
#include <QPushButton>
#include <QAction>
#include <QTableView>
#include <QToolBar>
#include <QDialog>
#include <QMap>
#include <QSortFilterProxyModel>

#include <extcap_parser.h>
#include <extcap_argument.h>

#include "extcap_options_dialog.h"

/**
 * @brief A proxy model that filters rows in a tree structure.
 */
class TreeSortFilterProxyModel : public QSortFilterProxyModel
{
public:
    /**
     * @brief Determines if a row from the source model should be included.
     * @param sourceRow The row in the source model.
     * @param sourceParent The parent index in the source model.
     * @return True if the row is accepted, false otherwise.
     */
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

    /**
     * @brief Inherits constructors from QSortFilterProxyModel.
     */
    using QSortFilterProxyModel::QSortFilterProxyModel;
};

/**
 * @brief Represents an extcap argument that allows selecting multiple values via a tree view.
 */
class ExtArgMultiSelect : public ExtcapArgument
{
    Q_OBJECT
public:
    /**
     * @brief Constructs an ExtArgMultiSelect.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ExtArgMultiSelect(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Destroys the ExtArgMultiSelect.
     */
    virtual ~ExtArgMultiSelect();

    /**
     * @brief Retrieves the currently selected values.
     * @return A comma-separated string of selected values.
     */
    virtual QString value();

    /**
     * @brief Checks if the current selection is valid.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid();

    /**
     * @brief Retrieves the default values for the selector.
     * @return A comma-separated string of default values.
     */
    virtual QString defaultValue();

    /**
     * @brief Checks if setting default values is supported.
     * @return True if supported, false otherwise.
     */
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    /**
     * @brief Sets the selector to its default values.
     */
    virtual void setDefaultValue();

protected:
    /**
     * @brief Traverses the value list to create standard items.
     * @param list The list of extcap values to process.
     * @param defaults A list of default value strings to be updated.
     * @return A list of created QStandardItem objects.
     */
    virtual QList<QStandardItem *> valueWalker(ExtcapValueList list, QStringList &defaults);

    /**
     * @brief Traverses and checks items recursively based on default values.
     * @param item The root item to start traversing from.
     * @param defaults The list of default values to check against.
     */
    void checkItemsWalker(QStandardItem * item, QStringList defaults);

    /**
     * @brief Creates the editor widget for the multi-select argument.
     * @param parent The parent widget.
     * @return A pointer to the created tree view widget.
     */
    virtual QWidget * createEditor(QWidget * parent);

    /**
     * @brief Retrieves a list of all currently checked values.
     * @return A string list of checked values.
     */
    virtual QStringList checkedValues();

    /** The model providing data for the tree view. */
    QStandardItemModel* viewModel;

    /** This stores the displays associated with a value. */
    QMap<QString, QString> displayNames;

private:
    /** The tree view widget used for displaying multi-select options. */
    QTreeView * treeView;
};

/**
 * @brief Represents an extcap argument displayed as an editable table.
 */
class ExtArgTable : public ExtArgMultiSelect
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgTable.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ExtArgTable(extcap_arg* argument, QObject* parent = Q_NULLPTR);

    /**
     * @brief Destroys the ExtArgTable.
     */
    virtual ~ExtArgTable();

    /**
     * @brief Retrieves the serialized string representing the table's values.
     * @return The serialized values string.
     */
    virtual QString value();

public Q_SLOTS:
    /**
     * @brief Sets the table to its default state.
     */
    virtual void setDefaultValue();

protected:
    /**
     * @brief Creates the editor widget for the table argument.
     * @param parent The parent widget.
     * @return A pointer to the created table widget.
     */
    virtual QWidget* createEditor(QWidget* parent);

    /**
     * @brief Adds a known entry to the table.
     */
    void addKnown();

    /**
     * @brief Opens a dialog to add a custom entry to the table.
     */
    void addCustom();

    /**
     * @brief Removes the currently selected entries from the table.
     */
    void removeSelected();

    /**
     * @brief Adds a list of checked items to the table.
     * @param checked The list of checked strings.
     * @param options The corresponding list of options.
     */
    void addChecked(QStringList checked, QStringList options);

    /**
     * @brief Displays the extcap options dialog for a specific item.
     * @param item The standard item to edit.
     * @param option_value The current option value.
     */
    virtual void showExtcapOptionsDialogForOptionValue(QStandardItem* item, QString& option_value);

    /**
     * @brief Handles the completion of the extcap options dialog.
     * @param item The standard item that was edited.
     */
    virtual void extcap_options_finished(QStandardItem* item);

private:
    /** Dialog for configuring detailed extcap options. */
    ExtcapOptionsDialog* extcap_options_dialog;

    /** Dialog used to add new custom entries. */
    QDialog* addDialog;

    /** The model providing data for the table view. */
    QStandardItemModel* tableViewModel;

    /** The table view widget. */
    QTableView* tableView;

    /** The layout managing the table pane. */
    QVBoxLayout* paneLayout;

    /** The toolbar containing table actions. */
    QToolBar* toolbar;
};

/**
 * @brief A dialog for adding new entries to an ExtArgTable.
 */
class ExtArgTableAddDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ExtArgTableAddDialog.
     * @param parent The parent widget.
     * @param selector The widget providing the selection UI.
     */
    ExtArgTableAddDialog(QWidget* parent, QWidget* selector);
};

#endif /* UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_ */
