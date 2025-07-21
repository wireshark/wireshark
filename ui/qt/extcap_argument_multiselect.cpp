/* extcap_argument_multiselect.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <extcap_argument.h>
#include <extcap_argument_file.h>

#include <wsutil/utf8_entities.h>

#include <QLabel>
#include <QLineEdit>
#include <QBoxLayout>
#include <QVariant>
#include <QPushButton>
#include <QMenu>
#include <QHeaderView>
#include <QInputDialog>

#include <epan/prefs.h>
#include <ui/qt/widgets/stock_icon_tool_button.h>
#include <ui/qt/utils/color_utils.h>

#include <extcap.h>
#include <extcap_parser.h>
#include <extcap_argument_multiselect.h>
#include "ui/capture_globals.h"

ExtArgMultiSelect::ExtArgMultiSelect(extcap_arg * argument, QObject *parent) :
        ExtcapArgument(argument, parent), viewModel(0), treeView(0) {}

ExtArgMultiSelect::~ExtArgMultiSelect()
{
    if (treeView != 0)
        delete treeView;
    if (viewModel != 0)
        delete viewModel;
}

// NOLINTNEXTLINE(misc-no-recursion)
QList<QStandardItem *> ExtArgMultiSelect::valueWalker(ExtcapValueList list, QStringList &defaults)
{
    ExtcapValueList::iterator iter = list.begin();
    QList<QStandardItem *> items;

    while (iter != list.end())
    {
        QStandardItem * item = new QStandardItem((*iter).value());
        if ((*iter).enabled() == false)
        {
            item->setCheckable(false);
        }
        else
        {
            item->setCheckable(true);
        }

        item->setData((*iter).call(), Qt::UserRole);
        if ((*iter).isDefault())
            defaults << (*iter).call();

        displayNames[(*iter).call()] = (*iter).value();

        item->setSelectable(false);
        item->setEditable(false);
        // We recurse here, but the tree is only two levels deep
        QList<QStandardItem *> childs = valueWalker((*iter).children(), defaults);
        if (childs.length() > 0)
            item->appendRows(childs);

        items << item;
        ++iter;
    }

    return items;
}

// NOLINTNEXTLINE(misc-no-recursion)
void ExtArgMultiSelect::checkItemsWalker(QStandardItem * item, QStringList defaults)
{
    QModelIndex index;

    if (item->hasChildren())
    {
        for (int row = 0; row < item->rowCount(); row++)
        {
            QStandardItem * child = item->child(row);
            if (child != 0)
            {
                // We recurse here, but the tree is only two levels deep
                checkItemsWalker(child, defaults);
            }
        }
    }

    QString data = item->data(Qt::UserRole).toString();

    if (defaults.contains(data))
    {
        item->setCheckState(Qt::Checked);
        index = item->index();
        while (index.isValid())
        {
            treeView->setExpanded(index, true);
            index = index.parent();
        }
    } else if (item->isCheckable()) {
        item->setCheckState(Qt::Unchecked);
    }
}

QWidget * ExtArgMultiSelect::createEditor(QWidget * parent)
{
    QStringList checked;

    QList<QStandardItem *> items = valueWalker(values, checked);
    if (items.length() == 0)
        return new QWidget();

    /* Value can be empty if no items are checked */
    if (_argument->pref_valptr && (*_argument->pref_valptr))
    {
        checked = QString(*_argument->pref_valptr).split(",", Qt::SkipEmptyParts);
    }

    viewModel = new QStandardItemModel();
    QList<QStandardItem *>::const_iterator iter = items.constBegin();
    while (iter != items.constEnd())
    {
        viewModel->appendRow((*iter));
        ++iter;
    }

    treeView = new QTreeView(parent);
    treeView->setModel(viewModel);

    /* Shows at minimum 6 entries at most desktops */
    treeView->setMinimumHeight(100);
    treeView->setHeaderHidden(true);
    treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    treeView->expandAll();

    for (int row = 0; row < viewModel->rowCount(); row++)
        checkItemsWalker(((QStandardItemModel*)viewModel)->item(row), checked);

    connect(viewModel, &QStandardItemModel::itemChanged, this, &ExtArgMultiSelect::valueChanged);

    return treeView;
}

QStringList ExtArgMultiSelect::checkedValues()
{
    if (viewModel == 0)
        return QStringList();

    QStringList result;
    QModelIndexList checked = viewModel->match(viewModel->index(0, 0), Qt::CheckStateRole, Qt::Checked, -1, Qt::MatchExactly | Qt::MatchRecursive);
    if (checked.size() <= 0)
        return QStringList();

    QModelIndexList::const_iterator iter = checked.constBegin();
    while (iter != checked.constEnd())
    {
        QModelIndex index = (QModelIndex)(*iter);

        result << viewModel->data(index, Qt::UserRole).toString();

        ++iter;
    }

    return result;
}

QString ExtArgMultiSelect::value()
{
    return checkedValues().join(QString(','));
}

bool ExtArgMultiSelect::isValid()
{
    bool valid = true;

    if (isRequired())
    {
        if (viewModel == 0)
            valid = false;
        else
        {
            QModelIndexList checked = viewModel->match(viewModel->index(0, 0), Qt::CheckStateRole, Qt::Checked, -1, Qt::MatchExactly | Qt::MatchRecursive);
            if (checked.size() <= 0)
                valid = false;
        }
    }

    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_filter_invalid_bg).name();
    QString txtStyle("QTreeView { background-color: %1; } ");
    if (viewModel != 0)
        treeView->setStyleSheet(txtStyle.arg(valid ? QString("") : lblInvalidColor));

    return valid;
}

QString ExtArgMultiSelect::defaultValue()
{
    QStringList checked;

    valueWalker(values, checked);

    return checked.join(QString(','));
}

bool ExtArgMultiSelect::isSetDefaultValueSupported()
{
    return true;
}

void ExtArgMultiSelect::setDefaultValue()
{
    QStringList checked;

    if (viewModel == 0)
        return;

    checked = defaultValue().split(",", Qt::SkipEmptyParts);
    for (int row = 0; row < viewModel->rowCount(); row++)
        checkItemsWalker(((QStandardItemModel*)viewModel)->item(row), checked);
}

ExtArgTable::ExtArgTable(extcap_arg* argument, QObject* parent) :
    ExtArgMultiSelect(argument, parent), extcap_options_dialog(0), addDialog(0), tableViewModel(0), tableView(0), paneLayout(0), toolbar(0) {}

ExtArgTable::~ExtArgTable()
{
    // dialog is freed by its parent QWidget
    if (tableView != 0)
        delete tableView;
    if (tableViewModel != 0)
        delete tableViewModel;
    if (toolbar != 0)
        delete toolbar;
    if (paneLayout != 0)
        delete paneLayout;
}

ExtArgTableAddDialog::ExtArgTableAddDialog(QWidget* parent, QWidget* selector) : QDialog(parent)
{
    setWindowTitle("Add element");
    setMinimumWidth(400);

    QVBoxLayout* layout = new QVBoxLayout(this);
    QPushButton* okButton = new QPushButton("OK", this);
    QPushButton* cancelButton = new QPushButton("Cancel", this);

    layout->addWidget(selector);
    layout->addWidget(okButton);
    layout->addWidget(cancelButton);

    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
}

QWidget* ExtArgTable::createEditor(QWidget* parent)
{
    // The wrapper widget we return
    QWidget* pane = new QWidget(parent);
    paneLayout = new QVBoxLayout(pane);

    // Create dialog
    QWidget* treeViewWidget = ExtArgMultiSelect::createEditor(addDialog);
    addDialog = new ExtArgTableAddDialog(parent, treeViewWidget);

    // Instanciate the menu bar
    toolbar = new QToolBar(pane);
    toolbar->setStyleSheet("QToolBar { border: 1px solid gray; border-radius: 3px; }");
    QAction* addAction = toolbar->addAction("Add");
    QAction* addActionCustom = toolbar->addAction("Add custom");
    QAction* removeAction = toolbar->addAction("Remove");
    paneLayout->addWidget(toolbar);

    // Instanciate empty table
    tableView = new QTableView(pane);
    tableView->setMinimumHeight(200);
    tableView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    if (_argument->configurable)
        tableView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    tableView->verticalHeader()->hide();
    tableView->horizontalHeader()->hide();

    tableViewModel = new QStandardItemModel(pane);
    tableView->setModel(tableViewModel);
    paneLayout->addWidget(tableView);

    /* Value can be empty if no items are checked */
    if (_argument->pref_valptr && (*_argument->pref_valptr))
    {
        QStringList checked;
        QStringList options;

        if (_argument->prefix)
        {
            QStringList splitted = QString(*_argument->pref_valptr).split(_argument->prefix, Qt::SkipEmptyParts);
            QStringList parts;
            for (QString item : splitted)
            {
                parts = item.split(" ", Qt::SkipEmptyParts);
                checked << parts.takeFirst();
                options << parts.join(" ");
            }
        }
        else
        {
            checked = QString(*_argument->pref_valptr).split(" ", Qt::SkipEmptyParts);
        }
        addChecked(checked, options);
    }

    // Add handler for click
    connect(addAction, &QAction::triggered, this, &ExtArgTable::addKnown);
    connect(addActionCustom, &QAction::triggered, this, &ExtArgTable::addCustom);
    connect(removeAction, &QAction::triggered, this, &ExtArgTable::removeSelected);
    pane->setLayout(paneLayout);
    return pane;
}

QString ExtArgTable::value()
{
    QStringList results;
    for (int row = 0; row < tableViewModel->rowCount(); row++) {
        QString s = ((QStandardItemModel*)tableViewModel)->item(row)->data(Qt::UserRole).toString();
        QString config = ((QStandardItemModel*)tableViewModel)->item(row)->data(Qt::UserRole + 1).toString();
        if (_argument->prefix != NULL)
        {
            s.prepend(" ");
            s.prepend(_argument->prefix);
        }
        if (!config.isEmpty())
        {
            s.append(" ");
            s.append(config);
        }
        results << s;
    }
    return results.join(" ");
}

void ExtArgTable::addChecked(QStringList checked, QStringList options)
{
    for (int i = 0; i < checked.size(); ++i) {
        QStandardItem* item = new QStandardItem(checked[i]);
        item->setData(checked[i], Qt::UserRole);
        if (displayNames.contains(checked[i]))
        {
            item->setText(displayNames[checked[i]]);
        }

        if (_argument->configurable)
        {
            if (options.size() > i)
            {
                item->setData(QString(options[i]), Qt::UserRole + 1);  // Currently: no configuration
            }
            else
            {
                item->setData(QString(), Qt::UserRole + 1);  // Currently: no configuration
            }

            QStandardItem* btnItem = new QStandardItem();
            tableViewModel->appendRow({ item, btnItem });

            // Add button
            StockIconToolButton* settingsButton = new StockIconToolButton(tableView, "x-capture-options");
            settingsButton->setFixedWidth(30);
            tableView->setIndexWidget(tableViewModel->indexFromItem(btnItem), settingsButton);

            connect(settingsButton, &StockIconToolButton::clicked, this, [=]() {
                QString optionValue = checked[i];
                this->showExtcapOptionsDialogForOptionValue(item, optionValue);
            });
        }
        else
        {
            tableViewModel->appendRow(item);
        }
    }

    tableView->resizeColumnToContents(1);
    tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
}

void ExtArgTable::setDefaultValue()
{
    QStringList checked;

    if (tableViewModel == 0)
        return;

    tableViewModel->clear();
    checked = defaultValue().split(",", Qt::SkipEmptyParts);
    addChecked(checked, QStringList());
}

void ExtArgTable::addKnown()
{
    // Un-select everything in the selector: it's a new day.
    QStringList checked;
    for (int row = 0; row < viewModel->rowCount(); row++)
        checkItemsWalker(((QStandardItemModel*)viewModel)->item(row), checked);

    // Display "add" popup
    if (addDialog->exec() == QDialog::Accepted)
    {
        checked = ExtArgMultiSelect::checkedValues();
        addChecked(checked, QStringList());
    }
}

void ExtArgTable::addCustom()
{
    // Prompt for custom input
    bool ok;
    QString text = QInputDialog::getText(
        tableView,
        tr("Add custom data"),
        tr("Custom:"),
        QLineEdit::Normal,
        "",
        &ok
    );
    if (ok && !text.isEmpty())
    {
        addChecked({ text }, QStringList());
    }
}

void ExtArgTable::removeSelected()
{
    // Get current selection
    QModelIndexList selected = tableView->selectionModel()->selectedIndexes();

    // Remove them from list
    for (int row = 0; row < selected.size(); row++)
        tableViewModel->removeRow(selected[row].row());
}

void ExtArgTable::showExtcapOptionsDialogForOptionValue(QStandardItem* item, QString& option_value)
{
    QString device_name(_argument->device_name);
    QString option_name(_argument->call + 2); /* skip -- */
    extcap_options_dialog = ExtcapOptionsDialog::createForDevice(device_name, false, tableView->parentWidget(),
                                                                                      &option_name, &option_value);
    /* The dialog returns null, if the given device name is not a valid extcap device */
    if (extcap_options_dialog) {
        extcap_options_dialog->setModal(true);
        extcap_options_dialog->setAttribute(Qt::WA_DeleteOnClose);
        connect(extcap_options_dialog, &ExtcapOptionsDialog::finished, this, [=]() {
            this->extcap_options_finished(item);
        });
        extcap_options_dialog->show();
    }
}

QString
extcap_format_external_arguments(GHashTable* extcap_args)
{
    QString command_line;

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, extcap_args);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        if (key != NULL)
        {
            command_line.append(g_strdup((char*)key));
            command_line.append(" ");
        }
        if (value != NULL)
        {
            command_line.append(g_strdup((char*)value));
            command_line.append(" ");
        }
    }

    return command_line;
}

void ExtArgTable::extcap_options_finished(QStandardItem* item)
{
    interface_t* device;
    bool dev_found = false;
    for (unsigned if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++)
    {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
        if (g_strcmp0(_argument->device_name, device->name) == 0 && device->if_info.type == IF_EXTCAP)
        {
            dev_found = true;
            break;
        }
    }

    if (dev_found && device->external_cap_args_settings != NULL)
    {
        QString arguments = extcap_format_external_arguments(device->external_cap_args_settings);
        item->setData(arguments, Qt::UserRole + 1);
    }
}
