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

#include <extcap_parser.h>
#include <extcap_argument.h>

#include "extcap_options_dialog.h"

class ExtArgMultiSelect : public ExtcapArgument
{
    Q_OBJECT
public:
    ExtArgMultiSelect(extcap_arg * argument, QObject *parent = Q_NULLPTR);
    virtual ~ExtArgMultiSelect();

    virtual QString value();
    virtual bool isValid();
    virtual QString defaultValue();
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    virtual void setDefaultValue();

protected:
    virtual QList<QStandardItem *> valueWalker(ExtcapValueList list, QStringList &defaults);
    void checkItemsWalker(QStandardItem * item, QStringList defaults);
    virtual QWidget * createEditor(QWidget * parent);
    virtual QStringList checkedValues();
    QStandardItemModel* viewModel;
    /* This stores the displays associated with a value */
    QMap<QString, QString> displayNames;

private:
    QTreeView * treeView;

};


class ExtArgTable : public ExtArgMultiSelect
{
    Q_OBJECT

public:
    ExtArgTable(extcap_arg* argument, QObject* parent = Q_NULLPTR);
    virtual ~ExtArgTable();

    virtual QString value();

public Q_SLOTS:
    virtual void setDefaultValue();

protected:
    virtual QWidget* createEditor(QWidget* parent);
    void addKnown();
    void addCustom();
    void removeSelected();
    void addChecked(QStringList checked, QStringList options);
    virtual void showExtcapOptionsDialogForOptionValue(QStandardItem* item, QString& option_value);
    virtual void extcap_options_finished(QStandardItem* item);

private:
    ExtcapOptionsDialog* extcap_options_dialog;
    QDialog* addDialog;

    QStandardItemModel* tableViewModel;
    QTableView* tableView;

    QVBoxLayout* paneLayout;
    QToolBar* toolbar;
};

class ExtArgTableAddDialog : public QDialog
{
    Q_OBJECT

public:
    ExtArgTableAddDialog(QWidget* parent, QWidget* selector);
};

#endif /* UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_ */
