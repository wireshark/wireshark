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

#include <extcap_parser.h>
#include <extcap_argument.h>

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

private:

    QTreeView * treeView;
    QStandardItemModel * viewModel;

};

#endif /* UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_ */
