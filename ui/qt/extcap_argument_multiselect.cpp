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

#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QBoxLayout>
#include <QPushButton>
#include <QVariant>

#include <epan/prefs.h>
#include <ui/qt/utils/color_utils.h>

#include <extcap_parser.h>
#include <extcap_argument_multiselect.h>

ExtArgMultiSelect::ExtArgMultiSelect(extcap_arg * argument, QObject *parent) :
        ExtcapArgument(argument, parent), treeView(0), viewModel(0) {}

ExtArgMultiSelect::~ExtArgMultiSelect()
{
    if (treeView != 0)
        delete treeView;
    if (viewModel != 0)
        delete viewModel;
}

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

        item->setSelectable(false);
        item->setEditable(false);
        QList<QStandardItem *> childs = valueWalker((*iter).children(), defaults);
        if (childs.length() > 0)
            item->appendRows(childs);

        items << item;
        ++iter;
    }

    return items;
}

void ExtArgMultiSelect::checkItemsWalker(QStandardItem * item, QStringList defaults)
{
    QModelIndexList results;
    QModelIndex index;

    if (item->hasChildren())
    {
        for (int row = 0; row < item->rowCount(); row++)
        {
            QStandardItem * child = item->child(row);
            if (child != 0)
            {
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
    }
}

QWidget * ExtArgMultiSelect::createEditor(QWidget * parent)
{
    QStringList checked;

    QList<QStandardItem *> items = valueWalker(values, checked);
    if (items.length() == 0)
        return new QWidget();

    if (_argument->pref_valptr && *_argument->pref_valptr)
    {
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        checked = QString(*_argument->pref_valptr).split(",", Qt::SkipEmptyParts);
#else
        checked = QString(*_argument->pref_valptr).split(",", QString::SkipEmptyParts);
#endif
    }

    viewModel = new QStandardItemModel();
    QList<QStandardItem *>::const_iterator iter = items.constBegin();
    while (iter != items.constEnd())
    {
        ((QStandardItemModel *)viewModel)->appendRow((*iter));
        ++iter;
    }

    treeView = new QTreeView(parent);
    treeView->setModel(viewModel);

    /* Shows at minimum 6 entries at most desktops */
    treeView->setMinimumHeight(100);
    treeView->setHeaderHidden(true);
    treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    for (int row = 0; row < viewModel->rowCount(); row++)
        checkItemsWalker(((QStandardItemModel*)viewModel)->item(row), checked);

    connect (viewModel,
            SIGNAL(itemChanged(QStandardItem *)),
            SLOT(itemChanged(QStandardItem *)));

    return treeView;
}

QString ExtArgMultiSelect::value()
{
    if (viewModel == 0)
        return QString();

    QStringList result;
    QModelIndexList checked = viewModel->match(viewModel->index(0, 0), Qt::CheckStateRole, Qt::Checked, -1, Qt::MatchExactly | Qt::MatchRecursive);
    if (checked.size() <= 0)
        return QString();

    QModelIndexList::const_iterator iter = checked.constBegin();
    while (iter != checked.constEnd())
    {
        QModelIndex index = (QModelIndex)(*iter);

        result << viewModel->data(index, Qt::UserRole).toString();

        ++iter;
    }

    return result.join(QString(","));
}

void ExtArgMultiSelect::itemChanged(QStandardItem *)
{
    emit valueChanged();
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

    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();
    QString txtStyle("QTreeView { background-color: %1; } ");
    if (viewModel != 0)
        treeView->setStyleSheet(txtStyle.arg(valid ? QString("") : lblInvalidColor));

    return valid;
}


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
