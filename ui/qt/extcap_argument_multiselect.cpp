/* extcap_argument_multiselect.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include <color_utils.h>

#include <extcap_parser.h>
#include <extcap_argument_multiselect.h>

ExtArgMultiSelect::ExtArgMultiSelect(extcap_arg * argument) :
        ExtcapArgument(argument), treeView(0), viewModel(0) {}

ExtArgMultiSelect::~ExtArgMultiSelect()
{
    if ( treeView != 0 )
        delete treeView;
    if ( viewModel != 0 )
        delete viewModel;
}

QList<QStandardItem *> ExtArgMultiSelect::valueWalker(ExtcapValueList list, QStringList &defaults)
{
    ExtcapValueList::iterator iter = list.begin();
    QList<QStandardItem *> items;

    while ( iter != list.end() )
    {
        QStandardItem * item = new QStandardItem((*iter).value());
        if ( (*iter).enabled() == false )
        {
            item->setSelectable(false);
        }
        else
            item->setSelectable(true);

        item->setData((*iter).call(), Qt::UserRole);
        if ((*iter).isDefault())
            defaults << (*iter).call();

        item->setEditable(false);
        QList<QStandardItem *> childs = valueWalker((*iter).children(), defaults);
        if ( childs.length() > 0 )
            item->appendRows(childs);

        items << item;
        ++iter;
    }

    return items;
}

void ExtArgMultiSelect::selectItemsWalker(QStandardItem * item, QStringList defaults)
{
    QModelIndexList results;
    QModelIndex index;

    if ( item->hasChildren() )
    {
        for (int row = 0; row < item->rowCount(); row++)
        {
            QStandardItem * child = item->child(row);
            if ( child != 0 )
            {
                selectItemsWalker(child, defaults);
            }
        }
    }

    QString data = item->data(Qt::UserRole).toString();

    if ( defaults.contains(data) )
    {
        treeView->selectionModel()->select(item->index(), QItemSelectionModel::Select);
        index = item->index();
        while ( index.isValid() )
        {
            treeView->setExpanded(index, true);
            index = index.parent();
        }
    }
}

QWidget * ExtArgMultiSelect::createEditor(QWidget * parent)
{
    QStringList defaults;

    QList<QStandardItem *> items = valueWalker(values, defaults);
    if (items.length() == 0)
        return new QWidget();

    if ( defaultValue().length() > 0 )
        defaults = defaultValue().split(",", QString::SkipEmptyParts);

    viewModel = new QStandardItemModel();
    QList<QStandardItem *>::const_iterator iter = items.constBegin();
    while ( iter != items.constEnd() )
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

    for (int row = 0; row < viewModel->rowCount(); row++ )
        selectItemsWalker(((QStandardItemModel*)viewModel)->item(row), defaults);

    connect ( treeView->selectionModel(),
            SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
            SLOT(selectionChanged(const QItemSelection &, const QItemSelection &)) );

    return treeView;
}

QString ExtArgMultiSelect::value()
{
    if ( viewModel == 0 )
        return QString();

    QStringList result;
    QModelIndexList selected = treeView->selectionModel()->selectedIndexes();

    if ( selected.size() <= 0 )
        return QString();

    QModelIndexList::const_iterator iter = selected.constBegin();
    while ( iter != selected.constEnd() )
    {
        QModelIndex index = (QModelIndex)(*iter);

        result << viewModel->data(index, Qt::UserRole).toString();

        ++iter;
    }

    return result.join(QString(","));
}

void ExtArgMultiSelect::selectionChanged(const QItemSelection &, const QItemSelection &)
{
    emit valueChanged();
}

bool ExtArgMultiSelect::isValid()
{
    bool valid = true;

    if ( isRequired() )
    {
        if ( viewModel == 0 )
            valid = false;
        else
        {
            QStringList result;
            QModelIndexList selected = treeView->selectionModel()->selectedIndexes();

            if ( selected.size() <= 0 )
                valid = false;
        }
    }

    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();
    QString txtStyle("QTreeView { background-color: %1; } ");
    if ( viewModel != 0 )
        treeView->setStyleSheet( txtStyle.arg(valid ? QString("") : lblInvalidColor) );

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
