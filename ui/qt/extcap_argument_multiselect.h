/* extcap_argument_multiselect.h
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
    ExtArgMultiSelect(extcap_arg * argument);
    virtual ~ExtArgMultiSelect();

    virtual QString value();
    virtual bool isValid();

protected:
    virtual QList<QStandardItem *> valueWalker(ExtcapValueList list, QStringList &defaults);
    void selectItemsWalker(QStandardItem * item, QStringList defaults);
    virtual QWidget * createEditor(QWidget * parent);

private Q_SLOTS:

    void selectionChanged(const QItemSelection & selected, const QItemSelection & deselected);

private:

    QTreeView * treeView;
    QAbstractItemModel * viewModel;

};

#endif /* UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_ */

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
