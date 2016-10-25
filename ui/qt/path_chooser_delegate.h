/* path_chooser_delegate.h
 * Delegate to select a file path for a treeview entry
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

#ifndef PATH_CHOOSER_DELEGATE_H_
#define PATH_CHOOSER_DELEGATE_H_

#include <QStyledItemDelegate>

class PathChooserDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    PathChooserDelegate(QObject *parent = 0);

protected:
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &idx) const;
    void updateEditorGeometry (QWidget * editor, const QStyleOptionViewItem & option, const QModelIndex & idx) const;
    void setEditorData(QWidget *editor, const QModelIndex &idx) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &idx) const;

private slots:
    void browse_button_clicked();
};

#endif /* PATH_CHOOSER_DELEGATE_H_ */

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
