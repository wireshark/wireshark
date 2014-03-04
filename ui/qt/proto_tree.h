/* proto_tree.h
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

#ifndef PROTO_TREE_H
#define PROTO_TREE_H

#include "config.h"

#include <epan/proto.h>

#include <QTreeWidget>
#include <QMenu>

Q_DECLARE_METATYPE(field_info *)

class ProtoTree : public QTreeWidget
{
    Q_OBJECT
public:
    explicit ProtoTree(QWidget *parent = 0);
    void fillProtocolTree(proto_tree *protocol_tree);
    void emitRelatedFrame(int related_frame);
    void clear();

protected:
     void contextMenuEvent(QContextMenuEvent *event);

private:
     QMenu ctx_menu_;
     QAction *decode_as_;

signals:
    void protoItemSelected(QString &);
    void protoItemSelected(field_info *);
    void goToFrame(int);
    void relatedFrame(int);

public slots:
    void updateSelectionStatus(QTreeWidgetItem*);
    void expand(const QModelIndex & index);
    void collapse(const QModelIndex & index);
    void expandSubtrees();
    void expandAll();
    void collapseAll();
    void itemDoubleClick(QTreeWidgetItem *item, int column);
};

#endif // PROTO_TREE_H

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
