/* proto_tree.h
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PROTO_TREE_H
#define PROTO_TREE_H

#include "config.h"

#include <epan/proto.h>

#include <QTreeWidget>


class ProtoTree : public QTreeWidget
{
    Q_OBJECT
public:
    explicit ProtoTree(QWidget *parent = 0);
    void fillProtocolTree(proto_tree *protocol_tree);
    void clear();

private:

signals:
    void protoItemSelected(QString &);
    void protoItemUnselected();

public slots:
    void updateSelectionStatus(QTreeWidgetItem*);

};

#endif // PROTO_TREE_H
