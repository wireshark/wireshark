/* packet_list.h
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

#ifndef PACKET_LIST_H
#define PACKET_LIST_H

#include "packet_list_model.h"
#include "byte_view_tab.h"

#include <QTreeView>
#include <QTreeWidget>

// It might make more sense to subclass QTableView here.
class PacketList : public QTreeView
{
    Q_OBJECT
public:
    explicit PacketList(QWidget *parent = 0);
    PacketListModel *packetListModel() const;
    void setProtoTree(QTreeWidget *protoTree);
    void setByteViewTab(ByteViewTab *byteViewTab);
    void clear();
    void writeRecent(FILE *rf);

protected:
    void showEvent (QShowEvent *event);
    void selectionChanged (const QItemSelection & selected, const QItemSelection & deselected);

private:
    PacketListModel *m_packet_list_model;
    QTreeWidget *m_protoTree;
    ByteViewTab *m_byteViewTab;

signals:

public slots:

};

#endif // PACKET_LIST_H
