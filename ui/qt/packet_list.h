/* packet_list.h
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

#ifndef PACKET_LIST_H
#define PACKET_LIST_H

#include "byte_view_tab.h"
#include "packet_list_model.h"
#include "proto_tree.h"
#include "related_packet_delegate.h"

#include <QTreeView>
#include <QTreeWidget>
#include <QMenu>

// It might make more sense to subclass QTableView here.
class PacketList : public QTreeView
{
    Q_OBJECT
public:
    explicit PacketList(QWidget *parent = 0);
    PacketListModel *packetListModel() const;
    void setProtoTree(ProtoTree *proto_tree);
    void setByteViewTab(ByteViewTab *byteViewTab);
    void updateAll();
    void freeze();
    void thaw();
    void clear();
    void writeRecent(FILE *rf);
    bool contextMenuActive();
    QString &getFilterFromRowAndColumn();
    QString packetComment();
    void setPacketComment(QString new_comment);
    QString allPacketComments();

protected:
    void showEvent (QShowEvent *event);
    void selectionChanged (const QItemSelection & selected, const QItemSelection & deselected);
    void contextMenuEvent(QContextMenuEvent *event);


private:
    PacketListModel *packet_list_model_;
    ProtoTree *proto_tree_;
    ByteViewTab *byte_view_tab_;
    capture_file *cap_file_;
    QMenu ctx_menu_;
    QList<QMenu *> submenus_;
    QList<QAction *> filter_actions_;
    QAction *decode_as_;
    int ctx_column_;
    RelatedPacketDelegate related_packet_delegate_;

    void markFramesReady();
    void setFrameMark(gboolean set, frame_data *fdata);
    void setFrameIgnore(gboolean set, frame_data *fdata);
    void setFrameReftime(gboolean set, frame_data *fdata);
    void setColumnVisibility();

signals:
    void packetDissectionChanged();
    void packetSelectionChanged();

public slots:
    void setCaptureFile(capture_file *cf);
    void goNextPacket();
    void goPreviousPacket();
    void goFirstPacket();
    void goLastPacket();
    void goToPacket(int packet);
    void markFrame();
    void markAllDisplayedFrames(bool set);
    void ignoreFrame();
    void ignoreAllDisplayedFrames(bool set);
    void setTimeReference();
    void unsetAllTimeReferences();

private slots:
    void addRelatedFrame(int related_frame);
};

#endif // PACKET_LIST_H

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
