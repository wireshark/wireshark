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
#include "preferences_dialog.h"
#include "proto_tree.h"
#include "protocol_preferences_menu.h"
#include "related_packet_delegate.h"

#include <QMenu>
#include <QTime>
#include <QTreeView>
#include <QPainter>

class OverlayScrollBar;

class QAction;
class QTimerEvent;

class PacketList : public QTreeView
{
    Q_OBJECT
public:
    enum ColumnActions {
        caAlignLeft,
        caAlignCenter,
        caAlignRight,
        caColumnPreferences,
        caEditColumn,
        caResolveNames,
        caResizeToContents,
        caDisplayedColumns,
        caHideColumn,
        caRemoveColumn
    };
    explicit PacketList(QWidget *parent = 0);
    PacketListModel *packetListModel() const;
    QMenu *conversationMenu() { return &conv_menu_; }
    QMenu *colorizeMenu() { return &colorize_menu_; }
    void setProtoTree(ProtoTree *proto_tree);
    void setByteViewTab(ByteViewTab *byteViewTab);
    void freeze();
    void thaw();
    void clear();
    void writeRecent(FILE *rf);
    bool contextMenuActive();
    QString getFilterFromRowAndColumn();
    void resetColorized();
    QString packetComment();
    void setPacketComment(QString new_comment);
    QString allPacketComments();
    void setVerticalAutoScroll(bool enabled = true);
    void setCaptureInProgress(bool in_progress = false) { capture_in_progress_ = in_progress; tail_at_end_ = in_progress; }
    void captureFileReadFinished();
    void resetColumns();

protected:
    void showEvent(QShowEvent *);
    void selectionChanged(const QItemSelection & selected, const QItemSelection & deselected);
    void contextMenuEvent(QContextMenuEvent *event);
    void timerEvent(QTimerEvent *event);
    void paintEvent(QPaintEvent *event);
    virtual void mousePressEvent (QMouseEvent *event);
    virtual void resizeEvent(QResizeEvent *event);

protected slots:
    void rowsInserted(const QModelIndex &parent, int start, int end);
    void drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const;

private:
    PacketListModel *packet_list_model_;
    ProtoTree *proto_tree_;
    ByteViewTab *byte_view_tab_;
    capture_file *cap_file_;
    QMenu ctx_menu_;
    QMenu conv_menu_;
    QMenu colorize_menu_;
    ProtocolPreferencesMenu proto_prefs_menu_;
    QAction *decode_as_;
    QList<QAction *> copy_actions_;
    int ctx_column_;
    QByteArray column_state_;
    OverlayScrollBar *overlay_sb_;
    int overlay_timer_id_;
    bool create_near_overlay_;
    bool create_far_overlay_;
    QVector<QRgb> overlay_colors_;

    RelatedPacketDelegate related_packet_delegate_;
    QMenu header_ctx_menu_;
    QMap<ColumnActions, QAction*> header_actions_;
    QList<ColumnActions> checkable_actions_;
    int header_ctx_column_;
    QAction *show_hide_separator_;
    QList<QAction *>show_hide_actions_;
    bool capture_in_progress_;
    int tail_timer_id_;
    bool tail_at_end_;
    bool rows_inserted_;
    bool columns_changed_;
    bool set_column_visibility_;

    void setFrameReftime(gboolean set, frame_data *fdata);
    void setColumnVisibility();
    int sizeHintForColumn(int column) const;
    void setRecentColumnWidth(int column);
    void initHeaderContextMenu();
    void drawCurrentPacket();
    void applyRecentColumnWidths();

signals:
    void packetDissectionChanged();
    void packetSelectionChanged();
    void showColumnPreferences(PreferencesDialog::PreferencesPane start_pane);
    void editColumn(int column);
    void packetListScrolled(bool at_end);
    void showProtocolPreferences(const QString module_name);
    void editProtocolPreference(struct preference *pref, struct pref_module *module);

public slots:
    void setCaptureFile(capture_file *cf);
    void setMonospaceFont(const QFont &mono_font);
    void goNextPacket();
    void goPreviousPacket();
    void goFirstPacket();
    void goLastPacket();
    void goToPacket(int packet);
    void goToPacket(int packet, int hf_id);
    void markFrame();
    void markAllDisplayedFrames(bool set);
    void ignoreFrame();
    void ignoreAllDisplayedFrames(bool set);
    void setTimeReference();
    void unsetAllTimeReferences();
    void applyTimeShift();
    void recolorPackets();
    void redrawVisiblePackets();
    void columnsChanged();
    void fieldsChanged(capture_file *cf);
    void preferencesChanged();

private slots:
    void showHeaderMenu(QPoint pos);
    void headerMenuTriggered();
    void columnVisibilityTriggered();
    void sectionResized(int col, int, int new_width);
    void sectionMoved(int, int, int);
    void updateRowHeights(const QModelIndex &ih_index);
    void copySummary();
    void vScrollBarActionTriggered(int);
    void drawFarOverlay();
    void drawNearOverlay();
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
