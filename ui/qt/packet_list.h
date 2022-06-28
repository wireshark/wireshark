/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIST_H
#define PACKET_LIST_H

#include "byte_view_tab.h"
#include <ui/qt/models/packet_list_model.h>
#include "proto_tree.h"
#include "protocol_preferences_menu.h"
#include <ui/qt/models/related_packet_delegate.h>
#include <ui/qt/utils/field_information.h>

#include <QMenu>
#include <QTime>
#include <QTreeView>
#include <QPainter>

class PacketListHeader;
class OverlayScrollBar;

class QAction;
class QTimerEvent;

//
// XXX - Wireshark supports up to 2^32-1 packets in a capture, but
// row numbers in a QAbstractItemModel are ints, not unsigned ints,
// so we can only have 2^31-1 rows on ILP32, LP64, and LLP64 platforms.
// Does that mean we're permanently stuck at a maximum of 2^31-1 packets
// per capture?
//
class PacketList : public QTreeView
{
    Q_OBJECT
public:
    explicit PacketList(QWidget *parent = 0);

    enum SummaryCopyType {
        CopyAsText,
        CopyAsCSV,
        CopyAsYAML
    };
    Q_ENUM(SummaryCopyType)

    QMenu *conversationMenu() { return &conv_menu_; }
    QMenu *colorizeMenu() { return &colorize_menu_; }
    void setProtoTree(ProtoTree *proto_tree);

    /** Disable and clear the packet list.
     *
     * Disable packet list widget updates, clear the detail and byte views,
     * and disconnect the model.
     */
    void freeze();
    /** Enable and restore the packet list.
     *
     * Enable packet list widget updates and reconnect the model.
     *
     * @param restore_selection If true, redissect the previously selected
     * packet. This includes filling in the detail and byte views.
     */
    void thaw(bool restore_selection = false);
    void clear();
    void writeRecent(FILE *rf);
    bool contextMenuActive();
    QString getFilterFromRowAndColumn(QModelIndex idx);
    void resetColorized();
    QString getPacketComment(guint c_number);
    void addPacketComment(QString new_comment);
    void setPacketComment(guint c_number, QString new_comment);
    QString allPacketComments();
    void deleteCommentsFromPackets();
    void deleteAllPacketComments();
    void setVerticalAutoScroll(bool enabled = true);
    void setCaptureInProgress(bool in_progress = false) { capture_in_progress_ = in_progress; tail_at_end_ = in_progress; }
    void captureFileReadFinished();
    void resetColumns();
    bool haveNextHistory(bool update_cur = false);
    bool havePreviousHistory(bool update_cur = false);

    frame_data * getFDataForRow(int row) const;

    bool multiSelectActive();
    QList<int> selectedRows(bool useFrameNum = false);

    QString createSummaryText(QModelIndex idx, SummaryCopyType type);
    QString createHeaderSummaryText(SummaryCopyType type);

    void resizeAllColumns(bool onlyTimeFormatted = false);

protected:

    void selectionChanged(const QItemSelection & selected, const QItemSelection & deselected) override;
    virtual void contextMenuEvent(QContextMenuEvent *event) override;
    void timerEvent(QTimerEvent *event) override;
    void paintEvent(QPaintEvent *event) override;
    virtual void mousePressEvent (QMouseEvent *event) override;
    virtual void mouseReleaseEvent (QMouseEvent *event) override;
    virtual void mouseMoveEvent (QMouseEvent *event) override;
    virtual void resizeEvent(QResizeEvent *event) override;
    virtual void keyPressEvent(QKeyEvent *event) override;

protected slots:
    void rowsInserted(const QModelIndex &parent, int start, int end) override;
    virtual void drawRow(QPainter *painter, const QStyleOptionViewItem &option,
        const QModelIndex &index) const override;

private:
    PacketListModel *packet_list_model_;
    PacketListHeader * packet_list_header_;
    ProtoTree *proto_tree_;
    capture_file *cap_file_;
    QMenu conv_menu_;
    QMenu colorize_menu_;
    QMenu proto_prefs_menus_;
    int ctx_column_;
    QByteArray column_state_;
    OverlayScrollBar *overlay_sb_;
    int overlay_timer_id_;
    bool create_near_overlay_;
    bool create_far_overlay_;
    QVector<QRgb> overlay_colors_;

    QModelIndex mouse_pressed_at_;

    RelatedPacketDelegate related_packet_delegate_;
    QAction *show_hide_separator_;
    QList<QAction *>show_hide_actions_;
    bool capture_in_progress_;
    int tail_timer_id_;
    bool tail_at_end_;
    bool rows_inserted_;
    bool columns_changed_;
    bool set_column_visibility_;
    QModelIndexList frozen_rows_;
    QVector<int> selection_history_;
    int cur_history_;
    bool in_history_;

    void setFrameReftime(gboolean set, frame_data *fdata);
    void setColumnVisibility();
    int sizeHintForColumn(int column) const override;
    void setRecentColumnWidth(int column);
    void drawCurrentPacket();
    void applyRecentColumnWidths();
    void scrollViewChanged(bool at_end);
    void colorsChanged();
    QString joinSummaryRow(QStringList col_parts, int row, SummaryCopyType type);

signals:
    void packetDissectionChanged();
    void showColumnPreferences(QString pane_name);
    void editColumn(int column);
    void packetListScrolled(bool at_end);
    void showProtocolPreferences(const QString module_name);
    void editProtocolPreference(struct preference *pref, struct pref_module *module);

    void framesSelected(QList<int>);
    void fieldSelected(FieldInformation *);

public slots:
    void setCaptureFile(capture_file *cf);
    void setMonospaceFont(const QFont &mono_font);
    void goNextPacket();
    void goPreviousPacket();
    void goFirstPacket(bool user_selected = true);
    void goLastPacket();
    void goToPacket(int packet, int hf_id = -1);
    void goNextHistoryPacket();
    void goPreviousHistoryPacket();
    void markFrame();
    void markAllDisplayedFrames(bool set);
    void ignoreFrame();
    void ignoreAllDisplayedFrames(bool set);
    void setTimeReference();
    void unsetAllTimeReferences();
    void applyTimeShift();
    void recolorPackets();
    void redrawVisiblePackets();
    void redrawVisiblePacketsDontSelectCurrent();
    void columnsChanged();
    void fieldsChanged(capture_file *cf);
    void preferencesChanged();

private slots:
    void columnVisibilityTriggered();
    void sectionResized(int col, int, int new_width);
    void sectionMoved(int, int, int);
    void updateRowHeights(const QModelIndex &ih_index);
    void copySummary();
    void vScrollBarActionTriggered(int);
    void drawFarOverlay();
    void drawNearOverlay();
    void updatePackets(bool redraw);
    void ctxDecodeAsDialog();
};

#endif // PACKET_LIST_H
