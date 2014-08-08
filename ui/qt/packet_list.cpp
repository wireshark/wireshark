/* packet_list.cpp
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

#include "config.h"

#include <glib.h>

#include "file.h"

#include <epan/epan.h>
#include <epan/epan_dissect.h>

#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet_list.h"
#include "proto_tree.h"
#include "wireshark_application.h"
#include "epan/ipproto.h"

#include "qt_ui_utils.h"

#include "ui/main_statusbar.h"
#include "ui/packet_list_utils.h"
#include "ui/preference_utils.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/ui_util.h"
#include "ui/utf8_entities.h"

#include "wsutil/str_util.h"

#include "frame_tvbuff.h"

#include <QAction>
#include <QActionGroup>
#include <QContextMenuEvent>
#include <QFontMetrics>
#include <QHeaderView>
#include <QMessageBox>
#include <QScrollBar>
#include <QTabWidget>
#include <QTextEdit>
#include <QTimerEvent>
#include <QTreeWidget>

// To do:
// - Catch column reordering and rebuild the column list accoringly.
// - Use a timer to trigger automatic scrolling.

// If we ever add the ability to open multiple capture files we might be
// able to use something like QMap<capture_file *, PacketList *> to match
// capture files against packet lists and models.
static PacketList *gbl_cur_packet_list = NULL;

const int max_comments_to_fetch_ = 20000000; // Arbitrary
const int tail_update_interval_ = 100; // Milliseconds.

guint
packet_list_append(column_info *cinfo, frame_data *fdata)
{
    Q_UNUSED(cinfo);

    if (!gbl_cur_packet_list)
        return 0;

    /* fdata should be filled with the stuff we need
     * strings are built at display time.
     */
    guint visible_pos;

    visible_pos = gbl_cur_packet_list->packetListModel()->appendPacket(fdata);
    return visible_pos;
}

// Copied from ui/gtk/packet_list.c
void packet_list_resize_column(gint col)
{
    if (!gbl_cur_packet_list) return;
    gbl_cur_packet_list->resizeColumnToContents(col);
}

void
packet_list_select_first_row(void)
{
    if (!gbl_cur_packet_list)
        return;
    gbl_cur_packet_list->goFirstPacket();
    gbl_cur_packet_list->setFocus();
}

void
packet_list_select_last_row(void)
{
    if (!gbl_cur_packet_list)
        return;
    gbl_cur_packet_list->goLastPacket();
    gbl_cur_packet_list->setFocus();
}

/*
 * Given a frame_data structure, scroll to and select the row in the
 * packet list corresponding to that frame.  If there is no such
 * row, return FALSE, otherwise return TRUE.
 */
gboolean
packet_list_select_row_from_data(frame_data *fdata_needle)
{
    int row = gbl_cur_packet_list->packetListModel()->visibleIndexOf(fdata_needle);
    if (row >= 0) {
        gbl_cur_packet_list->setCurrentIndex(gbl_cur_packet_list->packetListModel()->index(row,0));
        return TRUE;
    }

    return FALSE;
}

gboolean
packet_list_check_end(void)
{
    return FALSE; // GTK+ only.
}

void
packet_list_clear(void)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->clear();
    }
}

void
packet_list_enable_color(gboolean enable)
{
    Q_UNUSED(enable);
    if (gbl_cur_packet_list && gbl_cur_packet_list->packetListModel()) {
        gbl_cur_packet_list->packetListModel()->resetColorized();
        gbl_cur_packet_list->update();
    }
}

void
packet_list_freeze(void)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->freeze();
    }
}

void
packet_list_thaw(void)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->thaw();
    }

    packets_bar_update();
}

void
packet_list_recreate_visible_rows(void)
{
    if (gbl_cur_packet_list && gbl_cur_packet_list->packetListModel()) {
        gbl_cur_packet_list->packetListModel()->recreateVisibleRows();
    }
}

frame_data *
packet_list_get_row_data(gint row)
{
    if (gbl_cur_packet_list && gbl_cur_packet_list->packetListModel()) {
        return gbl_cur_packet_list->packetListModel()->getRowFdata(row);
    }
    return NULL;
}

// Called from cf_continue_tail and cf_finish_tail when auto_scroll_live
// is enabled.
void
packet_list_moveto_end(void)
{
    // gbl_cur_packet_list->scrollToBottom();
}

/* Redraw the packet list *and* currently-selected detail */
void
packet_list_queue_draw(void)
{
    if (gbl_cur_packet_list)
        gbl_cur_packet_list->redrawVisiblePackets();
}

void
packet_list_recent_write_all(FILE *rf) {
    if (!gbl_cur_packet_list)
        return;

    gbl_cur_packet_list->writeRecent(rf);
}

#define MIN_COL_WIDTH_STR "...."

Q_DECLARE_METATYPE(PacketList::ColumnActions)

PacketList::PacketList(QWidget *parent) :
    QTreeView(parent),
    proto_tree_(NULL),
    byte_view_tab_(NULL),
    cap_file_(NULL),
    decode_as_(NULL),
    ctx_column_(-1),
    capture_in_progress_(false),
    tail_timer_id_(0),
    rows_inserted_(false)
{
    QMenu *submenu, *subsubmenu;
    QAction *action;

    setItemsExpandable(false);
    setRootIsDecorated(false);
    setSortingEnabled(true);
    setAccessibleName("Packet list");
    setItemDelegateForColumn(0, &related_packet_delegate_);

    packet_list_model_ = new PacketListModel(this, cap_file_);
    setModel(packet_list_model_);
    sortByColumn(-1, Qt::AscendingOrder);

    // XXX We might want to reimplement setParent() and fill in the context
    // menu there.
    ctx_menu_.addAction(window()->findChild<QAction *>("actionEditMarkPacket"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionEditIgnorePacket"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionEditSetTimeReference"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionEditTimeShift"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionEditPacketComment"));

    ctx_menu_.addSeparator();

    action = window()->findChild<QAction *>("actionFollow");
    submenu = new QMenu();
    action->setMenu(submenu);
    ctx_menu_.addAction(action);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowTCPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowUDPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowSSLStream"));

    action = window()->findChild<QAction *>("actionSCTP");
    submenu = new QMenu();
    action->setMenu(submenu);
    ctx_menu_.addAction(action);
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionSCTPAnalyseThisAssociation"));
    submenu->addAction(window()->findChild<QAction *>("actionSCTPShowAllAssociations"));
    submenu->addAction(window()->findChild<QAction *>("actionSCTPFilterThisAssociation"));

    ctx_menu_.addSeparator();

//    "     <menuitem name='ManuallyResolveAddress' action='/ManuallyResolveAddress'/>\n"
//    ctx_menu_.addSeparator();

    action = window()->findChild<QAction *>("actionApply_as_Filter");
    submenu = new QMenu();
    action->setMenu(submenu);
    ctx_menu_.addAction(action);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrNotSelected"));

    action = window()->findChild<QAction *>("actionPrepare_a_Filter");
    submenu = new QMenu();
    action->setMenu(submenu);
    ctx_menu_.addAction(action);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrNotSelected"));

    QMenu *main_conv_menu = window()->findChild<QMenu *>("menuConversationFilter");
    conv_menu_.setTitle(main_conv_menu->title());
    ctx_menu_.addMenu(&conv_menu_);

//    "     <menu name= 'ConversationFilter' action='/Conversation Filter'>\n"
//    "       <menuitem name='Ethernet' action='/Conversation Filter/Ethernet'/>\n"
//    "       <menuitem name='IP' action='/Conversation Filter/IP'/>\n"
//    "       <menuitem name='TCP' action='/Conversation Filter/TCP'/>\n"
//    "       <menuitem name='UDP' action='/Conversation Filter/UDP'/>\n"
//    "       <menuitem name='PN-CBA' action='/Conversation Filter/PN-CBA'/>\n"
    //submenu = new QMenu(tr("Colorize with Filter"));
//    "     <menu name= 'ColorizeConversation' action='/Colorize Conversation'>\n"
//    "        <menu name= 'Ethernet' action='/Colorize Conversation/Ethernet'>\n"
//    "          <menuitem name='Color1' action='/Colorize Conversation/Ethernet/Color 1'/>\n"
//    "          <menuitem name='Color2' action='/Colorize Conversation/Ethernet/Color 2'/>\n"
//    "          <menuitem name='Color3' action='/Colorize Conversation/Ethernet/Color 3'/>\n"
//    "          <menuitem name='Color4' action='/Colorize Conversation/Ethernet/Color 4'/>\n"
//    "          <menuitem name='Color5' action='/Colorize Conversation/Ethernet/Color 5'/>\n"
//    "          <menuitem name='Color6' action='/Colorize Conversation/Ethernet/Color 6'/>\n"
//    "          <menuitem name='Color7' action='/Colorize Conversation/Ethernet/Color 7'/>\n"
//    "          <menuitem name='Color8' action='/Colorize Conversation/Ethernet/Color 8'/>\n"
//    "          <menuitem name='Color9' action='/Colorize Conversation/Ethernet/Color 9'/>\n"
//    "          <menuitem name='Color10' action='/Colorize Conversation/Ethernet/Color 10'/>\n"
//    "          <menuitem name='NewColoringRule' action='/Colorize Conversation/Ethernet/New Coloring Rule'/>\n"
//    "        <menu name= 'IP' action='/Colorize Conversation/IP'>\n"
//    "          <menuitem name='Color1' action='/Colorize Conversation/IP/Color 1'/>\n"
//    "          <menuitem name='Color2' action='/Colorize Conversation/IP/Color 2'/>\n"
//    "          <menuitem name='Color3' action='/Colorize Conversation/IP/Color 3'/>\n"
//    "          <menuitem name='Color4' action='/Colorize Conversation/IP/Color 4'/>\n"
//    "          <menuitem name='Color5' action='/Colorize Conversation/IP/Color 5'/>\n"
//    "          <menuitem name='Color6' action='/Colorize Conversation/IP/Color 6'/>\n"
//    "          <menuitem name='Color7' action='/Colorize Conversation/IP/Color 7'/>\n"
//    "          <menuitem name='Color8' action='/Colorize Conversation/IP/Color 8'/>\n"
//    "          <menuitem name='Color9' action='/Colorize Conversation/IP/Color 9'/>\n"
//    "          <menuitem name='Color10' action='/Colorize Conversation/IP/Color 10'/>\n"
//    "          <menuitem name='NewColoringRule' action='/Colorize Conversation/IP/New Coloring Rule'/>\n"
//    "        <menu name= 'TCP' action='/Colorize Conversation/TCP'>\n"
//    "          <menuitem name='Color1' action='/Colorize Conversation/TCP/Color 1'/>\n"
//    "          <menuitem name='Color2' action='/Colorize Conversation/TCP/Color 2'/>\n"
//    "          <menuitem name='Color3' action='/Colorize Conversation/TCP/Color 3'/>\n"
//    "          <menuitem name='Color4' action='/Colorize Conversation/TCP/Color 4'/>\n"
//    "          <menuitem name='Color5' action='/Colorize Conversation/TCP/Color 5'/>\n"
//    "          <menuitem name='Color6' action='/Colorize Conversation/TCP/Color 6'/>\n"
//    "          <menuitem name='Color7' action='/Colorize Conversation/TCP/Color 7'/>\n"
//    "          <menuitem name='Color8' action='/Colorize Conversation/TCP/Color 8'/>\n"
//    "          <menuitem name='Color9' action='/Colorize Conversation/TCP/Color 9'/>\n"
//    "          <menuitem name='Color10' action='/Colorize Conversation/TCP/Color 10'/>\n"
//    "          <menuitem name='NewColoringRule' action='/Colorize Conversation/TCP/New Coloring Rule'/>\n"
//    "        <menu name= 'UDP' action='/Colorize Conversation/UDP'>\n"
//    "          <menuitem name='Color1' action='/Colorize Conversation/UDP/Color 1'/>\n"
//    "          <menuitem name='Color2' action='/Colorize Conversation/UDP/Color 2'/>\n"
//    "          <menuitem name='Color3' action='/Colorize Conversation/UDP/Color 3'/>\n"
//    "          <menuitem name='Color4' action='/Colorize Conversation/UDP/Color 4'/>\n"
//    "          <menuitem name='Color5' action='/Colorize Conversation/UDP/Color 5'/>\n"
//    "          <menuitem name='Color6' action='/Colorize Conversation/UDP/Color 6'/>\n"
//    "          <menuitem name='Color7' action='/Colorize Conversation/UDP/Color 7'/>\n"
//    "          <menuitem name='Color8' action='/Colorize Conversation/UDP/Color 8'/>\n"
//    "          <menuitem name='Color9' action='/Colorize Conversation/UDP/Color 9'/>\n"
//    "          <menuitem name='Color10' action='/Colorize Conversation/UDP/Color 10'/>\n"
//    "          <menuitem name='NewColoringRule' action='/Colorize Conversation/UDP/New Coloring Rule'/>\n"
//    "        <menu name= 'PN-CBA' action='/Colorize Conversation/PN-CBA'>\n"
//    "          <menuitem name='Color1' action='/Colorize Conversation/PN-CBA/Color 1'/>\n"
//    "          <menuitem name='Color2' action='/Colorize Conversation/PN-CBA/Color 2'/>\n"
//    "          <menuitem name='Color3' action='/Colorize Conversation/PN-CBA/Color 3'/>\n"
//    "          <menuitem name='Color4' action='/Colorize Conversation/PN-CBA/Color 4'/>\n"
//    "          <menuitem name='Color5' action='/Colorize Conversation/PN-CBA/Color 5'/>\n"
//    "          <menuitem name='Color6' action='/Colorize Conversation/PN-CBA/Color 6'/>\n"
//    "          <menuitem name='Color7' action='/Colorize Conversation/PN-CBA/Color 7'/>\n"
//    "          <menuitem name='Color8' action='/Colorize Conversation/PN-CBA/Color 8'/>\n"
//    "          <menuitem name='Color9' action='/Colorize Conversation/PN-CBA/Color 9'/>\n"
//    "          <menuitem name='Color10' action='/Colorize Conversation/PN-CBA/Color 10'/>\n"
//    "          <menuitem name='NewColoringRule' action='/Colorize Conversation/PN-CBA/New Coloring Rule'/>\n"
//    "     <menu name= 'SCTP' action='/SCTP'>\n"
//    "        <menuitem name='AnalysethisAssociation' action='/SCTP/Analyse this Association'/>\n"
//    "        <menuitem name='PrepareFilterforthisAssociation' action='/SCTP/Prepare Filter for this Association'/>\n"
//    "     <menuitem name='FollowTCPStream' action='/Follow TCP Stream'/>\n"
//    "     <menuitem name='FollowUDPStream' action='/Follow UDP Stream'/>\n"
//    "     <menuitem name='FollowSSLStream' action='/Follow SSL Stream'/>\n"
    ctx_menu_.addSeparator();

    action = window()->findChild<QAction *>("actionCopy");
    submenu = new QMenu();
    action->setMenu(submenu);
    ctx_menu_.addAction(action);
    //    "        <menuitem name='SummaryTxt' action='/Copy/SummaryTxt'/>\n"
    //    "        <menuitem name='SummaryCSV' action='/Copy/SummaryCSV'/>\n"
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyAsFilter"));
    submenu->addSeparator();

    action = window()->findChild<QAction *>("actionBytes");
    subsubmenu = new QMenu();
    action->setMenu(subsubmenu);
    submenu->addAction(action);
    //    "           <menuitem name='OffsetHexText' action='/Copy/Bytes/OffsetHexText'/>\n"
    //    "           <menuitem name='OffsetHex' action='/Copy/Bytes/OffsetHex'/>\n"
    //    "           <menuitem name='PrintableTextOnly' action='/Copy/Bytes/PrintableTextOnly'/>\n"
//    ctx_menu_.addSeparator();
//    "           <menuitem name='HexStream' action='/Copy/Bytes/HexStream'/>\n"
//    "           <menuitem name='BinaryStream' action='/Copy/Bytes/BinaryStream'/>\n"
    ctx_menu_.addSeparator();
//    "     <menuitem name='ProtocolPreferences' action='/ProtocolPreferences'/>\n"
    decode_as_ = window()->findChild<QAction *>("actionAnalyzeDecodeAs");
    ctx_menu_.addAction(decode_as_);
    // "Print" not ported intentionally
//    "     <menuitem name='ShowPacketinNewWindow' action='/ShowPacketinNewWindow'/>\n"
    action = window()->findChild<QAction *>("actionViewShowPacketInNewWindow");
    ctx_menu_.addAction(action);

    initHeaderContextMenu();

    g_assert(gbl_cur_packet_list == NULL);
    gbl_cur_packet_list = this;

    connect(packet_list_model_, SIGNAL(goToPacket(int)), this, SLOT(goToPacket(int)));
    connect(wsApp, SIGNAL(addressResolutionChanged()), this, SLOT(redrawVisiblePackets()));

    header()->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(header(), SIGNAL(customContextMenuRequested(QPoint)),
            this, SLOT(showHeaderMenu(QPoint)));
    connect(header(), SIGNAL(sectionResized(int,int,int)),
            this, SLOT(sectionResized(int,int,int)));

    connect(verticalScrollBar(), SIGNAL(actionTriggered(int)), this, SLOT(vScrollBarActionTriggered(int)));
}

void PacketList::setProtoTree (ProtoTree *proto_tree) {
    proto_tree_ = proto_tree;

    connect(proto_tree_, SIGNAL(goToPacket(int)), this, SLOT(goToPacket(int)));
    connect(proto_tree_, SIGNAL(relatedFrame(int,ft_framenum_type_t)),
            &related_packet_delegate_, SLOT(addRelatedFrame(int,ft_framenum_type_t)));
}

void PacketList::setByteViewTab (ByteViewTab *byte_view_tab) {
    byte_view_tab_ = byte_view_tab;

    connect(proto_tree_, SIGNAL(currentItemChanged(QTreeWidgetItem*,QTreeWidgetItem*)),
            byte_view_tab_, SLOT(protoTreeItemChanged(QTreeWidgetItem*)));
}

PacketListModel *PacketList::packetListModel() const {
    return packet_list_model_;
}

void PacketList::showEvent (QShowEvent *) {
    setColumnVisibility();
}

void PacketList::selectionChanged (const QItemSelection & selected, const QItemSelection & deselected) {
    QTreeView::selectionChanged(selected, deselected);

    if (!cap_file_) return;

    if (selected.isEmpty()) {
        cf_unselect_packet(cap_file_);
    } else {
        int row = selected.first().top();
        cf_select_packet(cap_file_, row);
    }

    related_packet_delegate_.clear();
    if (proto_tree_) proto_tree_->clear();
    if (byte_view_tab_) byte_view_tab_->clear();

    emit packetSelectionChanged();

    if (!cap_file_->edt) {
        viewport()->update();
        return;
    }

    if (proto_tree_ && cap_file_->edt->tree) {
        packet_info *pi = &cap_file_->edt->pi;
        related_packet_delegate_.setCurrentFrame(pi->fd->num);
        proto_tree_->fillProtocolTree(cap_file_->edt->tree);
        conversation_t *conv = find_conversation(pi->fd->num, &pi->src, &pi->dst, pi->ptype,
                                                pi->srcport, pi->destport, 0);
        if (conv) {
            related_packet_delegate_.setConversation(conv);
        }
        viewport()->update();
    }

    if (byte_view_tab_) {
        GSList *src_le;
        struct data_source *source;
        char* source_name;

        for (src_le = cap_file_->edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
            source = (struct data_source *)src_le->data;
            source_name = get_data_source_name(source);
            byte_view_tab_->addTab(source_name, get_data_source_tvb(source), cap_file_->edt->tree, proto_tree_, cap_file_->current_frame->flags.encoding);
            wmem_free(NULL, source_name);
        }
        byte_view_tab_->setCurrentIndex(0);
    }
}

void PacketList::contextMenuEvent(QContextMenuEvent *event)
{
    QAction *action;
    gboolean is_tcp = FALSE, is_udp = FALSE, is_sctp = FALSE;

    /* walk the list of a available protocols in the packet to see what we have */
    if (cap_file_ != NULL && cap_file_->edt != NULL)
        proto_get_frame_protocols(cap_file_->edt->pi.layers, NULL, &is_tcp, &is_udp, &is_sctp, NULL);

    QMenu *main_conv_menu = window()->findChild<QMenu *>("menuConversationFilter");
    conv_menu_.clear();
    foreach (action, main_conv_menu->actions()) {
        conv_menu_.addAction(action);
    }

    action = window()->findChild<QAction *>("actionSCTP");
    if (cap_file_ != NULL && cap_file_->edt != NULL && is_sctp)
        action->setEnabled(TRUE);
    else
        action->setEnabled(FALSE);

    action = window()->findChild<QAction *>("actionAnalyzeFollowTCPStream");
    action->setEnabled(is_tcp);

    action = window()->findChild<QAction *>("actionAnalyzeFollowUDPStream");
    action->setEnabled(is_udp);

    action = window()->findChild<QAction *>("actionAnalyzeFollowSSLStream");

    if (cap_file_ != NULL && cap_file_->edt != NULL &&
            epan_dissect_packet_contains_field(cap_file_->edt, "ssl"))
        action->setEnabled(TRUE);
    else
        action->setEnabled(FALSE);

    decode_as_->setData(qVariantFromValue(true));
    ctx_column_ = columnAt(event->x());
    ctx_menu_.exec(event->globalPos());
    ctx_column_ = -1;
    decode_as_->setData(QVariant());
}

// Auto scroll if:
// - We're not at the end
// - We are capturing
// - actionGoAutoScroll in the main UI is checked.
// - It's been more than tail_update_interval_ ms since we last scrolled
// - The last user-set vertical scrollbar position was at the end.

// Using a timer assumes that we can save CPU overhead by updating
// periodically. If that's not the case we can dispense with it and call
// scrollToBottom() from rowsInserted().
void PacketList::timerEvent(QTimerEvent *event)
{
    QTreeView::timerEvent(event);

    if (rows_inserted_
            && event->timerId() == tail_timer_id_
            && capture_in_progress_
            && tail_at_end_) {
        scrollToBottom();
        rows_inserted_ = false;
    }
}

void PacketList::markFramesReady()
{
    packets_bar_update();
    redrawVisiblePackets();
}

void PacketList::setFrameMark(gboolean set, frame_data *fdata)
{
    if (set)
        cf_mark_frame(cap_file_, fdata);
    else
        cf_unmark_frame(cap_file_, fdata);
}

void PacketList::setFrameIgnore(gboolean set, frame_data *fdata)
{
    if (set)
        cf_ignore_frame(cap_file_, fdata);
    else
        cf_unignore_frame(cap_file_, fdata);
}

void PacketList::setFrameReftime(gboolean set, frame_data *fdata)
{
    if (!fdata || !cap_file_) return;
    if (set) {
        fdata->flags.ref_time=1;
        cap_file_->ref_time_count++;
    } else {
        fdata->flags.ref_time=0;
        cap_file_->ref_time_count--;
    }
    cf_reftime_packets(cap_file_);
    if (!fdata->flags.ref_time && !fdata->flags.passed_dfilter) {
        cap_file_->displayed_count--;
        packet_list_model_->recreateVisibleRows();
    }
}

void PacketList::setColumnVisibility()
{
    for (int i = 0; i < prefs.num_cols; i++) {
        setColumnHidden(i, get_column_visible(i) ? false : true);
    }
}

int PacketList::sizeHintForColumn(int column) const
{
    int size_hint = 0;

    // This is a bit hacky but Qt does a fine job of column sizing and
    // reimplementing QTreeView::sizeHintForColumn seems like a worse idea.
    if (itemDelegateForColumn(column)) {
        // In my (gcc) testing this results in correct behavior on Windows but adds extra space
        // on OS X and Linux. We might want to add Q_OS_... #ifdefs accordingly.
        size_hint = itemDelegateForColumn(column)->sizeHint(viewOptions(), QModelIndex()).width();
    }
    packet_list_model_->setSizeHintEnabled(false);
    size_hint += QTreeView::sizeHintForColumn(column); // Decoration padding
    packet_list_model_->setSizeHintEnabled(true);
    return size_hint;
}

void PacketList::initHeaderContextMenu()
{
    header_ctx_menu_.clear();
    header_actions_.clear();

    // Leave these out for now since Qt doesn't have a "no sort" option
    // and the user can sort by left-clicking on the header.
//    header_actions_[] = header_ctx_menu_.addAction(tr("Sort Ascending"));
//    header_actions_[] = header_ctx_menu_.addAction(tr("Sort Descending"));
//    header_actions_[] = header_ctx_menu_.addAction(tr("Do Not Sort"));
//    header_ctx_menu_.addSeparator();
    header_actions_[caAlignLeft] = header_ctx_menu_.addAction(tr("Align Left"));
    header_actions_[caAlignCenter] = header_ctx_menu_.addAction(tr("Align Center"));
    header_actions_[caAlignRight] = header_ctx_menu_.addAction(tr("Align Right"));
    header_ctx_menu_.addSeparator();
    header_actions_[caColumnPreferences] = header_ctx_menu_.addAction(tr("Column Preferences" UTF8_HORIZONTAL_ELLIPSIS));
    header_actions_[caEditColumn] = header_ctx_menu_.addAction(tr("Edit Column")); // XXX Create frame instead of dialog
    header_actions_[caResizeToContents] = header_ctx_menu_.addAction(tr("Resize To Contents"));
    header_actions_[caResolveNames] = header_ctx_menu_.addAction(tr("Resolve Names"));
    header_ctx_menu_.addSeparator();
//    header_actions_[caDisplayedColumns] = header_ctx_menu_.addAction(tr("Displayed Columns"));
    show_hide_separator_ = header_ctx_menu_.addSeparator();
//    header_actions_[caHideColumn] = header_ctx_menu_.addAction(tr("Hide This Column"));
    header_actions_[caRemoveColumn] = header_ctx_menu_.addAction(tr("Remove This Column"));

    foreach (ColumnActions ca, header_actions_.keys()) {
        header_actions_[ca]->setData(qVariantFromValue(ca));
        connect(header_actions_[ca], SIGNAL(triggered()), this, SLOT(headerMenuTriggered()));
    }

    checkable_actions_ = QList<ColumnActions>() << caAlignLeft << caAlignCenter << caAlignRight << caResolveNames;
    foreach (ColumnActions ca, checkable_actions_) {
        header_actions_[ca]->setCheckable(true);
    }
}

// Redraw the packet list and detail. Called from many places, including
// columnsChanged.
void PacketList::redrawVisiblePackets() {
    if (!cap_file_) return;

    if (cap_file_->edt && cap_file_->edt->tree) {
        proto_tree_->fillProtocolTree(cap_file_->edt->tree);
    }

    int row = currentIndex().row();

    prefs.num_cols = g_list_length(prefs.col_list);
    col_cleanup(&cap_file_->cinfo);
    build_column_format_array(&cap_file_->cinfo, prefs.num_cols, FALSE);
    setColumnVisibility();

    packet_list_model_->resetColumns();
    if (row >= 0) {
        setCurrentIndex(packet_list_model_->index(row, 0));
    }

    update();
    header()->update();
}

// Column widths should
// - Load from recent when we load a new profile (including at starting up).
// - Persist across freezes and thaws.
// - Persist across file closing and opening.
// - Save to recent when we save our profile (including shutting down).

// Called via recentFilesRead.
void PacketList::applyRecentColumnWidths()
{
    // Either we've just started up or a profile has changed. Read
    // the recent settings, apply them, and save the header state.
    QFontMetrics fm = QFontMetrics(wsApp->monospaceFont());
    for (int i = 0; i < prefs.num_cols; i++) {
        int col_width = recent_get_column_width(i);

        if (col_width < 1) {
            int fmt;
            const char *long_str;

            fmt = get_column_format(i);
            long_str = get_column_width_string(fmt, i);
            if (long_str) {
                col_width = fm.width(long_str);
            } else {
                col_width = fm.width(MIN_COL_WIDTH_STR);
            }
            // Custom delegate padding
            if (itemDelegateForColumn(i)) {
                col_width += itemDelegateForColumn(i)->sizeHint(viewOptions(), QModelIndex()).width();
            }
        }
        setColumnWidth(i, col_width) ;
    }
    column_state_ = header()->saveState();
}

void PacketList::recolorPackets()
{
    packet_list_model_->resetColorized();
    redrawVisiblePackets();
}

/* Enable autoscroll timer. Note: must be called after the capture is started,
 * otherwise the timer will not be executed. */
void PacketList::setAutoScroll(bool enabled)
{
    tail_at_end_ = enabled;
    if (enabled && capture_in_progress_) {
        scrollToBottom();
        if (tail_timer_id_ == 0) tail_timer_id_ = startTimer(tail_update_interval_);
    } else if (tail_timer_id_ != 0) {
        killTimer(tail_timer_id_);
        tail_timer_id_ = 0;
    }
}

void PacketList::freeze()
{
    setUpdatesEnabled(false);
    setModel(NULL);
    // It looks like GTK+ sends a cursor-changed signal at this point but Qt doesn't
    // call selectionChanged.
    related_packet_delegate_.clear();
    proto_tree_->clear();
    byte_view_tab_->clear();
}

void PacketList::thaw()
{
    setUpdatesEnabled(true);
    setModel(packet_list_model_);

    // Resetting the model resets our column widths so we restore them here.
    // We don't reapply the recent settings because the user could have
    // resized the columns manually since they were initially loaded.
    header()->restoreState(column_state_);

    setColumnVisibility();
}

void PacketList::clear() {
    //    packet_history_clear();
    related_packet_delegate_.clear();
    packet_list_model_->clear();
    proto_tree_->clear();
    byte_view_tab_->clear();

    /* XXX is this correct in all cases?
     * Reset the sort column, use packetlist as model in case the list is frozen.
     */
    sortByColumn(-1, Qt::AscendingOrder);
    setColumnVisibility();
}

void PacketList::writeRecent(FILE *rf) {
    gint col, width, col_fmt;
    gchar xalign;

    fprintf (rf, "%s:", RECENT_KEY_COL_WIDTH);
    for (col = 0; col < prefs.num_cols; col++) {
        if (col > 0) {
            fprintf (rf, ",");
        }
        col_fmt = get_column_format(col);
        if (col_fmt == COL_CUSTOM) {
            fprintf (rf, " %%Cus:%s,", get_column_custom_field(col));
        } else {
            fprintf (rf, " %s,", col_format_to_string(col_fmt));
        }
        width = recent_get_column_width (col);
        xalign = recent_get_column_xalign (col);
        fprintf (rf, " %d", width);
        if (xalign != COLUMN_XALIGN_DEFAULT) {
            fprintf (rf, ":%c", xalign);
        }
    }
    fprintf (rf, "\n");

}

bool PacketList::contextMenuActive()
{
    return ctx_column_ >= 0 ? true : false;
}

QString &PacketList::getFilterFromRowAndColumn()
{
    frame_data *fdata;
    QString &filter = *new QString();
    int row = currentIndex().row();

    if (!cap_file_ || !packet_list_model_ || ctx_column_ < 0 || ctx_column_ >= cap_file_->cinfo.num_cols) return filter;

    fdata = packet_list_model_->getRowFdata(row);

    if (fdata != NULL) {
        epan_dissect_t edt;

        if (!cf_read_record(cap_file_, fdata))
            return filter; /* error reading the record */
        /* proto tree, visible. We need a proto tree if there's custom columns */
        epan_dissect_init(&edt, cap_file_->epan, have_custom_cols(&cap_file_->cinfo), FALSE);
        col_custom_prime_edt(&edt, &cap_file_->cinfo);

        epan_dissect_run(&edt, cap_file_->cd_t, &cap_file_->phdr, frame_tvbuff_new_buffer(fdata, &cap_file_->buf), fdata, &cap_file_->cinfo);
        epan_dissect_fill_in_columns(&edt, TRUE, TRUE);

        if ((cap_file_->cinfo.col_custom_occurrence[ctx_column_]) ||
            (strchr (cap_file_->cinfo.col_expr.col_expr_val[ctx_column_], ',') == NULL))
        {
            /* Only construct the filter when a single occurrence is displayed
             * otherwise we might end up with a filter like "ip.proto==1,6".
             *
             * Or do we want to be able to filter on multiple occurrences so that
             * the filter might be calculated as "ip.proto==1 && ip.proto==6"
             * instead?
             */
            if (strlen(cap_file_->cinfo.col_expr.col_expr[ctx_column_]) != 0 &&
                strlen(cap_file_->cinfo.col_expr.col_expr_val[ctx_column_]) != 0) {
                if (cap_file_->cinfo.col_fmt[ctx_column_] == COL_CUSTOM) {
                    header_field_info *hfi = proto_registrar_get_byname(cap_file_->cinfo.col_custom_field[ctx_column_]);
                    if (hfi->parent == -1) {
                        /* Protocol only */
                        filter.append(cap_file_->cinfo.col_expr.col_expr[ctx_column_]);
                    } else if (hfi->type == FT_STRING) {
                        /* Custom string, add quotes */
                        filter.append(QString("%1 == \"%2\"")
                                      .arg(cap_file_->cinfo.col_expr.col_expr[ctx_column_])
                                      .arg(cap_file_->cinfo.col_expr.col_expr_val[ctx_column_]));
                    }
                }
                if (filter.isEmpty()) {
                    filter.append(QString("%1 == %2")
                                  .arg(cap_file_->cinfo.col_expr.col_expr[ctx_column_])
                                  .arg(cap_file_->cinfo.col_expr.col_expr_val[ctx_column_]));
                }
            }
        }

        epan_dissect_cleanup(&edt);
    }

    return filter;
}

QString PacketList::packetComment()
{
    int row = currentIndex().row();
    const frame_data *fdata;
    char *pkt_comment;

    if (!cap_file_ || !packet_list_model_) return NULL;

    fdata = packet_list_model_->getRowFdata(row);

    if (!fdata) return NULL;

    pkt_comment = cf_get_comment(cap_file_, fdata);

    return QString(pkt_comment);

    /* XXX, g_free(pkt_comment) */
}

void PacketList::setPacketComment(QString new_comment)
{
    int row = currentIndex().row();
    frame_data *fdata;
    gchar *new_packet_comment = new_comment.toUtf8().data();

    if (!cap_file_ || !packet_list_model_) return;

    fdata = packet_list_model_->getRowFdata(row);

    if (!fdata) return;

    /* Check if we are clearing the comment */
    if(new_comment.isEmpty()) {
        new_packet_comment = NULL;
    }

    cf_set_user_packet_comment(cap_file_, fdata, new_packet_comment);

    redrawVisiblePackets();
}

QString PacketList::allPacketComments()
{
    guint32 framenum;
    frame_data *fdata;
    QString buf_str;

    if (!cap_file_) return buf_str;

    for (framenum = 1; framenum <= cap_file_->count ; framenum++) {
        fdata = frame_data_sequence_find(cap_file_->frames, framenum);

        char *pkt_comment = cf_get_comment(cap_file_, fdata);

        if (pkt_comment) {
            buf_str.append(QString(tr("Frame %1: %2\n\n")).arg(framenum).arg(pkt_comment));
            g_free(pkt_comment);
        }
        if (buf_str.length() > max_comments_to_fetch_) {
            buf_str.append(QString(tr("[ Comment text exceeds %1. Stopping. ]"))
                           .arg(format_size(max_comments_to_fetch_, format_size_unit_bytes|format_size_prefix_si)));
            return buf_str;
        }
    }
    return buf_str;
}

// Slots

void PacketList::setCaptureFile(capture_file *cf)
{
    if (cf) {
        // We're opening. Restore our column widths.
        header()->restoreState(column_state_);
    }
    cap_file_ = cf;
    packet_list_model_->setCaptureFile(cf);
}

void PacketList::setMonospaceFont(const QFont &mono_font)
{
    setFont(mono_font);
    header()->setFont(wsApp->font());

    // qtreeview.cpp does something similar in Qt 5 so this *should* be
    // safe...
    int row_height = itemDelegate()->sizeHint(viewOptions(), QModelIndex()).height();
    packet_list_model_->setMonospaceFont(mono_font, row_height);
    redrawVisiblePackets();
}

void PacketList::goNextPacket(void) {
    if (!selectionModel()->hasSelection()) return;
    setCurrentIndex(moveCursor(MoveDown, Qt::NoModifier));
}

void PacketList::goPreviousPacket(void) {
    if (!selectionModel()->hasSelection()) return;
    setCurrentIndex(moveCursor(MoveUp, Qt::NoModifier));
}

void PacketList::goFirstPacket(void) {
    if (packet_list_model_->rowCount() < 1) return;
    setCurrentIndex(packet_list_model_->index(0, 0));
}

void PacketList::goLastPacket(void) {
    if (packet_list_model_->rowCount() < 1) return;
    setCurrentIndex(packet_list_model_->index(0, 0));
    setCurrentIndex(moveCursor(MoveEnd, Qt::NoModifier));
}

// XXX We can jump to the wrong packet if a display filter is applied
void PacketList::goToPacket(int packet) {
    int row = packet_list_model_->packetNumberToRow(packet);
    if (row >= 0) {
        setCurrentIndex(packet_list_model_->index(row, 0));
    }
}

void PacketList::goToPacket(int packet, int hf_id)
{
    goToPacket(packet);
    proto_tree_->goToField(hf_id);
}

void PacketList::markFrame()
{
    int row = currentIndex().row();
    frame_data *fdata;

    if (!cap_file_ || !packet_list_model_) return;

    fdata = packet_list_model_->getRowFdata(row);

    if (!fdata) return;

    setFrameMark(!fdata->flags.marked, fdata);
    markFramesReady();
}

void PacketList::markAllDisplayedFrames(bool set)
{
    guint32 framenum;
    frame_data *fdata;

    if (!cap_file_ || !packet_list_model_) return;

    for (framenum = 1; framenum <= cap_file_->count; framenum++) {
        fdata = frame_data_sequence_find(cap_file_->frames, framenum);
        if (fdata->flags.passed_dfilter)
            setFrameMark(set, fdata);
    }
    markFramesReady();
}

void PacketList::ignoreFrame()
{
    int row = currentIndex().row();
    frame_data *fdata;

    if (!cap_file_ || !packet_list_model_) return;

    fdata = packet_list_model_->getRowFdata(row);

    setFrameIgnore(!fdata->flags.ignored, fdata);
    emit packetDissectionChanged();
}

void PacketList::ignoreAllDisplayedFrames(bool set)
{
    guint32 framenum;
    frame_data *fdata;

    if (!cap_file_ || !packet_list_model_) return;

    for (framenum = 1; framenum <= cap_file_->count; framenum++) {
        fdata = frame_data_sequence_find(cap_file_->frames, framenum);
        if (!set || fdata->flags.passed_dfilter)
            setFrameIgnore(set, fdata);
    }
    emit packetDissectionChanged();
}

void PacketList::setTimeReference()
{
    if (!cap_file_) return;

    if (cap_file_->current_frame) {
        if(recent.gui_time_format != TS_RELATIVE && cap_file_->current_frame->flags.ref_time==0) {
            int ret = QMessageBox::question(
                        this,
                        tr("Change Time Display Format?"),
                        tr("Time References don't work well with the currently selected Time Display Format.\n"
                           "Do you want to switch to \"Seconds Since Beginning of Capture\" now?"),
                        QMessageBox::Yes | QMessageBox::No
                        );
            if (ret == QMessageBox::Yes) {
                timestamp_set_type(TS_RELATIVE);
                recent.gui_time_format  = TS_RELATIVE;
                cf_timestamp_auto_precision(cap_file_);
                setFrameReftime(!cap_file_->current_frame->flags.ref_time,
                                cap_file_->current_frame);
            }
        } else {
            setFrameReftime(!cap_file_->current_frame->flags.ref_time,
                            cap_file_->current_frame);
        }
    }
    redrawVisiblePackets();
}

void PacketList::unsetAllTimeReferences()
{
    if (!cap_file_) return;

    /* XXX: we might need a progressbar here */
    guint32 framenum;
    frame_data *fdata;
    for (framenum = 1; framenum <= cap_file_->count && cap_file_->ref_time_count > 0; framenum++) {
        fdata = frame_data_sequence_find(cap_file_->frames, framenum);
        if (fdata->flags.ref_time == 1) {
            setFrameReftime(FALSE, fdata);
        }
    }
    redrawVisiblePackets();
}

void PacketList::showHeaderMenu(QPoint pos)
{
    header_ctx_column_ = header()->logicalIndexAt(pos);
    foreach (ColumnActions ca, checkable_actions_) {
        header_actions_[ca]->setChecked(false);
    }

    switch (recent_get_column_xalign(header_ctx_column_)) {
    case COLUMN_XALIGN_LEFT:
        header_actions_[caAlignLeft]->setChecked(true);
        break;
    case COLUMN_XALIGN_CENTER:
        header_actions_[caAlignCenter]->setChecked(true);
        break;
    case COLUMN_XALIGN_RIGHT:
        header_actions_[caAlignRight]->setChecked(true);
        break;
    default:
        break;
    }

    bool can_resolve = resolve_column(header_ctx_column_, cap_file_);
    header_actions_[caResolveNames]->setChecked(can_resolve && get_column_resolved(header_ctx_column_));
    header_actions_[caResolveNames]->setEnabled(can_resolve);

    foreach (QAction *action, show_hide_actions_) {
        header_ctx_menu_.removeAction(action);
        delete action;
    }
    show_hide_actions_.clear();
    for (int i = 0; i < prefs.num_cols; i++) {
        QAction *action = new QAction(get_column_title(i), &header_ctx_menu_);
        action->setCheckable(true);
        action->setChecked(get_column_visible(i));
        action->setData(qVariantFromValue(i));
        connect(action, SIGNAL(triggered()), this, SLOT(columnVisibilityTriggered()));
        header_ctx_menu_.insertAction(show_hide_separator_, action);
        show_hide_actions_ << action;
    }

    header_ctx_menu_.popup(header()->viewport()->mapToGlobal(pos));
}

void PacketList::headerMenuTriggered()
{
    QAction *ha = qobject_cast<QAction*>(sender());
    if (!ha) return;

    bool checked = ha->isChecked();
    bool redraw = false;

    switch(ha->data().value<ColumnActions>()) {
    case caAlignLeft:
        recent_set_column_xalign(header_ctx_column_, checked ? COLUMN_XALIGN_LEFT : COLUMN_XALIGN_DEFAULT);
        break;
    case caAlignCenter:
        recent_set_column_xalign(header_ctx_column_, checked ? COLUMN_XALIGN_CENTER : COLUMN_XALIGN_DEFAULT);
        break;
    case caAlignRight:
        recent_set_column_xalign(header_ctx_column_, checked ? COLUMN_XALIGN_RIGHT : COLUMN_XALIGN_DEFAULT);
        break;
    case caColumnPreferences:
        emit showPreferences(PreferencesDialog::ppColumn);
        break;
    case caEditColumn:
        emit editColumn(header_ctx_column_);
        break;
    case caResolveNames:
        set_column_resolved(header_ctx_column_, checked);
        redraw = true;
        break;
    case caResizeToContents:
        resizeColumnToContents(header_ctx_column_);
        break;
    case caDisplayedColumns:
        // No-op
        break;
    case caHideColumn:
        set_column_visible(header_ctx_column_, FALSE);
        hideColumn(header_ctx_column_);
        break;
    case caRemoveColumn:
        column_prefs_remove_nth(header_ctx_column_);
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }
        setColumnVisibility();
        redraw = true;
        break;
    default:
        break;
    }

    if (redraw) {
        redrawVisiblePackets();
    } else {
        update();
    }
}

void PacketList::columnVisibilityTriggered()
{
    QAction *ha = qobject_cast<QAction*>(sender());
    if (!ha) return;

    set_column_visible(ha->data().toInt(), ha->isChecked());
    setColumnVisibility();
}

void PacketList::sectionResized(int col, int, int new_width)
{
    if (isVisible()) {
        // Column 1 gets an invalid value (32 on OS X) when we're not yet
        // visible.
        recent_set_column_width(col, new_width);
    }
}

// We need to tell when the user has scrolled the packet list, either to
// the end or anywhere other than the end.
void PacketList::vScrollBarActionTriggered(int)
{
    // If we're scrolling with a mouse wheel or trackpad sliderPosition can end up
    // past the end.
    tail_at_end_ = (verticalScrollBar()->sliderPosition() >= verticalScrollBar()->maximum());

    if (capture_in_progress_ && prefs.capture_auto_scroll) {
        emit packetListScrolled(tail_at_end_);
    }
}

void PacketList::rowsInserted(const QModelIndex &parent, int start, int end)
{
    QTreeView::rowsInserted(parent, start, end);
    rows_inserted_ = true;
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
