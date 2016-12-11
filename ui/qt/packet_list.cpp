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

#include "packet_list.h"

#include "config.h"

#include <glib.h>

#include "file.h"

#include <epan/epan.h>
#include <epan/epan_dissect.h>

#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/ipproto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>

#include "ui/main_statusbar.h"
#include "ui/packet_list_utils.h"
#include "ui/preference_utils.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/ui_util.h"
#include <wsutil/utf8_entities.h>
#include "ui/util.h"

#include "wsutil/str_util.h"

#include <epan/color_filters.h>
#include "frame_tvbuff.h"

#include "color_utils.h"
#include "overlay_scroll_bar.h"
#include "proto_tree.h"
#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QAction>
#include <QActionGroup>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QtCore/qmath.h>
#include <QElapsedTimer>
#include <QFontMetrics>
#include <QHeaderView>
#include <QMessageBox>
#include <QPainter>
#include <QScreen>
#include <QScrollBar>
#include <QTabWidget>
#include <QTextEdit>
#include <QTimerEvent>
#include <QTreeWidget>

#ifdef Q_OS_WIN
#include "wsutil/file_util.h"
#include <QSysInfo>
#endif

// To do:
// - Fix "apply as filter" behavior.
// - Add colorize conversation.
// - Use a timer to trigger automatic scrolling.

// If we ever add the ability to open multiple capture files we might be
// able to use something like QMap<capture_file *, PacketList *> to match
// capture files against packet lists and models.
static PacketList *gbl_cur_packet_list = NULL;

const int max_comments_to_fetch_ = 20000000; // Arbitrary
const int tail_update_interval_ = 100; // Milliseconds.
const int overlay_update_interval_ = 100; // 250; // Milliseconds.

guint
packet_list_append(column_info *, frame_data *fdata)
{
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
}

void
packet_list_select_last_row(void)
{
    if (!gbl_cur_packet_list)
        return;
    gbl_cur_packet_list->goLastPacket();
}

/*
 * Given a frame_data structure, scroll to and select the row in the
 * packet list corresponding to that frame.  If there is no such
 * row, return FALSE, otherwise return TRUE.
 */
gboolean
packet_list_select_row_from_data(frame_data *fdata_needle)
{
    gbl_cur_packet_list->packetListModel()->flushVisibleRows();
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
packet_list_enable_color(gboolean)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->recolorPackets();
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

#define MIN_COL_WIDTH_STR "MMMMMM"

Q_DECLARE_METATYPE(PacketList::ColumnActions)

enum copy_summary_type {
    copy_summary_text_,
    copy_summary_csv_,
    copy_summary_yaml_
};

PacketList::PacketList(QWidget *parent) :
    QTreeView(parent),
    proto_tree_(NULL),
    byte_view_tab_(NULL),
    cap_file_(NULL),
    decode_as_(NULL),
    ctx_column_(-1),
    overlay_timer_id_(0),
    create_near_overlay_(true),
    create_far_overlay_(true),
    capture_in_progress_(false),
    tail_timer_id_(0),
    rows_inserted_(false),
    columns_changed_(false),
    set_column_visibility_(false)
{
    QMenu *main_menu_item, *submenu;
    QAction *action;

    setItemsExpandable(false);
    setRootIsDecorated(false);
    setSortingEnabled(true);
    setUniformRowHeights(true);
    setAccessibleName("Packet list");

    overlay_sb_ = new OverlayScrollBar(Qt::Vertical, this);
    setVerticalScrollBar(overlay_sb_);

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

    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewEditResolvedName"));
    ctx_menu_.addSeparator();

    main_menu_item = window()->findChild<QMenu *>("menuApplyAsFilter");
    submenu = new QMenu(main_menu_item->title());
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrNotSelected"));

    main_menu_item = window()->findChild<QMenu *>("menuPrepareAFilter");
    submenu = new QMenu(main_menu_item->title());
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrNotSelected"));

    const char *conv_menu_name = "menuConversationFilter";
    main_menu_item = window()->findChild<QMenu *>(conv_menu_name);
    conv_menu_.setTitle(main_menu_item->title());
    conv_menu_.setObjectName(conv_menu_name);
    ctx_menu_.addMenu(&conv_menu_);

    const char *colorize_menu_name = "menuColorizeConversation";
    main_menu_item = window()->findChild<QMenu *>(colorize_menu_name);
    colorize_menu_.setTitle(main_menu_item->title());
    colorize_menu_.setObjectName(colorize_menu_name);
    ctx_menu_.addMenu(&colorize_menu_);

    main_menu_item = window()->findChild<QMenu *>("menuSCTP");
    submenu = new QMenu(main_menu_item->title());
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionSCTPAnalyseThisAssociation"));
    submenu->addAction(window()->findChild<QAction *>("actionSCTPShowAllAssociations"));
    submenu->addAction(window()->findChild<QAction *>("actionSCTPFilterThisAssociation"));

    main_menu_item = window()->findChild<QMenu *>("menuFollow");
    submenu = new QMenu(main_menu_item->title());
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowTCPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowUDPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowSSLStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowHTTPStream"));

    ctx_menu_.addSeparator();

    main_menu_item = window()->findChild<QMenu *>("menuEditCopy");
    submenu = new QMenu(main_menu_item->title());
    ctx_menu_.addMenu(submenu);

    action = submenu->addAction(tr("Summary as Text"));
    action->setData(copy_summary_text_);
    connect(action, SIGNAL(triggered()), this, SLOT(copySummary()));
    action = submenu->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as CSV"));
    action->setData(copy_summary_csv_);
    connect(action, SIGNAL(triggered()), this, SLOT(copySummary()));
    action = submenu->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as YAML"));
    action->setData(copy_summary_yaml_);
    connect(action, SIGNAL(triggered()), this, SLOT(copySummary()));
    submenu->addSeparator();

    submenu->addAction(window()->findChild<QAction *>("actionEditCopyAsFilter"));
    submenu->addSeparator();

    action = window()->findChild<QAction *>("actionContextCopyBytesHexTextDump");
    submenu->addAction(action);
    copy_actions_ << action;
    action = window()->findChild<QAction *>("actionContextCopyBytesHexDump");
    submenu->addAction(action);
    copy_actions_ << action;
    action = window()->findChild<QAction *>("actionContextCopyBytesPrintableText");
    submenu->addAction(action);
    copy_actions_ << action;
    action = window()->findChild<QAction *>("actionContextCopyBytesHexStream");
    submenu->addAction(action);
    copy_actions_ << action;
    action = window()->findChild<QAction *>("actionContextCopyBytesBinary");
    submenu->addAction(action);
    copy_actions_ << action;

    ctx_menu_.addSeparator();
    ctx_menu_.addMenu(&proto_prefs_menu_);
    decode_as_ = window()->findChild<QAction *>("actionAnalyzeDecodeAs");
    ctx_menu_.addAction(decode_as_);
    // "Print" not ported intentionally
    action = window()->findChild<QAction *>("actionViewShowPacketInNewWindow");
    ctx_menu_.addAction(action);

    initHeaderContextMenu();

    g_assert(gbl_cur_packet_list == NULL);
    gbl_cur_packet_list = this;

    bool style_inactive_selected = true;

#ifdef Q_OS_WIN // && Qt version >= 4.8.6
    if (QSysInfo::windowsVersion() < QSysInfo::WV_WINDOWS8) {
        // See if we're running Vista or 7 and we have a theme applied.
        HMODULE uxtheme_lib = (HMODULE) ws_load_library("uxtheme.dll");

        if (uxtheme_lib) {
            typedef BOOL (WINAPI *IsAppThemedHandler)(void);
            typedef BOOL (WINAPI *IsThemeActiveHandler)(void);

            IsAppThemedHandler PIsAppThemed = (IsAppThemedHandler) GetProcAddress(uxtheme_lib, "IsAppThemed");
            IsThemeActiveHandler PIsThemeActive = (IsThemeActiveHandler) GetProcAddress(uxtheme_lib, "IsThemeActive");
            if (PIsAppThemed && PIsAppThemed() && PIsThemeActive && PIsThemeActive()) {
                style_inactive_selected = false;
            }
        }
    }
#endif

    if (style_inactive_selected) {
        // XXX Style the protocol tree as well?
        QPalette inactive_pal = palette();
        inactive_pal.setCurrentColorGroup(QPalette::Inactive);
        QColor border = QColor::fromRgb(ColorUtils::alphaBlend(
                                                inactive_pal.highlightedText(),
                                                inactive_pal.highlight(),
                                                0.25));
        QColor shadow = QColor::fromRgb(ColorUtils::alphaBlend(
                                                inactive_pal.highlightedText(),
                                                inactive_pal.highlight(),
                                                0.07));
        setStyleSheet(QString(
                          "QTreeView::item:selected:first:!active {"
                          "  border-left: 1px solid %1;"
                          "}"
                          "QTreeView::item:selected:last:!active {"
                          "  border-right: 1px solid %1;"
                          "}"
                          "QTreeView::item:selected:!active {"
                          "  border-top: 1px solid %1;"
                          "  border-bottom: 1px solid %1;"
                          "  color: %2;"
                          // Try to approximate a subtle box shadow.
                          "  background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1"
                          "    stop: 0 %4, stop: 0.2 %3, stop: 0.8 %3, stop: 1 %4);"
                          "}")
                      .arg(border.name())
                      .arg(inactive_pal.highlightedText().color().name())
                      .arg(inactive_pal.highlight().color().name())
                      .arg(shadow.name())
                      );
    }

    connect(packet_list_model_, SIGNAL(goToPacket(int)), this, SLOT(goToPacket(int)));
    connect(packet_list_model_, SIGNAL(itemHeightChanged(const QModelIndex&)), this, SLOT(updateRowHeights(const QModelIndex&)));
    connect(wsApp, SIGNAL(addressResolutionChanged()), this, SLOT(redrawVisiblePackets()));

    header()->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(header(), SIGNAL(customContextMenuRequested(QPoint)),
            this, SLOT(showHeaderMenu(QPoint)));
    connect(header(), SIGNAL(sectionResized(int,int,int)),
            this, SLOT(sectionResized(int,int,int)));
    connect(header(), SIGNAL(sectionMoved(int,int,int)),
            this, SLOT(sectionMoved(int,int,int)));

    connect(verticalScrollBar(), SIGNAL(actionTriggered(int)), this, SLOT(vScrollBarActionTriggered(int)));

    connect(&proto_prefs_menu_, SIGNAL(showProtocolPreferences(QString)),
            this, SIGNAL(showProtocolPreferences(QString)));
    connect(&proto_prefs_menu_, SIGNAL(editProtocolPreference(preference*,pref_module*)),
            this, SIGNAL(editProtocolPreference(preference*,pref_module*)));
}

void PacketList::drawRow (QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QTreeView::drawRow(painter, option, index);

    if (prefs.gui_qt_packet_list_separator) {
        QRect rect = visualRect(index);

        painter->setPen(QColor(Qt::white));
        painter->drawLine(0, rect.y() + rect.height() - 1, width(), rect.y() + rect.height() - 1);
    }
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
        related_packet_delegate_.setCurrentFrame(pi->num);
        proto_tree_->fillProtocolTree(cap_file_->edt->tree);
        conversation_t *conv = find_conversation(pi->num, &pi->src, &pi->dst, pi->ptype,
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
            byte_view_tab_->addTab(source_name, get_data_source_tvb(source), cap_file_->edt->tree, proto_tree_, (packet_char_enc)cap_file_->current_frame->flags.encoding);
            wmem_free(NULL, source_name);
        }
        byte_view_tab_->setCurrentIndex(0);
    }

    if (cap_file_->search_in_progress &&
        (cap_file_->search_pos != 0 || (cap_file_->string && cap_file_->decode_data)))
    {
        match_data  mdata;
        field_info *fi = NULL;

        if (cap_file_->string && cap_file_->decode_data) {
            // The tree where the target string matched one of the labels was discarded in
            // match_protocol_tree() so we have to search again in the latest tree.
            if (cf_find_string_protocol_tree(cap_file_, cap_file_->edt->tree, &mdata)) {
                fi = mdata.finfo;
            }
        } else {
            // Find the finfo that corresponds to our byte.
            fi = proto_find_field_from_offset(cap_file_->edt->tree, cap_file_->search_pos,
                                              cap_file_->edt->tvb);
        }

        if (fi && proto_tree_) {
            proto_tree_->selectField(fi);
        }
    } else if (!cap_file_->search_in_progress && proto_tree_) {
        proto_tree_->restoreSelectedField();
    }
}

void PacketList::contextMenuEvent(QContextMenuEvent *event)
{
    const char *module_name = NULL;
    if (cap_file_ && cap_file_->edt && cap_file_->edt->tree) {
        GPtrArray          *finfo_array = proto_all_finfos(cap_file_->edt->tree);

        for (guint i = finfo_array->len - 1; i > 0 ; i --) {
            field_info *fi = (field_info *)g_ptr_array_index (finfo_array, i);
            header_field_info *hfinfo =  fi->hfinfo;

            if (!g_str_has_prefix(hfinfo->abbrev, "text") &&
                !g_str_has_prefix(hfinfo->abbrev, "_ws.expert") &&
                !g_str_has_prefix(hfinfo->abbrev, "_ws.malformed")) {

                if (hfinfo->parent == -1) {
                    module_name = hfinfo->abbrev;
                } else {
                    module_name = proto_registrar_get_abbrev(hfinfo->parent);
                }
                break;
            }
        }
    }
    proto_prefs_menu_.setModule(module_name);

    foreach (QAction *action, copy_actions_) {
        action->setData(QVariant());
    }

    decode_as_->setData(qVariantFromValue(true));
    ctx_column_ = columnAt(event->x());

    // Set menu sensitivity for the current column and set action data.
    emit packetSelectionChanged();

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
    if (event->timerId() == tail_timer_id_) {
        if (rows_inserted_ && capture_in_progress_ && tail_at_end_) {
            scrollToBottom();
            rows_inserted_ = false;
        }
    } else if (event->timerId() == overlay_timer_id_) {
        if (!capture_in_progress_) {
            if (create_near_overlay_) drawNearOverlay();
            if (create_far_overlay_) drawFarOverlay();
        }
    } else {
        QTreeView::timerEvent(event);
    }
}

void PacketList::paintEvent(QPaintEvent *event)
{
    // XXX This is overkill, but there are quite a few events that
    // require a new overlay, e.g. page up/down, scrolling, column
    // resizing, etc.
    create_near_overlay_ = true;
    QTreeView::paintEvent(event);
}

void PacketList::mousePressEvent (QMouseEvent *event)
{
    setAutoScroll(false);
    QTreeView::mousePressEvent(event);
    setAutoScroll(true);
}

void PacketList::resizeEvent(QResizeEvent *event)
{
    create_near_overlay_ = true;
    create_far_overlay_ = true;
    QTreeView::resizeEvent(event);
}

void PacketList::setColumnVisibility()
{
    set_column_visibility_ = true;
    for (int i = 0; i < prefs.num_cols; i++) {
        setColumnHidden(i, get_column_visible(i) ? false : true);
    }
    set_column_visibility_ = false;
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
    size_hint += QTreeView::sizeHintForColumn(column); // Decoration padding
    return size_hint;
}

void PacketList::setRecentColumnWidth(int col)
{
    int col_width = recent_get_column_width(col);

    if (col_width < 1) {
        int fmt = get_column_format(col);
        const char *long_str = get_column_width_string(fmt, col);

        QFontMetrics fm = QFontMetrics(wsApp->monospaceFont());
        if (long_str) {
            col_width = fm.width(long_str);
        } else {
            col_width = fm.width(MIN_COL_WIDTH_STR);
        }

        // Custom delegate padding
        if (itemDelegateForColumn(col)) {
            col_width += itemDelegateForColumn(col)->sizeHint(viewOptions(), QModelIndex()).width();
        }
    }

    setColumnWidth(col, col_width);
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

void PacketList::drawCurrentPacket()
{
    QModelIndex current_index = currentIndex();
    setCurrentIndex(QModelIndex());
    if (current_index.isValid()) {
        setCurrentIndex(current_index);
    }
}

// Redraw the packet list and detail. Called from many places.
// XXX We previously re-selected the packet here, but that seems to cause
// automatic scrolling problems.
void PacketList::redrawVisiblePackets() {
    update();
    header()->update();
    drawCurrentPacket();
}

void PacketList::resetColumns()
{
    packet_list_model_->resetColumns();
}

// prefs.col_list has changed.
void PacketList::columnsChanged()
{
    columns_changed_ = true;
    if (!cap_file_) {
        // Keep columns_changed_ = true until we load a capture file.
        return;
    }

    prefs.num_cols = g_list_length(prefs.col_list);
    col_cleanup(&cap_file_->cinfo);
    build_column_format_array(&cap_file_->cinfo, prefs.num_cols, FALSE);
    create_far_overlay_ = true;
    resetColumns();
    applyRecentColumnWidths();
    setColumnVisibility();
    columns_changed_ = false;
}

// Fields have changed, update custom columns
void PacketList::fieldsChanged(capture_file *cf)
{
    prefs.num_cols = g_list_length(prefs.col_list);
    col_cleanup(&cf->cinfo);
    build_column_format_array(&cf->cinfo, prefs.num_cols, FALSE);
    // call packet_list_model_->resetColumns() ?
}

// Column widths should
// - Load from recent when we load a new profile (including at starting up).
// - Reapply when changing columns.
// - Persist across freezes and thaws.
// - Persist across file closing and opening.
// - Save to recent when we save our profile (including shutting down).
// - Not be affected by the behavior of stretchLastSection.
void PacketList::applyRecentColumnWidths()
{
    // Either we've just started up or a profile has changed. Read
    // the recent settings, apply them, and save the header state.

    int column_width = 0;

    for (int col = 0; col < prefs.num_cols; col++) {
        setRecentColumnWidth(col);
        column_width += columnWidth(col);
    }

    if (column_width > width()) {
        resize(column_width, height());
    }

    column_state_ = header()->saveState();
}

void PacketList::preferencesChanged()
{
    // Related packet delegate
    if (prefs.gui_packet_list_show_related) {
        setItemDelegateForColumn(0, &related_packet_delegate_);
    } else {
        setItemDelegateForColumn(0, 0);
    }

    // Intelligent scroll bar (minimap)
    if (prefs.gui_packet_list_show_minimap) {
        if (overlay_timer_id_ == 0) {
            overlay_timer_id_ = startTimer(overlay_update_interval_);
        }
    } else {
        if (overlay_timer_id_ != 0) {
            killTimer(overlay_timer_id_);
            overlay_timer_id_ = 0;
        }
    }

    // Elide mode.
    // This sets the mode for the entire view. If we want to make this setting
    // per-column we'll either have to generalize RelatedPacketDelegate so that
    // we can set it for entire rows or create another delegate.
    Qt::TextElideMode elide_mode = Qt::ElideRight;
    switch (prefs.gui_packet_list_elide_mode) {
    case ELIDE_LEFT:
        elide_mode = Qt::ElideLeft;
        break;
    case ELIDE_MIDDLE:
        elide_mode = Qt::ElideMiddle;
        break;
    case ELIDE_NONE:
        elide_mode = Qt::ElideNone;
        break;
    default:
        break;
    }
    setTextElideMode(elide_mode);
}

void PacketList::recolorPackets()
{
    packet_list_model_->resetColorized();
    redrawVisiblePackets();
}

/* Enable autoscroll timer. Note: must be called after the capture is started,
 * otherwise the timer will not be executed. */
void PacketList::setVerticalAutoScroll(bool enabled)
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

// Called when we finish reading, reloading, rescanning, and retapping
// packets.
void PacketList::captureFileReadFinished()
{
    packet_list_model_->flushVisibleRows();
    packet_list_model_->dissectIdle(true);
}

void PacketList::freeze()
{
    setUpdatesEnabled(false);
    column_state_ = header()->saveState();
    selectionModel()->clear();
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
    selectionModel()->clear();
    packet_list_model_->clear();
    proto_tree_->clear();
    byte_view_tab_->clear();

    QImage overlay;
    overlay_sb_->setNearOverlayImage(overlay);
    overlay_sb_->setMarkedPacketImage(overlay);
    create_near_overlay_ = true;
    create_far_overlay_ = true;

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
            fprintf (rf, " %%Cus:%s,", get_column_custom_fields(col));
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

QString PacketList::getFilterFromRowAndColumn()
{
    frame_data *fdata;
    QString filter;
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

        if ((cap_file_->cinfo.columns[ctx_column_].col_custom_occurrence) ||
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
                if (cap_file_->cinfo.columns[ctx_column_].col_fmt == COL_CUSTOM) {
                    header_field_info *hfi = proto_registrar_get_byname(cap_file_->cinfo.columns[ctx_column_].col_custom_fields);
                    if (hfi && hfi->parent == -1) {
                        /* Protocol only */
                        filter.append(cap_file_->cinfo.col_expr.col_expr[ctx_column_]);
                    } else if (hfi && hfi->type == FT_STRING) {
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

void PacketList::resetColorized()
{
    packet_list_model_->resetColorized();
    update();
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
    gchar *new_packet_comment;

    if (!cap_file_ || !packet_list_model_) return;

    fdata = packet_list_model_->getRowFdata(row);

    if (!fdata) return;

    /* Check if we are clearing the comment */
    if(new_comment.isEmpty()) {
        new_packet_comment = NULL;
    } else {
        new_packet_comment = qstring_strdup(new_comment);
    }

    cf_set_user_packet_comment(cap_file_, fdata, new_packet_comment);
    g_free(new_packet_comment);

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
    if (cap_file_ && columns_changed_) {
        columnsChanged();
    }
    packet_list_model_->setCaptureFile(cf);
    create_near_overlay_ = true;
    sortByColumn(-1, Qt::AscendingOrder);
}

void PacketList::setMonospaceFont(const QFont &mono_font)
{
    setFont(mono_font);
    header()->setFont(wsApp->font());
}

void PacketList::goNextPacket(void) {
    if (selectionModel()->hasSelection()) {
        setCurrentIndex(moveCursor(MoveDown, Qt::NoModifier));
    } else {
        // First visible packet.
        setCurrentIndex(indexAt(viewport()->rect().topLeft()));
    }
}

void PacketList::goPreviousPacket(void) {
    if (selectionModel()->hasSelection()) {
        setCurrentIndex(moveCursor(MoveUp, Qt::NoModifier));
    } else {
        // Last visible packet.
        QModelIndex last_idx = indexAt(viewport()->rect().bottomLeft());
        if (last_idx.isValid()) {
            setCurrentIndex(last_idx);
        } else {
            goLastPacket();
        }
    }
}

void PacketList::goFirstPacket(void) {
    if (packet_list_model_->rowCount() < 1) return;
    setCurrentIndex(packet_list_model_->index(0, 0));
    scrollTo(currentIndex());
}

void PacketList::goLastPacket(void) {
    if (packet_list_model_->rowCount() < 1) return;
    setCurrentIndex(packet_list_model_->index(packet_list_model_->rowCount() - 1, 0));
    scrollTo(currentIndex());
}

// XXX We can jump to the wrong packet if a display filter is applied
void PacketList::goToPacket(int packet) {
    if (!cf_goto_frame(cap_file_, packet)) return;
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
    if (!cap_file_ || !packet_list_model_) return;

    packet_list_model_->toggleFrameMark(currentIndex());
    create_far_overlay_ = true;
    packets_bar_update();
}

void PacketList::markAllDisplayedFrames(bool set)
{
    if (!cap_file_ || !packet_list_model_) return;

    packet_list_model_->setDisplayedFrameMark(set);
    create_far_overlay_ = true;
    packets_bar_update();
}

void PacketList::ignoreFrame()
{
    if (!cap_file_ || !packet_list_model_) return;

    packet_list_model_->toggleFrameIgnore(currentIndex());
    create_far_overlay_ = true;
    int sb_val = verticalScrollBar()->value(); // Surely there's a better way to keep our position?
    setUpdatesEnabled(false);
    emit packetDissectionChanged();
    setUpdatesEnabled(true);
    verticalScrollBar()->setValue(sb_val);
}

void PacketList::ignoreAllDisplayedFrames(bool set)
{
    if (!cap_file_ || !packet_list_model_) return;

    packet_list_model_->setDisplayedFrameIgnore(set);
    create_far_overlay_ = true;
    emit packetDissectionChanged();
}

void PacketList::setTimeReference()
{
    if (!cap_file_ || !packet_list_model_) return;
    packet_list_model_->toggleFrameRefTime(currentIndex());
    create_far_overlay_ = true;
}

void PacketList::unsetAllTimeReferences()
{
    if (!cap_file_ || !packet_list_model_) return;
    packet_list_model_->unsetAllFrameRefTime();
    create_far_overlay_ = true;
}

void PacketList::applyTimeShift()
{
    packet_list_model_->applyTimeShift();
    redrawVisiblePackets();
    // XXX emit packetDissectionChanged(); ?
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

    header_actions_[caRemoveColumn]->setEnabled(header_ctx_column_ >= 0 && header()->count() > 2);

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
        emit showColumnPreferences(PreferencesDialog::ppColumn);
        break;
    case caEditColumn:
        emit editColumn(header_ctx_column_);
        break;
    case caResolveNames:
        set_column_resolved(header_ctx_column_, checked);
        packet_list_model_->resetColumns();
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }
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
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }
        break;
    case caRemoveColumn:
    {
        if (header()->count() > 2) {
            column_prefs_remove_nth(header_ctx_column_);
            columnsChanged();
            if (!prefs.gui_use_pref_save) {
                prefs_main_write();
            }
        }
        break;
    }
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

    int col = ha->data().toInt();
    set_column_visible(col, ha->isChecked());
    setColumnVisibility();
    if (ha->isChecked()) {
        setRecentColumnWidth(col);
    }
    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }
}

void PacketList::sectionResized(int col, int, int new_width)
{
    if (isVisible() && !columns_changed_ && !set_column_visibility_ && new_width > 0) {
        // Column 1 gets an invalid value (32 on OS X) when we're not yet
        // visible.
        //
        // Don't set column width when columns changed or setting column
        // visibility because we may get a sectionReized() from QTreeView
        // with values from a old columns layout.
        //
        // Don't set column width when hiding a column.

        recent_set_column_width(col, new_width);
    }
}

// The user moved a column. Make sure prefs.col_list, the column format
// array, and the header's visual and logical indices all agree.
// gtk/packet_list.c:column_dnd_changed_cb
void PacketList::sectionMoved(int, int, int)
{
    GList *new_col_list = NULL;
    QList<int> saved_sizes;

    // Build a new column list based on the header's logical order.
    for (int vis_idx = 0; vis_idx < header()->count(); vis_idx++) {
        int log_idx = header()->logicalIndex(vis_idx);
        saved_sizes << header()->sectionSize(log_idx);

        void *pref_data = g_list_nth_data(prefs.col_list, log_idx);
        if (!pref_data) continue;

        new_col_list = g_list_append(new_col_list, pref_data);
    }

    // Clear and rebuild our (and the header's) model. There doesn't appear
    // to be another way to reset the logical index.
    freeze();

    g_list_free(prefs.col_list);
    prefs.col_list = new_col_list;

    thaw();

    for (int i = 0; i < saved_sizes.length(); i++) {
        if (saved_sizes[i] < 1) continue;
        header()->resizeSection(i, saved_sizes[i]);
    }

    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }

    wsApp->emitAppSignal(WiresharkApplication::ColumnsChanged);
}

void PacketList::updateRowHeights(const QModelIndex &ih_index)
{
    QStyleOptionViewItem option = viewOptions();
    int max_height = 0;

    // One of our columns increased the maximum row height. Find out which one.
    for (int col = 0; col < packet_list_model_->columnCount(); col++) {
        QSize size_hint = itemDelegate()->sizeHint(option, packet_list_model_->index(ih_index.row(), col));
        max_height = qMax(max_height, size_hint.height());
    }

    if (max_height > 0) {
        packet_list_model_->setMaximiumRowHeight(max_height);
    }
}

void PacketList::copySummary()
{
    if (!currentIndex().isValid()) return;

    QAction *ca = qobject_cast<QAction*>(sender());
    if (!ca) return;

    bool ok = false;
    int copy_type = ca->data().toInt(&ok);
    if (!ok) return;

    QStringList col_parts;
    int row = currentIndex().row();
    for (int col = 0; col < packet_list_model_->columnCount(); col++) {
        if (get_column_visible(col)) {
            col_parts << packet_list_model_->data(packet_list_model_->index(row, col), Qt::DisplayRole).toString();
        }
    }

    QString copy_text;
    switch (copy_type) {
    case copy_summary_csv_:
        copy_text = "\"";
        copy_text += col_parts.join("\",\"");
        copy_text += "\"";
        break;
    case copy_summary_yaml_:
        copy_text = "----\n";
        copy_text += QString("# Packet %1 from %2\n").arg(row).arg(cap_file_->filename);
        copy_text += "- ";
        copy_text += col_parts.join("\n- ");
        copy_text += "\n";
        break;
    case copy_summary_text_:
    default:
        copy_text = col_parts.join("\t");
    }
    wsApp->clipboard()->setText(copy_text);
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

// Goal: Overlay the packet list scroll bar with the colors of all of the
// packets.
// Try 1: Average packet colors in each scroll bar raster line. This has
// two problems: It's easy to wash out colors and we dissect every packet.
// Try 2: Color across a 5000 or 10000 packet window. We still end up washing
// out colors.
// Try 3: One packet per vertical scroll bar pixel. This seems to work best
// but has the smallest window.
// Try 4: Use a multiple of the scroll bar heigh and scale the image down
// using Qt::SmoothTransformation. This gives us more packets per raster
// line.

// Odd (prime?) numbers resulted in fewer scaling artifacts. A multiplier
// of 9 washed out colors a little too much.
//const int height_multiplier_ = 7;
void PacketList::drawNearOverlay()
{
    if (create_near_overlay_) {
        create_near_overlay_ = false;
    }

    if (!cap_file_ || cap_file_->state != FILE_READ_DONE) return;

    if (!prefs.gui_packet_list_show_minimap) return;

    qreal dp_ratio = 1.0;
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
    dp_ratio = overlay_sb_->devicePixelRatio();
#endif
    int o_height = overlay_sb_->height() * dp_ratio;
    int o_rows = qMin(packet_list_model_->rowCount(), o_height);
    int o_width = (wsApp->fontMetrics().height() * 2 * dp_ratio) + 2; // 2ems + 1-pixel border on either side.
    int selected_pos = -1;

    if (recent.packet_list_colorize && o_rows > 0) {
        QImage overlay(o_width, o_height, QImage::Format_ARGB32_Premultiplied);

        QPainter painter(&overlay);

        overlay.fill(Qt::transparent);

        int cur_line = 0;
        int start = 0;

        if (packet_list_model_->rowCount() > o_height && overlay_sb_->maximum() > 0) {
            start += ((double) overlay_sb_->value() / overlay_sb_->maximum()) * (packet_list_model_->rowCount() - o_rows);
        }
        int end = start + o_rows;
        for (int row = start; row < end; row++) {
            packet_list_model_->ensureRowColorized(row);

            frame_data *fdata = packet_list_model_->getRowFdata(row);
            const color_t *bgcolor = NULL;
            if (fdata->color_filter) {
                const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
                bgcolor = &color_filter->bg_color;
            }

            int next_line = (row - start) * o_height / o_rows;
            if (bgcolor) {
                QColor color(ColorUtils::fromColorT(bgcolor));
                painter.fillRect(0, cur_line, o_width, next_line - cur_line, color);
            }
            cur_line = next_line;
        }

        // If the selected packet is in the overlay set selected_pos
        // accordingly. Otherwise, pin it to either the top or bottom.
        if (selectionModel()->hasSelection()) {
            int sel_row = selectionModel()->currentIndex().row();
            if (sel_row < start) {
                selected_pos = 0;
            } else if (sel_row >= end) {
                selected_pos = overlay.height() - 1;
            } else {
                selected_pos = (sel_row - start) * o_height / o_rows;
            }
        }

        overlay_sb_->setNearOverlayImage(overlay, packet_list_model_->rowCount(), start, end, selected_pos);
    } else {
        QImage overlay;
        overlay_sb_->setNearOverlayImage(overlay);
    }
}

void PacketList::drawFarOverlay()
{
    if (create_far_overlay_) {
        create_far_overlay_ = false;
    }

    if (!cap_file_ || cap_file_->state != FILE_READ_DONE) return;

    if (!prefs.gui_packet_list_show_minimap) return;

    QSize groove_size = overlay_sb_->grooveRect().size();
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
    qreal dp_ratio = 1.0;
    dp_ratio = overlay_sb_->devicePixelRatio();
    groove_size *= dp_ratio;
#endif
    int o_width = groove_size.width();
    int o_height = groove_size.height();
    int pl_rows = packet_list_model_->rowCount();
    QImage overlay(o_width, o_height, QImage::Format_ARGB32_Premultiplied);
    bool have_marked_image = false;

    // If only there were references from popular culture about getting into
    // some sort of groove.
    if (!overlay.isNull() && recent.packet_list_colorize && pl_rows > 0) {

        QPainter painter(&overlay);

        // Draw text-colored tick marks on a transparent background.
        // Hopefully no themes use the text color for the groove color.
        overlay.fill(Qt::transparent);

        QColor tick_color = palette().text().color();
        tick_color.setAlphaF(0.3);
        painter.setPen(tick_color);

        for (int row = 0; row < pl_rows; row++) {

            frame_data *fdata = packet_list_model_->getRowFdata(row);
            if (fdata->flags.marked || fdata->flags.ref_time || fdata->flags.ignored) {
                int new_line = row * o_height / pl_rows;
                int tick_width = o_width / 3;
                // Marked or ignored: left side, time refs: right side.
                // XXX Draw ignored ticks in the middle?
                int x1 = fdata->flags.ref_time ? o_width - tick_width : 1;
                int x2 = fdata->flags.ref_time ? o_width - 1 : tick_width;

                painter.drawLine(x1, new_line, x2, new_line);
                have_marked_image = true;
            }
        }

        if (have_marked_image) {
            overlay_sb_->setMarkedPacketImage(overlay);
            return;
        }
    }

    if (!have_marked_image) {
        QImage null_overlay;
        overlay_sb_->setMarkedPacketImage(null_overlay);
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
