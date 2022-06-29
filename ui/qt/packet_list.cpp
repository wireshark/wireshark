/* packet_list.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/packet_list.h>

#include "config.h"

#include <glib.h>

#include "file.h"

#include <epan/epan.h>
#include <epan/epan_dissect.h>

#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>

#include "ui/main_statusbar.h"
#include "ui/packet_list_utils.h"
#include "ui/preference_utils.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/ws_ui_util.h"
#include <wsutil/utf8_entities.h>
#include "ui/util.h"

#include "wiretap/wtap_opttypes.h"
#include "wsutil/str_util.h"
#include <wsutil/wslog.h>

#include <epan/color_filters.h>
#include "frame_tvbuff.h"

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/overlay_scroll_bar.h>
#include "proto_tree.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"
#include <ui/qt/utils/data_printer.h>
#include <ui/qt/utils/frame_information.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/models/pref_models.h>
#include <ui/qt/widgets/packet_list_header.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/widgets/drag_label.h>
#include <ui/qt/filter_action.h>
#include <ui/qt/decode_as_dialog.h>

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
#include <QWindow>
#include <QJsonObject>
#include <QJsonDocument>

#ifdef Q_OS_WIN
#include "wsutil/file_util.h"
#include <QSysInfo>
#include <Uxtheme.h>
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


/*
 * Given a frame_data structure, scroll to and select the row in the
 * packet list corresponding to that frame.  If there is no such
 * row, return FALSE, otherwise return TRUE.
 */
gboolean
packet_list_select_row_from_data(frame_data *fdata_needle)
{
    if (! gbl_cur_packet_list || ! gbl_cur_packet_list->model())
        return FALSE;

    PacketListModel * model = qobject_cast<PacketListModel *>(gbl_cur_packet_list->model());

    if (! model)
        return FALSE;

    model->flushVisibleRows();
    int row = -1;
    if (!fdata_needle)
        row = 0;
    else
        row = model->visibleIndexOf(fdata_needle);

    if (row >= 0) {
        /* Calling ClearAndSelect with setCurrentIndex clears the "current"
         * item, but doesn't clear the "selected" item. We want to clear
         * the "selected" item as well so that selectionChanged() will be
         * emitted in order to force an update of the packet details and
         * packet bytes after a search.
         */
        gbl_cur_packet_list->selectionModel()->clearSelection();
        gbl_cur_packet_list->selectionModel()->setCurrentIndex(model->index(row, 0), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        return TRUE;
    }

    return FALSE;
}

void
packet_list_clear(void)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->clear();
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

gboolean
packet_list_multi_select_active(void)
{
    if (gbl_cur_packet_list) {
        return gbl_cur_packet_list->multiSelectActive();
    }
    return FALSE;
}

#define MIN_COL_WIDTH_STR "MMMMMM"

PacketList::PacketList(QWidget *parent) :
    QTreeView(parent),
    proto_tree_(NULL),
    cap_file_(NULL),
    ctx_column_(-1),
    overlay_timer_id_(0),
    create_near_overlay_(true),
    create_far_overlay_(true),
    mouse_pressed_at_(QModelIndex()),
    capture_in_progress_(false),
    tail_timer_id_(0),
    tail_at_end_(0),
    rows_inserted_(false),
    columns_changed_(false),
    set_column_visibility_(false),
    frozen_rows_(QModelIndexList()),
    cur_history_(-1),
    in_history_(false)
{
    setItemsExpandable(false);
    setRootIsDecorated(false);
    setSortingEnabled(prefs.gui_packet_list_sortable);
    setUniformRowHeights(true);
    setAccessibleName("Packet list");

    proto_prefs_menus_.setTitle(tr("Protocol Preferences"));

    packet_list_header_ = new PacketListHeader(header()->orientation());
    connect(packet_list_header_, &PacketListHeader::resetColumnWidth, this, &PacketList::setRecentColumnWidth);
    connect(packet_list_header_, &PacketListHeader::updatePackets, this, &PacketList::updatePackets);
    connect(packet_list_header_, &PacketListHeader::showColumnPreferences, this, &PacketList::showProtocolPreferences);
    connect(packet_list_header_, &PacketListHeader::editColumn, this, &PacketList::editColumn);
    connect(packet_list_header_, &PacketListHeader::columnsChanged, this, &PacketList::columnsChanged);
    setHeader(packet_list_header_);

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    header()->setFirstSectionMovable(true);
#endif

    setSelectionMode(QAbstractItemView::ExtendedSelection);

    // Shrink down to a small but nonzero size in the main splitter.
    int one_em = fontMetrics().height();
    setMinimumSize(one_em, one_em);

    overlay_sb_ = new OverlayScrollBar(Qt::Vertical, this);
    setVerticalScrollBar(overlay_sb_);

    header()->setSortIndicator(-1, Qt::AscendingOrder);

    packet_list_model_ = new PacketListModel(this, cap_file_);
    setModel(packet_list_model_);

    Q_ASSERT(gbl_cur_packet_list == Q_NULLPTR);
    gbl_cur_packet_list = this;

    connect(packet_list_model_, SIGNAL(goToPacket(int)), this, SLOT(goToPacket(int)));
    connect(packet_list_model_, SIGNAL(itemHeightChanged(const QModelIndex&)), this, SLOT(updateRowHeights(const QModelIndex&)));
    connect(mainApp, SIGNAL(addressResolutionChanged()), this, SLOT(redrawVisiblePacketsDontSelectCurrent()));
    connect(mainApp, SIGNAL(columnDataChanged()), this, SLOT(redrawVisiblePacketsDontSelectCurrent()));
    connect(mainApp, &MainApplication::preferencesChanged, this, [=]() {
        if ((bool) (prefs.gui_packet_list_sortable) != isSortingEnabled()) {
            setSortingEnabled(prefs.gui_packet_list_sortable);
        }
    });

    connect(header(), SIGNAL(sectionResized(int,int,int)),
            this, SLOT(sectionResized(int,int,int)));
    connect(header(), SIGNAL(sectionMoved(int,int,int)),
            this, SLOT(sectionMoved(int,int,int)));

    connect(verticalScrollBar(), SIGNAL(actionTriggered(int)), this, SLOT(vScrollBarActionTriggered(int)));
}

void PacketList::colorsChanged()
{
    const QString c_active   = "active";
    const QString c_inactive = "!active";

    QString flat_style_format =
        "QTreeView::item:selected:%1 {"
        "  color: %2;"
        "  background-color: %3;"
        "}";

    QString gradient_style_format =
        "QTreeView::item:selected:%1 {"
        "  color: %2;"
        "  background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1 stop: 0 %4, stop: 0.5 %3, stop: 1 %4);"
        "}";

    QString hover_style;
#if !defined(Q_OS_WIN)
    hover_style = QString(
        "QTreeView:item:hover {"
        "  background-color: %1;"
        "  color: palette(text);"
        "}").arg(ColorUtils::hoverBackground().name(QColor::HexArgb));
#endif

    QString active_style   = QString();
    QString inactive_style = QString();

    if (prefs.gui_active_style == COLOR_STYLE_DEFAULT) {
        // ACTIVE = Default
    } else if (prefs.gui_active_style == COLOR_STYLE_FLAT) {
        // ACTIVE = Flat
        QColor foreground = ColorUtils::fromColorT(prefs.gui_active_fg);
        QColor background = ColorUtils::fromColorT(prefs.gui_active_bg);

        active_style = flat_style_format.arg(
                           c_active,
                           foreground.name(),
                           background.name());
    } else if (prefs.gui_active_style == COLOR_STYLE_GRADIENT) {
        // ACTIVE = Gradient
        QColor foreground  = ColorUtils::fromColorT(prefs.gui_active_fg);
        QColor background1 = ColorUtils::fromColorT(prefs.gui_active_bg);
        QColor background2 = QColor::fromRgb(ColorUtils::alphaBlend(foreground, background1, COLOR_STYLE_ALPHA));

        active_style = gradient_style_format.arg(
                           c_active,
                           foreground.name(),
                           background1.name(),
                           background2.name());
    }

    // INACTIVE style sheet settings
    if (prefs.gui_inactive_style == COLOR_STYLE_DEFAULT) {
        // INACTIVE = Default
    } else if (prefs.gui_inactive_style == COLOR_STYLE_FLAT) {
        // INACTIVE = Flat
        QColor foreground = ColorUtils::fromColorT(prefs.gui_inactive_fg);
        QColor background = ColorUtils::fromColorT(prefs.gui_inactive_bg);

        inactive_style = flat_style_format.arg(
                             c_inactive,
                             foreground.name(),
                             background.name());
    } else if (prefs.gui_inactive_style == COLOR_STYLE_GRADIENT) {
        // INACTIVE = Gradient
        QColor foreground  = ColorUtils::fromColorT(prefs.gui_inactive_fg);
        QColor background1 = ColorUtils::fromColorT(prefs.gui_inactive_bg);
        QColor background2 = QColor::fromRgb(ColorUtils::alphaBlend(foreground, background1, COLOR_STYLE_ALPHA));

        inactive_style = gradient_style_format.arg(
                             c_inactive,
                             foreground.name(),
                             background1.name(),
                             background2.name());
    }

    // Set the style sheet
    if(prefs.gui_qt_packet_list_hover_style) {
        setStyleSheet(active_style + inactive_style + hover_style);
    } else {
        setStyleSheet(active_style + inactive_style);
    }
}

QString PacketList::joinSummaryRow(QStringList col_parts, int row, SummaryCopyType type)
{
    QString copy_text;
    switch (type) {
    case CopyAsCSV:
        copy_text = "\"";
        copy_text += col_parts.join("\",\"");
        copy_text += "\"";
        break;
    case CopyAsYAML:
        copy_text = "----\n";
        copy_text += QString("# Packet %1 from %2\n").arg(row).arg(cap_file_->filename);
        copy_text += "- ";
        copy_text += col_parts.join("\n- ");
        copy_text += "\n";
        break;
    case CopyAsText:
    default:
        copy_text = col_parts.join("\t");
    }

    return copy_text;
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

bool PacketList::multiSelectActive()
{
    return selectionModel()->selectedRows(0).count() > 1 ? true : false;
}

QList<int> PacketList::selectedRows(bool useFrameNum)
{
    QList<int> rows;
    if (selectionModel() && selectionModel()->hasSelection())
    {
        foreach (QModelIndex idx, selectionModel()->selectedRows(0))
        {
            if (idx.isValid())
            {
                if (! useFrameNum)
                    rows << idx.row();
                else if (useFrameNum)
                {
                    frame_data * frame = getFDataForRow(idx.row());
                    if (frame)
                        rows << frame->num;
                }
            }
        }
    }
    else if (currentIndex().isValid())
    {
        //
        // XXX - will we ever have a current index but not a selection
        // model?
        //
        if (! useFrameNum)
            rows << currentIndex().row();
        else
        {
            frame_data *frame = getFDataForRow(currentIndex().row());
            if (frame)
                rows << frame->num;
        }
    }

    return rows;
}

void PacketList::selectionChanged (const QItemSelection & selected, const QItemSelection & deselected)
{
    QTreeView::selectionChanged(selected, deselected);

    if (!cap_file_) return;

    int row = -1;
    static bool multiSelect = false;

    if (selectionModel())
    {
        QModelIndexList selRows = selectionModel()->selectedRows(0);
        if (selRows.count() > 1)
        {
            QList<int> rows;
            foreach (QModelIndex idx, selRows)
            {
                if (idx.isValid())
                    rows << idx.row();
            }

            emit framesSelected(rows);
            emit fieldSelected(0);
            cf_unselect_packet(cap_file_);

            /* We have to repaint the content while changing state, as some delegates react to multi-select */
            if (! multiSelect)
            {
                related_packet_delegate_.clear();
                viewport()->update();
            }

            multiSelect = true;

            return;
        }
        else if (selRows.count() > 0 && selRows.at(0).isValid())
        {
            multiSelect = false;
            row = selRows.at(0).row();
        }

        /* Handling empty selection */
        if (selRows.count() <= 0)
        {
            /* Nothing selected, but multiSelect is still active */
            if (multiSelect)
            {
                multiSelect = false;
                if (currentIndex().isValid())
                {
                    selectionModel()->select(currentIndex(), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows );
                    return;
                }
            }
            /* Nothing selected, so in WS <= 3.0 nothing was indicated as well */
            else if (currentIndex().isValid())
            {
                setCurrentIndex(QModelIndex());
            }
        }
    }

    if (row < 0 || !packet_list_model_)
        cf_unselect_packet(cap_file_);
    else {
        frame_data * fdata = packet_list_model_->getRowFdata(row);
        cf_select_packet(cap_file_, fdata);
    }

    if (!in_history_ && cap_file_->current_frame) {
        cur_history_++;
        selection_history_.resize(cur_history_);
        selection_history_.append(cap_file_->current_frame->num);
    }
    in_history_ = false;

    related_packet_delegate_.clear();

    // The previous dissection state has been invalidated by cf_select_packet
    // above, receivers must clear the previous state and apply the updated one.
    emit framesSelected(QList<int>() << row);

    if (!cap_file_->edt) {
        viewport()->update();
        emit fieldSelected(0);
        return;
    }

    if (cap_file_->edt->tree) {
        packet_info *pi = &cap_file_->edt->pi;
        related_packet_delegate_.setCurrentFrame(pi->num);
        conversation_t *conv = find_conversation_pinfo(pi, 0);
        if (conv) {
            related_packet_delegate_.setConversation(conv);
        }
        viewport()->update();
    }

    if (cap_file_->search_in_progress) {
        match_data  mdata;
        field_info *fi = NULL;

        if (cap_file_->string && cap_file_->decode_data) {
            // The tree where the target string matched one of the labels was discarded in
            // match_protocol_tree() so we have to search again in the latest tree.
            if (cf_find_string_protocol_tree(cap_file_, cap_file_->edt->tree, &mdata)) {
                fi = mdata.finfo;
            }
        } else if (cap_file_->search_pos != 0) {
            // Find the finfo that corresponds to our byte.
            fi = proto_find_field_from_offset(cap_file_->edt->tree, cap_file_->search_pos,
                                              cap_file_->edt->tvb);
        }

        if (fi) {
            FieldInformation finfo(fi, this);
            emit fieldSelected(&finfo);
        } else {
            emit fieldSelected(0);
        }
    } else if (proto_tree_) {
        proto_tree_->restoreSelectedField();
    }
}

void PacketList::contextMenuEvent(QContextMenuEvent *event)
{
    const char *module_name = NULL;

    proto_prefs_menus_.clear();

    if (cap_file_ && cap_file_->edt && cap_file_->edt->tree) {
        GPtrArray *finfo_array = proto_all_finfos(cap_file_->edt->tree);
        QList<QString> added_proto_prefs;

        for (guint i = 0; i < finfo_array->len; i++) {
            field_info *fi = (field_info *)g_ptr_array_index (finfo_array, i);
            header_field_info *hfinfo =  fi->hfinfo;

            if (prefs_is_registered_protocol(hfinfo->abbrev)) {
                if (hfinfo->parent == -1) {
                    module_name = hfinfo->abbrev;
                } else {
                    module_name = proto_registrar_get_abbrev(hfinfo->parent);
                }

                if (added_proto_prefs.contains(module_name)) {
                    continue;
                }

                ProtocolPreferencesMenu *proto_prefs_menu = new ProtocolPreferencesMenu(hfinfo->name, module_name, &proto_prefs_menus_);

                connect(proto_prefs_menu, SIGNAL(showProtocolPreferences(QString)),
                        this, SIGNAL(showProtocolPreferences(QString)));
                connect(proto_prefs_menu, SIGNAL(editProtocolPreference(preference*,pref_module*)),
                        this, SIGNAL(editProtocolPreference(preference*,pref_module*)));

                proto_prefs_menus_.addMenu(proto_prefs_menu);
                added_proto_prefs << module_name;
            }
        }
        g_ptr_array_free(finfo_array, TRUE);
    }

    QModelIndex ctxIndex = indexAt(event->pos());

    if (selectionModel() && selectionModel()->selectedRows(0).count() > 1)
        selectionModel()->select(ctxIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);

    // frameData will be owned by one of the submenus, see below.
    FrameInformation * frameData =
            new FrameInformation(new CaptureFile(this, cap_file_), packet_list_model_->getRowFdata(ctxIndex.row()));

    QMenu * ctx_menu = new QMenu(this);
    // XXX We might want to reimplement setParent() and fill in the context
    // menu there.
    ctx_menu->addAction(window()->findChild<QAction *>("actionEditMarkPacket"));
    ctx_menu->addAction(window()->findChild<QAction *>("actionEditIgnorePacket"));
    ctx_menu->addAction(window()->findChild<QAction *>("actionEditSetTimeReference"));
    ctx_menu->addAction(window()->findChild<QAction *>("actionEditTimeShift"));
    ctx_menu->addMenu(window()->findChild<QMenu *>("menuPacketComment"));

    ctx_menu->addSeparator();

    ctx_menu->addAction(window()->findChild<QAction *>("actionViewEditResolvedName"));
    ctx_menu->addSeparator();

    QString selectedfilter = getFilterFromRowAndColumn(currentIndex());

    if (! hasFocus() && cap_file_ && cap_file_->finfo_selected) {
        char *tmp_field = proto_construct_match_selected_string(cap_file_->finfo_selected, cap_file_->edt);
        selectedfilter = QString(tmp_field);
        wmem_free(NULL, tmp_field);
    }

    bool have_filter_expr = !selectedfilter.isEmpty();
    ctx_menu->addMenu(FilterAction::createFilterMenu(FilterAction::ActionApply, selectedfilter, have_filter_expr, ctx_menu));
    ctx_menu->addMenu(FilterAction::createFilterMenu(FilterAction::ActionPrepare, selectedfilter, have_filter_expr, ctx_menu));

    const char *conv_menu_name = "menuConversationFilter";
    QMenu * main_menu_item = window()->findChild<QMenu *>(conv_menu_name);
    conv_menu_.setTitle(main_menu_item->title());
    conv_menu_.setObjectName(conv_menu_name);
    ctx_menu->addMenu(&conv_menu_);

    const char *colorize_menu_name = "menuColorizeConversation";
    main_menu_item = window()->findChild<QMenu *>(colorize_menu_name);
    colorize_menu_.setTitle(main_menu_item->title());
    colorize_menu_.setObjectName(colorize_menu_name);
    ctx_menu->addMenu(&colorize_menu_);

    QMenu * submenu;
    main_menu_item = window()->findChild<QMenu *>("menuSCTP");
    if (main_menu_item) {
        submenu = new QMenu(main_menu_item->title(), ctx_menu);
        ctx_menu->addMenu(submenu);
        submenu->addAction(window()->findChild<QAction *>("actionSCTPAnalyseThisAssociation"));
        submenu->addAction(window()->findChild<QAction *>("actionSCTPShowAllAssociations"));
        submenu->addAction(window()->findChild<QAction *>("actionSCTPFilterThisAssociation"));
    }

    main_menu_item = window()->findChild<QMenu *>("menuFollow");
    submenu = new QMenu(main_menu_item->title(), ctx_menu);
    ctx_menu->addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowTCPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowUDPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowDCCPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowTLSStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowHTTPStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowHTTP2Stream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowQUICStream"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeFollowSIPCall"));

    ctx_menu->addSeparator();

    main_menu_item = window()->findChild<QMenu *>("menuEditCopy");
    submenu = new QMenu(main_menu_item->title(), ctx_menu);
    ctx_menu->addMenu(submenu);

    QAction * action = submenu->addAction(tr("Summary as Text"));
    action->setData(CopyAsText);
    connect(action, SIGNAL(triggered()), this, SLOT(copySummary()));
    action = submenu->addAction(tr("…as CSV"));
    action->setData(CopyAsCSV);
    connect(action, SIGNAL(triggered()), this, SLOT(copySummary()));
    action = submenu->addAction(tr("…as YAML"));
    action->setData(CopyAsYAML);
    connect(action, SIGNAL(triggered()), this, SLOT(copySummary()));
    submenu->addSeparator();

    submenu->addAction(window()->findChild<QAction *>("actionEditCopyAsFilter"));
    submenu->addSeparator();

    QActionGroup * copyEntries = DataPrinter::copyActions(this, frameData);
    submenu->addActions(copyEntries->actions());
    copyEntries->setParent(submenu);
    frameData->setParent(submenu);

    ctx_menu->addSeparator();
    ctx_menu->addMenu(&proto_prefs_menus_);
    action = ctx_menu->addAction(tr("Decode As…"));
    action->setProperty("create_new", QVariant(true));
    connect(action, &QAction::triggered, this, &PacketList::ctxDecodeAsDialog);
    // "Print" not ported intentionally
    action = window()->findChild<QAction *>("actionViewShowPacketInNewWindow");
    ctx_menu->addAction(action);


    // Set menu sensitivity for the current column and set action data.
    if (frameData)
        emit framesSelected(QList<int>() << frameData->frameNum());
    else
        emit framesSelected(QList<int>());

    ctx_menu->exec(event->globalPos());
}

void PacketList::ctxDecodeAsDialog()
{
    QAction *da_action = qobject_cast<QAction*>(sender());
    if (! da_action)
        return;
    bool create_new = da_action->property("create_new").toBool();

    DecodeAsDialog *da_dialog = new DecodeAsDialog(this, cap_file_, create_new);
    connect(da_dialog, SIGNAL(destroyed(QObject*)), mainApp, SLOT(flushAppSignals()));
    da_dialog->setWindowModality(Qt::ApplicationModal);
    da_dialog->setAttribute(Qt::WA_DeleteOnClose);
    da_dialog->show();
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

    QModelIndex curIndex = indexAt(event->pos());
    mouse_pressed_at_ = curIndex;

#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
    bool midButton = (event->buttons() & Qt::MiddleButton) == Qt::MiddleButton;
#else
    bool midButton = (event->buttons() & Qt::MidButton) == Qt::MidButton;
#endif
    if (midButton && cap_file_ && packet_list_model_)
    {
        packet_list_model_->toggleFrameMark(QModelIndexList() << curIndex);

        // Make sure the packet list's frame.marked related field text is updated.
        redrawVisiblePackets();

        create_far_overlay_ = true;
        packets_bar_update();
    }
}

void PacketList::mouseReleaseEvent(QMouseEvent *event) {
    QTreeView::mouseReleaseEvent(event);

    mouse_pressed_at_ = QModelIndex();
}

void PacketList::mouseMoveEvent (QMouseEvent *event)
{
    QModelIndex curIndex = indexAt(event->pos());
    if (event->buttons() & Qt::LeftButton && curIndex.isValid() && curIndex == mouse_pressed_at_)
    {
        ctx_column_ = curIndex.column();
        QMimeData * mimeData = new QMimeData();
        QWidget * content = nullptr;

        QString filter = getFilterFromRowAndColumn(curIndex);
        QList<int> rows = selectedRows();
        if (rows.count() > 1)
        {
            QStringList content;
            foreach (int row, rows)
            {
                QModelIndex idx = model()->index(row, 0);
                if (! idx.isValid())
                    continue;

                QString entry = createSummaryText(idx, CopyAsText);
                content << entry;
            }

            if (content.count() > 0)
                mimeData->setText(content.join("\n"));
        }
        else if (! filter.isEmpty())
        {
            QString abbrev;
            QString name = model()->headerData(curIndex.column(), header()->orientation()).toString();

            if (! filter.isEmpty())
            {
                abbrev = filter.left(filter.indexOf(' '));
            }
            else
            {
                filter = model()->data(curIndex).toString().toLower();
                abbrev = filter;
            }

            mimeData->setText(filter);

            QJsonObject filterData;
            filterData["filter"] = filter;
            filterData["name"] = abbrev;
            filterData["description"] = name;

            mimeData->setData(WiresharkMimeData::DisplayFilterMimeType, QJsonDocument(filterData).toJson());
            content = new DragLabel(QString("%1\n%2").arg(name, abbrev), this);
        }
        else
        {
            QString text = model()->data(curIndex).toString();
            if (! text.isEmpty())
                mimeData->setText(text);
        }

        if (mimeData->hasText() || mimeData->hasFormat(WiresharkMimeData::DisplayFilterMimeType))
        {
            QDrag * drag = new QDrag(this);
            drag->setMimeData(mimeData);
            if (content)
            {
                qreal dpr = window()->windowHandle()->devicePixelRatio();
                QPixmap pixmap= QPixmap(content->size() * dpr);
                pixmap.setDevicePixelRatio(dpr);
                content->render(&pixmap);
                drag->setPixmap(pixmap);
            }

            drag->exec(Qt::CopyAction);
        }
        else
        {
            delete mimeData;
        }
    }
}

void PacketList::keyPressEvent(QKeyEvent *event)
{
    QTreeView::keyPressEvent(event);
    if (event->matches(QKeySequence::Copy))
    {
        QStringList content;
        if (model() && selectionModel() && selectionModel()->hasSelection())
        {
            QList<int> rows;
            QModelIndexList selRows = selectionModel()->selectedRows(0);
            foreach(QModelIndex row, selRows)
                rows.append(row.row());

            foreach(int row, rows)
            {
                QModelIndex idx = model()->index(row, 0);
                if (! idx.isValid())
                    continue;

                QString entry = createSummaryText(idx, CopyAsText);
                content << entry;
            }
        }

        if (content.count() > 0)
            mainApp->clipboard()->setText(content.join('\n'), QClipboard::Clipboard);
    }
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
        QStyleOptionViewItem option;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        initViewItemOption(&option);
#else
        option = viewOptions();
#endif
        // In my (gcc) testing this results in correct behavior on Windows but adds extra space
        // on macOS and Linux. We might want to add Q_OS_... #ifdefs accordingly.
        size_hint = itemDelegateForColumn(column)->sizeHint(option, QModelIndex()).width();
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

        QFontMetrics fm = QFontMetrics(mainApp->monospaceFont());
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
        if (long_str) {
            col_width = fm.horizontalAdvance(long_str);
        } else {
            col_width = fm.horizontalAdvance(MIN_COL_WIDTH_STR);
        }
#else
        if (long_str) {
            col_width = fm.width(long_str);
        } else {
            col_width = fm.width(MIN_COL_WIDTH_STR);
        }
#endif
        // Custom delegate padding
        if (itemDelegateForColumn(col)) {
            QStyleOptionViewItem option;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
            initViewItemOption(&option);
#else
            option = viewOptions();
#endif
            col_width += itemDelegateForColumn(col)->sizeHint(option, QModelIndex()).width();
        }
    }

    setColumnWidth(col, col_width);
}

void PacketList::drawCurrentPacket()
{
    QModelIndex current_index = currentIndex();
    if (selectionModel() && current_index.isValid()) {
        selectionModel()->clearCurrentIndex();
        selectionModel()->setCurrentIndex(current_index, QItemSelectionModel::SelectCurrent | QItemSelectionModel::Rows);
    }
}

// Redraw the packet list and detail.  Re-selects the current packet (causes
// the UI to scroll to that packet).
// Called from many places.
void PacketList::redrawVisiblePackets() {
    redrawVisiblePacketsDontSelectCurrent();
    drawCurrentPacket();
}

// Redraw the packet list and detail.
// Does not scroll back to the selected packet.
void PacketList::redrawVisiblePacketsDontSelectCurrent() {
    packet_list_model_->invalidateAllColumnStrings();
}

void PacketList::resetColumns()
{
    packet_list_model_->resetColumns();
}

// Return true if we have a visible packet further along in the history.
bool PacketList::haveNextHistory(bool update_cur)
{
    if (selection_history_.size() < 1 || cur_history_ >= selection_history_.size() - 1) {
        return false;
    }

    for (int i = cur_history_ + 1; i < selection_history_.size(); i++) {
        if (packet_list_model_->packetNumberToRow(selection_history_.at(i)) >= 0) {
            if (update_cur) {
                cur_history_ = i;
            }
            return true;
        }
    }
    return false;
}

// Return true if we have a visible packet back in the history.
bool PacketList::havePreviousHistory(bool update_cur)
{
    if (selection_history_.size() < 1 || cur_history_ < 1) {
        return false;
    }

    for (int i = cur_history_ - 1; i >= 0; i--) {
        if (packet_list_model_->packetNumberToRow(selection_history_.at(i)) >= 0) {
            if (update_cur) {
                cur_history_ = i;
            }
            return true;
        }
    }
    return false;
}

frame_data *PacketList::getFDataForRow(int row) const
{
    return packet_list_model_->getRowFdata(row);
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
    resetColumns();
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
        // The column must be shown before setting column width.
        // Visibility will be updated in setColumnVisibility().
        setColumnHidden(col, false);
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
    // Update color style changes
    colorsChanged();

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
    // Invalidating the column strings picks up and request/response
    // tracking changes. We might just want to call it from flushVisibleRows.
    packet_list_model_->invalidateAllColumnStrings();
}

void PacketList::freeze()
{
    column_state_ = header()->saveState();
    setHeaderHidden(true);
    frozen_rows_ = selectedIndexes();
    selectionModel()->clear();
    setModel(Q_NULLPTR);
    // It looks like GTK+ sends a cursor-changed signal at this point but Qt doesn't
    // call selectionChanged.
    related_packet_delegate_.clear();

    /* Clears packet list as well as byteview */
    emit framesSelected(QList<int>());
}

void PacketList::thaw(bool restore_selection)
{
    setHeaderHidden(false);
    setModel(packet_list_model_);

    // Resetting the model resets our column widths so we restore them here.
    // We don't reapply the recent settings because the user could have
    // resized the columns manually since they were initially loaded.
    header()->restoreState(column_state_);

    if (restore_selection && frozen_rows_.length() > 0 && selectionModel()) {
        /* This updates our selection, which redissects the current packet,
         * which is needed when we're called from MainWindow::layoutPanes.
         * Also, this resets all ProtoTree and ByteView data */
        clearSelection();
        foreach (QModelIndex idx, frozen_rows_) {
            selectionModel()->select(idx, QItemSelectionModel::Select | QItemSelectionModel::Rows);
        }
    }
    frozen_rows_ = QModelIndexList();
}

void PacketList::clear() {
    related_packet_delegate_.clear();
    selectionModel()->clear();
    packet_list_model_->clear();
    proto_tree_->clear();
    selection_history_.clear();
    cur_history_ = -1;
    in_history_ = false;

    QImage overlay;
    overlay_sb_->setNearOverlayImage(overlay);
    overlay_sb_->setMarkedPacketImage(overlay);
    create_near_overlay_ = true;
    create_far_overlay_ = true;
}

void PacketList::writeRecent(FILE *rf) {
    gint col, width, col_fmt;
    gchar xalign;

    fprintf (rf, "%s:\n", RECENT_KEY_COL_WIDTH);
    for (col = 0; col < prefs.num_cols; col++) {
        if (col > 0) {
            fprintf (rf, ",\n");
        }
        col_fmt = get_column_format(col);
        if (col_fmt == COL_CUSTOM) {
            fprintf (rf, "        \"%%Cus:%s\",", get_column_custom_fields(col));
        } else {
            fprintf (rf, "        %s,", col_format_to_string(col_fmt));
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

QString PacketList::getFilterFromRowAndColumn(QModelIndex idx)
{
    frame_data *fdata;
    QString filter;

    if (! idx.isValid())
        return filter;

    int row = idx.row();
    int column = idx.column();

    if (!cap_file_ || !packet_list_model_ || column < 0 || column >= cap_file_->cinfo.num_cols)
        return filter;

    fdata = packet_list_model_->getRowFdata(row);

    if (fdata != NULL) {
        epan_dissect_t edt;
        wtap_rec rec; /* Record metadata */
        Buffer buf;   /* Record data */

        wtap_rec_init(&rec);
        ws_buffer_init(&buf, 1514);
        if (!cf_read_record(cap_file_, fdata, &rec, &buf)) {
            wtap_rec_cleanup(&rec);
            ws_buffer_free(&buf);
            return filter; /* error reading the record */
        }
        /* proto tree, visible. We need a proto tree if there's custom columns */
        epan_dissect_init(&edt, cap_file_->epan, have_custom_cols(&cap_file_->cinfo), FALSE);
        col_custom_prime_edt(&edt, &cap_file_->cinfo);

        epan_dissect_run(&edt, cap_file_->cd_t, &rec,
                         frame_tvbuff_new_buffer(&cap_file_->provider, fdata, &buf),
                         fdata, &cap_file_->cinfo);
        epan_dissect_fill_in_columns(&edt, TRUE, TRUE);

        if ((cap_file_->cinfo.columns[column].col_custom_occurrence) ||
            (strchr (cap_file_->cinfo.col_expr.col_expr_val[column], ',') == NULL))
        {
            /* Only construct the filter when a single occurrence is displayed
             * otherwise we might end up with a filter like "ip.proto==1,6".
             *
             * Or do we want to be able to filter on multiple occurrences so that
             * the filter might be calculated as "ip.proto==1 && ip.proto==6"
             * instead?
             */
            if (strlen(cap_file_->cinfo.col_expr.col_expr[column]) != 0 &&
                strlen(cap_file_->cinfo.col_expr.col_expr_val[column]) != 0) {
                gboolean is_string_value = FALSE;
                if (cap_file_->cinfo.columns[column].col_fmt == COL_CUSTOM) {
                    header_field_info *hfi = proto_registrar_get_byname(cap_file_->cinfo.columns[column].col_custom_fields);
                    if (hfi && hfi->parent == -1) {
                        /* Protocol only */
                        filter.append(cap_file_->cinfo.col_expr.col_expr[column]);
                    } else if (hfi && hfi->type == FT_STRING) {
                        /* Custom string, add quotes */
                        is_string_value = TRUE;
                    }
                } else {
                    header_field_info *hfi = proto_registrar_get_byname(cap_file_->cinfo.col_expr.col_expr[column]);
                    if (hfi && hfi->type == FT_STRING) {
                        /* Could be an address type such as usb.src which must be quoted. */
                        is_string_value = TRUE;
                    }
                }

                if (filter.isEmpty()) {
                    if (is_string_value) {
                        filter.append(QString("%1 == \"%2\"")
                                      .arg(cap_file_->cinfo.col_expr.col_expr[column])
                                      .arg(cap_file_->cinfo.col_expr.col_expr_val[column]));
                    } else {
                        filter.append(QString("%1 == %2")
                                      .arg(cap_file_->cinfo.col_expr.col_expr[column])
                                      .arg(cap_file_->cinfo.col_expr.col_expr_val[column]));
                    }
                }
            }
        }

        epan_dissect_cleanup(&edt);
        wtap_rec_cleanup(&rec);
        ws_buffer_free(&buf);
    }

    return filter;
}

void PacketList::resetColorized()
{
    packet_list_model_->resetColorized();
    update();
}

QString PacketList::getPacketComment(guint c_number)
{
    int row = currentIndex().row();
    const frame_data *fdata;
    char *pkt_comment;
    wtap_opttype_return_val result;
    QString ret_val = NULL;

    if (!cap_file_ || !packet_list_model_) return NULL;

    fdata = packet_list_model_->getRowFdata(row);

    if (!fdata) return NULL;

    wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
    result = wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, c_number, &pkt_comment);
    if (result == WTAP_OPTTYPE_SUCCESS) {
        ret_val = QString(pkt_comment);
    }
    wtap_block_unref(pkt_block);
    return ret_val;
}

void PacketList::addPacketComment(QString new_comment)
{
    frame_data *fdata;

    if (!cap_file_ || !packet_list_model_) return;
    if (new_comment.isEmpty()) return;

    QByteArray ba = new_comment.toLocal8Bit();

    for (int i = 0; i < selectedRows().size(); i++) {
        int row = selectedRows().at(i);

        fdata = packet_list_model_->getRowFdata(row);

        if (!fdata) continue;

        wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);

        wtap_block_add_string_option(pkt_block, OPT_COMMENT, ba.data(), ba.size());

        cf_set_modified_block(cap_file_, fdata, pkt_block);
    }

    redrawVisiblePackets();
}

void PacketList::setPacketComment(guint c_number, QString new_comment)
{
    int row = currentIndex().row();
    frame_data *fdata;

    if (!cap_file_ || !packet_list_model_) return;

    fdata = packet_list_model_->getRowFdata(row);

    if (!fdata) return;

    wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);

    /* Check if we are clearing the comment */
    if (new_comment.isEmpty()) {
        wtap_block_remove_nth_option_instance(pkt_block, OPT_COMMENT, c_number);
    } else {
        QByteArray ba = new_comment.toLocal8Bit();
        wtap_block_set_nth_string_option_value(pkt_block, OPT_COMMENT, c_number, ba.data(), ba.size());
    }

    cf_set_modified_block(cap_file_, fdata, pkt_block);

    redrawVisiblePackets();
}

QString PacketList::allPacketComments()
{
    guint32 framenum;
    frame_data *fdata;
    QString buf_str;

    if (!cap_file_) return buf_str;

    for (framenum = 1; framenum <= cap_file_->count ; framenum++) {
        fdata = frame_data_sequence_find(cap_file_->provider.frames, framenum);

        wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);

        if (pkt_block) {
            guint n_comments = wtap_block_count_option(pkt_block, OPT_COMMENT);
            for (guint i = 0; i < n_comments; i++) {
                char *comment_text;
                if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, i, &comment_text)) {
                    buf_str.append(QString(tr("Frame %1: %2\n\n")).arg(framenum).arg(comment_text));
                    if (buf_str.length() > max_comments_to_fetch_) {
                        buf_str.append(QString(tr("[ Comment text exceeds %1. Stopping. ]"))
                                .arg(format_size(max_comments_to_fetch_, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));
                        return buf_str;
                    }
                }
            }
        }
    }
    return buf_str;
}

void PacketList::deleteCommentsFromPackets()
{
    frame_data *fdata;

    if (!cap_file_ || !packet_list_model_) return;

    for (int i = 0; i < selectedRows().size(); i++) {
        int row = selectedRows().at(i);

        fdata = packet_list_model_->getRowFdata(row);

        if (!fdata) continue;

        wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
        guint n_comments = wtap_block_count_option(pkt_block, OPT_COMMENT);

        for (guint j = 0; j < n_comments; j++) {
            wtap_block_remove_nth_option_instance(pkt_block, OPT_COMMENT, 0);
        }

        cf_set_modified_block(cap_file_, fdata, pkt_block);
    }

    redrawVisiblePackets();
}

void PacketList::deleteAllPacketComments()
{
    guint32 framenum;
    frame_data *fdata;
    QString buf_str;
    guint i;

    if (!cap_file_)
        return;

    for (framenum = 1; framenum <= cap_file_->count ; framenum++) {
        fdata = frame_data_sequence_find(cap_file_->provider.frames, framenum);
        wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
        guint n_comments = wtap_block_count_option(pkt_block, OPT_COMMENT);

        for (i = 0; i < n_comments; i++) {
            wtap_block_remove_nth_option_instance(pkt_block, OPT_COMMENT, 0);
        }
        cf_set_modified_block(cap_file_, fdata, pkt_block);
    }

    cap_file_->packet_comment_count = 0;
    expert_update_comment_count(cap_file_->packet_comment_count);
    redrawVisiblePackets();
}


// Slots

void PacketList::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    packet_list_model_->setCaptureFile(cf);
    if (cf) {
        if (columns_changed_) {
            columnsChanged();
        } else {
            // Restore columns widths and visibility.
            header()->restoreState(column_state_);
            setColumnVisibility();
        }
    }
    create_near_overlay_ = true;
    sortByColumn(-1, Qt::AscendingOrder);
}

void PacketList::setMonospaceFont(const QFont &mono_font)
{
    setFont(mono_font);
    header()->setFont(mainApp->font());
}

void PacketList::goNextPacket(void)
{
    if (QApplication::keyboardModifiers() & Qt::AltModifier) {
        // Alt+toolbar
        goNextHistoryPacket();
        return;
    }

    if (selectionModel()->hasSelection()) {
        selectionModel()->setCurrentIndex(moveCursor(MoveDown, Qt::NoModifier), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    } else {
        // First visible packet.
        selectionModel()->setCurrentIndex(indexAt(viewport()->rect().topLeft()), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    scrollViewChanged(false);
}

void PacketList::goPreviousPacket(void)
{
    if (QApplication::keyboardModifiers() & Qt::AltModifier) {
        // Alt+toolbar
        goPreviousHistoryPacket();
        return;
    }

    if (selectionModel()->hasSelection()) {
        selectionModel()->setCurrentIndex(moveCursor(MoveUp, Qt::NoModifier), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    } else {
        // Last visible packet.
        QModelIndex last_idx = indexAt(viewport()->rect().bottomLeft());
        if (last_idx.isValid()) {
            selectionModel()->setCurrentIndex(last_idx, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        } else {
            goLastPacket();
        }
    }

    scrollViewChanged(false);
}

void PacketList::goFirstPacket(bool user_selected) {
    if (packet_list_model_->rowCount() < 1) return;
    selectionModel()->setCurrentIndex(packet_list_model_->index(0, 0), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    scrollTo(currentIndex());

    if (user_selected) {
        scrollViewChanged(false);
    }
}

void PacketList::goLastPacket(void) {
    if (packet_list_model_->rowCount() < 1) return;
    selectionModel()->setCurrentIndex(packet_list_model_->index(packet_list_model_->rowCount() - 1, 0), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    scrollTo(currentIndex());

    scrollViewChanged(false);
}

// XXX We can jump to the wrong packet if a display filter is applied
void PacketList::goToPacket(int packet, int hf_id)
{
    if (!cf_goto_frame(cap_file_, packet))
        return;

    int row = packet_list_model_->packetNumberToRow(packet);
    if (row >= 0) {
        selectionModel()->setCurrentIndex(packet_list_model_->index(row, 0), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        proto_tree_->goToHfid(hf_id);
    }

    scrollViewChanged(false);
}

void PacketList::goNextHistoryPacket()
{
    if (haveNextHistory(true)) {
        in_history_ = true;
        goToPacket(selection_history_.at(cur_history_));
        in_history_ = false;
    }
}

void PacketList::goPreviousHistoryPacket()
{
    if (havePreviousHistory(true)) {
        in_history_ = true;
        goToPacket(selection_history_.at(cur_history_));
        in_history_ = false;
    }
}

void PacketList::markFrame()
{
    if (!cap_file_ || !packet_list_model_) return;

    QModelIndexList frames;

    if (selectionModel() && selectionModel()->hasSelection())
    {
        QModelIndexList selRows = selectionModel()->selectedRows(0);
        foreach (QModelIndex idx, selRows)
        {
            if (idx.isValid())
            {
                frames << idx;
            }
        }
    }
    else
        frames << currentIndex();

    packet_list_model_->toggleFrameMark(frames);

    // Make sure the packet list's frame.marked related field text is updated.
    redrawVisiblePackets();

    create_far_overlay_ = true;
    packets_bar_update();
}

void PacketList::markAllDisplayedFrames(bool set)
{
    if (!cap_file_ || !packet_list_model_) return;

    packet_list_model_->setDisplayedFrameMark(set);

    // Make sure the packet list's frame.marked related field text is updated.
    redrawVisiblePackets();

    create_far_overlay_ = true;
    packets_bar_update();
}

void PacketList::ignoreFrame()
{
    if (!cap_file_ || !packet_list_model_) return;

    QModelIndexList frames;

    if (selectionModel() && selectionModel()->hasSelection())
    {
        foreach (QModelIndex idx, selectionModel()->selectedRows(0))
        {
            if (idx.isValid())
            {
                frames << idx;
            }
        }
    }
    else
        frames << currentIndex();


    packet_list_model_->toggleFrameIgnore(frames);
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
    packet_list_model_->resetColumns();
    redrawVisiblePackets();
    // XXX emit packetDissectionChanged(); ?
}

void PacketList::updatePackets(bool redraw)
{
    if (redraw) {
        packet_list_model_->resetColumns();
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
    prefs_main_write();
}

void PacketList::sectionResized(int col, int, int new_width)
{
    if (isVisible() && !columns_changed_ && !set_column_visibility_ && new_width > 0) {
        // Column 1 gets an invalid value (32 on macOS) when we're not yet
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
void PacketList::sectionMoved(int logicalIndex, int oldVisualIndex, int newVisualIndex)
{
    GList *new_col_list = NULL;
    QList<int> saved_sizes;
    int sort_idx;

    // Since we undo the move below, these should always stay in sync.
    // Otherwise the order of columns can be unexpected after drag and drop.
    if (logicalIndex != oldVisualIndex) {
        ws_warning("Column moved from an unexpected state (%d, %d, %d)",
                logicalIndex, oldVisualIndex, newVisualIndex);
    }

    // Remember which column should be sorted. Use the visual index since this
    // points to the current GUI state rather than the outdated column order
    // (indicated by the logical index).
    sort_idx = header()->sortIndicatorSection();
    if (sort_idx != -1) {
        sort_idx = header()->visualIndex(sort_idx);
    }

    // Build a new column list based on the header's logical order.
    for (int vis_idx = 0; vis_idx < header()->count(); vis_idx++) {
        int log_idx = header()->logicalIndex(vis_idx);
        saved_sizes << header()->sectionSize(log_idx);

        void *pref_data = g_list_nth_data(prefs.col_list, log_idx);
        if (!pref_data) continue;

        new_col_list = g_list_append(new_col_list, pref_data);
    }

    // Undo move to ensure that the logical indices map to the visual indices,
    // otherwise the column order is changed twice (once via the modified
    // col_list, once because of the visual/logical index mismatch).
    disconnect(header(), SIGNAL(sectionMoved(int,int,int)),
               this, SLOT(sectionMoved(int,int,int)));
    header()->moveSection(newVisualIndex, oldVisualIndex);
    connect(header(), SIGNAL(sectionMoved(int,int,int)),
            this, SLOT(sectionMoved(int,int,int)));

    // Clear and rebuild our (and the header's) model. There doesn't appear
    // to be another way to reset the logical index.
    freeze();

    g_list_free(prefs.col_list);
    prefs.col_list = new_col_list;

    thaw(true);

    for (int i = 0; i < saved_sizes.length(); i++) {
        if (saved_sizes[i] < 1) continue;
        header()->resizeSection(i, saved_sizes[i]);
    }

    prefs_main_write();

    mainApp->emitAppSignal(MainApplication::ColumnsChanged);

    // If the column with the sort indicator got shifted, mark the new column
    // after updating the columns contents (via ColumnsChanged) to ensure that
    // the columns are sorted using the intended column contents.
    int left_col = MIN(oldVisualIndex, newVisualIndex);
    int right_col = MAX(oldVisualIndex, newVisualIndex);
    if (left_col <= sort_idx && sort_idx <= right_col) {
        header()->setSortIndicator(sort_idx, header()->sortIndicatorOrder());
    }
}

void PacketList::updateRowHeights(const QModelIndex &ih_index)
{
    QStyleOptionViewItem option;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    initViewItemOption(&option);
#else
    option = viewOptions();
#endif
    int max_height = 0;

    // One of our columns increased the maximum row height. Find out which one.
    for (int col = 0; col < packet_list_model_->columnCount(); col++) {
        QSize size_hint = itemDelegate()->sizeHint(option, packet_list_model_->index(ih_index.row(), col));
        max_height = qMax(max_height, size_hint.height());
    }

    if (max_height > 0) {
        packet_list_model_->setMaximumRowHeight(max_height);
    }
}

QString PacketList::createSummaryText(QModelIndex idx, SummaryCopyType type)
{
    if (! idx.isValid())
        return "";

    QStringList col_parts;
    int row = idx.row();
    for (int col = 0; col < packet_list_model_->columnCount(); col++) {
        if (get_column_visible(col)) {
            col_parts << packet_list_model_->data(packet_list_model_->index(row, col), Qt::DisplayRole).toString();
        }
    }
    return joinSummaryRow(col_parts, row, type);
}

QString PacketList::createHeaderSummaryText(SummaryCopyType type)
{
    QStringList col_parts;
    for (int col = 0; col < packet_list_model_->columnCount(); ++col)
    {
        if (get_column_visible(col)) {
            col_parts << packet_list_model_->headerData(col, Qt::Orientation::Horizontal, Qt::DisplayRole).toString();
        }
    }
    return joinSummaryRow(col_parts, 0, type);
}

void PacketList::copySummary()
{
    if (!currentIndex().isValid()) return;

    QAction *ca = qobject_cast<QAction*>(sender());
    if (!ca) return;

    QVariant type = ca->data();
    if (! type.canConvert<SummaryCopyType>())
        return;
    SummaryCopyType copy_type = type.value<SummaryCopyType>();

    QString copy_text = createSummaryText(currentIndex(), copy_type);

    mainApp->clipboard()->setText(copy_text);
}

// We need to tell when the user has scrolled the packet list, either to
// the end or anywhere other than the end.
void PacketList::vScrollBarActionTriggered(int)
{
    // If we're scrolling with a mouse wheel or trackpad sliderPosition can end up
    // past the end.
    tail_at_end_ = (overlay_sb_->sliderPosition() >= overlay_sb_->maximum());

    scrollViewChanged(tail_at_end_);
}

void PacketList::scrollViewChanged(bool at_end)
{
    if (capture_in_progress_ && prefs.capture_auto_scroll) {
        emit packetListScrolled(at_end);
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

    qreal dp_ratio = overlay_sb_->devicePixelRatio();
    int o_height = overlay_sb_->height() * dp_ratio;
    int o_rows = qMin(packet_list_model_->rowCount(), o_height);
    QFontMetricsF fmf(mainApp->font());
    int o_width = ((static_cast<int>(fmf.height())) * 2 * dp_ratio) + 2; // 2ems + 1-pixel border on either side.

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
        QList<int> positions;
        if (selectionModel()->hasSelection()) {

            QModelIndexList selRows = selectionModel()->selectedRows(0);
            int last_row = -1;
            int last_pos = -1;
            foreach (QModelIndex idx, selRows)
            {
                int selected_pos = -1;
                int sel_row = idx.row();
                if (sel_row < start) {
                    selected_pos = 0;
                } else if (sel_row >= end) {
                    selected_pos = overlay.height() - 1;
                } else {
                    selected_pos = (sel_row - start) * o_height / o_rows;
                }

                    /* Due to the difference in the display height, we sometimes get empty positions
                     * inbetween consecutive valid rows. If those are detected, they are signaled as
                     * being selected as well */
                if (last_pos >= 0 && selected_pos > (last_pos + 1) && (last_row + 1) == sel_row)
                {
                    for (int pos = (last_pos + 1); pos < selected_pos; pos++)
                    {
                        if (! positions.contains(pos))
                            positions << pos;
                    }
                }
                else if (selected_pos != -1 && ! positions.contains(selected_pos))
                    positions << selected_pos;

                last_row = sel_row;
                last_pos = selected_pos;
            }
        }

        overlay_sb_->setNearOverlayImage(overlay, packet_list_model_->rowCount(), start, end, positions, (o_height / o_rows));
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
    qreal dp_ratio = overlay_sb_->devicePixelRatio();
    groove_size *= dp_ratio;
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
        tick_color.setAlphaF(0.3f);
        painter.setPen(tick_color);

        for (int row = 0; row < pl_rows; row++) {

            frame_data *fdata = packet_list_model_->getRowFdata(row);
            if (fdata->marked || fdata->ref_time || fdata->ignored) {
                int new_line = row * o_height / pl_rows;
                int tick_width = o_width / 3;
                // Marked or ignored: left side, time refs: right side.
                // XXX Draw ignored ticks in the middle?
                int x1 = fdata->ref_time ? o_width - tick_width : 1;
                int x2 = fdata->ref_time ? o_width - 1 : tick_width;

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

void PacketList::resizeAllColumns(bool onlyTimeFormatted)
{
    if (!cap_file_ || cap_file_->state == FILE_CLOSED)
        return;

    for (int col = 0; col < cap_file_->cinfo.num_cols; col++) {
        if (! onlyTimeFormatted || col_has_time_fmt(&cap_file_->cinfo, col)) {
            resizeColumnToContents(col);
        }
    }
}