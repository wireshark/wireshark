/* proto_tree.cpp
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

#include <stdio.h>

#include "proto_tree.h"

#include <epan/ftypes/ftypes.h>
#include <epan/prefs.h>

#include "color_utils.h"

#include <QApplication>
#include <QContextMenuEvent>
#include <QDesktopServices>
#include <QHeaderView>
#include <QScrollBar>
#include <QTreeWidgetItemIterator>
#include <QUrl>

// To do:
// - Fix "apply as filter" behavior.

/* Fill a single protocol tree item with its string value and set its color. */
static void
proto_tree_draw_node(proto_node *node, gpointer data)
{
    field_info   *fi = PNODE_FINFO(node);
    QString       label;
    gboolean      is_branch;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    if (PROTO_ITEM_IS_HIDDEN(node) && !prefs.display_hidden_proto_items)
        return;

    // Fill in our label
    /* was a free format label produced? */
    if (fi->rep) {
        label = fi->rep->representation;
    }
    else { /* no, make a generic label */
        gchar label_str[ITEM_LABEL_LENGTH];
        proto_item_fill_label(fi, label_str);
        label = label_str;
    }

    if (node->first_child != NULL) {
        is_branch = TRUE;
        g_assert(fi->tree_type >= 0 && fi->tree_type < num_tree_types);
    }
    else {
        is_branch = FALSE;
    }

    if (PROTO_ITEM_IS_GENERATED(node)) {
        if (PROTO_ITEM_IS_HIDDEN(node)) {
            label = QString("<[%1]>").arg(label);
        } else {
            label = QString("[%1]").arg(label);
        }
    } else if (PROTO_ITEM_IS_HIDDEN(node)) {
        label = QString("<%1>").arg(label);
    }

    QTreeWidgetItem *parentItem = (QTreeWidgetItem *)data;
    QTreeWidgetItem *item;
    ProtoTree *proto_tree = qobject_cast<ProtoTree *>(parentItem->treeWidget());

    item = new QTreeWidgetItem(parentItem, 0);

    // Set our colors.
    QPalette pal = QApplication::palette();
    if (fi->hfinfo) {
        if(fi->hfinfo->type == FT_PROTOCOL) {
            item->setData(0, Qt::BackgroundRole, pal.window());
            item->setData(0, Qt::ForegroundRole, pal.windowText());
        }

        if((fi->hfinfo->type == FT_FRAMENUM) ||
                (FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type))) {
            QFont font = item->font(0);

            item->setData(0, Qt::ForegroundRole, pal.link());
            font.setUnderline(true);
            item->setData(0, Qt::FontRole, font);

            if (fi->hfinfo->type == FT_FRAMENUM) {
                ft_framenum_type_t framenum_type = (ft_framenum_type_t)GPOINTER_TO_INT(fi->hfinfo->strings);
                proto_tree->emitRelatedFrame(fi->value.value.uinteger, framenum_type);
            }
        }
    }

    // XXX - Add routines to get our severity colors.
    if(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        switch(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        case(PI_COMMENT):
            item->setData(0, Qt::BackgroundRole, ColorUtils::expert_color_comment);
            break;
        case(PI_CHAT):
            item->setData(0, Qt::BackgroundRole, ColorUtils::expert_color_chat);
            break;
        case(PI_NOTE):
            item->setData(0, Qt::BackgroundRole, ColorUtils::expert_color_note);
            break;
        case(PI_WARN):
            item->setData(0, Qt::BackgroundRole, ColorUtils::expert_color_warn);
            break;
        case(PI_ERROR):
            item->setData(0, Qt::BackgroundRole, ColorUtils::expert_color_error);
            break;
        default:
            g_assert_not_reached();
        }
        item->setData(0, Qt::ForegroundRole, ColorUtils::expert_color_foreground);
    }

    item->setText(0, label);
    item->setData(0, Qt::UserRole, qVariantFromValue(fi));

    if (is_branch) {
        if (tree_expanded(fi->tree_type)) {
            item->setExpanded(true);
        } else {
            item->setExpanded(false);
        }

        proto_tree_children_foreach(node, proto_tree_draw_node, item);
    }
}

ProtoTree::ProtoTree(QWidget *parent) :
    QTreeWidget(parent),
    decode_as_(NULL),
    column_resize_timer_(0)
{
    setAccessibleName(tr("Packet details"));
    // Leave the uniformRowHeights property as-is (false) since items might
    // have multiple lines (e.g. packet comments). If this slows things down
    // too much we should add a custom delegate which handles SizeHintRole
    // similar to PacketListModel::data.
    setHeaderHidden(true);

    if (window()->findChild<QAction *>("actionViewExpandSubtrees")) {
        // Assume we're a child of the main window.
        // XXX We might want to reimplement setParent() and fill in the context
        // menu there.
        QMenu *main_menu_item, *submenu;
        QAction *action;

        ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandSubtrees"));
        ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandAll"));
        ctx_menu_.addAction(window()->findChild<QAction *>("actionViewCollapseAll"));
        ctx_menu_.addSeparator();

        action = window()->findChild<QAction *>("actionAnalyzeCreateAColumn");
        ctx_menu_.addAction(action);
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

        QMenu *main_conv_menu = window()->findChild<QMenu *>("menuConversationFilter");
        conv_menu_.setTitle(main_conv_menu->title());
        ctx_menu_.addMenu(&conv_menu_);

        colorize_menu_.setTitle(tr("Colorize with Filter"));
        ctx_menu_.addMenu(&colorize_menu_);

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
        submenu->addAction(window()->findChild<QAction *>("actionCopyAllVisibleItems"));
        submenu->addAction(window()->findChild<QAction *>("actionCopyAllVisibleSelectedTreeItems"));
        submenu->addAction(window()->findChild<QAction *>("actionEditCopyDescription"));
        submenu->addAction(window()->findChild<QAction *>("actionEditCopyFieldName"));
        submenu->addAction(window()->findChild<QAction *>("actionEditCopyValue"));
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

        action = window()->findChild<QAction *>("actionContextShowPacketBytes");
        ctx_menu_.addAction(action);
        action = window()->findChild<QAction *>("actionFileExportPacketBytes");
        ctx_menu_.addAction(action);

        ctx_menu_.addSeparator();

        action = window()->findChild<QAction *>("actionContextWikiProtocolPage");
        ctx_menu_.addAction(action);
        action = window()->findChild<QAction *>("actionContextFilterFieldReference");
        ctx_menu_.addAction(action);
//    "     <menuitem name='ProtocolHelp' action='/ProtocolHelp'/>\n"
        ctx_menu_.addMenu(&proto_prefs_menu_);
        ctx_menu_.addSeparator();
        decode_as_ = window()->findChild<QAction *>("actionAnalyzeDecodeAs");
        ctx_menu_.addAction(decode_as_);
//    "     <menuitem name='ResolveName' action='/ResolveName'/>\n"
        ctx_menu_.addAction(window()->findChild<QAction *>("actionGoGoToLinkedPacket"));
        ctx_menu_.addAction(window()->findChild<QAction *>("actionContextShowLinkedPacketInNewWindow"));
    } else {
        ctx_menu_.clear();
    }

    connect(this, SIGNAL(currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)),
            this, SLOT(updateSelectionStatus(QTreeWidgetItem*)));
    connect(this, SIGNAL(expanded(QModelIndex)), this, SLOT(expand(QModelIndex)));
    connect(this, SIGNAL(collapsed(QModelIndex)), this, SLOT(collapse(QModelIndex)));
    connect(this, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)),
            this, SLOT(itemDoubleClick(QTreeWidgetItem*, int)));

    connect(&proto_prefs_menu_, SIGNAL(showProtocolPreferences(QString)),
            this, SIGNAL(showProtocolPreferences(QString)));
    connect(&proto_prefs_menu_, SIGNAL(editProtocolPreference(preference*,pref_module*)),
            this, SIGNAL(editProtocolPreference(preference*,pref_module*)));

    // resizeColumnToContents checks 1000 items by default. The user might
    // have scrolled to an area with a different width at this point.
    connect(verticalScrollBar(), SIGNAL(sliderReleased()),
            this, SLOT(updateContentWidth()));
}

void ProtoTree::closeContextMenu()
{
    ctx_menu_.close();
}

void ProtoTree::clear() {
    updateSelectionStatus(NULL);
    QTreeWidget::clear();
    updateContentWidth();
}

void ProtoTree::contextMenuEvent(QContextMenuEvent *event)
{
    if (ctx_menu_.isEmpty()) return; // We're in a PacketDialog

    QMenu *main_conv_menu = window()->findChild<QMenu *>("menuConversationFilter");
    conv_menu_.clear();
    foreach (QAction *action, main_conv_menu->actions()) {
        conv_menu_.addAction(action);
    }

    field_info *fi = NULL;
    const char *module_name = NULL;
    if (selectedItems().count() > 0) {
        fi = selectedItems()[0]->data(0, Qt::UserRole).value<field_info *>();
        if (fi && fi->hfinfo) {
            if (fi->hfinfo->parent == -1) {
                module_name = fi->hfinfo->abbrev;
            } else {
                module_name = proto_registrar_get_abbrev(fi->hfinfo->parent);
            }
        }
    }
    proto_prefs_menu_.setModule(module_name);

    foreach (QAction *action, copy_actions_) {
        action->setData(QVariant::fromValue<field_info *>(fi));
    }

    decode_as_->setData(qVariantFromValue(true));

    // Set menu sensitivity and action data.
    emit protoItemSelected(fi);
    ctx_menu_.exec(event->globalPos());
    decode_as_->setData(QVariant());
}

void ProtoTree::timerEvent(QTimerEvent *event)
{
    if (event->timerId() == column_resize_timer_) {
        killTimer(column_resize_timer_);
        column_resize_timer_ = 0;
        resizeColumnToContents(0);
    } else {
        QTreeWidget::timerEvent(event);
    }
}

// resizeColumnToContents checks 1000 items by default. The user might
// have scrolled to an area with a different width at this point.
void ProtoTree::keyReleaseEvent(QKeyEvent *event)
{
    if (event->isAutoRepeat()) return;

    switch(event->key()) {
        case Qt::Key_Up:
        case Qt::Key_Down:
        case Qt::Key_PageUp:
        case Qt::Key_PageDown:
        case Qt::Key_Home:
        case Qt::Key_End:
            updateContentWidth();
            break;
        default:
            break;
    }
}

void ProtoTree::updateContentWidth()
{
    if (column_resize_timer_ == 0) {
        column_resize_timer_ = startTimer(0);
    }
}

void ProtoTree::setMonospaceFont(const QFont &mono_font)
{
    mono_font_ = mono_font;
    setFont(mono_font_);
    update();
}

void ProtoTree::fillProtocolTree(proto_tree *protocol_tree) {
    clear();
    setFont(mono_font_);

    proto_tree_children_foreach(protocol_tree, proto_tree_draw_node, invisibleRootItem());
    updateContentWidth();
}

void ProtoTree::emitRelatedFrame(int related_frame, ft_framenum_type_t framenum_type)
{
    emit relatedFrame(related_frame, framenum_type);
}

// XXX We select the first match, which might not be the desired item.
void ProtoTree::goToField(int hf_id)
{
    if (hf_id < 0) return;

    QTreeWidgetItemIterator iter(this);
    while (*iter) {
        field_info *fi = (*iter)->data(0, Qt::UserRole).value<field_info *>();

        if (fi && fi->hfinfo) {
            if (fi->hfinfo->id == hf_id) {
                setCurrentItem(*iter);
                break;
            }
        }
        ++iter;
    }
}

void ProtoTree::updateSelectionStatus(QTreeWidgetItem* item)
{
    if (item) {
        field_info *fi;
        QString item_info;

        fi = item->data(0, Qt::UserRole).value<field_info *>();
        if (!fi || !fi->hfinfo) return;

        if (fi->hfinfo->blurb != NULL && fi->hfinfo->blurb[0] != '\0') {
            item_info.append(QString().fromUtf8(fi->hfinfo->blurb));
        } else {
            item_info.append(QString().fromUtf8(fi->hfinfo->name));
        }

        if (!item_info.isEmpty()) {
            int finfo_length;
            item_info.append(" (" + QString().fromUtf8(fi->hfinfo->abbrev) + ")");

            finfo_length = fi->length + fi->appendix_length;
            if (finfo_length == 1) {
                item_info.append(tr(", 1 byte"));
            } else if (finfo_length > 1) {
                item_info.append(QString(tr(", %1 bytes")).arg(finfo_length));
            }

            saveSelectedField(item);

            emit protoItemSelected("");
            emit protoItemSelected(NULL);
            emit protoItemSelected(item_info);
            emit protoItemSelected(fi);
        } // else the GTK+ version pushes an empty string as described below.
        /*
         * Don't show anything if the field name is zero-length;
         * the pseudo-field for text-only items is such
         * a field, and we don't want "Text (text)" showing up
         * on the status line if you've selected such a field.
         *
         * XXX - there are zero-length fields for which we *do*
         * want to show the field name.
         *
         * XXX - perhaps the name and abbrev field should be null
         * pointers rather than null strings for that pseudo-field,
         * but we'd have to add checks for null pointers in some
         * places if we did that.
         *
         * Or perhaps text-only items should have -1 as the field
         * index, with no pseudo-field being used, but that might
         * also require special checks for -1 to be added.
         */

    } else {
        emit protoItemSelected("");
        emit protoItemSelected(NULL);
    }
}

void ProtoTree::expand(const QModelIndex & index) {
    field_info *fi;

    fi = index.data(Qt::UserRole).value<field_info *>();
    if (!fi) return;

    if(prefs.gui_auto_scroll_on_expand) {
        ScrollHint scroll_hint = PositionAtTop;
        if (prefs.gui_auto_scroll_percentage > 66) {
            scroll_hint = PositionAtBottom;
        } else if (prefs.gui_auto_scroll_percentage >= 33) {
            scroll_hint = PositionAtCenter;
        }
        scrollTo(index, scroll_hint);
    }

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be expanded.
     */
    if (fi->tree_type != -1) {
        g_assert(fi->tree_type >= 0 &&
                 fi->tree_type < num_tree_types);
        tree_expanded_set(fi->tree_type, TRUE);
    }

    updateContentWidth();
}

void ProtoTree::collapse(const QModelIndex & index) {
    field_info *fi;

    fi = index.data(Qt::UserRole).value<field_info *>();
    if (!fi) return;

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be collapsed.
     */
    if (fi->tree_type != -1) {
        g_assert(fi->tree_type >= 0 &&
                 fi->tree_type < num_tree_types);
        tree_expanded_set(fi->tree_type, FALSE);
    }
    updateContentWidth();
}

void ProtoTree::expandSubtrees()
{
    QTreeWidgetItem *top_sel;

    if (selectedItems().length() < 1) {
        return;
    }

    top_sel = selectedItems()[0];

    if (!top_sel) {
        return;
    }

    while (top_sel->parent()) {
        top_sel = top_sel->parent();
    }

    QTreeWidgetItemIterator iter(top_sel);
    while (*iter) {
        if ((*iter) != top_sel && (*iter)->parent() == NULL) {
            // We found the next top-level item
            break;
        }
        (*iter)->setExpanded(true);
        ++iter;
    }
    updateContentWidth();
}

void ProtoTree::expandAll()
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_expanded_set(i, TRUE);
    }
    QTreeWidget::expandAll();
    updateContentWidth();
}

void ProtoTree::collapseAll()
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_expanded_set(i, FALSE);
    }
    QTreeWidget::collapseAll();
    updateContentWidth();
}

void ProtoTree::itemDoubleClick(QTreeWidgetItem *item, int) {
    field_info *fi;

    fi = item->data(0, Qt::UserRole).value<field_info *>();
    if (!fi || !fi->hfinfo) return;

    if (fi->hfinfo->type == FT_FRAMENUM) {
#if QT_VERSION >= QT_VERSION_CHECK(4, 8, 0)
        if (QApplication::queryKeyboardModifiers() & Qt::ShiftModifier) {
#else
        if (QApplication::keyboardModifiers() & Qt::ShiftModifier) {
#endif
            emit openPacketInNewWindow(true);
        } else {
            emit goToPacket(fi->value.value.uinteger);
        }
    } else if (FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type)) {
        gchar *url;
        url = fvalue_to_string_repr(NULL, &fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
        if(url){
//            browser_open_url(url);
            QDesktopServices::openUrl(QUrl(url));
            wmem_free(NULL, url);
        }
    }
}

void ProtoTree::selectField(field_info *fi)
{
    QTreeWidgetItemIterator iter(this);
    while (*iter) {
        if (fi == (*iter)->data(0, Qt::UserRole).value<field_info *>()) {
            setCurrentItem(*iter);
            scrollToItem(*iter);
            break;
        }
        ++iter;
    }
}

// Remember the currently focussed field based on:
// - current hf_id (obviously)
// - parent items (to avoid selecting a text item in a different tree)
// - position within a tree if there are multiple items (wishlist)
static QList<int> serializeAsPath(QTreeWidgetItem *item)
{
    QList<int> path;
    do {
        field_info *fi = item->data(0, Qt::UserRole).value<field_info *>();
        path.prepend(fi->hfinfo->id);
    } while ((item = item->parent()));
    return path;
}
void ProtoTree::saveSelectedField(QTreeWidgetItem *item)
{
    selected_field_path_ = serializeAsPath(item);
}

// Try to focus a tree item which was previously also visible
void ProtoTree::restoreSelectedField()
{
    if (selected_field_path_.isEmpty()) {
        return;
    }
    int last_hf_id = selected_field_path_.last();
    QTreeWidgetItemIterator iter(this);
    while (*iter) {
        field_info *fi = (*iter)->data(0, Qt::UserRole).value<field_info *>();
        if (last_hf_id == fi->hfinfo->id &&
            serializeAsPath(*iter) == selected_field_path_) {
            setCurrentItem(*iter);
            scrollToItem(*iter);
            break;
        }
        ++iter;
    }
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
