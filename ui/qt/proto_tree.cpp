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
#include <QTreeWidgetItemIterator>
#include <QUrl>

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
    if (fi && fi->hfinfo) {
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
    decode_as_(NULL)
{
    QMenu *submenu, *subsubmenu;
    QAction *action;

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
        ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandSubtrees"));
        ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandAll"));
        ctx_menu_.addAction(window()->findChild<QAction *>("actionViewCollapseAll"));
        ctx_menu_.addSeparator();

        action = window()->findChild<QAction *>("actionAnalyzeCreateAColumn");
        ctx_menu_.addAction(action);
        ctx_menu_.addSeparator();

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

//    action = window()->findChild<QAction *>("actionColorize_with_Filter");
//    submenu = new QMenu();
//    action->setMenu(submenu);
//    ctx_menu_.addAction(action);
//    "       <menuitem name='Color1' action='/Colorize with Filter/Color 1'/>\n"
//    "       <menuitem name='Color2' action='/Colorize with Filter/Color 2'/>\n"
//    "       <menuitem name='Color3' action='/Colorize with Filter/Color 3'/>\n"
//    "       <menuitem name='Color4' action='/Colorize with Filter/Color 4'/>\n"
//    "       <menuitem name='Color5' action='/Colorize with Filter/Color 5'/>\n"
//    "       <menuitem name='Color6' action='/Colorize with Filter/Color 6'/>\n"
//    "       <menuitem name='Color7' action='/Colorize with Filter/Color 7'/>\n"
//    "       <menuitem name='Color8' action='/Colorize with Filter/Color 8'/>\n"
//    "       <menuitem name='Color9' action='/Colorize with Filter/Color 9'/>\n"
//    "       <menuitem name='Color10' action='/Colorize with Filter/Color 10'/>\n"
//    "       <menuitem name='NewColoringRule' action='/Colorize with Filter/New Coloring Rule'/>\n"
//    "     </menu>\n"
//    "     <menuitem name='FollowTCPStream' action='/Follow TCP Stream'/>\n"
//    "     <menuitem name='FollowUDPStream' action='/Follow UDP Stream'/>\n"
//    "     <menuitem name='FollowSSLStream' action='/Follow SSL Stream'/>\n"
        ctx_menu_.addSeparator();

        action = window()->findChild<QAction *>("actionCopy");
        submenu = new QMenu();
        action->setMenu(submenu);
        ctx_menu_.addAction(action);
        submenu->addAction(window()->findChild<QAction *>("actionCopyAllVisibleItems"));
        submenu->addAction(window()->findChild<QAction *>("actionCopyAllVisibleSelectedTreeItems"));
        submenu->addAction(window()->findChild<QAction *>("actionEditCopyDescription"));
        submenu->addAction(window()->findChild<QAction *>("actionEditCopyFieldName"));
        submenu->addAction(window()->findChild<QAction *>("actionEditCopyValue"));
        submenu->addSeparator();
        submenu->addAction(window()->findChild<QAction *>("actionEditCopyAsFilter"));

        action = window()->findChild<QAction *>("actionBytes");
        subsubmenu = new QMenu();
        action->setMenu(subsubmenu);
        submenu->addAction(action);
        subsubmenu->addSeparator();
//    "        <menu name= 'Bytes' action='/Copy/Bytes'>\n"
//    "           <menuitem name='OffsetHexText' action='/Copy/Bytes/OffsetHexText'/>\n"
//    "           <menuitem name='OffsetHex' action='/Copy/Bytes/OffsetHex'/>\n"
//    "           <menuitem name='PrintableTextOnly' action='/Copy/Bytes/PrintableTextOnly'/>\n"
//    "           <separator/>\n"
//    "           <menuitem name='HexStream' action='/Copy/Bytes/HexStream'/>\n"
//    "           <menuitem name='BinaryStream' action='/Copy/Bytes/BinaryStream'/>\n"
//    "        </menu>\n"
//    "     </menu>\n"
//    "     <menuitem name='ExportSelectedPacketBytes' action='/ExportSelectedPacketBytes'/>\n"
//    ctx_menu_.addSeparator();
//    "     <menuitem name='WikiProtocolPage' action='/WikiProtocolPage'/>\n"
//    "     <menuitem name='FilterFieldReference' action='/FilterFieldReference'/>\n"
//    "     <menuitem name='ProtocolHelp' action='/ProtocolHelp'/>\n"
//    "     <menuitem name='ProtocolPreferences' action='/ProtocolPreferences'/>\n"
//    ctx_menu_.addSeparator();
        decode_as_ = window()->findChild<QAction *>("actionAnalyzeDecodeAs");
        ctx_menu_.addAction(decode_as_);
//    "     <menuitem name='DisableProtocol' action='/DisableProtocol'/>\n"
//    "     <menuitem name='ResolveName' action='/ResolveName'/>\n"
//    "     <menuitem name='GotoCorrespondingPacket' action='/GotoCorrespondingPacket'/>\n"
        ctx_menu_.addAction(window()->findChild<QAction *>("actionViewShowPacketReferenceInNewWindow"));
    } else {
        ctx_menu_.clear();
    }

    connect(this, SIGNAL(currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)),
            this, SLOT(updateSelectionStatus(QTreeWidgetItem*)));
    connect(this, SIGNAL(expanded(QModelIndex)), this, SLOT(expand(QModelIndex)));
    connect(this, SIGNAL(collapsed(QModelIndex)), this, SLOT(collapse(QModelIndex)));
    connect(this, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)),
            this, SLOT(itemDoubleClick(QTreeWidgetItem*, int)));
}

void ProtoTree::clear() {
    updateSelectionStatus(NULL);
    QTreeWidget::clear();
}

void ProtoTree::contextMenuEvent(QContextMenuEvent *event)
{
    if (ctx_menu_.isEmpty()) return; // We're in a PacketDialog

    QMenu *main_conv_menu = window()->findChild<QMenu *>("menuConversationFilter");
    conv_menu_.clear();
    foreach (QAction *action, main_conv_menu->actions()) {
        conv_menu_.addAction(action);
    }

    decode_as_->setData(qVariantFromValue(true));
    ctx_menu_.exec(event->globalPos());
    decode_as_->setData(QVariant());
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
        iter++;
    }
}

void ProtoTree::updateSelectionStatus(QTreeWidgetItem* item) {

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

            emit protoItemSelected(*new QString());
            emit protoItemSelected(NULL);
            emit protoItemSelected(item_info);
            emit protoItemSelected(fi);
        } // else the GTK+ version pushes an empty string as described below.
        /*
         * Don't show anything if the field name is zero-length;
         * the pseudo-field for "proto_tree_add_text()" is such
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
         * Or perhaps protocol tree items added with
         * "proto_tree_add_text()" should have -1 as the field index,
         * with no pseudo-field being used, but that might also
         * require special checks for -1 to be added.
         */

    } else {
        emit protoItemSelected(*new QString());
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
        iter++;
    }
}

void ProtoTree::expandAll()
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_expanded_set(i, TRUE);
    }
    QTreeWidget::expandAll();
}

void ProtoTree::collapseAll()
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_expanded_set(i, FALSE);
    }
    QTreeWidget::collapseAll();
}

void ProtoTree::itemDoubleClick(QTreeWidgetItem *item, int column) {
    Q_UNUSED(column);

    field_info *fi;

    fi = item->data(0, Qt::UserRole).value<field_info *>();
    if (!fi || !fi->hfinfo) return;

    if(fi->hfinfo->type == FT_FRAMENUM) {
#if QT_VERSION >= QT_VERSION_CHECK(4, 8, 0)
        if (QApplication::queryKeyboardModifiers() & Qt::ShiftModifier) {
#else
        if (QApplication::keyboardModifiers() & Qt::ShiftModifier) {
#endif
            emit openPacketInNewWindow(true);
        } else {
            emit goToPacket(fi->value.value.uinteger);
        }
    }

    if(FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type)) {
        gchar *url;
        url = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, fi->hfinfo->display, NULL);
        if(url){
//            browser_open_url(url);
            QDesktopServices::openUrl(QUrl(url));
            g_free(url);
        }
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
