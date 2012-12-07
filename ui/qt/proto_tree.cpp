/* proto_tree.cpp
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>

#include "proto_tree.h"

#include <epan/ftypes/ftypes.h>
#include <epan/prefs.h>

#include "wireshark_application.h"
#include <QHeaderView>
#include <QTreeWidgetItemIterator>
#include <QDesktopServices>
#include <QUrl>
#include <QContextMenuEvent>
#include <QMainWindow>

QColor        expert_color_comment    ( 0x00, 0xff, 0x00 );        /* Green */
QColor        expert_color_chat       ( 0x80, 0xb7, 0xf7 );        /* light blue */
QColor        expert_color_note       ( 0xa0, 0xff, 0xff );        /* bright turquoise */
QColor        expert_color_warn       ( 0xf7, 0xf2, 0x53 );        /* yellow */
QColor        expert_color_error      ( 0xff, 0x5c, 0x5c );        /* pale red */
QColor        expert_color_foreground ( 0x00, 0x00, 0x00 );        /* black */
QColor        hidden_proto_item       ( 0x44, 0x44, 0x44 );        /* gray */

/* Fill a single protocol tree item with its string value and set its color. */
static void
proto_tree_draw_node(proto_node *node, gpointer data)
{
    field_info   *fi = PNODE_FINFO(node);
    gchar         label_str[ITEM_LABEL_LENGTH];
    gchar        *label_ptr;
    gboolean      is_branch;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    if (PROTO_ITEM_IS_HIDDEN(node) && !prefs.display_hidden_proto_items)
        return;

    // Fill in our label
    /* was a free format label produced? */
    if (fi->rep) {
        label_ptr = fi->rep->representation;
    }
    else { /* no, make a generic label */
        label_ptr = label_str;
        proto_item_fill_label(fi, label_str);
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
            label_ptr = g_strdup_printf("<[%s]>", label_ptr);
        } else {
            label_ptr = g_strdup_printf("[%s]", label_ptr);
        }
    } else if (PROTO_ITEM_IS_HIDDEN(node)) {
        label_ptr = g_strdup_printf("<%s>", label_ptr);
    }

    QTreeWidgetItem *parentItem = (QTreeWidgetItem *)data;
    QTreeWidgetItem *item;
    item = new QTreeWidgetItem(parentItem, 0);

    // Set our colors.
    QPalette pal = QApplication::palette();
    if (fi && fi->hfinfo) {
        if(fi->hfinfo->type == FT_PROTOCOL) {
            item->setData(0, Qt::BackgroundRole, pal.alternateBase());
        }

        if((fi->hfinfo->type == FT_FRAMENUM) ||
                (FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type))) {
            QFont font = item->font(0);

            item->setData(0, Qt::ForegroundRole, pal.link());
            font.setUnderline(true);
            item->setData(0, Qt::FontRole, font);
        }
    }

    // XXX - Add routines to get our severity colors.
    if(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        switch(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        case(PI_COMMENT):
            item->setData(0, Qt::BackgroundRole, expert_color_comment);
            break;
        case(PI_CHAT):
            item->setData(0, Qt::BackgroundRole, expert_color_chat);
            break;
        case(PI_NOTE):
            item->setData(0, Qt::BackgroundRole, expert_color_note);
            break;
        case(PI_WARN):
            item->setData(0, Qt::BackgroundRole, expert_color_warn);
            break;
        case(PI_ERROR):
            item->setData(0, Qt::BackgroundRole, expert_color_error);
            break;
        default:
            g_assert_not_reached();
        }
        item->setData(0, Qt::ForegroundRole, expert_color_foreground);
    }

    item->setText(0, label_ptr);
    item->setData(0, Qt::UserRole, qVariantFromValue(fi));

    if (PROTO_ITEM_IS_GENERATED(node) || PROTO_ITEM_IS_HIDDEN(node)) {
        g_free(label_ptr);
    }

    if (is_branch) {
        if (tree_is_expanded[fi->tree_type]) {
            item->setExpanded(true);
        } else {
            item->setExpanded(false);
        }

        proto_tree_children_foreach(node, proto_tree_draw_node, item);
    }
}

ProtoTree::ProtoTree(QWidget *parent) :
    QTreeWidget(parent)
{
    QMenu *submenu, *subsubmenu;

    setAccessibleName(tr("Packet details"));
    setUniformRowHeights(true);

    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandSubtrees"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewExpandAll"));
    ctx_menu_.addAction(window()->findChild<QAction *>("actionViewCollapseAll"));
    ctx_menu_.addSeparator();
//    "     <menuitem name='ApplyasColumn' action='/Apply as Column'/>\n"
    ctx_menu_.addSeparator();
    submenu = new QMenu(tr("Apply as Filter"));
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzeAAFOrNotSelected"));
    submenu = new QMenu(tr("Prepare a Filter"));
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFAndNotSelected"));
    submenu->addAction(window()->findChild<QAction *>("actionAnalyzePAFOrNotSelected"));
    submenu = new QMenu(tr("Colorize with Filter"));
    ctx_menu_.addMenu(submenu);
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
    submenu = new QMenu(tr("Copy"));
    ctx_menu_.addMenu(submenu);
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyDescription"));
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyFieldName"));
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyValue"));
    submenu->addSeparator();
    submenu->addAction(window()->findChild<QAction *>("actionEditCopyAsFilter"));
    subsubmenu = new QMenu(tr("Bytes"));
    submenu->addMenu(subsubmenu);
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
    ctx_menu_.addSeparator();
//    "     <menuitem name='WikiProtocolPage' action='/WikiProtocolPage'/>\n"
//    "     <menuitem name='FilterFieldReference' action='/FilterFieldReference'/>\n"
//    "     <menuitem name='ProtocolHelp' action='/ProtocolHelp'/>\n"
//    "     <menuitem name='ProtocolPreferences' action='/ProtocolPreferences'/>\n"
    ctx_menu_.addSeparator();
//    "     <menuitem name='DecodeAs' action='/DecodeAs'/>\n"
//    "     <menuitem name='DisableProtocol' action='/DisableProtocol'/>\n"
//    "     <menuitem name='ResolveName' action='/ResolveName'/>\n"
//    "     <menuitem name='GotoCorrespondingPacket' action='/GotoCorrespondingPacket'/>\n"

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
    ctx_menu_.exec(event->globalPos());
}

void ProtoTree::fillProtocolTree(proto_tree *protocol_tree) {
    clear();
    setFont(wsApp->monospaceFont());

    proto_tree_children_foreach(protocol_tree, proto_tree_draw_node, invisibleRootItem());
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
    g_assert(fi);

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
        tree_is_expanded[fi->tree_type] = TRUE;
    }
}

void ProtoTree::collapse(const QModelIndex & index) {
    field_info *fi;

    fi = index.data(Qt::UserRole).value<field_info *>();
    g_assert(fi);

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be collapsed.
     */
    if (fi->tree_type != -1) {
        g_assert(fi->tree_type >= 0 &&
                 fi->tree_type < num_tree_types);
        tree_is_expanded[fi->tree_type] = FALSE;
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
        tree_is_expanded[i] = TRUE;
    }
    QTreeWidget::expandAll();
}

void ProtoTree::collapseAll()
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_is_expanded[i] = FALSE;
    }
    QTreeWidget::collapseAll();
}

void ProtoTree::itemDoubleClick(QTreeWidgetItem *item, int column) {
    Q_UNUSED(column);

    field_info *fi;

    fi = item->data(0, Qt::UserRole).value<field_info *>();

    if(fi->hfinfo->type == FT_FRAMENUM) {
        emit goToFrame(fi->value.value.uinteger);
    }

    if(FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type)) {
        gchar *url;
        url = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, NULL);
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
