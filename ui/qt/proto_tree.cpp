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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdio.h>

#include "proto_tree.h"
#include "monospace_font.h"

#include <epan/prefs.h>

#include <QApplication>
#include <QHeaderView>

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
    gboolean      is_leaf, is_expanded;

    g_assert(fi && "dissection with an invisible proto tree?");

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
        is_leaf = FALSE;
        g_assert(fi->tree_type >= 0 && fi->tree_type < num_tree_types);
        if (tree_is_expanded[fi->tree_type]) {
            is_expanded = TRUE;
        }
        else {
            is_expanded = FALSE;
        }
    }
    else {
        is_leaf = TRUE;
        is_expanded = FALSE;
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
            item->setData(0, Qt::ForegroundRole, pal.link());
            // XXX - Draw an underline?
        }
    }

    // XXX - Add routines to get our severity colors.
    if(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        switch(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
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

//    g_log(NULL, G_LOG_LEVEL_DEBUG, "new item %s", label_ptr);
    item->setText(0, label_ptr);
    item->setData(0, Qt::UserRole, qVariantFromValue((void *) fi));

    if (PROTO_ITEM_IS_GENERATED(node) || PROTO_ITEM_IS_HIDDEN(node)) {
        g_free(label_ptr);
    }

    if (!is_leaf) {
        proto_tree_children_foreach(node, proto_tree_draw_node, item);
    }
}

ProtoTree::ProtoTree(QWidget *parent) :
    QTreeWidget(parent)
{
    setAccessibleName(tr("Packet details"));
    setFont(get_monospace_font());

    connect(this, SIGNAL(currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)),
            this, SLOT(updateSelectionStatus(QTreeWidgetItem*)));
}

void ProtoTree::clear() {
    updateSelectionStatus(NULL);
    QTreeWidget::clear();
}

void ProtoTree::fillProtocolTree(proto_tree *protocol_tree) {
    // Clear out previous tree
    clear();

    proto_tree_children_foreach(protocol_tree, proto_tree_draw_node, invisibleRootItem());
}

void ProtoTree::updateSelectionStatus(QTreeWidgetItem* item) {

    if (item) {
        field_info *fi;
        QVariant v;
        QString itemInfo;
        int finfo_length;

        v = item->data(0, Qt::UserRole);
        fi = (field_info *) v.value<void *>();
        if (!fi || !fi->hfinfo) return;

        if (fi->hfinfo->blurb != NULL && fi->hfinfo->blurb[0] != '\0') {
            itemInfo.append(QString().fromUtf8(fi->hfinfo->blurb));
        } else {
            itemInfo.append(QString().fromUtf8(fi->hfinfo->name));
        }

        if (!itemInfo.isEmpty()) {
            itemInfo.append(" (" + QString().fromUtf8(fi->hfinfo->abbrev) + ")");

            finfo_length = fi->length + fi->appendix_length;
            if (finfo_length == 1) {
                itemInfo.append(tr(", 1 byte"));
            } else if (finfo_length > 1) {
                itemInfo.append(QString(tr(", %1 bytes")).arg(finfo_length));
            }

            emit protoItemUnselected();
            emit protoItemSelected(itemInfo);
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
        emit protoItemUnselected();
    }
}
