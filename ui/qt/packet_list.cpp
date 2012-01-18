/* packet_list.cpp
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/epan.h>
#include <epan/epan_dissect.h>

#include <epan/column_info.h>
#include <epan/column.h>
#include <epan/packet.h>

#include "packet_list.h"
#include "monospace_font.h"
#include "proto_tree.h"

#include "globals.h"
#include "qt_ui_utils.h"

#include "ui/main_statusbar.h"
#include "ui/recent.h"
#include "ui/ui_util.h"

#include <QTreeWidget>
#include <QTabWidget>
#include <QTextEdit>

static gboolean enable_color;

// If we ever add the ability to open multiple capture files we might be
// able to use something like QMap<capture_file *, PacketList *> to match
// capture files against packet lists and models.
static PacketList *cur_packet_list = NULL;

guint
new_packet_list_append(column_info *cinfo, frame_data *fdata, packet_info *pinfo)
{
    Q_UNUSED(cinfo);
    Q_UNUSED(pinfo);

    if (!cur_packet_list)
        return 0;

    /* fdata should be filled with the stuff we need
     * strings are built at display time.
     */
    guint visible_pos;

    visible_pos = cur_packet_list->packetListModel()->appendPacket(fdata);
    return visible_pos;
}

// Copied from ui/gtk/new_packet_list.c
void new_packet_list_resize_column(gint col)
{
    // xxx qtshark
//    gint col_width;
//    const gchar *long_str;

g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_resize_column %d", col);
//    long_str = packet_list_get_widest_column_string(packetlist, col);
//    if(!long_str || strcmp("",long_str)==0)
//        /* If we get an empty string leave the width unchanged */
//        return;
//    column = gtk_tree_view_get_column (GTK_TREE_VIEW(packetlist->view), col);
//    col_width = get_default_col_size (packetlist->view, long_str);
//    gtk_tree_view_column_set_fixed_width(column, col_width);
}

void
new_packet_list_select_first_row(void)
{
    cur_packet_list->setCurrentIndex(cur_packet_list->packetListModel()->index(0,0));
    cur_packet_list->setFocus();
}

void
new_packet_list_select_last_row(void)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_select_last_row");
//    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
//    GtkTreeIter iter;
//    gint children;
//    guint last_row;

//    if((children = gtk_tree_model_iter_n_children(model, NULL)) == 0)
//        return;

//    last_row = children-1;
//    if(!gtk_tree_model_iter_nth_child(model, &iter, NULL, last_row))
//        return;

//    scroll_to_and_select_iter(model, NULL, &iter);
}

/*
 * Given a frame_data structure, scroll to and select the row in the
 * packet list corresponding to that frame.  If there is no such
 * row, return FALSE, otherwise return TRUE.
 */
gboolean
new_packet_list_select_row_from_data(frame_data *fdata_needle)
{
    int row = cur_packet_list->packetListModel()->visibleIndexOf(fdata_needle);
    if (row >= 0) {
        cur_packet_list->setCurrentIndex(cur_packet_list->packetListModel()->index(row,0));
        return TRUE;
    }

    return FALSE;
}

gboolean
new_packet_list_check_end(void)
{
        gboolean at_end = FALSE;
//	GtkAdjustment *adj;

        g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_check_end");

//	adj = gtk_tree_view_get_vadjustment(GTK_TREE_VIEW(packetlist->view));
//	g_return_val_if_fail(adj != NULL, FALSE);

//#if GTK_CHECK_VERSION(2,14,0)
//	if (gtk_adjustment_get_value(adj) >= gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj)) {
//#else
//	if (adj->value >= adj->upper - adj->page_size) {
//#endif
//		at_end = TRUE;
//	}
//#ifdef HAVE_LIBPCAP
//#if GTK_CHECK_VERSION(2,14,0)
//	if (gtk_adjustment_get_value(adj) > 0 && at_end != last_at_end && at_end != auto_scroll_live) {
//#else
//	if (adj->value > 0 && at_end != last_at_end && at_end != auto_scroll_live) {
//#endif
//		menu_auto_scroll_live_changed(at_end);
//	}
//#endif
//	last_at_end = at_end;
        return at_end;
}

void
new_packet_list_clear(void)
{

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_clear");

    cur_packet_list->clear();
}

void
new_packet_list_enable_color(gboolean enable)
{
    enable_color = enable;
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_enable_color: %d", enable);

    //	gtk_widget_queue_draw (packetlist->view);
}

void
new_packet_list_freeze(void)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_freeze");
//	/* So we don't lose the model by the time we want to thaw it */
//	g_object_ref(packetlist);

//	/* Detach view from model */
//	gtk_tree_view_set_model(GTK_TREE_VIEW(packetlist->view), NULL);
}

void
new_packet_list_thaw(void)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_thaw");
//	/* Apply model */
//	gtk_tree_view_set_model( GTK_TREE_VIEW(packetlist->view), GTK_TREE_MODEL(packetlist));

//	/* Remove extra reference added by new_packet_list_freeze() */
//	g_object_unref(packetlist);

        packets_bar_update();
}

void
new_packet_list_recreate_visible_rows(void)
{
    cur_packet_list->packetListModel()->recreateVisibleRows();
}

frame_data *
new_packet_list_get_row_data(gint row)
{
    if (!cur_packet_list)
        return NULL;
    return cur_packet_list->packetListModel()->getRowFdata(row);
}

void
new_packet_list_moveto_end(void)
{
//    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
//    GtkTreeIter iter;
//    GtkTreePath *path;
//    gint children;
//    guint last_row;

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_moveto_end");

//    if((children = gtk_tree_model_iter_n_children(model, NULL)) == 0)
//        return;

//    last_row = children-1;
//    if(!gtk_tree_model_iter_nth_child(model, &iter, NULL, last_row))
//        return;

//    path = gtk_tree_model_get_path(model, &iter);

//    gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(packetlist->view),
//                                 path,
//                                 NULL,
//                                 TRUE,	/* use_align */
//                                 0.5,	/* row_align determines where the row is placed, 0.5 means center */
//                                 0); 	/* The horizontal alignment of the column */

//    gtk_tree_path_free(path);

}

/* Redraw the packet list *and* currently-selected detail */
void
new_packet_list_queue_draw(void)
{
//    GtkTreeSelection *selection;
//    GtkTreeIter iter;
//    gint row;

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: new_packet_list_queue_draw");
//    gtk_widget_queue_draw (packetlist->view);

//    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
//    if (!gtk_tree_selection_get_selected(selection, NULL, &iter))
//        return;
//    row = row_number_from_iter(&iter);
//    cf_select_packet(&cfile, row);
    cf_select_packet(&cfile, 1);
}

#define MIN_COL_WIDTH_STR "...."

PacketList::PacketList(QWidget *parent) :
    QTreeView(parent)
{
    setItemsExpandable(FALSE);
    setRootIsDecorated(FALSE);
    setSortingEnabled(TRUE);
    setUniformRowHeights(TRUE);
    setAccessibleName("Packet list");

    m_packet_list_model = new PacketListModel(this, &cfile);
    setModel(m_packet_list_model);

    g_assert(cur_packet_list == NULL);
    cur_packet_list = this;

    m_protoTree = NULL;
    m_byteViewTab = NULL;
}

void PacketList::setProtoTree (ProtoTree *protoTree) {
    m_protoTree = protoTree;
}

void PacketList::setByteViewTab (ByteViewTab *byteViewTab) {
    m_byteViewTab = byteViewTab;
}

PacketListModel *PacketList::packetListModel() const {
    return m_packet_list_model;
}

void PacketList::showEvent (QShowEvent *event) {
    Q_UNUSED(event);
//    g_log(NULL, G_LOG_LEVEL_DEBUG, "cols: %d", cfile.cinfo.num_cols);
    for (int i = 0; i < cfile.cinfo.num_cols; i++) {
        int fmt, col_width;
        const char *long_str;

        fmt = get_column_format(i);
        long_str = get_column_width_string(fmt, i);
        if (long_str) {
            col_width = get_monospace_text_size(long_str, TRUE);
        } else {
            col_width = get_monospace_text_size(MIN_COL_WIDTH_STR, TRUE);
        }
        setColumnWidth(i, col_width);
    }
}

void PacketList::selectionChanged (const QItemSelection & selected, const QItemSelection & deselected) {
    QTreeView::selectionChanged(selected, deselected);

    if (m_protoTree) {
        int row = selected.first().top();
        cf_select_packet(&cfile, row);

        if (!cfile.edt && !cfile.edt->tree) {
            return;
        }

        m_protoTree->fillProtocolTree(cfile.edt->tree);
    }

    if (m_byteViewTab && cfile.edt) {
        GSList *src_le;
        data_source *source;

        // Clear out existing tabs
        while (m_byteViewTab->currentWidget()) {
            delete m_byteViewTab->currentWidget();
        }

        for (src_le = cfile.edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
            source = (data_source *)src_le->data;
            m_byteViewTab->addTab(get_data_source_name(source), source->tvb, cfile.edt->tree, m_protoTree, cfile.current_frame->flags.encoding);
        }
    }

    if (m_protoTree && m_byteViewTab) {
        // Connect signals between the proto tree and byte views.
        connect(m_protoTree, SIGNAL(currentItemChanged(QTreeWidgetItem*,QTreeWidgetItem*)),
                m_byteViewTab, SLOT(protoTreeItemChanged(QTreeWidgetItem*)));
    }
}

void PacketList::clear() {
    //    packet_history_clear();
    packetListModel()->clear();
    m_protoTree->clear();

    // Clear out existing tabs
    while (m_byteViewTab->currentWidget()) {
        delete m_byteViewTab->currentWidget();
    }

//	/* XXX is this correct in all cases?
//	 * Reset the sort column, use packetlist as model in case the list is frozen.
//	 */
    cur_packet_list->sortByColumn(0, Qt::AscendingOrder);
}

extern "C" void new_packet_list_recent_write_all(FILE *rf) {
    if (!cur_packet_list)
        return;

    cur_packet_list->writeRecent(rf);
}

void PacketList::writeRecent(FILE *rf) {
    gint col, width, col_fmt;
    gchar xalign;

    fprintf (rf, "%s:", RECENT_KEY_COL_WIDTH);
    for (col = 0; col < packetListModel()->columnCount(); col++) {
        if (col > 0) {
            fprintf (rf, ",");
        }
        col_fmt = get_column_format(col);
        if (col_fmt == COL_CUSTOM) {
            fprintf (rf, " %%Cus:%s,", get_column_custom_field(col));
        } else {
            fprintf (rf, " %s,", col_format_to_string(col_fmt));
        }
        width = columnWidth(col);
        xalign = recent_get_column_xalign (col);
        if (width == 0) {
            /* We have not initialized the packet list yet, use old values */
            width = recent_get_column_width (col);
        }
        fprintf (rf, " %d", width);
        if (xalign != COLUMN_XALIGN_DEFAULT) {
            fprintf (rf, ":%c", xalign);
        }
    }
    fprintf (rf, "\n");

}
