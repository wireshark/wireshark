/* proto_draw.c
 * Routines for GTK+ packet display
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Jeff Foster,    2001/03/12,  added support for displaying named
 *                              data sources as tabbed hex windows
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

#include <ctype.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <string.h>

#include <epan/epan_dissect.h>

#include <epan/packet.h>
#include <epan/charsets.h>
#include <epan/prefs.h>
#include <epan/filesystem.h>

#include "../isprint.h"
#include "../alert_box.h"
#include "../simple_dialog.h"
#include "../progress_dlg.h"
#include "../ui_util.h"
#include <wsutil/file_util.h>

#include "gtk/keys.h"
#include "gtk/color_utils.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/packet_win.h"
#include "gtk/file_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/gtkglobals.h"
#include "gtk/font_utils.h"
#include "gtk/webbrowser.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/main_proto_draw.h"
#include "gtk/recent.h"

#ifdef _WIN32
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "win32/file_dlg_win32.h"
#endif


#define E_BYTE_VIEW_TREE_PTR      "byte_view_tree_ptr"
#define E_BYTE_VIEW_TREE_VIEW_PTR "byte_view_tree_view_ptr"
#define E_BYTE_VIEW_NDIGITS_KEY   "byte_view_ndigits"
#define E_BYTE_VIEW_TVBUFF_KEY    "byte_view_tvbuff"
#define E_BYTE_VIEW_START_KEY     "byte_view_start"
#define E_BYTE_VIEW_END_KEY       "byte_view_end"
#define E_BYTE_VIEW_MASK_KEY      "byte_view_mask"
#define E_BYTE_VIEW_MASKLE_KEY    "byte_view_mask_le"
#define E_BYTE_VIEW_APP_START_KEY "byte_view_app_start"
#define E_BYTE_VIEW_APP_END_KEY   "byte_view_app_end"
#define E_BYTE_VIEW_ENCODE_KEY    "byte_view_encode"

static GtkWidget *
add_byte_tab(GtkWidget *byte_nb, const char *name, tvbuff_t *tvb,
             proto_tree *tree, GtkWidget *tree_view);

static void
proto_tree_draw_node(proto_node *node, gpointer data);

/* Get the current text window for the notebook. */
GtkWidget *
get_notebook_bv_ptr(GtkWidget *nb_ptr)
{
    int num;
    GtkWidget *bv_page;

    num = gtk_notebook_get_current_page(GTK_NOTEBOOK(nb_ptr));
    bv_page = gtk_notebook_get_nth_page(GTK_NOTEBOOK(nb_ptr), num);
    if (bv_page)
        return gtk_bin_get_child(GTK_BIN(bv_page));
    else
        return NULL;
}

/*
 * Get the data and length for a byte view, given the byte view page.
 * Return the pointer, or NULL on error, and set "*data_len" to the length.
 */
const guint8 *
get_byte_view_data_and_length(GtkWidget *byte_view, guint *data_len)
{
    tvbuff_t *byte_view_tvb;
    const guint8 *data_ptr;

    byte_view_tvb = g_object_get_data(G_OBJECT(byte_view), E_BYTE_VIEW_TVBUFF_KEY);
    if (byte_view_tvb == NULL)
        return NULL;

    data_ptr = tvb_get_ptr(byte_view_tvb, 0, -1);
    *data_len = tvb_length(byte_view_tvb);
    return data_ptr;
}

/*
 * Set the current text window for the notebook to the window that
 * refers to a particular tvbuff.
 */
void
set_notebook_page(GtkWidget *nb_ptr, tvbuff_t *tvb)
{
    int num;
    GtkWidget *bv_page, *bv;
    tvbuff_t *bv_tvb;

    for (num = 0;
         (bv_page = gtk_notebook_get_nth_page(GTK_NOTEBOOK(nb_ptr), num)) != NULL;
         num++) {
        bv = gtk_bin_get_child(GTK_BIN(bv_page));
        bv_tvb = g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_TVBUFF_KEY);
        if (bv_tvb == tvb) {
            /* Found it. */
            gtk_notebook_set_current_page(GTK_NOTEBOOK(nb_ptr), num);
            break;
        }
    }
}

/* Redraw a given byte view window. */
void
redraw_packet_bytes(GtkWidget *nb, frame_data *fd, field_info *finfo)
{
    GtkWidget *bv;
    const guint8 *data;
    guint len;

    bv = get_notebook_bv_ptr(nb);
    if (bv != NULL) {
        data = get_byte_view_data_and_length(bv, &len);
        if (data != NULL)
            packet_hex_print(bv, data, fd, finfo, len);
    }
}

/* Redraw all byte view windows. */
void
redraw_packet_bytes_all(void)
{
    if (cfile.current_frame != NULL)
        redraw_packet_bytes( byte_nb_ptr_gbl, cfile.current_frame, cfile.finfo_selected);

    redraw_packet_bytes_packet_wins();

    /* XXX - this is a hack, to workaround a bug in GTK2.x!
       when changing the font size, even refilling of the corresponding
       gtk_text_buffer doesn't seem to trigger an update.
       The only workaround is to freshly select the frame, which will remove any
       existing notebook tabs and "restart" the whole byte view again. */
    if (cfile.current_frame != NULL) {
        cfile.current_row = -1;
        cf_goto_frame(&cfile, cfile.current_frame->num);
    }
}

static void
expand_tree(GtkTreeView *tree_view, GtkTreeIter *iter,
            GtkTreePath *path _U_, gpointer user_data _U_)
{
    field_info   *finfo;
    GtkTreeModel *model;

    model = gtk_tree_view_get_model(tree_view);
    gtk_tree_model_get(model, iter, 1, &finfo, -1);
    g_assert(finfo);

	/* scroll the expanded item to reduce the need to do a manual scroll down
	 * and provide faster navigation of deeper trees */

	if(prefs.gui_auto_scroll_on_expand) 
		gtk_tree_view_scroll_to_cell(tree_view, path, NULL, TRUE, (prefs.gui_auto_scroll_percentage/100.0f), 0.0f);

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be expanded.
     */
    if (finfo->tree_type != -1) {
        g_assert(finfo->tree_type >= 0 &&
                 finfo->tree_type < num_tree_types);
        tree_is_expanded[finfo->tree_type] = TRUE;
    }
}

static void
collapse_tree(GtkTreeView *tree_view, GtkTreeIter *iter,
              GtkTreePath *path _U_, gpointer user_data _U_)
{
    field_info   *finfo;
    GtkTreeModel *model;

    model = gtk_tree_view_get_model(tree_view);
    gtk_tree_model_get(model, iter, 1, &finfo, -1);
    g_assert(finfo);

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be collapsed.
     */
    if (finfo->tree_type != -1) {
        g_assert(finfo->tree_type >= 0 &&
                 finfo->tree_type < num_tree_types);
        tree_is_expanded[finfo->tree_type] = FALSE;
    }
}

#define MAX_OFFSET_LEN   8      /* max length of hex offset of bytes */
#define BYTES_PER_LINE  16      /* max byte values in a line */
#define BITS_PER_LINE    8      /* max bit values in a line */
#define BYTE_VIEW_SEP    8      /* insert a space every BYTE_VIEW_SEP bytes */
#define HEX_DUMP_LEN    (BYTES_PER_LINE*3 + 1)
/* max number of characters hex dump takes -
   2 digits plus trailing blank
   plus separator between first and
   second 8 digits */
#define DATA_DUMP_LEN   (HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
/* number of characters those bytes take;
   3 characters per byte of hex dump,
   2 blanks separating hex from ASCII,
   1 character per byte of ASCII dump */
#define MAX_LINE_LEN    (MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
/* number of characters per line;
   offset, 2 blanks separating offset
   from data dump, data dump */
#define MAX_LINES       100
#define MAX_LINES_LEN   (MAX_LINES*MAX_LINE_LEN)

/* Which byte the offset is referring to. Associates
 * whitespace with the preceding digits. */
static int
byte_num(int offset, int start_point)
{
    return (offset - start_point) / 3;
}
static int
bit_num(int offset, int start_point)
{
    return (offset - start_point) / 9;
}

struct field_lookup_info {
    field_info  *fi;
    GtkTreeIter  iter;
};

static gboolean
lookup_finfo(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
             gpointer data)
{
    field_info *fi;
    struct field_lookup_info *fli = (struct field_lookup_info *)data;

    gtk_tree_model_get(model, iter, 1, &fi, -1);
    if (fi == fli->fi) {
        fli->iter = *iter;
        return TRUE;
    }
    return FALSE;
}

GtkTreePath
*tree_find_by_field_info(GtkTreeView *tree_view, field_info *finfo)
{
    GtkTreeModel *model;
    struct field_lookup_info fli;

    g_assert(finfo != NULL);

    model = gtk_tree_view_get_model(tree_view);
    fli.fi = finfo;
    gtk_tree_model_foreach(model, lookup_finfo, &fli);

    return gtk_tree_model_get_path(model, &fli.iter);
}

static int
hex_view_get_byte(guint ndigits, int row, int column)
{
    int           byte;
    int           digits_start_1;
    int           digits_end_1;
    int           digits_start_2;
    int           digits_end_2;
    int           text_start_1;
    int           text_end_1;
    int           text_start_2;
    int           text_end_2;

    /*
     * The column of the first hex digit in the first half.
     * That starts after "ndigits" digits of offset and two
     * separating blanks.
     */
    digits_start_1 = ndigits + 2;

    /*
     * The column of the last hex digit in the first half.
     * There are BYTES_PER_LINE/2 bytes displayed in the first
     * half; there are 2 characters per byte, plus a separating
     * blank after all but the last byte's characters.
     */
    digits_end_1 = digits_start_1 + (BYTES_PER_LINE/2)*2 +
        (BYTES_PER_LINE/2 - 1);

    /*
     * The column of the first hex digit in the second half.
     * Add 2 for the 2 separating blanks between the halves.
     */
    digits_start_2 = digits_end_1 + 2;

    /*
     * The column of the last hex digit in the second half.
     * Add the same value we used to get "digits_end_1" from
     * "digits_start_1".
     */
    digits_end_2 = digits_start_2 + (BYTES_PER_LINE/2)*2 +
        (BYTES_PER_LINE/2 - 1);

    /*
     * The column of the first "text dump" character in the first half.
     * Add 3 for the 3 separating blanks between the hex and text dump.
     */
    text_start_1 = digits_end_2 + 3;

    /*
     * The column of the last "text dump" character in the first half.
     * There are BYTES_PER_LINE/2 bytes displayed in the first
     * half; there is 1 character per byte.
     *
     * Then subtract 1 to get the last column of the first half
     * rather than the first column after the first half.
     */
    text_end_1 = text_start_1 + BYTES_PER_LINE/2 - 1;

    /*
     * The column of the first "text dump" character in the second half.
     * Add back the 1 to get the first column after the first half,
     * and then add 1 for the separating blank between the halves.
     */
    text_start_2 = text_end_1 + 2;

    /*
     * The column of the last "text dump" character in second half.
     * Add the same value we used to get "text_end_1" from
     * "text_start_1".
     */
    text_end_2 = text_start_2 + BYTES_PER_LINE/2 - 1;

    /* Given the column and row, determine which byte offset
     * the user clicked on. */
    if (column >= digits_start_1 && column <= digits_end_1) {
        byte = byte_num(column, digits_start_1);
        if (byte == -1) {
            return byte;
        }
    }
    else if (column >= digits_start_2 && column <= digits_end_2) {
        byte = byte_num(column, digits_start_2);
        if (byte == -1) {
            return byte;
        }
        byte += 8;
    }
    else if (column >= text_start_1 && column <= text_end_1) {
        byte = column - text_start_1;
    }
    else if (column >= text_start_2 && column <= text_end_2) {
        byte = 8 + column - text_start_2;
    }
    else {
        /* The user didn't select a hex digit or
         * text-dump character. */
        return -1;
    }

    /* Add the number of bytes from the previous rows. */
    byte += row * BYTES_PER_LINE;

    return byte;
}

static int
bit_view_get_byte(guint ndigits, int row, int column)
{
    int           byte;
    int           digits_start;
    int           digits_end;
    int           text_start;
    int           text_end;

    /*
     * The column of the first bit digit.
     * That starts after "ndigits" digits of offset and two
     * separating blanks.
     */
    digits_start = ndigits + 2;

    /*
     * The column of the last bit digit.
     * There are BITS_PER_LINE bytes displayed; there are
     * 8 characters per byte, plus a separating blank
     * after all but the last byte's characters.
     */
    digits_end = digits_start + (BITS_PER_LINE)*8 +
        (BITS_PER_LINE - 1);

    /*
     * The column of the first "text dump" character.
     * Add 3 for the 3 separating blanks between the bit and text dump.
     */
    text_start = digits_end + 3;

    /*
     * The column of the last "text dump" character.
     * There are BITS_PER_LINE bytes displayed; there is 1 character per byte.
     *
     * Then subtract 1 to get the last column.
     */
    text_end = text_start + BITS_PER_LINE - 1;

    /* Given the column and row, determine which byte offset
     * the user clicked on. */
    if (column >= digits_start && column <= digits_end) {
        byte = bit_num(column, digits_start);
        if (byte == -1) {
            return byte;
        }
    }
    else if (column >= text_start && column <= text_end) {
        byte = column - text_start;
    }
    else {
        /* The user didn't select a hex digit or
         * text-dump character. */
        return -1;
    }

    /* Add the number of bytes from the previous rows. */
    byte += row * BITS_PER_LINE;

    return byte;
}

/* If the user selected a certain byte in the byte view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and:
 *
 *    if we succeed, select it, and return TRUE;
 *    if we fail, return FALSE. */
gboolean
byte_view_select(GtkWidget *widget, GdkEventButton *event)
{
    GtkTextView  *bv = GTK_TEXT_VIEW(widget);
    proto_tree   *tree;
    GtkTreeView  *tree_view;
    GtkTextIter   iter;
    int           row, column;
    guint         ndigits;
    gint          x, y;
    int           byte = -1;
    tvbuff_t     *tvb;

    tree = g_object_get_data(G_OBJECT(widget), E_BYTE_VIEW_TREE_PTR);
    if (tree == NULL) {
        /*
         * Somebody clicked on the dummy byte view; do nothing.
         */
        return FALSE;
    }
    tree_view = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(widget),
                                              E_BYTE_VIEW_TREE_VIEW_PTR));

    /* get the row/column selected */
    gtk_text_view_window_to_buffer_coords(bv,
                         gtk_text_view_get_window_type(bv, event->window),
                         (gint) event->x, (gint) event->y, &x, &y);
    gtk_text_view_get_iter_at_location(bv, &iter, x, y);
    row = gtk_text_iter_get_line(&iter);
    column = gtk_text_iter_get_line_offset(&iter);

    /*
     * Get the number of digits of offset being displayed, and
     * compute the byte position in the buffer.
     */
    ndigits = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_NDIGITS_KEY));

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        byte = hex_view_get_byte(ndigits, row, column);
        break;
    case BYTES_BITS:
        byte = bit_view_get_byte(ndigits, row, column);
        break;
    default:
        g_assert_not_reached();
    }

    if (byte == -1) {
        return FALSE;
    }

    /* Get the data source tvbuff */
    tvb = g_object_get_data(G_OBJECT(widget), E_BYTE_VIEW_TVBUFF_KEY);

    return highlight_field(tvb, byte, tree_view, tree);
}

/* This highlights the field in the proto tree that is at position byte */
gboolean
highlight_field(tvbuff_t *tvb, gint byte, GtkTreeView *tree_view,
                proto_tree *tree)
{
    GtkTreeModel *model = NULL;
    GtkTreePath  *first_path = NULL, *path = NULL;
    GtkTreeIter   parent;
    field_info   *finfo = NULL;
    match_data    mdata;
    struct field_lookup_info fli;

    if (cfile.search_in_progress && cfile.string && cfile.decode_data) {
        /* The tree where the target string matched one of the labels was discarded in
           match_protocol_tree() so we have to search again in the latest tree. (Uugh) */
        if (cf_find_string_protocol_tree(&cfile, tree, &mdata)) {
            finfo = mdata.finfo;
        }
    } else {
        /* Find the finfo that corresponds to our byte. */
        finfo = proto_find_field_from_offset(tree, byte, tvb);
    }

    if (!finfo) {
        return FALSE;
    }

    model = gtk_tree_view_get_model(tree_view);
    fli.fi = finfo;
    gtk_tree_model_foreach(model, lookup_finfo, &fli);

    /* Expand our field's row */
    first_path = gtk_tree_model_get_path(model, &fli.iter);
    gtk_tree_view_expand_row(tree_view, first_path, FALSE);
    expand_tree(tree_view, &fli.iter, NULL, NULL);

    /* ... and its parents */
    while (gtk_tree_model_iter_parent(model, &parent, &fli.iter)) {
        path = gtk_tree_model_get_path(model, &parent);
        gtk_tree_view_expand_row(tree_view, path, FALSE);
        expand_tree(tree_view, &parent, NULL, NULL);
        fli.iter = parent;
        gtk_tree_path_free(path);
    }

    /* Refresh the display so that the expanded trees are visible */
    main_proto_tree_draw(tree);

    /* select our field's row */
    gtk_tree_selection_select_path(gtk_tree_view_get_selection(tree_view),
                                   first_path);

	/* If the last search was a string or hex search within "Packet data", the entire field might
       not be highlighted. If the user just clicked on one of the bytes comprising that field, the
       above call didn't trigger a 'gtk_tree_view_get_selection' event. Call redraw_packet_bytes()
       to make the highlighting of the entire field visible. */
    if (!cfile.search_in_progress) {
        if (cfile.hex || (cfile.string && cfile.packet_data)) {
            redraw_packet_bytes(byte_nb_ptr_gbl, cfile.current_frame, cfile.finfo_selected);
        }
    }

    /* And position the window so the selection is visible.
     * Position the selection in the middle of the viewable
     * pane. */
    gtk_tree_view_scroll_to_cell(tree_view, first_path, NULL, TRUE, 0.5f, 0.0f);

    gtk_tree_path_free(first_path);

    return TRUE;
}

/* Calls functions for different mouse-button presses. */
static gboolean
byte_view_button_press_cb(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    GdkEventButton *event_button = NULL;

    if(widget == NULL || event == NULL || data == NULL) {
        return FALSE;
    }

    if(event->type == GDK_BUTTON_PRESS) {
        event_button = (GdkEventButton *) event;

        /* To qoute the "Gdk Event Structures" doc:
         * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
        switch(event_button->button) {

        case 1:
            return byte_view_select(widget, event_button);
        case 3:
            return popup_menu_handler(widget, event, data);
        default:
            return FALSE;
        }
    }

    return FALSE;
}

GtkWidget *
byte_view_new(void)
{
    GtkWidget *byte_nb;

    byte_nb = gtk_notebook_new();
    gtk_notebook_set_tab_pos(GTK_NOTEBOOK(byte_nb), GTK_POS_BOTTOM);

    /* this will only have an effect, if no tabs are shown */
    gtk_notebook_set_show_border(GTK_NOTEBOOK(byte_nb), FALSE);

    /* set the tabs scrollable, if they don't fit into the pane */
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(byte_nb), TRUE);

    /* enable a popup menu containing the tab labels, will be helpful if tabs don't fit into the pane */
    gtk_notebook_popup_enable(GTK_NOTEBOOK(byte_nb));

    /* Add a placeholder byte view so that there's at least something
       displayed in the byte view notebook. */
    add_byte_tab(byte_nb, "", NULL, NULL, NULL);

    return byte_nb;
}

static void
byte_view_realize_cb(GtkWidget *bv, gpointer data _U_)
{
    const guint8 *byte_data;
    guint byte_len;

    byte_data = get_byte_view_data_and_length(bv, &byte_len);
    if (byte_data == NULL) {
        /* This must be the dummy byte view if no packet is selected. */
        return;
    }
    packet_hex_print(bv, byte_data, cfile.current_frame, NULL, byte_len);
}

static GtkWidget *
add_byte_tab(GtkWidget *byte_nb, const char *name, tvbuff_t *tvb,
             proto_tree *tree, GtkWidget *tree_view)
{
    GtkWidget *byte_view, *byte_scrollw, *label;
    GtkTextBuffer *buf;
    GtkStyle      *style;

    /* Byte view.  Create a scrolled window for the text. */
    byte_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(byte_scrollw),
                                        GTK_SHADOW_IN);
    /* Add scrolled pane to tabbed window */
    label = gtk_label_new(name);
    gtk_notebook_append_page(GTK_NOTEBOOK(byte_nb), byte_scrollw, label);

    gtk_widget_show(byte_scrollw);

    byte_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(byte_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(byte_view), FALSE);
    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(byte_view));

    style = gtk_widget_get_style(GTK_WIDGET(top_level));
    gtk_text_buffer_create_tag(buf, "plain", "font-desc", user_font_get_regular(), NULL);
    gtk_text_buffer_create_tag(buf, "reverse",
                               "font-desc", user_font_get_regular(),
                               "foreground-gdk", &style->text[GTK_STATE_SELECTED],
                               "background-gdk", &style->base[GTK_STATE_SELECTED],
                               NULL);

    gtk_text_buffer_create_tag(buf, "bold", "font-desc", user_font_get_bold(), NULL);
    g_object_set_data(G_OBJECT(byte_view), E_BYTE_VIEW_TVBUFF_KEY, tvb);
    gtk_container_add(GTK_CONTAINER(byte_scrollw), byte_view);

    g_signal_connect(byte_view, "show", G_CALLBACK(byte_view_realize_cb), NULL);
    g_signal_connect(byte_view, "button_press_event", G_CALLBACK(byte_view_button_press_cb),
                     g_object_get_data(G_OBJECT(popup_menu_object), PM_BYTES_VIEW_KEY));

    g_object_set_data(G_OBJECT(byte_view), E_BYTE_VIEW_TREE_PTR, tree);
    g_object_set_data(G_OBJECT(byte_view), E_BYTE_VIEW_TREE_VIEW_PTR, tree_view);

    gtk_widget_show(byte_view); /* triggers byte_view_realize_cb which calls packet_hex_print */

    /* no tabs if this is the first page */
    if (!(gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_scrollw)))
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), FALSE);
    else
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), TRUE);

    /* set this page */
    gtk_notebook_set_current_page(GTK_NOTEBOOK(byte_nb),
                                  gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_nb));

    return byte_view;
}

void
add_main_byte_views(epan_dissect_t *edt)
{
    add_byte_views(edt, tree_view_gbl, byte_nb_ptr_gbl);
}

void
add_byte_views(epan_dissect_t *edt, GtkWidget *tree_view,
               GtkWidget *byte_nb_ptr)
{
    GSList *src_le;
    data_source *src;

    /*
     * Get rid of all the old notebook tabs.
     */
    while (gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr), 0) != NULL)
        gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr), 0);

    /*
     * Add to the specified byte view notebook tabs for hex dumps
     * of all the data sources for the specified frame.
     */
    for (src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
        src = src_le->data;
        add_byte_tab(byte_nb_ptr, get_data_source_name(src), src->tvb, edt->tree,
                     tree_view);
    }

    /*
     * Initially select the first byte view.
     */
    gtk_notebook_set_current_page(GTK_NOTEBOOK(byte_nb_ptr), 0);
}



static GtkWidget *savehex_dlg=NULL;

static void
savehex_dlg_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
    savehex_dlg = NULL;
}


static void
copy_hex_all_info(GString* copy_buffer, const guint8* data_p, int data_len, gboolean append_text)
{
    const int byte_line_length = 16; /* Print out data for 16 bytes on one line */
    int i, j;
    gboolean end_of_line = TRUE; /* Initial state is end of line */
    int byte_line_part_length;

    GString* hex_str;
    GString* char_str;

    /* Write hex data for a line, then ascii data, then concatenate and add to buffer */
    hex_str = g_string_new("");
    char_str= g_string_new("");

    i = 0;
    while (i<data_len) {
        if(end_of_line) {
            g_string_append_printf(hex_str,"%04x  ",i); /* Offset - note that we _append_ here */
        }

        g_string_append_printf(hex_str," %02x",*data_p);
        if(append_text) {
            g_string_append_printf(char_str,"%c",isprint(*data_p) ? *data_p : '.');
        }

        ++data_p;

        /* Look ahead to see if this is the end of the data */
        byte_line_part_length = (++i) % byte_line_length;
        if(i == data_len){
            /* End of data - need to fill in spaces in hex string and then do "end of line".
             *
             */
            for(j = 0; append_text && (j < (byte_line_length - byte_line_part_length)); ++j) {
                g_string_append(hex_str,"   "); /* Three spaces for each missing byte */
            }
            end_of_line = TRUE;
        } else {
            end_of_line = (byte_line_part_length == 0 ? TRUE : FALSE);
        }


        if (end_of_line){
            /* End of line */
            g_string_append(copy_buffer, hex_str->str);
            if(append_text) {
                /* Two spaces between hex and text */
                g_string_append_c(copy_buffer, ' ');
                g_string_append_c(copy_buffer, ' ');
                g_string_append(copy_buffer, char_str->str);
            }
            /* Setup ready for next line */
            g_string_assign(char_str,"");
            g_string_assign(hex_str, "\n");
        }
    }

    g_string_free(hex_str, TRUE);
    g_string_free(char_str, TRUE);
}

static int
copy_hex_bytes_text_only(GString* copy_buffer, const guint8* data_p, int data_len _U_)
{

    gchar to_append;

    /* Copy printable characters, newlines, and (horizontal) tabs. */
    if(isprint(*data_p)) {
        to_append = *data_p;
    } else if(*data_p==0x0a) {
        to_append = '\n';
    } else if(*data_p==0x09) {
        to_append = '\t';
    } else {
        return 1; /* Just ignore non-printable bytes */
    }
    g_string_append_c(copy_buffer,to_append);
    return 1;
}

static
int copy_hex_bytes_hex(GString* copy_buffer, const guint8* data_p, int data_len _U_)
{
    g_string_append_printf(copy_buffer, "%02x", *data_p);
    return 1;
}

void
copy_hex_cb(GtkWidget * w _U_, gpointer data _U_, copy_data_type data_type)
{
    GtkWidget *bv;

    guint len = 0;
    int bytes_consumed = 0;
    int flags;

    const guint8* data_p;

    GString* copy_buffer = g_string_new(""); /* String to copy to clipboard */

    bv = get_notebook_bv_ptr(byte_nb_ptr_gbl);
    if (bv == NULL) {
        /* shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
        return;
    }

    data_p = get_byte_view_data_and_length(bv, &len);
    g_assert(data_p != NULL);

    flags = data_type & CD_FLAGSMASK;
    data_type = data_type & CD_TYPEMASK;

    if(flags & CD_FLAGS_SELECTEDONLY) {
        int start, end;

        /* Get the start and end of the highlighted bytes. */
        start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
        end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));

        if(start >= 0 && end > start && (end - start <= (int)len)) {
            len = end - start;
            data_p += start;
        }
    }

    switch(data_type) {
    case(CD_ALLINFO):
        /* This is too different from other text formats - handle separately */
        copy_hex_all_info(copy_buffer, data_p, len, TRUE);
        break;
    case(CD_HEXCOLUMNS):
        /* This could be done incrementally, but it is easier to mingle with the code for CD_ALLINFO */
        copy_hex_all_info(copy_buffer, data_p, len, FALSE);
        break;
    case(CD_BINARY):
        /* Completely different logic to text copies - leave copy buffer alone */
        copy_binary_to_clipboard(data_p,len);
        break;
    default:
        /* Incrementally write to text buffer in various formats */
        while (len > 0){
            switch(data_type) {
            case (CD_TEXTONLY):
                bytes_consumed = copy_hex_bytes_text_only(copy_buffer, data_p, len);
                break;
            case (CD_HEX):
                bytes_consumed = copy_hex_bytes_hex(copy_buffer, data_p, len);
                break;
            default:
                g_assert_not_reached();
                break;
            }

            g_assert(bytes_consumed>0);
            data_p += bytes_consumed;
            len -= bytes_consumed;
        }
        break;
    }

    if(copy_buffer->len > 0) {
        copy_to_clipboard(copy_buffer);
    }

    g_string_free(copy_buffer, TRUE);
}

/* save the current highlighted hex data */
static gboolean
savehex_save_clicked_cb(GtkWidget * w _U_, gpointer data _U_)
{
    GtkWidget *bv;
    int fd, start, end;
    guint len;
    const guint8 *data_p = NULL;
    char *file;

    file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(savehex_dlg));

#if 0 /* Not req'd: GtkFileChooserWidget currently being used won't return with a Null filename */
    if (!file ||! *file) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Please enter a filename!");
        g_free(file);
        return TRUE;
    }
#endif
    if (test_for_directory(file) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(file);
        g_free(file);
        file_selection_set_current_folder(savehex_dlg, get_last_open_dir());
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(savehex_dlg), "");
        return FALSE; /* do gtk_dialog_run again */
    }

    /* XXX: Must check if file name exists first */

    bv = get_notebook_bv_ptr(byte_nb_ptr_gbl);
    if (bv == NULL) {
        /* shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
        g_free(file);
        return TRUE;
    }
    /*
     * Retrieve the info we need
     */
    start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
    end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));
    data_p = get_byte_view_data_and_length(bv, &len);

    if (data_p == NULL || start == -1 || start > end) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "No data selected to save!");
        g_free(file);
        return TRUE;
    }

    fd = ws_open(file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
    if (fd == -1) {
        open_failure_alert_box(file, errno, TRUE);
        g_free(file);
        return TRUE;
    }
    if (ws_write(fd, data_p + start, end - start) < 0) {
        write_failure_alert_box(file, errno);
        ws_close(fd);
        g_free(file);
        return TRUE;
    }
    if (ws_close(fd) < 0) {
        write_failure_alert_box(file, errno);
        g_free(file);
        return TRUE;
    }

    /* Get rid of the dialog box */
    g_free(file);
#if 0 /* being handled by caller  (for now) */
    window_destroy(GTK_WIDGET(savehex_dlg));
#endif
    return TRUE;
}

/* Launch the dialog box to put up the file selection box etc */
#ifdef _WIN32
void
savehex_cb(GtkWidget * w _U_, gpointer data _U_)
{
    win32_export_raw_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)));
    return;
}
#else
void
savehex_cb(GtkWidget * w _U_, gpointer data _U_)
{
    int start, end;
    guint len;
    const guint8 *data_p = NULL;
    gchar *label;
    GtkWidget   *bv;
    GtkWidget   *dlg_lb;

    /* don't show up the dialog, if no data has to be saved */
    bv = get_notebook_bv_ptr(byte_nb_ptr_gbl);
    if (bv == NULL) {
        /* shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
        return;
    }
    start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
    end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));
    data_p = get_byte_view_data_and_length(bv, &len);

    if (data_p == NULL || start == -1 || start > end) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No data selected to save!");
        return;
    }

#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
    /* if the window is already open, bring it to front */
    if(savehex_dlg){
        reactivate_window(savehex_dlg);
        return;
    }
#endif
    /*
     * Build the dialog box we need.
     */
    savehex_dlg = file_selection_new("Wireshark: Export Selected Packet Bytes", FILE_SELECTION_SAVE);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(savehex_dlg), TRUE);

    /* label */
    label = g_strdup_printf("Will save %u %s of raw binary data to specified file.",
                            end - start, plurality(end - start, "byte", "bytes"));
    dlg_lb = gtk_label_new(label);
    g_free(label);
    file_selection_set_extra_widget(savehex_dlg, dlg_lb);
    gtk_widget_show(dlg_lb);

    g_signal_connect(savehex_dlg, "destroy", G_CALLBACK(savehex_dlg_destroy_cb), NULL);

#if 0
    if (gtk_dialog_run(GTK_DIALOG(savehex_dlg)) == GTK_RESPONSE_ACCEPT) {
        savehex_save_clicked_cb(savehex_dlg, savehex_dlg);
    } else {
        window_destroy(savehex_dlg);
    }
#endif
    /* "Run" the GtkFileChooserDialog.                                              */
    /* Upon exit: If "Accept" run the OK callback.                                  */
    /*            If the OK callback returns with a FALSE status, re-run the dialog.*/
    /*            If not accept (ie: cancel) destroy the window.                    */
    /* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
    /*      return with a TRUE status so that the dialog window will be destroyed.  */
    /*      Trying to re-run the dialog after popping up an alert box will not work */
    /*       since the user will not be able to dismiss the alert box.              */
    /*      The (somewhat unfriendly) effect: the user must re-invoke the           */
    /*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
    /*                                                                              */
    /*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
    /*            GtkFileChooserDialog.                                             */
    while (gtk_dialog_run(GTK_DIALOG(savehex_dlg)) == GTK_RESPONSE_ACCEPT) {
        if (savehex_save_clicked_cb(NULL, savehex_dlg)) {
            break; /* we're done */
        }
    }
    window_destroy(savehex_dlg);
}
#endif

static GtkTextMark *
packet_hex_apply_reverse_tag(GtkTextBuffer *buf, int bstart, int bend, guint32 mask, int mask_le, int use_digits, int create_mark)
{
    GtkTextIter i_start, i_stop, iter;

    GtkTextTag    *revstyle_tag;
    const char    *revstyle;

    int per_line = 0;
    int per_one = 0;
    int bits_per_one = 0;
    int hex_offset, ascii_offset;

    int start_line, start_line_pos;
    int stop_line, stop_line_pos;

    if (bstart == -1 || bend == -1)
        return NULL;

    /* Display with inverse video ? */
    if (prefs.gui_hex_dump_highlight_style)
        revstyle = "reverse";
    else
        revstyle = "bold";

    revstyle_tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), revstyle);

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        per_line = BYTES_PER_LINE;
        per_one  = 2+1;  /* "ff " */
        bits_per_one = 4;
        break;
    case BYTES_BITS:
        per_line = BITS_PER_LINE;
        per_one  = 8+1;  /* "10101010 " */
        bits_per_one = 1;
        break;
    default:
        g_assert_not_reached();
    }

    start_line = bstart / per_line;
    start_line_pos = bstart % per_line;

    stop_line = bend / per_line;
    stop_line_pos = bend % per_line;

#define hex_fix(pos)   hex_offset + (pos * per_one) + (pos / BYTE_VIEW_SEP) - (pos == per_line)
#define ascii_fix(pos) ascii_offset + pos + (pos / BYTE_VIEW_SEP) - (pos == per_line)

    hex_offset = use_digits + 2;
    ascii_offset = hex_fix(per_line) + 2;

    gtk_text_buffer_get_iter_at_line_index(buf, &iter, start_line, hex_fix(start_line_pos));

    if (mask == 0x00) {
        while (start_line <= stop_line) {
            int line_pos_end = (start_line == stop_line) ? stop_line_pos : per_line;
            int first_block_adjust = (recent.gui_bytes_view == BYTES_HEX) ? (line_pos_end == per_line/2) : 0;

            if (start_line_pos == line_pos_end) break;

            /* bits/hex */
            gtk_text_buffer_get_iter_at_line_index(buf, &i_start, start_line, hex_fix(start_line_pos));
            gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, start_line, hex_fix(line_pos_end)-1-first_block_adjust);
            gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);

            /* ascii */
            gtk_text_buffer_get_iter_at_line_index(buf, &i_start, start_line, ascii_fix(start_line_pos));
            gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, start_line, ascii_fix(line_pos_end)-first_block_adjust);
            gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);

            start_line_pos = 0;
            start_line++;
        }

    } else if (mask_le) { /* LSB of mask first (little-endian) */
        while (start_line <= stop_line) {
            int line_pos_end = (start_line == stop_line) ? stop_line_pos : per_line;
            int line_pos = start_line_pos;

            while (line_pos < line_pos_end) {
                int lop = 8 / bits_per_one;
                int mask_per_one = (1 << bits_per_one) - 1;
                int ascii_on = 0;

                while (lop--) {
                    if ((mask & mask_per_one)) {
                        /* bits/hex */
                        gtk_text_buffer_get_iter_at_line_index(buf, &i_start, start_line, hex_fix(line_pos)+lop);
                        gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, start_line, hex_fix(line_pos)+lop+1);
                        gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);

                        ascii_on = 1;
                    }
                    mask >>= bits_per_one;
                }

                /* at least one bit of ascii was one -> turn ascii on */
                if (ascii_on) {
                    /* ascii */
                    gtk_text_buffer_get_iter_at_line_index(buf, &i_start, start_line, ascii_fix(line_pos));
                    gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, start_line, ascii_fix(line_pos)+1);
                    gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);
                }

                if (!mask)
                    goto xend;

                line_pos++;
            }

            start_line_pos = 0;
            start_line++;
        }
    } else { /* mask starting from end (big-endian) */
        while (start_line <= stop_line) {
            int line_pos_start = (start_line == stop_line) ? start_line_pos : 0;
            int line_pos = stop_line_pos-1;

            while (line_pos >= line_pos_start) {
                int lop = 8 / bits_per_one;
                int mask_per_one = (1 << bits_per_one) - 1;
                int ascii_on = 0;

                while (lop--) {
                    if ((mask & mask_per_one)) {
                        /* bits/hex */
                        gtk_text_buffer_get_iter_at_line_index(buf, &i_start, stop_line, hex_fix(line_pos)+lop);
                        gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, stop_line, hex_fix(line_pos)+lop+1);
                        gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);

                        ascii_on = 1;
                    }
                    mask >>= bits_per_one;
                }

                /* at least one bit of ascii was one -> turn ascii on */
                if (ascii_on) {
                    /* ascii */
                    gtk_text_buffer_get_iter_at_line_index(buf, &i_start, stop_line, ascii_fix(line_pos));
                    gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, stop_line, ascii_fix(line_pos)+1);
                    gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);
                }

                if (!mask)
                    goto xend;

                line_pos--;
            }

            stop_line_pos = per_line;
            stop_line--;
        }
    }
xend:
    return (create_mark) ? gtk_text_buffer_create_mark(buf, NULL, &iter, TRUE) : NULL;
#undef hex_fix
#undef ascii_fix
}

/* Update the progress bar this many times when reading a file. */
#define N_PROGBAR_UPDATES        100
/* The minimum packet length required to check if a progress bar is needed or not */
#define MIN_PACKET_LENGTH       1024

/*
 * XXX - at least in GTK+ 2.x, this is not fast - in one capture with a
 * 64K-or-so reassembled HTTP reply, it takes about 3 seconds to construct
 * the hex dump pane on a 1.4 GHz G4 PowerMac on OS X 10.3.3.  (That's
 * presumably why there's a progress bar for it.)
 *
 * Perhaps what's needed is a custom widget (either one that lets you stuff
 * text into it more quickly, or one that's a "virtual" widget so that the
 * text for a row is constructed, via a callback, when the row is to be
 * displayed).  A custom widget might also let us treat the offset, hex
 * data, and ASCII data as three columns, so you can select purely in
 * the hex dump column.
 */
static void
packet_hex_print_common(GtkTextBuffer *buf, GtkWidget *bv, const guint8 *pd, int len, int encoding)
{
    int            i = 0, j, k = 0, b, cur;
    guchar         line[MAX_LINES_LEN + 1];
    static guchar  hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    static const guint8 bitmask[8] = {
        0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
    guchar         c = '\0';
    unsigned int   use_digits;
    GtkTextIter    iter;

    progdlg_t  *progbar = NULL;
    float       progbar_val;
    gboolean    progbar_stop_flag;
    GTimeVal    progbar_start_time;
    gchar       progbar_status_str[100];
    int         progbar_nextstep;
    int         progbar_quantum;

    gtk_text_buffer_set_text(buf, "", 0);
    gtk_text_buffer_get_start_iter(buf, &iter);

    /*
     * How many of the leading digits of the offset will we supply?
     * We always supply at least 4 digits, but if the maximum offset
     * won't fit in 4 digits, we use as many digits as will be needed.
     */
    if (((len - 1) & 0xF0000000) != 0)
        use_digits = 8; /* need all 8 digits */
    else if (((len - 1) & 0x0F000000) != 0)
        use_digits = 7; /* need 7 digits */
    else if (((len - 1) & 0x00F00000) != 0)
        use_digits = 6; /* need 6 digits */
    else if (((len - 1) & 0x000F0000) != 0)
        use_digits = 5; /* need 5 digits */
    else
        use_digits = 4; /* we'll supply 4 digits */

    /* Record the number of digits in this text view. */
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_NDIGITS_KEY, GUINT_TO_POINTER(use_digits));

    /* Update the progress bar when it gets to this value. */
    if (len > MIN_PACKET_LENGTH){
        progbar_nextstep = 0;
    }else{
        /* If length =< MIN_PACKET_LENGTH
         * there is no need to calculate the progress
         */
        progbar_nextstep = len+1;
    }

    /* When we reach the value that triggers a progress bar update,
       bump that value by this amount. */
    progbar_quantum = len/N_PROGBAR_UPDATES;
    /* Progress so far. */
    progbar_val = 0.0f;

    progbar_stop_flag = FALSE;
    g_get_current_time(&progbar_start_time);

    cur = 0;
    while (i < len) {
        /* Create the progress bar if necessary.
           We check on every iteration of the loop, so that it takes no
           longer than the standard time to create it (otherwise, for a
           large packet, we might take considerably longer than that standard
           time in order to get to the next progress bar step). */
        if ((progbar == NULL) && (len > MIN_PACKET_LENGTH))
            progbar = delayed_create_progress_dlg("Processing", "Packet Details",
                                                  TRUE,
                                                  &progbar_stop_flag,
                                                  &progbar_start_time,
                                                  progbar_val);

        /* Update the progress bar, but do it only N_PROGBAR_UPDATES times;
           when we update it, we have to run the GTK+ main loop to get it
           to repaint what's pending, and doing so may involve an "ioctl()"
           to see if there's any pending input from an X server, and doing
           that for every packet can be costly, especially on a big file. */
        if (i >= progbar_nextstep) {

            if (progbar != NULL) {
                /* let's not divide by zero. I should never be started
                 * with count == 0, so let's assert that
                 */
                g_assert(len > 0);
                progbar_val = (gfloat) i / len;
                g_snprintf(progbar_status_str, sizeof(progbar_status_str),
                           "%4u of %u bytes", i, len);
                update_progress_dlg(progbar, progbar_val, progbar_status_str);
            }

            progbar_nextstep += progbar_quantum;
        }

        if (progbar_stop_flag) {
            /* Well, the user decided to abort the operation.  Just stop,
               and arrange to return TRUE to our caller, so they know it
               was stopped explicitly. */
            break;
        }

        /* Print the line number */
        j = use_digits;
        do {
            j--;
            c = (i >> (j*4)) & 0xF;
            line[cur++] = hexchars[c];
        } while (j != 0);
        line[cur++] = ' ';
        line[cur++] = ' ';

        j   = i;
        switch (recent.gui_bytes_view) {
        case BYTES_HEX:
            k = i + BYTES_PER_LINE;
            break;
        case BYTES_BITS:
            k = i + BITS_PER_LINE;
            break;
        default:
            g_assert_not_reached();
        }
        /* Print the hex bit */
        while (i < k) {
            if (i < len) {
                switch (recent.gui_bytes_view) {
                case BYTES_HEX:
                    line[cur++] = hexchars[(pd[i] & 0xf0) >> 4];
                    line[cur++] = hexchars[pd[i] & 0x0f];
                    break;
                case BYTES_BITS:
                    for (b = 0; b < 8; b++) {
                        line[cur++] = (pd[i] & bitmask[b]) ? '1' : '0';
                    }
                    break;
                default:
                    g_assert_not_reached();
                }
            } else {
                switch (recent.gui_bytes_view) {
                case BYTES_HEX:
                    line[cur++] = ' '; line[cur++] = ' ';
                    break;
                case BYTES_BITS:
                    for (b = 0; b < 8; b++) {
                        line[cur++] = ' ';
                    }
                    break;
                default:
                    g_assert_not_reached();
                }
            }
            i++;
            /* Inter byte space if not at end of line */
            if (i < k) {
                line[cur++] = ' ';
                /* insert a space every BYTE_VIEW_SEP bytes */
                if( ( i % BYTE_VIEW_SEP ) == 0 ) {
                    line[cur++] = ' ';
                }
            }
        }

        /* Print some space at the end of the line */
        line[cur++] = ' '; line[cur++] = ' '; line[cur++] = ' ';

        /* Print the ASCII bit */
        i = j;

        while (i < k) {
            if (i < len) {
                if (encoding == PACKET_CHAR_ENC_CHAR_ASCII) {
                    c = pd[i];
                }
                else if (encoding == PACKET_CHAR_ENC_CHAR_EBCDIC) {
                    c = EBCDIC_to_ASCII1(pd[i]);
                }
                else {
                    g_assert_not_reached();
                }
                line[cur++] = isprint(c) ? c : '.';
            } else {
                line[cur++] = ' ';
            }
            i++;
            if (i < k) {
                /* insert a space every BYTE_VIEW_SEP bytes */
                if( ( i % BYTE_VIEW_SEP ) == 0 ) {
                    line[cur++] = ' ';
                }
            }
        }
        line[cur++] = '\n';
        if (cur >= (MAX_LINES_LEN - MAX_LINE_LEN)) {
            gtk_text_buffer_insert(buf, &iter, line, cur);
            cur = 0;
        }
    }

    /* We're done printing the packets; destroy the progress bar if
       it was created. */
    if (progbar != NULL)
        destroy_progress_dlg(progbar);

    if (cur) {
        gtk_text_buffer_insert(buf, &iter, line, cur);
    }
}

static void
packet_hex_update(GtkWidget *bv, const guint8 *pd, int len, int bstart,
                  int bend, guint32 bmask, int bmask_le,
                  int astart, int aend, int encoding)
{
    GtkTextView   *bv_text_view = GTK_TEXT_VIEW(bv);
    GtkTextBuffer *buf = gtk_text_view_get_buffer(bv_text_view);
    GtkTextMark   *mark;
    int ndigits;

    GtkTextIter start, end;

    g_object_ref(buf);

#if 0
    /* XXX: Setting the text_view buffer to NULL is apparently
     *      not a good idea; If a progress_bar is displayed below
     *      in delayed_create_progress_dlg() there will then be
     *      a crash internally in the gtk library.
     *      (It appears that gtk_text_view_set_buffer
     *       queues a callback to be run when this
     *       thread is next idle. Unfortunately the call to
     *       gtk_main_iteration() in delayed_create_progress_dlg()
     *       causes the internal callback to be run which then
     *       crashes (because the textview has no buffer ?))
     */
    gtk_text_view_set_buffer(bv_text_view, NULL);
#endif

    /* attach a dummy buffer in place of the real buffer.
     * (XXX: Presumably this is done so there's no attempt
     *       to display the real buffer until it has been
     *       completely generated).
     */
    gtk_text_view_set_buffer(bv_text_view, gtk_text_buffer_new(NULL));

    packet_hex_print_common(buf, bv, pd, len, encoding);

    /* mark everything with "plain" tag */
    gtk_text_buffer_get_start_iter(buf, &start);
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_apply_tag_by_name(buf, "plain", &start, &end);

    ndigits = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_NDIGITS_KEY));

    /* mark reverse tags */
    mark = packet_hex_apply_reverse_tag(buf, bstart, bend, bmask, bmask_le, ndigits, 1);
    packet_hex_apply_reverse_tag(buf, astart, aend, 0x00, 0, ndigits, 0);

    gtk_text_view_set_buffer(bv_text_view, buf);

    /* scroll text into position */
    if (mark) {
        gtk_text_view_scroll_to_mark(bv_text_view, mark, 0.0, TRUE, 1.0, 0.0);
        gtk_text_buffer_delete_mark(buf, mark);
    }
    g_object_unref(buf);
}

void
packet_hex_print(GtkWidget *bv, const guint8 *pd, frame_data *fd,
                 field_info *finfo, guint len)
{
    /* do the initial printing and save the information needed  */
    /* to redraw the display if preferences change.             */

    int bstart = -1, bend = -1, blen = -1;
    guint32 bmask = 0x00; int bmask_le = 0;
    int astart = -1, aend = -1, alen = -1;


    if (finfo != NULL) {

        if (cfile.search_in_progress && (cfile.hex || (cfile.string && cfile.packet_data))) {
            /* In the hex view, only highlight the target bytes or string. The entire
               field can then be displayed by clicking on any of the bytes in the field. */
            if (cfile.hex) {
                blen = (int)strlen(cfile.sfilter)/2;
            } else {
                blen = (int)strlen(cfile.sfilter);
            }
            bstart = cfile.search_pos - (blen-1);

        } else {
            blen = finfo->length;
            bstart = finfo->start;
        }

        /* bmask = finfo->hfinfo->bitmask << finfo->hfinfo->bitshift; */ /* (value & mask) >> shift */
        if (finfo->hfinfo) bmask = finfo->hfinfo->bitmask;
        astart = finfo->appendix_start;
        alen = finfo->appendix_length;

        if (FI_GET_FLAG(finfo, FI_LITTLE_ENDIAN))
            bmask_le = 1;
        else if (FI_GET_FLAG(finfo, FI_BIG_ENDIAN))
            bmask_le = 0;
        else { /* unknown endianess - disable mask
                  bmask_le = (G_BYTE_ORDER == G_LITTLE_ENDIAN);
               */
            bmask = 0x00;
        }

        if (bmask == 0x00) {
            int bito = FI_GET_BITS_OFFSET(finfo);
            int bitc = FI_GET_BITS_SIZE(finfo);
            int bitt = bito + bitc;

            /* construct mask using bito & bitc */
            /* XXX, mask has only 32 bit, later we can store bito&bitc, and use them (which should be faster) */
            if (bitt > 0 && bitt < 32) {

                bmask = ((1 << bitc) - 1) << (8-(bitt & 0x7)); /* always? */
                bmask_le = 0; /* ? */
            }
        }
    }

    if (bstart >= 0 && blen > 0) {
        bend = bstart + blen;
    }
    if (astart >= 0 && alen > 0) {
        aend = astart + alen;
    }

    if (bend == -1 && aend != -1) {
        bstart = astart;
        bmask = 0x00;
        bend = aend;
        astart = aend = -1;
    }

    /* don't exceed the end of available data */
    if (aend != -1 && (guint)aend > len) aend = len;
    if (bend != -1 && (guint)bend > len) bend = len;

    /* save the information needed to redraw the text */
    /* should we save the fd & finfo pointers instead ?? */
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY, GINT_TO_POINTER(bstart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY, GINT_TO_POINTER(bend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASK_KEY, GINT_TO_POINTER(bmask));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASKLE_KEY, GINT_TO_POINTER(bmask_le));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_START_KEY, GINT_TO_POINTER(astart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_END_KEY, GINT_TO_POINTER(aend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_ENCODE_KEY,
                      GUINT_TO_POINTER((guint)fd->flags.encoding));

    /* stig: it should be done only for bitview... */
    if (recent.gui_bytes_view != BYTES_BITS)
        bmask = 0x00;
    packet_hex_update(bv, pd, len, bstart, bend, bmask, bmask_le, astart, aend, fd->flags.encoding);
}

void
packet_hex_editor_print(GtkWidget *bv, const guint8 *pd, frame_data *fd, int offset, int bitoffset, guint len)
{
    /* do the initial printing and save the information needed  */
    /* to redraw the display if preferences change.             */

    int bstart = offset, bend = (bstart != -1) ? offset+1 : -1;
    guint32 bmask; int bmask_le = 0;
    int astart = -1, aend = -1;

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        bmask = (bitoffset == 0) ? 0xf0 : (bitoffset == 4) ? 0x0f : 0xff;
        break;

    case BYTES_BITS:
        bmask = (1 << (7-bitoffset));
        break;

	default:
		bmask = 0x00;
		g_assert_not_reached();
		break;
    }

    /* save the information needed to redraw the text */
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY, GINT_TO_POINTER(bstart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY, GINT_TO_POINTER(bend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASK_KEY, GINT_TO_POINTER(bmask));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASKLE_KEY, GINT_TO_POINTER(bmask_le));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_START_KEY, GINT_TO_POINTER(astart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_END_KEY, GINT_TO_POINTER(aend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_ENCODE_KEY,
                      GUINT_TO_POINTER((guint)fd->flags.encoding));

    packet_hex_update(bv, pd, len, bstart, bend, bmask, bmask_le, astart, aend, fd->flags.encoding);
}

/*
 * Redraw the text using the saved information; usually called if
 * the preferences have changed.
 */
void
packet_hex_reprint(GtkWidget *bv)
{
    int start, end, mask, mask_le, encoding;
    int astart, aend;
    const guint8 *data;
    guint len = 0;

    start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
    end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));
    mask = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_MASK_KEY));
    mask_le = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_MASKLE_KEY));
    astart = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_APP_START_KEY));
    aend = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_APP_END_KEY));
    data = get_byte_view_data_and_length(bv, &len);
    g_assert(data != NULL);
    encoding = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_ENCODE_KEY));

    /* stig: it should be done only for bitview... */
    if (recent.gui_bytes_view != BYTES_BITS)
        mask = 0x00;
    packet_hex_update(bv, data, len, start, end, mask, mask_le, astart, aend, encoding);
}

/* List of all protocol tree widgets, so we can globally set the selection
   mode and font of all of them. */
static GList *ptree_widgets;

/* Add a protocol tree widget to the list of protocol tree widgets. */
static void forget_ptree_widget(GtkWidget *ptreew, gpointer data);

static void
remember_ptree_widget(GtkWidget *ptreew)
{
    ptree_widgets = g_list_append(ptree_widgets, ptreew);

    /* Catch the "destroy" event on the widget, so that we remove it from
       the list when it's destroyed. */
    g_signal_connect(ptreew, "destroy", G_CALLBACK(forget_ptree_widget), NULL);
}

/* Remove a protocol tree widget from the list of protocol tree widgets. */
static void
forget_ptree_widget(GtkWidget *ptreew, gpointer data _U_)
{
    ptree_widgets = g_list_remove(ptree_widgets, ptreew);
}

/* Set the selection mode of a given packet tree window. */
static void
set_ptree_sel_browse(GtkWidget *tree, gboolean val)
{
    GtkTreeSelection *selection;

    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
    /* Yeah, GTK uses "browse" in the case where we do not, but oh well.
       I think "browse" in Wireshark makes more sense than "SINGLE" in
       GTK+ */
    if (val) {
        gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
    }
    else {
        gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
    }
}

static void
set_ptree_sel_browse_cb(gpointer data, gpointer user_data)
{
    set_ptree_sel_browse((GtkWidget *)data, *(gboolean *)user_data);
}

/* Set the selection mode of all packet tree windows. */
void
set_ptree_sel_browse_all(gboolean val)
{
    g_list_foreach(ptree_widgets, set_ptree_sel_browse_cb, &val);
}

static void
set_ptree_font_cb(gpointer data, gpointer user_data)
{
    gtk_widget_modify_font((GtkWidget *)data,
                           (PangoFontDescription *)user_data);
}

void
set_ptree_font_all(PangoFontDescription *font)
{
    g_list_foreach(ptree_widgets, set_ptree_font_cb, font);
}


/*
 * Each expert_color_* level below should match the light gradient
 * colors in image/expert_indicators.svg.
 */
static gboolean colors_ok = FALSE;

GdkColor        expert_color_chat       = { 0, 0x8080, 0xb7b7, 0xf7f7 };        /* light blue */
GdkColor        expert_color_note       = { 0, 0xa0a0, 0xffff, 0xffff };        /* bright turquoise */
GdkColor        expert_color_warn       = { 0, 0xf7f7, 0xf2f2, 0x5353 };        /* yellow */
GdkColor        expert_color_error      = { 0, 0xffff, 0x5c5c, 0x5c5c };        /* pale red */
GdkColor        expert_color_foreground = { 0, 0x0000, 0x0000, 0x0000 };        /* black */
GdkColor        hidden_proto_item       = { 0, 0x4444, 0x4444, 0x4444 };        /* gray */

gchar *expert_color_chat_str;
gchar *expert_color_note_str;
gchar *expert_color_warn_str;
gchar *expert_color_error_str;
gchar *expert_color_foreground_str;

void proto_draw_colors_init(void)
{
    if(colors_ok) {
        return;
    }

    get_color(&expert_color_chat);
    get_color(&expert_color_note);
    get_color(&expert_color_warn);
    get_color(&expert_color_error);
    get_color(&expert_color_foreground);
    expert_color_chat_str = gdk_color_to_string(&expert_color_chat);
    expert_color_note_str = gdk_color_to_string(&expert_color_note);
    expert_color_warn_str = gdk_color_to_string(&expert_color_warn);
    expert_color_error_str = gdk_color_to_string(&expert_color_error);
    expert_color_foreground_str = gdk_color_to_string(&expert_color_foreground);

    get_color(&hidden_proto_item);

    colors_ok = TRUE;
}


static void
tree_cell_renderer(GtkTreeViewColumn *tree_column _U_, GtkCellRenderer *cell,
                   GtkTreeModel *tree_model, GtkTreeIter *iter,
                   gpointer data _U_)
{
    field_info   *fi;

    gtk_tree_model_get(tree_model, iter, 1, &fi, -1);

    if(!colors_ok) {
        proto_draw_colors_init();
    }

    /* for the various possible attributes, see:
     * http://developer.gnome.org/doc/API/2.0/gtk/GtkCellRendererText.html
     *
     * color definitions can be found at:
     * http://cvs.gnome.org/viewcvs/gtk+/gdk-pixbuf/io-xpm.c?rev=1.42
     * (a good color overview: http://www.computerhope.com/htmcolor.htm)
     *
     * some experiences:
     * background-gdk: doesn't seem to work (probably the GdkColor must be allocated)
     * weight/style: doesn't take any effect
     */

    /* for each field, we have to reset the renderer attributes */
    g_object_set (cell, "foreground-set", FALSE, NULL);

    g_object_set (cell, "background-set", FALSE, NULL);

    g_object_set (cell, "underline", PANGO_UNDERLINE_NONE, NULL);
    g_object_set (cell, "underline-set", FALSE, NULL);

    /*g_object_set (cell, "style", PANGO_STYLE_NORMAL, NULL);
    g_object_set (cell, "style-set", FALSE, NULL);*/

    /*g_object_set (cell, "weight", PANGO_WEIGHT_NORMAL, NULL);
    g_object_set (cell, "weight-set", FALSE, NULL);*/

    if(FI_GET_FLAG(fi, FI_GENERATED)) {
        /* we use "[...]" to mark generated items, no need to change things here */

        /* as some fonts don't support italic, don't use this */
        /*g_object_set (cell, "style", PANGO_STYLE_ITALIC, NULL);
        g_object_set (cell, "style-set", TRUE, NULL);
        */
        /*g_object_set (cell, "weight", PANGO_WEIGHT_BOLD, NULL);
        g_object_set (cell, "weight-set", TRUE, NULL);*/
    }

    if(FI_GET_FLAG(fi, FI_HIDDEN)) {
        g_object_set (cell, "foreground-gdk", &hidden_proto_item, NULL);
        g_object_set (cell, "foreground-set", TRUE, NULL);
    }

    if (fi && fi->hfinfo) {
        if(fi->hfinfo->type == FT_PROTOCOL) {
            g_object_set (cell, "background", "gray90", NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            g_object_set (cell, "foreground", "black", NULL);
            g_object_set (cell, "foreground-set", TRUE, NULL);
            /*g_object_set (cell, "weight", PANGO_WEIGHT_BOLD, NULL);
            g_object_set (cell, "weight-set", TRUE, NULL);*/
        }

        if((fi->hfinfo->type == FT_FRAMENUM) ||
           (FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type))) {
            render_as_url(cell);
        }
    }

    if(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        switch(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        case(PI_CHAT):
            g_object_set (cell, "background-gdk", &expert_color_chat, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        case(PI_NOTE):
            g_object_set (cell, "background-gdk", &expert_color_note, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        case(PI_WARN):
            g_object_set (cell, "background-gdk", &expert_color_warn, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        case(PI_ERROR):
            g_object_set (cell, "background-gdk", &expert_color_error, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        default:
            g_assert_not_reached();
        }
        g_object_set (cell, "foreground", "black", NULL);
        g_object_set (cell, "foreground-set", TRUE, NULL);
    }
}

GtkWidget *
main_tree_view_new(e_prefs *prefs_p, GtkWidget **tree_view_p)
{
    GtkWidget *tv_scrollw, *tree_view;
    GtkTreeStore *store;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
    gint col_offset;

    /* Tree view */
    tv_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(tv_scrollw),
                                        GTK_SHADOW_IN);

    store = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_POINTER);
    tree_view = tree_view_new(GTK_TREE_MODEL(store));
    g_object_unref(G_OBJECT(store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tree_view), FALSE);
    renderer = gtk_cell_renderer_text_new();
    g_object_set (renderer, "ypad", 0, NULL);
    col_offset = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tree_view),
                                                             -1, "Name", renderer,
                                                             "text", 0, NULL);
    column = gtk_tree_view_get_column(GTK_TREE_VIEW(tree_view),
                                      col_offset - 1);
    gtk_tree_view_column_set_cell_data_func(column, renderer, tree_cell_renderer,
                                            NULL, NULL);

    gtk_tree_view_column_set_sizing(GTK_TREE_VIEW_COLUMN(column),
                                    GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    g_signal_connect(tree_view, "row-expanded", G_CALLBACK(expand_tree), NULL);
    g_signal_connect(tree_view, "row-collapsed", G_CALLBACK(collapse_tree), NULL);
    gtk_container_add( GTK_CONTAINER(tv_scrollw), tree_view );
    set_ptree_sel_browse(tree_view, prefs_p->gui_ptree_sel_browse);
    gtk_widget_modify_font(tree_view, user_font_get_regular());
    remember_ptree_widget(tree_view);

    *tree_view_p = tree_view;

    return tv_scrollw;
}

void
expand_all_tree(proto_tree *protocol_tree _U_, GtkWidget *tree_view)
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_is_expanded[i] = TRUE;
    }
    gtk_tree_view_expand_all(GTK_TREE_VIEW(tree_view));
}

void
collapse_all_tree(proto_tree *protocol_tree _U_, GtkWidget *tree_view)
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_is_expanded[i] = FALSE;
    }
    gtk_tree_view_collapse_all(GTK_TREE_VIEW(tree_view));
}


struct proto_tree_draw_info {
    GtkTreeView  *tree_view;
    GtkTreeIter  *iter;
};

void
main_proto_tree_draw(proto_tree *protocol_tree)
{
    proto_tree_draw(protocol_tree, tree_view_gbl);
}


static void
tree_view_follow_link(field_info   *fi)
{
    gchar *url;

    if(fi->hfinfo->type == FT_FRAMENUM) {
        cf_goto_frame(&cfile, fi->value.value.uinteger);
    }
    if(FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type)) {
        url = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, NULL);
        if(url){
            browser_open_url(url);
            g_free(url);
        }
    }
}


/* If the user selected a position in the tree view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and
 * select it. */
gboolean
tree_view_select(GtkWidget *widget, GdkEventButton *event)
{
    GtkTreeSelection    *sel;
    GtkTreePath         *path;

    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
                                      (gint) (((GdkEventButton *)event)->x),
                                      (gint) (((GdkEventButton *)event)->y),
                                      &path, NULL, NULL, NULL))
    {
        sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(widget));

        /* if that's a doubleclick, try to follow the link */
        if(event->type == GDK_2BUTTON_PRESS) {
            GtkTreeModel *model;
            GtkTreeIter iter;
            field_info   *fi;

            if(gtk_tree_selection_get_selected (sel, &model, &iter)) {
                gtk_tree_model_get(model, &iter, 1, &fi, -1);
                tree_view_follow_link(fi);
            }
        }
        else if (((GdkEventButton *)event)->button != 1) {
            /* if button == 1 gtk_tree_selection_select_path is already (or will be) called by the widget */
            gtk_tree_selection_select_path(sel, path);
        }
    } else {
        return FALSE;
    }
    return TRUE;
}

/* fill the whole protocol tree with the string values */
void
proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view)
{
    GtkTreeStore *store;
    struct proto_tree_draw_info info;

    info.tree_view = GTK_TREE_VIEW(tree_view);
    info.iter = NULL;

    store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view)));

    /*
     * Clear out any crud left over in the display of the protocol
     * tree, by removing all nodes from the tree.
     * This is how it's done in testgtk.c in GTK+.
     */
    gtk_tree_store_clear(store);

    proto_tree_children_foreach(protocol_tree, proto_tree_draw_node, &info);
}


/* fill a single protocol tree item with the string value */
static void
proto_tree_draw_node(proto_node *node, gpointer data)
{
    struct proto_tree_draw_info  info;
    struct proto_tree_draw_info *parent_info = (struct proto_tree_draw_info*) data;

    field_info   *fi = PNODE_FINFO(node);
    gchar         label_str[ITEM_LABEL_LENGTH];
    gchar        *label_ptr;
    gboolean      is_leaf, is_expanded;
    GtkTreeStore *store;
    GtkTreeIter   iter;
    GtkTreePath  *path;

    g_assert(fi && "dissection with an invisible proto tree?");

    if (PROTO_ITEM_IS_HIDDEN(node) && !prefs.display_hidden_proto_items)
        return;

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

    info.tree_view = parent_info->tree_view;
    store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(info.tree_view)));
    gtk_tree_store_append(store, &iter, parent_info->iter);
    gtk_tree_store_set(store, &iter, 0, label_ptr, 1, fi, -1);

    if (PROTO_ITEM_IS_GENERATED(node) || PROTO_ITEM_IS_HIDDEN(node)) {
        g_free(label_ptr);
    }

    if (!is_leaf) {
        info.iter = &iter;
        proto_tree_children_foreach(node, proto_tree_draw_node, &info);
        path = gtk_tree_model_get_path(GTK_TREE_MODEL(store), &iter);
        if (is_expanded)
            gtk_tree_view_expand_to_path(info.tree_view, path);
        else
            gtk_tree_view_collapse_row(info.tree_view, path);
        gtk_tree_path_free(path);
    }
}

/*
 * Clear the hex dump and protocol tree panes.
 */
void
clear_tree_and_hex_views(void)
{
    /* Clear the hex dump by getting rid of all the byte views. */
    while (gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr_gbl), 0) != NULL)
        gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr_gbl), 0);

    /* Add a placeholder byte view so that there's at least something
       displayed in the byte view notebook. */
    add_byte_tab(byte_nb_ptr_gbl, "", NULL, NULL, tree_view_gbl);

    /* Clear the protocol tree by removing all nodes in the ctree.
       This is how it's done in testgtk.c in GTK+ */
    gtk_tree_store_clear(GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view_gbl))));
}

void
select_bytes_view (GtkWidget *w _U_, gpointer data _U_, gint view)
{
    if (recent.gui_bytes_view != view) {
        recent.gui_bytes_view = view;
        redraw_packet_bytes_all();
    }
}
