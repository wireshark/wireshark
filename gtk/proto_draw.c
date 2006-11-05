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
 *				data sources as tabbed hex windows
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

#include <string.h>

#include <epan/epan_dissect.h>

#include "isprint.h"

#include "main.h"
#include <epan/packet.h>
#include <epan/charsets.h>
#include "menu.h"
#include "keys.h"

#include <epan/prefs.h>
#include "colors.h"
#include "capture_file_dlg.h"
#include "proto_draw.h"
#include "packet_win.h"
#if 0
#include "dlg_utils.h"
#endif
#include "file_dlg.h"
#include "gui_utils.h"
#include "gtkglobals.h"
#include "compat_macros.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "progress_dlg.h"
#include "font_utils.h"

#include "../ui_util.h"
#include "file_util.h"
#include "webbrowser.h"

#if GTK_MAJOR_VERSION >= 2 && _WIN32
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "win32-file-dlg.h"
#endif

#define BYTE_VIEW_WIDTH    16
#define BYTE_VIEW_SEP      8

#define E_BYTE_VIEW_TREE_PTR      "byte_view_tree_ptr"
#define E_BYTE_VIEW_TREE_VIEW_PTR "byte_view_tree_view_ptr"
#define E_BYTE_VIEW_NDIGITS_KEY   "byte_view_ndigits"
#define E_BYTE_VIEW_TVBUFF_KEY    "byte_view_tvbuff"
#define E_BYTE_VIEW_START_KEY     "byte_view_start"
#define E_BYTE_VIEW_END_KEY       "byte_view_end"
#define E_BYTE_VIEW_ENCODE_KEY    "byte_view_encode"


#if GTK_MAJOR_VERSION < 2
GtkStyle *item_style = NULL;
#endif

/* gtk_tree_view_expand_to_path doesn't exist in gtk+ v2.0 so we must include it
 * when building with this version (taken from gtk+ v2.2.4) */
#if GTK_MAJOR_VERSION >= 2 && GTK_MINOR_VERSION == 0
/**
 * gtk_tree_view_expand_to_path:
 * @tree_view: A #GtkTreeView.
 * @path: path to a row.
 *
 * Expands the row at @path. This will also expand all parent rows of
 * @path as necessary.
 *
 * Since: 2.2
 **/
void
gtk_tree_view_expand_to_path (GtkTreeView *tree_view,
                              GtkTreePath *path)
{
  gint i, depth;
  gint *indices;
  GtkTreePath *tmp;

  g_return_if_fail (GTK_IS_TREE_VIEW (tree_view));
  g_return_if_fail (path != NULL);

  depth = gtk_tree_path_get_depth (path);
  indices = gtk_tree_path_get_indices (path);

  tmp = gtk_tree_path_new ();
  g_return_if_fail (tmp != NULL);

  for (i = 0; i < depth; i++)
    {
      gtk_tree_path_append_index (tmp, indices[i]);
      gtk_tree_view_expand_row (tree_view, tmp, FALSE);
    }

  gtk_tree_path_free (tmp);
}
#endif

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
      return GTK_BIN(bv_page)->child;
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

  byte_view_tvb = OBJECT_GET_DATA(byte_view, E_BYTE_VIEW_TVBUFF_KEY);
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
    bv = GTK_BIN(bv_page)->child;
    bv_tvb = OBJECT_GET_DATA(bv, E_BYTE_VIEW_TVBUFF_KEY);
    if (bv_tvb == tvb) {
      /* Found it. */
      gtk_notebook_set_page(GTK_NOTEBOOK(nb_ptr), num);
      break;
    }
  }
}

/* Redraw a given byte view window. */
void
redraw_hex_dump(GtkWidget *nb, frame_data *fd, field_info *finfo)
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
redraw_hex_dump_all(void)
{
    if (cfile.current_frame != NULL)
            redraw_hex_dump( byte_nb_ptr, cfile.current_frame, cfile.finfo_selected);

  redraw_hex_dump_packet_wins();

#if GTK_MAJOR_VERSION >= 2
  /* XXX - this is a hack, to workaround a bug in GTK2.x!
     when changing the font size, even refilling of the corresponding
     gtk_text_buffer doesn't seem to trigger an update.
     The only workaround is to freshly select the frame, which will remove any
     existing notebook tabs and "restart" the whole byte view again. */
  if (cfile.current_frame != NULL)
    cf_goto_frame(&cfile, cfile.current_frame->num);
#endif
}

#if GTK_MAJOR_VERSION < 2
static void
expand_tree(GtkCTree *ctree, GtkCTreeNode *node, gpointer user_data _U_)
#else
static void
expand_tree(GtkTreeView *tree_view, GtkTreeIter *iter,
            GtkTreePath *path _U_, gpointer user_data _U_)
#endif
{
    field_info	 *finfo;
#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel *model;

    model = gtk_tree_view_get_model(tree_view);
    gtk_tree_model_get(model, iter, 1, &finfo, -1);
#else
    finfo = gtk_ctree_node_get_row_data( ctree, node);
#endif
    g_assert(finfo);

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

#if GTK_MAJOR_VERSION < 2
static void
collapse_tree(GtkCTree *ctree, GtkCTreeNode *node, gpointer user_data _U_)
#else
static void
collapse_tree(GtkTreeView *tree_view, GtkTreeIter *iter,
            GtkTreePath *path _U_, gpointer user_data _U_)
#endif
{
    field_info	 *finfo;
#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel *model;

    model = gtk_tree_view_get_model(tree_view);
    gtk_tree_model_get(model, iter, 1, &finfo, -1);
#else
    finfo = gtk_ctree_node_get_row_data( ctree, node);
#endif
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

#if GTK_MAJOR_VERSION < 2
static void
toggle_tree(GtkCTree *ctree, GdkEventKey *event, gpointer user_data _U_)
{
	if (event->keyval != GDK_Return)
		return;
	gtk_ctree_toggle_expansion(ctree, GTK_CTREE_NODE(ctree->clist.selection->data));
}
#endif

#define MAX_OFFSET_LEN	8	/* max length of hex offset of bytes */
#define BYTES_PER_LINE	16	/* max byte values in a line */
#define HEX_DUMP_LEN	(BYTES_PER_LINE*3 + 1)
				/* max number of characters hex dump takes -
				   2 digits plus trailing blank
				   plus separator between first and
				   second 8 digits */
#define DATA_DUMP_LEN	(HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
				/* number of characters those bytes take;
				   3 characters per byte of hex dump,
				   2 blanks separating hex from ASCII,
				   1 character per byte of ASCII dump */
#define MAX_LINE_LEN	(MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
				/* number of characters per line;
				   offset, 2 blanks separating offset
				   from data dump, data dump */

/* Which byte the offset is referring to. Associates
 * whitespace with the preceding digits. */
static int
byte_num(int offset, int start_point)
{
	return (offset - start_point) / 3;
}

#if GTK_MAJOR_VERSION >= 2
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

GtkTreePath *tree_find_by_field_info(GtkTreeView *tree_view, field_info *finfo) {
  GtkTreeModel *model;
  struct field_lookup_info fli;

  g_assert(finfo != NULL);

  model = gtk_tree_view_get_model(tree_view);
  fli.fi = finfo;
  gtk_tree_model_foreach(model, lookup_finfo, &fli);

  return gtk_tree_model_get_path(model, &fli.iter);
}

#endif

/* If the user selected a certain byte in the byte view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and:
 *
 *	if we succeed, select it, and return TRUE;
 *	if we fail, return FALSE. */
gboolean
byte_view_select(GtkWidget *widget, GdkEventButton *event)
{
    proto_tree   *tree;
#if GTK_MAJOR_VERSION < 2
    GtkCTree     *ctree;
    GtkCTreeNode *node, *parent;
    GtkText      *bv = GTK_TEXT(widget);
#else
    GtkTreeView  *tree_view;
    GtkTreeModel *model;
    GtkTreePath  *first_path, *path;
    GtkTreeIter   parent;
    GtkTextView  *bv = GTK_TEXT_VIEW(widget);
    gint          x, y;
    GtkTextIter   iter;
    struct field_lookup_info fli;
#endif
    field_info	 *finfo;
    int           row, column;
    int           byte;
    tvbuff_t     *tvb;
    guint         ndigits;
    int           digits_start_1;
    int           digits_end_1;
    int           digits_start_2;
    int           digits_end_2;
    int           text_start_1;
    int           text_end_1;
    int           text_start_2;
    int           text_end_2;

    /*
     * Get the number of digits of offset being displayed, and
     * compute the columns of various parts of the display.
     */
    ndigits = GPOINTER_TO_UINT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_NDIGITS_KEY));

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
     *
     * Then subtract 1 to get the last column of the first half
     * rather than the first column after the first half.
     */
    digits_end_1 = digits_start_1 + (BYTES_PER_LINE/2)*2 +
        (BYTES_PER_LINE/2 - 1) - 1;

    /*
     * The column of the first hex digit in the second half.
     * Add back the 1 to get the first column after the first
     * half, and then add 2 for the 2 separating blanks between
     * the halves.
     */
    digits_start_2 = digits_end_1 + 3;

    /*
     * The column of the last hex digit in the second half.
     * Add the same value we used to get "digits_end_1" from
     * "digits_start_1".
     */
    digits_end_2 = digits_start_2 + (BYTES_PER_LINE/2)*2 +
        (BYTES_PER_LINE/2 - 1) - 1;

    /*
     * The column of the first "text dump" character in the first half.
     * Add back the 1 to get the first column after the second
     * half's hex dump, and then add 3 for the 3 separating blanks
     * between the hex and text dummp.
     */
    text_start_1 = digits_end_2 + 4;

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

    tree = OBJECT_GET_DATA(widget, E_BYTE_VIEW_TREE_PTR);
    if (tree == NULL) {
        /*
         * Somebody clicked on the dummy byte view; do nothing.
         */
        return FALSE;
    }
#if GTK_MAJOR_VERSION < 2
    ctree = GTK_CTREE(OBJECT_GET_DATA(widget, E_BYTE_VIEW_TREE_VIEW_PTR));
#else
    tree_view = GTK_TREE_VIEW(OBJECT_GET_DATA(widget,
                                              E_BYTE_VIEW_TREE_VIEW_PTR));
#endif

#if GTK_MAJOR_VERSION < 2
    /* Given the mouse (x,y) and the current GtkText (h,v)
     * adjustments, and the size of the font, figure out
     * which text column/row the user selected. This could be off
     * if the bold version of the font is bigger than the
     * regular version of the font. */
    column = (int) ((bv->hadj->value + event->x) / user_font_get_regular_width());
    row = (int) ((bv->vadj->value + event->y) / user_font_get_regular_height());
#else
    /* get the row/column selected */
    gtk_text_view_window_to_buffer_coords(bv,
                         gtk_text_view_get_window_type(bv, event->window),
                         (gint) event->x, (gint) event->y, &x, &y);
    gtk_text_view_get_iter_at_location(bv, &iter, x, y);
    row = gtk_text_iter_get_line(&iter);
    column = gtk_text_iter_get_line_offset(&iter);
#endif

    /* Given the column and row, determine which byte offset
     * the user clicked on. */
    if (column >= digits_start_1 && column <= digits_end_1) {
        byte = byte_num(column, digits_start_1);
        if (byte == -1) {
            return FALSE;
        }
    }
    else if (column >= digits_start_2 && column <= digits_end_2) {
        byte = byte_num(column, digits_start_2);
        if (byte == -1) {
            return FALSE;
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
        return FALSE;
    }

    /* Add the number of bytes from the previous rows. */
    byte += row * 16;

    /* Get the data source tvbuff */
    tvb = OBJECT_GET_DATA(widget, E_BYTE_VIEW_TVBUFF_KEY);

    /* Find the finfo that corresponds to our byte. */
    finfo = proto_find_field_from_offset(tree, byte, tvb);

    if (!finfo) {
        return FALSE;
    }

#if GTK_MAJOR_VERSION < 2
    node = gtk_ctree_find_by_row_data(ctree, NULL, finfo);
    g_assert(node);

    /* Expand and select our field's row */
    gtk_ctree_expand(ctree, node);
    gtk_ctree_select(ctree, node);
    expand_tree(ctree, node, NULL);

    /* ... and its parents */
    parent = GTK_CTREE_ROW(node)->parent;
    while (parent) {
        gtk_ctree_expand(ctree, parent);
        expand_tree(ctree, parent, NULL);
        parent = GTK_CTREE_ROW(parent)->parent;
    }

    /* And position the window so the selection is visible.
     * Position the selection in the middle of the viewable
     * pane. */
    gtk_ctree_node_moveto(ctree, node, 0, .5, 0);

    return FALSE;
#else
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

    /* select our field's row */
    gtk_tree_selection_select_path(gtk_tree_view_get_selection(tree_view),
                                   first_path);

    /* And position the window so the selection is visible.
     * Position the selection in the middle of the viewable
     * pane. */
    gtk_tree_view_scroll_to_cell(tree_view, first_path, NULL, TRUE, 0.5, 0.0);

    gtk_tree_path_free(first_path);

    return TRUE;
#endif
}

/* Calls functions for different mouse-button presses. */
static gint
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
#if GTK_MAJOR_VERSION >= 2
  GtkTextBuffer *buf;
  GtkStyle      *style;
#endif

  /* Byte view.  Create a scrolled window for the text. */
  byte_scrollw = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION < 2
  /* The horizontal scrollbar of the scroll-window doesn't seem
   * to affect the GtkText widget at all, even when line wrapping
   * is turned off in the GtkText widget and there is indeed more
   * horizontal data. */
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(byte_scrollw),
			/* Horizontal */GTK_POLICY_NEVER,
			/* Vertical*/	GTK_POLICY_ALWAYS);
#else
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(byte_scrollw),
                                   GTK_SHADOW_IN);
#endif
  /* Add scrolled pane to tabbed window */
  label = gtk_label_new(name);
  gtk_notebook_append_page(GTK_NOTEBOOK(byte_nb), byte_scrollw, label);

  gtk_widget_show(byte_scrollw);

#if GTK_MAJOR_VERSION < 2
  byte_view = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(byte_view), FALSE);
#else
  byte_view = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(byte_view), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(byte_view), FALSE);
  buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(byte_view));
  style = gtk_widget_get_style(GTK_WIDGET(byte_view));
  gtk_text_buffer_create_tag(buf, "plain", "font-desc", user_font_get_regular(), NULL);
  gtk_text_buffer_create_tag(buf, "reverse",
                             "font-desc", user_font_get_regular(),
                             "foreground-gdk", &style->text[GTK_STATE_SELECTED],
                             "background-gdk", &style->base[GTK_STATE_SELECTED],
                             NULL);
  gtk_text_buffer_create_tag(buf, "bold", "font-desc", user_font_get_bold(), NULL);
#endif
  OBJECT_SET_DATA(byte_view, E_BYTE_VIEW_TVBUFF_KEY, tvb);
  gtk_container_add(GTK_CONTAINER(byte_scrollw), byte_view);

  SIGNAL_CONNECT(byte_view, "show", byte_view_realize_cb, NULL);
  SIGNAL_CONNECT(byte_view, "button_press_event", byte_view_button_press_cb,
                 OBJECT_GET_DATA(popup_menu_object, PM_HEXDUMP_KEY));

  OBJECT_SET_DATA(byte_view, E_BYTE_VIEW_TREE_PTR, tree);
  OBJECT_SET_DATA(byte_view, E_BYTE_VIEW_TREE_VIEW_PTR, tree_view);

  gtk_widget_show(byte_view);

  /* no tabs if this is the first page */
  if (!(gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_scrollw)))
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), FALSE);
  else
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), TRUE);

  /* set this page (this will print the packet data) */
  gtk_notebook_set_page(GTK_NOTEBOOK(byte_nb),
    gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_nb));

  return byte_view;
}

void
add_main_byte_views(epan_dissect_t *edt)
{
    add_byte_views(edt, tree_view, byte_nb_ptr);
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
		add_byte_tab(byte_nb_ptr, src->name, src->tvb, edt->tree,
                             tree_view);
	}

	/*
	 * Initially select the first byte view.
	 */
	gtk_notebook_set_page(GTK_NOTEBOOK(byte_nb_ptr), 0);
}



static GtkWidget *savehex_dlg=NULL;

static void
savehex_dlg_destroy_cb(void)
{
        savehex_dlg = NULL;
}

void
copy_hex_cb(GtkWidget * w _U_, gpointer data _U_, int data_type)
{
	GtkWidget *bv;
	int len;
	int i=0;
	const guint8 *data_p = NULL;
	GString *ASCII_representation = g_string_new("");
	GString *byte_str = g_string_new("");
	GString *text_str = g_string_new("");

	bv = get_notebook_bv_ptr(byte_nb_ptr);
	if (bv == NULL) {
		/* shouldn't happen */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
		return;
	}

	data_p = get_byte_view_data_and_length(bv, &len);
	g_assert(data_p != NULL);
        
    g_string_sprintfa(byte_str,"%04x  ",i); /* Offset 0000 */
	for (i=0; i<len; i++){
        if (data_type==1) {
            if (isprint(*data_p)) {
                g_string_sprintfa(ASCII_representation,"%c", *data_p);
            }
            else
            {
                if (*data_p==0x0a) {
                    g_string_sprintfa(ASCII_representation,"\n");
                }
            }
        }
        else
        {
            g_string_sprintfa(ASCII_representation,"%c",isprint(*data_p) ? *data_p : '.');
        }
        g_string_sprintfa(byte_str," %02x",*data_p++);
        if ((i+1)%16==0 && i!=0){
            g_string_sprintfa(byte_str,"  %s\n%04x  ",ASCII_representation->str,i+1);
            g_string_sprintfa(text_str,"%s",ASCII_representation->str);
            
            g_string_assign (ASCII_representation,"");
        }
	}

	if(ASCII_representation->len){
	  for (i=ASCII_representation->len; i<16; i++){
	    g_string_sprintfa(byte_str,"   ");
	  }
	  g_string_sprintfa(byte_str,"  %s\n",ASCII_representation->str);
	  g_string_sprintfa(text_str,"%s",ASCII_representation->str);
	}
	/* Now that we have the byte data, copy it into the default clipboard */
    if (data_type==1) {
        copy_to_clipboard(text_str);
    }
    else
    {
        copy_to_clipboard(byte_str);
    }
	g_string_free(byte_str, TRUE);                       /* Free the memory */
	g_string_free(text_str, TRUE);                       /* Free the memory */
	g_string_free(ASCII_representation, TRUE);           /* Free the memory */
}

/* save the current highlighted hex data */
static void
savehex_save_clicked_cb(GtkWidget * w _U_, gpointer data _U_)
{
        GtkWidget *bv;
	int fd, start, end, len;
	const guint8 *data_p = NULL;
	const char *file = NULL;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
	file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(savehex_dlg));
#else
	file = gtk_file_selection_get_filename(GTK_FILE_SELECTION(savehex_dlg));
#endif

	if (!file ||! *file) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Please enter a filename!");
		return;
	}

	/* Must check if file name exists first */

	bv = get_notebook_bv_ptr(byte_nb_ptr);
	if (bv == NULL) {
		/* shouldn't happen */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
		return;
	}
	/*
	 * Retrieve the info we need
	 */
	end = GPOINTER_TO_INT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_START_KEY));
	start = GPOINTER_TO_INT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_END_KEY));
	data_p = get_byte_view_data_and_length(bv, &len);

	if (data_p == NULL || start == -1 || start > end) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "No data selected to save!");
		return;
	}

	fd = eth_open(file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
	if (fd == -1) {
		open_failure_alert_box(file, errno, TRUE);
		return;
	}
	if (eth_write(fd, data_p + start, end - start) < 0) {
		write_failure_alert_box(file, errno);
		eth_close(fd);
		return;
	}
	if (eth_close(fd) < 0) {
		write_failure_alert_box(file, errno);
		return;
	}

	/* Get rid of the dialog box */
	window_destroy(GTK_WIDGET(savehex_dlg));
}

/* Launch the dialog box to put up the file selection box etc */
void savehex_cb(GtkWidget * w _U_, gpointer data _U_)
{
	int start, end, len;
	const guint8 *data_p = NULL;
        gchar *label;

        GtkWidget   *bv;
	GtkWidget   *dlg_lb;

#if GTK_MAJOR_VERSION >= 2 && _WIN32
	win32_export_raw_file(GDK_WINDOW_HWND(top_level->window));
	return;
#endif

    /* don't show up the dialog, if no data has to be saved */
	bv = get_notebook_bv_ptr(byte_nb_ptr);
	if (bv == NULL) {
		/* shouldn't happen */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
		return;
	}
	end = GPOINTER_TO_INT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_START_KEY));
	start = GPOINTER_TO_INT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_END_KEY));
	data_p = get_byte_view_data_and_length(bv, &len);

	if (data_p == NULL || start == -1 || start > end) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No data selected to save!");
		return;
	}

    /* if the window is already open, bring it to front */
	if(savehex_dlg){
		reactivate_window(savehex_dlg);
		return;
	}

	/*
	 * Build the dialog box we need.
	 */
    savehex_dlg = file_selection_new("Wireshark: Export Selected Packet Bytes", FILE_SELECTION_SAVE);

    /* label */
    label = g_strdup_printf("Will save %u %s of raw binary data to specified file.",
        end - start, plurality(end - start, "byte", "bytes"));
    dlg_lb = gtk_label_new(label);
    g_free(label);
    file_selection_set_extra_widget(savehex_dlg, dlg_lb);
	gtk_widget_show(dlg_lb);

    SIGNAL_CONNECT(savehex_dlg, "destroy", savehex_dlg_destroy_cb, NULL);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    if (gtk_dialog_run(GTK_DIALOG(savehex_dlg)) == GTK_RESPONSE_ACCEPT) {
        savehex_save_clicked_cb(savehex_dlg, savehex_dlg);
    } else {
        window_destroy(savehex_dlg);
    }
#else
    /* Connect the ok_button to file_save_as_ok_cb function and pass along a
    pointer to the file selection box widget */
    SIGNAL_CONNECT(GTK_FILE_SELECTION (savehex_dlg)->ok_button, "clicked",
        savehex_save_clicked_cb, savehex_dlg);

    window_set_cancel_button(savehex_dlg,
    GTK_FILE_SELECTION(savehex_dlg)->cancel_button, window_cancel_button_cb);

    SIGNAL_CONNECT(savehex_dlg, "delete_event", window_delete_event_cb, NULL);

    gtk_file_selection_set_filename(GTK_FILE_SELECTION(savehex_dlg), "");

    gtk_widget_show_all(savehex_dlg);
    window_present(savehex_dlg);
#endif
}



/* Update the progress bar this many times when reading a file. */
#define N_PROGBAR_UPDATES	100


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
packet_hex_print_common(GtkWidget *bv, const guint8 *pd, int len, int bstart,
			int bend, int encoding)
{
  int            i = 0, j, k, cur;
  guchar         line[MAX_LINE_LEN + 1];
  static guchar  hexchars[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  guchar         c = '\0';
  unsigned int   use_digits;
  gboolean       reverse, newreverse;
#if GTK_MAJOR_VERSION < 2
  GdkFont       *cur_font, *new_font;
  GdkColor      *fg, *bg;
  GtkTextView   *bv_text = GTK_TEXT(bv);
#else
  GtkTextView   *bv_text_view = GTK_TEXT_VIEW(bv);
  GtkTextBuffer *buf = gtk_text_view_get_buffer(bv_text_view);
  GtkTextIter    iter;
  const char    *revstyle;
  gchar         *convline;
  gsize          newsize;
  GtkTextMark   *mark = NULL;
#endif

  progdlg_t  *progbar = NULL;
  float       progbar_val;
  gboolean    progbar_stop_flag;
  GTimeVal    progbar_start_time;
  gchar       progbar_status_str[100];
  int         progbar_nextstep;
  int         progbar_quantum;

#if GTK_MAJOR_VERSION < 2
  /* Freeze the text for faster display */
  gtk_text_freeze(bv_text);

  /* Clear out the text */
  gtk_text_set_point(bv_text, 0);
  /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see
     http://www.ethereal.com/lists/ethereal-dev/199912/msg00312.html and
     http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
     for more information */
  gtk_adjustment_set_value(bv_text->vadj, 0.0);
  gtk_text_forward_delete(bv_text, gtk_text_get_length(bv_text));
#else
  gtk_text_buffer_set_text(buf, "", 0);
  gtk_text_buffer_get_start_iter(buf, &iter);
#endif

  /*
   * How many of the leading digits of the offset will we supply?
   * We always supply at least 4 digits, but if the maximum offset
   * won't fit in 4 digits, we use as many digits as will be needed.
   */
  if (((len - 1) & 0xF0000000) != 0)
    use_digits = 8;	/* need all 8 digits */
  else if (((len - 1) & 0x0F000000) != 0)
    use_digits = 7;	/* need 7 digits */
  else if (((len - 1) & 0x00F00000) != 0)
    use_digits = 6;	/* need 6 digits */
  else if (((len - 1) & 0x000F0000) != 0)
    use_digits = 5;	/* need 5 digits */
  else
    use_digits = 4;	/* we'll supply 4 digits */

  /* Record the number of digits in this text view. */
  OBJECT_SET_DATA(bv, E_BYTE_VIEW_NDIGITS_KEY, GUINT_TO_POINTER(use_digits));

  /* Update the progress bar when it gets to this value. */
  progbar_nextstep = 0;
  /* When we reach the value that triggers a progress bar update,
     bump that value by this amount. */
  progbar_quantum = len/N_PROGBAR_UPDATES;
  /* Progress so far. */
  progbar_val = 0.0;

  progbar_stop_flag = FALSE;
  g_get_current_time(&progbar_start_time);

  while (i < len) {
    /* Create the progress bar if necessary.
       We check on every iteration of the loop, so that it takes no
       longer than the standard time to create it (otherwise, for a
       large packet, we might take considerably longer than that standard
       time in order to get to the next progress bar step). */
    if (progbar == NULL)
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
      /* let's not divide by zero. I should never be started
       * with count == 0, so let's assert that
       */
      g_assert(len > 0);
      progbar_val = (gfloat) i / len;

      if (progbar != NULL) {
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
    cur = 0;
    do {
      j--;
      c = (i >> (j*4)) & 0xF;
      line[cur++] = hexchars[c];
    } while (j != 0);
    line[cur++] = ' ';
    line[cur++] = ' ';
    line[cur] = '\0';

    /* Display with inverse video ? */
#if GTK_MAJOR_VERSION < 2
    if (prefs.gui_hex_dump_highlight_style) {
      gtk_text_insert(bv_text, user_font_get_regular(), &BLACK, &WHITE, line, -1);
      /* Do we start in reverse? */
      reverse = i >= bstart && i < bend;
      fg = reverse ? &WHITE : &BLACK;
      bg = reverse ? &BLACK : &WHITE;
      j   = i;
      k   = i + BYTE_VIEW_WIDTH;
      cur = 0;
      /* Print the hex bit */
      while (i < k) {
	if (i < len) {
	  line[cur++] = hexchars[(pd[i] & 0xf0) >> 4];
	  line[cur++] = hexchars[pd[i] & 0x0f];
	} else {
	  line[cur++] = ' '; line[cur++] = ' ';
	}
	i++;
	newreverse = i >= bstart && i < bend;
	/* Have we gone from reverse to plain? */
	if (reverse && (reverse != newreverse)) {
	  gtk_text_insert(bv_text, user_font_get_regular(), fg, bg, line, cur);
	  fg = &BLACK;
	  bg = &WHITE;
	  cur = 0;
	}
	/* Inter byte space if not at end of line */
	if (i < k) {
	  line[cur++] = ' ';
	  /* insert a space every BYTE_VIEW_SEP bytes */
	  if( ( i % BYTE_VIEW_SEP ) == 0 ) {
	    line[cur++] = ' ';
	  }
	}
	/* Have we gone from plain to reversed? */
	if (!reverse && (reverse != newreverse)) {
	  gtk_text_insert(bv_text, user_font_get_regular(), fg, bg, line, cur);
	  fg = &WHITE;
	  bg = &BLACK;
	  cur = 0;
	}
	reverse = newreverse;
      }
      /* Print remaining part of line */
      gtk_text_insert(bv_text, user_font_get_regular(), fg, bg, line, cur);
      cur = 0;
      /* Print some space at the end of the line */
      line[cur++] = ' '; line[cur++] = ' '; line[cur++] = ' ';
      gtk_text_insert(bv_text, user_font_get_regular(), &BLACK, &WHITE, line, cur);
      cur = 0;

      /* Print the ASCII bit */
      i = j;
      /* Do we start in reverse? */
      reverse = i >= bstart && i < bend;
      fg = reverse ? &WHITE : &BLACK;
      bg = reverse ? &BLACK : &WHITE;
      while (i < k) {
	if (i < len) {
	  if (encoding == CHAR_ASCII) {
	    c = pd[i];
	  }
	  else if (encoding == CHAR_EBCDIC) {
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
	newreverse = i >= bstart && i < bend;
	/* Have we gone from reverse to plain? */
	if (reverse && (reverse != newreverse)) {
	  gtk_text_insert(bv_text, user_font_get_regular(), fg, bg, line, cur);
	  fg = &BLACK;
	  bg = &WHITE;
	  cur = 0;
	}
	if (i < k) {
	  /* insert a space every BYTE_VIEW_SEP bytes */
	  if( ( i % BYTE_VIEW_SEP ) == 0 ) {
	    line[cur++] = ' ';
	  }
	}
	/* Have we gone from plain to reversed? */
	if (!reverse && (reverse != newreverse)) {
	  gtk_text_insert(bv_text, user_font_get_regular(), fg, bg, line, cur);
	  fg = &WHITE;
	  bg = &BLACK;
	  cur = 0;
	}
	reverse = newreverse;
      }
      /* Print remaining part of line */
      gtk_text_insert(bv_text, user_font_get_regular(), fg, bg, line, cur);
      cur = 0;
      line[cur++] = '\n';
      line[cur]   = '\0';
      gtk_text_insert(bv_text, user_font_get_regular(), &BLACK, &WHITE, line, -1);
    }
    else {
      gtk_text_insert(bv_text, user_font_get_regular(), NULL, NULL, line, -1);
      /* Do we start in bold? */
      cur_font = (i >= bstart && i < bend) ? user_font_get_bold() : user_font_get_regular();
      j   = i;
      k   = i + BYTE_VIEW_WIDTH;
      cur = 0;
      /* Print the hex bit */
      while (i < k) {
	if (i < len) {
	  line[cur++] = hexchars[(pd[i] & 0xf0) >> 4];
	  line[cur++] = hexchars[pd[i] & 0x0f];
	} else {
	  line[cur++] = ' '; line[cur++] = ' ';
	}
	line[cur++] = ' ';
	i++;
	/* insert a space every BYTE_VIEW_SEP bytes */
	if( ( i % BYTE_VIEW_SEP ) == 0 ) line[cur++] = ' ';
	/* Did we cross a bold/plain boundary? */
	new_font = (i >= bstart && i < bend) ? user_font_get_bold() : user_font_get_regular();
	if (cur_font != new_font) {
	  gtk_text_insert(bv_text, cur_font, NULL, NULL, line, cur);
	  cur_font = new_font;
	  cur = 0;
	}
      }
      line[cur++] = ' ';
      gtk_text_insert(bv_text, cur_font, NULL, NULL, line, cur);

      cur = 0;
      i = j;
      /* Print the ASCII bit */
      cur_font = (i >= bstart && i < bend) ? user_font_get_bold() : user_font_get_regular();
      while (i < k) {
	if (i < len) {
	  if (encoding == CHAR_ASCII) {
	    c = pd[i];
	  }
	  else if (encoding == CHAR_EBCDIC) {
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
	/* insert a space every BYTE_VIEW_SEP bytes */
	if( ( i % BYTE_VIEW_SEP ) == 0 ) line[cur++] = ' ';
	/* Did we cross a bold/plain boundary? */
	new_font = (i >= bstart && i < bend) ? user_font_get_bold() : user_font_get_regular();
	if (cur_font != new_font) {
	  gtk_text_insert(bv_text, cur_font, NULL, NULL, line, cur);
	  cur_font = new_font;
	  cur = 0;
	}
      }
      line[cur++] = '\n';
      line[cur]   = '\0';
      gtk_text_insert(bv_text, cur_font, NULL, NULL, line, -1);
    }
#else
    if (prefs.gui_hex_dump_highlight_style)
      revstyle = "reverse";
    else
      revstyle = "bold";

    gtk_text_buffer_insert_with_tags_by_name(buf, &iter, line, -1, "plain",
                                             NULL);
    /* Do we start in reverse? */
    reverse = i >= bstart && i < bend;
    j   = i;
    k   = i + BYTE_VIEW_WIDTH;
    cur = 0;
    /* Print the hex bit */
    while (i < k) {
      if (i < len) {
        line[cur++] = hexchars[(pd[i] & 0xf0) >> 4];
        line[cur++] = hexchars[pd[i] & 0x0f];
      } else {
        line[cur++] = ' '; line[cur++] = ' ';
      }
      i++;
      newreverse = i >= bstart && i < bend;
      /* Have we gone from reverse to plain? */
      if (reverse && (reverse != newreverse)) {
        gtk_text_buffer_insert_with_tags_by_name(buf, &iter, line, cur,
                                                 revstyle, NULL);
        cur = 0;
      }
      /* Inter byte space if not at end of line */
      if (i < k) {
        line[cur++] = ' ';
        /* insert a space every BYTE_VIEW_SEP bytes */
        if( ( i % BYTE_VIEW_SEP ) == 0 ) {
          line[cur++] = ' ';
        }
      }
      /* Have we gone from plain to reversed? */
      if (!reverse && (reverse != newreverse)) {
        gtk_text_buffer_insert_with_tags_by_name(buf, &iter, line, cur,
                                                 "plain", NULL);
        mark = gtk_text_buffer_create_mark(buf, NULL, &iter, TRUE);
        cur = 0;
      }
      reverse = newreverse;
    }
    /* Print remaining part of line */
    gtk_text_buffer_insert_with_tags_by_name(buf, &iter, line, cur,
                                             reverse ? revstyle : "plain",
                                             NULL);
    cur = 0;
    /* Print some space at the end of the line */
    line[cur++] = ' '; line[cur++] = ' '; line[cur++] = ' ';
    gtk_text_buffer_insert_with_tags_by_name(buf, &iter, line, cur,
                                             "plain", NULL);
    cur = 0;

    /* Print the ASCII bit */
    i = j;
    /* Do we start in reverse? */
    reverse = i >= bstart && i < bend;
    while (i < k) {
      if (i < len) {
        if (encoding == CHAR_ASCII) {
          c = pd[i];
        }
        else if (encoding == CHAR_EBCDIC) {
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
      newreverse = i >= bstart && i < bend;
      /* Have we gone from reverse to plain? */
      if (reverse && (reverse != newreverse)) {
        convline = g_locale_to_utf8(line, cur, NULL, &newsize, NULL);
        gtk_text_buffer_insert_with_tags_by_name(buf, &iter, convline, newsize,
                                                 revstyle, NULL);
        g_free( (gpointer) convline);
        cur = 0;
      }
      if (i < k) {
        /* insert a space every BYTE_VIEW_SEP bytes */
        if( ( i % BYTE_VIEW_SEP ) == 0 ) {
          line[cur++] = ' ';
        }
      }
      /* Have we gone from plain to reversed? */
      if (!reverse && (reverse != newreverse)) {
        convline = g_locale_to_utf8(line, cur, NULL, &newsize, NULL);
        gtk_text_buffer_insert_with_tags_by_name(buf, &iter, convline, newsize,
                                                 "plain", NULL);
        g_free( (gpointer) convline);
        cur = 0;
      }
      reverse = newreverse;
    }
    /* Print remaining part of line */
    convline = g_locale_to_utf8(line, cur, NULL, &newsize, NULL);
    gtk_text_buffer_insert_with_tags_by_name(buf, &iter, convline, newsize,
                                             reverse ? revstyle : "plain",
                                             NULL);
    g_free( (gpointer) convline);
    cur = 0;
    line[cur++] = '\n';
    gtk_text_buffer_insert_with_tags_by_name(buf, &iter, line, cur,
                                             "plain", NULL);
#endif
  }

  /* We're done printing the packets; destroy the progress bar if
     it was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);

  /* scroll text into position */
#if GTK_MAJOR_VERSION < 2
  gtk_text_thaw(bv_text); /* must thaw before adjusting scroll bars */
  if ( bstart > 0 ) {
    int linenum;
    float scrollval;

    linenum = bstart / BYTE_VIEW_WIDTH;
    scrollval = MIN(linenum * user_font_get_regular_height(),
		    bv_text->vadj->upper - bv_text->vadj->page_size);

    gtk_adjustment_set_value(bv_text->vadj, scrollval);
  }
#else
  if (mark) {
    gtk_text_view_scroll_to_mark(bv_text_view, mark, 0.0, TRUE, 1.0, 0.0);
    gtk_text_buffer_delete_mark(buf, mark);
  }
#endif
}

void
packet_hex_print(GtkWidget *bv, const guint8 *pd, frame_data *fd,
		 field_info *finfo, guint len)
{
  /* do the initial printing and save the information needed 	*/
  /* to redraw the display if preferences change.		*/

  int bstart, bend = -1, blen;

  if (finfo != NULL) {
    bstart = finfo->start;
    blen = finfo->length;
  } else {
    bstart = -1;
    blen = -1;
  }
  if (bstart >= 0 && blen >= 0) {
    bend = bstart + blen;
  }

  /* save the information needed to redraw the text */
  /* should we save the fd & finfo pointers instead ?? */
  OBJECT_SET_DATA(bv, E_BYTE_VIEW_START_KEY, GINT_TO_POINTER(bend));
  OBJECT_SET_DATA(bv, E_BYTE_VIEW_END_KEY, GINT_TO_POINTER(bstart));
  OBJECT_SET_DATA(bv, E_BYTE_VIEW_ENCODE_KEY,
                  GINT_TO_POINTER(fd->flags.encoding));

  packet_hex_print_common(bv, pd, len, bstart, bend, fd->flags.encoding);
}

/*
 * Redraw the text using the saved information; usually called if
 * the preferences have changed.
 */
void
packet_hex_reprint(GtkWidget *bv)
{
  int start, end, encoding;
  const guint8 *data;
  guint len;

  start = GPOINTER_TO_INT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_START_KEY));
  end = GPOINTER_TO_INT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_END_KEY));
  data = get_byte_view_data_and_length(bv, &len);
  g_assert(data != NULL);
  encoding = GPOINTER_TO_INT(OBJECT_GET_DATA(bv, E_BYTE_VIEW_ENCODE_KEY));

  packet_hex_print_common(bv, data, len, start, end, encoding);
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
  SIGNAL_CONNECT(ptreew, "destroy", forget_ptree_widget, NULL);
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
#if GTK_MAJOR_VERSION >= 2
    GtkTreeSelection *selection;

    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
#endif
    /* Yeah, GTK uses "browse" in the case where we do not, but oh well.
       I think "browse" in Wireshark makes more sense than "SINGLE" in
       GTK+ */
    if (val) {
#if GTK_MAJOR_VERSION < 2
        gtk_clist_set_selection_mode(GTK_CLIST(tree),
                                     GTK_SELECTION_SINGLE);
#else
        gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
#endif
    }
    else {
#if GTK_MAJOR_VERSION < 2
        gtk_clist_set_selection_mode(GTK_CLIST(tree),
                                     GTK_SELECTION_BROWSE);
#else
        gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
#endif
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

#if GTK_MAJOR_VERSION < 2
static void
set_ptree_style_cb(gpointer data, gpointer user_data)
{
	gtk_widget_set_style((GtkWidget *)data, (GtkStyle *)user_data);
}
#else
static void
set_ptree_font_cb(gpointer data, gpointer user_data)
{
	gtk_widget_modify_font((GtkWidget *)data,
                               (PangoFontDescription *)user_data);
}
#endif

void
set_ptree_font_all(FONT_TYPE *font)
{
#if GTK_MAJOR_VERSION < 2
    GtkStyle *style;

    style = gtk_style_new();
    gdk_font_unref(style->font);
    style->font = font;
    gdk_font_ref(font);

    g_list_foreach(ptree_widgets, set_ptree_style_cb, style);

    /* Now nuke the old style and replace it with the new one. */
    gtk_style_unref(item_style);
    item_style = style;
#else
    g_list_foreach(ptree_widgets, set_ptree_font_cb, font);
#endif
}


gboolean colors_ok = FALSE;
GdkColor	expert_color_chat	= { 0, 0xcc00, 0xcc00, 0xe000 };	/* a pale bluegrey */
GdkColor	expert_color_note	= { 0, 0xa000, 0xff00, 0xff00 };	/* a bright turquoise */
GdkColor	expert_color_warn	= { 0, 0xff00, 0xff00, 0 };			/* yellow */
GdkColor	expert_color_error	= { 0, 0xff00, 0x5c00, 0x5c00 };	/* pale red */

void proto_draw_colors_init(void)
{
	if(colors_ok) {
		return;
	}

	get_color(&expert_color_chat);
	get_color(&expert_color_note);
	get_color(&expert_color_warn);
	get_color(&expert_color_error);

	colors_ok = TRUE;
}


#if GTK_MAJOR_VERSION >= 2
static void tree_cell_renderer(GtkTreeViewColumn *tree_column _U_,
                                             GtkCellRenderer *cell,
                                             GtkTreeModel *tree_model,
                                             GtkTreeIter *iter,
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

    g_object_set (cell, "background", "white", NULL);
    g_object_set (cell, "background-set", TRUE, NULL);

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

    if(fi->hfinfo->type == FT_PROTOCOL) {
        g_object_set (cell, "background", "gray90", NULL);
        g_object_set (cell, "background-set", TRUE, NULL);
        /*g_object_set (cell, "weight", PANGO_WEIGHT_BOLD, NULL);
        g_object_set (cell, "weight-set", TRUE, NULL);*/
	}

    if((fi->hfinfo->type == FT_FRAMENUM) ||
       (FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type))) {
        g_object_set (cell, "foreground", "blue", NULL);
        g_object_set (cell, "foreground-set", TRUE, NULL);

        g_object_set (cell, "underline", PANGO_UNDERLINE_SINGLE, NULL);
        g_object_set (cell, "underline-set", TRUE, NULL);
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
	}
}
#endif


#if GTK_MAJOR_VERSION >= 2
static int
tree_view_key_pressed_cb(GtkCTree *ctree _U_, GdkEventKey *event, gpointer user_data _U_)
{
    GtkTreeSelection* selection;
    GtkTreeIter iter;
    GtkTreeIter parent;
    GtkTreeModel* model;
    GtkTreePath* path;
    gboolean    expanded;
    gboolean    has_parent;


    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
    if(!selection) {
        return FALSE;
    }

    if(!gtk_tree_selection_get_selected (selection, &model, &iter)) {
        return FALSE;
    }

    path = gtk_tree_model_get_path(model, &iter);
    if(!path) {
        return FALSE;
    }

    if (event->keyval == GDK_Left) {
        expanded = gtk_tree_view_row_expanded(GTK_TREE_VIEW(tree_view), path);
        if(expanded) {
            /* subtree is expanded, collapse it */
            gtk_tree_view_collapse_row(GTK_TREE_VIEW(tree_view), path);
            return TRUE;
        } else {
            /* subtree is already collapsed, jump to parent node */
            has_parent = gtk_tree_model_iter_parent(model, &parent, &iter);
            path = gtk_tree_model_get_path(model, &parent);
            if(!path) {
                return FALSE;
            }
            gtk_tree_view_set_cursor(GTK_TREE_VIEW(tree_view), path,
                                             NULL /* focus_column */,
                                             FALSE /* !start_editing */);
            return TRUE;
        }
    }
    if (event->keyval == GDK_Right) {
        /* try to expand the subtree */
        gtk_tree_view_expand_row(GTK_TREE_VIEW(tree_view), path, FALSE /* !open_all */);
        return TRUE;
    }

    return FALSE;
}
#endif



GtkWidget *
main_tree_view_new(e_prefs *prefs, GtkWidget **tree_view_p)
{
  GtkWidget *tv_scrollw, *tree_view;
#if GTK_MAJOR_VERSION >= 2
  GtkTreeStore *store;
  GtkCellRenderer *renderer;
  GtkTreeViewColumn *column;
  gint col_offset;
#endif

  /* Tree view */
  tv_scrollw = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(tv_scrollw),
                                   GTK_SHADOW_IN);
#endif

#if GTK_MAJOR_VERSION < 2
  tree_view = ctree_new(1, 0);
  SIGNAL_CONNECT(tree_view, "key-press-event", toggle_tree, NULL );
  SIGNAL_CONNECT(tree_view, "tree-expand", expand_tree, NULL );
  SIGNAL_CONNECT(tree_view, "tree-collapse", collapse_tree, NULL );
  /* I need this next line to make the widget work correctly with hidden
   * column titles and GTK_SELECTION_BROWSE */
  gtk_clist_set_column_auto_resize( GTK_CLIST(tree_view), 0, TRUE );
#else
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
  gtk_tree_view_column_set_cell_data_func(column,
                                             renderer,
                                             tree_cell_renderer,
                                             NULL,
                                             NULL);

  gtk_tree_view_column_set_sizing(GTK_TREE_VIEW_COLUMN(column),
                                  GTK_TREE_VIEW_COLUMN_AUTOSIZE);
  SIGNAL_CONNECT(tree_view, "row-expanded", expand_tree, NULL);
  SIGNAL_CONNECT(tree_view, "row-collapsed", collapse_tree, NULL);
  SIGNAL_CONNECT(tree_view, "key-press-event", tree_view_key_pressed_cb, NULL );
#endif
  gtk_container_add( GTK_CONTAINER(tv_scrollw), tree_view );
  set_ptree_sel_browse(tree_view, prefs->gui_ptree_sel_browse);
#if GTK_MAJOR_VERSION < 2
  if(item_style == NULL) {
      item_style = gtk_style_new();
      gdk_font_unref(item_style->font);
      item_style->font = user_font_get_regular();
  }

  gtk_widget_set_style(tree_view, item_style);
#else
  gtk_widget_modify_font(tree_view, user_font_get_regular());
#endif
  remember_ptree_widget(tree_view);

  *tree_view_p = tree_view;

  return tv_scrollw;
}

#if GTK_MAJOR_VERSION < 2
void expand_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view)
#else
void expand_all_tree(proto_tree *protocol_tree _U_, GtkWidget *tree_view)
#endif
{
  int i;
  for(i=0; i < num_tree_types; i++) {
    tree_is_expanded[i] = TRUE;
  }
#if GTK_MAJOR_VERSION < 2
  proto_tree_draw(protocol_tree, tree_view);
  gtk_ctree_expand_recursive(GTK_CTREE(tree_view), NULL);
#else
  gtk_tree_view_expand_all(GTK_TREE_VIEW(tree_view));
#endif
}

#if GTK_MAJOR_VERSION < 2
void collapse_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view)
#else
void collapse_all_tree(proto_tree *protocol_tree _U_, GtkWidget *tree_view)
#endif
{
  int i;
  for(i=0; i < num_tree_types; i++) {
    tree_is_expanded[i] = FALSE;
  }
#if GTK_MAJOR_VERSION < 2
  proto_tree_draw(protocol_tree, tree_view);
#else
  gtk_tree_view_collapse_all(GTK_TREE_VIEW(tree_view));
#endif
}


struct proto_tree_draw_info {
#if GTK_MAJOR_VERSION < 2
    GtkCTree     *ctree;
    GtkCTreeNode *ctree_node;
#else
    GtkTreeView  *tree_view;
    GtkTreeIter	 *iter;
#endif
};

void
main_proto_tree_draw(proto_tree *protocol_tree)
{
    proto_tree_draw(protocol_tree, tree_view);
}


static void
tree_view_follow_link(field_info   *fi)
{
    gchar *url;

    if(fi->hfinfo->type == FT_FRAMENUM) {
        cf_goto_frame(&cfile, fi->value.value.integer);
    }
    if(FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type)) {
      url = g_strndup(tvb_get_ptr(fi->ds_tvb, fi->start, fi->length), fi->length);
      browser_open_url(url);
      g_free(url);
    }
}


/* If the user selected a position in the tree view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and
 * select it. */
gboolean
tree_view_select(GtkWidget *widget, GdkEventButton *event)
{
#if GTK_MAJOR_VERSION < 2
        GtkCTree     *ctree;
        GtkCTreeNode *node;
        gint         row;
        gint         column;
        field_info   *fi;


        if(gtk_clist_get_selection_info(GTK_CLIST(widget),
            (gint) (((GdkEventButton *)event)->x),
            (gint) (((GdkEventButton *)event)->y),
            &row, &column))
        {
            ctree = GTK_CTREE(widget);

            node = gtk_ctree_node_nth(ctree, row);
            g_assert(node);

            gtk_ctree_select(ctree, node);

            /* if that's a doubleclick, try to follow the link */
            if(event->type == GDK_2BUTTON_PRESS) {
                fi = gtk_ctree_node_get_row_data(ctree, node);
                tree_view_follow_link(fi);
            }
        } else {
            return FALSE;
        }
#else
        GtkTreeSelection    *sel;
        GtkTreePath         *path;

        if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
                                          (gint) (((GdkEventButton *)event)->x),
                                          (gint) (((GdkEventButton *)event)->y),
                                          &path, NULL, NULL, NULL))
        {
            sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(widget));
            gtk_tree_selection_select_path(sel, path);

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
        } else {
            return FALSE;
        }
#endif
    return TRUE;
}

/* fill the whole protocol tree with the string values */
void
proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view)
{
#if GTK_MAJOR_VERSION >= 2
    GtkTreeStore *store;
#endif
    struct proto_tree_draw_info	info;

#if GTK_MAJOR_VERSION < 2
    info.ctree = GTK_CTREE(tree_view);
    info.ctree_node = NULL;

    gtk_clist_freeze(GTK_CLIST(tree_view));
#else
    info.tree_view = GTK_TREE_VIEW(tree_view);
    info.iter = NULL;

    store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view)));
#endif

    /*
     * Clear out any crud left over in the display of the protocol
     * tree, by removing all nodes from the tree.
     * This is how it's done in testgtk.c in GTK+.
     */
#if GTK_MAJOR_VERSION < 2
    gtk_clist_clear(GTK_CLIST(tree_view));
#else
    gtk_tree_store_clear(store);
#endif

    proto_tree_children_foreach(protocol_tree, proto_tree_draw_node, &info);

#if GTK_MAJOR_VERSION < 2
    gtk_clist_thaw(GTK_CLIST(tree_view));
#endif
}


/* fill a single protocol tree item with the string value */
static void
proto_tree_draw_node(proto_node *node, gpointer data)
{
    struct proto_tree_draw_info	info;
    struct proto_tree_draw_info	*parent_info = (struct proto_tree_draw_info*) data;

    field_info   *fi = PITEM_FINFO(node);
    gchar         label_str[ITEM_LABEL_LENGTH];
    gchar        *label_ptr;
    gboolean      is_leaf, is_expanded;
#if GTK_MAJOR_VERSION < 2
    GtkCTreeNode *parent;
#else
    GtkTreeStore *store;
    GtkTreeIter   iter;
    GtkTreePath  *path;
#endif

    if (PROTO_ITEM_IS_HIDDEN(node))
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

    if(PROTO_ITEM_IS_GENERATED(node)) {
        label_ptr = g_strdup_printf("[%s]", label_ptr);
    }

#if GTK_MAJOR_VERSION < 2
    info.ctree = parent_info->ctree;
    parent = gtk_ctree_insert_node ( info.ctree, parent_info->ctree_node, NULL,
                                     &label_ptr, 5, NULL, NULL, NULL, NULL,
                                     is_leaf, is_expanded );

    gtk_ctree_node_set_row_data( GTK_CTREE(info.ctree), parent, fi );
#else
    info.tree_view = parent_info->tree_view;
    store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(info.tree_view)));
    gtk_tree_store_append(store, &iter, parent_info->iter);
    gtk_tree_store_set(store, &iter, 0, label_ptr, 1, fi, -1);
#endif

    if(PROTO_ITEM_IS_GENERATED(node)) {
        g_free(label_ptr);
    }

    if (!is_leaf) {
#if GTK_MAJOR_VERSION < 2
        info.ctree_node = parent;
#else
        info.iter = &iter;
#endif
        proto_tree_children_foreach(node, proto_tree_draw_node, &info);
#if GTK_MAJOR_VERSION >= 2
        path = gtk_tree_model_get_path(GTK_TREE_MODEL(store), &iter);
        if (is_expanded)
/* #if GTK_MINOR_VERSION >= 2 */
            gtk_tree_view_expand_to_path(info.tree_view, path);
/*#else
            gtk_tree_view_expand_row(info.tree_view, path, FALSE);
#endif*/
        else
            gtk_tree_view_collapse_row(info.tree_view, path);
        gtk_tree_path_free(path);
#endif
    }
}

/*
 * Clear the hex dump and protocol tree panes.
 */
void
clear_tree_and_hex_views(void)
{
  /* Clear the hex dump by getting rid of all the byte views. */
  while (gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr), 0) != NULL)
    gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr), 0);

  /* Add a placeholder byte view so that there's at least something
     displayed in the byte view notebook. */
  add_byte_tab(byte_nb_ptr, "", NULL, NULL, tree_view);

  /* Clear the protocol tree by removing all nodes in the ctree.
     This is how it's done in testgtk.c in GTK+ */
#if GTK_MAJOR_VERSION < 2
  gtk_clist_clear(GTK_CLIST(tree_view));
#else
  gtk_tree_store_clear(GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view))));
#endif
}

