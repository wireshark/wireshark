/* proto_draw.c
 * Routines for GTK+ packet display
 *
 * $Id: proto_draw.c,v 1.60 2002/11/03 17:38:34 oabad Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include <epan/epan_dissect.h>

#include "main.h"
#include <epan/packet.h>
#include "util.h"
#include "menu.h"
#include "keys.h"

#include "colors.h"
#include "prefs.h"
#include "proto_draw.h"
#include "packet_win.h"
#include "ui_util.h"
#include "gtkglobals.h"

#define BYTE_VIEW_WIDTH    16
#define BYTE_VIEW_SEP      8

#define E_BYTE_VIEW_TREE_PTR      "byte_view_tree_ptr"
#define E_BYTE_VIEW_TREE_VIEW_PTR "byte_view_tree_view_ptr"
#define E_BYTE_VIEW_NDIGITS_KEY   "byte_view_ndigits"
#define E_BYTE_VIEW_TVBUFF_KEY    "byte_view_tvbuff"
#define E_BYTE_VIEW_START_KEY     "byte_view_start"
#define E_BYTE_VIEW_END_KEY       "byte_view_end"
#define E_BYTE_VIEW_ENCODE_KEY    "byte_view_encode"

static GtkWidget *
add_byte_tab(GtkWidget *byte_nb, const char *name, tvbuff_t *tvb,
    proto_tree *tree, GtkWidget *tree_view);

static void
proto_tree_draw_node(GNode *node, gpointer data);

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

  byte_view_tvb = gtk_object_get_data(GTK_OBJECT(byte_view),
				      E_BYTE_VIEW_TVBUFF_KEY);
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
    bv_tvb = gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_TVBUFF_KEY);
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
#if GTK_MAJOR_VERSION < 2
      packet_hex_print(GTK_TEXT(bv), data, fd, finfo, len);
#else
      packet_hex_print(GTK_TEXT_VIEW(bv), data, fd, finfo, len);
#endif
  }
}

/* Redraw all byte view windows. */
void
redraw_hex_dump_all(void)
{
  if (cfile.current_frame != NULL)
    redraw_hex_dump( byte_nb_ptr, cfile.current_frame, finfo_selected);

  redraw_hex_dump_packet_wins();
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
#endif

/* If the user selected a certain byte in the byte view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and
 * select it. */
static gint
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
    ndigits = GPOINTER_TO_UINT(gtk_object_get_data(GTK_OBJECT(bv),
                                                   E_BYTE_VIEW_NDIGITS_KEY));

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

    tree = gtk_object_get_data(GTK_OBJECT(widget), E_BYTE_VIEW_TREE_PTR);
    if (tree == NULL) {
        /*
         * Somebody clicked on the dummy byte view; do nothing.
         */
        return FALSE;
    }
#if GTK_MAJOR_VERSION < 2
    ctree = GTK_CTREE(gtk_object_get_data(GTK_OBJECT(widget),
                                          E_BYTE_VIEW_TREE_VIEW_PTR));
#else
    tree_view = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(widget),
                                                E_BYTE_VIEW_TREE_VIEW_PTR));
#endif

#if GTK_MAJOR_VERSION < 2
    /* Given the mouse (x,y) and the current GtkText (h,v)
     * adjustments, and the size of the font, figure out
     * which text column/row the user selected. This could be off
     * if the bold version of the font is bigger than the
     * regular version of the font. */
    column = (bv->hadj->value + event->x) / m_font_width;
    row = (bv->vadj->value + event->y) / m_font_height;
#else
    /* get the row/column selected */
    gtk_text_view_window_to_buffer_coords(bv,
                         gtk_text_view_get_window_type(bv, event->window),
                         event->x, event->y, &x, &y);
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
    tvb = gtk_object_get_data(GTK_OBJECT(widget), E_BYTE_VIEW_TVBUFF_KEY);

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
create_byte_view(gint bv_size, GtkWidget *pane)
{
  GtkWidget *byte_nb;

  byte_nb = gtk_notebook_new();
  gtk_notebook_set_tab_pos(GTK_NOTEBOOK(byte_nb), GTK_POS_BOTTOM);

  gtk_paned_pack2(GTK_PANED(pane), byte_nb, FALSE, FALSE);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_set_usize(byte_nb, -1, bv_size);
#else
  gtk_widget_set_size_request(byte_nb, -1, bv_size);
#endif
  gtk_widget_show(byte_nb);

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
#if GTK_MAJOR_VERSION < 2
    packet_hex_print(GTK_TEXT(bv), byte_data, cfile.current_frame, NULL,
                     byte_len);
#else
    packet_hex_print(GTK_TEXT_VIEW(bv), byte_data, cfile.current_frame, NULL,
                     byte_len);
#endif
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

  /* Add scrolled pane to tabbed window */
  label = gtk_label_new(name);
  gtk_notebook_append_page(GTK_NOTEBOOK(byte_nb), byte_scrollw, label);

#if GTK_MAJOR_VERSION < 2
  /* The horizontal scrollbar of the scroll-window doesn't seem
   * to affect the GtkText widget at all, even when line wrapping
   * is turned off in the GtkText widget and there is indeed more
   * horizontal data. */
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(byte_scrollw),
			/* Horizontal */GTK_POLICY_NEVER,
			/* Vertical*/	GTK_POLICY_ALWAYS);
#else
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(byte_scrollw),
                                 GTK_POLICY_AUTOMATIC,
                                 GTK_POLICY_AUTOMATIC);
#endif
  gtk_widget_show(byte_scrollw);

#if GTK_MAJOR_VERSION < 2
  byte_view = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_object_set_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_TVBUFF_KEY,
		      (gpointer)tvb);
#else
  byte_view = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(byte_view), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(byte_view), FALSE);
  buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(byte_view));
  style = gtk_widget_get_style(GTK_WIDGET(byte_view));
  gtk_text_buffer_create_tag(buf, "plain", "font-desc", m_r_font, NULL);
  gtk_text_buffer_create_tag(buf, "reverse",
                             "font-desc", m_r_font,
                             "foreground-gdk", &style->text[GTK_STATE_SELECTED],
                             "background-gdk", &style->base[GTK_STATE_SELECTED],
                             NULL);
  gtk_text_buffer_create_tag(buf, "bold", "font-desc", m_b_font, NULL);
  g_object_set_data(G_OBJECT(byte_view), E_BYTE_VIEW_TVBUFF_KEY, (gpointer)tvb);
#endif
  gtk_container_add(GTK_CONTAINER(byte_scrollw), byte_view);

#if GTK_MAJOR_VERSION < 2
  gtk_signal_connect(GTK_OBJECT(byte_view), "show",
		     GTK_SIGNAL_FUNC(byte_view_realize_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(byte_view), "button_press_event",
		     GTK_SIGNAL_FUNC(byte_view_button_press_cb),
		     gtk_object_get_data(GTK_OBJECT(popup_menu_object),
					 PM_HEXDUMP_KEY));
#else
  g_signal_connect(G_OBJECT(byte_view), "show",
                   G_CALLBACK(byte_view_realize_cb), NULL);
  g_signal_connect(G_OBJECT(byte_view), "button_press_event",
                   G_CALLBACK(byte_view_button_press_cb),
                   gtk_object_get_data(GTK_OBJECT(popup_menu_object),
                                       PM_HEXDUMP_KEY));
#endif

  gtk_object_set_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_TREE_PTR,
		      tree);
  gtk_object_set_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_TREE_VIEW_PTR,
		      tree_view);

  gtk_widget_show(byte_view);

  /* no tabs if this is the first page */
  if (!(gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_scrollw)))
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), FALSE);
  else
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), TRUE);

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

#if GTK_MAJOR_VERSION < 2
static void
packet_hex_print_common(GtkText *bv, const guint8 *pd, int len, int bstart,
			int bend, int encoding)
#else
static void
packet_hex_print_common(GtkTextView *bv, const guint8 *pd, int len, int bstart,
			int bend, int encoding)
#endif
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
#else
  GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(bv));
  GtkTextIter    iter;
  char          *revstyle;
  gchar         *convline;
  gsize          newsize;
  GtkTextMark   *mark = NULL;
#endif

#if GTK_MAJOR_VERSION < 2
  /* Freeze the text for faster display */
  gtk_text_freeze(bv);

  /* Clear out the text */
  gtk_text_set_point(bv, 0);
  /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see
     http://www.ethereal.com/lists/ethereal-dev/199912/msg00312.html and
     http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
     for more information */
  gtk_adjustment_set_value(bv->vadj, 0.0);
  gtk_text_forward_delete(bv, gtk_text_get_length(bv));
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
  gtk_object_set_data(GTK_OBJECT(bv), E_BYTE_VIEW_NDIGITS_KEY,
                      GUINT_TO_POINTER(use_digits));

  while (i < len) {
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
      gtk_text_insert(bv, m_r_font, &BLACK, &WHITE, line, -1);
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
	  gtk_text_insert(bv, m_r_font, fg, bg, line, cur);
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
	  gtk_text_insert(bv, m_r_font, fg, bg, line, cur);
	  fg = &WHITE;
	  bg = &BLACK;
	  cur = 0;
	}
	reverse = newreverse;
      }
      /* Print remaining part of line */
      gtk_text_insert(bv, m_r_font, fg, bg, line, cur);
      cur = 0;
      /* Print some space at the end of the line */
      line[cur++] = ' '; line[cur++] = ' '; line[cur++] = ' ';
      gtk_text_insert(bv, m_r_font, &BLACK, &WHITE, line, cur);
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
	  gtk_text_insert(bv, m_r_font, fg, bg, line, cur);
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
	  gtk_text_insert(bv, m_r_font, fg, bg, line, cur);
	  fg = &WHITE;
	  bg = &BLACK;
	  cur = 0;
	}
	reverse = newreverse;
      }
      /* Print remaining part of line */
      gtk_text_insert(bv, m_r_font, fg, bg, line, cur);
      cur = 0;
      line[cur++] = '\n';
      line[cur]   = '\0';
      gtk_text_insert(bv, m_r_font, &BLACK, &WHITE, line, -1);
    }
    else {
      gtk_text_insert(bv, m_r_font, NULL, NULL, line, -1);
      /* Do we start in bold? */
      cur_font = (i >= bstart && i < bend) ? m_b_font : m_r_font;
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
	new_font = (i >= bstart && i < bend) ? m_b_font : m_r_font;
	if (cur_font != new_font) {
	  gtk_text_insert(bv, cur_font, NULL, NULL, line, cur);
	  cur_font = new_font;
	  cur = 0;
	}
      }
      line[cur++] = ' ';
      gtk_text_insert(bv, cur_font, NULL, NULL, line, cur);

      cur = 0;
      i = j;
      /* Print the ASCII bit */
      cur_font = (i >= bstart && i < bend) ? m_b_font : m_r_font;
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
	new_font = (i >= bstart && i < bend) ? m_b_font : m_r_font;
	if (cur_font != new_font) {
	  gtk_text_insert(bv, cur_font, NULL, NULL, line, cur);
	  cur_font = new_font;
	  cur = 0;
	}
      }
      line[cur++] = '\n';
      line[cur]   = '\0';
      gtk_text_insert(bv, cur_font, NULL, NULL, line, -1);
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
        g_free(convline);
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
        g_free(convline);
        cur = 0;
      }
      reverse = newreverse;
    }
    /* Print remaining part of line */
    convline = g_locale_to_utf8(line, cur, NULL, &newsize, NULL);
    gtk_text_buffer_insert_with_tags_by_name(buf, &iter, convline, newsize,
                                             reverse ? revstyle : "plain",
                                             NULL);
    g_free(convline);
    cur = 0;
    line[cur++] = '\n';
    gtk_text_buffer_insert_with_tags_by_name(buf, &iter, line, cur,
                                             "plain", NULL);
#endif
  }

  /* scroll text into position */
#if GTK_MAJOR_VERSION < 2
  gtk_text_thaw(bv); /* must thaw before adjusting scroll bars */
  if ( bstart > 0 ) {
    int linenum;
    float scrollval;

    linenum = bstart / BYTE_VIEW_WIDTH;
    scrollval = MIN(linenum * m_font_height,
		    bv->vadj->upper - bv->vadj->page_size);

    gtk_adjustment_set_value(bv->vadj, scrollval);
  }
#else
  if (mark) {
      gtk_text_view_scroll_to_mark(bv, mark, 0.0, TRUE, 1.0, 0.0);
      gtk_text_buffer_delete_mark(buf, mark);
  }
#endif
}

#if GTK_MAJOR_VERSION < 2
void
packet_hex_print(GtkText *bv, const guint8 *pd, frame_data *fd,
		 field_info *finfo, guint len)
#else
void
packet_hex_print(GtkTextView *bv, const guint8 *pd, frame_data *fd,
		 field_info *finfo, guint len)
#endif
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
  gtk_object_set_data(GTK_OBJECT(bv),  E_BYTE_VIEW_START_KEY, GINT_TO_POINTER(bend));
  gtk_object_set_data(GTK_OBJECT(bv),  E_BYTE_VIEW_END_KEY, GINT_TO_POINTER(bstart));
  gtk_object_set_data(GTK_OBJECT(bv),  E_BYTE_VIEW_ENCODE_KEY, GINT_TO_POINTER(fd->flags.encoding));

  packet_hex_print_common(bv, pd, len, bstart, bend, fd->flags.encoding);
}

/*
 * Redraw the text using the saved information; usually called if
 * the preferences have changed.
 */
#if GTK_MAJOR_VERSION < 2
void
packet_hex_reprint(GtkText *bv)
#else
void
packet_hex_reprint(GtkTextView *bv)
#endif
{
  int start, end, encoding;
  const guint8 *data;
  guint len;

  start = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv),
			  E_BYTE_VIEW_START_KEY));
  end = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv),
			E_BYTE_VIEW_END_KEY));
  data = get_byte_view_data_and_length(GTK_WIDGET(bv), &len);
  g_assert(data != NULL);
  encoding = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv),
			     E_BYTE_VIEW_ENCODE_KEY));

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
#if GTK_MAJOR_VERSION < 2
  gtk_signal_connect(GTK_OBJECT(ptreew), "destroy",
		     GTK_SIGNAL_FUNC(forget_ptree_widget), NULL);
#else
  g_signal_connect(G_OBJECT(ptreew), "destroy",
                   G_CALLBACK(forget_ptree_widget), NULL);
#endif
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
       I think "browse" in Ethereal makes more sense than "SINGLE" in
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

#if GTK_MAJOR_VERSION < 2
void
set_ptree_font_all(GdkFont *font)
#else
void
set_ptree_font_all(PangoFontDescription *font)
#endif
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

void
create_tree_view(gint tv_size, e_prefs *prefs, GtkWidget *pane,
		GtkWidget **tv_scrollw_p, GtkWidget **tree_view_p)
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
#if GTK_MAJOR_VERSION < 2
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(tv_scrollw),
                                  GTK_POLICY_ALWAYS, GTK_POLICY_ALWAYS);
#else
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(tv_scrollw),
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
#endif
  gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_set_usize(tv_scrollw, -1, tv_size);
#else
  gtk_widget_set_size_request(tv_scrollw, -1, tv_size);
#endif
  gtk_widget_show(tv_scrollw);

#if GTK_MAJOR_VERSION < 2
  tree_view = ctree_new(1, 0);
  gtk_signal_connect( GTK_OBJECT(tree_view), "key-press-event",
		      (GtkSignalFunc) toggle_tree, NULL );
  gtk_signal_connect( GTK_OBJECT(tree_view), "tree-expand",
		      (GtkSignalFunc) expand_tree, NULL );
  gtk_signal_connect( GTK_OBJECT(tree_view), "tree-collapse",
		      (GtkSignalFunc) collapse_tree, NULL );
  /* I need this next line to make the widget work correctly with hidden
   * column titles and GTK_SELECTION_BROWSE */
  gtk_clist_set_column_auto_resize( GTK_CLIST(tree_view), 0, TRUE );
#else
  store = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_POINTER);
  tree_view = tree_view_new(GTK_TREE_MODEL(store));
  g_object_unref(G_OBJECT(store));
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tree_view), FALSE);
  renderer = gtk_cell_renderer_text_new();
  col_offset = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tree_view),
                                                           -1, "Name", renderer,
                                                           "text", 0, NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(tree_view),
                                    col_offset - 1);
  gtk_tree_view_column_set_sizing(GTK_TREE_VIEW_COLUMN(column),
                                  GTK_TREE_VIEW_COLUMN_AUTOSIZE);
  g_signal_connect(G_OBJECT(tree_view), "row-expanded",
                   G_CALLBACK(expand_tree), NULL);
  g_signal_connect(GTK_OBJECT(tree_view), "row-collapsed",
                   G_CALLBACK(collapse_tree), NULL);
#endif
  gtk_container_add( GTK_CONTAINER(tv_scrollw), tree_view );
  set_ptree_sel_browse(tree_view, prefs->gui_ptree_sel_browse);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_set_style(tree_view, item_style);
#else
  gtk_widget_modify_font(tree_view, m_r_font);
#endif
  remember_ptree_widget(tree_view);

  *tree_view_p = tree_view;
  *tv_scrollw_p = tv_scrollw;
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

    g_node_children_foreach((GNode*) protocol_tree, G_TRAVERSE_ALL,
                            proto_tree_draw_node, &info);
#if GTK_MAJOR_VERSION < 2
    gtk_clist_thaw(GTK_CLIST(tree_view));
#endif
}

static void
proto_tree_draw_node(GNode *node, gpointer data)
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
#endif

    if (!fi->visible)
        return;

    /* was a free format label produced? */
    if (fi->representation) {
        label_ptr = fi->representation;
    }
    else { /* no, make a generic label */
        label_ptr = label_str;
        proto_item_fill_label(fi, label_str);
    }

    if (g_node_n_children(node) > 0) {
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

    if (!is_leaf) {
#if GTK_MAJOR_VERSION < 2
        info.ctree_node = parent;
#else
        info.iter = &iter;
#endif
        g_node_children_foreach(node, G_TRAVERSE_ALL,
                                proto_tree_draw_node, &info);
    }
#if GTK_MAJOR_VERSION >= 2
    if (is_expanded == TRUE)
    {
        GtkTreePath *path;
        path = gtk_tree_model_get_path(GTK_TREE_MODEL(store), &iter);
        gtk_tree_view_expand_row(info.tree_view, path, FALSE);
        gtk_tree_path_free(path);
    }
#endif
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
