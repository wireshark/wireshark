/* proto_draw.c
 * Routines for GTK+ packet display
 *
 * $Id: proto_draw.c,v 1.46 2002/02/18 01:08:44 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <ctype.h>
#include <stdarg.h>

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <stdio.h>
#include <string.h>

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
  GtkWidget *bv_page, *bv;

  num = gtk_notebook_get_current_page(GTK_NOTEBOOK(nb_ptr));
  bv_page = gtk_notebook_get_nth_page(GTK_NOTEBOOK(nb_ptr), num);
  return GTK_BIN(bv_page)->child;
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
 
  bv = get_notebook_bv_ptr(byte_nb_ptr);
  if (bv != NULL) {
    data = get_byte_view_data_and_length(bv, &len);
    if (data != NULL)
      packet_hex_print(GTK_TEXT(bv), data, fd, finfo, len);
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

static void
expand_tree(GtkCTree *ctree, GtkCTreeNode *node, gpointer user_data)
{
	field_info	*finfo;
	gboolean	*val;

	finfo = gtk_ctree_node_get_row_data( ctree, node);
	g_assert(finfo);

	val = &tree_is_expanded[finfo->tree_type];
	*val = TRUE;
}

static void
collapse_tree(GtkCTree *ctree, GtkCTreeNode *node, gpointer user_data)
{
	field_info	*finfo;
	gboolean	*val;

	finfo = gtk_ctree_node_get_row_data( ctree, node);
	g_assert(finfo);

	val = &tree_is_expanded[finfo->tree_type];
	*val = FALSE;
}

static void
toggle_tree(GtkCTree *ctree, GdkEventKey *event, gpointer user_data)
{
	if (event->keyval != GDK_Return)
		return;
	gtk_ctree_toggle_expansion(ctree, GTK_CTREE_NODE(ctree->clist.selection->data));
}

/* Which byte the offset is referring to. Associates
 * whitespace with the preceding digits. */
static int
byte_num(int offset, int start_point)
{
	return (offset - start_point) / 3;
}


/* If the user selected a certain byte in the byte view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and
 * select it. */
static gint
byte_view_select(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	proto_tree	*tree;
	GtkCTree	*ctree;
	GtkCTreeNode	*node, *parent;
	field_info	*finfo;
	GtkText		*bv = GTK_TEXT(widget);
	int		row, column;
	int		byte;
	tvbuff_t	*tvb;

	/* The column of the first hex digit in the first half */
	const int	digits_start_1 = 6;
	/* The column of the last hex digit in the first half. */
	const int	digits_end_1 = 28;

	/* The column of the first hex digit in the second half */
	const int	digits_start_2 = 31;
	/* The column of the last hex digit in the second half. */
	const int	digits_end_2 = 53;

	/* The column of the first "text dump" character in first half. */
	const int	text_start_1 = 57;
	/* The column of the last "text dump" character in first half. */
	const int	text_end_1 = 64;

	/* The column of the first "text dump" character in second half. */
	const int	text_start_2 = 66;
	/* The column of the last "text dump" character in second half. */
	const int	text_end_2 = 73;

	tree = gtk_object_get_data(GTK_OBJECT(widget), E_BYTE_VIEW_TREE_PTR);
	if (tree == NULL) {
		/*
		 * Somebody clicked on the dummy byte view; do nothing.
		 */
		return FALSE;
	}
	ctree = GTK_CTREE(gtk_object_get_data(GTK_OBJECT(widget),
					      E_BYTE_VIEW_TREE_VIEW_PTR));

	/* Given the mouse (x,y) and the current GtkText (h,v)
	 * adjustments, and the size of the font, figure out
	 * which text column/row the user selected. This could be off
	 * if the bold version of the font is bigger than the
	 * regular version of the font. */
	column = (bv->hadj->value + event->x) / m_font_width;
	row = (bv->vadj->value + event->y) / m_font_height;

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
			return byte_view_select(widget, event_button, data);
		case 3:
			return popup_menu_handler(widget, event, data);
		default:
			return FALSE;
		}
	}

	return FALSE;
}

GtkWidget *
create_byte_view(gint bv_size, GtkWidget *pane, int pos)
{
  GtkWidget *byte_nb;

  byte_nb = gtk_notebook_new();
  gtk_notebook_set_tab_pos(GTK_NOTEBOOK(byte_nb), GTK_POS_BOTTOM);

  gtk_paned_pack2(GTK_PANED(pane), byte_nb, FALSE, FALSE);
  gtk_widget_show(byte_nb);

  /* Add a placeholder byte view so that there's at least something
     displayed in the byte view notebook. */
  add_byte_tab(byte_nb, "", NULL, NULL, NULL);

  return byte_nb;
}

static void
byte_view_realize_cb(GtkWidget *bv, gpointer data)
{
 const guint8 *byte_data;
 guint byte_len;

 byte_data = get_byte_view_data_and_length(bv, &byte_len);
 if (byte_data == NULL) {
   /* This must be the dummy byte view if no packet is selected. */
   return;
 }
 packet_hex_print(GTK_TEXT(bv), byte_data, cfile.current_frame, NULL, byte_len);
}

static GtkWidget *
add_byte_tab(GtkWidget *byte_nb, const char *name, tvbuff_t *tvb,
    proto_tree *tree, GtkWidget *tree_view)
{
  GtkWidget *byte_view, *byte_scrollw, *label;

  /* Byte view.  Create a scrolled window for the text. */
  byte_scrollw = scrolled_window_new(NULL, NULL);

  /* Add scrolled pane to tabbed window */
  label = gtk_label_new(name);
  gtk_notebook_append_page(GTK_NOTEBOOK(byte_nb), byte_scrollw, label);

  /* The horizontal scrollbar of the scroll-window doesn't seem
   * to affect the GtkText widget at all, even when line wrapping
   * is turned off in the GtkText widget and there is indeed more
   * horizontal data. */
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(byte_scrollw),
			/* Horizontal */GTK_POLICY_NEVER,
			/* Vertical*/	GTK_POLICY_ALWAYS);
  gtk_widget_show(byte_scrollw);

  byte_view = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_object_set_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_TVBUFF_KEY,
		      (gpointer)tvb);
  gtk_container_add(GTK_CONTAINER(byte_scrollw), byte_view);

  gtk_signal_connect(GTK_OBJECT(byte_view), "show",
		     GTK_SIGNAL_FUNC(byte_view_realize_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(byte_view), "button_press_event",
		     GTK_SIGNAL_FUNC(byte_view_button_press_cb),
		     gtk_object_get_data(GTK_OBJECT(popup_menu_object),
					 PM_HEXDUMP_KEY));

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
add_byte_views(frame_data *frame, proto_tree *tree, GtkWidget *tree_view,
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
	for (src_le = frame->data_src; src_le != NULL; src_le = src_le->next) {
		src = src_le->data;
		add_byte_tab(byte_nb_ptr, src->name, src->tvb, tree,
		    tree_view);
	}

	/*
	 * Initially select the first byte view.
	 */
	gtk_notebook_set_page(GTK_NOTEBOOK(byte_nb_ptr), 0);
}

static void
packet_hex_print_common(GtkText *bv, const guint8 *pd, int len, int bstart,
			int bend, int encoding)
{
  int    i = 0, j, k, cur;
  guchar   line[128], hexchars[] = "0123456789abcdef", c = '\0';
  GdkFont *cur_font, *new_font;
  GdkColor *fg, *bg;
  gboolean reverse, newreverse;

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

  while (i < len) {
    /* Print the line number */
    sprintf(line, "%04x  ", i);
    
    /* Display with inverse video ? */
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
  }

  /* scroll text into position */
  gtk_text_thaw(bv); /* must thaw before adjusting scroll bars */
  if ( bstart > 0 ) {
    int linenum;
    float scrollval;

    linenum = bstart / BYTE_VIEW_WIDTH;
    scrollval = MIN(linenum * m_font_height,
		    bv->vadj->upper - bv->vadj->page_size);

    gtk_adjustment_set_value(bv->vadj, scrollval);
  }
}

void
packet_hex_print(GtkText *bv, const guint8 *pd, frame_data *fd,
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
  gtk_object_set_data(GTK_OBJECT(bv),  E_BYTE_VIEW_START_KEY, GINT_TO_POINTER(bend));
  gtk_object_set_data(GTK_OBJECT(bv),  E_BYTE_VIEW_END_KEY, GINT_TO_POINTER(bstart));
  gtk_object_set_data(GTK_OBJECT(bv),  E_BYTE_VIEW_ENCODE_KEY, GINT_TO_POINTER(fd->flags.encoding));

  packet_hex_print_common(bv, pd, len, bstart, bend, fd->flags.encoding);

}

/*
 * Redraw the text using the saved information; usually called if
 * the preferences have changed.
 */
void
packet_hex_reprint(GtkText *bv)
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
  gtk_signal_connect(GTK_OBJECT(ptreew), "destroy",
		     GTK_SIGNAL_FUNC(forget_ptree_widget), NULL);
}

/* Remove a protocol tree widget from the list of protocol tree widgets. */
static void
forget_ptree_widget(GtkWidget *ptreew, gpointer data)
{
  ptree_widgets = g_list_remove(ptree_widgets, ptreew);
}

/* Set the selection mode of a given packet tree window. */
static void
set_ptree_sel_browse(GtkWidget *ptreew, gboolean val)
{
	/* Yeah, GTK uses "browse" in the case where we do not, but oh well.
	   I think "browse" in Ethereal makes more sense than "SINGLE" in
	   GTK+ */
	if (val) {
		gtk_clist_set_selection_mode(GTK_CLIST(ptreew),
		    GTK_SELECTION_SINGLE);
	}
	else {
		gtk_clist_set_selection_mode(GTK_CLIST(ptreew),
		    GTK_SELECTION_BROWSE);
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
set_ptree_style_cb(gpointer data, gpointer user_data)
{
	gtk_widget_set_style((GtkWidget *)data, (GtkStyle *)user_data);
}
	
void
set_ptree_font_all(GdkFont *font)
{
	GtkStyle *style;

	style = gtk_style_new();
	gdk_font_unref(style->font);
	style->font = font;
	gdk_font_ref(font);

	g_list_foreach(ptree_widgets, set_ptree_style_cb, style);

	/* Now nuke the old style and replace it with the new one. */
	gtk_style_unref(item_style);
	item_style = style;
}

void
create_tree_view(gint tv_size, e_prefs *prefs, GtkWidget *pane,
		GtkWidget **tv_scrollw_p, GtkWidget **tree_view_p, int pos)
{
  GtkWidget *tv_scrollw, *tree_view;

  /* Tree view */
  tv_scrollw = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(tv_scrollw),
    GTK_POLICY_ALWAYS, GTK_POLICY_ALWAYS);
  gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
  gtk_widget_set_usize(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  
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
  gtk_container_add( GTK_CONTAINER(tv_scrollw), tree_view );
  set_ptree_sel_browse(tree_view, prefs->gui_ptree_sel_browse);
  gtk_widget_set_style(tree_view, item_style);
  remember_ptree_widget(tree_view);

  *tree_view_p = tree_view;
  *tv_scrollw_p = tv_scrollw;
}

void expand_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view) {
  int i;
  for(i=0; i < num_tree_types; i++) {
    tree_is_expanded[i] = TRUE;
  }
  proto_tree_draw(protocol_tree, tree_view);
  gtk_ctree_expand_recursive(GTK_CTREE(tree_view), NULL);
}

void collapse_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view) {
  int i;
  for(i=0; i < num_tree_types; i++) {
    tree_is_expanded[i] = FALSE;
  }
  proto_tree_draw(protocol_tree, tree_view);
}


struct proto_tree_draw_info {
	GtkCTree	*ctree;
	GtkCTreeNode	*ctree_node;
};

void
proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view)
{
	struct proto_tree_draw_info	info;

	info.ctree = GTK_CTREE(tree_view);
	info.ctree_node = NULL;

	gtk_clist_freeze(GTK_CLIST(tree_view));

	/*
	 * Clear out any crud left over in the display of the protocol
	 * tree, by removing all nodes from the ctree.
	 * This is how it's done in testgtk.c in GTK+.
	 */
	gtk_clist_clear(GTK_CLIST(tree_view));

	g_node_children_foreach((GNode*) protocol_tree, G_TRAVERSE_ALL,
		proto_tree_draw_node, &info);

	gtk_clist_thaw(GTK_CLIST(tree_view));
}

static void
proto_tree_draw_node(GNode *node, gpointer data)
{
	struct proto_tree_draw_info	info;
	struct proto_tree_draw_info	*parent_info = (struct proto_tree_draw_info*) data;

	field_info	*fi = PITEM_FINFO(node);
	gchar		label_str[ITEM_LABEL_LENGTH];
	gchar		*label_ptr;
	GtkCTreeNode	*parent;
	gboolean	is_leaf, is_expanded;
	int		i;

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
	
	info.ctree = parent_info->ctree;
	parent = gtk_ctree_insert_node ( info.ctree, parent_info->ctree_node, NULL,
			&label_ptr, 5, NULL, NULL, NULL, NULL,
			is_leaf, is_expanded );

	gtk_ctree_node_set_row_data( GTK_CTREE(info.ctree), parent, fi );

	if (!is_leaf) {
		info.ctree_node = parent;
		g_node_children_foreach(node, G_TRAVERSE_ALL,
			proto_tree_draw_node, &info);
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
  gtk_clist_clear(GTK_CLIST(tree_view));
}
