/* proto_draw.c
 * Routines for GTK+ packet display
 *
 * $Id: proto_draw.c,v 1.41 2001/11/20 10:37:16 guy Exp $
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
#include "packet.h"
#include "util.h"
#include "menu.h"
#include "keys.h"

#include "colors.h"
#include "prefs.h"
#include "proto_draw.h"
#include "packet_win.h"
#include "gtkglobals.h"


#define BYTE_VIEW_WIDTH    16
#define BYTE_VIEW_SEP      8

static void
proto_tree_draw_node(GNode *node, gpointer data);


GtkWidget*
get_notebook_bv_ptr(  GtkWidget *nb_ptr){

/* Get the current text window for the notebook */
  return gtk_object_get_data(GTK_OBJECT(nb_ptr), E_BYTE_VIEW_TEXT_INFO_KEY);
}


int get_byte_view_data( GtkWidget *byte_view_notebook, guint8 **data_ptr) {

/* get the data pointer and data length for a hex window */
/* return the length of the data or -1 on error		 */

	GtkWidget *byte_view = get_notebook_bv_ptr( byte_view_notebook);

	if ( !byte_view)
		return -1;	
        if ((*data_ptr = gtk_object_get_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_DATA_PTR_KEY)))
        	return GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(byte_view),
			E_BYTE_VIEW_DATA_LEN_KEY));
	return -1;
}


int get_byte_view_and_data( GtkWidget *byte_view_notebook, GtkWidget **byte_view, guint8 **data_ptr) {

/* Get both byte_view widget pointer and the data pointer */
/* return the data length or -1 if error 		  */

	*byte_view = get_notebook_bv_ptr( byte_view_notebook);
	if ( *byte_view)
		return get_byte_view_data( byte_view_notebook, data_ptr);
	return -1;
}


void
set_notebook_page(  GtkWidget *nb_ptr, int num){

/* Set the current text window for the notebook and set the */
/* text window pointer storage */

  GtkWidget* child;

  gtk_notebook_set_page ( GTK_NOTEBOOK( nb_ptr), num);

  child = gtk_notebook_get_nth_page( GTK_NOTEBOOK(nb_ptr), num);
  child = gtk_object_get_data(GTK_OBJECT(child), E_BYTE_VIEW_TEXT_INFO_KEY);
  gtk_object_set_data(GTK_OBJECT(nb_ptr), E_BYTE_VIEW_TEXT_INFO_KEY, child);
}


int find_notebook_page( GtkWidget *nb_ptr, gchar *label){

/* find the notebook page number for this label */

        int i = -1;
        gchar *ptr;
        GtkWidget* child;

        while(( child = gtk_notebook_get_nth_page(GTK_NOTEBOOK(nb_ptr), ++i))){
                child = gtk_notebook_get_tab_label(GTK_NOTEBOOK(nb_ptr), child);
                gtk_notebook_get_tab_label(GTK_NOTEBOOK(nb_ptr), child);
                gtk_label_get(GTK_LABEL(child), &ptr);
                if (!strcmp( label, ptr))
                        return i;
        }
        return -1;
}


/* Redraw a given byte view window. */
void
redraw_hex_dump(GtkWidget *nb, frame_data *fd, field_info *finfo)
{
  GtkWidget* bv;
  guint8* data;
  int len;
 
  len = get_byte_view_and_data( byte_nb_ptr, &bv, &data);
  if ( bv) 
    packet_hex_print(GTK_TEXT(bv), data, fd, finfo, len);
}

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
	proto_tree	*tree = gtk_object_get_data(GTK_OBJECT(widget),
			   E_BYTE_VIEW_TREE_PTR);
	GtkWidget	*tree_view =
			 gtk_object_get_data(GTK_OBJECT(widget),
			   E_BYTE_VIEW_TREE_VIEW_PTR);
	GtkCTree	*ctree = GTK_CTREE(tree_view);
	GtkCTreeNode	*node, *parent;
	field_info	*finfo;
	GtkText		*bv = GTK_TEXT(widget);
	int		row, column;
	int		byte;
	gchar 		*name;

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

	/* Get the data source name */
	name = gtk_object_get_data(GTK_OBJECT(widget), E_BYTE_VIEW_NAME_KEY);

	/* Find the finfo that corresponds to our byte. */
	finfo = proto_find_field_from_offset(tree, byte, name);

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


void
create_byte_view(gint bv_size, GtkWidget *pane, GtkWidget **byte_nb_p,
		GtkWidget **bv_scrollw_p, int pos)
{
  GtkWidget *byte_scrollw, *byte_nb;

  byte_nb = gtk_notebook_new();
  gtk_notebook_set_tab_pos ( GTK_NOTEBOOK(byte_nb), GTK_POS_BOTTOM);

  gtk_paned_pack2(GTK_PANED(pane), byte_nb, FALSE, FALSE);
  gtk_widget_show(byte_nb);

  /* Byte view.  Create a scrolled window for the text. */
  byte_scrollw = gtk_scrolled_window_new(NULL, NULL);
  *byte_nb_p = byte_nb;
  *bv_scrollw_p = byte_scrollw;
}


void
byte_view_realize_cb( GtkWidget *bv, gpointer data){

   guint8* byte_data = gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_DATA_PTR_KEY);
   int     byte_len = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_DATA_LEN_KEY));

   packet_hex_print(GTK_TEXT(bv), byte_data, cfile.current_frame, NULL, byte_len);

}


static GtkWidget *
add_byte_tab(GtkWidget *byte_nb, const char *name, const guint8 *data, int len,
    proto_tree *tree, GtkWidget *tree_view)
{
  GtkWidget *byte_view, *byte_scrollw, *label;
  gchar *name_ptr;

  /* Byte view.  Create a scrolled window for the text. */
  byte_scrollw = gtk_scrolled_window_new(NULL, NULL);
  /* Add scrolled pane to tabbed window */
  label = gtk_label_new (name);
  gtk_notebook_append_page (GTK_NOTEBOOK(byte_nb), byte_scrollw, label);

  /* The horizontal scrollbar of the scroll-window doesn't seem
   * to affect the GtkText widget at all, even when line wrapping
   * is turned off in the GtkText widget and there is indeed more
   * horizontal data. */
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(byte_scrollw),
			/* Horizontal */GTK_POLICY_NEVER,
			/* Vertical*/	GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(byte_scrollw,  prefs.gui_scrollbar_on_right);
  remember_scrolled_window(byte_scrollw);
  gtk_widget_show(byte_scrollw);

  byte_view = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_object_set_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_DATA_PTR_KEY,
		      (gpointer)data);
  gtk_object_set_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_DATA_LEN_KEY,
		      GINT_TO_POINTER(len));
  gtk_label_get(GTK_LABEL(label), &name_ptr);
  gtk_object_set_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_NAME_KEY, name_ptr);
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

  gtk_object_set_data(GTK_OBJECT(byte_scrollw), E_BYTE_VIEW_TEXT_INFO_KEY,
            byte_view);

/* no tabs if this is the first page */
  if ( !(gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_scrollw)))
        gtk_notebook_set_show_tabs ( GTK_NOTEBOOK(byte_nb), FALSE);
  else
        gtk_notebook_set_show_tabs ( GTK_NOTEBOOK(byte_nb), TRUE);

  return byte_view;
}

void
add_byte_views(frame_data *frame, proto_tree *tree, GtkWidget *tree_view,
    GtkWidget *byte_nb_ptr)
{
	int i;
	tvbuff_t *bv_tvb;

	/*
	 * Add to the specified byte view notebook tabs for hex dumps
	 * of all the data sources for the specified frame.
	 */
	for (i = 0;
	    (bv_tvb = g_slist_nth_data(frame->data_src, i)) != NULL; i++) {
		add_byte_tab(byte_nb_ptr, tvb_get_name(bv_tvb),
		    tvb_get_ptr(bv_tvb, 0, -1), tvb_length(bv_tvb),
		    tree, tree_view);
	}

	/*
	 * Initially select the first byte view.
	 */
	set_notebook_page(byte_nb_ptr, 0);
}

void
packet_hex_print_common(GtkText *bv, guint8 *pd, int len, int bstart, int bend, int encoding)
{
  gint     i = 0, j, k, cur;
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
packet_hex_print(GtkText *bv, guint8 *pd, frame_data *fd, field_info *finfo, int len){

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

  packet_hex_print_common( bv, pd, len, bstart, bend, fd->flags.encoding);

}

void
packet_hex_reprint(GtkText *bv){

  /* redraw the text using the saved information, 	*/
  /* usually called if the preferences haved changed.	*/

  int start, end, len, encoding;
  guint8 *data;

  start = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_START_KEY));
  end = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_END_KEY));
  len = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_DATA_LEN_KEY));
  data =  gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_DATA_PTR_KEY);
  encoding =  GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(bv), E_BYTE_VIEW_ENCODE_KEY));

  packet_hex_print_common( bv, data, len, start, end, encoding);
}


/* List of all protocol tree widgets, so we can globally set the selection
   mode, line style, expander style, and font of all of them. */
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

/* Set the line style of a given packet tree window. */
static void
set_ptree_line_style(GtkWidget *ptreew, gint style)
{
	/* I'm using an assert here since the preferences code limits
	 * the user input, both in the GUI and when reading the preferences file.
	 * If the value is incorrect, it's a program error, not a user-initiated error.
	 */
	g_assert(style >= GTK_CTREE_LINES_NONE && style <= GTK_CTREE_LINES_TABBED);
	gtk_ctree_set_line_style(GTK_CTREE(ptreew), style);
}

static void
set_ptree_line_style_cb(gpointer data, gpointer user_data)
{
	set_ptree_line_style((GtkWidget *)data, *(gint *)user_data);
}

/* Set the line style of all packet tree window. */
void
set_ptree_line_style_all(gint style)
{
	g_list_foreach(ptree_widgets, set_ptree_line_style_cb, &style);
}

/* Set the expander style of a given packet tree window. */
static void
set_ptree_expander_style(GtkWidget *ptreew, gint style)
{
	/* I'm using an assert here since the preferences code limits
	 * the user input, both in the GUI and when reading the preferences file.
	 * If the value is incorrect, it's a program error, not a user-initiated error.
	 */
	g_assert(style >= GTK_CTREE_EXPANDER_NONE && style <= GTK_CTREE_EXPANDER_CIRCULAR);
	gtk_ctree_set_expander_style(GTK_CTREE(ptreew), style);
}

static void
set_ptree_expander_style_cb(gpointer data, gpointer user_data)
{
	set_ptree_expander_style((GtkWidget *)data, *(gint *)user_data);
}
	
void
set_ptree_expander_style_all(gint style)
{
	g_list_foreach(ptree_widgets, set_ptree_expander_style_cb, &style);
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
  tv_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(tv_scrollw),
    GTK_POLICY_ALWAYS, GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(tv_scrollw, pos);
  remember_scrolled_window(tv_scrollw);
  gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
  gtk_widget_set_usize(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  
  tree_view = gtk_ctree_new(1, 0);
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
  set_ptree_line_style(tree_view, prefs->gui_ptree_line_style);
  set_ptree_expander_style(tree_view, prefs->gui_ptree_expander_style);
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
  gtk_clist_clear ( GTK_CLIST(tree_view) );
  proto_tree_draw(protocol_tree, tree_view);
  gtk_ctree_expand_recursive(GTK_CTREE(tree_view), NULL);
}

void collapse_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view) {
  int i;
  for(i=0; i < num_tree_types; i++) {
    tree_is_expanded[i] = FALSE;
  }
  gtk_clist_clear ( GTK_CLIST(tree_view) );
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

	gtk_clist_freeze ( GTK_CLIST(tree_view) );

	g_node_children_foreach((GNode*) protocol_tree, G_TRAVERSE_ALL,
		proto_tree_draw_node, &info);

	gtk_clist_thaw ( GTK_CLIST(tree_view) );
}

static void
proto_tree_draw_node(GNode *node, gpointer data)
{
	struct proto_tree_draw_info	info;
	struct proto_tree_draw_info	*parent_info = (struct proto_tree_draw_info*) data;

	field_info	*fi = (field_info*) (node->data);
	gchar		label_str[ITEM_LABEL_LENGTH];
	gchar		*label_ptr;
	GtkCTreeNode	*parent;
	gboolean	is_leaf, is_expanded;
	int		i;

	if (!fi->visible)
		return;
	/*
	 * XXX - why are we doing this?  This is done when we consruct
	 * the protocol tree display, but, as far as I can tell, it only
	 * needs to be done when a particular field in the tree is
	 * selected.
	 */
	if (fi->ds_name != NULL) {
		i = find_notebook_page(byte_nb_ptr, fi->ds_name);
		if (i < 0)
			return; 	/* no notebook pages ?? */
		set_notebook_page(byte_nb_ptr, i);
	}

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
  /* Clear the hex dump. */

  GtkWidget *byte_view;
  int i;

/* Get the current tab scroll window, then get the text widget  */
/* from the E_BYTE_VIEW_TEXT_INFO_KEY data field 		*/

  i = gtk_notebook_get_current_page( GTK_NOTEBOOK(byte_nb_ptr));

  if ( i >= 0){
    byte_view = gtk_notebook_get_nth_page( GTK_NOTEBOOK(byte_nb_ptr), i);
    byte_view = gtk_object_get_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_TEXT_INFO_KEY);

    gtk_text_freeze(GTK_TEXT(byte_view));
    gtk_text_set_point(GTK_TEXT(byte_view), 0);
    gtk_text_forward_delete(GTK_TEXT(byte_view),
      gtk_text_get_length(GTK_TEXT(byte_view)));
    gtk_text_thaw(GTK_TEXT(byte_view));
  }
  /* Remove all nodes in ctree. This is how it's done in testgtk.c in GTK+ */
  gtk_clist_clear ( GTK_CLIST(tree_view) );

}
