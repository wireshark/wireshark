/* gtkpacket.c
 * Routines for GTK+ packet display
 *
 * $Id: proto_draw.c,v 1.18 2000/08/21 08:09:16 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <stdio.h>
#include "main.h"
#include "packet.h"
#include "util.h"

#include "prefs.h"
#include "proto_draw.h"
#include "gtkglobals.h"

#define BYTE_VIEW_WIDTH    16
#define BYTE_VIEW_SEP      8

extern GdkFont      *m_r_font, *m_b_font;

static void
proto_tree_draw_node(GNode *node, gpointer data);

void
create_byte_view(gint bv_size, GtkWidget *pane, GtkWidget **byte_view_p,
		GtkWidget **bv_scrollw_p, int pos)
{
  GtkWidget *byte_view, *byte_scrollw;

  /* Byte view.  Create a scrolled window for the text. */
  byte_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_paned_pack2(GTK_PANED(pane), byte_scrollw, FALSE, FALSE);
  gtk_widget_set_usize(byte_scrollw, -1, bv_size);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(byte_scrollw),
					GTK_POLICY_NEVER,
					GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(byte_scrollw, pos);
  remember_scrolled_window(byte_scrollw);
  gtk_widget_show(byte_scrollw);

  byte_view = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_container_add(GTK_CONTAINER(byte_scrollw), byte_view);
  gtk_widget_show(byte_view);

  *byte_view_p = byte_view;
  *bv_scrollw_p = byte_scrollw;
}

void
packet_hex_print(GtkText *bv, guint8 *pd, gint len, gint bstart, gint blen,
		char_enc encoding) {
  gint     i = 0, j, k, cur;
  guchar   line[128], hexchars[] = "0123456789abcdef", c = '\0';
  GdkFont *cur_font, *new_font;
  gint	   bend = -1;

  /* Freeze the text for faster display */
  gtk_text_freeze(bv);

  /* Clear out the text */
  gtk_text_set_point(bv, 0);
  /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see 
     http://ethereal.zing.org/lists/ethereal-dev/199912/msg00312.html and
     http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
     for more information */
  gtk_adjustment_set_value(bv->vadj, 0.0);
  gtk_text_forward_delete(bv, gtk_text_get_length(bv));

  if (bstart >= 0 && blen >= 0) {
	  bend = bstart + blen;
  }

  while (i < len) {
    /* Print the line number */
    sprintf(line, "%04x  ", i);
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
              line[cur++] = (isprint(c)) ? c : '.';
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

  /* scroll text into position */
  gtk_text_thaw(bv); /* must thaw before adjusting scroll bars */
  if ( bstart > 0 ) {
    int lineheight, linenum;
    float scrollval;
    linenum = bstart / BYTE_VIEW_WIDTH;

    /* need to change to some way of getting that offset instead of +4 */
    lineheight = gdk_string_height(m_b_font, "0") + 4;
    scrollval = MIN(linenum * lineheight,bv->vadj->upper - bv->vadj->page_size);

    gtk_adjustment_set_value(bv->vadj, scrollval);
  }
}

/* List of all protocol tree widgets, so we can globally set the selection
   mode, line style, expander style, and font of all of them. */
static GList *ptree_widgets;

/* Add a protocol tree widget to the list of protocol tree widgets. */
static void forget_ptree_widget(GtkWidget *ptreew, gpointer data);

void
remember_ptree_widget(GtkWidget *ptreew)
{
  ptree_widgets = g_list_append(ptree_widgets, ptreew);

  /* Catch the "destroy" event on the widget, so that we remove it from
     the list when it's destroyed. */
  gtk_signal_connect(GTK_OBJECT(ptreew), "destroy",
		     GTK_SIGNAL_FUNC(forget_ptree_widget), NULL);
}

/* Remove a scrolled window from the list of scrolled windows. */
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
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  set_scrollbar_placement_scrollw(tv_scrollw, pos);
  remember_scrolled_window(tv_scrollw);
  gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
  gtk_widget_set_usize(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  
  tree_view = gtk_ctree_new(1, 0);
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

static void
expand_tree(GtkCTree *ctree, GList *node, gpointer user_data)
{
	field_info	*finfo;
	gboolean	*val;

	finfo = gtk_ctree_node_get_row_data( ctree, GTK_CTREE_NODE(node) );
	g_assert(finfo);

	val = &tree_is_expanded[finfo->tree_type];
	*val = TRUE;
}

static void
collapse_tree(GtkCTree *ctree, GList *node, gpointer user_data)
{
	field_info	*finfo;
	gboolean	*val;

	finfo = gtk_ctree_node_get_row_data( ctree, GTK_CTREE_NODE(node) );
	g_assert(finfo);

	val = &tree_is_expanded[finfo->tree_type];
	*val = FALSE;
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

	gtk_signal_connect( GTK_OBJECT(info.ctree), "tree-expand",
		(GtkSignalFunc) expand_tree, NULL );
	gtk_signal_connect( GTK_OBJECT(info.ctree), "tree-collapse",
		(GtkSignalFunc) collapse_tree, NULL );

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
