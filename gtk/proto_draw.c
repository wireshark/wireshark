/* gtkpacket.c
 * Routines for GTK+ packet display
 *
 * $Id: proto_draw.c,v 1.9 1999/12/14 06:52:09 gram Exp $
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

#include "proto_draw.h"

#define BYTE_VIEW_WIDTH    16
#define BYTE_VIEW_SEP      8

extern GdkFont      *m_r_font, *m_b_font;

static void
proto_tree_draw_node(GNode *node, gpointer data);

void
packet_hex_print(GtkText *bv, guint8 *pd, gint len, gint bstart, gint blen,
		char_enc encoding) {
  gint     i = 0, j, k, cur;
  gchar    line[128], hexchars[] = "0123456789abcdef", c = '\0';
  GdkFont *cur_font, *new_font;
  gint	   bend = -1;

  /* Freeze the text for faster display */
  gtk_text_freeze(bv);

  /* Clear out the text */
  gtk_text_set_point(bv, 0);
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
              line[cur++] = (isgraph(c)) ? c : '.';
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

void expand_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view) {
  int i;
  for(i=0; i < num_tree_types; i++) {
    tree_is_expanded[i] = TRUE;
  }
  gtk_tree_clear_items(GTK_TREE(tree_view), 0, -1);
  proto_tree_draw(protocol_tree, tree_view);
}

void collapse_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view) {
  int i;
  for(i=0; i < num_tree_types; i++) {
    tree_is_expanded[i] = FALSE;
  }
  gtk_tree_clear_items(GTK_TREE(tree_view), 0, -1);
  proto_tree_draw(protocol_tree, tree_view);
}

static void
expand_tree(GtkWidget *w, gpointer data) {
  gboolean *val = (gint *) data;
  *val = TRUE;
}

static void
collapse_tree(GtkWidget *w, gpointer data) {
  gboolean *val = (gint *) data;
  *val = FALSE;
}

static void
set_item_style(GtkWidget *widget, gpointer dummy)
{
  gtk_widget_set_style(widget, item_style);
}

void
proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view)
{
	g_node_children_foreach((GNode*) protocol_tree, G_TRAVERSE_ALL,
		proto_tree_draw_node, tree_view);
}

static void
proto_tree_draw_node(GNode *node, gpointer data)
{
	GtkWidget	*tree_view = (GtkWidget*) data;
	field_info	*fi = (field_info*) (node->data);
	GtkWidget	*ti, *subtree;
	gchar		label_str[ITEM_LABEL_LENGTH];
	gchar		*label_ptr;

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
		
	ti = gtk_tree_item_new_with_label(label_ptr);
	gtk_container_foreach(GTK_CONTAINER(ti), set_item_style, NULL);
	
	gtk_object_set_data(GTK_OBJECT(ti), E_TREEINFO_FIELD_INFO_KEY, (gpointer) fi);
	gtk_tree_append(GTK_TREE(tree_view), ti);
	gtk_widget_show(ti);

	if (g_node_n_children(node) > 0) {
		subtree = gtk_tree_new();
		gtk_tree_item_set_subtree(GTK_TREE_ITEM(ti), GTK_WIDGET(subtree));
		if (tree_is_expanded[fi->tree_type])
			gtk_tree_item_expand(GTK_TREE_ITEM(ti));
		gtk_signal_connect(GTK_OBJECT(ti), "expand", (GtkSignalFunc) expand_tree,
			(gpointer) &tree_is_expanded[fi->tree_type]);
		gtk_signal_connect(GTK_OBJECT(ti), "collapse", (GtkSignalFunc) collapse_tree,
			(gpointer) &tree_is_expanded[fi->tree_type]);

		g_node_children_foreach(node, G_TRAVERSE_ALL,
			proto_tree_draw_node, subtree);
	}
}
