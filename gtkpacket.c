/* gtkpacket.c
 * Routines for GTK+ packet display
 *
 * $Id: gtkpacket.c,v 1.4 1999/04/16 18:39:07 gram Exp $
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
#include "ethereal.h"
#include "packet.h"

#ifndef __GTKPACKET_H__
#include "gtkpacket.h"
#endif

#define BYTE_VIEW_WIDTH    16
#define BYTE_VIEW_SEP      8

extern GtkWidget    *byte_view;
extern GdkFont      *m_r_font, *m_b_font;

void
packet_hex_print(GtkText *bv, guchar *pd, gint len, gint bstart, gint blen) {
  gint     i = 0, j, k, cur;
  gchar    line[128], hexchars[] = "0123456789abcdef";
  GdkFont *cur_font, *new_font;
  
  while (i < len) {
    /* Print the line number */
    sprintf(line, "%04x  ", i);
    gtk_text_insert(bv, m_r_font, NULL, NULL, line, -1);
    /* Do we start in bold? */
    cur_font = (i >= bstart && i < (bstart + blen)) ? m_b_font : m_r_font;
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
      new_font = (i >= bstart && i < (bstart + blen)) ? m_b_font : m_r_font;
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
    cur_font = (i >= bstart && i < (bstart + blen)) ? m_b_font : m_r_font;
    while (i < k) {
      if (i < len) {
        line[cur++] = (isgraph(pd[i])) ? pd[i] : '.';
      } else {
        line[cur++] = ' ';
      }
      i++;
      /* insert a space every BYTE_VIEW_SEP bytes */
      if( ( i % BYTE_VIEW_SEP ) == 0 ) line[cur++] = ' ';
      /* Did we cross a bold/plain boundary? */
      new_font = (i >= bstart && i < (bstart + blen)) ? m_b_font : m_r_font;
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

static void
expand_tree(GtkWidget *w, gpointer data) {
  gint *val = (gint *) data;
  *val = 1;
}

static void
collapse_tree(GtkWidget *w, gpointer data) {
  gint *val = (gint *) data;
  *val = 0;
}

static void
set_item_style(GtkWidget *widget, gpointer dummy)
{
  gtk_widget_set_style(widget, item_style);
}

proto_item *
proto_tree_add_item(proto_tree *tree, gint start, gint len,
  gchar *format, ...) {
  GtkWidget *ti;
  va_list    ap;
  gchar      label_str[256];

  if (!tree)
    return(NULL);
  
  va_start(ap, format);
  vsnprintf(label_str, 256, format, ap);
  ti = gtk_tree_item_new_with_label(label_str);
  gtk_container_foreach(GTK_CONTAINER(ti), set_item_style, NULL);
  gtk_object_set_data(GTK_OBJECT(ti), E_TREEINFO_START_KEY, (gpointer) start);
  gtk_object_set_data(GTK_OBJECT(ti), E_TREEINFO_LEN_KEY, (gpointer) len);
  gtk_tree_append(GTK_TREE(tree), ti);
  gtk_widget_show(ti);

  return (proto_item*) ti;
}

void
proto_item_set_len(proto_item *ti, gint len)
{
  gtk_object_set_data(GTK_OBJECT(ti), E_TREEINFO_LEN_KEY, (gpointer) len);
}

void
proto_item_add_subtree(proto_item *ti, proto_tree *subtree, gint idx) {
  static gint tree_type[NUM_TREE_TYPES];

  gtk_tree_item_set_subtree(GTK_TREE_ITEM(ti), GTK_WIDGET(subtree));
  if (tree_type[idx])
    gtk_tree_item_expand(GTK_TREE_ITEM(ti));
  gtk_signal_connect(GTK_OBJECT(ti), "expand", (GtkSignalFunc) expand_tree,
    (gpointer) &tree_type[idx]);
  gtk_signal_connect(GTK_OBJECT(ti), "collapse", (GtkSignalFunc) collapse_tree,
    (gpointer) &tree_type[idx]);
}

proto_tree*
proto_tree_new(void)
{
	return (proto_tree*) gtk_tree_new();
}
