/* packet.c
 * Routines for packet disassembly
 *
 * $Id: packet.c,v 1.2 1998/09/16 03:22:13 gerald Exp $
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

#include <gtk/gtk.h>

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "packet.h"
#include "ethereal.h"
#include "etypes.h"
#include "file.h"

extern GtkWidget    *byte_view;
extern GdkFont      *m_r_font, *m_b_font;
extern capture_file  cf;

gchar *
ether_to_str(guint8 *ad) {
  static gchar  str[3][18];
  static gchar *cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  sprintf(cur, "%02x:%02x:%02x:%02x:%02x:%02x", ad[0], ad[1], ad[2],
    ad[3], ad[4], ad[5]);
  return cur;
}

gchar *
ip_to_str(guint8 *ad) {
  static gchar  str[3][16];
  static gchar *cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  sprintf(cur, "%d.%d.%d.%d", ad[0], ad[1], ad[2], ad[3]);
  return cur;
}

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

GtkWidget *
add_item_to_tree(GtkWidget *tree, gint start, gint len,
  gchar *format, ...) {
  GtkWidget *ti;
  va_list    ap;
  gchar      label_str[256];
  guint32    t_info;
  
  /* This limits us to a max packet size of 65535 bytes. */
  /* Are there any systems out there with < 32-bit pointers? */
  /* To do: use gtk_object_set_data instead, now that I know it exists. */
  t_info = ((start & 0xffff) << 16) | (len & 0xffff);
  va_start(ap, format);
  vsnprintf(label_str, 256, format, ap);
  ti = gtk_tree_item_new_with_label(label_str);
  gtk_object_set_user_data(GTK_OBJECT(ti), (gpointer) t_info);
  gtk_tree_append(GTK_TREE(tree), ti);
  gtk_widget_show(ti);

  return ti;
}

void
add_subtree(GtkWidget *ti, GtkWidget *subtree, gint idx) {
  static gint tree_type[NUM_TREE_TYPES];

  gtk_tree_item_set_subtree(GTK_TREE_ITEM(ti), subtree);
  if (tree_type[idx])
    gtk_tree_item_expand(GTK_TREE_ITEM(ti));
  gtk_signal_connect(GTK_OBJECT(ti), "expand", (GtkSignalFunc) expand_tree,
    (gpointer) &tree_type[idx]);
  gtk_signal_connect(GTK_OBJECT(ti), "collapse", (GtkSignalFunc) collapse_tree,
    (gpointer) &tree_type[idx]);
}

void
expand_tree(GtkWidget *w, gpointer data) {
  gint *val = (gint *) data;
  *val = 1;
}

void
collapse_tree(GtkWidget *w, gpointer data) {
  gint *val = (gint *) data;
  *val = 0;
}

/* decodes the protocol start and length thare are encoded into
	the t_info field in add_item_to_tree. */
void
decode_start_len(GtkTreeItem *ti, gint *pstart, gint *plen)
{
	guint32		t_info;
	int			start, len;

	t_info = (guint32) gtk_object_get_user_data(GTK_OBJECT(ti));
	*pstart = t_info >> 16;
	*plen =	t_info & 0xffff;
}


/* this routine checks the frame type from the cf structure */
void
dissect_packet(const u_char *pd, frame_data *fd, GtkTree *tree) {

	switch (cf.lnk_t) {
		case DLT_EN10MB :
			dissect_eth(pd, fd, tree);
			break;
		case DLT_IEEE802 :
			dissect_tr(pd, fd, tree);
			break;
		case DLT_RAW :
	        dissect_raw(pd, fd, tree);
			break;
	}
}
