/* packet.c
 * Routines for packet disassembly
 *
 * $Id: packet.c,v 1.19 1999/01/28 21:29:36 gram Exp $
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

#include <gtk/gtk.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"
#include "file.h"

extern GtkWidget    *byte_view;
extern GdkFont      *m_r_font, *m_b_font;
extern capture_file  cf;

gchar *
ether_to_str(const guint8 *ad) {
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
ip_to_str(const guint8 *ad) {
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

#define	PLURALIZE(n)	(((n) > 1) ? "s" : "")
#define	COMMA(do_it)	((do_it) ? ", " : "")

gchar *
time_secs_to_str(guint32 time)
{
  static gchar  str[3][8+1+4+2+2+5+2+2+7+2+2+7+1];
  static gchar *cur, *p;
  int hours, mins, secs;
  int do_comma;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }

  secs = time % 60;
  time /= 60;
  mins = time % 60;
  time /= 60;
  hours = time % 24;
  time /= 24;

  p = cur;
  if (time != 0) {
    sprintf(p, "%u day%s", time, PLURALIZE(time));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (hours != 0) {
    sprintf(p, "%s%u hour%s", COMMA(do_comma), hours, PLURALIZE(hours));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (mins != 0) {
    sprintf(p, "%s%u minute%s", COMMA(do_comma), mins, PLURALIZE(mins));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (secs != 0)
    sprintf(p, "%s%u second%s", COMMA(do_comma), secs, PLURALIZE(secs));
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

static void
set_item_style(GtkWidget *widget, gpointer dummy)
{
  gtk_widget_set_style(widget, item_style);
}

GtkWidget *
add_item_to_tree(GtkWidget *tree, gint start, gint len,
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

  return ti;
}

void
set_item_len(GtkWidget *ti, gint len)
{
  gtk_object_set_data(GTK_OBJECT(ti), E_TREEINFO_LEN_KEY, (gpointer) len);
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

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
gchar*
val_to_str(guint32 val, const value_string *vs, const char *fmt) {
  gchar *ret;
  static gchar  str[3][64];
  static gchar *cur;

  ret = match_strval(val, vs);
  if (ret != NULL)
    return ret;
  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  snprintf(cur, 64, fmt, val);
  return cur;
}

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match, or NULL on failure. */
gchar*
match_strval(guint32 val, const value_string *vs) {
  gint i = 0;
  
  while (vs[i].strptr) {
    if (vs[i].value == val)
      return(vs[i].strptr);
    i++;
  }
  
  return(NULL);
}

/* Checks to see if a particular packet information element is needed for
   the packet list */
gint
check_col(frame_data *fd, gint el) {
  int i;
  
  if (fd->cinfo) {
    for (i = 0; i < fd->cinfo->num_cols; i++) {
      if (fd->cinfo->fmt_matx[i][el])
        return TRUE;
    }
  }
  return FALSE;
}

/* To do: Add check_col checks to the pinfo_add* routines */

/* Adds a vararg list to a packet info string. */
void
col_add_fstr(frame_data *fd, gint el, gchar *format, ...) {
  va_list    ap;
  int        i;
  
  va_start(ap, format);
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el])
      vsnprintf(fd->cinfo->col_data[i], COL_MAX_LEN, format, ap);
  }
}

void
col_add_str(frame_data *fd, gint el, gchar* str) {
  int i;
  
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      strncpy(fd->cinfo->col_data[i], str, COL_MAX_LEN);
      fd->cinfo->col_data[i][COL_MAX_LEN - 1] = 0;
    }
  }
}

static const char *mon_names[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

/* this routine checks the frame type from the cf structure */
void
dissect_packet(const u_char *pd, frame_data *fd, GtkTree *tree)
{
	GtkWidget *fh_tree, *ti;
	struct tm *tmp;
	time_t then;

	/* Put in frame header information. */
	if (check_col(fd, COL_ABS_TIME)) {
	  then = fd->abs_secs;
	  tmp = localtime(&then);
	  col_add_fstr(fd, COL_ABS_TIME, "%02d:%02d:%02d.%04ld",
	    tmp->tm_hour,
	    tmp->tm_min,                                                      
	    tmp->tm_sec,
	    (long)fd->abs_usecs/100);
  }
	if (check_col(fd, COL_REL_TIME)) {
	    col_add_fstr(fd, COL_REL_TIME, "%d.%06d", fd->rel_secs, fd->rel_usecs);
	}
	if (check_col(fd, COL_DELTA_TIME)) {
	    col_add_fstr(fd, COL_DELTA_TIME, "%d.%06d", fd->del_secs, fd->del_usecs);
	}

	if (tree) {
	  ti = add_item_to_tree(GTK_WIDGET(tree), 0, fd->cap_len,
	    "Frame (%d on wire, %d captured)",
	    fd->pkt_len, fd->cap_len);

	  fh_tree = gtk_tree_new();
	  add_subtree(ti, fh_tree, ETT_FRAME);
	  then = fd->abs_secs;
	  tmp = localtime(&then);
	  add_item_to_tree(fh_tree, 0, 0,
	    "Frame arrived on %s %2d, %d %02d:%02d:%02d.%04ld",
	    mon_names[tmp->tm_mon],
	    tmp->tm_mday,
	    tmp->tm_year + 1900,
	    tmp->tm_hour,
	    tmp->tm_min,                                                      
	    tmp->tm_sec,
	    (long)fd->abs_usecs/100);

	  add_item_to_tree(fh_tree, 0, 0, "Total frame length: %d bytes",
	    fd->pkt_len);
	  add_item_to_tree(fh_tree, 0, 0, "Capture frame length: %d bytes",
	    fd->cap_len);
	}

#ifdef WITH_WIRETAP
	switch (fd->lnk_t) {
		case WTAP_ENCAP_ETHERNET :
			dissect_eth(pd, fd, tree);
			break;
		case WTAP_ENCAP_FDDI :
			dissect_fddi(pd, fd, tree);
			break;
		case WTAP_ENCAP_TR :
			dissect_tr(pd, fd, tree);
			break;
		case WTAP_ENCAP_NONE :
			dissect_null(pd, fd, tree);
			break;
		case WTAP_ENCAP_PPP :
			dissect_ppp(pd, fd, tree);
			break;
		case WTAP_ENCAP_RAW_IP :
			dissect_raw(pd, fd, tree);
			break;
	}
#else
	switch (cf.lnk_t) {
		case DLT_EN10MB :
			dissect_eth(pd, fd, tree);
			break;
		case DLT_FDDI :
			dissect_fddi(pd, fd, tree);
			break;
		case DLT_IEEE802 :
			dissect_tr(pd, fd, tree);
			break;
		case DLT_NULL :
			dissect_null(pd, fd, tree);
			break;
		case DLT_PPP :
			dissect_ppp(pd, fd, tree);
			break;
		case DLT_RAW :
			dissect_raw(pd, fd, tree);
			break;
	}
#endif
}
