/* help_dlg.c
 *
 * $Id: help_dlg.c,v 1.20 2002/01/11 07:40:31 guy Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2000 Gerald Combs
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "help_dlg.h"
#include "prefs.h"
#include "globals.h"
#include "gtkglobals.h"
#include "main.h"
#include "ui_util.h"
#include "proto.h"

typedef enum {
  OVERVIEW_HELP,
  PROTOCOL_HELP,
  DFILTER_HELP,
  CFILTER_HELP
} help_type_t;

static void help_close_cb(GtkWidget *w, gpointer data);
static void help_destroy_cb(GtkWidget *w, gpointer data);
static void set_text(GtkWidget *w, char *buffer, int nchars);
static void set_help_text(GtkWidget *w, help_type_t type);

/*
 * Keep a static pointer to the current "Help" window, if any, so that
 * if somebody tries to do "Help->Help" while there's already a
 * "Help" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *help_w = NULL;

/*
 * Keep static pointers to the text widgets as well.
 */
GtkWidget *overview_text, *proto_text, *dfilter_text, *cfilter_text;

void help_cb(GtkWidget *w, gpointer data)
{

  GtkWidget *main_vb, *bbox, *help_nb, *close_bt, *label, *txt_scrollw,
    *overview_vb,
    *proto_vb,
    *dfilter_tb, *dfilter_vsb,
    *cfilter_vb;
  
  if (help_w != NULL) {
    /* There's already a "Help" dialog box; reactivate it. */
    reactivate_window(help_w);
    return;
  }
  
  help_w = gtk_window_new(GTK_WINDOW_DIALOG);
  gtk_widget_set_name(help_w, "Ethereal Help window" );
  gtk_window_set_title(GTK_WINDOW(help_w), "Ethereal: Help");
  gtk_signal_connect(GTK_OBJECT(help_w), "destroy",
		     GTK_SIGNAL_FUNC(help_destroy_cb), NULL);
  gtk_signal_connect (GTK_OBJECT (help_w), "realize",
		     GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);
  gtk_widget_set_usize(GTK_WIDGET(help_w), DEF_WIDTH * 2/3, DEF_HEIGHT * 2/3);
  gtk_container_border_width(GTK_CONTAINER(help_w), 2);
  
  /* Container for each row of widgets */

  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 1);
  gtk_container_add(GTK_CONTAINER(help_w), main_vb);
  gtk_widget_show(main_vb);

  /* help topics container */

  help_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), help_nb);

  /* Overview panel */

  overview_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(overview_vb), 1);  
  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(overview_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_ALWAYS);
  overview_text = gtk_text_new(NULL, NULL );
  gtk_text_set_editable(GTK_TEXT(overview_text), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(overview_text), TRUE);
  gtk_text_set_line_wrap(GTK_TEXT(overview_text), TRUE);
  set_help_text(overview_text, OVERVIEW_HELP);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), overview_text);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(overview_text);
  gtk_widget_show(overview_vb);
  label = gtk_label_new("Overview");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), overview_vb, label);

  /* humm, gtk 1.2 does not support horizontal scrollbar for text widgets */

  /* protocol list */

  proto_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(proto_vb), 1);
  
  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(proto_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_ALWAYS,
				 GTK_POLICY_ALWAYS);
  proto_text = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(proto_text), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(proto_text), FALSE);
  set_help_text(proto_text, PROTOCOL_HELP);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(txt_scrollw),
					proto_text);  
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(proto_text);
  gtk_widget_show(proto_vb);
  label = gtk_label_new("Protocols");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), proto_vb, label);
  
  /* display filter help */
  /* X windows have a maximum size of 32767.  Since the height can easily
     exceed this, we have to jump through some hoops to have a functional
     vertical scroll bar. */
  
  dfilter_tb = gtk_table_new(2, 2, FALSE);
  gtk_table_set_col_spacing (GTK_TABLE (dfilter_tb), 0, 3);
  gtk_table_set_row_spacing (GTK_TABLE (dfilter_tb), 0, 3);
  gtk_container_border_width(GTK_CONTAINER(dfilter_tb), 1);  

  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_ALWAYS,
				 GTK_POLICY_NEVER);
  dfilter_text = gtk_text_new(NULL, NULL);
  dfilter_vsb = gtk_vscrollbar_new(GTK_TEXT(dfilter_text)->vadj);
  if (prefs.gui_scrollbar_on_right) {
    gtk_table_attach (GTK_TABLE (dfilter_tb), txt_scrollw, 0, 1, 0, 1,
                            GTK_EXPAND | GTK_SHRINK | GTK_FILL,
                            GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0);
    gtk_table_attach (GTK_TABLE (dfilter_tb), dfilter_vsb, 1, 2, 0, 1,
                            GTK_FILL, GTK_SHRINK | GTK_FILL, 0, 0);
  } else {
    gtk_table_attach (GTK_TABLE (dfilter_tb), txt_scrollw, 1, 2, 0, 1,
                            GTK_EXPAND | GTK_SHRINK | GTK_FILL,
                            GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0);
    gtk_table_attach (GTK_TABLE (dfilter_tb), dfilter_vsb, 0, 1, 0, 1,
                            GTK_FILL, GTK_SHRINK | GTK_FILL, 0, 0);
  }
  gtk_text_set_editable(GTK_TEXT(dfilter_text), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(dfilter_text), FALSE);
  set_help_text(dfilter_text, DFILTER_HELP);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(txt_scrollw),
					dfilter_text);  
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(dfilter_text);
  gtk_widget_show(dfilter_tb);
  gtk_widget_show(dfilter_vsb);
  label = gtk_label_new("Display Filters");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), dfilter_tb, label);

  /* capture filter help (this one has no horizontal scrollbar) */

  cfilter_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(cfilter_vb), 1);  
  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(cfilter_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_ALWAYS);
  cfilter_text = gtk_text_new(NULL, NULL );
  gtk_text_set_editable(GTK_TEXT(cfilter_text), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(cfilter_text), TRUE);
  gtk_text_set_line_wrap(GTK_TEXT(cfilter_text), TRUE);
  set_help_text(cfilter_text, CFILTER_HELP);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), cfilter_text);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(cfilter_text);
  gtk_widget_show(cfilter_vb);
  label = gtk_label_new("Capture Filters");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), cfilter_vb, label);

  /* XXX add other help panels here ... */

  gtk_widget_show(help_nb);

  /* Buttons (only one for now) */  

  bbox = gtk_hbox_new(FALSE, 1);
  gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);
  close_bt = gtk_button_new_with_label("Close");
  gtk_signal_connect(GTK_OBJECT(close_bt), "clicked",
		     GTK_SIGNAL_FUNC(help_close_cb), GTK_OBJECT(help_w));
  GTK_WIDGET_SET_FLAGS(close_bt, GTK_CAN_DEFAULT);
  gtk_container_add(GTK_CONTAINER(bbox), close_bt);
  gtk_widget_grab_default(close_bt);
  gtk_widget_show(close_bt);
  
  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(help_w));
  gtk_widget_show(help_w);

} /* help_cb */

static void help_close_cb(GtkWidget *w, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void help_destroy_cb(GtkWidget *w, gpointer data)
{
  /* Note that we no longer have a Help window. */
  help_w = NULL;
}

static void set_text(GtkWidget *w, char *buffer, int nchars)
{
  gtk_text_insert(GTK_TEXT(w), m_r_font, NULL, NULL, buffer, nchars);
}

static char *proto_help = 
"The protocols (and packet types) currently supported by "
"Ethereal are the following:\n\n";

static char *dfilter_help = 
"The following list shows all per-protocol fields that "
"can be used in a display filter:\n";

static char *cfilter_help = 
"Packet capturing is performed with the pcap library. The capture filter "
"syntax follows the rules of this library.\nSo this syntax is different "
"from the display filter syntax: see manual page of tcpdump.\n"
#ifndef HAVE_LIBPCAP
"\nNote: packet capturing is not enabled in this version.\n";
#else
;
#endif

static char *overview_help = 
"Ethereal is a GUI network protocol analyzer. It lets you interactively "
"browse packet data from a live network or from a previously saved capture "
"file. Ethereal knows how to read libpcap capture files, including those "
"of tcpdump. In addition, Ethereal can read capture files from snoop "
"(including Shomiti) and atmsnoop, LanAlyzer, Sniffer (compressed or "
"uncompressed), Microsoft Network Monitor, AIX's iptrace, NetXray, "
"Sniffer Pro, RADCOM's WAN/LAN analyzer, Lucent/Ascend router debug output, "
"HP-UX's nettl, the dump output from Toshiba's ISDN routers, the output from "
"i4btrace from the ISDN4BSD project, and output in IPLog format from the "
"Cisco Secure Intrusion Detection System."
"There is no need to tell Ethereal what type of file you are reading; it will "
"determine the file type by itself. Ethereal is also capable of reading any "
"of these file formats if they are compressed using gzip. Ethereal recognizes "
"this directly from the file; the '.gz' extension is not required for this "
"purpose.";

static void set_help_text(GtkWidget *w, help_type_t type)
{

#define BUFF_LEN 4096
#define B_LEN    256
  char buffer[BUFF_LEN];
  header_field_info *hfinfo;
  int i, len, maxlen = 0, maxlen2 = 0, maxlen3 = 0, nb_lines = 0;
  int width, height;
  const char *type_name;
  char blanks[B_LEN];
  int blks;
  void *cookie;

  /*
   * XXX quick hack:
   * the width and height computations are performed to make the
   * horizontal scrollbar work. This is only necessary for the
   * PROTOCOL_HELP and DFILTER_HELP windows since all others should
   * not have any horizontal scrollbar (line wrapping enabled).
   */

  memset(blanks, ' ', B_LEN - 1);
  blanks[B_LEN-1] = '\0';

  gtk_text_freeze(GTK_TEXT(w));

  switch(type) {

  case OVERVIEW_HELP :
    set_text(w, overview_help, -1);
    break;

  case PROTOCOL_HELP :    
    /* first pass to know the maximum length of first field */
    for (i = proto_get_first_protocol(&cookie); i != -1;
	    i = proto_get_next_protocol(&cookie)) {
      hfinfo = proto_registrar_get_nth(i);
      if ((len = strlen(hfinfo->abbrev)) > maxlen)
	maxlen = len;
    }

    maxlen++;

    maxlen2 = strlen(proto_help);
    width = gdk_string_width(m_r_font, proto_help);
    set_text(w, proto_help, maxlen2);
    
    /* ok, display the correctly aligned strings */
    for (i = proto_get_first_protocol(&cookie); i != -1;
	    i = proto_get_next_protocol(&cookie)) {
      hfinfo = proto_registrar_get_nth(i);
      blks = maxlen - strlen(hfinfo->abbrev);
      snprintf(buffer, BUFF_LEN, "%s%s%s\n",
	       hfinfo->abbrev,
	       &blanks[B_LEN - blks - 2],
	       hfinfo->name);
      if ((len = strlen(buffer)) > maxlen2) {
	maxlen2 = len;
	if ((len = gdk_string_width(m_r_font, buffer)) > width)
	  width = len;
      }
      set_text(w, buffer, strlen(buffer));
      nb_lines++;
    }

    height = (2 + nb_lines) * m_font_height;
    gtk_widget_set_usize(GTK_WIDGET(w), 20 + width, 20 + height);
    break;

  case DFILTER_HELP  :

    /* XXX we should display hinfo->blurb instead of name (if not empty) */

    /* first pass to know the maximum length of first and second fields */
    for (i = 0; i < proto_registrar_n() ; i++) {
      if (!proto_registrar_is_protocol(i)) {
	hfinfo = proto_registrar_get_nth(i);
	if ((len = strlen(hfinfo->abbrev)) > maxlen)
	  maxlen = len;
	if ((len = strlen(hfinfo->name)) > maxlen2)
	  maxlen2 = len;
      }
    }
    maxlen++;
    maxlen2++;

    maxlen3 = strlen(dfilter_help);
    width = gdk_string_width(m_r_font, dfilter_help);
    set_text(w, dfilter_help, maxlen3);

    for (i = 0; i < proto_registrar_n() ; i++) {
      hfinfo = proto_registrar_get_nth(i);	
      if (proto_registrar_is_protocol(i)) {
	snprintf(buffer, BUFF_LEN, "\n%s:\n", hfinfo->name);
	set_text(w, buffer, strlen(buffer));
	nb_lines += 2;
      } else {

	type_name = ftype_pretty_name(hfinfo->type);
	snprintf(buffer, BUFF_LEN, "%s%s%s%s(%s)\n",
		 hfinfo->abbrev, 
		 &blanks[B_LEN - (maxlen - strlen(hfinfo->abbrev)) - 2],
		 hfinfo->name,
		 &blanks[B_LEN - (maxlen2 - strlen(hfinfo->name)) - 2],
		 type_name);
	if ((len = strlen(buffer)) > maxlen3) {
	  maxlen3 = len;
	  if ((len = gdk_string_width(m_r_font, buffer)) > width)
	    width = len;
	}
	set_text(w, buffer, strlen(buffer));
	nb_lines ++;
      }
    }

    height = (1 + nb_lines) * m_font_height;
    gtk_widget_set_usize(GTK_WIDGET(w), 20 + width, 20 + height);

    break;
  case CFILTER_HELP :
    set_text(w, cfilter_help, -1);
    break;
  default :
    g_assert_not_reached();
    break;
  } /* switch(type) */

  gtk_text_thaw(GTK_TEXT(w));

} /* set_help_text */

static void clear_help_text(GtkWidget *w)
{
  GtkText *txt = GTK_TEXT(w);

  gtk_text_set_point(txt, 0);
  /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see 
     http://www.ethereal.com/lists/ethereal-dev/199912/msg00312.html and
     http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
     for more information */
  gtk_adjustment_set_value(txt->vadj, 0.0);
  gtk_text_forward_delete(txt, gtk_text_get_length(txt));
}

/* Redraw all the text widgets, to use a new font. */
void help_redraw(void)
{
  if (help_w != NULL) {
    gtk_text_freeze(GTK_TEXT(overview_text));
    clear_help_text(overview_text);
    set_help_text(overview_text, OVERVIEW_HELP);
    gtk_text_thaw(GTK_TEXT(overview_text));

    gtk_text_freeze(GTK_TEXT(proto_text));
    clear_help_text(proto_text);
    set_help_text(proto_text, PROTOCOL_HELP);
    gtk_text_thaw(GTK_TEXT(proto_text));

    gtk_text_freeze(GTK_TEXT(dfilter_text));
    clear_help_text(dfilter_text);
    set_help_text(dfilter_text, DFILTER_HELP);
    gtk_text_thaw(GTK_TEXT(dfilter_text));

    gtk_text_freeze(GTK_TEXT(cfilter_text));
    clear_help_text(cfilter_text);
    set_help_text(cfilter_text, CFILTER_HELP);
    gtk_text_thaw(GTK_TEXT(cfilter_text));
  }
}
