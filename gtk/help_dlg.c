/* help_dlg.c
 *
 * $Id: help_dlg.c,v 1.6 2000/08/22 06:38:32 gram Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 *
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
#include "util.h"
#include "ui_util.h"

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

void help_cb(GtkWidget *w, gpointer data)
{

  GtkWidget *main_vb, *bbox, *help_nb, *close_bt, *label, *txt_scrollw,
    *overview_vb, *overview_text,
    *proto_vb, *proto_text,
    *dfilter_vb, *dfilter_text,
    *cfilter_vb, *cfilter_text;
  
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
  txt_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(overview_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(txt_scrollw, prefs.gui_scrollbar_on_right);
  remember_scrolled_window(txt_scrollw);
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
  
  txt_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(proto_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_ALWAYS,
				 GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(txt_scrollw, prefs.gui_scrollbar_on_right);
  remember_scrolled_window(txt_scrollw);
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

  dfilter_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(dfilter_vb), 1);  
  txt_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(dfilter_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_ALWAYS,
				 GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(txt_scrollw, prefs.gui_scrollbar_on_right);
  remember_scrolled_window(txt_scrollw);
  dfilter_text = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(dfilter_text), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(dfilter_text), FALSE);
  set_help_text(dfilter_text, DFILTER_HELP);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(txt_scrollw),
					dfilter_text);  
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(dfilter_text);
  gtk_widget_show(dfilter_vb);
  label = gtk_label_new("Display Filters");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), dfilter_vb, label);

  /* capture filter help (this one has no horizontal scrollbar) */

  cfilter_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(cfilter_vb), 1);  
  txt_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(cfilter_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(txt_scrollw, prefs.gui_scrollbar_on_right);
  remember_scrolled_window(txt_scrollw);
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
"from the display filter syntax: see manual page of tcpdump.\n";

static char *overview_help = 
"Ethereal is a GUI network protocol analyzer. It lets you interactively "
"browse packet data from a live network or from a previously saved capture "
"file. Ethereal knows how to read libpcap capture files, including those "
"of tcpdump. In addition, Ethereal can read capture files from snoop "
"(including Shomiti) and atmsnoop, LanAlyzer, Sniffer (compressed or "
"uncompressed), Microsoft Network Monitor, AIX's iptrace, NetXray, "
"Sniffer Pro, RADCOM's WAN/LAN analyzer, Lucent/Ascend router debug output, "
"HP-UX's nettl, the dump output from Toshiba's ISDN routers, and i4btrace "
"from the ISDN4BSD project. There is no need to tell Ethereal what type of "
"file you are reading; it will determine the file type by itself. Ethereal "
"is also capable of reading any of these file formats if they are compressed "
"using gzip. Ethereal recognizes this directly from the file; the '.gz' "
"extension is not required for this purpose.";

static void set_help_text(GtkWidget *w, help_type_t type)
{

#define BUFF_LEN 4096
#define B_LEN    256
  char buffer[BUFF_LEN];
  header_field_info *hfinfo;
  int i, len, maxlen = 0, maxlen2 = 0, maxlen3 = 0, nb_lines = 0;
  int width, height;
  char *type_name;
  char blanks[B_LEN];

  /*
   * XXX quick hack:
   * the width and height computations are performed to make the
   * horizontal scrollbar work. This is only necessary for the
   * PROTOCOL_HELP and DFILTER_HELP windows since all others should
   * not have any horizontal scrollbar (line wrapping enabled).
   */

  memset(blanks, ' ', B_LEN - 2);
  blanks[B_LEN-1] = '\0';

  gtk_text_freeze(GTK_TEXT(w));

  switch(type) {

  case OVERVIEW_HELP :
    set_text(w, overview_help, -1);
    break;

  case PROTOCOL_HELP :    
    /* first pass to know the maximum length of first field */
    for (i = 0; i < proto_registrar_n() ; i++) {
      if (proto_registrar_is_protocol(i)) {
	hfinfo = proto_registrar_get_nth(i);
	if ((len = strlen(hfinfo->abbrev)) > maxlen)
	  maxlen = len;
      }
    }

    maxlen++;

    maxlen2 = strlen(proto_help);
    width = gdk_string_width(m_r_font, proto_help);
    set_text(w, proto_help, maxlen2);
    
    /* ok, display the correctly aligned strings */
    for (i = 0; i < proto_registrar_n() ; i++) {
      if (proto_registrar_is_protocol(i)) {
	int blks;
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
    }

    height = (2 + nb_lines) * (m_r_font->ascent + m_r_font->descent);
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

	/* XXX should convert this ? */
	switch(hfinfo->type) {
	case FT_NONE:
	  type_name = "FT_NONE";
	  break;
	case FT_BOOLEAN:
	  type_name = "FT_BOOLEAN";
	  break;
	case FT_UINT8:
	  type_name = "FT_UINT8";
	  break;
	case FT_UINT16:
	  type_name = "FT_UINT16";
	  break;
	case FT_UINT24:
	  type_name = "FT_UINT24";
	  break;
	case FT_UINT32:
	  type_name = "FT_UINT32";
	  break;
	case FT_INT8:
	  type_name = "FT_INT8";
	  break;
	case FT_INT16:
	  type_name = "FT_INT16";
	  break;
	case FT_INT24:
	  type_name = "FT_INT24";
	  break;
	case FT_INT32:
	  type_name = "FT_INT32";
	  break;
	case FT_DOUBLE:
	  type_name = "FT_DOUBLE";
	  break;
	case FT_ABSOLUTE_TIME:
	  type_name = "FT_ABSOLUTE_TIME";
	  break;
	case FT_RELATIVE_TIME:
	  type_name = "FT_RELATIVE_TIME";
	  break;
	case FT_UINT_STRING:
	  type_name = "FT_UINT_STRING";
	  break;
	case FT_STRING:
	  type_name = "FT_STRING";
	  break;
	case FT_ETHER:
	  type_name = "FT_ETHER";
	  break;
	case FT_BYTES:
	  type_name = "FT_BYTES";
	  break;
	case FT_IPv4:
	  type_name = "FT_IPv4";
	  break;
	case FT_IPv6:
	  type_name = "FT_IPv6";
	  break;
	case FT_IPXNET:
	  type_name = "FT_IPXNET";
	  break;
	case FT_TEXT_ONLY:
	  type_name = "FT_TEXT_ONLY";
	  break;
	default:
	  g_assert_not_reached();
	  type_name = NULL;
	}
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

      height = (1 + nb_lines) * (m_r_font->ascent + m_r_font->descent);
      gtk_widget_set_usize(GTK_WIDGET(w), 20 + width, 20 + height);

    }
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
