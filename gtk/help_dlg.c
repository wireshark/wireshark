/* help_dlg.c
 *
 * $Id: help_dlg.c,v 1.35 2003/08/25 21:42:33 guy Exp $
 *
 * Laurent Deniel <laurent.deniel@free.fr>
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
#include <string.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "help_dlg.h"
#include "prefs.h"
#include "globals.h"
#include "gtkglobals.h"
#include "main.h"
#include "ui_util.h"
#include <epan/proto.h>
#include "compat_macros.h"

typedef enum {
  OVERVIEW_HELP,
  PROTOCOL_HELP,
  DFILTER_HELP,
  CFILTER_HELP,
  FAQ_HELP
} help_type_t;

static void help_close_cb(GtkWidget *w, gpointer data);
static void help_destroy_cb(GtkWidget *w, gpointer data);
static void insert_text(GtkWidget *w, const char *buffer, int nchars);
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
GtkWidget *overview_text, *proto_text, *dfilter_text, *faq_text, *cfilter_text;

void help_cb(GtkWidget *w _U_, gpointer data _U_)
{

  GtkWidget *main_vb, *bbox, *help_nb, *close_bt, *label, *txt_scrollw,
    *overview_vb,
    *proto_vb,
#if GTK_MAJOR_VERSION < 2
    *dfilter_tb, *dfilter_vsb,
#else
    *dfilter_vb,
#endif
    *faq_vb,
    *cfilter_vb;

  if (help_w != NULL) {
    /* There's already a "Help" dialog box; reactivate it. */
    reactivate_window(help_w);
    return;
  }

#if GTK_MAJOR_VERSION < 2
  help_w = gtk_window_new(GTK_WINDOW_DIALOG);
#else
  help_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
#endif
  gtk_widget_set_name(help_w, "Ethereal Help window" );
  gtk_window_set_title(GTK_WINDOW(help_w), "Ethereal: Help");
  SIGNAL_CONNECT(help_w, "destroy", help_destroy_cb, NULL);
  SIGNAL_CONNECT(help_w, "realize", window_icon_realize_cb, NULL);
  WIDGET_SET_SIZE(help_w, DEF_WIDTH * 2/3, DEF_HEIGHT * 2/3);
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
#if GTK_MAJOR_VERSION < 2
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_ALWAYS);
  overview_text = gtk_text_new(NULL, NULL );
  gtk_text_set_editable(GTK_TEXT(overview_text), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(overview_text), TRUE);
  gtk_text_set_line_wrap(GTK_TEXT(overview_text), TRUE);
#else
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_AUTOMATIC,
				 GTK_POLICY_AUTOMATIC);
  overview_text = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(overview_text), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(overview_text), GTK_WRAP_WORD);
#endif
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
#if GTK_MAJOR_VERSION < 2
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_ALWAYS,
				 GTK_POLICY_ALWAYS);
  proto_text = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(proto_text), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(proto_text), FALSE);
  set_help_text(proto_text, PROTOCOL_HELP);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(txt_scrollw),
					proto_text);
#else
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_AUTOMATIC,
				 GTK_POLICY_AUTOMATIC);
  proto_text = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(proto_text), FALSE);
  set_help_text(proto_text, PROTOCOL_HELP);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), proto_text);
#endif
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(proto_text);
  gtk_widget_show(proto_vb);
  label = gtk_label_new("Protocols");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), proto_vb, label);

  /* display filter help */
#if GTK_MAJOR_VERSION < 2
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
#else
  dfilter_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(dfilter_vb), 1);

  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(dfilter_vb), txt_scrollw, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_AUTOMATIC,
				 GTK_POLICY_AUTOMATIC);
  dfilter_text = gtk_text_view_new();
  if (prefs.gui_scrollbar_on_right) {
    gtk_scrolled_window_set_placement(GTK_SCROLLED_WINDOW(txt_scrollw),
                                      GTK_CORNER_TOP_LEFT);
  }
  else {
    gtk_scrolled_window_set_placement(GTK_SCROLLED_WINDOW(txt_scrollw),
                                      GTK_CORNER_TOP_RIGHT);
  }
  gtk_text_view_set_editable(GTK_TEXT_VIEW(dfilter_text), FALSE);
  set_help_text(dfilter_text, DFILTER_HELP);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), dfilter_text);
#endif
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(dfilter_text);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_show(dfilter_tb);
  gtk_widget_show(dfilter_vsb);
#else
  gtk_widget_show(dfilter_vb);
#endif
  label = gtk_label_new("Display Filters");
#if GTK_MAJOR_VERSION < 2
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), dfilter_tb, label);
#else
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), dfilter_vb, label);
#endif

  /* capture filter help (this one has no horizontal scrollbar) */

  cfilter_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(cfilter_vb), 1);
  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(cfilter_vb), txt_scrollw, TRUE, TRUE, 0);
#if GTK_MAJOR_VERSION < 2
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_ALWAYS);
  cfilter_text = gtk_text_new(NULL, NULL );
  gtk_text_set_editable(GTK_TEXT(cfilter_text), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(cfilter_text), TRUE);
  gtk_text_set_line_wrap(GTK_TEXT(cfilter_text), TRUE);
#else
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_AUTOMATIC);
  cfilter_text = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(cfilter_text), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(cfilter_text), GTK_WRAP_WORD);
#endif
  set_help_text(cfilter_text, CFILTER_HELP);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), cfilter_text);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(cfilter_text);
  gtk_widget_show(cfilter_vb);
  label = gtk_label_new("Capture Filters");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), cfilter_vb, label);

  /* FAQ help (this one has no horizontal scrollbar) */

  faq_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(faq_vb), 1);
  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(faq_vb), txt_scrollw, TRUE, TRUE, 0);
#if GTK_MAJOR_VERSION < 2
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_ALWAYS);
  faq_text = gtk_text_new(NULL, NULL );
  gtk_text_set_editable(GTK_TEXT(faq_text), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(faq_text), TRUE);
  gtk_text_set_line_wrap(GTK_TEXT(faq_text), TRUE);
#else
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER,
				 GTK_POLICY_AUTOMATIC);
  faq_text = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(faq_text), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(faq_text), GTK_WRAP_WORD);
#endif
  set_help_text(faq_text, FAQ_HELP);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), faq_text);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(faq_text);
  gtk_widget_show(faq_vb);
  label = gtk_label_new("FAQ");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), faq_vb, label);

  /* XXX add other help panels here ... */

  gtk_widget_show(help_nb);

  /* Buttons (only one for now) */

  bbox = gtk_hbox_new(FALSE, 1);
  gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);
#if GTK_MAJOR_VERSION < 2
  close_bt = gtk_button_new_with_label("Close");
#else
  close_bt = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
#endif
  SIGNAL_CONNECT(close_bt, "clicked", help_close_cb, help_w);
  GTK_WIDGET_SET_FLAGS(close_bt, GTK_CAN_DEFAULT);
  gtk_container_add(GTK_CONTAINER(bbox), close_bt);
  gtk_widget_grab_default(close_bt);
  gtk_widget_show(close_bt);

  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(help_w));
  gtk_widget_show(help_w);

} /* help_cb */

static void help_close_cb(GtkWidget *w _U_, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void help_destroy_cb(GtkWidget *w _U_, gpointer data _U_)
{
  /* Note that we no longer have a Help window. */
  help_w = NULL;
}

static void insert_text(GtkWidget *w, const char *buffer, int nchars)
{
#if GTK_MAJOR_VERSION < 2
    gtk_text_insert(GTK_TEXT(w), m_r_font, NULL, NULL, buffer, nchars);
#else
    GtkTextBuffer *buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(w));
    GtkTextIter    iter;

    gtk_text_buffer_get_end_iter(buf, &iter);
    gtk_widget_modify_font(w, m_r_font);
    if (!g_utf8_validate(buffer, -1, NULL))
        printf(buffer);
    gtk_text_buffer_insert(buf, &iter, buffer, nchars);
#endif
}

static const char *proto_help =
"The following %d protocols (and packet types) are currently\n"
"supported by Ethereal:\n\n";

static const char *dfilter_help =
"The following per-protocol fields can be used in display\n"
"filters:\n";

static const char *cfilter_help =
"Packet capturing is performed with the pcap library. The capture filter "
"syntax follows the rules of this library.\nSo this syntax is different "
"from the display filter syntax: see manual page of tcpdump.\n"
#ifndef HAVE_LIBPCAP
"\nNote: packet capturing is not enabled in this version.\n";
#else
;
#endif

static const char *overview_help =
"Ethereal is a GUI network protocol analyzer.  It lets you interactively "
"browse packet data from a live network or from a previously saved "
"capture file.  Ethereal's native capture file format is libpcap format, "
"which is also the format used by tcpdump and various other tools.  In "
"addition, Ethereal can read capture files from snoop and atmsnoop, "
"Shomiti/Finisar Surveyor, Novell LANalyzer, Network General/Network "
"Associates DOS-based Sniffer (compressed or uncompressed), Microsoft "
"Network Monitor, AIX's iptrace, Cinco Networks NetXRay, Network "
"Associates Windows-based Sniffer, AG Group/WildPackets "
"EtherPeek/TokenPeek/AiroPeek, RADCOM's WAN/LAN analyzer, Lucent/Ascend "
"router debug output, HP-UX's nettl, the dump output from Toshiba's ISDN "
"routers, the output from i4btrace from the ISDN4BSD project, the output "
"in IPLog format from the Cisco Secure Intrusion Detection System, pppd "
"logs (pppdump format), the output from VMS's TCPIPtrace utility, the "
"text output from the DBS Etherwatch VMS utility, traffic capture files "
"from Visual Networks' Visual UpTime, and the output from CoSine L2 debug."
"\n\n"
"There is no need to tell Ethereal what type of file you are reading; " 
"it will determine the file type by itself.  Ethereal is also "
"capable of reading any of these file formats if they are compressed "
"using gzip.  Ethereal recognizes this directly from the file; the '.gz' "
"extension is not required for this purpose.";

/* FAQ_PARTS, FAQ_SIZE, faq_part[0] ... faq_part[FAQ_PARTS-1] */
#include "../FAQ.include"

static void set_help_text(GtkWidget *w, help_type_t type)
{

#define BUFF_LEN 4096
#define B_LEN    256
  char buffer[BUFF_LEN];
  header_field_info *hfinfo;
  int i, len, maxlen = 0, maxlen2 = 0, maxlen4 = 0;
#if GTK_MAJOR_VERSION < 2
  int maxlen3 = 0, nb_lines = 0;
  int width, height;
#endif
  const char *type_name;
  void *cookie, *cookie2;
  char *name, *short_name, *filter_name;
  int namel = 0, short_namel = 0, filter_namel = 0;
  int count, fcount;

  /*
   * XXX quick hack:
   * the width and height computations are performed to make the
   * horizontal scrollbar work in gtk1.2. This is only necessary for the
   * PROTOCOL_HELP and DFILTER_HELP windows since all others should
   * not have any horizontal scrollbar (line wrapping enabled).
   */


#if GTK_MAJOR_VERSION < 2
  gtk_text_freeze(GTK_TEXT(w));
#endif

  switch(type) {

  case OVERVIEW_HELP :
    insert_text(w, overview_help, -1);
    break;

  case PROTOCOL_HELP :
    /* first pass to know the maximum length of first field */
    count = 0;
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {
	    count++;
	    name = proto_get_protocol_name(i);
	    short_name = proto_get_protocol_short_name(i);
	    filter_name = proto_get_protocol_filter_name(i);
	    if ((len = strlen(name)) > namel)
		    namel = len;
	    if ((len = strlen(short_name)) > short_namel)
		    short_namel = len;
	    if ((len = strlen(filter_name)) > filter_namel)
		    filter_namel = len;
    }
    maxlen = namel + short_namel + filter_namel;

    len = snprintf(buffer, BUFF_LEN, proto_help, count);
#if GTK_MAJOR_VERSION < 2
    maxlen2 = len;
    width = gdk_string_width(m_r_font, buffer);
    insert_text(w, buffer, maxlen2);
#else
    insert_text(w, buffer, len);
#endif

    /* ok, display the correctly aligned strings */
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {
	    name = proto_get_protocol_name(i);
	    short_name = proto_get_protocol_short_name(i);
	    filter_name = proto_get_protocol_filter_name(i);
 
	    /* the name used for sorting in the left column */
	    len = snprintf(buffer, BUFF_LEN, "%*s %*s %*s\n",
			   -short_namel,  short_name,
			   -namel,	  name,
			   -filter_namel, filter_name);
#if GTK_MAJOR_VERSION < 2
	    if (len > maxlen2) {
		    maxlen2 = len;
		    if ((len = gdk_string_width(m_r_font, buffer)) > width)
			    width = len;
	    }
	    insert_text(w, buffer, strlen(buffer));
	    nb_lines++;
#else
	    insert_text(w, buffer, strlen(buffer));
#endif
    }

#if GTK_MAJOR_VERSION < 2
    height = (3 + nb_lines) * m_font_height;
    WIDGET_SET_SIZE(w, 20 + width, 20 + height);
#endif
    break;

  case DFILTER_HELP  :

    /* XXX we should display hinfo->blurb instead of name (if not empty) */

    /* first pass to know the maximum length of first and second fields */
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {

	    for (hfinfo = proto_get_first_protocol_field(i, &cookie2); hfinfo != NULL;
		 hfinfo = proto_get_next_protocol_field(&cookie2)) {

		    if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
			    continue;

		    if ((len = strlen(hfinfo->abbrev)) > maxlen)
			    maxlen = len;
		    if ((len = strlen(hfinfo->name)) > maxlen2)
			    maxlen2 = len;
		    if ((len = strlen(hfinfo->blurb)) > maxlen4)
			    maxlen4 = len;
	    }
    }

#if GTK_MAJOR_VERSION < 2
    maxlen3 = strlen(dfilter_help);
    width = gdk_string_width(m_r_font, dfilter_help);
    insert_text(w, dfilter_help, maxlen3);
#else
    insert_text(w, dfilter_help, strlen(dfilter_help));
#endif

    fcount = 0;
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {
	    name = proto_get_protocol_name(i);
	    short_name = proto_get_protocol_short_name(i);
	    filter_name = proto_get_protocol_filter_name(i);

	    count = 0;
	    for (hfinfo = proto_get_first_protocol_field(i, &cookie2); hfinfo != NULL;
		 hfinfo = proto_get_next_protocol_field(&cookie2)) {

		    if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
			    continue;
		    count++;
	    }
	    fcount += count;

	    len = snprintf(buffer, BUFF_LEN, "\n%s - %s (%s) [%d fields]:\n",
			   short_name, name, filter_name, count);
	    insert_text(w, buffer, len);

	    for (hfinfo = proto_get_first_protocol_field(i, &cookie2); hfinfo != NULL;
		 hfinfo = proto_get_next_protocol_field(&cookie2)) {

		    if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
			    continue;

		    type_name = ftype_pretty_name(hfinfo->type);
		    len = snprintf(buffer, BUFF_LEN, "%*s %*s %*s (%s)\n",
				   -maxlen,  hfinfo->abbrev,
				   -maxlen2, hfinfo->name,
				   -maxlen4, hfinfo->blurb,
				   type_name);
#if GTK_MAJOR_VERSION < 2
		    if (len > maxlen3) {
			    maxlen3 = len;
			    if ((len = gdk_string_width(m_r_font, buffer)) > width)
				    width = len;
		    }
		    insert_text(w, buffer, strlen(buffer));
		    nb_lines ++;
#else
		    insert_text(w, buffer, strlen(buffer));
#endif
	    }
    }
    len = snprintf(buffer, BUFF_LEN, "\n-- Total %d fields\n", fcount);
    insert_text(w, buffer, len);

#if GTK_MAJOR_VERSION < 2
    height = (5 + nb_lines) * m_font_height;
    WIDGET_SET_SIZE(w, 20 + width, 20 + height);
#endif
    break;
  case FAQ_HELP :
    for (i=0; i<FAQ_PARTS; i++) {
      insert_text(w, faq_part[i], strlen(faq_part[i]));
    }
    break;
  case CFILTER_HELP :
    insert_text(w, cfilter_help, -1);
    break;
  default :
    g_assert_not_reached();
    break;
  } /* switch(type) */
#if GTK_MAJOR_VERSION < 2
  gtk_text_thaw(GTK_TEXT(w));
#endif
} /* set_help_text */

static void clear_help_text(GtkWidget *w)
{
#if GTK_MAJOR_VERSION < 2
  GtkText *txt = GTK_TEXT(w);

  gtk_text_set_point(txt, 0);
  /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see
     http://www.ethereal.com/lists/ethereal-dev/199912/msg00312.html and
     http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
     for more information */
  gtk_adjustment_set_value(txt->vadj, 0.0);
  gtk_text_forward_delete(txt, gtk_text_get_length(txt));
#else
  GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(w));

  gtk_text_buffer_set_text(buf, "", 0);
#endif
}

/* Redraw all the text widgets, to use a new font. */
void help_redraw(void)
{
  if (help_w != NULL) {
#if GTK_MAJOR_VERSION < 2
    gtk_text_freeze(GTK_TEXT(overview_text));
#endif
    clear_help_text(overview_text);
    set_help_text(overview_text, OVERVIEW_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(overview_text));

    gtk_text_freeze(GTK_TEXT(proto_text));
#endif
    clear_help_text(proto_text);
    set_help_text(proto_text, PROTOCOL_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(proto_text));

    gtk_text_freeze(GTK_TEXT(dfilter_text));
#endif
    clear_help_text(dfilter_text);
    set_help_text(dfilter_text, DFILTER_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(dfilter_text));

    gtk_text_freeze(GTK_TEXT(cfilter_text));
#endif
    clear_help_text(cfilter_text);
    set_help_text(cfilter_text, CFILTER_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(cfilter_text));

    gtk_text_freeze(GTK_TEXT(faq_text));
#endif
    clear_help_text(faq_text);
    set_help_text(faq_text, FAQ_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(faq_text));
#endif
  }
}
