/* supported_protos_dlg.c
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <stdio.h>
#include <string.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "../globals.h"

#include "gtk/supported_protos_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/font_utils.h"



static const char *proto_supported =
"The following %d protocols (and packet types) are currently\n"
"supported by Wireshark:\n\n";

static const char *dfilter_supported =
"The following per-protocol fields are currently supported by\n"
"Wireshark and can be used in display filters:\n";



typedef enum {
  PROTOCOL_SUPPORTED,
  DFILTER_SUPPORTED
} supported_type_t;

static void supported_destroy_cb(GtkWidget *w, gpointer data);
static void insert_text(GtkWidget *w, const char *buffer, int nchars);
static void set_supported_text(GtkWidget *w, supported_type_t type);

/*
 * Keep a static pointer to the current "Supported" window, if any, so that
 * if somebody tries to do "Help->Supported" while there's already a
 * "Supported" window up, we just pop up the existing one, rather than
 * creating a new one.
*/
static GtkWidget *supported_w = NULL;

/*
 * Keep static pointers to the text widgets as well (for text format changes).
 */
static GtkWidget *proto_text, *dfilter_text;



void supported_cb(GtkWidget *w _U_, gpointer data _U_)
{

  GtkWidget *main_vb, *bbox, *supported_nb, *ok_bt, *label, *txt_scrollw,
    *proto_vb,
    *dfilter_vb;

  if (supported_w != NULL) {
    /* There's already a "Supported" dialog box; reactivate it. */
    reactivate_window(supported_w);
    return;
  }

  supported_w = window_new(GTK_WINDOW_TOPLEVEL, "Wireshark: Supported Protocols");
  gtk_window_set_default_size(GTK_WINDOW(supported_w), DEF_WIDTH * 2/3, DEF_HEIGHT * 2/3);
  gtk_container_set_border_width(GTK_CONTAINER(supported_w), 2);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 1);
  gtk_container_add(GTK_CONTAINER(supported_w), main_vb);
  gtk_widget_show(main_vb);

  /* supported topics container */
  supported_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), supported_nb);


  /* protocol list */
  proto_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(proto_vb), 1);

  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw),
                                   GTK_SHADOW_IN);
  gtk_box_pack_start(GTK_BOX(proto_vb), txt_scrollw, TRUE, TRUE, 0);
  proto_text = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(proto_text), FALSE);
  set_supported_text(proto_text, PROTOCOL_SUPPORTED);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), proto_text);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(proto_text);
  gtk_widget_show(proto_vb);
  label = gtk_label_new("Protocols");
  gtk_notebook_append_page(GTK_NOTEBOOK(supported_nb), proto_vb, label);

  /* display filter fields */
  dfilter_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(dfilter_vb), 1);

  txt_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw),
                                   GTK_SHADOW_IN);
  gtk_box_pack_start(GTK_BOX(dfilter_vb), txt_scrollw, TRUE, TRUE, 0);
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
  set_supported_text(dfilter_text, DFILTER_SUPPORTED);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), dfilter_text);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(dfilter_text);
  gtk_widget_show(dfilter_vb);
  label = gtk_label_new("Display Filter Fields");
  gtk_notebook_append_page(GTK_NOTEBOOK(supported_nb), dfilter_vb, label);

  /* XXX add other panels here ... */

  gtk_widget_show(supported_nb);

  /* Button row */
  bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
  gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  window_set_cancel_button(supported_w, ok_bt, window_cancel_button_cb);

  g_signal_connect(supported_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(supported_w, "destroy", G_CALLBACK(supported_destroy_cb), NULL);

  gtk_widget_show(supported_w);
  window_present(supported_w);
} /* supported_cb */

static void supported_destroy_cb(GtkWidget *w _U_, gpointer data _U_)
{
  /* Note that we no longer have a Help window. */
  supported_w = NULL;
}

static void insert_text(GtkWidget *w, const char *buffer, int nchars)
{
    GtkTextBuffer *buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(w));
    GtkTextIter    iter;

    gtk_text_buffer_get_end_iter(buf, &iter);
    gtk_widget_modify_font(w, user_font_get_regular());
    if (!g_utf8_validate(buffer, -1, NULL))
        printf("Invalid utf8 encoding: %s\n", buffer);  /* ToDo: Don't use printf ?? */
    gtk_text_buffer_insert(buf, &iter, buffer, nchars);
}


static void set_supported_text(GtkWidget *w, supported_type_t type)
{

#define BUFF_LEN 4096
#define B_LEN    256
  char buffer[BUFF_LEN];
  header_field_info *hfinfo;
  int i, len, maxlen = 0, maxlen2 = 0, maxlen4 = 0;
  const char *type_name;
  void *cookie, *cookie2;
  protocol_t *protocol;
  const char *name, *short_name, *filter_name;
  int namel = 0, short_namel = 0, filter_namel = 0;
  int count, fcount;


  /*
   * XXX quick hack:
   * the width and height computations are performed to make the
   * horizontal scrollbar work in gtk1.2. This is only necessary for the
   * PROTOCOL_SUPPORTED and DFILTER_SUPPORTED windows since all others should
   * not have any horizontal scrollbar (line wrapping enabled).
   */


  switch(type) {

  case PROTOCOL_SUPPORTED :
    /* first pass to know the maximum length of first field */
    count = 0;
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {
	    count++;
	    protocol = find_protocol_by_id(i);
	    name = proto_get_protocol_name(i);
	    short_name = proto_get_protocol_short_name(protocol);
	    filter_name = proto_get_protocol_filter_name(i);
	    if ((len = (int) strlen(name)) > namel)
		    namel = len;
	    if ((len = (int) strlen(short_name)) > short_namel)
		    short_namel = len;
	    if ((len = (int) strlen(filter_name)) > filter_namel)
		    filter_namel = len;
    }

    len = g_snprintf(buffer, BUFF_LEN, proto_supported, count);
    insert_text(w, buffer, len);

    /* ok, display the correctly aligned strings */
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {
	    protocol = find_protocol_by_id(i);
	    name = proto_get_protocol_name(i);
	    short_name = proto_get_protocol_short_name(protocol);
	    filter_name = proto_get_protocol_filter_name(i);

	    /* the name used for sorting in the left column */
	    len = g_snprintf(buffer, BUFF_LEN, "%*s %*s %*s\n",
			   -short_namel,  short_name,
			   -namel,	  name,
			   -filter_namel, filter_name);
	    insert_text(w, buffer, len);
    }

    break;

  case DFILTER_SUPPORTED  :

    /* XXX we should display hinfo->blurb instead of name (if not empty) */

    /* first pass to know the maximum length of first and second fields */
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {

	    for (hfinfo = proto_get_first_protocol_field(i, &cookie2); hfinfo != NULL;
		 hfinfo = proto_get_next_protocol_field(&cookie2)) {

		    if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
			    continue;

		    if ((len = (int) strlen(hfinfo->abbrev)) > maxlen)
			    maxlen = len;
		    if ((len = (int) strlen(hfinfo->name)) > maxlen2)
			    maxlen2 = len;
		    if (hfinfo->blurb != NULL) {
			    if ((len = (int) strlen(hfinfo->blurb)) > maxlen4)
				maxlen4 = len;
		    }
	    }
    }

    insert_text(w, dfilter_supported, (int) strlen(dfilter_supported));

    fcount = 0;
    for (i = proto_get_first_protocol(&cookie); i != -1;
         i = proto_get_next_protocol(&cookie)) {
	    protocol = find_protocol_by_id(i);
	    name = proto_get_protocol_name(i);
	    short_name = proto_get_protocol_short_name(protocol);
	    filter_name = proto_get_protocol_filter_name(i);

	    count = 0;
	    for (hfinfo = proto_get_first_protocol_field(i, &cookie2); hfinfo != NULL;
		 hfinfo = proto_get_next_protocol_field(&cookie2)) {

		    if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
			    continue;
		    count++;
	    }
	    fcount += count;

	    len = g_snprintf(buffer, BUFF_LEN, "\n%s - %s (%s) [%d fields]:\n",
			   short_name, name, filter_name, count);
	    insert_text(w, buffer, len);

	    for (hfinfo = proto_get_first_protocol_field(i, &cookie2); hfinfo != NULL;
		 hfinfo = proto_get_next_protocol_field(&cookie2)) {

		    if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
			    continue;

		    type_name = ftype_pretty_name(hfinfo->type);
		    if (hfinfo->blurb != NULL && hfinfo->blurb[0] != '\0') {
			    len = g_snprintf(buffer, BUFF_LEN, "%*s %*s %*s (%s)\n",
					     -maxlen,  hfinfo->abbrev,
					     -maxlen2, hfinfo->name,
					     -maxlen4, hfinfo->blurb,
					     type_name);
		    } else {
			    len = g_snprintf(buffer, BUFF_LEN, "%*s %*s (%s)\n",
					     -maxlen,  hfinfo->abbrev,
					     -maxlen2, hfinfo->name,
					     type_name);
		    }
		    insert_text(w, buffer, len);
	    }
    }
    len = g_snprintf(buffer, BUFF_LEN, "\n-- Total %d fields\n", fcount);
    insert_text(w, buffer, len);

    break;
  default :
    g_assert_not_reached();
    break;
  } /* switch(type) */
} /* set_supported_text */


static void clear_supported_text(GtkWidget *w)
{
  GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(w));

  gtk_text_buffer_set_text(buf, "", 0);
}


/* Redraw all the text widgets, to use a new font. */
void supported_redraw(void)
{
  if (supported_w != NULL) {
    clear_supported_text(proto_text);
    set_supported_text(proto_text, PROTOCOL_SUPPORTED);
    clear_supported_text(dfilter_text);
    set_supported_text(dfilter_text, DFILTER_SUPPORTED);
  }
}
