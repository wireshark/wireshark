/* stream_prefs.c
 * Dialog boxes for preferences for the stream window
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
#include "config.h"
#endif

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "../color.h"
#include "../print.h"

#include "gtk/color_utils.h"
#include "gtk/prefs_stream.h"
#include "gtk/keys.h"
#include "gtk/follow_tcp.h"


#define SAMPLE_MARKED_TEXT  "Sample marked packet text\n"
#define SAMPLE_IGNORED_TEXT "Sample ignored packet text\n"
#define SAMPLE_CLIENT_TEXT  "Sample TCP stream client text\n"
#define SAMPLE_SERVER_TEXT  "Sample TCP stream server text\n"
#define MFG_IDX 0
#define MBG_IDX 1
#define IFG_IDX 2
#define IBG_IDX 3
#define CFG_IDX 4
#define CBG_IDX 5
#define SFG_IDX 6
#define SBG_IDX 7
#define MAX_IDX 8 /* set this to the number of IDX values */
#define STREAM_SAMPLE_KEY "stream_entry"
#define STREAM_CS_KEY "stream_colorselection"
#define CS_RED 0
#define CS_GREEN 1
#define CS_BLUE 2
#define CS_OPACITY 3

static void update_text_color(GtkWidget *, gpointer);
static void update_current_color(GtkWidget *, gpointer);

static GdkColor tcolors[MAX_IDX], *curcolor = NULL;

GtkWidget *
stream_prefs_show(void)
{
  GtkWidget *main_vb, *main_tb, *label, *combo_box;
  GtkWidget *sample, *colorsel;
  int        width, height, i;
  const gchar     *mt[] = {
	  "Marked packet foreground",		/* MFG_IDX 0*/
	  "Marked packet background",		/* MBG_IDX 1*/
	  "Ignored packet foreground",		/* IFG_IDX 2*/
	  "Ignored packet background",		/* IBG_IDX 3*/
	  "TCP stream client foreground",	/* CFG_IDX 4*/
	  "TCP stream client background",	/* CBG_IDX 5*/
	  "TCP stream server foreground",	/* SFG_IDX 6*/
	  "TCP stream server background"	/* SBG_IDX 7*/
  };
  int mcount = sizeof(mt) / sizeof (gchar *);
  GtkTextBuffer *buf;
  GtkTextIter    iter;
  PangoLayout   *layout;

  color_t_to_gdkcolor(&tcolors[MFG_IDX], &prefs.gui_marked_fg);
  color_t_to_gdkcolor(&tcolors[MBG_IDX], &prefs.gui_marked_bg);
  color_t_to_gdkcolor(&tcolors[IFG_IDX], &prefs.gui_ignored_fg);
  color_t_to_gdkcolor(&tcolors[IBG_IDX], &prefs.gui_ignored_bg);
  color_t_to_gdkcolor(&tcolors[CFG_IDX], &prefs.st_client_fg);
  color_t_to_gdkcolor(&tcolors[CBG_IDX], &prefs.st_client_bg);
  color_t_to_gdkcolor(&tcolors[SFG_IDX], &prefs.st_server_fg);
  color_t_to_gdkcolor(&tcolors[SBG_IDX], &prefs.st_server_bg);

  curcolor = &tcolors[CFG_IDX];

  /* Enclosing containers for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);

  main_tb = gtk_table_new(3, 3, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);

  label = gtk_label_new("Set:");
  gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 0, 1);
  gtk_widget_show(label);

  /* We have to create this now, and configure it below. */
  colorsel = gtk_color_selection_new();

  combo_box = gtk_combo_box_new_text ();
  for (i = 0; i < mcount; i++){
	  gtk_combo_box_append_text (GTK_COMBO_BOX (combo_box), mt[i]);
  }
  gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), CFG_IDX);
  g_signal_connect(combo_box, "changed", G_CALLBACK(update_current_color), colorsel);
  gtk_table_attach(GTK_TABLE(main_tb), combo_box, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);

  gtk_widget_show(combo_box);

  sample = gtk_text_view_new();
  layout = gtk_widget_create_pango_layout(sample, SAMPLE_SERVER_TEXT);
  pango_layout_get_pixel_size(layout, &width, &height);
  g_object_unref(G_OBJECT(layout));
  gtk_widget_set_size_request(sample, width, height * 2);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(sample), FALSE);
  buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(sample));
  gtk_text_buffer_get_start_iter(buf, &iter);
  gtk_text_buffer_create_tag(buf, "marked",
                             "foreground-gdk", &tcolors[MFG_IDX],
                             "background-gdk", &tcolors[MBG_IDX], NULL);
  gtk_text_buffer_create_tag(buf, "ignored",
                             "foreground-gdk", &tcolors[IFG_IDX],
                             "background-gdk", &tcolors[IBG_IDX], NULL);
  gtk_text_buffer_create_tag(buf, "client",
                             "foreground-gdk", &tcolors[CFG_IDX],
                             "background-gdk", &tcolors[CBG_IDX], NULL);
  gtk_text_buffer_create_tag(buf, "server",
                             "foreground-gdk", &tcolors[SFG_IDX],
                             "background-gdk", &tcolors[SBG_IDX], NULL);
  gtk_text_buffer_insert_with_tags_by_name(buf, &iter, SAMPLE_MARKED_TEXT, -1,
                                           "marked", NULL);
  gtk_text_buffer_insert_with_tags_by_name(buf, &iter, SAMPLE_IGNORED_TEXT, -1,
                                           "ignored", NULL);
  gtk_text_buffer_insert_with_tags_by_name(buf, &iter, SAMPLE_CLIENT_TEXT, -1,
                                           "client", NULL);
  gtk_text_buffer_insert_with_tags_by_name(buf, &iter, SAMPLE_SERVER_TEXT, -1,
                                           "server", NULL);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), sample, 2, 3, 0, 2);
  gtk_widget_show(sample);

  gtk_color_selection_set_current_color(GTK_COLOR_SELECTION(colorsel),
                                        curcolor);
  gtk_table_attach(GTK_TABLE(main_tb), colorsel, 0, 3, 2, 3,
		  GTK_SHRINK, GTK_SHRINK, 0, 0);

  g_object_set_data(G_OBJECT(colorsel), STREAM_SAMPLE_KEY, sample);
  g_signal_connect(colorsel, "color-changed", G_CALLBACK(update_text_color), NULL);
  gtk_widget_show(colorsel);

  gtk_widget_show(main_vb);
  return(main_vb);
}

static void
update_text_color(GtkWidget *w, gpointer data _U_) {
  GtkTextView *sample = g_object_get_data(G_OBJECT(w), STREAM_SAMPLE_KEY);
  GtkTextBuffer *buf;
  GtkTextTag    *tag;

  gtk_color_selection_get_current_color(GTK_COLOR_SELECTION(w), curcolor);

  buf = gtk_text_view_get_buffer(sample);
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "marked");
  g_object_set(tag, "foreground-gdk", &tcolors[MFG_IDX], "background-gdk",
               &tcolors[MBG_IDX], NULL);
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "ignored");
  g_object_set(tag, "foreground-gdk", &tcolors[IFG_IDX], "background-gdk",
               &tcolors[IBG_IDX], NULL);
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "client");
  g_object_set(tag, "foreground-gdk", &tcolors[CFG_IDX], "background-gdk",
               &tcolors[CBG_IDX], NULL);
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "server");
  g_object_set(tag, "foreground-gdk", &tcolors[SFG_IDX], "background-gdk",
               &tcolors[SBG_IDX], NULL);
}

static void
update_current_color(GtkWidget *combo_box, gpointer data)
{
  GtkColorSelection *colorsel = data;
  int i;

  i = gtk_combo_box_get_active (GTK_COMBO_BOX(combo_box));
  curcolor = &tcolors[i];

  gtk_color_selection_set_current_color(colorsel, curcolor);
}

void
stream_prefs_fetch(GtkWidget *w _U_)
{
  gdkcolor_to_color_t(&prefs.gui_marked_fg, &tcolors[MFG_IDX]);
  gdkcolor_to_color_t(&prefs.gui_marked_bg, &tcolors[MBG_IDX]);
  gdkcolor_to_color_t(&prefs.gui_ignored_fg, &tcolors[IFG_IDX]);
  gdkcolor_to_color_t(&prefs.gui_ignored_bg, &tcolors[IBG_IDX]);
  gdkcolor_to_color_t(&prefs.st_client_fg, &tcolors[CFG_IDX]);
  gdkcolor_to_color_t(&prefs.st_client_bg, &tcolors[CBG_IDX]);
  gdkcolor_to_color_t(&prefs.st_server_fg, &tcolors[SFG_IDX]);
  gdkcolor_to_color_t(&prefs.st_server_bg, &tcolors[SBG_IDX]);
}

void
stream_prefs_apply(GtkWidget *w _U_)
{
	follow_tcp_redraw_all();
}

void
stream_prefs_destroy(GtkWidget *w _U_)
{
}
