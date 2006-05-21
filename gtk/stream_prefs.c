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

#include "color.h"
#include "colors.h"
#include "globals.h"
#include "stream_prefs.h"
#include "keys.h"
#include "print.h"
#include <epan/prefs.h>
#include "compat_macros.h"
#include "follow_dlg.h"
#include "packet_list.h"

#define SAMPLE_MARKED_TEXT "Sample marked packet text\n"
#define SAMPLE_CLIENT_TEXT "Sample TCP stream client text\n"
#define SAMPLE_SERVER_TEXT "Sample TCP stream server text\n"
#define MFG_IDX 0
#define MBG_IDX 1
#define CFG_IDX 2
#define CBG_IDX 3
#define SFG_IDX 4
#define SBG_IDX 5
#define MAX_IDX 6 /* set this to the number of IDX values */
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
stream_prefs_show()
{
  GtkWidget *main_vb, *main_tb, *label, *optmenu, *menu, *menuitem;
  GtkWidget *sample, *colorsel;
  int        width, height, i;
  gchar     *mt[] = { "Marked packet foreground", "Marked packet background",
                      "TCP stream client foreground", "TCP stream client background",
                      "TCP stream server foreground", "TCP stream server background" };
  int mcount = sizeof(mt) / sizeof (gchar *);
#if GTK_MAJOR_VERSION < 2
  gdouble scolor[4];
#else
  GtkTextBuffer *buf;
  GtkTextIter    iter;
  PangoLayout   *layout;
#endif

  color_t_to_gdkcolor(&tcolors[MFG_IDX], &prefs.gui_marked_fg);
  color_t_to_gdkcolor(&tcolors[MBG_IDX], &prefs.gui_marked_bg);
  color_t_to_gdkcolor(&tcolors[CFG_IDX], &prefs.st_client_fg);
  color_t_to_gdkcolor(&tcolors[CBG_IDX], &prefs.st_client_bg);
  color_t_to_gdkcolor(&tcolors[SFG_IDX], &prefs.st_server_fg);
  color_t_to_gdkcolor(&tcolors[SBG_IDX], &prefs.st_server_bg);

  curcolor = &tcolors[CFG_IDX];

#if GTK_MAJOR_VERSION < 2
  scolor[CS_RED]     = (gdouble) (curcolor->red)   / 65535.0;
  scolor[CS_GREEN]   = (gdouble) (curcolor->green) / 65535.0;
  scolor[CS_BLUE]    = (gdouble) (curcolor->blue)  / 65535.0;
  scolor[CS_OPACITY] = 1.0;
#endif

  /* Enclosing containers for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

  main_tb = gtk_table_new(3, 3, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);

  label = gtk_label_new("Set:");
  gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 0, 1);
  gtk_widget_show(label);

  /* We have to create this now, and configure it below. */
  colorsel = gtk_color_selection_new();

  optmenu = gtk_option_menu_new ();
  menu = gtk_menu_new ();
  for (i = 0; i < mcount; i++){
    menuitem = gtk_menu_item_new_with_label (mt[i]);
    OBJECT_SET_DATA(menuitem, STREAM_CS_KEY, colorsel);
    SIGNAL_CONNECT(menuitem, "activate", update_current_color, &tcolors[i]);
    gtk_widget_show (menuitem);
    gtk_menu_append (GTK_MENU (menu), menuitem);
  }
  gtk_option_menu_set_menu (GTK_OPTION_MENU (optmenu), menu);
  gtk_table_attach(GTK_TABLE(main_tb), optmenu, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
  gtk_widget_show(optmenu);

#if GTK_MAJOR_VERSION < 2
  sample = gtk_text_new(FALSE, FALSE);
  height = (mcount/2+1) * (sample->style->font->ascent + sample->style->font->descent);
  width = gdk_string_width(sample->style->font, SAMPLE_SERVER_TEXT);
  WIDGET_SET_SIZE(sample, width, height);
  gtk_text_set_editable(GTK_TEXT(sample), FALSE);
  gtk_text_insert(GTK_TEXT(sample), NULL, &tcolors[MFG_IDX], &tcolors[MBG_IDX],
                  SAMPLE_MARKED_TEXT, -1);
  gtk_text_insert(GTK_TEXT(sample), NULL, &tcolors[CFG_IDX], &tcolors[CBG_IDX],
                  SAMPLE_CLIENT_TEXT, -1);
  gtk_text_insert(GTK_TEXT(sample), NULL, &tcolors[SFG_IDX], &tcolors[SBG_IDX],
                  SAMPLE_SERVER_TEXT, -1);
#else
  sample = gtk_text_view_new();
  layout = gtk_widget_create_pango_layout(sample, SAMPLE_SERVER_TEXT);
  pango_layout_get_pixel_size(layout, &width, &height);
  g_object_unref(G_OBJECT(layout));
  WIDGET_SET_SIZE(sample, width, height * 2);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(sample), FALSE);
  buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(sample));
  gtk_text_buffer_get_start_iter(buf, &iter);
  gtk_text_buffer_create_tag(buf, "marked",
                             "foreground-gdk", &tcolors[MFG_IDX],
                             "background-gdk", &tcolors[MBG_IDX], NULL);
  gtk_text_buffer_create_tag(buf, "client",
                             "foreground-gdk", &tcolors[CFG_IDX],
                             "background-gdk", &tcolors[CBG_IDX], NULL);
  gtk_text_buffer_create_tag(buf, "server",
                             "foreground-gdk", &tcolors[SFG_IDX],
                             "background-gdk", &tcolors[SBG_IDX], NULL);
  gtk_text_buffer_insert_with_tags_by_name(buf, &iter, SAMPLE_MARKED_TEXT, -1,
                                           "marked", NULL);
  gtk_text_buffer_insert_with_tags_by_name(buf, &iter, SAMPLE_CLIENT_TEXT, -1,
                                           "client", NULL);
  gtk_text_buffer_insert_with_tags_by_name(buf, &iter, SAMPLE_SERVER_TEXT, -1,
                                           "server", NULL);
#endif
  gtk_table_attach_defaults(GTK_TABLE(main_tb), sample, 2, 3, 0, 2);
  gtk_widget_show(sample);

#if GTK_MAJOR_VERSION < 2
  gtk_color_selection_set_color(GTK_COLOR_SELECTION(colorsel), &scolor[CS_RED]);
#else
  gtk_color_selection_set_current_color(GTK_COLOR_SELECTION(colorsel),
                                        curcolor);
#endif
  gtk_table_attach(GTK_TABLE(main_tb), colorsel, 0, 3, 2, 3,
		  GTK_SHRINK, GTK_SHRINK, 0, 0);

  OBJECT_SET_DATA(colorsel, STREAM_SAMPLE_KEY, sample);
  SIGNAL_CONNECT(colorsel, "color-changed", update_text_color, NULL);
  gtk_widget_show(colorsel);

  gtk_widget_show(main_vb);
  return(main_vb);
}

static void
update_text_color(GtkWidget *w, gpointer data _U_) {
#if GTK_MAJOR_VERSION < 2
  GtkText  *sample   = OBJECT_GET_DATA(w, STREAM_SAMPLE_KEY);
  gdouble   scolor[4];
#else
  GtkTextView *sample = OBJECT_GET_DATA(w, STREAM_SAMPLE_KEY);
  GtkTextBuffer *buf;
  GtkTextTag    *tag;
#endif

#if GTK_MAJOR_VERSION < 2
  gtk_color_selection_get_color(GTK_COLOR_SELECTION(w), &scolor[CS_RED]);

  curcolor->red   = (gushort) (scolor[CS_RED]   * 65535.0);
  curcolor->green = (gushort) (scolor[CS_GREEN] * 65535.0);
  curcolor->blue  = (gushort) (scolor[CS_BLUE]  * 65535.0);

  gtk_text_freeze(sample);
  gtk_text_set_point(sample, 0);
  gtk_text_forward_delete(sample, gtk_text_get_length(sample));
  gtk_text_insert(sample, NULL, &tcolors[MFG_IDX], &tcolors[MBG_IDX],
    SAMPLE_MARKED_TEXT, -1);
  gtk_text_insert(sample, NULL, &tcolors[CFG_IDX], &tcolors[CBG_IDX],
    SAMPLE_CLIENT_TEXT, -1);
  gtk_text_insert(sample, NULL, &tcolors[SFG_IDX], &tcolors[SBG_IDX],
    SAMPLE_SERVER_TEXT, -1);
  gtk_text_thaw(sample);
#else
  gtk_color_selection_get_current_color(GTK_COLOR_SELECTION(w), curcolor);

  buf = gtk_text_view_get_buffer(sample);
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "marked");
  g_object_set(tag, "foreground-gdk", &tcolors[MFG_IDX], "background-gdk",
               &tcolors[MBG_IDX], NULL);
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "client");
  g_object_set(tag, "foreground-gdk", &tcolors[CFG_IDX], "background-gdk",
               &tcolors[CBG_IDX], NULL);
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "server");
  g_object_set(tag, "foreground-gdk", &tcolors[SFG_IDX], "background-gdk",
               &tcolors[SBG_IDX], NULL);
#endif
}

static void
update_current_color(GtkWidget *w, gpointer data)
{
  GtkColorSelection *colorsel;
#if GTK_MAJOR_VERSION < 2
  gdouble            scolor[4];
#endif

  colorsel = GTK_COLOR_SELECTION(OBJECT_GET_DATA(w, STREAM_CS_KEY));
  curcolor = (GdkColor *) data;

#if GTK_MAJOR_VERSION < 2
  scolor[CS_RED]     = (gdouble) (curcolor->red)   / 65535.0;
  scolor[CS_GREEN]   = (gdouble) (curcolor->green) / 65535.0;
  scolor[CS_BLUE]    = (gdouble) (curcolor->blue)  / 65535.0;
  scolor[CS_OPACITY] = 1.0;

  gtk_color_selection_set_color(colorsel, &scolor[CS_RED]);
#else
  gtk_color_selection_set_current_color(colorsel, curcolor);
#endif
}

void
stream_prefs_fetch(GtkWidget *w _U_)
{
  gdkcolor_to_color_t(&prefs.gui_marked_fg, &tcolors[MFG_IDX]);
  gdkcolor_to_color_t(&prefs.gui_marked_bg, &tcolors[MBG_IDX]);
  gdkcolor_to_color_t(&prefs.st_client_fg, &tcolors[CFG_IDX]);
  gdkcolor_to_color_t(&prefs.st_client_bg, &tcolors[CBG_IDX]);
  gdkcolor_to_color_t(&prefs.st_server_fg, &tcolors[SFG_IDX]);
  gdkcolor_to_color_t(&prefs.st_server_bg, &tcolors[SBG_IDX]);
}

void
stream_prefs_apply(GtkWidget *w _U_)
{
	follow_redraw_all();

	packet_list_update_marked_frames();
}

void
stream_prefs_destroy(GtkWidget *w _U_)
{
}
