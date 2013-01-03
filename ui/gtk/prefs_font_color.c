/* prefs_font_color.c
 * Font and Color preferences widget
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "../color.h"
#include "../print.h"

#include "ui/recent.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/color_utils.h"
#include "ui/gtk/follow_tcp.h"
#include "ui/gtk/font_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/packet_panes.h"
#include "ui/gtk/prefs_font_color.h"

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
#define COLOR_SAMPLE_KEY "text_color_sample"
#define FONT_SAMPLE_KEY "font_sample"
#define STREAM_CS_KEY "stream_colorselection"
#define CS_RED 0
#define CS_GREEN 1
#define CS_BLUE 2
#define CS_OPACITY 3

static void select_font(GtkWidget *, gpointer);
static void update_font(PangoFontDescription *, GtkWidget *, GtkWidget *);
static void update_text_color(GtkWidget *, gpointer);
static void update_current_color(GtkWidget *, gpointer);

static GdkColor tcolors[MAX_IDX], *curcolor = NULL;

/* Set to FALSE initially; set to TRUE if the user ever hits "OK" on
   the "Font..." dialog, so that we know that they (probably) changed
   the font, and therefore that the "apply" function needs to take care
   of that */
static gboolean font_changed;

/* Font name from the font dialog box; if "font_changed" is TRUE, this
   has been set to the name of the font the user selected. */
static gchar *new_font_name;

static GtkWidget *font_button;

static const char *font_pangrams[] = {
  "Example GIF query packets have jumbo window sizes",
  "Lazy badgers move unique waxy jellyfish packets"
};
#define NUM_FONT_PANGRAMS (sizeof font_pangrams / sizeof font_pangrams[0])

GtkWidget *
font_color_prefs_show(void)
{
  GtkWidget *main_vb, *main_tb, *label, *combo_box;
  GtkWidget *font_sample, *color_sample, *colorsel;
  int        i;
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
  GRand         *rand_state = g_rand_new();
  GString       *preview_string = g_string_new("");

  /* The font hasn't been changed yet. */
  font_changed = FALSE;

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
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);

  main_tb = gtk_table_new(4, 3, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);

  label = gtk_label_new("Main window font:");
  gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 0, 1);
  gtk_widget_show(label);

  font_button = gtk_font_button_new_with_font(prefs.gui_font_name);
  gtk_font_button_set_title(GTK_FONT_BUTTON(font_button), "Wireshark: Font");
  gtk_table_attach(GTK_TABLE(main_tb), font_button, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
  gtk_widget_show(font_button);

  g_string_printf(preview_string, " %s 0123456789",
		  font_pangrams[g_rand_int_range(rand_state, 0, NUM_FONT_PANGRAMS)]);

  font_sample = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(font_sample), FALSE);
  buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(font_sample));
  gtk_text_buffer_get_start_iter(buf, &iter);
  srand((unsigned int) time(NULL));
  gtk_text_buffer_insert(buf, &iter, preview_string->str, -1);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), font_sample, 2, 3, 0, 1);
  g_signal_connect(font_button, "font-set", G_CALLBACK(select_font), NULL);
  gtk_widget_show(font_sample);

  g_string_free(preview_string, TRUE);
  g_object_set_data(G_OBJECT(font_button), FONT_SAMPLE_KEY, font_sample);

  label = gtk_label_new("Colors:");
  gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 1, 2);
  gtk_widget_show(label);

  /* We have to create this now, and configure it below. */
  colorsel = gtk_color_selection_new();

  combo_box = gtk_combo_box_text_new();
  for (i = 0; i < mcount; i++){
	   gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), mt[i]);
  }
  gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), CFG_IDX);
  g_signal_connect(combo_box, "changed", G_CALLBACK(update_current_color), colorsel);
  gtk_table_attach(GTK_TABLE(main_tb), combo_box, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);

  gtk_widget_show(combo_box);

  color_sample = gtk_text_view_new();
  update_font(user_font_get_regular(), font_sample, color_sample);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(color_sample), FALSE);
  buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(color_sample));
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
  gtk_table_attach_defaults(GTK_TABLE(main_tb), color_sample, 2, 3, 1, 3);
  gtk_widget_show(color_sample);

  gtk_color_selection_set_current_color(GTK_COLOR_SELECTION(colorsel),
                                        curcolor);
  gtk_table_attach(GTK_TABLE(main_tb), colorsel, 0, 3, 3, 4,
		  GTK_SHRINK, GTK_SHRINK, 0, 0);


  g_object_set_data(G_OBJECT(combo_box), COLOR_SAMPLE_KEY, color_sample);
  g_object_set_data(G_OBJECT(colorsel), COLOR_SAMPLE_KEY, color_sample);
  g_signal_connect(colorsel, "color-changed", G_CALLBACK(update_text_color), NULL);
  gtk_widget_show(colorsel);

  g_rand_free(rand_state);
  gtk_widget_show(main_vb);
  return(main_vb);
}

static void
update_font(PangoFontDescription *font, GtkWidget *font_sample _U_, GtkWidget *color_sample _U_) {

  if (!font_sample || !color_sample) return;

#if GTK_CHECK_VERSION(3,0,0)
  gtk_widget_override_font(font_sample, font);
  gtk_widget_override_font(color_sample, font);
#else
  gtk_widget_modify_font(font_sample, font);
  gtk_widget_modify_font(color_sample, font);
#endif

}

static gboolean
font_fetch(void)
{
  gchar   *font_name;

  if (!font_button) return FALSE;

  font_name = g_strdup(gtk_font_button_get_font_name(
    GTK_FONT_BUTTON(font_button)));
  if (font_name == NULL) {
    /* No font was selected; let the user know, but don't
       tear down the font selection dialog, so they can
       try again. */
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "You have not selected a font.");
    return FALSE;
  }

  if (!user_font_test(font_name)) {
    /* The font isn't usable; "user_font_test()" has already
       told the user why.  Don't tear down the font selection
       dialog. */
    g_free(font_name);
    return FALSE;
  }
  new_font_name = font_name;
  return TRUE;
}

static void
select_font(GtkWidget *w, gpointer data _U_)
{
  GtkWidget *font_sample = g_object_get_data(G_OBJECT(w), FONT_SAMPLE_KEY);
  GtkWidget *color_sample = g_object_get_data(G_OBJECT(w), COLOR_SAMPLE_KEY);
  const gchar *font_name;

  if (!font_sample || !color_sample) return;

  font_name = gtk_font_button_get_font_name(GTK_FONT_BUTTON(w));
  if (font_name) {
    PangoFontDescription *font = pango_font_description_from_string(font_name);
    update_font(font, font_sample, color_sample);
  }
}

static void
update_text_color(GtkWidget *w, gpointer data _U_) {
  GtkTextView *sample = g_object_get_data(G_OBJECT(w), COLOR_SAMPLE_KEY);
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
  GtkTextView *color_sample = g_object_get_data(G_OBJECT(combo_box), COLOR_SAMPLE_KEY);
  GtkTextIter iter;

  i = gtk_combo_box_get_active (GTK_COMBO_BOX(combo_box));
  curcolor = &tcolors[i];

  gtk_color_selection_set_current_color(colorsel, curcolor);

  gtk_text_buffer_get_start_iter(gtk_text_view_get_buffer(color_sample), &iter);
  gtk_text_iter_set_line(&iter, i/2);
  gtk_text_view_scroll_to_iter(color_sample, &iter, 0.0, FALSE, 0, 0);
}

void
font_color_prefs_fetch(GtkWidget *w _U_)
{
  gdkcolor_to_color_t(&prefs.gui_marked_fg, &tcolors[MFG_IDX]);
  gdkcolor_to_color_t(&prefs.gui_marked_bg, &tcolors[MBG_IDX]);
  gdkcolor_to_color_t(&prefs.gui_ignored_fg, &tcolors[IFG_IDX]);
  gdkcolor_to_color_t(&prefs.gui_ignored_bg, &tcolors[IBG_IDX]);
  gdkcolor_to_color_t(&prefs.st_client_fg, &tcolors[CFG_IDX]);
  gdkcolor_to_color_t(&prefs.st_client_bg, &tcolors[CBG_IDX]);
  gdkcolor_to_color_t(&prefs.st_server_fg, &tcolors[SFG_IDX]);
  gdkcolor_to_color_t(&prefs.st_server_bg, &tcolors[SBG_IDX]);

  /*
   * XXX - we need to have a way to fetch the preferences into
   * local storage and only set the permanent preferences if there
   * weren't any errors in those fetches, as there are several
   * places where there *can* be a bad preference value.
   */
  if (font_fetch()) {
    if (strcmp(new_font_name, prefs.gui_font_name) != 0) {
      font_changed = TRUE;
      g_free(prefs.gui_font_name);
      prefs.gui_font_name = g_strdup(new_font_name);
    }
  }
}

void
font_color_prefs_apply(GtkWidget *w _U_, gboolean redissect)
{
  if (font_changed) {
    /* This redraws the packet bytes windows. */
    switch (user_font_apply()) {

    case FA_SUCCESS:
      break;

    case FA_FONT_NOT_RESIZEABLE:
      /* "user_font_apply()" popped up an alert box. */
      /* turn off zooming - font can't be resized */
      recent.gui_zoom_level = 0;
      break;

    case FA_FONT_NOT_AVAILABLE:
      /* We assume this means that the specified size
	 isn't available. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	"That font isn't available at the specified zoom level;\n"
	"turning zooming off.");
      recent.gui_zoom_level = 0;
      break;
    }
  } else if (!redissect) {
    /* Redraw the packet bytes windows, in case the
       highlight style changed, only if we aren't redissecting the whole file.
       XXX - do it only if the highlight style *did* change. */
    redraw_packet_bytes_all();
  }

  follow_tcp_redraw_all();
}

void
font_color_prefs_destroy(GtkWidget *w _U_)
{
  /* Free up any saved font name. */
  if (new_font_name != NULL) {
    g_free(new_font_name);
    new_font_name = NULL;
  }
  font_button = NULL;
}
