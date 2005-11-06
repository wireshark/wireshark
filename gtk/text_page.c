/* text_page.c
 *
 * $Id$
 *
 * Ulf Lamping
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
#include <stdio.h>
#include <errno.h>

#include "epan/filesystem.h"
#include "text_page.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "simple_dialog.h"
#include "font_utils.h"
#include "file_util.h"

#define TEXT_KEY        "txt_key"

static void text_page_insert(GtkWidget *page, const char *buffer, int nchars);
static void text_page_set_text(GtkWidget *page, const char *absolute_path);


/*
 * Construct a simple text page widget from a file.
 */
GtkWidget * text_page_new(const char *absolute_path)
{
  GtkWidget *page_vb, *txt_scrollw, *txt;

  page_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(page_vb), 1);
  txt_scrollw = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw), 
                                   GTK_SHADOW_IN);
#endif
  gtk_box_pack_start(GTK_BOX(page_vb), txt_scrollw, TRUE, TRUE, 0);

#if GTK_MAJOR_VERSION < 2
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
  txt = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(txt), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(txt), TRUE);
  gtk_text_set_line_wrap(GTK_TEXT(txt), TRUE);
#else
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  txt = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(txt), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(txt), GTK_WRAP_WORD);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(txt), FALSE);
  /* XXX: there seems to be no way to add a small border *around* the whole text,
   * so the text will be "bump" against the edges.
   * the following is only working for left and right edges,
   * there is no such thing for top and bottom :-( */
  /* gtk_text_view_set_left_margin(GTK_TEXT_VIEW(txt), 3); */
  /* gtk_text_view_set_right_margin(GTK_TEXT_VIEW(txt), 3); */
#endif

  OBJECT_SET_DATA(page_vb, TEXT_KEY, txt);

  text_page_set_text(page_vb, absolute_path);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), txt);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(txt);

  return page_vb;
}


/*
 * Insert some text to a text page.
 */
static void text_page_insert(GtkWidget *page, const char *buffer, int nchars)
{
    GtkWidget *txt = OBJECT_GET_DATA(page, TEXT_KEY);

#if GTK_MAJOR_VERSION < 2
    gtk_text_insert(GTK_TEXT(txt), user_font_get_regular(), NULL, NULL, buffer, nchars);
#else
    GtkTextBuffer *buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt));
    GtkTextIter    iter;

    gtk_text_buffer_get_end_iter(buf, &iter);
    gtk_widget_modify_font(GTK_WIDGET(txt), user_font_get_regular());
    if (!g_utf8_validate(buffer, -1, NULL))
        printf("Invalid utf8 encoding: %s\n", buffer);
    gtk_text_buffer_insert(buf, &iter, buffer, nchars);
#endif
}


/*
 * Put the complete text file into a text page.
 */
static void text_page_set_text(GtkWidget *page, const char *absolute_path)
{
  FILE *text_file;
  char line[4096+1];	/* XXX - size? */

#if GTK_MAJOR_VERSION < 2
  GtkText *txt = GTK_TEXT(OBJECT_GET_DATA(page, TEXT_KEY));
  gtk_text_freeze(txt);
#endif

  text_file = eth_fopen(absolute_path, "r");
  if (text_file != NULL) {
    while (fgets(line, sizeof line, text_file) != NULL) {
      text_page_insert(page, line, strlen(line));
    }
    if(ferror(text_file)) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Error reading file \"%s\": %s",
                    absolute_path, strerror(errno));
    }
    fclose(text_file);
  } else {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not open file \"%s\": %s",
                    absolute_path, strerror(errno));
  }
#if GTK_MAJOR_VERSION < 2
  gtk_text_thaw(txt);
#endif
}


/**
 * Clear the text from the text page.
 */
static void text_page_clear(GtkWidget *page)
{
#if GTK_MAJOR_VERSION < 2
  GtkText *txt = GTK_TEXT(OBJECT_GET_DATA(page, TEXT_KEY));

  gtk_text_set_point(txt, 0);
  /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see
     http://www.ethereal.com/lists/ethereal-dev/199912/msg00312.html and
     http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
     for more information */
  gtk_adjustment_set_value(txt->vadj, 0.0);
  gtk_text_forward_delete(txt, gtk_text_get_length(txt));
#else
  GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(OBJECT_GET_DATA(page, TEXT_KEY)));

  gtk_text_buffer_set_text(buf, "", 0);
#endif
}


/**
 * Redraw a single text page, e.g. to use a new font.
 */
void text_page_redraw(GtkWidget *page, const char *absolute_path)
{
#if GTK_MAJOR_VERSION < 2
  GtkWidget *txt = OBJECT_GET_DATA(page, TEXT_KEY);
#endif

#if GTK_MAJOR_VERSION < 2
  gtk_text_freeze(GTK_TEXT(txt));
#endif
  text_page_clear(page);
  text_page_set_text(page, absolute_path);
#if GTK_MAJOR_VERSION < 2
  gtk_text_thaw(GTK_TEXT(txt));
#endif
}
