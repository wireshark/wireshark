/* help_dlg.c
 *
 * $Id: help_dlg.c,v 1.40 2003/12/22 21:52:41 guy Exp $
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
#include <stdio.h>
#include <errno.h>

#include "epan/filesystem.h"
#include "help_dlg.h"
#include "prefs.h"
#include "gtkglobals.h"
#include "ui_util.h"
#include "compat_macros.h"
#include "dlg_utils.h"
#include "simple_dialog.h"

#define HELP_DIR	"help"

static void help_close_cb(GtkWidget *w, gpointer data);
static void help_destroy_cb(GtkWidget *w, gpointer data);
static void insert_text(GtkWidget *w, const char *buffer, int nchars);
static void set_help_text(GtkWidget *w, const char *help_file_path);

/*
 * Keep a static pointer to the current "Help" window, if any, so that
 * if somebody tries to do "Help->Help" while there's already a
 * "Help" window up, we just pop up the existing one, rather than
 * creating a new one.
*/
static GtkWidget *help_w = NULL;

/*
 * Keep a list of text widgets and corresponding file names as well
 * (for text format changes).
 */
typedef struct {
  char *pathname;
  GtkWidget *txt;
} help_page_t;

static GSList *help_text_pages = NULL;

/*
 * Helper function to show a simple help text page.
 */
static GtkWidget * help_page(const char *filename)
{
  GtkWidget *page_vb, *txt_scrollw, *txt;
  char *relative_path, *absolute_path;
  help_page_t *page;

  page_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(page_vb), 1);
  txt_scrollw = scrolled_window_new(NULL, NULL);
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
				 GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  txt = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(txt), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(txt), GTK_WRAP_WORD);
#endif

  relative_path = g_strconcat(HELP_DIR, G_DIR_SEPARATOR_S, filename, NULL);
  absolute_path = get_datafile_path(relative_path);
  g_free(relative_path);
  set_help_text(txt, absolute_path);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), txt);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(txt);
  gtk_widget_show(page_vb);

  page = g_malloc(sizeof (help_page_t));
  page->pathname = absolute_path;
  page->txt = txt;
  help_text_pages = g_slist_prepend(help_text_pages, page);

  return page_vb;
}


/*
 * Create and show help dialog.
 */
void help_cb(GtkWidget *w _U_, gpointer data _U_)
{
  GtkWidget *main_vb, *bbox, *help_nb, *close_bt, *label, *topic_vb;
  char line[4096+1];	/* XXX - size? */
  char *p;
  char *filename;
  char *help_toc_file_path;
  FILE *help_toc_file;

  if (help_w != NULL) {
    /* There's already a "Help" dialog box; reactivate it. */
    reactivate_window(help_w);
    return;
  }

  help_toc_file_path = get_datafile_path(HELP_DIR G_DIR_SEPARATOR_S "toc");
  help_toc_file = fopen(help_toc_file_path, "r");
  if (help_toc_file == NULL) {
    simple_dialog(ESD_TYPE_CRIT, ESD_BTN_OK, "Could not open file \"%s\": %s",
                  help_toc_file_path, strerror(errno));
    g_free(help_toc_file_path);
    return;
  }

  help_w = dlg_window_new("Ethereal: Help");
  SIGNAL_CONNECT(help_w, "destroy", help_destroy_cb, NULL);
  /* XXX: improve this, e.g. remember the last window size in a file */
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

  /* help topics */
  while (fgets(line, sizeof line, help_toc_file) != NULL) {
    /* Strip off line ending. */
    p = strpbrk(line, "\r\n");
    if (p == NULL)
      break;		/* last line has no line ending */
    *p = '\0';
    /* {Topic title}:{filename of help file} */
    p = strchr(line, ':');
    if (p != NULL) {
      *p++ = '\0';
      filename = p;

      /*
       * "line" refers to the topic now, and "filename" refers to the
       * file name.
       */
      topic_vb = help_page(filename);
      label = gtk_label_new(line);
      gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), topic_vb, label);
    }
  }
  if(ferror(help_toc_file)) {
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Error reading file \"%s\": %s",
                  help_toc_file_path, strerror(errno));
  }
  fclose(help_toc_file);

  gtk_widget_show(help_nb);

  /* Buttons (only "Close" for now) */
  bbox = gtk_hbutton_box_new();
  /*bbox = gtk_hbox_new(FALSE, 1);*/
  gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);
#if GTK_MAJOR_VERSION < 2
  close_bt = gtk_button_new_with_label("OK");
#else
  close_bt = gtk_button_new_from_stock(GTK_STOCK_OK);
#endif
  SIGNAL_CONNECT(close_bt, "clicked", help_close_cb, help_w);
  GTK_WIDGET_SET_FLAGS(close_bt, GTK_CAN_DEFAULT);
  gtk_container_add(GTK_CONTAINER(bbox), close_bt);
  gtk_widget_grab_default(close_bt);
  gtk_widget_show(close_bt);

  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(help_w));

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(help_w, close_bt);

  gtk_widget_show(help_w);

} /* help_cb */


/*
 * Close help dialog.
 */
static void help_close_cb(GtkWidget *w _U_, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}


/*
 * Help dialog is closed now.
 */
static void help_destroy_cb(GtkWidget *w _U_, gpointer data _U_)
{
  GSList *help_page_ent;
  help_page_t *page;

  /* Free up the list of help pages. */
  for (help_page_ent = help_text_pages; help_page_ent != NULL;
       help_page_ent = g_slist_next(help_page_ent)) {
    page = (help_page_t *)help_page_ent->data;
    g_free(page->pathname);
    g_free(page);
  }
  g_slist_free(help_text_pages);
  help_text_pages = NULL;

  /* Note that we no longer have a Help window. */
  help_w = NULL;
}


/*
 * Insert some text to a help page.
 */
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


/*
 * Put the complete help text into a help page.
 */
static void set_help_text(GtkWidget *w, const char *help_file_path)
{
  FILE *help_file;
  char line[4096+1];	/* XXX - size? */

#if GTK_MAJOR_VERSION < 2
  gtk_text_freeze(GTK_TEXT(w));
#endif

  help_file = fopen(help_file_path, "r");
  if (help_file != NULL) {
    while (fgets(line, sizeof line, help_file) != NULL) {
      insert_text(w, line, strlen(line));
    }
    if(ferror(help_file)) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Error reading file \"%s\": %s",
                    help_file_path, strerror(errno));
    }
    fclose(help_file);
  } else {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Could not open file \"%s\": %s",
                    help_file_path, strerror(errno));
  }
#if GTK_MAJOR_VERSION < 2
  gtk_text_thaw(GTK_TEXT(w));
#endif
} /* set_help_text */


/*
 * Clear the help text from the help page.
 */
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


/*
 * Redraw a single help page.
 */
void help_redraw_page(const help_page_t *page)
{
#if GTK_MAJOR_VERSION < 2
  gtk_text_freeze(GTK_TEXT(page->txt));
#endif
  clear_help_text(page->txt);
  set_help_text(page->txt, page->pathname);
#if GTK_MAJOR_VERSION < 2
  gtk_text_thaw(GTK_TEXT(page->txt));
#endif
}

/*
 * Redraw all help pages, to use a new font.
 */
void help_redraw(void)
{
  GSList *help_page_ent;

  if (help_w != NULL) {
    for (help_page_ent = help_text_pages; help_page_ent != NULL;
         help_page_ent = g_slist_next(help_page_ent))
      help_redraw_page((help_page_t *)help_page_ent->data);
  }
}
