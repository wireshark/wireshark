/* help_dlg.c
 *
 * $Id: help_dlg.c,v 1.38 2003/11/27 23:25:55 ulfl Exp $
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

#include "help_dlg.h"
#include "prefs.h"
#include "gtkglobals.h"
#include "ui_util.h"
#include "compat_macros.h"
#include "dlg_utils.h"


/* include texts from converted ascii ".txt" files */
#include "../help/overview.h"
#include "../help/capture_filters.h"
#include "../help/display_filters.h"
#include "../help/well_known.h"
#include "../help/faq.h"


typedef enum {
  OVERVIEW_HELP,
  CFILTER_HELP,
  DFILTER_HELP,
  WELL_KNOWN_HELP,
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
 * Keep static pointers to the text widgets as well (for text format changes).
 */
static GtkWidget *overview_text, *cfilter_text, *dfilter_text;
static GtkWidget *well_known_text, *faq_text;


/*
 * Helper function to show a simple help text page.
 */
static GtkWidget * help_page(help_type_t page_type, GtkWidget **page_text)
{
  GtkWidget *page_vb, *txt_scrollw;

  page_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(page_vb), 1);
  txt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(page_vb), txt_scrollw, TRUE, TRUE, 0);
#if GTK_MAJOR_VERSION < 2
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
  *page_text = gtk_text_new(NULL, NULL );
  gtk_text_set_editable(GTK_TEXT(*page_text), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(*page_text), TRUE);
  gtk_text_set_line_wrap(GTK_TEXT(*page_text), TRUE);
#else
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				 GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  *page_text = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(*page_text), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(*page_text), GTK_WRAP_WORD);
#endif
  set_help_text(*page_text, page_type);
  gtk_container_add(GTK_CONTAINER(txt_scrollw), *page_text);
  gtk_widget_show(txt_scrollw);
  gtk_widget_show(*page_text);
  gtk_widget_show(page_vb);

  return page_vb;
}



void help_cb(GtkWidget *w _U_, gpointer data _U_)
{

  GtkWidget *main_vb, *bbox, *help_nb, *close_bt, *label,
    *overview_vb,
    *cfilter_vb,
    *dfilter_vb,
    *well_known_vb,
    *faq_vb;

  if (help_w != NULL) {
    /* There's already a "Help" dialog box; reactivate it. */
    reactivate_window(help_w);
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


  /* Overview panel */
  overview_vb = help_page(OVERVIEW_HELP, &overview_text);
  label = gtk_label_new("Overview");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), overview_vb, label);

  /* capture filter help (this one has no horizontal scrollbar) */
  cfilter_vb = help_page(CFILTER_HELP, &cfilter_text);
  label = gtk_label_new("Capture Filters");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), cfilter_vb, label);

  /* display filter help (this one has no horizontal scrollbar) */
  dfilter_vb = help_page(DFILTER_HELP, &dfilter_text);
  label = gtk_label_new("Display Filters");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), dfilter_vb, label);

  /* well known things help (this one has no horizontal scrollbar) */
  well_known_vb = help_page(WELL_KNOWN_HELP, &well_known_text);
  label = gtk_label_new("Well Known");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), well_known_vb, label);

  /* FAQ help (this one has no horizontal scrollbar) */
  faq_vb = help_page(FAQ_HELP, &faq_text);
  label = gtk_label_new("FAQ");
  gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), faq_vb, label);

  /* XXX add other help panels here ... */

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


static void set_help_text(GtkWidget *w, help_type_t type)
{
  int i;
#ifndef HAVE_LIBPCAP
  char *tmp;
#endif


#if GTK_MAJOR_VERSION < 2
  gtk_text_freeze(GTK_TEXT(w));
#endif

  switch(type) {

  case OVERVIEW_HELP :
    for (i=0; i<OVERVIEW_PARTS; i++) {
      insert_text(w, overview_part[i], strlen(overview_part[i]));
    }
    break;
  case CFILTER_HELP :
#ifndef HAVE_LIBPCAP
    tmp = "NOTE: packet capturing is not enabled in this version!\n \n";
    insert_text(w, tmp, strlen(tmp));
#endif
    for (i=0; i<CAPTURE_FILTERS_PARTS; i++) {
      insert_text(w, capture_filters_part[i], strlen(capture_filters_part[i]));
    }
    break;
  case DFILTER_HELP :
    for (i=0; i<DISPLAY_FILTERS_PARTS; i++) {
      insert_text(w, display_filters_part[i], strlen(display_filters_part[i]));
    }
    break;
  case WELL_KNOWN_HELP :
    for (i=0; i<WELL_KNOWN_PARTS; i++) {
      insert_text(w, well_known_part[i], strlen(well_known_part[i]));
    }
    break;
  case FAQ_HELP :
    for (i=0; i<FAQ_PARTS; i++) {
      insert_text(w, faq_part[i], strlen(faq_part[i]));
    }
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

    gtk_text_freeze(GTK_TEXT(cfilter_text));
#endif
    clear_help_text(cfilter_text);
    set_help_text(cfilter_text, CFILTER_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(cfilter_text));

    gtk_text_freeze(GTK_TEXT(dfilter_text));
#endif
    clear_help_text(dfilter_text);
    set_help_text(dfilter_text, DFILTER_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(dfilter_text));

    gtk_text_freeze(GTK_TEXT(well_known_text));
#endif
    clear_help_text(well_known_text);
    set_help_text(well_known_text, WELL_KNOWN_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(well_known_text));

    gtk_text_freeze(GTK_TEXT(faq_text));
#endif
    clear_help_text(faq_text);
    set_help_text(faq_text, FAQ_HELP);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(faq_text));
#endif
  }
}
