/* about_dlg.c
 *
 * $Id$
 *
 * Ulf Lamping <ulf.lamping@web.de>
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

#include <epan/filesystem.h>
#include <epan/plugins.h>
#include "about_dlg.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "globals.h"
#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
#include "text_page.h"
#endif

#include "../image/eicon3d64.xpm"
#include "gtkglobals.h"
#include "version_info.h"
#include "main.h"
#include "plugins_dlg.h"

static void about_ethereal_destroy_cb(GtkWidget *, gpointer);


/*
 * Keep a static pointer to the current "About Ethereal" window, if any, so
 * that if somebody tries to do "About Ethereal" while there's already an
 * "About Ethereal" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *about_ethereal_w;


static void
about_ethereal(GtkWidget *parent, GtkWidget *main_vb, const char *title)
{
  GtkWidget   *msg_label, *icon;
#if GTK_MAJOR_VERSION >= 2
  gchar       *message;
#endif

  icon = xpm_to_widget_from_parent(parent, eicon3d64_xpm);
  gtk_container_add(GTK_CONTAINER(main_vb), icon);

  msg_label = gtk_label_new(title);
#if GTK_MAJOR_VERSION >= 2
  message = g_strdup_printf("<span size=\"x-large\" weight=\"bold\">%s</span>", title);
  gtk_label_set_markup(GTK_LABEL(msg_label), message);
  g_free(message);
#endif
  gtk_container_add(GTK_CONTAINER(main_vb), msg_label);
}


GtkWidget *
splash_new(char *message)
{
    GtkWidget *win;
    GtkWidget *main_lb;

    GtkWidget *main_vb;

    win = splash_window_new();

    /* When calling about_ethereal(), we must realize the top-level
       widget for the window, otherwise GTK will throw a warning
       because we don't have a colormap associated with that window and
       can't handle the pixmap. */
    gtk_widget_realize(win);

    main_vb = gtk_vbox_new(FALSE, 6);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 24);
    gtk_container_add(GTK_CONTAINER(win), main_vb);

    about_ethereal(win, main_vb, "Ethereal - Network Protocol Analyzer");

    main_lb = gtk_label_new(message);
    gtk_container_add(GTK_CONTAINER(main_vb), main_lb);
    OBJECT_SET_DATA(win, "splash_label", main_lb);
    
    gtk_widget_show_all(win);

    splash_update(win, message);

    return win;
}

void
splash_update(GtkWidget *win, char *message)
{
    GtkWidget *main_lb;

    if (win == NULL) return;

    main_lb = OBJECT_GET_DATA(win, "splash_label");
    gtk_label_set_text(GTK_LABEL(main_lb), message);

    /* Process all pending GUI events before continuing, so that
       the splash screen window gets updated. */
    while (gtk_events_pending()) gtk_main_iteration();
}

guint
splash_destroy(GtkWidget *win)
{
    if (win == NULL) return FALSE;

    gtk_widget_destroy(win);
    return FALSE;
}


static GtkWidget *
about_ethereal_page_new(void)
{
  GtkWidget   *main_vb, *msg_label /*, *icon*/;
  gchar       *message;
  const char   title[] = "Ethereal - Network Protocol Analyzer";

  main_vb = gtk_vbox_new(FALSE, 6);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 12);

  about_ethereal(top_level, main_vb, title);

  /* Construct the message string */
  message = g_strdup_printf(
       "Version " VERSION "%s"
       " (C) 1998-2005 Gerald Combs <gerald@ethereal.com>\n\n"
       "%s\n\n"
       "%s\n\n"

       "Ethereal is Open Source Software released under the GNU General Public License.\n\n"

       "Check the man page and http://www.ethereal.com for more information.",
       svnversion, comp_info_str->str, runtime_info_str->str);

  msg_label = gtk_label_new(message);
  g_free(message);
  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
#if GTK_MAJOR_VERSION >= 2
  gtk_label_set_selectable(GTK_LABEL(msg_label), TRUE);
#endif
  gtk_container_add(GTK_CONTAINER(main_vb), msg_label);

  return main_vb;
}

#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
static GtkWidget *
about_authors_page_new(void)
{
  GtkWidget   *page;
  char *absolute_path;

  absolute_path = get_datafile_path("AUTHORS-SHORT");
  page = text_page_new(absolute_path);

  return page;
}
#endif

static void
about_folders_row(GtkWidget *table, const char *label, const char *dir, const char *tip)
{
  simple_list_append(table, 0, label, 1, dir, 2, tip, -1);
}


static GtkWidget *
about_folders_page_new(void)
{
  GtkWidget   *table;
  const char *constpath;
  char *path;
  const gchar *titles[] = { "Name", "Folder", "Typical Files"};
  GtkWidget *scrolledwindow;

  scrolledwindow = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), 
                                   GTK_SHADOW_IN);
#endif

  /* Container for our data */
  table = simple_list_new(3, titles);

  /* "file open" */
  about_folders_row(table, "\"File\" dialogs", get_last_open_dir(),
      "capture files");

  /* temp */
  path = get_tempfile_path("");
  about_folders_row(table, "Temp", path,
      "untitled capture files");
  g_free((void *) path);

  /* pers conf */
  path = get_persconffile_path("", FALSE);
  about_folders_row(table, "Personal configuration", path, 
      "\"dfilters\", \"preferences\", \"ethers\", ...");
  g_free((void *) path);

  /* global conf */
  constpath = get_datafile_dir();
  about_folders_row(table, "Global configuration", constpath,
      "\"dfilters\", \"preferences\", \"manuf\", ...");

  /* system */
  constpath = get_systemfile_dir();
  about_folders_row(table, "System", constpath,
      "\"ethers\", \"ipxnets\"");

  /* program */
  path = g_strdup(ethereal_path);
  path = get_dirname(path);
  about_folders_row(table, "Program", path,
      "program files");
  g_free((void *) path);

#ifdef HAVE_PLUGINS
  /* pers plugins */
  path = get_plugins_pers_dir();
  about_folders_row(table, "Personal Plugins", path,
      "dissector plugins");
  g_free((void *) path);

  /* global plugins */
  path = get_plugins_global_dir(PLUGIN_DIR);
  about_folders_row(table, "Global Plugins", path,
      "dissector plugins");
  g_free((void *) path);
#endif

  gtk_container_add(GTK_CONTAINER(scrolledwindow), table);

  return scrolledwindow;
}


void
about_ethereal_cb( GtkWidget *w _U_, gpointer data _U_ )
{
  GtkWidget   *main_vb, *main_nb, *bbox, *ok_btn;

  GtkWidget   *page_lb, *about_page, *folders_page, *plugins_page;
#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
  GtkWidget   *authors_page;
#endif

  if (about_ethereal_w != NULL) {
    /* There's already an "About Ethereal" dialog box; reactivate it. */
    reactivate_window(about_ethereal_w);
    return;
  }

  /*
   * XXX - use GtkDialog?  The GNOME 2.x GnomeAbout widget does.
   * Should we use GtkDialog for simple_dialog() as well?  Or
   * is the GTK+ 2.x GtkDialog appropriate but the 1.2[.x] one
   * not?  (The GNOME 1.x GnomeAbout widget uses GnomeDialog.)
   */
  about_ethereal_w = dlg_window_new("About Ethereal");
  /* set the initial position (must be done, before show is called!) */
  /* default position is not appropriate for the about dialog */
#if GTK_MAJOR_VERSION >= 2
  gtk_window_set_position(GTK_WINDOW(about_ethereal_w), GTK_WIN_POS_CENTER_ON_PARENT);
#else
  gtk_window_set_position(GTK_WINDOW(about_ethereal_w), GTK_WIN_POS_CENTER);
#endif
  /* setting the size is dangerous here, as making it too short will 
   * clip content on GTK1, so simply use the natural size */
  /*gtk_window_set_default_size(GTK_WINDOW(about_ethereal_w), 600, 400);*/
  gtk_container_border_width(GTK_CONTAINER(about_ethereal_w), 6);

  main_vb = gtk_vbox_new(FALSE, 12);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 6);
  gtk_container_add(GTK_CONTAINER(about_ethereal_w), main_vb);

  main_nb = gtk_notebook_new();
  gtk_box_pack_start(GTK_BOX(main_vb), main_nb, TRUE, TRUE, 0);

  about_page = about_ethereal_page_new();
  page_lb = gtk_label_new("Ethereal");
  gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), about_page, page_lb);

#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
  authors_page = about_authors_page_new();
  page_lb = gtk_label_new("Authors");
  gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), authors_page, page_lb);
#endif

  folders_page = about_folders_page_new();
  page_lb = gtk_label_new("Folders");
  gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), folders_page, page_lb);

#ifdef HAVE_PLUGINS
  plugins_page = about_plugins_page_new();
  page_lb = gtk_label_new("Plugins");
  gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), plugins_page, page_lb);
#endif

  /* Button row */
  bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

  ok_btn = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  window_set_cancel_button(about_ethereal_w, ok_btn, window_cancel_button_cb);

  SIGNAL_CONNECT(about_ethereal_w, "delete_event", window_delete_event_cb, NULL);
  SIGNAL_CONNECT(about_ethereal_w, "destroy", about_ethereal_destroy_cb, NULL);

  gtk_widget_show_all(about_ethereal_w);
  window_present(about_ethereal_w);
}

static void
about_ethereal_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have an "About Ethereal" dialog box. */
  about_ethereal_w = NULL;
}


