/* about_dlg.c
 *
 * $Id: about_dlg.c,v 1.1 2004/05/20 12:01:12 ulfl Exp $
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
#include "ui_util.h"
#include "dlg_utils.h"
#include "compat_macros.h"

extern GString *comp_info_str, *runtime_info_str;

static void about_ethereal_destroy_cb(GtkWidget *, gpointer);


/*
 * Keep a static pointer to the current "About Ethereal" window, if any, so
 * that if somebody tries to do "About Ethereal" while there's already an
 * "About Ethereal" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *about_ethereal_w;


static GtkWidget *
about_ethereal_new(void)
{
  GtkWidget   *main_vb, *top_hb, *msg_label;
  gchar       *message;

  /* Container for our rows */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

  /* Top row: Message text */
  top_hb = gtk_hbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);

  /* Construct the message string */
  message = g_strdup_printf(
	   "Ethereal - Network Protocol Analyzer\n\n"
	   
	   "Version " VERSION
#ifdef CVSVERSION
	   " (" CVSVERSION ")"
#endif
	   " (C) 1998-2004 Gerald Combs <gerald@ethereal.com>\n\n"

       "%s\n"
       "%s\n\n"

       "Ethereal is Open Source software released under the GNU General Public License.\n\n"

	   "Check the man page for complete documentation and\n"
	   "for the list of contributors.\n\n"

	   "See http://www.ethereal.com for more information.",
	    comp_info_str->str, runtime_info_str->str);

  msg_label = gtk_label_new(message);
  g_free(message);
  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
  gtk_container_add(GTK_CONTAINER(top_hb), msg_label);

  return main_vb;
}


static void
about_dirs_row(GtkWidget *table, guint row, const char *label, const char *dir, const char *tip)
{
  GtkWidget   *prefs_lb;

  prefs_lb = gtk_label_new(label);
  gtk_table_attach_defaults(GTK_TABLE(table), prefs_lb, 0, 1, row, row+1);
  gtk_misc_set_alignment(GTK_MISC(prefs_lb), 1.0, 0.5);

  prefs_lb = gtk_label_new(dir);
  gtk_table_attach_defaults(GTK_TABLE(table), prefs_lb, 1, 2, row, row+1);
  gtk_misc_set_alignment(GTK_MISC(prefs_lb), 0.0, 0.5);

  prefs_lb = gtk_label_new(tip);
  gtk_table_attach_defaults(GTK_TABLE(table), prefs_lb, 2, 3, row, row+1);
  gtk_misc_set_alignment(GTK_MISC(prefs_lb), 0.0, 0.5);
}


static GtkWidget *
about_dirs_new(void)
{
  GtkWidget   *table;
  guint row;
  const char *path;

  /* Container for our rows */
  table = gtk_table_new(4, 3, FALSE);
  gtk_table_set_col_spacings(GTK_TABLE(table), 6);
  row = 0;

  path = get_persconffile_path("", FALSE);
  about_dirs_row(table, row, "Personal configuration:", path, 
      "\"dfilters\", \"preferences\", ...");
  g_free((void *) path);
  row++;

  path = get_datafile_dir();
  about_dirs_row(table, row, "Global configuration and data:", path,
      "same as in personal conf.");
  /*g_free(path);*/
  row++;

  path = get_systemfile_dir();
  about_dirs_row(table, row, "System:", path,
      "\"ethers\", ...");
  /*g_free(path);*/
  row++;

  path = get_tempfile_path("");
  about_dirs_row(table, row, "Temp:", path,
      "untitled capture files");
  g_free((void *) path);
  row++;

  return table;
}


void
about_ethereal_cb( GtkWidget *w _U_, gpointer data _U_ )
{
  GtkWidget   *main_vb, *main_nb, *bbox, *ok_btn;

  GtkWidget   *about, *about_lb, *dirs, *dirs_lb;

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
  SIGNAL_CONNECT(about_ethereal_w, "destroy", about_ethereal_destroy_cb, NULL);
  gtk_container_border_width(GTK_CONTAINER(about_ethereal_w), 7);

  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(about_ethereal_w), main_vb);

  main_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), main_nb);

  about = about_ethereal_new();
  about_lb = gtk_label_new("Ethereal");
  gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), about, about_lb);

  dirs = about_dirs_new();
  dirs_lb = gtk_label_new("Directories");
  gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), dirs, dirs_lb);

  /* Button row */
  bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);

  ok_btn = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  SIGNAL_CONNECT_OBJECT(ok_btn, "clicked", gtk_widget_destroy,
                        about_ethereal_w);
  gtk_widget_grab_default(ok_btn);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(about_ethereal_w, ok_btn);

  gtk_widget_show_all(about_ethereal_w);
}

static void
about_ethereal_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have an "About Ethereal" dialog box. */
  about_ethereal_w = NULL;
}

