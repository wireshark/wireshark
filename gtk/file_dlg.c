/* file_dlg.c
 * Dialog boxes for handling files
 *
 * $Id: file_dlg.c,v 1.13 1999/12/06 09:02:48 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <string.h>

#ifndef __GLOBALS_H__
#include "globals.h"
#endif
#ifndef __GTKGLOBALS_H__
#include "gtkglobals.h"
#endif

#ifndef __KEYS_H__
#include "keys.h"
#endif

#ifndef __PREFS_DLG_H__
#include "prefs_dlg.h"
#endif

#ifndef __UTIL_H__
#include "util.h"
#endif

#ifndef __MENU_H__
#include "menu.h"
#endif

#ifndef __MAIN_H__
#include "main.h"
#endif

static void file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void select_file_type_cb(GtkWidget *w, gpointer data);
static void file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs);

/* Open a file */
void
file_open_cmd_cb(GtkWidget *w, gpointer data) {
  GtkWidget *filter_hbox, *filter_bt, *filter_te;

  if (last_open_dir)
	  chdir(last_open_dir);

  file_sel = gtk_file_selection_new ("Ethereal: Open Capture File");
  
  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_open_ok_cb, file_sel );

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_sel)->ok_button),
      E_DFILTER_TE_KEY, gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY));

  filter_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_sel)->action_area),
    filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_cb), (gpointer) E_PR_PG_FILTER);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  gtk_widget_show(filter_te);

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_sel)->ok_button),
    E_RFILTER_TE_KEY, filter_te);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  gtk_widget_show(file_sel);
}

static void
file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar     *cf_name, *rfilter, *s;
  GtkWidget *filter_te;
  dfilter   *rfcode = NULL;
  int        err;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_RFILTER_TE_KEY);
  rfilter = gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (dfilter_compile(rfilter, &rfcode) != 0) {
    simple_dialog(ESD_TYPE_WARN, NULL, dfilter_error_msg);
    return;
  }

  /* Try to open the capture file. */
  if ((err = open_cap_file(cf_name, FALSE, &cf)) != 0) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    if (rfcode != NULL)
      dfilter_destroy(rfcode);
    return;
  }

  /* Attach the new read filter to "cf" ("open_cap_file()" succeeded, so
     it closed the previous capture file, and thus destroyed any
     previous read filter attached to "cf"). */
  cf.rfcode = rfcode;

  /* We've crossed the Rubicon; get rid of the file selection box. */
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  err = read_cap_file(&cf);
  /* Save the directory name; we can write over cf_name. */
  s = strrchr(cf_name, '/');
  if (s && last_open_dir) {
	  *s = '\0';
	  if (strcmp(last_open_dir, cf_name) != 0) {
		  g_free(last_open_dir);
		  last_open_dir = g_strdup(cf_name);
	  }
  }
  else if (s) { /* ! last_open_dir */
	  *s = '\0';
	  last_open_dir = g_strdup(cf_name);
  }
  else {
	  last_open_dir = NULL;
  }
  g_free(cf_name);
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget, gpointer data) {
  close_cap_file(&cf, info_bar);
}

void
file_save_cmd_cb(GtkWidget *w, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File");

  /* If the file's already been saved, do nothing.  */
  if (cf.user_saved)
    return;

  /* Do a "Save As". */
  file_save_as_cmd_cb(w, data);
}

/* XXX - can we make these not be static? */
static gboolean filtered;
static int filetype;
static GtkWidget *filter_cb;
static GtkWidget *ft_om;

static gboolean
can_save_with_wiretap(int ft)
{
  /* To save a file with Wiretap, Wiretap has to handle that format,
     and its code to handle that format must be able to write a file
     with this file's encapsulation type. */
  return wtap_dump_can_open(ft) && wtap_dump_can_write_encap(ft, cf.lnk_t);
}

/* Generate a list of the file types we can save this file as.

   "filetype" is the type it has now.

   "encap" is the encapsulation for its packets (which could be
   "unknown" or "per-packet").

   "filtered" is TRUE if we're to save only the packets that passed
   the display filter (in which case we have to save it using Wiretap)
   and FALSE if we're to save the entire file (in which case, if we're
   saving it in the type it has already, we can just copy it). */
static void
set_file_type_list(GtkWidget *option_menu)
{
  GtkWidget *ft_menu, *ft_menu_item;
  int ft;
  guint index;
  guint item_to_select;

  /* Default to the first supported file type, if the file's current
     type isn't supported. */
  item_to_select = 0;

  ft_menu = gtk_menu_new();

  /* Check all file types. */
  index = 0;
  for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
    if (filtered || ft != cf.cd_t) {
      /* Filtered, or a different file type.  We have to use Wiretap. */
      if (!can_save_with_wiretap(ft))
        continue;	/* We can't. */
    }

    /* OK, we can write it out in this type. */
    ft_menu_item = gtk_menu_item_new_with_label(wtap_file_type_string(ft));
    if (ft == filetype) {
      /* Default to the same format as the file, if it's supported. */
      item_to_select = index;
    }
    gtk_signal_connect(GTK_OBJECT(ft_menu_item), "activate",
      GTK_SIGNAL_FUNC(select_file_type_cb), (gpointer)ft);
    gtk_menu_append(GTK_MENU(ft_menu), ft_menu_item);
    gtk_widget_show(ft_menu_item);
    index++;
  }

  gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), ft_menu);
  gtk_option_menu_set_history(GTK_OPTION_MENU(option_menu), item_to_select);
}

static void
select_file_type_cb(GtkWidget *w, gpointer data)
{
  int new_filetype = (int)data;

  if (filetype != new_filetype) {
    /* We can select only the filtered packets to be saved iff we can
       use Wiretap to save the file. */
    gtk_widget_set_sensitive(filter_cb, can_save_with_wiretap(new_filetype));
    filetype = new_filetype;
  }
}

static void
toggle_filtered_cb(GtkWidget *widget, gpointer data)
{
  gboolean new_filtered;

  new_filtered = GTK_TOGGLE_BUTTON (widget)->active;

  if (filtered != new_filtered) {
    /* They changed the state of the "filtered" button. */
    filtered = new_filtered;
    set_file_type_list(ft_om);
  }
}

void
file_save_as_cmd_cb(GtkWidget *w, gpointer data)
{
  GtkWidget *ok_bt, *main_vb, *ft_hb, *ft_lb;

  /* Default to saving all packets, in the file's current format. */
  filtered = FALSE;
  filetype = cf.cd_t;

  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File As");

  /* Connect the ok_button to file_save_as_ok_cb function and pass along a
     pointer to the file selection box widget */
  ok_bt = GTK_FILE_SELECTION (file_sel)->ok_button;
  gtk_signal_connect (GTK_OBJECT (ok_bt), "clicked",
    (GtkSignalFunc) file_save_as_ok_cb, file_sel );

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_sel)->action_area),
    main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);
  
  filter_cb = gtk_check_button_new_with_label("Save only packets currently being displayed");
  gtk_container_add(GTK_CONTAINER(main_vb), filter_cb);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(filter_cb), FALSE);
  gtk_signal_connect(GTK_OBJECT(filter_cb), "toggled",
			GTK_SIGNAL_FUNC(toggle_filtered_cb), NULL);
  gtk_widget_set_sensitive(filter_cb, can_save_with_wiretap(filetype));
  gtk_widget_show(filter_cb);

  /* File type row */
  ft_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), ft_hb);
  gtk_widget_show(ft_hb);
  
  ft_lb = gtk_label_new("File type:");
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_lb, FALSE, FALSE, 0);
  gtk_widget_show(ft_lb);

  ft_om = gtk_option_menu_new();

  /* Generate the list of file types we can save. */
  set_file_type_list(ft_om);
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_om, FALSE, FALSE, 0);
  gtk_widget_show(ft_om);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");
  gtk_widget_show(file_sel);
}

static void
file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar	*cf_name;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  /* Write out the packets (all, or only the ones that are currently
     displayed) to the file with the specified name. */
  save_cap_file(cf_name, &cf, filtered, filetype);

  /* If "save_cap_file()" saved the file name we handed it, it saved
     a copy, so we should free up our copy. */
  g_free(cf_name);
}

/* Reload a file using the current read and display filters */
void
file_reload_cmd_cb(GtkWidget *w, gpointer data) {
  /*GtkWidget *filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);*/
  GtkWidget *filter_te;
  gchar *filename;
  gboolean is_tempfile;

  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

  if (cf.dfilter)
    g_free(cf.dfilter);
  cf.dfilter = g_strdup(gtk_entry_get_text(GTK_ENTRY(filter_te)));

  /* If the file could be opened, "open_cap_file()" calls "close_cap_file()"
     to get rid of state for the old capture file before filling in state
     for the new capture file.  "close_cap_file()" will remove the file if
     it's a temporary file; we don't want that to happen (for one thing,
     it'd prevent subsequent reopens from working).  Remember whether it's
     a temporary file, mark it as not being a temporary file, and then
     reopen it as the type of file it was.

     Also, "close_cap_file()" will free "cf.filename", so we must make
     a copy of it first. */
  filename = strdup(cf.filename);
  is_tempfile = cf.is_tempfile;
  cf.is_tempfile = FALSE;
  if (open_cap_file(filename, is_tempfile, &cf) == 0)
    read_cap_file(&cf);
  else {
    /* The open failed, so "cf.is_tempfile" wasn't set to "is_tempfile".
       Instead, the file was left open, so we should restore "cf.is_tempfile"
       ourselves.

       XXX - change the menu?  Presumably "open_cap_file()" will do that;
       make sure it does! */
    cf.is_tempfile = is_tempfile;
  }
  /* "open_cap_file()" made a copy of the file name we handed it, so
     we should free up our copy. */
  g_free(filename);
}
