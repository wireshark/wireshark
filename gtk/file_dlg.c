/* file_dlg.c
 * Dialog boxes for handling files
 *
 * $Id: file_dlg.c,v 1.43 2001/10/24 07:18:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <string.h>

#include <glib.h>

#include <epan/filesystem.h>

#include "globals.h"
#include "gtkglobals.h"
#include "prefs.h"
#include "resolv.h"
#include "keys.h"
#include "filter_prefs.h"
#include "ui_util.h"
#include "simple_dialog.h"
#include "menu.h"
#include "file_dlg.h"
#include "dlg_utils.h"
#include "main.h"

static void file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_open_destroy_cb(GtkWidget *win, gpointer user_data);
static void select_file_type_cb(GtkWidget *w, gpointer data);
static void file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_save_as_destroy_cb(GtkWidget *win, gpointer user_data);

#define E_FILE_M_RESOLVE_KEY	  "file_dlg_mac_resolve_key"
#define E_FILE_N_RESOLVE_KEY	  "file_dlg_network_resolve_key"
#define E_FILE_T_RESOLVE_KEY	  "file_dlg_transport_resolve_key"

/*
 * Keep a static pointer to the current "Open Capture File" window, if
 * any, so that if somebody tries to do "File:Open" while there's already
 * an "Open Capture File" window up, we just pop up the existing one,
 * rather than creating a new one.
 */
static GtkWidget *file_open_w;

/* Open a file */
void
file_open_cmd_cb(GtkWidget *w, gpointer data)
{
  GtkWidget	*main_vb, *filter_hbox, *filter_bt, *filter_te,
  		*m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
  GtkAccelGroup *accel_group;
  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */
  static construct_args_t args = {
  	"Ethereal: Read Filter",
  	FALSE,
  	FALSE
  };

  if (file_open_w != NULL) {
    /* There's already an "Open Capture File" dialog box; reactivate it. */
    reactivate_window(file_open_w);
    return;
  }

  file_open_w = gtk_file_selection_new ("Ethereal: Open Capture File");
  gtk_signal_connect(GTK_OBJECT(file_open_w), "destroy",
	GTK_SIGNAL_FUNC(file_open_destroy_cb), NULL);

  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_open_w), accel_group);

  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_open_w), last_open_dir);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_open_w)->action_area),
    main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);

  filter_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vb), filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(display_filter_construct_cb), &args);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  gtk_widget_show(filter_te);

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_open_w)->ok_button),
    E_RFILTER_TE_KEY, filter_te);

  m_resolv_cb = dlg_check_button_new_with_label_with_mnemonic(
		  "Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(m_resolv_cb),
	prefs.name_resolve & PREFS_RESOLV_MAC);
  gtk_box_pack_start(GTK_BOX(main_vb), m_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(m_resolv_cb);
  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_open_w)->ok_button),
		  E_FILE_M_RESOLVE_KEY, m_resolv_cb);

  n_resolv_cb = dlg_check_button_new_with_label_with_mnemonic(
		  "Enable _network name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(n_resolv_cb),
	prefs.name_resolve & PREFS_RESOLV_NETWORK);
  gtk_box_pack_start(GTK_BOX(main_vb), n_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(n_resolv_cb);
  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_open_w)->ok_button),
		  E_FILE_N_RESOLVE_KEY, n_resolv_cb);

  t_resolv_cb = dlg_check_button_new_with_label_with_mnemonic(
		  "Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(t_resolv_cb),
	prefs.name_resolve & PREFS_RESOLV_TRANSPORT);
  gtk_box_pack_start(GTK_BOX(main_vb), t_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(t_resolv_cb);
  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_open_w)->ok_button),
		  E_FILE_T_RESOLVE_KEY, t_resolv_cb);
  
  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect(GTK_OBJECT (GTK_FILE_SELECTION(file_open_w)->ok_button),
    "clicked", (GtkSignalFunc) file_open_ok_cb, file_open_w);

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_open_w)->ok_button),
      E_DFILTER_TE_KEY, gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY));

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_open_w)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_open_w));

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(file_open_w, GTK_FILE_SELECTION(file_open_w)->cancel_button);

  gtk_widget_show(file_open_w);
}

static void
file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar     *cf_name, *rfilter, *s;
  GtkWidget *filter_te, *m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
  dfilter_t *rfcode = NULL;
  int        err;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_RFILTER_TE_KEY);
  rfilter = gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (!dfilter_compile(rfilter, &rfcode)) {
    simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
    return;
  }

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
	/* It's a directory - set the file selection box to display that
	   directory, don't try to open the directory as a capture file. */
	set_last_open_dir(cf_name);
	gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);
    	return;
  }

  /* Try to open the capture file. */
  if ((err = open_cap_file(cf_name, FALSE, &cfile)) != 0) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    if (rfcode != NULL)
      dfilter_free(rfcode);
    g_free(cf_name);
    return;
  }

  /* Attach the new read filter to "cf" ("open_cap_file()" succeeded, so
     it closed the previous capture file, and thus destroyed any
     previous read filter attached to "cf"). */
  cfile.rfcode = rfcode;

  /* Set the global resolving variable */
  prefs.name_resolve = 0;
  m_resolv_cb = gtk_object_get_data(GTK_OBJECT(w), E_FILE_M_RESOLVE_KEY);
  prefs.name_resolve |= GTK_TOGGLE_BUTTON (m_resolv_cb)->active ? PREFS_RESOLV_MAC : PREFS_RESOLV_NONE;
  n_resolv_cb = gtk_object_get_data(GTK_OBJECT(w), E_FILE_N_RESOLVE_KEY);
  prefs.name_resolve |= GTK_TOGGLE_BUTTON (n_resolv_cb)->active ? PREFS_RESOLV_NETWORK : PREFS_RESOLV_NONE;
  t_resolv_cb = gtk_object_get_data(GTK_OBJECT(w), E_FILE_T_RESOLVE_KEY);
  prefs.name_resolve |= GTK_TOGGLE_BUTTON (t_resolv_cb)->active ? PREFS_RESOLV_TRANSPORT : PREFS_RESOLV_NONE;

  /* We've crossed the Rubicon; get rid of the file selection box. */
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  switch (read_cap_file(&cfile, &err)) {

  case READ_SUCCESS:
  case READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file. */
    break;

  case READ_ABORTED:
    /* The user bailed out of re-reading the capture file; the
       capture file has been closed - just free the capture file name
       string and return (without changing the last containing
       directory). */
    g_free(cf_name);
    return;
  }
    
  /* Save the name of the containing directory specified in the path name,
     if any; we can write over cf_name, which is a good thing, given that
     "get_dirname()" does write over its argument. */
  s = get_dirname(cf_name);
  set_last_open_dir(s);

  g_free(cf_name);
}

static void
file_open_destroy_cb(GtkWidget *win, gpointer user_data)
{
  GtkWidget *file_open_filter_w;

  /* Is there a filter edit/selection dialog associated with this
     Open Capture File dialog? */
  file_open_filter_w = gtk_object_get_data(GTK_OBJECT(win), E_FILT_DIALOG_PTR_KEY);

  if (file_open_filter_w != NULL) {
    /* Yes.  Destroy it. */
    gtk_widget_destroy(file_open_filter_w);
  }

  /* Note that we no longer have a "Open Capture File" dialog box. */
  file_open_w = NULL;
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget, gpointer data) {
  close_cap_file(&cfile);
}

void
file_save_cmd_cb(GtkWidget *w, gpointer data) {
  /* If the file's already been saved, do nothing.  */
  if (cfile.user_saved)
    return;

  /* Do a "Save As". */
  file_save_as_cmd_cb(w, data);
}

/* XXX - can we make these not be static? */
static gboolean filtered;
static gboolean marked;
static int filetype;
static GtkWidget *filter_cb;
static GtkWidget *mark_cb;
static GtkWidget *ft_om;

static gboolean
can_save_with_wiretap(int ft)
{
  /* To save a file with Wiretap, Wiretap has to handle that format,
     and its code to handle that format must be able to write a file
     with this file's encapsulation type. */
  return wtap_dump_can_open(ft) && wtap_dump_can_write_encap(ft, cfile.lnk_t);
}

/* Generate a list of the file types we can save this file as.

   "filetype" is the type it has now.

   "encap" is the encapsulation for its packets (which could be
   "unknown" or "per-packet").

   "filtered" is TRUE if we're to save only the packets that passed
   the display filter (in which case we have to save it using Wiretap)
   and FALSE if we're to save the entire file (in which case, if we're
   saving it in the type it has already, we can just copy it). 

   "marked" is TRUE if we have to save only the marked packets,
   the same remark as "filtered" applies.
*/
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
    if (filtered || marked || ft != cfile.cd_t) {
      /* Filtered, marked or a different file type.  We have to use Wiretap. */
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
    /* We can select only the filtered or marked packets to be saved if we can
       use Wiretap to save the file. */
    gtk_widget_set_sensitive(filter_cb, can_save_with_wiretap(new_filetype));
    gtk_widget_set_sensitive(mark_cb, can_save_with_wiretap(new_filetype));
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

static void
toggle_marked_cb(GtkWidget *widget, gpointer data)
{
  gboolean new_marked;

  new_marked = GTK_TOGGLE_BUTTON (widget)->active;

  if (marked != new_marked) {
    /* They changed the state of the "marked" button. */
    marked = new_marked;
    set_file_type_list(ft_om);
  }
}

/*
 * Keep a static pointer to the current "Save Capture File As" window, if
 * any, so that if somebody tries to do "File:Save" or "File:Save As"
 * while there's already a "Save Capture File As" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static GtkWidget *file_save_as_w;

void
file_save_as_cmd_cb(GtkWidget *w, gpointer data)
{
  GtkWidget *ok_bt, *main_vb, *ft_hb, *ft_lb;

  if (file_save_as_w != NULL) {
    /* There's already an "Save Capture File As" dialog box; reactivate it. */
    reactivate_window(file_save_as_w);
    return;
  }

  /* Default to saving all packets, in the file's current format. */
  filtered = FALSE;
  marked   = FALSE;
  filetype = cfile.cd_t;

  file_save_as_w = gtk_file_selection_new ("Ethereal: Save Capture File As");
  gtk_signal_connect(GTK_OBJECT(file_save_as_w), "destroy",
	GTK_SIGNAL_FUNC(file_save_as_destroy_cb), NULL);

  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_save_as_w), last_open_dir);

  /* Connect the ok_button to file_save_as_ok_cb function and pass along a
     pointer to the file selection box widget */
  ok_bt = GTK_FILE_SELECTION (file_save_as_w)->ok_button;
  gtk_signal_connect(GTK_OBJECT (ok_bt), "clicked",
    (GtkSignalFunc) file_save_as_ok_cb, file_save_as_w);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_save_as_w)->action_area),
    main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);
  
  /*
   * XXX - should this be sensitive only if the current display filter
   * has rejected some packets, so that not all packets are currently
   * being displayed, and if it has accepted some packets, so that some
   * packets are currently being displayed?
   */
  filter_cb = gtk_check_button_new_with_label("Save only packets currently being displayed");
  gtk_container_add(GTK_CONTAINER(main_vb), filter_cb);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(filter_cb), FALSE);
  gtk_signal_connect(GTK_OBJECT(filter_cb), "toggled",
			GTK_SIGNAL_FUNC(toggle_filtered_cb), NULL);
  gtk_widget_set_sensitive(filter_cb, can_save_with_wiretap(filetype));
  gtk_widget_show(filter_cb);

  /*
   * XXX - should this be sensitive only if at least one packet is
   * marked, so that there are marked packets to save, and if not
   * all packets are marked, so that "only marked packets" is different
   * from "all packets"?
   */
  mark_cb = gtk_check_button_new_with_label("Save only marked packets");
  gtk_container_add(GTK_CONTAINER(main_vb), mark_cb);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(mark_cb), FALSE);
  gtk_signal_connect(GTK_OBJECT(mark_cb), "toggled",
		     GTK_SIGNAL_FUNC(toggle_marked_cb), NULL);
  gtk_widget_set_sensitive(mark_cb, can_save_with_wiretap(filetype));
  gtk_widget_show(mark_cb);

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
    (file_save_as_w)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_save_as_w));

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(file_save_as_w, GTK_FILE_SELECTION(file_save_as_w)->cancel_button);

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_save_as_w), "");
  gtk_widget_show(file_save_as_w);
}

static void
file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar	*cf_name;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  /* Write out the packets (all, or only the ones that are currently
     displayed or marked) to the file with the specified name. */
  save_cap_file(cf_name, &cfile, filtered, marked, filetype);

  /* If "save_cap_file()" saved the file name we handed it, it saved
     a copy, so we should free up our copy. */
  g_free(cf_name);
}

static void
file_save_as_destroy_cb(GtkWidget *win, gpointer user_data)
{
  /* Note that we no longer have a "Save Capture File As" dialog box. */
  file_save_as_w = NULL;
}

/* Reload a file using the current read and display filters */
void
file_reload_cmd_cb(GtkWidget *w, gpointer data) {
  /*GtkWidget *filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);*/
  GtkWidget *filter_te;
  gchar *filename;
  gboolean is_tempfile;
  int err;

  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

  if (cfile.dfilter)
    g_free(cfile.dfilter);
  cfile.dfilter = g_strdup(gtk_entry_get_text(GTK_ENTRY(filter_te)));

  /* If the file could be opened, "open_cap_file()" calls "close_cap_file()"
     to get rid of state for the old capture file before filling in state
     for the new capture file.  "close_cap_file()" will remove the file if
     it's a temporary file; we don't want that to happen (for one thing,
     it'd prevent subsequent reopens from working).  Remember whether it's
     a temporary file, mark it as not being a temporary file, and then
     reopen it as the type of file it was.

     Also, "close_cap_file()" will free "cfile.filename", so we must make
     a copy of it first. */
  filename = strdup(cfile.filename);
  is_tempfile = cfile.is_tempfile;
  cfile.is_tempfile = FALSE;
  if (open_cap_file(filename, is_tempfile, &cfile) == 0) {
    switch (read_cap_file(&cfile, &err)) {

    case READ_SUCCESS:
    case READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file. */
      break;

    case READ_ABORTED:
      /* The user bailed out of re-reading the capture file; the
         capture file has been closed - just free the capture file name
         string and return (without changing the last containing
         directory). */
      g_free(filename);
      return;
    }
  } else {
    /* The open failed, so "cfile.is_tempfile" wasn't set to "is_tempfile".
       Instead, the file was left open, so we should restore "cfile.is_tempfile"
       ourselves.

       XXX - change the menu?  Presumably "open_cap_file()" will do that;
       make sure it does! */
    cfile.is_tempfile = is_tempfile;
  }
  /* "open_cap_file()" made a copy of the file name we handed it, so
     we should free up our copy. */
  g_free(filename);
}
