/* file_dlg.c
 * Dialog boxes for handling files
 *
 * $Id: file_dlg.c,v 1.91 2004/02/01 20:28:11 ulfl Exp $
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

#include <gtk/gtk.h>

#include "range.h"
#include <epan/filesystem.h>

#include "globals.h"
#include "gtkglobals.h"
#include <epan/resolv.h>
#include "keys.h"
#include "filter_prefs.h"
#include "ui_util.h"
#include "simple_dialog.h"
#include "menu.h"
#include "file_dlg.h"
#include "dlg_utils.h"
#include "main.h"
#include "compat_macros.h"
#include "prefs.h"
#include "recent.h"
#include "color.h"
#include "../ui_util.h"
#include "gtk/color_filters.h"
#include "gtk/color_dlg.h"
#ifdef HAVE_LIBPCAP
#include "capture_dlg.h"
#endif


static void file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_open_destroy_cb(GtkWidget *win, gpointer user_data);
static void select_file_type_cb(GtkWidget *w, gpointer data);
static void file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_save_as_destroy_cb(GtkWidget *win, gpointer user_data);
static void file_color_import_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_color_import_destroy_cb(GtkWidget *win, gpointer user_data);
static void file_color_export_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_color_export_destroy_cb(GtkWidget *win, gpointer user_data);
static void file_select_ok_cb(GtkWidget *w, gpointer data);
static void file_select_cancel_cb(GtkWidget *w, gpointer data);
static void file_select_destroy_cb(GtkWidget *win, GtkWidget* file_te);
static void toggle_captured_cb(GtkWidget *widget, gpointer data _U_);

#define E_FILE_M_RESOLVE_KEY	  "file_dlg_mac_resolve_key"
#define E_FILE_N_RESOLVE_KEY	  "file_dlg_network_resolve_key"
#define E_FILE_T_RESOLVE_KEY	  "file_dlg_transport_resolve_key"

#define ARGUMENT_CL "argument_cl"

/*
 * Keep a static pointer to the current "Save Capture File As" window, if
 * any, so that if somebody tries to do "File:Save" or "File:Save As"
 * while there's already a "Save Capture File As" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static GtkWidget *file_save_as_w;

/*
 * A generic select_file_cb routine that is intended to be connected to
 * a Browse button on other dialog boxes. This allows the user to browse
 * for a file and select it. We fill in the text_entry that is asssociated
 * with the button that invoked us. 
 *
 * We display the window label specified in our args.
 */
void
select_file_cb(GtkWidget *file_bt, const char *label)
{
  GtkWidget *caller = gtk_widget_get_toplevel(file_bt);
  GtkWidget *fs, *file_te;

  /* Has a file selection dialog box already been opened for that top-level
     widget? */
  fs = OBJECT_GET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY);
  file_te = OBJECT_GET_DATA(file_bt, E_FILE_TE_PTR_KEY);
  if (fs != NULL) {
    /* Yes.  Just re-activate that dialog box. */
    reactivate_window(fs);
    return;
  }

  fs = file_selection_new (label);

  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);

  OBJECT_SET_DATA(fs, PRINT_FILE_TE_KEY, file_te);

  /* Set the E_FS_CALLER_PTR_KEY for the new dialog to point to our caller. */
  OBJECT_SET_DATA(fs, E_FS_CALLER_PTR_KEY, caller);

  /* Set the E_FILE_SEL_DIALOG_PTR_KEY for the caller to point to us */
  OBJECT_SET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY, fs);

  /* Call a handler when the file selection box is destroyed, so we can inform
     our caller, if any, that it's been destroyed. */
  SIGNAL_CONNECT(fs, "destroy", GTK_SIGNAL_FUNC(file_select_destroy_cb), 
		 file_te);

  SIGNAL_CONNECT(GTK_FILE_SELECTION(fs)->ok_button, "clicked", 
		 file_select_ok_cb, fs);

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(fs)->cancel_button, "clicked",
                 file_select_cancel_cb, fs);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(fs, GTK_FILE_SELECTION(fs)->cancel_button);

  gtk_widget_show(fs);
}

static void
file_select_ok_cb(GtkWidget *w _U_, gpointer data)
{
  gchar     *f_name;

  f_name = g_strdup(gtk_file_selection_get_filename(
    GTK_FILE_SELECTION (data)));

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(f_name) == EISDIR) {
        /* It's a directory - set the file selection box to display it. */
        set_last_open_dir(f_name);
        g_free(f_name);
        gtk_file_selection_set_filename(GTK_FILE_SELECTION(data),
          last_open_dir);
        return;
  }

  gtk_entry_set_text(GTK_ENTRY(OBJECT_GET_DATA(data, PRINT_FILE_TE_KEY)),
                     f_name);
  gtk_widget_destroy(GTK_WIDGET(data));

  g_free(f_name);
}

static void
file_select_cancel_cb(GtkWidget *w _U_, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
file_select_destroy_cb(GtkWidget *win, GtkWidget* file_te)
{
  GtkWidget *caller;

  /* Get the widget that requested that we be popped up.
     (It should arrange to destroy us if it's destroyed, so
     that we don't get a pointer to a non-existent window here.) */
  caller = OBJECT_GET_DATA(win, E_FS_CALLER_PTR_KEY);

  /* Tell it we no longer exist. */
  OBJECT_SET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY, NULL);

  /* Now nuke this window. */
  gtk_grab_remove(GTK_WIDGET(win));
  gtk_widget_destroy(GTK_WIDGET(win));

  /* Give the focus to the file text entry widget so the user can just press
     Return to print to the file. */
  gtk_widget_grab_focus(file_te);
}

/*
 * Keep a static pointer to the current "Open Capture File" window, if
 * any, so that if somebody tries to do "File:Open" while there's already
 * an "Open Capture File" window up, we just pop up the existing one,
 * rather than creating a new one.
 */
static GtkWidget *file_open_w;

/* Open a file */
void
file_open_cmd(GtkWidget *w)
{
  GtkWidget	*main_vb, *filter_hbox, *filter_bt, *filter_te,
  		*m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
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

  file_open_w = file_selection_new ("Ethereal: Open Capture File");
  SIGNAL_CONNECT(file_open_w, "destroy", file_open_destroy_cb, NULL);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_open_w), accel_group);
#endif

  switch (prefs.gui_fileopen_style) {

  case FO_STYLE_LAST_OPENED:
    /* The user has specified that we should start out in the last directory
       we looked in.  If we've already opened a file, use its containing
       directory, if we could determine it, as the directory, otherwise
       use the "last opened" directory saved in the preferences file if
       there was one. */
    if (last_open_dir) {
      gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_open_w),
				      last_open_dir);
    }
    else {
      if (recent.gui_fileopen_remembered_dir != NULL) {
	gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_open_w),
					recent.gui_fileopen_remembered_dir);
      }
    }
    break;

  case FO_STYLE_SPECIFIED:
    /* The user has specified that we should always start out in a
       specified directory; if they've specified that directory,
       start out by showing the files in that dir. */
    if (prefs.gui_fileopen_dir[0] != '\0') {
      gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_open_w),
				      prefs.gui_fileopen_dir);
    }
    break;
  }
    
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

  filter_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY);
  SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
  SIGNAL_CONNECT(filter_bt, "destroy", filter_button_destroy_cb, NULL);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);

  filter_te = gtk_entry_new();
  OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  gtk_widget_show(filter_te);

  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
                  E_RFILTER_TE_KEY, filter_te);

  m_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(m_resolv_cb),
	g_resolv_flags & RESOLV_MAC);
  gtk_box_pack_start(GTK_BOX(main_vb), m_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(m_resolv_cb);
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
                  E_FILE_M_RESOLVE_KEY, m_resolv_cb);

  n_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Enable _network name resolution", accel_group);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(n_resolv_cb),
	g_resolv_flags & RESOLV_NETWORK);
  gtk_box_pack_start(GTK_BOX(main_vb), n_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(n_resolv_cb);
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
		  E_FILE_N_RESOLVE_KEY, n_resolv_cb);

  t_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_resolv_cb),
	g_resolv_flags & RESOLV_TRANSPORT);
  gtk_box_pack_start(GTK_BOX(main_vb), t_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(t_resolv_cb);
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
		  E_FILE_T_RESOLVE_KEY, t_resolv_cb);

  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(file_open_w)->ok_button, "clicked",
                 file_open_ok_cb, file_open_w);

  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
                  E_DFILTER_TE_KEY, OBJECT_GET_DATA(w, E_DFILTER_TE_KEY));

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT_OBJECT(GTK_FILE_SELECTION(file_open_w)->cancel_button,
                        "clicked", (GtkSignalFunc)gtk_widget_destroy,
                        file_open_w);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(file_open_w, GTK_FILE_SELECTION(file_open_w)->cancel_button);

  gtk_widget_show(file_open_w);
}

void file_open_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_YES):
        /* save file first */
        file_save_as_cmd(after_save_open_dialog, data);
        break;
    case(ESD_BTN_NO):
        file_open_cmd(data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

void
file_open_cmd_cb(GtkWidget *widget, gpointer data _U_) {
  gpointer  dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_WARN | ESD_TYPE_MODAL, 
                ESD_BTN_YES | ESD_BTN_NO | ESD_BTN_CANCEL, 
                PRIMARY_TEXT_START "Save capture file before opening a new one?" PRIMARY_TEXT_END "\n\n"
                "If you open a new capture file without saving, your capture data will be discarded.");
    simple_dialog_set_cb(dialog, file_open_answered_cb, widget);
  } else {
    /* unchanged file, just open a new one */
    file_open_cmd(widget);
  }
}

static void
file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar     *cf_name, *rfilter, *s;
  GtkWidget *filter_te, *m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
  dfilter_t *rfcode = NULL;
  int        err;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  filter_te = OBJECT_GET_DATA(w, E_RFILTER_TE_KEY);
  rfilter = (gchar *)gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (!dfilter_compile(rfilter, &rfcode)) {
    g_free(cf_name);
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, dfilter_error_msg);
    return;
  }

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
	/* It's a directory - set the file selection box to display that
	   directory, don't try to open the directory as a capture file. */
	set_last_open_dir(cf_name);
        g_free(cf_name);
	gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);
    	return;
  }

  /* Try to open the capture file. */
  if ((err = cf_open(cf_name, FALSE, &cfile)) != 0) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    if (rfcode != NULL)
      dfilter_free(rfcode);
    g_free(cf_name);
    return;
  }

  /* Attach the new read filter to "cf" ("cf_open()" succeeded, so
     it closed the previous capture file, and thus destroyed any
     previous read filter attached to "cf"). */
  cfile.rfcode = rfcode;

  /* Set the global resolving variable */
  g_resolv_flags = prefs.name_resolve & RESOLV_CONCURRENT;
  m_resolv_cb = OBJECT_GET_DATA(w, E_FILE_M_RESOLVE_KEY);
  g_resolv_flags |= gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (m_resolv_cb)) ? RESOLV_MAC : RESOLV_NONE;
  n_resolv_cb = OBJECT_GET_DATA(w, E_FILE_N_RESOLVE_KEY);
  g_resolv_flags |= gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (n_resolv_cb)) ? RESOLV_NETWORK : RESOLV_NONE;
  t_resolv_cb = OBJECT_GET_DATA(w, E_FILE_T_RESOLVE_KEY);
  g_resolv_flags |= gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (t_resolv_cb)) ? RESOLV_TRANSPORT : RESOLV_NONE;

  /* We've crossed the Rubicon; get rid of the file selection box. */
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  switch (cf_read(&cfile)) {

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
  gtk_widget_grab_focus(packet_list);

  g_free(cf_name);
}

static void
file_open_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Open Capture File" dialog box. */
  file_open_w = NULL;
}

void file_close_confirmed_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_YES):
        /* save file first */
        file_save_as_cmd(after_save_close_file, NULL);
        break;
    case(ESD_BTN_NO):
        cf_close(&cfile);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget _U_, gpointer data _U_) {
  gpointer  dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_WARN | ESD_TYPE_MODAL, 
                ESD_BTN_YES | ESD_BTN_NO | ESD_BTN_CANCEL, 
                PRIMARY_TEXT_START "Save capture file before closing it?" PRIMARY_TEXT_END "\n\n"
                "If you close without saving, your capture data will be discarded.");

    simple_dialog_set_cb(dialog, file_close_confirmed_cb, NULL);
  } else {
    /* unchanged file, just close it */
    cf_close(&cfile);
  }
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
static packet_range_t range;
static gboolean color_marked;
static int filetype;
static GtkWidget *captured_bt;
static GtkWidget *displayed_bt;
static GtkWidget *select_all_rb;
static GtkWidget *select_all_c_lb;
static GtkWidget *select_all_d_lb;
static GtkWidget *select_curr_rb;
static GtkWidget *select_curr_c_lb;
static GtkWidget *select_curr_d_lb;
static GtkWidget *select_marked_only_rb;
static GtkWidget *select_marked_only_c_lb;
static GtkWidget *select_marked_only_d_lb;
static GtkWidget *select_marked_range_rb;
static GtkWidget *select_marked_range_c_lb;
static GtkWidget *select_marked_range_d_lb;
static GtkWidget *select_user_range_rb;
static GtkWidget *select_user_range_c_lb;
static GtkWidget *select_user_range_d_lb;
static GtkWidget *select_user_range_entry;
static GtkWidget *cfmark_cb;
static GtkWidget *ft_om;

static gboolean
can_save_with_wiretap(int ft)
{
  /* To save a file with Wiretap, Wiretap has to handle that format,
     and its code to handle that format must be able to write a file
     with this file's encapsulation type. */
  return wtap_dump_can_open(ft) && wtap_dump_can_write_encap(ft, cfile.lnk_t);
}

static void
file_set_save_dynamics(void) {
  gboolean      filtered_active;
  gchar         label_text[100];
  gint          selected_num;


  filtered_active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(displayed_bt));

  gtk_widget_set_sensitive(displayed_bt, can_save_with_wiretap(filetype));

  gtk_widget_set_sensitive(select_all_c_lb, !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", cfile.count);
  gtk_label_set_text(GTK_LABEL(select_all_c_lb), label_text);
  gtk_widget_set_sensitive(select_all_d_lb, filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range.displayed_cnt);

  gtk_label_set_text(GTK_LABEL(select_all_d_lb), label_text);

  selected_num = (cfile.current_frame) ? cfile.current_frame->num : 0;
  /* XXX: how to update the radio button label but keep the mnemonic? */
/*  g_snprintf(label_text, sizeof(label_text), "_Selected packet #%u only", selected_num);
  gtk_label_set_text(GTK_LABEL(GTK_BIN(select_curr_rb)->child), label_text);*/
  gtk_widget_set_sensitive(select_curr_rb, selected_num);
  g_snprintf(label_text, sizeof(label_text), "%u", selected_num ? 1 : 0);
  gtk_label_set_text(GTK_LABEL(select_curr_c_lb), label_text);
  gtk_widget_set_sensitive(select_curr_c_lb, selected_num && !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", selected_num ? 1 : 0);
  gtk_label_set_text(GTK_LABEL(select_curr_d_lb), label_text);
  gtk_widget_set_sensitive(select_curr_d_lb, selected_num && filtered_active);

  gtk_widget_set_sensitive(select_marked_only_rb, cfile.marked_count);
  g_snprintf(label_text, sizeof(label_text), "%u", cfile.marked_count);
  gtk_label_set_text(GTK_LABEL(select_marked_only_c_lb), label_text);
  gtk_widget_set_sensitive(select_marked_only_c_lb, cfile.marked_count && !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range.displayed_marked_cnt);
  gtk_label_set_text(GTK_LABEL(select_marked_only_d_lb), label_text);
  gtk_widget_set_sensitive(select_marked_only_d_lb, range.displayed_marked_cnt && filtered_active);

  gtk_widget_set_sensitive(select_marked_range_rb, range.mark_range_cnt);
  g_snprintf(label_text, sizeof(label_text), "%u", range.mark_range_cnt);
  gtk_label_set_text(GTK_LABEL(select_marked_range_c_lb), label_text);
  gtk_widget_set_sensitive(select_marked_range_c_lb, range.mark_range_cnt && !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range.displayed_mark_range_cnt);
  gtk_label_set_text(GTK_LABEL(select_marked_range_d_lb), label_text);
  gtk_widget_set_sensitive(select_marked_range_d_lb, range.displayed_mark_range_cnt && filtered_active);

  gtk_widget_set_sensitive(select_user_range_rb, TRUE);
  g_snprintf(label_text, sizeof(label_text), "%u", range.user_range_cnt);
  gtk_label_set_text(GTK_LABEL(select_user_range_c_lb), label_text);
  gtk_widget_set_sensitive(select_user_range_c_lb, !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range.displayed_user_range_cnt);
  gtk_label_set_text(GTK_LABEL(select_user_range_d_lb), label_text);
  gtk_widget_set_sensitive(select_user_range_d_lb, filtered_active);
}

/* Generate a list of the file types we can save this file as.

   "filetype" is the type it has now.

   "encap" is the encapsulation for its packets (which could be
   "unknown" or "per-packet").

   "filtered" is TRUE if we're to save only the packets that passed
   the display filter (in which case we have to save it using Wiretap)
   and FALSE if we're to save the entire file (in which case, if we're
   saving it in the type it has already, we can just copy it).

   The same applies for sel_curr, sel_all, sel_m_only, sel_m_range and sel_man_range
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
    if (!packet_range_process_all(&range) || ft != cfile.cd_t) {
      /* not all unfiltered packets or a different file type.  We have to use Wiretap. */
      if (!can_save_with_wiretap(ft))
        continue;	/* We can't. */
    }

    /* OK, we can write it out in this type. */
    ft_menu_item = gtk_menu_item_new_with_label(wtap_file_type_string(ft));
    if (ft == filetype) {
      /* Default to the same format as the file, if it's supported. */
      item_to_select = index;
    }
    SIGNAL_CONNECT(ft_menu_item, "activate", select_file_type_cb,
                   GINT_TO_POINTER(ft));
    gtk_menu_append(GTK_MENU(ft_menu), ft_menu_item);
    gtk_widget_show(ft_menu_item);
    index++;
  }

  gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), ft_menu);
  gtk_option_menu_set_history(GTK_OPTION_MENU(option_menu), item_to_select);
}

static void
select_file_type_cb(GtkWidget *w _U_, gpointer data)
{
  int new_filetype = GPOINTER_TO_INT(data);

  if (filetype != new_filetype) {
    /* We can select only the filtered or marked packets to be saved if we can
       use Wiretap to save the file. */
    gtk_widget_set_sensitive(displayed_bt, can_save_with_wiretap(new_filetype));
    filetype = new_filetype;
    file_set_save_marked_sensitive();
  }
}

static void
toggle_captured_cb(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    /* They changed the state of the "captured" button. */
    range.process_filtered = FALSE;
    /* XXX: the following line fails, I have no idea why */
    /* set_file_type_list(ft_om);*/

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(captured_bt), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(displayed_bt), FALSE);

    file_set_save_dynamics();
  }
}

static void
toggle_filtered_cb(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process_filtered = TRUE;
    set_file_type_list(ft_om);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(captured_bt), FALSE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(displayed_bt), TRUE);
    
    file_set_save_dynamics();
  }
}

static void
toggle_select_all(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_all;
    set_file_type_list(ft_om);
    file_set_save_dynamics();
  }
}

static void
toggle_select_selected(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_selected;
    set_file_type_list(ft_om);
    file_set_save_dynamics();
  }
}

static void
toggle_select_marked_only(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_marked;
    set_file_type_list(ft_om);
    file_set_save_dynamics();
  }
}

static void
toggle_select_marked_range(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_marked_range;
    set_file_type_list(ft_om);
    file_set_save_dynamics();
  }
}

static void
toggle_select_user_range(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_user_range;
    set_file_type_list(ft_om);
    file_set_save_dynamics();
  }
	
  /* Make the entry widget sensitive or insensitive */
  gtk_widget_set_sensitive(select_user_range_entry, range.process == range_process_user_range);

  /* When selecting user specified range, then focus on the entry */
  if (range.process == range_process_user_range)
      gtk_widget_grab_focus(select_user_range_entry);

}

static void
range_entry(GtkWidget *entry)
{
  const gchar *entry_text;

  entry_text = gtk_entry_get_text (GTK_ENTRY (entry));
  packet_range_convert_str(&range, entry_text);
  file_set_save_dynamics();
}

/*
 * Set the "Save only marked packets" toggle button as appropriate for
 * the current output file type and count of marked packets.
 *
 * Called when the "Save As..." dialog box is created and when either
 * the file type or the marked count changes.
 */
void
file_set_save_marked_sensitive(void)
{
  if (file_save_as_w == NULL) {
    /* We don't currently have a "Save As..." dialog box up. */
    return;
  }
	
  /* We can request that only the marked packets be saved only if we
     can use Wiretap to save the file and if there *are* marked packets. */
  if (can_save_with_wiretap(filetype) && cfile.marked_count != 0) {
    gtk_widget_set_sensitive(select_marked_only_rb, TRUE);
    gtk_widget_set_sensitive(select_marked_range_rb, TRUE);	  
  }
  else {
    /* Force the "Save only marked packets" toggle to "false", turn
       off the flag it controls, and update the list of types we can
       save the file as. */
    range.process = range_process_all;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_marked_only_rb), FALSE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_marked_range_rb), FALSE);	  
    set_file_type_list(ft_om);
    gtk_widget_set_sensitive(select_marked_only_rb,  FALSE);
    gtk_widget_set_sensitive(select_marked_range_rb, FALSE);	  
  }
}

action_after_save_e action_after_save_g;
gpointer            action_after_save_data_g;


void
file_save_as_cmd(action_after_save_e action_after_save, gpointer action_after_save_data)
{
  GtkWidget     *ok_bt, *main_vb, *ft_hb, *ft_lb, *range_fr, *range_tb;
  GtkTooltips   *tooltips;

#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
	  
  if (file_save_as_w != NULL) {
    /* There's already an "Save Capture File As" dialog box; reactivate it. */
    reactivate_window(file_save_as_w);
    return;
  }

  /* Default to saving all packets, in the file's current format. */
  filetype = cfile.cd_t;

  /* init the packet range */
  packet_range_init(&range);

  /* Enable tooltips */
  tooltips = gtk_tooltips_new();
	  
  /* build the file selection */
  file_save_as_w = file_selection_new ("Ethereal: Save Capture File As");
  SIGNAL_CONNECT(file_save_as_w, "destroy", file_save_as_destroy_cb, NULL);

  /* as the dialog might already be gone, when using this values, we cannot
   * set data to the dialog object, but keep global values */
  action_after_save_g       = action_after_save;
  action_after_save_data_g  = action_after_save_data;

#if GTK_MAJOR_VERSION < 2
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_save_as_w), accel_group);
#endif
	
  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_save_as_w), last_open_dir);

  /* Connect the ok_button to file_save_as_ok_cb function and pass along a
     pointer to the file selection box widget */
  ok_bt = GTK_FILE_SELECTION (file_save_as_w)->ok_button;
  SIGNAL_CONNECT(ok_bt, "clicked", file_save_as_ok_cb, file_save_as_w);

  /* Container for each row of widgets */
       
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_save_as_w)->action_area),
    main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);	
		
  /*** Packet Range frame ***/
  range_fr = gtk_frame_new("Packet Range");
  gtk_box_pack_start(GTK_BOX(main_vb), range_fr, FALSE, FALSE, 0);
  gtk_widget_show(range_fr);
  
  /* range table */
  range_tb = gtk_table_new(7, 3, FALSE);
  gtk_container_border_width(GTK_CONTAINER(range_tb), 5);
  gtk_container_add(GTK_CONTAINER(range_fr), range_tb);
  gtk_widget_show(range_tb);

  /* captured button */
  captured_bt = TOGGLE_BUTTON_NEW_WITH_MNEMONIC("_Captured", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), captured_bt, 1, 2, 0, 1);
  SIGNAL_CONNECT(captured_bt, "toggled", toggle_captured_cb, NULL);
  gtk_tooltips_set_tip (tooltips,captured_bt,("Process all the below chosen packets"), NULL);
  gtk_widget_show(captured_bt);

  /* displayed button */
  displayed_bt = TOGGLE_BUTTON_NEW_WITH_MNEMONIC("_Displayed", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), displayed_bt, 2, 3, 0, 1);
  SIGNAL_CONNECT(displayed_bt, "toggled", toggle_filtered_cb, NULL);
  gtk_tooltips_set_tip (tooltips,displayed_bt,("Process only the below chosen packets, which also passes the current display filter"), NULL);
  gtk_widget_show(displayed_bt);


  /* Process all packets */
  select_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "_All packets", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_all_rb, 0, 1, 1, 2);
  gtk_tooltips_set_tip (tooltips,select_all_rb,("Process all packets"), NULL);
  SIGNAL_CONNECT(select_all_rb, "toggled", toggle_select_all, NULL);
  gtk_widget_show(select_all_rb);

  select_all_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_all_c_lb, 1, 2, 1, 2);
  gtk_widget_show(select_all_c_lb);
  select_all_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_all_d_lb, 2, 3, 1, 2);
  gtk_widget_show(select_all_d_lb);

	
  /* Process currently selected */
  select_curr_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "_Selected packet only", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_curr_rb, 0, 1, 2, 3);
  gtk_tooltips_set_tip (tooltips,select_curr_rb,("Process the currently selected packet only"), NULL);
  SIGNAL_CONNECT(select_curr_rb, "toggled", toggle_select_selected, NULL);
  gtk_widget_show(select_curr_rb);
	
  select_curr_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_curr_c_lb, 1, 2, 2, 3);
  gtk_widget_show(select_curr_c_lb);
  select_curr_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_curr_d_lb, 2, 3, 2, 3);
  gtk_widget_show(select_curr_d_lb);


  /* Process marked packets */
  select_marked_only_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "_Marked packets only", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_only_rb, 0, 1, 3, 4);
  gtk_tooltips_set_tip (tooltips,select_marked_only_rb,("Process marked packets only"), NULL);
  SIGNAL_CONNECT(select_marked_only_rb, "toggled", toggle_select_marked_only, NULL);
  gtk_widget_show(select_marked_only_rb);

  select_marked_only_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_only_c_lb, 1, 2, 3, 4);
  gtk_widget_show(select_marked_only_c_lb);
  select_marked_only_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_only_d_lb, 2, 3, 3, 4);
  gtk_widget_show(select_marked_only_d_lb);

  
  /* Process packet range between first and last packet */
  select_marked_range_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "From first _to last marked packet", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_range_rb, 0, 1, 4, 5);
  gtk_tooltips_set_tip (tooltips,select_marked_range_rb,("Process all packets between the first and last marker"), NULL);
  SIGNAL_CONNECT(select_marked_range_rb, "toggled", toggle_select_marked_range, NULL);
  gtk_widget_show(select_marked_range_rb);

  select_marked_range_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_range_c_lb, 1, 2, 4, 5);
  gtk_widget_show(select_marked_range_c_lb);
  select_marked_range_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_range_d_lb, 2, 3, 4, 5);
  gtk_widget_show(select_marked_range_d_lb);


  /* Process a user specified provided packet range : -10,30,40-70,80- */
  select_user_range_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "Specify a packet _range:", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_rb, 0, 1, 5, 6);
  gtk_tooltips_set_tip (tooltips,select_user_range_rb,("Process a specified packet range"), NULL);
  SIGNAL_CONNECT(select_user_range_rb, "toggled", toggle_select_user_range, NULL);
  gtk_widget_show(select_user_range_rb);

  select_user_range_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_c_lb, 1, 2, 5, 6);
  gtk_widget_show(select_user_range_c_lb);
  select_user_range_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_d_lb, 2, 3, 5, 6);
  gtk_widget_show(select_user_range_d_lb);


  /* The entry part */
  select_user_range_entry = gtk_entry_new();
  gtk_entry_set_max_length (GTK_ENTRY (select_user_range_entry), 254);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_entry, 0, 1, 6, 7);
  gtk_tooltips_set_tip (tooltips,select_user_range_entry, 
	("Specify a range of packet numbers :     \nExample :  1-10,18,25-100,332-"), NULL);
  SIGNAL_CONNECT(select_user_range_entry,"changed", range_entry, select_user_range_entry);	
  gtk_widget_set_sensitive(select_user_range_entry, FALSE);
  gtk_widget_show(select_user_range_entry);

  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(captured_bt), TRUE);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(displayed_bt), FALSE);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_all_rb),  TRUE);
  
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

  /*
   * Set the sensitivity of the "Save only marked packets" toggle
   * button
   *
   * This has to be done after we create the file type menu option,
   * as the routine that sets it also sets that menu.
   */
  file_set_save_marked_sensitive();
	
  /* dynamic values in the range frame */
  file_set_save_dynamics();

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT_OBJECT(GTK_FILE_SELECTION(file_save_as_w)->cancel_button,
                        "clicked", (GtkSignalFunc)gtk_widget_destroy,
                        file_save_as_w);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(file_save_as_w, GTK_FILE_SELECTION(file_save_as_w)->cancel_button);

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_save_as_w), "");

  gtk_widget_show(file_save_as_w);
}

void
file_save_as_cmd_cb(GtkWidget *w _U_, gpointer data _U_)
{
  file_save_as_cmd(after_save_no_action, NULL);
}

static void
file_save_as_ok_cb(GtkWidget *w _U_, GtkFileSelection *fs) {
  gchar	*cf_name;
  gchar	*dirname;

	  
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);
        return;
  }

  /* don't show the dialog while saving */
  gtk_widget_hide(GTK_WIDGET (fs));

  /* Write out the packets (all, or only the ones from the current
     range) to the file with the specified name. */
  if (! cf_save(cf_name, &cfile, &range, filetype)) {
    /* The write failed; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the error, try again. */
    g_free(cf_name);
    gtk_widget_show(GTK_WIDGET (fs));
    return;
  }

  /* The write succeeded; get rid of the file selection box. */
  /* cf_save might already closed our dialog! */
  if (file_save_as_w)
    gtk_widget_destroy(GTK_WIDGET (fs));

  /* Save the directory name for future file dialogs. */
  dirname = get_dirname(cf_name);  /* Overwrites cf_name */
  set_last_open_dir(dirname);
  g_free(cf_name);

  /* we have finished saving, do we have pending things to do? */
  switch(action_after_save_g) {
  case(after_save_no_action):
      break;
  case(after_save_open_dialog):
      file_open_cmd(action_after_save_data_g);
      break;
  case(after_save_open_recent_file):
      menu_open_recent_file_cmd(action_after_save_data_g);
      break;
  case(after_save_open_dnd_file):
      dnd_open_file_cmd(action_after_save_data_g);
      break;
#ifdef HAVE_LIBPCAP
  case(after_save_capture_dialog):
      capture_prep();
      break;
#endif
  case(after_save_close_file):
      cf_close(&cfile);
      break;
  case(after_save_exit):
      main_do_quit();
      break;
  default:
      g_assert_not_reached();
  }

  action_after_save_g = after_save_no_action;
}

void
file_save_as_destroy(void)
{
  if (file_save_as_w)
    gtk_widget_destroy(file_save_as_w);
}

static void
file_save_as_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Save Capture File As" dialog box. */
  file_save_as_w = NULL;
}

/* Reload a file using the current read and display filters */
void
file_reload_cmd_cb(GtkWidget *w _U_, gpointer data _U_) {
  gchar *filename;
  gboolean is_tempfile;

  /* If the file could be opened, "cf_open()" calls "cf_close()"
     to get rid of state for the old capture file before filling in state
     for the new capture file.  "cf_close()" will remove the file if
     it's a temporary file; we don't want that to happen (for one thing,
     it'd prevent subsequent reopens from working).  Remember whether it's
     a temporary file, mark it as not being a temporary file, and then
     reopen it as the type of file it was.

     Also, "cf_close()" will free "cfile.filename", so we must make
     a copy of it first. */
  filename = g_strdup(cfile.filename);
  is_tempfile = cfile.is_tempfile;
  cfile.is_tempfile = FALSE;
  if (cf_open(filename, is_tempfile, &cfile) == 0) {
    switch (cf_read(&cfile)) {

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

       XXX - change the menu?  Presumably "cf_open()" will do that;
       make sure it does! */
    cfile.is_tempfile = is_tempfile;
  }
  /* "cf_open()" made a copy of the file name we handed it, so
     we should free up our copy. */
  g_free(filename);
}

/******************** Color Filters *********************************/
/*
 * Keep a static pointer to the current "Color Export" window, if
 * any, so that if somebody tries to do "Export"
 * while there's already a "Color Export" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static GtkWidget *file_color_import_w;

/* sets the file path to the global color filter file.
   WARNING: called by both the import and the export dialog.
*/
static void
color_global_cb(GtkWidget *widget _U_, gpointer data)
{
  GtkWidget *fs_widget = data;
  
	gchar *path;

	/* decide what file to open (from dfilter code) */
	path = get_datafile_path("colorfilters");

  gtk_file_selection_set_filename (GTK_FILE_SELECTION(fs_widget), path);

  g_free((gchar *)path);
}

/* Import color filters */
void
file_color_import_cmd_cb(GtkWidget *w _U_, gpointer data)
{
  GtkWidget	*main_vb, *cfglobal_but;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */

  if (file_color_import_w != NULL) {
    /* There's already an "Import Color Filters" dialog box; reactivate it. */
    reactivate_window(file_color_import_w);
    return;
  }

  file_color_import_w = gtk_file_selection_new ("Ethereal: Import Color Filters");
  SIGNAL_CONNECT(file_color_import_w, "destroy", file_color_import_destroy_cb, NULL);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_color_import_w), accel_group);
#endif

  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_color_import_w), last_open_dir);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_color_import_w)->action_area),
    main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);


  cfglobal_but = gtk_button_new_with_label("Global Color Filter File");
  gtk_container_add(GTK_CONTAINER(main_vb), cfglobal_but);
  SIGNAL_CONNECT(cfglobal_but, "clicked", color_global_cb, file_color_import_w);
  gtk_widget_show(cfglobal_but);

  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(file_color_import_w)->ok_button, "clicked",
                 file_color_import_ok_cb, file_color_import_w);

  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_color_import_w)->ok_button,
                  ARGUMENT_CL, data);

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT_OBJECT(GTK_FILE_SELECTION(file_color_import_w)->cancel_button,
                        "clicked", (GtkSignalFunc)gtk_widget_destroy,
                        file_color_import_w);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(file_color_import_w, GTK_FILE_SELECTION(file_color_import_w)->cancel_button);

  gtk_widget_show(file_color_import_w);
}

static void
file_color_import_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar     *cf_name, *s;
  gpointer  argument;

  argument = OBJECT_GET_DATA(w, ARGUMENT_CL);     /* to be passed back into read_other_filters */
  
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
	/* It's a directory - set the file selection box to display that
	   directory, don't try to open the directory as a capture file. */
	set_last_open_dir(cf_name);
        g_free(cf_name);
	gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);
    	return;
  }

  /* Try to open the capture file. */

  if (!read_other_filters(cf_name, argument)) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    g_free(cf_name);
    return;
  }

  /* We've crossed the Rubicon; get rid of the file selection box. */
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  /* Save the name of the containing directory specified in the path name,
     if any; we can write over cf_name, which is a good thing, given that
     "get_dirname()" does write over its argument. */
  s = get_dirname(cf_name);
  set_last_open_dir(s);
  gtk_widget_grab_focus(packet_list);

  g_free(cf_name);
}

static void
file_color_import_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Open Capture File" dialog box. */
  file_color_import_w = NULL;
}

static GtkWidget *file_color_export_w;
/*
 * Set the "Export only marked filters" toggle button as appropriate for
 * the current output file type and count of marked filters.
 *
 * Called when the "Export" dialog box is created and when the marked
 * count changes.
 */
void
color_set_export_marked_sensitive(GtkWidget * cfmark_cb)
{
  if (file_color_export_w == NULL) {
    /* We don't currently have an "Export" dialog box up. */
    return;
  }

  /* We can request that only the marked filters be saved only if
        there *are* marked filters. */
  if (color_marked_count() != 0)
    gtk_widget_set_sensitive(cfmark_cb, TRUE);
  else {
    /* Force the "Export only marked filters" toggle to "false", turn
       off the flag it controls. */
    color_marked = FALSE;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cfmark_cb), FALSE);
    gtk_widget_set_sensitive(cfmark_cb, FALSE);
  }
}

static void
color_toggle_marked_cb(GtkWidget *widget, gpointer data _U_)
{
  color_marked = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));
}

void
file_color_export_cmd_cb(GtkWidget *w _U_, gpointer data _U_)
{
  GtkWidget *ok_bt, *main_vb, *cfglobal_but;

  if (file_color_export_w != NULL) {
    /* There's already an "Color Filter Export" dialog box; reactivate it. */
    reactivate_window(file_color_export_w);
    return;
  }

  /* Default to saving all packets, in the file's current format. */
  color_marked   = FALSE;
  filetype = cfile.cd_t;

  file_color_export_w = gtk_file_selection_new ("Ethereal: Export Color Filters");
  SIGNAL_CONNECT(file_color_export_w, "destroy", file_color_export_destroy_cb, NULL);

  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_color_export_w), last_open_dir);

  /* Connect the ok_button to file_export_ok_cb function and pass along a
     pointer to the file selection box widget */
  ok_bt = GTK_FILE_SELECTION (file_color_export_w)->ok_button;
  SIGNAL_CONNECT(ok_bt, "clicked", file_color_export_ok_cb, file_color_export_w);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_color_export_w)->action_area),
    main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);

  cfmark_cb = gtk_check_button_new_with_label("Export only marked filters");
  gtk_container_add(GTK_CONTAINER(main_vb), cfmark_cb);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cfmark_cb), FALSE);
  SIGNAL_CONNECT(cfmark_cb, "toggled", color_toggle_marked_cb, NULL);
  gtk_widget_show(cfmark_cb);
  color_set_export_marked_sensitive(cfmark_cb);

  cfglobal_but = gtk_button_new_with_label("Global Color Filter File");
  gtk_container_add(GTK_CONTAINER(main_vb), cfglobal_but);
  SIGNAL_CONNECT(cfglobal_but, "clicked", color_global_cb, file_color_export_w);
  gtk_widget_show(cfglobal_but);

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT_OBJECT(GTK_FILE_SELECTION(file_color_export_w)->cancel_button,
                        "clicked", (GtkSignalFunc)gtk_widget_destroy,
                        file_color_export_w);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(file_color_export_w, GTK_FILE_SELECTION(file_color_export_w)->cancel_button);

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_color_export_w), "");

  gtk_widget_show(file_color_export_w);
}

static void
file_color_export_ok_cb(GtkWidget *w _U_, GtkFileSelection *fs) {
  gchar	*cf_name;
  gchar	*dirname;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);
        return;
  }

  /* Write out the filters (all, or only the ones that are currently
     displayed or marked) to the file with the specified name. */

   if (!write_other_filters(cf_name, color_marked))
   {
    /* The write failed; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the error, try again. */

       g_free(cf_name);
       return;
   }

  /* The write succeeded; get rid of the file selection box. */
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  /* Save the directory name for future file dialogs. */
  dirname = get_dirname(cf_name);  /* Overwrites cf_name */
  set_last_open_dir(dirname);
  g_free(cf_name);
}

static void
file_color_export_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  file_color_export_w = NULL;
}


