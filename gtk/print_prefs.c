/* print_prefs.c
 * Dialog boxes for preferences for printing
 *
 * $Id: print_prefs.c,v 1.7 2000/08/21 08:09:15 guy Exp $
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

#include <errno.h>

#include "globals.h"
#include "print_prefs.h"
#include "keys.h"
#include "print.h"
#include "prefs_dlg.h"
#include "util.h"
#include "ui_util.h"
#include "dlg_utils.h"

static void printer_opts_file_cb(GtkWidget *w, gpointer te);
static void printer_opts_fs_ok_cb(GtkWidget *w, gpointer data);
static void printer_opts_fs_cancel_cb(GtkWidget *w, gpointer data);
static void printer_opts_fs_destroy_cb(GtkWidget *win, gpointer data);
static void printer_opts_toggle_format(GtkWidget *widget, gpointer data);
static void printer_opts_toggle_dest(GtkWidget *widget, gpointer data);

#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"
#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"

GtkWidget * printer_prefs_show()
{
	GtkWidget	*main_vb, *main_tb, *button;
	GtkWidget	*format_hb, *format_lb;
	GtkWidget	*dest_hb, *dest_lb;
	GtkWidget	*cmd_lb, *cmd_te;
	GtkWidget	*file_bt_hb, *file_bt, *file_te;
	GSList		*format_grp, *dest_grp;

	/* Enclosing containers for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

	main_tb = gtk_table_new(4, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);

	/* Output format */
	format_lb = gtk_label_new("Format:");
  gtk_misc_set_alignment(GTK_MISC(format_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_lb, 0, 1, 0, 1);
	gtk_widget_show(format_lb);

	format_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_hb, 1, 2, 0, 1);
	gtk_widget_show(format_hb);

	button = gtk_radio_button_new_with_label(NULL, "Plain Text");
	if (prefs.pr_format == PR_FMT_TEXT) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	button = gtk_radio_button_new_with_label(format_grp, "PostScript");
	if (prefs.pr_format == PR_FMT_PS) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	gtk_signal_connect(GTK_OBJECT(button), "toggled",
			GTK_SIGNAL_FUNC(printer_opts_toggle_format), NULL);
	gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	/* Output destination */
	dest_lb = gtk_label_new("Print to:");
  gtk_misc_set_alignment(GTK_MISC(dest_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_lb, 0, 1, 1, 2);
	gtk_widget_show(dest_lb);

	dest_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_hb, 1, 2, 1, 2);
	gtk_widget_show(dest_hb);

	button = gtk_radio_button_new_with_label(NULL, "Command");
	if (prefs.pr_dest == PR_DEST_CMD) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	dest_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	gtk_box_pack_start(GTK_BOX(dest_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	button = gtk_radio_button_new_with_label(dest_grp, "File");
	if (prefs.pr_dest == PR_DEST_FILE) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	gtk_signal_connect(GTK_OBJECT(button), "toggled",
			GTK_SIGNAL_FUNC(printer_opts_toggle_dest), NULL);
	gtk_box_pack_start(GTK_BOX(dest_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	/* Command text entry */
	cmd_lb = gtk_label_new("Command:");
  gtk_misc_set_alignment(GTK_MISC(cmd_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_lb, 0, 1, 2, 3);
	gtk_widget_show(cmd_lb);

	cmd_te = gtk_entry_new();
	gtk_object_set_data(GTK_OBJECT(main_vb), PRINT_CMD_TE_KEY, cmd_te);
	if (prefs.pr_cmd) gtk_entry_set_text(GTK_ENTRY(cmd_te), prefs.pr_cmd);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_te, 1, 2, 2, 3);
	gtk_widget_show(cmd_te);

	/* File button and text entry */
	file_bt_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_bt_hb, 0, 1, 3, 4);
	gtk_widget_show(file_bt_hb);

	file_bt = gtk_button_new_with_label("File:");
	gtk_box_pack_end(GTK_BOX(file_bt_hb), file_bt, FALSE, FALSE, 0);
	gtk_widget_show(file_bt);

	file_te = gtk_entry_new();
	gtk_object_set_data(GTK_OBJECT(main_vb), PRINT_FILE_TE_KEY, file_te);
	if (prefs.pr_file) gtk_entry_set_text(GTK_ENTRY(file_te), prefs.pr_file);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_te, 1, 2, 3, 4);
	gtk_widget_show(file_te);

	gtk_signal_connect(GTK_OBJECT(file_bt), "clicked",
			GTK_SIGNAL_FUNC(printer_opts_file_cb), GTK_OBJECT(file_te));

	gtk_widget_show(main_vb);
	return(main_vb);
}


static void
printer_opts_file_cb(GtkWidget *file_bt, gpointer file_te) {
  GtkWidget *caller = gtk_widget_get_toplevel(file_bt);
  GtkWidget *fs;

  /* Has a file selection dialog box already been opened for that top-level
     widget? */
  fs = gtk_object_get_data(GTK_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Just re-activate that dialog box. */
    reactivate_window(fs);
    return;
  }

  fs = gtk_file_selection_new ("Ethereal: Print to a File");
	gtk_object_set_data(GTK_OBJECT(fs), PRINT_FILE_TE_KEY, file_te);

  /* Set the E_FS_CALLER_PTR_KEY for the new dialog to point to our caller. */
  gtk_object_set_data(GTK_OBJECT(fs), E_FS_CALLER_PTR_KEY, caller);

  /* Set the E_FILE_SEL_DIALOG_PTR_KEY for the caller to point to us */
  gtk_object_set_data(GTK_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY, fs);

  /* Call a handler when the file selection box is destroyed, so we can inform
     our caller, if any, that it's been destroyed. */
  gtk_signal_connect(GTK_OBJECT(fs), "destroy",
	    GTK_SIGNAL_FUNC(printer_opts_fs_destroy_cb), NULL);

  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->ok_button),
    "clicked", (GtkSignalFunc) printer_opts_fs_ok_cb, fs);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->cancel_button),
    "clicked", (GtkSignalFunc) printer_opts_fs_cancel_cb, fs);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(fs, GTK_FILE_SELECTION(fs)->cancel_button);

  gtk_widget_show(fs);
}

static void
printer_opts_fs_ok_cb(GtkWidget *w, gpointer data) {
	  
	gtk_entry_set_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(data),
  	PRINT_FILE_TE_KEY)),
		gtk_file_selection_get_filename (GTK_FILE_SELECTION(data)));
	printer_opts_fs_cancel_cb(w, data);
}

static void
printer_opts_fs_cancel_cb(GtkWidget *w, gpointer data) {
	  
	gtk_widget_destroy(GTK_WIDGET(data));
} 

static void
printer_opts_fs_destroy_cb(GtkWidget *win, gpointer data)
{
  GtkWidget *caller;

  /* Get the widget that requested that we be popped up.
     (It should arrange to destroy us if it's destroyed, so
     that we don't get a pointer to a non-existent window here.) */
  caller = gtk_object_get_data(GTK_OBJECT(win), E_FS_CALLER_PTR_KEY);

  /* Tell it we no longer exist. */
  gtk_object_set_data(GTK_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY, NULL);

  /* Now nuke this window. */
  gtk_grab_remove(GTK_WIDGET(win));
  gtk_widget_destroy(GTK_WIDGET(win));
}

void
printer_prefs_fetch(GtkWidget *w)
{
	if (prefs.pr_cmd)
		g_free(prefs.pr_cmd);
	prefs.pr_cmd =  
		g_strdup(gtk_entry_get_text(
		    GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(w),
		      PRINT_CMD_TE_KEY))));

	if (prefs.pr_file)
		g_free(prefs.pr_file);
	prefs.pr_file =  
		g_strdup(gtk_entry_get_text(
		    GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(w),
		      PRINT_FILE_TE_KEY))));
}

void
printer_prefs_apply(GtkWidget *w)
{
}

void
printer_prefs_destroy(GtkWidget *w)
{
  GtkWidget *caller = gtk_widget_get_toplevel(w);
  GtkWidget *fs;

  /* Is there a file selection dialog associated with this
     Preferences dialog? */
  fs = gtk_object_get_data(GTK_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Destroy it. */
    gtk_widget_destroy(fs);
  }
}

static void
printer_opts_toggle_format(GtkWidget *widget, gpointer data)
{
	if (GTK_TOGGLE_BUTTON (widget)->active) {
		prefs.pr_format = PR_FMT_PS;
		/* toggle file/cmd */
	}
	else {
		prefs.pr_format = PR_FMT_TEXT;
		/* toggle file/cmd */
	}
}

static void
printer_opts_toggle_dest(GtkWidget *widget, gpointer data)
{
	if (GTK_TOGGLE_BUTTON (widget)->active) {
		prefs.pr_dest = PR_DEST_FILE;
	}
	else {
		prefs.pr_dest = PR_DEST_CMD;
	}
}
