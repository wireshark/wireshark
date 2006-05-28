/* print_prefs.c
 * Dialog boxes for preferences for printing
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <gtk/gtk.h>

#include "globals.h"
#include "print_prefs.h"
#include "keys.h"
#include "print.h"
#include <epan/prefs.h>
#include "prefs_dlg.h"
#include "util.h"
#include "gui_utils.h"
#if 0
#include "dlg_utils.h"
#endif
#include "file_dlg.h"
#include "capture_file_dlg.h"
#include "compat_macros.h"
#include "gtkglobals.h"

static void printer_browse_file_cb(GtkWidget *file_bt, GtkWidget *file_te);

#define E_PRINT_FORMAT_KEY        "print_format"
#define E_PRINT_DESTINATION_KEY   "print_destination"

static const enum_val_t print_format_vals[] = {
	{ "text",       "Plain Text", PR_FMT_TEXT },
	{ "postscript", "Postscript", PR_FMT_PS },
	{ NULL,         NULL,         0 }
};

static const enum_val_t print_dest_vals[] = {
#ifdef _WIN32
	/* "PR_DEST_CMD" means "to printer" on Windows */
	{ "command", "Printer", PR_DEST_CMD },
#else
	{ "command", "Command", PR_DEST_CMD },
#endif
	{ "file",    "File",    PR_DEST_FILE },
	{ NULL,      NULL,      0 }
};

GtkWidget * printer_prefs_show(void)
{
	GtkWidget	*main_vb, *main_tb, *button;
#ifndef _WIN32
	GtkWidget	*cmd_te;
#endif
	GtkWidget	*file_lb_hb, *file_lb, *file_bt_hb, *file_bt, *file_te;

	/* Enclosing containers for each row of widgets */
	main_vb = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

	main_tb = gtk_table_new(4, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
	gtk_widget_show(main_tb);

	/* Output format */
	button = create_preference_radio_buttons(main_tb, 0, "Format:",
	   NULL, print_format_vals, prefs.pr_format);
	OBJECT_SET_DATA(main_vb, E_PRINT_FORMAT_KEY, button);

	/* Output destination */
	button = create_preference_radio_buttons(main_tb, 1, "Print to:",
	   NULL, print_dest_vals, prefs.pr_dest);
	OBJECT_SET_DATA(main_vb, E_PRINT_DESTINATION_KEY,
	   button);

#ifndef _WIN32
	/* Command text entry */
	cmd_te = create_preference_entry(main_tb, 2, "Command:", NULL,
	  prefs.pr_cmd);
	OBJECT_SET_DATA(main_vb, PRINT_CMD_TE_KEY, cmd_te);
#endif


	file_lb_hb = gtk_hbox_new(FALSE, 0);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), file_lb_hb, 0, 1, 3, 4);
	gtk_widget_show(file_lb_hb);

    file_lb = gtk_label_new("File:");
	gtk_box_pack_end(GTK_BOX(file_lb_hb), file_lb, FALSE, FALSE, 0);
	gtk_widget_show(file_lb);

	/* File button and text entry */
	file_bt_hb = gtk_hbox_new(FALSE, 0);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), file_bt_hb, 1, 2, 3, 4);
	gtk_widget_show(file_bt_hb);

    file_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_BROWSE);
	gtk_box_pack_end(GTK_BOX(file_bt_hb), file_bt, FALSE, FALSE, 0);
	gtk_widget_show(file_bt);

	file_te = gtk_entry_new();
	OBJECT_SET_DATA(main_vb, PRINT_FILE_TE_KEY, file_te);
	if (prefs.pr_file) gtk_entry_set_text(GTK_ENTRY(file_te), prefs.pr_file);
	gtk_box_pack_start(GTK_BOX(file_bt_hb), file_te, TRUE, TRUE, 0);
	gtk_widget_show(file_te);

	SIGNAL_CONNECT(file_bt, "clicked", printer_browse_file_cb, file_te);

	gtk_widget_show(main_vb);
	return(main_vb);
}


static void
printer_browse_file_cb(GtkWidget *file_bt, GtkWidget *file_te)
{
    file_selection_browse(file_bt, file_te, "Wireshark: Print to a File",
                          FILE_SELECTION_WRITE_BROWSE);
}


void
printer_prefs_fetch(GtkWidget *w)
{
  prefs.pr_format = fetch_preference_radio_buttons_val(
	OBJECT_GET_DATA(w, E_PRINT_FORMAT_KEY), print_format_vals);

  prefs.pr_dest = fetch_preference_radio_buttons_val(
	OBJECT_GET_DATA(w, E_PRINT_DESTINATION_KEY), print_dest_vals);

#ifndef _WIN32
  if (prefs.pr_cmd)
    g_free(prefs.pr_cmd);
  prefs.pr_cmd = g_strdup(gtk_entry_get_text(
			  GTK_ENTRY(OBJECT_GET_DATA(w, PRINT_CMD_TE_KEY))));
#endif

  if (prefs.pr_file)
    g_free(prefs.pr_file);
  prefs.pr_file = g_strdup(gtk_entry_get_text(
			   GTK_ENTRY(OBJECT_GET_DATA(w, PRINT_FILE_TE_KEY))));
}

void
printer_prefs_apply(GtkWidget *w _U_)
{
}

void
printer_prefs_destroy(GtkWidget *w)
{
  GtkWidget *caller = gtk_widget_get_toplevel(w);
  GtkWidget *fs;

  /* Is there a file selection dialog associated with this
     Preferences dialog? */
  fs = OBJECT_GET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Destroy it. */
    window_destroy(fs);
  }
}
