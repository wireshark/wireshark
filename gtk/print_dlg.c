/* print_dlg.c
 * Dialog boxes for printing
 *
 * $Id: print_dlg.c,v 1.12 2000/01/03 06:59:24 guy Exp $
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

#ifndef __GLOBALS_H__
#include "globals.h"
#endif

#ifndef __KEYS_H__
#include "keys.h"
#endif

#ifndef __PRINT_H__
#include "print.h"
#endif

#ifndef __PREFS_DLG_H__
#include "prefs_dlg.h"
#endif

#ifndef __DIALOG_H__
#include "simple_dialog.h"
#endif

static void print_cmd_toggle_dest(GtkWidget *widget, gpointer data);
static void print_cmd_toggle_detail(GtkWidget *widget, gpointer data);
static void print_file_cb(GtkWidget *file_bt, gpointer file_te);
static void print_fs_ok_cb(GtkWidget *w, gpointer data);
static void print_fs_cancel_cb(GtkWidget *w, gpointer data);
static void print_ok_cb(GtkWidget *ok_bt, gpointer parent_w);
static void print_close_cb(GtkWidget *close_bt, gpointer parent_w);

/*
 * Remember whether we printed to a printer or a file the last time we
 * printed something.
 */
static int     print_to_file;

#define PRINT_SUMMARY_RB_KEY      "printer_summary_radio_button"
#define PRINT_HEX_CB_KEY          "printer_hex_check_button"
#define PRINT_EXPAND_ALL_RB_KEY   "printer_expand_all_radio_button"
#define PRINT_AS_DISPLAYED_RB_KEY "printer_as_displayed_radio_button"

/* Print the capture */
void
file_print_cmd_cb(GtkWidget *widget, gpointer data)
{
  GtkWidget     *print_w;
  GtkWidget     *main_vb, *main_tb, *button;
#if 0
  GtkWidget     *format_hb, *format_lb;
  GSList        *format_grp;
#endif
  GtkWidget     *dest_rb;
  GtkWidget     *dest_hb, *dest_lb;
  GtkWidget     *cmd_lb, *cmd_te;
  GtkWidget     *file_bt_hb, *file_bt, *file_te;
  GSList        *dest_grp;
  GtkWidget     *options_hb;
  GtkWidget     *print_type_vb, *summary_rb, *detail_rb, *hex_cb;
  GSList        *summary_grp;
  GtkWidget     *expand_vb, *expand_all_rb, *as_displayed_rb;
  GSList        *expand_grp;
  GtkWidget     *bbox, *ok_bt, *cancel_bt;

  /* XXX - don't pop up one if there's already one open; instead,
       give it the input focus if that's possible. */

  print_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(print_w), "Ethereal: Print");

  /* Enclosing containers for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(print_w), main_vb);
  gtk_widget_show(main_vb);
  
  main_tb = gtk_table_new(4, 2, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);

  /* XXX - printing multiple frames in PostScript looks as if it's
     tricky - you have to deal with page boundaries, I think -
     and I'll have to spend some time learning enough about
     PostScript to figure it out, so, for now, we only print
     multiple frames as text. */
#if 0
  /* Output format */
  format_lb = gtk_label_new("Format:");
  gtk_misc_set_alignment(GTK_MISC(format_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_lb, 0, 1, 0, 1);
  gtk_widget_show(format_lb);

  format_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_hb, 1, 2, 0, 1);
  gtk_widget_show(format_hb);

  button = gtk_radio_button_new_with_label(NULL, "Plain Text");
  if (prefs.pr_format == PR_FMT_TEXT)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
  format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
  gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
  gtk_widget_show(button);

  button = gtk_radio_button_new_with_label(format_grp, "PostScript");
  if (prefs.pr_format == PR_FMT_PS)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
  gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
  gtk_widget_show(button);
#endif

  /* Output destination */
  dest_lb = gtk_label_new("Print to:");
  gtk_misc_set_alignment(GTK_MISC(dest_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_lb, 0, 1, 1, 2);
  gtk_widget_show(dest_lb);

  dest_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_hb, 1, 2, 1, 2);
  gtk_widget_show(dest_hb);

  button = gtk_radio_button_new_with_label(NULL, "Command");
  if (!print_to_file)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
  dest_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
  gtk_box_pack_start(GTK_BOX(dest_hb), button, FALSE, FALSE, 10);
  gtk_widget_show(button);

  dest_rb = gtk_radio_button_new_with_label(dest_grp, "File");
  if (print_to_file)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(dest_rb), TRUE);
  gtk_signal_connect(GTK_OBJECT(dest_rb), "toggled",
			GTK_SIGNAL_FUNC(print_cmd_toggle_dest), NULL);
  gtk_box_pack_start(GTK_BOX(dest_hb), dest_rb, FALSE, FALSE, 10);
  gtk_widget_show(dest_rb);

  /* Command text entry */
  cmd_lb = gtk_label_new("Command:");
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_CMD_LB_KEY, cmd_lb);
  gtk_misc_set_alignment(GTK_MISC(cmd_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_lb, 0, 1, 2, 3);
  gtk_widget_set_sensitive(cmd_lb, !print_to_file);
  gtk_widget_show(cmd_lb);

  cmd_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_CMD_TE_KEY, cmd_te);
  if (prefs.pr_cmd)
    gtk_entry_set_text(GTK_ENTRY(cmd_te), prefs.pr_cmd);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_te, 1, 2, 2, 3);
  gtk_widget_set_sensitive(cmd_te, !print_to_file);
  gtk_widget_show(cmd_te);

  /* File button and text entry */
  file_bt_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_bt_hb, 0, 1, 3, 4);
  gtk_widget_show(file_bt_hb);

  file_bt = gtk_button_new_with_label("File:");
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_FILE_BT_KEY, file_bt);
  gtk_box_pack_end(GTK_BOX(file_bt_hb), file_bt, FALSE, FALSE, 0);
  gtk_widget_set_sensitive(file_bt, print_to_file);
  gtk_widget_show(file_bt);

  file_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_FILE_TE_KEY, file_te);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_te, 1, 2, 3, 4);
  gtk_widget_set_sensitive(file_te, print_to_file);
  gtk_widget_show(file_te);

  gtk_signal_connect(GTK_OBJECT(file_bt), "clicked",
		GTK_SIGNAL_FUNC(print_file_cb), GTK_OBJECT(file_te));

  /* Horizontal box into which to put two vertical boxes of option
     buttons. */
  options_hb = gtk_hbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(options_hb), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), options_hb);
  gtk_widget_show(options_hb);

  /* Vertical box into which to put the "Print summary"/"Print detail"
     radio buttons and the "Print hex" check button. */
  print_type_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(print_type_vb), 5);
  gtk_container_add(GTK_CONTAINER(options_hb), print_type_vb);
  gtk_widget_show(print_type_vb);

  /* "Print summary"/"Print detail" radio buttons */
  summary_rb = gtk_radio_button_new_with_label(NULL, "Print summary");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(summary_rb), FALSE);
  summary_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(summary_rb));
  gtk_container_add(GTK_CONTAINER(print_type_vb), summary_rb);
  gtk_widget_show(summary_rb);
  detail_rb = gtk_radio_button_new_with_label(summary_grp, "Print detail");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(detail_rb), TRUE);
  gtk_signal_connect(GTK_OBJECT(detail_rb), "toggled",
			GTK_SIGNAL_FUNC(print_cmd_toggle_detail), NULL);
  gtk_container_add(GTK_CONTAINER(print_type_vb), detail_rb);
  gtk_widget_show(detail_rb);
  
  /* "Print hex" check button. */
  hex_cb = gtk_check_button_new_with_label("Print hex data");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(hex_cb), FALSE);
  gtk_container_add(GTK_CONTAINER(print_type_vb), hex_cb);
  gtk_widget_show(hex_cb);

  /* Vertical box into which to put the "Expand all levels"/"Print as displayed"
     radio buttons. */
  expand_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(expand_vb), 5);
  gtk_container_add(GTK_CONTAINER(options_hb), expand_vb);
  gtk_widget_show(expand_vb);

  /* "Expand all levels"/"Print as displayed" radio buttons */
  expand_all_rb = gtk_radio_button_new_with_label(NULL, "Expand all levels");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(expand_all_rb), TRUE);
  expand_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(expand_all_rb));
  gtk_container_add(GTK_CONTAINER(expand_vb), expand_all_rb);
  gtk_widget_show(expand_all_rb);
  as_displayed_rb = gtk_radio_button_new_with_label(expand_grp, "Print as displayed");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(as_displayed_rb), FALSE);
  gtk_container_add(GTK_CONTAINER(expand_vb), as_displayed_rb);
  gtk_widget_show(as_displayed_rb);

  gtk_object_set_data(GTK_OBJECT(detail_rb), PRINT_EXPAND_ALL_RB_KEY,
			expand_all_rb);
  gtk_object_set_data(GTK_OBJECT(detail_rb), PRINT_AS_DISPLAYED_RB_KEY,
			as_displayed_rb);
  gtk_object_set_data(GTK_OBJECT(detail_rb), PRINT_HEX_CB_KEY,
			hex_cb);

  /* Button row: OK and Cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_DEST_RB_KEY, dest_rb);
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_CMD_TE_KEY, cmd_te);
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_FILE_TE_KEY, file_te);
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_SUMMARY_RB_KEY, summary_rb);
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_HEX_CB_KEY, hex_cb);
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(print_ok_cb), GTK_OBJECT(print_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(print_close_cb), GTK_OBJECT(print_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

#if 0
  display_opt_window_active = TRUE;
#endif
  gtk_widget_show(print_w);
}

static void
print_cmd_toggle_dest(GtkWidget *widget, gpointer data)
{
  GtkWidget     *cmd_lb, *cmd_te, *file_bt, *file_te;
  int            to_file;

  cmd_lb = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_CMD_LB_KEY));
  cmd_te = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_CMD_TE_KEY));
  file_bt = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_FILE_BT_KEY));
  file_te = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_FILE_TE_KEY));
  if (GTK_TOGGLE_BUTTON (widget)->active) {
    /* They selected "Print to File" */
    to_file = TRUE;
  } else {
    /* They selected "Print to Command" */
    to_file = FALSE;
  }
  gtk_widget_set_sensitive(cmd_lb, !to_file);
  gtk_widget_set_sensitive(cmd_te, !to_file);
  gtk_widget_set_sensitive(file_bt, to_file);
  gtk_widget_set_sensitive(file_te, to_file);
}

static void
print_cmd_toggle_detail(GtkWidget *widget, gpointer data)
{
  GtkWidget     *expand_all_rb, *as_displayed_rb, *hex_cb;
  gboolean      print_detail;

  expand_all_rb = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_EXPAND_ALL_RB_KEY));
  as_displayed_rb = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_AS_DISPLAYED_RB_KEY));
  hex_cb = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_HEX_CB_KEY));
  if (GTK_TOGGLE_BUTTON (widget)->active) {
    /* They selected "Print detail" */
    print_detail = TRUE;
  } else {
    /* They selected "Print summary" */
    print_detail = FALSE;
  }
  gtk_widget_set_sensitive(expand_all_rb, print_detail);
  gtk_widget_set_sensitive(as_displayed_rb, print_detail);
  gtk_widget_set_sensitive(hex_cb, print_detail);
}

static void
print_file_cb(GtkWidget *file_bt, gpointer file_te)
{
  GtkWidget *fs;

  fs = gtk_file_selection_new ("Ethereal: Print to File");
	gtk_object_set_data(GTK_OBJECT(fs), PRINT_FILE_TE_KEY, file_te);

  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->ok_button),
    "clicked", (GtkSignalFunc) print_fs_ok_cb, fs);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->cancel_button),
    "clicked", (GtkSignalFunc) print_fs_cancel_cb, fs);

  gtk_widget_show(fs);
}

static void
print_fs_ok_cb(GtkWidget *w, gpointer data)
{
  
  gtk_entry_set_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(data),
      PRINT_FILE_TE_KEY)),
      gtk_file_selection_get_filename (GTK_FILE_SELECTION(data)));
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
print_fs_cancel_cb(GtkWidget *w, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
print_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  GtkWidget *button;
  print_args_t print_args;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(ok_bt),
                                              PRINT_DEST_RB_KEY);
  print_to_file = GTK_TOGGLE_BUTTON (button)->active;
  print_args.to_file = print_to_file;

  if (print_args.to_file)
    print_args.dest = g_strdup(gtk_entry_get_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(ok_bt),
      PRINT_FILE_TE_KEY))));
  else
    print_args.dest = g_strdup(gtk_entry_get_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(ok_bt),
      PRINT_CMD_TE_KEY))));

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(ok_bt),
                                              PRINT_SUMMARY_RB_KEY);
  print_args.print_summary = GTK_TOGGLE_BUTTON (button)->active;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(ok_bt),
                                              PRINT_HEX_CB_KEY);
  print_args.print_hex = GTK_TOGGLE_BUTTON (button)->active;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(ok_bt),
                                              PRINT_EXPAND_ALL_RB_KEY);
  print_args.expand_all = GTK_TOGGLE_BUTTON (button)->active;

  gtk_widget_destroy(GTK_WIDGET(parent_w));
#if 0
  display_opt_window_active = FALSE;
#endif

  /* Now print the packets */
  if (!print_packets(&cf, &print_args)) {
    if (print_args.to_file)
      simple_dialog(ESD_TYPE_WARN, NULL,
        file_write_error_message(errno), print_args.dest);
    else
      simple_dialog(ESD_TYPE_WARN, NULL, "Couldn't run print command %s.",
        print_args.dest);
  }

  g_free(print_args.dest);
}

static void
print_close_cb(GtkWidget *close_bt, gpointer parent_w)
{

  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
#if 0
  display_opt_window_active = FALSE;
#endif
}

/* Print a packet */
void
file_print_packet_cmd_cb(GtkWidget *widget, gpointer data) {
  FILE *fh;
  print_args_t print_args;

  switch (prefs.pr_dest) {

  case PR_DEST_CMD:
    fh = popen(prefs.pr_cmd, "w");
    print_args.to_file = FALSE;
    print_args.dest = prefs.pr_cmd;
    break;

  case PR_DEST_FILE:
    fh = fopen(prefs.pr_file, "w");
    print_args.to_file = TRUE;
    print_args.dest = prefs.pr_file;
    break;

  default:
    fh = NULL;	/* XXX - "can't happen" */
    break;
  }
  if (fh == NULL) {
    switch (prefs.pr_dest) {

    case PR_DEST_CMD:
      simple_dialog(ESD_TYPE_WARN, NULL, "Couldn't run print command %s.",
        prefs.pr_cmd);
      break;

    case PR_DEST_FILE:
      simple_dialog(ESD_TYPE_WARN, NULL, file_write_error_message(errno),
        prefs.pr_file);
      break;
    }
    return;
  }

  print_preamble(fh);
  print_args.print_summary = FALSE;
  print_args.print_hex = FALSE;
  print_args.expand_all = TRUE;
  proto_tree_print(TRUE, &print_args, (GNode*) cf.protocol_tree, cf.pd,
		cf.current_frame, fh);
  print_finale(fh);
  close_print_dest(print_args.to_file, fh);
}

