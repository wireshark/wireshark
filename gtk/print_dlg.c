/* print_dlg.c
 * Dialog boxes for printing
 *
 * $Id: print_dlg.c,v 1.45 2003/11/18 19:27:39 ulfl Exp $
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

#include "globals.h"
#include "keys.h"
#include "print.h"
#include "prefs.h"
#include "simple_dialog.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "main.h"
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#ifdef _WIN32
#include <io.h>
#include "print_mswin.h"
#endif
#include "compat_macros.h"


/* On Win32, a GUI application apparently can't use "popen()" (it
  "returns an invalid file handle, if used in a Windows program,
  that will cause the program to hang indefinitely"), so we can't
  use a pipe to a print command to print to a printer.

  Eventually, we should try to use the native Win32 printing API
  for this (and also use various UNIX printing APIs, when present?).
*/

static void print_cmd_toggle_dest(GtkWidget *widget, gpointer data);
static void print_cmd_toggle_detail(GtkWidget *widget, gpointer data);
static void print_file_cb(GtkWidget *file_bt, gpointer file_te);
static void print_fs_ok_cb(GtkWidget *w, gpointer data);
static void print_fs_cancel_cb(GtkWidget *w, gpointer data);
static void print_fs_destroy_cb(GtkWidget *win, GtkWidget* file_te);
static void print_ok_cb(GtkWidget *ok_bt, gpointer parent_w);
static void print_close_cb(GtkWidget *close_bt, gpointer parent_w);
static void print_destroy_cb(GtkWidget *win, gpointer user_data);

static gboolean print_prefs_init = FALSE;

/*
 * Remember whether we printed to a printer or a file the last time we
 * printed something.
 */
static int     print_to_file;

/*
 * Remember whether we printed as text or PostScript the last time we
 * printed something.
 */
static gint	print_format;

static gchar * print_file;
static gchar * print_cmd;

#define PRINT_FORMAT_RB_KEY       "printer_format_radio_button"
#define PRINT_DEST_CB_KEY         "printer_destination_check_button"

#define PRINT_DETAILS_FR_KEY      "printer_details_frame"
#define PRINT_DETAILS_CB_KEY      "printer_details_check_button"
#define PRINT_HEX_CB_KEY          "printer_hex_check_button"
#define PRINT_COLLAPSE_ALL_RB_KEY "printer_collapse_all_radio_button"
#define PRINT_AS_DISPLAYED_RB_KEY "printer_as_displayed_radio_button"
#define PRINT_EXPAND_ALL_RB_KEY   "printer_expand_all_radio_button"
#define PRINT_PRINT_ONLY_MARKED_RB_KEY "printer_print_only_marked_radio_button"

#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"
#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"

/*
 * Keep a static pointer to the current "Print" window, if any, so that if
 * somebody tries to do "File:Print" while there's already a "Print" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *print_w;

/* Print the capture */
void
file_print_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif

  GtkWidget     *main_vb;

  GtkWidget     *printer_fr, *printer_vb;
  GtkWidget     *text_rb, *format_rb;
  GtkWidget     *printer_tb, *dest_cb;
#ifndef _WIN32
  GtkWidget     *cmd_lb, *cmd_te;
#endif
  GtkWidget     *file_bt, *file_te;

  GtkWidget     *range_fr, *range_vb;
  GtkWidget     *all_captured_rb, *all_displayed_rb, *selected_rb, *marked_rb;
  GtkWidget     *range_rb;

  GtkWidget     *packet_fr, *packet_vb;
  GtkWidget     *details_cb, *details_fr, *details_vb;
  GtkWidget     *collapse_all_rb, *as_displayed_rb, *expand_all_rb,*hex_cb;

  GtkWidget     *bbox, *ok_bt, *cancel_bt;

  GtkTooltips   *tooltips;
  gchar         label_text[100];
  frame_data    *packet;
  guint32       displayed_count;


  if (print_w != NULL) {
    /* There's already a "Print" dialog box; reactivate it. */
    reactivate_window(print_w);
    return;
  }

  /* count displayed packets */
  /* XXX: there should be a displayed_count in cfile, so we don't have to do this here */
  displayed_count = 0;
  packet = cfile.plist;
  while(packet != NULL) {
    if (packet->flags.passed_dfilter) {
      displayed_count++;
    }
    packet = packet->next;
  }

  /* get settings from preferences only once */
  if(print_prefs_init == FALSE) {
      print_prefs_init  = TRUE;
      print_to_file     = prefs.pr_dest;
      print_format      = prefs.pr_format;
      print_cmd         = prefs.pr_cmd;
      print_file        = prefs.pr_file;
  }

  tooltips = gtk_tooltips_new();

  /* dialog window */
  print_w = dlg_window_new("Ethereal: Print");
  SIGNAL_CONNECT(print_w, "destroy", print_destroy_cb, NULL);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(print_w), accel_group);
#endif

  /* Vertical enclosing container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(print_w), main_vb);
  gtk_widget_show(main_vb);

/*****************************************************/

  /*** printer frame ***/
  printer_fr = gtk_frame_new("Printer");
  gtk_box_pack_start(GTK_BOX(main_vb), printer_fr, FALSE, FALSE, 0);
  gtk_widget_show(printer_fr);
  printer_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(printer_vb), 5);
  gtk_container_add(GTK_CONTAINER(printer_fr), printer_vb);
  gtk_widget_show(printer_vb);

  /* "Plain text" / "Postscript" radio buttons */
#if GTK_MAJOR_VERSION < 2
  text_rb = dlg_radio_button_new_with_label_with_mnemonic(NULL, "Plain _text",
                                                         accel_group);
#else
  text_rb = gtk_radio_button_new_with_mnemonic(NULL, "Plain _text");
#endif
  if (print_format == PR_FMT_TEXT)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(text_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, text_rb, ("Print output in ascii \"plain text\" format"), NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), text_rb, FALSE, FALSE, 0);
  gtk_widget_show(text_rb);

#if GTK_MAJOR_VERSION < 2
  format_rb = dlg_radio_button_new_with_label_with_mnemonic(
                    gtk_radio_button_group(GTK_RADIO_BUTTON(text_rb)),
                                                            "_PostScript",
                                                            accel_group);
#else
  format_rb = gtk_radio_button_new_with_mnemonic_from_widget(
                                GTK_RADIO_BUTTON(text_rb), "_PostScript");
#endif
  if (print_format == PR_FMT_PS)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(format_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, format_rb, ("Print output in \"postscript\" format"), NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), format_rb, FALSE, FALSE, 0);
  gtk_widget_show(format_rb);


  /* printer table */
#ifndef _WIN32
  printer_tb = gtk_table_new(2, 3, FALSE);
#else
  printer_tb = gtk_table_new(2, 2, FALSE);
#endif
  gtk_box_pack_start(GTK_BOX(printer_vb), printer_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(printer_tb), 5);
  gtk_table_set_col_spacings(GTK_TABLE(printer_tb), 5);
  gtk_widget_show(printer_tb);


  /* Output to file button */
#if GTK_MAJOR_VERSION < 2
  dest_cb = dlg_check_button_new_with_label_with_mnemonic("Output to _File:",
                                                          accel_group);
#else
  dest_cb = gtk_check_button_new_with_mnemonic("Output to _File:");
#endif
  if (print_to_file)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(dest_cb), TRUE);
  gtk_tooltips_set_tip (tooltips, dest_cb, ("Output to file instead of printer"), NULL);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), dest_cb, 0, 1, 0, 1);
  gtk_widget_show(dest_cb);
  
  /* File text entry and "Browse" button */
  file_te = gtk_entry_new();
  OBJECT_SET_DATA(dest_cb, PRINT_FILE_TE_KEY, file_te);
  gtk_tooltips_set_tip (tooltips, file_te, ("Enter Output filename"), NULL);
  gtk_entry_set_text(GTK_ENTRY(file_te), print_file);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), file_te, 1, 2, 0, 1);
  gtk_widget_set_sensitive(file_te, print_to_file);
  gtk_widget_show(file_te);
  if (print_to_file)
    gtk_widget_grab_focus(file_te);

  file_bt = gtk_button_new_with_label("Browse");
  OBJECT_SET_DATA(dest_cb, PRINT_FILE_BT_KEY, file_bt);
  gtk_tooltips_set_tip (tooltips, file_bt, ("Browse output filename in filesystem"), NULL);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), file_bt, 2, 3, 0, 1);
  gtk_widget_set_sensitive(file_bt, print_to_file);
  gtk_widget_show(file_bt);

  /* Command label and text entry */
#ifndef _WIN32
  cmd_lb = gtk_label_new("Print command:");
  OBJECT_SET_DATA(dest_cb, PRINT_CMD_LB_KEY, cmd_lb);
  gtk_misc_set_alignment(GTK_MISC(cmd_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), cmd_lb, 0, 1, 1, 2);
  gtk_widget_set_sensitive(cmd_lb, !print_to_file);
  gtk_widget_show(cmd_lb);

  cmd_te = gtk_entry_new();
  OBJECT_SET_DATA(dest_cb, PRINT_CMD_TE_KEY, cmd_te);
  if (prefs.pr_cmd)
    gtk_entry_set_text(GTK_ENTRY(cmd_te), prefs.pr_cmd);
  gtk_tooltips_set_tip (tooltips, cmd_te, ("Enter print command"), NULL);
  gtk_entry_set_text(GTK_ENTRY(cmd_te), print_cmd);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), cmd_te, 1, 2, 1, 2);
  gtk_widget_set_sensitive(cmd_te, !print_to_file);
  gtk_widget_show(cmd_te);
#endif

  SIGNAL_CONNECT(dest_cb, "toggled", print_cmd_toggle_dest, NULL);
  SIGNAL_CONNECT(file_bt, "clicked", print_file_cb, file_te);


/*****************************************************/

  /*** print range frame ***/
  range_fr = gtk_frame_new("Print Range");
  gtk_box_pack_start(GTK_BOX(main_vb), range_fr, FALSE, FALSE, 0);
  gtk_widget_show(range_fr);
  range_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(range_vb), 5);
  gtk_container_add(GTK_CONTAINER(range_fr), range_vb);
  gtk_widget_show(range_vb);


  /* "All packets captured" */
  /* "All packets displayed" */
  /* "Selected packet only" */
  /* "Marked packets only" */
  /* "Packets from x to y" */

  g_snprintf(label_text, sizeof(label_text), "XXX: All packets _captured, XXX%u packet(s)", 0);
#if GTK_MAJOR_VERSION < 2
  all_captured_rb = dlg_radio_button_new_with_label_with_mnemonic(NULL,
				label_text, accel_group);
#else
  all_captured_rb = gtk_radio_button_new_with_mnemonic(NULL, label_text);
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(all_captured_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, all_captured_rb, 
      ("Print all packets captured"), NULL);
  gtk_container_add(GTK_CONTAINER(range_vb), all_captured_rb);
  /*gtk_widget_show(all_captured_rb);*/

  g_snprintf(label_text, sizeof(label_text), "All packets _displayed, %u packet(s)", displayed_count);
#if GTK_MAJOR_VERSION < 2
  all_displayed_rb = dlg_radio_button_new_with_label_with_mnemonic(
                gtk_radio_button_group(GTK_RADIO_BUTTON(all_captured_rb)),
				label_text, accel_group);
#else
  all_displayed_rb = gtk_radio_button_new_with_mnemonic_from_widget(
                    GTK_RADIO_BUTTON(all_captured_rb), label_text);
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(all_displayed_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, all_displayed_rb, 
      ("Print all packets currently displayed"), NULL);
  gtk_container_add(GTK_CONTAINER(range_vb), all_displayed_rb);
  gtk_widget_show(all_displayed_rb);

#if GTK_MAJOR_VERSION < 2
  selected_rb = dlg_radio_button_new_with_label_with_mnemonic(
                gtk_radio_button_group(GTK_RADIO_BUTTON(all_captured_rb)),
				"XXX: _Selected packet only", accel_group);
#else
  selected_rb = gtk_radio_button_new_with_mnemonic_from_widget(
                    GTK_RADIO_BUTTON(all_captured_rb), "XXX: _Selected packet only");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(selected_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, selected_rb, ("Print the currently selected packet only"), NULL);
  gtk_container_add(GTK_CONTAINER(range_vb), selected_rb);
  /*gtk_widget_show(selected_rb);*/

  g_snprintf(label_text, sizeof(label_text), "_Marked packets only, %u packet(s)", cfile.marked_count);
#if GTK_MAJOR_VERSION < 2
  marked_rb = dlg_radio_button_new_with_label_with_mnemonic(
                gtk_radio_button_group(GTK_RADIO_BUTTON(all_captured_rb)),
				label_text, accel_group);
#else
  marked_rb = gtk_radio_button_new_with_mnemonic_from_widget(
                    GTK_RADIO_BUTTON(all_captured_rb), label_text);
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(marked_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, marked_rb, ("Print marked packets only"), NULL);
  gtk_container_add(GTK_CONTAINER(range_vb), marked_rb);
  gtk_widget_set_sensitive(marked_rb, cfile.marked_count);
  gtk_widget_show(marked_rb);

#if GTK_MAJOR_VERSION < 2
  range_rb = dlg_radio_button_new_with_label_with_mnemonic(
                gtk_radio_button_group(GTK_RADIO_BUTTON(all_captured_rb)),
				"XXX: Packets f_rom X to Y", accel_group);
#else
  range_rb = gtk_radio_button_new_with_mnemonic_from_widget(
                    GTK_RADIO_BUTTON(all_captured_rb), "XXX: Packets f_rom X to Y");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(range_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, range_rb, ("Print packets from number X to Y only"), NULL);
  gtk_container_add(GTK_CONTAINER(range_vb), range_rb);
  /*gtk_widget_show(range_rb);*/


/*****************************************************/

  /*** packet format frame ***/
  packet_fr = gtk_frame_new("Packet Format");
  gtk_box_pack_start(GTK_BOX(main_vb), packet_fr, FALSE, FALSE, 0);
  gtk_widget_show(packet_fr);
  packet_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(packet_vb), 5);
  gtk_container_add(GTK_CONTAINER(packet_fr), packet_vb);
  gtk_widget_show(packet_vb);

  /* "Print detail" check buttons */
#if GTK_MAJOR_VERSION < 2
  details_cb = dlg_check_button_new_with_label_with_mnemonic("Print packet d_etails", 
                                                            accel_group);
#else
  details_cb = gtk_check_button_new_with_mnemonic("Print packet d_etails");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(details_cb), TRUE);
  SIGNAL_CONNECT(details_cb, "clicked", print_cmd_toggle_detail, NULL);
  gtk_tooltips_set_tip (tooltips, details_cb, ("Print packet details, or packet summary only"), NULL);
  gtk_container_add(GTK_CONTAINER(packet_vb), details_cb);
  gtk_widget_show(details_cb);


  /*** (inner) details frame ***/
  details_fr = gtk_frame_new("Details");
  gtk_box_pack_start(GTK_BOX(packet_vb), details_fr, FALSE, FALSE, 0);
  gtk_widget_show(details_fr);

  details_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(details_vb), 5);
  gtk_container_add(GTK_CONTAINER(details_fr), details_vb);
  gtk_widget_show(details_vb);

  /* "As displayed"/"All Expanded" radio buttons */
#if GTK_MAJOR_VERSION < 2
  collapse_all_rb = dlg_radio_button_new_with_label_with_mnemonic(NULL,
				    "XXX: All dissections co_llapsed", accel_group);
#else
  collapse_all_rb = gtk_radio_button_new_with_mnemonic(
                    NULL, "XXX: All dissections co_llapsed");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(collapse_all_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, collapse_all_rb, ("Print packet details tree \"collapsed\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), collapse_all_rb);
  /*gtk_widget_show(collapse_all_rb);*/

#if GTK_MAJOR_VERSION < 2
  as_displayed_rb = dlg_radio_button_new_with_label_with_mnemonic(
                    gtk_radio_button_group(GTK_RADIO_BUTTON(collapse_all_rb)),
				    "Dissections as displa_yed", accel_group);
#else
  as_displayed_rb = gtk_radio_button_new_with_mnemonic_from_widget(
                    GTK_RADIO_BUTTON(collapse_all_rb), "Dissections as displa_yed");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(as_displayed_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, as_displayed_rb, ("Print packet details tree \"as displayed\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), as_displayed_rb);
  gtk_widget_show(as_displayed_rb);

#if GTK_MAJOR_VERSION < 2
  expand_all_rb = dlg_radio_button_new_with_label_with_mnemonic(
                    gtk_radio_button_group(GTK_RADIO_BUTTON(collapse_all_rb)),
				    "All dissections e_xpanded", accel_group);
#else
  expand_all_rb = gtk_radio_button_new_with_mnemonic_from_widget(
                    GTK_RADIO_BUTTON(collapse_all_rb), "All dissections e_xpanded");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(expand_all_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, expand_all_rb, ("Print packet details tree \"expanded\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), expand_all_rb);
  gtk_widget_show(expand_all_rb);

  /* "Print hex" check button. */
#if GTK_MAJOR_VERSION < 2
  hex_cb = dlg_check_button_new_with_label_with_mnemonic("Packet _hex data",
                                                         accel_group);
#else
  hex_cb = gtk_check_button_new_with_mnemonic("Packet _hex data");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(hex_cb), FALSE);
  gtk_tooltips_set_tip (tooltips, hex_cb, ("Add hexdump of packet data"), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), hex_cb);
  gtk_widget_show(hex_cb);


  OBJECT_SET_DATA(details_cb, PRINT_DETAILS_FR_KEY, details_fr);
  OBJECT_SET_DATA(details_cb, PRINT_COLLAPSE_ALL_RB_KEY, collapse_all_rb);
  OBJECT_SET_DATA(details_cb, PRINT_AS_DISPLAYED_RB_KEY, as_displayed_rb);
  OBJECT_SET_DATA(details_cb, PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  OBJECT_SET_DATA(details_cb, PRINT_HEX_CB_KEY, hex_cb);

/*****************************************************/


  /* Button row: OK and Cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

#if GTK_MAJOR_VERSION < 2
  ok_bt = gtk_button_new_with_label ("OK");
#else
  ok_bt = gtk_button_new_from_stock(GTK_STOCK_OK);
#endif
  OBJECT_SET_DATA(ok_bt, PRINT_FORMAT_RB_KEY, format_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_DEST_CB_KEY, dest_cb);
#ifndef _WIN32
  OBJECT_SET_DATA(ok_bt, PRINT_CMD_TE_KEY, cmd_te);
#endif

  OBJECT_SET_DATA(ok_bt, PRINT_FILE_TE_KEY, file_te);
  OBJECT_SET_DATA(ok_bt, PRINT_DETAILS_CB_KEY, details_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_HEX_CB_KEY, hex_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_PRINT_ONLY_MARKED_RB_KEY, marked_rb);
  SIGNAL_CONNECT(ok_bt, "clicked", print_ok_cb, print_w);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_tooltips_set_tip (tooltips, ok_bt, ("Perform printing"), NULL);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

#if GTK_MAJOR_VERSION < 2
  cancel_bt = gtk_button_new_with_label ("Cancel");
#else
  cancel_bt = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
  SIGNAL_CONNECT(cancel_bt, "clicked", print_close_cb, print_w);
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_tooltips_set_tip (tooltips, cancel_bt, ("Cancel print and exit"), NULL);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Catch the "activate" signal on the "Command" and "File" text entries,
     so that if the user types Return there, we act as if the "OK" button
     had been selected, as happens if Return is typed if some widget
     that *doesn't* handle the Return key has the input focus. */

#ifndef _WIN32
  dlg_set_activate(cmd_te, ok_bt);
#endif
  dlg_set_activate(file_te, ok_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(print_w, cancel_bt);

  gtk_widget_show(print_w);
}

static void
print_cmd_toggle_dest(GtkWidget *widget, gpointer data _U_)
{
#ifndef _WIN32
  GtkWidget     *cmd_lb, *cmd_te;
#endif
  GtkWidget     *file_bt, *file_te;
  int            to_file;

#ifndef _WIN32
  cmd_lb = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_CMD_LB_KEY));
  cmd_te = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_CMD_TE_KEY));
#endif
  file_bt = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_FILE_BT_KEY));
  file_te = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_FILE_TE_KEY));
  if (GTK_TOGGLE_BUTTON (widget)->active) {
    /* They selected "Print to File" */
    to_file = TRUE;
  } else {
    /* They selected "Print to Command" on UNIX or "Print to Printer"
       on Windows */
    to_file = FALSE;
  }
#ifndef _WIN32
  gtk_widget_set_sensitive(cmd_lb, !to_file);
  gtk_widget_set_sensitive(cmd_te, !to_file);
#endif
  gtk_widget_set_sensitive(file_bt, to_file);
  gtk_widget_set_sensitive(file_te, to_file);
}

static void
print_cmd_toggle_detail(GtkWidget *widget, gpointer data _U_)
{
  GtkWidget     *collapse_all_rb, *expand_all_rb, *as_displayed_rb, *hex_cb, *details_fr;
  gboolean      print_detail;

  details_fr = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_DETAILS_FR_KEY));
  collapse_all_rb = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_COLLAPSE_ALL_RB_KEY));
  as_displayed_rb = GTK_WIDGET(OBJECT_GET_DATA(widget,
                                               PRINT_AS_DISPLAYED_RB_KEY));
  expand_all_rb = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_EXPAND_ALL_RB_KEY));
  hex_cb = GTK_WIDGET(OBJECT_GET_DATA(widget, PRINT_HEX_CB_KEY));

  if (GTK_TOGGLE_BUTTON (widget)->active) {
    /* They selected "Print detail" */
    print_detail = TRUE;
  } else {
    /* They selected "Print summary" */
    print_detail = FALSE;
  }

  gtk_widget_set_sensitive(details_fr, print_detail);
  gtk_widget_set_sensitive(collapse_all_rb, print_detail);
  gtk_widget_set_sensitive(as_displayed_rb, print_detail);
  gtk_widget_set_sensitive(expand_all_rb, print_detail);
  gtk_widget_set_sensitive(hex_cb, print_detail);
}

static void
print_file_cb(GtkWidget *file_bt, gpointer file_te)
{
  GtkWidget *caller = gtk_widget_get_toplevel(file_bt);
  GtkWidget *fs;

  /* Has a file selection dialog box already been opened for that top-level
     widget? */
  fs = OBJECT_GET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Just re-activate that dialog box. */
    reactivate_window(fs);
    return;
  }

  fs = file_selection_new ("Ethereal: Print to File");

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
  SIGNAL_CONNECT(fs, "destroy", GTK_SIGNAL_FUNC(print_fs_destroy_cb), file_te);

  SIGNAL_CONNECT(GTK_FILE_SELECTION(fs)->ok_button, "clicked", print_fs_ok_cb,
                 fs);

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(fs)->cancel_button, "clicked",
                 print_fs_cancel_cb, fs);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(fs, GTK_FILE_SELECTION(fs)->cancel_button);

  gtk_widget_show(fs);
}

static void
print_fs_ok_cb(GtkWidget *w _U_, gpointer data)
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
print_fs_cancel_cb(GtkWidget *w _U_, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
print_fs_destroy_cb(GtkWidget *win, GtkWidget* file_te)
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

#ifdef _WIN32

void setup_mswin_print( print_args_t *print_args) {

/*XXX should use temp file stuff in util routines */

    char *path1;

    path1 = tmpnam(NULL);

    print_args->dest = g_strdup(path1);
    print_args->to_file = TRUE;
}
#endif

static void
print_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  GtkWidget     *button;
  print_args_t  print_args;
  const gchar   *g_dest;
  gchar         *f_name;
  gchar         *dirname;
#ifdef _WIN32
  int win_printer_flag = FALSE;
#endif

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_DEST_CB_KEY);
  print_to_file = GTK_TOGGLE_BUTTON (button)->active;
  print_args.to_file = print_to_file;

  if (print_args.to_file) {
    g_dest = gtk_entry_get_text(GTK_ENTRY(OBJECT_GET_DATA(ok_bt,
                                                          PRINT_FILE_TE_KEY)));
    if (!g_dest[0]) {
      simple_dialog(ESD_TYPE_CRIT, NULL,
        "Printing to file, but no file specified.");
      return;
    }
    print_args.dest = g_strdup(g_dest);
    /* Save the directory name for future file dialogs. */
    f_name = g_strdup(g_dest);
    dirname = get_dirname(f_name);  /* Overwrites f_name */
    set_last_open_dir(dirname);
    g_free(f_name);
  } else {
#ifdef _WIN32
    win_printer_flag = TRUE;
    setup_mswin_print(&print_args);
#else
    print_args.dest = g_strdup(gtk_entry_get_text(GTK_ENTRY(OBJECT_GET_DATA(ok_bt,
      PRINT_CMD_TE_KEY))));
#endif
  }

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_FORMAT_RB_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    print_format = PR_FMT_PS;
  else
    print_format = PR_FMT_TEXT;
  print_args.format = print_format;

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_DETAILS_CB_KEY);
  print_args.print_summary = !(GTK_TOGGLE_BUTTON (button)->active);

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_HEX_CB_KEY);
  print_args.print_hex = GTK_TOGGLE_BUTTON (button)->active;

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY);
  print_args.expand_all = GTK_TOGGLE_BUTTON (button)->active;

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_PRINT_ONLY_MARKED_RB_KEY);
  print_args.print_only_marked = GTK_TOGGLE_BUTTON (button)->active;

  gtk_widget_destroy(GTK_WIDGET(parent_w));

  /* Now print the packets */
  if (!print_packets(&cfile, &print_args)) {
    if (print_args.to_file)
      simple_dialog(ESD_TYPE_WARN, NULL,
        file_write_error_message(errno), print_args.dest);
    else
      simple_dialog(ESD_TYPE_WARN, NULL, "Couldn't run print command %s.",
        print_args.dest);
  }

#ifdef _WIN32
  if (win_printer_flag) {
    print_mswin(print_args.dest);

    /* trash temp file */
    remove(print_args.dest);
  }
#endif

  g_free(print_args.dest);
}

static void
print_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
print_destroy_cb(GtkWidget *win, gpointer user_data _U_)
{
  GtkWidget *fs;

  /* Is there a file selection dialog associated with this
     Print File dialog? */
  fs = OBJECT_GET_DATA(win, E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Destroy it. */
    gtk_widget_destroy(fs);
  }

  /* Note that we no longer have a "Print" dialog box. */
  print_w = NULL;
}

/* Print a packet */
void
file_print_packet_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
  FILE *fh;
  print_args_t print_args;
#ifdef _WIN32
  int win_printer_flag = FALSE;
#endif

  switch (prefs.pr_dest) {

  case PR_DEST_CMD:
#ifdef _WIN32
    /* "PR_DEST_CMD" means "to printer" on Windows */
    win_printer_flag = TRUE;
    setup_mswin_print(&print_args);
    fh = fopen(print_args.dest, "w");
    print_args.to_file = TRUE;
    break;
#else
    fh = popen(prefs.pr_cmd, "w");
    print_args.to_file = FALSE;
    print_args.dest = prefs.pr_cmd;
    break;
#endif

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

  print_preamble(fh, prefs.pr_format);
  print_args.format = prefs.pr_format;
  print_args.print_summary = FALSE;
  print_args.print_hex = FALSE;
  print_args.expand_all = TRUE;
  print_args.print_only_marked = FALSE;
  proto_tree_print(&print_args, cfile.edt, fh);
  print_finale(fh, prefs.pr_format);
  close_print_dest(print_args.to_file, fh);

#ifdef _WIN32
  if (win_printer_flag) {
    print_mswin(print_args.dest);

    /* trash temp file */
    remove(print_args.dest);
    g_free(print_args.dest);
  }
#endif
}
