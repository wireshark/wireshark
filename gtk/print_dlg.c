/* print_dlg.c
 * Dialog boxes for printing
 *
 * $Id: print_dlg.c,v 1.70 2004/04/22 21:40:48 ulfl Exp $
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

#include <string.h>

#include <gtk/gtk.h>

#include "globals.h"
#include "keys.h"
#include "print.h"
#include "prefs.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "file_dlg.h"
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
#include "range_utils.h"


/* On Win32, a GUI application apparently can't use "popen()" (it
  "returns an invalid file handle, if used in a Windows program,
  that will cause the program to hang indefinitely"), so we can't
  use a pipe to a print command to print to a printer.

  Eventually, we should try to use the native Win32 printing API
  for this (and also use various UNIX printing APIs, when present?).
*/

static void print_cmd_toggle_dest(GtkWidget *widget, gpointer data);
static void print_cmd_toggle_detail(GtkWidget *widget, gpointer data);
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

#define PRINT_PS_RB_KEY           "printer_ps_radio_button"
#define PRINT_PDML_RB_KEY         "printer_pdml_radio_button"
#define PRINT_PSML_RB_KEY         "printer_psml_radio_button"
#define PRINT_DEST_CB_KEY         "printer_destination_check_button"

#define PRINT_SUMMARY_CB_KEY      "printer_summary_check_button"
#define PRINT_DETAILS_CB_KEY      "printer_details_check_button"
#define PRINT_COLLAPSE_ALL_RB_KEY "printer_collapse_all_radio_button"
#define PRINT_AS_DISPLAYED_RB_KEY "printer_as_displayed_radio_button"
#define PRINT_EXPAND_ALL_RB_KEY   "printer_expand_all_radio_button"
#define PRINT_HEX_CB_KEY          "printer_hex_check_button"
#define PRINT_FORMFEED_CB_KEY     "printer_formfeed_check_button"

#define PRINT_BT_KEY              "printer_button"

/*
 * Keep a static pointer to the current "Print" window, if any, so that if
 * somebody tries to do "File:Print" while there's already a "Print" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *print_w;

static packet_range_t range;



/* Print the capture */
void
file_print_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif

  GtkWidget     *main_vb;

  GtkWidget     *printer_fr, *printer_vb;
  GtkWidget     *text_rb, *ps_rb, *pdml_rb, *psml_rb;
  GtkWidget     *printer_tb, *dest_cb;
#ifndef _WIN32
  GtkWidget     *cmd_lb, *cmd_te;
#endif
  GtkWidget     *file_bt, *file_te;

  GtkWidget     *range_fr, *range_tb;

  GtkWidget     *packet_hb;

  GtkWidget     *format_fr, *format_vb;
  GtkWidget     *summary_cb;

  GtkWidget     *details_cb;
  GtkWidget     *details_hb, *details_vb;
  GtkWidget     *collapse_all_rb, *as_displayed_rb, *expand_all_rb;
  GtkWidget     *hex_cb;
  GtkWidget     *sep, *formfeed_cb;

  GtkWidget     *bbox, *ok_bt, *cancel_bt;

  GtkTooltips   *tooltips;


  if (print_w != NULL) {
    /* There's already a "Print" dialog box; reactivate it. */
    reactivate_window(print_w);
    return;
  }

  /* init the packet range */
  packet_range_init(&range);

  /* get settings from preferences only once */
  if(print_prefs_init == FALSE) {
      print_prefs_init  = TRUE;
      print_to_file     = prefs.pr_dest;
      print_format      = prefs.pr_format;
      print_cmd         = prefs.pr_cmd;
      print_file        = prefs.pr_file;
  }

  /* Enable tooltips */
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

  /* "Plain text" / "Postscript" / "PDML" radio buttons */
  text_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "Plain _text", accel_group);
  if (print_format == PR_FMT_TEXT)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(text_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, text_rb, ("Print output in ascii \"plain text\" format. If you're unsure, use this format."), NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), text_rb, FALSE, FALSE, 0);
  gtk_widget_show(text_rb);

  ps_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "_PostScript", accel_group);
  if (print_format == PR_FMT_PS)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ps_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, ps_rb, ("Print output in \"postscript\" format, for postscript capable printers or print servers."), NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), ps_rb, FALSE, FALSE, 0);
  gtk_widget_show(ps_rb);

  pdml_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "PDM_L (XML: Packet Details Markup Language)", accel_group);
  if (print_format == PR_FMT_PDML)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(pdml_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, pdml_rb, (
      "Print output in \"PDML\" (Packet Details Markup Language), "
      "an XML based packet data interchange format. "
      "Usually used in combination with the \"Output to file\" option to export packet data into an XML file."), NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), pdml_rb, FALSE, FALSE, 0);
  gtk_widget_show(pdml_rb);

  psml_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "PSML (XML: Packet Summary Markup Language)", accel_group);
  if (print_format == PR_FMT_PSML)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(psml_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, psml_rb, (
      "Print output in \"PSML\" (Packet Summary Markup Language), "
      "an XML based packet summary interchange format. "
      "Usually used in combination with the \"Output to file\" option to export packet data into an XML file."), NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), psml_rb, FALSE, FALSE, 0);
  gtk_widget_show(psml_rb);

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
  dest_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Output to _file:", accel_group);
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

  file_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_BROWSE);
  OBJECT_SET_DATA(dest_cb, PRINT_FILE_BT_KEY, file_bt);
  OBJECT_SET_DATA(file_bt, E_FILE_TE_PTR_KEY, file_te);
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
  SIGNAL_CONNECT(file_bt, "clicked", select_file_cb, "Ethereal: Print to File");


/*****************************************************/

  /*** hor box for range and format frames ***/
  packet_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), packet_hb);
  gtk_widget_show(packet_hb);

  /*** packet range frame ***/
  range_fr = gtk_frame_new("Packet Range");
  gtk_box_pack_start(GTK_BOX(packet_hb), range_fr, FALSE, FALSE, 0);
  gtk_widget_show(range_fr);

  range_tb = range_new(&range
#if GTK_MAJOR_VERSION < 2
  , accel_group
#endif
  );
  gtk_container_add(GTK_CONTAINER(range_fr), range_tb);
  gtk_widget_show(range_tb);

/*****************************************************/

  /*** packet format frame ***/
  format_fr = gtk_frame_new("Packet Format");
  gtk_box_pack_start(GTK_BOX(packet_hb), format_fr, TRUE, TRUE, 0);
  gtk_widget_show(format_fr);
  format_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(format_vb), 5);
  gtk_container_add(GTK_CONTAINER(format_fr), format_vb);
  gtk_widget_show(format_vb);

  /* "Print summary line" check button */
  summary_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Packet summary line", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(summary_cb), FALSE);
  SIGNAL_CONNECT(summary_cb, "clicked", print_cmd_toggle_detail, print_w);
  gtk_tooltips_set_tip (tooltips, summary_cb, ("Print a packet summary line, like in the packet list"), NULL);
  gtk_container_add(GTK_CONTAINER(format_vb), summary_cb);
  gtk_widget_show(summary_cb);


  /* "Details" check button */
  details_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Packet details:", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(details_cb), TRUE);
  SIGNAL_CONNECT(details_cb, "clicked", print_cmd_toggle_detail, print_w);
  gtk_tooltips_set_tip (tooltips, details_cb, ("Print the selected packet details (protocol tree)."), NULL);
  gtk_container_add(GTK_CONTAINER(format_vb), details_cb);
  gtk_widget_show(details_cb);

  /*** packet details ***/
  details_hb = gtk_hbox_new(FALSE, 6);
  gtk_container_border_width(GTK_CONTAINER(details_hb), 0);
  gtk_container_add(GTK_CONTAINER(format_vb), details_hb);
  gtk_widget_show(details_hb);

  details_vb = gtk_vbox_new(FALSE, 6);
  gtk_container_border_width(GTK_CONTAINER(details_vb), 0);
  gtk_container_add(GTK_CONTAINER(details_hb), details_vb);
  gtk_widget_show(details_vb);

  details_vb = gtk_vbox_new(FALSE, 6);
  gtk_container_border_width(GTK_CONTAINER(details_vb), 0);
  gtk_container_add(GTK_CONTAINER(details_hb), details_vb);
  gtk_widget_show(details_vb);

  /* "All collapsed"/"As displayed"/"All Expanded" radio buttons */
  collapse_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "All co_llapsed", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(collapse_all_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, collapse_all_rb, ("Print packet details tree \"collapsed\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), collapse_all_rb);
  gtk_widget_show(collapse_all_rb);

  as_displayed_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(collapse_all_rb, "As displa_yed", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(as_displayed_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, as_displayed_rb, ("Print packet details tree \"as displayed\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), as_displayed_rb);
  gtk_widget_show(as_displayed_rb);

  expand_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(collapse_all_rb, "All e_xpanded", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(expand_all_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, expand_all_rb, ("Print packet details tree \"expanded\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), expand_all_rb);
  gtk_widget_show(expand_all_rb);

  /* "Print hex" check button. */
  hex_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Packet bytes", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(hex_cb), FALSE);
  SIGNAL_CONNECT(hex_cb, "clicked", print_cmd_toggle_detail, print_w);
  gtk_tooltips_set_tip (tooltips, hex_cb, ("Add hexdump of packet data"), NULL);
  gtk_container_add(GTK_CONTAINER(format_vb), hex_cb);
  gtk_widget_show(hex_cb);

  /* seperator */
  sep = gtk_hseparator_new();
  gtk_container_add(GTK_CONTAINER(format_vb), sep);
  gtk_widget_show(sep);

  /* "Each packet on a new page" check button. */
  formfeed_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Each packet on a new page", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(formfeed_cb), FALSE);
  gtk_tooltips_set_tip (tooltips, formfeed_cb, ("When checked, a new page will be used for each packet printed. "
      "This is done by adding a formfeed (or similar) between the packet printouts."), NULL);
  gtk_container_add(GTK_CONTAINER(format_vb), formfeed_cb);
  gtk_widget_show(formfeed_cb);


  OBJECT_SET_DATA(print_w, PRINT_SUMMARY_CB_KEY, summary_cb);
  OBJECT_SET_DATA(print_w, PRINT_DETAILS_CB_KEY, details_cb);
  OBJECT_SET_DATA(print_w, PRINT_COLLAPSE_ALL_RB_KEY, collapse_all_rb);
  OBJECT_SET_DATA(print_w, PRINT_AS_DISPLAYED_RB_KEY, as_displayed_rb);
  OBJECT_SET_DATA(print_w, PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  OBJECT_SET_DATA(print_w, PRINT_HEX_CB_KEY, hex_cb);

/*****************************************************/


  /* Button row */
  bbox = dlg_button_row_new(GTK_STOCK_PRINT, GTK_STOCK_CANCEL, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_PRINT);

  OBJECT_SET_DATA(print_w, PRINT_BT_KEY, ok_bt);

  OBJECT_SET_DATA(ok_bt, PRINT_PS_RB_KEY, ps_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_PDML_RB_KEY, pdml_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_PSML_RB_KEY, psml_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_DEST_CB_KEY, dest_cb);
#ifndef _WIN32
  OBJECT_SET_DATA(ok_bt, PRINT_CMD_TE_KEY, cmd_te);
#endif

  OBJECT_SET_DATA(ok_bt, PRINT_FILE_TE_KEY, file_te);
  OBJECT_SET_DATA(ok_bt, PRINT_SUMMARY_CB_KEY, summary_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_DETAILS_CB_KEY, details_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_COLLAPSE_ALL_RB_KEY, collapse_all_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_AS_DISPLAYED_RB_KEY, as_displayed_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_HEX_CB_KEY, hex_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_FORMFEED_CB_KEY, formfeed_cb);
  SIGNAL_CONNECT(ok_bt, "clicked", print_ok_cb, print_w);
  gtk_widget_grab_default(ok_bt);

  cancel_bt  = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  SIGNAL_CONNECT(cancel_bt, "clicked", print_close_cb, print_w);
  gtk_tooltips_set_tip (tooltips, cancel_bt, ("Cancel print and exit dialog"), NULL);

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

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
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
print_cmd_toggle_detail(GtkWidget *widget _U_, gpointer data)
{
  GtkWidget     *print_bt, *summary_cb, *details_cb, *collapse_all_rb, *expand_all_rb, *as_displayed_rb, *hex_cb;
  gboolean      print_detail;


  print_bt = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_BT_KEY));
  summary_cb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_SUMMARY_CB_KEY));
  details_cb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_DETAILS_CB_KEY));
  collapse_all_rb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_COLLAPSE_ALL_RB_KEY));
  as_displayed_rb = GTK_WIDGET(OBJECT_GET_DATA(data,
                                               PRINT_AS_DISPLAYED_RB_KEY));
  expand_all_rb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_EXPAND_ALL_RB_KEY));
  hex_cb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_HEX_CB_KEY));

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (details_cb))) {
    /* They selected "Print detail" */
    print_detail = TRUE;
  } else {
    /* They selected "Print summary" */
    print_detail = FALSE;
  }

  gtk_widget_set_sensitive(collapse_all_rb, print_detail);
  gtk_widget_set_sensitive(as_displayed_rb, print_detail);
  gtk_widget_set_sensitive(expand_all_rb, print_detail);

  print_detail = 
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (summary_cb)) ||
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (details_cb)) ||
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hex_cb));

  gtk_widget_set_sensitive(print_bt, print_detail);
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
  print_to_file = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));
  print_args.to_file = print_to_file;

  if (print_args.to_file) {
    g_dest = gtk_entry_get_text(GTK_ENTRY(OBJECT_GET_DATA(ok_bt,
                                                          PRINT_FILE_TE_KEY)));
    if (!g_dest[0]) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
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

  print_format = PR_FMT_TEXT;
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_PS_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    print_format = PR_FMT_PS;
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_PDML_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    print_format = PR_FMT_PDML;
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_PSML_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    print_format = PR_FMT_PSML;
  print_args.format = print_format;

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_SUMMARY_CB_KEY);
  print_args.print_summary = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_COLLAPSE_ALL_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    print_args.print_dissections = print_dissections_collapsed;
  }
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_AS_DISPLAYED_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    print_args.print_dissections = print_dissections_as_displayed;
  }
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    print_args.print_dissections = print_dissections_expanded;
  }

  /* the details setting has priority over the radio buttons */
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_DETAILS_CB_KEY);
  if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    print_args.print_dissections = print_dissections_none;
  }

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_HEX_CB_KEY);
  print_args.print_hex = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_FORMFEED_CB_KEY);
  print_args.print_formfeed = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  print_args.range = range;

  gtk_widget_destroy(GTK_WIDGET(parent_w));

  /* Now print the packets */
  switch (print_packets(&cfile, &print_args)) {

  case PP_OK:
    break;

  case PP_OPEN_ERROR:
    if (print_args.to_file)
      open_failure_alert_box(print_args.dest, errno, TRUE);
    else
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't run print command %s.",
        print_args.dest);
    break;

  case PP_WRITE_ERROR:
    if (print_args.to_file)
      write_failure_alert_box(print_args.dest, errno);
    else
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	"Error writing to print command: %s", strerror(errno));
    break;
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




