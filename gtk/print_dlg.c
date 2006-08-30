/* print_dlg.c
 * Dialog boxes for printing and exporting to text files
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

#include <string.h>

#include <gtk/gtk.h>

#include "globals.h"
#include "gtkglobals.h"
#include "keys.h"
#include "print.h"
#include <epan/prefs.h>
#include "alert_box.h"
#include "simple_dialog.h"
#include "capture_file_dlg.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "file_dlg.h"
#include "main.h"
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#ifdef _WIN32
#include "print_mswin.h"
#endif
#include "compat_macros.h"
#include "range_utils.h"
#include "help_dlg.h"
#include "file_util.h"
#include "tempfile.h"
#include "util.h"

#if GTK_MAJOR_VERSION >= 2 && _WIN32
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "win32-file-dlg.h"
#endif

/* dialog output action */
typedef enum {
  output_action_print,          /* print text to printer */
  output_action_export_text,    /* export to plain text */
  output_action_export_ps,      /* export to postscript */
  output_action_export_psml,    /* export to packet summary markup language */
  output_action_export_pdml,    /* export to packet data markup language */
  output_action_export_csv      /* export to csv file */
} output_action_e;


/* On Win32, a GUI application apparently can't use "popen()" (it
  "returns an invalid file handle, if used in a Windows program,
  that will cause the program to hang indefinitely"), so we can't
  use a pipe to a print command to print to a printer.

  Eventually, we should try to use the native Win32 printing API
  for this (and also use various UNIX printing APIs, when present?).
*/

static GtkWidget *
open_print_dialog(const char *title, output_action_e action, print_args_t *args);
static void print_cmd_toggle_dest(GtkWidget *widget, gpointer data);
static void print_cmd_toggle_detail(GtkWidget *widget, gpointer data);
static void print_ok_cb(GtkWidget *ok_bt, gpointer parent_w);
static void print_destroy_cb(GtkWidget *win, gpointer user_data);



#define PRINT_ARGS_KEY            "printer_args"

#define PRINT_PS_RB_KEY           "printer_ps_radio_button"
#define PRINT_PDML_RB_KEY         "printer_pdml_radio_button"
#define PRINT_PSML_RB_KEY         "printer_psml_radio_button"
#define PRINT_CSV_RB_KEY          "printer_csv_radio_button"
#define PRINT_DEST_CB_KEY         "printer_destination_check_button"

#define PRINT_SUMMARY_CB_KEY      "printer_summary_check_button"
#define PRINT_DETAILS_CB_KEY      "printer_details_check_button"
#define PRINT_COLLAPSE_ALL_RB_KEY "printer_collapse_all_radio_button"
#define PRINT_AS_DISPLAYED_RB_KEY "printer_as_displayed_radio_button"
#define PRINT_EXPAND_ALL_RB_KEY   "printer_expand_all_radio_button"
#define PRINT_HEX_CB_KEY          "printer_hex_check_button"
#define PRINT_FORMFEED_CB_KEY     "printer_formfeed_check_button"

#define PRINT_BT_KEY              "printer_button"

#define PRINT_TE_PTR_KEY          "printer_file_te_ptr"


/*
 * Keep a static pointer to the current "Print" window, if any, so that if
 * somebody tries to do "File:Print" while there's already a "Print" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *print_win = NULL;

static print_args_t  print_args;

static gboolean print_prefs_init = FALSE;


static void
file_print_cmd(gboolean print_selected)
{
  print_args_t *args = &print_args;

  if (print_win != NULL) {
    /* There's already a "Print" dialog box; reactivate it. */
    reactivate_window(print_win);
    return;
  }

  /* get settings from preferences (and other initial values) only once */
  if(print_prefs_init == FALSE) {
      print_prefs_init          = TRUE;
      args->format              = prefs.pr_format;
      args->to_file             = prefs.pr_dest;
      args->file                = g_strdup(prefs.pr_file);
      args->cmd                 = g_strdup(prefs.pr_cmd);
      args->print_summary       = TRUE;
      args->print_dissections   = print_dissections_as_displayed;
      args->print_hex           = FALSE;
      args->print_formfeed      = FALSE;
  }

  /* init the printing range */
  packet_range_init(&args->range);

  if(print_selected) {
      args->range.process = range_process_selected;
  }

  print_win = open_print_dialog("Wireshark: Print", output_action_print, args);
  SIGNAL_CONNECT(print_win, "destroy", print_destroy_cb, &print_win);
}

void
file_print_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    file_print_cmd(FALSE);
}

void
file_print_selected_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    file_print_cmd(TRUE);
}

/*
 * Keep a static pointer to the current "Export text" window, if any, so that if
 * somebody tries to do "File:Export to text" while there's already a "Export text" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *export_text_win = NULL;

static print_args_t  export_text_args;

static gboolean export_text_prefs_init = FALSE;


void
export_text_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
  print_args_t *args = &export_text_args;

#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_export_file(GDK_WINDOW_HWND(top_level->window), export_type_text);
  return;
#endif

  if (export_text_win != NULL) {
    /* There's already a "Export text" dialog box; reactivate it. */
    reactivate_window(export_text_win);
    return;
  }

  /* get settings from preferences (and other initial values) only once */
  if(export_text_prefs_init == FALSE) {
      export_text_prefs_init    = TRUE;
      args->format              = PR_FMT_TEXT;
      args->to_file             = TRUE;
      args->file                = g_strdup("");
      args->cmd                 = g_strdup("");
      args->print_summary       = TRUE;
      args->print_dissections   = print_dissections_as_displayed;
      args->print_hex           = FALSE;
      args->print_formfeed      = FALSE;
  }

  /* init the printing range */
  packet_range_init(&args->range);

  export_text_win = open_print_dialog("Wireshark: Export as \"Plain Text\" File", output_action_export_text, args);
  SIGNAL_CONNECT(export_text_win, "destroy", print_destroy_cb, &export_text_win);
}


/*
 * Keep a static pointer to the current "Export ps" window, if any, so that if
 * somebody tries to do "File:Export to ps" while there's already a "Export ps" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *export_ps_win = NULL;

static print_args_t  export_ps_args;

static gboolean export_ps_prefs_init = FALSE;


void
export_ps_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
  print_args_t *args = &export_ps_args;

#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_export_file(GDK_WINDOW_HWND(top_level->window), export_type_ps);
  return;
#endif

  if (export_ps_win != NULL) {
    /* There's already a "Export ps" dialog box; reactivate it. */
    reactivate_window(export_ps_win);
    return;
  }

  /* get settings from preferences (and other initial values) only once */
  if(export_ps_prefs_init == FALSE) {
      export_ps_prefs_init      = TRUE;
      args->format              = PR_FMT_PS;
      args->to_file             = TRUE;
      args->file                = g_strdup("");
      args->cmd                 = g_strdup("");
      args->print_summary       = TRUE;
      args->print_dissections   = print_dissections_as_displayed;
      args->print_hex           = FALSE;
      args->print_formfeed      = FALSE;
  }

  /* init the printing range */
  packet_range_init(&args->range);

  export_ps_win = open_print_dialog("Wireshark: Export as \"PostScript\" file", output_action_export_ps, args);
  SIGNAL_CONNECT(export_ps_win, "destroy", print_destroy_cb, &export_ps_win);
}


/*
 * Keep a static pointer to the current "Export psml" window, if any, so that if
 * somebody tries to do "File:Export to psml" while there's already a "Export psml" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *export_psml_win = NULL;

static print_args_t  export_psml_args;

static gboolean export_psml_prefs_init = FALSE;


void
export_psml_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
  print_args_t *args = &export_psml_args;

#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_export_file(GDK_WINDOW_HWND(top_level->window), export_type_psml);
  return;
#endif

  if (export_psml_win != NULL) {
    /* There's already a "Export psml" dialog box; reactivate it. */
    reactivate_window(export_psml_win);
    return;
  }

  /* get settings from preferences (and other initial values) only once */
  if(export_psml_prefs_init == FALSE) {
      export_psml_prefs_init    = TRUE;
      args->format              = PR_FMT_TEXT;	/* XXX */
      args->to_file             = TRUE;
      args->file                = g_strdup("");
      args->cmd                 = g_strdup("");
      args->print_summary       = TRUE;
      args->print_dissections   = print_dissections_as_displayed;
      args->print_hex           = FALSE;
      args->print_formfeed      = FALSE;
  }

  /* init the printing range */
  packet_range_init(&args->range);

  export_psml_win = open_print_dialog("Wireshark: Export as \"PSML\" file", output_action_export_psml, args);
  SIGNAL_CONNECT(export_psml_win, "destroy", print_destroy_cb, &export_psml_win);
}


/*
 * Keep a static pointer to the current "Export pdml" window, if any, so that if
 * somebody tries to do "File:Export to pdml" while there's already a "Export pdml" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *export_pdml_win = NULL;

static print_args_t  export_pdml_args;

static gboolean export_pdml_prefs_init = FALSE;


void
export_pdml_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
  print_args_t *args = &export_pdml_args;

#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_export_file(GDK_WINDOW_HWND(top_level->window), export_type_pdml);
  return;
#endif

  if (export_pdml_win != NULL) {
    /* There's already a "Export pdml" dialog box; reactivate it. */
    reactivate_window(export_pdml_win);
    return;
  }

  /* get settings from preferences (and other initial values) only once */
  if(export_pdml_prefs_init == FALSE) {
      export_pdml_prefs_init    = TRUE;
      args->format              = PR_FMT_TEXT;	/* XXX */
      args->to_file             = TRUE;
      args->file                = g_strdup("");
      args->cmd                 = g_strdup("");
      args->print_summary       = TRUE;
      args->print_dissections   = print_dissections_as_displayed;
      args->print_hex           = FALSE;
      args->print_formfeed      = FALSE;
  }

  /* init the printing range */
  packet_range_init(&args->range);

  export_pdml_win = open_print_dialog("Wireshark: Export as \"PDML\" file", output_action_export_pdml, args);
  SIGNAL_CONNECT(export_pdml_win, "destroy", print_destroy_cb, &export_pdml_win);
}

/*
 * Keep a static pointer to the current "Export csv" window, if any, so that if
 * somebody tries to do "File:Export to CSV" while there's already a "Export csv" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *export_csv_win = NULL;

static print_args_t  export_csv_args;

static gboolean export_csv_prefs_init = FALSE;

void
export_csv_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
  print_args_t *args = &export_csv_args;

#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_export_file(GDK_WINDOW_HWND(top_level->window), export_type_csv);
  return;
#endif

  if (export_csv_win != NULL) {
    /* There's already a "Export csv" dialog box; reactivate it. */
    reactivate_window(export_csv_win);
    return;
  }

  /* get settings from preferences (and other initial values) only once */
  if(export_csv_prefs_init == FALSE) {
      export_csv_prefs_init     = TRUE;
      args->format              = PR_FMT_TEXT; /* XXX */
      args->to_file             = TRUE;
      args->file                = g_strdup("");
      args->cmd                 = g_strdup("");
      args->print_summary       = FALSE;
      args->print_dissections   = print_dissections_none;
      args->print_hex           = FALSE;
      args->print_formfeed      = FALSE;
  }

  /* init the printing range */
  packet_range_init(&args->range);

  export_csv_win = open_print_dialog("Wireshark: Export as \"Comma Separated Values\" File", output_action_export_csv, args);
  SIGNAL_CONNECT(export_csv_win, "destroy", print_destroy_cb, &export_csv_win);
}

static void
print_browse_file_cb(GtkWidget *file_bt, GtkWidget *file_te)
{
    file_selection_browse(file_bt, file_te, "Wireshark: Print to File",
                          FILE_SELECTION_WRITE_BROWSE);
}



/* Open the print dialog */
static GtkWidget *
open_print_dialog(const char *title, output_action_e action, print_args_t *args)
{
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif

  GtkWidget     *main_win;
  GtkWidget     *main_vb;

  GtkWidget     *printer_fr, *printer_vb, *export_format_lb;
  GtkWidget     *text_rb, *ps_rb, *pdml_rb, *psml_rb, *csv_rb;
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

  GtkWidget     *bbox, *ok_bt, *cancel_bt, *help_bt;

  GtkTooltips   *tooltips;


  /* dialog window */
  main_win = dlg_window_new(title);

  /* Enable tooltips */
  tooltips = gtk_tooltips_new();

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(main_win), accel_group);
#endif

  /* Vertical enclosing container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(main_win), main_vb);
  gtk_widget_show(main_vb);

/*****************************************************/

  /*** printer frame ***/
  printer_fr = gtk_frame_new(action == output_action_print ? "Printer" : "Export to file:");
  gtk_box_pack_start(GTK_BOX(main_vb), printer_fr, FALSE, FALSE, 0);
  gtk_widget_show(printer_fr);
  printer_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(printer_vb), 5);
  gtk_container_add(GTK_CONTAINER(printer_fr), printer_vb);
  gtk_widget_show(printer_vb);

  /* "Plain text" / "Postscript" / "PDML", ... radio buttons */
  text_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "Plain _text", accel_group);
  if (args->format == PR_FMT_TEXT)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(text_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, text_rb, "Print output in ascii \"plain text\" format. If you're unsure, use this format.", NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), text_rb, FALSE, FALSE, 0);
  if(action == output_action_print)
    gtk_widget_show(text_rb);

  ps_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "_PostScript", accel_group);
  if (args->format == PR_FMT_PS)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ps_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, ps_rb, "Print output in \"postscript\" format, for postscript capable printers or print servers.", NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), ps_rb, FALSE, FALSE, 0);
  if(action == output_action_print)
    gtk_widget_show(ps_rb);

  pdml_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "PDM_L (XML: Packet Details Markup Language)", accel_group);
  if (action == output_action_export_pdml)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(pdml_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, pdml_rb,
      "Print output in \"PDML\" (Packet Details Markup Language), "
      "an XML based packet data interchange format. "
      "Usually used in combination with the \"Output to file\" option to export packet data into an XML file.", NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), pdml_rb, FALSE, FALSE, 0);
  /* gtk_widget_show(pdml_rb); */

  psml_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "PSML (XML: Packet Summary Markup Language)", accel_group);
  if (action == output_action_export_psml)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(psml_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, psml_rb,
      "Print output in \"PSML\" (Packet Summary Markup Language), "
      "an XML based packet summary interchange format. "
      "Usually used in combination with the \"Output to file\" option to export packet data into an XML file.", NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), psml_rb, FALSE, FALSE, 0);
  /* gtk_widget_show(psml_rb); */

  csv_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "_CSV", accel_group);
  if (action == output_action_export_csv)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(csv_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, csv_rb,
      "Print output in \"Comma Separated Values\" (CSV) format, "
      "a text format compatible with OpenOffice and Excel. "
      "One row for each packet, with its timestamp and size.", NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), csv_rb, FALSE, FALSE, 0);
  /* gtk_widget_show(csv_rb); */

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
  if (args->to_file)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(dest_cb), TRUE);
  gtk_tooltips_set_tip (tooltips, dest_cb, "Output to file instead of printer", NULL);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), dest_cb, 0, 1, 0, 1);
  if(action == output_action_print)
    gtk_widget_show(dest_cb);

  /* File text entry */
  file_te = gtk_entry_new();
  OBJECT_SET_DATA(dest_cb, PRINT_FILE_TE_KEY, file_te);
  gtk_tooltips_set_tip (tooltips, file_te, "Enter Output filename", NULL);
  gtk_entry_set_text(GTK_ENTRY(file_te), args->file);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), file_te, 1, 2, 0, 1);
  gtk_widget_set_sensitive(file_te, args->to_file);
  gtk_widget_show(file_te);
  if (args->to_file)
    gtk_widget_grab_focus(file_te);

  /* "Browse" button */
  file_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_BROWSE);
  OBJECT_SET_DATA(dest_cb, PRINT_FILE_BT_KEY, file_bt);
  OBJECT_SET_DATA(file_bt, PRINT_TE_PTR_KEY, file_te);
  gtk_tooltips_set_tip (tooltips, file_bt, "Browse output filename in filesystem", NULL);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), file_bt, 2, 3, 0, 1);
  gtk_widget_set_sensitive(file_bt, args->to_file);
  gtk_widget_show(file_bt);

  /* Command label and text entry */
#ifndef _WIN32
  cmd_lb = gtk_label_new("Print command:");
  OBJECT_SET_DATA(dest_cb, PRINT_CMD_LB_KEY, cmd_lb);
  gtk_misc_set_alignment(GTK_MISC(cmd_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), cmd_lb, 0, 1, 1, 2);
  gtk_widget_set_sensitive(cmd_lb, !args->to_file);
  if(action == output_action_print)
    gtk_widget_show(cmd_lb);

  cmd_te = gtk_entry_new();
  OBJECT_SET_DATA(dest_cb, PRINT_CMD_TE_KEY, cmd_te);
  gtk_tooltips_set_tip (tooltips, cmd_te, "Enter print command", NULL);
  gtk_entry_set_text(GTK_ENTRY(cmd_te), args->cmd);
  gtk_table_attach_defaults(GTK_TABLE(printer_tb), cmd_te, 1, 2, 1, 2);
  gtk_widget_set_sensitive(cmd_te, !args->to_file);
  if(action == output_action_print)
    gtk_widget_show(cmd_te);
#endif

  SIGNAL_CONNECT(dest_cb, "toggled", print_cmd_toggle_dest, NULL);
  SIGNAL_CONNECT(file_bt, "clicked", print_browse_file_cb, file_te);

  if(action == output_action_export_ps) {
    export_format_lb = gtk_label_new("(PostScript files can be easily converted to PDF files using ghostscript's ps2pdf)");
    gtk_box_pack_start(GTK_BOX(printer_vb), export_format_lb, FALSE, FALSE, 0);
    gtk_widget_show(export_format_lb);
  }

/*****************************************************/

  /*** hor box for range and format frames ***/
  packet_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), packet_hb);
  gtk_widget_show(packet_hb);

  /*** packet range frame ***/
  range_fr = gtk_frame_new("Packet Range");
  gtk_box_pack_start(GTK_BOX(packet_hb), range_fr, FALSE, FALSE, 0);
  gtk_widget_show(range_fr);

  range_tb = range_new(&args->range
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
  if(   action == output_action_print ||
        action == output_action_export_text ||
        action == output_action_export_ps)
    gtk_widget_show(format_fr);
  format_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(format_vb), 5);
  gtk_container_add(GTK_CONTAINER(format_fr), format_vb);
  gtk_widget_show(format_vb);

  /* "Print summary line" check button */
  summary_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Packet summary line", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(summary_cb), args->print_summary);
  SIGNAL_CONNECT(summary_cb, "clicked", print_cmd_toggle_detail, main_win);
  gtk_tooltips_set_tip (tooltips, summary_cb, "Output of a packet summary line, like in the packet list", NULL);
  gtk_container_add(GTK_CONTAINER(format_vb), summary_cb);
  gtk_widget_show(summary_cb);


  /* "Details" check button */
  details_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Packet details:", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(details_cb), args->print_dissections != print_dissections_none);
  SIGNAL_CONNECT(details_cb, "clicked", print_cmd_toggle_detail, main_win);
  gtk_tooltips_set_tip (tooltips, details_cb, "Output format of the selected packet details (protocol tree).", NULL);
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
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(collapse_all_rb), args->print_dissections == print_dissections_collapsed);
  gtk_tooltips_set_tip (tooltips, collapse_all_rb, "Output of the packet details tree \"collapsed\"", NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), collapse_all_rb);
  gtk_widget_show(collapse_all_rb);

  as_displayed_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(collapse_all_rb, "As displa_yed", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(as_displayed_rb), args->print_dissections == print_dissections_as_displayed);
  gtk_tooltips_set_tip (tooltips, as_displayed_rb, "Output of the packet details tree \"as displayed\"", NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), as_displayed_rb);
  gtk_widget_show(as_displayed_rb);

  expand_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(collapse_all_rb, "All e_xpanded", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(expand_all_rb), args->print_dissections == print_dissections_expanded);
  gtk_tooltips_set_tip (tooltips, expand_all_rb, "Output of the packet details tree \"expanded\"", NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), expand_all_rb);
  gtk_widget_show(expand_all_rb);

  /* "Print hex" check button. */
  hex_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Packet bytes", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(hex_cb), args->print_hex);
  SIGNAL_CONNECT(hex_cb, "clicked", print_cmd_toggle_detail, main_win);
  gtk_tooltips_set_tip (tooltips, hex_cb, "Add a hexdump of the packet data", NULL);
  gtk_container_add(GTK_CONTAINER(format_vb), hex_cb);
  gtk_widget_show(hex_cb);

  /* seperator */
  sep = gtk_hseparator_new();
  gtk_container_add(GTK_CONTAINER(format_vb), sep);
  gtk_widget_show(sep);

  /* "Each packet on a new page" check button. */
  formfeed_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Each packet on a new page", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(formfeed_cb), args->print_formfeed);
  gtk_tooltips_set_tip (tooltips, formfeed_cb, "When checked, a new page will be used for each packet. "
      "This is done by adding a formfeed (or similar) between the packet outputs.", NULL);
  gtk_container_add(GTK_CONTAINER(format_vb), formfeed_cb);
  gtk_widget_show(formfeed_cb);


  OBJECT_SET_DATA(main_win, PRINT_ARGS_KEY, args);
  OBJECT_SET_DATA(main_win, PRINT_SUMMARY_CB_KEY, summary_cb);
  OBJECT_SET_DATA(main_win, PRINT_DETAILS_CB_KEY, details_cb);
  OBJECT_SET_DATA(main_win, PRINT_COLLAPSE_ALL_RB_KEY, collapse_all_rb);
  OBJECT_SET_DATA(main_win, PRINT_AS_DISPLAYED_RB_KEY, as_displayed_rb);
  OBJECT_SET_DATA(main_win, PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  OBJECT_SET_DATA(main_win, PRINT_HEX_CB_KEY, hex_cb);

/*****************************************************/


  /* Button row */
  if(topic_available(HELP_PRINT_DIALOG)) {
    bbox = dlg_button_row_new(action == output_action_print ? GTK_STOCK_PRINT : GTK_STOCK_OK, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  } else {
    bbox = dlg_button_row_new(action == output_action_print ? GTK_STOCK_PRINT : GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
  }
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  ok_bt = OBJECT_GET_DATA(bbox, action == output_action_print ? GTK_STOCK_PRINT : GTK_STOCK_OK);

  OBJECT_SET_DATA(main_win, PRINT_BT_KEY, ok_bt);

  OBJECT_SET_DATA(ok_bt, PRINT_PS_RB_KEY, ps_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_PDML_RB_KEY, pdml_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_PSML_RB_KEY, psml_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_CSV_RB_KEY, csv_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_DEST_CB_KEY, dest_cb);
#ifndef _WIN32
  OBJECT_SET_DATA(ok_bt, PRINT_CMD_TE_KEY, cmd_te);
#endif

  OBJECT_SET_DATA(ok_bt, PRINT_ARGS_KEY, args);
  OBJECT_SET_DATA(ok_bt, PRINT_FILE_TE_KEY, file_te);
  OBJECT_SET_DATA(ok_bt, PRINT_SUMMARY_CB_KEY, summary_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_DETAILS_CB_KEY, details_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_COLLAPSE_ALL_RB_KEY, collapse_all_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_AS_DISPLAYED_RB_KEY, as_displayed_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_HEX_CB_KEY, hex_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_FORMFEED_CB_KEY, formfeed_cb);
  SIGNAL_CONNECT(ok_bt, "clicked", print_ok_cb, main_win);
  gtk_tooltips_set_tip (tooltips, ok_bt, "Start output", NULL);

  cancel_bt  = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  window_set_cancel_button(main_win, cancel_bt, window_cancel_button_cb);
  gtk_tooltips_set_tip (tooltips, cancel_bt, "Cancel and exit dialog", NULL);

  if(action == output_action_print) {
    if(topic_available(HELP_PRINT_DIALOG)) {
      help_bt  = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
      SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_PRINT_DIALOG);
    }
  } else {
#if GTK_MAJOR_VERSION >= 2 && _WIN32
    if(topic_available(HELP_EXPORT_FILE_WIN32_DIALOG)) {
      help_bt  = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
      SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_EXPORT_FILE_WIN32_DIALOG);
    }
#else
    if(topic_available(HELP_EXPORT_FILE_DIALOG)) {
      help_bt  = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
      SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_EXPORT_FILE_DIALOG);
    }
#endif
  }

  gtk_widget_grab_default(ok_bt);

  /* Catch the "activate" signal on the "Command" and "File" text entries,
     so that if the user types Return there, we act as if the "OK" button
     had been selected, as happens if Return is typed if some widget
     that *doesn't* handle the Return key has the input focus. */
#ifndef _WIN32
  dlg_set_activate(cmd_te, ok_bt);
#endif
  if(action != output_action_print)
    dlg_set_activate(file_te, ok_bt);

  SIGNAL_CONNECT(main_win, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_show(main_win);
  window_present(main_win);

  return main_win;
}


/* user changed "print to" destination */
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

  to_file = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));
#ifndef _WIN32
  gtk_widget_set_sensitive(cmd_lb, !to_file);
  gtk_widget_set_sensitive(cmd_te, !to_file);
#endif
  gtk_widget_set_sensitive(file_bt, to_file);
  gtk_widget_set_sensitive(file_te, to_file);
}


/* user changed "packet details" */
static void
print_cmd_toggle_detail(GtkWidget *widget _U_, gpointer data)
{
  GtkWidget     *print_bt, *summary_cb, *details_cb, *collapse_all_rb, *expand_all_rb, *as_displayed_rb, *hex_cb;
  gboolean      print_detail;


  print_bt = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_BT_KEY));
  summary_cb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_SUMMARY_CB_KEY));
  details_cb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_DETAILS_CB_KEY));
  collapse_all_rb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_COLLAPSE_ALL_RB_KEY));
  as_displayed_rb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_AS_DISPLAYED_RB_KEY));
  expand_all_rb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_EXPAND_ALL_RB_KEY));
  hex_cb = GTK_WIDGET(OBJECT_GET_DATA(data, PRINT_HEX_CB_KEY));

  /* is user disabled details, disable the corresponding buttons */
  print_detail = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (details_cb));
  gtk_widget_set_sensitive(collapse_all_rb, print_detail);
  gtk_widget_set_sensitive(as_displayed_rb, print_detail);
  gtk_widget_set_sensitive(expand_all_rb, print_detail);

  /* if user selected nothing to print at all, disable the "ok" button */
  gtk_widget_set_sensitive(print_bt,
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (summary_cb)) ||
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (details_cb)) ||
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hex_cb)));
}


static void
print_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  GtkWidget         *button;
  print_args_t      *args;
  const gchar       *g_dest;
  gchar             *f_name;
  gchar             *dirname;
  gboolean          export_as_pdml = FALSE, export_as_psml = FALSE;
  gboolean          export_as_csv = FALSE;
#ifdef _WIN32
  gboolean          win_printer = FALSE;
  int               tmp_fd;
  char              tmp_namebuf[128+1];    /* XXX - length was used elsewhere too, why? */
  char              *tmp_oldfile;
#endif
  cf_print_status_t status;

  args = (print_args_t *)OBJECT_GET_DATA(ok_bt, PRINT_ARGS_KEY);

  /* Check whether the range is valid. */
  if (!range_check_validity(&args->range)) {
    /* The range isn't valid; don't dismiss the print/export dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the error, try again. */
    return;
  }

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_DEST_CB_KEY);
  args->to_file = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  if (args->to_file) {
    g_dest = gtk_entry_get_text(GTK_ENTRY(OBJECT_GET_DATA(ok_bt,
                                                          PRINT_FILE_TE_KEY)));
    if (!g_dest[0]) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "Output to file, but no file specified.");
      return;
    }
    g_free(args->file);
    args->file = g_strdup(g_dest);
    /* Save the directory name for future file dialogs. */
    f_name = g_strdup(g_dest);
    dirname = get_dirname(f_name);  /* Overwrites f_name */
    set_last_open_dir(dirname);
    g_free(f_name);
  } else {
#ifdef _WIN32
    win_printer = TRUE;
    /* We currently don't have a function in util.h to create just a tempfile */
    /* name, so simply create a tempfile using the "official" function, */
    /* then delete this file again. After this, the name MUST be available. */
    /* */
    /* Don't use tmpnam() or such, as this will fail under some ACL */
    /* circumstances: http://bugs.wireshark.org/bugzilla/show_bug.cgi?id=358 */

    tmp_fd = create_tempfile(tmp_namebuf, sizeof(tmp_namebuf), "ethprint");
    if(tmp_fd == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Couldn't create a temporary file for printing.");
        return;
    }
    /* remember to restore these values later! */
    tmp_oldfile = args->file;
    args->file = g_strdup(tmp_namebuf);
    eth_unlink(args->file);
    args->to_file = TRUE;
#else
    g_free(args->cmd);
    args->cmd = g_strdup(gtk_entry_get_text(GTK_ENTRY(OBJECT_GET_DATA(ok_bt,
      PRINT_CMD_TE_KEY))));
#endif
  }

  args->format = PR_FMT_TEXT;
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_PS_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    args->format = PR_FMT_PS;
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_PDML_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    export_as_pdml = TRUE;
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_PSML_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    export_as_psml = TRUE;
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_CSV_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    export_as_csv = TRUE;

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_SUMMARY_CB_KEY);
  args->print_summary = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_COLLAPSE_ALL_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    args->print_dissections = print_dissections_collapsed;
  }
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_AS_DISPLAYED_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    args->print_dissections = print_dissections_as_displayed;
  }
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    args->print_dissections = print_dissections_expanded;
  }

  /* the details setting has priority over the radio buttons */
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_DETAILS_CB_KEY);
  if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    args->print_dissections = print_dissections_none;
  }

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_HEX_CB_KEY);
  args->print_hex = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_FORMFEED_CB_KEY);
  args->print_formfeed = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));


  window_destroy(GTK_WIDGET(parent_w));

  /* Now print/export the packets */
  if (export_as_pdml)
    status = cf_write_pdml_packets(&cfile, args);
  else if (export_as_psml)
    status = cf_write_psml_packets(&cfile, args);
  else if (export_as_csv)
    status = cf_write_csv_packets(&cfile, args);
  else {
    switch (args->format) {

    case PR_FMT_TEXT:
      if (args->to_file) {
        args->stream = print_stream_text_new(TRUE, args->file);
        if (args->stream == NULL) {
          open_failure_alert_box(args->file, errno, TRUE);
          return;
        }
      } else {
        args->stream = print_stream_text_new(FALSE, args->cmd);
        if (args->stream == NULL) {
          simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                        "Couldn't run print command %s.", args->cmd);
        }
      }
      break;

    case PR_FMT_PS:
      if (args->to_file) {
        args->stream = print_stream_ps_new(TRUE, args->file);
        if (args->stream == NULL) {
          open_failure_alert_box(args->file, errno, TRUE);
          return;
        }
      } else {
        args->stream = print_stream_ps_new(FALSE, args->cmd);
        if (args->stream == NULL) {
          simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                        "Couldn't run print command %s.", args->cmd);
        }
      }
      break;

    default:
      g_assert_not_reached();
      return;
    }
    status = cf_print_packets(&cfile, args);
  }
  switch (status) {

  case CF_PRINT_OK:
    break;

  case CF_PRINT_OPEN_ERROR:
    if (args->to_file)
      open_failure_alert_box(args->file, errno, TRUE);
    else
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't run print command %s.",
        args->cmd);
    break;

  case CF_PRINT_WRITE_ERROR:
    if (args->to_file)
      write_failure_alert_box(args->file, errno);
    else
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	"Error writing to print command: %s", strerror(errno));
    break;
  }

#ifdef _WIN32
  if (win_printer) {
    print_mswin(args->file);

    /* trash temp file */
    eth_remove(args->file);

    /* restore old settings */
    args->to_file = FALSE;
    args->file = tmp_oldfile;
  }
#endif
}

static void
print_destroy_cb(GtkWidget *win, gpointer user_data)
{
  GtkWidget     *fs;

  /* Is there a file selection dialog associated with this
     Print File dialog? */
  fs = OBJECT_GET_DATA(win, E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Destroy it. */
    window_destroy(fs);
  }

  /* Note that we no longer have a "Print" dialog box. */
  *((gpointer *) user_data) = NULL;
}
