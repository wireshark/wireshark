/* print_dlg.c
 * Dialog boxes for printing
 *
 * $Id: print_dlg.c,v 1.54 2004/01/10 16:27:42 ulfl Exp $
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

#define PRINT_FORMAT_RB_KEY       "printer_format_radio_button"
#define PRINT_DEST_CB_KEY         "printer_destination_check_button"

#define PRINT_DETAILS_FR_KEY      "printer_details_frame"
#define PRINT_DETAILS_CB_KEY      "printer_details_check_button"
#define PRINT_HEX_CB_KEY          "printer_hex_check_button"
#define PRINT_COLLAPSE_ALL_RB_KEY "printer_collapse_all_radio_button"
#define PRINT_AS_DISPLAYED_RB_KEY "printer_as_displayed_radio_button"
#define PRINT_EXPAND_ALL_RB_KEY   "printer_expand_all_radio_button"

/* XXX - can we make these not be static? */
static packet_range_t range;
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

/*
 * Keep a static pointer to the current "Print" window, if any, so that if
 * somebody tries to do "File:Print" while there's already a "Print" window
 * up, we just pop up the existing one, rather than creating a new one.
 */
static GtkWidget *print_w;

static void
file_set_print_dynamics(void) {
  gboolean      filtered_active;
  gchar         label_text[100];
  gint          selected_num;


  filtered_active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(displayed_bt));

  gtk_widget_set_sensitive(displayed_bt, TRUE);

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

    file_set_print_dynamics();
  }
}

static void
toggle_filtered_cb(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process_filtered = TRUE;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(captured_bt), FALSE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(displayed_bt), TRUE);
    
    file_set_print_dynamics();
  }
}

static void
toggle_select_all(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_all;
    file_set_print_dynamics();
  }
}

static void
toggle_select_selected(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_selected;
    file_set_print_dynamics();
  }
}

static void
toggle_select_marked_only(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_marked;
    file_set_print_dynamics();
  }
}

static void
toggle_select_marked_range(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_marked_range;
    file_set_print_dynamics();
  }
}

static void
toggle_select_user_range(GtkWidget *widget, gpointer data _U_)
{
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range.process = range_process_user_range;
    file_set_print_dynamics();
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
  file_set_print_dynamics();
}

/*
 * Set the "Print only marked packets" toggle button as appropriate for
 * the current output file type and count of marked packets.
 *
 * Called when the "Print..." dialog box is created and when either
 * the file type or the marked count changes.
 */
void
file_set_print_marked_sensitive(void)
{
  if (print_w == NULL) {
    /* We don't currently have a "Print" dialog box up. */
    return;
  }
	
  /* We can request that only the marked packets be printed only if we
     if there *are* marked packets. */
  if (cfile.marked_count != 0) {
    gtk_widget_set_sensitive(select_marked_only_rb, TRUE);
    gtk_widget_set_sensitive(select_marked_range_rb, TRUE);	  
  }
  else {
    /* Force the "Process only marked packets" toggle to "false", turn
       off the flag it controls. */
    range.process = range_process_all;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_marked_only_rb), FALSE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_marked_range_rb), FALSE);	  
    gtk_widget_set_sensitive(select_marked_only_rb,  FALSE);
    gtk_widget_set_sensitive(select_marked_range_rb, FALSE);	  
  }
}


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

  GtkWidget     *range_fr, *range_tb;

  GtkWidget     *packet_fr, *packet_vb;
  GtkWidget     *details_cb, *details_fr, *details_vb;
  GtkWidget     *collapse_all_rb, *as_displayed_rb, *expand_all_rb,*hex_cb;

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

  /* "Plain text" / "Postscript" radio buttons */
  text_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "Plain _text", accel_group);
  if (print_format == PR_FMT_TEXT)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(text_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, text_rb, ("Print output in ascii \"plain text\" format"), NULL);
  gtk_box_pack_start(GTK_BOX(printer_vb), text_rb, FALSE, FALSE, 0);
  gtk_widget_show(text_rb);

  format_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(text_rb, "_PostScript", accel_group);
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
  dest_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Output to _File:", accel_group);
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

  /*** packet range frame ***/
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
  gtk_tooltips_set_tip (tooltips, select_all_rb, 
      ("Process all packets"), NULL);
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
  gtk_tooltips_set_tip (tooltips, select_curr_rb, ("Process the currently selected packet only"), NULL);
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
  gtk_tooltips_set_tip (tooltips, select_marked_only_rb, ("Process marked packets only"), NULL);
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
  details_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Print packet d_etails", accel_group);
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

  /* "All collapsed"/"As displayed"/"All Expanded" radio buttons */
  collapse_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "All dissections co_llapsed", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(collapse_all_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, collapse_all_rb, ("Print packet details tree \"collapsed\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), collapse_all_rb);
  gtk_widget_show(collapse_all_rb);

  as_displayed_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(collapse_all_rb, "Dissections as displa_yed", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(as_displayed_rb), TRUE);
  gtk_tooltips_set_tip (tooltips, as_displayed_rb, ("Print packet details tree \"as displayed\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), as_displayed_rb);
  gtk_widget_show(as_displayed_rb);

  expand_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(collapse_all_rb, "All dissections e_xpanded", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(expand_all_rb), FALSE);
  gtk_tooltips_set_tip (tooltips, expand_all_rb, ("Print packet details tree \"expanded\""), NULL);
  gtk_container_add(GTK_CONTAINER(details_vb), expand_all_rb);
  gtk_widget_show(expand_all_rb);

  /* "Print hex" check button. */
  hex_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Packet _hex data", accel_group);
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

  ok_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_OK);
  OBJECT_SET_DATA(ok_bt, PRINT_FORMAT_RB_KEY, format_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_DEST_CB_KEY, dest_cb);
#ifndef _WIN32
  OBJECT_SET_DATA(ok_bt, PRINT_CMD_TE_KEY, cmd_te);
#endif

  OBJECT_SET_DATA(ok_bt, PRINT_FILE_TE_KEY, file_te);
  OBJECT_SET_DATA(ok_bt, PRINT_DETAILS_CB_KEY, details_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_HEX_CB_KEY, hex_cb);
  OBJECT_SET_DATA(ok_bt, PRINT_AS_DISPLAYED_RB_KEY, as_displayed_rb);
  OBJECT_SET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY, expand_all_rb);
  SIGNAL_CONNECT(ok_bt, "clicked", print_ok_cb, print_w);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_tooltips_set_tip (tooltips, ok_bt, ("Perform printing"), NULL);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CANCEL);
  SIGNAL_CONNECT(cancel_bt, "clicked", print_close_cb, print_w);
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_tooltips_set_tip (tooltips, cancel_bt, ("Cancel print and exit dialog"), NULL);
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

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
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
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)))
    print_format = PR_FMT_PS;
  else
    print_format = PR_FMT_TEXT;
  print_args.format = print_format;

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_DETAILS_CB_KEY);
  print_args.print_summary = !gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_HEX_CB_KEY);
  print_args.print_hex = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button));

  print_args.print_dissections = print_dissections_collapsed;

  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_AS_DISPLAYED_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    print_args.print_dissections = print_dissections_as_displayed;
  }
  button = (GtkWidget *)OBJECT_GET_DATA(ok_bt, PRINT_EXPAND_ALL_RB_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button))) {
    print_args.print_dissections = print_dissections_expanded;
  }

  print_args.range = range;

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




