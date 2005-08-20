/* range_utils.c
 * Packet range routines (save, print, ...) for GTK things
 *
 * $Id$
 *
 * Ulf Lamping <ulf.lamping@web.de>
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

#include "packet-range.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "simple_dialog.h"


#define RANGE_VALUES_KEY                "range_values"
#define RANGE_CAPTURED_BT_KEY           "range_captured_button"
#define RANGE_DISPLAYED_BT_KEY          "range_displayed_button"

#define RANGE_SELECT_ALL_C_KEY          "range_select_all_c_lb"
#define RANGE_SELECT_ALL_D_KEY          "range_select_all_d_lb"
#define RANGE_SELECT_CURR_KEY           "range_select_curr_rb"
#define RANGE_SELECT_CURR_C_KEY         "range_select_curr_c_lb"
#define RANGE_SELECT_CURR_D_KEY         "range_select_curr_d_lb"
#define RANGE_SELECT_MARKED_KEY         "range_select_marked_only_rb"
#define RANGE_SELECT_MARKED_C_KEY       "range_select_marked_only_c_lb"
#define RANGE_SELECT_MARKED_D_KEY       "range_select_marked_only_d_lb"
#define RANGE_SELECT_MARKED_RANGE_KEY   "range_select_marked_range_rb"
#define RANGE_SELECT_MARKED_RANGE_C_KEY "range_select_marked_range_c_lb"
#define RANGE_SELECT_MARKED_RANGE_D_KEY "range_select_marked_range_d_lb"
#define RANGE_SELECT_USER_KEY           "range_select_user_range_rb"
#define RANGE_SELECT_USER_C_KEY         "range_select_user_range_c_lb"
#define RANGE_SELECT_USER_D_KEY         "range_select_user_range_d_lb"
#define RANGE_SELECT_USER_ENTRY_KEY     "range_select_user_range_entry"

gboolean
range_check_validity(packet_range_t *range)
{
  switch (packet_range_check(range)) {

  case CVT_NO_ERROR:
    return TRUE;

  case CVT_SYNTAX_ERROR:
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "The specified range of packets isn't a valid range.");
    return FALSE;

  case CVT_NUMBER_TOO_BIG:
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "The specified range of packets has a packet number that's too large.");
    return FALSE;

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

/* update all "dynamic" things */
void
range_update_dynamics(gpointer data) {
  gboolean      filtered_active;
  gchar         label_text[100];
  gint          selected_num;
  GtkWidget     *bt;
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);

  
  bt = OBJECT_GET_DATA(data, RANGE_DISPLAYED_BT_KEY);
  filtered_active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(bt));

  gtk_widget_set_sensitive(bt, TRUE);

  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_ALL_C_KEY), !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", cfile.count);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_ALL_C_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_ALL_D_KEY), filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range->displayed_cnt);

  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_ALL_D_KEY)), label_text);

  selected_num = (cfile.current_frame) ? cfile.current_frame->num : 0;
  /* XXX: how to update the radio button label but keep the mnemonic? */
/*  g_snprintf(label_text, sizeof(label_text), "_Selected packet #%u only", selected_num);
  gtk_label_set_text(GTK_LABEL(GTK_BIN(select_curr_rb)->child), label_text);*/
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_CURR_KEY), selected_num);
  g_snprintf(label_text, sizeof(label_text), "%u", selected_num ? 1 : 0);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_CURR_C_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_CURR_C_KEY), selected_num && !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", selected_num ? 1 : 0);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_CURR_D_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_CURR_D_KEY), selected_num && filtered_active);

  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_KEY), cfile.marked_count > 0);
  g_snprintf(label_text, sizeof(label_text), "%u", cfile.marked_count);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_C_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_C_KEY), cfile.marked_count > 0 && !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range->displayed_marked_cnt);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_D_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_D_KEY), range->displayed_marked_cnt && filtered_active);

  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_KEY), range->mark_range_cnt);
  g_snprintf(label_text, sizeof(label_text), "%u", range->mark_range_cnt);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_C_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_C_KEY), range->mark_range_cnt && !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range->displayed_mark_range_cnt);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_D_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_D_KEY), range->displayed_mark_range_cnt && filtered_active);

  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_USER_KEY), TRUE);
  g_snprintf(label_text, sizeof(label_text), "%u", range->user_range_cnt);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_USER_C_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_USER_C_KEY), !filtered_active);
  g_snprintf(label_text, sizeof(label_text), "%u", range->displayed_user_range_cnt);
  gtk_label_set_text(GTK_LABEL(OBJECT_GET_DATA(data, RANGE_SELECT_USER_D_KEY)), label_text);
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_USER_D_KEY), filtered_active);
}


static void
toggle_captured_cb(GtkWidget *widget, gpointer data)
{
  GtkWidget *bt;
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);

  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    /* They changed the state of the "captured" button. */
    range->process_filtered = FALSE;

    bt = OBJECT_GET_DATA(data, RANGE_CAPTURED_BT_KEY);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(bt), TRUE);
    bt = OBJECT_GET_DATA(data, RANGE_DISPLAYED_BT_KEY);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(bt), FALSE);

    range_update_dynamics(data);
  }
}

static void
toggle_filtered_cb(GtkWidget *widget, gpointer data)
{
  GtkWidget *bt;
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);
  
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range->process_filtered = TRUE;
    bt = OBJECT_GET_DATA(data, RANGE_CAPTURED_BT_KEY);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(bt), FALSE);
    bt = OBJECT_GET_DATA(data, RANGE_DISPLAYED_BT_KEY);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(bt), TRUE);
    
    range_update_dynamics(data);
  }
}

static void
toggle_select_all(GtkWidget *widget, gpointer data)
{
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);
  
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range->process = range_process_all;
    range_update_dynamics(data);
  }
}

static void
toggle_select_selected(GtkWidget *widget, gpointer data)
{
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);
  
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range->process = range_process_selected;
    range_update_dynamics(data);
  }
}

static void
toggle_select_marked_only(GtkWidget *widget, gpointer data)
{
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);
  
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range->process = range_process_marked;
    range_update_dynamics(data);
  }
}

static void
toggle_select_marked_range(GtkWidget *widget, gpointer data)
{
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);
  
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range->process = range_process_marked_range;
    range_update_dynamics(data);
  }
}

static void
toggle_select_user_range(GtkWidget *widget, gpointer data)
{
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);
  
  /* is the button now active? */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))) {
    range->process = range_process_user_range;
    range_update_dynamics(data);
  }
	
  /* Make the entry widget sensitive or insensitive */
  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_USER_ENTRY_KEY), range->process == range_process_user_range);

  /* When selecting user specified range, then focus on the entry */
  if (range->process == range_process_user_range)
      gtk_widget_grab_focus(OBJECT_GET_DATA(data, RANGE_SELECT_USER_ENTRY_KEY));

}


static void
range_entry(GtkWidget *widget _U_, gpointer data)
{
  const gchar   *entry_text;
  GtkWidget     *entry;
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);  
  entry = OBJECT_GET_DATA(data, RANGE_SELECT_USER_ENTRY_KEY);

  gtk_toggle_button_set_active(OBJECT_GET_DATA(data, RANGE_SELECT_USER_KEY), TRUE);
  entry_text = gtk_entry_get_text (GTK_ENTRY (entry));
  packet_range_convert_str(range, entry_text);
  range_update_dynamics(data);
}


static void
range_entry_in_event(GtkWidget *widget, GdkEventFocus *event _U_, gpointer user_data)
{
    range_entry(widget, user_data);
}


/* set the "Process only marked packets" toggle button as appropriate */
void
range_set_marked_sensitive(gpointer data, gboolean marked_valid)
{
  packet_range_t *range;


  range = OBJECT_GET_DATA(data, RANGE_VALUES_KEY);  

  /* We can request that only the marked packets be processed only if we
     if there *are* marked packets. */
  if (marked_valid) {
    gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_KEY), TRUE);
    gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_KEY), TRUE);	  
  }
  else {
    /* Force the "Process only marked packets" toggle to "false", turn
       off the flag it controls. */
    range->process = range_process_all;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_KEY)), FALSE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_KEY)), FALSE);	  
    gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_KEY),  FALSE);
    gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_SELECT_MARKED_RANGE_KEY), FALSE);	  
  }
}


/* set the "displayed" button as appropriate */
void
range_set_displayed_sensitive(gpointer data, gboolean displayed_valid)
{

  gtk_widget_set_sensitive(OBJECT_GET_DATA(data, RANGE_DISPLAYED_BT_KEY), displayed_valid);
}


/* create a new range "widget" */
GtkWidget *range_new(packet_range_t *range
#if GTK_MAJOR_VERSION < 2
, GtkAccelGroup *accel_group
#endif
) {
  GtkWidget     *range_tb;
  GtkWidget     *captured_bt;
  GtkWidget     *displayed_bt;

  GtkWidget     *select_all_rb;
  GtkWidget     *select_all_c_lb;
  GtkWidget     *select_all_d_lb;
  GtkWidget     *select_curr_rb;
  GtkWidget     *select_curr_c_lb;
  GtkWidget     *select_curr_d_lb;
  GtkWidget     *select_marked_only_rb;
  GtkWidget     *select_marked_only_c_lb;
  GtkWidget     *select_marked_only_d_lb;
  GtkWidget     *select_marked_range_rb;
  GtkWidget     *select_marked_range_c_lb;
  GtkWidget     *select_marked_range_d_lb;
  GtkWidget     *select_user_range_rb;
  GtkWidget     *select_user_range_c_lb;
  GtkWidget     *select_user_range_d_lb;
  GtkWidget     *select_user_range_entry;
 
  GtkTooltips   *tooltips;


  /* Enable tooltips */
  tooltips = gtk_tooltips_new();

  /* range table */
  range_tb = gtk_table_new(7, 3, FALSE);
  gtk_container_border_width(GTK_CONTAINER(range_tb), 5);

  /* captured button */
  captured_bt = TOGGLE_BUTTON_NEW_WITH_MNEMONIC("_Captured", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), captured_bt, 1, 2, 0, 1);
  SIGNAL_CONNECT(captured_bt, "toggled", toggle_captured_cb, range_tb);
  gtk_tooltips_set_tip (tooltips,captured_bt,("Process all the below chosen packets"), NULL);

  /* displayed button */
  displayed_bt = TOGGLE_BUTTON_NEW_WITH_MNEMONIC("_Displayed", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), displayed_bt, 2, 3, 0, 1);
  SIGNAL_CONNECT(displayed_bt, "toggled", toggle_filtered_cb, range_tb);
  gtk_tooltips_set_tip (tooltips,displayed_bt,("Process only the below chosen packets, which also passes the current display filter"), NULL);


  /* Process all packets */
  select_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "_All packets", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_all_rb, 0, 1, 1, 2);
  gtk_tooltips_set_tip (tooltips, select_all_rb, 
      ("Process all packets"), NULL);
  SIGNAL_CONNECT(select_all_rb, "toggled", toggle_select_all, range_tb);

  select_all_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_all_c_lb, 1, 2, 1, 2);
  select_all_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_all_d_lb, 2, 3, 1, 2);


  /* Process currently selected */
  select_curr_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "_Selected packet only", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_curr_rb, 0, 1, 2, 3);
  gtk_tooltips_set_tip (tooltips, select_curr_rb, ("Process the currently selected packet only"), NULL);
  SIGNAL_CONNECT(select_curr_rb, "toggled", toggle_select_selected, range_tb);

  select_curr_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_curr_c_lb, 1, 2, 2, 3);
  select_curr_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_curr_d_lb, 2, 3, 2, 3);


  /* Process marked packets */
  select_marked_only_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "_Marked packets only", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_only_rb, 0, 1, 3, 4);
  gtk_tooltips_set_tip (tooltips, select_marked_only_rb, ("Process marked packets only"), NULL);
  SIGNAL_CONNECT(select_marked_only_rb, "toggled", toggle_select_marked_only, range_tb);

  select_marked_only_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_only_c_lb, 1, 2, 3, 4);
  select_marked_only_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_only_d_lb, 2, 3, 3, 4);


  /* Process packet range between first and last packet */
  select_marked_range_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "From first _to last marked packet", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_range_rb, 0, 1, 4, 5);
  gtk_tooltips_set_tip (tooltips,select_marked_range_rb,("Process all packets between the first and last marker"), NULL);
  SIGNAL_CONNECT(select_marked_range_rb, "toggled", toggle_select_marked_range, range_tb);

  select_marked_range_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_range_c_lb, 1, 2, 4, 5);
  select_marked_range_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_marked_range_d_lb, 2, 3, 4, 5);


  /* Process a user specified provided packet range : -10,30,40-70,80- */
  select_user_range_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "Specify a packet _range:", accel_group);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_rb, 0, 1, 5, 6);
  gtk_tooltips_set_tip (tooltips,select_user_range_rb,("Process a specified packet range"), NULL);
  SIGNAL_CONNECT(select_user_range_rb, "toggled", toggle_select_user_range, range_tb);

  select_user_range_c_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_c_lb, 1, 2, 5, 6);
  select_user_range_d_lb = gtk_label_new("?");
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_d_lb, 2, 3, 5, 6);


  /* The entry part */
  select_user_range_entry = gtk_entry_new();
  gtk_entry_set_max_length (GTK_ENTRY (select_user_range_entry), 254);
  gtk_table_attach_defaults(GTK_TABLE(range_tb), select_user_range_entry, 0, 1, 6, 7);
  gtk_tooltips_set_tip (tooltips,select_user_range_entry, 
	("Specify a range of packet numbers :     \nExample :  1-10,18,25-100,332-"), NULL);
  SIGNAL_CONNECT(select_user_range_entry,"changed", range_entry, range_tb);
  SIGNAL_CONNECT(select_user_range_entry,"activate", range_entry_in_event, range_tb);


  gtk_widget_show_all(range_tb);


  OBJECT_SET_DATA(range_tb, RANGE_VALUES_KEY,               range);
  OBJECT_SET_DATA(range_tb, RANGE_CAPTURED_BT_KEY,          captured_bt);
  OBJECT_SET_DATA(range_tb, RANGE_DISPLAYED_BT_KEY,         displayed_bt);

  OBJECT_SET_DATA(range_tb, RANGE_SELECT_ALL_C_KEY,         select_all_c_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_ALL_D_KEY,         select_all_d_lb);

  OBJECT_SET_DATA(range_tb, RANGE_SELECT_CURR_KEY,          select_curr_rb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_CURR_C_KEY,        select_curr_c_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_CURR_D_KEY,        select_curr_d_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_CURR_D_KEY,        select_curr_d_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_MARKED_KEY,        select_marked_only_rb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_MARKED_C_KEY,      select_marked_only_c_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_MARKED_D_KEY,      select_marked_only_d_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_MARKED_RANGE_KEY,  select_marked_range_rb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_MARKED_RANGE_C_KEY,select_marked_range_c_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_MARKED_RANGE_D_KEY,select_marked_range_d_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_USER_KEY,          select_user_range_rb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_USER_C_KEY,        select_user_range_c_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_USER_D_KEY,        select_user_range_d_lb);
  OBJECT_SET_DATA(range_tb, RANGE_SELECT_USER_ENTRY_KEY,    select_user_range_entry);

  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(captured_bt), !range->process_filtered);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(displayed_bt), range->process_filtered);

  switch(range->process) {
  case(range_process_all):
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_all_rb),  TRUE);
    break;
  case(range_process_selected):
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_curr_rb),  TRUE);
    break;
  case(range_process_marked):
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_marked_only_rb),  TRUE);
    break;
  case(range_process_marked_range):
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_marked_range_rb),  TRUE);
    break;
  case(range_process_user_range):
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_user_range_rb),  TRUE);
    break;
  default:
      g_assert_not_reached();
  }

  return range_tb;
}
