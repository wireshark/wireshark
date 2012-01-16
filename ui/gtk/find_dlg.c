/* find_dlg.c
 * Routines for "find frame" window
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
# include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <gtk/gtk.h>

#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>
#include <epan/strutil.h>
#include <epan/prefs.h>

#include "../globals.h"
#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/main_statusbar.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/find_dlg.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/prefs_dlg.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/filter_autocomplete.h"
#include "ui/gtk/old-gtk-compat.h"

/* Capture callback data keys */
#define E_FIND_FILT_KEY       "find_filter_te"
#define E_FIND_BACKWARD_KEY   "find_backward"
#define E_FIND_HEXDATA_KEY    "find_hex"
#define E_FIND_STRINGDATA_KEY "find_string"
#define E_FIND_FILTERDATA_KEY "find_filter"
#define E_FIND_STRINGTYPE_KEY "find_string_type"
#define E_FIND_STRINGTYPE_LABEL_KEY "find_string_type_label"
#define E_CASE_SEARCH_KEY     "case_insensitive_search"
#define E_SOURCE_DATA_KEY     "packet_data_source"
#define E_SOURCE_DECODE_KEY   "decode_data_source"
#define E_SOURCE_SUMMARY_KEY  "summary_data_source"
#define E_FILT_TE_BUTTON_KEY  "find_filter_button"

static gboolean case_type = TRUE;
static gboolean summary_data = FALSE;
static gboolean decode_data = FALSE;
static gboolean packet_data = FALSE;

static void
find_filter_te_syntax_check_cb(GtkWidget *w, gpointer parent_w);

static void
find_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

static void
find_frame_close_cb(GtkWidget *close_bt, gpointer parent_w);

static void
find_frame_destroy_cb(GtkWidget *win, gpointer user_data);

static void
hex_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w);

static void
string_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w);

static void
filter_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w);

/*
 * Keep a static pointer to the current "Find Packet" window, if any, so
 * that if somebody tries to do "Find Packet" while there's already a
 * "Find Packet" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *find_frame_w;
static GtkWidget *filter_text_box;

/*
 * Save the presskey handlers to be able to dissable the auto-completion
 * feature for hex and string searches.
 */
static gulong te_presskey_handler_id;
static gulong win_presskey_handler_id;

void
find_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget     *main_vb, *main_find_hb, *main_options_hb,

                *find_type_frame, *find_type_vb,
                *find_type_hb, *find_type_lb, *hex_rb, *string_rb, *filter_rb,
                *filter_hb, *filter_bt,

                *direction_frame, *direction_vb,
                *up_rb, *down_rb,

                *data_frame, *data_vb,
                *packet_data_rb, *decode_data_rb, *summary_data_rb,

                *string_opt_frame, *string_opt_vb,
                *case_cb, *combo_lb, *combo_cb,

                *bbox, *ok_bt, *cancel_bt, *help_bt;


  /* No Apply button, but "OK" not only sets our text widget, it
     activates it (i.e., it causes us to do the search). */
  static construct_args_t args = {
  	"Wireshark: Search Filter",
  	FALSE,
  	TRUE,
    FALSE
  };

  if (find_frame_w != NULL) {
    /* There's already a "Find Packet" dialog box; reactivate it. */
    reactivate_window(find_frame_w);
    return;
  }

  find_frame_w = dlg_window_new("Wireshark: Find Packet");

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(find_frame_w), main_vb);
  gtk_widget_show(main_vb);


  /* */
  main_find_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), main_find_hb);
  gtk_widget_show(main_find_hb);


  /* find frame */
  find_type_frame = gtk_frame_new("Find");
  gtk_box_pack_start(GTK_BOX(main_find_hb), find_type_frame, TRUE, TRUE, 0);
  gtk_widget_show(find_type_frame);

  find_type_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(find_type_vb), 3);
  gtk_container_add(GTK_CONTAINER(find_type_frame), find_type_vb);
  gtk_widget_show(find_type_vb);

  /* find type row */
  find_type_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(find_type_vb), find_type_hb);
  gtk_widget_show(find_type_hb);

  find_type_lb = gtk_label_new("By:");
  gtk_box_pack_start(GTK_BOX(find_type_hb), find_type_lb, FALSE, FALSE, 0);
  gtk_widget_show(find_type_lb);

  /* Filter */
  filter_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL, "_Display filter");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(filter_rb), !cfile.hex && !cfile.string);
  gtk_box_pack_start(GTK_BOX(find_type_hb), filter_rb, FALSE, FALSE, 0);
  gtk_widget_set_tooltip_text(filter_rb, "Search for data by display filter syntax.\ne.g. ip.addr==10.1.1.1");
  gtk_widget_show(filter_rb);

  /* Hex */
  hex_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(filter_rb), "_Hex value");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hex_rb), cfile.hex);
  gtk_box_pack_start(GTK_BOX(find_type_hb), hex_rb, FALSE, FALSE, 0);
  gtk_widget_set_tooltip_text(hex_rb, "Search for data by hex string.\ne.g. fffffda5");
  gtk_widget_show(hex_rb);

  /* ASCII Search */
  string_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(filter_rb), "_String");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(string_rb), cfile.string);
  gtk_box_pack_start(GTK_BOX(find_type_hb), string_rb, FALSE, FALSE, 0);
  gtk_widget_set_tooltip_text(string_rb, "Search for data by string value.\ne.g. My String");
  gtk_widget_show(string_rb);

  /* Filter row */
  filter_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(find_type_vb), filter_hb, FALSE, FALSE, 0);
  gtk_widget_show(filter_hb);

  filter_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
  g_signal_connect(filter_bt, "clicked", G_CALLBACK(display_filter_construct_cb), &args);
  g_signal_connect(filter_bt, "destroy", G_CALLBACK(filter_button_destroy_cb), NULL);
  g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_BUTTON_KEY, filter_bt);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, TRUE, 0);
  gtk_widget_set_tooltip_text(filter_bt, "Click on the filter button to select a display filter,\nor enter your search criteria into the text box");
  gtk_widget_show(filter_bt);

  filter_text_box = gtk_entry_new();
  if (cfile.sfilter) gtk_entry_set_text(GTK_ENTRY(filter_text_box), cfile.sfilter);
  g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_text_box);
  g_object_set_data(G_OBJECT(find_frame_w), E_FILT_TE_PTR_KEY, filter_text_box);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_text_box, TRUE, TRUE, 0);
  g_signal_connect(filter_text_box, "changed", G_CALLBACK(find_filter_te_syntax_check_cb), find_frame_w);
  g_object_set_data(G_OBJECT(find_frame_w), E_FILT_AUTOCOMP_PTR_KEY, NULL);
  te_presskey_handler_id = g_signal_connect(filter_text_box, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
  win_presskey_handler_id = g_signal_connect(find_frame_w, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
  gtk_widget_show(filter_text_box);


  /* */
  main_options_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), main_options_hb);
  gtk_widget_show(main_options_hb);


  /* search in frame */
  data_frame = gtk_frame_new("Search In");
  gtk_box_pack_start(GTK_BOX(main_options_hb), data_frame, TRUE, TRUE, 0);
  gtk_widget_show(data_frame);

  /* search in row */
  data_vb = gtk_vbox_new(TRUE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(data_vb), 3);
  gtk_container_add(GTK_CONTAINER(data_frame), data_vb);
  gtk_widget_show(data_vb);

  /* Packet list */
  summary_data_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL, "Packet list");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(summary_data_rb), summary_data);
  gtk_box_pack_start(GTK_BOX(data_vb), summary_data_rb, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(summary_data_rb, "Search for string in the Info column of the packet summary (summary pane)");
  gtk_widget_show(summary_data_rb);

  /* Packet details */
  decode_data_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(summary_data_rb), "Packet details");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(decode_data_rb), decode_data);
  gtk_box_pack_start(GTK_BOX(data_vb), decode_data_rb, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(decode_data_rb, "Search for string among the decoded packet display labels (tree view pane)");
  gtk_widget_show(decode_data_rb);

  /* Packet bytes */
  packet_data_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(summary_data_rb), "Packet bytes");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(packet_data_rb), packet_data);
  gtk_box_pack_start(GTK_BOX(data_vb), packet_data_rb, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(packet_data_rb, "Search for string in the ASCII-converted packet data (hex view pane)");
  gtk_widget_show(packet_data_rb);

  /* string options frame */
  string_opt_frame = gtk_frame_new("String Options");
  gtk_box_pack_start(GTK_BOX(main_options_hb), string_opt_frame, TRUE, TRUE, 0);
  gtk_widget_show(string_opt_frame);

  string_opt_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(string_opt_frame), string_opt_vb);
  gtk_container_set_border_width(GTK_CONTAINER(string_opt_vb), 3);
  gtk_widget_show(string_opt_vb);

  case_cb = gtk_check_button_new_with_mnemonic("Case sensitive");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(case_cb), !case_type);
  gtk_container_add(GTK_CONTAINER(string_opt_vb), case_cb);
  gtk_widget_set_tooltip_text(case_cb, "Search by mixed upper/lower case?");
  gtk_widget_show(case_cb);

  combo_lb = gtk_label_new("Character set:");
  gtk_container_add(GTK_CONTAINER(string_opt_vb), combo_lb);
  gtk_misc_set_alignment(GTK_MISC(combo_lb), 0.0f, 0.5f);
  gtk_widget_show(combo_lb);

  /* Character Type Selection Dropdown Box
     These only apply to the string find option */
  /* Create Combo Box */

  combo_cb = gtk_combo_box_text_new();

  gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(combo_cb), "ASCII Unicode & Non-Unicode");
  gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(combo_cb), "ASCII Non-Unicode");
  gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(combo_cb), "ASCII Unicode");

  gtk_combo_box_set_active(GTK_COMBO_BOX(combo_cb),0);
  gtk_container_add(GTK_CONTAINER(string_opt_vb), combo_cb);

  gtk_widget_show(combo_cb);


  /* direction frame */
  direction_frame = gtk_frame_new("Direction");
  gtk_box_pack_start(GTK_BOX(main_options_hb), direction_frame, FALSE, FALSE, 0);
  gtk_widget_show(direction_frame);

  /* Direction row: Forward and reverse radio buttons */
  direction_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(direction_vb), 3);
  gtk_container_add(GTK_CONTAINER(direction_frame), direction_vb);
  gtk_widget_show(direction_vb);

  up_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL, "_Up");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(up_rb), cfile.dir == SD_BACKWARD);
  gtk_box_pack_start(GTK_BOX(direction_vb), up_rb, FALSE, FALSE, 0);
  gtk_widget_show(up_rb);

  down_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(up_rb), "_Down");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(down_rb), cfile.dir == SD_FORWARD);
  gtk_box_pack_start(GTK_BOX(direction_vb), down_rb, FALSE, FALSE, 0);
  gtk_widget_show(down_rb);


  /* Button row */
  bbox = dlg_button_row_new(GTK_STOCK_FIND, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_FIND);
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(find_frame_ok_cb), find_frame_w);

  cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  g_signal_connect(cancel_bt, "clicked", G_CALLBACK(find_frame_close_cb), find_frame_w);

  help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_FIND_DIALOG);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  g_object_set_data(G_OBJECT(find_frame_w), E_FIND_FILT_KEY, filter_text_box);
  g_object_set_data(G_OBJECT(find_frame_w), E_FIND_BACKWARD_KEY, up_rb);
  g_object_set_data(G_OBJECT(find_frame_w), E_FIND_FILTERDATA_KEY, filter_rb);
  g_object_set_data(G_OBJECT(find_frame_w), E_FIND_HEXDATA_KEY, hex_rb);
  g_object_set_data(G_OBJECT(find_frame_w), E_FIND_STRINGDATA_KEY, string_rb);
  g_object_set_data(G_OBJECT(find_frame_w), E_FIND_STRINGTYPE_LABEL_KEY, combo_lb);
  g_object_set_data(G_OBJECT(find_frame_w), E_FIND_STRINGTYPE_KEY, combo_cb);
  g_object_set_data(G_OBJECT(find_frame_w), E_CASE_SEARCH_KEY, case_cb);
  g_object_set_data(G_OBJECT(find_frame_w), E_SOURCE_DATA_KEY, packet_data_rb);
  g_object_set_data(G_OBJECT(find_frame_w), E_SOURCE_DECODE_KEY, decode_data_rb);
  g_object_set_data(G_OBJECT(find_frame_w), E_SOURCE_SUMMARY_KEY, summary_data_rb);
  g_object_set_data(G_OBJECT(find_frame_w), E_FILT_TE_BUTTON_KEY, filter_bt);

  /*
   * Now that we've attached the pointers, connect the signals - if
   * we do so before we've attached the pointers, the signals may
   * be delivered before the pointers are attached; the signal
   * handlers expect the pointers to be attached, and won't be happy.
   */
  g_signal_connect(hex_rb, "clicked", G_CALLBACK(hex_selected_cb), find_frame_w);
  g_signal_connect(string_rb, "clicked", G_CALLBACK(string_selected_cb), find_frame_w);
  g_signal_connect(filter_rb, "clicked", G_CALLBACK(filter_selected_cb), find_frame_w);

  string_selected_cb(NULL, find_frame_w);
  filter_selected_cb(NULL, find_frame_w);

  window_set_cancel_button(find_frame_w, cancel_bt, window_cancel_button_cb);

  gtk_widget_grab_default(ok_bt);

  /* Catch the "activate" signal on the filter text entry, so that
     if the user types Return there, we act as if the "OK" button
     had been selected, as happens if Return is typed if some widget
     that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(filter_text_box, ok_bt);

  /* Give the initial focus to the "Filter" entry box. */
  gtk_widget_grab_focus(filter_text_box);

  g_signal_connect(find_frame_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(find_frame_w, "destroy", G_CALLBACK(find_frame_destroy_cb), NULL);

  gtk_widget_show(find_frame_w);
  window_present(find_frame_w);
}

/* this function opens the find frame dialogue and sets the filter string */
void
find_frame_with_filter(char *filter)
{
	find_frame_cb(NULL, NULL);
	gtk_entry_set_text(GTK_ENTRY(filter_text_box), filter);
}

/*
 * Check the filter syntax based on the type of search we're doing.
 */
static void
find_filter_te_syntax_check_cb(GtkWidget *w, gpointer parent_w)
{
  const gchar     *strval;
  GtkWidget       *hex_rb, *string_rb;
  guint8          *bytes = NULL;
  size_t           nbytes;

  hex_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_HEXDATA_KEY);
  string_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_STRINGDATA_KEY);

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hex_rb))) {
    /*
     * Hex search - scan the search string to make sure it's valid hex.
     */
    strval = gtk_entry_get_text(GTK_ENTRY(w));
    if (strval == NULL) {
      /* XXX - can this happen? */
      colorize_filter_te_as_invalid(w);
    } else {
      bytes = convert_string_to_hex(strval, &nbytes);
      if (bytes == NULL)
        colorize_filter_te_as_invalid(w);
      else {
        g_free(bytes);
        colorize_filter_te_as_valid(w);
      }
    }
  } else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (string_rb))) {
    /*
     * String search.  Make sure the string isn't empty.
     */
    strval = gtk_entry_get_text(GTK_ENTRY(w));
    if (strval == NULL) {
      /* XXX - can this happen? */
      colorize_filter_te_as_invalid(w);
    } else {
      if (strcmp(strval, "") == 0)
        colorize_filter_te_as_invalid(w);
      else
        colorize_filter_te_as_valid(w);
    }
  } else {
    /*
     * Display filter search; check it with "filter_te_syntax_check_cb()".
     */
      filter_te_syntax_check_cb(w, NULL);
  }
}

/*
 *  This function will re-check the search text syntax.
 */
static void
hex_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w)
{
    GtkWidget   *filter_tb, *hex_rb;

    filter_tb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_FILT_TE_PTR_KEY);
    hex_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_HEXDATA_KEY);

    /* Disable AutoCompletion feature */
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hex_rb)) && g_signal_handler_is_connected(filter_tb, te_presskey_handler_id)) {
      g_signal_handler_disconnect(filter_tb, te_presskey_handler_id);
      g_signal_handler_disconnect(parent_w, win_presskey_handler_id);
    }

    /* Re-check the display filter. */
    find_filter_te_syntax_check_cb(filter_tb, parent_w);
    return;
}

/*
 *  This function will disable the string options until
 *  the string search is selected.
 */
static void
string_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w)
{
    GtkWidget   *string_rb, *packet_data_rb, *decode_data_rb, *summary_data_rb,
                *data_combo_lb, *data_combo_cb, *data_case_cb, *filter_tb;

    string_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_STRINGDATA_KEY);
    packet_data_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_SOURCE_DATA_KEY);
    decode_data_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_SOURCE_DECODE_KEY);
    summary_data_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_SOURCE_SUMMARY_KEY);

    data_combo_lb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_STRINGTYPE_LABEL_KEY);
    data_combo_cb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_STRINGTYPE_KEY);
    data_case_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CASE_SEARCH_KEY);
    filter_tb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_FILT_TE_PTR_KEY);

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(string_rb))) {
        gtk_widget_set_sensitive(GTK_WIDGET(packet_data_rb), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(decode_data_rb), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(summary_data_rb), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_combo_lb), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_combo_cb), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_case_cb), TRUE);

	/* Disable AutoCompletion feature */
	if(g_signal_handler_is_connected(filter_tb, te_presskey_handler_id)) {
	  g_signal_handler_disconnect(filter_tb, te_presskey_handler_id);
	  g_signal_handler_disconnect(parent_w, win_presskey_handler_id);
	}

    } else {
        gtk_widget_set_sensitive(GTK_WIDGET(packet_data_rb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(decode_data_rb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(summary_data_rb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_combo_lb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_combo_cb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_case_cb), FALSE);
    }
    /* Re-check the display filter. */
    find_filter_te_syntax_check_cb(filter_tb, parent_w);
    return;
}

/*
 *  This function will disable the filter button until
 *  the filter search is selected.
 */
static void
filter_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w)
{
    GtkWidget   *filter_bt, *filter_rb, *filter_te;

    filter_bt = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FILT_TE_BUTTON_KEY);
    filter_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_FILTERDATA_KEY);
    filter_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FILT_TE_PTR_KEY);

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(filter_rb)))
    {
        gtk_widget_set_sensitive(GTK_WIDGET(filter_bt), TRUE);
	/* Enable AutoCompletion feature */
	if(!g_signal_handler_is_connected(filter_te, te_presskey_handler_id)) {
	  te_presskey_handler_id = g_signal_connect(filter_te, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
	  win_presskey_handler_id = g_signal_connect(parent_w, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
	}
    }
    else
    {
        gtk_widget_set_sensitive(GTK_WIDGET(filter_bt), FALSE);
    }
    return;
}

static void
find_frame_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  GtkWidget       *filter_te, *up_rb, *hex_rb, *string_rb, *combo_cb,
                  *case_cb, *packet_data_rb, *decode_data_rb, *summary_data_rb;
  const gchar     *filter_text;
  search_charset_t scs_type = SCS_ASCII_AND_UNICODE;
  guint8          *bytes = NULL;
  size_t           nbytes = 0;
  char            *string = NULL;
  dfilter_t       *sfcode = NULL;
  gboolean         found_packet=FALSE;
  gboolean         hex_search;
  gboolean         string_search;
  int		   string_type;

  filter_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_FILT_KEY);
  up_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_BACKWARD_KEY);
  hex_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_HEXDATA_KEY);
  string_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_STRINGDATA_KEY);
  combo_cb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_FIND_STRINGTYPE_KEY);
  case_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CASE_SEARCH_KEY);
  packet_data_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_SOURCE_DATA_KEY);
  decode_data_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_SOURCE_DECODE_KEY);
  summary_data_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_SOURCE_SUMMARY_KEY);

  filter_text = gtk_entry_get_text(GTK_ENTRY(filter_te));

  /* Corresponds to the enum in file.c
   * Character set for text search.
   * typedef enum {
   *   SCS_ASCII_AND_UNICODE,
   *   SCS_ASCII,
   *   SCS_UNICODE
   *   / * add EBCDIC when it's implemented * /
   * } search_charset_t;
   */
  string_type = gtk_combo_box_get_active (GTK_COMBO_BOX(combo_cb));

  case_type     = !gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(case_cb));
  packet_data   =  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(packet_data_rb));
  decode_data   =  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(decode_data_rb));
  summary_data  =  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(summary_data_rb));
  hex_search    =  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hex_rb));
  string_search =  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (string_rb));
  /*
   * Process the search criterion.
   */
  if (hex_search) {
    /*
     * Hex search - scan the search string to make sure it's valid hex
     * and to find out how many bytes there are.
     */
    bytes = convert_string_to_hex(filter_text, &nbytes);
    if (bytes == NULL) {
      statusbar_push_temporary_msg("That's not a valid hex string.");
      return;
    }
  } else if (string_search) {
    /*
     * String search.
     * Make sure we're searching for something, first.
     */
    if (strcmp(filter_text, "") == 0) {
      statusbar_push_temporary_msg("You didn't specify any text for which to search.");
      return;
    }

    /*
     * We are - get the character set type.
     */
    if (string_type == SCS_ASCII_AND_UNICODE)
      scs_type = SCS_ASCII_AND_UNICODE;
    else if (string_type == SCS_ASCII)
      scs_type = SCS_ASCII;
    else if (string_type == SCS_UNICODE)
      scs_type = SCS_UNICODE;
    else {
      statusbar_push_temporary_msg("You didn't choose a valid character set.");
      return;
    }
    string = convert_string_case(filter_text, case_type);
  } else {
    /*
     * Display filter search - try to compile the filter.
     */
    if (!dfilter_compile(filter_text, &sfcode)) {
      /* The attempt failed; report an error. */
      bad_dfilter_alert_box(filter_text);
      return;
    }

    /* Was it empty? */
    if (sfcode == NULL) {
      /* Yes - complain. */
      statusbar_push_temporary_msg("That filter doesn't test anything.");
      return;
    }
  }

  /*
   * Remember the search parameters.
   */
  g_free(cfile.sfilter);
  cfile.sfilter = g_strdup(filter_text);
  cfile.dir          = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (up_rb)) ? SD_BACKWARD : SD_FORWARD;
  cfile.hex          = hex_search;
  cfile.string       = string_search;
  cfile.scs_type     = scs_type;
  cfile.case_type    = case_type;
  cfile.packet_data  = packet_data;
  cfile.decode_data  = decode_data;
  cfile.summary_data = summary_data;

  if (cfile.hex) {
    /* Hex value in packet data */
    found_packet = cf_find_packet_data(&cfile, bytes, nbytes, cfile.dir);
    g_free(bytes);
    if (!found_packet) {
      /* We didn't find a packet */
      statusbar_push_temporary_msg("No packet contained those bytes.");
      return;
    }
  } else if (cfile.string) {
    if (cfile.summary_data) {
      /* String in the Info column of the summary line */
      found_packet = cf_find_packet_summary_line(&cfile, string, cfile.dir);
      g_free(string);
      if (!found_packet) {
        statusbar_push_temporary_msg("No packet contained that string in its Info column.");
        return;
      }
    } else if (cfile.decode_data) {
      /* String in the protocol tree headings */
      found_packet = cf_find_packet_protocol_tree(&cfile, string, cfile.dir);
      g_free(string);
      if (!found_packet) {
        statusbar_push_temporary_msg("No packet contained that string in its dissected display.");
        return;
      }
    } else if (cfile.packet_data && string) {
      /* String in the ASCII-converted packet data */
      found_packet = cf_find_packet_data(&cfile, string, strlen(string), cfile.dir);
      g_free(string);
      if (!found_packet) {
        statusbar_push_temporary_msg("No packet contained that string in its ASCII-converted data.");
        return;
      }
    }
  } else {
    /* Search via display filter */
    found_packet = cf_find_packet_dfilter(&cfile, sfcode, cfile.dir);
    dfilter_free(sfcode);
    if (!found_packet) {
      statusbar_push_temporary_msg("No packet matched that filter.");
      g_free(bytes);
      return;
    }
  }
  window_destroy(GTK_WIDGET(parent_w));
}

static void
find_frame_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  window_destroy(GTK_WIDGET(parent_w));
}

static void
find_frame_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Find Packet" dialog box. */
  find_frame_w = NULL;
}

static void
find_previous_next(GtkWidget *w, gpointer d, search_direction dir)
{
  guint8    *bytes;
  size_t     nbytes;
  char      *string;
  dfilter_t *sfcode;

  if (cfile.sfilter) {
    cfile.dir = dir;
    if (cfile.hex) {
      bytes = convert_string_to_hex(cfile.sfilter, &nbytes);
      if (bytes == NULL) {
	/*
	 * XXX - this shouldn't happen, as we've already successfully
	 * translated the string once.
	 */
        return;
      }
      cf_find_packet_data(&cfile, bytes, nbytes, dir);
      g_free(bytes);
    } else if (cfile.string) {
      string = convert_string_case(cfile.sfilter, cfile.case_type);
      /* OK, what are we searching? */
      if (cfile.decode_data) {
        /* The text in the protocol tree */
        cf_find_packet_protocol_tree(&cfile, string, dir);
      } else if (cfile.summary_data) {
        /* The text in the summary line */
        cf_find_packet_summary_line(&cfile, string, dir);
      } else {
        /* The raw packet data */
        cf_find_packet_data(&cfile, string, strlen(string), dir);
      }
      g_free(string);
    } else {
      if (!dfilter_compile(cfile.sfilter, &sfcode)) {
	/*
	 * XXX - this shouldn't happen, as we've already successfully
	 * translated the string once.
	 */
        return;
      }
      if (sfcode == NULL) {
	/*
	 * XXX - this shouldn't happen, as we've already found that the
	 * string wasn't null.
	 */
        return;
      }
      cf_find_packet_dfilter(&cfile, sfcode, dir);
      dfilter_free(sfcode);
    }
  } else
     find_frame_cb(w, d);
}

void
find_next_cb(GtkWidget *w , gpointer d)
{
  find_previous_next(w, d, SD_FORWARD);
}

void
find_previous_cb(GtkWidget *w , gpointer d)
{
  find_previous_next(w, d, SD_BACKWARD);
}
