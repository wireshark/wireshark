/* find_dlg.c
 * Routines for "find frame" window
 *
 * $Id: find_dlg.c,v 1.31 2003/08/11 22:41:10 sharpe Exp $
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
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>
#include "globals.h"

#include "ui_util.h"
#include "find_dlg.h"
#include "filter_prefs.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "prefs.h"
#include "prefs_dlg.h"
#include "keys.h"

/* Capture callback data keys */
#define E_FIND_FILT_KEY     "find_filter_te"
#define E_FIND_BACKWARD_KEY "find_backward"
#define E_FIND_HEXDATA_KEY "find_hex"
#define E_FIND_ASCIIDATA_KEY "find_ascii"
#define E_FIND_FILTERDATA_KEY "find_filter"
#define E_FIND_STRINGTYPE_KEY "find_string_type"
#define E_CASE_SEARCH_KEY "case_insensitive_search"
#define E_SOURCE_HEX_KEY "hex_data_source"
#define E_SOURCE_DECODE_KEY "decode_data_source"
#define E_SOURCE_SUMMARY_KEY "summary_data_source"

static gboolean case_type = TRUE;
static gboolean summary_data = FALSE;
static gboolean decode_data = FALSE;

static void
find_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

static void
find_frame_close_cb(GtkWidget *close_bt, gpointer parent_w);

static void
find_frame_destroy_cb(GtkWidget *win, gpointer user_data);

static void
ascii_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w);

/*
 * Keep a static pointer to the current "Find Frame" window, if any, so
 * that if somebody tries to do "Find Frame" while there's already a
 * "Find Frame" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *find_frame_w;

void
find_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget     *main_vb, *filter_hb, *filter_bt, *filter_te,
                *direction_hb, *forward_rb, *backward_rb, 
                *hex_hb, *hex_rb, *ascii_rb, *filter_rb,
                *data_hb, *hex_data_rb, *decode_data_rb, *summary_data_rb,
                *combo_hb, *combo_cb, *combo_lb,
                *bbox, *ok_bt, *cancel_bt, *case_cb;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
  GList *glist = NULL;
  /* No Apply button, but "OK" not only sets our text widget, it
     activates it (i.e., it causes us to do the search). */
  static construct_args_t args = {
  	"Ethereal: Search Filter",
  	FALSE,
  	TRUE
  };

  if (find_frame_w != NULL) {
    /* There's already a "Find Frame" dialog box; reactivate it. */
    reactivate_window(find_frame_w);
    return;
  }

  find_frame_w = dlg_window_new("Ethereal: Find Frame");
  SIGNAL_CONNECT(find_frame_w, "destroy", find_frame_destroy_cb, NULL);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(find_frame_w), accel_group);
#endif

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(find_frame_w), main_vb);
  gtk_widget_show(main_vb);

  /* Filter row */
  filter_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), filter_hb);
  gtk_widget_show(filter_hb);

  filter_bt = gtk_button_new_with_label("Filter:");
  SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
  SIGNAL_CONNECT(filter_bt, "destroy", filter_button_destroy_cb, NULL);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);

  filter_te = gtk_entry_new();
  if (cfile.sfilter) gtk_entry_set_text(GTK_ENTRY(filter_te), cfile.sfilter);
  OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_te, TRUE, TRUE, 0);
  gtk_widget_show(filter_te);

  /* Misc row: Forward and reverse radio buttons */
  direction_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), direction_hb);
  gtk_widget_show(direction_hb);

#if GTK_MAJOR_VERSION < 2
  forward_rb = dlg_radio_button_new_with_label_with_mnemonic(NULL, "_Forward",
                                                             accel_group);
#else
  forward_rb = gtk_radio_button_new_with_mnemonic(NULL, "_Forward");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(forward_rb), !cfile.sbackward);
  gtk_box_pack_start(GTK_BOX(direction_hb), forward_rb, TRUE, TRUE, 0);
  gtk_widget_show(forward_rb);

#if GTK_MAJOR_VERSION < 2
  backward_rb = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(forward_rb)),
               "_Backward", accel_group);
#else
  backward_rb = gtk_radio_button_new_with_mnemonic_from_widget(
               GTK_RADIO_BUTTON(forward_rb), "_Backward");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(backward_rb), cfile.sbackward);
  gtk_box_pack_start(GTK_BOX(direction_hb), backward_rb, TRUE, TRUE, 0);
  gtk_widget_show(backward_rb);


  /* Filter/Hex/Ascii Search */
  /* Filter */
  hex_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), hex_hb);
  gtk_widget_show(hex_hb);

#if GTK_MAJOR_VERSION < 2
  filter_rb = dlg_radio_button_new_with_label_with_mnemonic(NULL, "_Display Filter",
                                                             accel_group);
#else
  filter_rb = gtk_radio_button_new_with_mnemonic(NULL, "_Display Filter");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(filter_rb), !cfile.hex && !cfile.ascii);
  gtk_box_pack_start(GTK_BOX(hex_hb), filter_rb, TRUE, TRUE, 0);
  gtk_widget_show(filter_rb);

  /* Hex */
#if GTK_MAJOR_VERSION < 2
  hex_rb = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(filter_rb)),
               "_Hex", accel_group);
#else
  hex_rb = gtk_radio_button_new_with_mnemonic_from_widget(
               GTK_RADIO_BUTTON(filter_rb), "_Hex");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(hex_rb), cfile.hex);
  gtk_box_pack_start(GTK_BOX(hex_hb), hex_rb, TRUE, TRUE, 0);
  gtk_widget_show(hex_rb);

  /* ASCII Search */

#if GTK_MAJOR_VERSION < 2
  ascii_rb = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(filter_rb)),
               "_String", accel_group);
#else
  ascii_rb = gtk_radio_button_new_with_mnemonic_from_widget(
               GTK_RADIO_BUTTON(filter_rb), "_String");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ascii_rb), cfile.ascii);
  gtk_box_pack_start(GTK_BOX(hex_hb), ascii_rb, TRUE, TRUE, 0);
  SIGNAL_CONNECT(ascii_rb, "clicked", ascii_selected_cb, find_frame_w);
  gtk_widget_show(ascii_rb);

  /* Hex, Decode, or Summary Data Search */
  /* Source Hex Data Search Window*/
  data_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), data_hb);
  gtk_widget_show(data_hb);

#if GTK_MAJOR_VERSION < 2
  hex_data_rb = dlg_radio_button_new_with_label_with_mnemonic(NULL, "Hex",
                                                             accel_group);
#else
  hex_data_rb = gtk_radio_button_new_with_mnemonic(NULL, "Hex");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(hex_data_rb), !decode_data && !summary_data);
  gtk_box_pack_start(GTK_BOX(data_hb), hex_data_rb, TRUE, TRUE, 0);
  gtk_widget_show(hex_data_rb);

  /* Search Decode Window */
#if GTK_MAJOR_VERSION < 2
  decode_data_rb = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(hex_data_rb)),
               "Decode", accel_group);
#else
  decode_data_rb = gtk_radio_button_new_with_mnemonic_from_widget(
               GTK_RADIO_BUTTON(hex_data_rb), "Decode");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(decode_data_rb), decode_data);
  gtk_box_pack_start(GTK_BOX(data_hb), decode_data_rb, TRUE, TRUE, 0);
  gtk_widget_show(decode_data_rb);

  /* Search Summary Window */

#if GTK_MAJOR_VERSION < 2
  summary_data_rb = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(hex_data_rb)),
               "Summary", accel_group);
#else
  summary_data_rb = gtk_radio_button_new_with_mnemonic_from_widget(
               GTK_RADIO_BUTTON(hex_data_rb), "Summary");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(summary_data_rb), summary_data);
  gtk_box_pack_start(GTK_BOX(data_hb), summary_data_rb, TRUE, TRUE, 0);
  gtk_widget_show(summary_data_rb);

  /* String Type Selection Dropdown Box 
     These only apply to the Hex Window search option */
  combo_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), combo_hb);
  gtk_widget_show(combo_hb);
  /* Create Label */
  combo_lb = gtk_label_new("Find String Type:");
  gtk_box_pack_start(GTK_BOX(combo_hb), combo_lb, FALSE, FALSE, 6);
  gtk_widget_show(combo_lb);
  /* Create Combo Box */
  combo_cb = gtk_combo_new();

  glist = g_list_append(glist, "ASCII Unicode & Non-Unicode");
  glist = g_list_append(glist, "ASCII Non-Unicode");
  glist = g_list_append(glist, "ASCII Unicode");
  glist = g_list_append(glist, "EBCDIC");

  gtk_combo_set_popdown_strings(GTK_COMBO(combo_cb), glist);
  gtk_container_add(GTK_CONTAINER(main_vb), combo_cb);
  gtk_widget_show(combo_cb);

#if GTK_MAJOR_VERSION < 2
  case_cb = dlg_check_button_new_with_label_with_mnemonic(
		"Case Insensitive Search", accel_group);
#else
  case_cb = gtk_check_button_new_with_mnemonic(
		"Case Insensitive Search");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(case_cb),
		case_type);
  gtk_container_add(GTK_CONTAINER(main_vb), case_cb);
  gtk_widget_show(case_cb);

  /* Button row: OK and cancel buttons */
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
  SIGNAL_CONNECT(ok_bt, "clicked", find_frame_ok_cb, find_frame_w);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

#if GTK_MAJOR_VERSION < 2
  cancel_bt = gtk_button_new_with_label ("Cancel");
#else
  cancel_bt = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
  SIGNAL_CONNECT(cancel_bt, "clicked", find_frame_close_cb, find_frame_w);
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  OBJECT_SET_DATA(find_frame_w, E_FIND_FILT_KEY, filter_te);
  OBJECT_SET_DATA(find_frame_w, E_FIND_BACKWARD_KEY, backward_rb);
  OBJECT_SET_DATA(find_frame_w, E_FIND_FILTERDATA_KEY, filter_rb);
  OBJECT_SET_DATA(find_frame_w, E_FIND_HEXDATA_KEY, hex_rb);
  OBJECT_SET_DATA(find_frame_w, E_FIND_ASCIIDATA_KEY, ascii_rb);
  OBJECT_SET_DATA(find_frame_w, E_FIND_STRINGTYPE_KEY, combo_cb);
  OBJECT_SET_DATA(find_frame_w, E_CASE_SEARCH_KEY, case_cb);
  OBJECT_SET_DATA(find_frame_w, E_SOURCE_HEX_KEY, hex_data_rb);
  OBJECT_SET_DATA(find_frame_w, E_SOURCE_DECODE_KEY, decode_data_rb);
  OBJECT_SET_DATA(find_frame_w, E_SOURCE_SUMMARY_KEY, summary_data_rb);
  

  ascii_selected_cb(NULL, find_frame_w);
  /* Catch the "activate" signal on the filter text entry, so that
     if the user types Return there, we act as if the "OK" button
     had been selected, as happens if Return is typed if some widget
     that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(filter_te, ok_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(find_frame_w, cancel_bt);

  /* Give the initial focus to the "Filter" entry box. */
  gtk_widget_grab_focus(filter_te);

  gtk_widget_show(find_frame_w);
}

/* 
 *  This function will disable the string options until
 *  the string search is selected.
 */  
static void
ascii_selected_cb(GtkWidget *button_rb _U_, gpointer parent_w)
{
    GtkWidget   *ascii_rb, *hex_data_rb, *decode_data_rb, *summary_data_rb,
                *data_combo_cb, *data_case_cb;

    ascii_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_ASCIIDATA_KEY);
    hex_data_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_SOURCE_HEX_KEY);
    decode_data_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_SOURCE_DECODE_KEY);
    summary_data_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_SOURCE_SUMMARY_KEY);
    data_combo_cb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_STRINGTYPE_KEY);
    data_case_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CASE_SEARCH_KEY);

    
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ascii_rb))) {
      gtk_widget_set_sensitive(GTK_WIDGET(hex_data_rb), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(decode_data_rb), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(summary_data_rb), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(data_combo_cb), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(data_case_cb), TRUE);
    } else {
        gtk_widget_set_sensitive(GTK_WIDGET(hex_data_rb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(decode_data_rb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(summary_data_rb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_combo_cb), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(data_case_cb), FALSE);
    }
    return;
}


static void
find_frame_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  GtkWidget *filter_te, *backward_rb, *hex_rb, *ascii_rb, *combo_cb, *case_cb,
            *decode_data_rb, *summary_data_rb;
  gchar     *filter_text, *string_type;
  dfilter_t *sfcode;

  filter_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_FILT_KEY);
  backward_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_BACKWARD_KEY);
  hex_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_HEXDATA_KEY);
  ascii_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_ASCIIDATA_KEY);
  combo_cb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_STRINGTYPE_KEY);
  case_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CASE_SEARCH_KEY);
  decode_data_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_SOURCE_DECODE_KEY);
  summary_data_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_SOURCE_SUMMARY_KEY);

  filter_text = gtk_entry_get_text(GTK_ENTRY(filter_te));
  string_type = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(combo_cb)->entry));

  case_type = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(case_cb));
  decode_data = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(decode_data_rb));
  summary_data = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(summary_data_rb));

  /*
   * Try to compile the filter.
   */
  if (!dfilter_compile(filter_text, &sfcode) && !GTK_TOGGLE_BUTTON (hex_rb)->active && !GTK_TOGGLE_BUTTON (ascii_rb)->active) {
    /* The attempt failed; report an error. */
    simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
    return;
  }

  /* Was it empty? */
  if (sfcode == NULL && !GTK_TOGGLE_BUTTON (hex_rb)->active && !GTK_TOGGLE_BUTTON (ascii_rb)->active) {
    /* Yes - complain. */
    simple_dialog(ESD_TYPE_CRIT, NULL,
       "You didn't specify valid search criteria.");
    return;
  }

  /*
   * Remember the filter.
   */
  if (cfile.sfilter)
    g_free(cfile.sfilter);
  cfile.sfilter = g_strdup(filter_text);

  cfile.sbackward = GTK_TOGGLE_BUTTON (backward_rb)->active;
  cfile.hex = GTK_TOGGLE_BUTTON (hex_rb)->active;
  cfile.ascii = GTK_TOGGLE_BUTTON (ascii_rb)->active;
  cfile.ftype = g_strdup(string_type);

  if (!GTK_TOGGLE_BUTTON (hex_rb)->active && !GTK_TOGGLE_BUTTON (ascii_rb)->active ) {
      if (!find_packet(&cfile, sfcode)) {
        /* We didn't find the packet. */
        simple_dialog(ESD_TYPE_CRIT, NULL, "No packet matched that filter.");
        return;
      }
  }
  else
  {
      if (!decode_data && !summary_data) {
          if (!find_ascii(&cfile, filter_text, cfile.ascii, string_type, case_type)) {
              /* We didn't find the packet. */
              simple_dialog(ESD_TYPE_CRIT, NULL, "No packet matched search criteria.");
              return;
          }
      }
      else
      {
          /* Use the cfile.hex to indicate if summary or decode search */
          /* This way the Next and Previous find options will work */
          cfile.hex = summary_data; 
          if (!find_in_gtk_data(&cfile, parent_w, filter_text, case_type, summary_data)) {
              /* We didn't find the packet. */
              simple_dialog(ESD_TYPE_CRIT, NULL, "No packet matched search criteria.");
              return;
          }
      }
  }
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
find_frame_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
find_frame_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Find Frame" dialog box. */
  find_frame_w = NULL;
}

static void
find_previous_next(GtkWidget *w, gpointer d, gboolean sens)
{
  dfilter_t *sfcode;


  if (cfile.sfilter) {
     if (!dfilter_compile(cfile.sfilter, &sfcode) && !cfile.hex && !cfile.ascii)
        return;
     if (sfcode == NULL && !cfile.hex && !cfile.ascii)
        return;
     cfile.sbackward = sens;
     if (cfile.hex || cfile.ascii) 
     {
         if (!decode_data && !summary_data) {
            find_ascii(&cfile, cfile.sfilter, cfile.ascii, cfile.ftype, case_type);
         }
         else {
            find_in_gtk_data(&cfile, d, cfile.sfilter, case_type, cfile.hex);
         }
     }
     else 
     {
         find_packet(&cfile, sfcode);
     }
  } else
     find_frame_cb(w, d);
}

void
find_next_cb(GtkWidget *w , gpointer d)
{
  find_previous_next(w, d, FALSE);
}

void
find_previous_cb(GtkWidget *w , gpointer d)
{
  find_previous_next(w, d, TRUE);
}
