/* airpcap_dlg.h
 * Declarations of routines for the "Airpcap" dialog
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

#ifndef __AIRPCAP_DLG_H__
#define __AIRPCAP_DLG_H__

#define AIRPCAP_ADVANCED_FROM_TOOLBAR 0
#define AIRPCAP_ADVANCED_FROM_OPTIONS 1

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
void airpcap_add_keys_from_list(GtkWidget *w, airpcap_if_info_t *if_info);

/*
 * Pop-up window, used to ask the user if he wants to save the selected interface settings
 * when closing the window.
 */
void
airpcap_ask_for_save_before_closing(GtkWidget *w _U_, gpointer data);

/* user confirmed the "Save settings..." dialog */
void
airpcap_dialog_save_before_closing_cb(gpointer dialog _U_, gint btn, gpointer data);

/*
 * Pop-up window, used to ask the user if he wants to save the selected interface settings
 */
void
airpcap_ask_for_save(GtkWidget *entry _U_, gpointer data);

/*
 * Function used to change the selected interface and advanced dialog box
 */ 
void 
airpcap_change_if(GtkWidget *entry _U_, gpointer data);

/*
 * Fill the interface combo box specified
 */
void
airpcap_fill_if_combo(GtkWidget *combo, GList* if_list);

/*
 * Add key window destroy callback
 */
static void
add_key_w_destroy_cb(GtkWidget *button, gpointer data _U_);

/*
 * Changed callback for the channel combobox
 */
static void
channel_changed_cb(GtkWidget *w _U_, gpointer data);

/*
 * Activate callback for the link layer combobox
 */
static void
link_layer_activate_cb(GtkWidget *w _U_, gpointer data);

/*
 * Changed callback for the link layer combobox
 */
static void
link_layer_changed_cb(GtkWidget *w _U_, gpointer data);

/*
 * Callback for the crc chackbox
 */
static void
crc_check_cb(GtkWidget *w, gpointer user_data);

/*
 * Callback for the wrong crc chackbox
 */
static void
wrong_crc_check_cb(GtkWidget *w, gpointer user_data);

/*
 * Callbackfunction for WEP key list
 */
static void
key_sel_list_cb(GtkWidget *l, gpointer data _U_);

/*
 * Callback function for WEP key list
 */ 
static gint
key_sel_list_button_cb(GtkWidget *widget, GdkEventButton *event,gpointer func_data);

/*
 * Activate callback for the adapter combobox 
 */
static void
combo_if_activate_cb(GtkWidget *w _U_, gpointer data);

/*
 * Changed callback for the adapter combobox
 */
static void
airpcap_advanced_combo_if_changed_cb(GtkWidget *w _U_, gpointer data);

/*
 * Pop-up window that appears when user confirms the "Save settings..." dialog 
 */
static void
airpcap_dialog_save_cb(GtkWidget* dialog _U_, gint btn, gpointer data);

/*
 * Thread function used to blink the led
 */
void update_blink(gpointer data _U_);

/*
 * Blink button callback
 */
void blink_cb(GtkWidget *blink_bt _U_, gpointer if_data);

/** Create a "Airpcap" dialog box caused by a button click.
 *
 * @param widget parent widget
 * @param construct_args_ptr parameters to construct the dialog (construct_args_t)
 */
void display_airpcap_advanced_cb(GtkWidget *widget, gpointer construct_args_ptr);

#endif
