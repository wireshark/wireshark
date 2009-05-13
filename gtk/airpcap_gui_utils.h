/* airpcap_utils.h
 * Declarations of utility routines for the "Airpcap" dialog widgets
 *
 * $Id$
 *
 * Giorgio Tino <giorgio.tino@cacetech.com>
 * Copyright (c) CACE Technologies, LLC 2006
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

#ifndef __AIRPCAP_GUI_UTILS_H__
#define __AIRPCAP_GUI_UTILS_H__

#define AIRPCAP_VALIDATION_TYPE_NAME_ALL     "All Frames"
#define AIRPCAP_VALIDATION_TYPE_NAME_CORRECT "Valid Frames"
#define AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT "Invalid Frames"
#define AIRPCAP_VALIDATION_TYPE_NAME_UNKNOWN	     "Unknown"

#define AIRPCAP_LINK_TYPE_NAME_802_11_ONLY			"802.11 Only"
#define AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO	"802.11 + Radio"
#define AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_PPI		"802.11 + PPI"
#define AIRPCAP_LINK_TYPE_NAME_UNKNOWN				"Unknown"

#define AIRPCAP_LINK_TYPE_NUM_802_11_ONLY			0
#define AIRPCAP_LINK_TYPE_NUM_802_11_PLUS_RADIO	1
#define AIRPCAP_LINK_TYPE_NUM_802_11_PLUS_PPI		2

#define AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK "Wireshark"
#define AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP   "Driver"
#define AIRPCAP_DECRYPTION_TYPE_STRING_NONE      "None"

#define NO_ROW_SELECTED -1
#define NO_COLUMN_SELECTED -1

/* Controls the releay of settings back to the adapter. */
extern gboolean change_airpcap_settings;

/*
 * This structure is used because we need to store infos about the currently selected
 * row in the key list.
 */
typedef struct{
    gint row;
    gint column;
}airpcap_key_ls_selected_info_t;

/*
 * set up the airpcap toolbar for the new capture interface
 */
void
airpcap_set_toolbar_start_capture(airpcap_if_info_t* if_info);

/*
 * Set up the airpcap toolbar for the new capture interface
 */
void
airpcap_set_toolbar_stop_capture(airpcap_if_info_t* if_info);

/*
 * Add a key (string) to the given list
 */
void
airpcap_add_key_to_list(GtkWidget *keylist, gchar* type, gchar* key, gchar* ssid);

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
void
airpcap_add_keys_to_driver_from_list(GtkWidget *key_ls,airpcap_if_info_t *fake_if_info);

/*
 * Modify a key given a list and a row
 */
void
airpcap_modify_key_in_list(GtkWidget *keylist, gint row, gchar* type, gchar* key, gchar* ssid);

/*
 * Fill the list with the keys
 */
void
airpcap_fill_key_list(GtkWidget *keylist);

/*
 * Function used to retrieve the AirpcapValidationType given the string name.
 */
AirpcapValidationType
airpcap_get_validation_type(const gchar* name);

/*
 * Function used to retrieve the string name given an AirpcapValidationType.
 */
gchar*
airpcap_get_validation_name(AirpcapValidationType vt);

/*
 * Return an appropriate combo box entry number for the given an AirpcapValidationType.
 */
gint
airpcap_get_validation_combo_entry(AirpcapValidationType vt);

/*
 * Returns the AirpcapLinkType corresponding to the given string name.
 */
AirpcapLinkType
airpcap_get_link_type(const gchar* name);

/*
 * Returns the string name corresponding to the given AirpcapLinkType.
 */
gchar*
airpcap_get_link_name(AirpcapLinkType lt);

/*
 * Sets the entry of the link type combo using the AirpcapLinkType.
 */
void
airpcap_link_type_combo_set_by_type(GtkWidget* c, AirpcapLinkType type);

/*
 * Retrieves the name in link type the combo entry.
 */
AirpcapLinkType
airpcap_link_type_combo_get_type(GtkWidget* c);

/*
 * Sets the entry of the validation combo using the AirpcapValidationType.
 */
void
airpcap_validation_type_combo_set_by_type(GtkWidget* c,AirpcapValidationType type);

/*
 * Update channel offset combo box to 'offset'.
 */
void
airpcap_update_channel_offset_combo(airpcap_if_info_t* if_info, guint32 ch_freq, GtkWidget *channel_offset_cb);


/*
 * Retrieve the guint corresponding to the given string (channel only, handle with care!)
 */
gchar*
airpcap_get_channel_name(guint n);

/*
 * Set the combo box entry string given an guint channel number
 */
void
airpcap_channel_combo_set_by_frequency(GtkWidget* w,guint channel);

/** Respond to the user changing the channel combo box.
 * Update the active interface channel and update the offset
 * combo box.
 * Requires AirPcap globals.
 *
 * @param channel_cb The channel GtkComboBox
 * @param channel_offset_cb The channel offset GtkComboBox
 */
void
airpcap_channel_changed_cb(GtkWidget *channel_cb, gpointer channel_offset_cb);

/** Respond to the user changing the channel offset combo box.
 * Update the active interface channel offset.
 * Requires AirPcap globals.
 *
 * @param channel_offset_cb The channel offset GtkComboBox
 * @param data Unused
 */
void
airpcap_channel_offset_changed_cb(GtkWidget *channel_offset_cb, gpointer data);

/*
 * Returns '1' if this is the "Any" adapter, '0' otherwise
 */
int
airpcap_if_is_any(airpcap_if_info_t* if_info);

/*
 * Change channel of Airpcap Adapter
 */
gboolean
airpcap_update_frequency_and_offset(airpcap_if_info_t* if_info);

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
void
airpcap_add_keys_from_list(GtkWidget *w, airpcap_if_info_t *if_info);

/*
 * Update channel combo box. If the airpcap interface is "Any", the combo box will be disabled.
 */
void
airpcap_update_channel_combo(GtkWidget* channel_cb, airpcap_if_info_t* if_info);

/*
 * Update the channel offset of the given combobox
 */
void
airpcap_update_channel_offset_cb(airpcap_if_info_t* if_info, guint32 ch_freq, GtkWidget *channel_offset_cb);

/*
 * This function will take the current keys (widget list), specified for the
 * current adapter, and save them as default for ALL the others.
 */
void
airpcap_read_and_save_decryption_keys_from_clist(GtkWidget* key_ls, airpcap_if_info_t* info_if, GList* if_list);

/*
 * This function will load from the preferences file ALL the
 * keys (WEP, WPA and WPA_BIN) and will set them as default for
 * each adapter. To do this, it will save the keys in the registry...
 */
void
airpcap_load_decryption_keys(GList* if_list);

/*
 * This function will load from the preferences file ALL the
 * keys (WEP, WPA and WPA_BIN) and will set them as default for
 * each adapter. To do this, it will save the keys in the registry...
 */
gboolean
airpcap_check_decryption_keys(GList* if_list);

/*
 * This function will set the gibven GList of decryption_key_t structures
 * as the defoult for both Wireshark and the AirPcap adapters...
 */
void
airpcap_save_decryption_keys(GList* key_list, GList* adapters_list);

/*
 * This function is used to enable/disable the toolbar widgets
 * depending on the type of interface selected...
 */
void
airpcap_enable_toolbar_widgets(GtkWidget* w, gboolean en);

/*
 * This function sets up the correct airpcap toolbar that must
 * be displayed when no airpcap if is found on the system...
 */
void
airpcap_set_toolbar_no_if(GtkWidget* w);

#endif
