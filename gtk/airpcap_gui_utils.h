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
#define AIRPCAP_LINK_TYPE_NAME_UNKNOWN					"Unknown"

#define AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK "Wireshark"
#define AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP   "Driver"
#define AIRPCAP_DECRYPTION_TYPE_STRING_NONE      "None"

#define NO_ROW_SELECTED -1
#define NO_COLUMN_SELECTED -1

/*
 * This structure is used because we need to store infos about the currently selected 
 * row in the key list. 
 */
typedef struct{
gint row;
gint column;
}airpcap_key_ls_selected_info_t;

/*
 * Used to retrieve a string containing a list of all the channels
 * on which at least one adapter is capturing. This is true
 * if the adapter passed as parameter is "Any" ... if not,
 * this function returns the only channel number string.
 */
gchar*
airpcap_get_all_channels_list(airpcap_if_info_t* if_info);

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
 * Retrieves the name in the validation combo entry.
 */
AirpcapValidationType
airpcap_validation_type_combo_get_type(GtkWidget* c);

/*
 * Returns the string corresponding to the given UINT (1-14, for channel only)
 */
UINT
airpcap_get_channel_number(const gchar* s);

/*
 * Retrieve the UINT corresponding to the given string (channel only, handle with care!)
 */
gchar*
airpcap_get_channel_name(UINT n);

/*
 * Set the combo box entry string given an UINT channel number
 */
void
airpcap_channel_combo_set_by_number(GtkWidget* w,UINT channel);

/*
 * Returns '1' if this is the "Any" adapter, '0' otherwise
 */
int
airpcap_if_is_any(airpcap_if_info_t* if_info);

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
void 
airpcap_add_keys_from_list(GtkWidget *w, airpcap_if_info_t *if_info);

/*
 * Update channel combo box. If the airpcap interface is "Any", the combo box will be disabled.
 */
void
airpcap_update_channel_combo(GtkWidget* w, airpcap_if_info_t* if_info);

/*
 * This function will take the current keys (widget list), specified for the
 * current adapter, and save them as default for ALL the others.
 */
void
airpcap_read_and_save_decryption_keys_from_clist(GtkWidget* key_ls, airpcap_if_info_t* info_if, GList* if_list);

/*
 * This function will load from the preferences file ALL the
 * keys (WEP, WPA and WPA2) and will set them as default for 
 * each adapter. To do this, it will save the keys in the registry...
 */
void
airpcap_load_decryption_keys(GList* if_list);

/*
 * This function will load from the preferences file ALL the
 * keys (WEP, WPA and WPA2) and will set them as default for 
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

#endif
