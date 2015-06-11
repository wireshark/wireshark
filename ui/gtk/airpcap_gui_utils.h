/* airpcap_utils.h
 * Declarations of utility routines for the "Airpcap" dialog widgets
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

/* Key list columns */
enum {
  KL_COL_TYPE,
  KL_COL_KEY,
  KL_COL_SSID,
  KL_NUM_COLS
};

/* Controls the releay of settings back to the adapter. */
extern gboolean change_airpcap_settings;

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
airpcap_add_key_to_list(GtkListStore *key_list_store, gchar* type, gchar* key, gchar* ssid);

/*
 * Fill the list with the keys
 */
void
airpcap_fill_key_list(GtkListStore *key_list_store);

/*
 * Function used to retrieve the AirpcapValidationType given the string name.
 */
AirpcapValidationType
airpcap_get_validation_type(const gchar* name);

/*
 * Function used to retrieve the string name given an AirpcapValidationType.
 */
const gchar*
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
const gchar*
airpcap_get_link_name(AirpcapLinkType lt);

/*
 * Sets the entry of the validation combo using the AirpcapValidationType.
 */
void
airpcap_validation_type_combo_set_by_type(GtkWidget* c,AirpcapValidationType type);

/*
 * Update channel offset combo box to 'offset'.
 */
void
airpcap_update_channel_offset_combo(airpcap_if_info_t* if_info, guint32 ch_freq, GtkWidget *channel_offset_cb, gboolean set);


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
airpcap_channel_changed_set_cb(GtkWidget *channel_cb, gpointer channel_offset_cb);

/** Respond to the user changing the channel combo box.
 * Update the offset combo box but not the channel.
 * Requires AirPcap globals.
 *
 * @param channel_cb The channel GtkComboBox
 * @param channel_offset_cb The channel offset GtkComboBox
 */
void
airpcap_channel_changed_noset_cb(GtkWidget *channel_cb, gpointer channel_offset_cb);

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
 * Update channel combo box. If the airpcap interface is "Any", the combo box will be disabled.
 */
void
airpcap_update_channel_combo(GtkWidget* channel_cb, airpcap_if_info_t* if_info);

/*
 * This function will take the current keys (widget list), specified for the
 * current adapter, and save them as default for ALL the others.
 */
void
airpcap_read_and_save_decryption_keys_from_list_store(GtkListStore* key_list_store, airpcap_if_info_t* info_if, GList* if_list);

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
 * Returns the default airpcap interface of a list, NULL if list is empty
 */
airpcap_if_info_t*
airpcap_get_default_if(GList* airpcap_if_list);

/*
 * DECRYPTION KEYS FUNCTIONS
 */

/*
 * Retrieves a GList of decryption_key_t structures containing infos about the
 * keys for the given adapter... returns NULL if no keys are found.
 */
GList*
get_airpcap_device_keys(airpcap_if_info_t* if_info);

/*
 * Retrieves a GList of decryption_key_t structures containing infos about the
 * keys for the global AirPcap driver... returns NULL if no keys are found.
 */
GList*
get_airpcap_driver_keys(void);

/*
 * Returns the list of the decryption keys specified for wireshark, NULL if
 * no key is found
 */
GList*
get_wireshark_keys(void);

/*
 * Tests if two collection of keys are equal or not, to be considered equals, they have to
 * contain the same keys in the SAME ORDER! (If both lists are NULL, which means empty will
 * return TRUE)
 */
gboolean
key_lists_are_equal(GList* list1, GList* list2);

/*
 * Merges two lists of keys. If a key is found multiple times, it will just appear once!
 */
GList*
merge_key_list(GList* list1, GList* list2);

/*
 * If the given key is contained in the list, returns TRUE.
 * Returns FALSE otherwise.
 */
gboolean
key_is_in_list(decryption_key_t *dk,GList *list);

/*
 * Returns TRUE if keys are equals, FALSE otherwise
 */
gboolean
keys_are_equals(decryption_key_t *k1,decryption_key_t *k2);

/*
 * Use this function to free a key list.
 */
void
free_key_list(GList *list);

/*
 * Returns TRUE if the Wireshark decryption is active, FALSE otherwise
 */
gboolean
wireshark_decryption_on(void);

/*
 * Returns TRUE if the AirPcap decryption for the current adapter is active, FALSE otherwise
 */
gboolean
airpcap_decryption_on(void);

/*
 * Enables decryption for Wireshark if on_off is TRUE, disables it otherwise.
 */
void
set_wireshark_decryption(gboolean on_off);

/*
 * Enables decryption for all the adapters if on_off is TRUE, disables it otherwise.
 */
gboolean
set_airpcap_decryption(gboolean on_off);

#endif
