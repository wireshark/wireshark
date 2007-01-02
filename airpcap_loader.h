/* airpcap_loader.h
 * Declarations of routines for the "About" dialog
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

#ifndef __AIRPCAP_LOADER_H__
#define __AIRPCAP_LOADER_H__

#include <epan/crypt/airpdcap_user.h>

/* Error values from "get_airpcap_interface_list()". */
#define	CANT_GET_AIRPCAP_INTERFACE_LIST	0	/* error getting list */
#define	NO_AIRPCAP_INTERFACES_FOUND	1	/* list is empty */

#define AIRPCAP_CHANNEL_ANY_NAME "ANY"

#define AIRPCAP_WEP_KEY_STRING  "WEP"
/*
 * XXX - WPA_PWD is the passphrase+ssid and WPA-PSK is the hexadecimal key
 */
#define AIRPCAP_WPA_PWD_KEY_STRING  "WPA-PWD"
#define AIRPCAP_WPA_BIN_KEY_STRING  "WPA-PSK"

#define AIRPCAP_DLL_OK			0
#define AIRPCAP_DLL_OLD			1
#define AIRPCAP_DLL_ERROR		2
#define AIRPCAP_DLL_NOT_FOUND	3

typedef PCHAR (*AirpcapGetLastErrorHandler)(PAirpcapHandle AdapterHandle);
typedef BOOL (*AirpcapGetDeviceListHandler)(PAirpcapDeviceDescription *PPAllDevs, PCHAR Ebuf);
typedef VOID (*AirpcapFreeDeviceListHandler)(PAirpcapDeviceDescription PAllDevs);
typedef PAirpcapHandle (*AirpcapOpenHandler)(PCHAR DeviceName, PCHAR Ebuf);
typedef VOID (*AirpcapCloseHandler)(PAirpcapHandle AdapterHandle);
typedef BOOL (*AirpcapGetLinkTypeHandler)(PAirpcapHandle AdapterHandle, PAirpcapLinkType PLinkType);
typedef BOOL (*AirpcapSetLinkTypeHandler)(PAirpcapHandle AdapterHandle, AirpcapLinkType NewLinkType);
typedef BOOL (*AirpcapSetKernelBufferHandler)(PAirpcapHandle AdapterHandle, UINT BufferSize);
typedef BOOL (*AirpcapSetFilterHandler)(PAirpcapHandle AdapterHandle, PVOID Instructions, UINT Len);
typedef BOOL (*AirpcapGetMacAddressHandler)(PAirpcapHandle AdapterHandle, PAirpcapMacAddress PMacAddress);
typedef BOOL (*AirpcapSetMinToCopyHandler)(PAirpcapHandle AdapterHandle, UINT MinToCopy);
typedef BOOL (*AirpcapGetReadEventHandler)(PAirpcapHandle AdapterHandle, HANDLE* PReadEvent);
typedef BOOL (*AirpcapReadHandler)(PAirpcapHandle AdapterHandle, PBYTE Buffer, UINT BufSize, PUINT PReceievedBytes);
typedef BOOL (*AirpcapGetStatsHandler)(PAirpcapHandle AdapterHandle, PAirpcapStats PStats);
typedef BOOL (*AirpcapTurnLedOnHandler)(PAirpcapHandle  AdapterHandle, UINT  LedNumber);
typedef BOOL (*AirpcapTurnLedOffHandler)(PAirpcapHandle  AdapterHandle, UINT  LedNumber);
typedef BOOL (*AirpcapSetDeviceChannelHandler)(PAirpcapHandle  AdapterHandle, UINT  Channel);
typedef BOOL (*AirpcapGetDeviceChannelHandler)(PAirpcapHandle  AdapterHandle, PUINT PChannel);
typedef BOOL (*AirpcapSetFcsPresenceHandler)(PAirpcapHandle  AdapterHandle, BOOL  IsFcsPresent);
typedef BOOL (*AirpcapGetFcsPresenceHandler)(PAirpcapHandle  AdapterHandle, PBOOL PIsFcsPresent);
typedef BOOL (*AirpcapSetFcsValidationHandler)(PAirpcapHandle  AdapterHandle, AirpcapValidationType ValidationType);
typedef BOOL (*AirpcapGetFcsValidationHandler)(PAirpcapHandle  AdapterHandle, PAirpcapValidationType PValidationType);
typedef BOOL (*AirpcapSetDeviceKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);
typedef BOOL (*AirpcapGetDeviceKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize);
typedef BOOL (*AirpcapSetDriverKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);
typedef BOOL (*AirpcapGetDriverKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize);
typedef BOOL (*AirpcapSetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);
typedef BOOL (*AirpcapGetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);
typedef BOOL (*AirpcapSetDriverDecryptionStateHandler)(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);
typedef BOOL (*AirpcapGetDriverDecryptionStateHandler)(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);
typedef BOOL (*AirpcapStoreCurConfigAsAdapterDefaultHandler)(PAirpcapHandle AdapterHandle);
typedef VOID (*AirpcapGetVersionHandler)(PUINT VersionMajor, PUINT VersionMinor, PUINT VersionRev, PUINT VersionBuild);

/*
 * The list of interfaces returned by "get_airpcap_interface_list()" is
 * a list of these structures.
 */
typedef struct {
	char					*name;				/* e.g. "eth0" */
	char					*description;		/* from OS, e.g. "Local Area Connection" or NULL */
	GSList					*ip_addr;			/* containing address values of if_addr_t */
	gboolean				loopback;			/* TRUE if loopback, FALSE otherwise */
	AirpcapLinkType			linkType;			/* The link layer type*/
	UINT					channel;			/* Channel (1-14)*/
	BOOL					IsFcsPresent;		/* Include 802.11 CRC in frames */
	AirpcapValidationType	CrcValidationOn;	/* Capture Frames with Wrong CRC */
	AirpcapDecryptionState  DecryptionOn;		/* TRUE if decryption is on, FALSE otherwise*/
	PAirpcapKeysCollection  keysCollection;		/* WEP Key collection for the adapter */
	UINT					keysCollectionSize;	/* Size of the key collection */
	gboolean				blinking;			/* TRUE if is blinkng, FALSE otherwise*/
	gboolean				led;				/* TRUE if on, FALSE if off*/
	gboolean				saved;				/* TRUE if current configuration has been saved, FALSE otherwise */
	gint					tag;				/* int for the gtk blinking callback */
} airpcap_if_info_t;

/*
 * Struct used to store infos to pass to the preferences manager callbacks
 */
typedef struct {
   GList *list;
   int current_index;
   int number_of_keys;
} keys_cb_data_t;

/* Airpcap interface list */
extern GList *airpcap_if_list;

/* Airpcap current selected interface */
extern airpcap_if_info_t *airpcap_if_selected;

/* Airpcap current active interface */
extern airpcap_if_info_t *airpcap_if_active;

/* WLAN preferences pointer */
//extern module_t *wlan_prefs;

/*
 * Function used to read the Decryption Keys from the preferences and store them
 * properly into the airpcap adapter.
 */
BOOL
load_wlan_driver_wep_keys();

/*
 *  Function used to save to the prefereces file the Decryption Keys.
 */
BOOL
save_wlan_wep_keys(airpcap_if_info_t* info_if);

/*
 * This function will tell the airpcap driver the key list to use
 * This will be stored into the registry...
 */
gboolean
write_wlan_wep_keys_to_regitry(airpcap_if_info_t* info_if, GList* key_list);

/* Returs TRUE if the WEP key is valid, false otherwise */
gboolean
wep_key_is_valid(char* key);

/*
 * Callback used to free an instance of airpcap_if_info_t
 */
static void
free_airpcap_if_cb(gpointer data, gpointer user_data _U_);

/*
 * USED FOR DEBUG ONLY... PRINTS AN AirPcap ADAPTER STRUCTURE in a fancy way.
 */
void
airpcap_if_info_print(airpcap_if_info_t* if_info);

/*
 * Used to retrieve the two chars string from interface
 */
gchar*
airpcap_get_if_string_number_from_description(gchar* description);

/*
 * Function used to free the airpcap interface list
 */
void
free_airpcap_interface_list(GList *if_list);

/*
 * Used to retrieve the interface given the name
 * (the name is used in AirpcapOpen)
 */
airpcap_if_info_t* get_airpcap_if_by_name(GList* if_list, const gchar* name);

/*
 * Airpcap wrapper, used to store the current settings for the selected adapter
 */
BOOL
airpcap_if_store_cur_config_as_adapter_default(PAirpcapHandle ah);

/*
 * Function used to load the WEP keys for a selected interface
 */
BOOL
airpcap_if_load_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info);

/*
 * Function used to load the WEP keys from the global driver list
 */
BOOL
airpcap_if_load_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info);

/*
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info);

/*
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info);

/*
 * Airpcap wrapper, used to get the fcs validation of an airpcap adapter
 */
BOOL
airpcap_if_get_fcs_validation(PAirpcapHandle ah, PAirpcapValidationType val);

/*
 * Airpcap wrapper, used to set the fcs validation of an airpcap adapter
 */
BOOL
airpcap_if_set_fcs_validation(PAirpcapHandle ah, AirpcapValidationType val);

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap adapter
 */
BOOL
airpcap_if_get_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState val);

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap adapter
 */
BOOL
airpcap_if_set_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState val);

/*
 * Airpcap wrapper, used to get the fcs presence of an airpcap adapter
 */
BOOL
airpcap_if_get_fcs_presence(PAirpcapHandle ah, PBOOL ch);

/*
 * Airpcap wrapper, used to set the fcs presence of an airpcap adapter
 */
BOOL
airpcap_if_set_fcs_presence(PAirpcapHandle ah, BOOL ch);

/*
 * Airpcap wrapper, used to get the link type of an airpcap adapter
 */
BOOL
airpcap_if_get_link_type(PAirpcapHandle ah, PAirpcapLinkType lt);

/*
 * Airpcap wrapper, used to set the link type of an airpcap adapter
 */
BOOL
airpcap_if_set_link_type(PAirpcapHandle ah, AirpcapLinkType lt);

/*
 * Airpcap wrapper, used to get the channel of an airpcap adapter
 */
BOOL
airpcap_if_get_device_channel(PAirpcapHandle ah, PUINT ch);

/*
 * Airpcap wrapper, used to set the channel of an airpcap adapter
 */
BOOL
airpcap_if_set_device_channel(PAirpcapHandle ah, UINT ch);

/*
 * Airpcap wrapper, used to open an airpcap adapter
 */
PAirpcapHandle airpcap_if_open(PCHAR name, PCHAR err);

/*
 * Airpcap wrapper, used to close an airpcap adapter
 */
VOID airpcap_if_close(PAirpcapHandle handle);

/*
 * Airpcap wrapper, used to turn on the led of an airpcap adapter
 */
BOOL airpcap_if_turn_led_on(PAirpcapHandle AdapterHandle, UINT LedNumber);

/*
 * Airpcap wrapper, used to turn off the led of an airpcap adapter
 */
BOOL airpcap_if_turn_led_off(PAirpcapHandle AdapterHandle, UINT LedNumber);

/*
 * This function will create a new airpcap_if_info_t using a name and a description
 */
airpcap_if_info_t* airpcap_if_info_new(char *name, char *description);

/*
 * This function will create a new fake drivers' interface, to load global keys...
 */
airpcap_if_info_t* airpcap_driver_fake_if_info_new();

/*
 *  Used to dinamically load the airpcap library in order link it only when
 *  it's present on the system.
 */
int load_airpcap(void);

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_airpcap_interface_list()".
 */
gchar*
cant_get_airpcap_if_list_error_message(const char *err_str);

/*
 * This function will use the airpcap.dll to find all the airpcap devices.
 * Will return null if no device is found.
 */
GList*
get_airpcap_interface_list(int *err, char *err_str);

/*
 * Returns the ASCII string of a key given the key bites
 */
gchar*
airpcap_get_key_string(AirpcapKey key);

/*
 * Load the configuration for the specified interface
 */
void
airpcap_load_selected_if_configuration(airpcap_if_info_t* if_info);

/*
 * Save the configuration for the specified interface
 */
void
airpcap_save_selected_if_configuration(airpcap_if_info_t* if_info);

/*
 * Used to retrieve the name of the interface given the description
 * (the name is used in AirpcapOpen, the description is put in the combo box)
 */
gchar*
get_airpcap_name_from_description(GList* if_list, gchar* description);

/*
 * Used to retrieve the airpcap_if_info_t of the selected interface given the
 * description (that is the entry of the combo box).
 */
gpointer
get_airpcap_if_from_description(GList* if_list, const gchar* description);

/*
 * Used to retrieve the two chars string from interface description
 */
gchar*
airpcap_get_if_string_number(airpcap_if_info_t* if_info);

/*
 * Returns the default airpcap interface of a list, NULL if list is empty
 */
airpcap_if_info_t*
airpcap_get_default_if(GList* airpcap_if_list);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_set_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_get_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_set_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_get_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize);

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap driver
 */
BOOL
airpcap_if_get_driver_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable);
/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap driver
 */
BOOL
airpcap_if_set_driver_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable);

/*
 * Save the configuration for the specified interface
 */
void
airpcap_save_driver_if_configuration(airpcap_if_info_t* fake_if_info);

/*
 * Free an instance of airpcap_if_info_t
 */
void
airpcap_if_info_free(airpcap_if_info_t *if_info);

/*
 * This function will tell the airpcap driver the key list to use
 * This will be stored into the registry...
 */
BOOL
write_wlan_driver_wep_keys_to_regitry(GList* key_list);

/*
 * Clear keys and decryption status for the specified interface
 */
void
airpcap_if_clear_decryption_settings(airpcap_if_info_t* info_if);

/*
 *  Function used to save to the preference file the Decryption Keys.
 */
int
save_wlan_driver_wep_keys();

/*
 *  Function used to save to the preference file the Decryption Keys.
 */
int
save_wlan_wireshark_wep_keys(GList* key_ls);

/*
 * DECRYPTION KEYS FUNCTIONS
 */
/*
 * This function is used for DEBUG PURPOSES ONLY!!!
 */
void
print_key_list(GList* key_list);

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
get_airpcap_driver_keys();

/*
 * Returns the list of the decryption keys specified for wireshark, NULL if
 * no key is found
 */
GList*
get_wireshark_keys();

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
wireshark_decryption_on();

/*
 * Returns TRUE if the AirPcap decryption for the current adapter is active, FALSE otherwise
 */
gboolean
airpcap_decryption_on();

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

/*
 * Adds compiled version string to str
 */
void
get_compiled_airpcap_version(GString *str);

void
get_runtime_airpcap_version(GString *str);

/*
 * Returns the decryption_key_t struct given a string describing the key.
 * Returns NULL if the key_string cannot be parsed.
 */
decryption_key_t*
parse_key_string(gchar* key_string);

/*
 * Returns a newly allocated string representing the given decryption_key_t struct
 */
gchar*
get_key_string(decryption_key_t* dk);

#endif
