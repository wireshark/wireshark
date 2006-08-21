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

/* Error values from "get_airpcap_interface_list()". */
#define	CANT_GET_AIRPCAP_INTERFACE_LIST	0	/* error getting list */
#define	NO_AIRPCAP_INTERFACES_FOUND	1	/* list is empty */

#define MAX_ENCRYPTION_KEYS 64

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
typedef BOOL (*AirpcapSetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);
typedef BOOL (*AirpcapGetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);
typedef BOOL (*AirpcapStoreCurConfigAsAdapterDefaultHandler)(PAirpcapHandle AdapterHandle);
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

/* Airpcap interface list */
extern GList *airpcap_if_list;

/* Airpcap current selected interface */
extern airpcap_if_info_t *airpcap_if_selected;

/* Airpcap current active interface */
extern airpcap_if_info_t *airpcap_if_active;

/*
 * Callback used to free an instance of airpcap_if_info_t
 */
static void
free_airpcap_if_cb(gpointer data, gpointer user_data _U_);

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
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info);

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

/* HAVE_AIRPCAP_API */

/*
 *  Used to dinamically load the airpcap library in order link it only when
 *  it's present on the system.
 */
BOOL load_airpcap(void);

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
#endif
