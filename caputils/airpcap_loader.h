/* airpcap_loader.h
 * Declarations of routines for the "About" dialog
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

#ifndef __AIRPCAP_LOADER_H__
#define __AIRPCAP_LOADER_H__

#include <epan/crypt/airpdcap_system.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error values from "get_airpcap_interface_list()". */
#define CANT_GET_AIRPCAP_INTERFACE_LIST 0    /* error getting list */
#define NO_AIRPCAP_INTERFACES_FOUND     1    /* list is empty */
#define AIRPCAP_NOT_LOADED              2    /* Airpcap DLL not loaded */

#define AIRPCAP_CHANNEL_ANY_NAME "ANY"

#define AIRPCAP_WEP_KEY_STRING  "WEP"
/*
 * XXX - WPA_PWD is the passphrase+ssid and WPA-PSK is the hexadecimal key
 */
#define AIRPCAP_WPA_PWD_KEY_STRING  "WPA-PWD"
#define AIRPCAP_WPA_BIN_KEY_STRING  "WPA-PSK"

#define AIRPCAP_DLL_OK        0
#define AIRPCAP_DLL_OLD       1
#define AIRPCAP_DLL_ERROR     2
#define AIRPCAP_DLL_NOT_FOUND 3

/* #define AIRPCAP_DEBUG 1 */

typedef gchar * (*AirpcapGetLastErrorHandler)(PAirpcapHandle AdapterHandle);
typedef gboolean (*AirpcapGetDeviceListHandler)(PAirpcapDeviceDescription *PPAllDevs, gchar * Ebuf);
typedef void (*AirpcapFreeDeviceListHandler)(PAirpcapDeviceDescription PAllDevs);
typedef PAirpcapHandle (*AirpcapOpenHandler)(gchar * DeviceName, gchar * Ebuf);
typedef void (*AirpcapCloseHandler)(PAirpcapHandle AdapterHandle);
typedef gboolean (*AirpcapGetLinkTypeHandler)(PAirpcapHandle AdapterHandle, PAirpcapLinkType PLinkType);
typedef gboolean (*AirpcapSetLinkTypeHandler)(PAirpcapHandle AdapterHandle, AirpcapLinkType NewLinkType);
typedef gboolean (*AirpcapSetKernelBufferHandler)(PAirpcapHandle AdapterHandle, guint BufferSize);
typedef gboolean (*AirpcapSetFilterHandler)(PAirpcapHandle AdapterHandle, void * Instructions, guint Len);
typedef gboolean (*AirpcapGetMacAddressHandler)(PAirpcapHandle AdapterHandle, PAirpcapMacAddress PMacAddress);
typedef gboolean (*AirpcapSetMinToCopyHandler)(PAirpcapHandle AdapterHandle, guint MinToCopy);
typedef gboolean (*AirpcapGetReadEventHandler)(PAirpcapHandle AdapterHandle, void *** PReadEvent);
typedef gboolean (*AirpcapReadHandler)(PAirpcapHandle AdapterHandle, guint8 * Buffer, guint BufSize, guint * PReceievedBytes);
typedef gboolean (*AirpcapGetStatsHandler)(PAirpcapHandle AdapterHandle, PAirpcapStats PStats);
typedef gboolean (*AirpcapTurnLedOnHandler)(PAirpcapHandle  AdapterHandle, guint  LedNumber);
typedef gboolean (*AirpcapTurnLedOffHandler)(PAirpcapHandle  AdapterHandle, guint  LedNumber);
typedef gboolean (*AirpcapSetDeviceChannelHandler)(PAirpcapHandle  AdapterHandle, guint  Channel);
typedef gboolean (*AirpcapGetDeviceChannelHandler)(PAirpcapHandle  AdapterHandle, guint * PChannel);
typedef gboolean (*AirpcapSetFcsPresenceHandler)(PAirpcapHandle  AdapterHandle, gboolean  IsFcsPresent);
typedef gboolean (*AirpcapGetFcsPresenceHandler)(PAirpcapHandle  AdapterHandle, gboolean * PIsFcsPresent);
typedef gboolean (*AirpcapSetFcsValidationHandler)(PAirpcapHandle  AdapterHandle, AirpcapValidationType ValidationType);
typedef gboolean (*AirpcapGetFcsValidationHandler)(PAirpcapHandle  AdapterHandle, PAirpcapValidationType PValidationType);
typedef gboolean (*AirpcapSetDeviceKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);
typedef gboolean (*AirpcapGetDeviceKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize);
typedef gboolean (*AirpcapSetDriverKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);
typedef gboolean (*AirpcapGetDriverKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize);
typedef gboolean (*AirpcapSetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);
typedef gboolean (*AirpcapGetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);
typedef gboolean (*AirpcapSetDriverDecryptionStateHandler)(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);
typedef gboolean (*AirpcapGetDriverDecryptionStateHandler)(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);
typedef gboolean (*AirpcapStoreCurConfigAsAdapterDefaultHandler)(PAirpcapHandle AdapterHandle);
typedef void (*AirpcapGetVersionHandler)(guint * VersionMajor, guint * VersionMinor, guint * VersionRev, guint * VersionBuild);
typedef gboolean (*AirpcapSetDeviceChannelExHandler)(PAirpcapHandle AdapterHandle, AirpcapChannelInfo ChannelInfo);
typedef gboolean (*AirpcapGetDeviceChannelExHandler)(PAirpcapHandle AdapterHandle, PAirpcapChannelInfo PChannelInfo);
typedef gboolean (*AirpcapGetDeviceSupportedChannelsHandler)(PAirpcapHandle AdapterHandle, AirpcapChannelInfo **ppChannelInfo, guint32 * pNumChannelInfo);

#define FLAG_CAN_BE_LOW    0x00000001
#define FLAG_CAN_BE_HIGH   0x00000002
#define FLAG_IS_BG_CHANNEL 0x00000004
#define FLAG_IS_A_CHANNEL  0x00000008

typedef struct _Dot11Channel
{
    guint  Channel;
    guint32 Frequency;
    guint32 Flags;
} Dot11Channel;

/*
 * The list of interfaces returned by "get_airpcap_interface_list()" is
 * a list of these structures.
 */
typedef struct {
    char                    *name;              /* e.g. "eth0" */
    char                    *description;       /* from OS, e.g. "Local Area Connection" or NULL */
    GSList                  *ip_addr;           /* containing address values of if_addr_t */
    gboolean                loopback;           /* TRUE if loopback, FALSE otherwise */
    AirpcapLinkType         linkType;           /* The link layer type */
    AirpcapChannelInfo      channelInfo;        /* Channel Information */
    gboolean                IsFcsPresent;       /* Include 802.11 CRC in frames */
    AirpcapValidationType   CrcValidationOn;    /* Capture Frames with Wrong CRC */
    AirpcapDecryptionState  DecryptionOn;       /* TRUE if decryption is on, FALSE otherwise */
    PAirpcapKeysCollection  keysCollection;     /* WEP Key collection for the adapter */
    guint                   keysCollectionSize; /* Size of the key collection */
    gboolean                blinking;           /* TRUE if is blinkng, FALSE otherwise */
    gboolean                led;                /* TRUE if on, FALSE if off */
    gboolean                saved;              /* TRUE if current configuration has been saved, FALSE otherwise */
    gint                    tag;                /* int for the gtk blinking callback */
    Dot11Channel            *pSupportedChannels;
    guint32                 numSupportedChannels;
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
extern GList *g_airpcap_if_list;

/* Airpcap current selected interface */
extern airpcap_if_info_t *airpcap_if_selected;

/* Airpcap current active interface */
extern airpcap_if_info_t *airpcap_if_active;

#ifdef AIRPCAP_DEBUG
/*
 * USED FOR DEBUG ONLY... PRINTS AN AirPcap ADAPTER STRUCTURE in a fancy way.
 */
void
airpcap_if_info_print(airpcap_if_info_t* if_info);
#endif

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
 * (the name is used in AirpcapOpen).
 */
airpcap_if_info_t* get_airpcap_if_from_name(GList* if_list, const gchar* name);

/*
 * Airpcap wrapper, used to store the current settings for the selected adapter
 */
gboolean
airpcap_if_store_cur_config_as_adapter_default(PAirpcapHandle ah);

/*
 * Function used to load the WEP keys for a selected interface
 */
gboolean
airpcap_if_load_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info);

/*
 * Function used to load the WEP keys from the global driver list
 */
gboolean
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
gboolean
airpcap_if_get_fcs_validation(PAirpcapHandle ah, PAirpcapValidationType val);

/*
 * Airpcap wrapper, used to set the fcs validation of an airpcap adapter
 */
gboolean
airpcap_if_set_fcs_validation(PAirpcapHandle ah, AirpcapValidationType val);

/* Many of these are GTK+ only. */
/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap adapter
 */
gboolean
airpcap_if_get_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState val);

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap adapter
 */
gboolean
airpcap_if_set_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState val);

/*
 * Airpcap wrapper, used to get the fcs presence of an airpcap adapter
 */
gboolean
airpcap_if_get_fcs_presence(PAirpcapHandle ah, gboolean * ch);

/*
 * Airpcap wrapper, used to set the fcs presence of an airpcap adapter
 */
gboolean
airpcap_if_set_fcs_presence(PAirpcapHandle ah, gboolean ch);

/*
 * Airpcap wrapper, used to get the link type of an airpcap adapter
 */
gboolean
airpcap_if_get_link_type(PAirpcapHandle ah, PAirpcapLinkType lt);

/*
 * Airpcap wrapper, used to set the link type of an airpcap adapter
 */
gboolean
airpcap_if_set_link_type(PAirpcapHandle ah, AirpcapLinkType lt);

/*
 * Airpcap wrapper, used to get the channel of an airpcap adapter
 */
gboolean
airpcap_if_get_device_channel(PAirpcapHandle ah, guint * ch);

/*
 * Airpcap wrapper, get the channels supported by the adapter
 */
gboolean
airpcap_if_get_device_supported_channels(PAirpcapHandle ah, AirpcapChannelInfo **cInfo, guint32 * nInfo);

/*
 * Airpcap wrapper, get supported channels formatted into an array
 */
Dot11Channel*
airpcap_if_get_device_supported_channels_array(PAirpcapHandle ah, guint32 * pNumSupportedChannels);

/*
 * Airpcap wrapper, used to set the channel of an airpcap adapter
 */
gboolean
airpcap_if_set_device_channel(PAirpcapHandle ah, guint ch);

/*
 * Airpcap wrapper, used to get the frequency of an airpcap adapter
 */
gboolean
airpcap_if_get_device_channel_ex(PAirpcapHandle ah, PAirpcapChannelInfo pChannelInfo);

/*
 * Airpcap wrapper, used to set the frequency of an airpcap adapter
 */
gboolean
airpcap_if_set_device_channel_ex(PAirpcapHandle ah, AirpcapChannelInfo ChannelInfo);

/*
 * Airpcap wrapper, used to open an airpcap adapter
 */
PAirpcapHandle airpcap_if_open(gchar * name, gchar * err);

/*
 * Airpcap wrapper, used to close an airpcap adapter
 */
void airpcap_if_close(PAirpcapHandle handle);

/*
 * Retrieve the state of the Airpcap DLL
 */
int
airpcap_get_dll_state(void);

/*
 * Airpcap wrapper, used to turn on the led of an airpcap adapter
 */
gboolean airpcap_if_turn_led_on(PAirpcapHandle AdapterHandle, guint LedNumber);

/*
 * Airpcap wrapper, used to turn off the led of an airpcap adapter
 */
gboolean airpcap_if_turn_led_off(PAirpcapHandle AdapterHandle, guint LedNumber);

/*
 * This function will create a new airpcap_if_info_t using a name and a description
 */
airpcap_if_info_t* airpcap_if_info_new(char *name, char *description);

/*
 * This function will create a new fake drivers' interface, to load global keys...
 */
airpcap_if_info_t* airpcap_driver_fake_if_info_new(void);

/*
 *  Used to dinamically load the airpcap library in order link it only when
 *  it's present on the system.
 */
int load_airpcap(void);

/*
 * This function will use the airpcap.dll to find all the airpcap devices.
 * Will return null if no device is found.
 */
GList* get_airpcap_interface_list(int *err, char **err_str);

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
 * Used to retrieve the two chars string from interface description
 */
gchar*
airpcap_get_if_string_number(airpcap_if_info_t* if_info);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_set_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_get_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_set_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_get_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize);

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap driver
 */
gboolean
airpcap_if_get_driver_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable);
/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap driver
 */
gboolean
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
 * Clear keys and decryption status for the specified interface
 */
void
airpcap_if_clear_decryption_settings(airpcap_if_info_t* info_if);

/*
 * Adds compiled version string to str
 */
void
get_compiled_airpcap_version(GString *str);

void
get_runtime_airpcap_version(GString *str);

#ifdef __cplusplus
}
#endif

#endif /* __AIRPCAP_LOADER_H__ */
