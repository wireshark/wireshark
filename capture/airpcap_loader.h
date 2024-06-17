/** @file
 *
 * Declarations of routines for the "About" dialog
 *
 * Giorgio Tino <giorgio.tino@cacetech.com>
 * Copyright (c) CACE Technologies, LLC 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __AIRPCAP_LOADER_H__
#define __AIRPCAP_LOADER_H__

#include <epan/crypt/dot11decrypt_system.h>
#include <wsutil/feature_list.h>

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

typedef char * (*AirpcapGetLastErrorHandler)(PAirpcapHandle AdapterHandle);
typedef bool (*AirpcapGetDeviceListHandler)(PAirpcapDeviceDescription *PPAllDevs, char * Ebuf);
typedef void (*AirpcapFreeDeviceListHandler)(PAirpcapDeviceDescription PAllDevs);
typedef PAirpcapHandle (*AirpcapOpenHandler)(char * DeviceName, char * Ebuf);
typedef void (*AirpcapCloseHandler)(PAirpcapHandle AdapterHandle);
typedef bool (*AirpcapGetLinkTypeHandler)(PAirpcapHandle AdapterHandle, PAirpcapLinkType PLinkType);
typedef bool (*AirpcapSetLinkTypeHandler)(PAirpcapHandle AdapterHandle, AirpcapLinkType NewLinkType);
typedef bool (*AirpcapSetKernelBufferHandler)(PAirpcapHandle AdapterHandle, unsigned BufferSize);
typedef bool (*AirpcapSetFilterHandler)(PAirpcapHandle AdapterHandle, void * Instructions, unsigned Len);
typedef bool (*AirpcapGetMacAddressHandler)(PAirpcapHandle AdapterHandle, PAirpcapMacAddress PMacAddress);
typedef bool (*AirpcapSetMinToCopyHandler)(PAirpcapHandle AdapterHandle, unsigned MinToCopy);
typedef bool (*AirpcapGetReadEventHandler)(PAirpcapHandle AdapterHandle, void *** PReadEvent);
typedef bool (*AirpcapReadHandler)(PAirpcapHandle AdapterHandle, uint8_t * Buffer, unsigned BufSize, unsigned * PReceievedBytes);
typedef bool (*AirpcapGetStatsHandler)(PAirpcapHandle AdapterHandle, PAirpcapStats PStats);
typedef bool (*AirpcapTurnLedOnHandler)(PAirpcapHandle  AdapterHandle, unsigned  LedNumber);
typedef bool (*AirpcapTurnLedOffHandler)(PAirpcapHandle  AdapterHandle, unsigned  LedNumber);
typedef bool (*AirpcapSetDeviceChannelHandler)(PAirpcapHandle  AdapterHandle, unsigned  Channel);
typedef bool (*AirpcapGetDeviceChannelHandler)(PAirpcapHandle  AdapterHandle, unsigned * PChannel);
typedef bool (*AirpcapSetFcsPresenceHandler)(PAirpcapHandle  AdapterHandle, bool  IsFcsPresent);
typedef bool (*AirpcapGetFcsPresenceHandler)(PAirpcapHandle  AdapterHandle, bool * PIsFcsPresent);
typedef bool (*AirpcapSetFcsValidationHandler)(PAirpcapHandle  AdapterHandle, AirpcapValidationType ValidationType);
typedef bool (*AirpcapGetFcsValidationHandler)(PAirpcapHandle  AdapterHandle, PAirpcapValidationType PValidationType);
typedef bool (*AirpcapSetDeviceKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);
typedef bool (*AirpcapGetDeviceKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, unsigned * PKeysCollectionSize);
typedef bool (*AirpcapSetDriverKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);
typedef bool (*AirpcapGetDriverKeysHandler)(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, unsigned * PKeysCollectionSize);
typedef bool (*AirpcapSetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);
typedef bool (*AirpcapGetDecryptionStateHandler)(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);
typedef bool (*AirpcapSetDriverDecryptionStateHandler)(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);
typedef bool (*AirpcapGetDriverDecryptionStateHandler)(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);
typedef bool (*AirpcapStoreCurConfigAsAdapterDefaultHandler)(PAirpcapHandle AdapterHandle);
typedef void (*AirpcapGetVersionHandler)(unsigned * VersionMajor, unsigned * VersionMinor, unsigned * VersionRev, unsigned * VersionBuild);
typedef bool (*AirpcapSetDeviceChannelExHandler)(PAirpcapHandle AdapterHandle, AirpcapChannelInfo ChannelInfo);
typedef bool (*AirpcapGetDeviceChannelExHandler)(PAirpcapHandle AdapterHandle, PAirpcapChannelInfo PChannelInfo);
typedef bool (*AirpcapGetDeviceSupportedChannelsHandler)(PAirpcapHandle AdapterHandle, AirpcapChannelInfo **ppChannelInfo, uint32_t * pNumChannelInfo);

#define FLAG_CAN_BE_LOW    0x00000001
#define FLAG_CAN_BE_HIGH   0x00000002
#define FLAG_IS_BG_CHANNEL 0x00000004
#define FLAG_IS_A_CHANNEL  0x00000008

typedef struct _Dot11Channel
{
    unsigned  Channel;
    uint32_t Frequency;
    uint32_t Flags;
} Dot11Channel;

/*
 * The list of interfaces returned by "get_airpcap_interface_list()" is
 * a list of these structures.
 */
typedef struct {
    char                    *name;              /* e.g. "eth0" */
    char                    *description;       /* from OS, e.g. "Local Area Connection" or NULL */
    GSList                  *ip_addr;           /* containing address values of if_addr_t */
    bool                loopback;           /* true if loopback, false otherwise */
    AirpcapLinkType         linkType;           /* The link layer type */
    AirpcapChannelInfo      channelInfo;        /* Channel Information */
    bool                IsFcsPresent;       /* Include 802.11 CRC in frames */
    AirpcapValidationType   CrcValidationOn;    /* Capture Frames with Wrong CRC */
    AirpcapDecryptionState  DecryptionOn;       /* true if decryption is on, false otherwise */
    PAirpcapKeysCollection  keysCollection;     /* WEP Key collection for the adapter */
    unsigned                keysCollectionSize; /* Size of the key collection */
    bool                    blinking;           /* true if is blinking, false otherwise */
    bool                    led;                /* true if on, false if off */
    bool                    saved;              /* true if current configuration has been saved, false otherwise */
    int                     tag;                /* int for the gtk blinking callback */
    Dot11Channel            *pSupportedChannels;
    uint32_t                numSupportedChannels;
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
char*
airpcap_get_if_string_number_from_description(char* description);

/*
 * Function used to free the airpcap interface list
 */
void
free_airpcap_interface_list(GList *if_list);

/*
 * Used to retrieve the interface given the name
 * (the name is used in AirpcapOpen).
 */
airpcap_if_info_t* get_airpcap_if_from_name(GList* if_list, const char* name);

/*
 * Airpcap wrapper, used to store the current settings for the selected adapter
 */
bool
airpcap_if_store_cur_config_as_adapter_default(PAirpcapHandle ah);

/*
 * Function used to load the WEP keys for a selected interface
 */
bool
airpcap_if_load_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info);

/*
 * Function used to load the WEP keys from the global driver list
 */
bool
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
bool
airpcap_if_get_fcs_validation(PAirpcapHandle ah, PAirpcapValidationType val);

/*
 * Airpcap wrapper, used to set the fcs validation of an airpcap adapter
 */
bool
airpcap_if_set_fcs_validation(PAirpcapHandle ah, AirpcapValidationType val);

/* Many of these are GTK+ only. */
/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap adapter
 */
bool
airpcap_if_get_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState val);

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap adapter
 */
bool
airpcap_if_set_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState val);

/*
 * Airpcap wrapper, used to get the fcs presence of an airpcap adapter
 */
bool
airpcap_if_get_fcs_presence(PAirpcapHandle ah, bool * ch);

/*
 * Airpcap wrapper, used to set the fcs presence of an airpcap adapter
 */
bool
airpcap_if_set_fcs_presence(PAirpcapHandle ah, bool ch);

/*
 * Airpcap wrapper, used to get the link type of an airpcap adapter
 */
bool
airpcap_if_get_link_type(PAirpcapHandle ah, PAirpcapLinkType lt);

/*
 * Airpcap wrapper, used to set the link type of an airpcap adapter
 */
bool
airpcap_if_set_link_type(PAirpcapHandle ah, AirpcapLinkType lt);

/*
 * Airpcap wrapper, used to get the channel of an airpcap adapter
 */
bool
airpcap_if_get_device_channel(PAirpcapHandle ah, unsigned * ch);

/*
 * Airpcap wrapper, get the channels supported by the adapter
 */
bool
airpcap_if_get_device_supported_channels(PAirpcapHandle ah, AirpcapChannelInfo **cInfo, uint32_t * nInfo);

/*
 * Airpcap wrapper, get supported channels formatted into an array
 */
Dot11Channel*
airpcap_if_get_device_supported_channels_array(PAirpcapHandle ah, uint32_t * pNumSupportedChannels);

/*
 * Airpcap wrapper, used to set the channel of an airpcap adapter
 */
bool
airpcap_if_set_device_channel(PAirpcapHandle ah, unsigned ch);

/*
 * Airpcap wrapper, used to get the frequency of an airpcap adapter
 */
bool
airpcap_if_get_device_channel_ex(PAirpcapHandle ah, PAirpcapChannelInfo pChannelInfo);

/*
 * Airpcap wrapper, used to set the frequency of an airpcap adapter
 */
bool
airpcap_if_set_device_channel_ex(PAirpcapHandle ah, AirpcapChannelInfo ChannelInfo);

/*
 * Airpcap wrapper, used to open an airpcap adapter
 */
PAirpcapHandle airpcap_if_open(char * name, char * err);

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
bool airpcap_if_turn_led_on(PAirpcapHandle AdapterHandle, unsigned LedNumber);

/*
 * Airpcap wrapper, used to turn off the led of an airpcap adapter
 */
bool airpcap_if_turn_led_off(PAirpcapHandle AdapterHandle, unsigned LedNumber);

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
char*
airpcap_get_if_string_number(airpcap_if_info_t* if_info);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
bool
airpcap_if_set_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
bool
airpcap_if_get_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, unsigned * PKeysCollectionSize);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
bool
airpcap_if_set_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
bool
airpcap_if_get_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, unsigned * PKeysCollectionSize);

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap driver
 */
bool
airpcap_if_get_driver_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable);
/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap driver
 */
bool
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
gather_airpcap_compile_info(feature_list l);

void
gather_airpcap_runtime_info(feature_list l);

#ifdef __cplusplus
}
#endif

#endif /* __AIRPCAP_LOADER_H__ */
