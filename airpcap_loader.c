/* airpcap_loader.c
 *
 * $Id$
 *
 * Giorgio Tino <giorgio.tino@cacetech.com>
 * Copyright (c) CACE Technologies, LLC 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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

#ifdef _WIN32

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP
#include <glib.h>
#include <gmodule.h>


#include <wtap.h>
#include <pcap.h>
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include "capture_ui_utils.h"

#include "simple_dialog.h"

#include <airpcap.h>
#include "airpcap_loader.h"

/*
 * We load dinamically the dag library in order link it only when
 * it's present on the system
 */
static HMODULE AirpcapLib = NULL;

/*
 * Set to TRUE if the DLL was successfully loaded AND all functions
 * are present.
 */
static gboolean AirpcapLoaded = FALSE;

static AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
static AirpcapGetDeviceListHandler g_PAirpcapGetDeviceList;
static AirpcapFreeDeviceListHandler g_PAirpcapFreeDeviceList;
static AirpcapOpenHandler g_PAirpcapOpen;
static AirpcapCloseHandler g_PAirpcapClose;
static AirpcapGetLinkTypeHandler g_PAirpcapGetLinkType;
static AirpcapSetLinkTypeHandler g_PAirpcapSetLinkType;
static AirpcapSetKernelBufferHandler g_PAirpcapSetKernelBuffer;
static AirpcapSetFilterHandler g_PAirpcapSetFilter;
static AirpcapGetMacAddressHandler g_PAirpcapGetMacAddress;
static AirpcapSetMinToCopyHandler g_PAirpcapSetMinToCopy;
static AirpcapGetReadEventHandler g_PAirpcapGetReadEvent;
static AirpcapReadHandler g_PAirpcapRead;
static AirpcapGetStatsHandler g_PAirpcapGetStats;
static AirpcapTurnLedOnHandler g_PAirpcapTurnLedOn;
static AirpcapTurnLedOffHandler g_PAirpcapTurnLedOff;
static AirpcapGetDeviceChannelHandler g_PAirpcapGetDeviceChannel;
static AirpcapSetDeviceChannelHandler g_PAirpcapSetDeviceChannel;
static AirpcapGetFcsPresenceHandler g_PAirpcapGetFcsPresence;
static AirpcapSetFcsPresenceHandler g_PAirpcapSetFcsPresence;
static AirpcapGetFcsValidationHandler g_PAirpcapGetFcsValidation;
static AirpcapSetFcsValidationHandler g_PAirpcapSetFcsValidation;
static AirpcapGetDeviceKeysHandler g_PAirpcapGetDeviceKeys;
static AirpcapSetDeviceKeysHandler g_PAirpcapSetDeviceKeys;
static AirpcapGetDriverKeysHandler g_PAirpcapGetDriverKeys;
static AirpcapSetDriverKeysHandler g_PAirpcapSetDriverKeys;
static AirpcapGetDecryptionStateHandler g_PAirpcapGetDecryptionState;
static AirpcapSetDecryptionStateHandler g_PAirpcapSetDecryptionState;
static AirpcapGetDriverDecryptionStateHandler g_PAirpcapGetDriverDecryptionState;
static AirpcapSetDriverDecryptionStateHandler g_PAirpcapSetDriverDecryptionState;
static AirpcapStoreCurConfigAsAdapterDefaultHandler g_PAirpcapStoreCurConfigAsAdapterDefault;
static AirpcapGetVersionHandler g_PAirpcapGetVersion;

/* Airpcap interface list */
GList *airpcap_if_list = NULL;

/* Airpcap current selected interface */
airpcap_if_info_t *airpcap_if_selected = NULL;

/* Airpcap current active interface */
airpcap_if_info_t *airpcap_if_active = NULL;

/* WLAN preferences pointer */
module_t *wlan_prefs = NULL;

/* Callback used by the load_wlan_keys() routine in order to read a WEP decryption key */
static guint
get_wep_key(pref_t *pref, gpointer ud _U_)
{
gchar *my_string = NULL;
keys_cb_data_t* user_data;

decryption_key_t* new_key;

/* Retrieve user data info */
user_data = (keys_cb_data_t*)ud;

if (g_strncasecmp(pref->name, "wep_key", 7) == 0 && pref->type == PREF_STRING)
    {
    my_string = g_strdup(*pref->varp.string);

    if( my_string != NULL)
        {
        /* Key is added only if not null ... */
        if( (g_strcasecmp(my_string,"") != 0) && (wep_key_is_valid(my_string)))
            {
            new_key = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

            new_key->key = g_string_new(my_string);
            g_free(my_string);

            new_key->bits = new_key->key->len * 4;

            new_key->type = AIRPCAP_KEYTYPE_WEP;

            new_key->ssid = NULL;

            user_data->list = g_list_append(user_data->list,new_key);
            user_data->number_of_keys++;
            user_data->current_index++;
            }
        }
    }
return 0;
}

/* Callback used by the load_wlan_keys() routine in order to read a WPA decryption key */
static guint
get_wpa_key(pref_t *pref, gpointer ud _U_)
{
return 1;
}

/* Callback used by the load_wlan_keys() routine in order to read a WPA2 decryption key */
static guint
get_wpa2_key(pref_t *pref, gpointer ud _U_)
{
return 1;
}

/* Returs TRUE if the WEP key is valid, false otherwise */
gboolean
wep_key_is_valid(char* key)
{
GString *new_key_string;
guint i=0;

if(key == NULL)
	return FALSE;

new_key_string = g_string_new(key);

if( ((new_key_string->len) > WEP_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < 2))
	{
	g_string_free(new_key_string,FALSE);
	return FALSE;
	}
if((new_key_string->len % 2) != 0)
	{
	g_string_free(new_key_string,FALSE);
	return FALSE;
	}
for(i = 0; i < new_key_string->len; i++)
	{
	if(!g_ascii_isxdigit(new_key_string->str[i]))
		{
		g_string_free(new_key_string,FALSE);
		return FALSE;
		}
	}

g_string_free(new_key_string,FALSE);
return TRUE;
}

/* Callback used by the save_wlan_keys() routine in order to write a decryption key */
static guint
set_wep_key(pref_t *pref, gpointer ud _U_)
{
gchar *my_string = NULL;
keys_cb_data_t* user_data;
gint wep_key_number = 0;

/* Retrieve user data info */
user_data = (keys_cb_data_t*)ud;

if (g_strncasecmp(pref->name, "wep_key", 7) == 0 && pref->type == PREF_STRING)
    {
    /* Ok, the pref we're gonna set is a wep_key ... but what number? */
    sscanf(pref->name,"wep_key%d",&wep_key_number);

    if(user_data->current_index < user_data->number_of_keys)
        {
        if(wep_key_number == (user_data->current_index+1))
            {
            my_string = g_strdup((char*)g_list_nth_data(user_data->list,user_data->current_index));

			g_free((void *)*pref->varp.string);
			*pref->varp.string = (void *)g_strdup(my_string);

            g_free(my_string);
            }
        }
    else /* If the number of keys has been reduced somehow, we need to delete all the other keys
          * (remember that the new ones have been probably overwritten)
          */
        {
        g_free((void *)*pref->varp.string);
        *pref->varp.string = (void *)g_strdup("");  /* Do not just free memory!!! Put an 'empty' string! */
        }
    user_data->current_index++;
    }

return 0;
}

/*
 * Function used to read the Decryption Keys from the preferences and store them
 * properly into the airpcap adapter.
 */
BOOL
load_wlan_wep_keys(airpcap_if_info_t* info_if)
{
keys_cb_data_t* user_data;
guint i;
gchar *tmp = NULL;

if(info_if == NULL) return FALSE;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Allocate a structure used to keep infos  between the callbacks */
user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

/* Fill the structure */
user_data->list = NULL;
user_data->current_index = 0;
user_data->number_of_keys= 0; /* Still unknown */

/* Run the callback on each 802.11 preference */
prefs_pref_foreach(wlan_prefs, get_wep_key, (gpointer)user_data);

/* Now the key list should be filled */

/*
 * Signal that we've changed things, and run the 802.11 dissector's
 * callback
 */
wlan_prefs->prefs_changed = TRUE;

prefs_apply(wlan_prefs);

write_wlan_wep_keys_to_regitry(info_if,user_data->list);

/* FREE MEMORY */
/* free the WEP key string */
for(i=0;i<g_list_length(user_data->list);i++)
    {
    g_free(g_list_nth(user_data->list,i)->data);
    }

/* free the (empty) list */
g_list_free(user_data->list);

/* free the user_data structure */
g_free(user_data);

return TRUE;
}



/*
 * Function used to read the Decryption Keys from the preferences and store them
 * properly into the airpcap adapter.
 */
BOOL
load_wlan_driver_wep_keys()
{
keys_cb_data_t* user_data;
guint i;
gchar *tmp = NULL;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Allocate a structure used to keep infos  between the callbacks */
user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

/* Fill the structure */
user_data->list = NULL;
user_data->current_index = 0;
user_data->number_of_keys= 0; /* Still unknown */

/* Run the callback on each 802.11 preference */
prefs_pref_foreach(wlan_prefs, get_wep_key, (gpointer)user_data);

/* Now the key list should be filled */

/*
 * Signal that we've changed things, and run the 802.11 dissector's
 * callback
 */
wlan_prefs->prefs_changed = TRUE;

prefs_apply(wlan_prefs);

write_wlan_driver_wep_keys_to_regitry(user_data->list);

/* FREE MEMORY */
/* free the WEP key string */
for(i=0;i<g_list_length(user_data->list);i++)
    {
    g_free(g_list_nth(user_data->list,i)->data);
    }

/* free the (empty) list */
g_list_free(user_data->list);

/* free the user_data structure */
g_free(user_data);

/* airpcap_if_info_free(fake_info_if); */

return TRUE;
}

/*
 * This function will tell the airpcap driver the key list to use
 * This will be stored into the registry...
 */
BOOL
write_wlan_wep_keys_to_regitry(airpcap_if_info_t* info_if, GList* key_list)
{
UINT i,j;
GString *new_key;
gchar s[3];
PAirpcapKeysCollection KeysCollection;
ULONG KeysCollectionSize;
UCHAR KeyByte;
UINT keys_in_list = 0;
decryption_key_t* key_item = NULL;

keys_in_list = g_list_length(key_list);

/*
 * Save the encryption keys, if we have any of them
 */
KeysCollectionSize = 0;

/*
 * Calculate the size of the keys collection
 */
KeysCollectionSize = sizeof(AirpcapKeysCollection) + keys_in_list * sizeof(AirpcapKey);

/*
 * Allocate the collection
 */
KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);
if(!KeysCollection)
{
	return FALSE;
}

/*
 * Populate the key collection
 */
KeysCollection->nKeys = keys_in_list;

for(i = 0; i < keys_in_list; i++)
{
    KeysCollection->Keys[i].KeyType = AIRPCAP_KEYTYPE_WEP;

	/* Retrieve the Item corresponding to the i-th key */
	key_item = (decryption_key_t*)g_list_nth_data(key_list,i);
	new_key = g_string_new(key_item->key->str);

	KeysCollection->Keys[i].KeyLen = new_key->len / 2;
	memset(&KeysCollection->Keys[i].KeyData, 0, sizeof(KeysCollection->Keys[i].KeyData));

	for(j = 0 ; j < new_key->len; j += 2)
	{
		s[0] = new_key->str[j];
		s[1] = new_key->str[j+1];
		s[2] = '\0';
		KeyByte = (UCHAR)strtol(s, NULL, 16);
		KeysCollection->Keys[i].KeyData[j / 2] = KeyByte;
	}

	g_string_free(new_key,TRUE);

}
/*
 * Free the old adapter key collection!
 */
if(info_if->keysCollection != NULL)
	g_free(info_if->keysCollection);

/*
 * Set this collection ad the new one
 */
info_if->keysCollection = KeysCollection;
info_if->keysCollectionSize = KeysCollectionSize;

/*
 * Configuration must be saved
 */
info_if->saved = FALSE;

/*
 * Write down the changes to the registry
 */
airpcap_save_selected_if_configuration(info_if);

return TRUE;
}

/*
 * This function will tell the airpcap driver the key list to use
 * This will be stored into the registry...
 */
BOOL
write_wlan_driver_wep_keys_to_regitry(GList* key_list)
{
UINT i,j;
GString *new_key;
gchar s[3];
PAirpcapKeysCollection KeysCollection;
ULONG KeysCollectionSize;
UCHAR KeyByte;
UINT keys_in_list = 0;
decryption_key_t* key_item = NULL;
airpcap_if_info_t* fake_info_if = NULL;

/* Create the fake_info_if from the first adapter of the list */
fake_info_if = airpcap_driver_fake_if_info_new();

keys_in_list = g_list_length(key_list);

/*
 * Save the encryption keys, if we have any of them
 */
KeysCollectionSize = 0;

/*
 * Calculate the size of the keys collection
 */
KeysCollectionSize = sizeof(AirpcapKeysCollection) + keys_in_list * sizeof(AirpcapKey);

/*
 * Allocate the collection
 */
KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);
if(!KeysCollection)
{
	return FALSE;
}

/*
 * Populate the key collection
 */
KeysCollection->nKeys = keys_in_list;

for(i = 0; i < keys_in_list; i++)
{
    KeysCollection->Keys[i].KeyType = AIRPCAP_KEYTYPE_WEP;

	/* Retrieve the Item corresponding to the i-th key */
	key_item = (decryption_key_t*)g_list_nth_data(key_list,i);
	new_key = g_string_new(key_item->key->str);

	KeysCollection->Keys[i].KeyLen = new_key->len / 2;
	memset(&KeysCollection->Keys[i].KeyData, 0, sizeof(KeysCollection->Keys[i].KeyData));

	for(j = 0 ; j < new_key->len; j += 2)
	{
		s[0] = new_key->str[j];
		s[1] = new_key->str[j+1];
		s[2] = '\0';
		KeyByte = (UCHAR)strtol(s, NULL, 16);
		KeysCollection->Keys[i].KeyData[j / 2] = KeyByte;
	}

	g_string_free(new_key,TRUE);
}

/*
 * Free the old adapter key collection!
 */
if(fake_info_if->keysCollection != NULL)
	g_free(fake_info_if->keysCollection);

/*
 * Set this collection ad the new one
 */
fake_info_if->keysCollection = KeysCollection;
fake_info_if->keysCollectionSize = KeysCollectionSize;

/*
 * Configuration must be saved
 */
fake_info_if->saved = FALSE;

/*
 * Write down the changes to the registry
 */
airpcap_save_driver_if_configuration(fake_info_if);

airpcap_if_info_free(fake_info_if);

return TRUE;
}

/*
 *  Function used to save to the preference file the Decryption Keys.
 */
gboolean
save_wlan_wep_keys(airpcap_if_info_t* info_if)
{
GList* key_list = NULL;
char* tmp_key = NULL;
guint keys_in_list,i;
keys_cb_data_t* user_data;

if(info_if == NULL) return FALSE;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Allocate a structure used to keep infos  between the callbacks */
user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

/* Number of keys in key list */
/* Number of keys in key list */
if(info_if->keysCollectionSize != 0)
    keys_in_list = (guint)(info_if->keysCollectionSize -  sizeof(AirpcapKeysCollection))/sizeof(AirpcapKey);
else
    keys_in_list = 0;

for(i=0; i<keys_in_list; i++)
{
/* Only if it is a WEP key... */
if(info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_WEP)
    {
    tmp_key = airpcap_get_key_string(info_if->keysCollection->Keys[i]);
    key_list = g_list_append(key_list,g_strdup(tmp_key));
    g_free(tmp_key);
    }
}

/* Now we know the exact number of WEP keys in the list, so store it ... */
keys_in_list = g_list_length(key_list);

/* Fill the structure */
user_data->list = key_list;
user_data->current_index = 0;
user_data->number_of_keys= keys_in_list;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Run the callback on each 802.11 preference */
prefs_pref_foreach(wlan_prefs, set_wep_key,  (gpointer)user_data);

/* Signal that we've changed things, and run the 802.11 dissector's
 * callback */
wlan_prefs->prefs_changed = TRUE;

/* Apply changes for the specified preference */
prefs_apply(wlan_prefs);

/* FREE MEMORY */
/* free the WEP key string */
for(i=0;i<g_list_length(user_data->list);i++)
    {
    g_free(g_list_nth(user_data->list,i)->data);
    }

/* free the (empty) list */
g_list_free(user_data->list);

/* free the user_data structure */
g_free(user_data);

return TRUE;
}

/*
 *  Function used to save to the preference file the Decryption Keys.
 */
int
save_wlan_driver_wep_keys()
{
GList* key_list = NULL;
char* tmp_key = NULL;
guint keys_in_list,i;
keys_cb_data_t* user_data;
airpcap_if_info_t* fake_info_if = NULL;

/* Create the fake_info_if from the first adapter of the list */
fake_info_if = airpcap_driver_fake_if_info_new();

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Allocate a structure used to keep infos  between the callbacks */
user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

/* Number of keys in key list */
/* Number of keys in key list */
if(fake_info_if->keysCollectionSize != 0)
    keys_in_list = (guint)(fake_info_if->keysCollectionSize -  sizeof(AirpcapKeysCollection))/sizeof(AirpcapKey);
else
    keys_in_list = 0;

for(i=0; i<keys_in_list; i++)
{
/* Only if it is a WEP key... */
if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_WEP)
    {
    tmp_key = airpcap_get_key_string(fake_info_if->keysCollection->Keys[i]);
    key_list = g_list_append(key_list,g_strdup(tmp_key));
    g_free(tmp_key);
    }
}

/* Now we know the exact number of WEP keys in the list, so store it ... */
keys_in_list = g_list_length(key_list);

/* Fill the structure */
user_data->list = key_list;
user_data->current_index = 0;
user_data->number_of_keys= keys_in_list;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Run the callback on each 802.11 preference */
prefs_pref_foreach(wlan_prefs, set_wep_key,  (gpointer)user_data);

/* Signal that we've changed things, and run the 802.11 dissector's
 * callback */
wlan_prefs->prefs_changed = TRUE;

/* Apply changes for the specified preference */
prefs_apply(wlan_prefs);

/* FREE MEMORY */
/* free the WEP key string */
for(i=0;i<g_list_length(user_data->list);i++)
    {
    g_free(g_list_nth(user_data->list,i)->data);
    }

/* free the (empty) list */
g_list_free(user_data->list);

/* free the user_data structure */
g_free(user_data);

airpcap_if_info_free(fake_info_if);

return keys_in_list;
}

/*
 *  Function used to save to the preference file the Decryption Keys.
 */
int
save_wlan_wireshark_wep_keys(GList* key_ls)
{
GList* key_list = NULL;
char* tmp_key = NULL;
guint keys_in_list,i;
keys_cb_data_t* user_data;
airpcap_if_info_t* fake_info_if = NULL;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Allocate a structure used to keep infos  between the callbacks */
user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

keys_in_list = g_list_length(key_ls);

key_list = key_ls;

/* Fill the structure */
user_data->list = key_list;
user_data->current_index = 0;
user_data->number_of_keys= keys_in_list;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Run the callback on each 802.11 preference */
prefs_pref_foreach(wlan_prefs, set_wep_key,  (gpointer)user_data);

/* Signal that we've changed things, and run the 802.11 dissector's
 * callback */
wlan_prefs->prefs_changed = TRUE;

/* Apply changes for the specified preference */
prefs_apply(wlan_prefs);

/* FREE MEMORY */
/* free the WEP key string */
for(i=0;i<g_list_length(user_data->list);i++)
    {
    g_free(g_list_nth(user_data->list,i)->data);
    }

/* free the (empty) list */
g_list_free(user_data->list);

/* free the user_data structure */
g_free(user_data);

return keys_in_list;
}

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_airpcap_interface_list()".
 */
gchar *
cant_get_airpcap_if_list_error_message(const char *err_str)
{
	return g_strdup_printf("Can't get list of Wireless interfaces: %s", err_str);
}

/*
 * Airpcap wrapper, used to store the current settings for the selected adapter
 */
BOOL
airpcap_if_store_cur_config_as_adapter_default(PAirpcapHandle ah)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapStoreCurConfigAsAdapterDefault(ah);
}

/*
 * Airpcap wrapper, used to open an airpcap adapter
 */
PAirpcapHandle
airpcap_if_open(PCHAR name, PCHAR err)
{
	if (!AirpcapLoaded) return NULL;
	return g_PAirpcapOpen(name,err);
}

/*
 * Airpcap wrapper, used to close an airpcap adapter
 */
VOID
airpcap_if_close(PAirpcapHandle handle)
{
	if (!AirpcapLoaded) return;
	g_PAirpcapClose(handle);
}

/*
 * Airpcap wrapper, used to turn on the led of an airpcap adapter
 */
BOOL
airpcap_if_turn_led_on(PAirpcapHandle AdapterHandle, UINT LedNumber)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapTurnLedOn(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to turn off the led of an airpcap adapter
 */
BOOL
airpcap_if_turn_led_off(PAirpcapHandle AdapterHandle, UINT LedNumber)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapTurnLedOff(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to get the channel of an airpcap adapter
 */
BOOL
airpcap_if_get_device_channel(PAirpcapHandle ah, PUINT ch)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapGetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to set the channel of an airpcap adapter
 */
BOOL
airpcap_if_set_device_channel(PAirpcapHandle ah, UINT ch)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapSetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to get the link type of an airpcap adapter
 */
BOOL
airpcap_if_get_link_type(PAirpcapHandle ah, PAirpcapLinkType lt)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapGetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to set the link type of an airpcap adapter
 */
BOOL
airpcap_if_set_link_type(PAirpcapHandle ah, AirpcapLinkType lt)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapSetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to get the fcs presence of an airpcap adapter
 */
BOOL
airpcap_if_get_fcs_presence(PAirpcapHandle ah, PBOOL fcs)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapGetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to set the fcs presence of an airpcap adapter
 */
BOOL
airpcap_if_set_fcs_presence(PAirpcapHandle ah, BOOL fcs)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapSetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap adapter
 */
BOOL
airpcap_if_get_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapGetDecryptionState(ah,PEnable);
}

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap adapter
 */
BOOL
airpcap_if_set_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapSetDecryptionState(ah,Enable);
}

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap driver
 */
BOOL
airpcap_if_get_driver_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable)
{
	if (!AirpcapLoaded || (g_PAirpcapGetDriverDecryptionState==NULL)) return FALSE;
	return g_PAirpcapGetDriverDecryptionState(ah,PEnable);
}

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap driver
 */
BOOL
airpcap_if_set_driver_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable)
{
	if (!AirpcapLoaded || (g_PAirpcapSetDriverDecryptionState==NULL)) return FALSE;
	return g_PAirpcapSetDriverDecryptionState(ah,Enable);
}

/*
 * Airpcap wrapper, used to get the fcs validation of an airpcap adapter
 */
BOOL
airpcap_if_get_fcs_validation(PAirpcapHandle ah, PAirpcapValidationType val)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapGetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to set the fcs validation of an airpcap adapter
 */
BOOL
airpcap_if_set_fcs_validation(PAirpcapHandle ah, AirpcapValidationType val)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapSetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_set_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapSetDeviceKeys(AdapterHandle,KeysCollection);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_get_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize)
{
	if (!AirpcapLoaded) return FALSE;
	return g_PAirpcapGetDeviceKeys(AdapterHandle,KeysCollection,PKeysCollectionSize);
}

/*
 * Airpcap wrapper, used to save the driver's set of keys
 */
BOOL
airpcap_if_set_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection)
{
	if (!AirpcapLoaded || (g_PAirpcapSetDriverKeys==NULL)) return FALSE;
	return g_PAirpcapSetDriverKeys(AdapterHandle,KeysCollection);
}

/*
 * Airpcap wrapper, used to load the driver's set of keys
 */
BOOL
airpcap_if_get_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize)
{
	if (!AirpcapLoaded || (g_PAirpcapGetDriverKeys==NULL)) return FALSE;
	return g_PAirpcapGetDriverKeys(AdapterHandle,KeysCollection,PKeysCollectionSize);
}

/*
 * This function will create a new airpcap_if_info_t using a name and a description
 */
airpcap_if_info_t *
airpcap_if_info_new(char *name, char *description)
{
PAirpcapHandle ad;
gchar ebuf[AIRPCAP_ERRBUF_SIZE];

	airpcap_if_info_t *if_info;

	if_info = g_malloc(sizeof (airpcap_if_info_t));
	if_info->name = g_strdup(name);
	if (description == NULL)
		if_info->description = NULL;
	else
		if_info->description = g_strdup(description);
	if_info->ip_addr = NULL;
	if_info->loopback = FALSE;

	/* Probably I have to switch on the leds!!! */
	ad = airpcap_if_open(if_info->name, ebuf);
	if(ad)
		{
		airpcap_if_get_fcs_validation(ad,&(if_info->CrcValidationOn));
		airpcap_if_get_fcs_presence(ad,&(if_info->IsFcsPresent));
		airpcap_if_get_link_type(ad,&(if_info->linkType));
		airpcap_if_get_device_channel(ad,&(if_info->channel));
		airpcap_if_turn_led_on(ad, 0);
		airpcap_if_get_decryption_state(ad, &(if_info->DecryptionOn));
		if_info->led = TRUE;
		if_info->blinking = FALSE;
		if_info->saved = TRUE; /* NO NEED TO BE SAVED */

		/* get the keys, if everything is ok, close the adapter */
		if(airpcap_if_load_keys(ad,if_info))
			airpcap_if_close(ad);
		}
	return if_info;
}

/*
 * This function will create a new fake drivers' interface, to load global keys...
 */
airpcap_if_info_t*
airpcap_driver_fake_if_info_new()
{
	PAirpcapHandle ad;
	gchar ebuf[AIRPCAP_ERRBUF_SIZE];

	airpcap_if_info_t *if_info = NULL;
	airpcap_if_info_t *fake_if_info = NULL;

	/*
	 * Retrieve the first AirPcap adapter available. If no interface is found,
	 * it is not possible to retrieve the driver's settings, so return NULL.
	 */
	if_info = g_list_nth_data(airpcap_if_list,0);
	if(if_info == NULL)
		return NULL;

	fake_if_info = g_malloc(sizeof (airpcap_if_info_t));
	fake_if_info->name = g_strdup(if_info->name);
	fake_if_info->description = g_strdup(if_info->description);
	fake_if_info->loopback = FALSE;
	fake_if_info->ip_addr = NULL;

	/* Open the 'fake' adapter */
	ad = airpcap_if_open(if_info->name, ebuf);
	if(ad)
		{
		airpcap_if_get_driver_decryption_state(ad, &(fake_if_info->DecryptionOn));
		airpcap_if_get_fcs_validation(ad,&(fake_if_info->CrcValidationOn));
		airpcap_if_get_fcs_presence(ad,&(fake_if_info->IsFcsPresent));
		airpcap_if_get_link_type(ad,&(fake_if_info->linkType));
		airpcap_if_get_device_channel(ad,&(fake_if_info->channel));
		airpcap_if_turn_led_on(ad, 0);
		fake_if_info->led = TRUE;
		fake_if_info->blinking = FALSE;
		fake_if_info->saved = TRUE; /* NO NEED TO BE SAVED */

		/* get the keys, if everything is ok, close the adapter */
		if(airpcap_if_load_driver_keys(ad,fake_if_info))
			airpcap_if_close(ad);
		}

	return fake_if_info;
}

/*
 * USED FOR DEBUG ONLY... PRINTS AN AirPcap ADAPTER STRUCTURE in a fancy way.
 */
void
airpcap_if_info_print(airpcap_if_info_t* if_info)
{
if(if_info == NULL)
	{
	g_print("\nWARNING : AirPcap Interface pointer is NULL!\n");
	return;
	}

g_print("\n----------------- AirPcap Interface \n");
g_print("              NAME: %s\n",if_info->name);
g_print("       DESCRIPTION: %s\n",if_info->description);
g_print("          BLINKING: %s\n",if_info->blinking ? "TRUE" : "FALSE");
g_print("           CHANNEL: %2u\n",if_info->channel);
g_print("     CRCVALIDATION: %s\n",if_info->CrcValidationOn ? "ON" : "OFF");
g_print("        DECRYPTION: %s\n",if_info->DecryptionOn ? "ON" : "OFF");
g_print("           IP ADDR: %s\n",if_info->ip_addr!=NULL ? "NOT NULL" : "NULL");
g_print("        FCSPRESENT: %s\n",if_info->IsFcsPresent ? "TRUE" : "FALSE");
g_print("    KEYSCOLLECTION: %s\n",if_info->keysCollection!=NULL ? "NOT NULL" : "NULL");
g_print("KEYSCOLLECTIONSIZE: %u\n",if_info->keysCollectionSize);
g_print("               LED: %s\n",if_info->led ? "ON" : "OFF");
g_print("          LINKTYPE: %d\n",if_info->linkType);
g_print("          LOOPBACK: %s\n",if_info->loopback ? "YES" : "NO");
g_print("         (GTK) TAG: %d\n",if_info->tag);
g_print("\n\n");
}

/*
 * Function used to load the WEP keys for a selected interface
 */
BOOL
airpcap_if_load_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
if(!if_info) return FALSE;

if_info->keysCollectionSize = 0;
if_info->keysCollection = NULL;

if(!airpcap_if_get_device_keys(ad, NULL, &(if_info->keysCollectionSize)))
	{
	if(if_info->keysCollectionSize == 0)
		{
		if_info->keysCollection = NULL;
		airpcap_if_close(ad);
		return FALSE;
		}

	if_info->keysCollection = (PAirpcapKeysCollection)g_malloc(if_info->keysCollectionSize);
	if(!if_info->keysCollection)
		{
		if_info->keysCollectionSize = 0;
		if_info->keysCollection = NULL;
		airpcap_if_close(ad);
		return FALSE;
		}

	airpcap_if_get_device_keys(ad, if_info->keysCollection, &(if_info->keysCollectionSize));
	return TRUE;
	}

airpcap_if_close(ad);
return FALSE;
}

/*
 * Function used to load the WEP keys for a selected interface
 */
BOOL
airpcap_if_load_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
if_info->keysCollectionSize = 0;
if_info->keysCollection = NULL;

if(!airpcap_if_get_driver_keys(ad, NULL, &(if_info->keysCollectionSize)))
	{
	if(if_info->keysCollectionSize == 0)
		{
		if_info->keysCollection = NULL;
		airpcap_if_close(ad);
		return FALSE;
		}

	if_info->keysCollection = (PAirpcapKeysCollection)g_malloc(if_info->keysCollectionSize);
	if(!if_info->keysCollection)
		{
		if_info->keysCollectionSize = 0;
		if_info->keysCollection = NULL;
		airpcap_if_close(ad);
		return FALSE;
		}

	airpcap_if_get_driver_keys(ad, if_info->keysCollection, &(if_info->keysCollectionSize));
	return TRUE;
	}

airpcap_if_close(ad);
return FALSE;
}

/*
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
	if(!if_info || !AirpcapLoaded) return;

	if(if_info->keysCollection != NULL)
		g_PAirpcapSetDeviceKeys(ad,if_info->keysCollection);
}

/*
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
	if(if_info->keysCollection != NULL)
		airpcap_if_set_driver_keys(ad,if_info->keysCollection);
}

/*
 * Callback used to free an instance of airpcap_if_info_t
 */
static void
free_airpcap_if_cb(gpointer data, gpointer user_data _U_)
{
	airpcap_if_info_t *if_info = data;

	if (if_info->name != NULL)
		g_free(if_info->name);

	if (if_info->description != NULL)
		g_free(if_info->description);

	/* XXX - FREE THE WEP KEY LIST HERE!!!*/
	if(if_info->keysCollection != NULL)
		{
		g_free(if_info->keysCollection);
		if_info->keysCollection = NULL;
		}

	if(if_info->ip_addr != NULL)
		g_slist_free(if_info->ip_addr);

	if(if_info != NULL)
		g_free(if_info);
}

/*
 * Function used to free the airpcap interface list
 */
void
free_airpcap_interface_list(GList *if_list)
{
	g_list_foreach(if_list, free_airpcap_if_cb, NULL);
	g_list_free(if_list);
	if_list = NULL;
}

/*
 * This function will use the airpcap.dll to find all the airpcap devices.
 * Will return null if no device is found.
 */
GList*
get_airpcap_interface_list(int *err, char *err_str)
{
	GList  *il = NULL;
	airpcap_if_info_t *if_info;
	int i, n_adapts;
    AirpcapDeviceDescription *devsList, *adListEntry;

	if (err)
		*err = NO_AIRPCAP_INTERFACES_FOUND;

	if(!AirpcapLoaded || !g_PAirpcapGetDeviceList(&devsList, err_str))
	{
		/* No interfaces, return il = NULL; */
		return il;
	}

	/*
	 * Count the adapters
	 */
	adListEntry = devsList;
	n_adapts = 0;
	while(adListEntry)
	{
		n_adapts++;
		adListEntry = adListEntry->next;
	}

	if(n_adapts == 0)
	{
		/* No interfaces, return il= NULL */
		g_PAirpcapFreeDeviceList(devsList);
		return il;
	}

	/*
	 * Insert the adapters in our list
	 */
	adListEntry = devsList;
	for(i = 0; i < n_adapts; i++)
	{
		if_info = airpcap_if_info_new(adListEntry->Name, adListEntry->Description);
        il = g_list_append(il, if_info);

		adListEntry = adListEntry->next;
	}

	g_PAirpcapFreeDeviceList(devsList);

	return il;
}

/*
 * Used to retrieve the name of the interface given the description
 * (the name is used in AirpcapOpen, the description is put in the combo box)
 */
gchar* get_airpcap_name_from_description(GList* if_list, gchar* description)
{
unsigned int ifn;
GList* curr;
airpcap_if_info_t* if_info;

ifn = 0;
if(if_list != NULL)
	{
	while( ifn < g_list_length(if_list) )
		{
		curr = g_list_nth(if_list, ifn);

		if_info = NULL;
		if(curr != NULL)
			if_info = curr->data;
		if(if_info != NULL)
			if ( g_ascii_strcasecmp(if_info->description,description) == 0)
				{
				return if_info->name;
				}
		ifn++;
		}
	}
return NULL;
}

/*
 * Used to retrieve the interface given the name
 * (the name is used in AirpcapOpen)
 */
airpcap_if_info_t* get_airpcap_if_by_name(GList* if_list, const gchar* name)
{
unsigned int ifn;
GList* curr;
airpcap_if_info_t* if_info;

ifn = 0;
if(if_list != NULL)
	{
	while( ifn < g_list_length(if_list) )
		{
		curr = g_list_nth(if_list, ifn);

		if_info = NULL;
		if(curr != NULL)
			if_info = curr->data;
		if(if_info != NULL)
			if ( g_ascii_strcasecmp(if_info->name,name) == 0)
				{
				return if_info;
				}
		ifn++;
		}
	}
return NULL;
}

/*
 * Returns the ASCII string of a key given the key bytes
 */
gchar*
airpcap_get_key_string(AirpcapKey key)
{
unsigned int j = 0;
unsigned int l = 0;
gchar *dst,*src;

src = NULL;

if(key.KeyType == AIRPCAP_KEYTYPE_WEP)
	{
	if(key.KeyLen != 0)
	    {
        /* Allocate the string used to store the ASCII representation of the WEP key */
        dst = (gchar*)g_malloc(sizeof(gchar)*WEP_KEY_MAX_CHAR_SIZE + 1);
        /* Make sure that the first char is '\0' in order to make g_strlcat() work */
        dst[0]='\0';

	    for(j = 0; j < key.KeyLen; j++)
		    {
		    src = g_strdup_printf("%.2x\0", key.KeyData[j]);
			/*
			 * XXX - use g_strconcat() or GStrings instead ???
			 */
	    	l = g_strlcat(dst,src,WEP_KEY_MAX_CHAR_SIZE+1);
	    	}
    	g_free(src);
        }
	}
else if(key.KeyType == AIRPCAP_KEYTYPE_TKIP)
    {
    /* XXX - Add code here */
    }
else if(key.KeyType == AIRPCAP_KEYTYPE_CCMP)
    {
    /* XXX - Add code here */
    }
else
    {
    /* XXX - Add code here */
    }

return dst;
}

/*
 * Clear keys and decryption status for the specified interface
 */
void
airpcap_if_clear_decryption_settings(airpcap_if_info_t* info_if)
{
if(info_if != NULL)
	{
	if(info_if->keysCollection != NULL)
		{
		g_free(info_if->keysCollection);
		info_if->keysCollection = NULL;
		}

	info_if->keysCollectionSize = 0;

	info_if->DecryptionOn = FALSE;
	info_if->saved = FALSE;
	}
}

/*
 * Used to retrieve the airpcap_if_info_t of the selected interface given the
 * description (that is the entry of the combo box).
 */
gpointer get_airpcap_if_from_description(GList* if_list, const gchar* description)
{
unsigned int ifn;
GList* curr;
airpcap_if_info_t* if_info;

ifn = 0;
if(if_list != NULL)
	{
	while( ifn < g_list_length(if_list) )
		{
		curr = g_list_nth(if_list, ifn);

		if_info = NULL;
		if(curr != NULL)
			if_info = curr->data;
		if(if_info != NULL)
			if ( g_ascii_strcasecmp(if_info->description,description) == 0)
				{
				return if_info;
				}
		ifn++;
		}
	}
return NULL;
}

/*
 * Used to retrieve the two chars string from interface
 */
gchar*
airpcap_get_if_string_number(airpcap_if_info_t* if_info)
{
	gchar* number;
	guint n;
	int a;

	a = sscanf(if_info->name,AIRPCAP_DEVICE_NUMBER_EXTRACT_STRING,&n);

    /* If sscanf() returned 1, it means that has read a number, so interface is not "Any"
     * Otherwise, check if it is the "Any" adapter...
     */
     if(a == 0)
          {
          if(g_strcasecmp(if_info->name,AIRPCAP_DEVICE_ANY_EXTRACT_STRING)!=0)
               number = g_strdup_printf("??");
          else
               number = g_strdup_printf(AIRPCAP_CHANNEL_ANY_NAME);
          }
     else
          {
          number = g_strdup_printf("%.2u\0",n);
          }

	return number;
}

/*
 * Used to retrieve the two chars string from interface
 */
gchar*
airpcap_get_if_string_number_from_description(gchar* description)
{
	gchar* number;
	gchar* pointer;

	number = (gchar*)g_malloc(sizeof(gchar)*3);

	pointer = g_strrstr(description,"#\0");

	number[0] = *(pointer+1);
	number[1] = *(pointer+2);
	number[2] = '\0';

	return number;
}

/*
 * Returns the default airpcap interface of a list, NULL if list is empty
 */
airpcap_if_info_t*
airpcap_get_default_if(GList* airpcap_if_list)
{
int ifn = 0;
GList* popdown_if_list = NULL;
GList* curr = NULL;

	gchar* s;
	airpcap_if_info_t* if_info = NULL;

    if(prefs.capture_device != NULL)
    {
	s = g_strdup(get_if_name(prefs.capture_device));
	if_info = get_airpcap_if_by_name(airpcap_if_list,g_strdup(get_if_name(prefs.capture_device)));
	g_free(s);
    }
	return if_info;
}

/*
 * Load the configuration for the specified interface
 */
void
airpcap_load_selected_if_configuration(airpcap_if_info_t* if_info)
{
gchar ebuf[AIRPCAP_ERRBUF_SIZE];
PAirpcapHandle ad;

if(if_info != NULL)
	{
	ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list, if_info->description), ebuf);

	if(ad)
		{
		/* Stop blinking (if it was blinkig!)*/
		if(if_info->blinking)
			{
			/* Turn on the light (if it was off) */
			if(!(if_info->led)) airpcap_if_turn_led_on(ad, 0);
			}

		/* Apply settings... */
		airpcap_if_get_device_channel(ad,&(if_info->channel));
		airpcap_if_get_fcs_validation(ad,&(if_info->CrcValidationOn));
		airpcap_if_get_fcs_presence(ad,&(if_info->IsFcsPresent));
		airpcap_if_get_link_type(ad,&(if_info->linkType));
		airpcap_if_get_decryption_state(ad, &(if_info->DecryptionOn));
		/* get the keys, if everything is ok, close the adapter */
		if(airpcap_if_load_keys(ad,if_info))
			airpcap_if_close(ad);

		if_info->saved = TRUE;
		}
	else
		{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",if_info->description);
		}
	}
}

/*
 * Save the configuration for the specified interface
 */
void
airpcap_save_selected_if_configuration(airpcap_if_info_t* if_info)
{
gchar ebuf[AIRPCAP_ERRBUF_SIZE];
PAirpcapHandle ad;

if(if_info != NULL)
	{
	ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list, if_info->description), ebuf);

	if(ad)
		{
		/* Stop blinking (if it was blinkig!)*/
		if(if_info->blinking)
			{
			/* Turn on the light (if it was off) */
			if(!(if_info->led)) airpcap_if_turn_led_on(ad, 0);
			}

		/* Apply settings... */
		airpcap_if_set_device_channel(ad,if_info->channel);
		airpcap_if_set_fcs_validation(ad,if_info->CrcValidationOn);
		airpcap_if_set_fcs_presence(ad,if_info->IsFcsPresent);
		airpcap_if_set_link_type(ad,if_info->linkType);
		airpcap_if_set_decryption_state(ad, if_info->DecryptionOn);
		airpcap_if_save_keys(ad,if_info);

		/* ... and save them */
		if(!airpcap_if_store_cur_config_as_adapter_default(ad))
			{
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save Wireless configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
			if_info->saved = FALSE;
			airpcap_if_close(ad);
			return;
			}

		if_info->saved = TRUE;
		airpcap_if_close(ad);
		}
	else
		{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",if_info->description);
		}
	}
}

/*
 * Save the configuration for the specified interface
 */
void
airpcap_save_driver_if_configuration(airpcap_if_info_t* fake_if_info)
{
gchar ebuf[AIRPCAP_ERRBUF_SIZE];
PAirpcapHandle ad;

if(fake_if_info != NULL)
	{
	ad = airpcap_if_open(fake_if_info->name, ebuf);

	if(ad)
		{
		/* Apply decryption settings... */
		airpcap_if_set_driver_decryption_state(ad, fake_if_info->DecryptionOn);
		airpcap_if_save_driver_keys(ad,fake_if_info);
		airpcap_if_close(ad);
		}
	else
		{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",fake_if_info->description);
		}
	}

return;
}

/*
 * DECRYPTION KEYS FUNCTIONS
 */
/*
 * This function is used for DEBUG POURPOSES ONLY!!!
 */
void
print_key_list(GList* key_list)
{
gint n,i;
decryption_key_t* tmp;

if(key_list == NULL)
{
g_print("\n\n******* KEY LIST NULL *******\n\n");
return;
}

n = g_list_length(key_list);

g_print("\n\n********* KEY LIST **********\n\n");

g_print("NUMBER OF KEYS IN LIST : %d\n\n",n);

for(i =0; i < n; i++)
{
g_print("[%d] :\n",i+1);
tmp = (decryption_key_t*)(g_list_nth_data(key_list,i));
g_print("KEY : %s\n",tmp->key->str);

g_print("BITS: %d\n",tmp->bits);

if(tmp->type == AIRPCAP_KEYTYPE_WEP)
    g_print("TYPE: %s\n",AIRPCAP_WEP_KEY_STRING);
else if(tmp->type == AIRPCAP_KEYTYPE_TKIP)
    g_print("TYPE: %s\n",AIRPCAP_WPA_KEY_STRING);
else if(tmp->type == AIRPCAP_KEYTYPE_CCMP)
    g_print("TYPE: %s\n",AIRPCAP_WPA2_KEY_STRING);
else
    g_print("TYPE: %s\n","???");

g_print("SSID: %s\n",(tmp->ssid != NULL) ? tmp->ssid->str : "---");
g_print("\n");
}

g_print("\n*****************************\n\n");
}

/*
 * Retrieves a GList of decryption_key_t structures containing infos about the
 * keys for the given adapter... returns NULL if no keys are found.
 */
GList*
get_airpcap_device_keys(airpcap_if_info_t* info_if)
{
/* tmp vars */
char* tmp_key = NULL;
guint i,keys_in_list = 0;

/* real vars*/
decryption_key_t *new_key  = NULL;
GList            *key_list = NULL;

/* Number of keys in key list */
if(info_if->keysCollectionSize != 0)
    keys_in_list = (guint)(info_if->keysCollectionSize -  sizeof(AirpcapKeysCollection))/sizeof(AirpcapKey);
else
    keys_in_list = 0;

for(i=0; i<keys_in_list; i++)
{
/* Different things to do depending on the key type  */
if(info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_WEP)
    {
    /* allocate memory for the new key item */
    new_key = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

    /* fill the fields */
    /* KEY */
    tmp_key = airpcap_get_key_string(info_if->keysCollection->Keys[i]);
    new_key->key = g_string_new(tmp_key);
    g_free(tmp_key);

    /* BITS */
    new_key->bits = new_key->key->len *4; /* every char is 4 bits in WEP keys (it is an exadecimal number) */

    /* SSID not used in WEP keys */
    new_key->ssid = NULL;

    /* TYPE (WEP in this case) */
    new_key->type = info_if->keysCollection->Keys[i].KeyType;

    /* Append the new element in the list */
    key_list = g_list_append(key_list,(gpointer)new_key);
    }
else if(info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_TKIP)
    {
    /* XXX - Not supported yet */
    }
else if(info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_CCMP)
    {
    /* XXX - Not supported yet */
    }
}

return key_list;
}

/*
 * Retrieves a GList of decryption_key_t structures containing infos about the
 * keys for the global AirPcap driver... returns NULL if no keys are found.
 */
GList*
get_airpcap_driver_keys()
{
/* tmp vars */
char* tmp_key = NULL;
guint i,keys_in_list = 0;

/* real vars*/
decryption_key_t *new_key  = NULL;
GList            *key_list = NULL;

/*
 * To read the drivers general settings we need to create and use one airpcap adapter...
 * The only way to do that is to instantiate a fake adapter, and then close it and delete it.
 */
airpcap_if_info_t* fake_info_if = NULL;

/* Create the fake_info_if from the first adapter of the list */
fake_info_if = airpcap_driver_fake_if_info_new();

if(fake_info_if == NULL)
	return NULL;

/* Number of keys in key list */
if(fake_info_if->keysCollectionSize != 0)
    keys_in_list = (guint)(fake_info_if->keysCollectionSize -  sizeof(AirpcapKeysCollection))/sizeof(AirpcapKey);
else
    keys_in_list = 0;

for(i=0; i<keys_in_list; i++)
{
/* Different things to do depending on the key type  */
if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_WEP)
    {
    /* allocate memory for the new key item */
    new_key = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

    /* fill the fields */
    /* KEY */
    tmp_key = airpcap_get_key_string(fake_info_if->keysCollection->Keys[i]);
    new_key->key = g_string_new(tmp_key);
    g_free(tmp_key);

    /* BITS */
    new_key->bits = new_key->key->len *4; /* every char is 4 bits in WEP keys (it is an exadecimal number) */

    /* SSID not used in WEP keys */
    new_key->ssid = NULL;

    /* TYPE (WEP in this case) */
    new_key->type = fake_info_if->keysCollection->Keys[i].KeyType;

    /* Append the new element in the list */
    key_list = g_list_append(key_list,(gpointer)new_key);
    }
else if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_TKIP)
    {
    /* XXX - Not supported yet */
    }
else if(fake_info_if->keysCollection->Keys[i].KeyType == AIRPCAP_KEYTYPE_CCMP)
    {
    /* XXX - Not supported yet */
    }
}

airpcap_if_info_free(fake_info_if);

return key_list;
}

/*
 * Returns the list of the decryption keys specified for wireshark, NULL if
 * no key is found
 */
GList*
get_wireshark_keys()
{
keys_cb_data_t* wep_user_data = NULL;
keys_cb_data_t* wpa_user_data = NULL;
keys_cb_data_t* wpa2_user_data= NULL;

gchar *tmp = NULL;

GList* final_list = NULL;
GList* wep_final_list = NULL;
GList* wpa_final_list = NULL;
GList* wpa2_final_list = NULL;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Allocate a structure used to keep infos  between the callbacks */
wep_user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

/* Fill the structure */
wep_user_data->list = NULL;
wep_user_data->current_index = 0;
wep_user_data->number_of_keys= 0; /* Still unknown */

/* Run the callback on each 802.11 preference */
/* XXX - Right now, only WEP keys will be loaded */
prefs_pref_foreach(wlan_prefs, get_wep_key, (gpointer)wep_user_data);
prefs_pref_foreach(wlan_prefs, get_wpa_key, (gpointer)wpa_user_data);
prefs_pref_foreach(wlan_prefs, get_wpa2_key, (gpointer)wpa2_user_data);

/* Copy the list field in the user data structure pointer into the final_list */
if(wep_user_data != NULL)  wep_final_list  = wep_user_data->list;
if(wpa_user_data != NULL)  wpa_final_list  = wpa_user_data->list;
if(wpa2_user_data != NULL) wpa2_final_list = wpa2_user_data->list;

/* XXX - Merge the three lists!!!!! */
final_list = wep_final_list;

/* free the wep_user_data structure */
g_free(wep_user_data);
/* free the wpa_user_data structure */
g_free(wpa_user_data);
/* free the wpa2_user_data structure */
g_free(wpa2_user_data);

return final_list;
}

/*
 * Merges two lists of keys and return a newly created GList. If a key is
 * found multiple times, it will just appear once!
 * list1 and list 2 pointer will have to be freed manually if needed!!!
 * If the total number of keys exceeeds the maximum number allowed,
 * exceeding keys will be discarded...
 */
GList*
merge_key_list(GList* list1, GList* list2)
{
guint n1=0,n2=0;
guint i;
decryption_key_t *dk1=NULL,
                 *dk2=NULL,
                 *new_dk=NULL;

GList* merged_list = NULL;

if( (list1 == NULL) && (list2 == NULL) )
    return NULL;

if(list1 == NULL)
    {
    n1 = 0;
    n2 = g_list_length(list2);

    for(i=0;i<n2;i++)
        {
        new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
        dk2 = (decryption_key_t *)g_list_nth_data(list2,i);

        new_dk->bits = dk2->bits;
        new_dk->type = dk2->type;
        new_dk->key  = g_string_new(dk2->key->str);
        if(dk2->ssid != NULL)
            new_dk->ssid = g_string_new(dk2->ssid->str);
        else
            new_dk->ssid = NULL;

  		/* Check the total length of the merged list */
		if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
			merged_list = g_list_append(merged_list,(gpointer)new_dk);
        }
    }
else if(list2 == NULL)
    {
    n1 = g_list_length(list1);
    n2 = 0;

    for(i=0;i<n1;i++)
        {
        new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
        dk1 = (decryption_key_t*)g_list_nth_data(list1,i);

        new_dk->bits = dk1->bits;
        new_dk->type = dk1->type;
        new_dk->key  = g_string_new(dk1->key->str);
        if(dk1->ssid != NULL)
            new_dk->ssid = g_string_new(dk1->ssid->str);
        else
            new_dk->ssid = NULL;

		/* Check the total length of the merged list */
		if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
			merged_list = g_list_append(merged_list,(gpointer)new_dk);
        }
    }
else
    {
    n1 = g_list_length(list1);
    n2 = g_list_length(list2);

    /* Copy the whole list1 into merged_list */
    for(i=0;i<n1;i++)
    {
    new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
    dk1 = (decryption_key_t *)g_list_nth_data(list1,i);

    new_dk->bits = dk1->bits;
    new_dk->type = dk1->type;
    new_dk->key  = g_string_new(dk1->key->str);

    if(dk1->ssid != NULL)
        new_dk->ssid = g_string_new(dk1->ssid->str);
    else
        new_dk->ssid = NULL;

	/* Check the total length of the merged list */
	if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
		merged_list = g_list_append(merged_list,(gpointer)new_dk);
    }

    /* Look for keys that are present in list2 but aren't in list1 yet...
     * Add them to merged_list
     */
    for(i=0;i<n2;i++)
        {
        dk2 = (decryption_key_t *)g_list_nth_data(list2,i);

        if(!key_is_in_list(dk2,merged_list))
            {
            new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

            new_dk->bits = dk2->bits;
            new_dk->type = dk2->type;
            new_dk->key  = g_string_new(dk2->key->str);
            if(dk2->ssid != NULL)
                new_dk->ssid = g_string_new(dk2->ssid->str);
            else
                new_dk->ssid = NULL;

			/* Check the total length of the merged list */
			if(g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
				merged_list = g_list_append(merged_list,(gpointer)new_dk);
            }
        }
    }

return merged_list;
}

/*
 * Use this function to free a key list.
 */
void
free_key_list(GList *list)
{
guint i,n;
decryption_key_t *curr_key;

if(list == NULL)
    return;

n = g_list_length(list);

for(i = 0; i < n; i++)
{
curr_key = (decryption_key_t*)g_list_nth_data(list,i);

/* Free all the strings */
if(curr_key->key != NULL)
    g_string_free(curr_key->key,TRUE);

if(curr_key->ssid != NULL)
g_string_free(curr_key->ssid,TRUE);

/* free the decryption_key_t structure*/
g_free(curr_key);
curr_key = NULL;
}

/* Free the list */
g_list_free(list);

return;
}


/*
 * If the given key is contained in the list, returns TRUE.
 * Returns FALSE otherwise.
 */
gboolean
key_is_in_list(decryption_key_t *dk,GList *list)
{
guint i,n;
decryption_key_t* curr_key = NULL;
gboolean found = FALSE;

if( (list == NULL) || (dk == NULL) )
    return FALSE;

n = g_list_length(list);

if(n < 1)
    return FALSE;

for(i = 0; i < n; i++)
{
curr_key = (decryption_key_t*)g_list_nth_data(list,i);
if(keys_are_equals(dk,curr_key))
    found = TRUE;
}

return found;
}

/*
 * Returns TRUE if keys are equals, FALSE otherwise
 */
gboolean
keys_are_equals(decryption_key_t *k1,decryption_key_t *k2)
{

if((k1==NULL) || (k2==NULL))
    return FALSE;

if( g_string_equal(k1->key,k2->key) &&
    (k1->bits == k2->bits) && /* If the previous is TRUE, this must be TRUE as well */
    k1->type == k2->type)
    {
    /* Check the ssid... if the key type is WEP, the two fields should be NULL */
    if((k1->ssid == NULL) && (k2->ssid == NULL))
        return TRUE;

    /* Check if one of them is null and one is not... */
    if((k1->ssid == NULL) || (k2->ssid == NULL))
        return FALSE;

    /* If they are not null, they must share the same ssid */
    return g_string_equal(k1->ssid,k2->ssid);
    }

/* Some field is not equal ... */
return FALSE;
}

/*
 * Tests if two collection of keys are equal or not, to be considered equals, they have to
 * contain the same keys in the SAME ORDER! (If both lists are NULL, which means empty will
 * return TRUE)
 */
gboolean
key_lists_are_equal(GList* list1, GList* list2)
{
guint n1=0,n2=0;
guint i;
decryption_key_t *dk1=NULL,*dk2=NULL;

n1 = g_list_length(list1);
n2 = g_list_length(list2);

/*
 * Commented, because in the new AirPcap version all the keys will be saved
 * into the driver, and all the keys for every specific adapter will be
 * removed. This means that this check will always fail... and the user will
 * always be asked what to do... and it doesn't make much sense.
 */
if(n1 != n2) return FALSE;

for(i=0;i<n1;i++)
{
dk1=(decryption_key_t*)g_list_nth_data(list1,i);
dk2=(decryption_key_t*)g_list_nth_data(list2,i);

if(!g_string_equal(dk1->key,dk2->key)) return FALSE;
}

return TRUE;
}

static guint
test_if_on(pref_t *pref, gpointer ud _U_)
{
gboolean *is_on;
gboolean number;

/* Retrieve user data info */
is_on = (gboolean*)ud;


if (g_strncasecmp(pref->name, "enable_decryption", 17) == 0 && pref->type == PREF_BOOL)
    {
    number = *pref->varp.boolp;

    if(number) *is_on = TRUE;
    else *is_on = FALSE;

    return 1;
    }
return 0;
}

/*
 * Returns TRUE if the Wireshark decryption is active, false otherwise
 */
gboolean
wireshark_decryption_on()
{
gboolean is_on;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Run the callback on each 802.11 preference */
prefs_pref_foreach(wlan_prefs, test_if_on, (gpointer)&is_on);

return is_on;
}

/*
 * Returns TRUE if the AirPcap decryption for the current adapter is active, false otherwise
 */
gboolean
airpcap_decryption_on()
{
gboolean is_on = FALSE;

airpcap_if_info_t* fake_if_info = NULL;

fake_if_info = airpcap_driver_fake_if_info_new();

if(fake_if_info != NULL)
    {
    is_on = (gboolean)fake_if_info->DecryptionOn;
    }

airpcap_if_info_free(fake_if_info);

return is_on;
}

/*
 * Free an instance of airpcap_if_info_t
 */
void
airpcap_if_info_free(airpcap_if_info_t *if_info)
{
if(if_info != NULL)
	{
	if (if_info->name != NULL)
		g_free(if_info->name);

	if (if_info->description != NULL)
		g_free(if_info->description);

	if(if_info->keysCollection != NULL)
		{
		g_free(if_info->keysCollection);
		if_info->keysCollection = NULL;
		}

	if(if_info->ip_addr != NULL)
		{
		g_slist_free(if_info->ip_addr);
		if_info->ip_addr = NULL;
		}

	if(if_info != NULL)
		{
		g_free(if_info);
		if_info = NULL;
		}
	}
}

static guint
set_on_off(pref_t *pref, gpointer ud _U_)
{
gboolean *is_on;
gboolean number;

/* Retrieve user data info */
is_on = (gboolean*)ud;

if (g_strncasecmp(pref->name, "enable_decryption", 17) == 0 && pref->type == PREF_BOOL)
    {
    number = *pref->varp.boolp;

    g_free((void *)*pref->varp.boolp);
    if(*is_on)
        *pref->varp.boolp = TRUE;
    else
        *pref->varp.boolp = FALSE;

    return 1;
    }
return 0;
}

/*
 * Enables decryption for Wireshark if on_off is TRUE, disables it otherwise.
 */
void
set_wireshark_decryption(gboolean on_off)
{
gboolean is_on;

is_on = on_off;

/* Retrieve the wlan preferences */
wlan_prefs = prefs_find_module("wlan");

/* Run the callback on each 802.11 preference */
prefs_pref_foreach(wlan_prefs, set_on_off, (gpointer)&is_on);

/*
 * Signal that we've changed things, and run the 802.11 dissector's
 * callback
 */
wlan_prefs->prefs_changed = TRUE;

prefs_apply(wlan_prefs);
}

/*
 * Enables decryption for all the adapters if on_off is TRUE, disables it otherwise.
 */
gboolean
set_airpcap_decryption(gboolean on_off)
{
	/* We need to directly access the .dll functions here... */
	gchar ebuf[AIRPCAP_ERRBUF_SIZE];
	PAirpcapHandle ad,ad_driver;

	gboolean success = TRUE;

	gint n = 0;
	gint i = 0;
	airpcap_if_info_t* curr_if = NULL;
	airpcap_if_info_t* fake_if_info = NULL;

	fake_if_info = airpcap_driver_fake_if_info_new();

	if(fake_if_info == NULL)
		/* We apparently don't have any adapters installed.
		 * This isn't a failure, so return TRUE
		 */
		return TRUE;

	/* Set the driver decryption */
	ad_driver = airpcap_if_open(fake_if_info->name, ebuf);
	if(ad)
		{
		if(on_off)
			airpcap_if_set_driver_decryption_state(ad_driver,AIRPCAP_DECRYPTION_ON);
		else
			airpcap_if_set_driver_decryption_state(ad_driver,AIRPCAP_DECRYPTION_OFF);

		airpcap_if_close(ad_driver);
		}

	airpcap_if_info_free(fake_if_info);

	n = g_list_length(airpcap_if_list);

	/* Set to FALSE the decryption for all the adapters */
	/* Apply this change to all the adapters !!! */
	for(i = 0; i < n; i++)
	    {
	    curr_if = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);

	    if( curr_if != NULL )
		{
		ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list,curr_if->description), ebuf);
			if(ad)
		    {
		    curr_if->DecryptionOn = (gboolean)AIRPCAP_DECRYPTION_OFF;
			airpcap_if_set_decryption_state(ad,curr_if->DecryptionOn);
			/* Save configuration for the curr_if */
			if(!airpcap_if_store_cur_config_as_adapter_default(ad))
				{
				success = FALSE;
				}
			airpcap_if_close(ad);
		    }
		}
	    }

	return success;
}


/* DYNAMIC LIBRARY LOADER */
/*
 *  Used to dynamically load the airpcap library in order link it only when
 *  it's present on the system
 */
int load_airpcap(void)
{
BOOL base_functions = TRUE;
BOOL new_functions = TRUE;

 if((AirpcapLib =  LoadLibrary(TEXT("airpcap.dll"))) == NULL)
 {
  /* Report the error but go on */
  return AIRPCAP_DLL_NOT_FOUND;
 }
 else
 {
  if((g_PAirpcapGetLastError = (AirpcapGetLastErrorHandler) GetProcAddress(AirpcapLib, "AirpcapGetLastError")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetDeviceList = (AirpcapGetDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceList")) == NULL) base_functions = FALSE;
  if((g_PAirpcapFreeDeviceList = (AirpcapFreeDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapFreeDeviceList")) == NULL) base_functions = FALSE;
  if((g_PAirpcapOpen = (AirpcapOpenHandler) GetProcAddress(AirpcapLib, "AirpcapOpen")) == NULL) base_functions = FALSE;
  if((g_PAirpcapClose = (AirpcapCloseHandler) GetProcAddress(AirpcapLib, "AirpcapClose")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetLinkType = (AirpcapGetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapGetLinkType")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetLinkType = (AirpcapSetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapSetLinkType")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetKernelBuffer = (AirpcapSetKernelBufferHandler) GetProcAddress(AirpcapLib, "AirpcapSetKernelBuffer")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetFilter = (AirpcapSetFilterHandler) GetProcAddress(AirpcapLib, "AirpcapSetFilter")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetMacAddress = (AirpcapGetMacAddressHandler) GetProcAddress(AirpcapLib, "AirpcapGetMacAddress")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetMinToCopy = (AirpcapSetMinToCopyHandler) GetProcAddress(AirpcapLib, "AirpcapSetMinToCopy")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetReadEvent = (AirpcapGetReadEventHandler) GetProcAddress(AirpcapLib, "AirpcapGetReadEvent")) == NULL) base_functions = FALSE;
  if((g_PAirpcapRead = (AirpcapReadHandler) GetProcAddress(AirpcapLib, "AirpcapRead")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetStats = (AirpcapGetStatsHandler) GetProcAddress(AirpcapLib, "AirpcapGetStats")) == NULL) base_functions = FALSE;
  if((g_PAirpcapTurnLedOn = (AirpcapTurnLedOnHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOn")) == NULL) base_functions = FALSE;
  if((g_PAirpcapTurnLedOff = (AirpcapTurnLedOffHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOff")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetDeviceChannel = (AirpcapGetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceChannel")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetDeviceChannel = (AirpcapSetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceChannel")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetFcsPresence = (AirpcapGetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsPresence")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetFcsPresence = (AirpcapSetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsPresence")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetFcsValidation = (AirpcapGetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsValidation")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetFcsValidation = (AirpcapSetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsValidation")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetDeviceKeys = (AirpcapGetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceKeys")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetDeviceKeys = (AirpcapSetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceKeys")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetDecryptionState = (AirpcapGetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapGetDecryptionState")) == NULL) base_functions = FALSE;
  if((g_PAirpcapSetDecryptionState = (AirpcapSetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapSetDecryptionState")) == NULL) base_functions = FALSE;
  if((g_PAirpcapStoreCurConfigAsAdapterDefault = (AirpcapStoreCurConfigAsAdapterDefaultHandler) GetProcAddress(AirpcapLib, "AirpcapStoreCurConfigAsAdapterDefault")) == NULL) base_functions = FALSE;
  if((g_PAirpcapGetVersion = (AirpcapGetVersionHandler) GetProcAddress(AirpcapLib, "AirpcapGetVersion")) == NULL) base_functions = FALSE;

  /* TEST IF WE CAN FIND AIRPCAP NEW DRIVER FEATURES */
  if((g_PAirpcapGetDriverDecryptionState = (AirpcapGetDriverDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapGetDriverDecryptionState")) == NULL) new_functions = FALSE;
  if((g_PAirpcapSetDriverDecryptionState = (AirpcapSetDriverDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapSetDriverDecryptionState")) == NULL) new_functions = FALSE;
  if((g_PAirpcapGetDriverKeys = (AirpcapGetDriverKeysHandler) GetProcAddress(AirpcapLib, "AirpcapGetDriverKeys")) == NULL) new_functions = FALSE;
  if((g_PAirpcapSetDriverKeys = (AirpcapSetDriverKeysHandler) GetProcAddress(AirpcapLib, "AirpcapSetDriverKeys")) == NULL) new_functions = FALSE;

  if(base_functions)
  {
	  if(new_functions)
	  {
	  AirpcapLoaded = TRUE;
	  return AIRPCAP_DLL_OK;
	  }
	  else
	  {
	  AirpcapLoaded = TRUE;
	  return AIRPCAP_DLL_OLD;
	  }
  }
  else
  {
	  AirpcapLoaded = FALSE;
	  return AIRPCAP_DLL_ERROR;
  }
 }
}

/*
 * Append the version of AirPcap with which we were compiled to a GString.
 */
void
get_compiled_airpcap_version(GString *str)
{
	g_string_append(str, "with AirPcap");
}

/*
 * Append the version of AirPcap with which we we're running to a GString.
 */
void
get_runtime_airpcap_version(GString *str)
{
	guint vmaj, vmin, vrev, build;

	/* See if the DLL has been loaded successfully.  Bail if it hasn't */
	if (AirpcapLoaded == FALSE) {
		g_string_append(str, "without AirPcap");
		return;
	}

	g_PAirpcapGetVersion(&vmaj, &vmin, &vrev, &build);
	g_string_sprintfa(str, "with AirPcap %d.%d.%d build %d", vmaj, vmin,
		vrev, build);
}

#endif /* _WIN32 */
