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

#include "capture_ui_utils.h"
#include <epan/prefs.h>

#include "simple_dialog.h"

#include <airpcap.h>
#include "airpcap_loader.h"

/*
 * We load dinamically the dag library in order link it only when
 * it's present on the system
 */
static HMODULE AirpcapLib;

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
static AirpcapGetDecryptionStateHandler g_PAirpcapGetDecryptionState;
static AirpcapSetDecryptionStateHandler g_PAirpcapSetDecryptionState;
static AirpcapStoreCurConfigAsAdapterDefaultHandler g_PAirpcapStoreCurConfigAsAdapterDefault;

/* Airpcap interface list */
GList *airpcap_if_list = NULL;

/* Airpcap current selected interface */
airpcap_if_info_t *airpcap_if_selected = NULL;

/* Airpcap current active interface */
airpcap_if_info_t *airpcap_if_active = NULL;

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
	return g_PAirpcapStoreCurConfigAsAdapterDefault(ah);
}

/*
 * Airpcap wrapper, used to open an airpcap adapter
 */
PAirpcapHandle
airpcap_if_open(PCHAR name, PCHAR err)
{
	return g_PAirpcapOpen(name,err);
}

/*
 * Airpcap wrapper, used to close an airpcap adapter
 */
VOID
airpcap_if_close(PAirpcapHandle handle)
{
g_PAirpcapClose(handle);

}

/*
 * Airpcap wrapper, used to turn on the led of an airpcap adapter
 */
BOOL
airpcap_if_turn_led_on(PAirpcapHandle AdapterHandle, UINT LedNumber)
{
	return g_PAirpcapTurnLedOn(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to turn off the led of an airpcap adapter
 */
BOOL
airpcap_if_turn_led_off(PAirpcapHandle AdapterHandle, UINT LedNumber)
{
	return g_PAirpcapTurnLedOff(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to get the channel of an airpcap adapter
 */
BOOL
airpcap_if_get_device_channel(PAirpcapHandle ah, PUINT ch)
{
	return g_PAirpcapGetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to set the channel of an airpcap adapter
 */
BOOL
airpcap_if_set_device_channel(PAirpcapHandle ah, UINT ch)
{
	return g_PAirpcapSetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to get the link type of an airpcap adapter
 */
BOOL
airpcap_if_get_link_type(PAirpcapHandle ah, PAirpcapLinkType lt)
{
	return g_PAirpcapGetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to set the link type of an airpcap adapter
 */
BOOL
airpcap_if_set_link_type(PAirpcapHandle ah, AirpcapLinkType lt)
{
	return g_PAirpcapSetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to get the fcs presence of an airpcap adapter
 */
BOOL
airpcap_if_get_fcs_presence(PAirpcapHandle ah, PBOOL fcs)
{
	return g_PAirpcapGetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to set the fcs presence of an airpcap adapter
 */
BOOL
airpcap_if_set_fcs_presence(PAirpcapHandle ah, BOOL fcs)
{
	return g_PAirpcapSetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap adapter
 */
BOOL
airpcap_if_get_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable)
{
	return g_PAirpcapGetDecryptionState(ah,PEnable);
}

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap adapter
 */
BOOL
airpcap_if_set_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable)
{
	return g_PAirpcapSetDecryptionState(ah,Enable);
}

/*
 * Airpcap wrapper, used to get the fcs validation of an airpcap adapter
 */
BOOL
airpcap_if_get_fcs_validation(PAirpcapHandle ah, PAirpcapValidationType val)
{
	return g_PAirpcapGetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to set the fcs validation of an airpcap adapter
 */
BOOL
airpcap_if_set_fcs_validation(PAirpcapHandle ah, AirpcapValidationType val)
{
	return g_PAirpcapSetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_set_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection)
{
	return g_PAirpcapSetDeviceKeys(AdapterHandle,KeysCollection);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
BOOL
airpcap_if_get_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize)
{
	return g_PAirpcapGetDeviceKeys(AdapterHandle,KeysCollection,PKeysCollectionSize);
}

/*
 * This function will create a new airpcap_if_info_t using a name and a description
 */
airpcap_if_info_t *
airpcap_if_info_new(char *name, char *description)
{
PAirpcapHandle ad;
char* ebuf = NULL;

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
 * Function used to load the WEP keys for a selected interface
 */
BOOL
airpcap_if_load_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
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

	if_info->keysCollection = (PAirpcapKeysCollection)malloc(if_info->keysCollectionSize);
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
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
	if(if_info->keysCollection != NULL)
		g_PAirpcapSetDeviceKeys(ad,if_info->keysCollection);
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
		g_free(if_info->keysCollection);

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

	if(!g_PAirpcapGetDeviceList(&devsList, err_str))
	{
		/* No interfaces, return il = NULL; */
		*err = NO_AIRPCAP_INTERFACES_FOUND;
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
		*err = NO_AIRPCAP_INTERFACES_FOUND;
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
 * Returns the ASCII string of a key given the key bites
 */
gchar*
airpcap_get_key_string(AirpcapKey key)
{
unsigned int j = 0;
gchar *s,*s1;

s = NULL;
s1 = NULL;

if(key.KeyType == AIRPCAP_KEYTYPE_WEP)
	{
	s = g_strdup_printf("");
	for(j = 0; j < key.KeyLen != 0; j++)
		{
		s1 = g_strdup_printf("%.2x", key.KeyData[j]);
		g_strlcat(s,s1,WEP_KEY_MAX_SIZE);
		}
	}
return s;
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

	number = g_strdup_printf("%.2u\0",n);

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
 *  Used to dinamically load the airpcap library in order link it only when
 *  it's present on the system
 */
BOOL load_airpcap(void)
{
 if((AirpcapLib =  LoadLibrary(TEXT("airpcap.dll"))) == NULL)
 {
  /* Report the error but go on */
  return FALSE;
 }
 else
 {
  if((g_PAirpcapGetLastError = (AirpcapGetLastErrorHandler) GetProcAddress(AirpcapLib, "AirpcapGetLastError")) == NULL) return FALSE;
  if((g_PAirpcapGetDeviceList = (AirpcapGetDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceList")) == NULL) return FALSE;
  if((g_PAirpcapFreeDeviceList = (AirpcapFreeDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapFreeDeviceList")) == NULL) return FALSE;
  if((g_PAirpcapOpen = (AirpcapOpenHandler) GetProcAddress(AirpcapLib, "AirpcapOpen")) == NULL) return FALSE;
  if((g_PAirpcapClose = (AirpcapCloseHandler) GetProcAddress(AirpcapLib, "AirpcapClose")) == NULL) return FALSE;
  if((g_PAirpcapGetLinkType = (AirpcapGetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapGetLinkType")) == NULL) return FALSE;
  if((g_PAirpcapSetLinkType = (AirpcapSetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapSetLinkType")) == NULL) return FALSE;
  if((g_PAirpcapSetKernelBuffer = (AirpcapSetKernelBufferHandler) GetProcAddress(AirpcapLib, "AirpcapSetKernelBuffer")) == NULL) return FALSE;
  if((g_PAirpcapSetFilter = (AirpcapSetFilterHandler) GetProcAddress(AirpcapLib, "AirpcapSetFilter")) == NULL) return FALSE;
  if((g_PAirpcapGetMacAddress = (AirpcapGetMacAddressHandler) GetProcAddress(AirpcapLib, "AirpcapGetMacAddress")) == NULL) return FALSE;
  if((g_PAirpcapSetMinToCopy = (AirpcapSetMinToCopyHandler) GetProcAddress(AirpcapLib, "AirpcapSetMinToCopy")) == NULL) return FALSE;
  if((g_PAirpcapGetReadEvent = (AirpcapGetReadEventHandler) GetProcAddress(AirpcapLib, "AirpcapGetReadEvent")) == NULL) return FALSE;
  if((g_PAirpcapRead = (AirpcapReadHandler) GetProcAddress(AirpcapLib, "AirpcapRead")) == NULL) return FALSE;
  if((g_PAirpcapGetStats = (AirpcapGetStatsHandler) GetProcAddress(AirpcapLib, "AirpcapGetStats")) == NULL) return FALSE;
  if((g_PAirpcapTurnLedOn = (AirpcapTurnLedOnHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOn")) == NULL) return FALSE;
  if((g_PAirpcapTurnLedOff = (AirpcapTurnLedOffHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOff")) == NULL) return FALSE;
  if((g_PAirpcapGetDeviceChannel = (AirpcapGetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceChannel")) == NULL) return FALSE;
  if((g_PAirpcapSetDeviceChannel = (AirpcapSetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceChannel")) == NULL) return FALSE;
  if((g_PAirpcapGetFcsPresence = (AirpcapGetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsPresence")) == NULL) return FALSE;
  if((g_PAirpcapSetFcsPresence = (AirpcapSetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsPresence")) == NULL) return FALSE;
  if((g_PAirpcapGetFcsValidation = (AirpcapGetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsValidation")) == NULL) return FALSE;
  if((g_PAirpcapSetFcsValidation = (AirpcapSetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsValidation")) == NULL) return FALSE;
  if((g_PAirpcapGetDeviceKeys = (AirpcapGetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceKeys")) == NULL) return FALSE;
  if((g_PAirpcapSetDeviceKeys = (AirpcapSetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceKeys")) == NULL) return FALSE;
  if((g_PAirpcapGetDecryptionState = (AirpcapGetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapGetDecryptionState")) == NULL) return FALSE;
  if((g_PAirpcapSetDecryptionState = (AirpcapSetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapSetDecryptionState")) == NULL) return FALSE;
  if((g_PAirpcapStoreCurConfigAsAdapterDefault = (AirpcapStoreCurConfigAsAdapterDefaultHandler) GetProcAddress(AirpcapLib, "AirpcapStoreCurConfigAsAdapterDefault")) == NULL) return FALSE;
  return TRUE;
 }
}

#endif /* _WIN32 */
