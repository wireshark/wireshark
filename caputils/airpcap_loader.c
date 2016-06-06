/* airpcap_loader.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/crypt/airpdcap_ws.h>
#include <epan/strutil.h>
#include <wsutil/file_util.h>
#include <wsutil/frequency-utils.h>

#include <caputils/airpcap.h>
#include <caputils/airpcap_loader.h>


/*
 * Set to TRUE if the DLL was successfully loaded AND all functions
 * are present.
 */
static gboolean AirpcapLoaded = FALSE;

#ifdef _WIN32
/*
 * We load dynamically the dag library in order link it only when
 * it's present on the system
 */
static void * AirpcapLib = NULL;

static AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
static AirpcapSetKernelBufferHandler g_PAirpcapSetKernelBuffer;
static AirpcapSetFilterHandler g_PAirpcapSetFilter;
static AirpcapGetMacAddressHandler g_PAirpcapGetMacAddress;
static AirpcapSetMinToCopyHandler g_PAirpcapSetMinToCopy;
static AirpcapGetReadEventHandler g_PAirpcapGetReadEvent;
static AirpcapReadHandler g_PAirpcapRead;
static AirpcapGetStatsHandler g_PAirpcapGetStats;
#endif

static int AirpcapVersion = 3;

static AirpcapGetDeviceListHandler g_PAirpcapGetDeviceList;
static AirpcapFreeDeviceListHandler g_PAirpcapFreeDeviceList;
static AirpcapOpenHandler g_PAirpcapOpen;
static AirpcapCloseHandler g_PAirpcapClose;
static AirpcapGetLinkTypeHandler g_PAirpcapGetLinkType;
static AirpcapSetLinkTypeHandler g_PAirpcapSetLinkType;
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
static AirpcapSetDeviceChannelExHandler g_PAirpcapSetDeviceChannelEx;
static AirpcapGetDeviceChannelExHandler g_PAirpcapGetDeviceChannelEx;
static AirpcapGetDeviceSupportedChannelsHandler g_PAirpcapGetDeviceSupportedChannels;

/* Airpcap interface list */
GList *g_airpcap_if_list = NULL;

/* Airpcap current selected interface */
airpcap_if_info_t *airpcap_if_selected = NULL;

/* Airpcap current active interface */
airpcap_if_info_t *airpcap_if_active = NULL;

Dot11Channel *pSupportedChannels;
guint numSupportedChannels;

static AirpcapChannelInfo LegacyChannels[] =
{
    {2412, 0, {0,0,0}},
    {2417, 0, {0,0,0}},
    {2422, 0, {0,0,0}},
    {2427, 0, {0,0,0}},
    {2432, 0, {0,0,0}},
    {2437, 0, {0,0,0}},
    {2442, 0, {0,0,0}},
    {2447, 0, {0,0,0}},
    {2452, 0, {0,0,0}},
    {2457, 0, {0,0,0}},
    {2462, 0, {0,0,0}},
    {2467, 0, {0,0,0}},
    {2472, 0, {0,0,0}},
    {2484, 0, {0,0,0}},
};

static guint num_legacy_channels = 14;

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_airpcap_interface_list()".
 */
static gchar *
cant_get_airpcap_if_list_error_message(const char *err_str)
{
    return g_strdup_printf("Can't get list of Wireless interfaces: %s", err_str);
}

/*
 * Airpcap wrapper, used to store the current settings for the selected adapter
 */
gboolean
airpcap_if_store_cur_config_as_adapter_default(PAirpcapHandle ah)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapStoreCurConfigAsAdapterDefault(ah);
}

/*
 * Airpcap wrapper, used to open an airpcap adapter
 */
PAirpcapHandle
airpcap_if_open(gchar * name, gchar * err)
{
    if (!AirpcapLoaded) return NULL;
    if (name == NULL) return NULL;
    return g_PAirpcapOpen(name,err);
}

/*
 * Airpcap wrapper, used to close an airpcap adapter
 */
void
airpcap_if_close(PAirpcapHandle handle)
{
    if (!AirpcapLoaded) return;
    g_PAirpcapClose(handle);
}

/*
 * Retrieve the state of the Airpcap DLL
 */
int
airpcap_get_dll_state(void)
{
    return AirpcapVersion;
}

/*
 * Airpcap wrapper, used to turn on the led of an airpcap adapter
 */
gboolean
airpcap_if_turn_led_on(PAirpcapHandle AdapterHandle, guint LedNumber)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapTurnLedOn(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to turn off the led of an airpcap adapter
 */
gboolean
airpcap_if_turn_led_off(PAirpcapHandle AdapterHandle, guint LedNumber)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapTurnLedOff(AdapterHandle,LedNumber);
}

/*
 * Airpcap wrapper, used to get the channel of an airpcap adapter
 */
gboolean
airpcap_if_get_device_channel(PAirpcapHandle ah, guint * ch)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to get the supported channels of an airpcap adapter
 */
gboolean
airpcap_if_get_device_supported_channels(PAirpcapHandle ah, AirpcapChannelInfo **cInfo, guint * nInfo)
{
    if (!AirpcapLoaded) return FALSE;
    if (airpcap_get_dll_state() == AIRPCAP_DLL_OLD) {
        *nInfo = num_legacy_channels;
        *cInfo = (AirpcapChannelInfo*)&LegacyChannels;

        return TRUE;
    } else if (airpcap_get_dll_state() == AIRPCAP_DLL_OK) {
        return g_PAirpcapGetDeviceSupportedChannels(ah, cInfo, nInfo);
    }
    return FALSE;
}

/*
 * Airpcap wrapper, used to get the supported channels of an airpcap adapter
 */
Dot11Channel*
airpcap_if_get_device_supported_channels_array(PAirpcapHandle ah, guint * pNumSupportedChannels)
{
    AirpcapChannelInfo *chanInfo;
    guint i=0, j=0, numInfo = 0;

    if (!AirpcapLoaded)
        return NULL;
    if (airpcap_if_get_device_supported_channels(ah, &chanInfo, &numInfo) == FALSE)
        return NULL;
    numSupportedChannels = 0;

    /*
     * allocate a bigger array
     */
    if (numInfo == 0)
        return NULL;

    pSupportedChannels = (Dot11Channel *)g_malloc(numInfo * (sizeof *pSupportedChannels));

    for (i = 0; i < numInfo; i++)
    {
        guint supportedChannel = G_MAXUINT;

        /*
         * search if we have it already
         */
        for (j = 0; j < numSupportedChannels; j++)
        {
            if (pSupportedChannels[j].Frequency == chanInfo[i].Frequency)
            {
                supportedChannel = j;
                break;
            }
        }

        if (supportedChannel == G_MAXUINT)
        {
            /*
             * not found, create a new item
             */
            pSupportedChannels[numSupportedChannels].Frequency = chanInfo[i].Frequency;

            switch(chanInfo[i].ExtChannel)
            {
                case -1:
                    pSupportedChannels[numSupportedChannels].Flags = FLAG_CAN_BE_LOW;
                    break;
                case +1:
                    pSupportedChannels[numSupportedChannels].Flags = FLAG_CAN_BE_HIGH;
                    break;
                case 0:
                default:
                    pSupportedChannels[numSupportedChannels].Flags = 0;
            }

            /*
             * Gather channel information
             */

            pSupportedChannels[numSupportedChannels].Flags |=
                FREQ_IS_BG(pSupportedChannels[numSupportedChannels].Frequency) ?
                    FLAG_IS_BG_CHANNEL : FLAG_IS_A_CHANNEL;
            pSupportedChannels[numSupportedChannels].Channel =
                ieee80211_mhz_to_chan(pSupportedChannels[numSupportedChannels].Frequency);
            numSupportedChannels++;
        }
        else
        {
            /*
             * just update the ext channel flags
             */
            switch(chanInfo[i].ExtChannel)
            {
                case -1:
                    pSupportedChannels[supportedChannel].Flags |= FLAG_CAN_BE_LOW;
                    break;
                case +1:
                    pSupportedChannels[supportedChannel].Flags |= FLAG_CAN_BE_HIGH;
                    break;
                case 0:
                default:
                    break;
            }
        }
    }

    if (numSupportedChannels < 1)
        return NULL;
    /*
     * Now sort the list by frequency
     */
    for (i = 0 ; i < numSupportedChannels - 1; i++)
    {
        for (j = i + 1; j < numSupportedChannels; j++)
        {
            if (pSupportedChannels[i].Frequency > pSupportedChannels[j].Frequency)
            {
                Dot11Channel temp = pSupportedChannels[i];
                pSupportedChannels[i] = pSupportedChannels[j];
                pSupportedChannels[j] = temp;
            }
        }
    }

    *pNumSupportedChannels = numSupportedChannels;
    return pSupportedChannels;
}

/*
 * Airpcap wrapper, used to set the channel of an airpcap adapter
 */
gboolean
airpcap_if_set_device_channel(PAirpcapHandle ah, guint ch)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetDeviceChannel(ah,ch);
}

/*
 * Airpcap wrapper, used to set the frequency of an airpcap adapter
 */
gboolean
airpcap_if_set_device_channel_ex(PAirpcapHandle ah, AirpcapChannelInfo ChannelInfo)
{
    if (!AirpcapLoaded) return FALSE;
    if (airpcap_get_dll_state() == AIRPCAP_DLL_OLD){
        gint channel = 0;
        channel = ieee80211_mhz_to_chan(ChannelInfo.Frequency);

        if (channel < 0){
            return FALSE;
        } else {
            return airpcap_if_set_device_channel(ah, channel);
        }
    } else if (airpcap_get_dll_state() == AIRPCAP_DLL_OK){
        return g_PAirpcapSetDeviceChannelEx (ah, ChannelInfo);
    }

    return FALSE;
}

/*
 * Airpcap wrapper, used to get the frequency of an airpcap adapter
 */
gboolean
airpcap_if_get_device_channel_ex(PAirpcapHandle ah, PAirpcapChannelInfo pChannelInfo)
{
    if (!AirpcapLoaded) return FALSE;

    pChannelInfo->Frequency = 0;
    pChannelInfo->ExtChannel = 0;
    pChannelInfo->Reserved[0] = 0;
    pChannelInfo->Reserved[1] = 0;
    pChannelInfo->Reserved[2] = 0;

    if (airpcap_get_dll_state() == AIRPCAP_DLL_OLD){
        guint channel = 0;
        guint chan_freq = 0;

        if (!airpcap_if_get_device_channel(ah, &channel)) return FALSE;

        chan_freq = ieee80211_chan_to_mhz(channel, TRUE);
        if (chan_freq == 0) return FALSE;
        pChannelInfo->Frequency = chan_freq;

        return TRUE;
    } else if (airpcap_get_dll_state() == AIRPCAP_DLL_OK){
        return g_PAirpcapGetDeviceChannelEx (ah, pChannelInfo);
    }
    return FALSE;
}

/*
 * Airpcap wrapper, used to get the link type of an airpcap adapter
 */
gboolean
airpcap_if_get_link_type(PAirpcapHandle ah, PAirpcapLinkType lt)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to set the link type of an airpcap adapter
 */
gboolean
airpcap_if_set_link_type(PAirpcapHandle ah, AirpcapLinkType lt)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetLinkType(ah,lt);
}

/*
 * Airpcap wrapper, used to get the fcs presence of an airpcap adapter
 */
gboolean
airpcap_if_get_fcs_presence(PAirpcapHandle ah, gboolean * fcs)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to set the fcs presence of an airpcap adapter
 */
gboolean
airpcap_if_set_fcs_presence(PAirpcapHandle ah, gboolean fcs)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetFcsPresence(ah,fcs);
}

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap adapter
 */
gboolean
airpcap_if_get_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetDecryptionState(ah,PEnable);
}

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap adapter
 */
gboolean
airpcap_if_set_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetDecryptionState(ah,Enable);
}

/*
 * Airpcap wrapper, used to get the decryption enabling of an airpcap driver
 */
gboolean
airpcap_if_get_driver_decryption_state(PAirpcapHandle ah, PAirpcapDecryptionState PEnable)
{
    if (!AirpcapLoaded || (g_PAirpcapGetDriverDecryptionState==NULL)) return FALSE;
    return g_PAirpcapGetDriverDecryptionState(ah,PEnable);
}

/*
 * Airpcap wrapper, used to set the decryption enabling of an airpcap driver
 */
gboolean
airpcap_if_set_driver_decryption_state(PAirpcapHandle ah, AirpcapDecryptionState Enable)
{
    if (!AirpcapLoaded || (g_PAirpcapSetDriverDecryptionState==NULL)) return FALSE;
    return g_PAirpcapSetDriverDecryptionState(ah,Enable);
}

/*
 * Airpcap wrapper, used to get the fcs validation of an airpcap adapter
 */
gboolean
airpcap_if_get_fcs_validation(PAirpcapHandle ah, PAirpcapValidationType val)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to set the fcs validation of an airpcap adapter
 */
gboolean
airpcap_if_set_fcs_validation(PAirpcapHandle ah, AirpcapValidationType val)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetFcsValidation(ah,val);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_set_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapSetDeviceKeys(AdapterHandle,KeysCollection);
}

/*
 * Airpcap wrapper, used to save the settings for the selected_if
 */
gboolean
airpcap_if_get_device_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize)
{
    if (!AirpcapLoaded) return FALSE;
    return g_PAirpcapGetDeviceKeys(AdapterHandle,KeysCollection,PKeysCollectionSize);
}

/*
 * Airpcap wrapper, used to save the driver's set of keys
 */
gboolean
airpcap_if_set_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection)
{
    if (!AirpcapLoaded || (g_PAirpcapSetDriverKeys==NULL)) return FALSE;
    return g_PAirpcapSetDriverKeys(AdapterHandle,KeysCollection);
}

/*
 * Airpcap wrapper, used to load the driver's set of keys
 */
gboolean
airpcap_if_get_driver_keys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, guint * PKeysCollectionSize)
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

    airpcap_if_info_t *if_info = NULL;

    /* Probably I have to switch on the leds!!! */
    ad = airpcap_if_open(name, ebuf);
    if (ad)
    {
        if_info = (airpcap_if_info_t *)g_malloc0(sizeof (airpcap_if_info_t));
        if_info->name = g_strdup(name);
        if (description == NULL){
            if_info->description = NULL;
        }else{
            if_info->description = g_strdup(description);
        }

        if_info->ip_addr = NULL;
        if_info->loopback = FALSE;
        airpcap_if_get_fcs_validation(ad,&(if_info->CrcValidationOn));
        airpcap_if_get_fcs_presence(ad,&(if_info->IsFcsPresent));
        airpcap_if_get_link_type(ad,&(if_info->linkType));
        airpcap_if_get_device_channel_ex(ad,&(if_info->channelInfo));
        if_info->pSupportedChannels = airpcap_if_get_device_supported_channels_array(ad, &(if_info->numSupportedChannels));
        airpcap_if_turn_led_on(ad, 0);
        airpcap_if_get_decryption_state(ad, &(if_info->DecryptionOn));
        if_info->led = TRUE;
        if_info->blinking = FALSE;
        if_info->saved = TRUE; /* NO NEED TO BE SAVED */

        /* get the keys, if everything is ok, close the adapter */
        if (airpcap_if_load_keys(ad,if_info))
        {
            airpcap_if_close(ad);
        }
    }
    return if_info;
}

/*
 * This function will create a new fake drivers' interface, to load global keys...
 */
airpcap_if_info_t*
airpcap_driver_fake_if_info_new(void)
{
    PAirpcapHandle ad;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];

    airpcap_if_info_t *if_info = NULL;
    airpcap_if_info_t *fake_if_info = NULL;

    /* Maybe for some reason no airpcap adapter is found */
    if (g_airpcap_if_list == NULL)
        return NULL;

    /*
     * Retrieve the first AirPcap adapter available. If no interface is found,
     * it is not possible to retrieve the driver's settings, so return NULL.
     */
    if_info = (airpcap_if_info_t *)g_list_nth_data(g_airpcap_if_list,0);
    if (if_info == NULL)
        return NULL;

    /* Open the 'fake' adapter */
    ad = airpcap_if_open(if_info->name, ebuf);
    if (ad)
    {
        fake_if_info = (airpcap_if_info_t *)g_malloc(sizeof (airpcap_if_info_t));
        fake_if_info->name = g_strdup(if_info->name);
        fake_if_info->description = g_strdup(if_info->description);
        fake_if_info->loopback = FALSE;
        fake_if_info->ip_addr = NULL;
        airpcap_if_get_driver_decryption_state(ad, &(fake_if_info->DecryptionOn));
        airpcap_if_get_fcs_validation(ad,&(fake_if_info->CrcValidationOn));
        airpcap_if_get_fcs_presence(ad,&(fake_if_info->IsFcsPresent));
        airpcap_if_get_link_type(ad,&(fake_if_info->linkType));
        airpcap_if_get_device_channel_ex(ad,&(fake_if_info->channelInfo));
        airpcap_if_turn_led_on(ad, 0);
        fake_if_info->led = TRUE;
        fake_if_info->blinking = FALSE;
        fake_if_info->saved = TRUE; /* NO NEED TO BE SAVED */

        /* get the keys, if everything is ok, close the adapter */
        if (airpcap_if_load_driver_keys(ad,fake_if_info))
        {
            airpcap_if_close(ad);
        }
    }

    return fake_if_info;
}

#ifdef AIRPCAP_DEBUG
/*
 * USED FOR DEBUG ONLY... PRINTS AN AirPcap ADAPTER STRUCTURE in a fancy way.
 */
void
airpcap_if_info_print(airpcap_if_info_t* if_info)
{
    guint i;
    if (if_info == NULL)
    {
        g_print("\nWARNING : AirPcap Interface pointer is NULL!\n");
        return;
    }

    g_print("\n----------------- AirPcap Interface \n");
    g_print("                      NAME: %s\n",if_info->name);
    g_print("               DESCRIPTION: %s\n",if_info->description);
    g_print("                  BLINKING: %s\n",if_info->blinking ? "TRUE" : "FALSE");
    g_print("     channelInfo.Frequency: %u\n",if_info->channelInfo.Frequency);
    g_print("    channelInfo.ExtChannel: %d\n",if_info->channelInfo.ExtChannel);
    g_print("             CRCVALIDATION: %s\n",if_info->CrcValidationOn ? "ON" : "OFF");
    g_print("                DECRYPTION: %s\n",if_info->DecryptionOn ? "ON" : "OFF");
    g_print("                   IP ADDR: %s\n",if_info->ip_addr!=NULL ? "NOT NULL" : "NULL");
    g_print("                FCSPRESENT: %s\n",if_info->IsFcsPresent ? "TRUE" : "FALSE");
    g_print("            KEYSCOLLECTION: %s\n",if_info->keysCollection!=NULL ? "NOT NULL" : "NULL");
    g_print("        KEYSCOLLECTIONSIZE: %u\n",if_info->keysCollectionSize);
    g_print("                       LED: %s\n",if_info->led ? "ON" : "OFF");
    g_print("                  LINKTYPE: %d\n",if_info->linkType);
    g_print("                  LOOPBACK: %s\n",if_info->loopback ? "YES" : "NO");
    g_print("                 (GTK) TAG: %d\n",if_info->tag);
    g_print("SUPPORTED CHANNELS POINTER: %p\n",if_info->pSupportedChannels);
    g_print("    NUM SUPPORTED CHANNELS: %u\n",if_info->numSupportedChannels);

    for(i=0; i<(if_info->numSupportedChannels); i++){
        g_print("\n        SUPPORTED CHANNEL #%u\n",i+1);
        g_print("                   CHANNEL: %u\n",if_info->pSupportedChannels[i].Channel);
        g_print("                 FREQUENCY: %u\n",if_info->pSupportedChannels[i].Frequency);
        g_print("                     FLAGS: %u\n",if_info->pSupportedChannels[i].Flags);
    }
    g_print("\n\n");
}
#endif /* AIRPCAP_DEBUG */

/*
 * Function used to load the WEP keys for a selected interface
 */
gboolean
airpcap_if_load_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
    if (!if_info) return FALSE;

    if_info->keysCollectionSize = 0;
    if_info->keysCollection = NULL;

    if (!airpcap_if_get_device_keys(ad, NULL, &(if_info->keysCollectionSize)))
    {
        if (if_info->keysCollectionSize == 0)
        {
            if_info->keysCollection = NULL;
            airpcap_if_close(ad);
            return FALSE;
        }

        if_info->keysCollection = (PAirpcapKeysCollection)g_malloc(if_info->keysCollectionSize);
        if (!if_info->keysCollection)
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
gboolean
airpcap_if_load_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
    if_info->keysCollectionSize = 0;
    if_info->keysCollection = NULL;

    if (!airpcap_if_get_driver_keys(ad, NULL, &(if_info->keysCollectionSize)))
    {
        if (if_info->keysCollectionSize == 0)
        {
            if_info->keysCollection = NULL;
            airpcap_if_close(ad);
            return FALSE;
        }

        if_info->keysCollection = (PAirpcapKeysCollection)g_malloc(if_info->keysCollectionSize);
        if (!if_info->keysCollection)
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
    if (!if_info || !AirpcapLoaded) return;

    if (if_info->keysCollection != NULL)
        g_PAirpcapSetDeviceKeys(ad,if_info->keysCollection);
}

/*
 * Function used to save the WEP keys for a selected interface
 */
void
airpcap_if_save_driver_keys(PAirpcapHandle ad, airpcap_if_info_t *if_info)
{
    if (if_info->keysCollection != NULL)
        airpcap_if_set_driver_keys(ad,if_info->keysCollection);
}

/*
 * Callback used to free an instance of airpcap_if_info_t
 */
static void
free_airpcap_if_cb(gpointer data, gpointer user_data _U_)
{
    airpcap_if_info_t *if_info = (airpcap_if_info_t *)data;

    if (NULL == if_info)
        return;

    if (if_info->name != NULL)
        g_free(if_info->name);

    if (if_info->description != NULL)
        g_free(if_info->description);

    /* XXX - FREE THE WEP KEY LIST HERE!!!*/
    if (if_info->keysCollection != NULL)
    {
        g_free(if_info->keysCollection);
        if_info->keysCollection = NULL;
    }

    if (if_info->ip_addr != NULL)
        g_slist_free(if_info->ip_addr);

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
}

/*
 * This function will use the airpcap.dll to find all the airpcap devices.
 * Will return null if no device is found.
 */
GList*
get_airpcap_interface_list(int *err, char **err_str)
{
    GList  *il = NULL;
    airpcap_if_info_t *if_info;
    int n_adapts;
    AirpcapDeviceDescription *devsList, *adListEntry;
    char errbuf[AIRPCAP_ERRBUF_SIZE];

    *err = 0;

    if (!AirpcapLoaded)
    {
        *err = AIRPCAP_NOT_LOADED;
        return il;
    }

    if (!g_PAirpcapGetDeviceList(&devsList, errbuf))
    {
        /* No interfaces, return il = NULL; */
        *err = CANT_GET_AIRPCAP_INTERFACE_LIST;
        if (err_str != NULL)
            *err_str = cant_get_airpcap_if_list_error_message(errbuf);
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

    if (n_adapts == 0)
    {
        /* No interfaces, return il= NULL */
        g_PAirpcapFreeDeviceList(devsList);
        *err = NO_AIRPCAP_INTERFACES_FOUND;
        if (err_str != NULL)
            *err_str = NULL;
        return il;
    }

    /*
     * Insert the adapters in our list
     */
    adListEntry = devsList;
    while(adListEntry)
    {
        if_info = airpcap_if_info_new(adListEntry->Name, adListEntry->Description);
        if (if_info != NULL){
            il = g_list_append(il, if_info);
        }

        adListEntry = adListEntry->next;
    }

    g_PAirpcapFreeDeviceList(devsList);

    return il;
}

/*
 * Used to retrieve the interface given the name
 * (the name is used in AirpcapOpen)
 */
airpcap_if_info_t* get_airpcap_if_from_name(GList* if_list, const gchar* name)
{
    GList* curr;
    airpcap_if_info_t* if_info;

    for (curr = g_list_first(if_list); curr; curr = g_list_next(curr)) {
        if_info = (airpcap_if_info_t *)curr->data;
        if (if_info && (g_ascii_strcasecmp(if_info->name, name) == 0)) {
            return (if_info);
        }
        /* Try the name without the "\\.\" prefix. */
        if (strlen(if_info->name) > 4 && (g_ascii_strcasecmp(if_info->name + 4, name) == 0)) {
            return (if_info);
        }
    }
    return (NULL);
}

/*
 * Clear keys and decryption status for the specified interface
 */
void
airpcap_if_clear_decryption_settings(airpcap_if_info_t* info_if)
{
    if (info_if != NULL)
    {
        if (info_if->keysCollection != NULL)
        {
            g_free(info_if->keysCollection);
            info_if->keysCollection = NULL;
        }

        info_if->keysCollectionSize = 0;

        info_if->DecryptionOn = AIRPCAP_DECRYPTION_OFF;
        info_if->saved = FALSE;
    }
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
    if (a == 0)
    {
        if (g_ascii_strcasecmp(if_info->name,AIRPCAP_DEVICE_ANY_EXTRACT_STRING)!=0)
            number = g_strdup("??");
        else
            number = g_strdup(AIRPCAP_CHANNEL_ANY_NAME);
    }
    else
    {
        number = g_strdup_printf("%.2u",n);
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
 * Load the configuration for the specified interface
 */
void
airpcap_load_selected_if_configuration(airpcap_if_info_t* if_info)
{
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];
    PAirpcapHandle ad;

    if (if_info != NULL)
    {
        ad = airpcap_if_open(if_info->name, ebuf);

        if (ad)
        {
            /* Stop blinking (if it was blinking!)*/
            if (if_info->blinking)
            {
                /* Turn on the light (if it was off) */
                if (!(if_info->led)) airpcap_if_turn_led_on(ad, 0);
            }

            /* Apply settings... */
            airpcap_if_get_device_channel_ex(ad,&(if_info->channelInfo));
            airpcap_if_get_fcs_validation(ad,&(if_info->CrcValidationOn));
            airpcap_if_get_fcs_presence(ad,&(if_info->IsFcsPresent));
            airpcap_if_get_link_type(ad,&(if_info->linkType));
            airpcap_if_get_decryption_state(ad, &(if_info->DecryptionOn));
            /* get the keys, if everything is ok, close the adapter */
            if (airpcap_if_load_keys(ad,if_info))
                airpcap_if_close(ad);

            if_info->saved = TRUE;
        }
#if 0
        else
        {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",if_info->description);
        }
#endif
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

    if (if_info != NULL)
    {
        ad = airpcap_if_open(if_info->name, ebuf);

        if (ad)
        {
            /* Stop blinking (if it was blinking!)*/
            if (if_info->blinking)
            {
                /* Turn on the light (if it was off) */
                if (!(if_info->led)) airpcap_if_turn_led_on(ad, 0);
            }

            /* Apply settings... */
            airpcap_if_set_device_channel_ex(ad,if_info->channelInfo);
            airpcap_if_set_fcs_validation(ad,if_info->CrcValidationOn);
            airpcap_if_set_fcs_presence(ad,if_info->IsFcsPresent);
            airpcap_if_set_link_type(ad,if_info->linkType);
            airpcap_if_set_decryption_state(ad, if_info->DecryptionOn);
            airpcap_if_save_keys(ad,if_info);

            /* ... and save them */
            if (!airpcap_if_store_cur_config_as_adapter_default(ad))
            {
#if 0
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save Wireless configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
#endif
                if_info->saved = FALSE;
                airpcap_if_close(ad);
                return;
            }

            if_info->saved = TRUE;
            airpcap_if_close(ad);
        }
#if 0
        else
        {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",if_info->description);
        }
#endif
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

    if (fake_if_info != NULL)
    {
        ad = airpcap_if_open(fake_if_info->name, ebuf);

        if (ad)
        {
            /* Apply decryption settings... */
            airpcap_if_set_driver_decryption_state(ad, fake_if_info->DecryptionOn);
            airpcap_if_save_driver_keys(ad,fake_if_info);
            airpcap_if_close(ad);
        }
#if 0
        else
        {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, " Error in opening adapter for %s",fake_if_info->description);
        }
#endif
    }

    return;
}

/*
 * Free an instance of airpcap_if_info_t
 */
void
airpcap_if_info_free(airpcap_if_info_t *if_info)
{
    if (if_info != NULL)
    {
        if (if_info->name != NULL)
            g_free(if_info->name);

        if (if_info->description != NULL)
            g_free(if_info->description);

        if (if_info->keysCollection != NULL)
        {
            g_free(if_info->keysCollection);
            if_info->keysCollection = NULL;
        }

        if (if_info->ip_addr != NULL)
        {
            g_slist_free(if_info->ip_addr);
            if_info->ip_addr = NULL;
        }

        if (if_info != NULL)
        {
            g_free(if_info);
        }
    }
}


/* DYNAMIC LIBRARY LOADER */
/*
 *  Used to dynamically load the airpcap library in order link it only when
 *  it's present on the system
 */
int load_airpcap(void)
{
#ifdef _WIN32
    gboolean base_functions     = TRUE;
    gboolean eleven_n_functions = TRUE;

    if ((AirpcapLib = ws_load_library("airpcap.dll")) == NULL)
    {
        /* Report the error but go on */
        AirpcapVersion = AIRPCAP_DLL_NOT_FOUND;
        return AirpcapVersion;
    }
    else
    {
        if ((g_PAirpcapGetLastError = (AirpcapGetLastErrorHandler) GetProcAddress(AirpcapLib, "AirpcapGetLastError")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetDeviceList = (AirpcapGetDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceList")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapFreeDeviceList = (AirpcapFreeDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapFreeDeviceList")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapOpen = (AirpcapOpenHandler) GetProcAddress(AirpcapLib, "AirpcapOpen")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapClose = (AirpcapCloseHandler) GetProcAddress(AirpcapLib, "AirpcapClose")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetLinkType = (AirpcapGetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapGetLinkType")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetLinkType = (AirpcapSetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapSetLinkType")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetKernelBuffer = (AirpcapSetKernelBufferHandler) GetProcAddress(AirpcapLib, "AirpcapSetKernelBuffer")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetFilter = (AirpcapSetFilterHandler) GetProcAddress(AirpcapLib, "AirpcapSetFilter")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetMacAddress = (AirpcapGetMacAddressHandler) GetProcAddress(AirpcapLib, "AirpcapGetMacAddress")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetMinToCopy = (AirpcapSetMinToCopyHandler) GetProcAddress(AirpcapLib, "AirpcapSetMinToCopy")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetReadEvent = (AirpcapGetReadEventHandler) GetProcAddress(AirpcapLib, "AirpcapGetReadEvent")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapRead = (AirpcapReadHandler) GetProcAddress(AirpcapLib, "AirpcapRead")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetStats = (AirpcapGetStatsHandler) GetProcAddress(AirpcapLib, "AirpcapGetStats")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapTurnLedOn = (AirpcapTurnLedOnHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOn")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapTurnLedOff = (AirpcapTurnLedOffHandler) GetProcAddress(AirpcapLib, "AirpcapTurnLedOff")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetDeviceChannel = (AirpcapGetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceChannel")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetDeviceChannel = (AirpcapSetDeviceChannelHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceChannel")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetFcsPresence = (AirpcapGetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsPresence")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetFcsPresence = (AirpcapSetFcsPresenceHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsPresence")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetFcsValidation = (AirpcapGetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapGetFcsValidation")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetFcsValidation = (AirpcapSetFcsValidationHandler) GetProcAddress(AirpcapLib, "AirpcapSetFcsValidation")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetDeviceKeys = (AirpcapGetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceKeys")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetDeviceKeys = (AirpcapSetDeviceKeysHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceKeys")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetDecryptionState = (AirpcapGetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapGetDecryptionState")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetDecryptionState = (AirpcapSetDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapSetDecryptionState")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapStoreCurConfigAsAdapterDefault = (AirpcapStoreCurConfigAsAdapterDefaultHandler) GetProcAddress(AirpcapLib, "AirpcapStoreCurConfigAsAdapterDefault")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetVersion = (AirpcapGetVersionHandler) GetProcAddress(AirpcapLib, "AirpcapGetVersion")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetDriverDecryptionState = (AirpcapGetDriverDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapGetDriverDecryptionState")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetDriverDecryptionState = (AirpcapSetDriverDecryptionStateHandler) GetProcAddress(AirpcapLib, "AirpcapSetDriverDecryptionState")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapGetDriverKeys = (AirpcapGetDriverKeysHandler) GetProcAddress(AirpcapLib, "AirpcapGetDriverKeys")) == NULL) base_functions = FALSE;
        if ((g_PAirpcapSetDriverKeys = (AirpcapSetDriverKeysHandler) GetProcAddress(AirpcapLib, "AirpcapSetDriverKeys")) == NULL) base_functions = FALSE;

        /* TEST IF AIRPCAP SUPPORTS 11N */
        if ((g_PAirpcapSetDeviceChannelEx = (AirpcapSetDeviceChannelExHandler) GetProcAddress(AirpcapLib, "AirpcapSetDeviceChannelEx")) == NULL) eleven_n_functions = FALSE;
        if ((g_PAirpcapGetDeviceChannelEx = (AirpcapGetDeviceChannelExHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceChannelEx")) == NULL) eleven_n_functions = FALSE;
        if ((g_PAirpcapGetDeviceSupportedChannels = (AirpcapGetDeviceSupportedChannelsHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceSupportedChannels")) == NULL) eleven_n_functions = FALSE;

        if (base_functions && eleven_n_functions){
            AirpcapLoaded = TRUE;
            AirpcapVersion = AIRPCAP_DLL_OK;
        } else if (base_functions){
            AirpcapLoaded = TRUE;
            AirpcapVersion = AIRPCAP_DLL_OLD;
            return AIRPCAP_DLL_OK;
        }else{
            AirpcapLoaded = FALSE;
            AirpcapVersion = AIRPCAP_DLL_ERROR;
        }
    }
    return AirpcapVersion;
#else /* _WIN32 */
    return AIRPCAP_DLL_NOT_FOUND;
#endif /* _WIN32 */
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
    g_string_append_printf(str, "with AirPcap %d.%d.%d build %d", vmaj, vmin,
        vrev, build);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
