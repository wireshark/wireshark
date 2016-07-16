/* airpcap_gui_utils.c
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

#include <gtk/gtk.h>
#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wsutil/filesystem.h>
#include <wsutil/frequency-utils.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/uat-int.h>
#include <epan/strutil.h>
#include <epan/crypt/airpdcap_ws.h>
#include <epan/crypt/wep-wpadefs.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-ieee80211.h>

#include "ui/capture_ui_utils.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/main.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dfilter_expr_dlg.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/old-gtk-compat.h"

#include <caputils/airpcap.h>
#include <caputils/airpcap_loader.h>
#include "airpcap_gui_utils.h"


/* Controls the releay of settings back to the adapter. */
gboolean change_airpcap_settings = FALSE;

/* WLAN preferences pointer */
module_t *wlan_prefs = NULL;

/*
 * Set up the airpcap toolbar for the new capture interface
 */
void
airpcap_set_toolbar_start_capture(airpcap_if_info_t* if_info)
{
    GtkWidget *airpcap_toolbar_label;
    GtkWidget *toolbar_channel_cb;
    GtkWidget *airpcap_toolbar_channel_lb;
    GtkWidget *airpcap_toolbar_channel_offset;
    GtkWidget *airpcap_toolbar_channel_offset_lb;
    GtkWidget *airpcap_toolbar_button;
    GtkWidget *airpcap_toolbar_fcs;
    GtkWidget *airpcap_toolbar_fcs_lb;
    GtkWidget *airpcap_toolbar_decryption;
    GtkWidget *airpcap_toolbar_decryption_lb;
    GtkWidget *airpcap_toolbar_keys_button;

    gchar *if_label_text;

    airpcap_toolbar_label              = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_INTERFACE_KEY);
    toolbar_channel_cb                 = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_KEY);
    airpcap_toolbar_channel_lb         = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
    airpcap_toolbar_channel_offset     = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY);
    airpcap_toolbar_channel_offset_lb  = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY);
    airpcap_toolbar_fcs                = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    airpcap_toolbar_fcs_lb             = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
    airpcap_toolbar_button             = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_ADVANCED_KEY);
    airpcap_toolbar_decryption         = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY);
    airpcap_toolbar_decryption_lb      = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY);
    airpcap_toolbar_keys_button        = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY);

    /* The current interface is an airpcap interface */
    if (if_info != NULL)
    {
        gtk_widget_set_sensitive(wireless_tb,TRUE);
        gtk_widget_set_sensitive(airpcap_toolbar_label,TRUE);
        gtk_widget_set_sensitive(toolbar_channel_cb,TRUE);
        gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,TRUE);
        gtk_widget_set_sensitive(airpcap_toolbar_channel_offset,TRUE);
        gtk_widget_set_sensitive(airpcap_toolbar_channel_offset_lb,TRUE);
        gtk_widget_set_sensitive(airpcap_toolbar_fcs,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_decryption,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_keys_button,FALSE);

        /*decryption check box*/
        g_signal_handlers_block_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, wireless_tb);
        if (if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
        else
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
        g_signal_handlers_unblock_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, wireless_tb);

        if_label_text = g_strdup_printf("Current Wireless Interface: #%s", airpcap_get_if_string_number(if_info));
        gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
        g_free(if_label_text);

        change_airpcap_settings = FALSE;
        if (if_info->pSupportedChannels != NULL && if_info->numSupportedChannels > 0) {
            guint i = 0;

            for (; i<if_info->numSupportedChannels; i++) {
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(toolbar_channel_cb), ieee80211_mhz_to_str(if_info->pSupportedChannels[i].Frequency));
            }
        }

        airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cb),if_info);
        airpcap_update_channel_offset_combo(if_info, if_info->channelInfo.Frequency, airpcap_toolbar_channel_offset, TRUE);
        change_airpcap_settings = TRUE;
    }
    else /* Current interface is NOT an AirPcap one... */
    {
        gtk_widget_set_sensitive(wireless_tb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_label,FALSE);
        gtk_widget_set_sensitive(toolbar_channel_cb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_channel_offset,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_channel_offset_lb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_fcs,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_decryption,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,FALSE);
        gtk_widget_set_sensitive(airpcap_toolbar_keys_button,FALSE);
    }
}

/*
 * Set up the airpcap toolbar for the new capture interface
 */
void
airpcap_set_toolbar_stop_capture(airpcap_if_info_t* if_info)
{
    GtkWidget *airpcap_toolbar_crc_filter_combo;
    GtkWidget *airpcap_toolbar_label;
    GtkWidget *toolbar_channel_cb;
    GtkWidget *airpcap_toolbar_channel_lb;
    GtkWidget *airpcap_toolbar_channel_offset;
    GtkWidget *airpcap_toolbar_channel_offset_lb;
    GtkWidget *airpcap_toolbar_button;
    GtkWidget *airpcap_toolbar_fcs;
    GtkWidget *airpcap_toolbar_fcs_lb;
    GtkWidget *airpcap_toolbar_decryption;
    GtkWidget *airpcap_toolbar_decryption_lb;
    GtkWidget *airpcap_toolbar_keys_button;

    gchar *if_label_text;

    airpcap_toolbar_crc_filter_combo    = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    airpcap_toolbar_label               = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_INTERFACE_KEY);
    toolbar_channel_cb                  = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_KEY);
    airpcap_toolbar_channel_lb          = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
    airpcap_toolbar_channel_offset      = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY);
    airpcap_toolbar_channel_offset_lb   = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY);
    airpcap_toolbar_fcs                 = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    airpcap_toolbar_fcs_lb              = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
    airpcap_toolbar_button              = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_ADVANCED_KEY);
    airpcap_toolbar_decryption          = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY);
    airpcap_toolbar_decryption_lb       = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY);
    airpcap_toolbar_keys_button         = (GtkWidget *)g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY);

    /* The current interface is an airpcap interface */
    if (if_info != NULL)
    {
          gtk_widget_set_sensitive(wireless_tb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_label,TRUE);
          gtk_widget_set_sensitive(toolbar_channel_cb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_channel_offset,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_channel_offset_lb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_fcs,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_button,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_crc_filter_combo,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_decryption,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_keys_button,TRUE);
          airpcap_validation_type_combo_set_by_type(airpcap_toolbar_crc_filter_combo, if_info->CrcValidationOn);

          /*decription check box*/
          g_signal_handlers_block_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, wireless_tb);
          if (if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
              gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
          else
              gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
          g_signal_handlers_unblock_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, wireless_tb);

          if_label_text = g_strdup_printf("Current Wireless Interface: #%s", airpcap_get_if_string_number(if_info));
          gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
          g_free(if_label_text);

          change_airpcap_settings = FALSE;
          if (if_info->pSupportedChannels != NULL && if_info->numSupportedChannels > 0) {
              guint i = 0;

              for (; i<if_info->numSupportedChannels; i++) {
                  gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(toolbar_channel_cb), ieee80211_mhz_to_str(if_info->pSupportedChannels[i].Frequency));
              }
          }

          airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cb),if_info);
          airpcap_update_channel_offset_combo(if_info, if_info->channelInfo.Frequency, airpcap_toolbar_channel_offset, TRUE);
          change_airpcap_settings = TRUE;
      }
    else
    {
          gtk_widget_set_sensitive(wireless_tb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_label,FALSE);
          gtk_widget_set_sensitive(toolbar_channel_cb,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_channel_offset,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_channel_offset_lb,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_fcs,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_crc_filter_combo,FALSE);
          gtk_widget_set_sensitive(airpcap_toolbar_decryption,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,TRUE);
          gtk_widget_set_sensitive(airpcap_toolbar_keys_button,TRUE);
          change_airpcap_settings = FALSE;
    }
}

#if 0
/* Returs TRUE if the WEP key is valid, false otherwise */
gboolean
wep_key_is_valid(char* key)
{
    size_t strsize, i;

    if (key == NULL)
        return FALSE;

    strsize = strlen(key);

    if ( (strsize > WEP_KEY_MAX_CHAR_SIZE) || (strsize < 2))
    {
        return FALSE;
    }
    if ((strsize % 2) != 0)
    {
        return FALSE;
    }
    for(i = 0; i < strsize; i++)
    {
        if (!g_ascii_isxdigit(key[i]))
        {
            return FALSE;
        }
    }

    return TRUE;
}
#endif

/*
 * Callback used by the load_wlan_keys() routine in order to read a WEP decryption key
 */
static guint
get_wep_key(pref_t *pref, gpointer ud)
{
    gchar *key_string = NULL;
    guint8 key_type = AIRPDCAP_KEY_TYPE_WEP;
    keys_cb_data_t* user_data;
    uat_t *uat;
    guint i;
    char* err = NULL;
    uat_wep_key_record_t* wep_keys;
    decryption_key_t* new_key;

    /* Retrieve user data info */
    user_data = (keys_cb_data_t*)ud;

    if (g_ascii_strcasecmp(pref->name, "wep_key_table") == 0 && pref->type == PREF_UAT)
    {
        uat = pref->varp.uat;
        /* This is just a sanity check.  UAT should be loaded */
        if (!uat->loaded)
        {
            if (!uat_load(uat, &err))
            {
                /* XXX - report the error */
                g_free(err);
                return 1;
            }
        }

        for (i = 0, wep_keys = (uat_wep_key_record_t*)*uat->user_ptr; i < *uat->nrows_p; i++, wep_keys++)
        {
            /* strip out key type if present */
            if (g_ascii_strncasecmp(wep_keys->string, STRING_KEY_TYPE_WEP ":", 4) == 0) {
                key_type = AIRPDCAP_KEY_TYPE_WEP;
                key_string = (gchar*)wep_keys->string+4;
            }
            else if (g_ascii_strncasecmp(wep_keys->string, STRING_KEY_TYPE_WPA_PWD ":", 8) == 0) {
                key_string = (gchar*)wep_keys->string+8;
                key_type = AIRPDCAP_KEY_TYPE_WPA_PWD;
            }
            else if (g_ascii_strncasecmp(wep_keys->string, STRING_KEY_TYPE_WPA_PSK ":", 8) == 0) {
                key_string = (gchar*)wep_keys->string+8;
                key_type = AIRPDCAP_KEY_TYPE_WPA_PSK;
            }
            else {
                key_type = wep_keys->key;
                key_string = (gchar*)wep_keys->string;
            }

            /* Here we have the string describing the key... */
            new_key = parse_key_string(key_string, key_type);

            if (new_key != NULL)
            {
                /* Key is added only if not null ... */
                user_data->list = g_list_append(user_data->list,new_key);
                user_data->number_of_keys++;
                user_data->current_index++;
            }
        }
    }
    return 0;
}

/* Callback used by the save_wlan_keys() routine in order to write a decryption key */
static guint
set_wep_key(pref_t *pref, gpointer ud _U_)
{
    keys_cb_data_t*  user_data;
    uat_t *uat;
    gint i;
    char* err = NULL;
    uat_wep_key_record_t uat_key;

    decryption_key_t* new_key;

    /* Retrieve user data info */
    user_data = (keys_cb_data_t*)ud;

    if (g_ascii_strcasecmp(pref->name, "wep_key_table") == 0 && pref->type == PREF_UAT)
    {
        uat = pref->varp.uat;
        if (!uat->loaded)
        {
            /* UAT will only be loaded if previous keys exist, so it may need
               to be loaded now */
            if (!uat_load(uat, &err))
            {
                /* XXX - report the error */
                g_free(err);
                return 1;
            }
            uat->loaded = 1;
        }
        /* Free the old records */
        uat_clear(uat);

        for (i = 0; i < user_data->number_of_keys; i++)
        {
            new_key = (decryption_key_t*)g_list_nth_data(user_data->list,i);

            uat_key.string = get_key_string(new_key);
            uat_key.key = new_key->type;
            uat_add_record(uat, &uat_key, TRUE);
        }

        if (!uat_save(uat, &err))
        {
            /* XXX - report the error */
            g_free(err);
            return 1;
        }
    }

    return 0;
}

/*
 * This function will tell the airpcap driver the key list to use
 * This will be stored into the registry...
 */
static gboolean
write_wlan_driver_wep_keys_to_registry(GList* key_list)
{
    guint                   i,j,k,n,y;
    GString                *new_key;
    gchar                   s[3];
    PAirpcapKeysCollection  KeysCollection;
    guint                   KeysCollectionSize;
    guint8                  KeyByte;
    guint                   keys_in_list = 0;
    decryption_key_t*       key_item     = NULL;
    airpcap_if_info_t*      fake_info_if = NULL;

    /* Create the fake_info_if from the first adapter of the list */
    fake_info_if = airpcap_driver_fake_if_info_new();

    if (fake_info_if == NULL)
        return FALSE;

    /*
     * XXX - When WPA will be supported, change this to: keys_in_list = g_list_length(key_list);
     * but right now we will have to count only the WEP keys (or we will have a malloc-mess :-) )
     */
    n = g_list_length(key_list);
    for(k = 0; k < n; k++ )
        if (((decryption_key_t*)g_list_nth_data(key_list,k))->type == AIRPDCAP_KEY_TYPE_WEP)
            keys_in_list++;

    /*
     * Calculate the size of the keys collection
     */
    KeysCollectionSize = (guint)AirpcapKeysCollectionSize(keys_in_list);

    /*
     * Allocate the collection
     */
    KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);
    if (!KeysCollection)
    {
        return FALSE;
    }

    /*
     * Populate the key collection
     */
    KeysCollection->nKeys = keys_in_list;

    /*
     * XXX - If we have, let's say, six keys, the first three are WEP, then two are WPA, and the
     * last is WEP, we have to scroll the whole list (n) but increment the array counter only
     * when a WEP key is found (y) .. When WPA will be supported by the driver, I'll have to change
     * this
     */
    y = 0; /* Current position in the key list */

    for(i = 0; i < n; i++)
    {
        /* Retrieve the Item corresponding to the i-th key */
        key_item = (decryption_key_t*)g_list_nth_data(key_list,i);

        /*
         * XXX - The AIRPDCAP_KEY_TYPE_WEP is the only supported right now!
         * We will have to modify the AirpcapKey structure in order to
         * support the other two types! What happens now, is that simply the
         * not supported keys will just be discarded (they will be saved in Wireshark though)
         */
        if (key_item->type == AIRPDCAP_KEY_TYPE_WEP)
        {
            KeysCollection->Keys[y].KeyType = AIRPDCAP_KEY_TYPE_WEP;

            new_key = g_string_new(key_item->key->str);

            KeysCollection->Keys[y].KeyLen = (guint) new_key->len / 2;
            memset(&KeysCollection->Keys[y].KeyData, 0, sizeof(KeysCollection->Keys[y].KeyData));

            for(j = 0 ; j < new_key->len; j += 2)
            {
                s[0] = new_key->str[j];
                s[1] = new_key->str[j+1];
                s[2] = '\0';
                KeyByte = (guint8)strtol(s, NULL, 16);
                KeysCollection->Keys[y].KeyData[j / 2] = KeyByte;
            }
            /* XXX - Change when WPA will be supported!!! */
            y++;
            g_string_free(new_key,TRUE);
        }
        else if (key_item->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
        {
            /* XXX - The driver cannot deal with this kind of key yet... */
        }
        else if (key_item->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
        {
            /* XXX - The driver cannot deal with this kind of key yet... */
        }
    }

    /*
     * Free the old adapter key collection!
     */
    if (fake_info_if->keysCollection != NULL)
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
 * Function used to read the Decryption Keys from the preferences and store them
 * properly into the airpcap adapter.
 */
static gboolean
load_wlan_driver_wep_keys(void)
{
    keys_cb_data_t* user_data;

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

    write_wlan_driver_wep_keys_to_registry(user_data->list);

    /* FREE MEMORY */
    /* free the WEP key string */
    g_list_foreach(user_data->list, (GFunc)free_key_string, NULL);

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
static gboolean
write_wlan_wep_keys_to_registry(airpcap_if_info_t* info_if, GList* key_list)
{
    guint i,j;
    GString *new_key;
    gchar s[3];
    PAirpcapKeysCollection KeysCollection;
    guint KeysCollectionSize;
    guint8 KeyByte;
    guint keys_in_list = 0;
    decryption_key_t* key_item = NULL;

    keys_in_list = g_list_length(key_list);

    /*
     * Calculate the size of the keys collection
     */
    KeysCollectionSize = (guint)AirpcapKeysCollectionSize(keys_in_list);

    /*
     * Allocate the collection
     */
    KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);
    if (!KeysCollection)
    {
        return FALSE;
    }

    /*
     * Populate the key collection
     */
    KeysCollection->nKeys = keys_in_list;

    for(i = 0; i < keys_in_list; i++)
    {
        KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WEP;

        /* Retrieve the Item corresponding to the i-th key */
        key_item = (decryption_key_t*)g_list_nth_data(key_list,i);
        new_key = g_string_new(key_item->key->str);

        KeysCollection->Keys[i].KeyLen = (guint) new_key->len / 2;
        memset(&KeysCollection->Keys[i].KeyData, 0, sizeof(KeysCollection->Keys[i].KeyData));

        for(j = 0 ; j < new_key->len; j += 2)
        {
            s[0] = new_key->str[j];
            s[1] = new_key->str[j+1];
            s[2] = '\0';
            KeyByte = (guint8)strtol(s, NULL, 16);
            KeysCollection->Keys[i].KeyData[j / 2] = KeyByte;
        }

        g_string_free(new_key,TRUE);

    }
    /*
     * Free the old adapter key collection!
     */
    if (info_if->keysCollection != NULL)
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
 * Returns the ASCII string of a key given the key bytes
 */
static gchar*
airpcap_get_key_string(AirpcapKey key)
{
    unsigned int j = 0;
    gchar *dst,*src;

    dst = NULL;
    src = NULL;

    if (key.KeyType == AIRPDCAP_KEY_TYPE_WEP)
    {
        if (key.KeyLen != 0)
        {
            /* Allocate the string used to store the ASCII representation of the WEP key */
            dst = (gchar*)g_malloc(sizeof(gchar)*WEP_KEY_MAX_CHAR_SIZE + 1);
            /* Make sure that the first char is '\0' in order to make g_strlcat() work */
            dst[0]='\0';

            for(j = 0; j < key.KeyLen; j++)
            {
                src = g_strdup_printf("%.2x", key.KeyData[j]);
                /*
                 * XXX - use g_strconcat() or GStrings instead ???
                 */
                g_strlcat(dst, src, WEP_KEY_MAX_CHAR_SIZE+1);
            }
            g_free(src);
        }
    }
    else if (key.KeyType == AIRPDCAP_KEY_TYPE_WPA_PWD)
    {
        /* XXX - Add code here */
    }
    else if (key.KeyType == AIRPDCAP_KEY_TYPE_WPA_PMK)
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
 *  Function used to save to the preference file the Decryption Keys.
 */
static int
save_wlan_driver_wep_keys(void)
{
    GList*             key_list     = NULL;
    char*              tmp_key      = NULL;
    guint              keys_in_list,i;
    keys_cb_data_t*    user_data;
    airpcap_if_info_t* fake_info_if = NULL;

    /* Create the fake_info_if from the first adapter of the list */
    fake_info_if = airpcap_driver_fake_if_info_new();

    if (fake_info_if == NULL)
        return 0;

    /* Retrieve the wlan preferences */
    wlan_prefs = prefs_find_module("wlan");

    /* Allocate a structure used to keep infos  between the callbacks */
    user_data = (keys_cb_data_t*)g_malloc(sizeof(keys_cb_data_t));

    /* Number of keys in key list */
    if (fake_info_if->keysCollectionSize != 0)
        keys_in_list = AirpcapKeysCollectionSizeToKeyCount(fake_info_if->keysCollectionSize);
    else
        keys_in_list = 0;

    for(i=0; i<keys_in_list; i++)
    {
    /* Only if it is a WEP key... */
        if (fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
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
static int
save_wlan_wireshark_wep_keys(GList* key_ls)
{
    GList* key_list = NULL;
    guint keys_in_list,i;
    keys_cb_data_t* user_data;
    decryption_key_t* tmp_dk;

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
        tmp_dk = (decryption_key_t*)g_list_nth(user_data->list,i)->data;
        g_string_free(tmp_dk->key,TRUE);
        if (tmp_dk->ssid != NULL) g_byte_array_free(tmp_dk->ssid,TRUE);
    }

    /* free the (empty) list */
    g_list_free(user_data->list);

    /* free the user_data structure */
    g_free(user_data);

    return keys_in_list;
}

/*
 * Returns the default airpcap interface of a list, NULL if list is empty
 */
airpcap_if_info_t*
airpcap_get_default_if(GList* airpcap_if_list_p)
{
    airpcap_if_info_t* if_info = NULL;

    if ((prefs.capture_device != NULL) && (*prefs.capture_device != '\0'))
    {
        if_info = get_airpcap_if_from_name(airpcap_if_list_p,
                                           get_if_name(prefs.capture_device));
    }
    return if_info;
}

/*
 * DECRYPTION KEYS FUNCTIONS
 */
#if 0
/*
 * This function is used for DEBUG POURPOSES ONLY!!!
 */
void
print_key_list(GList* key_list)
{
    gint n,i;
    decryption_key_t* tmp;

    if (key_list == NULL)
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

        if (tmp->type == AIRPDCAP_KEY_TYPE_WEP)
            g_print("TYPE: %s\n",AIRPCAP_WEP_KEY_STRING);
        else if (tmp->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
            g_print("TYPE: %s\n",AIRPCAP_WPA_PWD_KEY_STRING);
        else if (tmp->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
            g_print("TYPE: %s\n",AIRPCAP_WPA_BIN_KEY_STRING);
        else
            g_print("TYPE: %s\n","???");

        g_print("SSID: %s\n",(tmp->ssid != NULL) ?
                format_text((guchar *)tmp->ssid->data, tmp->ssid->len) : "---");
        g_print("\n");
    }

    g_print("\n*****************************\n\n");
}
#endif

/*
 * Retrieves a GList of decryption_key_t structures containing infos about the
 * keys for the given adapter... returns NULL if no keys are found.
 */
GList *
get_airpcap_device_keys(airpcap_if_info_t* info_if)
{
    /* tmp vars */
    char* tmp_key = NULL;
    guint i,keys_in_list = 0;

    /* real vars*/
    decryption_key_t *new_key  = NULL;
    GList            *key_list = NULL;

    /* Number of keys in key list */
    if (info_if->keysCollectionSize != 0)
        keys_in_list = AirpcapKeysCollectionSizeToKeyCount(info_if->keysCollectionSize);
    else
        keys_in_list = 0;

    for(i=0; i<keys_in_list; i++)
    {
        /* Different things to do depending on the key type  */
        if (info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
        {
            /* allocate memory for the new key item */
            new_key = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

            /* fill the fields */
            /* KEY */
            tmp_key = airpcap_get_key_string(info_if->keysCollection->Keys[i]);
            new_key->key = g_string_new(tmp_key);
            g_free(tmp_key);

            /* BITS */
            new_key->bits = (guint) new_key->key->len *4; /* every char is 4 bits in WEP keys (it is an hexadecimal number) */

            /* SSID not used in WEP keys */
            new_key->ssid = NULL;

            /* TYPE (WEP in this case) */
            new_key->type = info_if->keysCollection->Keys[i].KeyType;

            /* Append the new element in the list */
            key_list = g_list_append(key_list,(gpointer)new_key);
        }
        else if (info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PWD)
        {
            /* XXX - Not supported yet */
        }
        else if (info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PMK)
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
GList *
get_airpcap_driver_keys(void)
{
    /* tmp vars */
    char  *tmp_key        = NULL;
    guint  i,keys_in_list = 0;

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

    if (fake_info_if == NULL)
        return NULL;

    /* Number of keys in key list */
    if (fake_info_if->keysCollectionSize != 0)
        keys_in_list = AirpcapKeysCollectionSizeToKeyCount(fake_info_if->keysCollectionSize);
    else
        keys_in_list = 0;

    for(i=0; i<keys_in_list; i++)
    {
        /* Different things to do depending on the key type  */
        if (fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
        {
            /* allocate memory for the new key item */
            new_key = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

            /* fill the fields */
            /* KEY */
            tmp_key = airpcap_get_key_string(fake_info_if->keysCollection->Keys[i]);
            new_key->key = g_string_new(tmp_key);
            if (tmp_key != NULL) g_free(tmp_key);

            /* BITS */
            new_key->bits = (guint) new_key->key->len *4; /* every char is 4 bits in WEP keys (it is an hexadecimal number) */

            /* SSID not used in WEP keys */
            new_key->ssid = NULL;

            /* TYPE (WEP in this case) */
            new_key->type = fake_info_if->keysCollection->Keys[i].KeyType;

            /* Append the new element in the list */
            key_list = g_list_append(key_list,(gpointer)new_key);
        }
        else if (fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PWD)
        {
            /* XXX - Not supported yet */
        }
        else if (fake_info_if->keysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WPA_PMK)
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
GList *
get_wireshark_keys(void)
{
    keys_cb_data_t *wep_user_data = NULL;

    GList *final_list     = NULL;
    GList *wep_final_list = NULL;

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

    /* Copy the list field in the user data structure pointer into the final_list */
    wep_final_list = wep_user_data->list;

    /* XXX - Merge the three lists!!!!! */
    final_list = wep_final_list;

    /* free the wep_user_data structure */
    g_free(wep_user_data);

    return final_list;
}


static guint
test_if_on(pref_t *pref, gpointer ud)
{
    gboolean *is_on;
    gboolean  number;

    /* Retrieve user data info */
    is_on = (gboolean*)ud;


    if (g_ascii_strncasecmp(pref->name, "enable_decryption", 17) == 0 && pref->type == PREF_BOOL)
    {
        number = *pref->varp.boolp;

        if (number) *is_on = TRUE;
        else *is_on = FALSE;

        return 1;
    }
    return 0;
}

/*
 * Merges two lists of keys and return a newly created GList. If a key is
 * found multiple times, it will just appear once!
 * list1 and list 2 pointer will have to be freed manually if needed!!!
 * If the total number of keys exceeeds the maximum number allowed,
 * exceeding keys will be discarded...
 */
GList *
merge_key_list(GList* list1, GList* list2)
{
    guint n1=0,n2=0;
    guint i;
    decryption_key_t *dk1=NULL,
                     *dk2=NULL,
                     *new_dk=NULL;

    GList* merged_list = NULL;

    if ( (list1 == NULL) && (list2 == NULL) )
        return NULL;

    if (list1 == NULL)
    {
        n2 = g_list_length(list2);

        for(i=0;i<n2;i++)
        {
            new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
            dk2 = (decryption_key_t *)g_list_nth_data(list2,i);

            new_dk->bits = dk2->bits;
            new_dk->type = dk2->type;
            new_dk->key  = g_string_new(dk2->key->str);
            new_dk->ssid = byte_array_dup(dk2->ssid);

            /* Check the total length of the merged list */
            if (g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
                merged_list = g_list_append(merged_list,(gpointer)new_dk);
        }
    }
    else if (list2 == NULL)
    {
        n1 = g_list_length(list1);

        for(i=0;i<n1;i++)
        {
            new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
            dk1 = (decryption_key_t*)g_list_nth_data(list1,i);

            new_dk->bits = dk1->bits;
            new_dk->type = dk1->type;
            new_dk->key  = g_string_new(dk1->key->str);
            new_dk->ssid = byte_array_dup(dk1->ssid);

            /* Check the total length of the merged list */
            if (g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
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
            new_dk->ssid = byte_array_dup(dk1->ssid);

            /* Check the total length of the merged list */
            if (g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
                merged_list = g_list_append(merged_list,(gpointer)new_dk);
        }

        /* Look for keys that are present in list2 but aren't in list1 yet...
         * Add them to merged_list
         */
        for(i=0;i<n2;i++)
        {
            dk2 = (decryption_key_t *)g_list_nth_data(list2,i);

            if (!key_is_in_list(dk2,merged_list))
            {
                new_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

                new_dk->bits = dk2->bits;
                new_dk->type = dk2->type;
                new_dk->key  = g_string_new(dk2->key->str);
                new_dk->ssid = byte_array_dup(dk2->ssid);

                /* Check the total length of the merged list */
                if (g_list_length(merged_list) < MAX_ENCRYPTION_KEYS)
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

    if (list == NULL)
        return;

    n = g_list_length(list);

    for(i = 0; i < n; i++)
    {
        curr_key = (decryption_key_t*)g_list_nth_data(list,i);

        /* Free all the strings */
        if (curr_key->key != NULL)
            g_string_free(curr_key->key, TRUE);

        if (curr_key->ssid != NULL)
        g_byte_array_free(curr_key->ssid, TRUE);

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
    decryption_key_t *curr_key = NULL;
    gboolean found = FALSE;

    if ( (list == NULL) || (dk == NULL) )
        return FALSE;

    n = g_list_length(list);

    if (n < 1)
        return FALSE;

    for(i = 0; i < n; i++)
    {
        curr_key = (decryption_key_t*)g_list_nth_data(list,i);
        if (keys_are_equals(dk,curr_key))
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

    if ((k1==NULL) || (k2==NULL))
        return FALSE;

    /* XXX - Remove this check when we will have the WPA/WPA2 decryption in the Driver! */
    /** if ( (k1->type == AIRPDCAP_KEY_TYPE_WPA_PWD) || (k2->type == AIRPDCAP_KEY_TYPE_WPA_PWD) || (k1->type == AIRPDCAP_KEY_TYPE_WPA_PMK) || (k2->type == AIRPDCAP_KEY_TYPE_WPA_PMK) ) **/
    /**         return TRUE;  **/

    if (g_string_equal(k1->key,k2->key) &&
        (k1->bits == k2->bits) && /* If the previous is TRUE, this must be TRUE as well */
        (k1->type == k2->type))
    {
        /* Check the ssid... if the key type is WEP, the two fields should be NULL */
        if ((k1->ssid == NULL) && (k2->ssid == NULL))
            return TRUE;

        /* If they are not null, they must share the same ssid */
        return byte_array_equal(k1->ssid,k2->ssid);
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
    guint  n1        = 0,n2=0;
    /* XXX - Remove */
    guint  wep_n1    = 0,wep_n2=0;
    GList *wep_list1 = NULL;
    GList *wep_list2 = NULL;
    /* XXX - END*/
    guint i/*,j*/;
    decryption_key_t *dk1=NULL,*dk2=NULL;

    n1 = g_list_length(list1);
    n2 = g_list_length(list2);

    /*
     * XXX - START : Retrieve the aublists of WEP keys!!! This is needed only 'till Driver WPA decryption
     * is implemented.
     */
    for(i=0;i<n1;i++)
    {
        dk1=(decryption_key_t*)g_list_nth_data(list1,i);
        if (dk1->type == AIRPDCAP_KEY_TYPE_WEP)
        {
            wep_list1 = g_list_append(wep_list1,(gpointer)dk1);
            wep_n1++;
        }
    }
    for(i=0;i<n2;i++)
    {
        dk2=(decryption_key_t*)g_list_nth_data(list2,i);
        if (dk2->type == AIRPDCAP_KEY_TYPE_WEP)
        {
            wep_list2 = g_list_append(wep_list2,(gpointer)dk2);
            wep_n2++;
        }
    }

    /*
     * XXX - END : Remove from START to END when the WPA/WPA2 decryption will be implemented in
     * the Driver
     */

    /*
     * Commented, because in the new AirPcap version all the keys will be saved
     * into the driver, and all the keys for every specific adapter will be
     * removed. This means that this check will always fail... and the user will
     * always be asked what to do... and it doesn't make much sense.
     */
    /* if (n1 != n2) return FALSE; */
    if (wep_n1 != wep_n2) return FALSE;

    n2 = wep_n2;

    /*for(i=0;i<n1;i++)
    {
    dk1=(decryption_key_t*)g_list_nth_data(list1,i);
    dk2=(decryption_key_t*)g_list_nth_data(list2,i);

    if (!g_string_equal(dk1->key,dk2->key)) return FALSE;
    }*/
    for(i=0;i<n2;i++)
    {
        dk2=(decryption_key_t*)g_list_nth_data(wep_list2,i);
        if (!key_is_in_list(dk2,wep_list1)) return FALSE;
    }

    return TRUE;
}


/*
 * Returns TRUE if the Wireshark decryption is active, false otherwise
 * XXX - Should we just add a routine to packet-ieee80211.c to grab this directly?
 */
gboolean
wireshark_decryption_on(void)
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
airpcap_decryption_on(void)
{
    gboolean is_on = FALSE;

    airpcap_if_info_t* fake_if_info = NULL;

    fake_if_info = airpcap_driver_fake_if_info_new();

    if (fake_if_info != NULL)
    {
        if (fake_if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
            is_on = TRUE;
        else if (fake_if_info->DecryptionOn == AIRPCAP_DECRYPTION_OFF)
            is_on = FALSE;
    }

    airpcap_if_info_free(fake_if_info);

    return is_on;
}

static guint
set_on_off(pref_t *pref, gpointer ud)
{
    gboolean *is_on;

    /* Retrieve user data info */
    is_on = (gboolean*)ud;

    if (g_ascii_strncasecmp(pref->name, "enable_decryption", 17) == 0 && pref->type == PREF_BOOL)
    {

        if (*is_on)
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

    if (fake_if_info == NULL)
        /* We apparently don't have any adapters installed.
         * This isn't a failure, so return TRUE
         */
        return TRUE;

    /* Set the driver decryption */
    ad_driver = airpcap_if_open(fake_if_info->name, ebuf);
    if (ad_driver)
    {
        if (on_off)
            airpcap_if_set_driver_decryption_state(ad_driver,AIRPCAP_DECRYPTION_ON);
        else
            airpcap_if_set_driver_decryption_state(ad_driver,AIRPCAP_DECRYPTION_OFF);

        airpcap_if_close(ad_driver);
    }

    airpcap_if_info_free(fake_if_info);

    n = g_list_length(g_airpcap_if_list);

    /* Set to FALSE the decryption for all the adapters */
    /* Apply this change to all the adapters !!! */
    for(i = 0; i < n; i++)
    {
        curr_if = (airpcap_if_info_t*)g_list_nth_data(g_airpcap_if_list,i);

        if (curr_if != NULL)
        {
            ad = airpcap_if_open(curr_if->name, ebuf);
            if (ad)
            {
                curr_if->DecryptionOn = AIRPCAP_DECRYPTION_OFF;
                airpcap_if_set_decryption_state(ad,curr_if->DecryptionOn);
                /* Save configuration for the curr_if */
                if (!airpcap_if_store_cur_config_as_adapter_default(ad))
                {
                    success = FALSE;
                }
                airpcap_if_close(ad);
            }
        }
    }

    return success;
}



/*
 * Add a key (string) to the given list
 */
void
airpcap_add_key_to_list(GtkListStore *key_list_store, gchar* type, gchar* key, gchar* ssid)
{
    GtkTreeIter iter;

    gtk_list_store_insert_with_values(key_list_store , &iter, G_MAXINT,
        KL_COL_TYPE, type,
        KL_COL_KEY, key,
        KL_COL_SSID, ssid,
        -1);
}

/*
 * Fill the list with the keys. BEWARE! At this point, Wireshark and Drivers
 * keys should be EQUALS! But is better to load keys from Wireshark, because
 * the driver is not always present, and maybe that cannot support some keys
 * (i.e. the WPA problem)
 */
void
airpcap_fill_key_list(GtkListStore *key_list_store)
{
    const gchar*       s = NULL;
    unsigned int       i,n;
    airpcap_if_info_t* fake_if_info;
    GList*             wireshark_key_list = NULL;
    decryption_key_t*  curr_key           = NULL;
    GtkTreeIter        iter;

    fake_if_info = airpcap_driver_fake_if_info_new();

    /* We can retrieve the driver's key list (i.e. we have the right .dll)*/
    wireshark_key_list = get_wireshark_keys();
    n = g_list_length(wireshark_key_list);

    for(i = 0; i < n; i++)
    {
        curr_key = (decryption_key_t*)g_list_nth_data(wireshark_key_list,i);

        if (curr_key->type == AIRPDCAP_KEY_TYPE_WEP)
        {
            gtk_list_store_insert_with_values(key_list_store , &iter, G_MAXINT,
                KL_COL_TYPE, AIRPCAP_WEP_KEY_STRING,
                KL_COL_KEY, curr_key->key->str,
                KL_COL_SSID, "",
                -1);
        }
        else if (curr_key->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
        {
            if (curr_key->ssid != NULL)
                s = format_uri(curr_key->ssid, ":");
            else
                s = "";

            gtk_list_store_insert_with_values(key_list_store , &iter, G_MAXINT,
                KL_COL_TYPE, AIRPCAP_WPA_PWD_KEY_STRING,
                KL_COL_KEY, curr_key->key->str,
                KL_COL_SSID, s,
                -1);

        }
        else if (curr_key->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
        {
            gtk_list_store_insert_with_values(key_list_store , &iter, G_MAXINT,
                KL_COL_TYPE, AIRPCAP_WPA_BIN_KEY_STRING,
                KL_COL_KEY, curr_key->key->str,
                KL_COL_SSID, "",
                -1);

        }
    }

    airpcap_if_info_free(fake_if_info);
    return;
}

/*
 * Function used to retrieve the AirpcapValidationType given the string name.
 */
AirpcapValidationType
airpcap_get_validation_type(const gchar* name)
{
    if (!(g_ascii_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_ALL,name)))
    {
        return AIRPCAP_VT_ACCEPT_EVERYTHING;
    }
    else if (!(g_ascii_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_CORRECT,name)))
    {
        return AIRPCAP_VT_ACCEPT_CORRECT_FRAMES;
    }
    else if (!(g_ascii_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT,name)))
    {
        return AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES;
    }
    return AIRPCAP_VT_UNKNOWN;
}

/*
 * Function used to retrieve the string name given an AirpcapValidationType,
 * or NULL in case of error
 */
const gchar*
airpcap_get_validation_name(AirpcapValidationType vt)
{
    if (vt == AIRPCAP_VT_ACCEPT_EVERYTHING)
    {
        return AIRPCAP_VALIDATION_TYPE_NAME_ALL;
    }
    else if (vt == AIRPCAP_VT_ACCEPT_CORRECT_FRAMES)
    {
        return AIRPCAP_VALIDATION_TYPE_NAME_CORRECT;
    }
    else if (vt == AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES)
    {
        return AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT;
    }
    else if (vt == AIRPCAP_VT_UNKNOWN)
    {
        return AIRPCAP_VALIDATION_TYPE_NAME_UNKNOWN;
    }
    return NULL;
}

/*
 * Return an appropriate combo box entry number for the given an AirpcapValidationType,
 * defaulting to 0
 */
gint
airpcap_get_validation_combo_entry(AirpcapValidationType vt)
{
    switch (vt) {
        case AIRPCAP_VT_ACCEPT_CORRECT_FRAMES:
            return 1;
            break;
        case AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES:
            return 2;
            break;
        default:
            return 0;
            break;
    }
}

/*
 * Returns the AirpcapLinkType corresponding to the given string name.
 */
AirpcapLinkType
airpcap_get_link_type(const gchar* name)
{
    if (!(g_ascii_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_ONLY,name))) {
        return AIRPCAP_LT_802_11;
    }else if (!(g_ascii_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO,name))) {
        return AIRPCAP_LT_802_11_PLUS_RADIO;
    }else if (!(g_ascii_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_PPI,name))) {
        return AIRPCAP_LT_802_11_PLUS_PPI;
    }else{
        return AIRPCAP_LT_UNKNOWN;
    }
}

/*
 * Returns the string name corresponding to the given AirpcapLinkType, or
 * NULL in case of error.
 */
const gchar*
airpcap_get_link_name(AirpcapLinkType lt)
{
    if (lt == AIRPCAP_LT_802_11) {
        return AIRPCAP_LINK_TYPE_NAME_802_11_ONLY;
    }else if (lt == AIRPCAP_LT_802_11_PLUS_RADIO) {
        return AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO;
    }else if (lt == AIRPCAP_LT_802_11_PLUS_PPI) {
        return AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_PPI;
    }else if (lt == AIRPCAP_LT_UNKNOWN) {
        return AIRPCAP_LINK_TYPE_NAME_UNKNOWN;
    }
    return NULL;
}

/*
 * Sets the entry of the validation combo using the AirpcapValidationType.
 */
void
airpcap_validation_type_combo_set_by_type(GtkWidget* c, AirpcapValidationType type)
{
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), airpcap_get_validation_combo_entry(type));
}

/*
 * Returns the string corresponding to the given guint (1-14, for channel only)
 */
gchar*
airpcap_get_channel_name(guint n)
{
    return g_strdup_printf("%d",n);
}


/*
 * Set the combo box entry string given a channel frequency
 */
void
airpcap_channel_combo_set_by_frequency(GtkWidget* cb, guint chan_freq)
{
    guint i;

    for (i = 0; i < airpcap_if_selected->numSupportedChannels; i++) {
        if (airpcap_if_selected->pSupportedChannels[i].Frequency == chan_freq) {
            gtk_combo_box_set_active(GTK_COMBO_BOX(cb), i);
            break;
        }
    }
}

/*
 * Change channel of Airpcap Adapter
 */
static gboolean
airpcap_update_frequency_and_offset(airpcap_if_info_t* if_info)
{
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];
    PAirpcapHandle ad;
    gboolean return_value = FALSE;

    if (if_info != NULL) {
        ad = airpcap_if_open(if_info->name, ebuf);

        if (ad != NULL) {
            return_value = airpcap_if_set_device_channel_ex(ad,if_info->channelInfo);
            airpcap_if_close(ad);
        }
    }

    return return_value;
}

/*
 * Changed callback for the channel combobox - common routine
 */
static void
airpcap_channel_changed_common(GtkWidget *channel_cb, gpointer channel_offset_cb, gboolean set)
{
    gint cur_chan_idx;

    if (channel_cb && channel_offset_cb && change_airpcap_settings && airpcap_if_active) {
        cur_chan_idx = gtk_combo_box_get_active(GTK_COMBO_BOX(channel_cb));
        if (cur_chan_idx >= 0 && cur_chan_idx < (gint) airpcap_if_active->numSupportedChannels) {
            if (set) {
                airpcap_if_active->channelInfo.Frequency = airpcap_if_active->pSupportedChannels[cur_chan_idx].Frequency;
            }
            airpcap_update_channel_offset_combo(airpcap_if_active,
                    airpcap_if_active->channelInfo.Frequency,
                    GTK_WIDGET(channel_offset_cb), set);
        }
    }
}

/*
 * Changed callback for the channel combobox - set channel and offset
 */
void
airpcap_channel_changed_set_cb(GtkWidget *channel_cb, gpointer channel_offset_cb)
{
    airpcap_channel_changed_common(channel_cb, channel_offset_cb, TRUE);
}

/*
 * Changed callback for the channel combobox - don't set channel and offset
 */
void
airpcap_channel_changed_noset_cb(GtkWidget *channel_cb, gpointer channel_offset_cb)
{
    airpcap_channel_changed_common(channel_cb, channel_offset_cb, FALSE);
}

static int
airpcap_get_selected_channel_offset(GtkWidget *channel_offset_cb) {
    int    offset;
    gchar *off_str;
    int    retval = 0;


    if (channel_offset_cb == NULL || !gtk_widget_get_sensitive(channel_offset_cb)) {
        return 0;
    }

    off_str = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(channel_offset_cb));
    if (off_str && (g_ascii_strcasecmp("", off_str)))
    {
        if (airpcap_if_selected != NULL)
        {
            if (sscanf(off_str, "%d", &offset) == 1) {
                if (offset >= -1 && offset <= 1) {
                    retval = offset;
                }
            }
        }
    }
    g_free(off_str);
    return retval;
}

/*
 * Changed callback for the channel offset combobox
 */
void
airpcap_channel_offset_changed_cb(GtkWidget *channel_offset_cb, gpointer data _U_)
{
    airpcap_if_selected->channelInfo.ExtChannel = airpcap_get_selected_channel_offset(channel_offset_cb);
    airpcap_if_selected->saved = FALSE;
    change_airpcap_settings = TRUE;
    if (!airpcap_update_frequency_and_offset(airpcap_if_selected)) {
        simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,
                      "Unable to set extension channel %d",
                      airpcap_if_selected->channelInfo.ExtChannel);
    }
}


/*
 * Update the channel offset of the given combobox according to the given frequency.
 */
void
airpcap_update_channel_offset_combo(airpcap_if_info_t* if_info, guint chan_freq, GtkWidget *channel_offset_cb, gboolean set)
{
    gint  current_offset;
    gint  new_offset;
    guint i;
    gint  active_idx = 0;
    gint  idx_count  = -1;

    if (!if_info || airpcap_if_is_any(if_info) || if_info->pSupportedChannels == NULL || if_info->numSupportedChannels < 1) {
        gtk_widget_set_sensitive(GTK_WIDGET(channel_offset_cb),FALSE);
        gtk_combo_box_set_active(GTK_COMBO_BOX(channel_offset_cb), -1);
        return;
    }

    new_offset = current_offset = if_info->channelInfo.ExtChannel;

    /* Clear out the list */
    while (gtk_tree_model_iter_n_children(gtk_combo_box_get_model(GTK_COMBO_BOX(channel_offset_cb)), NULL) > 0) {
        gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(channel_offset_cb), 0);
    }

    gtk_widget_set_sensitive(GTK_WIDGET(channel_offset_cb), TRUE);

    for (i = 0; i < if_info->numSupportedChannels; i++) {
        if (if_info->pSupportedChannels[i].Frequency == chan_freq) {

            /* If we can't be low or high, nudge the offset to 0 */
            if (current_offset == -1 && !(if_info->pSupportedChannels[i].Flags & FLAG_CAN_BE_LOW)) {
                new_offset = 0;
            } else if (current_offset == 1 && !(if_info->pSupportedChannels[i].Flags & FLAG_CAN_BE_HIGH)) {
                new_offset = 0;
            }

            if ((if_info->pSupportedChannels[i].Flags & FLAG_CAN_BE_LOW)) {
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(channel_offset_cb), "-1");
                idx_count++;
                if (new_offset == -1) {
                    active_idx = idx_count;
                }
            }
            gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(channel_offset_cb), "0");
            idx_count++;
            if (new_offset == 0) {
                active_idx = idx_count;
            }
            if ((if_info->pSupportedChannels[i].Flags & FLAG_CAN_BE_HIGH)) {
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(channel_offset_cb), "+1");
                idx_count++;
                if (new_offset == 1) {
                    active_idx = idx_count;
                }
            }
            break;
        }
    }

    gtk_combo_box_set_active(GTK_COMBO_BOX(channel_offset_cb), active_idx);


    if (set) {
        change_airpcap_settings = TRUE;

        if_info->channelInfo.ExtChannel = new_offset;
        if (!airpcap_update_frequency_and_offset(if_info)) {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Adapter failed to be set with the following settings: Frequency - %d   Extension Channel - %d", if_info->channelInfo.Frequency, if_info->channelInfo.ExtChannel);
        }
    }

    if (idx_count < 1) {
        gtk_widget_set_sensitive(channel_offset_cb, FALSE);
    }
}

/*
 * Returns '1' if this is the "Any" adapter, '0' otherwise
 */
int
airpcap_if_is_any(airpcap_if_info_t* if_info)
{
    if (g_ascii_strcasecmp(if_info->name,AIRPCAP_DEVICE_ANY_EXTRACT_STRING)==0)
        return 1;
    else
        return 0;
}

/*
 * Update channel combo box. If the airpcap interface is "Any", the combo box will be disabled.
 */
void
airpcap_update_channel_combo(GtkWidget* channel_cb, airpcap_if_info_t* if_info)
{
    if (!if_info || airpcap_if_is_any(if_info) || !airpcap_if_selected)
    {
        gtk_combo_box_set_active(GTK_COMBO_BOX(channel_cb), -1);
        change_airpcap_settings = FALSE;
        gtk_widget_set_sensitive(GTK_WIDGET(channel_cb),FALSE);
    }
    else
    {
        while (gtk_tree_model_iter_n_children(gtk_combo_box_get_model(GTK_COMBO_BOX(channel_cb)), NULL) > 0) {
            gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(channel_cb), 0);
        }

        if (if_info->pSupportedChannels != NULL && if_info->numSupportedChannels > 0) {
            guint i;
            for (i = 0; i<(if_info->numSupportedChannels); i++) {
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(channel_cb), ieee80211_mhz_to_str(airpcap_if_selected->pSupportedChannels[i].Frequency));
            }
        }

        airpcap_channel_combo_set_by_frequency(channel_cb, if_info->channelInfo.Frequency);
        change_airpcap_settings = TRUE;
        gtk_widget_set_sensitive(GTK_WIDGET(channel_cb), TRUE);
    }
}

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
static void
airpcap_add_keys_to_driver_from_list(GtkListStore *key_list_store, airpcap_if_info_t *fake_if_info)
{
    GtkTreePath  *path;
    GtkTreeIter   iter;
    GtkTreeModel *model = GTK_TREE_MODEL(key_list_store);

    /* airpcap stuff */
    guint i, j;
    gchar s[3];
    PAirpcapKeysCollection KeysCollection;
    guint KeysCollectionSize;
    guint8 KeyByte;

    guint keys_in_list = 0;

    gchar *row_type, *row_key; /* SSID not needed for AirPcap */
    size_t key_len;

    if (fake_if_info == NULL)
        return;

    keys_in_list = gtk_tree_model_iter_n_children(model, NULL);

    /*
     * Calculate the size of the keys collection
     */
    KeysCollectionSize = (guint)AirpcapKeysCollectionSize(keys_in_list);

    /*
     * Allocate the collection
     */
    KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);

    /*
     * Populate the key collection
     */
    KeysCollection->nKeys = keys_in_list;

    for(i = 0; i < keys_in_list; i++)
    {
        path = gtk_tree_path_new_from_indices(i, -1);
        gtk_tree_model_get_iter(model, &iter, path);
        gtk_tree_path_free(path);
        gtk_tree_model_get(model, &iter,
                           KL_COL_TYPE, &row_type,
                           KL_COL_KEY, &row_key,
                           -1);

        if (g_ascii_strcasecmp(row_type,AIRPCAP_WEP_KEY_STRING) == 0)
            KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WEP;
        else if (g_ascii_strcasecmp(row_type,AIRPCAP_WPA_PWD_KEY_STRING) == 0)
            KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WPA_PWD;
        else if (g_ascii_strcasecmp(row_type,AIRPCAP_WPA_BIN_KEY_STRING) == 0)
            KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WPA_PMK;

        /* Retrieve the Item corresponding to the i-th key */
        key_len = strlen(row_key);

        KeysCollection->Keys[i].KeyLen = (guint) key_len / 2;
        memset(&KeysCollection->Keys[i].KeyData, 0, sizeof(KeysCollection->Keys[i].KeyData));

        /* Key must be saved in a different way, depending on its type... */
        if (KeysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
        {
            for(j = 0 ; j < key_len; j += 2)
            {
                s[0] = row_key[j];
                s[1] = row_key[j+1];
                s[2] = '\0';
                KeyByte = (guint8)strtol(s, NULL, 16);
                KeysCollection->Keys[i].KeyData[j / 2] = KeyByte;
            }
        }
        g_free(row_type);
        g_free(row_key);
    }

    /*
     * Free the old adapter key collection!
     */
    if (fake_if_info->keysCollection != NULL)
        g_free(fake_if_info->keysCollection);

    /*
     * Set this collection ad the new one
     */
    fake_if_info->keysCollection = KeysCollection;
    fake_if_info->keysCollectionSize = KeysCollectionSize;
    return;
}

/*
 * This function will take the current keys (widget list), specified for the
 * current adapter, and save them as default for ALL the others.
 */
void
airpcap_read_and_save_decryption_keys_from_list_store(GtkListStore* key_list_store, airpcap_if_info_t* info_if, GList* if_list)
{
    GtkTreeIter iter;
    GtkTreeModel *model = GTK_TREE_MODEL(key_list_store);
    gboolean items_left;
    gint if_n = 0;
    gint i    = 0;
    airpcap_if_info_t* curr_if = NULL;
    airpcap_if_info_t* fake_info_if = NULL;
    GList* key_list = NULL;

    char* tmp_type = NULL;
    char* tmp_key  = NULL;
    char* tmp_ssid = NULL;

    decryption_key_t* tmp_dk=NULL;

    /*
     * Save the keys for Wireshark...
     */

    /* Create a list of keys from the list store */
    for (items_left = gtk_tree_model_get_iter_first (model, &iter);
         items_left;
         items_left = gtk_tree_model_iter_next (model, &iter)) {

        gtk_tree_model_get(model, &iter,
                           KL_COL_TYPE, &tmp_type,
                           KL_COL_KEY, &tmp_key,
                           KL_COL_SSID, &tmp_ssid,
                           -1);

        if (g_ascii_strcasecmp(tmp_type, AIRPCAP_WEP_KEY_STRING) == 0)
        {
            tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
            tmp_dk->key = g_string_new(tmp_key);
            tmp_dk->ssid = NULL;
            tmp_dk->type = AIRPDCAP_KEY_TYPE_WEP;
            tmp_dk->bits = (guint) tmp_dk->key->len * 4;
            key_list = g_list_append(key_list,tmp_dk);
        }
        else if (g_ascii_strcasecmp(tmp_type, AIRPCAP_WPA_PWD_KEY_STRING) == 0)
        {
            tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
            tmp_dk->key = g_string_new(tmp_key);
            tmp_dk->ssid = g_byte_array_new();
            uri_str_to_bytes(tmp_ssid?tmp_ssid:"", tmp_dk->ssid);
            tmp_dk->type = AIRPDCAP_KEY_TYPE_WPA_PWD;
            tmp_dk->bits = 256;
            key_list = g_list_append(key_list,tmp_dk);
        }
        else if (g_ascii_strcasecmp(tmp_type, AIRPCAP_WPA_BIN_KEY_STRING) == 0)
        {
            tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
            tmp_dk->key = g_string_new(tmp_key);
            tmp_dk->ssid = NULL; /* No SSID in this case */
            tmp_dk->type = AIRPDCAP_KEY_TYPE_WPA_PMK;
            tmp_dk->bits = 256;
            key_list = g_list_append(key_list,tmp_dk);
        }
        g_free(tmp_type);
        g_free(tmp_ssid);
    }

    save_wlan_wireshark_wep_keys(key_list);
    /* The key_list has been freed!!! */

    /*
     * Save the key list for driver.
     */
    if ( (if_list == NULL) || (info_if == NULL) ) return;

    fake_info_if = airpcap_driver_fake_if_info_new();

    airpcap_add_keys_to_driver_from_list(key_list_store,fake_info_if);
    airpcap_save_driver_if_configuration(fake_info_if);
    airpcap_if_info_free(fake_info_if);

    if_n = g_list_length(if_list);

    /* For all the adapters in the list, empty the key list */
    for(i = 0; i < if_n; i++)
    {
        curr_if = (airpcap_if_info_t*)g_list_nth_data(if_list,i);

        if (curr_if != NULL)
        {
            /* XXX - Set an empty collection */
            airpcap_if_clear_decryption_settings(curr_if);

            /* Save to registry */
            airpcap_save_selected_if_configuration(curr_if);
        }
    }
}

/*
 * This function will load from the preferences file ALL the
 * keys (WEP, WPA and WPA_BIN) and will set them as default for
 * each adapter. To do this, it will save the keys in the registry...
 * A check will be performed, to make sure that keys found in
 * registry and keys found in Wireshark preferences are the same. If not,
 * the user will be asked to choose if use all keys (merge them),
 * or use Wireshark preferences ones. In the last case, registry keys will
 * be overwritten for all the connected AirPcap adapters.
 * In the first case, adapters will use their own keys, but those
 * keys will not be accessible via Wireshark...
 */
gboolean
airpcap_check_decryption_keys(GList* if_list)
{
    gint if_n            = 0;
    gint i               = 0;
    gint n_adapters_keys = 0;
    gint n_driver_keys   = 0;
    airpcap_if_info_t* curr_if = NULL;

    GList* wireshark_key_list;
    GList* driver_key_list;
    GList* curr_adapter_key_list;

    gboolean equals = TRUE;
    gboolean adapters_keys_equals=TRUE;

    /*
     * If no AirPcap interface is found, return TRUE, so Wireshark
     * will use HIS OWN keys.
     */
    if (if_list == NULL)
        return TRUE;

    if_n = g_list_length(if_list);

    /* Get Wireshark preferences keys */
    wireshark_key_list = get_wireshark_keys();

    /* Retrieve AirPcap driver's keys */
    driver_key_list = get_airpcap_driver_keys();
    n_driver_keys = g_list_length(driver_key_list);

    equals &= key_lists_are_equal(wireshark_key_list,driver_key_list);

    for(i = 0; i < if_n; i++)
    {
        curr_if = (airpcap_if_info_t*)g_list_nth_data(if_list,i);
        curr_adapter_key_list = get_airpcap_device_keys(curr_if);
        n_adapters_keys += g_list_length(curr_adapter_key_list);
        adapters_keys_equals &= key_lists_are_equal(wireshark_key_list,curr_adapter_key_list);
    }

    if (n_adapters_keys != 0) /* If for some reason at least one specific key has been found */
        equals &= adapters_keys_equals;        /* */

    if (n_driver_keys == 0) /* No keys set in any of the AirPcap adapters... */
        return TRUE; /* Use Wireshark keys and set them ad default for airpcap devices */

    return equals;
}

/*
 * This function will load from the preferences file ALL the
 * keys (WEP, WPA_PWD and WPA_BIN) and will set them as default for
 * each adapter. To do this, it will save the keys in the registry...
 * A check will be performed, to make sure that keys found in
 * registry and keys found in Wireshark preferences are the same. If not,
 * the user will be asked to choose if use all keys (merge them),
 * or use Wireshark preferences ones. In the last case, registry keys will
 * be overwritten for all the connected AirPcap adapters.
 * In the first case, adapters will use their own keys, but those
 * keys will not be accessible via Wireshark...
 */
void
airpcap_load_decryption_keys(GList* if_list)
{
    gint if_n = 0;
    gint i    = 0;

    if (if_list == NULL) return;

    if_n = g_list_length(if_list);

    for(i = 0; i < if_n; i++)
    {
        load_wlan_driver_wep_keys();
    }
}

/*
 * This function will set the gibven GList of decryption_key_t structures
 * as the defoult for both Wireshark and the AirPcap adapters...
 */
void
airpcap_save_decryption_keys(GList* key_list, GList* adapters_list)
{
    gint if_n = 0;
    gint i    = 0;
    airpcap_if_info_t* curr_if = NULL;
    GList* empty_key_list = NULL;

    if ( (key_list == NULL) || (adapters_list == NULL)) return;

    if_n = g_list_length(adapters_list);

    /* Set the driver's global list of keys. */
    write_wlan_driver_wep_keys_to_registry(key_list);

    /* Empty the key list for each interface */
    for(i = 0; i < if_n; i++)
    {
        curr_if = (airpcap_if_info_t*)g_list_nth_data(adapters_list,i);
        write_wlan_wep_keys_to_registry(curr_if,empty_key_list);
    }

    /*
     * This will set the keys of the current adapter as Wireshark default...
     * Now all the adapters have the same keys, so curr_if is ok as any other...
     */
    save_wlan_wireshark_wep_keys(key_list);
}

/*
 * This function is used to enable/disable the toolbar widgets
 * depending on the type of interface selected... Not the whole
 * toolbar must be grayed/enabled ... Only some widgets...
 */
void
airpcap_enable_toolbar_widgets(GtkWidget* w, gboolean en)
{
    GtkWidget   *toolbar_tb,
                *if_description_lb,
                *toolbar_channel_cb,
                *channel_lb,
                *channel_offset_cb,
                *channel_offset_lb,
                *fcs_cb,
                *fcs_lb,
                *advanced_bt;

    if (w == NULL)
        return;

    toolbar_tb = w;

    if_description_lb   = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_INTERFACE_KEY);
    channel_lb          = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
    toolbar_channel_cb  = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_KEY);
    channel_offset_cb   = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY);
    channel_offset_lb   = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY);
    fcs_lb              = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
    fcs_cb              = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    advanced_bt         = (GtkWidget *)g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_ADVANCED_KEY);


    if (if_description_lb != NULL)
        gtk_widget_set_sensitive(if_description_lb,en);
    if (channel_lb != NULL)
        gtk_widget_set_sensitive(channel_lb,en);
    if (toolbar_channel_cb != NULL)
        gtk_widget_set_sensitive(toolbar_channel_cb,en);
    if (channel_offset_cb != NULL)
        gtk_widget_set_sensitive(channel_offset_cb,en);
    if (channel_offset_lb != NULL)
        gtk_widget_set_sensitive(channel_offset_lb,en);
    if (fcs_lb != NULL)
        gtk_widget_set_sensitive(fcs_lb,en);
    if (fcs_cb != NULL)
        gtk_widget_set_sensitive(fcs_cb,en);
    if (advanced_bt != NULL)
        gtk_widget_set_sensitive(advanced_bt,en);

    return;
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
