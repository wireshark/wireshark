/* airpcap_gui_utils.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_AIRPCAP

#include <gtk/gtk.h>
#include <glib.h>

#include <string.h>

#include <epan/filesystem.h>

#include "gtk/main.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "simple_dialog.h"
#include "dfilter_expr_dlg.h"
#include "compat_macros.h"
#include "gtkglobals.h"
#include "help_dlg.h"

#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"

#include "../airpdcap/airpdcap_ws.h"

#include "keys.h"

/*
 * Used to retrieve a string containing a list of all the channels
 * on which at least one adapter is capturing. This is true
 * if the adapter passed as parameter is "Any" ... if not,
 * this function returns the only channel number string.
 */
gchar*
airpcap_get_all_channels_list(airpcap_if_info_t* if_info)
{
gchar *channels;
gchar *tmp;
guint n,i; 
GList *current_item;
airpcap_if_info_t* current_adapter;

/* Allocate the string used to store the ASCII representation of the WEP key */
channels = (gchar*)g_malloc(sizeof(gchar)*128);
/* Make sure that the first char is '\0' in order to make g_strlcat() work */
channels[0]='\0';

if(airpcap_if_is_any(if_info))
    {
    n = g_list_length(airpcap_if_list);
        
    for(i = 0; i < n; i++)
        {
        current_item = g_list_nth(airpcap_if_list,i);
        current_adapter = (airpcap_if_info_t*)current_item->data;
        if(current_adapter != if_info)
            {
            tmp = g_strdup_printf("%d",current_adapter->channel);
            g_strlcat(channels,tmp,128);
            g_free(tmp);
            
            if(i<(n-1)) g_strlcat(channels,",",128);  
            }
        }       
    }
    
return channels;
}

/*
 * Set up the airpcap toolbar for the new capture interface
 */
void
airpcap_set_toolbar_start_capture(airpcap_if_info_t* if_info)
{
GtkWidget *airpcap_toolbar_label;
GtkWidget *airpcap_toolbar_channel;
GtkWidget *airpcap_toolbar_channel_lb;
GtkWidget *airpcap_toolbar_button;
GtkWidget *airpcap_toolbar_fcs;
GtkWidget *airpcap_toolbar_fcs_lb;
GtkWidget *airpcap_toolbar_decryption;
GtkWidget *airpcap_toolbar_decryption_lb;
GtkWidget *airpcap_toolbar_keys_button;

gchar *if_label_text;

airpcap_toolbar_label    = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_INTERFACE_KEY);
airpcap_toolbar_channel  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_CHANNEL_KEY);
airpcap_toolbar_channel_lb  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
airpcap_toolbar_fcs  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
airpcap_toolbar_fcs_lb  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
airpcap_toolbar_button   = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_ADVANCED_KEY);
airpcap_toolbar_decryption = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_KEY);
airpcap_toolbar_decryption_lb = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY);
airpcap_toolbar_keys_button = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY);

/* The current interface is an airpcap interface */
if(if_info != NULL)
	{
	gtk_widget_set_sensitive(airpcap_tb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_label,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_keys_button,FALSE);
    airpcap_update_channel_combo(GTK_WIDGET(airpcap_toolbar_channel),if_info);

	/*decription check box*/
   	gtk_signal_handler_block_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);
	if(if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
   	gtk_signal_handler_unblock_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);

	if_label_text = g_strdup_printf("Current Wireless Interface: #%s", airpcap_get_if_string_number(if_info));
	gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
	g_free(if_label_text);
	}
else /* Current interface is NOT an AirPcap one... */
		{
		gtk_widget_set_sensitive(airpcap_tb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_label,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_keys_button,FALSE);
	airpcap_set_toolbar_no_if(airpcap_tb);
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
GtkWidget *airpcap_toolbar_channel;
GtkWidget *airpcap_toolbar_channel_lb;
GtkWidget *airpcap_toolbar_button;
GtkWidget *airpcap_toolbar_fcs;
GtkWidget *airpcap_toolbar_fcs_lb;
GtkWidget *airpcap_toolbar_decryption;
GtkWidget *airpcap_toolbar_decryption_lb;
GtkWidget *airpcap_toolbar_keys_button;

gchar *if_label_text;

airpcap_toolbar_crc_filter_combo = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
airpcap_toolbar_label    = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_INTERFACE_KEY);
airpcap_toolbar_channel  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_CHANNEL_KEY);
airpcap_toolbar_channel_lb  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
airpcap_toolbar_fcs  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
airpcap_toolbar_fcs_lb  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
airpcap_toolbar_button   = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_ADVANCED_KEY);
airpcap_toolbar_decryption = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_KEY);
airpcap_toolbar_decryption_lb = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY);
airpcap_toolbar_keys_button = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY);

/* The current interface is an airpcap interface */
if(if_info != NULL)
	{
	gtk_widget_set_sensitive(airpcap_tb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_label,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_crc_filter_combo,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_keys_button,TRUE);
	airpcap_validation_type_combo_set_by_type(GTK_WIDGET(airpcap_toolbar_crc_filter_combo),if_info->CrcValidationOn);
    airpcap_update_channel_combo(GTK_WIDGET(airpcap_toolbar_channel),if_info);

	/*decription check box*/
   	gtk_signal_handler_block_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);
	if(if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
   	gtk_signal_handler_unblock_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);


	if_label_text = g_strdup_printf("Current Wireless Interface: #%s", airpcap_get_if_string_number(if_info));
	gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
	g_free(if_label_text);
	}
else
	{
	gtk_widget_set_sensitive(airpcap_tb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_label,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel_lb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_fcs_lb,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_crc_filter_combo,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption_lb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_keys_button,TRUE);
	airpcap_set_toolbar_no_if(airpcap_tb);
	}
}

/*
 * Add a key (string) to the given list
 */
void
airpcap_add_key_to_list(GtkWidget *keylist, gchar* type, gchar* key, gchar* ssid)
{

gchar*       new_row[3];

new_row[0] = g_strdup(type);
new_row[1] = g_strdup(key);
new_row[2] = g_strdup(ssid);

gtk_clist_append(GTK_CLIST(keylist),new_row);

g_free(new_row[0]);
g_free(new_row[1]);
g_free(new_row[2]);
}

/*
 * Modify a key given a list and a row
 */
void
airpcap_modify_key_in_list(GtkWidget *keylist, gint row, gchar* type, gchar* key, gchar* ssid)
{
gchar*       new_row[3];

new_row[0] = g_strdup(type);
new_row[1] = g_strdup(key);
new_row[2] = g_strdup(ssid);

gtk_clist_set_text(GTK_CLIST(keylist),row,0,new_row[0]);
gtk_clist_set_text(GTK_CLIST(keylist),row,1,new_row[1]);
gtk_clist_set_text(GTK_CLIST(keylist),row,2,new_row[2]);

g_free(new_row[0]);
g_free(new_row[1]);
g_free(new_row[2]);
}

/*
 * Fill the list with the keys. BEWARE! At this point, Wireshark and Drivers
 * keys should be EQUALS! But is better to load keys from Wireshark, because
 * the driver is not always present, and maybe that cannot support some keys
 * (i.e. the WPA problem)
 */
void
airpcap_fill_key_list(GtkWidget *keylist)
{
gchar*		 s = NULL;
gchar*		 s2 = NULL;
unsigned int i,n;
gchar*       new_row[3];
airpcap_if_info_t* fake_if_info;
GList*		 wireshark_key_list=NULL;
decryption_key_t* curr_key = NULL;

n = 0;

fake_if_info = airpcap_driver_fake_if_info_new();
	
	/* We can retrieve the driver's key list (i.e. we have the right .dll)*/
		wireshark_key_list = get_wireshark_keys();
		n = g_list_length(wireshark_key_list);
		
 		for(i = 0; i < n; i++)
			{
			curr_key = (decryption_key_t*)g_list_nth_data(wireshark_key_list,i);
			
			if(curr_key->type == AIRPDCAP_KEY_TYPE_WEP)
			{
				s = g_strdup(curr_key->key->str);
				
            new_row[0] = g_strdup(AIRPCAP_WEP_KEY_STRING);
			new_row[1] = g_strdup(s);
			new_row[2] = g_strdup("");

				gtk_clist_append(GTK_CLIST(keylist),new_row);
				
				g_free(new_row[0]);
				g_free(new_row[1]);
				g_free(new_row[2]);
				
				g_free(s);
            }
			else if(curr_key->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
            {
				s = g_strdup(curr_key->key->str);
				if(curr_key->ssid != NULL) 
					s2= g_strdup(curr_key->ssid->str);
				else 
					s2 = NULL;
				
				new_row[0] = g_strdup(AIRPCAP_WPA_PWD_KEY_STRING);
			new_row[1] = g_strdup(s);

				if(curr_key->ssid != NULL) 
					new_row[2] = g_strdup(s2);
            else
			new_row[2] = g_strdup("");
			
			gtk_clist_append(GTK_CLIST(keylist),new_row);
			
			g_free(new_row[0]);
			g_free(new_row[1]);
			g_free(new_row[2]);
			
			g_free(s);
				if(s2 != NULL)  g_free(s2);
			}
			else if(curr_key->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
			{
			s = g_strdup(curr_key->key->str);
			
				new_row[0] = g_strdup(AIRPCAP_WPA_BIN_KEY_STRING);
			new_row[1] = g_strdup(s);
			new_row[2] = g_strdup("");

			gtk_clist_append(GTK_CLIST(keylist),new_row);
			
			g_free(new_row[0]);
			g_free(new_row[1]);
			g_free(new_row[2]);
			
			g_free(s);
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
	if(!(g_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_ALL,name)))
		{
		return AIRPCAP_VT_ACCEPT_EVERYTHING;
		}
	else if(!(g_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_CORRECT,name)))
		{
		return AIRPCAP_VT_ACCEPT_CORRECT_FRAMES;
		}
	else if(!(g_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT,name)))
		{
		return AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES;
		}
	else
		{
		return AIRPCAP_VT_UNKNOWN;
		}
}

/*
 * Function used to retrieve the string name given an AirpcapValidationType,
 * or NULL in case of error
 */
gchar*
airpcap_get_validation_name(AirpcapValidationType vt)
{
	if(vt == AIRPCAP_VT_ACCEPT_EVERYTHING)
		{
		return AIRPCAP_VALIDATION_TYPE_NAME_ALL;
		}
	else if(vt == AIRPCAP_VT_ACCEPT_CORRECT_FRAMES)
		{
		return AIRPCAP_VALIDATION_TYPE_NAME_CORRECT;
		}
	else if(vt == AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES)
		{
		return AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT;
		}
	else if(vt == AIRPCAP_VT_UNKNOWN)
		{
		return AIRPCAP_VALIDATION_TYPE_NAME_UNKNOWN;
		}
	return NULL;
}

/*
 * Returns the AirpcapLinkType corresponding to the given string name.
 */
AirpcapLinkType
airpcap_get_link_type(const gchar* name)
{
	if(!(g_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_ONLY,name)))
		{
		return AIRPCAP_LT_802_11;
		}
	else if(!(g_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO,name)))
		{
		return AIRPCAP_LT_802_11_PLUS_RADIO;
		}
	else
		{
		return AIRPCAP_LT_UNKNOWN;
		}
}

/*
 * Returns the string name corresponding to the given AirpcapLinkType, or
 * NULL in case of error.
 */
gchar*
airpcap_get_link_name(AirpcapLinkType lt)
{
	if(lt == AIRPCAP_LT_802_11)
		{
		return AIRPCAP_LINK_TYPE_NAME_802_11_ONLY;
		}
	else if(lt == AIRPCAP_LT_802_11_PLUS_RADIO)
		{
		return AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO;
		}
	else if(lt == AIRPCAP_LT_UNKNOWN)
		{
		return AIRPCAP_LINK_TYPE_NAME_UNKNOWN;
		}
	return NULL;
}

/*
 * Sets the entry of the link type combo using the AirpcapLinkType.
 */
void
airpcap_link_type_combo_set_by_type(GtkWidget* c, AirpcapLinkType type)
{
gchar* s;

s = airpcap_get_link_name(type);
gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(c)->entry),s);
}

/*
 * Retrieves the name in link type the combo entry.
 */
AirpcapLinkType
airpcap_link_type_combo_get_type(GtkWidget* c)
{
const gchar* s;

s = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(c)->entry));

return airpcap_get_link_type(s);
}

/*
 * Sets the entry of the validation combo using the AirpcapValidationType.
 */
void
airpcap_validation_type_combo_set_by_type(GtkWidget* c, AirpcapValidationType type)
{
const gchar* s;

s = airpcap_get_validation_name(type);
gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(c)->entry),s);
}

/*
 * Retrieves the name in the validation combo entry.
 */
AirpcapValidationType
airpcap_validation_type_combo_get_type(GtkWidget* c)
{
const gchar* s;

s = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(c)->entry));

return airpcap_get_validation_type(s);
}

/*
 * Retrieve the UINT corresponding to the given string (channel only, handle with care!)
 */
UINT
airpcap_get_channel_number(const gchar* s)
{
int ch_num;

sscanf(s,"%d",&ch_num);

/* XXX - check for ch_num btween 1-14, and return -1 otherwise??? */

return ch_num;
}

/*
 * Returns the string corresponding to the given UINT (1-14, for channel only)
 */
gchar*
airpcap_get_channel_name(UINT n)
{
return g_strdup_printf("%d",n);
}

/*
 * Set the combo box entry string given an UINT channel number
 */
void
airpcap_channel_combo_set_by_number(GtkWidget* w,UINT channel)
{
	gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(w)->entry),airpcap_get_channel_name(channel));
}

/*
 * Returns '1' if this is the "Any" adapter, '0' otherwise
 */
int
airpcap_if_is_any(airpcap_if_info_t* if_info)
{
if(g_strcasecmp(if_info->name,AIRPCAP_DEVICE_ANY_EXTRACT_STRING)==0)  
    return 1;
else
    return 0;                                   
}

/*
 * Update channel combo box. If the airpcap interface is "Any", the combo box will be disabled.
 */
void 
airpcap_update_channel_combo(GtkWidget* w, airpcap_if_info_t* if_info)
{
gchar* channels_list;
                                        
if(airpcap_if_is_any(if_info))
    {
    channels_list = airpcap_get_all_channels_list(if_info);
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(w)->entry),channels_list);
    g_free(channels_list);
    gtk_widget_set_sensitive(GTK_WIDGET(w),FALSE);
    }
else
    {
    airpcap_channel_combo_set_by_number(w,if_info->channel);
    gtk_widget_set_sensitive(GTK_WIDGET(w),TRUE);
    }
}

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
void
airpcap_add_keys_from_list(GtkWidget *key_ls, airpcap_if_info_t *if_info)
{
GString		*new_key;

gchar		*text_entered = NULL;

/* airpcap stuff */
UINT i, j;
gchar s[3];
PAirpcapKeysCollection KeysCollection;
ULONG KeysCollectionSize;
UCHAR KeyByte;

UINT keys_in_list = 0;

gchar *row_type,
      *row_key,
      *row_ssid;

keys_in_list = GTK_CLIST(key_ls)->rows;

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
	/* Simple dialog ERROR */
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","Failed mamory allocation for KeysCollection!");
	return;
}

/*
 * Populate the key collection
 */
KeysCollection->nKeys = keys_in_list;

for(i = 0; i < keys_in_list; i++)
{
    /* Retrieve the row infos */
    gtk_clist_get_text(GTK_CLIST(key_ls),i,0,&row_type);  
    gtk_clist_get_text(GTK_CLIST(key_ls),i,1,&row_key);
    gtk_clist_get_text(GTK_CLIST(key_ls),i,2,&row_ssid); 
    
    if(g_strcasecmp(row_type,AIRPCAP_WEP_KEY_STRING) == 0)
    KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WEP;
    else if(g_strcasecmp(row_type,AIRPCAP_WPA_PWD_KEY_STRING) == 0)
    KeysCollection->Keys[i].KeyType = AIRPCAP_KEYTYPE_TKIP;
    else if(g_strcasecmp(row_type,AIRPCAP_WPA_BIN_KEY_STRING) == 0)
    KeysCollection->Keys[i].KeyType = AIRPCAP_KEYTYPE_CCMP;

	/* Retrieve the Item corresponding to the i-th key */
	new_key = g_string_new(row_key);
	
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
}

/*
 * Free the old adapter key collection!
 */
if(airpcap_if_selected->keysCollection != NULL)
	g_free(airpcap_if_selected->keysCollection);

/*
 * Set this collection ad the new one
 */
airpcap_if_selected->keysCollection = KeysCollection;
airpcap_if_selected->keysCollectionSize = KeysCollectionSize;

return;
}

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
void
airpcap_add_keys_to_driver_from_list(GtkWidget *key_ls,airpcap_if_info_t *fake_if_info)
{
GString		*new_key;

gchar		*text_entered = NULL;

/* airpcap stuff */
UINT i, j;
gchar s[3];
PAirpcapKeysCollection KeysCollection;
ULONG KeysCollectionSize;
UCHAR KeyByte;

UINT keys_in_list = 0;

gchar *row_type,
      *row_key,
      *row_ssid;

if(fake_if_info == NULL)
	return;

keys_in_list = GTK_CLIST(key_ls)->rows;

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
	/* Simple dialog ERROR */
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","Failed mamory allocation for KeysCollection!");
	return;
}

/*
 * Populate the key collection
 */
KeysCollection->nKeys = keys_in_list;

for(i = 0; i < keys_in_list; i++)
{
    /* Retrieve the row infos */
    gtk_clist_get_text(GTK_CLIST(key_ls),i,0,&row_type);  
    gtk_clist_get_text(GTK_CLIST(key_ls),i,1,&row_key);
    gtk_clist_get_text(GTK_CLIST(key_ls),i,2,&row_ssid); 
    
    if(g_strcasecmp(row_type,AIRPCAP_WEP_KEY_STRING) == 0)
    KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WEP;
    else if(g_strcasecmp(row_type,AIRPCAP_WPA_PWD_KEY_STRING) == 0)
    KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WPA_PWD;
    else if(g_strcasecmp(row_type,AIRPCAP_WPA_BIN_KEY_STRING) == 0)
    KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WPA_PMK;

	/* Retrieve the Item corresponding to the i-th key */
	new_key = g_string_new(row_key);
	
	KeysCollection->Keys[i].KeyLen = new_key->len / 2;
	memset(&KeysCollection->Keys[i].KeyData, 0, sizeof(KeysCollection->Keys[i].KeyData));

	/* Key must be saved in adifferent way, depending on its type... */
	if(KeysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
	{
	for(j = 0 ; j < new_key->len; j += 2)
	{
		s[0] = new_key->str[j];
		s[1] = new_key->str[j+1];
		s[2] = '\0';
		KeyByte = (UCHAR)strtol(s, NULL, 16);
		KeysCollection->Keys[i].KeyData[j / 2] = KeyByte;
	}
}
	/* XXX - Save the keys that are not WEP!!! */
}

/*
 * Free the old adapter key collection!
 */
if(fake_if_info->keysCollection != NULL)
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
airpcap_read_and_save_decryption_keys_from_clist(GtkWidget* key_ls, airpcap_if_info_t* info_if, GList* if_list)
{
gint if_n = 0;
gint i = 0;
gint r = 0;
gint n = 0;
airpcap_if_info_t* curr_if = NULL;
airpcap_if_info_t* fake_info_if = NULL;
GList* key_list=NULL;

char* tmp_type = NULL;
char* tmp_key = NULL;
char* tmp_ssid = NULL;

decryption_key_t* tmp_dk=NULL;

/* 
 * Save the keys for Wireshark...
 */

/* Create a list of keys from the list widget... */
n = GTK_CLIST(key_ls)->rows;

for(i = 0; i < n; i++)
	{
	/* XXX - Create a decryption_key_t struct, and pass a list of those structs!!! */
	gtk_clist_get_text(GTK_CLIST(key_ls),i,0,&tmp_type);
	gtk_clist_get_text(GTK_CLIST(key_ls),i,1,&tmp_key);
	gtk_clist_get_text(GTK_CLIST(key_ls),i,2,&tmp_ssid);

	if(g_strcasecmp(tmp_type,AIRPCAP_WEP_KEY_STRING) == 0)
		{
		tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
		tmp_dk->key = g_string_new(tmp_key);
		tmp_dk->ssid = NULL;
		tmp_dk->type = AIRPDCAP_KEY_TYPE_WEP;
		tmp_dk->bits = tmp_dk->key->len * 4;
		key_list = g_list_append(key_list,tmp_dk);
		}
	else if(g_strcasecmp(tmp_type,AIRPCAP_WPA_PWD_KEY_STRING) == 0)
		{
		tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
		tmp_dk->key = g_string_new(tmp_key);
		tmp_dk->ssid = g_string_new(tmp_ssid);
		tmp_dk->type = AIRPDCAP_KEY_TYPE_WPA_PWD;
		tmp_dk->bits = 256;
		key_list = g_list_append(key_list,tmp_dk);
		}
	else if(g_strcasecmp(tmp_type,AIRPCAP_WPA_BIN_KEY_STRING) == 0)
		{
		tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
		tmp_dk->key = g_string_new(tmp_key);
		tmp_dk->ssid = NULL; /* No SSID in this case */
		tmp_dk->type = AIRPDCAP_KEY_TYPE_WPA_PMK;
		tmp_dk->bits = 256;
		key_list = g_list_append(key_list,tmp_dk);
		}
	}

r = save_wlan_wireshark_wep_keys(key_list);
/* The key_list has been freed!!! */

/*
 * Save the key list for driver.
 */
if( (if_list == NULL) || (info_if == NULL) ) return;

fake_info_if = airpcap_driver_fake_if_info_new();

airpcap_add_keys_to_driver_from_list(key_ls,fake_info_if);
airpcap_save_driver_if_configuration(fake_info_if);
airpcap_if_info_free(fake_info_if);

if_n = g_list_length(if_list);

/* For all the adapters in the list, empty the key list */
for(i = 0; i < if_n; i++)
      {
      curr_if = (airpcap_if_info_t*)g_list_nth_data(if_list,i);
      
      if(curr_if != NULL)
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
gint if_n = 0;
gint i = 0;
gint n_adapters_keys = 0; 
gint n_driver_keys = 0;
gint n_wireshark_keys = 0;
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
if(if_list == NULL) 
    return TRUE;

if_n = g_list_length(if_list);

/* Get Wireshark preferences keys */
wireshark_key_list = get_wireshark_keys();
n_wireshark_keys = g_list_length(wireshark_key_list);

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

if(n_adapters_keys != 0) /* If for some reason at least one specific key has been found */
	equals &= adapters_keys_equals;	/* */

if(n_driver_keys == 0) /* No keys set in any of the AirPcap adapters... */
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
gint i = 0;
airpcap_if_info_t* curr_if = NULL;

if(if_list == NULL) return;

if_n = g_list_length(if_list);

for(i = 0; i < if_n; i++)
      {
      curr_if = (airpcap_if_info_t*)g_list_nth_data(if_list,i);
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
gint key_n = 0;
gint i = 0;
airpcap_if_info_t* curr_if = NULL;
GList* empty_key_list = NULL;

if( (key_list == NULL) || (adapters_list == NULL)) return;

if_n = g_list_length(adapters_list);
key_n = g_list_length(key_list);

/* Set the driver's global list of keys. */
write_wlan_driver_wep_keys_to_regitry(key_list);

/* Empty the key list for each interface */
for(i = 0; i < if_n; i++)
      {
      curr_if = (airpcap_if_info_t*)g_list_nth_data(adapters_list,i);
      write_wlan_wep_keys_to_regitry(curr_if,empty_key_list);
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
GtkWidget	*toolbar_tb,
			*if_description_lb,
			*channel_cb,
			*channel_lb,
			*fcs_cb,
			*fcs_lb,
			*advanced_bt;

if(w == NULL)
	return;

toolbar_tb = w;

if_description_lb	= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_INTERFACE_KEY);
channel_lb			= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
channel_cb			= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_CHANNEL_KEY);
fcs_lb				= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
fcs_cb				= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
advanced_bt			= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_ADVANCED_KEY);


if(if_description_lb != NULL)	gtk_widget_set_sensitive(if_description_lb,en);
if(channel_lb != NULL)			gtk_widget_set_sensitive(channel_lb,en);
if(channel_cb != NULL)			gtk_widget_set_sensitive(channel_cb,en);
if(fcs_lb != NULL)				gtk_widget_set_sensitive(fcs_lb,en);
if(fcs_cb != NULL)				gtk_widget_set_sensitive(fcs_cb,en);
if(advanced_bt != NULL)			gtk_widget_set_sensitive(advanced_bt,en);

return;
}

/*
 * This function sets up the correct airpcap toolbar that must
 * be displayed when no airpcap if is found on the system...
 */
void
airpcap_set_toolbar_no_if(GtkWidget* w)
{
GtkWidget	*toolbar_tb,
			*if_description_lb,
			*channel_cb,
			*channel_lb,
			*fcs_cb,
			*fcs_lb,
			*advanced_bt;

if(w == NULL)
	return;

toolbar_tb = w;

if_description_lb	= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_INTERFACE_KEY);
channel_lb			= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
channel_cb			= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_CHANNEL_KEY);
fcs_lb				= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
fcs_cb				= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
advanced_bt			= OBJECT_GET_DATA(toolbar_tb,AIRPCAP_TOOLBAR_ADVANCED_KEY);

if(fcs_cb != NULL)				gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(fcs_cb)->entry),"");
if(channel_cb != NULL)			gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_cb)->entry),"");
if(if_description_lb != NULL)	gtk_label_set_text(GTK_LABEL(if_description_lb),"Current Wireless Interface: None");

/*if(if_description_lb != NULL)	gtk_widget_set_sensitive(if_description_lb,FALSE);
if(channel_lb != NULL)			gtk_widget_set_sensitive(channel_lb,FALSE);
if(channel_cb != NULL)			gtk_widget_set_sensitive(channel_cb,FALSE);
if(fcs_lb != NULL)				gtk_widget_set_sensitive(fcs_lb,FALSE);
if(fcs_cb != NULL)				gtk_widget_set_sensitive(fcs_cb,FALSE);
if(advanced_bt != NULL)			gtk_widget_set_sensitive(advanced_bt,FALSE);*/
}

#endif /* HAVE_AIRPCAP */
