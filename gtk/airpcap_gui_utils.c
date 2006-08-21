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

#include "keys.h"

/*
 * Set up the airpcap toolbar for the new capture interface
 */
void
airpcap_set_toolbar_start_capture(airpcap_if_info_t* if_info)
{
GtkWidget *airpcap_toolbar_crc_filter_combo;
GtkWidget *airpcap_toolbar_label;
GtkWidget *airpcap_toolbar_channel;
GtkWidget *airpcap_toolbar_button;
GtkWidget *airpcap_toolbar_decryption;

gchar *if_label_text;

airpcap_toolbar_crc_filter_combo = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_WRONG_CRC_KEY);
airpcap_toolbar_label    = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_INTERFACE_KEY);
airpcap_toolbar_channel  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_CHANNEL_KEY);
airpcap_toolbar_button   = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_ADVANCED_KEY);
airpcap_toolbar_decryption = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_KEY);

/* The current interface is an airpcap interface */
if(if_info != NULL)
	{
	gtk_widget_set_sensitive(airpcap_tb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_crc_filter_combo,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,FALSE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption,FALSE);
	airpcap_validation_type_combo_set_by_type(GTK_WIDGET(airpcap_toolbar_crc_filter_combo),if_info->CrcValidationOn);
    airpcap_channel_combo_set_by_number(GTK_WIDGET(airpcap_toolbar_channel),if_info->channel);

	/*decription check box*/
   	gtk_signal_handler_block_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);
	if(if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
   	gtk_signal_handler_unblock_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);

	if_label_text = g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(if_info));
	gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
	g_free(if_label_text);
	}
else
	{
	if(airpcap_if_list != NULL)
		{
		gtk_widget_set_sensitive(airpcap_tb,FALSE);
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_crc_filter_combo)->entry),"");
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_channel)->entry),"");
		gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),"Not a valid Wireless Interface");
		}
	else
		{
		gtk_widget_set_sensitive(airpcap_tb,FALSE);
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_crc_filter_combo)->entry),"");
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_channel)->entry),"");
		gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),"No Wireless Interface Found");
		}
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
GtkWidget *airpcap_toolbar_button;
GtkWidget *airpcap_toolbar_decryption;

gchar *if_label_text;

airpcap_toolbar_crc_filter_combo = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_WRONG_CRC_KEY);
airpcap_toolbar_label    = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_INTERFACE_KEY);
airpcap_toolbar_channel  = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_CHANNEL_KEY);
airpcap_toolbar_button   = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_ADVANCED_KEY);
airpcap_toolbar_decryption = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_KEY);

/* The current interface is an airpcap interface */
if(if_info != NULL)
	{
	gtk_widget_set_sensitive(airpcap_tb,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_channel,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_crc_filter_combo,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_button,TRUE);
	gtk_widget_set_sensitive(airpcap_toolbar_decryption,TRUE);
	airpcap_validation_type_combo_set_by_type(GTK_WIDGET(airpcap_toolbar_crc_filter_combo),if_info->CrcValidationOn);
    airpcap_channel_combo_set_by_number(GTK_WIDGET(airpcap_toolbar_channel),if_info->channel);

	/*decription check box*/
   	gtk_signal_handler_block_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);
	if(if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
   	gtk_signal_handler_unblock_by_func (GTK_OBJECT(airpcap_toolbar_decryption),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), airpcap_tb);


	if_label_text = g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(if_info));
	gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
	g_free(if_label_text);
	}
else
	{
	if(airpcap_if_list != NULL)
		{
		gtk_widget_set_sensitive(airpcap_tb,FALSE);
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_crc_filter_combo)->entry),"");
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_channel)->entry),"");
		gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),"Not a valid Wireless Interface");
		}
	else
		{
		gtk_widget_set_sensitive(airpcap_tb,FALSE);
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_crc_filter_combo)->entry),"");
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(airpcap_toolbar_channel)->entry),"");
		gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),"No Wireless Interface Found");
		}
	}
}

/*
 * Add a key (string) to the given list
 */
void
airpcap_add_key_to_list(GtkWidget *keylist, gchar* s)
{
GtkWidget	*nl_item,*nl_lb;

nl_lb   = gtk_label_new(s);
nl_item = gtk_list_item_new();

gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
gtk_widget_show(nl_lb);
gtk_container_add(GTK_CONTAINER(keylist), nl_item);
gtk_widget_show(nl_item);
}

/*
 * Fill the list with the keys
 */
void
airpcap_fill_key_list(GtkWidget *keylist,airpcap_if_info_t* if_info)
{
GtkWidget	 *nl_item,*nl_lb;
gchar*		 s;
unsigned int i;

	if( (if_info != NULL) && (if_info->keysCollection != NULL))
		{
 		for(i = 0; i < if_info->keysCollection->nKeys; i++)
			{
			s = airpcap_get_key_string(if_info->keysCollection->Keys[i]);
			nl_lb   = gtk_label_new(s);
			nl_item = gtk_list_item_new();
			gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
			gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
			gtk_widget_show(nl_lb);
			gtk_container_add(GTK_CONTAINER(keylist), nl_item);
			gtk_widget_show(nl_item);
			}
		}
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

#endif /* HAVE_AIRPCAP */
