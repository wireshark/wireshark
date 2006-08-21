/* airpcap_dlg.c
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
#include "airpcap_dlg.h"

#include "keys.h"

/* temporary block signals to widgets */
BOOL block_advanced_signals;

/*
 * This struct will contain useful data for the selected (actual) airpcap device
 */
void
airpcap_fill_if_combo(GtkWidget *combo, GList* if_list)
{
int ifn = 0;
GList* popdown_if_list = NULL;
GList* curr = NULL;
airpcap_if_info_t* if_info = NULL;

	curr = g_list_nth(if_list, ifn);
	if_info = NULL;
	if(curr != NULL) if_info = curr->data;

	popdown_if_list = NULL;
	ifn = g_list_length(if_list) - 1;
	while(ifn >= 0) /* reverse order */
		{
		curr = g_list_nth(if_list, ifn);
		if_info = NULL;
		if(curr != NULL)
			if_info = curr->data;
		if(if_info != NULL)
			popdown_if_list = g_list_append( popdown_if_list , if_info->description) ;
		ifn--;
		}
	gtk_combo_set_popdown_strings( GTK_COMBO(combo), popdown_if_list) ;

	if(airpcap_if_selected != NULL)
		{
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(combo)->entry), airpcap_if_selected->description);
		}
	else
		{
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(combo)->entry), "No Wireless Interfaces Found");
		}
}

/*
 * Callback for the crc chackbox
 */
static void
crc_check_cb(GtkWidget *w, gpointer user_data)
{
if( !block_advanced_signals && (airpcap_if_selected != NULL))
	{
	if(airpcap_if_selected->IsFcsPresent)
		{
		airpcap_if_selected->IsFcsPresent = FALSE;
		airpcap_if_selected->saved = FALSE;
		}
	else
		{
		airpcap_if_selected->IsFcsPresent = TRUE;
		airpcap_if_selected->saved = FALSE;
		}
	}
}

/*
 * Callback for the wrong crc combo
 */
static void
wrong_crc_combo_cb(GtkWidget *w, gpointer data)
{
const gchar *s;

s = gtk_entry_get_text(GTK_ENTRY(data));

if( !block_advanced_signals && (data != NULL) && (w != NULL) )
	{
	if((g_strcasecmp("",s)))
		{
		airpcap_if_selected->CrcValidationOn = airpcap_get_validation_type(s);
		airpcap_if_selected->saved = FALSE;
		}
	}
}

/*
 * Changed callback for the channel combobox
 */
static void
channel_changed_cb(GtkWidget *w _U_, gpointer data)
{
const gchar *s;

  s = gtk_entry_get_text(GTK_ENTRY(data));

if( !block_advanced_signals && (data != NULL) && (w != NULL) )
	{
	s = gtk_entry_get_text(GTK_ENTRY(data));
	if((g_strcasecmp("",s)))
		{
		if(airpcap_if_selected != NULL)
			{
			airpcap_if_selected->channel = airpcap_get_channel_number(s);
			airpcap_if_selected->saved = FALSE;
			}
		}
	}
}

/*
 * Changed callback for the link layer combobox
 */
static void
link_type_changed_cb(GtkWidget *w _U_, gpointer data)
{
const gchar *s;

s = gtk_entry_get_text(GTK_ENTRY(data));

if( !block_advanced_signals && (data != NULL) && (w != NULL) )
	{
	if((g_strcasecmp("",s)))
		{
		airpcap_if_selected->linkType = airpcap_get_link_type(s);
		airpcap_if_selected->saved = FALSE;
		}
	}
}

/*
 * Activate callback for the adapter combobox
 */
static void
combo_if_activate_cb(GtkWidget *entry _U_, gpointer data)
{
}

/*
 * Changed callback for the adapter combobox
 */
static void
airpcap_advanced_combo_if_changed_cb(GtkWidget *w _U_, gpointer data)
{
const gchar* s = NULL;

s = gtk_entry_get_text(GTK_ENTRY(w));

if((g_strcasecmp("",s)))
	{
  /* We are trying to change the interface to set up...*/
  /* Check if the current interface settings need to be SAVED! */
  if( (airpcap_if_selected != NULL) && !block_advanced_signals)
		{
		if( (airpcap_if_selected->saved) ) /* Just change interface */
			{
			/* No changes for this interface, no need to save anything */
			airpcap_change_if(w,data);
			}
		else
			{
			/* Popup a dialog to ask if user wants to save settings for selected
			 * interface before changing it...
			 */
			airpcap_ask_for_save(w,data);
			}
		}
	}
}

/*
 * Takes the keys from the GtkList widget, and add them to the interface list
 */
void
airpcap_add_keys_from_list(GtkWidget *keylist, airpcap_if_info_t *if_info)
{
GtkWidget	*key_ls;

GString		*new_key;

gchar		*text_entered = NULL;

GtkWidget	*nl_item,*nl_lb;

GList		*list,
			*children;

/* airpcap stuff */
UINT i, j;
gchar s[3];
PAirpcapKeysCollection KeysCollection;
ULONG KeysCollectionSize;
UCHAR KeyByte;

UINT keys_in_list = 0;

key_ls	= keylist;

keys_in_list = (UINT)g_list_length(GTK_LIST(key_ls)->children);

if(keys_in_list > 0)
{
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
	 * We use malloc so it's easier to reuse the code in C programs
	 */
	KeysCollection = (PAirpcapKeysCollection)malloc(KeysCollectionSize);
	if(!KeysCollection)
	{
		/* Simple dialog ERROR */
		simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","Failed mamory allocation for KeysCollection!");
		return;
	}

	/*
	 * Populate the key collection
	 */
	list = GTK_LIST(key_ls)->children;
	KeysCollection->nKeys = keys_in_list;

	for(i = 0; i < keys_in_list; i++)
	{
		KeysCollection->Keys[i].KeyType = AIRPCAP_KEYTYPE_WEP;

		/* Retrieve the Item corresponding to the i-th key */
		nl_item = g_list_nth_data(list, i);
		children = gtk_container_children(GTK_CONTAINER(nl_item));
		nl_lb = g_list_nth_data(children,0);
		new_key = g_string_new(GTK_LABEL(nl_lb)->label);

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
	 * XXX - Free the old adapter key collection!
	 */
	if(airpcap_if_selected->keysCollection != NULL)
		g_free(airpcap_if_selected->keysCollection);

	/*
	 * Set this collection ad the new one
	 */
	airpcap_if_selected->keysCollection = KeysCollection;
	airpcap_if_selected->keysCollectionSize = KeysCollectionSize;
}
}


/*
 * Pop-up window, used to ask the user if he wants to save the selected interface settings
 * when closing the window.
 */
void
airpcap_ask_for_save_before_closing(GtkWidget *w _U_, gpointer data)
{
	GtkWidget* dialog;

    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                PRIMARY_TEXT_START "Save settings before closing?" PRIMARY_TEXT_END "\n\n"
                "If you close the window without saving, changes you made will\nbe discarded.");
    simple_dialog_set_cb(dialog, airpcap_dialog_save_before_closing_cb, data);
}

/* user confirmed the "Save settings..." dialog */
void
airpcap_dialog_save_before_closing_cb(gpointer dialog _U_, gint btn, gpointer data)
{
GtkWidget* interface_combo;
GtkWidget* key_ls;

/* I need the combo box entry */
interface_combo		= GTK_WIDGET(OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_INTERFACE_KEY));
key_ls				= GTK_WIDGET(OBJECT_GET_DATA(data,AIRPCAP_ADVANCED_KEYLIST_KEY));

    switch(btn) {
    case(ESD_BTN_SAVE):
        /* save interface and exit  */
		airpcap_add_keys_from_list(key_ls,airpcap_if_selected);
		airpcap_save_selected_if_configuration(airpcap_if_selected);
		/* Remove gtk timeout */
		gtk_timeout_remove(airpcap_if_selected->tag);
        break;
    case(ESD_BTN_DONT_SAVE):
        /* exit without saving */
        break;

    default:
		break;
    }
}

/*
 * Pop-up window, used to ask the user if he wants to save the selected interface settings
 * when changing the interface in the advanced dialog box
 */
void
airpcap_ask_for_save(GtkWidget *entry _U_, gpointer data)
{
	GtkWidget* dialog;

    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                PRIMARY_TEXT_START "Save settings before changing interface?" PRIMARY_TEXT_END "\n\n"
                "If you change interface without saving, changes you made will\nbe discarded.");
    simple_dialog_set_cb(dialog, airpcap_dialog_save_cb, data);

}

/* user confirmed the "Save settings..." dialog */
void
airpcap_dialog_save_cb(GtkWidget* dialog _U_, gint btn, gpointer data)
{
GtkWidget* interface_combo;
GtkWidget* key_ls;

/* I need the combo box entry */
interface_combo		= GTK_WIDGET(OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_INTERFACE_KEY));
key_ls				= GTK_WIDGET(OBJECT_GET_DATA(data,AIRPCAP_ADVANCED_KEYLIST_KEY));

    switch(btn) {
    case(ESD_BTN_SAVE):
        /* save interface and change  */
		airpcap_add_keys_from_list(key_ls,airpcap_if_selected);
		airpcap_save_selected_if_configuration(airpcap_if_selected);
		/* Remove gtk timeout */
		gtk_timeout_remove(airpcap_if_selected->tag);
		airpcap_change_if(GTK_COMBO(interface_combo)->entry,data);
        break;
    case(ESD_BTN_DONT_SAVE):
        /* change interface without saving */
		airpcap_change_if(GTK_COMBO(interface_combo)->entry,data);
        break;
    case(ESD_BTN_CANCEL):
		/* don't change interface and don't save */
        break;
    default:
		break;
    }
}

/*
 * Function used to change the selected interface and advanced dialog box
 */
void
airpcap_change_if(GtkWidget *entry _U_, gpointer data)
{
  const gchar *s;
  gchar *channel_s;
  gchar *capture_s;
  GtkWidget *main_w;

  GtkWidget *interface_combo;
  GtkWidget *channel_combo;
  GtkWidget *capture_combo;
  GtkWidget *crc_check;
  GtkWidget *wrong_crc_combo;
  GtkWidget *blink_bt;
  GtkWidget *key_ls;

  airpcap_if_info_t *new_if;

  /* Retrieve the GUI object pointers */
  main_w = GTK_WIDGET(data);
  interface_combo   = GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_INTERFACE_KEY));
  channel_combo		= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_CHANNEL_KEY));
  capture_combo		= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_LINK_TYPE_KEY));
  crc_check			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_CRC_KEY));
  wrong_crc_combo	= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_WRONG_CRC_KEY));
  blink_bt			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_BLINK_KEY));
  key_ls			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_KEYLIST_KEY));

  s = gtk_entry_get_text(GTK_ENTRY(entry));

  /* Select actual interface*/
  new_if = get_airpcap_if_from_description(airpcap_if_list, s);

  /* And change the GUI according to it... */
  /* This should always happen, but it seems that the callback is
   * called twice, the first time with an 'empty' text... so it
   * will return NULL!
   */
  if(new_if != NULL)
	{
	airpcap_if_selected = new_if;

	new_if = NULL;
	/* I need to 'block' signals to widgets or they will receive a signal now
	   and will change twice */
	block_advanced_signals = TRUE;

	/* Blink button */
	if(airpcap_if_selected->blinking)
		{
		#if GTK_MAJOR_VERSION >= 2
		gtk_button_set_label(GTK_BUTTON(blink_bt),"Stop Blinking");
		#else
		gtk_label_set_text(GTK_LABEL(GTK_BIN(blink_bt)->child),"Stop Blinking");
		#endif
		}
	else
		{
		#if GTK_MAJOR_VERSION >= 2
		gtk_button_set_label(GTK_BUTTON(blink_bt),"  Blink Led  ");
		#else
		gtk_label_set_text(GTK_LABEL(GTK_BIN(blink_bt)->child),"  Blink Led  ");
		#endif
		}

	/* Channel combo */
	channel_s = g_strdup_printf("%d",airpcap_if_selected->channel);
	if(channel_combo != NULL) /* this event seems to happen when combo is still NULL */
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_combo)->entry), channel_s);

	/* Link Layer combo */
	capture_s = NULL;
	if(airpcap_if_selected->linkType == AIRPCAP_LT_802_11)
		{
			capture_s = g_strdup_printf(AIRPCAP_LINK_TYPE_NAME_802_11_ONLY);
			if(capture_combo != NULL) /* this event seems to happen when combo is still NULL */
				gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(capture_combo)->entry), capture_s);
		}
	else if(airpcap_if_selected->linkType == AIRPCAP_LT_802_11_PLUS_RADIO)
		{
			capture_s = g_strdup_printf(AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO);
			if(capture_combo != NULL) /* this event seems to happen when combo is still NULL */
				gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(capture_combo)->entry), capture_s);
		}

	/* Fcs Presence check box */
	if(airpcap_if_selected->IsFcsPresent)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(crc_check),TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(crc_check),FALSE);

	/* Wrong Crc combo box */
	if(airpcap_if_selected->CrcValidationOn == AIRPCAP_VT_ACCEPT_EVERYTHING)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(wrong_crc_combo)->entry),AIRPCAP_VALIDATION_TYPE_NAME_ALL);
	else if(airpcap_if_selected->CrcValidationOn == AIRPCAP_VT_ACCEPT_CORRECT_FRAMES)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(wrong_crc_combo)->entry),AIRPCAP_VALIDATION_TYPE_NAME_CORRECT);
	else if(airpcap_if_selected->CrcValidationOn == AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(wrong_crc_combo)->entry),AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT);

	/* Remove old keys */
	gtk_list_remove_items(GTK_LIST(key_ls),GTK_LIST(key_ls)->children);
	/* Add new keys */
	airpcap_fill_key_list(key_ls,airpcap_if_selected);

	/* Enable the signals again */
	block_advanced_signals = FALSE;
	}
}

/*
 * Thread function used to blink the led
 */
void update_blink(gpointer data _U_)
{
airpcap_if_info_t* sel;
PAirpcapHandle ad;
char* ebuf = NULL;

sel = (airpcap_if_info_t*)data;

ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list, sel->description), ebuf);
if(ad)
	{
	if(sel->led)
		{
		airpcap_if_turn_led_off(ad, 0);
		sel->led = FALSE;
		}
	else
		{
		airpcap_if_turn_led_on(ad, 0);
		sel->led = TRUE;
		}
	airpcap_if_close(ad);
	}
}

/*
 * Blink button callback
 */
void
blink_cb( GtkWidget *blink_bt _U_, gpointer if_data )
{
PAirpcapHandle ad = NULL;
char* ebuf = NULL;

if(airpcap_if_selected != NULL)
	if(!(airpcap_if_selected->blinking))
		{
		#if GTK_MAJOR_VERSION >= 2
		gtk_button_set_label(GTK_BUTTON(blink_bt),"Stop Blinking");
		#else
		gtk_label_set_text(GTK_LABEL(GTK_BIN(blink_bt)->child),"Stop Blinking");
		#endif
		airpcap_if_selected->tag = gtk_timeout_add(500, (GtkFunction)update_blink,airpcap_if_selected);
		airpcap_if_selected->blinking = TRUE;
		}
	else
		{
		#if GTK_MAJOR_VERSION >= 2
		gtk_button_set_label(GTK_BUTTON(blink_bt),"  Blink Led  ");
		#else
		gtk_label_set_text(GTK_LABEL(GTK_BIN(blink_bt)->child),"  Blink Led  ");
		#endif
		gtk_timeout_remove(airpcap_if_selected->tag);
		airpcap_if_selected->blinking = FALSE;
		/* Switch on the led!  */
		ad = airpcap_if_open(airpcap_if_selected->name, ebuf);
		if(ad)
			{
			gtk_timeout_remove(airpcap_if_selected->tag);
			airpcap_if_turn_led_on(ad, 0);
			airpcap_if_selected->blinking = FALSE;
			airpcap_if_selected->led = TRUE;
			airpcap_if_close(ad);
			}
		}
}

/* the window was closed, cleanup things */
static void
airpcap_if_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
	PAirpcapHandle ad = NULL;
	char* ebuf = NULL;

	/* Retrieve object data */
    GtkWidget *main_w;
    GtkWidget *channel_combo;
    GtkWidget *capture_combo;
    GtkWidget *crc_check;
    GtkWidget *wrong_crc_combo;
    GtkWidget *blink_bt;
	GtkWidget *interface_combo;
	GtkWidget *cancel_bt;
	GtkWidget *ok_bt;
	GtkWidget *key_ls;

	/* widgets in the toolbar */
	GtkWidget	*toolbar,
				*toolbar_if_lb,
				*toolbar_channel_cm,
				*toolbar_wrong_crc_cm,
				*toolbar_decryption_ck,
				*advanced_bt;

	gint *from_widget = NULL;

    /* Retrieve the GUI object pointers */
    main_w = GTK_WIDGET(user_data);
	interface_combo		= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_INTERFACE_KEY));
    channel_combo		= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_CHANNEL_KEY));
    capture_combo		= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_LINK_TYPE_KEY));
    crc_check			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_CRC_KEY));
    wrong_crc_combo		= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_WRONG_CRC_KEY));
    blink_bt			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_BLINK_KEY));
	cancel_bt			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_CANCEL_KEY));
	ok_bt				= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_OK_KEY));
	key_ls				= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_KEYLIST_KEY));
	advanced_bt			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_KEY));

	toolbar = GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_TOOLBAR_KEY));

	/* retrieve toolbar info */
	toolbar_if_lb			= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
	toolbar_channel_cm		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
	toolbar_wrong_crc_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_WRONG_CRC_KEY));
	toolbar_decryption_ck	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_DECRYPTION_KEY));

	from_widget	= (gint*)OBJECT_GET_DATA(toolbar,AIRPCAP_ADVANCED_FROM_KEY);

	/* ... */
	/* gray out the toolbar (if we came here from the toolbar advanced button)*/
	if( *from_widget == AIRPCAP_ADVANCED_FROM_TOOLBAR)
		gtk_widget_set_sensitive(toolbar,TRUE);

	/* Stop blinking ALL leds (go through the airpcap_if_list) */
	if(airpcap_if_selected != NULL)
	{
	ad = airpcap_if_open(airpcap_if_selected->name, ebuf);
	if(ad)
		{
		gtk_timeout_remove(airpcap_if_selected->tag);
		airpcap_if_turn_led_on(ad, 0);
		airpcap_if_selected->blinking = FALSE;
		airpcap_if_selected->led = TRUE;
		airpcap_if_close(ad);
		}
	}

	/* See if the 'Cancel' button was pressed or not
	 * if button is pressed, don't save configuration!
	 */
	if(GTK_BUTTON(cancel_bt)->in_button)
		{
		/* reload the configuration!!! Configuration has not been saved but
		   the corresponding structure has been modified probably...*/
		if(!airpcap_if_selected->saved)
			{
			airpcap_load_selected_if_configuration(airpcap_if_selected);
			}

		/* NULL to everything */
		main_w = NULL;
		blink_bt = NULL;
		channel_combo = NULL;
		interface_combo = NULL;
		capture_combo = NULL;
		crc_check = NULL;
		wrong_crc_combo = NULL;

		/* ... */
		/* gray out the toolbar (if we came here from the toolbar advanced button)*/
		if( *from_widget == AIRPCAP_ADVANCED_FROM_TOOLBAR)
			gtk_widget_set_sensitive(toolbar,TRUE);

		g_free(from_widget);
		return;
		}
	else if(GTK_BUTTON(ok_bt)->in_button)
		{

		/* ??? - Ask if want to save configuration */

		/* Save the configuration */
		airpcap_add_keys_from_list(key_ls,airpcap_if_selected);
		airpcap_save_selected_if_configuration(airpcap_if_selected);
		/* Remove gtk timeout */
		gtk_timeout_remove(airpcap_if_selected->tag);

		/* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
		if( g_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
			{
			gtk_label_set_text(GTK_LABEL(toolbar_if_lb), g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_selected)));
			airpcap_channel_combo_set_by_number(toolbar_channel_cm,airpcap_if_selected->channel);
			airpcap_validation_type_combo_set_by_type(toolbar_wrong_crc_cm,airpcap_if_selected->CrcValidationOn);

			gtk_signal_handler_block_by_func (GTK_OBJECT(toolbar_decryption_ck),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), toolbar);
			if(airpcap_if_active->DecryptionOn == AIRPCAP_DECRYPTION_ON)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toolbar_decryption_ck),TRUE);
			else
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toolbar_decryption_ck),FALSE);
			gtk_signal_handler_unblock_by_func (GTK_OBJECT(toolbar_decryption_ck),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), toolbar);
			}

		/* If interface active is airpcap, set sensitive TRUE for airpcap toolbar */
		if( get_airpcap_if_by_name(airpcap_if_list,airpcap_if_active->description) != NULL)
			{
			airpcap_set_toolbar_start_capture(airpcap_if_active);
			}
		else
			{
			airpcap_set_toolbar_stop_capture(airpcap_if_active);
			}

			/* NULL to everything */
			main_w = NULL;
			blink_bt = NULL;
			channel_combo = NULL;
			interface_combo = NULL;
			capture_combo = NULL;
			crc_check = NULL;
			wrong_crc_combo = NULL;

				/* ... */
		/* gray out the toolbar (if we came here from the toolbar advanced button)*/
		if( *from_widget == AIRPCAP_ADVANCED_FROM_OPTIONS)
			gtk_widget_set_sensitive(toolbar,FALSE);

		g_free(from_widget);
		return;
		}

		/* reload the configuration!!! Configuration has not been saved but
	   the corresponding structure has been modified probably...*/
	if(!airpcap_if_selected->saved)
		{
		airpcap_load_selected_if_configuration(airpcap_if_selected);
		}
}

/*
 * Callback for the 'Apply' button.
 */
static void
airpcap_advanced_apply_cb(GtkWidget *button, gpointer data _U_)
{
	/* advenced window */
	GtkWidget	*main_w;

	/* widgets in the toolbar */
	GtkWidget	*toolbar,
				*toolbar_if_lb,
				*toolbar_channel_cm,
				*toolbar_wrong_crc_cm,
				*toolbar_decryption_ck;

	GtkWidget   *key_ls;

	/* retrieve main window */
	main_w = GTK_WIDGET(data);
	key_ls	= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_KEYLIST_KEY));

	toolbar = GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_TOOLBAR_KEY));

	/* retrieve toolbar info */
	toolbar_if_lb			= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
	toolbar_channel_cm		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
	toolbar_wrong_crc_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_WRONG_CRC_KEY));
	toolbar_decryption_ck	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_DECRYPTION_KEY));

	/* Save the configuration */
	airpcap_add_keys_from_list(key_ls,airpcap_if_selected);
	airpcap_save_selected_if_configuration(airpcap_if_selected);

	/* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
	if( g_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
		{
		gtk_label_set_text(GTK_LABEL(toolbar_if_lb), g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_selected)));
		airpcap_channel_combo_set_by_number(toolbar_channel_cm,airpcap_if_selected->channel);
		airpcap_validation_type_combo_set_by_type(toolbar_wrong_crc_cm,airpcap_if_selected->CrcValidationOn);

     	gtk_signal_handler_block_by_func (GTK_OBJECT(toolbar_decryption_ck),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), toolbar);
		if(airpcap_if_active->DecryptionOn == AIRPCAP_DECRYPTION_ON)
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toolbar_decryption_ck),TRUE);
		else
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toolbar_decryption_ck),FALSE);
		gtk_signal_handler_unblock_by_func (GTK_OBJECT(toolbar_decryption_ck),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), toolbar);
		}
}

/*
 * Callback for the 'Ok' button.
 */
static void
airpcap_advanced_ok_cb(GtkWidget *w, gpointer data _U_)
{
	/* advenced window */
	GtkWidget	*main_w;

	/* widgets in the toolbar */
	GtkWidget	*toolbar,
				*toolbar_if_lb,
				*toolbar_channel_cm,
				*toolbar_wrong_crc_cm,
				*toolbar_decryption_ck;

	GtkWidget	*key_ls;

	/* retrieve main window */
	main_w = GTK_WIDGET(data);

	toolbar = GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_TOOLBAR_KEY));

	key_ls	= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_KEYLIST_KEY));

	/* retrieve toolbar info */
	toolbar_if_lb			= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
	toolbar_channel_cm		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
	toolbar_wrong_crc_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_WRONG_CRC_KEY));
	toolbar_decryption_ck	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_DECRYPTION_KEY));

	/* Save the configuration */
	airpcap_add_keys_from_list(key_ls,airpcap_if_selected);
	airpcap_save_selected_if_configuration(airpcap_if_selected);
	/* Remove gtk timeout */
	gtk_timeout_remove(airpcap_if_selected->tag);

	/* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
	if( g_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
		{
		gtk_label_set_text(GTK_LABEL(toolbar_if_lb), g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_selected)));
		airpcap_channel_combo_set_by_number(toolbar_channel_cm,airpcap_if_selected->channel);
		airpcap_validation_type_combo_set_by_type(toolbar_wrong_crc_cm,airpcap_if_selected->CrcValidationOn);

     	gtk_signal_handler_block_by_func (GTK_OBJECT(toolbar_decryption_ck),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), toolbar);
		if(airpcap_if_active->DecryptionOn == AIRPCAP_DECRYPTION_ON)
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toolbar_decryption_ck),TRUE);
		else
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toolbar_decryption_ck),FALSE);
		gtk_signal_handler_unblock_by_func (GTK_OBJECT(toolbar_decryption_ck),GTK_SIGNAL_FUNC(airpcap_toolbar_encryption_cb), toolbar);
		}
}

/*
 * Callback for the 'Reset Configuration' button.
 */
static void
airpcap_advanced_reset_configuration_cb(GtkWidget *button, gpointer data _U_)
{

}

/*
 * Callback for the 'About' button.
 */
static void
airpcap_advanced_about_cb(GtkWidget *button, gpointer data _U_)
{
	/* retrieve toolbar info */
}

/*
 * Callback used to add a WEP key in the add new key box;
 */
static void
add_key(GtkWidget *widget, gpointer data _U_)
{
GtkWidget	*text,
			*key_ls,
			*ok_bt;

GString		*new_key;

gchar		*text_entered = NULL;

int keys_in_list = 0;
unsigned int i;

text	= OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_ADD_KEY_TEXT_KEY);
ok_bt	= OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_ADD_KEY_OK_KEY);
key_ls	= OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_KEYLIST_KEY);

keys_in_list = g_list_length(GTK_LIST(key_ls)->children);
text_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(text)));

/* Too many keys? */
if(keys_in_list == MAX_ENCRYPTION_KEYS)
	{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","Reached the Wep Keys Limit for this Interface.");
	return;
	}

/* Check if key is correct */
new_key = g_string_new(text_entered);

g_strchug(new_key->str);
g_strchomp(new_key->str);

if((new_key->len % 2) != 0)
	{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","1) A Wep key must is an arbitrary length hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.\nThe number of characters must be even.");
	return;
	}

for(i = 0; i < new_key->len; i++)
	{
	if(!g_ascii_isxdigit(new_key->str[i]))
		{
		simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","2) A Wep key must is an arbitrary length hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.\nThe number of characters must be even.");
		return;
		}
	}

/* If so... Add key */
airpcap_add_key_to_list(key_ls,new_key->str);

airpcap_if_selected->saved = FALSE;

g_string_free(new_key,TRUE);
g_free(text_entered);

window_destroy(GTK_WIDGET(data));
return;
}

/*
 * Callback used to add a WEP key in the edit key box;
 */
static void
edit_key(GtkWidget *widget, gpointer data _U_)
{
GtkWidget	*text,
			*key_ls,
			*ok_bt;

GString		*new_key;

gchar		*text_entered = NULL;

GtkWidget	*label;


int keys_in_list = 0;
unsigned int i;

text	= OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_TEXT_KEY);
ok_bt	= OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_OK_KEY);
key_ls	= OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_KEYLIST_KEY);
label   = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_LABEL_KEY);

keys_in_list = g_list_length(GTK_LIST(key_ls)->children);
text_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(text)));

/* Check if key is correct */
new_key = g_string_new(text_entered);

g_strchug(new_key->str);
g_strchomp(new_key->str);

if((new_key->len % 2) != 0)
	{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","1) A Wep key must is an arbitrary length hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.\nThe number of characters must be even.");
	return;
	}

for(i = 0; i < new_key->len; i++)
	{
	if(!g_ascii_isxdigit(new_key->str[i]))
		{
		simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"%s","2) A Wep key must is an arbitrary length hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.\nThe number of characters must be even.");
		return;
		}
	}

/* If so... modify key */
gtk_label_set_text(GTK_LABEL(label),new_key->str);

airpcap_if_selected->saved = FALSE;

g_string_free(new_key,TRUE);
g_free(text_entered);

window_destroy(GTK_WIDGET(data));
return;
}

/*
 * Callback for the 'Add Key' button.
 */
static void
airpcap_advanced_add_key_cb(GtkWidget *button, gpointer data _U_)
{
/* Window */
GtkWidget	*add_key_w;

/*  Frame */
GtkWidget	*add_key_frame;

/* Boxes */
GtkWidget	*main_box,	/* vertical */
			*key_box,	/* orizontal */
			*text_box,  /* orizontal */
			*button_box;/* orizontal (packed to end)*/

/* Text Entry */
GtkWidget	*key_text_entry;

/* Buttons */
GtkWidget	*key_ok_bt,
			*key_cancel_bt;

/* Key List Widget */
GtkWidget	*key_ls;

	/* Pop-up a new window */
	add_key_w = window_new (GTK_WINDOW_TOPLEVEL,"Add a WEP Key");

	/* Connect events */
    SIGNAL_CONNECT(add_key_w, "delete_event",window_delete_event_cb, add_key_w);
    SIGNAL_CONNECT(add_key_w, "destroy",add_key_w_destroy_cb, add_key_w);

	/* Sets the border width of the window. */
	gtk_container_set_border_width (GTK_CONTAINER (add_key_w), 5);

	/* Retrieve the key list widget pointer, and add it to the add_key_w */
	key_ls = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_KEYLIST_KEY);
	OBJECT_SET_DATA(GTK_WIDGET(add_key_w),AIRPCAP_ADVANCED_KEYLIST_KEY,key_ls);
	OBJECT_SET_DATA(GTK_WIDGET(add_key_w),AIRPCAP_ADVANCED_KEY,data);

	/* Create boxes */
	main_box = gtk_vbox_new(FALSE,1);
	key_box = gtk_hbox_new(FALSE,1);
	button_box = gtk_hbox_new(FALSE,1);
	text_box = gtk_hbox_new(TRUE,1);

	/* Add the two sub boxes to the main box */
	gtk_box_pack_start(GTK_BOX(main_box), key_box, FALSE, FALSE, 1);
	gtk_box_pack_start(GTK_BOX(main_box), button_box, FALSE, FALSE, 1);

	/* Add the main box to the main window */
	gtk_container_add(GTK_CONTAINER(add_key_w),main_box);

	/* Crete key frame */
	add_key_frame = gtk_frame_new("");
	gtk_frame_set_label(GTK_FRAME(add_key_frame),"Key");
	#if GTK_MAJOR_VERSION < 2
	gtk_widget_set_usize( GTK_WIDGET(add_key_frame),
                                  200,
                                  -1 );
	#else
	gtk_widget_set_size_request( GTK_WIDGET(add_key_frame),
                                  200,
                                  -1 );
    #endif

	gtk_box_pack_start(GTK_BOX(key_box), add_key_frame, FALSE, FALSE, 1);

	/* Create and Add text entry*/
	key_text_entry = gtk_entry_new();
	OBJECT_SET_DATA(add_key_w, AIRPCAP_ADVANCED_ADD_KEY_TEXT_KEY, key_text_entry);
	SIGNAL_CONNECT(key_text_entry, "activate", add_key, add_key_w );
	gtk_box_pack_start(GTK_BOX(text_box), key_text_entry, FALSE, FALSE, 1);
	gtk_container_add(GTK_CONTAINER(add_key_frame),text_box);
	gtk_container_set_border_width (GTK_CONTAINER (text_box), 5);

	/* Create and add buttons */
	key_ok_bt = gtk_button_new_with_label("OK");
	SIGNAL_CONNECT(key_ok_bt, "clicked", add_key, add_key_w );
	OBJECT_SET_DATA(add_key_w, AIRPCAP_ADVANCED_ADD_KEY_OK_KEY, key_ok_bt);
		#if GTK_MAJOR_VERSION < 2
	gtk_widget_set_usize( GTK_WIDGET(key_ok_bt),
                                  50,
                                  -1 );
	#else
	gtk_widget_set_size_request( GTK_WIDGET(key_ok_bt),
                                  50,
                                  -1 );
    #endif
	key_cancel_bt = gtk_button_new_with_label("Cancel");
	SIGNAL_CONNECT(key_cancel_bt, "clicked", window_cancel_button_cb, add_key_w );
		#if GTK_MAJOR_VERSION < 2
	gtk_widget_set_usize( GTK_WIDGET(key_cancel_bt),
                                  50,
                                  -1 );
	#else
	gtk_widget_set_size_request( GTK_WIDGET(key_cancel_bt),
                                  50,
                                  -1 );
    #endif

	gtk_box_pack_end(GTK_BOX(button_box), key_cancel_bt, FALSE, FALSE, 1);
	gtk_box_pack_end(GTK_BOX(button_box), key_ok_bt, FALSE, FALSE, 1);

	/* Show all */
	gtk_widget_show(key_ok_bt);
	gtk_widget_show(key_cancel_bt);
	gtk_widget_show(key_text_entry);
	gtk_widget_show(add_key_frame);
	gtk_widget_show(text_box);
	gtk_widget_show(button_box);
	gtk_widget_show(key_box);
	gtk_widget_show(main_box);
	gtk_widget_show(add_key_w);
}

/*
 * Add key window destroy callback
 */
static void
add_key_w_destroy_cb(GtkWidget *button, gpointer data _U_)
{
return;
}

/*
 * Edit key window destroy callback
 */
static void
edit_key_w_destroy_cb(GtkWidget *button, gpointer data _U_)
{
return;
}

/*
 * Callback for the 'Remove Key' button.
 */
static void
airpcap_advanced_remove_key_cb(GtkWidget *button, gpointer data _U_)
{
GtkList *key_ls;
GtkWidget *label;
GList *item = NULL;
gint n;

/* retrieve key list */
key_ls = GTK_LIST(data);

/* Remove selected keys*/
if(key_ls->selection != NULL)
	{
	item = g_list_nth(key_ls->selection,0);
	if(item != NULL)
		{
		n = gtk_list_child_position(key_ls,item->data);
		label = GTK_BIN(item->data)->child;
		gtk_list_clear_items(key_ls,n,n+1);
		}
	}

/* Need to save config... */
airpcap_if_selected->saved = FALSE;
}

/*
 * Callback for the 'Edit Key' button.
 */
static void
airpcap_advanced_edit_key_cb(GtkWidget *button, gpointer data _U_)
{
/* Window */
GtkWidget	*edit_key_w;

/*  Frame */
GtkWidget	*edit_key_frame;

/* Boxes */
GtkWidget	*main_box,	/* vertical */
			*key_box,	/* orizontal */
			*text_box,  /* orizontal */
			*button_box;/* orizontal (packed to end)*/

/* Text Entry */
GtkWidget	*key_text_entry;

/* Buttons */
GtkWidget	*key_ok_bt,
			*key_cancel_bt;

/* Key List Widget */
GtkWidget	*key_ls;

GtkWidget *label;
GList *item = NULL;
gint n;

/* Retrieve the key list widget pointer, and add it to the edit_key_w */
key_ls = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_KEYLIST_KEY);

/*
 * Check if a key has been selected. If not, just do nothing.
 */
if(GTK_LIST(key_ls)->selection != NULL)
    {
    item = g_list_nth(GTK_LIST(key_ls)->selection,0);
    if(item != NULL)
    	{
    	/* Pop-up a new window */
    	edit_key_w = window_new (GTK_WINDOW_TOPLEVEL,"Edit a WEP Key");

    	/* Connect events */
        SIGNAL_CONNECT(edit_key_w, "delete_event",window_delete_event_cb, edit_key_w);
        SIGNAL_CONNECT(edit_key_w, "destroy",edit_key_w_destroy_cb, edit_key_w);

    	/* Sets the border width of the window. */
    	gtk_container_set_border_width (GTK_CONTAINER (edit_key_w), 5);

    	OBJECT_SET_DATA(GTK_WIDGET(edit_key_w),AIRPCAP_ADVANCED_KEYLIST_KEY,key_ls);
    	OBJECT_SET_DATA(GTK_WIDGET(edit_key_w),AIRPCAP_ADVANCED_KEY,data);

    	/* Create boxes */
    	main_box = gtk_vbox_new(FALSE,1);
    	key_box = gtk_hbox_new(FALSE,1);
    	button_box = gtk_hbox_new(FALSE,1);
    	text_box = gtk_hbox_new(TRUE,1);

    	/* Add the two sub boxes to the main box */
    	gtk_box_pack_start(GTK_BOX(main_box), key_box, FALSE, FALSE, 1);
    	gtk_box_pack_start(GTK_BOX(main_box), button_box, FALSE, FALSE, 1);

    	/* Add the main box to the main window */
    	gtk_container_add(GTK_CONTAINER(edit_key_w),main_box);

    	/* Crete key frame */
    	edit_key_frame = gtk_frame_new("");
    	gtk_frame_set_label(GTK_FRAME(edit_key_frame),"Key");
    	#if GTK_MAJOR_VERSION < 2
    	gtk_widget_set_usize( GTK_WIDGET(edit_key_frame),
                                      200,
                                      -1 );
    	#else
    	gtk_widget_set_size_request( GTK_WIDGET(edit_key_frame),
                                      200,
                                      -1 );
        #endif

    	gtk_box_pack_start(GTK_BOX(key_box), edit_key_frame, FALSE, FALSE, 1);

    	/* Create and Add text entry*/
    	key_text_entry = gtk_entry_new();
    	/* Retrieve the currently selected entry */
    	if(GTK_LIST(key_ls)->selection != NULL)
    		{
    		item = g_list_nth(GTK_LIST(key_ls)->selection,0);
    		if(item != NULL)
    			{
    			n = gtk_list_child_position(GTK_LIST(key_ls),item->data);
    			label = GTK_BIN(item->data)->child;
    			/* Pass the pointer as data */
    			OBJECT_SET_DATA(edit_key_w,AIRPCAP_ADVANCED_EDIT_KEY_LABEL_KEY,label);
    			}
    		}
    	gtk_entry_set_text(GTK_ENTRY(key_text_entry),GTK_LABEL(label)->label);
    	OBJECT_SET_DATA(edit_key_w, AIRPCAP_ADVANCED_EDIT_KEY_TEXT_KEY, key_text_entry);
    	SIGNAL_CONNECT(key_text_entry, "activate", edit_key, edit_key_w );
    	gtk_box_pack_start(GTK_BOX(text_box), key_text_entry, FALSE, FALSE, 1);
    	gtk_container_add(GTK_CONTAINER(edit_key_frame),text_box);
    	gtk_container_set_border_width (GTK_CONTAINER (text_box), 5);

    	/* Create and add buttons */
    	key_ok_bt = gtk_button_new_with_label("OK");
    	SIGNAL_CONNECT(key_ok_bt, "clicked", edit_key, edit_key_w );
    	OBJECT_SET_DATA(edit_key_w, AIRPCAP_ADVANCED_EDIT_KEY_OK_KEY, key_ok_bt);
    		#if GTK_MAJOR_VERSION < 2
    	gtk_widget_set_usize( GTK_WIDGET(key_ok_bt),
                                      50,
                                      -1 );
    	#else
    	gtk_widget_set_size_request( GTK_WIDGET(key_ok_bt),
                                      50,
                                      -1 );
        #endif
    	key_cancel_bt = gtk_button_new_with_label("Cancel");
    	SIGNAL_CONNECT(key_cancel_bt, "clicked", window_cancel_button_cb, edit_key_w );
    		#if GTK_MAJOR_VERSION < 2
    	gtk_widget_set_usize( GTK_WIDGET(key_cancel_bt),
                                      50,
                                      -1 );
    	#else
    	gtk_widget_set_size_request( GTK_WIDGET(key_cancel_bt),
                                      50,
                                      -1 );
        #endif

    	gtk_box_pack_end(GTK_BOX(button_box), key_cancel_bt, FALSE, FALSE, 1);
    	gtk_box_pack_end(GTK_BOX(button_box), key_ok_bt, FALSE, FALSE, 1);

    	/* Show all */
    	gtk_widget_show(key_ok_bt);
    	gtk_widget_show(key_cancel_bt);
    	gtk_widget_show(key_text_entry);
    	gtk_widget_show(edit_key_frame);
    	gtk_widget_show(text_box);
    	gtk_widget_show(button_box);
    	gtk_widget_show(key_box);
    	gtk_widget_show(main_box);
    	gtk_widget_show(edit_key_w);
        }
    }
}

/*
 * Callback for the 'Move Key Up' button.
 */
static void
airpcap_advanced_move_key_up_cb(GtkWidget *button, gpointer data _U_)
{
GtkList *key_ls;
GtkWidget *label,*nl_lb,*nl_item;
GList *new_list = NULL;
GList *item = NULL;
gint n;

/* retrieve key list */
key_ls = GTK_LIST(data);

/* Remove selected keys*/
if(key_ls->selection != NULL)
	{
	item = g_list_nth(key_ls->selection,0);
	if(item != NULL)
		{
		n = gtk_list_child_position(key_ls,item->data);
		if(n>0)
			{
			label = GTK_BIN(item->data)->child;
			nl_lb = gtk_label_new(GTK_LABEL(label)->label);
			gtk_list_clear_items(key_ls,n,n+1);
			nl_item = gtk_list_item_new();
			gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
			gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
			gtk_widget_show(nl_lb);
			gtk_widget_show(nl_item);
			new_list = g_list_append(new_list,nl_item);
			gtk_list_insert_items(key_ls,new_list,n-1);
			gtk_list_select_item(key_ls,n-1);
			}
		}
	}

/* Need to save config... */
airpcap_if_selected->saved = FALSE;
}

/*
 * Callback for the 'Move Key Down' button.
 */
static void
airpcap_advanced_move_key_down_cb(GtkWidget *button, gpointer data _U_)
{
GtkList *key_ls;
GtkWidget *label,*nl_lb,*nl_item;
GList *new_list = NULL;
GList *item = NULL;
unsigned int n;

/* retrieve key list */
key_ls = GTK_LIST(data);

/* Remove selected keys*/
if(key_ls->selection != NULL)
	{
	item = g_list_nth(key_ls->selection,0);
	if(item != NULL)
		{
		n = gtk_list_child_position(key_ls,item->data);
		if(n< (g_list_length(key_ls->children)-1))
			{
			label = GTK_BIN(item->data)->child;
			nl_lb = gtk_label_new(GTK_LABEL(label)->label);
			gtk_list_clear_items(key_ls,n,n+1);

			nl_item = gtk_list_item_new();
			gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
			gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
			gtk_widget_show(nl_lb);
			gtk_widget_show(nl_item);

			new_list = g_list_append(new_list,nl_item);
			gtk_list_insert_items(key_ls,new_list,n+1);
			gtk_list_select_item(key_ls,n+1);
			}
		}
	}

/* Need to save config... */
airpcap_if_selected->saved = FALSE;
}

/* Turns the decryption on or off */
static void
encryption_check_cb(GtkWidget *w, gpointer data)
{
if( !block_advanced_signals && (airpcap_if_selected != NULL))
	{
	if(airpcap_if_selected->DecryptionOn == AIRPCAP_DECRYPTION_ON)
		{
		airpcap_if_selected->DecryptionOn = AIRPCAP_DECRYPTION_OFF;
		airpcap_if_selected->saved = FALSE;
		}
	else
		{
		airpcap_if_selected->DecryptionOn = AIRPCAP_DECRYPTION_ON;
		airpcap_if_selected->saved = FALSE;
		}
	}
}


/* Called to create the airpcap settings' window */
void
display_airpcap_advanced_cb(GtkWidget *w, gpointer data)
{
	/* Main window */
	GtkWidget   *airpcap_advanced_w;

	/* Blink button */
	GtkWidget	*blink_bt,
				*channel_combo;
	/* Combos */
	GtkWidget	*interface_combo,
				*capture_combo;

	/* check */
	GtkWidget   *wrong_crc_combo;

	/* key list*/
	GtkWidget   *key_ls;

	/* frames */
	GtkWidget   *interface_frame,
				*basic_frame,
				*wep_frame;
	/* boxes */
	GtkWidget	*main_box,
				*buttons_box_1,
				*buttons_box_2,
				*interface_box,
				*basic_box,
				*basic_combo_box,
				*basic_check_box,
				*basic_label_box,
				*basic_wrong_box,
				*wep_box,
				*wep_sub_box,
				*encryption_box,
				*wep_buttons_box;
	/* buttons */
	/* blink button is global */
	GtkWidget	*add_new_key_bt,
				*remove_key_bt,
				*edit_key_bt,
				*move_key_up_bt,
				*move_key_down_bt,
				*reset_configuration_bt,
				*about_bt,
				*apply_bt,
				*ok_bt,
				*cancel_bt;
	/* combo */

	/* shortcut to combo entry */
	GtkWidget	*link_type_te,
				*wrong_crc_te,
				*channel_te;
	/* check */
	/* global check buttons */
	GtkWidget   *crc_check,
				*encryption_check;
	/* label */
	GtkWidget	*channel_lb,
				*wrong_lb,
				*capture_lb;
	/* text field */
	GtkWidget   *key_text;

	/* widgets in the toolbar */
	GtkWidget	*toolbar,
				*toolbar_if_lb,
				*toolbar_channel_cm,
				*toolbar_wrong_crc_cm;

	/* other stuff */
	GList				*channel_list,*capture_list;
	GList				*linktype_list = NULL;
	gchar				*channel_s,*capture_s;


	/* user data - RETRIEVE pointers of toolbar widgets */
	toolbar				= GTK_WIDGET(data);
    toolbar_if_lb		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
    toolbar_channel_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
    toolbar_wrong_crc_cm= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_WRONG_CRC_KEY));

	/* gray out the toolbar */
	gtk_widget_set_sensitive(toolbar,FALSE);

	/* main window */
	/* global */

	/* NULL to global widgets */
	blink_bt = NULL;
	channel_combo = NULL;
	block_advanced_signals = FALSE;

	/* the selected is the active, for now */
	airpcap_if_selected = airpcap_if_active;

	/* Create the new window */
	airpcap_advanced_w = window_new(GTK_WINDOW_TOPLEVEL, "Advanced Wireless Settings");

	/*
	 * I will need the toolbar and the main widget in some callback,
	 * so I will add the toolbar pointer to the airpcap_advanced_w
	 */
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_TOOLBAR_KEY,toolbar);

	/* Connect the callbacks */
	SIGNAL_CONNECT(airpcap_advanced_w, "delete_event", window_delete_event_cb, airpcap_advanced_w);
    SIGNAL_CONNECT(airpcap_advanced_w, "destroy", airpcap_if_destroy_cb, airpcap_advanced_w);

	/* Set the size */
	/* Sets the border width of the window. */
	gtk_container_set_border_width (GTK_CONTAINER (airpcap_advanced_w), 10);

	/* Create the main box */
	main_box = gtk_vbox_new(FALSE,0);

	/* Create the button boxes */
	buttons_box_1 = gtk_hbox_new(FALSE,0);
	buttons_box_2 = gtk_hbox_new(FALSE,0);

	/* Create the buttons for box 1 */
	reset_configuration_bt = gtk_button_new_with_label("Reset Configuration");
	SIGNAL_CONNECT(reset_configuration_bt, "clicked", airpcap_advanced_reset_configuration_cb, toolbar);
	gtk_widget_show(reset_configuration_bt);

	about_bt = gtk_button_new_with_label("About");
	SIGNAL_CONNECT(about_bt, "clicked", airpcap_advanced_about_cb, toolbar);
	gtk_widget_show(about_bt);

	/* Add them to box 1 */
	gtk_box_pack_start (GTK_BOX (buttons_box_1), reset_configuration_bt, FALSE, FALSE, 1);
	gtk_box_pack_start (GTK_BOX (buttons_box_1), about_bt, FALSE, FALSE, 1);

    /* Create the buttons for box 2 */
	apply_bt = gtk_button_new_with_label("Apply");
	SIGNAL_CONNECT(apply_bt, "clicked", airpcap_advanced_apply_cb, airpcap_advanced_w);
	gtk_widget_show(apply_bt);

	ok_bt = gtk_button_new_with_label("Ok");
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_OK_KEY,ok_bt);
	window_set_cancel_button(airpcap_advanced_w, ok_bt, window_cancel_button_cb);
	gtk_widget_show(ok_bt);

	cancel_bt = gtk_button_new_with_label("Cancel");
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_CANCEL_KEY,cancel_bt);
	window_set_cancel_button(airpcap_advanced_w, cancel_bt, window_cancel_button_cb);
	gtk_widget_show(cancel_bt);

	/* Add them to box 2 */
	gtk_box_pack_end (GTK_BOX (buttons_box_2), cancel_bt, FALSE, FALSE, 1);
	gtk_box_pack_end (GTK_BOX (buttons_box_2), apply_bt,  FALSE, FALSE, 1);
	gtk_box_pack_end (GTK_BOX (buttons_box_2), ok_bt,     FALSE, FALSE, 1);

	/* Create the three main frames */
	interface_frame = gtk_frame_new("");
	gtk_frame_set_label(GTK_FRAME(interface_frame),"Interface");

	basic_frame = gtk_frame_new("");
	gtk_frame_set_label(GTK_FRAME(basic_frame),"Basic Parameters");

	wep_frame = gtk_frame_new("");
	gtk_frame_set_label(GTK_FRAME(wep_frame),"WEP Keys");

	/* Create the three sub boxes */
	interface_box = gtk_hbox_new(FALSE,0);
	basic_box     = gtk_hbox_new(FALSE,0);
	wep_box       = gtk_vbox_new(FALSE,0);

	/* Fill the interface_box */
	if(airpcap_if_active != NULL)
		{
		interface_combo = gtk_label_new(airpcap_if_active->description);
		}
	else
		{
		interface_combo = gtk_label_new("No airpcap interface found!");
		gtk_widget_set_sensitive(main_box,FALSE);
		}

	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_INTERFACE_KEY,interface_combo);
	gtk_box_pack_start (GTK_BOX (interface_box), interface_combo, TRUE, TRUE, 0);
	gtk_widget_show(interface_combo);

	/* blink led button (BEFORE interface_combo, 'cause its callback will need blink_bt)*/
	blink_bt = gtk_button_new_with_label("  Blink Led  ");
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_BLINK_KEY,blink_bt);
	gtk_box_pack_end (GTK_BOX (interface_box), blink_bt, FALSE, FALSE, 0);
	SIGNAL_CONNECT(blink_bt, "clicked", blink_cb, NULL);
	gtk_widget_show(blink_bt);

	gtk_container_set_border_width (GTK_CONTAINER (interface_box), 10);

	/* Fill the basic_box */
	/* Create the two vertical boxes for combo and check */
	basic_combo_box = gtk_vbox_new(TRUE,0);
	basic_check_box = gtk_vbox_new(TRUE,0);
	basic_label_box = gtk_vbox_new(TRUE,0);

	/* Create the Wrong CRC horiziontal box */
	basic_wrong_box = gtk_hbox_new(FALSE,0);

	/* Fill the label vbox */
	channel_lb = gtk_label_new("Channel:      ");
	gtk_label_set_justify(GTK_LABEL(channel_lb),GTK_JUSTIFY_LEFT);
	gtk_box_pack_start (GTK_BOX (basic_label_box), channel_lb, TRUE, TRUE, 0);
	gtk_widget_show(channel_lb);
	capture_lb = gtk_label_new("Capture Type:");
	gtk_label_set_justify(GTK_LABEL(capture_lb),GTK_JUSTIFY_LEFT);
	gtk_box_pack_start (GTK_BOX (basic_label_box), capture_lb, TRUE, TRUE, 0);
	gtk_widget_show(capture_lb);

	/* Create the two combo boxes */
	channel_combo = gtk_combo_new();
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_CHANNEL_KEY,channel_combo);

	channel_list = NULL;
	channel_list = g_list_append(channel_list, "1");
    channel_list = g_list_append(channel_list, "2");
    channel_list = g_list_append(channel_list, "3");
    channel_list = g_list_append(channel_list, "4");
	channel_list = g_list_append(channel_list, "5");
	channel_list = g_list_append(channel_list, "6");
	channel_list = g_list_append(channel_list, "7");
	channel_list = g_list_append(channel_list, "8");
	channel_list = g_list_append(channel_list, "9");
	channel_list = g_list_append(channel_list, "10");
	channel_list = g_list_append(channel_list, "11");
	channel_list = g_list_append(channel_list, "12");
	channel_list = g_list_append(channel_list, "13");
	channel_list = g_list_append(channel_list, "14");
	gtk_combo_set_popdown_strings( GTK_COMBO(channel_combo), channel_list) ;

	/* Select the first entry */
	if(airpcap_if_selected != NULL)
		{
		channel_s = g_strdup_printf("%d",airpcap_if_selected->channel);
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_combo)->entry), channel_s);
		}

	channel_te = GTK_COMBO(channel_combo)->entry;
	gtk_editable_set_editable(GTK_EDITABLE(channel_te),FALSE);
    SIGNAL_CONNECT(channel_te, "changed",  channel_changed_cb, channel_te);
	gtk_box_pack_start (GTK_BOX (basic_combo_box), channel_combo, FALSE, FALSE, 0);
	gtk_widget_show(channel_combo);

	capture_combo = gtk_combo_new();
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_LINK_TYPE_KEY,capture_combo);
	capture_list = NULL;
	capture_list = g_list_append(capture_list, AIRPCAP_LINK_TYPE_NAME_802_11_ONLY);
    capture_list = g_list_append(capture_list, AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO);
	gtk_combo_set_popdown_strings( GTK_COMBO(capture_combo), capture_list) ;

	capture_s = NULL;
	if(airpcap_if_selected != NULL)
		{
		if(airpcap_if_selected->linkType == AIRPCAP_LT_802_11)
			capture_s = g_strdup_printf("%s",AIRPCAP_LINK_TYPE_NAME_802_11_ONLY);
		else if(airpcap_if_selected->linkType == AIRPCAP_LT_802_11_PLUS_RADIO)
			capture_s = g_strdup_printf("%s",AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO);
		if(capture_s != NULL) gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(capture_combo)->entry), capture_s);
		}
	g_free(capture_s);

	link_type_te = GTK_COMBO(capture_combo)->entry;
	gtk_editable_set_editable(GTK_EDITABLE(link_type_te),FALSE);
    SIGNAL_CONNECT(link_type_te, "changed",  link_type_changed_cb, link_type_te);
	gtk_box_pack_start (GTK_BOX (basic_combo_box), capture_combo, FALSE, FALSE, 1);
	gtk_widget_show(capture_combo);

	/* Create the two check boxes */
	crc_check		= gtk_check_button_new_with_label("Include 802.11 FCS in Frames");
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_CRC_KEY,crc_check);

	/* Fcs Presence check box */
	if(airpcap_if_selected != NULL)
		{
		if(airpcap_if_selected->IsFcsPresent)
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(crc_check),TRUE);
		else
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(crc_check),FALSE);
		}

	SIGNAL_CONNECT(crc_check,"toggled",crc_check_cb,NULL);
	gtk_box_pack_start (GTK_BOX (basic_check_box), crc_check, FALSE, FALSE, 0);
	gtk_widget_show(crc_check);

	/* CRC Filter label */
	wrong_lb = gtk_label_new("FCS Filter:");
	gtk_box_pack_start (GTK_BOX (basic_wrong_box), wrong_lb, FALSE, FALSE, 0);
	gtk_widget_show(wrong_lb);

	/* CRC Filter combo */
	wrong_crc_combo = gtk_combo_new();
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_WRONG_CRC_KEY,wrong_crc_combo);

	linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_ALL);
	linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_CORRECT);
    linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT);

	gtk_combo_set_popdown_strings( GTK_COMBO(wrong_crc_combo), linktype_list) ;

	wrong_crc_te = GTK_COMBO(wrong_crc_combo)->entry;

	if(airpcap_if_selected != NULL)
		{
		airpcap_validation_type_combo_set_by_type(wrong_crc_combo,airpcap_if_selected->CrcValidationOn);
		}

	gtk_editable_set_editable(GTK_EDITABLE(wrong_crc_te),FALSE);
	SIGNAL_CONNECT(wrong_crc_te,"changed",wrong_crc_combo_cb,wrong_crc_te);
	gtk_box_pack_start (GTK_BOX (basic_wrong_box), wrong_crc_combo, FALSE, FALSE, 0);
	gtk_widget_show(wrong_crc_combo);

	gtk_box_pack_start(GTK_BOX(basic_check_box), basic_wrong_box, FALSE, FALSE, 0);
	gtk_widget_show(basic_wrong_box);

	/* Add the vertical inner boxes to the basic_box */
	gtk_box_pack_start (GTK_BOX (basic_box), basic_label_box, FALSE, FALSE, 10);
	gtk_box_pack_start (GTK_BOX (basic_box), basic_combo_box, FALSE, FALSE, 10);
	gtk_box_pack_start (GTK_BOX (basic_box), basic_check_box, FALSE, FALSE, 10);

	gtk_container_set_border_width (GTK_CONTAINER (basic_box), 10);

	/* Fill the wep_box */
	wep_sub_box = gtk_hbox_new(FALSE,1);
	gtk_widget_show(wep_sub_box);
	encryption_box = gtk_hbox_new(FALSE,1);
	gtk_widget_show(encryption_box);

	/* encryption enabled box */
	encryption_check = gtk_check_button_new_with_label("Enable WEP Decryption");
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_DECRYPTION_KEY,encryption_check);

	/* Fcs Presence check box */
	if(airpcap_if_selected != NULL)
		{
		if(airpcap_if_selected->DecryptionOn == AIRPCAP_DECRYPTION_ON)
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(encryption_check),TRUE);
		else
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(encryption_check),FALSE);
		}

	SIGNAL_CONNECT(encryption_check,"toggled",encryption_check_cb,NULL);
	gtk_box_pack_start (GTK_BOX (encryption_box), encryption_check, FALSE, FALSE, 0);
	gtk_widget_show(encryption_check);

	/* WEP text box */
	key_text = scrolled_window_new(NULL, NULL);
    /* never use a scrollbar in x direction, show the complete relation string */
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(key_text),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    #if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(key_text),
                                   GTK_SHADOW_IN);
    #endif

	/* add WEP keys if present... */
    key_ls = gtk_list_new();
    gtk_list_set_selection_mode(GTK_LIST(key_ls), GTK_SELECTION_SINGLE);
	OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEYLIST_KEY,key_ls);

	airpcap_fill_key_list(key_ls,airpcap_if_selected);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(key_text),key_ls);
	gtk_widget_show(key_ls);
	gtk_box_pack_start (GTK_BOX (wep_sub_box), key_text, TRUE, TRUE, 0);
	gtk_widget_show(key_text);

	/* WEP buttons */
	wep_buttons_box = gtk_vbox_new(FALSE,0);

	/* Create and add buttons */
	add_new_key_bt = gtk_button_new_with_label("Add New Key");
	SIGNAL_CONNECT(add_new_key_bt, "clicked", airpcap_advanced_add_key_cb, airpcap_advanced_w);
	gtk_box_pack_start (GTK_BOX (wep_buttons_box), add_new_key_bt, FALSE, FALSE, 0);
	gtk_widget_show(add_new_key_bt);
	remove_key_bt = gtk_button_new_with_label("Remove Key");
	SIGNAL_CONNECT(remove_key_bt, "clicked", airpcap_advanced_remove_key_cb, key_ls);
	gtk_box_pack_start (GTK_BOX (wep_buttons_box), remove_key_bt, FALSE, FALSE, 0);
	gtk_widget_show(remove_key_bt);
	edit_key_bt = gtk_button_new_with_label("Edit Key");
	SIGNAL_CONNECT(edit_key_bt, "clicked", airpcap_advanced_edit_key_cb, airpcap_advanced_w);
	gtk_box_pack_start (GTK_BOX (wep_buttons_box), edit_key_bt, FALSE, FALSE, 0);
	gtk_widget_show(edit_key_bt);
	move_key_up_bt = gtk_button_new_with_label("Move Key Up");
	SIGNAL_CONNECT(move_key_up_bt, "clicked", airpcap_advanced_move_key_up_cb, key_ls);
	gtk_box_pack_start (GTK_BOX (wep_buttons_box), move_key_up_bt, FALSE, FALSE, 0);
	gtk_widget_show(move_key_up_bt);
	move_key_down_bt = gtk_button_new_with_label("Move Key Down");
	SIGNAL_CONNECT(move_key_down_bt, "clicked", airpcap_advanced_move_key_down_cb, key_ls);
	gtk_box_pack_start (GTK_BOX (wep_buttons_box), move_key_down_bt, FALSE, FALSE, 0);
	gtk_widget_show(move_key_down_bt);

	gtk_box_pack_end (GTK_BOX (wep_sub_box), wep_buttons_box, FALSE, FALSE, 0);

	gtk_container_set_border_width (GTK_CONTAINER (wep_sub_box), 10);

	gtk_box_pack_start (GTK_BOX (wep_box), encryption_box, FALSE, FALSE,0);
	gtk_box_pack_start (GTK_BOX (wep_box), wep_sub_box, FALSE, FALSE,0);
	gtk_widget_show(wep_sub_box);

	/* Add them to the frames */
	gtk_container_add(GTK_CONTAINER(interface_frame),interface_box);
	gtk_container_add(GTK_CONTAINER(basic_frame),basic_box);
	gtk_container_add(GTK_CONTAINER(wep_frame),wep_box);

	/* Add frames to the main box */
	gtk_box_pack_start (GTK_BOX (main_box), interface_frame, FALSE, FALSE, 1);
	gtk_box_pack_start (GTK_BOX (main_box), basic_frame, FALSE, FALSE, 1);
	gtk_box_pack_start (GTK_BOX (main_box), wep_frame, FALSE, FALSE, 1);

	/* Add buttons' boxes to the main box */
	gtk_box_pack_start (GTK_BOX (main_box), buttons_box_2, FALSE, FALSE, 1);

	/* Add the main box to the main window */
	gtk_container_add(GTK_CONTAINER(airpcap_advanced_w),main_box);

	/* SHOW EVERYTHING */
	/* Show the WEP key buttons */
	gtk_widget_show (wep_buttons_box);

	/* Show the combo and check boxes */
	gtk_widget_show (basic_label_box);
	gtk_widget_show (basic_combo_box);
	gtk_widget_show (basic_check_box);

	/* Show the button boxes */
	gtk_widget_show (buttons_box_1);
	gtk_widget_show (buttons_box_2);

	/* Show the frames */
	gtk_widget_show (interface_frame);
	gtk_widget_show (basic_frame);
	gtk_widget_show (wep_frame);

	/* Show the sub main boxes */
	gtk_widget_show (interface_box);
	gtk_widget_show (basic_box);
	gtk_widget_show (wep_box);

	/* Show the main box */
	gtk_widget_show (main_box);

	/* Show the window */
	gtk_widget_show (airpcap_advanced_w);
}

#endif /* HAVE_AIRPCAP */
