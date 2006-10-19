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
#include <glib/gprintf.h>

#include <string.h>

#include <epan/filesystem.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>

#include <pcap.h>

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
 * This function is used to write the preferences to the preferences file.
 * It has the same behaviour as prefs_main_write() in prefs_dlg.c
 */
static void
write_prefs_to_file(void)
{
  int err;
  char *pf_dir_path;
  char *pf_path;

  /* Create the directory that holds personal configuration files, if
     necessary.  */
  if (create_persconffile_dir(&pf_dir_path) == -1) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "Can't create directory\n\"%s\"\nfor preferences file: %s.", pf_dir_path,
      strerror(errno));
     g_free(pf_dir_path);
  } else {
    /* Write the preferencs out. */
    err = write_prefs(&pf_path);
    if (err != 0) {
       simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "Can't open preferences file\n\"%s\": %s.", pf_path,
        strerror(err));
       g_free(pf_path);
    }
  }
}

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
 * Callback for the select row event in the key list widget
 */
void
on_key_ls_select_row(GtkWidget *widget, 
                     gint row,
                     gint column,
                     GdkEventButton *event,
                     gpointer data)
{
airpcap_key_ls_selected_info_t*  selected_item;
                             
selected_item = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);

selected_item->row = row;
selected_item->column = column;
}

/*
 * Callback for the unselect row event in the key list widget
 */
void
on_key_ls_unselect_row(GtkWidget *widget,
                       gint row,
                       gint column,
                       GdkEventButton *event,
                       gpointer data)
{
airpcap_key_ls_selected_info_t*  selected_item;
                             
selected_item = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);

selected_item->row = NO_ROW_SELECTED;
selected_item->column = NO_COLUMN_SELECTED;
}

/*
 * Callback for the click column event in the key list widget
 */
void
on_key_ls_click_column(GtkWidget *widget,
                       gint column,
                       gpointer data)
{

}

/*
 * Callback for the crc chackbox
 */
static void
on_fcs_ck_toggled(GtkWidget *w, gpointer user_data)
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
on_edit_type_en_changed(GtkWidget *w, gpointer data)
{
GtkWidget *edit_key_w;
GtkWidget *edit_ssid_te;
GtkWidget *type_te;

gchar* type_text = NULL;

edit_key_w = GTK_WIDGET(data);
type_te    = w;

edit_ssid_te = OBJECT_GET_DATA(edit_key_w,AIRPCAP_ADVANCED_EDIT_KEY_SSID_KEY);

type_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(type_te)));

if(string_is_not_empty(type_text))
    {
    /* 
     * If it is a WEP key, no SSID is required! Gray out rhe entry text so 
     * it doesn't create confusion ...
     */
    if(g_strcasecmp(type_text,AIRPCAP_WEP_KEY_STRING) == 0)
        {
        gtk_widget_set_sensitive(edit_ssid_te,FALSE);
        }
    else
        {
        gtk_widget_set_sensitive(edit_ssid_te,TRUE);
        }
    }
gtk_widget_show(edit_ssid_te);

g_free(type_text);
}

/*
 * Callback for the wrong crc combo
 */
static void
on_add_type_en_changed(GtkWidget *w, gpointer data)
{
GtkWidget *add_key_w;
GtkWidget *add_ssid_te;
GtkWidget *type_te;

gchar* type_text = NULL;

add_key_w = GTK_WIDGET(data);
type_te    = w;

add_ssid_te = OBJECT_GET_DATA(add_key_w,AIRPCAP_ADVANCED_ADD_KEY_SSID_KEY);

type_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(type_te)));

if(string_is_not_empty(type_text))
    {
    /* 
     * If it is a WEP key, no SSID is required! Gray out rhe entry text so 
     * it doesn't create confusion ...
     */
    if(g_strcasecmp(type_text,AIRPCAP_WEP_KEY_STRING) == 0)
        {
        gtk_widget_set_sensitive(add_ssid_te,FALSE);
        }
    else
        {
        gtk_widget_set_sensitive(add_ssid_te,TRUE);
        }
    }
gtk_widget_show(add_ssid_te);

g_free(type_text);
}

/*
 * Returns FALSE if a text string has lenght 0, i.e. the first char 
 * is '\0', TRUE otherwise
 */
gboolean
string_is_not_empty(gchar *s)
{
if(g_strcasecmp(s,"") != 0)
    return TRUE;
else
    return FALSE;
}

/*
 * Callback for the wrong crc combo
 */
static void
on_fcs_filter_en_changed(GtkWidget *w, gpointer data)
{
const gchar *s;

s = gtk_entry_get_text(GTK_ENTRY(w));

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
on_channel_en_changed(GtkWidget *w _U_, gpointer data)
{
const gchar *s;

  s = gtk_entry_get_text(GTK_ENTRY(w));

if( !block_advanced_signals && (data != NULL) && (w != NULL) )
	{
	s = gtk_entry_get_text(GTK_ENTRY(w));
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
 * Changed callback for the capture type combobox
 */
static void
on_capture_type_en_changed(GtkWidget *w _U_, gpointer data)
{
const gchar *s;

s = gtk_entry_get_text(GTK_ENTRY(w));

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
  crc_check			= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_FCS_CHECK_KEY));
  wrong_crc_combo	= GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_ADVANCED_FCS_FILTER_KEY));
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
gchar ebuf[AIRPCAP_ERRBUF_SIZE];

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
on_blink_bt_clicked( GtkWidget *blink_bt _U_, gpointer if_data )
{
PAirpcapHandle ad = NULL;
gchar ebuf[AIRPCAP_ERRBUF_SIZE];

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

/*
 * Callback for the 'Any' adapter What's This button.
 */
void
on_what_s_this_bt_clicked( GtkWidget *blink_bt _U_, gpointer if_data )
{
simple_dialog(ESD_TYPE_INFO,ESD_BTN_OK,"The Multi-Channel Aggregator is a virtual device that can be used to capture packets from all the AirPcap adapters at the same time.\nThe Capture Type, FCS and Encryption settings of this virtual device can be configured as for any real adapter.\nThe channel cannot be changed for this adapter.\nRefer to the AirPcap manual for more information.");
}

/* the window was closed, cleanup things */
void
on_key_management_destroy(GtkWidget *w _U_, gpointer data _U_)
{
GtkWidget	*airpcap_advanced_w,
			*toolbar;
	
gint *from_widget = NULL;

/* Retrieve the GUI object pointers */
airpcap_advanced_w  = GTK_WIDGET(data);

toolbar	= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_TOOLBAR_KEY));

/* ... */
from_widget	= (gint*)OBJECT_GET_DATA(toolbar,AIRPCAP_ADVANCED_FROM_KEY);
/* gray out the toolbar (if we came here from the toolbar advanced button)*/
if( *from_widget == AIRPCAP_ADVANCED_FROM_TOOLBAR)
	gtk_widget_set_sensitive(toolbar,TRUE);
else
	gtk_widget_set_sensitive(toolbar,FALSE);
g_free(from_widget);

/* reload the configuration!!! Configuration has not been saved but
the corresponding structure has been modified probably...*/
if(!airpcap_if_selected->saved)
	{
	airpcap_load_selected_if_configuration(airpcap_if_selected);
	}
}

/* the Advenced wireless Settings window was closed, cleanup things */
static void
on_airpcap_advanced_destroy(GtkWidget *w _U_, gpointer data _U_)
{
GtkWidget	*airpcap_advanced_w,
			*toolbar;
	
gint *from_widget = NULL;

/* Retrieve the GUI object pointers */
airpcap_advanced_w  = GTK_WIDGET(data);

toolbar	= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_TOOLBAR_KEY));

/* ... */
from_widget	= (gint*)OBJECT_GET_DATA(toolbar,AIRPCAP_ADVANCED_FROM_KEY);
/* gray out the toolbar (if we came here from the toolbar advanced button)*/
if( *from_widget == AIRPCAP_ADVANCED_FROM_TOOLBAR)
	gtk_widget_set_sensitive(toolbar,TRUE);
else
	gtk_widget_set_sensitive(toolbar,FALSE);
g_free(from_widget);

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
void
on_key_management_apply_bt_clicked(GtkWidget *button, gpointer data _U_)
{
/* advenced window */
GtkWidget	*key_management_w;

/* widgets in the toolbar */
GtkWidget	*toolbar;
GtkWidget *toolbar_cm;

GtkWidget   *key_ls;

GtkWidget   *decryption_en;

char* decryption_mode_string = NULL;

/* retrieve main window */
key_management_w      = GTK_WIDGET(data);
decryption_en         = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_WEP_DECRYPTION_KEY));
key_ls	              = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_KEYLIST_KEY));
toolbar               = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_TOOLBAR_KEY));
toolbar_cm            = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_TOOLBAR_DECRYPTION_KEY));

#define CANT_SAVE_ERR_STR "Cannot save configuration!\n" \
	"In order to store the configuration in the registry you must:\n\n" \
	"- Close all the airpcap-based applications.\n"\
	"- Have administrative privileges."
/* Set the Decryption Mode */
if(g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK) == 0)
    {
    set_wireshark_decryption(TRUE);
    if(!set_airpcap_decryption(FALSE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }
else if(g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP) == 0)
    {
    set_wireshark_decryption(FALSE);
    if(!set_airpcap_decryption(TRUE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }
else if(g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_NONE) == 0)
    {
    set_wireshark_decryption(FALSE);
    if(!set_airpcap_decryption(FALSE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }

/* Save the configuration */
if( (airpcap_if_selected != NULL) )
    {
    airpcap_read_and_save_decryption_keys_from_clist(key_ls,airpcap_if_selected,airpcap_if_list); /* This will save the keys for every adapter */
    
    /* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
    if( g_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
    	{
		update_decryption_mode_cm(toolbar_cm);
		}
    }

/* Redissect all the packets, and re-evaluate the display filter. */
cf_redissect_packets(&cfile);
}

/*
 * Callback for the Wireless Advanced Settings 'Apply' button.
 */
void
on_advanced_apply_bt_clicked(GtkWidget *button, gpointer data _U_)
{
	/* advenced window */
	GtkWidget	*main_w;

	/* widgets in the toolbar */
	GtkWidget	*toolbar,
				*toolbar_if_lb,
				*toolbar_channel_cm,
				*toolbar_wrong_crc_cm;
				
	/* retrieve main window */
	main_w = GTK_WIDGET(data);

	toolbar = GTK_WIDGET(OBJECT_GET_DATA(main_w,AIRPCAP_TOOLBAR_KEY));

	/* retrieve toolbar info */
	toolbar_if_lb			= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
	toolbar_channel_cm		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
	toolbar_wrong_crc_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_FCS_FILTER_KEY));

	/* Save the configuration (for all ) */
	airpcap_save_selected_if_configuration(airpcap_if_selected);

	/* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
	if( g_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
		{
		gtk_label_set_text(GTK_LABEL(toolbar_if_lb), g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_selected)));
        airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cm),airpcap_if_selected);
		airpcap_validation_type_combo_set_by_type(toolbar_wrong_crc_cm,airpcap_if_selected->CrcValidationOn);
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
	toolbar_wrong_crc_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_FCS_FILTER_KEY));
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
		airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cm),airpcap_if_selected);
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
void
on_reset_configuration_bt_clicked(GtkWidget *button, gpointer data _U_)
{
return;
}

/*
 * Callback used to add a WEP key in the add new key box;
 */
static void
add_key(GtkWidget *widget, gpointer data _U_)
{
GtkWidget	*type_cm,
			*key_en,
			*ssid_en;
			
GtkWidget   *key_ls;

GString     *new_type_string,	
            *new_key_string,            
            *new_ssid_string;

gchar		*type_entered = NULL;
gchar		*key_entered = NULL;
gchar		*ssid_entered = NULL;

airpcap_key_ls_selected_info_t *selected_item;

int keys_in_list = 0;

unsigned int i;

gint r = NO_ROW_SELECTED;
gint c = NO_COLUMN_SELECTED;

key_ls = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_ADD_KEY_LIST_KEY);
selected_item = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);
type_cm = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_ADD_KEY_TYPE_KEY);
key_en = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_ADD_KEY_KEY_KEY);
ssid_en = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_ADD_KEY_SSID_KEY);

r = selected_item->row;
c = selected_item->column;

keys_in_list = GTK_CLIST(key_ls)->rows;

type_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(type_cm)->entry)));
key_entered  = g_strdup(gtk_entry_get_text(GTK_ENTRY(key_en)));
ssid_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(ssid_en)));

/* Check if key is correct */
new_type_string = g_string_new(type_entered);
new_key_string = g_string_new(key_entered);
new_ssid_string = g_string_new(ssid_entered);

g_strchug(new_key_string->str);
g_strchomp(new_key_string->str);

g_strchug(new_ssid_string->str);
g_strchomp(new_ssid_string->str);

/* Check which type of key the user has entered */
if(g_strcasecmp(new_type_string->str,AIRPCAP_WEP_KEY_STRING) == 0) /* WEP key */
{
                                                             
if( ((new_key_string->len) > WEP_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < 2))
	{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WEP key size out of range!\nValid key size range is 2-%d characters (8-%d bits).",WEP_KEY_MAX_CHAR_SIZE,WEP_KEY_MAX_SIZE*8);	
    
    g_string_free(new_type_string,TRUE);
    g_string_free(new_key_string, TRUE);
    g_string_free(new_ssid_string,TRUE);
    
    g_free(type_entered);
    g_free(key_entered );
    g_free(ssid_entered);
    return;
	}

if((new_key_string->len % 2) != 0)
	{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nThe number of characters must be even.");
	
    g_string_free(new_type_string,TRUE);
    g_string_free(new_key_string, TRUE);
    g_string_free(new_ssid_string,TRUE);
    
    g_free(type_entered);
    g_free(key_entered );
    g_free(ssid_entered);
    return;
	}

for(i = 0; i < new_key_string->len; i++)
	{
	if(!g_ascii_isxdigit(new_key_string->str[i]))
		{
		simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nA WEP key must be a hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.");
		
        g_string_free(new_type_string,TRUE);
        g_string_free(new_key_string, TRUE);
        g_string_free(new_ssid_string,TRUE);
        
        g_free(type_entered);
        g_free(key_entered );
        g_free(ssid_entered);
        return;
		}
	}

/* If so... Modify key */
airpcap_add_key_to_list(key_ls, new_type_string->str, new_key_string->str, new_ssid_string->str);

airpcap_if_selected->saved = FALSE;	
}
else if(g_strcasecmp(new_type_string->str,AIRPCAP_WPA_KEY_STRING) == 0) /* WPA Key */
{
/* XXX - Perform some WPA related input fields check */
/* If everything is ok, modify the entry int he list */

airpcap_if_selected->saved = FALSE;
}
else if(g_strcasecmp(new_type_string->str,AIRPCAP_WPA2_KEY_STRING) == 0) /* WPA2 Key */
{
/* XXX - Perform some WPA2 related input fields check */
/* If everything is ok, modify the entry int he list */

airpcap_if_selected->saved = FALSE;
}
else /* Should never happen!!! */
{ 
simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Unknown error in the key \"Type\" field!"); 
}

g_string_free(new_type_string,TRUE);
g_string_free(new_key_string, TRUE);
g_string_free(new_ssid_string,TRUE);

g_free(type_entered);
g_free(key_entered );
g_free(ssid_entered); 

window_destroy(GTK_WIDGET(data));
return;
}

/*
 * Callback used to edit a WEP key in the edit key box;
 */
static void
on_edit_key_ok_bt_clicked(GtkWidget *widget, gpointer data _U_)
{
GtkWidget	*type_cm,
			*key_en,
			*ssid_en;
			
GtkWidget   *key_ls;

GString     *new_type_string,	
            *new_key_string,            
            *new_ssid_string;

gchar		*type_entered = NULL;
gchar		*key_entered = NULL;
gchar		*ssid_entered = NULL;

airpcap_key_ls_selected_info_t *selected_item;

int keys_in_list = 0;

unsigned int i;

gint r = NO_ROW_SELECTED;
gint c = NO_COLUMN_SELECTED;

key_ls = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_LIST_KEY);
selected_item = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_SELECTED_KEY);
type_cm = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_TYPE_KEY);
key_en = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_KEY_KEY);
ssid_en = OBJECT_GET_DATA(GTK_WIDGET(data),AIRPCAP_ADVANCED_EDIT_KEY_SSID_KEY);

r = selected_item->row;
c = selected_item->column;

keys_in_list = GTK_CLIST(key_ls)->rows;

type_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(type_cm)->entry)));
key_entered  = g_strdup(gtk_entry_get_text(GTK_ENTRY(key_en)));
ssid_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(ssid_en)));

/* Check if key is correct */
new_type_string = g_string_new(type_entered);
new_key_string = g_string_new(key_entered);
new_ssid_string = g_string_new(ssid_entered);

g_strchug(new_key_string->str);
g_strchomp(new_key_string->str);

g_strchug(new_ssid_string->str);
g_strchomp(new_ssid_string->str);

/* Check which type of key the user has entered */
if(g_strcasecmp(new_type_string->str,AIRPCAP_WEP_KEY_STRING) == 0) /* WEP key */
{
                                                             
if( ((new_key_string->len) > WEP_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < 2))
	{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WEP key size out of range!\nValid key size range is 2-%d characters (8-%d bits).",WEP_KEY_MAX_CHAR_SIZE,WEP_KEY_MAX_SIZE*8);	
    
    g_string_free(new_type_string,TRUE);
    g_string_free(new_key_string, TRUE);
    g_string_free(new_ssid_string,TRUE);
    
    g_free(type_entered);
    g_free(key_entered );
    g_free(ssid_entered);
    return;
	}

if((new_key_string->len % 2) != 0)
	{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nThe number of characters must be even.");
	
    g_string_free(new_type_string,TRUE);
    g_string_free(new_key_string, TRUE);
    g_string_free(new_ssid_string,TRUE);
    
    g_free(type_entered);
    g_free(key_entered );
    g_free(ssid_entered);
    return;
	}

for(i = 0; i < new_key_string->len; i++)
	{
	if(!g_ascii_isxdigit(new_key_string->str[i]))
		{
		simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nA WEP key must be an hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.");
		
        g_string_free(new_type_string,TRUE);
        g_string_free(new_key_string, TRUE);
        g_string_free(new_ssid_string,TRUE);
        
        g_free(type_entered);
        g_free(key_entered );
        g_free(ssid_entered);
        return;
		}
	}

/* If so... Modify key */
airpcap_modify_key_in_list(key_ls, r, new_type_string->str, new_key_string->str, new_ssid_string->str);

airpcap_if_selected->saved = FALSE;	
}
else if(g_strcasecmp(new_type_string->str,AIRPCAP_WPA_KEY_STRING) == 0) /* WPA Key */
{
/* XXX - Perform some WPA related input fields check */
/* If everything is ok, modify the entry int he list */

airpcap_if_selected->saved = FALSE;
}
else if(g_strcasecmp(new_type_string->str,AIRPCAP_WPA2_KEY_STRING) == 0) /* WPA2 Key */
{
/* XXX - Perform some WPA2 related input fields check */
/* If everything is ok, modify the entry int he list */

airpcap_if_selected->saved = FALSE;
}
else /* Should never happen!!! */
{ 
simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Unknown error in the key \"Type\" field!"); 
}

g_string_free(new_type_string,TRUE);
g_string_free(new_key_string, TRUE);
g_string_free(new_ssid_string,TRUE);

g_free(type_entered);
g_free(key_entered );
g_free(ssid_entered); 

window_destroy(GTK_WIDGET(data));
return;
}

/*
 * Callback for the 'Add Key' button.
 */
void
on_add_new_key_bt_clicked(GtkWidget *button, gpointer data _U_)
{
GtkWidget *add_key_window;
GtkWidget *add_frame;
GtkWidget *main_v_box;
GtkWidget *add_tb;
GtkWidget *add_frame_al;
GtkWidget *add_type_cm;
GList *add_type_cm_items = NULL;
GtkWidget *add_type_en;
GtkWidget *add_key_te;
GtkWidget *add_ssid_te;
GtkWidget *add_type_lb;
GtkWidget *add_key_lb;
GtkWidget *add_ssid_lb;
GtkWidget *low_h_button_box;
GtkWidget *ok_bt;
GtkWidget *cancel_bt;
GtkWidget *add_frame_lb;

GtkWidget *airpcap_advanced_w;

/* Key List Widget */
GtkWidget	*key_ls;

gint keys_in_list = 0;

/* Selected entry in the key list (if any)*/
airpcap_key_ls_selected_info_t* selected_item;

GList *item = NULL;
gint r,c;

airpcap_advanced_w = GTK_WIDGET(data);

/* Retrieve the selected item... if no row is selected, this is null... */
selected_item = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);

r = selected_item->row;
c = selected_item->column;

/* Retrieve the key list widget pointer, and add it to the add_key_w */
key_ls = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEYLIST_KEY);

keys_in_list = GTK_CLIST(key_ls)->rows;

if(keys_in_list >= MAX_ENCRYPTION_KEYS) /* Check if we have already reached the maximum number of allowed keys... */
{
	simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Maximum number (%d) of decryption keys reached! You cannot add another key!\n",MAX_ENCRYPTION_KEYS);	
    return;
}

/* Gray out the Advanced Wireless Setting window */
gtk_widget_set_sensitive(airpcap_advanced_w,FALSE);

/* Pop-up a new window */   
add_key_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
gtk_widget_set_name (add_key_window, "add_key_window");
gtk_container_set_border_width (GTK_CONTAINER (add_key_window), 5);
gtk_window_set_title (GTK_WINDOW (add_key_window), "Add Decryption Key");
#if GTK_MAJOR_VERSION >= 2
gtk_window_set_resizable (GTK_WINDOW (add_key_window), FALSE);
#else
gtk_window_set_policy(GTK_WINDOW(add_key_window), FALSE, FALSE, TRUE);
#endif

main_v_box = gtk_vbox_new (FALSE, 0);
gtk_widget_set_name (main_v_box, "main_v_box");
gtk_widget_show (main_v_box);
gtk_container_add (GTK_CONTAINER (add_key_window), main_v_box);

add_frame = gtk_frame_new (NULL);
gtk_widget_set_name (add_frame, "add_frame");
gtk_widget_show (add_frame);
gtk_box_pack_start (GTK_BOX (main_v_box), add_frame, TRUE, TRUE, 0);

add_frame_al = gtk_alignment_new (0.5, 0.5, 1, 1);
gtk_widget_set_name (add_frame_al, "add_frame_al");
gtk_widget_show (add_frame_al);
gtk_container_add (GTK_CONTAINER (add_frame), add_frame_al);
#if GTK_MAJOR_VERSION >= 2
gtk_alignment_set_padding (GTK_ALIGNMENT (add_frame_al), 0, 0, 12, 0);
#else
gtk_alignment_set (GTK_ALIGNMENT (add_frame_al), 0, 0, 12, 0);
#endif

add_tb = gtk_table_new (2, 3, FALSE);
gtk_widget_set_name (add_tb, "add_tb");
gtk_container_set_border_width(GTK_CONTAINER(add_tb),5);
gtk_widget_show (add_tb);
gtk_container_add (GTK_CONTAINER (add_frame_al), add_tb);

add_type_cm = gtk_combo_new ();
gtk_widget_set_name (add_type_cm, "add_type_cm");
gtk_widget_show (add_type_cm);
gtk_table_attach (GTK_TABLE (add_tb), add_type_cm, 0, 1, 1, 2,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
#if GTK_MAJOR_VERSION >= 2
gtk_widget_set_size_request (add_type_cm, 63, -1);
#else
gtk_widget_set_usize (add_type_cm, 63, -1);
#endif
add_type_cm_items = g_list_append (add_type_cm_items, (gpointer) AIRPCAP_WEP_KEY_STRING);

/* XXX - DEcomment only when WPA and WPA2 will be ready */
/*
add_type_cm_items = g_list_append (add_type_cm_items, (gpointer) AIRPCAP_WPA_KEY_STRING);
add_type_cm_items = g_list_append (add_type_cm_items, (gpointer) AIRPCAP_WPA2_KEY_STRING);*/
gtk_combo_set_popdown_strings (GTK_COMBO (add_type_cm),
			 add_type_cm_items);
g_list_free (add_type_cm_items);

add_type_en = GTK_COMBO (add_type_cm)->entry;
gtk_widget_set_name (add_type_en, "add_type_en");
gtk_editable_set_editable (GTK_EDITABLE (add_type_en), FALSE);
gtk_widget_show (add_type_en);

add_key_te = gtk_entry_new ();
gtk_widget_set_name (add_key_te, "add_key_te");

gtk_widget_show (add_key_te);
gtk_table_attach (GTK_TABLE (add_tb), add_key_te, 1, 2, 1, 2,
	    (GtkAttachOptions) (0), (GtkAttachOptions) (0), 0, 0);
#if GTK_MAJOR_VERSION >= 2
gtk_widget_set_size_request (add_key_te, 178, -1);
#else
gtk_widget_set_usize (add_key_te, 178, -1);
#endif

add_ssid_te = gtk_entry_new ();
gtk_widget_set_name (add_ssid_te, "add_ssid_te");
gtk_widget_set_sensitive(add_ssid_te,FALSE);
/* XXX - Decomment only when WPA and WPA2 will be ready */
/* gtk_widget_show (add_ssid_te); */
gtk_table_attach (GTK_TABLE (add_tb), add_ssid_te, 2, 3, 1, 2,
	    (GtkAttachOptions) (0), (GtkAttachOptions) (0), 0, 0);

add_type_lb = gtk_label_new ("Type");
gtk_widget_set_name (add_type_lb, "add_type_lb");
gtk_widget_show (add_type_lb);
gtk_table_attach (GTK_TABLE (add_tb), add_type_lb, 0, 1, 0, 1,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_label_set_justify (GTK_LABEL (add_type_lb), GTK_JUSTIFY_CENTER);

add_key_lb = gtk_label_new ("Key");
gtk_widget_set_name (add_key_lb, "add_key_lb");
gtk_widget_show (add_key_lb); 
gtk_table_attach (GTK_TABLE (add_tb), add_key_lb, 1, 2, 0, 1,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_label_set_justify (GTK_LABEL (add_key_lb), GTK_JUSTIFY_CENTER);

add_ssid_lb = gtk_label_new ("SSID");
gtk_widget_set_name (add_ssid_lb, "add_ssid_lb");
/* XXX - Decomment only when WPA and WPA2 will be ready */
/* gtk_widget_show (add_ssid_lb); */
gtk_table_attach (GTK_TABLE (add_tb), add_ssid_lb, 2, 3, 0, 1,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_label_set_justify (GTK_LABEL (add_ssid_lb), GTK_JUSTIFY_CENTER);

low_h_button_box = gtk_hbutton_box_new ();
gtk_widget_set_name (low_h_button_box, "low_h_button_box");
 gtk_container_set_border_width (GTK_CONTAINER (low_h_button_box), 5);
gtk_widget_show (low_h_button_box);
gtk_box_pack_end (GTK_BOX (main_v_box), low_h_button_box, FALSE, FALSE, 0);
gtk_button_box_set_layout (GTK_BUTTON_BOX (low_h_button_box),
		     GTK_BUTTONBOX_END);

#if GTK_MAJOR_VERISON >= 2
ok_bt = gtk_button_new_with_mnemonic ("Ok");
#else
ok_bt = gtk_button_new_with_label ("Ok");
#endif
gtk_widget_set_name (ok_bt, "ok_bt");
gtk_widget_show (ok_bt);
gtk_container_add (GTK_CONTAINER (low_h_button_box), ok_bt);
GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERISON >= 2
cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
#else
cancel_bt = gtk_button_new_with_label ("Cancel");
#endif
gtk_widget_set_name (cancel_bt, "cancel_bt");
gtk_widget_show (cancel_bt);
gtk_container_add (GTK_CONTAINER (low_h_button_box), cancel_bt);
GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);

add_frame_lb = gtk_label_new ("<b>Modify Selected Key</b>");
gtk_widget_set_name (add_frame_lb, "add_frame_lb");
gtk_widget_show (add_frame_lb);
#if GTK_MAJOR_VERSION >= 2
gtk_frame_set_label_widget (GTK_FRAME (add_frame), add_frame_lb);
gtk_label_set_use_markup (GTK_LABEL (add_frame_lb), TRUE);
#else
gtk_frame_set_label (GTK_FRAME (add_frame), "Modify Selected Key");
#endif

/* Add callbacks */
SIGNAL_CONNECT(ok_bt, "clicked", add_key, add_key_window );
SIGNAL_CONNECT(cancel_bt, "clicked", window_cancel_button_cb, add_key_window );
SIGNAL_CONNECT(add_type_en, "changed",on_add_type_en_changed, add_key_window);
SIGNAL_CONNECT(add_key_window, "delete_event",window_delete_event_cb, add_key_window);
SIGNAL_CONNECT(add_key_window, "destroy",on_add_key_w_destroy, data);

/* Add widget data */
OBJECT_SET_DATA(add_key_window,AIRPCAP_ADVANCED_ADD_KEY_LIST_KEY,key_ls);
OBJECT_SET_DATA(add_key_window,AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY,selected_item);
OBJECT_SET_DATA(add_key_window,AIRPCAP_ADVANCED_ADD_KEY_TYPE_KEY,add_type_cm);
OBJECT_SET_DATA(add_key_window,AIRPCAP_ADVANCED_ADD_KEY_KEY_KEY,add_key_te);
OBJECT_SET_DATA(add_key_window,AIRPCAP_ADVANCED_ADD_KEY_SSID_KEY,add_ssid_te);

gtk_widget_show(add_key_window);
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
void
on_edit_key_w_destroy(GtkWidget *button, gpointer data _U_)
{
GtkWidget *airpcap_advanced_w;

airpcap_advanced_w = GTK_WIDGET(data);

gtk_widget_set_sensitive(GTK_WIDGET(airpcap_advanced_w),TRUE);

return;
}

/*
 * Add key window destroy callback
 */
void
on_add_key_w_destroy(GtkWidget *button, gpointer data _U_)
{
GtkWidget *airpcap_advanced_w;

airpcap_advanced_w = GTK_WIDGET(data);

gtk_widget_set_sensitive(GTK_WIDGET(airpcap_advanced_w),TRUE);

return;
}

/*
 * Callback for the 'Remove Key' button.
 */
void
on_remove_key_bt_clicked(GtkWidget *button, gpointer data _U_)
{
GtkWidget *key_ls;
GtkWidget *airpcap_advanced_w;

gint keys_in_list;

airpcap_key_ls_selected_info_t *selected_item;

gint c = NO_COLUMN_SELECTED;
gint r = NO_ROW_SELECTED;

airpcap_advanced_w = GTK_WIDGET(data);

/* retrieve needed stuff */
key_ls        = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEYLIST_KEY);
selected_item = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);

/* 
 * Better to store the selected_item data in two new variables, because maybe some 
 * select_row signal will be emitted somewhere...
 */
r = selected_item->row;
c = selected_item->column;

keys_in_list = GTK_CLIST(key_ls)->rows;

if( r == NO_ROW_SELECTED ) /* No key selected */
    return;

/* Remove selected key*/
gtk_clist_remove(GTK_CLIST(key_ls),r);

/* Reselect another row, if any... */
if( r < (keys_in_list-1) )
    gtk_clist_select_row(GTK_CLIST(key_ls),r,c);
else
    gtk_clist_select_row(GTK_CLIST(key_ls),r-1,c);  

/* Need to save config... */
airpcap_if_selected->saved = FALSE;
}

/*
 * Callback for the 'Edit Key' button.
 */
void
on_edit_key_bt_clicked(GtkWidget *button, gpointer data _U_)
{
GtkWidget *edit_key_window;
GtkWidget *edit_frame;
GtkWidget *main_v_box;
GtkWidget *edit_tb;
GtkWidget *edit_frame_al;
GtkWidget *edit_type_cm;
GList *edit_type_cm_items = NULL;
GtkWidget *edit_type_en;
GtkWidget *edit_key_te;
GtkWidget *edit_ssid_te;
GtkWidget *edit_type_lb;
GtkWidget *edit_key_lb;
GtkWidget *edit_ssid_lb;
GtkWidget *low_h_button_box;
GtkWidget *ok_bt;
GtkWidget *cancel_bt;
GtkWidget *edit_frame_lb;

GtkWidget *airpcap_advanced_w;

/* Key List Widget */
GtkWidget	*key_ls;

/* Selected entry in the key list (if any)*/
airpcap_key_ls_selected_info_t* selected_item;

gchar *row_type,
      *row_key,
      *row_ssid;

GList *item = NULL;
gint r,c;

airpcap_advanced_w = GTK_WIDGET(data);

/* Retrieve the selected item... if no row is selected, this is null... */
selected_item = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);

r = selected_item->row;
c = selected_item->column;

/* Retrieve the key list widget pointer, and add it to the edit_key_w */
key_ls = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEYLIST_KEY);

if((r != NO_ROW_SELECTED) && (c != NO_COLUMN_SELECTED))
    {
    gtk_clist_get_text(GTK_CLIST(key_ls),r,0,&row_type);
    gtk_clist_get_text(GTK_CLIST(key_ls),r,1,&row_key);
    gtk_clist_get_text(GTK_CLIST(key_ls),r,2,&row_ssid);
    
    /* Gray out the Advanced Wireless Setting window */
    gtk_widget_set_sensitive(airpcap_advanced_w,FALSE);
    
    /* Pop-up a new window */   
    edit_key_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_name (edit_key_window, "edit_key_window");
    gtk_container_set_border_width (GTK_CONTAINER (edit_key_window), 5);
    gtk_window_set_title (GTK_WINDOW (edit_key_window), "Edit Decryption Key");
    #if GTK_MAJOR_VERSION >= 2
    gtk_window_set_resizable (GTK_WINDOW (edit_key_window), FALSE);
    #else
    gtk_window_set_policy(GTK_WINDOW(edit_key_window), FALSE, FALSE, TRUE);
    #endif
    
    main_v_box = gtk_vbox_new (FALSE, 0);
    gtk_widget_set_name (main_v_box, "main_v_box");
    gtk_widget_show (main_v_box);
    gtk_container_add (GTK_CONTAINER (edit_key_window), main_v_box);
    
    edit_frame = gtk_frame_new (NULL);
    gtk_widget_set_name (edit_frame, "edit_frame");
    gtk_widget_show (edit_frame);
    gtk_box_pack_start (GTK_BOX (main_v_box), edit_frame, TRUE, TRUE, 0);
    
    edit_frame_al = gtk_alignment_new (0.5, 0.5, 1, 1);
    gtk_widget_set_name (edit_frame_al, "edit_frame_al");
    gtk_widget_show (edit_frame_al);
    gtk_container_add (GTK_CONTAINER (edit_frame), edit_frame_al);
    #if GTK_MAJOR_VERSION >= 2
    gtk_alignment_set_padding (GTK_ALIGNMENT (edit_frame_al), 0, 0, 12, 0);
    #else
    gtk_alignment_set (GTK_ALIGNMENT (edit_frame_al), 0, 0, 12, 0);
    #endif
    
    edit_tb = gtk_table_new (2, 3, FALSE);
    gtk_widget_set_name (edit_tb, "edit_tb");
    gtk_container_set_border_width(GTK_CONTAINER(edit_tb),5);
    gtk_widget_show (edit_tb);
    gtk_container_add (GTK_CONTAINER (edit_frame_al), edit_tb);
    
    edit_type_cm = gtk_combo_new ();
    gtk_widget_set_name (edit_type_cm, "edit_type_cm");
    gtk_widget_show (edit_type_cm);
    gtk_table_attach (GTK_TABLE (edit_tb), edit_type_cm, 0, 1, 1, 2,
    	    (GtkAttachOptions) (GTK_FILL),
    	    (GtkAttachOptions) (0), 0, 0);
    #if GTK_MAJOR_VERSION >= 2
    gtk_widget_set_size_request (edit_type_cm, 63, -1);
    #else
    gtk_widget_set_usize (edit_type_cm, 63, -1);
    #endif
    edit_type_cm_items = g_list_append (edit_type_cm_items, (gpointer) AIRPCAP_WEP_KEY_STRING);
    /* XXX - Decomment only when WPA and WPA2 support will be ready!!! */
/*  edit_type_cm_items = g_list_append (edit_type_cm_items, (gpointer) AIRPCAP_WPA_KEY_STRING);
    edit_type_cm_items = g_list_append (edit_type_cm_items, (gpointer) AIRPCAP_WPA2_KEY_STRING);*/
    gtk_combo_set_popdown_strings (GTK_COMBO (edit_type_cm),
    			 edit_type_cm_items);
    g_list_free (edit_type_cm_items);
    
    edit_type_en = GTK_COMBO (edit_type_cm)->entry;
    gtk_widget_set_name (edit_type_en, "edit_type_en");
    /* Set current type */
    gtk_entry_set_text(GTK_ENTRY(edit_type_en),row_type);
    gtk_editable_set_editable (GTK_EDITABLE (edit_type_en), FALSE);
    gtk_widget_show (edit_type_en);
    
    edit_key_te = gtk_entry_new ();
    gtk_widget_set_name (edit_key_te, "edit_key_te");
    /* Set current key */
    gtk_entry_set_text(GTK_ENTRY(edit_key_te),row_key);
    gtk_widget_show (edit_key_te);
    gtk_table_attach (GTK_TABLE (edit_tb), edit_key_te, 1, 2, 1, 2,
    	    (GtkAttachOptions) (0), (GtkAttachOptions) (0), 0, 0);
    #if GTK_MAJOR_VERSION >= 2
    gtk_widget_set_size_request (edit_key_te, 178, -1);
    #else
    gtk_widget_set_usize (edit_key_te, 178, -1);
    #endif
    
    edit_ssid_te = gtk_entry_new ();
    gtk_widget_set_name (edit_ssid_te, "edit_ssid_te");

    /* Set current ssid (if key type is not WEP!)*/
    if(g_strcasecmp(row_type,AIRPCAP_WEP_KEY_STRING) == 0)
    {
    gtk_widget_set_sensitive(edit_ssid_te,FALSE);
    }
    else
    {
    gtk_widget_set_sensitive(edit_ssid_te,TRUE);
    gtk_entry_set_text(GTK_ENTRY(edit_ssid_te),row_ssid);
    }
    
    /* XXX - Decomment only when WPA and WPA@ will be ready */
    /* gtk_widget_show (edit_ssid_te); */
    gtk_table_attach (GTK_TABLE (edit_tb), edit_ssid_te, 2, 3, 1, 2,
    	    (GtkAttachOptions) (0), (GtkAttachOptions) (0), 0, 0);
    
    edit_type_lb = gtk_label_new ("Type");
    gtk_widget_set_name (edit_type_lb, "edit_type_lb");
    gtk_widget_show (edit_type_lb);
    gtk_table_attach (GTK_TABLE (edit_tb), edit_type_lb, 0, 1, 0, 1,
    	    (GtkAttachOptions) (GTK_FILL),
    	    (GtkAttachOptions) (0), 0, 0);
    gtk_label_set_justify (GTK_LABEL (edit_type_lb), GTK_JUSTIFY_CENTER);
    
    edit_key_lb = gtk_label_new ("Key");
    gtk_widget_set_name (edit_key_lb, "edit_key_lb");
    gtk_widget_show (edit_key_lb);
    gtk_table_attach (GTK_TABLE (edit_tb), edit_key_lb, 1, 2, 0, 1,
    	    (GtkAttachOptions) (GTK_FILL),
    	    (GtkAttachOptions) (0), 0, 0);
    gtk_label_set_justify (GTK_LABEL (edit_key_lb), GTK_JUSTIFY_CENTER);
    
    edit_ssid_lb = gtk_label_new ("SSID");
    gtk_widget_set_name (edit_ssid_lb, "edit_ssid_lb");
    /* XXX - Decomment only when WPA and WPA2 will be ready */
    /* gtk_widget_show (edit_ssid_lb); */
    gtk_table_attach (GTK_TABLE (edit_tb), edit_ssid_lb, 2, 3, 0, 1,
    	    (GtkAttachOptions) (GTK_FILL),
    	    (GtkAttachOptions) (0), 0, 0);
    gtk_label_set_justify (GTK_LABEL (edit_ssid_lb), GTK_JUSTIFY_CENTER);
    
    low_h_button_box = gtk_hbutton_box_new ();
    gtk_widget_set_name (low_h_button_box, "low_h_button_box");
     gtk_container_set_border_width (GTK_CONTAINER (low_h_button_box), 5);
    gtk_widget_show (low_h_button_box);
    gtk_box_pack_end (GTK_BOX (main_v_box), low_h_button_box, FALSE, FALSE, 0);
    gtk_button_box_set_layout (GTK_BUTTON_BOX (low_h_button_box),
    		     GTK_BUTTONBOX_END);
    
    #if GTK_MAJOR_VERISON >= 2
    ok_bt = gtk_button_new_with_mnemonic ("Ok");
    #else
    ok_bt = gtk_button_new_with_label ("Ok");
    #endif
    gtk_widget_set_name (ok_bt, "ok_bt");
    gtk_widget_show (ok_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), ok_bt);
    GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);
    
    #if GTK_MAJOR_VERISON >= 2
    cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
    #else
    cancel_bt = gtk_button_new_with_label ("Cancel");
    #endif
    gtk_widget_set_name (cancel_bt, "cancel_bt");
    gtk_widget_show (cancel_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), cancel_bt);
    GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);
    
    edit_frame_lb = gtk_label_new ("<b>Modify Selected Key</b>");
    gtk_widget_set_name (edit_frame_lb, "edit_frame_lb");
    gtk_widget_show (edit_frame_lb);
    #if GTK_MAJOR_VERSION >= 2
    gtk_frame_set_label_widget (GTK_FRAME (edit_frame), edit_frame_lb);
    gtk_label_set_use_markup (GTK_LABEL (edit_frame_lb), TRUE);
    #else
    gtk_frame_set_label (GTK_FRAME (edit_frame), "Modify Selected Key");
    #endif
    
    /* Add callbacks */
    SIGNAL_CONNECT(ok_bt, "clicked", on_edit_key_ok_bt_clicked, edit_key_window );
    SIGNAL_CONNECT(cancel_bt, "clicked", window_cancel_button_cb, edit_key_window );
    SIGNAL_CONNECT(edit_type_en, "changed",on_edit_type_en_changed, edit_key_window);
    SIGNAL_CONNECT(edit_key_window, "delete_event",window_delete_event_cb, edit_key_window);
    SIGNAL_CONNECT(edit_key_window, "destroy",on_edit_key_w_destroy, data);
    
    /* Add widget data */
    OBJECT_SET_DATA(edit_key_window,AIRPCAP_ADVANCED_EDIT_KEY_LIST_KEY,key_ls);
    OBJECT_SET_DATA(edit_key_window,AIRPCAP_ADVANCED_EDIT_KEY_SELECTED_KEY,selected_item);
    OBJECT_SET_DATA(edit_key_window,AIRPCAP_ADVANCED_EDIT_KEY_TYPE_KEY,edit_type_cm);
    OBJECT_SET_DATA(edit_key_window,AIRPCAP_ADVANCED_EDIT_KEY_KEY_KEY,edit_key_te);
    OBJECT_SET_DATA(edit_key_window,AIRPCAP_ADVANCED_EDIT_KEY_SSID_KEY,edit_ssid_te);
    
    gtk_widget_show(edit_key_window);
    }
}

/*
 * Callback for the 'Move Key Up' button.
 */
void
on_move_key_up_bt_clicked(GtkWidget *button, gpointer data _U_)
{
GtkWidget *airpcap_advanced_w;
GtkWidget *key_ls;
GList *new_list = NULL;
GList *item = NULL;

gint keys_in_list;

airpcap_key_ls_selected_info_t *selected_item;

gint c = NO_COLUMN_SELECTED;
gint r = NO_ROW_SELECTED;

airpcap_advanced_w = GTK_WIDGET(data);

/* retrieve needed stuff */
key_ls        = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEYLIST_KEY);
selected_item = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);

/* 
 * Better to store the selected_item data in two new variables, because maybe some 
 * select_row signal will be emitted somewhere...
 */
r = selected_item->row;
c = selected_item->column;

keys_in_list = GTK_CLIST(key_ls)->rows;

if(keys_in_list < 2) /* With less than 2 keys, nothing can be moved ... */
    return;

if( r == 0 ) /* Cannot move up the first row */
    return;

/* Move up selected key */
gtk_clist_swap_rows (GTK_CLIST(key_ls),r-1,r);

/* 
 * Re-select the just moved key... so the user can keep pressing 'Move Key Up'
 * without re-select the row...
 */
gtk_clist_select_row (GTK_CLIST(key_ls),r-1,c);

/* Need to save config... */
airpcap_if_selected->saved = FALSE;
}

/*
 * Callback for the 'Move Key Down' button.
 */
void
on_move_key_down_bt_clicked(GtkWidget *button, gpointer data _U_)
{
GtkWidget *airpcap_advanced_w;
GtkWidget *key_ls;
GList *new_list = NULL;
GList *item = NULL;

gint keys_in_list;

airpcap_key_ls_selected_info_t *selected_item;

gint c = NO_COLUMN_SELECTED;
gint r = NO_ROW_SELECTED;

airpcap_advanced_w = GTK_WIDGET(data);

/* retrieve needed stuff */
key_ls        = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEYLIST_KEY);
selected_item = OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY);

/* 
 * Better to store the selected_item data in two new variables, because maybe some 
 * select_row signal will be emitted somewhere...
 */
r = selected_item->row;
c = selected_item->column;

keys_in_list = GTK_CLIST(key_ls)->rows;

if(keys_in_list < 2) /* With less than 2 keys, nothing can be moved ... */
    return;

if( (r+1) == keys_in_list ) /* Cannot move down the last row */
    return;

/* Move down selected key */
gtk_clist_swap_rows (GTK_CLIST(key_ls),r,r+1);

/* 
 * Re-select the just moved key... so the user can keep pressing 'Move Key Down'
 * without re-select the row...
 */
gtk_clist_select_row (GTK_CLIST(key_ls),r+1,c);

/* Need to save config... */
airpcap_if_selected->saved = FALSE;
}

/* Turns the decryption on or off */
void
on_enable_decryption_en_changed(GtkWidget *w, gpointer data)
{
GtkEntry *decryption_en;

char* decryption_mode_string = NULL;

decryption_en = GTK_ENTRY(w);

if(g_strcasecmp(gtk_entry_get_text(decryption_en),AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK) == 0)
    {
    set_wireshark_decryption(TRUE);
    if(!set_airpcap_decryption(FALSE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }
else if(g_strcasecmp(gtk_entry_get_text(decryption_en),AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP) == 0)
    {
    set_wireshark_decryption(FALSE);
    if(!set_airpcap_decryption(TRUE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }
else if(g_strcasecmp(gtk_entry_get_text(decryption_en),AIRPCAP_DECRYPTION_TYPE_STRING_NONE) == 0)
    {
    set_wireshark_decryption(FALSE);
    if(!set_airpcap_decryption(FALSE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }

/* Redissect all the packets, and re-evaluate the display filter. */
cf_redissect_packets(&cfile);
}

/*
 * Will fill the given combo box with the current decryption mode string
 */
void
update_decryption_mode_cm(GtkWidget *w)
{

/* Wireshark decryption is on */                       
if(wireshark_decryption_on())
    {
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(w)->entry),AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK);
    /* We don't know if AirPcap decryption is on or off, but we just turn it off */
    if(!set_airpcap_decryption(FALSE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }
/* AirPcap decryption is on */
else if(airpcap_decryption_on())
    {
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(w)->entry),AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP);
    }
/* No decryption enabled */
else
    {
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(w)->entry),AIRPCAP_DECRYPTION_TYPE_STRING_NONE);
    }
return;
}

/* Called to create the airpcap settings' window */
void
display_airpcap_advanced_cb(GtkWidget *w, gpointer data)
{
GtkWidget *airpcap_advanced_w;
GtkWidget *main_box;
GtkWidget *settings_sub_box;
GtkWidget *interface_fr;
GtkWidget *interface_al;
GtkWidget *interface_sub_h_box;
GtkWidget *interface_name_lb;
GtkWidget *blink_bt;
GtkWidget *interface_frame_lb;
GtkWidget *basic_parameters_fr;
GtkWidget *basic_parameters_al;
GtkWidget *basic_parameters_tb;
GtkWidget *channel_lb;
GtkWidget *capture_type_lb;
GtkWidget *channel_cm;
GList *channel_cm_items = NULL;
GtkWidget *channel_en;
GtkWidget *capture_type_cm;
GList *capture_type_cm_items = NULL;
GtkWidget *capture_type_en;
GtkWidget *fcs_ck;
GtkWidget *basic_parameters_fcs_h_box;
GtkWidget *basic_parameters_fcs_filter_lb;
GtkWidget *fcs_filter_cm;
GList *fcs_filter_cm_items = NULL;
GtkWidget *fcs_filter_en;
GtkWidget *basic_parameters_frame_lb;
GtkWidget *low_buttons_h_box;
GtkWidget *left_h_button_box;
GtkWidget *reset_configuration_bt;
GtkWidget *right_h_button_box;
GtkWidget *ok_bt;
GtkWidget *apply_bt;
GtkWidget *cancel_bt;

/* widgets in the toolbar */
GtkWidget	*toolbar,
			*toolbar_if_lb,
			*toolbar_channel_cm,
			*toolbar_wrong_crc_cm;

/* other stuff */
/*GList				*channel_list,*capture_list;*/
GList				*linktype_list = NULL;
gchar				*capture_s;

/* user data - RETRIEVE pointers of toolbar widgets */
toolbar				= GTK_WIDGET(data);
toolbar_if_lb		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
toolbar_channel_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
toolbar_wrong_crc_cm= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_FCS_FILTER_KEY));

/* gray out the toolbar */
gtk_widget_set_sensitive(toolbar,FALSE);

/* main window */
/* global */

/* NULL to global widgets */
block_advanced_signals = FALSE;

/* the selected is the active, for now */
airpcap_if_selected = airpcap_if_active;

/* Create the new window */
airpcap_advanced_w = window_new(GTK_WINDOW_TOPLEVEL, "Advanced Wireless Settings");

gtk_container_set_border_width (GTK_CONTAINER (airpcap_advanced_w), 5);
gtk_window_set_title (GTK_WINDOW (airpcap_advanced_w),
		"Advanced Wireless Settings");
gtk_window_set_position (GTK_WINDOW (airpcap_advanced_w),
		   GTK_WIN_POS_CENTER);
		   
#if GTK_MAJOR_VERSION >= 2
gtk_window_set_resizable (GTK_WINDOW (airpcap_advanced_w), FALSE);
gtk_window_set_type_hint (GTK_WINDOW (airpcap_advanced_w), GDK_WINDOW_TYPE_HINT_DIALOG);
#else
gtk_window_set_policy(GTK_WINDOW(airpcap_advanced_w), FALSE, FALSE, TRUE);
#endif

main_box = gtk_vbox_new (FALSE, 0);
gtk_widget_set_name (main_box, "main_box");
gtk_widget_show (main_box);
gtk_container_add (GTK_CONTAINER (airpcap_advanced_w), main_box);

settings_sub_box = gtk_vbox_new (FALSE, 0);
gtk_widget_set_name (settings_sub_box, "settings_sub_box");
gtk_widget_show (settings_sub_box);
gtk_box_pack_start (GTK_BOX (main_box), settings_sub_box, FALSE, TRUE, 0);

interface_fr = gtk_frame_new (NULL);
gtk_widget_set_name (interface_fr, "interface_fr");
gtk_widget_show (interface_fr);
gtk_box_pack_start (GTK_BOX (settings_sub_box), interface_fr, FALSE, FALSE,
	      0);
gtk_container_set_border_width (GTK_CONTAINER (interface_fr), 10);

interface_al = gtk_alignment_new (0.5, 0.5, 1, 1);
gtk_widget_set_name (interface_al, "interface_al");
gtk_widget_show (interface_al);
gtk_container_add (GTK_CONTAINER (interface_fr), interface_al);
#if GTK_MAJOR_VERSION >= 2
gtk_alignment_set_padding (GTK_ALIGNMENT (interface_al), 5, 5, 0, 0);
#else
gtk_alignment_set (GTK_ALIGNMENT (interface_al), 5, 5, 0, 0);
#endif

interface_sub_h_box = gtk_hbox_new (FALSE, 0);
gtk_widget_set_name (interface_sub_h_box, "interface_sub_h_box");
gtk_widget_show (interface_sub_h_box);
gtk_container_add (GTK_CONTAINER (interface_al), interface_sub_h_box);
gtk_container_set_border_width (GTK_CONTAINER (interface_sub_h_box), 5);

/* Fill the interface_box */
if(airpcap_if_active != NULL)
	{
	interface_name_lb = gtk_label_new(airpcap_if_active->description);
	}
else
	{
	interface_name_lb = gtk_label_new("No airpcap interface found!");
	gtk_widget_set_sensitive(main_box,FALSE);
	}
	
gtk_widget_set_name (interface_name_lb, "interface_name_lb");
gtk_widget_show (interface_name_lb);
gtk_box_pack_start (GTK_BOX (interface_sub_h_box), interface_name_lb, TRUE,
	      FALSE, 0);

/* If it is NOT the 'Any' Interface */
if(!airpcap_if_is_any(airpcap_if_selected))
	{
	#if GTK_MAJOR_VERSION >= 2
	blink_bt = gtk_button_new_with_mnemonic ("Blink Led");
	#else
	blink_bt = gtk_button_new_with_label("Blink Led");
	#endif
	}
else /* It is the any interface, so it doesn't make sense to have 'Blink' button... */
	{
	#if GTK_MAJOR_VERSION >= 2
	blink_bt = gtk_button_new_with_mnemonic ("What's This?");
	#else
	blink_bt = gtk_button_new_with_label("What's This?");
	#endif
	}
gtk_widget_set_name (blink_bt, "blink_bt");
gtk_widget_show (blink_bt);
gtk_box_pack_end (GTK_BOX (interface_sub_h_box), blink_bt, FALSE, FALSE, 0);

interface_frame_lb = gtk_label_new ("<b>Interface</b>");
gtk_widget_set_name (interface_frame_lb, "interface_frame_lb");
gtk_widget_show (interface_frame_lb);
#if GTK_MAJOR_VERSION >= 2
gtk_frame_set_label_widget (GTK_FRAME (interface_fr), interface_frame_lb);
gtk_label_set_use_markup (GTK_LABEL (interface_frame_lb), TRUE);
#else
gtk_frame_set_label(GTK_FRAME(interface_fr),"Interface");
#endif  

basic_parameters_fr = gtk_frame_new (NULL);
gtk_widget_set_name (basic_parameters_fr, "basic_parameters_fr");
gtk_widget_show (basic_parameters_fr);
gtk_box_pack_start (GTK_BOX (settings_sub_box), basic_parameters_fr, TRUE,FALSE, 0);
gtk_container_set_border_width (GTK_CONTAINER (basic_parameters_fr), 10);

basic_parameters_al = gtk_alignment_new (0.5, 0.5, 1, 1);
gtk_widget_set_name (basic_parameters_al, "basic_parameters_al");
gtk_widget_show (basic_parameters_al);
gtk_container_add (GTK_CONTAINER (basic_parameters_fr),basic_parameters_al);
#if GTK_MAJOR_VERSION >= 2
gtk_alignment_set_padding (GTK_ALIGNMENT (basic_parameters_al), 10, 10, 0, 0);
#else
gtk_alignment_set (GTK_ALIGNMENT (basic_parameters_al), 10, 10, 0, 0);
#endif

basic_parameters_tb = gtk_table_new (2, 3, FALSE);
gtk_widget_set_name (basic_parameters_tb, "basic_parameters_tb");
gtk_widget_show (basic_parameters_tb);
gtk_container_add (GTK_CONTAINER (basic_parameters_al),
	     basic_parameters_tb);
gtk_container_set_border_width (GTK_CONTAINER (basic_parameters_tb), 5);
gtk_table_set_col_spacings (GTK_TABLE (basic_parameters_tb), 20);

channel_lb = gtk_label_new ("Channel:");
gtk_widget_set_name (channel_lb, "channel_lb");
gtk_widget_show (channel_lb);
gtk_table_attach (GTK_TABLE (basic_parameters_tb), channel_lb, 0, 1, 0, 1,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_misc_set_alignment (GTK_MISC (channel_lb), 0, 0.5);

capture_type_lb = gtk_label_new ("Capture Type:");
gtk_widget_set_name (capture_type_lb, "capture_type_lb");
gtk_widget_show (capture_type_lb);
gtk_table_attach (GTK_TABLE (basic_parameters_tb), capture_type_lb, 0, 1, 1,
	    2, (GtkAttachOptions) (GTK_FILL), (GtkAttachOptions) (0),
	    0, 0);
gtk_misc_set_alignment (GTK_MISC (capture_type_lb), 0, 0.5);

channel_cm = gtk_combo_new ();
gtk_widget_set_name (channel_cm, "channel_cm");
gtk_widget_show (channel_cm);
gtk_table_attach (GTK_TABLE (basic_parameters_tb), channel_cm, 1, 2, 0, 1,
	    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "1");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "2");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "3");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "4");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "5");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "6");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "7");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "8");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "9");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "10");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "11");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "12");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "13");
channel_cm_items = g_list_append (channel_cm_items, (gpointer) "14");
gtk_combo_set_popdown_strings (GTK_COMBO (channel_cm), channel_cm_items);

  /* Select the first entry */
if(airpcap_if_selected != NULL)
	{
	airpcap_update_channel_combo(GTK_WIDGET(channel_cm), airpcap_if_selected);
	}
	
g_list_free (channel_cm_items);

channel_en = GTK_COMBO (channel_cm)->entry;
gtk_editable_set_editable(GTK_EDITABLE(channel_en),FALSE);
gtk_widget_set_name (channel_en, "channel_en");
gtk_widget_show (channel_en);

capture_type_cm = gtk_combo_new ();
gtk_widget_set_name (capture_type_cm, "capture_type_cm");
gtk_widget_show (capture_type_cm);
gtk_table_attach (GTK_TABLE (basic_parameters_tb), capture_type_cm, 1, 2, 1,
	    2, (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
capture_type_cm_items =
g_list_append (capture_type_cm_items, (gpointer) AIRPCAP_LINK_TYPE_NAME_802_11_ONLY);
capture_type_cm_items =
g_list_append (capture_type_cm_items, (gpointer) AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO);
gtk_combo_set_popdown_strings (GTK_COMBO (capture_type_cm),
			 capture_type_cm_items);
			 
/* Current interface value */
capture_s = NULL;
if(airpcap_if_selected != NULL)
	{
	if(airpcap_if_selected->linkType == AIRPCAP_LT_802_11)
		capture_s = g_strdup_printf("%s",AIRPCAP_LINK_TYPE_NAME_802_11_ONLY);
	else if(airpcap_if_selected->linkType == AIRPCAP_LT_802_11_PLUS_RADIO)
		capture_s = g_strdup_printf("%s",AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO);	
	if(capture_s != NULL) gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(capture_type_cm)->entry), capture_s);
	}
g_free(capture_s);

g_list_free (capture_type_cm_items);

capture_type_en = GTK_COMBO (capture_type_cm)->entry;
gtk_widget_set_name (capture_type_en, "capture_type_en");
gtk_widget_show (capture_type_en);

#if GTK_VERSION >= 2
fcs_ck = gtk_check_button_new_with_mnemonic ("Include 802.11 FCS in Frames");
#else
fcs_ck = gtk_check_button_new_with_label ("Include 802.11 FCS in Frames");
#endif
gtk_widget_set_name (fcs_ck, "fcs_ck");

/* Fcs Presence check box */
if(airpcap_if_selected != NULL)
	{
	if(airpcap_if_selected->IsFcsPresent)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fcs_ck),TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fcs_ck),FALSE);
	}
	
gtk_widget_show (fcs_ck);
gtk_table_attach (GTK_TABLE (basic_parameters_tb), fcs_ck, 2, 3, 0, 1,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);

basic_parameters_fcs_h_box = gtk_hbox_new (FALSE, 1);
gtk_widget_set_name (basic_parameters_fcs_h_box,
	       "basic_parameters_fcs_h_box");
gtk_widget_show (basic_parameters_fcs_h_box);
gtk_table_attach (GTK_TABLE (basic_parameters_tb),
	    basic_parameters_fcs_h_box, 2, 3, 1, 2,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (GTK_FILL), 3, 0);

basic_parameters_fcs_filter_lb = gtk_label_new ("FCS Filter:");
gtk_widget_set_name (basic_parameters_fcs_filter_lb,
	       "basic_parameters_fcs_filter_lb");
gtk_widget_show (basic_parameters_fcs_filter_lb);
gtk_box_pack_start (GTK_BOX (basic_parameters_fcs_h_box),
	      basic_parameters_fcs_filter_lb, FALSE, FALSE, 0);

fcs_filter_cm = gtk_combo_new ();
gtk_widget_set_name (fcs_filter_cm, "fcs_filter_cm");
gtk_widget_show (fcs_filter_cm);
gtk_box_pack_start (GTK_BOX (basic_parameters_fcs_h_box), fcs_filter_cm,
	      FALSE, FALSE, 0);
#if GTK_MAJOR_VERSION >= 2
gtk_widget_set_size_request (fcs_filter_cm, 112, -1);
#else
gtk_widget_set_usize (fcs_filter_cm, 112, -1);
#endif
fcs_filter_cm_items =
g_list_append (fcs_filter_cm_items, (gpointer) "All Frames");
fcs_filter_cm_items =
g_list_append (fcs_filter_cm_items, (gpointer) "Valid Frames");
fcs_filter_cm_items =
g_list_append (fcs_filter_cm_items, (gpointer) "Invalid Frames");
gtk_combo_set_popdown_strings (GTK_COMBO (fcs_filter_cm),
			 fcs_filter_cm_items);
g_list_free (fcs_filter_cm_items);

fcs_filter_en = GTK_COMBO (fcs_filter_cm)->entry;
gtk_widget_set_name (fcs_filter_en, "fcs_filter_en");

if(airpcap_if_selected != NULL)
	{
	airpcap_validation_type_combo_set_by_type(fcs_filter_cm,airpcap_if_selected->CrcValidationOn);
	}
	
gtk_widget_show (fcs_filter_en);

basic_parameters_frame_lb = gtk_label_new ("<b>Basic Parameters</b>");
gtk_widget_set_name (basic_parameters_frame_lb,
	       "basic_parameters_frame_lb");
gtk_widget_show (basic_parameters_frame_lb);

#if GTK_MAJOR_VERSION >= 2
gtk_frame_set_label_widget (GTK_FRAME (basic_parameters_fr),basic_parameters_frame_lb);
gtk_label_set_use_markup (GTK_LABEL (basic_parameters_frame_lb), TRUE);
#else
gtk_frame_set_label(GTK_FRAME (basic_parameters_fr),"Basic Parameters");
#endif

low_buttons_h_box = gtk_hbox_new (FALSE, 0);
gtk_widget_set_name (low_buttons_h_box, "low_buttons_h_box");
gtk_widget_show (low_buttons_h_box);
gtk_box_pack_end (GTK_BOX (main_box), low_buttons_h_box, FALSE, FALSE, 0);

left_h_button_box = gtk_hbutton_box_new ();
gtk_widget_set_name (left_h_button_box, "left_h_button_box");
gtk_widget_show (left_h_button_box);
gtk_box_pack_start (GTK_BOX (low_buttons_h_box), left_h_button_box, FALSE,
	      FALSE, 0);

#if GTK_MAJOR_VERSION >= 2
reset_configuration_bt = gtk_button_new_with_mnemonic ("Reset Configuration");
#else
reset_configuration_bt = gtk_button_new_with_label ("Reset Configuration");
#endif
gtk_widget_set_name (reset_configuration_bt, "reset_configuration_bt");
/* gtk_widget_show (reset_configuration_bt); */
gtk_container_add (GTK_CONTAINER (left_h_button_box),
	     reset_configuration_bt);
GTK_WIDGET_SET_FLAGS (reset_configuration_bt, GTK_CAN_DEFAULT);

right_h_button_box = gtk_hbutton_box_new ();
gtk_widget_set_name (right_h_button_box, "right_h_button_box");
gtk_widget_show (right_h_button_box);
gtk_box_pack_end (GTK_BOX (low_buttons_h_box), right_h_button_box, FALSE,
	    FALSE, 0);
gtk_button_box_set_layout (GTK_BUTTON_BOX (right_h_button_box),
		     GTK_BUTTONBOX_END);

#if GTK_MAJOR_VERSION >= 2
ok_bt = gtk_button_new_with_mnemonic ("Ok");
#else
ok_bt = gtk_button_new_with_label ("Ok");
#endif
gtk_widget_set_name (ok_bt, "ok_bt");
gtk_widget_show (ok_bt);
gtk_container_add (GTK_CONTAINER (right_h_button_box), ok_bt);
GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
apply_bt = gtk_button_new_with_mnemonic ("Apply");
#else
apply_bt = gtk_button_new_with_label ("Apply");
#endif
gtk_widget_set_name (apply_bt, "apply_bt");
gtk_widget_show (apply_bt);
gtk_container_add (GTK_CONTAINER (right_h_button_box), apply_bt);
GTK_WIDGET_SET_FLAGS (apply_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
#else
cancel_bt = gtk_button_new_with_label ("Cancel");
#endif
gtk_widget_set_name (cancel_bt, "cancel_bt");
gtk_widget_show (cancel_bt);
gtk_container_add (GTK_CONTAINER (right_h_button_box), cancel_bt);
GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);

/* Connect the callbacks */
SIGNAL_CONNECT (airpcap_advanced_w, "delete_event", window_delete_event_cb, airpcap_advanced_w);
SIGNAL_CONNECT (airpcap_advanced_w, "destroy", on_airpcap_advanced_destroy, airpcap_advanced_w);

if(!airpcap_if_is_any(airpcap_if_selected))
{
SIGNAL_CONNECT (blink_bt, "clicked", on_blink_bt_clicked, airpcap_advanced_w);
}
else
{
SIGNAL_CONNECT (blink_bt, "clicked", on_what_s_this_bt_clicked, airpcap_advanced_w);
}

SIGNAL_CONNECT (channel_en, "changed",on_channel_en_changed, airpcap_advanced_w);
SIGNAL_CONNECT (capture_type_en, "changed",on_capture_type_en_changed, airpcap_advanced_w);
SIGNAL_CONNECT (fcs_ck, "toggled",on_fcs_ck_toggled, airpcap_advanced_w);
SIGNAL_CONNECT (fcs_filter_en, "changed",on_fcs_filter_en_changed, airpcap_advanced_w);
SIGNAL_CONNECT (reset_configuration_bt, "clicked",on_reset_configuration_bt_clicked, airpcap_advanced_w);
SIGNAL_CONNECT (apply_bt, "clicked",on_advanced_apply_bt_clicked, airpcap_advanced_w);
SIGNAL_CONNECT (ok_bt,"clicked",on_advanced_ok_bt_clicked,airpcap_advanced_w);
SIGNAL_CONNECT (cancel_bt,"clicked",on_advanced_cancel_bt_clicked,airpcap_advanced_w);

/* Different because the window will be closed ... */
/*window_set_cancel_button(airpcap_advanced_w, ok_bt, window_cancel_button_cb);
window_set_cancel_button(airpcap_advanced_w, cancel_bt, window_cancel_button_cb);*/


/* Store pointers to all widgets, for use by lookup_widget(). */
OBJECT_SET_DATA (airpcap_advanced_w, AIRPCAP_ADVANCED_BLINK_KEY, blink_bt);
OBJECT_SET_DATA (airpcap_advanced_w, AIRPCAP_ADVANCED_CHANNEL_KEY,channel_cm);
OBJECT_SET_DATA (airpcap_advanced_w, AIRPCAP_ADVANCED_LINK_TYPE_KEY,capture_type_cm);
OBJECT_SET_DATA (airpcap_advanced_w, AIRPCAP_ADVANCED_FCS_CHECK_KEY, fcs_ck);
OBJECT_SET_DATA (airpcap_advanced_w, AIRPCAP_ADVANCED_FCS_FILTER_KEY, fcs_filter_cm);
OBJECT_SET_DATA (airpcap_advanced_w, AIRPCAP_ADVANCED_OK_KEY, ok_bt);
OBJECT_SET_DATA (airpcap_advanced_w, AIRPCAP_ADVANCED_CANCEL_KEY, cancel_bt);

/*
 * I will need the toolbar and the main widget in some callback,
 * so I will add the toolbar pointer to the airpcap_advanced_w
 */
OBJECT_SET_DATA(airpcap_advanced_w,AIRPCAP_TOOLBAR_KEY,toolbar);

/* At the end, so that it appears completely all together ... */
gtk_widget_show (airpcap_advanced_w);
}

/*
 * Callback for the OK button 'clicked' in the Advanced Wireless Settings window.
 */
void
on_advanced_ok_bt_clicked(GtkWidget *button, gpointer data _U_)
{
PAirpcapHandle ad = NULL;
gchar ebuf[AIRPCAP_ERRBUF_SIZE];

/* Retrieve object data */
GtkWidget *airpcap_advanced_w;
GtkWidget *channel_combo;
GtkWidget *capture_combo;
GtkWidget *crc_check;
GtkWidget *wrong_crc_combo;
GtkWidget *blink_bt;
GtkWidget *interface_combo;
GtkWidget *cancel_bt;
GtkWidget *ok_bt;

/* widgets in the toolbar */
GtkWidget	*toolbar,
			*toolbar_if_lb,
			*toolbar_channel_cm,
			*toolbar_wrong_crc_cm,
			*advanced_bt;

/* Retrieve the GUI object pointers */
airpcap_advanced_w  = GTK_WIDGET(data);
interface_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_INTERFACE_KEY));
channel_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_CHANNEL_KEY));
capture_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_LINK_TYPE_KEY));
crc_check			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_FCS_CHECK_KEY));
wrong_crc_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_FCS_FILTER_KEY));
blink_bt			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_BLINK_KEY));
cancel_bt			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_CANCEL_KEY));
ok_bt				= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_OK_KEY));
advanced_bt			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEY));

toolbar					= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_TOOLBAR_KEY));

/* retrieve toolbar info */
toolbar_if_lb			= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
toolbar_channel_cm		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
toolbar_wrong_crc_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_FCS_FILTER_KEY));

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

/* ??? - Ask if want to save configuration */

/* Save the configuration */
airpcap_save_selected_if_configuration(airpcap_if_selected);
/* Remove gtk timeout */
gtk_timeout_remove(airpcap_if_selected->tag);

/* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
if( g_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
	{
    gtk_label_set_text(GTK_LABEL(toolbar_if_lb), g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_selected)));
	
	airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cm),airpcap_if_selected);
	
    airpcap_validation_type_combo_set_by_type(toolbar_wrong_crc_cm,airpcap_if_selected->CrcValidationOn);
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

gtk_widget_destroy(airpcap_advanced_w);
}

/*
 * Callback for the CANCEL button 'clicked' in the Advanced Wireless Settings window.
 */
void
on_advanced_cancel_bt_clicked(GtkWidget *button, gpointer data _U_)
{
PAirpcapHandle ad = NULL;
gchar ebuf[AIRPCAP_ERRBUF_SIZE];

/* Retrieve object data */
GtkWidget *airpcap_advanced_w;
GtkWidget *channel_combo;
GtkWidget *capture_combo;
GtkWidget *crc_check;
GtkWidget *wrong_crc_combo;
GtkWidget *blink_bt;
GtkWidget *interface_combo;
GtkWidget *cancel_bt;
GtkWidget *ok_bt;

/* widgets in the toolbar */
GtkWidget	*toolbar,
			*toolbar_if_lb,
			*toolbar_channel_cm,
			*toolbar_wrong_crc_cm,
			*advanced_bt;

/* Retrieve the GUI object pointers */
airpcap_advanced_w  = GTK_WIDGET(data);
interface_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_INTERFACE_KEY));
channel_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_CHANNEL_KEY));
capture_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_LINK_TYPE_KEY));
crc_check			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_FCS_CHECK_KEY));
wrong_crc_combo		= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_FCS_FILTER_KEY));
blink_bt			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_BLINK_KEY));
cancel_bt			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_CANCEL_KEY));
ok_bt				= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_OK_KEY));
advanced_bt			= GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_ADVANCED_KEY));

toolbar = GTK_WIDGET(OBJECT_GET_DATA(airpcap_advanced_w,AIRPCAP_TOOLBAR_KEY));

/* retrieve toolbar info */
toolbar_if_lb			= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_INTERFACE_KEY));
toolbar_channel_cm		= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_CHANNEL_KEY));
toolbar_wrong_crc_cm	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_FCS_FILTER_KEY));

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

/* reload the configuration!!! Configuration has not been saved but
	the corresponding structure has been modified probably...*/
if(!airpcap_if_selected->saved)
	{
	airpcap_load_selected_if_configuration(airpcap_if_selected);
	}

gtk_widget_destroy(airpcap_advanced_w);
}

/* Called to create the key management window */
void
display_airpcap_key_management_cb(GtkWidget *w, gpointer data)
{
GtkWidget *key_management_w;
GtkWidget *main_box;
GtkWidget *keys_fr;
GtkWidget *keys_al;
GtkWidget *keys_h_sub_box;
GtkWidget *enable_decryption_tb;
GtkWidget *enable_decryption_lb;
GtkWidget *enable_decryption_cb;
GList     *enable_decryption_cb_items = NULL;
GtkWidget *enable_decryption_en;
GtkWidget *keys_v_sub_box;
GtkWidget *keys_scrolled_w;
GtkWidget *key_ls;
GtkWidget *key_list_decryption_type_col_lb;
GtkWidget *key_list_decryption_key_col_lb;
GtkWidget *key_ls_decryption_ssid_col_lb;
GtkWidget *key_v_button_box;
GtkWidget *add_new_key_bt;
GtkWidget *remove_key_bt;
GtkWidget *edit_key_bt;
GtkWidget *move_key_up_bt;
GtkWidget *move_key_down_bt;
GtkWidget *keys_frame_lb;
GtkWidget *low_buttons_h_box;
GtkWidget *left_h_button_box;
GtkWidget *reset_configuration_bt;
GtkWidget *right_h_button_box;
GtkWidget *ok_bt;
GtkWidget *apply_bt;
GtkWidget *cancel_bt;
  
/* widgets in the toolbar */
GtkWidget	*toolbar,
			*toolbar_decryption_ck;

/* other stuff */
/*GList				*channel_list,*capture_list;*/
GList				*linktype_list = NULL;
	
/* Selected row/column structure */
airpcap_key_ls_selected_info_t *key_ls_selected_item;
key_ls_selected_item = (airpcap_key_ls_selected_info_t*)g_malloc(sizeof(airpcap_key_ls_selected_info_t));
key_ls_selected_item->row = NO_ROW_SELECTED;
key_ls_selected_item->column = NO_COLUMN_SELECTED;

/* user data - RETRIEVE pointers of toolbar widgets */
toolbar				  = GTK_WIDGET(data);
toolbar_decryption_ck = GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_DECRYPTION_KEY));

/* gray out the toolbar */
gtk_widget_set_sensitive(toolbar,FALSE);

/* main window */
/* global */

/* NULL to global widgets */
block_advanced_signals = FALSE;

/* the selected is the active, for now */
airpcap_if_selected = airpcap_if_active;

/* Create the new window */
key_management_w = window_new(GTK_WINDOW_TOPLEVEL, "Decryption Keys Management");

gtk_container_set_border_width (GTK_CONTAINER (key_management_w), 5);
gtk_window_set_title (GTK_WINDOW (key_management_w),
		"Decryption Keys Management");
gtk_window_set_position (GTK_WINDOW (key_management_w),
		   GTK_WIN_POS_CENTER);
			   
#if GTK_MAJOR_VERSION >= 2
gtk_window_set_resizable (GTK_WINDOW (key_management_w), FALSE);
gtk_window_set_type_hint (GTK_WINDOW (key_management_w), GDK_WINDOW_TYPE_HINT_DIALOG);
#else
gtk_window_set_policy(GTK_WINDOW(key_management_w), FALSE, FALSE, TRUE);
#endif

main_box = gtk_vbox_new (FALSE, 0);
gtk_widget_set_name (main_box, "main_box");
gtk_widget_show (main_box);
gtk_container_add (GTK_CONTAINER (key_management_w), main_box);

keys_fr = gtk_frame_new (NULL);
gtk_widget_set_name (keys_fr, "keys_fr");
gtk_widget_show (keys_fr);
gtk_box_pack_start (GTK_BOX (main_box), keys_fr, FALSE, FALSE, 0);
gtk_container_set_border_width (GTK_CONTAINER (keys_fr), 10);

keys_al = gtk_alignment_new (0.5, 0.5, 1, 1);
gtk_widget_set_name (keys_al, "keys_al");
gtk_widget_show (keys_al);
gtk_container_add (GTK_CONTAINER (keys_fr), keys_al);
gtk_container_set_border_width (GTK_CONTAINER (keys_al), 5);

#if GTK_MAJOR_VERSION >= 2
gtk_alignment_set_padding (GTK_ALIGNMENT (keys_al), 0, 0, 12, 0);
#else
gtk_alignment_set (GTK_ALIGNMENT (keys_al), 0, 0, 12, 0);
#endif

keys_h_sub_box = gtk_vbox_new (FALSE, 0);
gtk_widget_set_name (keys_h_sub_box, "keys_h_sub_box");
gtk_widget_show (keys_h_sub_box);
gtk_container_add (GTK_CONTAINER (keys_al), keys_h_sub_box);

enable_decryption_tb = gtk_table_new (1, 2, FALSE);
gtk_widget_set_name (enable_decryption_tb, "enable_decryption_tb");
gtk_widget_show (enable_decryption_tb);
gtk_box_pack_start (GTK_BOX (keys_h_sub_box), enable_decryption_tb, FALSE,
	      FALSE, 0);
gtk_table_set_col_spacings (GTK_TABLE (enable_decryption_tb), 6);

enable_decryption_lb = gtk_label_new ("Select Decryption Mode");
gtk_widget_set_name (enable_decryption_lb, "enable_decryption_lb");
gtk_widget_show (enable_decryption_lb);
gtk_table_attach (GTK_TABLE (enable_decryption_tb), enable_decryption_lb, 1,
	    2, 0, 1, (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_misc_set_alignment (GTK_MISC (enable_decryption_lb), 0, 0.5);

enable_decryption_cb = gtk_combo_new ();
gtk_widget_set_name (enable_decryption_cb, "enable_decryption_cb");
gtk_widget_show (enable_decryption_cb);
gtk_table_attach (GTK_TABLE (enable_decryption_tb), enable_decryption_cb, 0,
	    1, 0, 1, (GtkAttachOptions) (0), (GtkAttachOptions) (0),
	    0, 0);
#if GTK_MAJOR_VERSION >= 2
gtk_widget_set_size_request (enable_decryption_cb, 83, -1);
#else
gtk_widget_set_usize (enable_decryption_cb, 83, -1);
#endif
enable_decryption_cb_items = g_list_append (enable_decryption_cb_items, AIRPCAP_DECRYPTION_TYPE_STRING_NONE);
enable_decryption_cb_items = g_list_append (enable_decryption_cb_items, AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK);
enable_decryption_cb_items = g_list_append (enable_decryption_cb_items, AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP);
gtk_combo_set_popdown_strings (GTK_COMBO (enable_decryption_cb), enable_decryption_cb_items);
g_list_free (enable_decryption_cb_items);

enable_decryption_en = GTK_COMBO (enable_decryption_cb)->entry;
gtk_widget_set_name (enable_decryption_en, "enable_decryption_en");
gtk_widget_show (enable_decryption_en);
gtk_editable_set_editable (GTK_EDITABLE (enable_decryption_en), FALSE);
GTK_WIDGET_UNSET_FLAGS (enable_decryption_en, GTK_CAN_FOCUS);

/* Set correct decryption mode!!!! */
update_decryption_mode_cm(enable_decryption_cb);

keys_v_sub_box = gtk_hbox_new (FALSE, 0);
gtk_widget_set_name (keys_v_sub_box, "keys_v_sub_box");
gtk_widget_show (keys_v_sub_box);
gtk_box_pack_start (GTK_BOX (keys_h_sub_box), keys_v_sub_box, TRUE, TRUE, 0);

keys_scrolled_w = gtk_scrolled_window_new (NULL, NULL);
gtk_widget_set_name (keys_scrolled_w, "keys_scrolled_w");
gtk_widget_show (keys_scrolled_w);
gtk_box_pack_start (GTK_BOX (keys_v_sub_box), keys_scrolled_w, TRUE, TRUE,
	      0);
gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (keys_scrolled_w), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

key_ls = gtk_clist_new (3);
gtk_widget_set_name (key_ls, "key_ls");
gtk_widget_show (key_ls);

airpcap_fill_key_list(key_ls,airpcap_if_selected);

gtk_container_add (GTK_CONTAINER (keys_scrolled_w), key_ls);
gtk_clist_set_column_width (GTK_CLIST (key_ls), 0, 54);
gtk_clist_set_column_width (GTK_CLIST (key_ls), 1, 113);
gtk_clist_set_column_width (GTK_CLIST (key_ls), 2, 80);
gtk_clist_column_titles_show (GTK_CLIST (key_ls));
gtk_clist_set_shadow_type (GTK_CLIST (key_ls), GTK_SHADOW_ETCHED_IN);
gtk_clist_set_column_justification(GTK_CLIST (key_ls),0,GTK_JUSTIFY_CENTER);

key_list_decryption_type_col_lb = gtk_label_new ("Type");
gtk_widget_set_name (key_list_decryption_type_col_lb,
	       "key_list_decryption_type_col_lb");
gtk_widget_show (key_list_decryption_type_col_lb);
gtk_clist_set_column_widget (GTK_CLIST (key_ls), 0, key_list_decryption_type_col_lb);

key_list_decryption_key_col_lb = gtk_label_new ("Key");
gtk_widget_set_name (key_list_decryption_key_col_lb,
	       "key_list_decryption_key_col_lb");
gtk_widget_show (key_list_decryption_key_col_lb);
gtk_clist_set_column_widget (GTK_CLIST (key_ls), 1,
		       key_list_decryption_key_col_lb);

key_ls_decryption_ssid_col_lb = gtk_label_new ("SSID");
gtk_widget_set_name (key_ls_decryption_ssid_col_lb,
	       "key_ls_decryption_ssid_col_lb");
gtk_widget_show (key_ls_decryption_ssid_col_lb);
gtk_clist_set_column_widget (GTK_CLIST (key_ls), 2,
		       key_ls_decryption_ssid_col_lb);

/* XXX - USED ONLY BECAUSE WPA and WPA2 are note ready YET... */
gtk_clist_set_column_visibility(GTK_CLIST (key_ls), 2, FALSE);

key_v_button_box = gtk_vbutton_box_new ();
gtk_widget_set_name (key_v_button_box, "key_v_button_box");
gtk_widget_show (key_v_button_box);
gtk_box_pack_start (GTK_BOX (keys_v_sub_box), key_v_button_box, FALSE, TRUE,
	      0);

#if GTK_MAJOR_VERSION >= 2
add_new_key_bt = gtk_button_new_with_mnemonic ("Add New Key");
#else
add_new_key_bt = gtk_button_new_with_label ("Add New Key");
#endif
gtk_widget_set_name (add_new_key_bt, "add_new_key_bt");
gtk_widget_show (add_new_key_bt);
gtk_container_add (GTK_CONTAINER (key_v_button_box), add_new_key_bt);
GTK_WIDGET_SET_FLAGS (add_new_key_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
remove_key_bt = gtk_button_new_with_mnemonic ("Remove Key");
#else
remove_key_bt = gtk_button_new_with_label ("Remove Key");
#endif
gtk_widget_set_name (remove_key_bt, "remove_key_bt");
gtk_widget_show (remove_key_bt);
gtk_container_add (GTK_CONTAINER (key_v_button_box), remove_key_bt);
GTK_WIDGET_SET_FLAGS (remove_key_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
edit_key_bt = gtk_button_new_with_mnemonic ("Edit Key");
#else
edit_key_bt = gtk_button_new_with_label ("Edit Key");
#endif  
gtk_widget_set_name (edit_key_bt, "edit_key_bt");
gtk_widget_show (edit_key_bt);
gtk_container_add (GTK_CONTAINER (key_v_button_box), edit_key_bt);
GTK_WIDGET_SET_FLAGS (edit_key_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
move_key_up_bt = gtk_button_new_with_mnemonic ("Move Key Up");
#else
move_key_up_bt = gtk_button_new_with_label ("Move Key Up");
#endif
gtk_widget_set_name (move_key_up_bt, "move_key_up_bt");
gtk_widget_show (move_key_up_bt);
gtk_container_add (GTK_CONTAINER (key_v_button_box), move_key_up_bt);
GTK_WIDGET_SET_FLAGS (move_key_up_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
move_key_down_bt = gtk_button_new_with_mnemonic ("Move Key Down");
#else
move_key_down_bt = gtk_button_new_with_label ("Move Key Down");
#endif
gtk_widget_set_name (move_key_down_bt, "move_key_down_bt");
gtk_widget_show (move_key_down_bt);
gtk_container_add (GTK_CONTAINER (key_v_button_box), move_key_down_bt);
GTK_WIDGET_SET_FLAGS (move_key_down_bt, GTK_CAN_DEFAULT);

keys_frame_lb = gtk_label_new ("<b>Decryption Keys</b>");
gtk_widget_set_name (keys_frame_lb, "keys_frame_lb");
gtk_widget_show (keys_frame_lb);

#if GTK_MAJOR_VERSION >= 2
gtk_frame_set_label_widget (GTK_FRAME (keys_fr), keys_frame_lb);
gtk_label_set_use_markup (GTK_LABEL (keys_frame_lb), TRUE);
#else
gtk_frame_set_label (GTK_FRAME (keys_fr), "Decryption Keys");
#endif

low_buttons_h_box = gtk_hbox_new (FALSE, 0);
gtk_widget_set_name (low_buttons_h_box, "low_buttons_h_box");
gtk_widget_show (low_buttons_h_box);
gtk_box_pack_end (GTK_BOX (main_box), low_buttons_h_box, FALSE, FALSE, 0);

left_h_button_box = gtk_hbutton_box_new ();
gtk_widget_set_name (left_h_button_box, "left_h_button_box");
gtk_widget_show (left_h_button_box);
gtk_box_pack_start (GTK_BOX (low_buttons_h_box), left_h_button_box, FALSE,
	      FALSE, 0);

#if GTK_MAJOR_VERSION >= 2
reset_configuration_bt = gtk_button_new_with_mnemonic ("Reset Configuration");
#else
reset_configuration_bt = gtk_button_new_with_label ("Reset Configuration");
#endif
gtk_widget_set_name (reset_configuration_bt, "reset_configuration_bt");
/* gtk_widget_show (reset_configuration_bt); */
gtk_container_add (GTK_CONTAINER (left_h_button_box),
	     reset_configuration_bt);
GTK_WIDGET_SET_FLAGS (reset_configuration_bt, GTK_CAN_DEFAULT);

right_h_button_box = gtk_hbutton_box_new ();
gtk_widget_set_name (right_h_button_box, "right_h_button_box");
gtk_widget_show (right_h_button_box);
gtk_box_pack_end (GTK_BOX (low_buttons_h_box), right_h_button_box, FALSE,
	    FALSE, 0);
gtk_button_box_set_layout (GTK_BUTTON_BOX (right_h_button_box),
		     GTK_BUTTONBOX_END);

#if GTK_MAJOR_VERSION >= 2
ok_bt = gtk_button_new_with_mnemonic ("Ok");
#else
ok_bt = gtk_button_new_with_label ("Ok");
#endif
gtk_widget_set_name (ok_bt, "ok_bt");
gtk_widget_show (ok_bt);
gtk_container_add (GTK_CONTAINER (right_h_button_box), ok_bt);
GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
apply_bt = gtk_button_new_with_mnemonic ("Apply");
#else
apply_bt = gtk_button_new_with_label ("Apply");
#endif
gtk_widget_set_name (apply_bt, "apply_bt");
gtk_widget_show (apply_bt);
gtk_container_add (GTK_CONTAINER (right_h_button_box), apply_bt);
GTK_WIDGET_SET_FLAGS (apply_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
#else
cancel_bt = gtk_button_new_with_label ("Cancel");
#endif
gtk_widget_set_name (cancel_bt, "cancel_bt");
gtk_widget_show (cancel_bt);
gtk_container_add (GTK_CONTAINER (right_h_button_box), cancel_bt);
GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);

/* Connect the callbacks */
SIGNAL_CONNECT (key_management_w, "delete_event", window_delete_event_cb, key_management_w);
SIGNAL_CONNECT (key_management_w, "destroy", on_key_management_destroy, key_management_w);
/*SIGNAL_CONNECT (enable_decryption_en, "changed",on_enable_decryption_en_changed, toolbar);*/
SIGNAL_CONNECT (add_new_key_bt, "clicked",on_add_new_key_bt_clicked, key_management_w);
SIGNAL_CONNECT (remove_key_bt, "clicked",on_remove_key_bt_clicked, key_management_w);
SIGNAL_CONNECT (edit_key_bt, "clicked",on_edit_key_bt_clicked, key_management_w);
SIGNAL_CONNECT (move_key_up_bt, "clicked",on_move_key_up_bt_clicked, key_management_w);
SIGNAL_CONNECT (move_key_down_bt, "clicked",on_move_key_down_bt_clicked, key_management_w);
SIGNAL_CONNECT (reset_configuration_bt, "clicked",on_reset_configuration_bt_clicked, key_management_w);
SIGNAL_CONNECT (apply_bt, "clicked",on_key_management_apply_bt_clicked, key_management_w);
SIGNAL_CONNECT (ok_bt, "clicked",on_key_management_ok_bt_clicked, key_management_w);
SIGNAL_CONNECT (cancel_bt, "clicked",on_key_management_cancel_bt_clicked, key_management_w);
SIGNAL_CONNECT (key_ls, "select_row",on_key_ls_select_row, key_management_w);
SIGNAL_CONNECT (key_ls, "unselect_row",on_key_ls_unselect_row, key_management_w);
SIGNAL_CONNECT (key_ls, "click_column",on_key_ls_click_column, key_management_w);

/* Different because the window will be closed ... */
/*window_set_cancel_button(key_management_w, ok_bt, window_cancel_button_cb);
window_set_cancel_button(key_management_w, cancel_bt, window_cancel_button_cb);*/

OBJECT_SET_DATA (key_management_w, AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY,key_ls_selected_item);

/* Store pointers to all widgets, for use by lookup_widget(). */
OBJECT_SET_DATA (key_management_w, AIRPCAP_ADVANCED_WEP_DECRYPTION_KEY, enable_decryption_en);
OBJECT_SET_DATA (key_management_w, AIRPCAP_ADVANCED_KEYLIST_KEY, key_ls);
OBJECT_SET_DATA (key_management_w, AIRPCAP_ADVANCED_OK_KEY, ok_bt);
OBJECT_SET_DATA (key_management_w, AIRPCAP_ADVANCED_CANCEL_KEY, cancel_bt);

/*
 * I will need the toolbar and the main widget in some callback,
 * so I will add the toolbar pointer to the key_management_w
 */
OBJECT_SET_DATA(key_management_w,AIRPCAP_TOOLBAR_KEY,toolbar);
OBJECT_SET_DATA (key_management_w, AIRPCAP_TOOLBAR_DECRYPTION_KEY, toolbar_decryption_ck);

/* 
 * This will read the decryption keys from the preferences file, and will store 
 * them into the registry... 
 */
if(!airpcap_check_decryption_keys(airpcap_if_list))
    {
    /* Ask the user what to do ...*/
    airpcap_keys_check_w(key_management_w,NULL);
    }
else /* Keys from lists are equals, or wireshark has got no keys */
    {
    airpcap_load_decryption_keys(airpcap_if_list);
    /* At the end, so that it appears completely all together ... */
    gtk_widget_show (key_management_w);    
    }
}

/*
 * Callback for the OK button 'clicked' in the Decryption Key Management window.
 */
void
on_key_management_ok_bt_clicked(GtkWidget *button, gpointer data _U_)
{
/* advenced window */
GtkWidget	*key_management_w;

/* widgets in the toolbar */
GtkWidget	*toolbar;
GtkWidget *toolbar_cm;

GtkWidget   *key_ls;

GtkWidget   *decryption_en;

char* decryption_mode_string = NULL;

/* retrieve main window */
key_management_w      = GTK_WIDGET(data);
decryption_en         = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_WEP_DECRYPTION_KEY));
key_ls	              = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_KEYLIST_KEY));
toolbar               = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_TOOLBAR_KEY));
toolbar_cm            = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_TOOLBAR_DECRYPTION_KEY));

/* Set the Decryption Mode */
if(g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK) == 0)
    {
    set_wireshark_decryption(TRUE);
    if(!set_airpcap_decryption(FALSE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }
else if(g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP) == 0)
    {
    set_wireshark_decryption(FALSE);
    if(!set_airpcap_decryption(TRUE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }
else if(g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_NONE) == 0)
    {
    set_wireshark_decryption(FALSE);
    if(!set_airpcap_decryption(FALSE)) simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, CANT_SAVE_ERR_STR);
    }

/* Save the configuration */
if( (airpcap_if_selected != NULL) )
    {
    airpcap_read_and_save_decryption_keys_from_clist(key_ls,airpcap_if_selected,airpcap_if_list); /* This will save the keys for every adapter */
    
    /* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
    if( g_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
    	{
		update_decryption_mode_cm(toolbar_cm);
		}
    }

/* Redissect all the packets, and re-evaluate the display filter. */
cf_redissect_packets(&cfile);

/* Save the preferences to preferences file!!! */
write_prefs_to_file();

/* If interface active is airpcap, set sensitive TRUE for airpcap toolbar */
if( get_airpcap_if_by_name(airpcap_if_list,airpcap_if_active->description) != NULL)
	{
	airpcap_set_toolbar_start_capture(airpcap_if_active);
	}
else
	{
	airpcap_set_toolbar_stop_capture(airpcap_if_active);
	}

gtk_widget_destroy(key_management_w);
}

/*
 * Callback for the CANCEL button 'clicked' in the Decryption Key Management window.
 */
void
on_key_management_cancel_bt_clicked(GtkWidget *button, gpointer data _U_)
{
PAirpcapHandle ad = NULL;

/* Retrieve object data */
GtkWidget *key_management_w;
GtkWidget *cancel_bt;
GtkWidget *ok_bt;
GtkWidget *key_ls;

/* widgets in the toolbar */
GtkWidget	*toolbar,
			*toolbar_decryption_ck,
			*key_management_bt;
			
/* Row selected structure */
airpcap_key_ls_selected_info_t *selected_item;

/* Retrieve the GUI object pointers */
key_management_w	= GTK_WIDGET(data);
cancel_bt			= GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_CANCEL_KEY));
ok_bt				= GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_OK_KEY));
key_ls				= GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_KEYLIST_KEY));
key_management_bt   = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_KEY));

toolbar = GTK_WIDGET(OBJECT_GET_DATA(key_management_w,AIRPCAP_TOOLBAR_KEY));

/* retrieve toolbar info */
toolbar_decryption_ck	= GTK_WIDGET(OBJECT_GET_DATA(toolbar,AIRPCAP_TOOLBAR_DECRYPTION_KEY));

/* Retrieve the selected row item pointer... */
selected_item			= (airpcap_key_ls_selected_info_t*)(OBJECT_GET_DATA(key_management_w,AIRPCAP_ADVANCED_SELECTED_KEY_LIST_ITEM_KEY));
/* And free it */
g_free(selected_item);

gtk_widget_destroy(key_management_w);
}

/*
 * Dialog box that appears whenever keys are not consistent between wireshark and AirPcap 
 */
void
airpcap_keys_check_w(GtkWidget *w, gpointer data)
{
GtkWidget *keys_check_w;
GtkWidget *main_v_box;
GtkWidget *warning_lb;
GtkWidget *radio_tb;
GtkWidget *keep_rb;
GSList *radio_bt_group = NULL;
GtkWidget *merge_rb;
GtkWidget *import_rb;
GtkWidget *ignore_rb;
GtkWidget *keep_lb;
GtkWidget *merge_lb;
GtkWidget *import_lb;
GtkWidget *ignore_lb;
GtkWidget *low_h_button_box;
GtkWidget *ok_bt;
GtkWidget *cancel_bt;

keys_check_w = gtk_window_new (GTK_WINDOW_TOPLEVEL);
gtk_widget_set_name (keys_check_w, "keys_check_w");
gtk_window_set_title (GTK_WINDOW (keys_check_w), "Decryption Keys WARNING!");
#if GTK_MAJOR_VERSION >= 2
gtk_window_set_resizable (GTK_WINDOW (keys_check_w), FALSE);
#else
gtk_window_set_policy(GTK_WINDOW(keys_check_w), FALSE, FALSE, TRUE);
#endif

main_v_box = gtk_vbox_new (FALSE, 0);
gtk_widget_set_name (main_v_box, "main_v_box");
gtk_widget_show (main_v_box);
gtk_container_add (GTK_CONTAINER (keys_check_w), main_v_box);

#if GTK_MAJOR_VERSION >= 2
warning_lb = gtk_label_new("<b>WARNING!</b> Decryption keys specified in Wireshark's preferences file differ from those specified for the AirPcap adapter(s). You can choose to:");
gtk_label_set_use_markup (GTK_LABEL (warning_lb), TRUE);
#else
warning_lb = gtk_label_new("WARNING! Decryption keys specified in Wireshark's preferences file differ from those specified for the AirPcap adapter(s). You can choose to:");
#endif
gtk_widget_set_name (warning_lb, "warning_lb");
gtk_widget_show (warning_lb);
gtk_box_pack_start (GTK_BOX (main_v_box), warning_lb, FALSE, FALSE, 0);
gtk_label_set_justify (GTK_LABEL (warning_lb), GTK_JUSTIFY_CENTER);
gtk_label_set_line_wrap (GTK_LABEL (warning_lb), TRUE);

radio_tb = gtk_table_new (4, 2, FALSE);
gtk_widget_set_name (radio_tb, "radio_tb");
gtk_widget_show (radio_tb);
gtk_box_pack_start (GTK_BOX (main_v_box), radio_tb, TRUE, FALSE, 0);
gtk_container_set_border_width (GTK_CONTAINER (radio_tb), 5);
gtk_table_set_col_spacings (GTK_TABLE (radio_tb), 8);

#if GTK_MAJOR_VERSION >= 2
keep_rb = gtk_radio_button_new_with_mnemonic (NULL, "Keep");
#else
keep_rb = gtk_radio_button_new_with_label (NULL, "Keep");
#endif
gtk_widget_set_name (keep_rb, "keep_rb");
gtk_widget_show (keep_rb);
gtk_table_attach (GTK_TABLE (radio_tb), keep_rb, 0, 1, 0, 1,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_radio_button_set_group (GTK_RADIO_BUTTON (keep_rb), radio_bt_group);
#if GTK_MAJOR_VERSION >= 2
radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (keep_rb));
#else
radio_bt_group = gtk_radio_button_group (GTK_RADIO_BUTTON (keep_rb));
#endif

#if GTK_MAJOR_VERSION >= 2
merge_rb = gtk_radio_button_new_with_mnemonic (NULL, "Merge");
#else
merge_rb = gtk_radio_button_new_with_label (NULL, "Merge");
#endif
gtk_widget_set_name (merge_rb, "merge_rb");
gtk_widget_show (merge_rb);
gtk_table_attach (GTK_TABLE (radio_tb), merge_rb, 0, 1, 1, 2,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_radio_button_set_group (GTK_RADIO_BUTTON (merge_rb), radio_bt_group);
#if GTK_MAJOR_VERSION >= 2
radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (merge_rb));
#else
radio_bt_group = gtk_radio_button_group (GTK_RADIO_BUTTON (merge_rb));
#endif

#if GTK_MAJOR_VERSION >= 2
import_rb = gtk_radio_button_new_with_mnemonic (NULL, "Import");
#else
import_rb = gtk_radio_button_new_with_label (NULL, "Import");
#endif
gtk_widget_set_name (import_rb, "import_rb");
gtk_widget_show (import_rb);
gtk_table_attach (GTK_TABLE (radio_tb), import_rb, 0, 1, 2, 3,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_radio_button_set_group (GTK_RADIO_BUTTON (import_rb), radio_bt_group);
#if GTK_MAJOR_VERSION >= 2
radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (import_rb));
#else
radio_bt_group = gtk_radio_button_group (GTK_RADIO_BUTTON (import_rb));
#endif

#if GTK_MAJOR_VERSION >= 2
ignore_rb = gtk_radio_button_new_with_mnemonic (NULL, "Ignore");
#else
ignore_rb = gtk_radio_button_new_with_label (NULL, "Ignore");
#endif
gtk_widget_set_name (ignore_rb, "ignore_rb");
gtk_widget_show (ignore_rb);
gtk_table_attach (GTK_TABLE (radio_tb), ignore_rb, 0, 1, 3, 4,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_radio_button_set_group (GTK_RADIO_BUTTON (ignore_rb), radio_bt_group);
#if GTK_MAJOR_VERSION >= 2
radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (ignore_rb));
#else
radio_bt_group = gtk_radio_button_group (GTK_RADIO_BUTTON (ignore_rb));
#endif

keep_lb =
gtk_label_new
("Use Wireshark keys, thus overwriting AirPcap adapter(s) ones.");
gtk_widget_set_name (keep_lb, "keep_lb");
gtk_widget_show (keep_lb);
gtk_table_attach (GTK_TABLE (radio_tb), keep_lb, 1, 2, 0, 1,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_misc_set_alignment (GTK_MISC (keep_lb), 0, 0.5);

merge_lb = gtk_label_new ("Merge Wireshark and AirPcap adapter(s) keys.");
gtk_widget_set_name (merge_lb, "merge_lb");
gtk_widget_show (merge_lb);
gtk_table_attach (GTK_TABLE (radio_tb), merge_lb, 1, 2, 1, 2,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_misc_set_alignment (GTK_MISC (merge_lb), 0, 0.5);

import_lb =
gtk_label_new
("Use AirPcap adapter(s) keys, thus overwriting Wireshark ones.");
gtk_widget_set_name (import_lb, "import_lb");
gtk_widget_show (import_lb);
gtk_table_attach (GTK_TABLE (radio_tb), import_lb, 1, 2, 2, 3,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_misc_set_alignment (GTK_MISC (import_lb), 0, 0.5);

ignore_lb =
gtk_label_new
("Keep using different set of keys. Remember that in this case, this dialog box will appear whenever you will attempt to modify/add/remove decryption keys.");
gtk_widget_set_name (ignore_lb, "ignore_lb");
gtk_widget_show (ignore_lb);
gtk_table_attach (GTK_TABLE (radio_tb), ignore_lb, 1, 2, 3, 4,
	    (GtkAttachOptions) (GTK_FILL),
	    (GtkAttachOptions) (0), 0, 0);
gtk_label_set_line_wrap (GTK_LABEL (ignore_lb), TRUE);
gtk_misc_set_alignment (GTK_MISC (ignore_lb), 0, 0.5);

low_h_button_box = gtk_hbutton_box_new ();
gtk_widget_set_name (low_h_button_box, "low_h_button_box");
gtk_widget_show (low_h_button_box);
gtk_box_pack_start (GTK_BOX (main_v_box), low_h_button_box, FALSE, FALSE,
	      0);
gtk_button_box_set_layout (GTK_BUTTON_BOX (low_h_button_box),
		     GTK_BUTTONBOX_SPREAD);

#if GTK_MAJOR_VERSION >= 2
ok_bt = gtk_button_new_with_mnemonic ("Ok");
#else
ok_bt = gtk_button_new_with_label ("Ok");
#endif
gtk_widget_set_name (ok_bt, "ok_bt");
gtk_widget_show (ok_bt);
gtk_container_add (GTK_CONTAINER (low_h_button_box), ok_bt);
GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);

#if GTK_MAJOR_VERSION >= 2
cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
#else
cancel_bt = gtk_button_new_with_label ("Cancel");
#endif
gtk_widget_set_name (cancel_bt, "cancel_bt");
gtk_widget_show (cancel_bt);
gtk_container_add (GTK_CONTAINER (low_h_button_box), cancel_bt);
GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);

/* Store pointers to all widgets, for use by lookup_widget(). */
SIGNAL_CONNECT (ok_bt, "clicked", on_keys_check_ok_bt_clicked, keys_check_w);
SIGNAL_CONNECT (cancel_bt, "clicked", on_keys_check_cancel_bt_clicked, keys_check_w);
SIGNAL_CONNECT (keys_check_w, "destroy", on_keys_check_w_destroy, keys_check_w);

/* Store pointers to all widgets, for use by lookup_widget(). */
OBJECT_SET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_KEY,w);
OBJECT_SET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_MERGE_KEY,merge_rb);
OBJECT_SET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_KEEP_KEY,keep_rb);
OBJECT_SET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_IMPORT_KEY,import_rb);
OBJECT_SET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_IGNORE_KEY,ignore_rb);
OBJECT_SET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_GROUP_KEY,radio_bt_group);

gtk_widget_set_sensitive(top_level,FALSE);
gtk_widget_show(keys_check_w);
}

void
on_keys_check_cancel_bt_clicked (GtkWidget *button, gpointer user_data)
{
GtkWidget *key_management_w;
GtkWidget *keys_check_w;

keys_check_w = GTK_WIDGET(user_data);

key_management_w = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_KEY);

/* w may be NULL if airpcap_keys_check_w() has been called while wireshark was loading, 
   and is not NULL if it was called when the Key Management widget has been clicked */
  if(key_management_w != NULL)
     {
     /*  ... */
     gtk_widget_show (key_management_w);
     }

gtk_widget_destroy(keys_check_w);
}

void
on_keys_check_ok_bt_clicked (GtkWidget *button, gpointer user_data)
{
GtkWidget *key_management_w;
GtkWidget *keys_check_w;

GtkWidget *merge_rb,
          *keep_rb,
          *import_rb,
          *ignore_rb;

keys_check_w = GTK_WIDGET(user_data);

key_management_w = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_KEY);
merge_rb  = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_MERGE_KEY);
keep_rb   = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_KEEP_KEY);
import_rb = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_IMPORT_KEY);
ignore_rb = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_RADIO_IGNORE_KEY);

/* Find out which radio button is selected and call the correct function */
if(GTK_TOGGLE_BUTTON(merge_rb)->active) on_merge_bt_clicked (merge_rb,keys_check_w);
else if(GTK_TOGGLE_BUTTON(keep_rb)->active) on_keep_bt_clicked (keep_rb,keys_check_w);
else if(GTK_TOGGLE_BUTTON(import_rb)->active) on_import_bt_clicked (import_rb,keys_check_w);
else if(GTK_TOGGLE_BUTTON(ignore_rb)->active) on_ignore_bt_clicked (ignore_rb,keys_check_w);
else on_keys_check_cancel_bt_clicked(NULL,keys_check_w);
}

void
on_keys_check_w_destroy (GtkWidget *w, gpointer user_data)
{
gtk_widget_set_sensitive(top_level,TRUE);
gtk_widget_set_sensitive(GTK_WIDGET(user_data),TRUE);
}

void
on_keep_bt_clicked (GtkWidget *button, gpointer user_data)
{
GtkWidget *key_management_w;
GtkWidget *keys_check_w;

keys_check_w = GTK_WIDGET(user_data);

key_management_w = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_KEY);

/* w may be NULL if airpcap_keys_check_w() has been called while wireshark was loading, 
   and is not NULL if it was called when the Key Management widget has been clicked */
  if(key_management_w != NULL)
     {
     /*  ... */
     gtk_widget_show (key_management_w);
     }

gtk_widget_destroy(keys_check_w);

airpcap_load_decryption_keys(airpcap_if_list);
}

void
on_merge_bt_clicked (GtkWidget * button, gpointer user_data)
{
GtkWidget *key_management_w;
GtkWidget *keys_check_w;

guint n_adapters = 0;
guint n_wireshark_keys = 0;
guint n_curr_adapter_keys = 0;
guint n_total_keys = 0;
guint n_merged_keys = 0;
guint i = 0;

GList* wireshark_keys=NULL;
GList* current_adapter_keys=NULL;
GList* merged_list = NULL;
GList* merged_list_tmp = NULL;

airpcap_if_info_t* curr_adapter;

keys_check_w = GTK_WIDGET(user_data);

key_management_w = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_KEY);


/* w may be NULL if airpcap_keys_check_w() has been called while wireshark was loading, 
   and is not NULL if it was called when the Key Management widget has been clicked */
if(key_management_w != NULL)
    {
    /*  ... */
    gtk_widget_show (key_management_w);
    }

n_adapters = g_list_length(airpcap_if_list);

wireshark_keys = get_wireshark_keys();
n_wireshark_keys = g_list_length(wireshark_keys);
n_total_keys += n_wireshark_keys;

merged_list = merge_key_list(wireshark_keys,NULL);

/* NOW wireshark_keys IS no more needed... at the end, we will have to free it! */
for(i = 0; i<n_adapters; i++)
    {
    curr_adapter = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);
    current_adapter_keys = get_airpcap_device_keys(curr_adapter);
    n_curr_adapter_keys = g_list_length(current_adapter_keys);

    merged_list_tmp = merged_list;    
    merged_list = merge_key_list(merged_list_tmp,current_adapter_keys);    
    free_key_list(merged_list_tmp);
    
    n_total_keys += n_curr_adapter_keys;    
    }

n_merged_keys = g_list_length(merged_list);

/* Set up this new list as default for Wireshark and Adapters... */
airpcap_save_decryption_keys(merged_list,airpcap_if_list);

free_key_list(wireshark_keys);

gtk_widget_destroy(keys_check_w);
}


void
on_import_bt_clicked (GtkWidget * button, gpointer user_data)
{
GtkWidget *key_management_w;
GtkWidget *keys_check_w;

guint n_adapters = 0;
guint n_wireshark_keys = 0;
guint n_curr_adapter_keys = 0;
guint n_total_keys = 0;
guint n_merged_keys = 0;
guint i = 0;

GList* wireshark_keys=NULL;
GList* current_adapter_keys=NULL;
GList* merged_list = NULL;
GList* merged_list_tmp = NULL;

airpcap_if_info_t* curr_adapter;

keys_check_w = GTK_WIDGET(user_data);

key_management_w = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_KEY);


/* w may be NULL if airpcap_keys_check_w() has been called while wireshark was loading, 
   and is not NULL if it was called when the Key Management widget has been clicked */
if(key_management_w != NULL)
    {
    /*  ... */
    gtk_widget_show (key_management_w);
    }

n_adapters = g_list_length(airpcap_if_list);

wireshark_keys = get_wireshark_keys();
n_wireshark_keys = g_list_length(wireshark_keys);
n_total_keys += n_wireshark_keys;

/* NOW wireshark_keys IS no more needed... at the end, we will have to free it! */
for(i = 0; i<n_adapters; i++)
    {
    curr_adapter = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);
    current_adapter_keys = get_airpcap_device_keys(curr_adapter);
    n_curr_adapter_keys = g_list_length(current_adapter_keys);

    merged_list_tmp = merged_list;    
    merged_list = merge_key_list(merged_list_tmp,current_adapter_keys);    
    free_key_list(merged_list_tmp);
    
    n_total_keys += n_curr_adapter_keys;    
    }

n_merged_keys = g_list_length(merged_list);

/* Set up this new list as default for Wireshark and Adapters... */
airpcap_save_decryption_keys(merged_list,airpcap_if_list);

free_key_list(wireshark_keys);

gtk_widget_destroy(keys_check_w);
}


void
on_ignore_bt_clicked (GtkWidget * button, gpointer user_data)
{
GtkWidget *key_management_w;
GtkWidget *keys_check_w;

keys_check_w = GTK_WIDGET(user_data);

key_management_w = OBJECT_GET_DATA(keys_check_w,AIRPCAP_CHECK_WINDOW_KEY);

/* w may be NULL if airpcap_keys_check_w() has been called while wireshark was loading, 
   and is not NULL if it was called when the Key Management widget has been clicked */
  if(key_management_w != NULL)
     {
     /*  ... */
     gtk_widget_show (key_management_w);
     }

gtk_widget_destroy(keys_check_w);
}


#endif /* HAVE_AIRPCAP */
