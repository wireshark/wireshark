/* main_airpcap_toolbar.c
 * The airpcap toolbar
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This file implements the wireless toolbar for Wireshark.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_AIRPCAP

#include <gtk/gtk.h>
#include "ui/gtk/old-gtk-compat.h"

#include <epan/epan.h>
#include <epan/frequency-utils.h>

#include "ui/simple_dialog.h"

#include "main.h"
#include "main_airpcap_toolbar.h"

#include "recent.h"
#include "keys.h"

#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_dlg.h"
#include "airpcap_gui_utils.h"

#include <epan/crypt/airpdcap_ws.h>


gboolean block_toolbar_signals = FALSE;
static GtkWidget *driver_warning_dialog;


/*
 * Callback for the wrong crc combo
 */
static void
airpcap_toolbar_fcs_filter_combo_cb(GtkWidget *fcs_filter_cb, gpointer user_data _U_)
{
    PAirpcapHandle ad;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];
    gchar *fcs_filter_str;

    if (fcs_filter_cb != NULL && !block_toolbar_signals && (airpcap_if_active != NULL)) {
        fcs_filter_str = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb));
        ad = airpcap_if_open(airpcap_if_active->name, ebuf);

        if (fcs_filter_str && (g_ascii_strcasecmp("", fcs_filter_str)) && ad) {
            airpcap_if_selected->CrcValidationOn = airpcap_get_validation_type(fcs_filter_str);
            airpcap_if_selected->saved = FALSE;
	    airpcap_if_set_fcs_validation(ad,airpcap_if_active->CrcValidationOn);
	    /* Save configuration */
	    airpcap_if_store_cur_config_as_adapter_default(ad);
	    airpcap_if_close(ad);
        }
        g_free(fcs_filter_str);
    }
}

void
airpcap_toolbar_encryption_cb(GtkWidget *entry _U_, gpointer user_data _U_)
{
  /* We need to directly access the .dll functions here... */
  gchar ebuf[AIRPCAP_ERRBUF_SIZE];
  PAirpcapHandle ad;

  gint n = 0;
  gint i = 0;
  airpcap_if_info_t* curr_if = NULL;

  /* Apply changes to the current adapter */
  if( (airpcap_if_active != NULL)) {
    ad = airpcap_if_open(airpcap_if_active->name, ebuf);

    if(ad) {
      if(airpcap_if_active->DecryptionOn == AIRPCAP_DECRYPTION_ON) {
        airpcap_if_active->DecryptionOn = AIRPCAP_DECRYPTION_OFF;
        airpcap_if_set_decryption_state(ad,airpcap_if_active->DecryptionOn);
        /* Save configuration */
        if(!airpcap_if_store_cur_config_as_adapter_default(ad))	{
          simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
	}
        airpcap_if_close(ad);
      } else {
        airpcap_if_active->DecryptionOn = AIRPCAP_DECRYPTION_ON;
        airpcap_if_set_decryption_state(ad,airpcap_if_active->DecryptionOn);
        /* Save configuration */
        if(!airpcap_if_store_cur_config_as_adapter_default(ad))	{
          simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
	}
        airpcap_if_close(ad);
      }
    }
  } else {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No active AirPcap Adapter selected!");
    return;
  }

  if (!(airpcap_if_list == NULL)) {
    n = g_list_length(airpcap_if_list);

    /* The same kind of settings should be propagated to all the adapters */
    /* Apply this change to all the adapters !!! */
    for(i = 0; i < n; i++) {
      curr_if = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);

      if( (curr_if != NULL) && (curr_if != airpcap_if_selected) ) {
	ad = airpcap_if_open(curr_if->name, ebuf);
	if(ad) {
	  curr_if->DecryptionOn = airpcap_if_selected->DecryptionOn;
	  airpcap_if_set_decryption_state(ad,curr_if->DecryptionOn);
	  /* Save configuration for the curr_if */
	  if(!airpcap_if_store_cur_config_as_adapter_default(ad))	{
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
	  }
	  airpcap_if_close(ad);
	}
      }
    }
  } else {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "AirPcap Adapter Error!");
    return;
  }
}

/*
 * Callback for the Advanced Wireless Settings button
 */
static void
toolbar_display_airpcap_advanced_cb(GtkWidget *w, gpointer data)
{
    int *from_widget;

    from_widget = (gint*)g_malloc(sizeof(gint));
    *from_widget = AIRPCAP_ADVANCED_FROM_TOOLBAR;
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_ADVANCED_FROM_KEY,from_widget);

    display_airpcap_advanced_cb(w,data);
}

/*
 * Callback for the Decryption Key Management button
 */
static void
toolbar_display_airpcap_key_management_cb(GtkWidget *w, gpointer data)
{
    int *from_widget;

    from_widget = (gint*)g_malloc(sizeof(gint));
    *from_widget = AIRPCAP_ADVANCED_FROM_TOOLBAR;
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_ADVANCED_FROM_KEY, from_widget);

    display_airpcap_key_management_cb(w,data);
}

GtkWidget *airpcap_toolbar_new(void)
{
    GtkWidget	  *channel_lb = NULL,
		  *channel_cb = NULL,
		  *channel_offset_lb = NULL,
		  *channel_offset_cb = NULL,
		  *fcs_filter_lb = NULL,
		  *fcs_filter_cb = NULL;
    GtkWidget     *airpcap_tb;

    GtkWidget     *decryption_mode_lb;
    GtkWidget     *decryption_mode_cb;

    GtkToolItem	  *key_management_bt = NULL,
		  *advanced_bt = NULL,
		  *tool_item;

    /* airpcap toolbar */
    airpcap_tb = gtk_toolbar_new();
    gtk_orientable_set_orientation(GTK_ORIENTABLE(airpcap_tb),
                                GTK_ORIENTATION_HORIZONTAL);

    /* Create the "802.11 Channel:" label */
    channel_lb = gtk_label_new("802.11 Channel: ");
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY, channel_lb);
    gtk_widget_show(channel_lb);

    gtk_widget_set_size_request(channel_lb, 85, -1);

    tool_item = gtk_tool_item_new ();
    gtk_container_add (GTK_CONTAINER (tool_item), channel_lb);
    gtk_widget_show (GTK_WIDGET (tool_item));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), tool_item, -1);

	gtk_widget_set_tooltip_text(GTK_WIDGET(tool_item), "Current 802.11 Channel");

    /* Create the channel combo box */
    channel_cb = gtk_combo_box_text_new();
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_CHANNEL_KEY, channel_cb);

    /* Select the current channel */
    airpcap_update_channel_combo(GTK_WIDGET(channel_cb), airpcap_if_selected);

    gtk_widget_set_size_request(channel_cb, 120, -1);

    gtk_widget_show(channel_cb);

    tool_item = gtk_tool_item_new ();
    gtk_container_add (GTK_CONTAINER (tool_item), channel_cb);
    gtk_widget_show (GTK_WIDGET (tool_item));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), tool_item, -1);

	gtk_widget_set_tooltip_text(GTK_WIDGET(tool_item), "802.11 Channel");

    /* Create the "Channel Offset:" label */
    channel_offset_lb = gtk_label_new("Channel Offset: ");
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY, channel_offset_lb);
    gtk_widget_show(channel_offset_lb);

    gtk_widget_set_size_request(channel_offset_lb, 90, -1);
    tool_item = gtk_tool_item_new ();
    gtk_container_add (GTK_CONTAINER (tool_item), channel_offset_lb);
    gtk_widget_show (GTK_WIDGET (tool_item));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), tool_item, -1);

	gtk_widget_set_tooltip_text(GTK_WIDGET(tool_item), "Current 802.11 Channel Offset");

    /* Start: Channel offset combo box */
    channel_offset_cb = gtk_combo_box_text_new();
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY, channel_offset_cb);

    if(airpcap_if_active != NULL){
        airpcap_update_channel_offset_combo(airpcap_if_active, airpcap_if_active->channelInfo.Frequency, channel_offset_cb, FALSE);
    } else {
        gtk_combo_box_set_active(GTK_COMBO_BOX(channel_offset_cb), -1);
    }

	gtk_widget_set_tooltip_text(channel_offset_cb, "Current 802.11 Channel Offset");

    gtk_widget_set_size_request(channel_offset_cb, 50, -1);

    gtk_widget_show(channel_offset_cb);

    tool_item = gtk_tool_item_new ();
    gtk_container_add (GTK_CONTAINER (tool_item), channel_offset_cb);
    gtk_widget_show (GTK_WIDGET (tool_item));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), tool_item, -1);

    /* callback for channel combo box */
    g_signal_connect(channel_cb,"changed", G_CALLBACK(airpcap_channel_changed_set_cb), channel_offset_cb);
    /* callback for channel offset combo box */
    g_signal_connect(channel_offset_cb, "changed", G_CALLBACK(airpcap_channel_offset_changed_cb), NULL);
    /* End: Channel offset combo box */

    /* Wrong CRC Label */
    fcs_filter_lb = gtk_label_new(" FCS Filter: ");
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY, fcs_filter_lb);
    gtk_widget_show(fcs_filter_lb);
    tool_item = gtk_tool_item_new ();
    gtk_container_add (GTK_CONTAINER (tool_item), fcs_filter_lb);
    gtk_widget_show (GTK_WIDGET (tool_item));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), tool_item, -1);

    /* FCS filter combo box */
    fcs_filter_cb = gtk_combo_box_text_new();
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_FCS_FILTER_KEY, fcs_filter_cb);

    gtk_widget_set_size_request(fcs_filter_cb, 100, -1);

     gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb), airpcap_get_validation_name(AIRPCAP_VT_ACCEPT_EVERYTHING));
     gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb), airpcap_get_validation_name(AIRPCAP_VT_ACCEPT_CORRECT_FRAMES));
     gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb), airpcap_get_validation_name(AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES));
    gtk_combo_box_set_active(GTK_COMBO_BOX(fcs_filter_cb), 0);

	gtk_widget_set_tooltip_text(fcs_filter_cb, "Select the 802.11 FCS filter that the wireless adapter will apply.");

    if (airpcap_if_selected != NULL) {
        airpcap_validation_type_combo_set_by_type(fcs_filter_cb, airpcap_if_selected->CrcValidationOn);
    }

    g_signal_connect (fcs_filter_cb, "changed", G_CALLBACK(airpcap_toolbar_fcs_filter_combo_cb), NULL);
    gtk_widget_show(fcs_filter_cb);

    tool_item = gtk_tool_item_new ();
    gtk_container_add (GTK_CONTAINER (tool_item), fcs_filter_cb);
    gtk_widget_show (GTK_WIDGET (tool_item));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), tool_item, -1);

    /* Decryption mode combo box */
    decryption_mode_lb = gtk_label_new ("Decryption Mode: ");
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY, decryption_mode_lb);
    gtk_widget_set_name (decryption_mode_lb, "decryption_mode_lb");
    gtk_widget_show (decryption_mode_lb);

    decryption_mode_cb = gtk_combo_box_text_new();
    gtk_widget_set_name (decryption_mode_cb, "decryption_mode_cb");
    gtk_widget_show (decryption_mode_cb);
    gtk_widget_set_size_request(decryption_mode_cb, 83, -1);
    update_decryption_mode_list(decryption_mode_cb);

    tool_item = gtk_tool_item_new ();
    gtk_container_add (GTK_CONTAINER (tool_item), decryption_mode_cb);
    gtk_widget_show (GTK_WIDGET (tool_item));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), tool_item, -1);

	gtk_widget_set_tooltip_text(fcs_filter_lb, "Choose a Decryption Mode");
    /* Set current decryption mode!!!! */
    update_decryption_mode(decryption_mode_cb);
    g_signal_connect(decryption_mode_cb, "changed", G_CALLBACK(on_decryption_mode_cb_changed), NULL);
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_DECRYPTION_KEY, decryption_mode_cb);

    /* Advanced button */
    advanced_bt = gtk_tool_button_new(NULL, /* a widget that will be used as icon widget, or NULL */
	    "Wireless Settings...");
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_ADVANCED_KEY, advanced_bt);

    g_signal_connect(advanced_bt, "clicked", G_CALLBACK(toolbar_display_airpcap_advanced_cb), airpcap_tb);
    gtk_widget_show(GTK_WIDGET(advanced_bt));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), advanced_bt, -1);

	gtk_widget_set_tooltip_text(GTK_WIDGET(advanced_bt), "Set Advanced Wireless Settings");
    /* Key Management button */
    key_management_bt = gtk_tool_button_new(NULL, /* a widget that will be used as icon widget, or NULL */
	    "Decryption Keys...");

    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY, key_management_bt);

    g_signal_connect(key_management_bt, "clicked", G_CALLBACK(toolbar_display_airpcap_key_management_cb), airpcap_tb);
    gtk_widget_show(GTK_WIDGET(key_management_bt));
    gtk_toolbar_insert(GTK_TOOLBAR(airpcap_tb), key_management_bt, -1);
	gtk_widget_set_tooltip_text(GTK_WIDGET(key_management_bt), "Manage Decryption Keys");

    /* If no airpcap interface is present, gray everything */
    if(airpcap_if_active == NULL) {
        if(airpcap_if_list == NULL || g_list_length(airpcap_if_list) == 0) {
            /* No airpcap device found */
            airpcap_enable_toolbar_widgets(airpcap_tb, FALSE);
            /* recent.airpcap_toolbar_show = TRUE; */
        } else {
            /* default adapter is not airpcap... or is airpcap but is not found*/
            airpcap_set_toolbar_stop_capture(airpcap_if_active);
            airpcap_enable_toolbar_widgets(airpcap_tb, FALSE);
            /* recent.airpcap_toolbar_show = TRUE; */
        }
    } else {
        airpcap_set_toolbar_stop_capture(airpcap_if_active);
        /* recent.airpcap_toolbar_show = TRUE; */
    }

    return airpcap_tb;
}

static void
driver_warning_dialog_cb(gpointer dialog, gint btn _U_, gpointer data _U_)
{
    gboolean r;

    r = simple_dialog_check_get(dialog);
    recent.airpcap_driver_check_show = !r;
}

void airpcap_toolbar_show(GtkWidget *airpcap_tb _U_)
{
  /*
   * This will read the decryption keys from the preferences file, and will
   * store them into the registry...
   */
  if(airpcap_if_list != NULL && g_list_length(airpcap_if_list) > 0){
    if (!airpcap_check_decryption_keys(airpcap_if_list)) {
      /* Ask the user what to do ...*/
      airpcap_keys_check_w(NULL,NULL);
    } else {
      /* Keys from lists are equals, or Wireshark has got no keys */
      airpcap_load_decryption_keys(airpcap_if_list);
    }
  }

  switch (airpcap_dll_ret_val) {

  case AIRPCAP_DLL_OK:
    break;

  case AIRPCAP_DLL_OLD:
    if(recent.airpcap_driver_check_show) {
      driver_warning_dialog = simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s",
			"WARNING: The version of AirPcap on this system\n"
			"does not support driver-level decryption.  Please\n"
			"download a more recent version from\n" "http://www.cacetech.com/support/downloads.htm \n");
      simple_dialog_check_set(driver_warning_dialog,"Don't show this message again.");
      simple_dialog_set_cb(driver_warning_dialog, driver_warning_dialog_cb, NULL);
    }
    break;

#if 0
  /*
   * XXX - Maybe we need to warn the user if one of the following happens???
   */
  case AIRPCAP_DLL_ERROR:
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DLL_ERROR\n");
    break;

  case AIRPCAP_DLL_NOT_FOUND:
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DDL_NOT_FOUND\n");
    break;
#endif
  }
}

#endif /* HAVE_AIRPCAP */
