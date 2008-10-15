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

#include <epan/epan.h>
#include <epan/frequency-utils.h>

#include "simple_dialog.h"
#include "main.h"
#include "main_airpcap_toolbar.h"

#include "recent.h"
#include "keys.h"

#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_dlg.h"
#include "airpcap_gui_utils.h"

#ifdef	HAVE_AIRPDCAP
#include <epan/crypt/airpdcap_ws.h>
#endif


gboolean block_toolbar_signals = FALSE;
static GtkWidget *driver_warning_dialog;



/*
 * Changed callback for the channel combobox
 */
static void
airpcap_toolbar_channel_changed_cb(GtkWidget *w, gpointer data)
{
  const gchar *s;
  ULONG ch_freq;

  if ((data != NULL) && (w != NULL) && change_airpcap_settings) {
	s = gtk_entry_get_text(GTK_ENTRY(w));
    if ((g_ascii_strcasecmp("",s))) {
      ch_freq = airpcap_get_frequency_from_str(s);
      if (airpcap_if_active != NULL) {
		airpcap_if_active->channelInfo.Frequency = ch_freq;
		airpcap_update_channel_offset_cb(airpcap_if_active, ch_freq, GTK_WIDGET(data));
      }
    }
  }
}

/*
 * Changed callback for the channel offset combobox
 */
static void
on_channel_offset_cb_changed(GtkWidget *w, gpointer data)
{
    const gchar *s;
    int offset;

    if (w == NULL || GTK_WIDGET_SENSITIVE(w)) {
        return;
    }
    
    if (data != NULL && change_airpcap_settings)
    {
        s = gtk_entry_get_text(GTK_ENTRY(w));
        if ((g_ascii_strcasecmp("",s)))
        {
            if (airpcap_if_active != NULL)
            {
                sscanf(s,"%d",&offset);
                airpcap_if_active->channelInfo.ExtChannel = offset;
                if (change_airpcap_settings != NULL)
                {
                    airpcap_update_frequency_and_offset(airpcap_if_active);
                }
            }
        }
    }
}

/*
 * Callback for the wrong crc combo
 */
static void
airpcap_toolbar_wrong_crc_combo_cb(GtkWidget *entry, gpointer user_data)
{
  gchar ebuf[AIRPCAP_ERRBUF_SIZE];
  PAirpcapHandle ad;

  if( !block_toolbar_signals && (airpcap_if_active != NULL)) {
    ad = airpcap_if_open(airpcap_if_active->name, ebuf);

    if (ad) {
      airpcap_if_active->CrcValidationOn = airpcap_get_validation_type(gtk_entry_get_text(GTK_ENTRY(entry)));
      airpcap_if_set_fcs_validation(ad,airpcap_if_active->CrcValidationOn);
      /* Save configuration */
      airpcap_if_store_cur_config_as_adapter_default(ad);
      airpcap_if_close(ad);
    }
  }
}

void
airpcap_toolbar_encryption_cb(GtkWidget *entry, gpointer user_data)
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

  if (!(airpcap_if_list == NULL)){
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
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_ADVANCED_FROM_KEY,from_widget);

    display_airpcap_key_management_cb(w,data);
}

GtkWidget *airpcap_toolbar_new()
{
    GtkWidget     *key_management_bt = NULL,
    		  *advanced_bt = NULL,
    		  *channel_lb = NULL,
    		  *channel_cm = NULL,
    		  *channel_offset_lb = NULL,
    		  *channel_offset_cb = NULL,
    		  *wrong_crc_lb = NULL,
    		  *wrong_crc_cm = NULL;
    GtkWidget     *airpcap_tb;

    GtkWidget     *enable_decryption_lb;
    GtkWidget     *enable_decryption_cb;
    GList         *enable_decryption_cb_items = NULL;
    GtkWidget     *enable_decryption_en;

    GList	  *channel_list = NULL;
    GList	  *linktype_list = NULL;
    GList	  *link_list = NULL;
    GtkTooltips	  *airpcap_tooltips;
    /* gchar	  *if_label_text; */
    gint          *from_widget = NULL;
    gchar         *chan_str;

    /* airpcap toolbar */
    airpcap_tooltips = gtk_tooltips_new();
    airpcap_tb = gtk_toolbar_new();
    gtk_toolbar_set_orientation(GTK_TOOLBAR(airpcap_tb),
                                GTK_ORIENTATION_HORIZONTAL);

    /* Interface Label */
    /*if(airpcap_if_active != NULL) {
        if_label_text = g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_active));
        interface_lb = gtk_label_new(if_label_text);
        g_free(if_label_text);
    } else {
        interface_lb = gtk_label_new("No Wireless Interface Found  ");
    }*/

    /* Add the label to the toolbar */
    /*gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), interface_lb,
                              "Current Wireless Interface", "Private");
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_INTERFACE_KEY,interface_lb);
    gtk_widget_show(interface_lb);
    gtk_toolbar_insert_space(GTK_TOOLBAR(airpcap_tb),1);*/


    /* Create the "802.11 Channel:" label */
    channel_lb = gtk_label_new("802.11 Channel: ");
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY,channel_lb);
    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), channel_lb,
                              "Current 802.11 Channel", "Private");
    gtk_widget_show(channel_lb);

    gtk_widget_set_size_request(channel_lb, 85, 28);

    /* Create the channel combo box */
    channel_cm = gtk_combo_new();
    gtk_editable_set_editable(GTK_EDITABLE(GTK_COMBO(channel_cm)->entry),FALSE);
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_KEY,channel_cm);

    if (airpcap_if_active != NULL && airpcap_if_active->pSupportedChannels != NULL && airpcap_if_active->numSupportedChannels > 0){
        guint i = 0;
        for (; i<airpcap_if_active->numSupportedChannels; i++){
            channel_list = g_list_append(channel_list, ieee80211_mhz_to_str(airpcap_if_active->pSupportedChannels[i].Frequency));
        }
        gtk_combo_set_popdown_strings( GTK_COMBO(channel_cm), channel_list);
        airpcap_free_channel_combo_list(channel_list);
    }

    gtk_tooltips_set_tip(airpcap_tooltips, GTK_WIDGET(GTK_COMBO(channel_cm)->entry),
		"Change the 802.11 RF channel", NULL);

    gtk_widget_set_size_request(channel_cm, 120, 28);

    if(airpcap_if_active != NULL) {
        chan_str = ieee80211_mhz_to_str(airpcap_if_active->channelInfo.Frequency);
        gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_cm)->entry), chan_str);
        g_free(chan_str);
    }
    else {
        gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_cm)->entry),"");
    }
    gtk_widget_show(channel_cm);

    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), channel_cm,
                              "802.11 Channel", "Private");

    /* gtk_toolbar_append_space(GTK_TOOLBAR(airpcap_tb)); */

    /* Create the "Channel Offset:" label */
    channel_offset_lb = gtk_label_new("Channel Offset: ");
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY,channel_offset_lb);
    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), channel_offset_lb,
                              "Current 802.11 Channel Offset", "Private");
    gtk_widget_show(channel_offset_lb);

    gtk_widget_set_size_request(channel_offset_lb, 80, 28);

    /* Start: Channel offset combo box */
    channel_offset_cb = gtk_combo_new();
    gtk_editable_set_editable(GTK_EDITABLE(GTK_COMBO(channel_offset_cb)->entry),FALSE);
    g_object_set_data(G_OBJECT(airpcap_tb), AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY, channel_offset_cb);

    if(airpcap_if_active != NULL){
		airpcap_update_channel_offset_cb(airpcap_if_active, airpcap_if_active->channelInfo.Frequency, channel_offset_cb);
		airpcap_update_channel_offset_combo_entry(channel_offset_cb, airpcap_if_active->channelInfo.ExtChannel);
    } else {
        gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_offset_cb)->entry),"");
    }

    gtk_tooltips_set_tip(airpcap_tooltips, GTK_WIDGET(GTK_COMBO(channel_offset_cb)->entry),
		"Change channel offset", NULL);

    gtk_widget_set_size_request(channel_offset_cb, 50, 28);

    gtk_widget_show(channel_offset_cb);

    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), channel_offset_cb,
                              "802.11 Channel Offset", "Private");

    gtk_toolbar_append_space(GTK_TOOLBAR(airpcap_tb));

    /* callback for channel combo box */
    g_signal_connect(GTK_COMBO(channel_cm)->entry,"changed", G_CALLBACK(airpcap_toolbar_channel_changed_cb), channel_offset_cb);
    /* callback for channel offset combo box */
    g_signal_connect(GTK_COMBO(channel_offset_cb)->entry,"changed", G_CALLBACK(on_channel_offset_cb_changed), channel_offset_cb);
    /* End: Channel offset combo box */

    /* Wrong CRC Label */
    wrong_crc_lb = gtk_label_new(" FCS Filter: ");
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY,wrong_crc_lb);
    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), wrong_crc_lb,
                              "", "Private");
    gtk_widget_show(wrong_crc_lb);

    /* Wrong CRC combo */
    wrong_crc_cm = gtk_combo_new();
    gtk_editable_set_editable(GTK_EDITABLE(GTK_COMBO(wrong_crc_cm)->entry),FALSE);
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY,wrong_crc_cm);
    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), wrong_crc_cm,
                              "", "Private");

    gtk_widget_set_size_request(wrong_crc_cm, 100, -1);

    linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_ALL);
    linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_CORRECT);
    linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT);

    gtk_combo_set_popdown_strings( GTK_COMBO(wrong_crc_cm), linktype_list) ;
    g_list_free(linktype_list);
    gtk_tooltips_set_tip(airpcap_tooltips, GTK_WIDGET(GTK_COMBO(wrong_crc_cm)->entry),
	"Select the 802.11 FCS filter that the wireless adapter will apply.",
        NULL);

    if(airpcap_if_active != NULL)
        gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(wrong_crc_cm)->entry), airpcap_get_validation_name(airpcap_if_active->CrcValidationOn));
    else
        gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(wrong_crc_cm)->entry),"");

    g_signal_connect(GTK_COMBO(wrong_crc_cm)->entry,"changed",G_CALLBACK(airpcap_toolbar_wrong_crc_combo_cb),airpcap_tb);
    gtk_widget_show(wrong_crc_cm);

    gtk_toolbar_append_space(GTK_TOOLBAR(airpcap_tb));

    /* Decryption mode combo box */
    enable_decryption_lb = gtk_label_new ("Decryption Mode: ");
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY,enable_decryption_lb);
    gtk_widget_set_name (enable_decryption_lb, "enable_decryption_lb");
    gtk_widget_show (enable_decryption_lb);
    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), enable_decryption_lb,
        NULL, "Private");

    enable_decryption_cb = gtk_combo_new ();
    gtk_widget_set_name (enable_decryption_cb, "enable_decryption_cb");
    gtk_widget_show (enable_decryption_cb);
    gtk_widget_set_size_request(enable_decryption_cb, 83, -1);
    update_decryption_mode_list(enable_decryption_cb);

    enable_decryption_en = GTK_COMBO (enable_decryption_cb)->entry;
    gtk_widget_set_name (enable_decryption_en, "enable_decryption_en");
    gtk_widget_show (enable_decryption_en);
    gtk_editable_set_editable (GTK_EDITABLE (enable_decryption_en), FALSE);
    GTK_WIDGET_UNSET_FLAGS (enable_decryption_en, GTK_CAN_FOCUS);

    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), enable_decryption_cb,
        "Choose a Decryption Mode", "Private");

    /* Set current decryption mode!!!! */
    update_decryption_mode_cm(enable_decryption_cb);
    g_signal_connect(enable_decryption_en, "changed", G_CALLBACK(on_enable_decryption_en_changed), airpcap_tb);
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY,enable_decryption_cb);

    gtk_toolbar_append_space(GTK_TOOLBAR(airpcap_tb));

    /* Advanced button */
    advanced_bt = gtk_button_new_with_label("Wireless Settings...");
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_ADVANCED_KEY,advanced_bt);

    g_signal_connect(advanced_bt, "clicked", G_CALLBACK(toolbar_display_airpcap_advanced_cb), airpcap_tb);
    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), advanced_bt,
        "Set Advanced Wireless Settings", "Private");


    gtk_widget_show(advanced_bt);

    /* Key Management button */
    key_management_bt = gtk_button_new_with_label("Decryption Keys...");
    g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY,key_management_bt);

    g_signal_connect(key_management_bt, "clicked", G_CALLBACK(toolbar_display_airpcap_key_management_cb), airpcap_tb);
    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), key_management_bt,
                              "Manage Decryption Keys", "Private");
    gtk_widget_show(key_management_bt);

    /* If no airpcap interface is present, gray everything */
    if(airpcap_if_active == NULL) {
        if(airpcap_if_list == NULL || g_list_length(airpcap_if_list) == 0) {
            /* No airpcap device found */
            airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
            /* recent.airpcap_toolbar_show = TRUE; */
        } else {
            /* default adapter is not airpcap... or is airpcap but is not found*/
            airpcap_set_toolbar_stop_capture(airpcap_if_active);
            airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
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

void airpcap_toolbar_show(GtkWidget *airpcap_tb)
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
