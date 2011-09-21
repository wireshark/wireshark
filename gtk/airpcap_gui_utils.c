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

#include <stdio.h>
#include <string.h>

#include <epan/filesystem.h>
#include <epan/strutil.h>
#include <epan/frequency-utils.h>
#include <epan/crypt/airpdcap_ws.h>

#include "../simple_dialog.h"

#include "gtk/main.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/dfilter_expr_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/keys.h"
#include "gtk/old-gtk-compat.h"

#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"


/* Controls the releay of settings back to the adapter. */
gboolean change_airpcap_settings = FALSE;

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

    airpcap_toolbar_label    = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_INTERFACE_KEY);
    toolbar_channel_cb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_KEY);
    airpcap_toolbar_channel_lb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
    airpcap_toolbar_channel_offset  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY);
    airpcap_toolbar_channel_offset_lb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY);
    airpcap_toolbar_fcs  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    airpcap_toolbar_fcs_lb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
    airpcap_toolbar_button   = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_ADVANCED_KEY);
    airpcap_toolbar_decryption = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY);
    airpcap_toolbar_decryption_lb = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY);
    airpcap_toolbar_keys_button = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY);

    /* The current interface is an airpcap interface */
    if(if_info != NULL)
    {
        gtk_widget_set_sensitive(airpcap_tb,TRUE);
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
        g_signal_handlers_block_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, airpcap_tb);
        if(if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
        else
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
        g_signal_handlers_unblock_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, airpcap_tb);

        if_label_text = g_strdup_printf("Current Wireless Interface: #%s", airpcap_get_if_string_number(if_info));
        gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
        g_free(if_label_text);

        change_airpcap_settings = FALSE;
        if (if_info->pSupportedChannels != NULL && if_info->numSupportedChannels > 0){
            guint i = 0;

            for (; i<if_info->numSupportedChannels; i++){
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(toolbar_channel_cb), ieee80211_mhz_to_str(if_info->pSupportedChannels[i].Frequency));
            }
        }

        airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cb),if_info);
        airpcap_update_channel_offset_combo(if_info, if_info->channelInfo.Frequency, airpcap_toolbar_channel_offset, TRUE);
        change_airpcap_settings = TRUE;
    }
    else /* Current interface is NOT an AirPcap one... */
    {
        gtk_widget_set_sensitive(airpcap_tb,FALSE);
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

    airpcap_toolbar_crc_filter_combo = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    airpcap_toolbar_label    = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_INTERFACE_KEY);
    toolbar_channel_cb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_KEY);
    airpcap_toolbar_channel_lb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
    airpcap_toolbar_channel_offset  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY);
    airpcap_toolbar_channel_offset_lb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY);
    airpcap_toolbar_fcs  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    airpcap_toolbar_fcs_lb  = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
    airpcap_toolbar_button   = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_ADVANCED_KEY);
    airpcap_toolbar_decryption = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY);
    airpcap_toolbar_decryption_lb = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY);
    airpcap_toolbar_keys_button = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY);

    /* The current interface is an airpcap interface */
    if(if_info != NULL)
    {
          gtk_widget_set_sensitive(airpcap_tb,TRUE);
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
          g_signal_handlers_block_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, airpcap_tb);
          if(if_info->DecryptionOn == AIRPCAP_DECRYPTION_ON)
              gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),TRUE);
          else
              gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(airpcap_toolbar_decryption),FALSE);
          g_signal_handlers_unblock_by_func (airpcap_toolbar_decryption,airpcap_toolbar_encryption_cb, airpcap_tb);

          if_label_text = g_strdup_printf("Current Wireless Interface: #%s", airpcap_get_if_string_number(if_info));
          gtk_label_set_text(GTK_LABEL(airpcap_toolbar_label),if_label_text);
          g_free(if_label_text);

          change_airpcap_settings = FALSE;
          if (if_info->pSupportedChannels != NULL && if_info->numSupportedChannels > 0){
              guint i = 0;

              for (; i<if_info->numSupportedChannels; i++){
                  gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(toolbar_channel_cb), ieee80211_mhz_to_str(if_info->pSupportedChannels[i].Frequency));
              }
          }

          airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cb),if_info);
          airpcap_update_channel_offset_combo(if_info, if_info->channelInfo.Frequency, airpcap_toolbar_channel_offset, TRUE);
          change_airpcap_settings = TRUE;
      }
    else
    {
          gtk_widget_set_sensitive(airpcap_tb,TRUE);
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
    gchar*         s = NULL;
    unsigned int i,n;
    airpcap_if_info_t* fake_if_info;
    GList*         wireshark_key_list=NULL;
    decryption_key_t* curr_key = NULL;
    GtkTreeIter    iter;

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
            gtk_list_store_insert_with_values(key_list_store , &iter, G_MAXINT,
                KL_COL_TYPE, AIRPCAP_WEP_KEY_STRING,
                KL_COL_KEY, curr_key->key->str,
                KL_COL_SSID, "",
                -1);
        }
        else if(curr_key->type == AIRPDCAP_KEY_TYPE_WPA_PWD)
        {
            if(curr_key->ssid != NULL)
                s = format_uri(curr_key->ssid, ":");
            else
                s = "";

            gtk_list_store_insert_with_values(key_list_store , &iter, G_MAXINT,
                KL_COL_TYPE, AIRPCAP_WPA_PWD_KEY_STRING,
                KL_COL_KEY, curr_key->key->str,
                KL_COL_SSID, s,
                -1);

        }
        else if(curr_key->type == AIRPDCAP_KEY_TYPE_WPA_PMK)
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
    if(!(g_ascii_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_ALL,name)))
    {
        return AIRPCAP_VT_ACCEPT_EVERYTHING;
    }
    else if(!(g_ascii_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_CORRECT,name)))
    {
        return AIRPCAP_VT_ACCEPT_CORRECT_FRAMES;
    }
    else if(!(g_ascii_strcasecmp(AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT,name)))
    {
        return AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES;
    }
    return AIRPCAP_VT_UNKNOWN;
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
    if(!(g_ascii_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_ONLY,name))){
        return AIRPCAP_LT_802_11;
    }else if(!(g_ascii_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO,name))){
        return AIRPCAP_LT_802_11_PLUS_RADIO;
    }else if(!(g_ascii_strcasecmp(AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_PPI,name))){
        return AIRPCAP_LT_802_11_PLUS_PPI;
    }else{
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
    if(lt == AIRPCAP_LT_802_11){
        return AIRPCAP_LINK_TYPE_NAME_802_11_ONLY;
    }else if(lt == AIRPCAP_LT_802_11_PLUS_RADIO){
        return AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO;
    }else if(lt == AIRPCAP_LT_802_11_PLUS_PPI){
        return AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_PPI;
    }else if(lt == AIRPCAP_LT_UNKNOWN){
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

    if (if_info != NULL){
        ad = airpcap_if_open(if_info->name, ebuf);

        if(ad != NULL) {
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
    int offset;
    gchar *off_str;
    int retval = 0;


    if (channel_offset_cb == NULL || !gtk_widget_get_sensitive(channel_offset_cb)) {
        return 0;
    }

    off_str = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(channel_offset_cb));
    if (off_str && (g_ascii_strcasecmp("", off_str)))
    {
        if (airpcap_if_selected != NULL)
        {
            sscanf(off_str, "%d", &offset);
            if (offset >= -1 && offset <= 1) {
                retval = offset;
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
    if (!airpcap_update_frequency_and_offset(airpcap_if_selected)){
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
    gint current_offset;
    gint new_offset;
    guint i;
    gint active_idx = 0;
    gint idx_count = -1;

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
            if ((if_info->pSupportedChannels[i].Flags & FLAG_CAN_BE_HIGH)){
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
        if (!airpcap_update_frequency_and_offset(if_info)){
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
    if(g_ascii_strcasecmp(if_info->name,AIRPCAP_DEVICE_ANY_EXTRACT_STRING)==0)
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
    if(!if_info || airpcap_if_is_any(if_info) || !airpcap_if_selected)
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

        if (if_info != NULL && if_info->pSupportedChannels != NULL && if_info->numSupportedChannels > 0){
            guint i;
            for (i = 0; i<(if_info->numSupportedChannels); i++){
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
    GtkTreePath *path;
    GtkTreeIter iter;
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

    if(fake_if_info == NULL)
        return;

    keys_in_list = gtk_tree_model_iter_n_children(model, NULL);

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

        if(g_ascii_strcasecmp(row_type,AIRPCAP_WEP_KEY_STRING) == 0)
            KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WEP;
        else if(g_ascii_strcasecmp(row_type,AIRPCAP_WPA_PWD_KEY_STRING) == 0)
            KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WPA_PWD;
        else if(g_ascii_strcasecmp(row_type,AIRPCAP_WPA_BIN_KEY_STRING) == 0)
            KeysCollection->Keys[i].KeyType = AIRPDCAP_KEY_TYPE_WPA_PMK;

        /* Retrieve the Item corresponding to the i-th key */
        key_len = strlen(row_key);

        KeysCollection->Keys[i].KeyLen = (guint) key_len / 2;
        memset(&KeysCollection->Keys[i].KeyData, 0, sizeof(KeysCollection->Keys[i].KeyData));

        /* Key must be saved in adifferent way, depending on its type... */
        if(KeysCollection->Keys[i].KeyType == AIRPDCAP_KEY_TYPE_WEP)
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
airpcap_read_and_save_decryption_keys_from_list_store(GtkListStore* key_list_store, airpcap_if_info_t* info_if, GList* if_list)
{
    GtkTreeIter iter;
    GtkTreeModel *model = GTK_TREE_MODEL(key_list_store);
    gboolean items_left;
    gint if_n = 0;
    gint i = 0;
    gint r = 0;
    airpcap_if_info_t* curr_if = NULL;
    airpcap_if_info_t* fake_info_if = NULL;
    GList* key_list=NULL;

    char* tmp_type = NULL;
    char* tmp_key = NULL;
    char* tmp_ssid = "";

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

        if(g_ascii_strcasecmp(tmp_type, AIRPCAP_WEP_KEY_STRING) == 0)
        {
            tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
            tmp_dk->key = g_string_new(tmp_key);
            tmp_dk->ssid = NULL;
            tmp_dk->type = AIRPDCAP_KEY_TYPE_WEP;
            tmp_dk->bits = (guint) tmp_dk->key->len * 4;
            key_list = g_list_append(key_list,tmp_dk);
        }
        else if(g_ascii_strcasecmp(tmp_type, AIRPCAP_WPA_PWD_KEY_STRING) == 0)
        {
            tmp_dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));
            tmp_dk->key = g_string_new(tmp_key);
            tmp_dk->ssid = g_byte_array_new();
            uri_str_to_bytes(tmp_ssid, tmp_dk->ssid);
            tmp_dk->type = AIRPDCAP_KEY_TYPE_WPA_PWD;
            tmp_dk->bits = 256;
            key_list = g_list_append(key_list,tmp_dk);
        }
        else if(g_ascii_strcasecmp(tmp_type, AIRPCAP_WPA_BIN_KEY_STRING) == 0)
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

    r = save_wlan_wireshark_wep_keys(key_list);
    /* The key_list has been freed!!! */

    /*
     * Save the key list for driver.
     */
    if( (if_list == NULL) || (info_if == NULL) ) return;

    fake_info_if = airpcap_driver_fake_if_info_new();

    airpcap_add_keys_to_driver_from_list(key_list_store,fake_info_if);
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
        equals &= adapters_keys_equals;        /* */

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

    if(w == NULL)
        return;

    toolbar_tb = w;

    if_description_lb   = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_INTERFACE_KEY);
    channel_lb          = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY);
    toolbar_channel_cb  = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_KEY);
    channel_offset_cb   = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY);
    channel_offset_lb   = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY);
    fcs_lb              = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY);
    fcs_cb              = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_FCS_FILTER_KEY);
    advanced_bt         = g_object_get_data(G_OBJECT(toolbar_tb),AIRPCAP_TOOLBAR_ADVANCED_KEY);


    if(if_description_lb != NULL)
        gtk_widget_set_sensitive(if_description_lb,en);
    if(channel_lb != NULL)
        gtk_widget_set_sensitive(channel_lb,en);
    if(toolbar_channel_cb != NULL)
        gtk_widget_set_sensitive(toolbar_channel_cb,en);
    if(channel_offset_cb != NULL)
        gtk_widget_set_sensitive(channel_offset_cb,en);
    if(channel_offset_lb != NULL)
        gtk_widget_set_sensitive(channel_offset_lb,en);
    if(fcs_lb != NULL)
        gtk_widget_set_sensitive(fcs_lb,en);
    if(fcs_cb != NULL)
        gtk_widget_set_sensitive(fcs_cb,en);
    if(advanced_bt != NULL)
        gtk_widget_set_sensitive(advanced_bt,en);

    return;
}

#endif /* HAVE_AIRPCAP */

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
