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

#include <string.h>

#include <epan/filesystem.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/frequency-utils.h>
#include <epan/crypt/wep-wpadefs.h>

#include <pcap.h>

#include "ui/simple_dialog.h"

#include "ui/gtk/main.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dfilter_expr_dlg.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/old-gtk-compat.h"

#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"
#include "airpcap_dlg.h"

/*
 * This structure is used because we need to store infos about the currently selected
 * row in the key list.
 */
typedef struct{
    gint row;
}airpcap_key_ls_selected_info_t;

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
                      g_strerror(errno));
        g_free(pf_dir_path);
    } else {
        /* Write the preferencs out. */
        err = write_prefs(&pf_path);
        if (err != 0) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                          "Can't open preferences file\n\"%s\": %s.", pf_path,
                          g_strerror(err));
            g_free(pf_path);
        }
    }
}

/*
 * Callback for the select row event in the key list widget
 */
static void
on_key_list_select_row(GtkTreeSelection *selection, gpointer data)
{
    GtkWidget *add_new_key_bt, *edit_key_bt, *remove_key_bt;
    GtkWidget *move_key_up_bt, *move_key_down_bt;
    GtkTreeIter iter;
    GtkTreeModel *model;
    GtkTreePath *path, *path_up, *path_down;

    add_new_key_bt = g_object_get_data(G_OBJECT(data), AIRPCAP_KEY_MGMT_NEW_KEY);
    edit_key_bt = g_object_get_data(G_OBJECT(data), AIRPCAP_KEY_MGMT_EDIT_KEY);
    remove_key_bt = g_object_get_data(G_OBJECT(data), AIRPCAP_KEY_MGMT_DELETE_KEY);
    move_key_up_bt = g_object_get_data(G_OBJECT(data), AIRPCAP_KEY_MGMT_UP_KEY);
    move_key_down_bt = g_object_get_data(G_OBJECT(data), AIRPCAP_KEY_MGMT_DOWN_KEY);

    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        path = gtk_tree_model_get_path(model, &iter);
        path_up = gtk_tree_path_copy(path);
        path_down = gtk_tree_path_copy(path);
        gtk_tree_path_next(path_down);

        if (gtk_tree_model_iter_n_children(model, NULL) >= MAX_ENCRYPTION_KEYS) {
            gtk_widget_set_sensitive(add_new_key_bt, FALSE);
        } else {
            gtk_widget_set_sensitive(add_new_key_bt, TRUE);
        }

        gtk_widget_set_sensitive(edit_key_bt, TRUE);
        gtk_widget_set_sensitive(remove_key_bt, TRUE);

        /* ...and we have to use two different methods to figure out first/last because? */
        if (gtk_tree_path_prev(path_up)) {
            gtk_widget_set_sensitive(move_key_up_bt, TRUE);
        } else {
            gtk_widget_set_sensitive(move_key_up_bt, FALSE);
        }

        if (gtk_tree_model_get_iter(model, &iter, path_down)) {
            gtk_widget_set_sensitive(move_key_down_bt, TRUE);
        } else {
            gtk_widget_set_sensitive(move_key_down_bt, FALSE);
        }

        gtk_tree_path_free(path);
        gtk_tree_path_free(path_up);
        gtk_tree_path_free(path_down);
    } else {
        gtk_widget_set_sensitive(add_new_key_bt, FALSE);
        gtk_widget_set_sensitive(edit_key_bt, FALSE);
        gtk_widget_set_sensitive(remove_key_bt, FALSE);
        gtk_widget_set_sensitive(move_key_up_bt, FALSE);
        gtk_widget_set_sensitive(move_key_down_bt, FALSE);
    }
}
/*
 * Callback for the select row event in the key list widget
 */
static void
on_key_list_reorder(GtkTreeModel *model _U_, GtkTreePath *path _U_, GtkTreeIter *iter _U_, gpointer no _U_, gpointer data) {
    GtkTreeSelection *selection;

    selection = g_object_get_data(G_OBJECT(data), AIRPCAP_ADVANCED_EDIT_KEY_SELECTION_KEY);
    on_key_list_select_row(selection, data);
}

/*
 * Callback for the crc checkbox
 */
static void
on_fcs_ck_toggled(GtkWidget *w _U_, gpointer user_data _U_)

{
    if (airpcap_if_selected != NULL)
    {
        if (airpcap_if_selected->IsFcsPresent)
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
on_edit_type_cb_changed(GtkWidget *w, gpointer data)
{
    GtkWidget *edit_key_w;
    GtkWidget *edit_ssid_te;
    GtkWidget *type_cb;
    GtkWidget *key_lb;
    GtkWidget *ssid_lb;

    gchar* type_text = NULL;

    edit_key_w = GTK_WIDGET(data);
    type_cb    = w;

    edit_ssid_te = g_object_get_data(G_OBJECT(edit_key_w),AIRPCAP_ADVANCED_EDIT_KEY_SSID_KEY);
    key_lb = g_object_get_data(G_OBJECT(edit_key_w),AIRPCAP_ADVANCED_EDIT_KEY_KEY_LABEL_KEY);
    ssid_lb = g_object_get_data(G_OBJECT(edit_key_w),AIRPCAP_ADVANCED_EDIT_KEY_SSID_LABEL_KEY);

    type_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(type_cb));

    if (g_ascii_strcasecmp(type_text, ""))
    {
        /*
         * If it is a WEP key, no SSID is required! Gray out the entry text so
         * it doesn't create confusion ...
         */
        if (g_ascii_strcasecmp(type_text,AIRPCAP_WEP_KEY_STRING) == 0)
        {
            gtk_widget_set_sensitive(edit_ssid_te,FALSE);
            /*
             * Maybe the user has already entered some text into the SSID field
             * and then switched to WEP...
             */
            gtk_entry_set_text(GTK_ENTRY(edit_ssid_te),"");
            gtk_label_set_text(GTK_LABEL(key_lb),"Key");
            gtk_label_set_text(GTK_LABEL(ssid_lb),"");
        }
        else if (g_ascii_strcasecmp(type_text,AIRPCAP_WPA_BIN_KEY_STRING) == 0)
        {
            gtk_widget_set_sensitive(edit_ssid_te,FALSE);
            /*
             * Maybe the user has already entered some text into the SSID field
             * and then switched to WPA...
             */
            gtk_entry_set_text(GTK_ENTRY(edit_ssid_te),"");
            gtk_label_set_text(GTK_LABEL(key_lb),"Key");
            gtk_label_set_text(GTK_LABEL(ssid_lb),"");
        }
        else if (g_ascii_strcasecmp(type_text,AIRPCAP_WPA_PWD_KEY_STRING) == 0)
        {
            gtk_widget_set_sensitive(edit_ssid_te,TRUE);
            /*
             * Maybe the user has already entered some text into the SSID field
             * and then switched to WPA...
             */
            gtk_entry_set_text(GTK_ENTRY(edit_ssid_te),"");
            gtk_label_set_text(GTK_LABEL(key_lb),"Passphrase");
            gtk_label_set_text(GTK_LABEL(ssid_lb),"SSID");
        }
    }
    gtk_widget_show(edit_ssid_te);

    g_free(type_text);
}

/*
 * Callback for the wrong crc combo
 */
static void
on_add_type_cb_changed(GtkWidget *w, gpointer data)
{
    GtkWidget *add_key_w;
    GtkWidget *add_ssid_te;
    GtkWidget *type_cb;
    GtkWidget *key_lb;
    GtkWidget *ssid_lb;

    gchar* type_text = NULL;

    add_key_w = GTK_WIDGET(data);
    type_cb   = w;

    add_ssid_te = g_object_get_data(G_OBJECT(add_key_w),AIRPCAP_ADVANCED_ADD_KEY_SSID_KEY);
    key_lb = g_object_get_data(G_OBJECT(add_key_w),AIRPCAP_ADVANCED_ADD_KEY_KEY_LABEL_KEY);
    ssid_lb = g_object_get_data(G_OBJECT(add_key_w),AIRPCAP_ADVANCED_ADD_KEY_SSID_LABEL_KEY);

    type_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(type_cb));

    if (g_ascii_strcasecmp(type_text, ""))
    {
        /*
         * If it is a WEP key, no SSID is required! Gray out rhe entry text so
         * it doesn't create confusion ...
         */
        if (g_ascii_strcasecmp(type_text,AIRPCAP_WEP_KEY_STRING) == 0)
        {
            gtk_widget_set_sensitive(add_ssid_te,FALSE);
            /*
             * Maybe the user has already entered some text into the SSID field
             * and then switched to WEP...
             */
            gtk_entry_set_text(GTK_ENTRY(add_ssid_te),"");
            gtk_label_set_text(GTK_LABEL(key_lb),"Key");
            gtk_label_set_text(GTK_LABEL(ssid_lb),"");
        }
        else if (g_ascii_strcasecmp(type_text,AIRPCAP_WPA_BIN_KEY_STRING) == 0)
        {
            gtk_widget_set_sensitive(add_ssid_te,FALSE);
            /*
             * Maybe the user has already entered some text into the SSID field
             * and then switched to WPA...
             */
            gtk_entry_set_text(GTK_ENTRY(add_ssid_te),"");
            gtk_label_set_text(GTK_LABEL(key_lb),"Key");
            gtk_label_set_text(GTK_LABEL(ssid_lb),"");
        }
        else if (g_ascii_strcasecmp(type_text,AIRPCAP_WPA_PWD_KEY_STRING) == 0)
        {
            gtk_widget_set_sensitive(add_ssid_te,TRUE);
            /*
             * Maybe the user has already entered some text into the SSID field
             * and then switched to WPA...
             */
            gtk_entry_set_text(GTK_ENTRY(add_ssid_te),"");
            gtk_label_set_text(GTK_LABEL(key_lb),"Passphrase");
            gtk_label_set_text(GTK_LABEL(ssid_lb),"SSID");
        }
    }
    gtk_widget_show(add_ssid_te);

    g_free(type_text);
}

/*
 * Callback for the wrong crc combo
 */
static void
on_fcs_filter_cb_changed(GtkWidget *fcs_filter_cb, gpointer data _U_)
{
    gchar *fcs_filter_str;

    if (fcs_filter_cb != NULL)
    {
        fcs_filter_str = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb));
        if (fcs_filter_str && (g_ascii_strcasecmp("", fcs_filter_str)))
        {
            airpcap_if_selected->CrcValidationOn = airpcap_get_validation_type(fcs_filter_str);
            airpcap_if_selected->saved = FALSE;
        }
        g_free(fcs_filter_str);
    }
}


/*
 * Changed callback for the capture type combobox
 */
static void
on_capture_type_cb_changed(GtkWidget *cb, gpointer user_data _U_)
{
    gchar *s;

    if (cb == NULL) {
        return;
    }

    s = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(cb));

    if ((g_ascii_strcasecmp("",s)))
    {
        airpcap_if_selected->linkType = airpcap_get_link_type(s);
        airpcap_if_selected->saved = FALSE;
    }
    g_free(s);
}

/*
 * Thread function used to blink the led
 */
static gboolean
update_blink(gpointer data)
{
    airpcap_if_info_t* sel;
    PAirpcapHandle ad;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];

    sel = (airpcap_if_info_t*)data;

    ad = airpcap_if_open(sel->name, ebuf);
    if (ad)
    {
        if (sel->led)
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
    return TRUE;
}

/*
 * Blink button callback
 */
static void
on_blink_bt_clicked( GtkWidget *blink_bt, gpointer data _U_)
{
    PAirpcapHandle ad = NULL;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];

    if (airpcap_if_selected != NULL) {
        if (!(airpcap_if_selected->blinking))
        {
            gtk_button_set_label(GTK_BUTTON(blink_bt),"Stop Blinking");
            airpcap_if_selected->tag = g_timeout_add(500,update_blink,airpcap_if_selected);
            airpcap_if_selected->blinking = TRUE;
        }
        else
        {
            gtk_button_set_label(GTK_BUTTON(blink_bt),"  Blink Led  ");
            g_source_remove(airpcap_if_selected->tag);
            airpcap_if_selected->blinking = FALSE;
            /* Switch on the led!  */
            ad = airpcap_if_open(airpcap_if_selected->name, ebuf);
            if (ad)
            {
                g_source_remove(airpcap_if_selected->tag);
                airpcap_if_turn_led_on(ad, 0);
                airpcap_if_selected->blinking = FALSE;
                airpcap_if_selected->led = TRUE;
                airpcap_if_close(ad);
            }
        }
    }
}

/*
 * Callback for the 'Any' adapter What's This button.
 */
static void
on_what_s_this_bt_clicked( GtkWidget *blink_bt _U_, gpointer data _U_)
{
    simple_dialog(ESD_TYPE_INFO,ESD_BTN_OK,
                  "The Multi-Channel Aggregator is a virtual device "
                  "that can be used to capture packets from all the "
                  "AirPcap adapters at the same time.\n"
                  "The Capture Type, FCS and Encryption settings of "
                  "this virtual device can be configured as for any "
                  "real adapter.\nThe channel cannot be changed for "
                  "this adapter.\n"
                  "Refer to the AirPcap manual for more information.");
}

/* the window was closed, cleanup things */
static void
on_key_management_destroy(GtkWidget *w _U_, gpointer data)
{
    GtkWidget *airpcap_advanced_w,
              *toolbar;

    gint *from_widget = NULL;

    /* Retrieve the GUI object pointers */
    airpcap_advanced_w = GTK_WIDGET(data);

    toolbar = GTK_WIDGET(g_object_get_data(G_OBJECT(airpcap_advanced_w),AIRPCAP_TOOLBAR_KEY));

    /* ... */
    from_widget = (gint*)g_object_get_data(G_OBJECT(toolbar),AIRPCAP_ADVANCED_FROM_KEY);
    /* gray out the toolbar (if we came here from the toolbar advanced button)*/
    if ( *from_widget == AIRPCAP_ADVANCED_FROM_TOOLBAR)
        gtk_widget_set_sensitive(toolbar,TRUE);
    else
        gtk_widget_set_sensitive(toolbar,FALSE);

    g_free(from_widget);

    /* reload the configuration!!! Configuration has not been saved but
    the corresponding structure has been modified probably...*/
    if (airpcap_if_selected != NULL)
    {
        if (!airpcap_if_selected->saved)
        {
            airpcap_load_selected_if_configuration(airpcap_if_selected);
        }
    }

}

/* the Advenced wireless Settings window was closed, cleanup things */
static void
on_airpcap_advanced_destroy(GtkWidget *w _U_, gpointer data)
{
    GtkWidget *airpcap_advanced_w,
              *toolbar;

    gint *from_widget = NULL;

    /* Retrieve the GUI object pointers */
    airpcap_advanced_w = GTK_WIDGET(data);

    toolbar = GTK_WIDGET(g_object_get_data(G_OBJECT(airpcap_advanced_w),AIRPCAP_TOOLBAR_KEY));

    /* ... */
    from_widget = (gint*)g_object_get_data(G_OBJECT(toolbar),AIRPCAP_ADVANCED_FROM_KEY);
    /* gray out the toolbar (if we came here from the toolbar advanced button)*/
    if ( *from_widget == AIRPCAP_ADVANCED_FROM_TOOLBAR)
        gtk_widget_set_sensitive(toolbar,TRUE);
    else
        gtk_widget_set_sensitive(toolbar,FALSE);

    g_free(from_widget);

    /* reload the configuration!!! Configuration has not been saved but
    the corresponding structure has been modified probably...*/
    if (!airpcap_if_selected->saved)
    {
        airpcap_load_selected_if_configuration(airpcap_if_selected);
    }
}

/*
 * Callback for the 'Apply' button.
 */
/*
 * XXX - Pressing 'Apply' has the same effect as pressing 'OK' -- you
 * can't revert back to the old set of keys by pressing 'Cancel'.  We
 * either need to fix reversion or get rid of the 'Apply' button.
 */
static void
on_key_management_apply_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    /* advenced window */
    GtkWidget   *key_management_w;

    /* widgets in the toolbar */
    GtkWidget   *toolbar_cb;
    GtkWidget   *decryption_mode_cb;

    GtkListStore *key_list_store;

    module_t *wlan_module = prefs_find_module("wlan");
    gchar *decryption_mode_string;

    /* retrieve main window */
    key_management_w      = GTK_WIDGET(data);
    decryption_mode_cb    = GTK_WIDGET(g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_ADVANCED_DECRYPTION_MODE_KEY));
    key_list_store        = GTK_LIST_STORE(g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_ADVANCED_KEYLIST_KEY));
    toolbar_cb            = GTK_WIDGET(g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_TOOLBAR_DECRYPTION_KEY));

#define CANT_SAVE_ERR_STR "Cannot save configuration! Another application " \
    "might be using AirPcap, or you might not have sufficient privileges."
    /* Set the Decryption Mode */

    decryption_mode_string = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(decryption_mode_cb));
    if (g_ascii_strcasecmp(decryption_mode_string, AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK) == 0)
    {
        set_wireshark_decryption(TRUE);
        if (!set_airpcap_decryption(FALSE)) g_warning(CANT_SAVE_ERR_STR);
    }
    else if (g_ascii_strcasecmp(decryption_mode_string, AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP) == 0)
    {
        set_wireshark_decryption(FALSE);
        if (!set_airpcap_decryption(TRUE)) g_warning(CANT_SAVE_ERR_STR);
    }
    else if (g_ascii_strcasecmp(decryption_mode_string, AIRPCAP_DECRYPTION_TYPE_STRING_NONE) == 0)
    {
        set_wireshark_decryption(FALSE);
        if (!set_airpcap_decryption(FALSE)) g_warning(CANT_SAVE_ERR_STR);
    }
    g_free(decryption_mode_string);

    /* Save the configuration */
    airpcap_read_and_save_decryption_keys_from_list_store(key_list_store,airpcap_if_selected,airpcap_if_list); /* This will save the keys for every adapter */

    /* The update will make redissect al the packets... no need to do it here again */
    update_decryption_mode(toolbar_cb);

    /* Redissect all the packets, and re-evaluate the display filter. */
    prefs_apply(wlan_module);
}

/*
 * Callback used to add a WEP key in the add new key box;
 */
static void
on_add_key_ok_bt_clicked(GtkWidget *widget _U_, gpointer data)
{
    GtkWidget   *type_cb,
                *key_en,
                *ssid_en;

    GtkListStore *key_list_store;

    GString     *new_type_string,
                *new_key_string,
                *new_ssid_string;

    gchar       *type_entered = NULL;
    gchar       *key_entered = NULL;
    gchar       *ssid_entered = NULL;

    unsigned int i;

    key_list_store = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_ADD_KEY_LIST_KEY);
    type_cb = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_ADD_KEY_TYPE_KEY);
    key_en = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_ADD_KEY_KEY_KEY);
    ssid_en = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_ADD_KEY_SSID_KEY);

    type_entered = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(type_cb));
    key_entered  = g_strdup(gtk_entry_get_text(GTK_ENTRY(key_en)));
    ssid_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(ssid_en)));

    /* Check if key is correct */
    new_type_string = g_string_new(type_entered);
    new_key_string = g_string_new(key_entered);
    new_ssid_string = g_string_new(ssid_entered);

    g_free(type_entered);
    g_free(key_entered );
    g_free(ssid_entered);

    g_strstrip(new_key_string->str);
    g_strstrip(new_ssid_string->str);

    /* Check which type of key the user has entered */
    if (g_ascii_strcasecmp(new_type_string->str,AIRPCAP_WEP_KEY_STRING) == 0) /* WEP key */
    {

        if ( ((new_key_string->len) > WEP_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < WEP_KEY_MIN_CHAR_SIZE))
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WEP key size out of range!\nValid key size range is %d-%d characters (%d-%d bits).",WEP_KEY_MIN_CHAR_SIZE,WEP_KEY_MAX_CHAR_SIZE,WEP_KEY_MIN_BIT_SIZE,WEP_KEY_MAX_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        if ((new_key_string->len % 2) != 0)
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nThe number of characters must be even.");

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        for (i = 0; i < new_key_string->len; i++)
        {
            if (!g_ascii_isxdigit(new_key_string->str[i]))
            {
                simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nA WEP key must be a hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.");

                g_string_free(new_type_string,TRUE);
                g_string_free(new_key_string, TRUE);
                g_string_free(new_ssid_string,TRUE);

                return;
            }
        }

        /* If so... add key */
        airpcap_add_key_to_list(key_list_store, new_type_string->str, new_key_string->str, new_ssid_string->str);

        if (airpcap_if_selected != NULL) airpcap_if_selected->saved = FALSE;
    }
    else if (g_ascii_strcasecmp(new_type_string->str,AIRPCAP_WPA_PWD_KEY_STRING) == 0) /* WPA Key */
    {
        /* XXX - Perform some WPA related input fields check */
        /* If everything is ok, modify the entry in the list */

        if ( ((new_key_string->len) > WPA_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < WPA_KEY_MIN_CHAR_SIZE))
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WPA key size out of range!\nValid key size range is %d-%d ASCII characters (%d-%d bits).",WPA_KEY_MIN_CHAR_SIZE,WPA_KEY_MAX_CHAR_SIZE,WPA_KEY_MIN_BIT_SIZE,WPA_KEY_MAX_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        /*
         * XXX - Maybe we need some check on the characters? I'm not sure if only standard ASCII are ok...
         */
        if ((new_ssid_string->len) > WPA_SSID_MAX_CHAR_SIZE)
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"SSID key size out of range!\nValid SSID size range is %d-%d ASCII characters (%d-%d bits).",WPA_SSID_MIN_CHAR_SIZE,WPA_SSID_MAX_CHAR_SIZE,WPA_SSID_MIN_BIT_SIZE,WPA_SSID_MAX_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        /* If so... add key */
        airpcap_add_key_to_list(key_list_store, new_type_string->str, new_key_string->str, new_ssid_string->str);

        if (airpcap_if_selected != NULL) airpcap_if_selected->saved = FALSE;
    }
    else if (g_ascii_strcasecmp(new_type_string->str,AIRPCAP_WPA_BIN_KEY_STRING) == 0) /* WPA_BIN Key */
    {
        /* XXX - Perform some WPA_BIN related input fields check */
        /* If everything is ok, modify the entry int he list */

        if ( ((new_key_string->len) != WPA_PSK_KEY_CHAR_SIZE))
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WPA PSK/PMK key size is wrong!\nValid key size is %d characters (%d bits).",WPA_PSK_KEY_CHAR_SIZE,WPA_PSK_KEY_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        for (i = 0; i < new_key_string->len; i++)
        {
            if (!g_ascii_isxdigit(new_key_string->str[i]))
            {
                simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WPA PSK/PMK key!\nKey must be an hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.");

                g_string_free(new_type_string,TRUE);
                g_string_free(new_key_string, TRUE);
                g_string_free(new_ssid_string,TRUE);

                return;
            }
        }

        /* If so... add key */
        airpcap_add_key_to_list(key_list_store, new_type_string->str, new_key_string->str, new_ssid_string->str);

        if (airpcap_if_selected != NULL) airpcap_if_selected->saved = FALSE;
    }
    else /* Should never happen!!! */
    {
        simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Unknown error in the key \"Type\" field!");
    }

    g_string_free(new_type_string,TRUE);
    g_string_free(new_key_string, TRUE);
    g_string_free(new_ssid_string,TRUE);

    window_destroy(GTK_WIDGET(data));
    return;
}

/*
 * Callback used to edit a WEP key in the edit key box;
 */
static void
on_edit_key_ok_bt_clicked(GtkWidget *widget _U_, gpointer data)
{
    GtkWidget   *type_cb,
                *key_en,
                *ssid_en;

    GtkListStore *key_list_store;
    GtkTreeSelection *selection;
    GtkTreeIter iter;

    GString     *new_type_string,
                *new_key_string,
                *new_ssid_string;

    gchar       *type_entered = NULL;
    gchar       *key_entered = NULL;
    gchar       *ssid_entered = NULL;

    unsigned int i;

    key_list_store = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_EDIT_KEY_LIST_KEY);
    selection = g_object_get_data(G_OBJECT(data), AIRPCAP_ADVANCED_EDIT_KEY_SELECTION_KEY);
    type_cb = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_EDIT_KEY_TYPE_KEY);
    key_en = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_EDIT_KEY_KEY_KEY);
    ssid_en = g_object_get_data(G_OBJECT(data),AIRPCAP_ADVANCED_EDIT_KEY_SSID_KEY);

    if (!gtk_tree_selection_get_selected(selection, NULL, &iter))
      return;

    type_entered = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(type_cb));
    key_entered  = g_strdup(gtk_entry_get_text(GTK_ENTRY(key_en)));
    ssid_entered = g_strdup(gtk_entry_get_text(GTK_ENTRY(ssid_en)));

    g_strstrip(key_entered);
    g_strstrip(ssid_entered);

    /* Check if key is correct */
    new_type_string = g_string_new(type_entered);
    new_key_string = g_string_new(key_entered);
    new_ssid_string = g_string_new(ssid_entered);

    g_free(type_entered);
    g_free(key_entered );
    g_free(ssid_entered);

    /* Check which type of key the user has entered */
    if (g_ascii_strcasecmp(new_type_string->str,AIRPCAP_WEP_KEY_STRING) == 0) /* WEP key */
    {

        if ( ((new_key_string->len) > WEP_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < WEP_KEY_MIN_CHAR_SIZE))
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WEP key size out of range!\nValid key size range is %d-%d characters (%d-%d bits).",WEP_KEY_MIN_CHAR_SIZE,WEP_KEY_MAX_CHAR_SIZE,WEP_KEY_MIN_BIT_SIZE,WEP_KEY_MAX_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        if ((new_key_string->len % 2) != 0)
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nThe number of characters must be even.");

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        for (i = 0; i < new_key_string->len; i++)
        {
            if (!g_ascii_isxdigit(new_key_string->str[i]))
            {
                simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WEP key!\nA WEP key must be an hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.");

                g_string_free(new_type_string,TRUE);
                g_string_free(new_key_string, TRUE);
                g_string_free(new_ssid_string,TRUE);

                return;
            }
        }

        /* If so... Modify key */
        gtk_list_store_set(key_list_store, &iter,
            KL_COL_TYPE, new_type_string->str,
            KL_COL_KEY, new_key_string->str,
            KL_COL_SSID, new_ssid_string->str,
            -1);

        if (airpcap_if_selected != NULL) airpcap_if_selected->saved = FALSE;
    }
    else if (g_ascii_strcasecmp(new_type_string->str,AIRPCAP_WPA_PWD_KEY_STRING) == 0) /* WPA Key */
    {
        /* XXX - Perform some WPA related input fields check */
        /* If everything is ok, modify the entry in the list */

        if ( ((new_key_string->len) > WPA_KEY_MAX_CHAR_SIZE) || ((new_key_string->len) < WPA_KEY_MIN_CHAR_SIZE))
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WPA key size out of range!\nValid key size range is %d-%d ASCII characters (%d-%d bits).",WPA_KEY_MIN_CHAR_SIZE,WPA_KEY_MAX_CHAR_SIZE,WPA_KEY_MIN_BIT_SIZE,WPA_KEY_MAX_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        /*
         * XXX - Maybe we need some check on the characters? I'm not sure if only standard ASCII are ok...
         */
        if ((new_ssid_string->len) > WPA_SSID_MAX_CHAR_SIZE)
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"SSID key size out of range!\nValid SSID size range is %d-%d ASCII characters (%d-%d bits).",WPA_SSID_MIN_CHAR_SIZE,WPA_SSID_MAX_CHAR_SIZE,WPA_SSID_MIN_BIT_SIZE,WPA_SSID_MAX_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        /* If so... Modify key */
        gtk_list_store_set(key_list_store, &iter,
            KL_COL_TYPE, new_type_string->str,
            KL_COL_KEY, new_key_string->str,
            KL_COL_SSID, new_ssid_string->str,
            -1);

        if (airpcap_if_selected != NULL) airpcap_if_selected->saved = FALSE;
    }
    else if (g_ascii_strcasecmp(new_type_string->str,AIRPCAP_WPA_BIN_KEY_STRING) == 0) /* WPA_BIN Key */
    {
        /* XXX - Perform some WPA_BIN related input fields check */
        /* If everything is ok, modify the entry in the list */

        if ( ((new_key_string->len) != WPA_PSK_KEY_CHAR_SIZE))
        {
            simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"WPA PSK/PMK key size is wrong!\nValid key size is %d characters (%d bits).",WPA_PSK_KEY_CHAR_SIZE,WPA_PSK_KEY_BIT_SIZE);

            g_string_free(new_type_string,TRUE);
            g_string_free(new_key_string, TRUE);
            g_string_free(new_ssid_string,TRUE);

            return;
        }

        for (i = 0; i < new_key_string->len; i++)
        {
            if (!g_ascii_isxdigit(new_key_string->str[i]))
            {
                simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Invalid WPA PSK/PMK key!\nKey must be an hexadecimal number.\nThe valid characters are: 0123456789ABCDEF.");

                g_string_free(new_type_string,TRUE);
                g_string_free(new_key_string, TRUE);
                g_string_free(new_ssid_string,TRUE);

                return;
            }
        }

        /* If so... Modify key */
        gtk_list_store_set(key_list_store, &iter,
            KL_COL_TYPE, new_type_string->str,
            KL_COL_KEY, new_key_string->str,
            KL_COL_SSID, new_ssid_string->str,
            -1);

        if (airpcap_if_selected != NULL) airpcap_if_selected->saved = FALSE;
    }
    else /* Should never happen!!! */
    {
        simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Unknown error in the key \"Type\" field!");
    }

    g_string_free(new_type_string,TRUE);
    g_string_free(new_key_string, TRUE);
    g_string_free(new_ssid_string,TRUE);

    window_destroy(GTK_WIDGET(data));
    return;
}

/*
 * Add key window destroy callback
 */
static void
on_add_key_w_destroy(GtkWidget *button _U_, gpointer data)
{
    GtkWidget *airpcap_advanced_w;

    airpcap_advanced_w = GTK_WIDGET(data);

    gtk_widget_set_sensitive(GTK_WIDGET(airpcap_advanced_w),TRUE);

    return;
}

/*
 * Callback for the 'Add Key' button.
 */
static void
on_add_new_key_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    GtkWidget *add_key_window;
    GtkWidget *add_frame;
    GtkWidget *main_v_box;
    GtkWidget *add_tb;
    GtkWidget *add_frame_al;
    GtkWidget *add_type_cb;
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

    GtkListStore *key_list_store;

    airpcap_advanced_w = GTK_WIDGET(data);

    key_list_store = g_object_get_data(G_OBJECT(airpcap_advanced_w),AIRPCAP_ADVANCED_KEYLIST_KEY);

    if (gtk_tree_model_iter_n_children(GTK_TREE_MODEL(key_list_store), NULL) >= MAX_ENCRYPTION_KEYS)
    {
        simple_dialog(ESD_TYPE_ERROR,ESD_BTN_OK,"Maximum number (%d) of decryption keys reached! You cannot add another key!\n",MAX_ENCRYPTION_KEYS);
        return;
    }

    /* Gray out the Advanced Wireless Setting window */
    gtk_widget_set_sensitive(airpcap_advanced_w,FALSE);

    /* Pop-up a new window */
    add_key_window = dlg_window_new ("Add Decryption Key");
    gtk_widget_set_name (add_key_window, "add_key_window");
    gtk_container_set_border_width (GTK_CONTAINER (add_key_window), 5);
    gtk_window_set_resizable (GTK_WINDOW (add_key_window), FALSE);

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
    gtk_alignment_set_padding (GTK_ALIGNMENT (add_frame_al), 0, 0, 12, 0);

    add_tb = gtk_table_new (2, 3, FALSE);
    gtk_widget_set_name (add_tb, "add_tb");
    gtk_container_set_border_width(GTK_CONTAINER(add_tb),5);
    gtk_widget_show (add_tb);
    gtk_container_add (GTK_CONTAINER (add_frame_al), add_tb);

    add_type_cb = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(add_type_cb), AIRPCAP_WEP_KEY_STRING);

    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(add_type_cb), AIRPCAP_WPA_PWD_KEY_STRING);
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(add_type_cb), AIRPCAP_WPA_BIN_KEY_STRING);
    gtk_combo_box_set_active(GTK_COMBO_BOX(add_type_cb), 0);
    gtk_widget_set_name (add_type_cb, "add_type_cb");
    gtk_widget_show (add_type_cb);
    gtk_table_attach (GTK_TABLE (add_tb), add_type_cb, 0, 1, 1, 2,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_widget_set_size_request (add_type_cb, 83, -1);

    add_key_te = gtk_entry_new ();
    gtk_widget_set_name (add_key_te, "add_key_te");

    gtk_widget_show (add_key_te);
    gtk_table_attach (GTK_TABLE (add_tb), add_key_te, 1, 2, 1, 2,
                      (GtkAttachOptions) (0), (GtkAttachOptions) (0), 0, 0);
    gtk_widget_set_size_request (add_key_te, 178, -1);

    add_ssid_te = gtk_entry_new ();
    gtk_widget_set_name (add_ssid_te, "add_ssid_te");
    gtk_widget_set_sensitive(add_ssid_te,FALSE);
    /* XXX - Decomment only when WPA and WPA_BIN will be ready */
    gtk_widget_show (add_ssid_te);
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

    add_ssid_lb = gtk_label_new ("");
    gtk_widget_set_name (add_ssid_lb, "add_ssid_lb");
    /* XXX - Decomment only when WPA and WPA_BIN will be ready */
    gtk_widget_show (add_ssid_lb);
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

    ok_bt = gtk_button_new_with_mnemonic ("OK");
    gtk_widget_set_name (ok_bt, "ok_bt");
    gtk_widget_show (ok_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), ok_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (ok_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);
#endif

    cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
    gtk_widget_set_name (cancel_bt, "cancel_bt");
    gtk_widget_show (cancel_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), cancel_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (cancel_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);
#endif

    add_frame_lb = gtk_label_new ("<b>Modify Selected Key</b>");
    gtk_widget_set_name (add_frame_lb, "add_frame_lb");
    gtk_widget_show (add_frame_lb);
    gtk_frame_set_label_widget (GTK_FRAME (add_frame), add_frame_lb);
    gtk_label_set_use_markup (GTK_LABEL (add_frame_lb), TRUE);

    /* Add callbacks */
    g_signal_connect(ok_bt, "clicked", G_CALLBACK(on_add_key_ok_bt_clicked), add_key_window );
    g_signal_connect(cancel_bt, "clicked", G_CALLBACK(window_cancel_button_cb), add_key_window );
    g_signal_connect(add_type_cb, "changed", G_CALLBACK(on_add_type_cb_changed), add_key_window);
    g_signal_connect(add_key_window, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(add_key_window, "destroy", G_CALLBACK(on_add_key_w_destroy), data);

    /* Add widget data */
    g_object_set_data(G_OBJECT(add_key_window),AIRPCAP_ADVANCED_ADD_KEY_LIST_KEY,key_list_store);
    g_object_set_data(G_OBJECT(add_key_window),AIRPCAP_ADVANCED_ADD_KEY_TYPE_KEY,add_type_cb);
    g_object_set_data(G_OBJECT(add_key_window),AIRPCAP_ADVANCED_ADD_KEY_KEY_KEY,add_key_te);
    g_object_set_data(G_OBJECT(add_key_window),AIRPCAP_ADVANCED_ADD_KEY_SSID_KEY,add_ssid_te);
    g_object_set_data(G_OBJECT(add_key_window),AIRPCAP_ADVANCED_ADD_KEY_KEY_LABEL_KEY,add_key_lb);
    g_object_set_data(G_OBJECT(add_key_window),AIRPCAP_ADVANCED_ADD_KEY_SSID_LABEL_KEY,add_ssid_lb);

    gtk_widget_show(add_key_window);
}

/*
 * Edit key window destroy callback
 */
static void
on_edit_key_w_destroy(GtkWidget *button _U_, gpointer data)
{
    GtkWidget *airpcap_advanced_w;

    airpcap_advanced_w = GTK_WIDGET(data);

    gtk_widget_set_sensitive(GTK_WIDGET(airpcap_advanced_w),TRUE);

    return;
}

/*
 * Callback for the 'Remove Key' button.
 */
static void
on_remove_key_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    GtkTreeModel *model;
    GtkTreeIter iter;
    GtkTreeSelection *selection;

    /* retrieve needed stuff */
    selection = g_object_get_data(G_OBJECT(data), AIRPCAP_ADVANCED_EDIT_KEY_SELECTION_KEY);

    if (!gtk_tree_selection_get_selected(selection, &model, &iter))
      return;

    /* Remove selected key */
    gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
    gtk_tree_selection_select_iter(selection, &iter);
    /* XXX - select the last item if needed? */

    /* Need to save config... */
    if (airpcap_if_selected != NULL) airpcap_if_selected->saved = FALSE;
}

/*
 * Callback for the 'Edit Key' button.
 */
static void
on_edit_key_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    GtkWidget *edit_key_window;
    GtkWidget *edit_frame;
    GtkWidget *main_v_box;
    GtkWidget *edit_tb;
    GtkWidget *edit_frame_al;
    GtkWidget *edit_type_cb;
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

    GtkTreeModel *model;
    GtkTreeIter iter;
    GtkTreeSelection *selection;

    /* Key List Store */
    GtkListStore *key_list_store;

    gchar *row_type,
          *row_key,
          *row_ssid = "";

    airpcap_advanced_w = GTK_WIDGET(data);

    /* Retrieve the selected item... if no row is selected, this is null... */
    selection = g_object_get_data(G_OBJECT(data), AIRPCAP_ADVANCED_EDIT_KEY_SELECTION_KEY);
    key_list_store = g_object_get_data (G_OBJECT(data), AIRPCAP_ADVANCED_KEYLIST_KEY);


    if (!gtk_tree_selection_get_selected(selection, &model, &iter))
      return;

    gtk_tree_model_get(model, &iter,
                       KL_COL_TYPE, &row_type,
                       KL_COL_KEY, &row_key,
                       KL_COL_SSID, &row_ssid,
                       -1);

    /* Gray out the Advanced Wireless Setting window */
    gtk_widget_set_sensitive(airpcap_advanced_w,FALSE);

    /* Pop-up a new window */
    edit_key_window = dlg_window_new("Edit Decryption Key");
    gtk_widget_set_name (edit_key_window, "edit_key_window");
    gtk_container_set_border_width (GTK_CONTAINER (edit_key_window), 5);
    gtk_window_set_resizable (GTK_WINDOW (edit_key_window), FALSE);

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
    gtk_alignment_set_padding (GTK_ALIGNMENT (edit_frame_al), 0, 0, 12, 0);

    edit_tb = gtk_table_new (2, 3, FALSE);
    gtk_widget_set_name (edit_tb, "edit_tb");
    gtk_container_set_border_width(GTK_CONTAINER(edit_tb),5);
    gtk_widget_show (edit_tb);
    gtk_container_add (GTK_CONTAINER (edit_frame_al), edit_tb);

    edit_type_cb = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(edit_type_cb), AIRPCAP_WEP_KEY_STRING);

    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(edit_type_cb), AIRPCAP_WPA_PWD_KEY_STRING);
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(edit_type_cb), AIRPCAP_WPA_BIN_KEY_STRING);
    /* Set current type */
    gtk_combo_box_set_active(GTK_COMBO_BOX(edit_type_cb), 0);
    if (g_ascii_strcasecmp(row_type, AIRPCAP_WPA_PWD_KEY_STRING) == 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(edit_type_cb), 1);
    } else if (g_ascii_strcasecmp(row_type, AIRPCAP_WPA_BIN_KEY_STRING) == 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(edit_type_cb), 2);
    }
    gtk_widget_set_name (edit_type_cb, "edit_type_cb");
    gtk_widget_show (edit_type_cb);
    gtk_table_attach (GTK_TABLE (edit_tb), edit_type_cb, 0, 1, 1, 2,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_widget_set_size_request (edit_type_cb, 83, -1);

    edit_key_te = gtk_entry_new ();
    gtk_widget_set_name (edit_key_te, "edit_key_te");
    /* Set current key */
    gtk_entry_set_text(GTK_ENTRY(edit_key_te),row_key);
    gtk_widget_show (edit_key_te);
    gtk_table_attach (GTK_TABLE (edit_tb), edit_key_te, 1, 2, 1, 2,
                      (GtkAttachOptions) (0), (GtkAttachOptions) (0), 0, 0);
    gtk_widget_set_size_request (edit_key_te, 178, -1);

    edit_ssid_te = gtk_entry_new ();
    gtk_widget_set_name (edit_ssid_te, "edit_ssid_te");

    /* Set current ssid (if key type is not WEP!)*/
    if (g_ascii_strcasecmp(row_type,AIRPCAP_WEP_KEY_STRING) == 0)
    {
        gtk_widget_set_sensitive(edit_ssid_te,FALSE);
    }
    else
    {
        gtk_widget_set_sensitive(edit_ssid_te,TRUE);
        gtk_entry_set_text(GTK_ENTRY(edit_ssid_te),row_ssid);
    }

    /* XXX - Decomment only when WPA and WPA@ will be ready */
    gtk_widget_show (edit_ssid_te);
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

    edit_ssid_lb = gtk_label_new ("");
    gtk_widget_set_name (edit_ssid_lb, "edit_ssid_lb");
    /* XXX - Decomment only when WPA and WPA_BIN will be ready */
    gtk_widget_show (edit_ssid_lb);
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

    ok_bt = gtk_button_new_with_mnemonic ("OK");
    gtk_widget_set_name (ok_bt, "ok_bt");
    gtk_widget_show (ok_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), ok_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (ok_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);
#endif

    cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
    gtk_widget_set_name (cancel_bt, "cancel_bt");
    gtk_widget_show (cancel_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), cancel_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (cancel_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);
#endif

    edit_frame_lb = gtk_label_new ("<b>Modify Selected Key</b>");
    gtk_widget_set_name (edit_frame_lb, "edit_frame_lb");
    gtk_widget_show (edit_frame_lb);
    gtk_frame_set_label_widget (GTK_FRAME (edit_frame), edit_frame_lb);
    gtk_label_set_use_markup (GTK_LABEL (edit_frame_lb), TRUE);

    /* Add callbacks */
    g_signal_connect(ok_bt, "clicked", G_CALLBACK(on_edit_key_ok_bt_clicked), edit_key_window );
    g_signal_connect(cancel_bt, "clicked", G_CALLBACK(window_cancel_button_cb), edit_key_window );
    g_signal_connect(edit_type_cb, "changed", G_CALLBACK(on_edit_type_cb_changed), edit_key_window);
    g_signal_connect(edit_key_window, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(edit_key_window, "destroy", G_CALLBACK(on_edit_key_w_destroy), data);

    /* Add widget data */
    g_object_set_data(G_OBJECT(edit_key_window),AIRPCAP_ADVANCED_EDIT_KEY_LIST_KEY,key_list_store);
    g_object_set_data(G_OBJECT(edit_key_window),AIRPCAP_ADVANCED_EDIT_KEY_SELECTION_KEY,selection);
    g_object_set_data(G_OBJECT(edit_key_window),AIRPCAP_ADVANCED_EDIT_KEY_TYPE_KEY,edit_type_cb);
    g_object_set_data(G_OBJECT(edit_key_window),AIRPCAP_ADVANCED_EDIT_KEY_KEY_KEY,edit_key_te);
    g_object_set_data(G_OBJECT(edit_key_window),AIRPCAP_ADVANCED_EDIT_KEY_SSID_KEY,edit_ssid_te);
    g_object_set_data(G_OBJECT(edit_key_window),AIRPCAP_ADVANCED_EDIT_KEY_KEY_LABEL_KEY,edit_key_lb);
    g_object_set_data(G_OBJECT(edit_key_window),AIRPCAP_ADVANCED_EDIT_KEY_SSID_LABEL_KEY,edit_ssid_lb);


    g_free(row_type);
    g_free(row_key);
    g_free(row_ssid);
    gtk_widget_show(edit_key_window);
}

/*
 * Callback for the 'Move Key Up' button.
 */
static void
on_move_key_up_bt_clicked(GtkWidget *button _U_, gpointer key_list)
{
    tree_view_list_store_move_selection(GTK_TREE_VIEW(key_list), TRUE);
}

/*
 * Callback for the 'Move Key Down' button.
 */
static void
on_move_key_down_bt_clicked(GtkWidget *button _U_, gpointer list_view)
{
    tree_view_list_store_move_selection(GTK_TREE_VIEW(list_view), FALSE);
}

/* Turns the decryption on or off */
void
on_decryption_mode_cb_changed(GtkWidget *cb, gpointer data _U_)
{
    gint cur_active;

    if (cb == NULL) {
        return;
    }

    cur_active = gtk_combo_box_get_active(GTK_COMBO_BOX(cb));

    if (cur_active < 0) {
        return;
    }

    switch(cur_active) {
        /* XXX - Don't use magic numbers here */
        case 1: /* Wireshark */
            set_wireshark_decryption(TRUE);
            if (!set_airpcap_decryption(FALSE)) g_warning(CANT_SAVE_ERR_STR);
            break;
        case 2: /* Driver */
            set_wireshark_decryption(FALSE);
            if (!set_airpcap_decryption(TRUE)) g_warning(CANT_SAVE_ERR_STR);
            break;
        default:
            set_wireshark_decryption(FALSE);
            if (!set_airpcap_decryption(FALSE)) g_warning(CANT_SAVE_ERR_STR);
            break;
    }

    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets();
}

/*
 * Selects the current decryption mode string in the decryption mode combo box
 */
void
update_decryption_mode(GtkWidget *cb)
{
    if (cb == NULL) {
        return;
    }

    /* Wireshark decryption is on */
    if (wireshark_decryption_on())
    {
        gtk_combo_box_set_active(GTK_COMBO_BOX(cb), 1);
    }
    /* AirPcap decryption is on */
    else if (airpcap_decryption_on())
    {
        gtk_combo_box_set_active(GTK_COMBO_BOX(cb), 2);
    }
    /* No decryption enabled */
    else
    {
        gtk_combo_box_set_active(GTK_COMBO_BOX(cb), 0);
    }

    return;
}

/*
 * Creates the list of available decryption modes, depending on the adapters found
 */
void
update_decryption_mode_list(GtkWidget *cb)
{
    gchar *current_text;

    if (cb == NULL)
        return;

    current_text = NULL;

    /*
     * XXX - Retrieve the current 'decryption mode'. It would be better just block the
     * signal handler, but it doesn't work... one of these days I'll try to figure out why...
     */
    current_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(cb));

    while (gtk_tree_model_iter_n_children(gtk_combo_box_get_model(GTK_COMBO_BOX(cb)), NULL) > 0) {
        gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(cb), 0);
    }

    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(cb), AIRPCAP_DECRYPTION_TYPE_STRING_NONE);
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(cb), AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK);

    if (airpcap_if_list != NULL && g_list_length(airpcap_if_list) > 0)
    {
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(cb), AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP);
    }
    else
    {
        /* The last decryption mode was 'Driver', but no more AirPcap adapter are found */
        if (current_text == NULL || g_ascii_strcasecmp(current_text, AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP) == 0)
        {
            g_free(current_text);
            current_text = g_strdup(AIRPCAP_DECRYPTION_TYPE_STRING_NONE);
        }
    }

    if (g_ascii_strcasecmp(current_text, AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK) == 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(cb), 1);
    } else if (g_ascii_strcasecmp(current_text, AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP) == 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(cb), 2);
    } else { /* None / Invalid */
        gtk_combo_box_set_active(GTK_COMBO_BOX(cb), 0);
    }

    g_free(current_text);
}


/*
 * Callback for the Wireless Advanced Settings 'Apply' button.
 */
static void
on_advanced_apply_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    /* advenced window */
    GtkWidget    *airpcap_advanced_w;
    GtkWidget    *channel_cb, *channel_offset_cb;

    /* widgets in the toolbar */
    GtkWidget    *toolbar,
                 *toolbar_if_lb,
                 *toolbar_channel_cb,
                 *toolbar_channel_offset_cb,
                 *toolbar_fcs_filter_cb;

    /* retrieve main window */
    airpcap_advanced_w = GTK_WIDGET(data);

    /* Set the channel and offset */
    channel_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(airpcap_advanced_w),AIRPCAP_ADVANCED_CHANNEL_KEY));
    channel_offset_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(airpcap_advanced_w),AIRPCAP_ADVANCED_CHANNEL_OFFSET_KEY));
    airpcap_channel_offset_changed_cb(channel_offset_cb, NULL);
    airpcap_channel_changed_set_cb(channel_cb, channel_offset_cb);


    toolbar = GTK_WIDGET(g_object_get_data(G_OBJECT(airpcap_advanced_w),AIRPCAP_TOOLBAR_KEY));

    /* retrieve toolbar info */
    toolbar_if_lb = GTK_WIDGET(g_object_get_data(G_OBJECT(toolbar),AIRPCAP_TOOLBAR_INTERFACE_KEY));
    toolbar_channel_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(toolbar),AIRPCAP_TOOLBAR_CHANNEL_KEY));
    toolbar_channel_offset_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(toolbar),AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY));
    toolbar_fcs_filter_cb = GTK_WIDGET(g_object_get_data(G_OBJECT(toolbar),AIRPCAP_TOOLBAR_FCS_FILTER_KEY));

    /* Save the configuration (for all ) */
    airpcap_save_selected_if_configuration(airpcap_if_selected);

    /* Update toolbar (only if airpcap_if_selected is airpcap_if_active)*/
    if ( g_ascii_strcasecmp(airpcap_if_selected->description,airpcap_if_active->description) == 0)
    {
        gtk_label_set_text(GTK_LABEL(toolbar_if_lb), g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_selected)));
        airpcap_update_channel_combo(GTK_WIDGET(toolbar_channel_cb),airpcap_if_selected);
        airpcap_update_channel_offset_combo(airpcap_if_selected, airpcap_if_selected->channelInfo.Frequency, toolbar_channel_offset_cb, TRUE);
        airpcap_validation_type_combo_set_by_type(toolbar_fcs_filter_cb,airpcap_if_selected->CrcValidationOn);
    }
}

/*
 * Callback for the OK button 'clicked' in the Advanced Wireless Settings window.
 */
static void
on_advanced_ok_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    PAirpcapHandle ad = NULL;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];

    /* Retrieve object data */
    GtkWidget *airpcap_advanced_w = GTK_WIDGET(data);

    if (airpcap_if_selected == NULL) { /* There's not much we can do. */
        gtk_widget_destroy(airpcap_advanced_w);
        return;
    }

    on_advanced_apply_bt_clicked(button, data);

    /* Stop blinking our LED */
    ad = airpcap_if_open(airpcap_if_selected->name, ebuf);
    if (ad)
    {
        g_source_remove(airpcap_if_selected->tag);
        airpcap_if_turn_led_on(ad, 0);
        airpcap_if_selected->blinking = FALSE;
        airpcap_if_selected->led = TRUE;
        airpcap_if_close(ad);
    }

    /* Remove GLIB timeout */
    g_source_remove(airpcap_if_selected->tag);

    gtk_widget_destroy(airpcap_advanced_w);
}

/*
 * Callback for the CANCEL button 'clicked' in the Advanced Wireless Settings window.
 */
static void
on_advanced_cancel_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    PAirpcapHandle ad = NULL;
    gchar ebuf[AIRPCAP_ERRBUF_SIZE];

    /* Retrieve object data */
    GtkWidget *airpcap_advanced_w;

    /* Retrieve the GUI object pointers */
    airpcap_advanced_w  = GTK_WIDGET(data);

    /* Stop blinking ALL leds (go through the airpcap_if_list) */
    if (airpcap_if_selected != NULL)
    {
        ad = airpcap_if_open(airpcap_if_selected->name, ebuf);
        if (ad)
        {
            g_source_remove(airpcap_if_selected->tag);
            airpcap_if_turn_led_on(ad, 0);
            airpcap_if_selected->blinking = FALSE;
            airpcap_if_selected->led = TRUE;
            airpcap_if_close(ad);
        }
    }

    /* reload the configuration!!! Configuration has not been saved but
        the corresponding structure has been modified probably...*/
    if (!airpcap_if_selected->saved)
    {
        airpcap_load_selected_if_configuration(airpcap_if_selected);
    }

    gtk_widget_destroy(airpcap_advanced_w);
}


/* Called to create the airpcap settings' window */
void
display_airpcap_advanced_cb(GtkWidget *w _U_, gpointer data)
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
    GtkWidget *channel_offset_lb;
    GtkWidget *capture_type_lb;
    GtkWidget *channel_cb;
    GtkWidget *channel_offset_cb;
    GtkWidget *capture_type_cb;
    GtkWidget *fcs_ck;
    GtkWidget *basic_parameters_fcs_h_box;
    GtkWidget *basic_parameters_fcs_filter_lb;
    GtkWidget *fcs_filter_cb;
    GtkWidget *basic_parameters_frame_lb;
    GtkWidget *low_buttons_h_box;
    GtkWidget *left_h_button_box;
    GtkWidget *right_h_button_box;
    GtkWidget *ok_bt;
    GtkWidget *apply_bt;
    GtkWidget *cancel_bt;

    /* widgets in the toolbar */
    GtkWidget *toolbar;

    /* user data - RETRIEVE pointers of toolbar widgets */
    toolbar              = GTK_WIDGET(data);

    /* gray out the toolbar */
    gtk_widget_set_sensitive(toolbar,FALSE);

    /* main window */
    /* global */

    /* the selected is the active, for now */
    airpcap_if_selected = airpcap_if_active;

    /* Create the new window */
    airpcap_advanced_w = dlg_window_new("Advanced Wireless Settings");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(airpcap_advanced_w), TRUE);

    gtk_container_set_border_width (GTK_CONTAINER (airpcap_advanced_w), 5);
    gtk_window_set_position (GTK_WINDOW (airpcap_advanced_w),
                             GTK_WIN_POS_CENTER);

    gtk_window_set_resizable (GTK_WINDOW (airpcap_advanced_w), FALSE);
    gtk_window_set_type_hint (GTK_WINDOW (airpcap_advanced_w), GDK_WINDOW_TYPE_HINT_DIALOG);

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
    gtk_alignment_set_padding (GTK_ALIGNMENT (interface_al), 5, 5, 0, 0);

    interface_sub_h_box = gtk_hbox_new (FALSE, 0);
    gtk_widget_set_name (interface_sub_h_box, "interface_sub_h_box");
    gtk_widget_show (interface_sub_h_box);
    gtk_container_add (GTK_CONTAINER (interface_al), interface_sub_h_box);
    gtk_container_set_border_width (GTK_CONTAINER (interface_sub_h_box), 5);

    /* Fill the interface_box */
    if (airpcap_if_active != NULL)
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
    if (!airpcap_if_is_any(airpcap_if_selected))
    {
        blink_bt = gtk_button_new_with_mnemonic ("Blink Led");
    }
    else /* It is the any interface, so it doesn't make sense to have 'Blink' button... */
    {
        blink_bt = gtk_button_new_with_mnemonic ("What's This?");
    }
    gtk_widget_set_name (blink_bt, "blink_bt");
    gtk_widget_show (blink_bt);
    gtk_box_pack_end (GTK_BOX (interface_sub_h_box), blink_bt, FALSE, FALSE, 0);

    interface_frame_lb = gtk_label_new ("<b>Interface</b>");
    gtk_widget_set_name (interface_frame_lb, "interface_frame_lb");
    gtk_widget_show (interface_frame_lb);
    gtk_frame_set_label_widget (GTK_FRAME (interface_fr), interface_frame_lb);
    gtk_label_set_use_markup (GTK_LABEL (interface_frame_lb), TRUE);

    basic_parameters_fr = gtk_frame_new (NULL);
    gtk_widget_set_name (basic_parameters_fr, "basic_parameters_fr");
    gtk_widget_show (basic_parameters_fr);
    gtk_box_pack_start (GTK_BOX (settings_sub_box), basic_parameters_fr, TRUE,FALSE, 0);
    gtk_container_set_border_width (GTK_CONTAINER (basic_parameters_fr), 10);

    basic_parameters_al = gtk_alignment_new (0.5, 0.5, 1, 1);
    gtk_widget_set_name (basic_parameters_al, "basic_parameters_al");
    gtk_widget_show (basic_parameters_al);
    gtk_container_add (GTK_CONTAINER (basic_parameters_fr),basic_parameters_al);
    gtk_alignment_set_padding (GTK_ALIGNMENT (basic_parameters_al), 10, 10, 0, 0);

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
    gtk_table_attach (GTK_TABLE (basic_parameters_tb), capture_type_lb, 0, 1, 2,
                      3, (GtkAttachOptions) (GTK_FILL), (GtkAttachOptions) (0),
                      0, 0);
    gtk_misc_set_alignment (GTK_MISC (capture_type_lb), 0, 0.5);

    /* Start: Channel offset label */
    channel_offset_lb = gtk_label_new ("Channel Offset:");
    gtk_widget_set_name (channel_offset_lb, "channel_offset_lb");
    gtk_widget_show (channel_offset_lb);
    gtk_table_attach (GTK_TABLE (basic_parameters_tb), channel_offset_lb, 0, 1, 1, 2,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_misc_set_alignment (GTK_MISC (channel_offset_lb), 0, 0.5);
    /* End: Channel offset label */

    /* Start: Channel offset combo box */
    channel_offset_cb = gtk_combo_box_text_new();
    gtk_widget_set_name (channel_offset_cb, "channel_offset_cb");

    airpcap_update_channel_offset_combo(airpcap_if_selected, airpcap_if_selected->channelInfo.Frequency, channel_offset_cb, FALSE);

    gtk_widget_show(channel_offset_cb);

    gtk_table_attach (GTK_TABLE (basic_parameters_tb), channel_offset_cb, 1, 2, 1, 2,
                  (GtkAttachOptions) (GTK_FILL),
                  (GtkAttachOptions) (0), 0, 0);
    /* End: Channel offset combo box */

    channel_cb = gtk_combo_box_text_new();
    gtk_widget_set_name (channel_cb, "channel_cb");
    gtk_widget_show (channel_cb);
    gtk_table_attach (GTK_TABLE (basic_parameters_tb), channel_cb, 1, 2, 0, 1,
                      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);

    /* Select the current channel */
    airpcap_update_channel_combo(GTK_WIDGET(channel_cb), airpcap_if_selected);

    capture_type_cb = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(capture_type_cb), AIRPCAP_LINK_TYPE_NAME_802_11_ONLY);
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(capture_type_cb), AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_RADIO);
    if (airpcap_get_dll_state() == AIRPCAP_DLL_OK) {
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(capture_type_cb), AIRPCAP_LINK_TYPE_NAME_802_11_PLUS_PPI);
    }

    gtk_widget_set_name (capture_type_cb, "capture_type_cb");
    gtk_widget_show (capture_type_cb);
    gtk_table_attach (GTK_TABLE (basic_parameters_tb), capture_type_cb, 1, 2, 2,
                      3, (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);

    /* Current interface value */
    if (airpcap_if_selected != NULL)
    {
        if (airpcap_if_selected->linkType == AIRPCAP_LT_802_11_PLUS_RADIO){
            gtk_combo_box_set_active(GTK_COMBO_BOX(capture_type_cb), AIRPCAP_LINK_TYPE_NUM_802_11_PLUS_RADIO);
        }else if (airpcap_if_selected->linkType == AIRPCAP_LT_802_11_PLUS_PPI){
            gtk_combo_box_set_active(GTK_COMBO_BOX(capture_type_cb), AIRPCAP_LINK_TYPE_NUM_802_11_PLUS_PPI);
        } else {
            gtk_combo_box_set_active(GTK_COMBO_BOX(capture_type_cb), AIRPCAP_LINK_TYPE_NUM_802_11_ONLY);
        }
    }

    fcs_ck = gtk_check_button_new_with_label ("Include 802.11 FCS in Frames");

    gtk_widget_set_name (fcs_ck, "fcs_ck");

    /* Fcs Presence check box */
    if (airpcap_if_selected != NULL)
    {
        if (airpcap_if_selected->IsFcsPresent)
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
                      basic_parameters_fcs_h_box, 2, 3, 2, 3,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (GTK_FILL), 3, 0);

    basic_parameters_fcs_filter_lb = gtk_label_new ("FCS Filter:");
    gtk_widget_set_name (basic_parameters_fcs_filter_lb,
                         "basic_parameters_fcs_filter_lb");
    gtk_widget_show (basic_parameters_fcs_filter_lb);
    gtk_box_pack_start (GTK_BOX (basic_parameters_fcs_h_box),
                        basic_parameters_fcs_filter_lb, FALSE, FALSE, 0);

    fcs_filter_cb = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb), airpcap_get_validation_name(AIRPCAP_VT_ACCEPT_EVERYTHING));
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb), airpcap_get_validation_name(AIRPCAP_VT_ACCEPT_CORRECT_FRAMES));
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(fcs_filter_cb), airpcap_get_validation_name(AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES));
    gtk_combo_box_set_active(GTK_COMBO_BOX(fcs_filter_cb), 0);
    gtk_widget_set_name (fcs_filter_cb, "fcs_filter_cb");
    gtk_widget_show (fcs_filter_cb);
    gtk_box_pack_start (GTK_BOX (basic_parameters_fcs_h_box), fcs_filter_cb,
                        FALSE, FALSE, 0);
    gtk_widget_set_size_request (fcs_filter_cb, 112, -1);

    if (airpcap_if_selected != NULL)
    {
        airpcap_validation_type_combo_set_by_type(fcs_filter_cb, airpcap_if_selected->CrcValidationOn);
    }

    basic_parameters_frame_lb = gtk_label_new ("<b>Basic Parameters</b>");
    gtk_widget_set_name (basic_parameters_frame_lb,
                         "basic_parameters_frame_lb");
    gtk_widget_show (basic_parameters_frame_lb);

    gtk_frame_set_label_widget (GTK_FRAME (basic_parameters_fr),basic_parameters_frame_lb);
    gtk_label_set_use_markup (GTK_LABEL (basic_parameters_frame_lb), TRUE);

    low_buttons_h_box = gtk_hbox_new (FALSE, 0);
    gtk_widget_set_name (low_buttons_h_box, "low_buttons_h_box");
    gtk_widget_show (low_buttons_h_box);
    gtk_box_pack_end (GTK_BOX (main_box), low_buttons_h_box, FALSE, FALSE, 0);

    left_h_button_box = gtk_hbutton_box_new ();
    gtk_widget_set_name (left_h_button_box, "left_h_button_box");
    gtk_widget_show (left_h_button_box);
    gtk_box_pack_start (GTK_BOX (low_buttons_h_box), left_h_button_box, FALSE,
                        FALSE, 0);

    right_h_button_box = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_CANCEL, NULL);
    gtk_widget_show (right_h_button_box);
    gtk_box_pack_end (GTK_BOX (low_buttons_h_box), right_h_button_box, FALSE,
                      FALSE, 0);
    gtk_button_box_set_layout (GTK_BUTTON_BOX (right_h_button_box),
                               GTK_BUTTONBOX_END);

    ok_bt = g_object_get_data(G_OBJECT(right_h_button_box), GTK_STOCK_OK);
    apply_bt = g_object_get_data(G_OBJECT(right_h_button_box), GTK_STOCK_APPLY);
    cancel_bt = g_object_get_data(G_OBJECT(right_h_button_box), GTK_STOCK_CANCEL);

    /* Connect the callbacks */
    g_signal_connect (airpcap_advanced_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect (airpcap_advanced_w, "destroy", G_CALLBACK(on_airpcap_advanced_destroy), airpcap_advanced_w);

    if (!airpcap_if_is_any(airpcap_if_selected))
    {
        g_signal_connect (blink_bt, "clicked", G_CALLBACK(on_blink_bt_clicked), NULL);
    }
    else
    {
        g_signal_connect (blink_bt, "clicked", G_CALLBACK(on_what_s_this_bt_clicked), NULL);
    }

    g_signal_connect (channel_cb, "changed", G_CALLBACK(airpcap_channel_changed_noset_cb), channel_offset_cb);
    /* We don't attach the channel offset combo because we don't want it changing anything yet. */
    g_signal_connect (capture_type_cb, "changed", G_CALLBACK(on_capture_type_cb_changed), NULL);
    g_signal_connect (fcs_ck, "toggled", G_CALLBACK(on_fcs_ck_toggled), NULL);
    g_signal_connect (fcs_filter_cb, "changed", G_CALLBACK(on_fcs_filter_cb_changed), NULL);
    g_signal_connect (apply_bt, "clicked", G_CALLBACK(on_advanced_apply_bt_clicked), airpcap_advanced_w);
    g_signal_connect (ok_bt,"clicked", G_CALLBACK(on_advanced_ok_bt_clicked), airpcap_advanced_w);
    g_signal_connect (cancel_bt,"clicked", G_CALLBACK(on_advanced_cancel_bt_clicked), airpcap_advanced_w);

    /* Different because the window will be closed ... */
    /*window_set_cancel_button(airpcap_advanced_w, ok_bt, window_cancel_button_cb);
    window_set_cancel_button(airpcap_advanced_w, cancel_bt, window_cancel_button_cb);*/


    /* Store pointers to all widgets, for use by lookup_widget(). */
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_BLINK_KEY, blink_bt);
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_CHANNEL_KEY,channel_cb);
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_CHANNEL_OFFSET_KEY, channel_offset_cb);
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_LINK_TYPE_KEY,capture_type_cb);
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_FCS_CHECK_KEY, fcs_ck);
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_FCS_FILTER_KEY, fcs_filter_cb);
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_OK_KEY, ok_bt);
    g_object_set_data (G_OBJECT(airpcap_advanced_w), AIRPCAP_ADVANCED_CANCEL_KEY, cancel_bt);

    /*
     * I will need the toolbar and the main widget in some callback,
     * so I will add the toolbar pointer to the airpcap_advanced_w
     */
    g_object_set_data(G_OBJECT(airpcap_advanced_w),AIRPCAP_TOOLBAR_KEY,toolbar);

    /* At the end, so that it appears completely all together ... */
    gtk_widget_show (airpcap_advanced_w);
}

/*
 * Callback for the OK button 'clicked' in the Decryption Key Management window.
 */
static void
on_key_management_ok_bt_clicked(GtkWidget *button, gpointer data)
{
    /* advanced window */
    GtkWidget    *key_management_w;

    /* retrieve main window */
    key_management_w      = GTK_WIDGET(data);

    /* Apply the current decryption preferences */
    on_key_management_apply_bt_clicked(button, data);

    /* Save the preferences to preferences file!!! */
    write_prefs_to_file();

    gtk_widget_destroy(key_management_w);
}

/*
 * Callback for the CANCEL button 'clicked' in the Decryption Key Management window.
 */
static void
on_key_management_cancel_bt_clicked(GtkWidget *button _U_, gpointer data)
{
    /* Retrieve object data */
    GtkWidget *key_management_w;

    /* Retrieve the GUI object pointers */
    key_management_w    = GTK_WIDGET(data);

    gtk_widget_destroy(key_management_w);
}

/* Called to create the key management window */
void
display_airpcap_key_management_cb(GtkWidget *w _U_, gpointer data)
{
    GtkWidget *key_management_w;
    GtkWidget *main_box;
    GtkWidget *keys_fr;
    GtkWidget *keys_al;
    GtkWidget *keys_h_sub_box;
    GtkWidget *decryption_mode_tb;
    GtkWidget *decryption_mode_lb;
    GtkWidget *decryption_mode_cb;
    GtkWidget *keys_v_sub_box;
    GtkWidget *keys_scrolled_w;
    GtkListStore *key_list_store;
    GtkWidget *key_list;
    GtkWidget *key_v_button_box;
    GtkWidget *add_new_key_bt;
    GtkWidget *remove_key_bt;
    GtkWidget *edit_key_bt;
    GtkWidget *move_key_up_bt;
    GtkWidget *move_key_down_bt;
    GtkWidget *keys_frame_lb;
    GtkWidget *low_buttons_h_box;
    GtkWidget *left_h_button_box;
    GtkWidget *right_h_button_box;
    GtkWidget *ok_bt;
    GtkWidget *apply_bt;
    GtkWidget *cancel_bt;

    /* widgets in the toolbar */
    GtkWidget *toolbar,
              *toolbar_decryption_ck;

    /* key list */
    GtkTreeViewColumn *column;
    GtkCellRenderer   *renderer;
    GtkTreeSelection  *selection;
    GtkTreeIter        iter;

    /* Selected row/column structure */
    airpcap_key_ls_selected_info_t *key_ls_selected_item;
    key_ls_selected_item = (airpcap_key_ls_selected_info_t*)g_malloc(sizeof(airpcap_key_ls_selected_info_t));
    key_ls_selected_item->row = NO_ROW_SELECTED;

    /* user data - RETRIEVE pointers of toolbar widgets */
    toolbar               = GTK_WIDGET(data);
    toolbar_decryption_ck = GTK_WIDGET(g_object_get_data(G_OBJECT(toolbar),AIRPCAP_TOOLBAR_DECRYPTION_KEY));

    /* gray out the toolbar */
    gtk_widget_set_sensitive(toolbar,FALSE);

    /* main window */
    /* global */

    /* the selected is the active, for now */
    airpcap_if_selected = airpcap_if_active;

    /* Create the new window */
    key_management_w = dlg_window_new("Decryption Key Management");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(key_management_w), TRUE);

    gtk_container_set_border_width (GTK_CONTAINER (key_management_w), 5);
    gtk_window_set_position (GTK_WINDOW (key_management_w),
                             GTK_WIN_POS_CENTER);

    gtk_window_set_resizable (GTK_WINDOW (key_management_w), FALSE);
    gtk_window_set_type_hint (GTK_WINDOW (key_management_w), GDK_WINDOW_TYPE_HINT_DIALOG);

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

    gtk_alignment_set_padding (GTK_ALIGNMENT (keys_al), 0, 0, 12, 0);

    keys_h_sub_box = gtk_vbox_new (FALSE, 0);
    gtk_widget_set_name (keys_h_sub_box, "keys_h_sub_box");
    gtk_widget_show (keys_h_sub_box);
    gtk_container_add (GTK_CONTAINER (keys_al), keys_h_sub_box);

    decryption_mode_tb = gtk_table_new (1, 2, FALSE);
    gtk_widget_set_name (decryption_mode_tb, "decryption_mode_tb");
    gtk_widget_show (decryption_mode_tb);
    gtk_box_pack_start (GTK_BOX (keys_h_sub_box), decryption_mode_tb, FALSE,
                        FALSE, 0);
    gtk_table_set_col_spacings (GTK_TABLE (decryption_mode_tb), 6);

    decryption_mode_lb = gtk_label_new ("Select Decryption Mode");
    gtk_widget_set_name (decryption_mode_lb, "decryption_mode_lb");
    gtk_widget_show (decryption_mode_lb);
    gtk_table_attach (GTK_TABLE (decryption_mode_tb), decryption_mode_lb, 1,
                      2, 0, 1, (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_misc_set_alignment (GTK_MISC (decryption_mode_lb), 0, 0.5);

    decryption_mode_cb = gtk_combo_box_text_new();
    update_decryption_mode_list(decryption_mode_cb);
    gtk_widget_set_name (decryption_mode_cb, "decryption_mode_cb");
    gtk_widget_show (decryption_mode_cb);
    gtk_table_attach (GTK_TABLE (decryption_mode_tb), decryption_mode_cb, 0,
                      1, 0, 1, (GtkAttachOptions) (0), (GtkAttachOptions) (0),
                      0, 0);
    gtk_widget_set_size_request (decryption_mode_cb, 83, -1);

    /* Set correct decryption mode!!!! */
    update_decryption_mode(decryption_mode_cb);

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



    /* Create the store */
    key_list_store = gtk_list_store_new(KL_NUM_COLS,
                                        G_TYPE_STRING, /* Type */
                                        G_TYPE_STRING /* Key */
                                        , G_TYPE_STRING /* SSID */
                                       );

    /* Create a view */
    key_list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(key_list_store));

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(key_list), TRUE);

    /* Setup the sortable columns */
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(key_list), FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref(G_OBJECT(key_list_store));

    /*
     * Create the first column packet, associating the "text" attribute of the
     * cell_renderer to the first column of the model
     */
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Type", renderer,
            "text", KL_COL_TYPE, NULL);
    gtk_tree_view_column_set_sort_column_id(column, KL_COL_TYPE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 60);
    gtk_tree_view_column_set_fixed_width(column, 100);
    /* Add the column to the view. */
    gtk_tree_view_append_column(GTK_TREE_VIEW(key_list), column);

    /* Key */
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Key", renderer,
            "text", KL_COL_KEY, NULL);
    gtk_tree_view_column_set_sort_column_id(column, KL_COL_KEY);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 120);
    gtk_tree_view_column_set_fixed_width(column, 200);
    gtk_tree_view_append_column(GTK_TREE_VIEW(key_list), column);

    /* SSID */
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("SSID", renderer,
            "text", KL_COL_SSID,
            NULL);
    gtk_tree_view_column_set_sort_column_id(column, KL_COL_SSID);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_column_set_fixed_width(column, 150);
    gtk_tree_view_append_column(GTK_TREE_VIEW(key_list), column);

    /* Now enable the sorting of each column */
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(key_list), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(key_list), TRUE);

    /* Setup the selection handler */
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(key_list));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

    gtk_widget_show (key_list);

    gtk_container_add (GTK_CONTAINER (keys_scrolled_w), key_list);

    key_v_button_box = gtk_vbutton_box_new ();
    gtk_widget_set_name (key_v_button_box, "key_v_button_box");
    gtk_widget_show (key_v_button_box);
    gtk_box_pack_start (GTK_BOX (keys_v_sub_box), key_v_button_box, FALSE, TRUE,
                        0);

    add_new_key_bt = gtk_button_new_from_stock(GTK_STOCK_NEW);
    gtk_widget_set_name (add_new_key_bt, "add_new_key_bt");
    gtk_widget_show (add_new_key_bt);
    gtk_container_add (GTK_CONTAINER (key_v_button_box), add_new_key_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (add_new_key_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (add_new_key_bt, GTK_CAN_DEFAULT);
#endif

    edit_key_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_EDIT);
    gtk_widget_set_name (edit_key_bt, "edit_key_bt");
    gtk_widget_show (edit_key_bt);
    gtk_container_add (GTK_CONTAINER (key_v_button_box), edit_key_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (edit_key_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (edit_key_bt, GTK_CAN_DEFAULT);
#endif

    remove_key_bt = gtk_button_new_from_stock(GTK_STOCK_DELETE);
    gtk_widget_set_name (remove_key_bt, "remove_key_bt");
    gtk_widget_show (remove_key_bt);
    gtk_container_add (GTK_CONTAINER (key_v_button_box), remove_key_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (remove_key_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (remove_key_bt, GTK_CAN_DEFAULT);
#endif

    move_key_up_bt = gtk_button_new_from_stock(GTK_STOCK_GO_UP);
    gtk_widget_set_name (move_key_up_bt, "move_key_up_bt");
    gtk_widget_show (move_key_up_bt);
    gtk_container_add (GTK_CONTAINER (key_v_button_box), move_key_up_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (move_key_up_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (move_key_up_bt, GTK_CAN_DEFAULT);
#endif

    move_key_down_bt = gtk_button_new_from_stock(GTK_STOCK_GO_DOWN);
    gtk_widget_set_name (move_key_down_bt, "move_key_down_bt");
    gtk_widget_show (move_key_down_bt);
    gtk_container_add (GTK_CONTAINER (key_v_button_box), move_key_down_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (move_key_down_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (move_key_down_bt, GTK_CAN_DEFAULT);
#endif

    keys_frame_lb = gtk_label_new ("<b>Decryption Keys</b>");
    gtk_widget_set_name (keys_frame_lb, "keys_frame_lb");
    gtk_widget_show (keys_frame_lb);

    gtk_frame_set_label_widget (GTK_FRAME (keys_fr), keys_frame_lb);
    gtk_label_set_use_markup (GTK_LABEL (keys_frame_lb), TRUE);

    low_buttons_h_box = gtk_hbox_new (FALSE, 0);
    gtk_widget_set_name (low_buttons_h_box, "low_buttons_h_box");
    gtk_widget_show (low_buttons_h_box);
    gtk_box_pack_end (GTK_BOX (main_box), low_buttons_h_box, FALSE, FALSE, 0);

    left_h_button_box = gtk_hbutton_box_new ();
    gtk_widget_set_name (left_h_button_box, "left_h_button_box");
    gtk_widget_show (left_h_button_box);
    gtk_box_pack_start (GTK_BOX (low_buttons_h_box), left_h_button_box, FALSE,
                        FALSE, 0);

    right_h_button_box = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_CANCEL, NULL);
    gtk_widget_set_name (right_h_button_box, "right_h_button_box");
    gtk_widget_show (right_h_button_box);
    gtk_box_pack_end (GTK_BOX (low_buttons_h_box), right_h_button_box, FALSE,
                      FALSE, 0);
    gtk_button_box_set_layout (GTK_BUTTON_BOX (right_h_button_box),
                               GTK_BUTTONBOX_END);

    ok_bt = g_object_get_data(G_OBJECT(right_h_button_box), GTK_STOCK_OK);
    apply_bt = g_object_get_data(G_OBJECT(right_h_button_box), GTK_STOCK_APPLY);
    cancel_bt = g_object_get_data(G_OBJECT(right_h_button_box), GTK_STOCK_CANCEL);

    /* Connect the callbacks */
    g_signal_connect (key_management_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect (key_management_w, "destroy", G_CALLBACK(on_key_management_destroy), key_management_w);
    g_signal_connect (add_new_key_bt, "clicked", G_CALLBACK(on_add_new_key_bt_clicked), key_management_w);
    g_signal_connect (remove_key_bt, "clicked", G_CALLBACK(on_remove_key_bt_clicked), key_management_w);
    g_signal_connect (edit_key_bt, "clicked", G_CALLBACK(on_edit_key_bt_clicked), key_management_w);
    g_signal_connect (move_key_up_bt, "clicked", G_CALLBACK(on_move_key_up_bt_clicked), key_list);
    g_signal_connect (move_key_down_bt, "clicked", G_CALLBACK(on_move_key_down_bt_clicked), key_list);
    g_signal_connect (apply_bt, "clicked", G_CALLBACK(on_key_management_apply_bt_clicked), key_management_w);
    g_signal_connect (ok_bt, "clicked", G_CALLBACK(on_key_management_ok_bt_clicked), key_management_w);
    g_signal_connect (cancel_bt, "clicked", G_CALLBACK(on_key_management_cancel_bt_clicked), key_management_w);
    g_signal_connect (selection, "changed", G_CALLBACK(on_key_list_select_row), key_management_w);
    g_signal_connect (key_list_store, "rows_reordered", G_CALLBACK(on_key_list_reorder), key_management_w);

    /* Different because the window will be closed ... */
    /*window_set_cancel_button(key_management_w, ok_bt, window_cancel_button_cb);
    window_set_cancel_button(key_management_w, cancel_bt, window_cancel_button_cb);*/

    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_ADVANCED_EDIT_KEY_SELECTION_KEY,selection);

    /* Store pointers to all widgets, for use by lookup_widget(). */
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_ADVANCED_DECRYPTION_MODE_KEY, decryption_mode_cb);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_ADVANCED_KEYLIST_KEY, key_list_store);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_ADVANCED_OK_KEY, ok_bt);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_ADVANCED_CANCEL_KEY, cancel_bt);

    /* Enable / disable buttons */
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_KEY_MGMT_NEW_KEY, add_new_key_bt);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_KEY_MGMT_EDIT_KEY, edit_key_bt);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_KEY_MGMT_DELETE_KEY, remove_key_bt);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_KEY_MGMT_UP_KEY, move_key_up_bt);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_KEY_MGMT_DOWN_KEY, move_key_down_bt);

    /*
     * I will need the toolbar and the main widget in some callback,
     * so I will add the toolbar pointer to the key_management_w
     */
    g_object_set_data(G_OBJECT(key_management_w),AIRPCAP_TOOLBAR_KEY,toolbar);
    g_object_set_data (G_OBJECT(key_management_w), AIRPCAP_TOOLBAR_DECRYPTION_KEY, toolbar_decryption_ck);

    /* FIRST OF ALL, CHECK THE KEY COLLECTIONS */
    /*
     * This will read the decryption keys from the preferences file, and will store
     * them into the registry...
     */
    if (!airpcap_check_decryption_keys(airpcap_if_list))
    {
        /* Ask the user what to do ...*/
        airpcap_keys_check_w(key_management_w,NULL);
    }
    else /* Keys from lists are equals, or Wireshark has got no keys */
    {
        airpcap_load_decryption_keys(airpcap_if_list);
        airpcap_fill_key_list(key_list_store);
        /* At the end, so that it appears completely all together ... */
        gtk_widget_show (key_management_w);
    }

    gtk_tree_model_get_iter_first(GTK_TREE_MODEL(key_list_store), &iter);
    gtk_tree_selection_select_iter(selection, &iter);
}


static void
on_keys_check_cancel_bt_clicked (GtkWidget *button _U_, gpointer user_data)
{
    GtkWidget *key_management_w;
    GtkWidget *keys_check_w;
    GtkListStore *key_list_store;

    keys_check_w = GTK_WIDGET(user_data);

    key_management_w = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_KEY);

    /* w may be NULL if airpcap_keys_check_w() has been called while Wireshark was loading,
       and is not NULL if it was called when the Key Management widget has been clicked */
    if (key_management_w != NULL)
    {
        /*  ... */
        key_list_store = g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_ADVANCED_KEYLIST_KEY);
        airpcap_fill_key_list(key_list_store);
        gtk_widget_show (key_management_w);
    }

    gtk_widget_destroy(keys_check_w);
}

static void
on_merge_bt_clicked (GtkWidget* button _U_, gpointer user_data)
{
    GtkWidget *key_management_w;
    GtkWidget *keys_check_w;
    GtkListStore *key_list_store;

    guint n_adapters = 0;
    guint n_wireshark_keys = 0;
    guint n_driver_keys = 0;
    guint n_curr_adapter_keys = 0;
    guint n_total_keys = 0;
    guint i = 0;

    GList* wireshark_keys=NULL;
    GList* driver_keys=NULL;
    GList* current_adapter_keys=NULL;
    GList* merged_list = NULL;
    GList* merged_list_tmp = NULL;

    airpcap_if_info_t* curr_adapter;

    keys_check_w = GTK_WIDGET(user_data);

    key_management_w = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_KEY);

    n_adapters = g_list_length(airpcap_if_list);

    /* Retrieve Wireshark keys */
    wireshark_keys = get_wireshark_keys();
    n_wireshark_keys = g_list_length(wireshark_keys);
    n_total_keys += n_wireshark_keys;

    merged_list = merge_key_list(wireshark_keys,NULL);

    /* Retrieve AirPcap driver's keys */
    driver_keys = get_airpcap_driver_keys();
    n_driver_keys = g_list_length(driver_keys);
    n_total_keys += n_driver_keys;

    merged_list = merge_key_list(merged_list,driver_keys);

    /* NOW wireshark_keys and driver_keys ARE no more needed... at the end, we will have to free them! */
    for (i = 0; i<n_adapters; i++)
    {
        curr_adapter = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);
        current_adapter_keys = get_airpcap_device_keys(curr_adapter);
        n_curr_adapter_keys = g_list_length(current_adapter_keys);

        merged_list_tmp = merged_list;
        merged_list = merge_key_list(merged_list_tmp,current_adapter_keys);
        free_key_list(merged_list_tmp);

        n_total_keys += n_curr_adapter_keys;
    }

    /* Set up this new list as default for Wireshark and Adapters... */
    airpcap_save_decryption_keys(merged_list,airpcap_if_list);

    /* Write the preferences to the preferences file */
    write_prefs_to_file();

    free_key_list(wireshark_keys);
    free_key_list(driver_keys);

    gtk_widget_destroy(keys_check_w);

    /* w may be NULL if airpcap_keys_check_w() has been called while Wireshark was loading,
       and is not NULL if it was called when the Key Management widget has been clicked */
    if (key_management_w != NULL)
    {
        /*  ... */
        key_list_store = g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_ADVANCED_KEYLIST_KEY);
        airpcap_fill_key_list(key_list_store);
        gtk_widget_show (key_management_w);
    }
}

static void
on_keep_bt_clicked (GtkWidget *button _U_, gpointer user_data)
{
    GtkWidget *key_management_w;
    GtkWidget *keys_check_w;
    GtkListStore *key_list_store=NULL;

    GList* wireshark_keys=NULL;
    guint n_wireshark_keys = 0;

    GList* merged_keys=NULL;

    guint n_total_keys=0;

    keys_check_w = GTK_WIDGET(user_data);

    key_management_w = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_KEY);

    /* Retrieve Wireshark keys */
    wireshark_keys = get_wireshark_keys();
    n_wireshark_keys = g_list_length(wireshark_keys);
    n_total_keys += n_wireshark_keys;

    merged_keys = merge_key_list(wireshark_keys,NULL);

    /* Set up this new list as default for Wireshark and Adapters... */
    airpcap_save_decryption_keys(merged_keys,airpcap_if_list);

    /* Write the preferences to the preferences file (here is not needed, by the way)*/
    write_prefs_to_file();

    /* Free the memory */
    free_key_list(wireshark_keys);

    /* Close the window */
    gtk_widget_destroy(keys_check_w);

    /* w may be NULL if airpcap_keys_check_w() has been called while Wireshark was loading,
       and is not NULL if it was called when the Key Management widget has been clicked */
    if (key_management_w != NULL)
    {
        /*  ... */
        key_list_store = g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_ADVANCED_KEYLIST_KEY);
        airpcap_fill_key_list(key_list_store);
        gtk_widget_show (key_management_w);
    }
}

static void
on_import_bt_clicked (GtkWidget* button _U_, gpointer user_data)
{
    GtkWidget *key_management_w;
    GtkWidget *keys_check_w;
    GtkListStore *key_list_store;

    guint n_adapters = 0;
    guint n_wireshark_keys = 0;
    guint n_driver_keys = 0;
    guint n_curr_adapter_keys = 0;
    guint n_total_keys = 0;
    guint i = 0;

    GList* wireshark_keys=NULL;
    GList* driver_keys=NULL;
    GList* current_adapter_keys=NULL;
    GList* merged_list = NULL;
    GList* merged_list_tmp = NULL;

    airpcap_if_info_t* curr_adapter;

    keys_check_w = GTK_WIDGET(user_data);

    key_management_w = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_KEY);

    n_adapters = g_list_length(airpcap_if_list);

    wireshark_keys = get_wireshark_keys();
    n_wireshark_keys = g_list_length(wireshark_keys);
    n_total_keys += n_wireshark_keys;

    /* Retrieve AirPcap driver's keys */
    driver_keys = get_airpcap_driver_keys();
    n_driver_keys = g_list_length(driver_keys);
    n_total_keys += n_driver_keys;

    merged_list = merge_key_list(merged_list,driver_keys);

    /* NOW wireshark_keys IS no more needed... at the end, we will have to free it! */
    for (i = 0; i<n_adapters; i++)
    {
        curr_adapter = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);
        current_adapter_keys = get_airpcap_device_keys(curr_adapter);
        n_curr_adapter_keys = g_list_length(current_adapter_keys);

        merged_list_tmp = merged_list;
        merged_list = merge_key_list(merged_list_tmp,current_adapter_keys);
        free_key_list(merged_list_tmp);

        n_total_keys += n_curr_adapter_keys;
    }

    /* Set up this new list as default for Wireshark and Adapters... */
    airpcap_save_decryption_keys(merged_list,airpcap_if_list);

    /* Write the preferences to the preferences file */
    write_prefs_to_file();

    free_key_list(wireshark_keys);
    free_key_list(driver_keys);

    gtk_widget_destroy(keys_check_w);

    /* w may be NULL if airpcap_keys_check_w() has been called while Wireshark was loading,
       and is not NULL if it was called when the Key Management widget has been clicked */
    if (key_management_w != NULL)
    {
        /*  ... */
        key_list_store = g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_ADVANCED_KEYLIST_KEY);
        airpcap_fill_key_list(key_list_store);
        gtk_widget_show (key_management_w);
    }
}

static void
on_ignore_bt_clicked (GtkWidget* button _U_, gpointer user_data)
{
    GtkWidget *key_management_w;
    GtkWidget *keys_check_w;
    GtkListStore *key_list_store;

    keys_check_w = GTK_WIDGET(user_data);

    key_management_w = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_KEY);

    /* w may be NULL if airpcap_keys_check_w() has been called while Wireshark was loading,
       and is not NULL if it was called when the Key Management widget has been clicked */
    if (key_management_w != NULL)
    {
        /*  ... */
        key_list_store = g_object_get_data(G_OBJECT(key_management_w),AIRPCAP_ADVANCED_KEYLIST_KEY);
        airpcap_fill_key_list(key_list_store);
        gtk_widget_show (key_management_w);
    }

    gtk_widget_destroy(keys_check_w);
}

static void
on_keys_check_ok_bt_clicked (GtkWidget *button _U_, gpointer user_data)
{
    GtkWidget *keys_check_w;

    GtkWidget *merge_rb,
              *keep_rb,
              *import_rb,
              *ignore_rb;

    keys_check_w = GTK_WIDGET(user_data);

    merge_rb  = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_MERGE_KEY);
    keep_rb   = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_KEEP_KEY);
    import_rb = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_IMPORT_KEY);
    ignore_rb = g_object_get_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_IGNORE_KEY);

    /* Find out which radio button is selected and call the correct function */
    if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(merge_rb)))
        on_merge_bt_clicked (merge_rb,keys_check_w);
    else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(keep_rb)))
        on_keep_bt_clicked (keep_rb,keys_check_w);
    else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(import_rb)))
        on_import_bt_clicked (import_rb,keys_check_w);
    else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ignore_rb)))
        on_ignore_bt_clicked (ignore_rb,keys_check_w);
    else on_keys_check_cancel_bt_clicked(NULL,keys_check_w);
}

static void
on_keys_check_w_destroy (GtkWidget *w _U_, gpointer user_data)
{
    gtk_widget_set_sensitive(top_level,TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(user_data),TRUE);
}

/*
 * Dialog box that appears whenever keys are not consistent between Wireshark and AirPcap
 */
void
airpcap_keys_check_w(GtkWidget *w, gpointer data _U_)
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

    keys_check_w = window_new (GTK_WINDOW_TOPLEVEL, "Decryption Key Warning");
    gtk_widget_set_name (keys_check_w, "keys_check_w");
    gtk_window_set_resizable (GTK_WINDOW (keys_check_w), FALSE);

    main_v_box = gtk_vbox_new (FALSE, 0);
    gtk_widget_set_name (main_v_box, "main_v_box");
    gtk_widget_show (main_v_box);
    gtk_container_add (GTK_CONTAINER (keys_check_w), main_v_box);

    warning_lb = gtk_label_new("<b>WARNING!</b> Decryption keys specified in Wireshark's preferences file differ from those specified for the AirPcap adapter(s). You can choose to:");
    gtk_label_set_use_markup (GTK_LABEL (warning_lb), TRUE);
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

    keep_rb = gtk_radio_button_new_with_mnemonic (NULL, "Keep");
    gtk_widget_set_name (keep_rb, "keep_rb");
    gtk_widget_show (keep_rb);
    gtk_table_attach (GTK_TABLE (radio_tb), keep_rb, 0, 1, 0, 1,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_radio_button_set_group (GTK_RADIO_BUTTON (keep_rb), radio_bt_group);
    radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (keep_rb));

    merge_rb = gtk_radio_button_new_with_mnemonic (NULL, "Merge");
    gtk_widget_set_name (merge_rb, "merge_rb");
    gtk_widget_show (merge_rb);
    gtk_table_attach (GTK_TABLE (radio_tb), merge_rb, 0, 1, 1, 2,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_radio_button_set_group (GTK_RADIO_BUTTON (merge_rb), radio_bt_group);
    radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (merge_rb));

    import_rb = gtk_radio_button_new_with_mnemonic (NULL, "Import");
    gtk_widget_set_name (import_rb, "import_rb");
    gtk_widget_show (import_rb);
    gtk_table_attach (GTK_TABLE (radio_tb), import_rb, 0, 1, 2, 3,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_radio_button_set_group (GTK_RADIO_BUTTON (import_rb), radio_bt_group);
    radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (import_rb));

    ignore_rb = gtk_radio_button_new_with_mnemonic (NULL, "Ignore");
    gtk_widget_set_name (ignore_rb, "ignore_rb");
    gtk_widget_show (ignore_rb);
    gtk_table_attach (GTK_TABLE (radio_tb), ignore_rb, 0, 1, 3, 4,
                      (GtkAttachOptions) (GTK_FILL),
                      (GtkAttachOptions) (0), 0, 0);
    gtk_radio_button_set_group (GTK_RADIO_BUTTON (ignore_rb), radio_bt_group);
    radio_bt_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (ignore_rb));

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

    ok_bt = gtk_button_new_with_mnemonic ("OK");
    gtk_widget_set_name (ok_bt, "ok_bt");
    gtk_widget_show (ok_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), ok_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (ok_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (ok_bt, GTK_CAN_DEFAULT);
#endif

    cancel_bt = gtk_button_new_with_mnemonic ("Cancel");
    gtk_widget_set_name (cancel_bt, "cancel_bt");
    gtk_widget_show (cancel_bt);
    gtk_container_add (GTK_CONTAINER (low_h_button_box), cancel_bt);
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_can_default (cancel_bt, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (cancel_bt, GTK_CAN_DEFAULT);
#endif

    /* Store pointers to all widgets, for use by lookup_widget(). */
    g_signal_connect (ok_bt, "clicked", G_CALLBACK(on_keys_check_ok_bt_clicked), keys_check_w);
    g_signal_connect (cancel_bt, "clicked", G_CALLBACK(on_keys_check_cancel_bt_clicked), keys_check_w);
    g_signal_connect (keys_check_w, "destroy", G_CALLBACK(on_keys_check_w_destroy), keys_check_w);

    /* Store pointers to all widgets, for use by lookup_widget(). */
    g_object_set_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_KEY,w);
    g_object_set_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_MERGE_KEY,merge_rb);
    g_object_set_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_KEEP_KEY,keep_rb);
    g_object_set_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_IMPORT_KEY,import_rb);
    g_object_set_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_IGNORE_KEY,ignore_rb);
    g_object_set_data(G_OBJECT(keys_check_w),AIRPCAP_CHECK_WINDOW_RADIO_GROUP_KEY,radio_bt_group);

    gtk_widget_set_sensitive(top_level,FALSE);
    gtk_widget_show(keys_check_w);
}


#endif /* HAVE_AIRPCAP */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
