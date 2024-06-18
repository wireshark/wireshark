/* pluginifdemo.c
 * Routines for plugin_if demo capability
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/plugin_if.h>
#include "pluginifdemo.h"

#include "ui/uihandler.h"

void proto_register_pluginifdemo(void);
void proto_reg_handoff_pluginifdemo(void);

static int proto_pluginifdemo;

void toolbar_cb(void *object, void *item_data, void *user_data);

void
menu_cb(ext_menubar_gui_type gui_type, void *gui_data, void *user_data _U_)
{
    pluginifdemo_ui_main(gui_type, gui_data);
}

void
about_cb(ext_menubar_gui_type gui_type _U_, void *gui_data _U_, void *user_data _U_)
{
    pluginifdemo_ui_about(gui_type, gui_data);
}

void
proto_register_pluginifdemo(void)
{

#if 0
    module_t *pluginif_module = NULL;
#endif
    ext_menu_t * ext_menu = NULL;

    proto_pluginifdemo = proto_register_protocol("Plugin IF Demo Protocol", "Pluginifdemo", "pluginifdemo");

    ext_menu = ext_menubar_register_menu ( proto_pluginifdemo, "Plugin IF Demonstration", true );
    ext_menubar_set_parentmenu (ext_menu, "Tools");

    ext_menubar_add_entry(ext_menu, "Toolbar Action Demonstrator", "Action demonstrator for the plugin toolbar", menu_cb, NULL);
    ext_menubar_add_separator(ext_menu);
    ext_menubar_add_website(ext_menu, "Wireshark Development", "See Wireshark Development", "https://www.wireshark.org/develop.html");
    ext_menubar_add_separator(ext_menu);
    ext_menubar_add_entry(ext_menu, "&About Plugin IF Demonstration", "Further information", about_cb, NULL);
#if 0
    pluginif_module = prefs_register_protocol(proto_pluginifdemo, NULL);
#endif


    ext_toolbar_t * tb = ext_toolbar_register_toolbar("Plugin Interface Demo Toolbar");

    ext_toolbar_add_entry(tb, EXT_TOOLBAR_BUTTON, "Button 1", 0, "Button 1 to press", false, 0, false, 0, toolbar_cb, 0);
    ext_toolbar_add_entry(tb, EXT_TOOLBAR_BUTTON, "Button 2", 0, "Button 2 to press", true, 0, false, 0, toolbar_cb, 0);
    ext_toolbar_add_entry(tb, EXT_TOOLBAR_BOOLEAN, "Checkbox", 0, "Checkbox to Select", false, 0, false, 0, toolbar_cb, 0);
    ext_toolbar_add_entry(tb, EXT_TOOLBAR_STRING, "String 1", "Default String", "String without validation", false, 0, true, 0, toolbar_cb, 0);
    ext_toolbar_add_entry(tb, EXT_TOOLBAR_STRING, "String 2", "ABC", "String with validation", false, 0, false, "^[A-Z]+", toolbar_cb, 0);
    GList * entries = 0;
    entries = ext_toolbar_add_val( entries, "1", "ABCD", false );
    entries = ext_toolbar_add_val(entries, "2", "EFG", false );
    entries = ext_toolbar_add_val(entries, "3", "HIJ", true );
    entries = ext_toolbar_add_val(entries, "4", "KLM", false );
    entries = ext_toolbar_add_val(entries, "5", "NOP", false );
    entries = ext_toolbar_add_val(entries, "6", "QRS", false );
    entries = ext_toolbar_add_val(entries, "7", "TUVW", false );
    entries = ext_toolbar_add_val(entries, "8", "XYZ", false );
    ext_toolbar_add_entry(tb, EXT_TOOLBAR_SELECTOR, "Selector", 0, "Selector to choose from", false, entries, false, 0, toolbar_cb, 0);

    pluginifdemo_toolbar_register(tb);
}

void* get_frame_data_cb(frame_data* fdata, void* user_data _U_) {
    return GUINT_TO_POINTER(fdata->num);
}

void* get_capture_file_cb(capture_file* cf, void* user_data _U_) {
    return cf->filename;
}

void toolbar_cb(void *toolbar_item, void *item_data, void *user_data _U_)
{
    if ( ! toolbar_item )
        return;

    char * message = 0;
    ext_toolbar_t * entry = (ext_toolbar_t *)toolbar_item;

    if (entry->item_type == EXT_TOOLBAR_BUTTON) {
        pluginifdemo_toolbar_log("Button pressed at toolbar");
        uint32_t fnum = GPOINTER_TO_UINT(plugin_if_get_frame_data(get_frame_data_cb, NULL));
        if (fnum) {
            message = ws_strdup_printf("Current frame is: %u", fnum);
            pluginifdemo_toolbar_log(message);
        }
        const char* fnm = (const char*)plugin_if_get_capture_file(get_capture_file_cb, NULL);
        if (fnm) {
            message = ws_strdup_printf("Capture file name is: %s", fnm);
            pluginifdemo_toolbar_log(message);
        }
    }
    else if ( entry->item_type == EXT_TOOLBAR_BOOLEAN )
    {
        bool data = *((bool *)item_data);
        message = ws_strdup_printf( "Checkbox selected value: %d", (int) (data) );
        pluginifdemo_toolbar_log(message);
    }
    else if ( entry->item_type == EXT_TOOLBAR_STRING )
    {
        char * data = (char *)item_data;
        message = ws_strdup_printf( "String entered in toolbar: %s", data );
        pluginifdemo_toolbar_log(message);
    }
    else if ( entry->item_type == EXT_TOOLBAR_SELECTOR )
    {
        ext_toolbar_value_t * data = (ext_toolbar_value_t *)item_data;
        message = ws_strdup_printf( "Value from toolbar: %s", data->value );
        pluginifdemo_toolbar_log(message);
    }

    g_free(message);
}

void
proto_reg_handoff_pluginifdemo(void)
{

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
