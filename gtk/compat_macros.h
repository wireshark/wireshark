/* compat_macros.h
 * GTK-related Global defines, etc.
 *
 * $Id: compat_macros.h,v 1.13 2004/01/31 12:13:22 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __COMPAT_MACROS_H__
#define __COMPAT_MACROS_H__


/*
 * helper macros fro gtk1.2/gtk2 compatibility :
 * in gtk2, gtk_signal_xxx is deprecated in favor of g_signal_xxx
 *          gtk_object_xxx is deprecated in favor of g_object_xxx
 *          gtk_widget_set_usize is deprecated in favor of
 *              gtk_widget_set_size_request
 */
#if GTK_MAJOR_VERSION < 2

#define SIGNAL_CONNECT(widget, name, callback, arg) \
gtk_signal_connect(GTK_OBJECT(widget), name, GTK_SIGNAL_FUNC(callback), \
                   (gpointer)(arg))

#define SIGNAL_CONNECT_OBJECT(widget, name, callback, arg) \
gtk_signal_connect_object(GTK_OBJECT(widget), name, GTK_SIGNAL_FUNC(callback), \
                          (gpointer)(arg))

#define SIGNAL_DISCONNECT_BY_FUNC(object, func, data) \
gtk_signal_disconnect_by_func(GTK_OBJECT(object), func, data)

#define OBJECT_SET_DATA(widget, key, data) \
gtk_object_set_data(GTK_OBJECT(widget), key, (gpointer)data)

#define OBJECT_SET_DATA_FULL(widget, key, data, destroy) \
gtk_object_set_data_full(GTK_OBJECT(widget), key, (gpointer)(data), \
                         (GtkDestroyNotify)(destroy))

#define OBJECT_GET_DATA(widget, key) \
gtk_object_get_data(GTK_OBJECT(widget), key)

#define WIDGET_SET_SIZE(widget, width, height) \
gtk_widget_set_usize(GTK_WIDGET(widget), width, height)

#define SIGNAL_EMIT_BY_NAME(widget, name) \
gtk_signal_emit_by_name(GTK_OBJECT(widget), name)

#define SIGNAL_EMIT_BY_NAME1(widget, name, arg) \
gtk_signal_emit_by_name(GTK_OBJECT(widget), name, arg)

#define SIGNAL_EMIT_STOP_BY_NAME(widget, name) \
gtk_signal_emit_stop_by_name(GTK_OBJECT(widget), name)

#define ITEM_FACTORY_ENTRY(path, accelerator, callback, action, type, data) \
{path, accelerator, GTK_MENU_FUNC(callback), action, type}

#define ITEM_FACTORY_STOCK_ENTRY(path, accelerator, callback, action, data) \
{path, accelerator, GTK_MENU_FUNC(callback), action, NULL}

#define GTK_STOCK_APPLY             "Apply"
#define GTK_STOCK_CANCEL            "Cancel"
#define GTK_STOCK_CLEAR             "Clear"
#define GTK_STOCK_CLOSE             "Close"
#define GTK_STOCK_COPY              "Copy"
#define GTK_STOCK_DELETE            "Delete"
#define GTK_STOCK_FIND              "Find"
#define GTK_STOCK_GO_BACK           "Back"
#define GTK_STOCK_GO_DOWN           "Down"
#define GTK_STOCK_GO_FORWARD        "Next"
#define GTK_STOCK_GO_UP             "Up"
#define GTK_STOCK_GOTO_BOTTOM       "Bottom"
#define GTK_STOCK_GOTO_TOP          "Top"
#define GTK_STOCK_HELP              "Help"
#define GTK_STOCK_JUMP_TO           "GoTo"
#define GTK_STOCK_NEW               "New"
#define GTK_STOCK_NO                "No"
#define GTK_STOCK_OK                "OK"
#define GTK_STOCK_OPEN              "Open"
#define GTK_STOCK_PRINT             "Print"
#define GTK_STOCK_PROPERTIES        "Properties"
#define GTK_STOCK_REFRESH           "Reload"
#define GTK_STOCK_REVERT_TO_SAVED   "Revert"
#define GTK_STOCK_SAVE              "Save"
#define GTK_STOCK_SAVE_AS           "Save As"
#define GTK_STOCK_SELECT_COLOR      "Color"
#define GTK_STOCK_SELECT_FONT       "Font"
#define GTK_STOCK_STOP              "Stop"
#define GTK_STOCK_YES               "Yes"
#define GTK_STOCK_ZOOM_IN           "Zoom In"
#define GTK_STOCK_ZOOM_OUT          "Zoom Out"
#define GTK_STOCK_ZOOM_100          "Zoom 100%"

#ifdef HAVE_LIBPCAP
#define ETHEREAL_STOCK_CAPTURE_START            "New"
#define ETHEREAL_STOCK_CAPTURE_FILTER           "CFilter"
#define ETHEREAL_STOCK_CAPTURE_FILTER_ENTRY     "Capture Filter:"
#endif
#define ETHEREAL_STOCK_DISPLAY_FILTER           "Filter"
#define ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY     "Filter:"
#define ETHEREAL_STOCK_PREFS                    "Prefs"
#define ETHEREAL_STOCK_BROWSE                   "Browse"
#define ETHEREAL_STOCK_CREATE_STAT              "Create Stat"
#define ETHEREAL_STOCK_EXPORT                   "Export..."
#define ETHEREAL_STOCK_IMPORT                   "Import..."
#define ETHEREAL_STOCK_EDIT                     "Edit..."
#define ETHEREAL_STOCK_ADD_EXPRESSION           "Add Expression..."

#define BUTTON_NEW_FROM_STOCK(stock_id) \
gtk_button_new_with_label(stock_id);

#define CHECK_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
dlg_check_button_new_with_label_with_mnemonic(label_text, accel_group)

#define RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_group, label_text, accel_group) \
dlg_radio_button_new_with_label_with_mnemonic( \
    radio_group ? gtk_radio_button_group(GTK_RADIO_BUTTON(radio_group)) : NULL, \
    label_text, accel_group)

#define TOGGLE_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
dlg_toggle_button_new_with_label_with_mnemonic(label_text, accel_group)

#define PRIMARY_TEXT_START ""
#define PRIMARY_TEXT_END ""

#else /* GTK_MAJOR_VERSION >= 2 */

#define SIGNAL_CONNECT(widget, name, callback, arg) \
g_signal_connect(G_OBJECT(widget), name, G_CALLBACK(callback), \
                 (gpointer)(arg))

#define SIGNAL_CONNECT_OBJECT(widget, name, callback, arg) \
g_signal_connect_swapped(G_OBJECT(widget), name, G_CALLBACK(callback), \
                         (gpointer)(arg))

#define SIGNAL_DISCONNECT_BY_FUNC(object, func, data) \
g_signal_handlers_disconnect_by_func(G_OBJECT(object), func, data)

#define OBJECT_SET_DATA(widget, key, data) \
g_object_set_data(G_OBJECT(widget), key, (gpointer)data)

#define OBJECT_SET_DATA_FULL(widget, key, data, destroy) \
g_object_set_data_full(G_OBJECT(widget), key, (gpointer)(data), \
                       (GDestroyNotify)(destroy))

#define OBJECT_GET_DATA(widget, key) \
g_object_get_data(G_OBJECT(widget), key)

#define WIDGET_SET_SIZE(widget, width, height) \
gtk_widget_set_size_request(GTK_WIDGET(widget), width, height)

#define SIGNAL_EMIT_BY_NAME(widget, name) \
g_signal_emit_by_name(G_OBJECT(widget), name)

#define SIGNAL_EMIT_BY_NAME1(widget, name, arg) \
g_signal_emit_by_name(G_OBJECT(widget), name, arg)

#define SIGNAL_EMIT_STOP_BY_NAME(widget, name) \
g_signal_stop_emission_by_name(G_OBJECT(widget), name)

#define ITEM_FACTORY_ENTRY(path, accelerator, callback, action, type, data) \
{path, accelerator, GTK_MENU_FUNC(callback), action, type, data}

#define ITEM_FACTORY_STOCK_ENTRY(path, accelerator, callback, action, data) \
{path, accelerator, GTK_MENU_FUNC(callback), action, "<StockItem>", data}

#ifdef HAVE_LIBPCAP
#define ETHEREAL_STOCK_LABEL_CAPTURE_START            "_New"
#define ETHEREAL_STOCK_LABEL_CAPTURE_FILTER           "_CFilter"
#define ETHEREAL_STOCK_LABEL_CAPTURE_FILTER_ENTRY     "_Capture Filter:"
#endif
#define ETHEREAL_STOCK_LABEL_DISPLAY_FILTER           "Filter"
#define ETHEREAL_STOCK_LABEL_DISPLAY_FILTER_ENTRY     "Filter:"
#define ETHEREAL_STOCK_LABEL_PREFS                    "_Prefs"
#define ETHEREAL_STOCK_LABEL_BROWSE                   "" /* icon only */
#define ETHEREAL_STOCK_LABEL_CREATE_STAT              "Create Stat"
#define ETHEREAL_STOCK_LABEL_EXPORT                   "Export..."
#define ETHEREAL_STOCK_LABEL_IMPORT                   "Import..."
#define ETHEREAL_STOCK_LABEL_EDIT                     "Edit..."
#define ETHEREAL_STOCK_LABEL_ADD_EXPRESSION           "Expression..." /* plus sign coming from icon */

#ifdef HAVE_LIBPCAP
#define ETHEREAL_STOCK_CAPTURE_START            "Ethereal_Stock_CaptureStart"
#define ETHEREAL_STOCK_CAPTURE_FILTER           "Ethereal_Stock_CaptureFilter"
#define ETHEREAL_STOCK_CAPTURE_FILTER_ENTRY     "Ethereal_Stock_CaptureFilter_Entry"
#endif
#define ETHEREAL_STOCK_DISPLAY_FILTER           "Ethereal_Stock_DisplayFilter"
#define ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY     "Ethereal_Stock_DisplayFilter_Entry"
#define ETHEREAL_STOCK_PREFS                    "Ethereal_Stock_Prefs"
#define ETHEREAL_STOCK_BROWSE                   "Ethereal_Stock_Browse"
#define ETHEREAL_STOCK_CREATE_STAT              "Ethereal_Stock_CreateStat"
#define ETHEREAL_STOCK_EXPORT                   "Ethereal_Stock_Export"
#define ETHEREAL_STOCK_IMPORT                   "Ethereal_Stock_Import"
#define ETHEREAL_STOCK_EDIT                     "Ethereal_Stock_Edit"
#define ETHEREAL_STOCK_ADD_EXPRESSION           "Ethereal_Stock_Edit_Add_Expression"

#define BUTTON_NEW_FROM_STOCK(stock_id) \
gtk_button_new_from_stock(stock_id);

#define CHECK_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
gtk_check_button_new_with_mnemonic(label_text)

#define RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_group, label_text, accel_group) \
gtk_radio_button_new_with_mnemonic_from_widget( \
    radio_group ? GTK_RADIO_BUTTON(radio_group) : NULL, label_text)

#define TOGGLE_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
gtk_toggle_button_new_with_mnemonic(label_text)

#define PRIMARY_TEXT_START "<span weight=\"bold\" size=\"larger\">"
#define PRIMARY_TEXT_END "</span>"

#endif /* GTK_MAJOR_VERSION */

#endif /* __COMPAT_MACROS_H__ */
