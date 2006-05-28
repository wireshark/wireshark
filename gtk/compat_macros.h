/* compat_macros.h
 * GTK-related Global defines, etc.
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

#ifndef __COMPAT_MACROS_H__
#define __COMPAT_MACROS_H__


/** @file
 *
 * Helper macros for gtk1.x / gtk2.x compatibility. Use these macros instead of the GTK deprecated functions, 
 * to keep compatibility between GTK 1.x and 2.x.
 * For example in gtk2.x, gtk_signal_xxx is deprecated in favor of g_signal_xxx,
 *          gtk_object_xxx is deprecated in favor of g_object_xxx,
 *          gtk_widget_set_usize is deprecated in favor of
 *              gtk_widget_set_size_request, ...
 */

#if GTK_MAJOR_VERSION < 2

/** Connect a signal handler to a particular object.
 *
 * @param widget the widget to connect to
 * @param name name of the signal
 * @param callback 	function pointer to attach to the signal
 * @param arg value to pass to your function
 * @return the connection id
 */
#define SIGNAL_CONNECT(widget, name, callback, arg) \
gtk_signal_connect(GTK_OBJECT(widget), name, GTK_SIGNAL_FUNC(callback), \
                   (gpointer)(arg))

/** This function is for registering a callback that will call another object's callback. 
 *  That is, instead of passing the object which is responsible for the event as the first 
 *  parameter of the callback, it is switched with the user data (so the object which emits 
 *  the signal will be the last parameter, which is where the user data usually is).
 *
 * @param widget the widget to connect to
 * @param name name of the signal
 * @param callback 	function pointer to attach to the signal
 * @param arg the object to pass as the first parameter to func
 * @return the connection id
 */
#define SIGNAL_CONNECT_OBJECT(widget, name, callback, arg) \
gtk_signal_connect_object(GTK_OBJECT(widget), name, GTK_SIGNAL_FUNC(callback), \
                          (gpointer)(arg))

/** Destroys all connections for a particular object, with the given 
 *  function-pointer and user-data.
 *
 * @param object the object which emits the signal
 * @param func the function pointer to search for
 * @param data 	the user data to search for
 */
#define SIGNAL_DISCONNECT_BY_FUNC(object, func, data) \
gtk_signal_disconnect_by_func(GTK_OBJECT(object), func, data)

/** Each object carries around a table of associations from strings to pointers,
 *  this function lets you set an association. If the object already had an 
 *  association with that name, the old association will be destroyed. 
 *
 * @param widget object containing the associations
 * @param key name of the key
 * @param data data to associate with that key
 */
#define OBJECT_SET_DATA(widget, key, data) \
gtk_object_set_data(GTK_OBJECT(widget), key, (data))

/** Get a named field from the object's table of associations (the object_data).
 *
 * @param widget object containing the associations
 * @param key name of the key
 * @return 	the data if found, or NULL if no such data exists
 */
#define OBJECT_GET_DATA(widget, key) \
gtk_object_get_data(GTK_OBJECT(widget), key)

/** Sets the size of a widget. This will be useful to set the size of 
 * e.g. a GtkEntry. Don't use WIDGET_SET_SIZE() to set the size of a dialog 
 * or window, use gtk_window_set_default_size() for that purpose!
 *
 * @param widget a GtkWidget
 * @param width  new width, or -1 to unset
 * @param height new height, or -1 to unset
 * @todo WIDGET_SET_SIZE would better be named WIDGET_SET_MIN_SIZE
 */
#define WIDGET_SET_SIZE(widget, width, height) \
gtk_widget_set_usize(GTK_WIDGET(widget), width, height)

/** Emits a signal. This causes the default handler and user-connected 
 *  handlers to be run.
 *
 * @param widget the object that emits the signal
 * @param name the name of the signal
 * @param arg value to pass to the handlers or NULL
 */
#define SIGNAL_EMIT_BY_NAME(widget, name, arg) \
gtk_signal_emit_by_name(GTK_OBJECT(widget), name, arg)

/** This function aborts a signal's current emission. It will prevent the 
 *  default method from running, if the signal was GTK_RUN_LAST and you 
 *  connected normally (i.e. without the "after" flag). It will print a 
 *  warning if used on a signal which isn't being emitted. It will lookup the 
 *  signal id for you.
 *
 * @param widget the object whose signal handlers you wish to stop
 * @param name the signal identifier, as returned by g_signal_lookup()
 */
#define SIGNAL_EMIT_STOP_BY_NAME(widget, name) \
gtk_signal_emit_stop_by_name(GTK_OBJECT(widget), name)

/** An entry for a GtkItemFactoryEntry array.
 *
 * @param path the path to this entry (e.g. "/File/Open")
 * @param accelerator accelerator key (e.g. "<control>M") or NULL
 * @param callback function to be called, when item is activated or NULL
 * @param action the action number to use (usually 0)
 * @param type special item type (e.g. "<Branch>", "<CheckItem>", ...) or NULL
 * @param data data to pass to the callback function or NULL
 */
#define ITEM_FACTORY_ENTRY(path, accelerator, callback, action, type, data) \
{path, accelerator, GTK_MENU_FUNC(callback), action, type}

/** Like ITEM_FACTORY_ENTRY(), but using a stock icon (as data)
 * @param path the path to this entry (e.g. "/File/Open")
 * @param accelerator accelerator key (e.g. "<control>M") or NULL
 * @param callback function to be called, when item is activated or NULL
 * @param action the action number to use (usually 0)
 * @param data the stock item id (e.g. GTK_STOCK_OK, unused by GTK1)
 */
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
#define GTK_STOCK_HOME              "Home"
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
#define WIRESHARK_STOCK_CAPTURE_INTERFACES       "Interfaces"
#define WIRESHARK_STOCK_CAPTURE_OPTIONS          "Options"
#define WIRESHARK_STOCK_CAPTURE_START            "Start"
#define WIRESHARK_STOCK_CAPTURE_STOP             "Stop"
#define WIRESHARK_STOCK_CAPTURE_RESTART          "Restart"
#define WIRESHARK_STOCK_CAPTURE_FILTER           "CFilter"
#define WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY     "Capture Filter:"
#endif
#define WIRESHARK_STOCK_DISPLAY_FILTER           "Filter"
#define WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY     "Filter:"
#define WIRESHARK_STOCK_PREFS                    "Prefs"
#define WIRESHARK_STOCK_BROWSE                   "Browse"
#define WIRESHARK_STOCK_CREATE_STAT              "Create Stat"
#define WIRESHARK_STOCK_EXPORT                   "Export..."
#define WIRESHARK_STOCK_IMPORT                   "Import..."
#define WIRESHARK_STOCK_EDIT                     "Edit..."
#define WIRESHARK_STOCK_ADD_EXPRESSION           "Add Expression..."
#define WIRESHARK_STOCK_DONT_SAVE                "Continue without Saving"
#define WIRESHARK_STOCK_ABOUT                    "About"
#define WIRESHARK_STOCK_COLORIZE                 "Colorize"
#define WIRESHARK_STOCK_AUTOSCROLL               "Auto Scroll"
#define WIRESHARK_STOCK_RESIZE_COLUMNS           "Resize Columns"
#define WIRESHARK_STOCK_TIME                     "Time"
#define WIRESHARK_STOCK_INTERNET                 "Internet"
#define WIRESHARK_STOCK_WEB_SUPPORT              "Web Support"
#define WIRESHARK_STOCK_WIKI                     "Wiki"
#define WIRESHARK_STOCK_CONVERSATIONS            "Conversations"
#define WIRESHARK_STOCK_ENDPOINTS                "Endpoints"
#define WIRESHARK_STOCK_GRAPHS                   "Graphs"
#define WIRESHARK_STOCK_TELEPHONY                "Telephony"
#define WIRESHARK_STOCK_DECODE_AS                "Decode As"
#define WIRESHARK_STOCK_CHECKBOX                 "Checkbox"
#define WIRESHARK_STOCK_FILE_SET_LIST            "List Files"
#define WIRESHARK_STOCK_FILE_SET_NEXT            "Next File"
#define WIRESHARK_STOCK_FILE_SET_PREVIOUS        "Previous File"
#define WIRESHARK_STOCK_FILTER_OUT_STREAM        "Filter Out This Stream"

/** Create a stock button. Will create a "normal" button for GTK1.
 *
 * @param stock_id the stock id for this button (e.g. GTK_STOCK_OK)
 * @return the new button
 */
#define BUTTON_NEW_FROM_STOCK(stock_id) \
gtk_button_new_with_label(stock_id);

/** Create a check button.
 *
 * @param label_text the text to display
 * @param accel_group accelerator group (GTK1 only)
 * @return the new check button
 */
#define CHECK_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
dlg_check_button_new_with_label_with_mnemonic(label_text, accel_group)

/** Create a radio button.
 *
 * @param radio_group group the radio buttons (another radio button or NULL for first one)
 * @param label_text the text to display
 * @param accel_group accelerator group (GTK1 only)
 * @return the new radio button
 */
#define RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_group, label_text, accel_group) \
dlg_radio_button_new_with_label_with_mnemonic( \
    radio_group ? gtk_radio_button_group(GTK_RADIO_BUTTON(radio_group)) : NULL, \
    label_text, accel_group)

/** Create a radio button.
 *
 * @param radio_group group the radio buttons (another radio button or NULL for first one)
 * @param label_text the text to display
 * @return the new radio button
 */
#define RADIO_BUTTON_NEW_WITH_LABEL(radio_group, label_text) \
gtk_radio_button_new_with_label ( \
    radio_group ? gtk_radio_button_group(GTK_RADIO_BUTTON(radio_group)) : NULL, \
    label_text)

/** Create a toggle button.
 *
 * @param label_text the text to display
 * @param accel_group accelerator group (GTK1 only)
 * @return the new toggle button
 */
#define TOGGLE_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
dlg_toggle_button_new_with_label_with_mnemonic(label_text, accel_group)

/** tag(s) start for first row of simple_dialog (and others). */
#define PRIMARY_TEXT_START ""
/** tag(s) end for first row of simple_dialog (and others). */
#define PRIMARY_TEXT_END ""

#define FONT_TYPE GdkFont

/*************************************************************************/

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
g_object_set_data(G_OBJECT(widget), key, (data))

#define OBJECT_GET_DATA(widget, key) \
g_object_get_data(G_OBJECT(widget), key)

/* WIDGET_SET_SIZE would better be named WIDGET_SET_MIN_SIZE. */
/* don't use WIDGET_SET_SIZE() to set the size of a dialog, */
/* use gtk_window_set_default_size() for that purpose! */
#define WIDGET_SET_SIZE(widget, width, height) \
gtk_widget_set_size_request(GTK_WIDGET(widget), width, height)

#define SIGNAL_EMIT_BY_NAME(widget, name, arg) \
g_signal_emit_by_name(G_OBJECT(widget), name, arg)

#define SIGNAL_EMIT_STOP_BY_NAME(widget, name) \
g_signal_stop_emission_by_name(G_OBJECT(widget), name)

#define ITEM_FACTORY_ENTRY(path, accelerator, callback, action, type, data) \
{path, accelerator, GTK_MENU_FUNC(callback), action, type, data}

#define ITEM_FACTORY_STOCK_ENTRY(path, accelerator, callback, action, data) \
{path, accelerator, GTK_MENU_FUNC(callback), action, "<StockItem>", data}

#ifdef HAVE_LIBPCAP
#define WIRESHARK_STOCK_LABEL_CAPTURE_INTERFACES       "_Interfaces"
#define WIRESHARK_STOCK_LABEL_CAPTURE_OPTIONS          "_Options"
#define WIRESHARK_STOCK_LABEL_CAPTURE_START            "_Start"
#define WIRESHARK_STOCK_LABEL_CAPTURE_STOP             "S_top"
#define WIRESHARK_STOCK_LABEL_CAPTURE_RESTART          "_Restart"
#define WIRESHARK_STOCK_LABEL_CAPTURE_FILTER           "_CFilter"
#define WIRESHARK_STOCK_LABEL_CAPTURE_FILTER_ENTRY     "_Capture Filter:"
#endif
#define WIRESHARK_STOCK_LABEL_DISPLAY_FILTER           "_Filter"
#define WIRESHARK_STOCK_LABEL_DISPLAY_FILTER_ENTRY     "_Filter:"
#define WIRESHARK_STOCK_LABEL_PREFS                    "_Prefs"
#define WIRESHARK_STOCK_LABEL_BROWSE                   "_Browse..."
#define WIRESHARK_STOCK_LABEL_CREATE_STAT              "Create _Stat"
#define WIRESHARK_STOCK_LABEL_EXPORT                   "_Export..."
#define WIRESHARK_STOCK_LABEL_IMPORT                   "_Import..."
#define WIRESHARK_STOCK_LABEL_EDIT                     "_Edit..."
#define WIRESHARK_STOCK_LABEL_ADD_EXPRESSION           "_Expression..." /* plus sign coming from icon */
#define WIRESHARK_STOCK_LABEL_DONT_SAVE                "Continue _without Saving"
#define WIRESHARK_STOCK_LABEL_ABOUT                    "_About"
#define WIRESHARK_STOCK_LABEL_COLORIZE                 "_Colorize"
#define WIRESHARK_STOCK_LABEL_AUTOSCROLL               "_Auto Scroll in Live Capture"
#define WIRESHARK_STOCK_LABEL_RESIZE_COLUMNS           "Resize Columns"
#define WIRESHARK_STOCK_LABEL_TIME                     "Time"
#define WIRESHARK_STOCK_LABEL_INTERNET                 "Internet"
#define WIRESHARK_STOCK_LABEL_WEB_SUPPORT              "Web Support"
#define WIRESHARK_STOCK_LABEL_WIKI                     "Wiki"
#define WIRESHARK_STOCK_LABEL_CONVERSATIONS            "Conversations"
#define WIRESHARK_STOCK_LABEL_ENDPOINTS                "Endpoints"
#define WIRESHARK_STOCK_LABEL_GRAPHS                   "Graphs"
#define WIRESHARK_STOCK_LABEL_TELEPHONY                "Telephony"
#define WIRESHARK_STOCK_LABEL_DECODE_AS                "Decode As"
#define WIRESHARK_STOCK_LABEL_CHECKBOX                 "Checkbox"
#define WIRESHARK_STOCK_LABEL_FILE_SET_LIST            "List Files"
#define WIRESHARK_STOCK_LABEL_FILE_SET_NEXT            "Next File"
#define WIRESHARK_STOCK_LABEL_FILE_SET_PREVIOUS        "Previous File"
#define WIRESHARK_STOCK_LABEL_FILTER_OUT_STREAM        "Filter Out This Stream"

#ifdef HAVE_LIBPCAP
#define WIRESHARK_STOCK_CAPTURE_INTERFACES       "Wireshark_Stock_CaptureInterfaces"
#define WIRESHARK_STOCK_CAPTURE_OPTIONS          "Wireshark_Stock_CaptureOptionss"
#define WIRESHARK_STOCK_CAPTURE_START            "Wireshark_Stock_CaptureStart"
#define WIRESHARK_STOCK_CAPTURE_STOP             "Wireshark_Stock_CaptureStop"
#define WIRESHARK_STOCK_CAPTURE_RESTART          "Wireshark_Stock_CaptureRestart"
#define WIRESHARK_STOCK_CAPTURE_FILTER           "Wireshark_Stock_CaptureFilter"
#define WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY     "Wireshark_Stock_CaptureFilter_Entry"
#endif
#define WIRESHARK_STOCK_DISPLAY_FILTER           "Wireshark_Stock_DisplayFilter"
#define WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY     "Wireshark_Stock_DisplayFilter_Entry"
#define WIRESHARK_STOCK_PREFS                    "Wireshark_Stock_Prefs"
#define WIRESHARK_STOCK_BROWSE                   "Wireshark_Stock_Browse"
#define WIRESHARK_STOCK_CREATE_STAT              "Wireshark_Stock_CreateStat"
#define WIRESHARK_STOCK_EXPORT                   "Wireshark_Stock_Export"
#define WIRESHARK_STOCK_IMPORT                   "Wireshark_Stock_Import"
#define WIRESHARK_STOCK_EDIT                     "Wireshark_Stock_Edit"
#define WIRESHARK_STOCK_ADD_EXPRESSION           "Wireshark_Stock_Edit_Add_Expression"
#define WIRESHARK_STOCK_DONT_SAVE                "Wireshark_Stock_Continue_without_Saving"
#define WIRESHARK_STOCK_ABOUT                    "Wireshark_Stock_About"
#define WIRESHARK_STOCK_COLORIZE                 "Wireshark_Stock_Colorize"
#define WIRESHARK_STOCK_AUTOSCROLL               "Wireshark_Stock_Autoscroll"
#define WIRESHARK_STOCK_RESIZE_COLUMNS           "Wireshark_Stock_Resize_Columns"
#define WIRESHARK_STOCK_TIME                     "Wireshark_Stock_Time"
#define WIRESHARK_STOCK_INTERNET                 "Wireshark_Stock_Internet"
#define WIRESHARK_STOCK_WEB_SUPPORT              "Wireshark_Stock_Web_Support"
#define WIRESHARK_STOCK_WIKI                     "Wireshark_Stock_Wiki"
#define WIRESHARK_STOCK_CONVERSATIONS            "Wireshark_Stock_Conversations"
#define WIRESHARK_STOCK_ENDPOINTS                "Wireshark_Stock_Endpoints"
#define WIRESHARK_STOCK_GRAPHS                   "Wireshark_Stock_Graphs"
#define WIRESHARK_STOCK_TELEPHONY                "Wireshark_Stock_Telephony"
#define WIRESHARK_STOCK_DECODE_AS                "Wireshark_Stock_DecodeAs"
#define WIRESHARK_STOCK_CHECKBOX                 "Wireshark_Stock_Checkbox"
#define WIRESHARK_STOCK_FILE_SET_LIST            "Wireshark_Stock_File_Set_List"
#define WIRESHARK_STOCK_FILE_SET_NEXT            "Wireshark_Stock_File_Set_Next"
#define WIRESHARK_STOCK_FILE_SET_PREVIOUS        "Wireshark_Stock_File_Set_Previous"
#define WIRESHARK_STOCK_FILTER_OUT_STREAM        "Wireshark_Stock_Filter_Out_This_Stream"

#define BUTTON_NEW_FROM_STOCK(stock_id) \
gtk_button_new_from_stock(stock_id);

#define CHECK_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
gtk_check_button_new_with_mnemonic(label_text)

#define RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_group, label_text, accel_group) \
gtk_radio_button_new_with_mnemonic_from_widget( \
    radio_group ? GTK_RADIO_BUTTON(radio_group) : NULL, label_text)

#define RADIO_BUTTON_NEW_WITH_LABEL(radio_group, label_text) \
gtk_radio_button_new_with_label_from_widget( \
    radio_group ? GTK_RADIO_BUTTON(radio_group) : NULL, label_text)

#define TOGGLE_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
gtk_toggle_button_new_with_mnemonic(label_text)

/* for details, see "Pango Text Attribute Markup" */
#define PRIMARY_TEXT_START "<span weight=\"bold\" size=\"larger\">"
#define PRIMARY_TEXT_END "</span>"

#define FONT_TYPE PangoFontDescription

#endif /* GTK_MAJOR_VERSION */

#endif /* __COMPAT_MACROS_H__ */
