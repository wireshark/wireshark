/* compat_macros.h
 * GTK-related Global defines, etc.
 *
 * $Id: compat_macros.h,v 1.5 2004/01/10 14:10:43 ulfl Exp $
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

#define STOCK_OK        "OK"
#define STOCK_CANCEL    "Cancel"
#define STOCK_NEW       "New"
#define STOCK_DELETE    "Delete"
#define STOCK_GO_UP     "Up"
#define STOCK_GO_DOWN   "Down"
#define STOCK_APPLY     "Apply"
#define STOCK_SAVE      "Save"
#define STOCK_REVERT_TO_SAVED "Revert"

#define BUTTON_NEW_FROM_STOCK(stock_id) \
gtk_button_new_with_label(stock_id);

#define CHECK_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
dlg_check_button_new_with_label_with_mnemonic(label_text, accel_group)

#define RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_group, label_text, accel_group) \
dlg_radio_button_new_with_label_with_mnemonic( \
    gtk_radio_button_group(GTK_RADIO_BUTTON(radio_group)), label_text, accel_group)

#define TOGGLE_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
dlg_toggle_button_new_with_label_with_mnemonic(label_text, accel_group)

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

#define STOCK_OK        GTK_STOCK_OK
#define STOCK_CANCEL    GTK_STOCK_CANCEL
#define STOCK_NEW       GTK_STOCK_NEW
#define STOCK_DELETE    GTK_STOCK_DELETE
#define STOCK_GO_UP     GTK_STOCK_GO_UP
#define STOCK_GO_DOWN   GTK_STOCK_GO_DOWN
#define STOCK_APPLY     GTK_STOCK_APPLY
#define STOCK_SAVE      GTK_STOCK_SAVE
#define STOCK_REVERT_TO_SAVED   GTK_STOCK_REVERT_TO_SAVED

#define BUTTON_NEW_FROM_STOCK(stock_id) \
gtk_button_new_from_stock(stock_id);

#define CHECK_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
gtk_check_button_new_with_mnemonic(label_text)

#define RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_group, label_text, accel_group) \
gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(radio_group), label_text)

#define TOGGLE_BUTTON_NEW_WITH_MNEMONIC(label_text, accel_group) \
gtk_toggle_button_new_with_mnemonic(label_text)

#endif /* GTK_MAJOR_VERSION */

#endif /* __COMPAT_MACROS_H__ */
