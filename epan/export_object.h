/* export_object.h
 * GUI independent helper routines common to all export object taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EXPORT_OBJECT_H__
#define __EXPORT_OBJECT_H__

#include "tap.h"
#include "wmem/wmem.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _export_object_entry_t {
    guint32 pkt_num;
    gchar *hostname;
    gchar *content_type;
    gchar *filename;
    /* We need to store a 64 bit integer to hold a file length
      (was guint payload_len;)

      XXX - we store the entire object in the program's address space,
      so the *real* maximum object size is size_t; if we were to export
      objects by going through all of the packets containing data from
      the object, one packet at a time, and write the object incrementally,
      we could support objects that don't fit into the address space. */
    gint64 payload_len;
    guint8 *payload_data;
} export_object_entry_t;

/** Maximum file name size for the file to which we save an object.
    This is the file name size, not the path name size; we impose
    the limit so that the file doesn't have a ridiculously long
    name, e.g. an HTTP object where the URL has a long query part. */
#define EXPORT_OBJECT_MAXFILELEN      255

typedef void (*export_object_object_list_add_entry_cb)(void* gui_data, struct _export_object_entry_t *entry);
typedef export_object_entry_t* (*export_object_object_list_get_entry_cb)(void* gui_data, int row);

typedef struct _export_object_list_t {
    export_object_object_list_add_entry_cb add_entry; //GUI specific handler for adding an object entry
    export_object_object_list_get_entry_cb get_entry; //GUI specific handler for retrieving an object entry
    void* gui_data;                                   //GUI specific data (for UI representation)
} export_object_list_t;

/** Structure for information about a registered exported object */
typedef struct register_eo register_eo_t;

/* When a protocol needs intermediate data structures to construct the
export objects, then it must specify a function that cleans up all
those data structures. This function is passed to export_object_window
and called when tap reset or windows closes occurs. If no function is needed
a NULL value should be passed instead */
typedef void (*export_object_gui_reset_cb)(void);

/** Register the export object handler for the Export Object windows.
 *
 * @param proto_id is the protocol with objects to export
 * @param export_packet_func the tap processing function
 * @param reset_cb handles clearing intermediate data structures constructed
 *  for exporting objects. If no function is needed a NULL value should be passed instead
 * @return Tap id registered for the Export Object
 */
WS_DLL_PUBLIC int register_export_object(const int proto_id, tap_packet_cb export_packet_func, export_object_gui_reset_cb reset_cb);

/** Get protocol ID from Export Object
 *
 * @param eo Registered Export Object
 * @return protocol id of Export Object
 */
WS_DLL_PUBLIC int get_eo_proto_id(register_eo_t* eo);

/** Get string for register_tap_listener call.  Typically of the form <dissector_name>_eo
 *
 * @param eo Registered Export Object
 * @return string for register_tap_listener call
 */
WS_DLL_PUBLIC const char* get_eo_tap_listener_name(register_eo_t* eo);

/** Get tap function handler from Export Object
 *
 * @param eo Registered Export Object
 * @return tap function handler of Export Object
 */
WS_DLL_PUBLIC tap_packet_cb get_eo_packet_func(register_eo_t* eo);

/** Get tap reset function handler from Export Object
 *
 * @param eo Registered Export Object
 * @return tap function handler of Export Object
 */
WS_DLL_PUBLIC export_object_gui_reset_cb get_eo_reset_func(register_eo_t* eo);

/** Get Export Object by its short protocol name
 *
 * @param name short protocol name to fetch.
 * @return Export Object handler pointer or NULL.
 */
WS_DLL_PUBLIC register_eo_t* get_eo_by_name(const char* name);

/** Iterator to walk Export Object list and execute func
 *
 * @param func action to be performed on all Export Objects
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void eo_iterate_tables(wmem_foreach_func func, gpointer user_data);

/** Find all disallowed characters/bytes and replace them with %xx
 *
 * @param in_str string to massage
 * @param maxlen maximum size a string can be post massage
 * @param dup return a copy of the massaged string (?)
 * @return massaged string
 */
WS_DLL_PUBLIC GString *eo_massage_str(const gchar *in_str, gsize maxlen, int dup);

/** Map the content type string to an extension string
 *
 * @param content_type content type to match with extension string
 * @return extension string for content type
 */
WS_DLL_PUBLIC const char *eo_ct2ext(const char *content_type);

/** Free the contents of export_object_entry_t structure
 *
 * @param entry export_object_entry_t structure to be freed
 */
WS_DLL_PUBLIC void eo_free_entry(export_object_entry_t *entry);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EXPORT_OBJECT_H__ */

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
