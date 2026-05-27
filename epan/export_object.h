/** @file
 * GUI independent helper routines common to all export object taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "tap.h"
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Represents a single object extracted from a packet capture for export.
 */
typedef struct _export_object_entry_t {
    uint32_t pkt_num;      /**< Packet number in the capture from which this object was extracted. */
    char*    hostname;     /**< Hostname of the server that served the object, if available. */
    char*    content_type; /**< MIME content type of the exported object (e.g. "image/png", "text/html"). */
    char*    filename;     /**< Suggested filename for saving the exported object, if available. */
    size_t   payload_len;  /**< Length in bytes of the exported object's payload data. */
    uint8_t* payload_data; /**< Raw bytes of the exported object's payload. */
} export_object_entry_t;

/** Maximum file name size for the file to which we save an object.
    This is the file name size, not the path name size; we impose
    the limit so that the file doesn't have a ridiculously long
    name, e.g. an HTTP object where the URL has a long query part. */
#define EXPORT_OBJECT_MAXFILELEN      255

/**
 * @brief Callback invoked by a dissector to add a newly extracted object entry into the GUI list.
 * @param gui_data GUI-specific context data passed through from the export_object_list_t.
 * @param entry    The export object entry to be added to the list.
 */
typedef void (*export_object_object_list_add_entry_cb)(void* gui_data, struct _export_object_entry_t* entry);

/**
 * @brief Callback invoked to retrieve an existing object entry from the GUI list by row index.
 * @param gui_data GUI-specific context data passed through from the export_object_list_t.
 * @param row      Zero-based row index of the entry to retrieve.
 * @return Pointer to the export_object_entry_t at the specified row, or NULL if not found.
 */
typedef export_object_entry_t* (*export_object_object_list_get_entry_cb)(void* gui_data, int row);

/**
 * @brief Abstracts the GUI-specific operations needed to manage a list of exported objects during dissection.
 */
typedef struct _export_object_list_t {
    export_object_object_list_add_entry_cb add_entry; /**< GUI-specific callback for appending a new object entry to the list. */
    export_object_object_list_get_entry_cb get_entry; /**< GUI-specific callback for retrieving an object entry by row index. */
    void*                                  gui_data;  /**< Opaque pointer to GUI-specific state passed to each callback. */
} export_object_list_t;

/** Structure for information about a registered exported object */
typedef struct register_eo register_eo_t;

/** When a protocol needs intermediate data structures to construct the
export objects, then it must specify a function that cleans up all
those data structures. This function is passed to export_object_window
and called when tap reset or windows closes occurs. If no function is needed
a NULL value should be passed instead */
typedef void (*export_object_gui_reset_cb)(void);

/** Initialize the export object system.
 */
extern void export_object_init(void);

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

/** Get Export Object by its protocol filter name
 *
 * @param name protocol filter name to fetch.
 * @return Export Object handler pointer or NULL.
 */
WS_DLL_PUBLIC register_eo_t* get_eo_by_name(const char* name);

/** Iterator to walk Export Object list and execute func
 *
 * @param func action to be performed on all Export Objects
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void eo_iterate_tables(wmem_foreach_func func, void *user_data);

/** Find all disallowed characters/bytes and replace them with %xx
 *
 * @param in_str string to massage
 * @param maxlen maximum size a string can be post massage
 * @param dup return a copy of the massaged string (?)
 * @return massaged string
 */
WS_DLL_PUBLIC GString *eo_massage_str(const char *in_str, size_t maxlen, int dup);

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

/** Produce a hash for an export_object_entry_t, ignoring the
 * packet number.
 *
 * @param entry The export_object_entry_t to hash
 * @return A hash
 */
WS_DLL_PUBLIC unsigned eo_entry_hash(export_object_entry_t *entry);

/** Compare two export_object_entry_t for equality. This ignores
 * the packet number, as a primary use case is ignoring objects
 * which are sent more than once in the same capture.
 *
 * @param entry_a The first export_object_entry_t to compare
 * @param entry_b The second export_object_entry_t to compare
 * @return Whether the two entries are equal (ignoring pkt_num).
 */
WS_DLL_PUBLIC bool eo_entry_equal(export_object_entry_t *entry_a, export_object_entry_t *entry_b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
