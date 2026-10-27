/* packet-json.h
 * Routines for JSON dissection
 * References:
 *     RFC 4627: https://tools.ietf.org/html/rfc4627
 *     Website:  http://json.org/
 *
 * Copyright 2010, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_JSON_H
#define _PACKET_JSON_H

#include <wsutil/wsjson.h>

/* XXX - This should probably be a string or custom dissector table */
extern GHashTable *json_header_fields_hash;

/* json data decoding function
 */
typedef void(*json_data_decoder_func)(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, int offset, int len, const char* key_str);

/* Array of functions to dissect IEs
*/
typedef struct _json_ie {
    json_data_decoder_func json_data_decoder;
} json_ie_t;

/* A struct to hold the hf and callback function stored in a hastable with the json key as key.
 * If the callback is null NULL the filter will be used useful to create filterable items in json.
 * XXX Todo: Implement hte UAT from the http dissector to enable the users to create filters? and/or
 * read config from file, similar to Diameter(filter only)?
 */
typedef struct {
    int *hf_id;
    json_data_decoder_func json_data_decoder;
} json_data_decoder_t;

typedef struct _json_key {
    int offset;
    int len;
    char* key_str;
    bool use_compact;
} json_key_t;

/* A struct holding data to be passed to the heuristic dissectors registered
 * in the "json" heuristic table.
 *
 * It carries the parsed form of the JSON data so that a subdissector does not
 * have to parse it again: the jsmn token array built for the JSON+ form
 * is handed over as is.
 *
 * Token offsets are relative to the start of the JSON data, which is also
 * offset 0 of the tvbuff passed to the heuristic dissector, so they can be
 * used directly as tvbuff offsets.
 */
typedef struct _json_heur_data {
    /* media_content_info_t * or NULL if not available */
    void *content_info;

    /* Pointer to the raw JSON. Not NULL terminated: use the token offsets.  */
    const char *buf;

    /* jsmn token array, NULL when the JSON could not be parsed. */
    jsmntok_t *tokens;
    int num_tokens;
} json_heur_data_t;

#endif /* _PACKET_JSON_H */

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
