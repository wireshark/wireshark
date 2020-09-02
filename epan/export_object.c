/* export_object.c
 * GUI independent helper routines common to all export object taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "proto.h"
#include "packet_info.h"
#include "export_object.h"

struct register_eo {
    int proto_id;                        /* protocol id (0-indexed) */
    const char* tap_listen_str;          /* string used in register_tap_listener (NULL to use protocol name) */
    tap_packet_cb eo_func;               /* function to be called for new incoming packets for SRT */
    export_object_gui_reset_cb reset_cb; /* function to parse parameters of optional arguments of tap string */
};

static wmem_tree_t *registered_eo_tables = NULL;

int
register_export_object(const int proto_id, tap_packet_cb export_packet_func, export_object_gui_reset_cb reset_cb)
{
    register_eo_t *table;
    DISSECTOR_ASSERT(export_packet_func);

    table = wmem_new(wmem_epan_scope(), register_eo_t);

    table->proto_id      = proto_id;
    table->tap_listen_str = wmem_strdup_printf(wmem_epan_scope(), "%s_eo", proto_get_protocol_filter_name(proto_id));
    table->eo_func = export_packet_func;
    table->reset_cb = reset_cb;

    if (registered_eo_tables == NULL)
        registered_eo_tables = wmem_tree_new(wmem_epan_scope());

    wmem_tree_insert_string(registered_eo_tables, proto_get_protocol_filter_name(proto_id), table, 0);
    return register_tap(table->tap_listen_str);
}

int get_eo_proto_id(register_eo_t* eo)
{
    if (!eo) {
        return -1;
    }
    return eo->proto_id;
}

const char* get_eo_tap_listener_name(register_eo_t* eo)
{
    return eo->tap_listen_str;
}

tap_packet_cb get_eo_packet_func(register_eo_t* eo)
{
    return eo->eo_func;
}

export_object_gui_reset_cb get_eo_reset_func(register_eo_t* eo)
{
    return eo->reset_cb;
}

register_eo_t* get_eo_by_name(const char* name)
{
    return (register_eo_t*)wmem_tree_lookup_string(registered_eo_tables, name, 0);
}

void eo_iterate_tables(wmem_foreach_func func, gpointer user_data)
{
    wmem_tree_foreach(registered_eo_tables, func, user_data);
}

static GString *eo_rename(GString *gstr, gsize maxlen, int dupn)
{
    GString *gstr_tmp;
    gchar *tmp_ptr;
    GString *ext_str = NULL;

    gstr_tmp = g_string_new("");
    if (dupn != 0) {
        g_string_append_printf (gstr_tmp, "(%d)", dupn);
    }
    if ( (tmp_ptr = strrchr(gstr->str, '.')) != NULL && ((ext_str = g_string_new(tmp_ptr))->len + strlen(gstr_tmp->str) < maxlen) ) {
        /* Retain the extension */
        gstr = g_string_truncate(gstr, gstr->len - ext_str->len);
        if ( gstr->len >= (maxlen - (strlen(gstr_tmp->str) + ext_str->len)) )
            gstr = g_string_truncate(gstr, maxlen - (strlen(gstr_tmp->str) + ext_str->len));
        gstr = g_string_append(gstr, gstr_tmp->str);
        gstr = g_string_append(gstr, ext_str->str);
    }
    else {
        if ( gstr->len >= (maxlen - strlen(gstr_tmp->str)) )
            gstr = g_string_truncate(gstr, maxlen - strlen(gstr_tmp->str));
        gstr = g_string_append(gstr, gstr_tmp->str);
    }

    if (ext_str) {
        g_string_free(ext_str, TRUE);
    }

    g_string_free(gstr_tmp, TRUE);
    return gstr;
}

GString *
eo_massage_str(const gchar *in_str, gsize maxlen, int dupn)
{
    gchar *tmp_ptr;
    /* The characters in "reject" come from:
     * https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions.
     * Add to the list as necessary for other OS's.
     */
    const gchar *reject = "<>:\"/\\|?*"
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
    "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    GString *out_str;

    out_str = g_string_new("");

    /* Find all disallowed characters/bytes and replace them with %xx */
    while ( (tmp_ptr = strpbrk(in_str, reject)) != NULL ) {
        out_str = g_string_append_len(out_str, in_str, tmp_ptr - in_str);
        g_string_append_printf(out_str, "%%%02x", *tmp_ptr);
        in_str = tmp_ptr + 1;
    }
    out_str = g_string_append(out_str, in_str);
    if ( dupn != 0 || out_str->len > maxlen )
        out_str = eo_rename(out_str, maxlen, dupn);
    return out_str;
}

const char *
eo_ct2ext(const char *content_type)
{
    /* TODO: Map the content type string to an extension string.  If no match,
     * return NULL. */
    return content_type;
}

void eo_free_entry(export_object_entry_t *entry)
{
    g_free(entry->hostname);
    g_free(entry->content_type);
    g_free(entry->filename);
    g_free(entry->payload_data);

    g_free(entry);
}

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
