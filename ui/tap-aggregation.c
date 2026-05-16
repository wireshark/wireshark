/* tap-aggregation.c
 * Definitions and functions for tap aggregation
 * By Hamdi Miladi <hamdi.miladi@technica-engineering.de>
 * Copyright 2025 Hamdi Miladi
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/aggregation_fields.h>
#include <recent.h>
#include <ui/tap-aggregation.h>

static aggregation_field_t* taps;
static int                  taps_num;

static tap_packet_status
tapPacket(void* ptr, packet_info* pinfo, epan_dissect_t* edt, const void* data _U_, tap_flags_t flags _U_) {
    const GPtrArray* gp = NULL;
    const aggregation_field_t* agg_field = (aggregation_field_t*)ptr;
    if (edt && agg_field && agg_field->hf_id > 0)
    {
        gp = proto_get_finfo_ptr_array(edt->tree, agg_field->hf_id);
    }
    if (!gp || gp->len < 1 || pinfo == NULL) {
        return TAP_PACKET_DONT_REDRAW;
    }
    GString* key = g_string_new("");
    for (unsigned i = 0; i < gp->len; i++) {
        const field_info* fip = (field_info*)(gp->pdata[i]);
        if (fip->hfinfo->type == FT_PROTOCOL) {
            g_string_append(key, g_strdup(agg_field->field));
            break;
        }
        char* string_repr = fvalue_to_string_repr(NULL, fip->value, FTREPR_DFILTER, 0);
        if (string_repr) {
            g_string_append(key, g_strdup(string_repr));
            wmem_free(NULL, string_repr);
        }
    }
    if (key->len > 0) {
        if (pinfo->fd->aggregation_key == NULL) {
            pinfo->fd->aggregation_key = g_strdup(key->str);
        }
        else {
            size_t len = strlen(key->str) + 1;
            len += strlen(pinfo->fd->aggregation_key);
            gchar* new_key = g_malloc(len);
            if (new_key) {
                snprintf(new_key, len, "%s%s", pinfo->fd->aggregation_key, key->str);
                g_free(pinfo->fd->aggregation_key);
                pinfo->fd->aggregation_key = new_key;
            }
        }
    }
    g_string_free(key, true);
    return TAP_PACKET_DONT_REDRAW;
}

void register_tap_listener_aggregation(void) {
    for (int i = 0; i < taps_num; i++) {
        remove_tap_listener(&taps[i]);
    }
    g_free(taps);
    taps = NULL;
    taps_num = 0;
    if (!recent.aggregation_view) {
        return;
    }
    bool one_valid = false;

    taps = g_new(aggregation_field_t, prefs.aggregation_fields_num);
    char* filter = NULL;
    GList* node;
    char* field;

    // build the filter
    for (int i = 0; i < prefs.aggregation_fields_num; i++) {
        node = g_list_nth(prefs.aggregation_fields, i);
        field = g_strdup((char*)node->data);
        if (filter) {
            char* old_filter = filter;
            filter = g_strdup_printf("%s && %s", old_filter, field);
            g_free(old_filter);
        } else {
            filter = g_strdup(field);
        }
        g_free(field);
    }

    GString* error_string = NULL;
    for (int i = 0; i < prefs.aggregation_fields_num; i++) {
        node = g_list_nth(prefs.aggregation_fields, i);
        field = g_strdup((char*)node->data);
        const header_field_info* hfi = proto_registrar_get_byname(field);
        if (hfi && hfi->id > -1 && taps) {
            taps[i].hf_id = hfi->id;
            taps[i].field = field;
            taps_num = taps_num + 1;
            error_string = register_tap_listener("frame",
                &taps[i],
                filter,
                TL_REQUIRES_PROTO_TREE,
                NULL,
                tapPacket,
                NULL,
                NULL);
            if (error_string) {
                ws_warning("Unable to register tap aggregation for %s field, error: %s", field, error_string->str);
                g_string_free(error_string, true);
            } else if (!one_valid) {
                one_valid = true;
            }
        } else {
            g_free(field);
        }
    }
    g_free(filter);
    recent.aggregation_view = one_valid;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
