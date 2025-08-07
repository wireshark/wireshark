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

aggregation_field_t* taps;
int                  taps_num;

static tap_packet_status
tapPacket(void* ptr, packet_info* pinfo, epan_dissect_t* edt, const void* data _U_, tap_flags_t flags _U_) {
    const GPtrArray* gp = NULL;
    const aggregation_field_t* agg_field = (aggregation_field_t*)ptr;
    if (edt && agg_field && agg_field->hf_id > 0)
    {
        gp = proto_get_finfo_ptr_array(edt->tree, agg_field->hf_id);
    }
    if (!gp || gp->len < 1) {
        return TAP_PACKET_DONT_REDRAW;
    }

    aggregation_key* key = g_new0(aggregation_key, 1);
    key->field = g_strdup(agg_field->field);
    key->values_num = 0;
    const fvalue_t* value;
    for (unsigned i = 0; i < gp->len; i++) {
        char* value_str = NULL;
        value = ((field_info*)gp->pdata[i])->value;
        switch (proto_registrar_get_ftype(agg_field->hf_id)) {
        case FT_PROTOCOL:
            value_str = g_strdup(key->field);
            break;
        case FT_INT8:
        case FT_INT16:
        case FT_INT32:
        case FT_INT40:
        case FT_INT48:
        case FT_INT56:
        case FT_INT64:
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
        case FT_UINT40:
        case FT_UINT48:
        case FT_UINT56:
        case FT_UINT64:
        case FT_IPv4:
        case FT_IPv6:
        case FT_FLOAT:
        case FT_DOUBLE:
        case FT_ETHER:
        case FT_AX25:
        case FT_IPXNET:
        case FT_EUI64:
        case FT_VINES:
        case FT_SYSTEM_ID:
        case FT_IEEE_11073_SFLOAT:
        case FT_IEEE_11073_FLOAT:
            value_str = fvalue_to_string_repr(NULL, value, FTREPR_DFILTER, BASE_NONE);
            break;
        default:
            break;
        }
        if (value_str) {
            key->values = g_slist_append(key->values, value_str);
            key->values_num = key->values_num + 1;
        }
    }
    if (pinfo && key->values_num > 0) {
        pinfo->fd->aggregation_keys = g_slist_append(pinfo->fd->aggregation_keys, key);
    }
    else {
        free_aggregation_key(key);
    }
    return TAP_PACKET_DONT_REDRAW;
}

bool register_tap_listener_aggregation(void) {
    for (int i = 0; i < taps_num; i++) {
        remove_tap_listener(&taps[i]);
    }
    g_free(taps);
    taps = NULL;
    taps_num = 0;

    if (prefs.aggregation_fields_num > 0 && recent.aggregation_view) {
        taps = g_new(aggregation_field_t, prefs.aggregation_fields_num);
    }
    else {
        return false;
    }

    gchar* filter = NULL;
    GList* node;
    char* field;

    // build the filter
    for (int i = 0; i < prefs.aggregation_fields_num; i++) {
        node = g_list_nth(prefs.aggregation_fields, i);
        field = g_strdup((char*)node->data);
        if (filter) {
            gchar* old_filter = filter;
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
            }
        } else {
            g_free(field);
        }
    }
    return true;
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
