/* packet-falco-bridge.c
 *
 * By Loris Degioanni
 * Copyright (C) 2021 Sysdig, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// To do:
// - Convert this to C++? It would let us get rid of the glue that is
//   sinsp-span and make string handling a lot easier. However,
//   epan/address.h and driver/ppm_events_public.h both define PT_NONE.
// - Add a configuration preference for configure_plugin?
// - Add a configuration preference for individual conversation filters vs ANDing them?
//   We would need to add deregister_(|log_)conversation_filter before we implement this.

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#include <dlfcn.h>
#endif

#include <epan/exceptions.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/conversation_filter.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>

#include "sinsp-span.h"

typedef enum bridge_field_flags_e {
    BFF_NONE = 0,
    BFF_HIDDEN = 1 << 1, // Unused
    BFF_INFO = 1 << 2,
    BFF_CONVERSATION = 1 << 3
} bridge_field_flags_e;

typedef struct conv_filter_info {
    hf_register_info *field_info;
    bool is_present;
    wmem_strbuf_t *strbuf;
} conv_filter_info;

typedef struct bridge_info {
    sinsp_source_info_t *ssi;
    uint32_t source_id;
    int proto;
    hf_register_info* hf;
    int* hf_ids;
    hf_register_info* hf_v4;
    int *hf_v4_ids;
    hf_register_info* hf_v6;
    int *hf_v6_ids;
    int* hf_id_to_addr_id; // Maps an hf offset to an hf_v[46] offset
    uint32_t visible_fields;
    uint32_t* field_flags;
    int* field_ids;
    uint32_t num_conversation_filters;
    conv_filter_info *conversation_filters;
} bridge_info;

static int proto_falco_bridge = -1;
static gint ett_falco_bridge = -1;
static gint ett_sinsp_span = -1;
static gint ett_address = -1;
static dissector_table_t ptype_dissector_table;

static int dissect_falco_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_sinsp_span(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

/*
 * Array of plugin bridges
 */
bridge_info* bridges = NULL;
guint nbridges = 0;
guint n_conv_fields = 0;

/*
 * sinsp extractor span
 */
sinsp_span_t *sinsp_span = NULL;

/*
 * Fields
 */
static int hf_sdp_source_id_size = -1;
static int hf_sdp_lengths = -1;
static int hf_sdp_source_id = -1;

static hf_register_info hf[] = {
    { &hf_sdp_source_id_size,
        { "Plugin ID size", "falcobridge.id.size",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sdp_lengths,
        { "Field Lengths", "falcobridge.lens",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sdp_source_id,
        { "Plugin ID", "falcobridge.id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
};

// Returns true if the field might contain an IPv4 or IPv6 address.
// XXX This should probably be a preference.
static bool is_addr_field(const char *abbrev) {
    if (strstr(abbrev, ".srcip")) { // ct.srcip
        return true;
    } else if (strstr(abbrev, ".client.ip")) { // okta.client.ip
        return true;
    }
    return false;
}

static gboolean
is_filter_valid(packet_info *pinfo, void *cfi_ptr)
{
    conv_filter_info *cfi = (conv_filter_info *)cfi_ptr;

    if (!cfi->is_present) {
        return FALSE;
    }

    int proto_id = proto_registrar_get_parent(cfi->field_info->hfinfo.id);

    if (proto_id < 0) {
        return false;
    }

    return proto_is_frame_protocol(pinfo->layers, proto_registrar_get_nth(proto_id)->abbrev);
}

static gchar*
build_filter(packet_info *pinfo _U_, void *cfi_ptr)
{
    conv_filter_info *cfi = (conv_filter_info *)cfi_ptr;

    if (!cfi->is_present) {
        return FALSE;
    }

    return ws_strdup_printf("%s eq %s", cfi->field_info->hfinfo.abbrev, cfi->strbuf->str);
}

void
configure_plugin(bridge_info* bi, char* config _U_)
{
    /*
     * Initialize the plugin
     */
    bi->source_id = get_sinsp_source_id(bi->ssi);

    size_t tot_fields = get_sinsp_source_nfields(bi->ssi);
    bi->visible_fields = 0;
    uint32_t addr_fields = 0;
    sinsp_field_info_t sfi;
    bi->num_conversation_filters = 0;

    for (size_t j = 0; j < tot_fields; j++) {
        get_sinsp_source_field_info(bi->ssi, j, &sfi);
        if (sfi.is_hidden) {
            /*
             * Skip the fields that are marked as hidden.
             * XXX Should we keep them and call proto_item_set_hidden?
             */
            continue;
        }
        if (sfi.type == SFT_STRINGZ && is_addr_field(sfi.abbrev)) {
            addr_fields++;
        }
        bi->visible_fields++;

        if (sfi.is_conversation) {
            bi->num_conversation_filters++;
        }
    }

    if (bi->visible_fields) {
        bi->hf = (hf_register_info*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(hf_register_info));
        bi->hf_ids = (int*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(int));
        bi->field_ids = (int*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(int));
        bi->field_flags = (guint32*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(guint32));

        if (addr_fields) {
            bi->hf_id_to_addr_id = (int *)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(int));
            bi->hf_v4 = (hf_register_info*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(hf_register_info));
            bi->hf_v4_ids = (int*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(int));
            bi->hf_v6 = (hf_register_info*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(hf_register_info));
            bi->hf_v6_ids = (int*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(int));
        }

        if (bi->num_conversation_filters) {
            bi->conversation_filters = (conv_filter_info *)wmem_alloc(wmem_epan_scope(), bi->num_conversation_filters * sizeof (conv_filter_info));
        }

        uint32_t fld_cnt = 0;
        size_t conv_fld_cnt = 0;
        uint32_t addr_fld_cnt = 0;

        for (size_t j = 0; j < tot_fields; j++)
        {
            bi->hf_ids[fld_cnt] = -1;
            bi->field_ids[fld_cnt] = (int) j;
            bi->field_flags[fld_cnt] = BFF_NONE;
            hf_register_info* ri = bi->hf + fld_cnt;

            get_sinsp_source_field_info(bi->ssi, j, &sfi);

            if (sfi.is_hidden) {
                /*
                 * Skip the fields that are marked as hidden
                 */
                continue;
            }

            enum ftenum ftype;
            int fdisplay = BASE_NONE;
            switch (sfi.type) {
            case SFT_STRINGZ:
                ftype = FT_STRINGZ;
                break;
            case SFT_UINT64:
                ftype = FT_UINT64;
                switch (sfi.display_format) {
                case SFDF_DECIMAL:
                    fdisplay = BASE_DEC;
                    break;
                case SFDF_HEXADECIMAL:
                    fdisplay = BASE_HEX;
                    break;
                case SFDF_OCTAL:
                    fdisplay = BASE_OCT;
                    break;
                default:
                    THROW_FORMATTED(DissectorError, "error in plugin %s: display format %s is not supported",
                        get_sinsp_source_name(bi->ssi),
                        sfi.abbrev);
                }
                break;
            default:
                THROW_FORMATTED(DissectorError, "error in plugin %s: type of field %s is not supported",
                    get_sinsp_source_name(bi->ssi),
                    sfi.abbrev);
            }

            hf_register_info finfo = {
                bi->hf_ids + fld_cnt,
                {
                    wmem_strdup(wmem_epan_scope(), sfi.display), wmem_strdup(wmem_epan_scope(), sfi.abbrev),
                    ftype, fdisplay,
                    NULL, 0x0,
                    wmem_strdup(wmem_epan_scope(), sfi.description), HFILL
                }
            };
            *ri = finfo;

            if (sfi.is_conversation) {
                bi->field_flags[fld_cnt] |= BFF_CONVERSATION;
                bi->conversation_filters[conv_fld_cnt].field_info = ri;
                bi->conversation_filters[conv_fld_cnt].strbuf = wmem_strbuf_new(wmem_epan_scope(), "");

                const char *source_name = get_sinsp_source_name(bi->ssi);
                const char *conv_filter_name = wmem_strdup_printf(wmem_epan_scope(), "%s %s", source_name, ri->hfinfo.name);
                register_log_conversation_filter(source_name, conv_filter_name, is_filter_valid, build_filter, &bi->conversation_filters[conv_fld_cnt]);
                if (conv_fld_cnt == 0) {
                    add_conversation_filter_protocol(source_name);
                }
                conv_fld_cnt++;
            }

            if (sfi.is_info) {
                bi->field_flags[fld_cnt] |= BFF_INFO;
            }

            if (sfi.type == SFT_STRINGZ && is_addr_field(sfi.abbrev)) {
                bi->hf_id_to_addr_id[fld_cnt] = addr_fld_cnt;

                bi->hf_v4_ids[addr_fld_cnt] = -1;
                hf_register_info* ri_v4 = bi->hf_v4 + addr_fld_cnt;
                hf_register_info finfo_v4 = {
                    bi->hf_v4_ids + addr_fld_cnt,
                    {
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv4)", sfi.display),
                        wmem_strdup_printf(wmem_epan_scope(), "%s.v4", sfi.abbrev),
                        FT_IPv4, BASE_NONE,
                        NULL, 0x0,
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv4)", sfi.description), HFILL
                    }
                };
                *ri_v4 = finfo_v4;

                bi->hf_v6_ids[addr_fld_cnt] = -1;
                hf_register_info* ri_v6 = bi->hf_v6 + addr_fld_cnt;
                hf_register_info finfo_v6 = {
                    bi->hf_v6_ids + addr_fld_cnt,
                    {
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv6)", sfi.display),
                        wmem_strdup_printf(wmem_epan_scope(), "%s.v6", sfi.abbrev),
                        FT_IPv4, BASE_NONE,
                        NULL, 0x0,
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv6)", sfi.description), HFILL
                    }
                };
                *ri_v6 = finfo_v6;
                addr_fld_cnt++;
            } else if (bi->hf_id_to_addr_id) {
                bi->hf_id_to_addr_id[fld_cnt] = -1;
            }
            fld_cnt++;
        }
        proto_register_field_array(proto_falco_bridge, bi->hf, fld_cnt);
        if (addr_fld_cnt) {
            proto_register_field_array(proto_falco_bridge, bi->hf_v4, addr_fld_cnt);
            proto_register_field_array(proto_falco_bridge, bi->hf_v6, addr_fld_cnt);
        }
    }
}

void
import_plugin(char* fname)
{
    nbridges++;
    bridge_info* bi = &bridges[nbridges - 1];

    char *err_str = create_sinsp_source(sinsp_span, fname, &(bi->ssi));
    if (err_str) {
        nbridges--;
        report_failure("Unable to load sinsp plugin %s: %s.", fname, err_str);
        g_free(err_str);
        return;
    }

    configure_plugin(bi, "");

    const char *source_name = get_sinsp_source_name(bi->ssi);
    const char *plugin_name = g_strdup_printf("%s Plugin", source_name);
    bi->proto = proto_register_protocol (
        plugin_name,       /* full name */
        source_name,       /* short name  */
        source_name        /* filter_name */
        );

    static dissector_handle_t ct_handle;
    ct_handle = create_dissector_handle(dissect_sinsp_span, bi->proto);
    dissector_add_uint("falcobridge.id", bi->source_id, ct_handle);
}

static void
on_wireshark_exit(void)
{
    // XXX This currently crashes in a sinsp thread.
    // destroy_sinsp_span(sinsp_span);
    sinsp_span = NULL;
}

void
proto_register_falcoplugin(void)
{
    proto_falco_bridge = proto_register_protocol (
        "Falco Bridge", /* name       */
        "Falco Bridge", /* short name */
        "falcobridge"   /* abbrev     */
        );
    register_dissector("falcobridge", dissect_falco_bridge, proto_falco_bridge);

    /*
     * Create the dissector table that we will use to route the dissection to
     * the appropriate Falco plugin.
     */
    ptype_dissector_table = register_dissector_table("falcobridge.id",
        "Falco Bridge Plugin ID", proto_falco_bridge, FT_UINT32, BASE_DEC);

    /*
     * Load the plugins
     */
    WS_DIR *dir;
    WS_DIRENT *file;
    char *filename;
    char *spdname = g_build_filename(get_plugins_dir_with_version(), "falco", NULL);
    char *ppdname = g_build_filename(get_plugins_pers_dir_with_version(), "falco", NULL);

    /*
     * We scan the plugins directory twice. The first time we count how many
     * plugins we have, which we need to know in order to allocate the right
     * amount of memory. The second time we actually load and configure
     * each plugin.
     */
    if ((dir = ws_dir_open(spdname, 0, NULL)) != NULL) {
        while ((ws_dir_read_name(dir)) != NULL) {
            nbridges++;
        }
        ws_dir_close(dir);
    }

    if ((dir = ws_dir_open(ppdname, 0, NULL)) != NULL) {
        while ((ws_dir_read_name(dir)) != NULL) {
            nbridges++;
        }
        ws_dir_close(dir);
    }

    sinsp_span = create_sinsp_span();

    bridges = g_new0(bridge_info, nbridges);
    nbridges = 0;

    if ((dir = ws_dir_open(spdname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = g_build_filename(spdname, ws_dir_get_name(file), NULL);
            import_plugin(filename);
            g_free(filename);
        }
        ws_dir_close(dir);
    }

    if ((dir = ws_dir_open(ppdname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = g_build_filename(ppdname, ws_dir_get_name(file), NULL);
            import_plugin(filename);
            g_free(filename);
        }
        ws_dir_close(dir);
    }

    g_free(spdname);
    g_free(ppdname);

    /*
     * Setup protocol subtree array
     */
    static gint *ett[] = {
        &ett_falco_bridge,
        &ett_sinsp_span,
        &ett_address,
    };

    proto_register_field_array(proto_falco_bridge, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_shutdown_routine(on_wireshark_exit);
}

static bridge_info*
get_bridge_info(guint32 source_id)
{
    for(guint j = 0; j < nbridges; j++)
    {
        if(bridges[j].source_id == source_id)
        {
            return &bridges[j];
        }
    }

    return NULL;
}

static int
dissect_falco_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Falco Bridge");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    // https://github.com/falcosecurity/libs/blob/9c942f27/userspace/libscap/scap.c#L1900
    proto_item *ti = proto_tree_add_item(tree, proto_falco_bridge, tvb, 0, 12, ENC_NA);
    proto_tree *fb_tree = proto_item_add_subtree(ti, ett_falco_bridge);
    proto_tree_add_item(fb_tree, hf_sdp_source_id_size, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(fb_tree, hf_sdp_lengths, tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_item *idti = proto_tree_add_item(fb_tree, hf_sdp_source_id, tvb, 8, 4, ENC_LITTLE_ENDIAN);

    guint32 source_id = tvb_get_guint32(tvb, 8, ENC_LITTLE_ENDIAN);
    bridge_info* bi = get_bridge_info(source_id);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Plugin ID: %u", source_id);

    if (bi == NULL) {
        proto_item_append_text(idti, " (NOT SUPPORTED)");
        col_append_str(pinfo->cinfo, COL_INFO, " (NOT SUPPORTED)");
        return tvb_captured_length(tvb);
    }

    const char *source_name = get_sinsp_source_name(bi->ssi);
    proto_item_append_text(idti, " (%s)", source_name);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", source_name);

    dissector_handle_t dissector = dissector_get_uint_handle(ptype_dissector_table, source_id);
    if (dissector) {
        tvbuff_t* next_tvb = tvb_new_subset_length(tvb, 12, tvb_captured_length(tvb) - 12);
        call_dissector_with_data(dissector, next_tvb, pinfo, tree, bi);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_sinsp_span(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* bi_ptr)
{
    bridge_info* bi = (bridge_info *) bi_ptr;
    guint plen = tvb_captured_length(tvb);
    const char *source_name = get_sinsp_source_name(bi->ssi);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, source_name);
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item* ti = proto_tree_add_item(tree, bi->proto, tvb, 0, plen, ENC_NA);
    proto_tree* fb_tree = proto_item_add_subtree(ti, ett_sinsp_span);

    guint8* payload = (guint8*)tvb_get_ptr(tvb, 0, plen);

    sinsp_field_extract_t *sinsp_fields = (sinsp_field_extract_t*) wmem_alloc(pinfo->pool, sizeof(sinsp_field_extract_t) * bi->visible_fields);
    for (uint32_t fld_idx = 0; fld_idx < bi->visible_fields; fld_idx++) {
        header_field_info* hfinfo = &(bi->hf[fld_idx].hfinfo);
        sinsp_field_extract_t *sfe = &sinsp_fields[fld_idx];

        sfe->field_id = bi->field_ids[fld_idx];
        sfe->field_name = hfinfo->abbrev;
        sfe->type = hfinfo->type == FT_STRINGZ ? SFT_STRINGZ : SFT_UINT64;
    }

    // If we have a failure, try to dissect what we can first, then bail out with an error.
    bool rc = extract_sisnp_source_fields(bi->ssi, pinfo->num, payload, plen, pinfo->pool, sinsp_fields, bi->visible_fields);

    for (uint32_t idx = 0; idx < bi->num_conversation_filters; idx++) {
        bi->conversation_filters[idx].is_present = false;
        wmem_strbuf_truncate(bi->conversation_filters[idx].strbuf, 0);
    }

    conversation_element_t *first_conv_els = NULL; // hfid + field val + CONVERSATION_LOG

    for (uint32_t fld_idx = 0; fld_idx < bi->visible_fields; fld_idx++) {
        sinsp_field_extract_t *sfe = &sinsp_fields[fld_idx];
        header_field_info* hfinfo = &(bi->hf[fld_idx].hfinfo);

        if (!sfe->is_present) {
            continue;
        }

        conv_filter_info *cur_conv_filter = NULL;
        conversation_element_t *cur_conv_els = NULL;
        if ((bi->field_flags[fld_idx] & BFF_CONVERSATION) != 0) {
            for (uint32_t cf_idx = 0; cf_idx < bi->num_conversation_filters; cf_idx++) {
                if (&(bi->conversation_filters[cf_idx].field_info)->hfinfo == hfinfo) {
                    cur_conv_filter = &bi->conversation_filters[cf_idx];
                    if (!first_conv_els) {
                        first_conv_els = wmem_alloc0(pinfo->pool, sizeof(conversation_element_t) * 3);
                        first_conv_els[0].type = CE_INT;
                        first_conv_els[0].int_val = hfinfo->id;
                        cur_conv_els = first_conv_els;
                    }
                    break;
                }
            }
        }


        if (sfe->type == SFT_STRINGZ && hfinfo->type == FT_STRINGZ) {
            proto_item *pi = proto_tree_add_string(fb_tree, bi->hf_ids[fld_idx], tvb, 0, plen, sfe->res_str);
            if (bi->field_flags[fld_idx] & BFF_INFO) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", sfe->res_str);
                // Mark it hidden, otherwise we end up with a bunch of empty "Info" tree items.
                proto_item_set_hidden(pi);
            }

            int addr_fld_idx = bi->hf_id_to_addr_id[fld_idx];
            if (addr_fld_idx >= 0) {
                ws_in4_addr v4_addr;
                ws_in6_addr v6_addr;
                proto_tree *addr_tree;
                proto_item *addr_item = NULL;
                if (ws_inet_pton4(sfe->res_str, &v4_addr)) {
                    addr_tree = proto_item_add_subtree(pi, ett_address);
                    addr_item = proto_tree_add_ipv4(addr_tree, bi->hf_v4_ids[addr_fld_idx], tvb, 0, 0, v4_addr);
                    set_address(&pinfo->net_src, AT_IPv4, sizeof(ws_in4_addr), &v4_addr);
                } else if (ws_inet_pton6(sfe->res_str, &v6_addr)) {
                    addr_tree = proto_item_add_subtree(pi, ett_address);
                    addr_item = proto_tree_add_ipv6(addr_tree, bi->hf_v6_ids[addr_fld_idx], tvb, 0, 0, &v6_addr);
                    set_address(&pinfo->net_src, AT_IPv6, sizeof(ws_in6_addr), &v6_addr);
                }
                if (addr_item) {
                    proto_item_set_generated(addr_item);
                }
                if (cur_conv_filter) {
                    wmem_strbuf_append(cur_conv_filter->strbuf, sfe->res_str);
                    cur_conv_filter->is_present = true;
                }
                if (cur_conv_els) {
                    cur_conv_els[1].type = CE_ADDRESS;
                    copy_address(&cur_conv_els[1].addr_val, &pinfo->net_src);
                }
            } else {
                if (cur_conv_filter) {
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "\"%s\"", sfe->res_str);
                    cur_conv_filter->is_present = true;
                }
                if (cur_conv_els) {
                    cur_conv_els[1].type = CE_STRING;
                    cur_conv_els[1].str_val = wmem_strdup(pinfo->pool, sfe->res_str);
                }
            }
        }
        else if (sfe->type == SFT_UINT64 && hfinfo->type == FT_UINT64) {
            proto_tree_add_uint64(fb_tree, bi->hf_ids[fld_idx], tvb, 0, plen, sfe->res_u64);
            if (cur_conv_filter) {
                switch (hfinfo->display) {
                case BASE_HEX:
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "%" PRIx64, sfe->res_u64);
                    break;
                case BASE_OCT:
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "%" PRIo64, sfe->res_u64);
                    break;
                default:
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "%" PRId64, sfe->res_u64);
                }
                cur_conv_filter->is_present = true;
            }

            if (cur_conv_els) {
                cur_conv_els[1].type = CE_UINT64;
                cur_conv_els[1].uint64_val = sfe->res_u64;
            }
        }
        else {
            REPORT_DISSECTOR_BUG("Field %s has an unrecognized or mismatched type %u != %u",
                hfinfo->abbrev, sfe->type, hfinfo->type);
        }
    }

    if (!rc) {
        REPORT_DISSECTOR_BUG("Falco plugin %s extract error", get_sinsp_source_name(bi->ssi));
    }

    if (first_conv_els) {
        first_conv_els[2].type = CE_CONVERSATION_TYPE;
        first_conv_els[2].conversation_type_val = CONVERSATION_LOG;
        pinfo->conv_elements = first_conv_els;
//        conversation_t *conv = find_or_create_conversation(pinfo);
//        if (!conv) {
//            conversation_new_full(pinfo->fd->num, pinfo->conv_elements);
//        }
    }

    return plen;
}

void
proto_reg_handoff_sdplugin(void)
{
}
