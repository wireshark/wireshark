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
#include "conversation-macros.h"

typedef enum bridge_field_flags_e {
    BFF_NONE = 0,
    BFF_HIDDEN = 1 << 1, // Unused
    BFF_INFO = 1 << 2,
    BFF_CONVERSATION = 1 << 3
} bridge_field_flags_e;

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
} bridge_info;

typedef struct conv_fld_info {
    const char* proto_name;
    hf_register_info* field_info;
    char field_val[4096];
} conv_fld_info;

static int proto_falco_bridge = -1;
static gint ett_falco_bridge = -1;
static gint ett_sinsp_span = -1;
static gint ett_address = -1;
static dissector_table_t ptype_dissector_table;

static int dissect_falco_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_sinsp_span(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

void register_conversation_filters_mappings(void);

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

/*
 * Conversation filters mappers setup
 */
#define MAX_CONV_FILTER_STR_LEN 1024
static conv_fld_info conv_fld_infos[MAX_N_CONV_FILTERS];
DECLARE_CONV_FLTS()
static char conv_flt_vals[MAX_N_CONV_FILTERS][MAX_CONV_FILTER_STR_LEN];
static guint conv_vals_cnt = 0;

void
register_conversation_filters_mappings(void)
{
    MAP_CONV_FLTS()
}

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

            if (sfi.is_info) {
                bi->field_flags[fld_cnt] |= BFF_INFO;
            }

            if (sfi.is_conversation) {
                bi->field_flags[fld_cnt] |= BFF_CONVERSATION;
                conv_fld_infos[conv_fld_cnt].field_info = ri;
                const char *source_name = get_sinsp_source_name(bi->ssi);
                conv_fld_infos[conv_fld_cnt].proto_name = source_name;
                // XXX We currently build a filter per field. Should we "and" them instead?
                register_log_conversation_filter(source_name, finfo.hfinfo.name, fv_func[conv_fld_cnt], bfs_func[conv_fld_cnt]);
                conv_fld_cnt++;
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
        if (conv_fld_cnt > 0) {
            add_conversation_filter_protocol(get_sinsp_source_name(bi->ssi));
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
     * Create the mapping infrastructure for conversation filtering
     */
    register_conversation_filters_mappings();

    /*
     * Load the plugins
     */
    WS_DIR *dir;
    WS_DIRENT *file;
    char *filename;
    char *dname = g_build_filename(get_plugins_dir_with_version(), "falco", NULL);

    /*
     * We scan the plugins directory twice. The first time we count how many
     * plugins we have, which we need to know in order to allocate the right
     * amount of memory. The second time we actually load and configure
     * each plugin.
     */
    if ((dir = ws_dir_open(dname, 0, NULL)) != NULL) {
        while ((ws_dir_read_name(dir)) != NULL) {
            nbridges++;
        }
        ws_dir_close(dir);
    }

    sinsp_span = create_sinsp_span();

    bridges = g_new0(bridge_info, nbridges);
    nbridges = 0;

    if ((dir = ws_dir_open(dname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = g_build_filename(dname, ws_dir_get_name(file), NULL);
            import_plugin(filename);
            g_free(filename);
        }
        ws_dir_close(dir);
    }
    g_free(dname);

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

#define PROTO_DATA_BRIDGE_HANDLE    0x00
static int
dissect_falco_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conv_vals_cnt = 0;

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
        p_add_proto_data(pinfo->pool, pinfo, proto_falco_bridge, PROTO_DATA_BRIDGE_HANDLE, bi);
        tvbuff_t* next_tvb = tvb_new_subset_length(tvb, 12, tvb_captured_length(tvb) - 12);
        call_dissector_with_data(dissector, next_tvb, pinfo, tree, data);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_sinsp_span(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    bridge_info* bi = p_get_proto_data(pinfo->pool, pinfo, proto_falco_bridge, PROTO_DATA_BRIDGE_HANDLE);
    guint plen = tvb_captured_length(tvb);
    const char *source_name = get_sinsp_source_name(bi->ssi);
    wmem_array_t *conversation_elements = wmem_array_new(pinfo->pool, sizeof(conversation_element_t));

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

    for (uint32_t fld_idx = 0; fld_idx < bi->visible_fields; fld_idx++) {
        sinsp_field_extract_t *sfe = &sinsp_fields[fld_idx];
        header_field_info* hfinfo = &(bi->hf[fld_idx].hfinfo);
        conversation_element_t conv_el = {0};

        if (!sfe->is_present) {
            continue;
        }

        if ((bi->field_flags[fld_idx] & BFF_CONVERSATION) != 0) {
            conv_vals_cnt++;
        }

        if (sfe->type == SFT_STRINGZ && hfinfo->type == FT_STRINGZ) {
            proto_item *pi = proto_tree_add_string(fb_tree, bi->hf_ids[fld_idx], tvb, 0, plen, sfe->res_str);
            if (bi->field_flags[fld_idx] & BFF_INFO) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", sfe->res_str);
                // Mark it hidden, otherwise we end up with a bunch of empty "Info" tree items.
                proto_item_set_hidden(pi);
            }

            if ((bi->field_flags[fld_idx] & BFF_CONVERSATION) != 0) {
                char* cvalptr = conv_flt_vals[conv_vals_cnt];
                snprintf(cvalptr, MAX_CONV_FILTER_STR_LEN, "%s", sfe->res_str);
                p_add_proto_data(pinfo->pool,
                                 pinfo,
                                 proto_falco_bridge,
                                 PROTO_DATA_CONVINFO_USER_BASE + conv_vals_cnt, cvalptr);
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
                if ((bi->field_flags[fld_idx] & BFF_CONVERSATION) != 0) {
                    conv_el.type = CE_ADDRESS;
                    copy_address(&conv_el.addr_val, &pinfo->net_src);
                }
            } else {
                if ((bi->field_flags[fld_idx] & BFF_CONVERSATION) != 0) {
                    conv_el.type = CE_STRING;
                    conv_el.str_val = wmem_strdup(pinfo->pool, sfe->res_str);
                }
            }
        }
        else if (sfe->type == SFT_UINT64 && hfinfo->type == FT_UINT64) {
            proto_tree_add_uint64(fb_tree, bi->hf_ids[fld_idx], tvb, 0, plen, sfe->res_u64);
            if ((bi->field_flags[fld_idx] & BFF_CONVERSATION) != 0) {
                conv_el.type = CE_UINT64;
                conv_el.uint64_val = sfe->res_u64;
            }
        }
        else {
            REPORT_DISSECTOR_BUG("Field %s has an unrecognized or mismatched type %u != %u",
                hfinfo->abbrev, sfe->type, hfinfo->type);
        }
        if (conv_el.type != CE_CONVERSATION_TYPE) {
            wmem_array_append_one(conversation_elements, conv_el);
        }
    }

    if (!rc) {
        REPORT_DISSECTOR_BUG("Falco plugin %s extract error", get_sinsp_source_name(bi->ssi));
    }

    unsigned num_conv_els = wmem_array_get_count(conversation_elements);
    if (num_conv_els > 0) {
        conversation_element_t conv_el;
        conv_el.type = CE_CONVERSATION_TYPE;
        conv_el.conversation_type_val = CONVERSATION_LOG;
        wmem_array_append_one(conversation_elements, conv_el);
        pinfo->conv_elements = (conversation_element_t *) wmem_array_get_raw(conversation_elements);
        conversation_t *conv = find_conversation_pinfo(pinfo, 0);
        if (!conv) {
            conversation_new_full(pinfo->fd->num, pinfo->conv_elements);
        }
    }

    return plen;
}

void
proto_reg_handoff_sdplugin(void)
{
}
