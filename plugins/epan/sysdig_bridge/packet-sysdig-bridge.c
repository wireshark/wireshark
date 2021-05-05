/* packet-sysdig-bridge.c
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

#include "config.h"

#ifdef _WIN32
#include <Windows.h>
#pragma warning(disable : 4189)
#else
#include <unistd.h>
#include <dlfcn.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
#include <stdio.h>
#include <inttypes.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <wsutil/wsjson.h>
#include <epan/conversation_filter.h>
#include "packet-sysdig-bridge.h"
#include "conversation-macros.h"

static int proto_sdplugin = -1;
static gint ett_sdplugin = -1;
static gint ett_bridge = -1;
static dissector_handle_t json_dissector_handle = NULL;
static dissector_table_t ptype_dissector_table;

static int dissect_sdplugin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);
static int dissect_plg_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

/*
 * Array of plugin bridges
 */
bridge_info* bridges = NULL;
guint nbridges = 0;
guint n_conv_fields = 0;

/*
 * Fields
 */
static int hf_sdp_lengths = -1;
static int hf_sdp_source_id = -1;

static hf_register_info hf[] = {
    { &hf_sdp_lengths,
        { "Field Lengths", "sysdig_plugin.lens",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sdp_source_id,
        { "Plugin ID", "sysdig_plugin.id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
};

/*
 * Conversation filters mappers setup
 */
conv_fld_info conv_fld_infos[MAX_N_CONV_FILTERS];
DECLARE_CONV_FLTS()
char conv_flt_vals[MAX_N_CONV_FILTERS][1024];
guint conv_vals_cnt = 0;
guint conv_fld_cnt = 0;

void
register_conversation_filters_mappings()
{
    MAP_CONV_FLTS()
}

void*
getsym(void* handle, const char* name)
{
#ifdef _WIN32
    return GetProcAddress((HINSTANCE)handle, name);
#else
    return dlsym(handle, name);
#endif
}

/*
 * Polulate a source_plugin_info struct with the symbols coming from a dynamic library
 */
gboolean
create_dynlib_source(const char* libname, ss_plugin_info* info)
{
#ifdef _WIN32
    HINSTANCE handle = LoadLibraryA(libname);
#else
    void* handle = dlopen(libname, RTLD_LAZY);
#endif
    if (handle == NULL) {
        return FALSE;
    }

    *(void**)(&(info->init)) = getsym(handle, "plugin_init");
    *(void**)(&(info->destroy)) = getsym(handle, "plugin_destroy");
    *(void**)(&(info->get_last_error)) = getsym(handle, "plugin_get_last_error");
    *(void**)(&(info->get_type)) = getsym(handle, "plugin_get_type");
    *(void**)(&(info->get_id)) = getsym(handle, "plugin_get_id");
    *(void**)(&(info->get_name)) = getsym(handle, "plugin_get_name");
    *(void**)(&(info->get_filter_name)) = getsym(handle, "plugin_get_filter_name");
    *(void**)(&(info->get_description)) = getsym(handle, "plugin_get_description");
    *(void**)(&(info->get_required_api_version)) = getsym(handle, "plugin_get_required_api_version");
    *(void**)(&(info->get_fields)) = getsym(handle, "plugin_get_fields");
    *(void**)(&(info->open)) = getsym(handle, "plugin_open");
    *(void**)(&(info->close)) = getsym(handle, "plugin_close");
    *(void**)(&(info->next)) = getsym(handle, "plugin_next");
    *(void**)(&(info->next_batch)) = getsym(handle, "plugin_next_batch");
    *(void**)(&(info->event_to_string)) = getsym(handle, "plugin_event_to_string");
    *(void**)(&(info->get_progress)) = getsym(handle, "plugin_get_progress");
    *(void**)(&(info->extract_str)) = getsym(handle, "plugin_extract_str");
    *(void**)(&(info->extract_u64)) = getsym(handle, "plugin_extract_u64");
    *(void**)(&(info->register_async_extractor)) = getsym(handle, "plugin_register_async_extractor");

    return TRUE;
}

void validate_plugin_version(ss_plugin_info* plugin_info)
{
    guint32 pv_maj, pv_min, pv_patch;
    char* avstr = plugin_info->get_required_api_version();

    if (sscanf(avstr, "%" PRIu32 ".%" PRIu32 ".%" PRIu32, &pv_maj, &pv_min, &pv_patch) != 3) {
        THROW_FORMATTED(DissectorError, "unable to load plugin %s: plugin's get_api_version() is returning invalid data. Required format is \"<major>.<minor>.<patch>\", e.g. \"1.2.3\"",
            plugin_info->get_name());
    }

    if (!(pv_maj == PLUGIN_API_VERSION_MAJOR && pv_min <= PLUGIN_API_VERSION_MINOR)) {
        THROW_FORMATTED(DissectorError, "unable to initialize plugin %s: plugin is requesting API version %s which is not supported by this engine (version %u.%u.%u)", 
            plugin_info->get_name(),
            avstr,
            (unsigned int)PLUGIN_API_VERSION_MAJOR,
            (unsigned int)PLUGIN_API_VERSION_MINOR,
            (unsigned int)PLUGIN_API_VERSION_PATCH);
    }
}

void async_plugin_notify(void* wait_ctx)
{
    volatile guint* plock = (volatile guint*)wait_ctx;

    while (TRUE) {
#ifdef _WIN32
        int old_val = InterlockedCompareExchange(plock, LS_INPUT_READY, LS_DONE);
#else
        int old_val = __sync_val_compare_and_swap(plock, LS_DONE, LS_INPUT_READY);
#endif

        if (old_val == LS_DONE) {
            break;
        }
    }

    /*
     * Once INPUT_READY state has been aquired, wait for worker completition
     */
    while(*plock != LS_DONE);
}

gboolean async_plugin_wait(void *wait_ctx)
{
    volatile guint *plock = (volatile guint *)wait_ctx;
    *plock = LS_DONE;
    uint64_t ncycles = 0;
    gboolean sleeping = FALSE;
    guint64 start_time = 0;

    /*
     * Worker has done and now waits for a new input or a shutdown request.
     * Note: we busy loop for the first 1ms to guarantee maximum performance.
     *       After 1ms we start sleeping to conserve CPU.
     */

    while (TRUE) {
#ifdef _WIN32
        int old_val = InterlockedCompareExchange(plock, LS_PROCESSING, LS_INPUT_READY);
#else
        int old_val = __sync_val_compare_and_swap(plock, LS_INPUT_READY, LS_PROCESSING);
#endif

        if (old_val == LS_PROCESSING) {
            return TRUE;
        }

        // shutdown
        if (old_val == LS_SHUTDOWN_REQ) {
            *plock = LS_SHUTDOWN_DONE;
            return FALSE;
        }
        old_val = LS_INPUT_READY;

        if (sleeping) {
#ifdef _WIN32
            Sleep(10);
#else
            usleep(10000);
#endif
        }
        else
        {
            ncycles++;
            if (ncycles >= 100000) {
                if (start_time == 0) {
                    start_time = g_get_monotonic_time();
                } else {
                    guint64 cur_time = g_get_monotonic_time();
                    guint64 delta_time = cur_time - start_time;
                    if (delta_time > 1000000) {
                        sleeping = TRUE;
                    } else {
                        ncycles = 0;
                    }
                }
            }
        }
    }

    /*
     * We should never get here
     */
    return TRUE;
}

void async_plugin_shutdown(void* wait_ctx)
{
    volatile guint* plock = (volatile guint*)wait_ctx;

    while (TRUE) {
#ifdef _WIN32
        int old_val = InterlockedCompareExchange(plock, LS_SHUTDOWN_REQ, LS_DONE);
#else
        int old_val = __sync_val_compare_and_swap(plock, LS_DONE, LS_SHUTDOWN_REQ);
#endif

        if (old_val == LS_DONE) {
            break;
        }
    }

    /*
     * Await shutdown
     */
    while(*plock != LS_SHUTDOWN_DONE);
}

#define ENSURE_PLUGIN_EXPORT(_fn) if(plugin_info->_fn == NULL) THROW_FORMATTED(DissectorError, "invalid source plugin %s: %s export missing", filename, #_fn);

// Returns true if the plugin is allocating a thread for high speed async extraction
gboolean
configure_plugin(char* filename, bridge_info* bi, char* config)
{
    guint32 init_res = SCAP_FAILURE;
    ss_plugin_info* plugin_info = &(bi->si);
    plugin_info->is_async_extractor_configured = FALSE;
    plugin_info->is_async_extractor_present = FALSE;
    plugin_info->lock = LS_INIT;

    ENSURE_PLUGIN_EXPORT(get_type);
    ENSURE_PLUGIN_EXPORT(get_last_error);
    ENSURE_PLUGIN_EXPORT(get_id);
    ENSURE_PLUGIN_EXPORT(get_name);
    ENSURE_PLUGIN_EXPORT(get_description);
    ENSURE_PLUGIN_EXPORT(get_required_api_version);
    ENSURE_PLUGIN_EXPORT(get_fields);
    ENSURE_PLUGIN_EXPORT(get_filter_name);

    /*
     * Get the plugin version and make sure we can run it
     */
    validate_plugin_version(plugin_info);

    /*
     * Initialize the plugin
     */
    if (plugin_info->init != NULL)
    {
        plugin_info->state = plugin_info->init(config, &init_res);
        if (init_res != SCAP_SUCCESS)
        {
            THROW_FORMATTED(DissectorError, "unable to initialize plugin %s", plugin_info->get_name());
        }
    }

    plugin_info->id = (guint32)plugin_info->get_id();
    plugin_info->name = plugin_info->get_name();

    /*
     * Get the plugin fields and convert them into dissector fields.
     * get_fields() returns a JSON-encoded string with an array of entries that look like this:
     *   {type: "string", ID: 1, name: "testname", desc: "test description"}
     * where type can currently be "string" or "uint64".
     * We use wsutil/wsjson.h to perform the JSON parsing.
     */
    if (plugin_info->get_fields) {
        char* sfields = plugin_info->get_fields();
        if(sfields == NULL)
        {
            THROW_FORMATTED(DissectorError, "error in plugin %s: get_fields returned a null string",
                plugin_info->get_name());
        }

        int ret = json_parse(sfields, NULL, 0);
        if (ret <= 0) {
            THROW_FORMATTED(DissectorError, "error in plugin %s: get_fields returned an invalid json",
                plugin_info->get_name());
        }

        jsmntok_t* tkfields = malloc(ret * sizeof(jsmntok_t));
        if (json_parse(sfields, tkfields, ret) <= 0)
        {
            THROW_FORMATTED(DissectorError, "error in plugin %s: get_fields returned an incorrect json",
                plugin_info->get_name());
        }

        /*
         * First pass: count how many fields we have
         */
        bi->n_fields = 0;
        for (int j = 0; j < ret; j++)
        {
            jsmntok_t* tok = tkfields + j;
            if (tok->type == JSMN_OBJECT) {
                char* properties = json_get_string(sfields, tok, "properties");
                if (properties != NULL && (strstr(properties, "hidden") != NULL)) {
                    /*
                     * Skip the fields that are marked as hidden
                     */
                    continue;
                }

                if (strstr(properties, "conversation") != NULL) {
                    n_conv_fields++;
                    if (n_conv_fields >= MAX_N_CONV_FILTERS) {
                        THROW_FORMATTED(DissectorError, "too many conversation fields in sysdig plugins.");
                    }
                }

                bi->n_fields++;
            }
        }

        bi->hf = (hf_register_info*)wmem_alloc(wmem_epan_scope(), bi->n_fields * sizeof(hf_register_info));
        bi->hf_ids = (int*)wmem_alloc(wmem_epan_scope(), bi->n_fields * sizeof(int));
        bi->field_ids = (guint64*)wmem_alloc(wmem_epan_scope(), bi->n_fields * sizeof(guint64));
        bi->field_flags = (guint32*)wmem_alloc(wmem_epan_scope(), bi->n_fields * sizeof(guint32));

        for (guint j = 0; j < bi->n_fields; j++)
        {
            bi->hf_ids[j] = -1;
            bi->field_ids[j] = -1;
            bi->field_flags[j] = 0;
        }

        /*
         * Second pass: parse the fields and populate the dissector list
         */
        guint fld_cnt = 0;
        for (int j = 0; j < ret; j++)
        {
            jsmntok_t* tok = tkfields + j;
            if (tok->type == JSMN_OBJECT) {
                hf_register_info* ri = bi->hf + fld_cnt;

                char* properties = json_get_string(sfields, tok, "properties");
                if (properties != NULL && (strstr(properties, "hidden") != NULL)) {
                    /*
                     * Skip the fields that are marked as hidden
                     */
                    continue;
                }

                char* type = json_get_string(sfields, tok, "type");
                char* name = json_get_string(sfields, tok, "name");
                char* display = json_get_string(sfields, tok, "display");
                char* desc = json_get_string(sfields, tok, "desc");
                double did;
                /*
                 * wsjson doesn't seem to have support for integer numbers, so we
                 * go through a floating point conversion.
                 */
                json_get_double(sfields, tok, "ID", &did);
                guint id = (guint)did;

                enum ftenum wstype;
                field_display_e disp;

                if (strcmp(type, "string") == 0) {
                    wstype = FT_STRINGZ;
                    disp = BASE_NONE;
                } else if (strcmp(type, "uint64") == 0) {
                    wstype = FT_UINT64;
                    disp = BASE_DEC;
                } else {
                    THROW_FORMATTED(DissectorError, "error in plugin %s: type of field %s is not supported",
                        plugin_info->get_name(),
                        name);
                }

                hf_register_info finfo = {
                    bi->hf_ids + fld_cnt,
                    {
                        display, name,
                        wstype, disp,
                        NULL, 0x0,
                        desc, HFILL
                    }
                };
                *ri = finfo;

                bi->field_ids[fld_cnt] = id;

                if (strstr(properties, "info") != NULL) {
                    bi->field_flags[fld_cnt] |= FLD_FLAG_USE_IN_INFO;
                }

                if (strstr(properties, "conversation") != NULL) {
                    bi->field_flags[fld_cnt] |= FLD_FLAG_USE_IN_CONVERSATIONS;
                    conv_fld_infos[conv_fld_cnt].field_info = ri;
                    conv_fld_infos[conv_fld_cnt].proto_name = plugin_info->get_filter_name();
                    register_conversation_filter(plugin_info->name, display, fv_func[conv_fld_cnt], bfs_func[conv_fld_cnt]);
                    conv_fld_cnt++;
                }

                fld_cnt++;
            }
        }

        free(tkfields);

        proto_register_field_array(proto_sdplugin, bi->hf, fld_cnt);
    }

    /*
     * If the plugin exports an async interface, configure it for usage
     */
    if (!plugin_info->is_async_extractor_configured) {
        if (plugin_info->register_async_extractor) {
            plugin_info->async_extractor_info.wait_ctx = (void*)&(plugin_info->lock);
            plugin_info->async_extractor_info.cb_wait = async_plugin_wait;

            if (plugin_info->register_async_extractor(plugin_info->state, &(plugin_info->async_extractor_info)) != SCAP_SUCCESS) {
                THROW_FORMATTED(DissectorError, "error in plugin %s: %s",
                    plugin_info->get_name(),
                    plugin_info->get_last_error(plugin_info->state));
            }

            plugin_info->is_async_extractor_present = TRUE;
        } else {
            plugin_info->is_async_extractor_present = FALSE;
        }

        plugin_info->is_async_extractor_configured = TRUE;
    }

    return FALSE;
}

void
import_plugin(char* fname, guint pos)
{
    bridge_info* bi = &bridges[pos];

    if (create_dynlib_source(fname, &(bi->si)) == FALSE) {
        THROW_FORMATTED(DissectorError, "unable to load sysdig plugin %s.", fname);
    }

    configure_plugin(fname, bi, "");

    bi->proto = proto_register_protocol (
        bi->si.name,              /* name */
        bi->si.get_filter_name(), /* short name  */
        bi->si.get_filter_name()  /* filter_name */
        );

    static dissector_handle_t ct_handle;
    ct_handle = create_dissector_handle(dissect_plg_bridge, bi->proto);
    dissector_add_uint("sysdig_plugin.id", bi->si.id, ct_handle);
}

static void
on_wireshark_exit(void)
{
    for (guint j = 0; j < nbridges; j++) {
        bridge_info* bi = bridges + j;
        if (bi->si.register_async_extractor != NULL) {
            async_plugin_shutdown((void*)&(bi->si.lock));
        }
    }
}

void
proto_register_sdplugin(void)
{
    proto_sdplugin = proto_register_protocol (
        "Sysdig Plugin", /* name       */
        "SDPLUGIN",      /* short name */
        "sdplugin"       /* abbrev     */
        );
    register_dissector("sdplugin", dissect_sdplugin, proto_sdplugin);

    /*
     * Create the dissector table that we will use to route the dissection to
     * the appropriate sysdig plugin.
     */
    ptype_dissector_table = register_dissector_table("sysdig_plugin.id",
        "Plugin ID", proto_sdplugin, FT_UINT32, BASE_DEC);

    /*
     * Create the mapping infrastructure for conversation filtering
     */
    register_conversation_filters_mappings();

    /*
     * Load the plugins
     */
    nbridges = 1;
    bridges = (bridge_info*)g_malloc(nbridges * sizeof(bridge_info));

#ifdef _WIN32
    import_plugin("cloudtrail.dll", 0);
#else
    import_plugin("libcloudtrail.so", 0);
#endif

    /*
     * Setup protocol subtree array
     */
    static gint *ett[] = {
        &ett_sdplugin,
        &ett_bridge,
    };

    proto_register_field_array(proto_sdplugin, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_cleanup_routine(on_wireshark_exit);
}

static bridge_info*
get_bridge_info(guint32 source_id)
{
    for(guint j = 0; j < nbridges; j++)
    {
        if(bridges[j].si.id == source_id)
        {
            return &bridges[j];
        }
    }

    return NULL;
}

static int
dissect_sdplugin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conv_vals_cnt = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Sysdig Plugin");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_sdplugin, tvb, 0, 8, ENC_NA);
    proto_tree *sdplugin_tree = proto_item_add_subtree(ti, ett_sdplugin);
    proto_tree_add_item(sdplugin_tree, hf_sdp_lengths, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_item *idti = proto_tree_add_item(sdplugin_tree, hf_sdp_source_id, tvb, 4, 4, ENC_LITTLE_ENDIAN);

    guint32 source_id = tvb_get_guint32(tvb, 4, ENC_LITTLE_ENDIAN);
    bridge_info* bi = get_bridge_info(source_id);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Plugin ID: %u", (unsigned)source_id);

    if (bi == NULL) {
        proto_item_append_text(idti, " (NOT SUPPORTED)");
        col_append_str(pinfo->cinfo, COL_INFO, " (NOT SUPPORTED)");
        return tvb_captured_length(tvb);
    }

    proto_item_append_text(idti, " (%s)", bi->si.name);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", bi->si.name);

    dissector_handle_t dissector = dissector_get_uint_handle(ptype_dissector_table, source_id);
    if (dissector) {
        p_add_proto_data(pinfo->pool, pinfo, proto_sdplugin, PROTO_DATA_BRIDGE_HANDLE, bi);
        tvbuff_t* next_tvb = tvb_new_subset_length(tvb, 8, tvb_captured_length(tvb) - 8);
        call_dissector_with_data(dissector, next_tvb, pinfo, tree, data);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_plg_bridge(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    bridge_info* bi = p_get_proto_data(pinfo->pool, pinfo, proto_sdplugin, PROTO_DATA_BRIDGE_HANDLE);
    guint plen = tvb_captured_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, bi->si.name);
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item* ti = proto_tree_add_item(tree, bi->proto, tvb, 0, plen, ENC_NA);
    proto_tree* sdplugin_tree = proto_item_add_subtree(ti, ett_bridge);

    guint8* payload = (guint8*)tvb_get_ptr(tvb, 0, plen);
    ss_plugin_info* si = &bi->si;

    for (guint j = 0; j < bi->n_fields; j++) {
        header_field_info* hfinfo = &(bi->hf[j].hfinfo);
        ss_plugin_info* plugin_info = &(bi->si);

        if (plugin_info->is_async_extractor_present) {
            plugin_info->async_extractor_info.evtnum = pinfo->num;
            plugin_info->async_extractor_info.id = (guint32)bi->field_ids[j];
            plugin_info->async_extractor_info.arg = NULL;
            plugin_info->async_extractor_info.data = payload;
            plugin_info->async_extractor_info.datalen = plen;
        }

        if (hfinfo->type == FT_STRINGZ) {
            if (plugin_info->extract_str == NULL) {
                REPORT_DISSECTOR_BUG("sysdig plugin %s is missing the extract_str export", bi->si.name);
            }

            gchar *pret;
            if (plugin_info->is_async_extractor_present) {
                plugin_info->async_extractor_info.ftype = PLG_PARAM_TYPE_CHARBUF;
                async_plugin_notify((void *)&plugin_info->lock);
                pret = plugin_info->async_extractor_info.res_str;
                guint32 rc = plugin_info->async_extractor_info.rc;
                if (rc != SCAP_SUCCESS) {
                    if (rc == SCAP_NOT_SUPPORTED) {
                        REPORT_DISSECTOR_BUG("sysdig plugin %s is missing the extract_str export", bi->si.name);
                    } else {
                        REPORT_DISSECTOR_BUG("sysdig plugin %s extract error %d", bi->si.name, (int)rc);
                    }
                }
            }
            else
            {
                pret = si->extract_str(si->state,
                                       pinfo->num, bi->field_ids[j],
                                       NULL, payload, plen);
            }

            if (pret != NULL && strlen(pret) != 0) {
                proto_tree_add_string(sdplugin_tree, bi->hf_ids[j], tvb, 0, plen, pret);
                if ((bi->field_flags[j] & FLD_FLAG_USE_IN_INFO) != 0) {
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", pret);
                }

                if ((bi->field_flags[j] & FLD_FLAG_USE_IN_CONVERSATIONS) != 0) {
                    char* cvalptr = conv_flt_vals[conv_vals_cnt];
                    sprintf(cvalptr, "%s", pret);
                    p_add_proto_data(pinfo->pool,
                        pinfo,
                        proto_sdplugin,
                        PROTO_DATA_CONVINFO_USER_BASE + conv_vals_cnt, cvalptr);
                }
            }

            if ((bi->field_flags[j] & FLD_FLAG_USE_IN_CONVERSATIONS) != 0) {
                conv_vals_cnt++;
            }
        }
        else if (hfinfo->type == FT_UINT64) {
            if (plugin_info->extract_u64 == NULL)
            {
                REPORT_DISSECTOR_BUG("sysdig plugin %s is missing the extract_u64 export", bi->si.name);
            }

            guint64 field_present;
            guint64 val;

            if (plugin_info->is_async_extractor_present) {
                plugin_info->async_extractor_info.ftype = PLG_PARAM_TYPE_UINT64;
                async_plugin_notify((void*)&plugin_info->lock);
                field_present = plugin_info->async_extractor_info.field_present;
                val = plugin_info->async_extractor_info.res_u64;
                guint32 rc = plugin_info->async_extractor_info.rc;
                if (rc != SCAP_SUCCESS) {
                    if (rc == SCAP_NOT_SUPPORTED) {
                        REPORT_DISSECTOR_BUG("sysdig plugin %s is missing the extract_str export", bi->si.name);
                    } else {
                        REPORT_DISSECTOR_BUG("sysdig plugin %s extract error %d", bi->si.name, (int)rc);
                    }
                }
            } else {
                val = si->extract_u64(si->state,
                    pinfo->num, bi->field_ids[j],
                    NULL, payload, plen, &field_present);
            }
            
            if (field_present) {
                proto_tree_add_uint64(sdplugin_tree, bi->hf_ids[j], tvb, 0, plen, val);
            }
        }
        else {
            REPORT_DISSECTOR_BUG("field %s has an unrecognized type %u",
                hfinfo->name, (unsigned)hfinfo->type);
        }
    }

    //if (json_dissector_handle == NULL) {
    //    json_dissector_handle = find_dissector("json");
    //}
    //call_dissector_with_data(json_dissector_handle, tvb, pinfo, tree, data);

    return plen;
}

void
proto_reg_handoff_sdplugin(void)
{
}

#ifndef _WIN32
#pragma GCC diagnostic pop
#endif
