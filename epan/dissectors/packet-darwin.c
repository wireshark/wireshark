/* packet-darwin.c
 * Support for Apple Legacy and Custom pcapng blocks and options
 * Copyright 2025, Omer Shapira <oesh@apple.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>

#define PNAME  "Apple Darwin"
#define PSNAME "Darwin"
#define PFNAME "darwin"

void proto_register_darwin(void);
void proto_reg_handoff_darwin(void);

/* Initialize the protocol and registered fields */
static int proto_darwin;

static int hf_process_info;
static int hf_process_info_pname;
static int hf_process_info_pid;
static int hf_process_info_epname;
static int hf_process_info_epid;

static int hf_darwin_metadata;
static int hf_darwin_metadata_svc_code;
static int hf_darwin_metadata_flags;
static int hf_darwin_metadata_flags_reserved;
static int hf_darwin_metadata_flags_wk;
static int hf_darwin_metadata_flags_ch;
static int hf_darwin_metadata_flags_so;
static int hf_darwin_metadata_flags_re;
static int hf_darwin_metadata_flags_ka;
static int hf_darwin_metadata_flags_nf;

static int hf_darwin_metadata_flow_id;
static int hf_darwin_metadata_trace_tag;
static int hf_darwin_metadata_dropped;
static int hf_darwin_metadata_drop_reason;
static int hf_darwin_metadata_drop_line;
static int hf_darwin_metadata_drop_func;

static int hf_darwin_metadata_comp_gencnt;

static int ett_proc_info;
static int ett_proc_info_proc;
static int ett_proc_info_eproc;
static int ett_darwin_metadata;
static int ett_darwin_metadata_flags;
static int ett_darwin_metadata_dropped;

static const value_string darwin_svc_class_vals[] = {
    { 0x0000,  "BE" },
    { 0x0064,  "BK_SYS" },
    { 0x00C8,  "BK" },
    { 0x012C,  "RD" },
    { 0x0190,  "OAM" },
    { 0x01F4,  "AV" },
    { 0x0258,  "RV" },
    { 0x02BC,  "VI" },
    { 0x0320,  "VO" },
    { 0x0384,  "CTL" },
    { 0, NULL }
};

typedef struct darwin_md {
#define PINFO_DARWIN_MD_HAS_DPIB_ID     1
    uint32_t dpib_id;             /**< Id of the Darwin Process Info Block that corresponds to the `proc` */
#define PINFO_DARWIN_MD_HAS_EDPIB_ID    2
    uint32_t effective_dpib_id;   /**< Id of the Darwin Process Info Block that corresponds to the `eproc` */
#define PINFO_DARWIN_MD_HAS_SVC_CODE    4
    uint32_t svc_code;            /**< Service Class Code  */
#define PINFO_DARWIN_MD_HAS_MD_FLAGS    8
    uint32_t md_flags;            /**< Metadata flags  */
#define PINFO_DARWIN_MD_HAS_FLOW_ID     16
    uint32_t flow_id;             /**< Internal flow id (flow =~ TCP / QUIC conn) */
#define PINFO_DARWIN_MD_HAS_TRACE_TAG   32
    uint32_t trace_tag;           /**< Internal trace tag */
#define PINFO_DARWIN_MD_HAS_DROP_REASON   64
    uint32_t drop_reason;         /**< Packet was dropped by kernel (not by libpcap) */
#define PINFO_DARWIN_MD_HAS_DROP_LINE   128
    uint32_t drop_line;           /**< Packet was dropped by kernel (not by libpcap) */
#define PINFO_DARWIN_MD_HAS_DROP_FUNC   256
    const char* drop_func;       /**< Packet was dropped by kernel (not by libpcap) */
#define PINFO_DARWIN_MD_HAS_COMP_GENCNT 512
    uint32_t comp_gencnt;         /**< Generation count */
#define PINFO_DARWIN_MD_OPT_BITMASK (\
    PINFO_DARWIN_MD_HAS_SVC_CODE|\
    PINFO_DARWIN_MD_HAS_MD_FLAGS|\
    PINFO_DARWIN_MD_HAS_FLOW_ID|\
    PINFO_DARWIN_MD_HAS_TRACE_TAG|\
    PINFO_DARWIN_MD_HAS_DROP_REASON|\
    PINFO_DARWIN_MD_HAS_DROP_LINE|\
    PINFO_DARWIN_MD_HAS_DROP_FUNC|\
    PINFO_DARWIN_MD_HAS_COMP_GENCNT\
) /**< Bitmask for Darwin-specific options (v.s. process info, which *may* be present on other systems ) */
    uint64_t present_opts;        /**< Bitmask for present codes */
} darwin_md;


#define DARWIN_MD_FLAG_WK 0x00000020
#define DARWIN_MD_FLAG_CH 0x00000010
#define DARWIN_MD_FLAG_SO 0x00000008
#define DARWIN_MD_FLAG_RE 0x00000004
#define DARWIN_MD_FLAG_KA 0x00000002
#define DARWIN_MD_FLAG_NF 0x00000001
#define DARWIN_MD_FLAG_RESERVED (~(\
	DARWIN_MD_FLAG_WK|\
	DARWIN_MD_FLAG_CH|\
	DARWIN_MD_FLAG_SO|\
	DARWIN_MD_FLAG_RE|\
	DARWIN_MD_FLAG_KA|\
	DARWIN_MD_FLAG_NF))
static int* const darwin_md_flags[] = {
    &hf_darwin_metadata_flags_reserved,
    &hf_darwin_metadata_flags_wk,
    &hf_darwin_metadata_flags_ch,
    &hf_darwin_metadata_flags_so,
    &hf_darwin_metadata_flags_re,
    &hf_darwin_metadata_flags_ka,
    &hf_darwin_metadata_flags_nf,
    NULL
};

static struct darwin_md*
get_darwin_proto_data(packet_info* pinfo)
{
    struct darwin_md* darwin = (struct darwin_md*)p_get_proto_data(wmem_file_scope(), pinfo, proto_darwin, 0);
    if (darwin == NULL)
    {
        darwin = wmem_new0(wmem_file_scope(), struct darwin_md);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_darwin, 0, darwin);
    }

    return darwin;
}

static int
dissect_darwin_dpib_id(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->dpib_id = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_DPIB_ID;

    return 1;
}

static int
dissect_darwin_effective_dpib_id(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->effective_dpib_id = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_EDPIB_ID;

    return 1;
}

static int
dissect_darwin_svc_code(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->svc_code = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_SVC_CODE;

    return 1;
}

static int
dissect_darwin_md_flags(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->md_flags = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_MD_FLAGS;

    return 1;
}

static int
dissect_darwin_flow_id(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->flow_id = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_FLOW_ID;

    return 1;
}

static int
dissect_darwin_trace_tag(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->trace_tag = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_TRACE_TAG;

    return 1;
}

static int
dissect_darwin_drop_reason(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->drop_reason = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_DROP_REASON;

    return 1;
}

static int
dissect_darwin_drop_line(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->drop_line = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_DROP_LINE;

    return 1;
}

static int
dissect_darwin_drop_func(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->drop_func = optval->stringval;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_DROP_FUNC;

    return 1;
}

static int
dissect_darwin_comp_gencnt(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data)
{
    wtap_optval_t* optval = (wtap_optval_t*)data;

    struct darwin_md* darwin = get_darwin_proto_data(pinfo);
    darwin->comp_gencnt = optval->uint32val;
    darwin->present_opts |= PINFO_DARWIN_MD_HAS_COMP_GENCNT;

    return 1;
}

static int
dissect_darwin_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    struct darwin_md* darwin = (struct darwin_md*)p_get_proto_data(wmem_file_scope(), pinfo, proto_darwin, 0);
    proto_item* ti;

    /* Reqiure darwin data */
    if (darwin == NULL)
        return 0;

    int section_number = (pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER) ? pinfo->rec->section_number : 0;

    if (darwin->present_opts & (PINFO_DARWIN_MD_HAS_DPIB_ID | PINFO_DARWIN_MD_HAS_EDPIB_ID)) {
        uint32_t proc_id;
        const char* proc_name;
        uint32_t eproc_id;
        const char* eproc_name;

        proc_id = epan_get_process_id(pinfo->epan, darwin->dpib_id, section_number);
        proc_name = epan_get_process_name(pinfo->epan, darwin->dpib_id, section_number);

        /* If the effective dpib id is not present, or is equal to the primary dpib id,
         * set the eproc_id to proc_id.
         */
        if (((darwin->present_opts & PINFO_DARWIN_MD_HAS_EDPIB_ID) == 0) ||
            (darwin->dpib_id == darwin->effective_dpib_id)) {
            eproc_id = proc_id;
            eproc_name = proc_name;
        }
        else {
            eproc_id = epan_get_process_id(pinfo->epan, darwin->effective_dpib_id, section_number);
            eproc_name = epan_get_process_name(pinfo->epan, darwin->effective_dpib_id, section_number);
        }

        if (proc_name) {
            proto_item* proc_info_item;
            proto_tree* proc_info_tree;

            if (proc_id == eproc_id) {
                proc_info_item = proto_tree_add_item(tree, hf_process_info, tvb, 0, 0, ENC_NA);
                proc_info_tree = proto_item_add_subtree(proc_info_item, ett_proc_info);
                PROTO_ITEM_SET_GENERATED(proc_info_item);
                proto_item_append_text(proc_info_item, ": %s(%u)", proc_name, proc_id);
                ti = proto_tree_add_uint(proc_info_tree, hf_process_info_pid, tvb, 0, 0, proc_id);
                PROTO_ITEM_SET_GENERATED(ti);
                ti = proto_tree_add_string(proc_info_tree, hf_process_info_pname, tvb, 0, 0, proc_name);
                PROTO_ITEM_SET_GENERATED(ti);
            }
            else {
                proc_info_item = proto_tree_add_item(tree, hf_process_info, tvb, 0, 0, ENC_NA);
                proc_info_tree = proto_item_add_subtree(proc_info_item, ett_proc_info);
                PROTO_ITEM_SET_GENERATED(proc_info_item);
                proto_item_append_text(proc_info_item, ": %s(%u) [%s(%u)]", proc_name, proc_id, eproc_name, eproc_id);
                ti = proto_tree_add_uint(proc_info_tree, hf_process_info_pid, tvb, 0, 0, proc_id);
                PROTO_ITEM_SET_GENERATED(ti);
                ti = proto_tree_add_string(proc_info_tree, hf_process_info_pname, tvb, 0, 0, proc_name);
                PROTO_ITEM_SET_GENERATED(ti);
            }

            proto_item_append_text(tree, " proc: %s(%u)", proc_name, proc_id);
        }
        else {
            proto_item_append_text(tree, " pid: %u", proc_id);
        }

        /* This extra scrutiny is to ensure that the effective process id
         * is _actually_ different from the primary process id.
         */
        if ((proc_id != eproc_id) && (eproc_name != NULL)) {
                proto_item_append_text(tree, " [%s(%u)]", eproc_name, eproc_id);
        }
        else {
            proto_item_append_text(tree, " [%u]", eproc_id);
        }
    }

    /* Check for Darwin-specific options, and create a subtree if needed */
    if (darwin->present_opts & PINFO_DARWIN_MD_OPT_BITMASK) {
        proto_item* dmd_item;
        proto_tree* dmd_tree;
        bool first_metadata_item = true;

        dmd_item = proto_tree_add_boolean_format(tree, hf_darwin_metadata, tvb, 0, 0, true, "Darwin Metadata:");
        dmd_tree = proto_item_add_subtree(dmd_item, ett_darwin_metadata);
        PROTO_ITEM_SET_GENERATED(dmd_item);

        if (darwin->present_opts & PINFO_DARWIN_MD_HAS_MD_FLAGS) {
            ti = proto_tree_add_bitmask_value(dmd_tree, tvb, 0, hf_darwin_metadata_flags, ett_darwin_metadata_flags, darwin_md_flags, darwin->md_flags);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(dmd_item, " flags=%s%s%s%s%s%s",
                (darwin->md_flags & DARWIN_MD_FLAG_WK) ? "W" : ".",
                (darwin->md_flags & DARWIN_MD_FLAG_CH) ? "C" : ".",
                (darwin->md_flags & DARWIN_MD_FLAG_SO) ? "S" : ".",
                (darwin->md_flags & DARWIN_MD_FLAG_RE) ? "R" : ".",
                (darwin->md_flags & DARWIN_MD_FLAG_KA) ? "K" : ".",
                (darwin->md_flags & DARWIN_MD_FLAG_NF) ? "N" : "."
            );
            first_metadata_item = false;
        }
        if (darwin->present_opts & PINFO_DARWIN_MD_HAS_SVC_CODE) {
            ti = proto_tree_add_uint(dmd_tree, hf_darwin_metadata_svc_code, tvb, 0, 0, darwin->svc_code);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(dmd_item, "%ssc=%s",
                first_metadata_item ? " " : "; ",
                val_to_str_const(darwin->svc_code, darwin_svc_class_vals, "Unknown"));
            first_metadata_item = false;
        }
        if (darwin->present_opts & PINFO_DARWIN_MD_HAS_FLOW_ID) {
            ti = proto_tree_add_uint(dmd_tree, hf_darwin_metadata_flow_id, tvb, 0, 0, darwin->flow_id);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(dmd_item, "%sfi=%x",
                first_metadata_item ? " " : "; ",
                darwin->flow_id);
            first_metadata_item = false;
        }
        if (darwin->present_opts & PINFO_DARWIN_MD_HAS_TRACE_TAG) {
            ti = proto_tree_add_uint(dmd_tree, hf_darwin_metadata_trace_tag, tvb, 0, 0, darwin->trace_tag);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(dmd_item, "%strace=%x",
                first_metadata_item ? " " : "; ",
                darwin->trace_tag);
            first_metadata_item = false;
        }
        if (darwin->present_opts & (PINFO_DARWIN_MD_HAS_DROP_REASON | PINFO_DARWIN_MD_HAS_DROP_LINE | PINFO_DARWIN_MD_HAS_DROP_FUNC)) {
            proto_tree* drop_tree;
            proto_item* drop_item;

            drop_item = proto_tree_add_boolean(dmd_tree, hf_darwin_metadata_dropped, tvb, 0, 0, true);
            drop_tree = proto_item_add_subtree(drop_item, ett_darwin_metadata_dropped);
            PROTO_ITEM_SET_GENERATED(drop_item);
            proto_item_append_text(dmd_item, "%sdrop", first_metadata_item ? " " : "; ");

            if (darwin->present_opts & PINFO_DARWIN_MD_HAS_DROP_FUNC) {
                ti = proto_tree_add_string(drop_tree, hf_darwin_metadata_drop_func, tvb, 0, 0, darwin->drop_func);
                PROTO_ITEM_SET_GENERATED(ti);
                proto_item_append_text(dmd_item, " %s", darwin->drop_func);
                proto_item_append_text(drop_item, " %s", darwin->drop_func);
            }
            if (darwin->present_opts & PINFO_DARWIN_MD_HAS_DROP_LINE) {
                ti = proto_tree_add_uint(drop_tree, hf_darwin_metadata_drop_line, tvb, 0, 0, darwin->drop_line);
                PROTO_ITEM_SET_GENERATED(ti);
                proto_item_append_text(dmd_item, "%s%u",
                    (darwin->present_opts & PINFO_DARWIN_MD_HAS_DROP_FUNC) ? ":" : " ",
                    darwin->drop_line);
                proto_item_append_text(drop_item, "%s%u",
                    (darwin->present_opts & PINFO_DARWIN_MD_HAS_DROP_FUNC) ? ":" : " ",
                    darwin->drop_line);
            }
            if (darwin->present_opts & PINFO_DARWIN_MD_HAS_DROP_REASON) {
                ti = proto_tree_add_uint(drop_tree, hf_darwin_metadata_drop_reason, tvb, 0, 0, darwin->drop_reason);
                PROTO_ITEM_SET_GENERATED(ti);
                proto_item_append_text(dmd_item, " 0x%x", darwin->drop_reason);
                proto_item_append_text(drop_item, " 0x%x", darwin->drop_reason);
            }
            first_metadata_item = false;
        }
        if (darwin->present_opts & PINFO_DARWIN_MD_HAS_COMP_GENCNT) {
            ti = proto_tree_add_uint(dmd_tree, hf_darwin_metadata_comp_gencnt, tvb, 0, 0, darwin->comp_gencnt);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(dmd_item, "%sgencnt=%u",
                first_metadata_item ? " " : "; ",
                darwin->comp_gencnt);
        }
    }

    return 1;
}

void
proto_register_darwin(void)
{
    /* Register the protocol name and description */
    proto_darwin = proto_register_protocol(PNAME, PSNAME, PFNAME);

    register_dissector("darwin", dissect_darwin_data, proto_darwin);
}


void
proto_reg_handoff_darwin(void)
{
    static hf_register_info hf_darwin_options[] = {
        { &hf_process_info,
          { "Process Information", "frame.darwin.process_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_process_info_pid,
          { "Id", "frame.darwin.process_info.pid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_process_info_pname,
          { "Name", "frame.darwin.process_info.pname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_process_info_epid,
          { "Effective Id", "frame.darwin.process_info.epid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_process_info_epname,
          { "Effective Name", "frame.darwin.process_info.epname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata,
          { "Darwin MD", "frame.darwin",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_svc_code,
          { "Service Class", "frame.darwin.sc",
            FT_UINT8, BASE_DEC, VALS(darwin_svc_class_vals), 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags,
          { "Flags", "frame.darwin.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags_reserved,
          { "Reserved", "frame.darwin.flags.reserved",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), DARWIN_MD_FLAG_RESERVED,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags_wk,
          { "Wake Packet(wk)", "frame.darwin.flags.wk",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), DARWIN_MD_FLAG_WK,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags_ch,
          { "Nexus Channel(ch)", "frame.darwin.flags.ch",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), DARWIN_MD_FLAG_CH,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags_so,
          { "Socket(so)", "frame.darwin.flags.so",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), DARWIN_MD_FLAG_SO,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags_re,
          { "ReXmit(re)", "frame.darwin.flags.re",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), DARWIN_MD_FLAG_RE,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags_ka,
          { "Keep Alive(ka)", "frame.darwin.flags.ka",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), DARWIN_MD_FLAG_KA,
            NULL, HFILL }},
        { &hf_darwin_metadata_flags_nf,
          { "New Flow(nf)",  "frame.darwin.flags.nf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), DARWIN_MD_FLAG_NF,
            NULL, HFILL }},
        { &hf_darwin_metadata_flow_id,
          { "Flow Id", "frame.darwin.flow_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_trace_tag,
          { "Trace Tag", "frame.darwin.trace_tag",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_dropped,
          { "Packet Dropped By Kernel", "frame.darwin.drop",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_drop_reason,
          { "Drop Reason", "frame.darwin.drop.reason_code",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_drop_line,
          { "Drop Line", "frame.darwin.drop.line",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_drop_func,
          { "Drop Func", "frame.darwin.drop.func",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_darwin_metadata_comp_gencnt,
          { "Compression gencnt", "frame.darwin.gencnt",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
    };

    static int *ett_frame_darwin_options[] = {
        &ett_proc_info,
        &ett_proc_info_proc,
        &ett_proc_info_eproc,
        &ett_darwin_metadata,
        &ett_darwin_metadata_flags,
        &ett_darwin_metadata_dropped
    };

    int proto_frame = proto_registrar_get_id_byname("frame");

    proto_register_subtree_array(ett_frame_darwin_options, array_length(ett_frame_darwin_options));
    proto_register_field_array(proto_frame, hf_darwin_options, array_length(hf_darwin_options));

    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_PIB_ID, create_dissector_handle(dissect_darwin_dpib_id, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_EFFECTIVE_PIB_ID, create_dissector_handle(dissect_darwin_effective_dpib_id, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_SVC_CODE, create_dissector_handle(dissect_darwin_svc_code, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_MD_FLAGS, create_dissector_handle(dissect_darwin_md_flags, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_FLOW_ID, create_dissector_handle(dissect_darwin_flow_id, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_TRACE_TAG, create_dissector_handle(dissect_darwin_trace_tag, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_DROP_REASON, create_dissector_handle(dissect_darwin_drop_reason, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_DROP_LINE, create_dissector_handle(dissect_darwin_drop_line, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_DROP_FUNC, create_dissector_handle(dissect_darwin_drop_func, proto_darwin));
    dissector_add_uint("pcapng_packet_block_option", OPT_PKT_DARWIN_COMP_GENCNT, create_dissector_handle(dissect_darwin_comp_gencnt, proto_darwin));
}

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
