/* packet-mctp.c
 * Routines for Management Component Transport Protocol (MCTP) packet
 * disassembly
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MCTP is a datagram-based protocol for intra-platform communication,
 * typically between a management controller and system devices.
 *
 * MCTP is defined by DMTF standard DSP0236: https://www.dmtf.org/dsp/DSP0236
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/capture_dissectors.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>
#include <epan/tfs.h>
#include <wiretap/wtap.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>
#include "packet-mctp.h"
#include "packet-sll.h"

/* DSP0236 Table 1: only a start packet carries the type byte. */
#define MCTP_HDR_LENGTH 4
#define MCTP_MIN_LENGTH 5       /* start packet: 4-byte header, plus message type */
#define MCTP_BASELINE_TU 64     /* DSP0236 8.4.2, packet payload bytes */

/* Outcome of the DSP0236 8.7/8.9 assembly checks, stashed per frame. */
#define MCTP_ASSEMBLY_OK        0
#define MCTP_ASSEMBLY_ORPHAN    1  /* 8.7: no assembly in progress; dropped */
#define MCTP_ASSEMBLY_RESTARTED 2  /* 8.9: a new SOM ended the one in progress */
#define MCTP_ASSEMBLY_SEQ_GAP   3  /* 8.9: out-of-sequence packet sequence number */
#define MCTP_ASSEMBLY_PACKET_LIMIT 4  /* the packet cap below, not a DSP0236 rule */
#define MCTP_ASSEMBLY_TIMEOUT   5  /* 8.9: timed-out continuation dropped */

void proto_register_mctp(void);
void proto_reg_handoff_mctp(void);

static int proto_mctp;

/* Packets one message assembly may take (DSP0236 8.5 leaves message size to
 * the message type).  0 counts as 1: an unbounded assembly would make each
 * packet's fragment_add_seq_next() walk a list that never stops growing. */
static unsigned mctp_max_assembly_packets = 4096;
#define MCTP_ASSEMBLY_PACKET_CAP MAX(mctp_max_assembly_packets, 1)
static unsigned mctp_inter_packet_timeout_ms = 100;
static bool mctp_drop_timed_out_assembly;

static bool
capture_mctp(const unsigned char *pd _U_, int offset _U_, int len _U_,
             capture_packet_info_t *cpinfo,
             const union wtap_pseudo_header *pseudo_header _U_)
{
    capture_dissector_increment_count(cpinfo, proto_mctp);
    return true;
}

static int hf_mctp_rsvd;
static int hf_mctp_ver;
static int hf_mctp_dst;
static int hf_mctp_src;
static int hf_mctp_flags;
static int hf_mctp_flags_som;
static int hf_mctp_flags_eom;
static int hf_mctp_seq;
static int hf_mctp_tag;
static int hf_mctp_tag_to;
static int hf_mctp_tag_value;
static int hf_mctp_msg_ic;
static int hf_mctp_msg_type;
static int hf_mctp_vdm;
static int hf_mctp_vdm_pci_vid;
static int hf_mctp_vdm_iana;

static int ett_mctp;
static int ett_mctp_fst;
static int ett_mctp_flags;
static int ett_mctp_tag;
static int ett_mctp_type;
static int ett_mctp_vdm;

static const true_false_string tfs_tag_to = { "Sender", "Receiver" };

static int hf_mctp_fragments;
static int hf_mctp_fragment;
static int hf_mctp_fragment_overlap;
static int hf_mctp_fragment_overlap_conflicts;
static int hf_mctp_fragment_multiple_tails;
static int hf_mctp_fragment_too_long_fragment;
static int hf_mctp_fragment_error;
static int hf_mctp_fragment_count;
static int hf_mctp_reassembled_in;
static int hf_mctp_reassembled_length;
static int hf_mctp_reassembled_data;

static int ett_mctp_fragment;
static int ett_mctp_fragments;

static expert_field ei_mctp_assembly_orphan;
static expert_field ei_mctp_assembly_restarted;
static expert_field ei_mctp_assembly_seq_gap;
static expert_field ei_mctp_assembly_packet_limit;
static expert_field ei_mctp_assembly_timeout;
static expert_field ei_mctp_physical_layer_drop;
static expert_field ei_mctp_bad_version;
static expert_field ei_mctp_tu_mismatch;
static expert_field ei_mctp_short;
static expert_field ei_mctp_vdm_short;
static expert_field ei_mctp_control_fragmented;

/* Per-frame data: assembly outcome, SOM data. */
#define MCTP_PROTO_DATA_ASSEMBLY   0
#define MCTP_PROTO_DATA_TIMEOUT   1
#define MCTP_PROTO_DATA_START      2

#define MCTP_PROTO_DATA_INGRESS_SCOPE 5

static const fragment_items mctp_frag_items = {
    /* Fragment subtrees */
    &ett_mctp_fragment,
    &ett_mctp_fragments,
    /* Fragment fields */
    &hf_mctp_fragments,
    &hf_mctp_fragment,
    &hf_mctp_fragment_overlap,
    &hf_mctp_fragment_overlap_conflicts,
    &hf_mctp_fragment_multiple_tails,
    &hf_mctp_fragment_too_long_fragment,
    &hf_mctp_fragment_error,
    &hf_mctp_fragment_count,
    /* "Reassembled in" field */
    &hf_mctp_reassembled_in,
    /* Reassembled length field */
    &hf_mctp_reassembled_length,
    &hf_mctp_reassembled_data,
    /* Tag */
    "Message fragments"
};

static const value_string flag_vals[] = {
    { 0x00, "none" },
    { 0x01, "EOM" },
    { 0x02, "SOM" },
    { 0x03, "SOM|EOM" },
    { 0x00, NULL },
};

/* DSP0239 1.12.0 Table 1, "MCTP Message Types" */
static const range_string type_vals[] = {
    { MCTP_TYPE_CONTROL, MCTP_TYPE_CONTROL, "MCTP Control Protocol" },
    { MCTP_TYPE_PLDM, MCTP_TYPE_PLDM, "PLDM" },
    { MCTP_TYPE_NCSI, MCTP_TYPE_NCSI, "NC-SI" },
    { MCTP_TYPE_ETHERNET, MCTP_TYPE_ETHERNET, "Ethernet" },
    { MCTP_TYPE_NVME, MCTP_TYPE_NVME, "NVMe-MI" },
    { MCTP_TYPE_SPDM, MCTP_TYPE_SPDM, "SPDM over MCTP" },
    { MCTP_TYPE_SECURED, MCTP_TYPE_SECURED, "Secured Messages" },
    { MCTP_TYPE_CXL_FM, MCTP_TYPE_CXL_FM, "CXL FM API over MCTP" },
    { MCTP_TYPE_CXL_CCI, MCTP_TYPE_CXL_CCI, "CXL CCI over MCTP" },
    { MCTP_TYPE_PCIE_MI, MCTP_TYPE_PCIE_MI, "PCIe-MI over MCTP" },
    { 0x0a, 0x7d, "Reserved" },
    { MCTP_TYPE_VDM_PCI, MCTP_TYPE_VDM_PCI, "Vendor Defined - PCI" },
    { MCTP_TYPE_VDM_IANA, MCTP_TYPE_VDM_IANA, "Vendor Defined - IANA" },
    { 0, 0, NULL },
};

/* DSP0236 Table 2. Assigned EIDs keep their plain numeric display. */
static const range_string mctp_dst_eid_vals[] = {
    { 0x00, 0x00, "Null Destination EID" },
    { 0x01, 0x07, "Reserved" },
    { 0xff, 0xff, "Broadcast EID" },
    { 0, 0, NULL },
};

static const range_string mctp_src_eid_vals[] = {
    { 0x00, 0x00, "Null Source EID" },
    { 0x01, 0x07, "Reserved" },
    { 0xff, 0xff, "Broadcast EID" },
    { 0, 0, NULL },
};

static dissector_handle_t mctp_handle;
static dissector_table_t mctp_dissector_table;
static dissector_table_t mctp_encap_dissector_table;
static dissector_table_t mctp_vdm_pci_dissector_table;
static dissector_table_t mctp_vdm_iana_dissector_table;
static dissector_handle_t mctp_vdm_handle;
static reassembly_table mctp_reassembly_table;

/* The ingress scope (capture domain) of this packet; never fails. */
void
mctp_ingress_scope_get(const packet_info *pinfo, mctp_ingress_scope *scope)
{
    const mctp_dissector_data *data;

    memset(scope, 0, sizeof(*scope));

    if (pinfo->rec != NULL && pinfo->rec->rec_type == REC_TYPE_PACKET) {
        if (pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER)
            scope->section = pinfo->rec->section_number;
        if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
            scope->interface_id_valid = 1;
            scope->interface_id =
                pinfo->rec->rec_header.packet_header.interface_id;
        }
    }

    data = (const mctp_dissector_data *)p_get_proto_data(
        pinfo->pool, (packet_info *)pinfo, proto_mctp,
        MCTP_PROTO_DATA_INGRESS_SCOPE);
    if (data && data->has_ingress_scope) {
        scope->kind = data->ingress_scope_kind;
        scope->value = data->ingress_scope_value;
        return;
    }

    if (scope->interface_id_valid) {
        scope->kind = MCTP_SCOPE_INTERFACE;
        scope->value = scope->interface_id;
    }
}

/* Reassembly key (DSP0236 8.6): the message terminus plus the destination
 * EID and the physical addresses, which tell null-EID endpoints apart. */
typedef struct _mctp_fragment_key {
    address phys_src;
    address phys_dst;
    address eid_src;
    address eid_dst;
    uint32_t id;
    /* The ingress scope can only tell assemblies apart, never split one. */
    mctp_ingress_scope scope;
} mctp_fragment_key;

/* The scope is hashed and compared as bytes: no padding, and
 * mctp_ingress_scope_get() zero-fills it. */
static_assert(sizeof(mctp_ingress_scope) == 5 * sizeof(uint32_t),
              "mctp_ingress_scope must have no padding");

static unsigned
mctp_fragment_hash(const void *k)
{
    const mctp_fragment_key *key = (const mctp_fragment_key *)k;
    unsigned hash_val = key->id;

    /* The id is only the 4-bit tag, so unlike the address-only tables in
     * epan/reassemble.c the addresses have to be hashed too. */
    hash_val = add_address_to_hash(hash_val, &key->phys_src);
    hash_val = add_address_to_hash(hash_val, &key->phys_dst);
    hash_val = add_address_to_hash(hash_val, &key->eid_src);
    hash_val = add_address_to_hash(hash_val, &key->eid_dst);
    for (size_t i = 0; i < sizeof(key->scope); i++)
        hash_val = (hash_val << 5) - hash_val + ((const uint8_t *)&key->scope)[i];

    return hash_val;
}

static int
mctp_fragment_equal(const void *k1, const void *k2)
{
    const mctp_fragment_key *key1 = (const mctp_fragment_key *)k1;
    const mctp_fragment_key *key2 = (const mctp_fragment_key *)k2;

    return key1->id == key2->id &&
           memcmp(&key1->scope, &key2->scope, sizeof(key1->scope)) == 0 &&
           addresses_equal(&key1->eid_src, &key2->eid_src) &&
           addresses_equal(&key1->eid_dst, &key2->eid_dst) &&
           addresses_equal(&key1->phys_src, &key2->phys_src) &&
           addresses_equal(&key1->phys_dst, &key2->phys_dst);
}

/* For lookup and deletion only: the addresses may point at packet-scoped
 * data, so this key must not be inserted. */
static void *
mctp_fragment_temporary_key(const packet_info *pinfo, const uint32_t id,
        const void *data _U_)
{
    mctp_fragment_key *key = g_slice_new(mctp_fragment_key);

    copy_address_shallow(&key->phys_src, &pinfo->net_src);
    copy_address_shallow(&key->phys_dst, &pinfo->net_dst);
    copy_address_shallow(&key->eid_src, &pinfo->src);
    copy_address_shallow(&key->eid_dst, &pinfo->dst);
    key->id = id;
    mctp_ingress_scope_get(pinfo, &key->scope);

    return key;
}

static void *
mctp_fragment_persistent_key(const packet_info *pinfo, const uint32_t id,
        const void *data _U_)
{
    mctp_fragment_key *key = g_slice_new(mctp_fragment_key);

    copy_address(&key->phys_src, &pinfo->net_src);
    copy_address(&key->phys_dst, &pinfo->net_dst);
    copy_address(&key->eid_src, &pinfo->src);
    copy_address(&key->eid_dst, &pinfo->dst);
    key->id = id;
    mctp_ingress_scope_get(pinfo, &key->scope);

    return key;
}

static void
mctp_fragment_free_temporary_key(void *ptr)
{
    g_slice_free(mctp_fragment_key, (mctp_fragment_key *)ptr);
}

static void
mctp_fragment_free_persistent_key(void *ptr)
{
    mctp_fragment_key *key = (mctp_fragment_key *)ptr;

    if (key) {
        free_address(&key->phys_src);
        free_address(&key->phys_dst);
        free_address(&key->eid_src);
        free_address(&key->eid_dst);
        g_slice_free(mctp_fragment_key, key);
    }
}

static const reassembly_table_functions mctp_reassembly_table_functions = {
    mctp_fragment_hash,
    mctp_fragment_equal,
    mctp_fragment_temporary_key,
    mctp_fragment_persistent_key,
    mctp_fragment_free_temporary_key,
    mctp_fragment_free_persistent_key
};

/* SOM metadata. */
typedef struct {
    unsigned payload_len;
    nstime_t start_time;
} mctp_start_metadata;

/* First-pass state of an assembly in progress, keyed on its fragment head. */
typedef struct {
    unsigned next_seq;      /* last accepted sequence number + 1 */
    unsigned packets;       /* packets taken in so far */
    const mctp_start_metadata *start;
    nstime_t last_time;
    unsigned last_len;      /* MCTP length of the last accepted packet */
    uint32_t last_frame;    /* frame of the last accepted packet */
} mctp_assembly_state;

/* Gaps above this are clamped; any of them exceeds the timeout anyway. */
#define MCTP_MAX_GAP_SECS 1000000

/* An inter-packet timeout, kept for the second pass. */
typedef struct {
    int64_t gap_ms;         /* capture-timestamp gap, rounded up */
    int64_t idle_ms;        /* gap less the bus time estimate, rounded up */
    int64_t bus_us;         /* bus time estimate of the larger packet */
    uint32_t prev_frame;    /* last packet of the timed-out assembly */
} mctp_timeout_info;

static wmem_map_t *mctp_assembly;

static mctp_assembly_state *
mctp_assembly_state_get(fragment_head *head)
{
    mctp_assembly_state *state = wmem_map_lookup(mctp_assembly, head);

    if (!state) {
        state = wmem_new0(wmem_file_scope(), mctp_assembly_state);
        wmem_map_insert(mctp_assembly, head, state);
    }
    return state;
}

/* DSP0236 8.9: terminate the message assembly in progress on this terminus
 * and drop all of its data. */
static void
mctp_drop_assembly(const packet_info *pinfo, fragment_head *head,
        uint8_t tag)
{
    tvbuff_t *dropped;

    wmem_map_remove(mctp_assembly, head);

    dropped = fragment_delete(&mctp_reassembly_table, pinfo, tag, NULL);
    if (dropped)
        tvb_free(dropped);
}

/* DSP0237 Table 8: the slave address byte may take 250 us (PT1b), and the
 * bytes from the command code through the PEC 250 us each (PT1a), clock
 * stretching included. */
#define MCTP_SMBUS_PT1_US_PER_BYTE 250

/* Worst-case bus time of one MCTP packet of mctp_len bytes on SMBus/I2C, in
 * microseconds: the slave address, command code, byte count and source
 * address, the MCTP bytes, and an assumed PEC (DSP0237 Table 1).  The
 * largest permitted time, so the idle gap is never overestimated. */
static int64_t
mctp_smbus_bus_time_us(unsigned mctp_len)
{
    return ((int64_t)mctp_len + 5) * MCTP_SMBUS_PT1_US_PER_BYTE;
}

/* DSP0237 Table 9 MT3a is the idle time from the end of one packet to the
 * start of the next, measured at the transmitter.  Capture timestamps mark
 * either the start or the end of each packet, so their gap includes one
 * packet's bus time: subtract the larger packet's estimate before comparing
 * the remaining idle time with the limit. */
static bool
mctp_inter_packet_timed_out(const mctp_dissector_data *binding_data,
        const mctp_assembly_state *state, const packet_info *pinfo,
        unsigned len, mctp_timeout_info *info)
{
    nstime_t delta;
    int64_t gap_us, idle_us;

    if (mctp_inter_packet_timeout_ms == 0 || !binding_data ||
        binding_data->ingress_scope_kind != MCTP_SCOPE_I2C_BUS || !state)
        return false;

    nstime_delta(&delta, &pinfo->abs_ts, &state->last_time);
    if (delta.secs < 0)
        return false;

    /* Clamp absurd gaps so the microsecond arithmetic cannot overflow. */
    if (delta.secs > MCTP_MAX_GAP_SECS) {
        delta.secs = MCTP_MAX_GAP_SECS;
        delta.nsecs = 0;
    }
    gap_us = (int64_t)delta.secs * 1000000 + (delta.nsecs + 999) / 1000;
    info->bus_us = mctp_smbus_bus_time_us(MAX(len, state->last_len));
    info->prev_frame = state->last_frame;
    idle_us = gap_us - info->bus_us;
    info->gap_ms = (gap_us + 999) / 1000;
    info->idle_ms = (idle_us + 999) / 1000;

    return idle_us > (int64_t)mctp_inter_packet_timeout_ms * 1000;
}

/* Render header bytes 1-3, as far as the packet reports them. */
static void
mctp_add_header_remainder(tvbuff_t *tvb, proto_tree *mctp_tree,
                          unsigned len, unsigned *seq,
                          proto_item **fst_item)
{
    static int * const mctp_flags[] = {
        &hf_mctp_flags_som,
        &hf_mctp_flags_eom,
        NULL
    };

    static int * const mctp_tag[] = {
        &hf_mctp_tag_to,
        &hf_mctp_tag_value,
        NULL,
    };

    proto_tree *fst_tree;
    unsigned fst;

    if (len >= 2)
        proto_tree_add_item(mctp_tree, hf_mctp_dst, tvb, 1, 1, ENC_NA);
    if (len >= 3)
        proto_tree_add_item(mctp_tree, hf_mctp_src, tvb, 2, 1, ENC_NA);
    if (len < 4)
        return;

    fst = tvb_get_uint8(tvb, 3);
    fst_tree = proto_tree_add_subtree_format(mctp_tree, tvb, 3, 1, ett_mctp_fst,
                                      fst_item, "Flags %s, seq %d, tag %u, TO %u",
                                      val_to_str_const(fst >> 6, flag_vals, ""),
                                      fst >> 4 & 0x3,
                                      fst & 0x7,
                                      (fst & 0x08) != 0);
    proto_tree_add_bitmask(fst_tree, tvb, 3, hf_mctp_flags,
                           ett_mctp_flags, mctp_flags, ENC_NA);
    if (seq != NULL)
        proto_tree_add_item_ret_uint(fst_tree, hf_mctp_seq, tvb, 3, 1, ENC_NA,
                                     seq);
    else
        proto_tree_add_item(fst_tree, hf_mctp_seq, tvb, 3, 1, ENC_NA);
    proto_tree_add_bitmask_with_flags(fst_tree, tvb, 3, hf_mctp_tag,
                           ett_mctp_tag, mctp_tag, ENC_NA, BMT_NO_FLAGS);
}

static unsigned
mctp_add_message_type(tvbuff_t *tvb, unsigned offset, proto_tree *mctp_tree)
{
    unsigned type = tvb_get_uint8(tvb, offset);
    proto_tree *type_tree;

    type_tree = proto_tree_add_subtree_format(mctp_tree, tvb, offset, 1,
                                              ett_mctp_type, NULL,
                                              "Type: %s (0x%02x)%s",
                                              rval_to_str_const(type & 0x7f,
                                                               type_vals,
                                                               "Unknown"),
                                              type & 0x7f,
                                              type & 0x80 ? " + IC" : "");
    proto_tree_add_item(type_tree, hf_mctp_msg_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(type_tree, hf_mctp_msg_ic, tvb, offset, 1,
                        ENC_BIG_ENDIAN);

    return type;
}

/* Add this fragment to its assembly; the reassembled message when it is
 * complete and its bytes are contiguous, else NULL. */
static tvbuff_t *
mctp_reassemble(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mctp_tree,
                unsigned len, unsigned fst, unsigned seq, uint8_t tag)
{
    fragment_head *frag_msg = NULL;
    tvbuff_t *new_tvb = NULL;

    pinfo->fragmented = true;

    /* As for IPv4, a fragment cut short by the capture cannot be reassembled:
     * drop the assembly, and let the bounds check mark the frame short. */
    if (!tvb_bytes_exist(tvb, 4, len - 4)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " fragment, seq %u", seq);
        if (!PINFO_FD_VISITED(pinfo)) {
            fragment_head *head = fragment_get(&mctp_reassembly_table, pinfo,
                                               tag, NULL);

            if (head)
                mctp_drop_assembly(pinfo, head, tag);
        }
        tvb_ensure_bytes_exist(tvb, 4, len - 4);
    }

    /* Id is the 4-bit tag including TO (DSP0236 8.6). */
    frag_msg = fragment_add_seq_next(&mctp_reassembly_table,
                                     tvb, 4, pinfo,
                                     tag, NULL,
                                     len - 4,
                                     !(fst & 0x40));

    if (!PINFO_FD_VISITED(pinfo)) {
        /* Record the sequence number for the next packet's check. */
        fragment_head *head = fragment_get(&mctp_reassembly_table, pinfo,
                                           tag, NULL);

        if (head) {
            mctp_assembly_state *state = mctp_assembly_state_get(head);

            /* A start packet begins the count. */
            if (fst & 0x80) {
                mctp_start_metadata *metadata =
                    wmem_new(wmem_file_scope(), mctp_start_metadata);

                metadata->payload_len = len - 4;
                metadata->start_time = pinfo->abs_ts;
                state->start = metadata;
                state->packets = 0;
            }
            state->next_seq = seq + 1;
            state->packets++;
            state->last_time = pinfo->abs_ts;
            state->last_len = len;
            state->last_frame = pinfo->num;
        }

        if (frag_msg)
            wmem_map_remove(mctp_assembly, frag_msg);
    }

    new_tvb = process_reassembled_data(tvb, 4, pinfo, "reassembled Message",
                                       frag_msg, &mctp_frag_items,
                                       NULL, mctp_tree);

    if (fst & 0x40)
        col_append_str(pinfo->cinfo, COL_INFO, " reassembled");
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, " fragment, seq %u", seq);

    return new_tvb;
}

static int
dissect_mctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    const mctp_dissector_data *binding_data = (const mctp_dissector_data *)data;
    proto_tree *mctp_tree;
    unsigned len, ver, type, seq = 0, fst;
    bool save_fragmented;
    proto_item *ti, *tti = NULL, *ver_ti;
    tvbuff_t *next_tvb;
    unsigned assembly;
    const mctp_start_metadata *start = NULL;
    const mctp_timeout_info *timeout = NULL;
    uint8_t tag;

    p_remove_proto_data(pinfo->pool, pinfo, proto_mctp,
                        MCTP_PROTO_DATA_INGRESS_SCOPE);
    if (binding_data && binding_data->has_ingress_scope) {
        mctp_dissector_data *packet_data = wmem_new(pinfo->pool,
                                                    mctp_dissector_data);
        *packet_data = *binding_data;
        p_set_proto_data(pinfo->pool, pinfo, proto_mctp,
                         MCTP_PROTO_DATA_INGRESS_SCOPE, packet_data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCTP");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_reported_length(tvb);

    /* Before the checks below, so a rejected packet is still filterable. */
    ti = proto_tree_add_item(tree, proto_mctp, tvb, 0, -1, ENC_NA);
    mctp_tree = proto_item_add_subtree(ti, ett_mctp);

    /* DSP0236 Table 1: the upper nibble is reserved. */
    ver_ti = NULL;
    ver = 0;
    if (len >= 1) {
        proto_tree_add_item(mctp_tree, hf_mctp_rsvd, tvb, 0, 1, ENC_NA);
        ver_ti = proto_tree_add_item_ret_uint(mctp_tree, hf_mctp_ver, tvb, 0,
                                              1, ENC_NA, &ver);
    }

    /* A four-octet continuation has an empty payload; it is not short. */
    unsigned min_len = MCTP_HDR_LENGTH;
    if (len >= MCTP_HDR_LENGTH && (tvb_get_uint8(tvb, 3) & 0x80))
        min_len = MCTP_MIN_LENGTH;
    if (len < min_len) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, min_len);
        mctp_add_header_remainder(tvb, mctp_tree, len, NULL, NULL);
        expert_add_info(pinfo, ti, &ei_mctp_short);
        return tvb_captured_length(tvb);
    }

    /* DSP0236 Table 1: header version 1. */
    if (ver != 1) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid version %u", ver);
        mctp_add_header_remainder(tvb, mctp_tree, len, NULL, NULL);
        expert_add_info(pinfo, ver_ti, &ei_mctp_bad_version);
        /* Show the undecodable bytes as data. */
        if (tvb_captured_length_remaining(tvb, 4) > 0)
            call_data_dissector(tvb_new_subset_remaining(tvb, 4), pinfo, tree);
        return tvb_captured_length(tvb);
    }

    set_address_tvb(&pinfo->dl_dst, AT_MCTP, 1, tvb, 1);
    copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
    set_address_tvb(&pinfo->dl_src, AT_MCTP, 1, tvb, 2);
    copy_address_shallow(&pinfo->src, &pinfo->dl_src);

    proto_item_append_text(ti, " Dst: %s, Src %s",
            address_to_str(pinfo->pool, &pinfo->dst),
            address_to_str(pinfo->pool, &pinfo->src));

    /* Standard header fields. */
    mctp_add_header_remainder(tvb, mctp_tree, len, &seq, &tti);

    fst = tvb_get_uint8(tvb, 3);
    tag = fst & 0x0f;

    /* Only SOM carries an IC/type byte. Render it even before reassembly
     * completes, but leave it in the payload passed to the reassembler. */
    if (fst & 0x80) {
        type = mctp_add_message_type(tvb, 4, mctp_tree);
        /* DSP0236 11.6: control messages fit in a single packet. */
        if (!(fst & 0x40) && (type & 0x7f) == 0)
            expert_add_info(pinfo, ti, &ei_mctp_control_fragmented);
    }

    col_set_str(pinfo->cinfo, COL_INFO, "MCTP message");

    if (binding_data && binding_data->drop_from_assembly) {
        expert_add_info(pinfo, tti, &ei_mctp_physical_layer_drop);
        col_append_str(pinfo->cinfo, COL_INFO,
                       " dropped by physical-layer validation");
        if (tvb_captured_length_remaining(tvb, 4) > 0)
            call_data_dissector(tvb_new_subset_remaining(tvb, 4), pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /* use the tags as our port numbers */
    pinfo->ptype = PT_MCTP;
    pinfo->srcport = tag;
    pinfo->destport = tag ^ 0x08; /* flip tag-owner bit */

    save_fragmented = pinfo->fragmented;

    /* One assembly per terminus (DSP0236 8.6); decided on the first pass. */
    if (!PINFO_FD_VISITED(pinfo)) {
        fragment_head *head;
        const mctp_assembly_state *state = NULL;
        mctp_timeout_info timeout_info = { 0 };
        bool timed_out = false;

        head = fragment_get(&mctp_reassembly_table, pinfo, tag, NULL);
        if (head)
            state = wmem_map_lookup(mctp_assembly, head);
        if (head && state)
            timed_out = mctp_inter_packet_timed_out(binding_data, state, pinfo,
                                                    len, &timeout_info);
        assembly = MCTP_ASSEMBLY_OK;
        if (timed_out) {
            mctp_timeout_info *saved = wmem_new(wmem_file_scope(),
                                                mctp_timeout_info);
            *saved = timeout_info;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_mctp,
                             MCTP_PROTO_DATA_TIMEOUT, saved);
            if ((fst & 0x80) || mctp_drop_timed_out_assembly) {
                mctp_drop_assembly(pinfo, head, tag);
                head = NULL;
                state = NULL;
            }
        }
        if (state && head && !(fst & 0x80)) {
            start = state->start;
            if (start)
                p_add_proto_data(wmem_file_scope(), pinfo, proto_mctp,
                                 MCTP_PROTO_DATA_START, (void *)start);
        }
        if (fst & 0x80) {
            /* 8.9: a new SOM terminates a still-live assembly in progress. */
            if (head) {
                mctp_drop_assembly(pinfo, head, tag);
                assembly = MCTP_ASSEMBLY_RESTARTED;
            }
        } else if (timed_out && mctp_drop_timed_out_assembly) {
            assembly = MCTP_ASSEMBLY_TIMEOUT;
        } else if (!head) {
            /* 8.7: a middle or end packet without a start is dropped. */
            assembly = MCTP_ASSEMBLY_ORPHAN;
        } else {
            /* 8.9: out-of-sequence packet. */
            if (state && seq != (state->next_seq & 0x03)) {
                mctp_drop_assembly(pinfo, head, tag);
                assembly = MCTP_ASSEMBLY_SEQ_GAP;
            } else if (state && state->packets >= MCTP_ASSEMBLY_PACKET_CAP) {
                /* This packet would take the assembly past the cap. */
                mctp_drop_assembly(pinfo, head, tag);
                assembly = MCTP_ASSEMBLY_PACKET_LIMIT;
            }
        }
        if (assembly != MCTP_ASSEMBLY_OK)
            p_add_proto_data(wmem_file_scope(), pinfo, proto_mctp,
                             MCTP_PROTO_DATA_ASSEMBLY,
                             GUINT_TO_POINTER(assembly));
    } else {
        assembly = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo,
                                                     proto_mctp,
                                                     MCTP_PROTO_DATA_ASSEMBLY));
        timeout = (const mctp_timeout_info *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_mctp, MCTP_PROTO_DATA_TIMEOUT);
        start = (const mctp_start_metadata *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_mctp, MCTP_PROTO_DATA_START);
    }

    if (!timeout)
        timeout = (const mctp_timeout_info *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_mctp, MCTP_PROTO_DATA_TIMEOUT);

    /* DSP0236 8.4.2 sender rules: diagnose and keep assembling. */
    if (!(fst & 0x40)) {
        if (len - 4 < MCTP_BASELINE_TU)
            proto_tree_add_expert_format_remaining(mctp_tree, pinfo,
                &ei_mctp_tu_mismatch, tvb, 4,
                "Non-final packet payload is %u bytes, below the %u-byte "
                "baseline transmission unit (DSP0236 8.4.2)",
                len - 4, MCTP_BASELINE_TU);
        if (start && len - 4 != start->payload_len)
            proto_tree_add_expert_format_remaining(mctp_tree, pinfo,
                &ei_mctp_tu_mismatch, tvb, 4,
                "Middle packet payload is %u bytes, differing from the "
                "start packet's %u bytes (DSP0236 8.4.2)",
                len - 4, start->payload_len);
    } else if (start && len - 4 > start->payload_len) {
        /* Final packet is exempt from equal-size/minimum, but not from exceeding the start TU. */
        proto_tree_add_expert_format_remaining(mctp_tree, pinfo,
            &ei_mctp_tu_mismatch, tvb, 4,
            "Final packet payload is %u bytes, exceeding the "
            "start packet's %u bytes (DSP0236 8.4.2)",
            len - 4, start->payload_len);
    }

    if (timeout) {
        /* DSP0236 8.9: the timeout ended the previous message, not this one.
         * Kept short: expert text is cut at ITEM_LABEL_LENGTH. */
        if (fst & 0x80)
            expert_add_info_format(pinfo, tti, &ei_mctp_assembly_timeout,
                "Previous message assembly on this terminus timed out and was "
                "dropped (DSP0236 8.9): gap of %" PRId64 " ms since frame %u, "
                "about %" PRId64 " ms after an estimated %" PRId64 " ms of bus "
                "time, exceeds the %u ms limit (DSP0237 MT3a)",
                timeout->gap_ms, timeout->prev_frame, timeout->idle_ms,
                (timeout->bus_us + 999) / 1000, mctp_inter_packet_timeout_ms);
        else
            expert_add_info_format(pinfo, tti, &ei_mctp_assembly_timeout,
                "Capture-timestamp gap of %" PRId64 " ms (about %" PRId64
                " ms after an estimated %" PRId64 " ms of worst-case DSP0237 "
                "PT1a/PT1b bus time) "
                "exceeds the %u ms inter-packet limit (DSP0237 MT3a, "
                "an estimate: MT3a is measured at the transmitter)",
                timeout->gap_ms, timeout->idle_ms,
                (timeout->bus_us + 999) / 1000, mctp_inter_packet_timeout_ms);
    }

    if (assembly == MCTP_ASSEMBLY_RESTARTED)
        expert_add_info(pinfo, tti, &ei_mctp_assembly_restarted);

    if (assembly == MCTP_ASSEMBLY_ORPHAN || assembly == MCTP_ASSEMBLY_SEQ_GAP ||
        assembly == MCTP_ASSEMBLY_PACKET_LIMIT || assembly == MCTP_ASSEMBLY_TIMEOUT) {
        /* Dropped (8.7/8.9, or the cap): nothing to hand to a type dissector. */
        if (assembly == MCTP_ASSEMBLY_ORPHAN) {
            expert_add_info(pinfo, tti, &ei_mctp_assembly_orphan);
            col_append_str(pinfo->cinfo, COL_INFO,
                           " dropped, no assembly in progress");
        } else if (assembly == MCTP_ASSEMBLY_SEQ_GAP) {
            expert_add_info(pinfo, tti, &ei_mctp_assembly_seq_gap);
            col_append_str(pinfo->cinfo, COL_INFO, " dropped, out of sequence");
        } else if (assembly == MCTP_ASSEMBLY_PACKET_LIMIT) {
            expert_add_info_format(pinfo, tti, &ei_mctp_assembly_packet_limit,
                "Message assembly dropped: this packet would take it past %u packets",
                MCTP_ASSEMBLY_PACKET_CAP);
            col_append_str(pinfo->cinfo, COL_INFO,
                           " dropped, assembly packet limit reached");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO,
                           " dropped, inter-packet timeout");
        }
        next_tvb = NULL;

        /* Still show the bytes, as the bad-version path does. */
        if (tvb_captured_length_remaining(tvb, 4) > 0)
            call_data_dissector(tvb_new_subset_remaining(tvb, 4), pinfo, tree);

    } else if ((fst & 0xc0) != 0xc0) {
        /* if we're not both the start and end of a message, handle as a
         * fragment */
        next_tvb = mctp_reassemble(tvb, pinfo, mctp_tree, len, fst, seq, tag);
    } else {
        next_tvb = tvb_new_subset_remaining(tvb, 4);
    }

    if (next_tvb) {
        const nstime_t *start_time = start ? &start->start_time : &pinfo->abs_ts;
        int rc;

        /* Retain the type for dispatch, without repeating SOM diagnostics. */
        if (fst & 0x80)
            type = tvb_get_uint8(next_tvb, 0);
        else
            type = mctp_add_message_type(next_tvb, 0, mctp_tree);

        /* "mctp.type" data: the message's start time (an nstime_t). */
        rc = dissector_try_uint_with_data(mctp_dissector_table, type & 0x7f,
                                          next_tvb, pinfo, tree, true,
                                          (void *)start_time);

        if (!rc) {
            /* The payload after the type byte. */
            tvbuff_t *encap_tvb = tvb_new_subset_remaining(next_tvb, 1);

            /* IC = 1 excludes the encap table: the MIC position is type-specific. */
            if (!(type & 0x80))
                rc = dissector_try_uint(mctp_encap_dissector_table, type,
                                        encap_tvb, pinfo, tree);

            /* Unclaimed payload goes to the data dissector. */
            if (!rc && tvb_captured_length(encap_tvb) > 0)
                call_data_dissector(encap_tvb, pinfo, tree);
        }
    }

    pinfo->fragmented = save_fragmented;

    return tvb_captured_length(tvb);
}

/* Vendor Defined - PCI / - IANA messages (DSP0236 13.1 Table 40, 13.2
 * Table 41): the vendor ID, MSB first, then a vendor-defined body.  The
 * tvb starts at the IC/message type byte, which packet-mctp.c shows. */
static int
dissect_mctp_vdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 void *data)
{
    bool pci = (tvb_get_uint8(tvb, 0) & 0x7f) == MCTP_TYPE_VDM_PCI;
    unsigned id_len = pci ? 2 : 4;
    unsigned len = tvb_reported_length(tvb);
    proto_item *ti;
    proto_tree *vdm_tree;
    tvbuff_t *body;
    uint32_t vendor;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCTP VDM");
    col_set_str(pinfo->cinfo, COL_INFO,
                pci ? "Vendor Defined - PCI" : "Vendor Defined - IANA");

    ti = proto_tree_add_item(tree, hf_mctp_vdm, tvb, 1,
                             MIN(len - 1, id_len), ENC_NA);
    proto_item_append_text(ti, pci ? " - PCI" : " - IANA");
    vdm_tree = proto_item_add_subtree(ti, ett_mctp_vdm);
    if (len < 1 + id_len) {
        expert_add_info_format(pinfo, ti, &ei_mctp_vdm_short,
            "%s message requires a %u-byte vendor ID, but %u byte%s "
            "follow%s the message type", pci ? "Vendor Defined - PCI" :
            "Vendor Defined - IANA", id_len, len - 1,
            plurality(len - 1, "", "s"), plurality(len - 1, "s", ""));
        if (len > 1)
            call_data_dissector(tvb_new_subset_remaining(tvb, 1), pinfo, tree);
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item_ret_uint(vdm_tree,
                                 pci ? hf_mctp_vdm_pci_vid : hf_mctp_vdm_iana,
                                 tvb, 1, id_len, ENC_BIG_ENDIAN, &vendor);
    if (pci)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Vendor ID 0x%04x", vendor);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Enterprise %u", vendor);

    /* The body, MIC included when IC is set, is the vendor's to define. */
    body = tvb_new_subset_remaining(tvb, 1 + id_len);
    if (tvb_reported_length(body) &&
        !dissector_try_uint_with_data(pci ? mctp_vdm_pci_dissector_table :
                                      mctp_vdm_iana_dissector_table,
                                      vendor, body, pinfo, tree, true, data))
        call_data_dissector(body, pinfo, tree);
    return tvb_captured_length(tvb);
}

void
proto_register_mctp(void)
{
    /* *INDENT-OFF* */
    /* Field definitions */
    static hf_register_info hf[] = {
        { &hf_mctp_rsvd,
          { "Reserved", "mctp.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xf0,
            NULL, HFILL },
        },
        { &hf_mctp_ver,
          { "Version", "mctp.version",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL },
        },
        { &hf_mctp_dst,
          { "Destination", "mctp.dst",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING | BASE_SPECIAL_VALS, RVALS(mctp_dst_eid_vals), 0x00,
            NULL, HFILL },
        },
        { &hf_mctp_src,
          { "Source", "mctp.src",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING | BASE_SPECIAL_VALS, RVALS(mctp_src_eid_vals), 0x00,
            NULL, HFILL },
        },
        { &hf_mctp_flags,
          { "Flags", "mctp.flags",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL },
        },
        { &hf_mctp_flags_som,
          { "Start of message", "mctp.flags.som",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            NULL, HFILL },
        },
        { &hf_mctp_flags_eom,
          { "End of message", "mctp.flags.eom",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL },
        },
        { &hf_mctp_seq,
          { "Sequence", "mctp.seq",
            FT_UINT8, BASE_HEX, NULL, 0x30,
            NULL, HFILL },
        },
        { &hf_mctp_tag,
          { "Tag Owner and Message Tag", "mctp.tag",
            FT_UINT8, BASE_HEX, NULL, 0x0f,
            NULL, HFILL },
        },
        { &hf_mctp_tag_to,
          { "Tag owner", "mctp.tag.to",
            FT_BOOLEAN, 8, TFS(&tfs_tag_to), 0x08,
            NULL, HFILL },
        },
        { &hf_mctp_tag_value,
          { "Tag value", "mctp.tag.value",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL },
        },

        /* message header */
        { &hf_mctp_msg_ic,
          { "Integrity check", "mctp.msg.ic",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x80,
            NULL, HFILL },
        },
        { &hf_mctp_msg_type,
          { "Message type", "mctp.msg.type",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(type_vals), 0x7f,
            NULL, HFILL },
        },

        /* generic fragmentation */
        {&hf_mctp_fragments,
            {"Message fragments", "mctp.fragments",
                FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment,
            {"Message fragment", "mctp.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_overlap,
            {"Message fragment overlap", "mctp.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_overlap_conflicts,
            {"Message fragment overlapping with conflicting data",
                "mctp.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_multiple_tails,
            {"Message has multiple tail fragments",
                "mctp.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_too_long_fragment,
            {"Message fragment too long", "mctp.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_error,
            {"Message defragmentation error", "mctp.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_fragment_count,
            {"Message fragment count", "mctp.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_reassembled_in,
            {"Reassembled in", "mctp.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_reassembled_length,
            {"Reassembled length", "mctp.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_reassembled_data,
            {"Reassembled data", "mctp.reassembled.data",
                FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_vdm,
            {"Vendor Defined Message", "mctp.vdm",
                FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_mctp_vdm_pci_vid,
            {"PCI Vendor ID", "mctp.vdm.pci_vid",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "PCI/PCIe Vendor ID, MSB first (DSP0236 Vendor Defined - PCI message format)", HFILL } },
        {&hf_mctp_vdm_iana,
            {"IANA Enterprise ID", "mctp.vdm.iana",
                FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x00,
                "IANA Private Enterprise Number, MSB first (DSP0236 Vendor Defined - IANA message format)", HFILL } },
    };

    /* Expert info */
    static ei_register_info ei[] = {
        { &ei_mctp_assembly_orphan,
          { "mctp.assembly.orphan", PI_REASSEMBLE, PI_WARN,
            "No message assembly in progress for this message terminus; "
            "packet dropped (DSP0236 8.7)",
            EXPFILL }},
        { &ei_mctp_assembly_restarted,
          { "mctp.assembly.restarted", PI_REASSEMBLE, PI_ERROR,
            "Start of message received while a message assembly was already "
            "in progress for this message terminus; the assembly in progress "
            "is terminated and its data dropped (DSP0236 8.9)",
            EXPFILL }},
        { &ei_mctp_assembly_seq_gap,
          { "mctp.assembly.seq_gap", PI_REASSEMBLE, PI_ERROR,
            "Packet sequence number is not a modulo-4 increment of the "
            "previous packet's for this message terminus; the message "
            "assembly in progress is terminated and its data dropped "
            "(DSP0236 8.9)",
            EXPFILL }},
        { &ei_mctp_assembly_packet_limit,
          { "mctp.assembly.packet_limit", PI_REASSEMBLE, PI_WARN,
            "Message assembly dropped at the packet limit preference",
            EXPFILL }},
        { &ei_mctp_assembly_timeout,
          { "mctp.assembly.timeout", PI_SEQUENCE, PI_WARN,
            "Capture-timestamp gap, less the estimated bus time, exceeds the "
            "inter-packet limit (DSP0237 MT3a)",
            EXPFILL }},
        { &ei_mctp_physical_layer_drop,
          { "mctp.physical_layer_drop", PI_REASSEMBLE, PI_WARN,
            "Packet dropped by physical-layer validation before message assembly "
            "(DSP0236 8.7)",
            EXPFILL }},
        { &ei_mctp_tu_mismatch,
          { "mctp.tu.mismatch", PI_PROTOCOL, PI_WARN,
            "Packet payload size breaks a transmission unit rule "
            "(DSP0236 8.4.2)",
            EXPFILL }},
        { &ei_mctp_short,
          { "mctp.too_short", PI_MALFORMED, PI_ERROR,
            "Packet is shorter than the four-byte MCTP transport header, or "
            "is a start packet without the message type byte it must carry, "
            "so it cannot be a complete MCTP packet (DSP0236 MCTP base protocol common fields)",
            EXPFILL }},
        { &ei_mctp_bad_version,
          { "mctp.version.unsupported", PI_PROTOCOL, PI_WARN,
            "MCTP header version is not 1; DSP0236 requires value 1, "
            "and 8.7 lists a bad header version among the conditions under "
            "which a packet is dropped",
            EXPFILL }},
        { &ei_mctp_vdm_short,
          { "mctp.vdm.too_short", PI_MALFORMED, PI_ERROR,
            "Vendor defined message is shorter than its vendor ID "
            "(DSP0236 Vendor Defined - PCI and - IANA message formats)",
            EXPFILL }},
        { &ei_mctp_control_fragmented,
          { "mctp.control.fragmented", PI_PROTOCOL, PI_WARN,
            "MCTP control message spans more than one packet; DSP0236 11.6 "
            "requires a single packet",
            EXPFILL }},
    };

    /* protocol subtree */
    static int *ett[] = {
        &ett_mctp,
        &ett_mctp_flags,
        &ett_mctp_fst,
        &ett_mctp_tag,
        &ett_mctp_type,
        &ett_mctp_vdm,
        &ett_mctp_fragment,
        &ett_mctp_fragments,
    };

    expert_module_t *expert_mctp;
    module_t *mctp_module;

    /* Register the protocol name and description */
    proto_mctp = proto_register_protocol("MCTP", "MCTP", "mctp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_mctp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_mctp = expert_register_protocol(proto_mctp);
    expert_register_field_array(expert_mctp, ei, array_length(ei));

    mctp_module = prefs_register_protocol(proto_mctp, NULL);
    prefs_register_uint_preference(mctp_module, "max_assembly_packets",
            "Maximum packets per message assembly",
            "Drop an assembly that would exceed this many packets (0 counts as 1)",
            10, &mctp_max_assembly_packets);
    prefs_register_uint_preference(mctp_module, "inter_packet_timeout_ms",
            "MCTP inter-packet timeout (ms)",
            "Diagnose MCTP over SMBus/I2C inter-packet gaps exceeding this "
            "interval (DSP0237 MT3a, 100 ms; 0: disabled). MT3a is the "
            "idle time measured at the transmitter, so it is estimated: the "
            "capture-timestamp gap less the worst-case bus time of the larger "
            "of the two packets, 250 us per byte for MCTP length + 5 bytes "
            "(DSP0237 PT1a/PT1b, clock stretching included).",
            10, &mctp_inter_packet_timeout_ms);
    prefs_register_bool_preference(mctp_module, "drop_timed_out_assembly",
            "Drop timed-out MCTP assemblies",
            "Drop the in-progress assembly and any non-start packet that arrives "
            "after the configured inter-packet timeout",
            &mctp_drop_timed_out_assembly);

    /* We have two dissector tables here, both keyed off the type byte, but
     * with different decode semantics:
     *
     * mctp.type: for protocols that are "MCTP-aware" - they perform their
     *    own decoding of the type byte, including the IC bit, and possibly the
     *    message integrity check (which is type-specific!). For example,
     *    NVMe-MI, which includes the type byte in packet specifications
     *
     * mctp.encap-type: for protocols that are trivially encapsulated in a
     *    MCTP message, and do not handle the type byte themselves. For
     *    example, NC-SI over MCTP, which just wraps a NC-SI packet within
     *    a MCTP message.
     *
     * it doesn't make sense to allow encap-type decoders to also have the IC
     * bit set, as there is no specification for what format the message
     * integrity check is in. So, we disallow the IC bit in the type field
     * for those dissectors.
     */
    mctp_dissector_table = register_dissector_table("mctp.type", "MCTP type",
                                                    proto_mctp, FT_UINT8,
                                                    BASE_HEX);
    mctp_encap_dissector_table = register_dissector_table("mctp.encap-type",
                                                          "MCTP encapsulated type",
                                                          proto_mctp, FT_UINT8,
                                                          BASE_HEX);

    /* Vendor Defined messages, keyed on the vendor ID; the body (after the
     * ID) is passed, with the "mctp.type" data. */
    mctp_vdm_pci_dissector_table = register_dissector_table("mctp.vdm.pci",
                                                    "MCTP Vendor Defined - PCI vendor ID",
                                                    proto_mctp, FT_UINT16,
                                                    BASE_HEX);
    mctp_vdm_iana_dissector_table = register_dissector_table("mctp.vdm.iana",
                                                    "MCTP Vendor Defined - IANA enterprise",
                                                    proto_mctp, FT_UINT32,
                                                    BASE_DEC);

    reassembly_table_register(&mctp_reassembly_table,
                              &mctp_reassembly_table_functions);

    mctp_assembly = wmem_map_new_autoreset(wmem_epan_scope(),
                                           wmem_file_scope(),
                                           g_direct_hash, g_direct_equal);

    mctp_handle = register_dissector("mctp", dissect_mctp, proto_mctp);
    mctp_vdm_handle = register_dissector_with_description("mctp-vdm",
            "MCTP Vendor Defined Message", dissect_mctp_vdm, proto_mctp);
    register_capture_dissector("mctp", capture_mctp, proto_mctp);
}

void
proto_reg_handoff_mctp(void)
{
    capture_dissector_handle_t mctp_cap_handle = find_capture_dissector("mctp");

    dissector_add_uint("sll.ltype", LINUX_SLL_P_MCTP, mctp_handle);
    dissector_add_uint("mctp.type", MCTP_TYPE_VDM_PCI, mctp_vdm_handle);
    dissector_add_uint("mctp.type", MCTP_TYPE_VDM_IANA, mctp_vdm_handle);

    capture_dissector_add_uint("sll.ltype", LINUX_SLL_P_MCTP, mctp_cap_handle);
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
