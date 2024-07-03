/* packet-bthci_iso.c
 * Routines for the Bluetooth ISO dissection
 * Copyright 2020, Jakub Pawlowski <jpawlowski@google.com>
 * Copyright 2020, Allan M. Madsen <almomadk@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>

#include "packet-bluetooth.h"
#include "packet-bthci_iso.h"

/* Initialize the protocol and registered fields */
static int proto_bthci_iso;
static int hf_bthci_iso_chandle;
static int hf_bthci_iso_pb_flag;
static int hf_bthci_iso_ts_flag;
static int hf_bthci_iso_reserved;
static int hf_bthci_iso_data_length;
static int hf_bthci_iso_data;
static int hf_bthci_iso_continuation_to;
static int hf_bthci_iso_reassembled_in;
static int hf_bthci_iso_connect_in;
static int hf_bthci_iso_disconnect_in;

static int proto_bthci_iso_data;
static int hf_bthci_iso_data_timestamp;
static int hf_bthci_iso_data_packet_seq_num;
static int hf_bthci_iso_data_sdu_length;
static int hf_bthci_iso_data_status_flag;
static int hf_bthci_iso_data_sdu;

/* Initialize the subtree pointers */
static int ett_bthci_iso;
static int ett_bthci_iso_data;

static expert_field ei_length_bad;

static dissector_handle_t bthci_iso_handle;
static dissector_handle_t bthci_iso_data_handle;

static bool iso_reassembly = true;

typedef struct _multi_fragment_pdu_t {
    uint32_t first_frame;
    uint32_t last_frame;
    uint16_t tot_len;
    char    *reassembled;
    int      cur_off;           /* counter used by reassembly */
} multi_fragment_pdu_t;

typedef struct _chandle_data_t {
    wmem_tree_t *start_fragments;  /* indexed by pinfo->num */
} chandle_data_t;

static wmem_tree_t *chandle_tree;

static const value_string iso_pb_flag_vals[] = {
    { 0x00, "First SDU Fragment"},
    { 0x01, "Continuation SDU Fragment"},
    { 0x02, "Complete SDU"},
    { 0x03, "Last SDU Fragment"},
    { 0x00, NULL}
};

static const value_string iso_data_status_vals[] = {
    { 0x00, "Valid"},
    { 0x01, "Possibly Invalid"},
    { 0x02, "Lost Data"},
    { 0x00, NULL}
};

void proto_register_bthci_iso(void);
void proto_reg_handoff_bthci_iso(void);
void proto_register_iso_data(void);

typedef struct _iso_data_info_t {
    uint16_t handle;
    bool timestamp_present;
} iso_data_info_t;

/* Code to actually dissect the packets */
static int
dissect_bthci_iso(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item               *bthci_iso_item;
    proto_tree               *bthci_iso_tree;
    proto_item               *sub_item;
    uint16_t                  flags;
    uint16_t                  pb_flag = false;
    uint16_t                  length;
    bool                      fragmented = false;
    int                       offset = 0;
    tvbuff_t                 *next_tvb;
    chandle_data_t           *chandle_data;
    bluetooth_data_t         *bluetooth_data;
    wmem_tree_key_t           key[6];
    uint32_t                  k_connection_handle = 0;
    uint32_t                  k_stream_handle;
    uint32_t                  k_frame_number;
    uint32_t                  k_interface_id;
    uint32_t                  k_adapter_id;
    uint32_t                  direction;
    remote_bdaddr_t          *remote_bdaddr;
    const char               *localhost_name;
    uint8_t                  *localhost_bdaddr;
    const char               *localhost_ether_addr;
    char                     *localhost_addr_name;
    int                       localhost_length;
    localhost_bdaddr_entry_t *localhost_bdaddr_entry;
    localhost_name_entry_t   *localhost_name_entry;
    chandle_session_t        *chandle_session;
    wmem_tree_t              *subtree;
    stream_connection_handle_pair_t *handle_pairs;
    iso_data_info_t          iso_data_info;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;

    bthci_iso_item = proto_tree_add_item(tree, proto_bthci_iso, tvb, offset, -1, ENC_NA);
    bthci_iso_tree = proto_item_add_subtree(bthci_iso_item, ett_bthci_iso);

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_ISO");

    flags   = tvb_get_letohs(tvb, offset);
    pb_flag = (flags >> 12) & 0x3;
    iso_data_info.timestamp_present = (flags >> 14) & 0x1;
    iso_data_info.handle = flags & 0xfff;
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_chandle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_pb_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_ts_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    length = tvb_get_letohs(tvb, offset);
    sub_item = proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* determine if packet is fragmented */
    if (pb_flag != 0x2) {
        fragmented = true;
    }

    bluetooth_data = (bluetooth_data_t *) data;
    DISSECTOR_ASSERT(bluetooth_data);

    k_interface_id      = bluetooth_data->interface_id;
    k_adapter_id        = bluetooth_data->adapter_id;
    k_stream_handle     = flags & 0x0fff;
    direction           = pinfo->p2p_dir;
    k_frame_number      = pinfo->num;

    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;
    key[2].length = 1;
    key[2].key    = &k_stream_handle;
    key[3].length = 0;
    key[3].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(bluetooth_data->chandle_sessions, key);
    chandle_session = (subtree) ? (chandle_session_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
    if (!(chandle_session &&
            chandle_session->connect_in_frame < pinfo->num &&
            chandle_session->disconnect_in_frame > pinfo->num)){
        chandle_session = NULL;
    }

    /* replace stream (CIS/BIS) handle with connection (ACL) handle */
    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(bluetooth_data->shandle_to_chandle, key);
    handle_pairs = (subtree) ? (stream_connection_handle_pair_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
    if (handle_pairs) {
        k_connection_handle = handle_pairs->chandle;
        key[2].key = &k_connection_handle;
    }

    key[3].length = 1;
    key[3].key    = &k_frame_number;
    key[4].length = 0;
    key[4].key    = NULL;

    /* remote bdaddr and name */
    remote_bdaddr = (remote_bdaddr_t *)wmem_tree_lookup32_array_le(bluetooth_data->chandle_to_bdaddr, key);
    /*
     * XXX - do this only if we found a handle pair, so that we have
     * a connection handle?
     */
    if (remote_bdaddr && remote_bdaddr->interface_id == bluetooth_data->interface_id &&
            remote_bdaddr->adapter_id == bluetooth_data->adapter_id &&
            remote_bdaddr->chandle == k_connection_handle) {
        uint32_t        k_bd_addr_oui;
        uint32_t        k_bd_addr_id;
        uint32_t        bd_addr_oui;
        uint32_t        bd_addr_id;
        device_name_t  *device_name;
        const char     *remote_name;
        const char     *remote_ether_addr;
        char           *remote_addr_name;
        int             remote_length;

        bd_addr_oui = remote_bdaddr->bd_addr[0] << 16 | remote_bdaddr->bd_addr[1] << 8 | remote_bdaddr->bd_addr[2];
        bd_addr_id  = remote_bdaddr->bd_addr[3] << 16 | remote_bdaddr->bd_addr[4] << 8 | remote_bdaddr->bd_addr[5];

        k_bd_addr_oui  = bd_addr_oui;
        k_bd_addr_id   = bd_addr_id;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_bd_addr_id;
        key[3].length = 1;
        key[3].key    = &k_bd_addr_oui;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        device_name = (device_name_t *)wmem_tree_lookup32_array_le(bluetooth_data->bdaddr_to_name, key);
        if (device_name && device_name->bd_addr_oui == bd_addr_oui && device_name->bd_addr_id == bd_addr_id)
            remote_name = device_name->name;
        else
            remote_name = "";

        remote_ether_addr = get_ether_name(remote_bdaddr->bd_addr);
        remote_length = (int)(strlen(remote_ether_addr) + 3 + strlen(remote_name) + 1);
        remote_addr_name = (char *)wmem_alloc(pinfo->pool, remote_length);

        snprintf(remote_addr_name, remote_length, "%s (%s)", remote_ether_addr, remote_name);

        if (pinfo->p2p_dir == P2P_DIR_RECV) {
            set_address(&pinfo->net_src, AT_STRINGZ, (int)strlen(remote_name) + 1, remote_name);
            set_address(&pinfo->dl_src, AT_ETHER, 6, remote_bdaddr->bd_addr);
            set_address(&pinfo->src, AT_STRINGZ, (int)strlen(remote_addr_name) + 1, remote_addr_name);
        } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
            set_address(&pinfo->net_dst, AT_STRINGZ, (int)strlen(remote_name) + 1, remote_name);
            set_address(&pinfo->dl_dst, AT_ETHER, 6, remote_bdaddr->bd_addr);
            set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(remote_addr_name) + 1, remote_addr_name);
        }
    } else {
        if (pinfo->p2p_dir == P2P_DIR_RECV) {
            set_address(&pinfo->net_src, AT_STRINGZ, 1, "");
            set_address(&pinfo->dl_src, AT_STRINGZ, 1, "");
            set_address(&pinfo->src, AT_STRINGZ, 10, "remote ()");
        } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
            set_address(&pinfo->net_dst, AT_STRINGZ, 1, "");
            set_address(&pinfo->dl_dst, AT_STRINGZ, 1, "");
            set_address(&pinfo->dst, AT_STRINGZ, 10, "remote ()");
        }
    }

    /* localhost bdaddr and name */
    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;
    key[2].length = 1;
    key[2].key    = &k_frame_number;
    key[3].length = 0;
    key[3].key    = NULL;


    localhost_bdaddr_entry = (localhost_bdaddr_entry_t *)wmem_tree_lookup32_array_le(bluetooth_data->localhost_bdaddr, key);
    localhost_bdaddr = (uint8_t *) wmem_alloc(pinfo->pool, 6);
    if (localhost_bdaddr_entry && localhost_bdaddr_entry->interface_id == bluetooth_data->interface_id &&
        localhost_bdaddr_entry->adapter_id == bluetooth_data->adapter_id) {

        localhost_ether_addr = get_ether_name(localhost_bdaddr_entry->bd_addr);
        memcpy(localhost_bdaddr, localhost_bdaddr_entry->bd_addr, 6);
    } else {
        localhost_ether_addr = "localhost";
        /* XXX - is this the right value to use? */
        memset(localhost_bdaddr, 0, 6);
    }

    localhost_name_entry = (localhost_name_entry_t *)wmem_tree_lookup32_array_le(bluetooth_data->localhost_name, key);
    if (localhost_name_entry && localhost_name_entry->interface_id == bluetooth_data->interface_id &&
            localhost_name_entry->adapter_id == bluetooth_data->adapter_id)
        localhost_name = localhost_name_entry->name;
    else
        localhost_name = "";

    localhost_length = (int)(strlen(localhost_ether_addr) + 3 + strlen(localhost_name) + 1);
    localhost_addr_name = (char *)wmem_alloc(pinfo->pool, localhost_length);

    snprintf(localhost_addr_name, localhost_length, "%s (%s)", localhost_ether_addr, localhost_name);

    if (pinfo->p2p_dir == P2P_DIR_RECV) {
        set_address(&pinfo->net_dst, AT_STRINGZ, (int)strlen(localhost_name) + 1, localhost_name);
        set_address(&pinfo->dl_dst, AT_ETHER, 6, localhost_bdaddr);
        set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(localhost_addr_name) + 1, localhost_addr_name);
    } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
        set_address(&pinfo->net_src, AT_STRINGZ, (int)strlen(localhost_name) + 1, localhost_name);
        set_address(&pinfo->dl_src, AT_ETHER, 6, localhost_bdaddr);
        set_address(&pinfo->src, AT_STRINGZ, (int)strlen(localhost_addr_name) + 1, localhost_addr_name);
    }

    /* find the chandle_data structure associated with this chandle */
    key[0].length = 1;
    key[0].key = &k_interface_id;
    key[1].length = 1;
    key[1].key = &k_adapter_id;
    key[2].length = 1;
    key[2].key = &k_stream_handle;
    key[3].length = 1;
    key[3].key = &direction;
    key[4].length = 0;
    key[4].key = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(chandle_tree, key);
    chandle_data = (subtree) ? (chandle_data_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
    if (!pinfo->fd->visited && !chandle_data) {
        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_stream_handle;
        key[3].length = 1;
        key[3].key = &direction;
        key[4].length = 1;
        key[4].key = &k_frame_number;
        key[5].length = 0;
        key[5].key = NULL;

        chandle_data = wmem_new(wmem_file_scope(), chandle_data_t);
        chandle_data->start_fragments = wmem_tree_new(wmem_file_scope());

        wmem_tree_insert32_array(chandle_tree, key, chandle_data);
    } else if (pinfo->fd->visited && !chandle_data) {
        DISSECTOR_ASSERT_HINT(0, "Impossible: no previously session saved");
    }

    if (!fragmented || (!iso_reassembly && !pb_flag)) {
        /* call ISO data dissector for PDUs that are not fragmented
         * also for the first fragment if reassembly is disabled
         */
        if (length < tvb_captured_length_remaining(tvb, offset)) {
            if (!fragmented)
                expert_add_info(pinfo, sub_item, &ei_length_bad);
            /* Try to dissect as much as possible */
            length = tvb_captured_length_remaining(tvb, offset);
        }

        next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_captured_length_remaining(tvb, offset), length);
        call_dissector_with_data(bthci_iso_data_handle, next_tvb, pinfo, tree, &iso_data_info);
    } else if (fragmented && iso_reassembly) {
        multi_fragment_pdu_t *mfp = NULL;
        int                   len;
        if (pb_flag == 0x00) { /* first fragment */
            if (!pinfo->fd->visited) {
                int timestamp_size = 0;
                mfp = (multi_fragment_pdu_t *) wmem_new(wmem_file_scope(), multi_fragment_pdu_t);
                mfp->first_frame = pinfo->num;
                mfp->last_frame  = 0;
                mfp->tot_len     = 4;
                len = tvb_captured_length_remaining(tvb, offset);
                if (flags & 0x4000) { /* 4 byte timestamp is present */
                    timestamp_size = 4;
                }
                mfp->tot_len += timestamp_size + (tvb_get_letohs(tvb, offset + 2 + timestamp_size) & 0xfff);
                mfp->reassembled = (char *) wmem_alloc(wmem_file_scope(), mfp->tot_len);
                if (len <= mfp->tot_len) {
                    tvb_memcpy(tvb, (uint8_t *) mfp->reassembled, offset, len);
                    mfp->cur_off = len;
                    wmem_tree_insert32(chandle_data->start_fragments, pinfo->num, mfp);
                }
            } else {
                mfp = (multi_fragment_pdu_t *)wmem_tree_lookup32(chandle_data->start_fragments, pinfo->num);
            }
            if (mfp != NULL && mfp->last_frame) {
                proto_item *item;

                item = proto_tree_add_uint(bthci_iso_tree, hf_bthci_iso_reassembled_in, tvb, 0, 0, mfp->last_frame);
                proto_item_set_generated(item);
                col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]", mfp->last_frame);
            }
        }
        else if (pb_flag & 0x01) { /* continuation/last fragment */
            mfp = (multi_fragment_pdu_t *)wmem_tree_lookup32_le(chandle_data->start_fragments, pinfo->num);
            if (!pinfo->fd->visited) {
                len = tvb_captured_length_remaining(tvb, offset);
                if (mfp != NULL && !mfp->last_frame) {
                    int avail = (int)mfp->tot_len - mfp->cur_off;
                    if (len > avail) {
                        expert_add_info(pinfo, sub_item, &ei_length_bad);
                        /* Try to reassemble as much as possible */
                        len = avail;
                    }
                    tvb_memcpy(tvb, (uint8_t *) mfp->reassembled + mfp->cur_off, offset, len);
                    mfp->cur_off += len;
                    if (pb_flag == 0x03)
                        mfp->last_frame = pinfo->num;
                }
            }
            if (mfp) {
                proto_item *item;

                item = proto_tree_add_uint(bthci_iso_tree, hf_bthci_iso_continuation_to, tvb, 0, 0, mfp->first_frame);
                proto_item_set_generated(item);
                col_append_frame_number(pinfo, COL_INFO, " [Continuation to #%u]", mfp->first_frame);
                if (mfp->last_frame && mfp->last_frame != pinfo->num) {
                    item = proto_tree_add_uint(bthci_iso_tree, hf_bthci_iso_reassembled_in, tvb, 0, 0, mfp->last_frame);
                    proto_item_set_generated(item);
                    col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]", mfp->last_frame);
                }

                if (pb_flag == 0x03) { /* last fragment */
                    next_tvb = tvb_new_child_real_data(tvb, (uint8_t *) mfp->reassembled, mfp->tot_len, mfp->tot_len);
                    add_new_data_source(pinfo, next_tvb, "Reassembled BTHCI ISO");

                    call_dissector_with_data(bthci_iso_data_handle, next_tvb, pinfo, tree, &iso_data_info);
                }
            }
        }
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        sub_item = proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_data, tvb, offset, -1, ENC_NA);
        if (fragmented) {
            proto_item_append_text(sub_item, " Fragment");
        }
    }

    if (chandle_session) {
        sub_item = proto_tree_add_uint(bthci_iso_tree, hf_bthci_iso_connect_in, tvb, 0, 0, chandle_session->connect_in_frame);
        proto_item_set_generated(sub_item);

        if (chandle_session->disconnect_in_frame < UINT32_MAX) {
            sub_item = proto_tree_add_uint(bthci_iso_tree, hf_bthci_iso_disconnect_in, tvb, 0, 0, chandle_session->disconnect_in_frame);
            proto_item_set_generated(sub_item);
        }
    }

    return tvb_reported_length(tvb);
}


void
proto_register_bthci_iso(void)
{
    module_t         *bthci_iso_module;
    expert_module_t  *bthci_iso_expert_module;
    static hf_register_info hf[] = {
        { &hf_bthci_iso_chandle,
          { "Connection Handle",           "bthci_iso.chandle",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_bthci_iso_pb_flag,
          { "PB Flag",               "bthci_iso.pb_flag",
            FT_UINT16, BASE_HEX, VALS(iso_pb_flag_vals), 0x3000,
            "Packet Boundary Flag", HFILL }
        },
        { &hf_bthci_iso_ts_flag,
          { "Timestamp present",               "bthci_iso.ts_flag",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_bthci_iso_reserved,
          { "Reserved",                    "bthci_iso.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_bthci_iso_continuation_to,
          { "This is a continuation to the PDU in frame",    "bthci_iso.continuation_to",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is a continuation to the PDU in frame #", HFILL }
        },
        { &hf_bthci_iso_reassembled_in,
          { "This PDU is reassembled in frame",              "bthci_iso.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This PDU is reassembled in frame #", HFILL }
        },
        { &hf_bthci_iso_connect_in,
          { "Connect in frame",            "bthci_iso.connect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_iso_disconnect_in,
          { "Disconnect in frame",         "bthci_iso.disconnect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_iso_data_length,
          { "Data Length",           "bthci_iso.data_length",
            FT_UINT16, BASE_DEC, NULL, 0x3FFF,
            NULL, HFILL }
        },
        { &hf_bthci_iso_data,
          { "Data",                        "bthci_iso.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_bthci_iso,
    };

    static ei_register_info ei[] = {
        { &ei_length_bad,      { "bthci_iso.length.bad",      PI_MALFORMED, PI_WARN, "Invalid length", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_bthci_iso = proto_register_protocol("Bluetooth HCI ISO Packet", "HCI_ISO", "bthci_iso");
    bthci_iso_handle = register_dissector("bthci_iso", dissect_bthci_iso, proto_bthci_iso);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthci_iso, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bthci_iso_expert_module = expert_register_protocol(proto_bthci_iso);
    expert_register_field_array(bthci_iso_expert_module, ei, array_length(ei));

    /* Register configuration preferences */
    bthci_iso_module = prefs_register_protocol_subtree("Bluetooth", proto_bthci_iso, NULL);
    prefs_register_bool_preference(bthci_iso_module, "hci_iso_reassembly",
        "Reassemble ISO Fragments",
        "Whether the ISO dissector should reassemble fragmented PDUs",
        &iso_reassembly);

    chandle_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}


void
proto_reg_handoff_bthci_iso(void)
{
    dissector_add_uint("hci_h4.type", HCI_H4_TYPE_ISO, bthci_iso_handle);
    dissector_add_uint("hci_h1.type", BTHCI_CHANNEL_ISO, bthci_iso_handle);
}

static int
dissect_iso_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item      *iso_data_load_item;
    proto_tree      *iso_data_load_tree;
    int remaining;
    uint16_t seq_no;
    uint32_t sdu_length;
    iso_data_info_t *iso_data_info = (iso_data_info_t *) data;
    int offset = 0;

    iso_data_load_item = proto_tree_add_item(tree, proto_bthci_iso_data, tvb, offset, -1, ENC_NA);
    iso_data_load_tree = proto_item_add_subtree(iso_data_load_item, ett_bthci_iso_data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO Data");

    if (iso_data_info->timestamp_present) {
        proto_tree_add_item(iso_data_load_tree, hf_bthci_iso_data_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    seq_no = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(iso_data_load_tree, hf_bthci_iso_data_packet_seq_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(iso_data_load_tree, hf_bthci_iso_data_sdu_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sdu_length);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Handle: 0x%x, SeqNo: %d, SDU length: %d", iso_data_info->handle, seq_no, sdu_length);

    if (pinfo->p2p_dir == P2P_DIR_RECV) {
        uint16_t status = tvb_get_letohs(tvb, offset) >> 14;
        proto_tree_add_item(iso_data_load_tree, hf_bthci_iso_data_status_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, VALS(iso_data_status_vals), "RFU"));
    }
    offset += 2;

    remaining = tvb_captured_length_remaining(tvb, offset);
    if (remaining > 0) {
        proto_item *item;
        item = proto_tree_add_item(iso_data_load_tree, hf_bthci_iso_data_sdu, tvb, offset, -1, ENC_NA);
        if (remaining < (uint16_t)sdu_length)
            proto_item_append_text(item, " (Incomplete)");
        offset += remaining;
    }

    return offset;
}

void
proto_register_iso_data(void)
{
    static hf_register_info hf[] = {
        { &hf_bthci_iso_data_timestamp,
          { "Timestamp",           "bthci_iso_data.timestamp",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_iso_data_packet_seq_num,
          { "Sequence Number",           "bthci_iso_data.packet_seq_num",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_iso_data_sdu_length,
          { "SDU Length",           "bthci_iso_data.sdu_length",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_bthci_iso_data_status_flag,
          { "Data Status Flag",           "bthci_iso_data.status_flag",
            FT_UINT16, BASE_DEC, VALS(iso_data_status_vals), 0xC000,
            NULL, HFILL }
        },
        { &hf_bthci_iso_data_sdu,
          { "SDU",                        "bthci_iso_data.sdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_bthci_iso_data
    };

    proto_bthci_iso_data = proto_register_protocol("Bluetooth ISO Data", "BT ISO Data", "bthci_iso_data");

    proto_register_field_array(proto_bthci_iso_data, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bthci_iso_data_handle = register_dissector("bthci_iso_data", dissect_iso_data, proto_bthci_iso_data);
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
