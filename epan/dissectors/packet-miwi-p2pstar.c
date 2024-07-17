/* packet-miwi_p2pstar.c
 * Dissector  routines for the Microchip MiWi_P2P_Star
 * Copyright 2013 Martin Leixner <info@sewio.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *------------------------------------------------------------
*/

#include "config.h"
#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/exceptions.h>
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/address_types.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>
#include <epan/etypes.h>
#include <epan/oui.h>
#include <wsutil/pint.h>

/* Use libgcrypt for cipher libraries. */
#include <wsutil/wsgcrypt.h>

#include <wsutil/filesystem.h>
#include "packet-ieee802154.h"
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <wsutil/wsgcrypt.h>

/*  Function declarations */
void proto_register_miwi_p2pstar(void);
void proto_reg_handoff_miwi_p2pstar(void);

/*  MiWi MAC Header FCF fields */
#define MIWI_MAC_FCF_FRAME_TYPE         0x0007
#define MIWI_MAC_FCF_SECURITY_EN        0x0008
#define MIWI_MAC_FCF_FRAME_PENDING      0x0010
#define MIWI_MAC_FCF_ACK_REQUEST        0x0020
#define MIWI_MAC_FCF_PANID_COMP         0x0040
#define MIWI_MAC_FCF_RESERVED           0x0380
#define MIWI_MAC_FCF_DEST_ADDR_MODE     0x0C00
#define MIWI_MAC_FCF_FRAME_VERSION      0x3000
#define MIWI_MAC_FCF_SRC_ADDR_MODE      0xC000

/*  MiWi NWK Header FCF fields */
#define MIWI_NWK_FCF_FRAME_TYPE         0x0003
#define MIWI_NWK_FCF_SECURITY_EN        0x0004
#define MIWI_NWK_FCF_INFRA_CLUSTER      0x0008
#define MIWI_NWK_FCF_ACK_REQUEST        0x0010
#define MIWI_NWK_FCF_ADDR_SAME_AS_MAC   0x0020
#define MIWI_NWK_FCF_RESERVED           0x00C0

/* Address Mode Definitions */
#define MIWI_FCF_ADDR_NONE              0x0
#define MIWI_FCF_ADDR_RESERVED          0x1
#define MIWI_FCF_ADDR_SHORT             0x2
#define MIWI_FCF_ADDR_EXT               0x3

#define MIWI_SOURCE_ADDR_MODE           0x00 // to check

/*  MiWi NWK Header FCF fields */
#define MIWI_CAP_INFO_RCV_ON_IDLE       0x0001
#define MIWI_CAP_INFO_REQ_DATA_ON_WP    0x0002
#define MIWI_CAP_INFO_NEED_TIME_SYNC    0x0004
#define MIWI_CAP_INFO_SECURITY_CAP      0x0008
#define MIWI_CAP_INFO_RESERVED          0x00F0

/*Defined addresses*/
#define MIWI_BCAST_ADDR                 0xFFFF

/*Command IDs*/
#define MIWI_P2P_CMD_CONN_REQ           0x81
#define MIWI_P2P_CMD_CONN_REMOVAL_REQ   0x82
#define MIWI_P2P_CMD_DATA_REQ           0x83
#define MIWI_P2P_CMD_CHANNEL_HOP        0x84
#define MIWI_P2P_CMD_ACTIVE_SCAN_REQ    0x87
#define MIWI_P2P_CMD_CONN_RES           0x91
#define MIWI_P2P_CMD_CONN_REMOVAL_RES   0x92
#define MIWI_P2P_CMD_ACTIVE_SCAN_RES    0x97

#define MIWI_STAR_CMD_FORWARD_PACKET    0xCC
#define MIWI_STAR_CMD_SOFT_ACK          0xDA
#define MIWI_STAR_CMD_LINK_STATUS       0x7A
#define MIWI_STAR_CMD_CONN_TABLE        0x77

#define MIWI_CONN_STATUS_SUCCESS        0x00
#define MIWI_CONN_STATUS_EXISTS         0x01
#define MIWI_CONN_STATUS_ACTIVE_SCAN    0x02
#define MIWI_CONN_STATUS_ENTRY_NOT_EXIST    0xF0
#define MIWI_CONN_STATUS_NOT_ENOUGH_SPACE   0xF1
#define MIWI_CONN_STATUS_NOT_SAME_PA    0xF2
#define MIWI_CONN_STATUS_NOT_PERMITTED  0xF3

/* FCS Types used by user configuration */
#define MIWI_P2PSTAR_FCS_16_BIT         1/*  CRC16 */

/**MiWI  Type of MAC frame */
#define MIWI_MAC_FRAME_BEACON           0x00
#define MIWI_MAC_FRAME_DATA             0x01
#define MIWI_MAC_FRAME_ACK              0x02
#define MIWI_MAC_FRAME_CMD              0x03
#define MIWI_MAC_FRAME_RESERVED         0x04

/* User string with the decryption key. */
//static const char *miwi_p2pstar_key_str = NULL;

/*  Initialize protocol and registered fields. */
static int proto_miwi_p2pstar;

/* Initialize protocol subtrees. */
static int ett_miwi_p2pstar;
static int ett_miwi_p2pstar_fcf;
static int ett_miwi_p2pstar_cmd_tree;
static int ett_miwi_p2pstar_cap_info;
static int ett_miwi_fcs;

static dissector_handle_t miwi_p2pstar_handle;

static int hf_miwi_frame_length;
static int hf_miwi_fcf;
static int hf_miwi_fcf_frame_type;
static int hf_miwi_fcf_security_enabled;
static int hf_miwi_fcf_frame_pending;
static int hf_miwi_fcf_ack_req;
static int hf_miwi_fcf_panid_comp;
static int hf_miwi_fcf_reserved;
static int hf_miwi_fcf_dest_addr_mode;
static int hf_miwi_fcf_frame_version;
static int hf_miwi_fcf_src_addr_mode;
static int hf_miwi_seq;
static int hf_miwi_dst_panid;
static int hf_miwi_short_dst_addr;
static int hf_miwi_ext_dst_addr;
//static int hf_miwi_no_dst_addr;
//static int hf_miwi_no_src_addr;
static int hf_miwi_ext_src_addr;
static int hf_miwi_short_src_addr;
static int hf_miwi_addr16;
static int hf_miwi_addr64;
static int hf_miwi_src64_origin;
static int hf_miwi_src_panid;
static int hf_miwi_cmd_id;
//static int hf_miwi_fcs;
//static int hf_miwi_fcs_ok;

static int hf_miwi_oper_chan;
static int hf_miwi_cap_info;
static int hf_miwi_cap_info_rcv_on_idle;
static int hf_miwi_cap_info_rqst_data_on_wp;
static int hf_miwi_cap_info_need_time_sync;
static int hf_miwi_cap_info_security_cap;
static int hf_miwi_cap_info_reserved;
static int hf_miwi_conn_res_status;

//static int hf_miwi_conn_rmv_req;
static int hf_miwi_conn_rmv_res_status;
//static int hf_miwi_data_req;
//static int hf_miwi_chan_hop;
//static int hf_miwi_conn_res;
//static int hf_miwi_conn_rmv_res;
//static int hf_miwi_active_scan_req;
//static int hf_miwi_active_scan_cur_chan;

//static int hf_miwi_active_scan_res;
//static int hf_miwi_active_scan_res_node_id;

//static int hf_miwi_fwd_pkt_cmd;
static int hf_miwi_fwd_pkt_dst_addr;
//static int hf_miwi_conn_tbl_bcast_cmd;
static int hf_miwi_conn_tbl_size;
//static int hf_miwi_software_ack;
//static int hf_miwi_link_status;

/*Channel hopping frame*/
static int hf_miwi_current_op_channel;
static int hf_miwi_dst_channel_to_jump_to;

//static int hf_miwi_mic;
//static int hf_miwi_key_number;

static int miwi_short_address_type;

//static expert_field ei_miwi_empty_payload;
static expert_field ei_miwi_frame_ver;
static expert_field ei_miwi_dst;
static expert_field ei_miwi_src;
static expert_field ei_miwi_invalid_addressing;
static expert_field ei_miwi_invalid_panid_compression;
static expert_field ei_miwi_invalid_panid_compression2;
//static expert_field ei_miwi_fcs;
/* 802.15.4-2003 security */
//static int hf_miwi_sec_frame_counter;
//static int hf_miwi_sec_key_sequence_counter;


/* ethertype for 802.15.4 tag - encapsulating an Ethernet packet */
static unsigned int miwi_ethertype = 0x809A;

/* boolean value set if the FCS must be ok before payload is dissected */
static bool miwi_fcs_ok = true;

/* boolean value set to enable ack tracking */
static bool miwi_ack_tracking = false;

/* Preferences for 2003 security */
//static int miwi_sec_suite = SECURITY_LEVEL_ENC_MIC_64;
//static bool miwi_extend_auth = true;

//static wmem_tree_t* mac_key_hash_handlers;

/*
 * Address Hash Tables
 *
 */
static ieee802154_map_tab_t miwi_map = {NULL, NULL};

//static ieee802154_key_t *miwi_keys = NULL;
//static unsigned num_miwi_keys = 0;

static int miwi_fcs_type = MIWI_P2PSTAR_FCS_16_BIT;

static int* const fields[] = {
    &hf_miwi_fcf_frame_type,
    &hf_miwi_fcf_security_enabled,
    &hf_miwi_fcf_frame_pending,
    &hf_miwi_fcf_ack_req,
    &hf_miwi_fcf_panid_comp,
    &hf_miwi_fcf_reserved,
    &hf_miwi_fcf_dest_addr_mode,
    &hf_miwi_fcf_frame_version,
    &hf_miwi_fcf_src_addr_mode,
    NULL
};

static const value_string miwi_p2pstar_cmd_names[] ={
    { MIWI_P2P_CMD_CONN_REQ,          " Connection Request"},
    { MIWI_P2P_CMD_CONN_REMOVAL_REQ,  " Connection Removal Request"},
    { MIWI_P2P_CMD_DATA_REQ,          " Data Request"},
    { MIWI_P2P_CMD_CHANNEL_HOP,       " Channel Hopping"},
    { MIWI_P2P_CMD_ACTIVE_SCAN_REQ,   " Active Scan Request"},
    { MIWI_P2P_CMD_CONN_RES,          " Connection Response"},
    { MIWI_P2P_CMD_CONN_REMOVAL_RES,  " Connection Removal Response"},
    { MIWI_P2P_CMD_ACTIVE_SCAN_RES,   " Active Scan Response"},
    { MIWI_STAR_CMD_FORWARD_PACKET,   " Forward packet"},
    { MIWI_STAR_CMD_SOFT_ACK,         " Soft Acknowledgement"},
    { MIWI_STAR_CMD_LINK_STATUS,      " Link Status"},
    { MIWI_STAR_CMD_CONN_TABLE,       " Connection Table"},
    { 0, NULL}
};

/* MAC Frame Types */
static const value_string miwi_mac_frame_types[] = {
    { MIWI_MAC_FRAME_BEACON,          "Beacon"},
    { MIWI_MAC_FRAME_DATA,            "Data"},
    { MIWI_MAC_FRAME_ACK,             "Acknowledgement"},
    { MIWI_MAC_FRAME_CMD,             "Command"},
    {MIWI_MAC_FRAME_RESERVED,         "Reserved"},
    { 0, NULL}
};

static const value_string miwi_addr_modes[] = {
    { MIWI_FCF_ADDR_NONE,             "None"},
    { MIWI_FCF_ADDR_RESERVED,         "Reserved"},
    { MIWI_FCF_ADDR_SHORT,            "Short/16-bit"},
    { MIWI_FCF_ADDR_EXT,              "Long/64-bit"},
    { 0, NULL}
};

/* Versions */
static const value_string miwi_frame_versions[] = {
    { IEEE802154_VERSION_2003,        "IEEE Std 802.15.4-2003"},
    { IEEE802154_VERSION_2006,        "IEEE Std 802.15.4-2006"},
    { IEEE802154_VERSION_2015,        "IEEE Std 802.15.4-2015"},
    { IEEE802154_VERSION_RESERVED,    "Reserved" },
    { 0, NULL}
};

static const value_string miwi_p2pstar_conn_status[] = {
    { MIWI_CONN_STATUS_SUCCESS,          " (Successful)"},
    { MIWI_CONN_STATUS_EXISTS,           " (Already Exists)"},
    { MIWI_CONN_STATUS_ACTIVE_SCAN,      " (Active Scan State)"},
    { MIWI_CONN_STATUS_ENTRY_NOT_EXIST,  " (Entry Not Exist)"},
    { MIWI_CONN_STATUS_NOT_ENOUGH_SPACE, " (Not Enough Space)"},
    { MIWI_CONN_STATUS_NOT_SAME_PA,      " (PANID Mismatch)"},
    { MIWI_CONN_STATUS_NOT_PERMITTED,    " (Not Permitted)"},
    { 0, NULL}
};

#define miwi_packet ieee802154_packet

   /* CRC definitions. IEEE 802.15.4 CRCs vary from ITU-T by using an initial value of
 * 0x0000, and no XOR out. IEEE802154_CRC_XOR is defined as 0xFFFF in order to un-XOR
 * the output from the ITU-T (CCITT) CRC routines in Wireshark. */
#define MIWI_CRC_SEED     0x0000
#define MIWI_CRC_XOROUT   0xFFFF
#define miwi_crc_tvb(tvb, offset)   (crc16_ccitt_tvb_seed(tvb, offset, MIWI_CRC_SEED) ^ MIWI_CRC_XOROUT)
/* For the 32-bit CRC, IEEE 802.15.4 uses ITU-T (CCITT) CRC-32. */
#define miwi_crc32_tvb(tvb, offset) (crc32_ccitt_tvb(tvb, offset))
   /**
 * Verify the 16/32 bit IEEE 802.15.4 FCS
 * @param tvb the IEEE 802.15.4 frame from the FCF up to and including the FCS
 * @return if the computed FCS matches the transmitted FCS
 */
static bool
is_fcs_ok(tvbuff_t *tvb, unsigned fcs_len)
{
    if(fcs_len == 2){
        /* The FCS is in the last two bytes of the packet. */
        uint16_t fcs = tvb_get_letohs(tvb, tvb_reported_length(tvb)-2);
        uint16_t fcs_calc = (uint16_t) miwi_crc_tvb(tvb, tvb_reported_length(tvb)-2);
        return fcs == fcs_calc;
    }
    else{
        /* The FCS is in the last four bytes of the packet. */
        uint32_t fcs = tvb_get_letohl(tvb, tvb_reported_length(tvb)-4);
        uint32_t fcs_calc = miwi_crc32_tvb(tvb, tvb_reported_length(tvb)-4);
        return fcs == fcs_calc;
    }
}/* is_fcs_ok */

/* Returns the prompt string for the Decode-As dialog. */
static void miwi_da_prompt(packet_info *pinfo _U_, char* result)
{
    ieee802154_hints_t *hints;
    hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_miwi_p2pstar, 0);
    if(hints)
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "MIWI P2P STAR PAN 0x%04x as", hints->src_pan);
    else
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "MIWI P2P STAR PAN Unknown");
}/* miwi_da_prompt */
/* Returns the value to index the panid decode table with (source PAN)*/
static void *miwi_da_value(packet_info *pinfo _U_)
{
    ieee802154_hints_t *hints;
    hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_miwi_p2pstar, 0);
    if(hints)
        return GUINT_TO_POINTER((unsigned)(hints->src_pan));
    else
        return NULL;
}/* miwi_da_value */
static int miwi_short_address_to_str(const address* addr, char *buf, int buf_len)
{
    uint16_t miwi_short_addr = pletoh16(addr->data);

    if (miwi_short_addr == 0xffff)
    {
        g_strlcpy(buf, "Broadcast", buf_len);
        return 10;
    }

    *buf++ = '0';
    *buf++ = 'x';
    buf = word_to_hex(buf, miwi_short_addr);
    *buf = '\0'; /* NULL terminate */

    return 7;
} /* miwi_short_address_to_str */
static int miwi_short_to_str(uint16_t miwi_short_addr, char *buf, int buf_len)
{
    if(miwi_short_addr == 0xffff)
    {
        g_strlcpy(buf, "Broadcast", buf_len);
        return 10;
    }

    *buf++ = '0';
    *buf++ = 'x';
    buf = word_to_hex(buf, miwi_short_addr);
    *buf = '\0'; /* NULL terminate */

    return 7;
}/* miwi_short_to_str */

static int miwi_short_address_str_len(const address* addr _U_)
{
    return 11;
}

static int miwi_short_address_len(void)
{
    return 2;
}

/**
 *Extracts an integer sub-field from an int with a given mask
 *
*/
#if 0
static unsigned miwi_get_bit_field(unsigned input, unsigned mask)
{
    /* Sanity Check, don't want infinite loops. */
    if(mask == 0) return 0;
    /* Shift input and mask together. */
    while (!(mask & 0x1)){
        input >>= 1;
        mask >>=1;
    }/* while */
    return (input & mask);
}/* miwi_get_bit_field */
#endif

/* Return the length in octets for the user configured
 * FCS/metadata following the PHY Payload */
static unsigned miwi_fcs_type_len(unsigned i)
{
    unsigned fcs_type_lengths[] = { 2, 2, 4 };
    if(i < array_length(fcs_type_lengths)){
        return fcs_type_lengths[i];
    }
    return 0;
}/* miwi_fcs_type_len */

#if 0
/* Set MAC key function. */
static unsigned miwi_set_mac_key(miwi_packet *packet, unsigned char *key, unsigned char *alt_key, ieee802154_key_t *uat_key)
{
    ieee802154_set_key_func func = (ieee802154_set_key_func)wmem_tree_lookup32(mac_key_hash_handlers, uat_key->hash_type);

    if(func != NULL)
        return func(packet, key, alt_key, uat_key);

    /* Right now, KEY_HASH_NONE and KEY_HASH_ZIP are not registered because they
        work with this "default" behavior */
    if(packet->key_index == uat_key->key_index)
    {
        memcpy(key, uat_key->key, IEEE802154_CIPHER_SIZE);
        return 1;
    }

    return 0;
}/* miwi_set_mac_key */
#endif
/**
 * Dissector helper, parses and displays the frame control field.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the FCF.
 *
 */
static void
dissect_miwi_fcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint16_t    miwi_fcf;

    /*Frame control fields*/
    miwi_fcf = tvb_get_letohs(tvb, (const int)*offset);
    packet->frame_type = (miwi_fcf & MIWI_MAC_FCF_FRAME_TYPE);
    packet->security_enable = (miwi_fcf & MIWI_MAC_FCF_SECURITY_EN) >> 3;
    packet->frame_pending = (miwi_fcf & MIWI_MAC_FCF_FRAME_PENDING) >> 4;
    packet->ack_request = (miwi_fcf & MIWI_MAC_FCF_ACK_REQUEST) >> 5;
    packet->pan_id_compression = (miwi_fcf & MIWI_MAC_FCF_PANID_COMP) >> 6;
    /*packet->reserved = (miwi_fcf & MIWI_MAC_FCF_RESERVED) >> 7;*/
    packet->dst_addr_mode = (miwi_fcf & MIWI_MAC_FCF_DEST_ADDR_MODE) >> 10;
    packet->version = (miwi_fcf & MIWI_MAC_FCF_FRAME_VERSION) >> 12;
    packet->src_addr_mode = (miwi_fcf & MIWI_MAC_FCF_SRC_ADDR_MODE) >> 14;

    proto_item_append_text(tree, " %s", val_to_str_const(packet->frame_type, miwi_mac_frame_types, "Reserved"));
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet->frame_type, miwi_mac_frame_types, "Reserved"));

    proto_tree_add_bitmask(tree, tvb,(const int)*offset, hf_miwi_fcf,
               ett_miwi_p2pstar_fcf, fields, ENC_LITTLE_ENDIAN);

    *offset += 2;
}/* dissect_miwi_fcf */

/**
 * Command subdissector routine for the Association request command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */

static void
dissect_miwi_connect_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint8_t cap,oper_chan;
    proto_tree *subtree;
    static int* const capability[] = {
        &hf_miwi_cap_info_rcv_on_idle,
        &hf_miwi_cap_info_rqst_data_on_wp,
        &hf_miwi_cap_info_need_time_sync,
        &hf_miwi_cap_info_security_cap,
        &hf_miwi_cap_info_reserved,
        NULL
    };

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1,ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const(packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));
    oper_chan = tvb_get_uint8(tvb, *offset);
    proto_tree_add_uint(subtree, hf_miwi_oper_chan, tvb, *offset, 1, oper_chan);
    *offset += 1;

    /* Get and display capability info. */
    cap = tvb_get_uint8(tvb, *offset);
    proto_tree_add_uint(subtree, hf_miwi_cap_info, tvb, *offset, 1, cap);
    proto_tree_add_bitmask_list(subtree, tvb, *offset, 1, capability, ENC_NA);
    *offset += 1;

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_connect_req */

/**
 * Command subdissector routine for the Association response command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */
static void
dissect_miwi_connect_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    proto_tree *subtree;
    proto_item *ti;
    uint8_t     status;
    uint8_t cap;
    static int* const capability[] = {
        &hf_miwi_cap_info_rcv_on_idle,
        &hf_miwi_cap_info_rqst_data_on_wp,
        &hf_miwi_cap_info_need_time_sync,
        &hf_miwi_cap_info_security_cap,
        &hf_miwi_cap_info_reserved,
        NULL
    };

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 3, ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const((const uint32_t)packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));

    /* Get and display the status. */
    status = tvb_get_uint8(tvb, *offset);
    if(tree){
        ti = proto_tree_add_uint(subtree, hf_miwi_conn_res_status, tvb, *offset, 1, status);
        proto_item_append_text(ti, "%s", val_to_str_const(status, miwi_p2pstar_conn_status, " (Reserved)"));
    }
    *offset += 1;
    col_append_fstr(pinfo->cinfo, COL_INFO, " Connection Response");

    /* Update the info column. */
    if(status == IEEE802154_CMD_ASRSP_AS_SUCCESS){
        /* Association was successful. */
        if(packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT){
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PAN: 0x%04x", packet->dst_pan);
        }
        if(packet->src16 != IEEE802154_NO_ADDR16){
            col_append_fstr(pinfo->cinfo, COL_INFO, " Addr: 0x%04x", packet->src16);
        }
    }
    else{
        /* Association was unsuccessful. */
        col_append_str(pinfo->cinfo, COL_INFO, ", Unsuccessful");
    }

    /* Update the address table. */
    if((status == IEEE802154_CMD_ASRSP_AS_SUCCESS) && (packet->src16 != IEEE802154_NO_ADDR16)){
        ieee802154_addr_update(&miwi_map, packet->src16, packet->dst_pan, packet->dst64,
                pinfo->current_proto, pinfo->num);
    }

    /* Get and display capability info. */
    cap = tvb_get_uint8(tvb, *offset);
    proto_tree_add_uint(subtree, hf_miwi_cap_info, tvb, *offset, 1, cap);
    proto_tree_add_bitmask_list(subtree, tvb, *offset, 1, capability, ENC_NA);
    *offset += 1;

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_connect_rsp */
/**
 * Command subdissector routine for the Channel Hopping command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */
static void
dissect_miwi_channel_hop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint8_t current_op_channel,dst_channel_to_jump_to;
    proto_tree *subtree;
    proto_item *ti;

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1,ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const(packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));
    current_op_channel = tvb_get_uint8(tvb, *offset);
    ti = proto_tree_add_uint(subtree, hf_miwi_current_op_channel, tvb, *offset, 1, current_op_channel);
    proto_item_append_text(ti, ", Current Operating Channel: %i", current_op_channel);
   *offset +=1;

    dst_channel_to_jump_to = tvb_get_uint8(tvb, *offset);
    ti = proto_tree_add_uint(subtree, hf_miwi_dst_channel_to_jump_to, tvb, *offset, 1, dst_channel_to_jump_to);
    proto_item_append_text(ti, ", Destination Channel to Jump to: %i", dst_channel_to_jump_to);
    *offset +=1;

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_channel_hop */

/**
 * Command subdissector routine for the Connection removal response command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */
static void
dissect_miwi_connect_removal_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint8_t conn_rmv_res_status;
    proto_tree *subtree;
    proto_item *ti;

   /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1,ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const(packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));
    conn_rmv_res_status = tvb_get_uint8(tvb, *offset);
    ti = proto_tree_add_uint(subtree, hf_miwi_conn_rmv_res_status, tvb, *offset, 1, conn_rmv_res_status);
    *offset +=1;
    if(conn_rmv_res_status == 0x00){
        proto_item_append_text(ti, ", Successful [Status: %i]", conn_rmv_res_status);
    } else
        proto_item_append_text(ti, ", Failed [Error Code: %i]", conn_rmv_res_status);

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_connect_removal_res */

/**
 * Command subdissector routine for the Scan request command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */
static void
dissect_miwi_active_scan_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint8_t scan_cur_chan;
    proto_tree *subtree;
    proto_item *ti;

   /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1,ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const(packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));
    scan_cur_chan = tvb_get_uint8(tvb, *offset);
    ti = proto_tree_add_uint(subtree, hf_miwi_current_op_channel, tvb, *offset, 1, scan_cur_chan);
    proto_item_append_text(ti, ", Current operating Channel %i", scan_cur_chan);
    *offset +=1;

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_active_scan_req */
/**
 * Command subdissector routine for the Scan response command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */

static void
dissect_miwi_active_scan_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint8_t cap,scan_res_node_id;
    proto_tree *subtree;
    static int* const capability[] = {
        &hf_miwi_cap_info_rcv_on_idle,
        &hf_miwi_cap_info_rqst_data_on_wp,
        &hf_miwi_cap_info_need_time_sync,
        &hf_miwi_cap_info_security_cap,
        &hf_miwi_cap_info_reserved,
        NULL
    };

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1,ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const(packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));

    /* Get and display capability info. */
    cap = tvb_get_uint8(tvb, *offset);
    proto_tree_add_uint(subtree, hf_miwi_cap_info, tvb, *offset, 1, cap);
    proto_tree_add_bitmask_list(subtree, tvb, *offset, 1, capability, ENC_NA);
    *offset += 1;

    scan_res_node_id = tvb_get_uint8(tvb, *offset);
    proto_tree_add_uint(subtree, hf_miwi_oper_chan, tvb, *offset, 1, scan_res_node_id);
    *offset += 1;

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_active_scan_res */
/**
 * Command subdissector routine for the forward Packet command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */
static void
dissect_miwi_fwd_packet_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint8_t fwd_pkt_dst_addr;
    proto_tree *subtree;

   /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1,ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const(packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));
    fwd_pkt_dst_addr = tvb_get_uint8(tvb, *offset);
    proto_tree_add_uint(subtree, hf_miwi_fwd_pkt_dst_addr, tvb, *offset, 1, fwd_pkt_dst_addr);
    *offset +=1;

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_fwd_packet_cmd */
/**
 * Command subdissector routine for the Connection table broadcast command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet Miwi P2PStar packet information.
 * @param offset offset into the tvb to find the packet information.
 */

static void
dissect_miwi_connect_tbl_bcast_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    uint8_t conn_tbl_size;
    proto_tree *subtree;

   /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1,ett_miwi_p2pstar_cmd_tree, NULL,
                    val_to_str_const(packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));
    conn_tbl_size = tvb_get_uint8(tvb, *offset);
    proto_tree_add_uint(subtree, hf_miwi_conn_tbl_size, tvb, *offset, 1, conn_tbl_size);
    *offset +=1;

    /* Call the data dissector for any leftover bytes. */
    if(tvb_captured_length(tvb) > *offset){
        call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    }
}/* dissect_miwi_connect_tbl_bcast_cmd */

/**
 * Subdissector routine for MiWi P2P Star commands
 *
 * @param tvb pointer to buffer containing the command payload
 * @param pinfo pointer to packet information fields
 * @param tree pointer to the protocol tree
 * @param packet Miwi P2P Star packet information
 * @param offset offset into the tvb to find the packet information.
 */
static void
dissect_miwi_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, miwi_packet *packet, unsigned *offset)
{
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const((const uint32_t)packet->command_id, miwi_p2pstar_cmd_names, "Unknown Command"));

    switch (packet->command_id){
        case MIWI_P2P_CMD_CONN_REQ:
            dissect_miwi_connect_req(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_P2P_CMD_CONN_RES:
            dissect_miwi_connect_rsp(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_P2P_CMD_CHANNEL_HOP:
            dissect_miwi_channel_hop(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_P2P_CMD_ACTIVE_SCAN_REQ:
            dissect_miwi_active_scan_req(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_P2P_CMD_CONN_REMOVAL_RES:
            dissect_miwi_connect_removal_res(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_P2P_CMD_ACTIVE_SCAN_RES:
            dissect_miwi_active_scan_res(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_STAR_CMD_FORWARD_PACKET:
            dissect_miwi_fwd_packet_cmd(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_STAR_CMD_CONN_TABLE:
            dissect_miwi_connect_tbl_bcast_cmd(tvb, pinfo, tree, packet,offset);
        break;
        case MIWI_P2P_CMD_DATA_REQ:
        case MIWI_P2P_CMD_CONN_REMOVAL_REQ:
        case MIWI_STAR_CMD_SOFT_ACK:
        case MIWI_STAR_CMD_LINK_STATUS:
            /* No payload expected. */
        break;
        default:
            proto_item_append_text(tree, ", Unknown Command");
              if(tvb_captured_length_remaining(tvb, 0) > 0){
                call_data_dissector(tvb, pinfo, tree);
        break;
            }
    }/* switch */
}/* dissect_miwi_command */

/**
 * Subdissector routine for MiWi P2P Star header parsing
 *
 * @param tvb pointer to buffer containing the command payload
 * @param pinfo pointer to packet information fields
 * @param tree pointer to the protocol tree
 * @param created_header_tree new tree to parse the MiWi packet .
 * @param parsed_info Miwi P2P Star packet information
 */
static unsigned
miwi_dissect_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree **created_header_tree, miwi_packet **parsed_info)
{
    proto_tree              *miwi_tree = NULL;
    proto_item              *proto_root = NULL;
    proto_item              *hidden_item;
    proto_item              *ti;
    unsigned                offset = 0;
    bool                    dstPanPresent = false;
    bool                    srcPanPresent = false;
    miwi_packet      *packet = wmem_new0(wmem_packet_scope(), miwi_packet);
    ieee802154_short_addr   addr16;
    ieee802154_hints_t     *ieee_hints;

    packet->short_table = miwi_map.short_table;

    /* Allocate frame data with hints for upper layers */
    if(!PINFO_FD_VISITED(pinfo) ||
        (ieee_hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_miwi_p2pstar, 0)) == NULL){
        ieee_hints = wmem_new0(wmem_file_scope(), ieee802154_hints_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_miwi_p2pstar, 0, ieee_hints);
    }

    /* Save a pointer to the whole packet */
    ieee_hints->packet = packet;

    /* Create the protocol tree. */
    if(tree){
        proto_root = proto_tree_add_protocol_format(tree, proto_miwi_p2pstar, tvb, 0, tvb_captured_length(tvb), "IEEE 802.15.4-MiWi");
        miwi_tree = proto_item_add_subtree(proto_root, ett_miwi_p2pstar);
    }
    /* Add the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MiWi P2P Star");

    /* Set out parameters */
    *created_header_tree = miwi_tree;
    *parsed_info = packet;

    /* Add the packet length to the filter field */
    hidden_item = proto_tree_add_uint(miwi_tree, hf_miwi_frame_length, NULL, 0, 0, tvb_reported_length(tvb));
    proto_item_set_hidden(hidden_item);

    /* Frame Control Field */
    dissect_miwi_fcf(tvb, pinfo, miwi_tree, packet, &offset);

    /* Sequence Number */
    /* IEEE 802.15.4 Sequence Number Suppression */
    packet->seqno = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(miwi_tree, hf_miwi_seq, tvb, offset, 1, packet->seqno);
    /* For Ack packets display this in the root. */
    if(packet->frame_type == IEEE802154_FCF_ACK){
        proto_item_append_text(proto_root, ", Sequence Number: %u", packet->seqno);
    }
    offset += 1;

    /*
     * ADDRESSING FIELDS
     */
    /* Clear out the addressing strings. */
    clear_address(&pinfo->net_dst);
    clear_address(&pinfo->dl_dst);
    clear_address(&pinfo->dst);
    clear_address(&pinfo->net_src);
    clear_address(&pinfo->dl_src);
    clear_address(&pinfo->src);

    if(packet->dst_addr_mode == IEEE802154_FCF_ADDR_RESERVED){
        /* Invalid Destination Address Mode. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_miwi_dst);
        return 0;
    }

    if(packet->src_addr_mode == IEEE802154_FCF_ADDR_RESERVED){
        /* Invalid Source Address Mode. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_miwi_src);
        return 0;
    }

    if(packet->version == IEEE802154_VERSION_RESERVED){
        /* Unknown Frame Version. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_miwi_frame_ver);
        return 0;
    }
    else if((packet->version == IEEE802154_VERSION_2003) ||  /* For Frame Version 0b00 and */
             (packet->version == IEEE802154_VERSION_2006))  { /* 0b01 effect defined in section 7.2.1.5 */

        if((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) && /* if both destination and source */
            (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE)){ /* addressing information is present */
            if(packet->pan_id_compression == 1){ /* PAN IDs are identical */
                dstPanPresent = true;
                srcPanPresent = false; /* source PAN ID is omitted */
            }
            else{ /* PAN IDs are different, both shall be included in the frame */
                dstPanPresent = true;
                srcPanPresent = true;
            }
        }
        else{
            if(packet->pan_id_compression == 1){ /* all remaining cases pan_id_compression must be zero */
                expert_add_info(pinfo, proto_root, &ei_miwi_invalid_panid_compression);
                return 0;
            }
            else{
                /* only either the destination or the source addressing information is present */
                if((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) &&        /*   Present   */
                    (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE)){        /* Not Present */
                    dstPanPresent = true;
                    srcPanPresent = false;
                }
                else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) &&   /* Not Present */
                         (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE)){   /*   Present   */
                    dstPanPresent = false;
                    srcPanPresent = true;
                }
                else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) &&   /* Not Present */
                         (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE)){   /* Not Present */
                    dstPanPresent = false;
                    srcPanPresent = false;
                }
                else{
                    expert_add_info(pinfo, proto_root, &ei_miwi_invalid_addressing);
                    return 0;
                }
            }
        }
    }
    else if(packet->version == IEEE802154_VERSION_2015){
        /* for Frame Version 0b10 PAN Id Compression only applies to these frame types */
        if((packet->frame_type == IEEE802154_FCF_BEACON) ||
            (packet->frame_type == IEEE802154_FCF_DATA)   ||
            (packet->frame_type == IEEE802154_FCF_ACK)    ||
            (packet->frame_type == IEEE802154_FCF_CMD)       ){

            /* Implements Table 7-6 of IEEE 802.15.4-2015
             *
             *      Destination Address  Source Address  Destination PAN ID  Source PAN ID   PAN ID Compression
             *-------------------------------------------------------------------------------------------------
             *  1.  Not Present          Not Present     Not Present         Not Present     0
             *  2.  Not Present          Not Present     Present             Not Present     1
             *  3.  Present              Not Present     Present             Not Present     0
             *  4.  Present              Not Present     Not Present         Not Present     1
             *
             *  5.  Not Present          Present         Not Present         Present         0
             *  6.  Not Present          Present         Not Present         Not Present     1
             *
             *  7.  Extended             Extended        Present             Not Present     0
             *  8.  Extended             Extended        Not Present         Not Present     1
             *
             *  9.  Short                Short           Present             Present         0
             * 10.  Short                Extended        Present             Present         0
             * 11.  Extended             Short           Present             Present         0
             *
             * 12.  Short                Extended        Present             Not Present     1
             * 13.  Extended             Short           Present             Not Present     1
             * 14.  Short                Short           Present             Not Present     1
             */

            /* Row 1 */
            if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) &&      /* Not Present */
                (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) &&      /* Not Present */
                (packet->pan_id_compression == 0)){
                        dstPanPresent = false;
                        srcPanPresent = false;
            }
            /* Row 2 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->pan_id_compression == 1)){
                        dstPanPresent = true;
                        srcPanPresent = false;
            }
            /* Row 3 */
            else if((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->pan_id_compression == 0)){
                        dstPanPresent = true;
                        srcPanPresent = false;
            }
            /* Row 4 */
            else if((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->pan_id_compression == 1)){
                        dstPanPresent = false;
                        srcPanPresent = false;
            }
            /* Row 5 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->pan_id_compression == 0)){
                        dstPanPresent = false;
                        srcPanPresent = true;
            }
            /* Row 6 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->pan_id_compression == 1)){
                        dstPanPresent = false;
                        srcPanPresent = false;
            }
            /* Row 7 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->pan_id_compression == 0)){
                        dstPanPresent = true;
                        srcPanPresent = false;
            }
            /* Row 8 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->pan_id_compression == 1)){
                        dstPanPresent = false;
                        srcPanPresent = false;
            }
            /* Row 9 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) && /*  Short     */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) && /*  Short     */
                     (packet->pan_id_compression == 0)){
                        dstPanPresent = true;
                        srcPanPresent = true;
            }
            /* Row 10 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) && /*  Short    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&   /*  Extended */
                     (packet->pan_id_compression == 0)){
                        dstPanPresent = true;
                        srcPanPresent = true;
            }
            /* Row 11 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)   &&   /*  Extended */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->pan_id_compression == 0)){
                        dstPanPresent = true;
                        srcPanPresent = true;
            }
            /* Row 12 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)   &&   /*  Extended */
                     (packet->pan_id_compression == 1)){
                        dstPanPresent = true;
                        srcPanPresent = false;
            }
            /* Row 13 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)   &&   /*  Extended */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->pan_id_compression == 1)){
                        dstPanPresent = true;
                        srcPanPresent = false;
            }
            /* Row 14 */
            else if((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->pan_id_compression == 1)){
                        dstPanPresent = true;
                        srcPanPresent = false;
            }
            else{
                expert_add_info(pinfo, proto_root, &ei_miwi_invalid_panid_compression2);
                return 0;
            }
        }
        else{ /* Frame Type is neither Beacon, Data, Ack, nor Command: PAN ID Compression is not used */
            dstPanPresent = false; /* no PAN ID will */
            srcPanPresent = false; /* be present     */
        }
    }
    else{
        /* Unknown Frame Version. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_miwi_frame_ver);
        return 0;
    }

    /*
     * Addressing Fields
     */

    /* Destination PAN Id */
    if(dstPanPresent){
        char* pan_id = (char *)wmem_new(pinfo->pool, uint64_t);

        packet->dst_pan = tvb_get_letohs(tvb, offset);
        miwi_short_to_str(packet->dst_pan,pan_id,10);

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Pan ID: %s", pan_id);
        proto_tree_add_uint(miwi_tree, hf_miwi_dst_panid, tvb, offset, 2, packet->dst_pan);
        offset += 2;
    }

    /* Destination Address  */
    if(packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT){
        char* dst_addr = (char *)wmem_new(pinfo->pool, uint64_t);

        /* Get the address. */
        packet->dst16 = tvb_get_letohs(tvb, offset);

        /* Provide address hints to higher layers that need it. */
        if(ieee_hints){
            ieee_hints->dst16 = packet->dst16;
        }

        set_address_tvb(&pinfo->dl_dst, miwi_short_address_type, 2, tvb, offset);
        copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
        miwi_short_to_str(packet->dst16,dst_addr,10);

        proto_tree_add_uint(miwi_tree, hf_miwi_short_dst_addr, tvb, offset, 2, packet->dst16);
        proto_item_append_text(proto_root, ", Dst: %s", dst_addr);
        ti = proto_tree_add_uint(miwi_tree, hf_miwi_addr16, tvb, offset, 2, packet->dst16);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", dst_addr);
        offset += 2;
    }
    else if(packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT){
        uint64_t *p_addr = (uint64_t *)wmem_new(pinfo->pool, uint64_t);

        /* Get the address */
        packet->dst64 = tvb_get_letoh64(tvb, offset);

        /* Copy and convert the address to network byte order. */
        *p_addr = pntoh64(&(packet->dst64));

        /* Display the destination address. */
        /* XXX - OUI resolution doesn't happen when displaying resolved
         * EUI64 addresses; that should probably be fixed in
         * epan/addr_resolv.c.
         */
        set_address(&pinfo->dl_dst, AT_EUI64, 8, p_addr);
        copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
        if(tree){
            proto_tree_add_item(miwi_tree, hf_miwi_ext_dst_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(proto_root, ", Dst: %s", eui64_to_display(wmem_packet_scope(), packet->dst64));
            ti = proto_tree_add_item(miwi_tree, hf_miwi_addr64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(ti);
            proto_item_set_hidden(ti);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", eui64_to_display(wmem_packet_scope(), packet->dst64));
        offset += 8;
    }

    /* Source PAN Id */
    if(srcPanPresent){
        char* pan_id = (char *)wmem_new(pinfo->pool, uint64_t);
        packet->src_pan = tvb_get_letohs(tvb, offset);
        miwi_short_to_str(packet->src_pan,pan_id,10);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Src Pan ID: %s", pan_id);
        proto_tree_add_uint(miwi_tree, hf_miwi_src_panid, tvb, offset, 2, packet->src_pan);
        offset += 2;
    }
    else{
        if(dstPanPresent){
            packet->src_pan = packet->dst_pan;
        }
        else{
            packet->src_pan = IEEE802154_BCAST_PAN;
        }
    }
    if(ieee_hints){
        ieee_hints->src_pan = packet->src_pan;
    }

    /* Source Address */
    if(packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT){
        char* src_addr = (char *)wmem_new(pinfo->pool, uint64_t);

        /* Get the address. */
        packet->src16 = tvb_get_letohs(tvb, offset);

        if(!PINFO_FD_VISITED(pinfo)){
            /* If we know our extended source address from previous packets,
                * provide a pointer to it in a hint for upper layers */
            addr16.addr = packet->src16;
            addr16.pan = packet->src_pan;

            if(ieee_hints){
                ieee_hints->src16 = packet->src16;
                ieee_hints->map_rec = (ieee802154_map_rec *)
                    g_hash_table_lookup(miwi_map.short_table, &addr16);
            }
        }

        set_address_tvb(&pinfo->dl_src, miwi_short_address_type, 2, tvb, offset);
        copy_address_shallow(&pinfo->src, &pinfo->dl_src);
        miwi_short_to_str(packet->src16,src_addr,10);

        /* Add the addressing info to the tree. */
        if(tree){
            proto_tree_add_uint(miwi_tree, hf_miwi_short_src_addr, tvb, offset, 2, packet->src16);
            proto_item_append_text(proto_root, ", Src: %s", src_addr);
            ti = proto_tree_add_uint(miwi_tree, hf_miwi_addr16, tvb, offset, 2, packet->src16);
            proto_item_set_generated(ti);
            proto_item_set_hidden(ti);

            if(ieee_hints && ieee_hints->map_rec){
                /* Display inferred source address info */
                ti = proto_tree_add_eui64(miwi_tree, hf_miwi_short_src_addr, tvb, offset, 0,
                        ieee_hints->map_rec->addr64);
                proto_item_set_generated(ti);
                ti = proto_tree_add_eui64(miwi_tree, hf_miwi_addr64, tvb, offset, 0, ieee_hints->map_rec->addr64);
                proto_item_set_generated(ti);
                proto_item_set_hidden(ti);

                if( ieee_hints->map_rec->start_fnum ){
                    ti = proto_tree_add_uint(miwi_tree, hf_miwi_src64_origin, tvb, 0, 0,
                        ieee_hints->map_rec->start_fnum);
                }
                else{
                    ti = proto_tree_add_uint_format_value(miwi_tree, hf_miwi_src64_origin, tvb, 0, 0,
                        ieee_hints->map_rec->start_fnum, "Pre-configured");
                }
                proto_item_set_generated(ti);
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", src_addr);

        offset += 2;
    }
    else if(packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT){
        uint64_t *p_addr = (uint64_t *)wmem_new(pinfo->pool, uint64_t);

        /* Get the address. */
        packet->src64 = tvb_get_letoh64(tvb, offset);

        /* Copy and convert the address to network byte order. */
        *p_addr = pntoh64(&(packet->src64));

        /* Display the source address. */
        /* XXX - OUI resolution doesn't happen when displaying resolved
         * EUI64 addresses; that should probably be fixed in
         * epan/addr_resolv.c.
         */
        set_address(&pinfo->dl_src, AT_EUI64, 8, p_addr);
        copy_address_shallow(&pinfo->src, &pinfo->dl_src);
        if(tree){
            proto_tree_add_item(miwi_tree, hf_miwi_ext_src_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(proto_root, ", Src: %s", eui64_to_display(wmem_packet_scope(), packet->src64));
            ti = proto_tree_add_item(miwi_tree, hf_miwi_addr64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(ti);
            proto_item_set_hidden(ti);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", eui64_to_display(wmem_packet_scope(), packet->src64));
        offset += 8;
    }

    /* All of the beacon fields, except the beacon payload are considered nonpayload. */
    if((packet->version == IEEE802154_VERSION_2003) || (packet->version == IEEE802154_VERSION_2006)){

        if(packet->frame_type == IEEE802154_FCF_CMD){
            /**
             * In IEEE802.15.4-2003 and 2006 the command identifier is considered to be part of the header
             * and is thus not encrypted. For IEEE802.15.4-2012e and later the command id is considered to be
             * part of the payload, is encrypted, and follows the payload IEs. Thus we only parse the command id
             * here for 2006 and earlier frames. */
            packet->command_id = tvb_get_uint8(tvb, offset);
            if(tree){
                proto_tree_add_uint(miwi_tree, hf_miwi_cmd_id, tvb, offset, 1, packet->command_id);
            }
            offset++;
        }
    }
    return offset;
}/*miwi_dissect_header*/

/**
 * Subdissector routine for MiWi P2P Star frame payload parsing
 *
 * @param tvb pointer to buffer containing the command payload
 * @param pinfo pointer to packet information fields
 * @param ieee802154_tree pointer to the protocol tree
 * @param packet Miwi P2P Star packet information
 * @param fcs_ok set to false to indicate FCS verification failed
 * @param offset offset into the tvb to find the packet information.
 */
static unsigned miwi_dissect_frame_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ieee802154_tree, miwi_packet *packet, bool fcs_ok, unsigned *offset)
{
    tvbuff_t *payload_tvb = tvb;
    proto_tree *tree = proto_tree_get_parent_tree(ieee802154_tree);
    //heur_dtbl_entry_t *hdtbl_entry;

    /* There are commands without payload */
    if(tvb_captured_length(payload_tvb) > 0 || packet->frame_type == IEEE802154_FCF_CMD){
        /*
         * Wrap the sub-dissection in a try/catch block in case the payload is
         * broken. First we store the current protocol so we can fix it if an
         * exception is thrown by the subdissectors.
         */
        const char* saved_proto = pinfo->current_proto;
        /* Try to dissect the payload. */
        TRY {
            switch (packet->frame_type){
            case IEEE802154_FCF_BEACON:
                     call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
            break;

            case IEEE802154_FCF_CMD:
                dissect_miwi_command(payload_tvb, pinfo, ieee802154_tree, packet,offset);
            break;

            case IEEE802154_FCF_DATA:
                /* Sanity-check. */
               if((!fcs_ok && miwi_fcs_ok) || !tvb_reported_length(payload_tvb)){
                    call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
                }
            break;
            default:
                /* Could not subdissect, call the data dissector instead. */
                call_data_dissector(tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
            break;
            }/* switch */
        }
        CATCH_ALL {
            /*
             * Someone encountered an error while dissecting the payload. But
             * we haven't yet finished processing all of our layer. Catch and
             * display the exception, then fall-through to finish displaying
             * the FCS (which we display last so the frame is ordered correctly
             * in the tree).
             */
            show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
            pinfo->current_proto = saved_proto;
        }
        ENDTRY;
    }
    return tvb_captured_length(tvb);
}

#if 0
/**
 * Dissect the FCS at the end of the frame.
 * That is only displayed if the included length of the tvb encompasses it.
 *
 * @param tvb the MiWi P2P Star frame tvb
 * @param ieee802154_tree the MiWi P2P Star protocol tree
 * @param fcs_len length of the FCS field
 * @param fcs_ok set to false to indicate FCS verification failed
 */
static void
miwi_dissect_fcs(tvbuff_t *tvb, proto_tree *ieee802154_tree, unsigned fcs_len, bool fcs_ok)
{
    proto_item *ti;
    /* The FCS should be the last bytes of the reported packet. */
    unsigned offset = tvb_reported_length(tvb)-fcs_len;
    /* Dissect the FCS only if it exists (captures which don't or can't get the
     * FCS will simply truncate the packet to omit it, but should still set the
     * reported length to cover the original packet length), so if the snapshot
     * is too short for an FCS don't make a fuss.
     */
    if(ieee802154_tree){
        if(fcs_len == 2){
            uint16_t    fcs = tvb_get_letohs(tvb, offset);

            ti = proto_tree_add_uint(ieee802154_tree, hf_miwi_fcs, tvb, offset, 2, fcs);
            if(fcs_ok){
                proto_item_append_text(ti, " (Correct)");
            }
            else{
                proto_item_append_text(ti, " (Incorrect, expected FCS=0x%04x)", miwi_crc_tvb(tvb, offset));
            }
            /* To Help with filtering, add the fcs_ok field to the tree.  */
            ti = proto_tree_add_boolean(ieee802154_tree, hf_miwi_fcs_ok, tvb, offset, 2, (uint32_t) fcs_ok);
            proto_item_set_hidden(ti);
        }
    }
}/* miwi_dissect_fcs */
#endif

/**
 * MiWi P2P Star packet dissection routine for Wireshark.
 *
 * This function extracts all the information first before displaying.
 * If payload exists, that portion will be passed into another dissector
 * for further processing.
 *
 * This is called after the individual dissect_p2pstar* functions
 * have been called to determine what sort of FCS is present, if any.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param fcs_len length of the FCS field
 */
static void
dissect_miwi_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned fcs_len)
{
    proto_tree *miwi_tree;
    miwi_packet *packet;
    //bool fcs_present;
    bool fcs_ok;
    tvbuff_t* no_fcs_tvb;
    unsigned  offset = 0;

    if(fcs_len != 0){
        /*
         * Well, this packet should, in theory, have an FCS or CC24xx
         * metadata.
         * Do we have the entire packet, and does it have enough data for
         * the FCS/metadata?
         */
        unsigned reported_len = tvb_reported_length(tvb);

        if(reported_len < fcs_len){
            /*
             * The packet is claimed not to even have enough data
             * for the FCS/metadata.  Pretend it doesn't have one.
             */
            no_fcs_tvb = tvb;
            //fcs_present = false;
            fcs_ok = true;  // assume OK if not present
        } else{
            /*
             * The packet is claimed to have enough data for the
             * FCS/metadata.
             * Slice it off from the reported length.
             */
            reported_len -= fcs_len;
            no_fcs_tvb = tvb_new_subset_length(tvb, 0, reported_len);

            /*
             * Is the FCS/metadata present in the captured data?
             * reported_len is now the length of the packet without the
             * FCS/metadata, so the FCS/metadata begins at an offset of
             * reported_len.
             */
            if(tvb_bytes_exist(tvb, reported_len, fcs_len)){
                /*
                 * Yes.  Check whether the FCS was OK.
                 *
                 * If we have an FCS, check it.
                 * If we have metadata, check its "FCS OK" flag.
                 */
                //fcs_present = true;
                fcs_ok = is_fcs_ok(tvb, fcs_len);
            } else{
                /*
                 * No.
                 *
                 * Either 1) this means that there was a snapshot length
                 * in effect when the capture was done, and that sliced
                 * some or all of the FCS/metadata off or 2) this is a
                 * capture with no FCS/metadata, using the same link-layer
                 * header type value as captures with the FCS/metadata,
                 * and indicating the lack of the FCS/metadata by having
                 * the captured length be the length of the packet minus
                 * the length of the FCS/metadata and the actual length
                 * being the length of the packet including the FCS/metadata,
                 * rather than by using the "no FCS" link-layer header type.
                 *
                 * We could try to distinguish between them by checking
                 * for a captured length that's exactly fcs_len bytes
                 * less than the actual length.  That would allow us to
                 * report packets that are cut short just before, or in
                 * the middle of, the FCS as having been cut short by the
                 * snapshot length.
                 *
                 * However, we can't distinguish between a packet that
                 * happened to be cut fcs_len bytes short due to a
                 * snapshot length being in effect when the capture was
                 * done and a packet that *wasn't* cut short by a snapshot
                 * length but that doesn't include the FCS/metadata.
                 * Let's hope that rarely happens.
                 */
                //fcs_present = false;
                fcs_ok = true;  // assume OK if not present
            }
        }
    } else{
        no_fcs_tvb = tvb;
        //fcs_present = false;
        fcs_ok = true;  // assume OK if not present
    }

    unsigned mhr_len = miwi_dissect_header(no_fcs_tvb, pinfo, tree, &miwi_tree, &packet);
    offset = mhr_len;
    if(!mhr_len || tvb_reported_length_remaining(no_fcs_tvb, mhr_len) < 0 ){
        return;
    }

        if(packet->frame_type == IEEE802154_FCF_DATA){
            if((!fcs_ok && miwi_fcs_ok)){
                call_data_dissector(tvb, pinfo, tree);
            }
        } else{
            miwi_dissect_frame_payload(tvb, pinfo, miwi_tree, packet, fcs_ok, &offset);
        }
}

/**
 * Dissector for MiWi P2P Star packet with an FCS containing a 16/32-bit
 * CRC value at the end.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_miwi_p2pstar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    unsigned fcs_len;

    /* Set the default FCS length based on the FCS type in the configuration */
  //  fcs_len = miwi_fcs_type_len(miwi_fcs_type);
   // unsigned offset = 0;
    proto_tree              *miwi_tree = NULL;
    proto_item              *proto_root = NULL;
   // miwi_packet      *packet = wmem_new0(wmem_packet_scope(), miwi_packet);

    /* Set the default FCS length based on the FCS type in the configuration */
    fcs_len = miwi_fcs_type_len(miwi_fcs_type);

    /* Call the common dissector. */
   // dissect_miwi_common1(tvb, pinfo, tree);//, fcs_len);
    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_miwi_p2pstar, tvb, 0, tvb_captured_length(tvb), "MiWi P2PStar Protocol");
        miwi_tree = proto_item_add_subtree(proto_root, ett_miwi_p2pstar);
    }
    /*Enter name of protocol to info field*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MiWi P2PStar");
    /* Call the common dissector. */
    dissect_miwi_common(tvb, pinfo, miwi_tree, fcs_len);
    return tvb_captured_length(tvb);
}/* dissect_miwi_p2pstar */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_miwimesh_heur
 *  DESCRIPTION
 *      Heuristic interpreter for the Lightweight Mesh.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      Boolean value, whether it handles the packet or not.
 *---------------------------------------------------------------
 */
static bool
dissect_miwi_p2pstar_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
#if 0
    uint8_t endpt, srcep, dstep;

    /* 1) first byte must have bits 0000xxxx */
    if(tvb_get_uint8(tvb, 0) & LWM_FCF_RESERVED)
        return (false);

    /* The header should be at least long enough for the base header. */
    if (tvb_reported_length(tvb) < LWM_HEADER_BASE_LEN)
        return (false);

    /* The endpoints should either both be zero, or both non-zero. */
    endpt = tvb_get_uint8(tvb, 6);
    srcep = (endpt & LWM_SRC_ENDP_MASK) >> LWM_SRC_ENDP_OFFSET;
    dstep = (endpt & LWM_DST_ENDP_MASK) >> LWM_DST_ENDP_OFFSET;
    if ((srcep == 0) && (dstep != 0))
        return (false);
    if ((srcep != 0) && (dstep == 0))
        return (false);
#endif
    dissect_miwi_p2pstar(tvb, pinfo, tree, data);
    return (true);
} /* dissect_lwm_heur */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_miwi_p2pstar
 *  DESCRIPTION
 *      MiWi P2P Star protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_miwi_p2pstar(void)
{

    static hf_register_info hf[] = {

        { &hf_miwi_frame_length,
        { "Frame Length", "miwi_p2pstar.frame_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Frame Length as reported from lower layer", HFILL }},

        { &hf_miwi_fcf,
        { "Frame Control Field", "miwi_p2pstar.fcf", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_miwi_fcf_frame_type,
        { "Frame Type", "miwi_p2pstar.type", FT_UINT16, BASE_HEX, VALS(miwi_mac_frame_types),
            MIWI_MAC_FCF_FRAME_TYPE, NULL, HFILL }},

        { &hf_miwi_fcf_security_enabled,
        { "Security Enabled", "miwi_p2pstar.security_enable", FT_BOOLEAN, 16, NULL, MIWI_MAC_FCF_SECURITY_EN,
            "Whether security operations are performed at the MAC layer or not.", HFILL }},

        { &hf_miwi_fcf_frame_pending,
        { "Frame Pending", "miwi_p2pstar.pending", FT_BOOLEAN, 16, NULL, MIWI_MAC_FCF_FRAME_PENDING,
            "Indication of additional packets waiting to be transferred from the source device.", HFILL }},

        { &hf_miwi_fcf_ack_req,
        { "Acknowledge Request", "miwi_p2pstar.ack_request", FT_BOOLEAN, 16, NULL, MIWI_MAC_FCF_ACK_REQUEST,
            "Whether the sender of this packet requests acknowledgment or not.", HFILL }},

        { &hf_miwi_fcf_panid_comp,
        { "PAN ID Compression", "miwi_p2pstar.pan_id_compression", FT_BOOLEAN, 16, NULL, MIWI_MAC_FCF_PANID_COMP,
            "Whether this packet contains the PAN ID or not.", HFILL }},

        { &hf_miwi_fcf_reserved,
        { "Reserved", "miwi_p2pstar.fcf.reserved", FT_UINT16, BASE_HEX, NULL, MIWI_MAC_FCF_RESERVED,
            NULL, HFILL }},

        { &hf_miwi_seq,
        { "Sequence Number", "miwi_p2pstar.seq_no", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_fcf_dest_addr_mode,
        { "Destination Addressing Mode", "miwi_p2pstar.dst_addr_mode", FT_UINT16, BASE_HEX, VALS(miwi_addr_modes),
            MIWI_MAC_FCF_DEST_ADDR_MODE, NULL, HFILL }},

        { &hf_miwi_fcf_src_addr_mode,
        { "Source Addressing Mode", "miwi_p2pstar.src_addr_mode", FT_UINT16, BASE_HEX, VALS(miwi_addr_modes),
            MIWI_MAC_FCF_SRC_ADDR_MODE, NULL, HFILL }},

        { &hf_miwi_fcf_frame_version,
        { "Frame Version", "miwi_p2pstar.version", FT_UINT16, BASE_DEC, VALS(miwi_frame_versions),
            MIWI_MAC_FCF_FRAME_VERSION, NULL, HFILL }},

        { &hf_miwi_dst_panid,
        { "Destination PAN", "miwi_p2pstar.dst_pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_short_dst_addr,
        { "Destination", "miwi_p2pstar.dst16", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_ext_dst_addr,
        { "Destination", "miwi_p2pstar.dst64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_src_panid,
        { "Source PAN", "miwi_p2pstar.src_pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_short_src_addr,
        { "Source", "miwi_p2pstar.src16", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_ext_src_addr,
        { "Extended Source", "miwi_p2pstar.src64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_addr16,
        { "Address", "miwi_p2pstar.addr16", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_addr64,
        { "Extended Address", "miwi_p2pstar.addr64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_src64_origin,
        { "Origin", "miwi_p2pstar.src64.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

#if 0
        { &hf_miwi_fcs,
        { "FCS", "miwi_p2pstar.fcs", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_fcs_ok,
        { "FCS Valid", "miwi_p2pstar.fcs_ok", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
#endif

        { &hf_miwi_cmd_id,
        { "Command Identifier", "miwi_p2pstar.cmd", FT_UINT8, BASE_HEX, VALS(miwi_p2pstar_cmd_names), 0x0,
            NULL, HFILL }},

        { &hf_miwi_cap_info,
        { "Capability Information", "miwi_p2pstar.cap_info", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_cap_info_rcv_on_idle,
        { "Receiver On When Idle", "miwi_p2pstar.recv_on_when_idle", FT_BOOLEAN, 16, NULL, MIWI_CAP_INFO_RCV_ON_IDLE,
            NULL, HFILL }},

        { &hf_miwi_cap_info_rqst_data_on_wp,
        { "Request Data On Wake-up", "miwi_p2pstar.req_data_on_wakeup", FT_BOOLEAN, 16, NULL, MIWI_CAP_INFO_REQ_DATA_ON_WP,
            NULL, HFILL }},

        { &hf_miwi_cap_info_need_time_sync,
        { "Need Time Synchronization", "miwi_p2pstar.need_time_sync", FT_BOOLEAN, 16, NULL, MIWI_CAP_INFO_NEED_TIME_SYNC,
            NULL, HFILL }},

        { &hf_miwi_cap_info_security_cap,
        { "Security Capable", "miwi_p2pstar.security_capable", FT_BOOLEAN, 16, NULL, MIWI_CAP_INFO_SECURITY_CAP,
            NULL, HFILL }},

        { &hf_miwi_cap_info_reserved,
        { "Reserved", "miwi_p2pstar.cap_info.reserved", FT_UINT16, BASE_HEX, NULL, MIWI_CAP_INFO_RESERVED,
            NULL, HFILL }},

        { &hf_miwi_oper_chan,
        { "Connection Request Operating Channel", "miwi_p2pstar.con_req_chan", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_conn_res_status,
        { "Connection Response Status", "miwi_p2pstar.con_res_status", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_current_op_channel,
        { "Channel Hop Current Operating Channel", "miwi_p2pstar.hop_op_chan", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_dst_channel_to_jump_to,
        { "Destination Channel to Jump to", "miwi_p2pstar.chan_jump_to", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_conn_rmv_res_status,
        { "Connection Removal Response Status", "miwi_p2pstar.con_rmvl_res_status", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_fwd_pkt_dst_addr,
        { "Forward Packet Command Destination Address", "miwi_p2pstar.fwd_pkt_dst-addr", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_miwi_conn_tbl_size,
        { "Connection Table Size", "miwi_p2pstar.conn_tbl_size", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        };


    /* Subtrees */
    static int *ett[] = {
        &ett_miwi_p2pstar,
        &ett_miwi_p2pstar_fcf,
        &ett_miwi_p2pstar_cmd_tree,
        &ett_miwi_p2pstar_cap_info,
        &ett_miwi_fcs,
    };

    static ei_register_info ei[] = {
        //{ &ei_miwi_empty_payload,     { "miwi_p2pstar.empty_payload",   PI_MALFORMED,      PI_ERROR, "Empty MiWi Payload!", EXPFILL }},
        { &ei_miwi_frame_ver,   { "miwi_p2pstar.frame_version_error", PI_COMMENTS_GROUP, PI_NOTE,  "Source address can not be broadcast address !", EXPFILL }},
        { &ei_miwi_dst, { "miwi_p2pstar.dst_addr_error",     PI_COMMENTS_GROUP, PI_WARN,  "destination address Error ", EXPFILL }},
        { &ei_miwi_src, { "miwi_p2pstar.src_addr_error",     PI_COMMENTS_GROUP, PI_WARN,  "Source address Error ", EXPFILL }},
        { &ei_miwi_invalid_addressing, { "miwi_p2pstar.invalid_addr_error", PI_PROTOCOL,   PI_NOTE,  "Invalid Address Error", EXPFILL }},
        { &ei_miwi_invalid_panid_compression, { "miwi_p2pstar.invalid_panid_comp_error", PI_PROTOCOL,   PI_WARN,  "Panid compression error", EXPFILL }},
        { &ei_miwi_invalid_panid_compression2, { "miwi_p2pstar.invalid_panid_comp2_error", PI_PROTOCOL,   PI_WARN,  "Panid2 compression error", EXPFILL }},
//        { &ei_miwi_fcs, { "miwi_p2pstar.fcs.bad", PI_CHECKSUM, PI_WARN, "Bad FCS", EXPFILL }},
    };

    static const enum_val_t fcs_type_vals[] = {
        {"16",     "CRC -16 BIT",          MIWI_P2PSTAR_FCS_16_BIT},
        {NULL, NULL, -1}
    };

    static build_valid_func     miwi_da_build_value[1] = {miwi_da_value};
    static decode_as_value_t    miwi_da_values = {miwi_da_prompt, 1, miwi_da_build_value};
    static decode_as_t         miwi_da = {
        IEEE802154_PROTOABBREV_WPAN, IEEE802154_PROTOABBREV_WPAN_PANID,
        1, 0, &miwi_da_values, NULL, NULL,
        decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change,NULL
    };

    module_t *miwi_p2pstar_module;
    expert_module_t* expert_miwi_p2pstar;

    /* Register the protocol name and description */
    proto_miwi_p2pstar = proto_register_protocol("MiWi P2P Star (v6.4)", "MiWi_P2PStar", "miwi_p2pstar");

    /* Required function calls to register the header fields and subtree used */
    proto_register_field_array(proto_miwi_p2pstar, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_miwi_p2pstar = expert_register_protocol(proto_miwi_p2pstar);
    expert_register_field_array(expert_miwi_p2pstar, ei, array_length(ei));

    miwi_short_address_type = address_type_dissector_register("AT_IEEE_802_15_4_SHORT", "IEEE 802.15.4 16-bit short address",                    miwi_short_address_to_str, miwi_short_address_str_len, NULL, NULL, miwi_short_address_len, NULL, NULL);

    /* add a user preference to set the 802.15.4 ethertype */
    miwi_p2pstar_module = prefs_register_protocol(proto_miwi_p2pstar,
                                   proto_reg_handoff_miwi_p2pstar);
    prefs_register_uint_preference(miwi_p2pstar_module, "miwi_ethertype",
                                   "802.15.4 Ethertype (in hex)",
                                   "(Hexadecimal) Ethertype used to indicate IEEE 802.15.4 frame.",
                                   16, &miwi_ethertype);
    prefs_register_enum_preference(miwi_p2pstar_module, "fcs_format",
                                   "FCS format",
                                   "The FCS format in the captured payload",
                                   &miwi_fcs_type, fcs_type_vals, false);
    prefs_register_bool_preference(miwi_p2pstar_module, "miwi_fcs_ok",
                                   "Dissect only good FCS",
                                   "Dissect payload only if FCS is valid.",
                                   &miwi_fcs_ok);
    prefs_register_bool_preference(miwi_p2pstar_module, "miwi_ack_tracking",
                                   "Enable ACK tracking",
                                   "Match frames with ACK request to ACK packets",
                                   &miwi_ack_tracking);

    miwi_p2pstar_handle = register_dissector("miwi_p2pstar", dissect_miwi_p2pstar, proto_miwi_p2pstar);
    /* Register a Decode-As handler */
    register_decode_as(&miwi_da);
}/* proto_register_miwi_p2pstar */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_miwi_p2pstar
 *  DESCRIPTION
 *      Registers the miwi_p2pstar dissector with Wireshark.
 *      Will be called during Wireshark startup.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_miwi_p2pstar(void)
{
#if 0
    static bool                prefs_initialized = false;
    static unsigned int        old_miwi_ethertype;

    if(!prefs_initialized){
        dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE802_15_4, miwi_p2pstar_handle);

        prefs_initialized = true;
    } else{
        dissector_delete_uint("ethertype", old_miwi_ethertype, miwi_p2pstar_handle);
    }

    old_miwi_ethertype = miwi_ethertype;

    /* Register dissector handles. */
    dissector_add_uint("ethertype", miwi_ethertype, miwi_p2pstar_handle);
#endif
    /* Register our dissector with IEEE 802.15.4 */
    dissector_add_for_decode_as(IEEE802154_PROTOABBREV_WPAN_PANID, miwi_p2pstar_handle);
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_miwi_p2pstar_heur, "Miwi P2PStar over IEEE 802.15.4", "miwip2pstar", proto_miwi_p2pstar, HEURISTIC_DISABLE);
}/* proto_reg_handoff_miwi_p2pstar */

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
