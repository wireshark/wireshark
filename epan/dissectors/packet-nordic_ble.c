/* packet-nordic_ble.c
 * Routines for nordic ble sniffer dissection
 * Copyright 2016, Nordic Semiconductor
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wiretap/pcap-encap.h>

/* Size of various UART Packet header fields */
#define BEEF_LENGTH_BYTES                   (2)
#define HEADER_LEN_LENGTH_BYTES             (1)
#define PACKET_LEN_LENGTH_BYTES             (1)
#define PROTOVER_LENGTH_BYTES               (1)
#define COUNTER_LENGTH_BYTES                (2)
#define ID_LENGTH_BYTES                     (1)

#define BLE_HEADER_LEN_LENGTH_BYTES         (1)
#define FLAGS_LENGTH_BYTES                  (1)
#define CHANNEL_LENGTH_BYTES                (1)
#define RSSI_LENGTH_BYTES                   (1)
#define EVENT_COUNTER_LENGTH_BYTES          (2)
#define TIMESTAMP_LENGTH_BYTES              (4)


#define BOARD_ID_INDEX                      (0)
#define BOARD_ID_LENGTH                     (1)

/* Define the index of the various fields in the UART_PACKET header */
#define UART_PACKET_HEADER_LEN_INDEX        (0)
#define UART_PACKET_PACKET_LEN_INDEX        (UART_PACKET_HEADER_LEN_INDEX       + HEADER_LEN_LENGTH_BYTES)
#define UART_PACKET_PROTOVER_INDEX          (UART_PACKET_PACKET_LEN_INDEX       + PACKET_LEN_LENGTH_BYTES)
#define UART_PACKET_COUNTER_INDEX           (UART_PACKET_PROTOVER_INDEX         + PROTOVER_LENGTH_BYTES)
#define UART_PACKET_ID_INDEX                (UART_PACKET_COUNTER_INDEX          + COUNTER_LENGTH_BYTES)

#define UART_PACKET_BLE_HEADER_LEN_INDEX    (UART_PACKET_ID_INDEX               + ID_LENGTH_BYTES)
#define UART_PACKET_FLAGS_INDEX             (UART_PACKET_BLE_HEADER_LEN_INDEX   + BLE_HEADER_LEN_LENGTH_BYTES)
#define UART_PACKET_CHANNEL_INDEX           (UART_PACKET_FLAGS_INDEX            + FLAGS_LENGTH_BYTES)
#define UART_PACKET_RSSI_INDEX              (UART_PACKET_CHANNEL_INDEX          + CHANNEL_LENGTH_BYTES)
#define UART_PACKET_EVENT_COUNTER_INDEX     (UART_PACKET_RSSI_INDEX             + RSSI_LENGTH_BYTES)
#define UART_PACKET_TIMESTAMP_INDEX         (UART_PACKET_EVENT_COUNTER_INDEX    + EVENT_COUNTER_LENGTH_BYTES)
#define UART_PACKET_ACCESS_ADDRESS_INDEX    (UART_PACKET_TIMESTAMP_INDEX        + TIMESTAMP_LENGTH_BYTES)

#define INDEX_OF_LENGTH_FIELD_IN_BLE_PACKET (5)
#define INDEX_OF_LENGTH_FIELD_IN_EVENT_PACKET (UART_PACKET_TIMESTAMP_INDEX + TIMESTAMP_LENGTH_BYTES + INDEX_OF_LENGTH_FIELD_IN_BLE_PACKET)

#define UART_HEADER_LEN                     (6)
#define BLE_HEADER_LEN                      (10)
#define PROTOVER                            (1)

#define US_PER_BYTE                                         (8)
#define NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH            (10) /* Preamble (1) + AA (4) + Header (1) + Length (1) + CRC (3)   = 10 Bytes */
#define BLE_METADATA_TRANFER_TIME_US                        (US_PER_BYTE * NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH)


#define UART_HEADER_LENGTH (UART_PACKET_ACCESS_ADDRESS_INDEX)
#define BLE_MIN_PACKET_LENGTH (NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH)
#define BLE_MAX_PACKET_LENGTH (50)
#define MIN_TOTAL_LENGTH (BLE_HEADER_LEN + BLE_MIN_PACKET_LENGTH)
#define MAX_TOTAL_LENGTH (UART_HEADER_LENGTH + BLE_MAX_PACKET_LENGTH)
#define BLE_LENGTH_POS (UART_HEADER_LENGTH + 5)

/*
* LEGACY DEFINES
* Defines used in the 0.9.7 version of the dissector
* Used to dissect packages with the old format
*/
#define _0_9_7_nordic_ble_MIN_LENGTH (8)
#define _0_9_7_UART_HEADER_LENGTH (17)
#define _0_9_7_BLE_EMPTY_PACKET_LENGTH (9)
#define _0_9_7_BLE_MAX_PACKET_LENGTH (50)
#define _0_9_7_MIN_TOTAL_LENGTH (_0_9_7_UART_HEADER_LENGTH + _0_9_7_BLE_EMPTY_PACKET_LENGTH)
#define _0_9_7_MAX_TOTAL_LENGTH (_0_9_7_UART_HEADER_LENGTH + _0_9_7_BLE_MAX_PACKET_LENGTH)
#define _0_9_7_BLE_LENGTH_POS (_0_9_7_UART_HEADER_LENGTH + 5)

#define _0_9_7_ID_POS               (2)
#define _0_9_7_PACKET_COUNTER_POS   (3)
#define _0_9_7_LENGTH_POS           (7)
#define _0_9_7_FLAGS_POS            (8)
#define _0_9_7_CHANNEL_POS          (9)
#define _0_9_7_RSSI_POS             (10)
#define _0_9_7_EVENT_COUNTER_POS    (11)
#define _0_9_7_TIMESTAMP_POS        (13)
#define _0_9_7_US_PER_BYTE          (8)
#define _0_9_7_NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH (10) /* Preamble (1) + AA (4) + Header (1) + Length (1) + CRC (3) = 10 Bytes */
#define _0_9_7_BLE_METADATA_TRANFER_TIME_US (_0_9_7_US_PER_BYTE * _0_9_7_NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH)

void proto_reg_handoff_nordic_ble(void);
void proto_register_nordic_ble(void);

/* Initialize the protocol and registered fields */
static int proto_nordic_ble = -1;

/*static guint udp_port = 32954;*/
/*static guint user_dlt_num = 55;*/ /* corresponds to pcap network type value 157, user type 10. */


static gboolean legacy_mode = FALSE;


#ifndef TRANSPARENT
/* Initialize the subtree pointers */
static gint ett_nordic_ble = -1;
static gint ett_flags = -1;

/* Declared static as they need to be transferred between mode handlers and main dissector */
static gboolean g_bad_length, g_bad_mic;

static int hf_nordic_ble_board_id = -1;
static int hf_nordic_ble_header_length = -1;
static int hf_nordic_ble_payload_length = -1;
static int hf_nordic_ble_packet_counter = -1;
static int hf_nordic_ble_flags = -1;
static int hf_nordic_ble_crcok = -1;
static int hf_nordic_ble_encrypted = -1;
static int hf_nordic_ble_micok = -1;
static int hf_nordic_ble_direction = -1;
static int hf_nordic_ble_channel = -1;
static int hf_nordic_ble_rssi = -1;
static int hf_nordic_ble_event_counter = -1;
static int hf_nordic_ble_delta_time = -1;
static int hf_nordic_ble_delta_time_ss = -1;


static expert_field ei_nordic_ble_bad_crc = EI_INIT;
static expert_field ei_nordic_ble_bad_mic = EI_INIT;
static expert_field ei_nordic_ble_bad_length = EI_INIT;

/*static guint8 src_addr_to_use[6] = { 0,0,0,0,0,0 }; */
/*static guint8 src_addr_zero[6] = { 0,0,0,0,0,0 };*/

static const true_false_string direction_tfs =
{
    "Master -> Slave",
    "Slave -> Master"
};
static const true_false_string ok_incorrect =
{
    "OK",
    "Incorrect"
};

#endif /* TRANSPARENT */
#if 0
/* functions hiding versioning in dissectors */
static guint8
get_id_index(void)
{
    return (legacy_mode ? _0_9_7_ID_POS : UART_PACKET_ID_INDEX);
}
#endif
static guint8
get_pc_index(void)
{
    return (legacy_mode ? _0_9_7_PACKET_COUNTER_POS : UART_PACKET_COUNTER_INDEX);
}

static guint8
get_flags_index(void)
{
    return (legacy_mode ? _0_9_7_FLAGS_POS : UART_PACKET_FLAGS_INDEX);
}

static guint8
get_ch_index(void)
{
    return (legacy_mode ? _0_9_7_CHANNEL_POS : UART_PACKET_CHANNEL_INDEX);
}

static guint8
get_rssi_index(void)
{
    return (legacy_mode ? _0_9_7_RSSI_POS : UART_PACKET_RSSI_INDEX);
}

static guint8
get_ec_index(void)
{
    return (legacy_mode ? _0_9_7_EVENT_COUNTER_POS : UART_PACKET_EVENT_COUNTER_INDEX);
}

static guint8
get_td_index(void)
{
    return (legacy_mode ? _0_9_7_TIMESTAMP_POS : UART_PACKET_TIMESTAMP_INDEX);
}

static guint8
get_header_length(void)
{
    return (legacy_mode ? _0_9_7_UART_HEADER_LENGTH : UART_HEADER_LENGTH);
}

static guint8
get_packet_length_index(void)
{
    return (legacy_mode ? _0_9_7_LENGTH_POS : UART_PACKET_PACKET_LEN_INDEX);
}

static guint8
get_total_len_min(void)
{
    return (legacy_mode ? _0_9_7_MIN_TOTAL_LENGTH : MIN_TOTAL_LENGTH);
}

static guint8
get_total_len_max(void)
{
    return (legacy_mode ? _0_9_7_MAX_TOTAL_LENGTH : MAX_TOTAL_LENGTH);
}

static guint8
get_metadata_transfer_time(void)
{
    return (legacy_mode ? _0_9_7_BLE_METADATA_TRANFER_TIME_US : BLE_METADATA_TRANFER_TIME_US);
}

static guint8
get_us_per_byte(void)
{
    return (legacy_mode ? _0_9_7_US_PER_BYTE : US_PER_BYTE);
}


static guint32 adv_aa = 0x8e89bed6;


/* next dissector */
static dissector_handle_t btle_dissector_handle = NULL;
static dissector_handle_t debug_handle = NULL;

#if 0
static gboolean
array_equal(const void* buf1, const void* buf2, int len)
{
    gboolean return_value = FALSE;
    int i;
    for (i = 0; i < len; i++) {
        if (((guint8*)buf1)[i] == ((guint8*)buf2)[i]) {
            return_value = TRUE;
        }
    }
    return return_value;
}

static void array_copy(void* dst, const void* src, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        ((guint8*)dst)[i] = ((guint8*)src)[i];
    }
}
#endif

static tvbuff_t *
dissect_board_id_and_strip_it_from_tvb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_nordic_ble_board_id, tvb, BOARD_ID_INDEX, BOARD_ID_LENGTH, ENC_BIG_ENDIAN);
    return tvb_new_subset(tvb, BOARD_ID_LENGTH, -1, -1);
}

static gboolean
dissect_lengths(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 hlen, plen;
    proto_item* item;
    gboolean bad_length = FALSE;

    if (legacy_mode) {
        hlen = tvb_get_guint8(tvb, _0_9_7_LENGTH_POS);
        plen = _0_9_7_nordic_ble_MIN_LENGTH;
    }
    else {
        hlen = tvb_get_guint8(tvb, UART_PACKET_HEADER_LEN_INDEX);
        plen = tvb_get_guint8(tvb, UART_PACKET_PACKET_LEN_INDEX);
    }

    if ((hlen + plen) != tvb_captured_length(tvb)) {
        if (!legacy_mode) {
            proto_tree_add_item(tree, hf_nordic_ble_header_length, tvb, UART_PACKET_HEADER_LEN_INDEX, 1, ENC_BIG_ENDIAN);
        }

        item = proto_tree_add_item(tree, hf_nordic_ble_payload_length, tvb, get_packet_length_index(), 1, ENC_BIG_ENDIAN);

        expert_add_info(pinfo, item, &ei_nordic_ble_bad_length);
        bad_length = TRUE;
    }
    else if ((hlen + plen) < get_total_len_min()) {
        if (!legacy_mode) {
            proto_tree_add_item(tree, hf_nordic_ble_header_length, tvb, UART_PACKET_HEADER_LEN_INDEX, 1, ENC_BIG_ENDIAN);
        }

        item = proto_tree_add_item(tree, hf_nordic_ble_payload_length, tvb, get_packet_length_index(), 1, ENC_BIG_ENDIAN);

        expert_add_info(pinfo, item, &ei_nordic_ble_bad_length);

        bad_length = TRUE;
    }
    else if ((hlen + plen) > get_total_len_max()) {
        if (!legacy_mode) {
            proto_tree_add_item(tree, hf_nordic_ble_header_length, tvb, UART_PACKET_HEADER_LEN_INDEX, 1, ENC_BIG_ENDIAN);
        }

        item = proto_tree_add_item(tree, hf_nordic_ble_payload_length, tvb, get_packet_length_index(), 1, ENC_BIG_ENDIAN);

        expert_add_info(pinfo, item, &ei_nordic_ble_bad_length);
        bad_length = TRUE;
    }
    return bad_length;
}


static void
dissect_packet_counter(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_nordic_ble_packet_counter, tvb, get_pc_index(), 2, ENC_LITTLE_ENDIAN);
}

#if 0
static void
dissect_id(tvbuff_t *tvb, proto_tree *tree)
{
    guint8 id;
    id = tvb_get_guint8(tvb, get_id_index());
}
#endif

static gboolean
dissect_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 flags;
    gboolean crcok, dir, encrypted, micok;
    /*gboolean bad_length = FALSE;*/
    gboolean bad_mic = FALSE;
    proto_item /**flags_item,*/ *item;

    flags = tvb_get_guint8(tvb, get_flags_index());
    crcok = !!(flags & 1);
    dir = !!(flags & 2);
    encrypted = !!(flags & 4);
    micok = !!(flags & 8);

    if (dir) {
        set_address(&pinfo->src, AT_STRINGZ, 7, "Master");
        set_address(&pinfo->dst, AT_STRINGZ, 6, "Slave");
    }
    else {
        set_address(&pinfo->src, AT_STRINGZ, 6, "Slave");
        set_address(&pinfo->dst, AT_STRINGZ, 7, "Master");
    }


    proto_tree_add_item(tree, hf_nordic_ble_flags, tvb, get_flags_index(), 1, ENC_BIG_ENDIAN);
    /*flags_tree = proto_item_add_subtree(flags_item, ett_flags); */
    if (encrypted) /* if encrypted, add MIC status */
    {
        item = proto_tree_add_bits_item(tree, hf_nordic_ble_micok, tvb, get_flags_index() * 8 + 4, 1, ENC_LITTLE_ENDIAN);
        if (!micok) {
            /* MIC is bad */
            expert_add_info(pinfo, item, &ei_nordic_ble_bad_mic);
            bad_mic = TRUE;
        }
    }
    proto_tree_add_bits_item(tree, hf_nordic_ble_encrypted, tvb, get_flags_index() * 8 + 5, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_bits_item(tree, hf_nordic_ble_direction, tvb, get_flags_index() * 8 + 6, 1, ENC_LITTLE_ENDIAN);
    item = proto_tree_add_bits_item(tree, hf_nordic_ble_crcok, tvb, get_flags_index() * 8 + 7, 1, ENC_LITTLE_ENDIAN);
    if (!crcok) {
        /* CRC is bad */
        expert_add_info(pinfo, item, &ei_nordic_ble_bad_crc);
    }
    return bad_mic;
}

static void
dissect_channel(tvbuff_t *tvb, proto_tree *tree)
{
    /*guint8 channel; */
    /*channel = tvb_get_guint8(tvb, get_ch_index()); */
    proto_tree_add_item(tree, hf_nordic_ble_channel, tvb, get_ch_index(), 1, ENC_BIG_ENDIAN);
}

static void
dissect_rssi(tvbuff_t *tvb, proto_tree *tree)
{
    gint32 rssi;
    rssi = (-1)*((gint32)tvb_get_guint8(tvb, get_rssi_index()));
    proto_tree_add_int(tree, hf_nordic_ble_rssi, tvb, get_rssi_index(), 1, rssi);
}

static void
dissect_event_counter(tvbuff_t *tvb, proto_tree *tree)
{
    guint32 aa;
    aa = tvb_get_letohl(tvb, get_header_length());
    if (aa != adv_aa) {
        proto_tree_add_item(tree, hf_nordic_ble_event_counter, tvb, get_ec_index(), 2, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_ble_delta_time(tvbuff_t *tvb, proto_tree *tree)
{
    static guint8 previous_ble_packet_length = 0;
    guint32 delta_time, delta_time_ss;

    /* end - start */
    delta_time = (guint32)tvb_get_letohl(tvb, get_td_index());
    proto_tree_add_item(tree, hf_nordic_ble_delta_time, tvb, get_td_index(), 4, ENC_LITTLE_ENDIAN);

    /* start - start */
    delta_time_ss = get_metadata_transfer_time() + (get_us_per_byte() * previous_ble_packet_length) + delta_time;
    proto_tree_add_uint(tree, hf_nordic_ble_delta_time_ss, tvb, get_td_index(), 4, delta_time_ss);

    previous_ble_packet_length = tvb_get_guint8(tvb, get_packet_length_index());
}


/*
* Specific for 1.0.0+ :
*/
#if 0
static void
dissect_ble_hlen(tvbuff_t *tvb, proto_tree *tree)
{
    guint8 ble_hlen;
    ble_hlen = tvb_get_guint8(tvb, UART_PACKET_BLE_HEADER_LEN_INDEX);

}

static void
dissect_protover(tvbuff_t *tvb, proto_tree *tree)
{
    guint8 protover;
    protover = tvb_get_guint8(tvb, UART_PACKET_PROTOVER_INDEX);

}
#endif


static guint32
is_0_9_7_packet(tvbuff_t *tvb)
{
    /* legacy packets started with 0xBEEF */
    if (tvb_get_guint8(tvb, 0) == 0xBE &&
        tvb_get_guint8(tvb, 1) == 0xEF) {
        return 1;
    }
    else {
        return 0;
    }
}


static void
dissect_header_0_9_7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *nordic_ble_tree;/*, *flags_tree;*/
   /* gboolean bad_crc = FALSE;*/


    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_nordic_ble, tvb, 0, -1, ENC_NA);
    nordic_ble_tree = proto_item_add_subtree(ti, ett_nordic_ble);

    pinfo->p2p_dir = P2P_DIR_RECV;

    /*** PROTOCOL TREE ***/

    dissect_packet_counter(tvb, nordic_ble_tree);
    g_bad_mic = dissect_flags(tvb, pinfo, nordic_ble_tree);
    dissect_channel(tvb, nordic_ble_tree);
    dissect_rssi(tvb, nordic_ble_tree);
    dissect_event_counter(tvb, nordic_ble_tree);
    g_bad_length = dissect_lengths(tvb, pinfo, nordic_ble_tree);

    dissect_ble_delta_time(tvb, nordic_ble_tree);
}

static void
dissect_header_1_0_0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *nordic_ble_tree;

    pinfo->p2p_dir = P2P_DIR_RECV;

    /*** PROTOCOL TREE ***/

    ti = proto_tree_add_item(tree, proto_nordic_ble, tvb, 0, -1, ENC_NA);
    nordic_ble_tree = proto_item_add_subtree(ti, ett_nordic_ble);

    tvb = dissect_board_id_and_strip_it_from_tvb(tvb, pinfo, nordic_ble_tree);
    g_bad_length = dissect_lengths(tvb, pinfo, nordic_ble_tree);
    /*dissect_protover(tvb, nordic_ble_tree); This does not do anything ???*/
    dissect_packet_counter(tvb, nordic_ble_tree);
    /*dissect_id(tvb, nordic_ble_tree); This does not do anything ???*/
    /*dissect_ble_hlen(tvb, nordic_ble_tree); This does not do anything ???*/

    g_bad_mic = dissect_flags(tvb, pinfo, nordic_ble_tree);

    dissect_channel(tvb, nordic_ble_tree);
    dissect_rssi(tvb, nordic_ble_tree);
    dissect_event_counter(tvb, nordic_ble_tree);

    dissect_ble_delta_time(tvb, nordic_ble_tree);
}







/* Main entry point for sniffer, any version */
static int
dissect_nordic_ble(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tvbuff_t *payload_tvb;

    g_bad_length = FALSE;
    g_bad_mic = FALSE;


    legacy_mode = is_0_9_7_packet(tvb);

    if (legacy_mode) {
        dissect_header_0_9_7(tvb, pinfo, tree, data);
        payload_tvb = tvb_new_subset(tvb, _0_9_7_UART_HEADER_LENGTH, -1, tvb_captured_length(tvb) - _0_9_7_UART_HEADER_LENGTH);
    }
    else {
        dissect_header_1_0_0(tvb, pinfo, tree, data);
        /* have to take BOARD_ID into account, as the stripped version is local to dissect_1_0_0 */
        payload_tvb = tvb_new_subset(tvb, UART_HEADER_LENGTH + BOARD_ID_LENGTH, -1,
            tvb_captured_length(tvb) - UART_HEADER_LENGTH - BOARD_ID_LENGTH);
    }

    if (!g_bad_length) {
        call_dissector(btle_dissector_handle, payload_tvb, pinfo, tree);
    }

    if (g_bad_mic) {
        col_add_str(pinfo->cinfo, COL_INFO, "Encrypted packet decrypted incorrectly (bad MIC)");
    }

    if (debug_handle) {
        call_dissector(debug_handle, payload_tvb, pinfo, tree);
    }

    if (legacy_mode) {
        return _0_9_7_UART_HEADER_LENGTH;
    }
    else {
        return UART_HEADER_LENGTH + BOARD_ID_LENGTH;
    }
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_nordic_ble(void)
{
    /* module_t *nordic_ble_module; */

    /* Setup list of header fields  See Section 1.6.1 of README.developer for
     * details.
     */

    static hf_register_info hf[] = {
    { &hf_nordic_ble_board_id,
        { "board", "nordic_ble.board_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nordic_ble_header_length,
        { "length of header", "nordic_ble.hlen",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nordic_ble_payload_length,
        { "length of payload", "nordic_ble.plen",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Payload length", HFILL }
    },
    { &hf_nordic_ble_packet_counter,
        { "uart packet counter", "nordic_ble.packet_counter",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Global packet counter for packets sent on UART.", HFILL }
    },
    { &hf_nordic_ble_flags,
        { "flags", "nordic_ble.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nordic_ble_crcok,
        { "CRC", "nordic_ble.crcok",
        FT_BOOLEAN, BASE_NONE, TFS(&ok_incorrect), 0x0,
        "Cyclic Redundancy Check state", HFILL }
    },
    { &hf_nordic_ble_direction,
        { "direction", "nordic_ble.direction",
        FT_BOOLEAN, BASE_NONE, TFS(&direction_tfs), 0x0,
        NULL, HFILL }
    },
    { &hf_nordic_ble_encrypted,
        { "encrypted", "nordic_ble.encrypted",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
        "Was the packet encrypted", HFILL }
    },
    { &hf_nordic_ble_micok,
        { "MIC", "nordic_ble.micok",
        FT_BOOLEAN, BASE_NONE, TFS(&ok_incorrect), 0x0,
        "Message Integrity Check state", HFILL }
    },
    { &hf_nordic_ble_channel,
        { "channel", "nordic_ble.channel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nordic_ble_rssi,
        { "RSSI (dBm)", "nordic_ble.rssi",
        FT_INT16, BASE_DEC, NULL, 0x0,
        "Received Signal Strength Indicator", HFILL }
    },
    { &hf_nordic_ble_event_counter,
        { "event counter", "nordic_ble.event_counter",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nordic_ble_delta_time,
        { "delta time (us end to start)", "nordic_ble.delta_time",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Delta time: us since last reported packet.", HFILL }
    },
    { &hf_nordic_ble_delta_time_ss,
        { "delta time (us start to start)", "nordic_ble.delta_time_ss",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Delta time: us since start of last reported packet.", HFILL }
    }
    };



    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_nordic_ble,
        &ett_flags
    };

     static ei_register_info ei[] = {
         { &ei_nordic_ble_bad_crc, { "nordic_ble.crc.bad", PI_CHECKSUM, PI_ERROR, "CRC is bad", EXPFILL }},
         { &ei_nordic_ble_bad_mic, { "nordic_ble.mic.bad", PI_CHECKSUM, PI_ERROR, "MIC is bad", EXPFILL }},
         { &ei_nordic_ble_bad_length, { "nordic_ble.length.bad", PI_MALFORMED, PI_ERROR, "Length is incorrect", EXPFILL }},
     };

     expert_module_t* expert_nordic_ble;
    /* Register the protocol name and description */
    proto_nordic_ble = proto_register_protocol("Nordic BLE sniffer meta",
        "nordic_ble", "nordic_ble");

    register_dissector("nordic_ble", dissect_nordic_ble, proto_nordic_ble);

    expert_nordic_ble = expert_register_protocol(proto_nordic_ble);
    expert_register_field_array(expert_nordic_ble, ei, array_length(ei));

    /* Required function calls to register the header fields and subtrees */

    proto_register_field_array(proto_nordic_ble, hf, array_length(hf));


    proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_nordic_ble(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t nordic_ble_handle;
    /*static int currentPort;*/

    if (!initialized) {
        /* Use new_create_dissector_handle() to indicate that
         * dissect_nordic_ble() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to nordic ble sniffer).
         */
        nordic_ble_handle = create_dissector_handle(dissect_nordic_ble, proto_nordic_ble);

        btle_dissector_handle = find_dissector("btle");
        debug_handle = find_dissector("nordic_debug");
        initialized = TRUE;
    }

#ifdef TRANSPARENT
    dissector_add_uint("udp.port", udp_port, btle_dissector_handle);
#else
    /*dissector_add_uint("udp.port", udp_port, nordic_ble_handle);*/
    /*dissector_add_uint("wtap_encap", user_dlt_num, nordic_ble_handle);*/
    dissector_add_for_decode_as("udp.port", nordic_ble_handle);

#endif
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth =4 tabstop =8 expandtab:
 * :indentSize =4:tabSize =8:noTabs =true:
 */
