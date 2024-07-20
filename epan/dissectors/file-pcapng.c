/* file-pcapng.c
 * Routines for PCAPNG File Format
 * https://github.com/pcapng/pcapng
 *
 * Copyright 2015, Michal Labedzki for Tieto Corporation
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
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/addr_resolv.h>
#include <wiretap/pcapng_module.h>
#include <wiretap/secrets-types.h>

#include "file-pcapng.h"
#include "packet-pcap_pktdata.h"

static int proto_pcapng;

static dissector_handle_t  pcap_pktdata_handle;

static int hf_pcapng_block;

static int hf_pcapng_block_type;
static int hf_pcapng_block_type_vendor;
static int hf_pcapng_block_type_value;
static int hf_pcapng_block_length;
static int hf_pcapng_block_length_trailer;
static int hf_pcapng_block_data;

static int hf_pcapng_section_header_byte_order_magic;
static int hf_pcapng_section_header_major_version;
static int hf_pcapng_section_header_minor_version;
static int hf_pcapng_section_header_section_length;
static int hf_pcapng_options;
static int hf_pcapng_option;
static int hf_pcapng_option_code;
static int hf_pcapng_option_code_section_header;
static int hf_pcapng_option_code_interface_description;
static int hf_pcapng_option_code_enhanced_packet;
static int hf_pcapng_option_code_packet;
static int hf_pcapng_option_code_interface_statistics;
static int hf_pcapng_option_code_name_resolution;
static int hf_pcapng_option_length;
static int hf_pcapng_option_data;
static int hf_pcapng_option_data_comment;
static int hf_pcapng_option_data_section_header_hardware;
static int hf_pcapng_option_data_section_header_os;
static int hf_pcapng_option_data_section_header_user_application;
static int hf_pcapng_option_data_interface_description_name;
static int hf_pcapng_option_data_interface_description_description;
static int hf_pcapng_option_data_ipv4;
static int hf_pcapng_option_data_ipv4_mask;
static int hf_pcapng_option_data_ipv6;
static int hf_pcapng_option_data_ipv6_mask;
static int hf_pcapng_option_data_mac_address;
static int hf_pcapng_option_data_eui_address;
static int hf_pcapng_option_data_interface_speed;
static int hf_pcapng_option_data_interface_timestamp_resolution;
static int hf_pcapng_option_data_interface_timestamp_resolution_base;
static int hf_pcapng_option_data_interface_timestamp_resolution_value;
static int hf_pcapng_option_data_interface_timezone;
static int hf_pcapng_option_data_interface_filter_type;
static int hf_pcapng_option_data_interface_filter_string;
static int hf_pcapng_option_data_interface_filter_bpf_program;
static int hf_pcapng_option_data_interface_filter_unknown;
static int hf_pcapng_option_data_interface_os;
static int hf_pcapng_option_data_interface_hardware;
static int hf_pcapng_option_data_interface_fcs_length;
static int hf_pcapng_option_data_interface_timestamp_offset;
static int hf_pcapng_option_data_packet_verdict_type;
static int hf_pcapng_option_data_packet_verdict_data;
static int hf_pcapng_option_data_packet_queue;
static int hf_pcapng_option_data_packet_id;
static int hf_pcapng_option_data_packet_drop_count;
static int hf_pcapng_option_data_packet_hash_algorithm;
static int hf_pcapng_option_data_packet_hash_data;
static int hf_pcapng_option_data_packet_flags;
static int hf_pcapng_option_data_packet_flags_link_layer_errors;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_symbol;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_preamble;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_start_frame_delimiter;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_unaligned_frame;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_wrong_inter_frame_gap;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_short;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_long;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_crc_error;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_reserved;
static int hf_pcapng_option_data_packet_flags_reserved;
static int hf_pcapng_option_data_packet_flags_fcs_length;
static int hf_pcapng_option_data_packet_flags_reception_type;
static int hf_pcapng_option_data_packet_flags_direction;
static int hf_pcapng_option_data_dns_name;
static int hf_pcapng_option_data_start_time;
static int hf_pcapng_option_data_end_time;
static int hf_pcapng_option_data_interface_received;
static int hf_pcapng_option_data_interface_dropped;
static int hf_pcapng_option_data_interface_accepted_by_filter;
static int hf_pcapng_option_data_interface_dropped_by_os;
static int hf_pcapng_option_data_interface_delivered_to_user;
static int hf_pcapng_option_padding;
static int hf_pcapng_interface_description_link_type;
static int hf_pcapng_interface_description_reserved;
static int hf_pcapng_interface_description_snap_length;
static int hf_pcapng_packet_block_interface_id;
static int hf_pcapng_packet_block_drops_count;
static int hf_pcapng_captured_length;
static int hf_pcapng_original_length;
static int hf_pcapng_packet_data;
static int hf_pcapng_packet_padding;
static int hf_pcapng_interface_id;
static int hf_pcapng_timestamp_high;
static int hf_pcapng_timestamp_low;
static int hf_pcapng_timestamp;
static int hf_pcapng_records;
static int hf_pcapng_record;
static int hf_pcapng_record_code;
static int hf_pcapng_record_length;
static int hf_pcapng_record_data;
static int hf_pcapng_record_ipv4;
static int hf_pcapng_record_ipv6;
static int hf_pcapng_record_name;
static int hf_pcapng_record_padding;

static int hf_pcapng_dsb_secrets_type;
static int hf_pcapng_dsb_secrets_length;
static int hf_pcapng_dsb_secrets_data;

static int hf_pcapng_cb_pen;
static int hf_pcapng_cb_data;
static int hf_pcapng_cb_option_string;
static int hf_pcapng_cb_option_data;

static int hf_pcapng_option_data_packet_darwin_dpeb_id;
static int hf_pcapng_option_data_packet_darwin_svc_class;
static int hf_pcapng_option_data_packet_darwin_edpeb_id;
static int hf_pcapng_option_data_packet_darwin_flags;
static int hf_pcapng_option_data_packet_darwin_flags_reserved;
static int hf_pcapng_option_data_packet_darwin_flags_wk;
static int hf_pcapng_option_data_packet_darwin_flags_ch;
static int hf_pcapng_option_data_packet_darwin_flags_so;
static int hf_pcapng_option_data_packet_darwin_flags_re;
static int hf_pcapng_option_data_packet_darwin_flags_ka;
static int hf_pcapng_option_data_packet_darwin_flags_nf;
static int hf_pcapng_option_data_packet_darwin_flow_id;

static expert_field ei_invalid_byte_order_magic;
static expert_field ei_block_length_below_block_minimum;
static expert_field ei_block_length_below_block_content_length;
static expert_field ei_block_length_not_multiple_of_4;
static expert_field ei_block_lengths_dont_match;
static expert_field ei_invalid_option_length;
static expert_field ei_invalid_record_length;
static expert_field ei_missing_idb;

static int ett_pcapng;
static int ett_pcapng_section_header_block;
static int ett_pcapng_block_data;
static int ett_pcapng_block_type;
static int ett_pcapng_options;
static int ett_pcapng_option;
static int ett_pcapng_records;
static int ett_pcapng_record;
static int ett_pcapng_packet_data;

static int * const hfx_pcapng_option_data_interface_timestamp_resolution[] = {
    &hf_pcapng_option_data_interface_timestamp_resolution_base,
    &hf_pcapng_option_data_interface_timestamp_resolution_value,
    NULL
};

static int * const hfx_pcapng_option_data_packet_flags_link_layer_errors[] = {
    &hf_pcapng_option_data_packet_flags_link_layer_errors_symbol,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_preamble,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_start_frame_delimiter,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_unaligned_frame,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_wrong_inter_frame_gap,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_short,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_long,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_crc_error,
    &hf_pcapng_option_data_packet_flags_link_layer_errors_reserved,
    NULL
};

static int * const hfx_pcapng_option_data_packet_flags[] = {
    &hf_pcapng_option_data_packet_flags_reserved,
    &hf_pcapng_option_data_packet_flags_fcs_length,
    &hf_pcapng_option_data_packet_flags_reception_type,
    &hf_pcapng_option_data_packet_flags_direction,
    NULL
};

static int * const hfx_pcapng_option_data_packet_darwin_flags[] = {
    &hf_pcapng_option_data_packet_darwin_flags_reserved,
    &hf_pcapng_option_data_packet_darwin_flags_wk,
    &hf_pcapng_option_data_packet_darwin_flags_ch,
    &hf_pcapng_option_data_packet_darwin_flags_so,
    &hf_pcapng_option_data_packet_darwin_flags_re,
    &hf_pcapng_option_data_packet_darwin_flags_ka,
    &hf_pcapng_option_data_packet_darwin_flags_nf,
    NULL
};

static bool pref_dissect_next_layer;

static const value_string block_type_vals[] = {
    { BLOCK_TYPE_IDB,                       "Interface Description Block" },
    { BLOCK_TYPE_PB,                        "Packet Block" },
    { BLOCK_TYPE_SPB,                       "Simple Packet Block" },
    { BLOCK_TYPE_NRB,                       "Name Resolution Block" },
    { BLOCK_TYPE_ISB,                       "Interface Statistics Block" },
    { BLOCK_TYPE_EPB,                       "Enhanced Packet Block" },
    { BLOCK_TYPE_IRIG_TS,                   "IRIG Timestamp Block" },
    { BLOCK_TYPE_ARINC_429,                 "Arinc 429 in AFDX Encapsulation Information Block" },
    { BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT,    "systemd Journal Export Block" },
    { BLOCK_TYPE_DSB,                       "Decryption Secrets Block" },
    { BLOCK_TYPE_SYSDIG_MI,                 "Sysdig Machine Info Block" },
    { BLOCK_TYPE_SYSDIG_PL_V1,              "Sysdig Process List Block" },
    { BLOCK_TYPE_SYSDIG_FDL_V1,             "Sysdig File Descriptor List Block" },
    { BLOCK_TYPE_SYSDIG_EVENT,              "Sysdig Event Block" },
    { BLOCK_TYPE_SYSDIG_IL_V1,              "Sysdig Interface List Block" },
    { BLOCK_TYPE_SYSDIG_UL_V1,              "Sysdig User List Block" },
    { BLOCK_TYPE_SYSDIG_PL_V2,              "Sysdig Process List Block version 2" },
    { BLOCK_TYPE_SYSDIG_EVF,                "Sysdig Event Block with flags" },
    { BLOCK_TYPE_SYSDIG_PL_V3,              "Sysdig Process List Block version 3" },
    { BLOCK_TYPE_SYSDIG_PL_V4,              "Sysdig Process List Block version 4" },
    { BLOCK_TYPE_SYSDIG_PL_V5,              "Sysdig Process List Block version 5" },
    { BLOCK_TYPE_SYSDIG_PL_V6,              "Sysdig Process List Block version 6" },
    { BLOCK_TYPE_SYSDIG_PL_V7,              "Sysdig Process List Block version 7" },
    { BLOCK_TYPE_SYSDIG_PL_V8,              "Sysdig Process List Block version 8" },
    { BLOCK_TYPE_SYSDIG_PL_V9,              "Sysdig Process List Block version 9" },
    { BLOCK_TYPE_SYSDIG_EVENT_V2,           "Sysdig Event Block v2" },
    { BLOCK_TYPE_SYSDIG_EVF_V2,             "Sysdig Event Block with flags v2" },
    { BLOCK_TYPE_SYSDIG_FDL_V2,             "Sysdig File Descriptor List Block" },
    { BLOCK_TYPE_SYSDIG_IL_V2,              "Sysdig Interface List Block version 2" },
    { BLOCK_TYPE_SYSDIG_UL_V2,              "Sysdig User List Block version 2" },
    { BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE,     "Sysdig Event Block v2 large payload" },
    { BLOCK_TYPE_SYSDIG_EVF_V2_LARGE,       "Sysdig Event Block with flags v2 large payload" },
    { BLOCK_TYPE_CB_COPY,                   "Custom Block which can be copied"},
    { BLOCK_TYPE_CB_NO_COPY,                "Custom Block which should not be copied"},
    { BLOCK_TYPE_SHB,                       "Section Header Block" },
    { 0, NULL }
};


/* blockId-> local_block_callback_info_t* */
static GHashTable *s_local_block_callback_table;

#define OPTION_CODE_CUSTOM_OPTIONS \
    { 2988,  "Custom Option UTF-8 string which can be copied" }, \
    { 2989,  "Custom Option which can be copied" }, \
    { 19372, "Custom Option UTF-8 string which should not be copied" }, \
    { 19373, "Custom Option which should not be copied" }

static const value_string option_code_section_header_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Hardware Description" },
    { 3,  "OS Description" },
    { 4,  "User Application" },
    OPTION_CODE_CUSTOM_OPTIONS,
    { 0, NULL }
};

static const value_string option_code_interface_description_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Interface Name" },
    { 3,  "Interface Description" },
    { 4,  "IPv4 Address" },
    { 5,  "IPv6 Address" },
    { 6,  "MAC Address" },
    { 7,  "EUI Address" },
    { 8,  "Speed" },
    { 9,  "Timestamp Resolution" },
    { 10, "Timezone" },
    { 11, "Filter" },
    { 12, "OS" },
    { 13, "FCS Length" },
    { 14, "Timestamp Offset" },
    { 15, "Hardware" },
    OPTION_CODE_CUSTOM_OPTIONS,
    { 0, NULL }
};


/*
 * Enhanced Packet Block (EPB) options for supporting Darwin process information
 *
 *    Enhanced Packet Blocks may be augmented with an Apple defined Darwin
 *    process event block id option (dpeb_id) and / or an effective Darwin
 *    process event block id option (edpeb_id) that refer to particular
 *    Darwin processes via the supplied DPEB ID option payload value.  There
 *    must be a Darwin Process Event Block for each Darwin process to which an
 *    augmented EPB references.  If the file does not contain any EPBs that
 *    contain any Darwin dpeb_id or edpeb_id options then the file does not need
 *    to have any DPEBs.
 *
 *    A Darwin Process Event Block is valid only inside the section to which
 *    it belongs.  The structure of a Darwin Process Event Block is shown in
 *    Figure XXX.1 below.
 *
 *    An Enhanced Packet Block (EPB) may be augmented with any or all of the
 *    following block options for Darwin process information:
 *
 *          +------------------+-------+--------+-------------------+
 *          | Name             | Code  | Length | Multiple allowed? |
 *          +------------------+-------+--------+-------------------+
 *          | darwin_dpeb_id   | 32769 | 4      | no?               |
 *          | darwin_svc_class | 32770 | 4      | no?               |
 *          | darwin_edpeb_id  | 32771 | 4      | no?               |
 *          | darwin_flags     | 32772 | 4      | no?               |
 *          | darwin_flow_id   | 32773 | 4      | no?               |
 *          +------------------+------+---------+-------------------+
 *
 *           Table XXX.2: Darwin options for Enhanced Packet Blocks
 *
 *    darwin_dpeb_id:
 *            The darwin_dpeb_id option specifies the Darwin Process Event
 *            Block ID for the process (proc) this packet is associated with;
 *            the correct DPEB will be the one whose DPEB ID (within the
 *            current Section of the file) is identified by the same number
 *            (see Section XXX.X) of this field.  The DPEB ID MUST be valid,
 *            which means that a matching Darwin Process Event Block MUST
 *            exist.
 *
 *    darwin_srv_class:
 *            The darwin_svc_class option is a number that maps to a
 *            specific Darwin Service Class mnemonic that the packet is
 *            associated with.
 *
 *    The following Darwin Service Class values are defined:
 *
 *              +---------------------+------------------------+
 *              | Service Class Value | Service Class Mnemonic |
 *              +---------------------+------------------------+
 *              | 0                   | BE                     |
 *              | 100                 | BK_SYS                 |
 *              | 200                 | BK                     |
 *              | 300                 | RD                     |
 *              | 400                 | OAM                    |
 *              | 500                 | AV                     |
 *              | 600                 | RV                     |
 *              | 700                 | VI                     |
 *              | 800                 | VO                     |
 *              | 900                 | CTL                    |
 *              +---------------------+------------------------+
 *
 *              Table XXX.3: Darwin Service Class Option Values
 *
 *    darwin_edpeb_id:
 *            The darwin_edpeb_id option specifies the Darwin Process Event
 *            Block ID for the effective process (eproc) this packet is
 *            associated with; the correct DPEB will be the one whose DPEB
 *            ID (within the current Section of the file) is identified by
 *            the same number (see Section XXX.X) of this field.  The DPEB
 *            ID MUST be valid, which means that a matching Darwin Process
 *            Event Block MUST exist.
 *
 *    darwin_flags:
 *            The darwin_flags option is a 32 bit field for indicating
 *            various Darwin specific flags.
 *
 *    The following Darwin Flags are defined:
 *
 *                          +-------------------------+
 *                          |     FLAG_MASK    | Flag |
 *                          +-------------------------+
 *                          |    0x00000020    |  wk  |
 *                          |    0x00000010    |  ch  |
 *                          |    0x00000008    |  so  |
 *                          |    0x00000004    |  re  |
 *                          |    0x00000002    |  ka  |
 *                          |    0x00000001    |  nf  |
 *                          +-------------------------+
 *
 *                           Table XXX.4: Darwin Flags
 *
 *      wk = Wake Packet
 *      ch = Nexus Channel
 *      so = Socket
 *      re = ReXmit
 *      ka = Keep Alive
 *      nf = New Flow
 *
 *    darwin_flow_id:
 *            The darwin_flow_id option is a 32 bit value that
 *            identifies a specific flow this packet is a part of.
 */


static const value_string option_code_enhanced_packet_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Flags" },
    { 3,  "Hash" },
    { 4,  "Drop Count" },
    { 5,  "Packet ID" },
    { 6,  "Queue" },
    { 7,  "Verdict" },
    OPTION_CODE_CUSTOM_OPTIONS,
    { 32769,   "Darwin DPEB ID" },
    { 32770,   "Darwin Service Class" },
    { 32771,   "Darwin Effective DPEB ID" },
    { 32772,   "Darwin Flags" },
    { 32773,   "Darwin Flow ID" },
    { 0, NULL }
};

static const value_string option_code_packet_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Flags" },
    { 3,  "Hash" },
    OPTION_CODE_CUSTOM_OPTIONS,
    { 0, NULL }
};

static const value_string option_code_name_resolution_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "DNS Name" },
    { 3,  "DNS IPv4 Address" },
    { 4,  "DNS IPv6 Address" },
    OPTION_CODE_CUSTOM_OPTIONS,
    { 0, NULL }
};

static const value_string option_code_interface_statistics_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Start Time" },
    { 3,  "End Time" },
    { 4,  "Number of Received Packets" },
    { 5,  "Number of Dropped Packets" },
    { 6,  "Number of Accepted Packets" },
    { 7,  "Number of Packets Dropped by OS" },
    { 8,  "Number of Packets Delivered to the User" },
    OPTION_CODE_CUSTOM_OPTIONS,
    { 0, NULL }
};

static const value_string option_code_darwin_svc_class_vals[] = {
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

static const value_string record_code_vals[] = {
    { 0x0000,  "End of Records" },
    { 0x0001,  "IPv4 Record" },
    { 0x0002,  "IPv6 Record" },
    { 0, NULL }
};

static const value_string timestamp_resolution_base_vals[] = {
    { 0x0000,  "Power of 10" },
    { 0x0001,  "Power of 2" },
    { 0, NULL }
};

static const value_string interface_filter_type_vals[] = {
    { 0, "Libpcap string" },
    { 1, "BPF program" },
    { 0, NULL }
};

static const value_string packet_verdict_type_vals[] = {
    { 0,  "Hardware" },
    { 1,  "Linux eBPF TC" },
    { 2,  "Linux eBPF XDP" },
    { 0, NULL }
};

static const value_string packet_hash_algorithm_vals[] = {
    { 0,  "2's complement" },
    { 1,  "XOR" },
    { 2,  "CRC32" },
    { 3,  "MD5" },
    { 4,  "SHA1" },
    { 0, NULL }
};

static const value_string packet_flags_direction_vals[] = {
    { 0x00,  "Information Not Available" },
    { 0x01,  "Inbound" },
    { 0x02,  "Outbound" },
    { 0, NULL }
};

static const value_string flags_reception_type_vals[] = {
    { 0x00,  "Not Specified" },
    { 0x01,  "Unicast" },
    { 0x02,  "Multicast" },
    { 0x03,  "Broadcast" },
    { 0x04,  "Promiscuous" },
    { 0, NULL }
};

static const value_string dsb_secrets_types_vals[] = {
    { SECRETS_TYPE_TLS,             "TLS Key Log" },
    { SECRETS_TYPE_SSH,             "SSH Key Log" },
    { SECRETS_TYPE_WIREGUARD,       "WireGuard Key Log" },
    { SECRETS_TYPE_ZIGBEE_NWK_KEY,  "Zigbee NWK Key" },
    { SECRETS_TYPE_ZIGBEE_APS_KEY,  "Zigbee APS Key" },
    { SECRETS_TYPE_OPCUA,           "OPC UA Key Log" },
    { 0, NULL }
};

void proto_register_pcapng(void);
void proto_reg_handoff_pcapng(void);

#define BYTE_ORDER_MAGIC_SIZE  4

static const uint8_t pcapng_big_endian_magic[BYTE_ORDER_MAGIC_SIZE] = {
    0x1A, 0x2B, 0x3C, 0x4D
};
static const uint8_t pcapng_little_endian_magic[BYTE_ORDER_MAGIC_SIZE] = {
    0x4D, 0x3C, 0x2B, 0x1A
};

static
void dissect_custom_options(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                            uint32_t option_code, uint32_t option_length, unsigned encoding)
{
    proto_tree_add_item(tree, hf_pcapng_cb_pen, tvb, offset, 4, encoding);
    offset += 4;

    /* Todo: Add known PEN custom options dissection. */
    switch (option_code) {
    case 2988:
    case 19372:
        proto_tree_add_item(tree, hf_pcapng_cb_option_string, tvb, offset, option_length - 4, ENC_UTF_8);
        break;
    case 2989:
    case 19373:
        proto_tree_add_item(tree, hf_pcapng_cb_option_data, tvb, offset, option_length - 4, encoding);
        break;
    }
}

int dissect_options(proto_tree *tree, packet_info *pinfo,
        uint32_t block_type, tvbuff_t *tvb, int offset, unsigned encoding,
        void *user_data)
{
    proto_tree   *options_tree;
    proto_item   *options_item;
    proto_tree   *option_tree;
    proto_item   *option_item;
    proto_item   *option_length_item;
    proto_item   *p_item;
    uint32_t      option_code;
    uint32_t      option_length;
    int           hfj_pcapng_option_code;
    char         *str;
    const char   *const_str;
    wmem_strbuf_t *strbuf;
    address       addr;
    address       addr_mask;
    uint32_t      if_filter_type;
    const value_string  *vals = NULL;
    uint8_t       value_u8;
    uint32_t      value_u32;
    uint64_t      value_u64;

    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return 0;

    /* Lookup handlers for known local block type */
    local_block_callback_info_t *p_local_block_callback = NULL;
    if (block_type >= 0x80000000) {
        p_local_block_callback = (local_block_callback_info_t*)g_hash_table_lookup(s_local_block_callback_table, GUINT_TO_POINTER(block_type));
        DISSECTOR_ASSERT((p_local_block_callback->option_root_hf > 0) &&
                          p_local_block_callback->option_dissector &&
                          p_local_block_callback->option_vals);
    }

    options_item = proto_tree_add_item(tree, hf_pcapng_options, tvb, offset, -1, ENC_NA);
    options_tree = proto_item_add_subtree(options_item, ett_pcapng_options);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        str = NULL;
        option_item = proto_tree_add_item(options_tree, hf_pcapng_option, tvb, offset, -1, ENC_NA);
        option_tree = proto_item_add_subtree(option_item, ett_pcapng_option);

        /* TODO: could have done this once outside of loop? */
        switch (block_type) {
        case BLOCK_TYPE_SHB:
            hfj_pcapng_option_code = hf_pcapng_option_code_section_header;
            vals = option_code_section_header_vals;
            break;
        case BLOCK_TYPE_IDB:
            hfj_pcapng_option_code = hf_pcapng_option_code_interface_description;
            vals = option_code_interface_description_vals;
            break;
        case BLOCK_TYPE_EPB:
            hfj_pcapng_option_code = hf_pcapng_option_code_enhanced_packet;
            vals = option_code_enhanced_packet_vals;
            break;
        case BLOCK_TYPE_PB:
            hfj_pcapng_option_code = hf_pcapng_option_code_packet;
            vals = option_code_packet_vals;
            break;
        case BLOCK_TYPE_NRB:
            hfj_pcapng_option_code = hf_pcapng_option_code_name_resolution;
            vals = option_code_name_resolution_vals;
            break;
        case BLOCK_TYPE_ISB:
            hfj_pcapng_option_code = hf_pcapng_option_code_interface_statistics;
            vals = option_code_interface_statistics_vals;
            break;

        default:
            /* Use and handling we have for a local lock type */
            if (p_local_block_callback) {
                hfj_pcapng_option_code = p_local_block_callback->option_root_hf;
                vals = p_local_block_callback->option_vals;
            }
            else {
                hfj_pcapng_option_code = hf_pcapng_option_code;
            }
        }

        proto_tree_add_item_ret_uint(option_tree, hfj_pcapng_option_code, tvb, offset, 2, encoding, &option_code);
        if (vals)
            proto_item_append_text(option_item, ": %s", val_to_str_const(option_code, vals, "Unknown"));
        offset += 2;

        option_length_item = proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_length, tvb, offset, 2, encoding, &option_length);
        offset += 2;

        if (option_code == 0) {
            if (option_length != 0)
                expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
            proto_item_set_len(option_item, option_length + 2 * 2);
            break;
        } else if (option_code == 1) {
            proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_comment, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
            proto_item_append_text(option_item, " = %s", str);
            offset += option_length;
        } else if (option_code == 2988 || option_code == 2989 || option_code == 19372 || option_code == 19373) {
            dissect_custom_options(option_tree, pinfo, tvb, offset, option_code, option_length, encoding);
            offset += option_length;
        } else switch (block_type) {
        case BLOCK_TYPE_SHB:
            switch (option_code) {
            case 2:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_section_header_hardware, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;
                break;
            case 3:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_section_header_os, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;
                break;
            case 4:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_section_header_user_application, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;
                break;
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
            }
            break;
        case BLOCK_TYPE_IDB: {
            struct interface_description  *interface_description = (struct interface_description *) user_data;

            switch (option_code) {
            case 2:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_interface_description_name, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;
                break;
            case 3:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_interface_description_description, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;
                break;
            case 4:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }
                proto_tree_add_item(option_tree, hf_pcapng_option_data_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                set_address_tvb(&addr, AT_IPv4, 4, tvb, offset);
                offset += 4;

                proto_tree_add_item(option_tree, hf_pcapng_option_data_ipv4_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
                set_address_tvb(&addr_mask, AT_IPv4, 4, tvb, offset);
                offset += 4;

                proto_item_append_text(option_item, " = %s/%s",
                        address_to_display(pinfo->pool,  &addr),
                        address_to_display(pinfo->pool,  &addr_mask));
                break;
            case 5:
                if (option_length != 17) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_ipv6, tvb, offset, 16, ENC_NA);
                set_address_tvb(&addr, AT_IPv6, 16, tvb, offset);
                offset += 16;

                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_ipv6_mask, tvb, offset, 1, ENC_NA, &value_u32);
                offset += 1;

                proto_item_append_text(option_item, " = %s/%u",
                    address_to_display(pinfo->pool,  &addr), value_u32);

                break;
            case 6:
                if (option_length != 6) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_mac_address, tvb, offset, 6, encoding);
                proto_item_append_text(option_item, " = %s",
                    tvb_get_ether_name(tvb, offset));
                offset += 6;

                break;
            case 7:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_eui_address, tvb, offset, 8, encoding);
                set_address_tvb(&addr, AT_EUI64, 8, tvb, offset);
                offset += 8;

                proto_item_append_text(option_item, " = %s",
                    address_to_display(pinfo->pool,  &addr));

                break;
            case 8:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                p_item = proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_interface_speed, tvb, offset, 8, encoding, &value_u64);
                /* XXX - is there a general routine to do this mapping? */
                if (value_u64 == 10000000) {
                    const_str = "10 Mbps";
                } else if (value_u64 == 100000000) {
                    const_str = "100 Mbps";
                } else if (value_u64 == 1000000000) {
                    const_str = "1 Gbps";
                } else {
                    const_str = wmem_strdup_printf(pinfo->pool, "%"PRIu64, value_u64);
                }
                proto_item_append_text(p_item, "%s", const_str);
                proto_item_append_text(option_item, " = %s", const_str);
                offset += 8;

                break;
            case 9:
            {
                uint32_t    base;
                uint32_t    exponent;
                uint32_t    i;
                uint64_t    resolution;

                if (option_length != 1) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_interface_timestamp_resolution, ett_pcapng_option, hfx_pcapng_option_data_interface_timestamp_resolution, ENC_NA);
                value_u8 = tvb_get_uint8(tvb, offset);
                offset += 1;

                if (value_u8 & 0x80) {
                    base = 2;
                } else {
                    base = 10;
                }
                exponent = value_u8 & 0x7F;

                strbuf = wmem_strbuf_new(pinfo->pool, "");
                wmem_strbuf_append_printf(strbuf, "%u^-%u", base, exponent);
                resolution = 1;
                for (i = 0; i < exponent; i += 1)
                    resolution *= base;
                if (interface_description) {
                    interface_description->timestamp_resolution = resolution;
                }
                switch (resolution) {

                case 0:
                    /* Overflow */
                    wmem_strbuf_append(strbuf, " (overflow)");
                    break;

                case 1:
                    wmem_strbuf_append(strbuf, " (seconds)");
                    break;

                case 10:
                    wmem_strbuf_append(strbuf, " (.1 seconds)");
                    break;

                case 100:
                    wmem_strbuf_append(strbuf, " (.01 seconds)");
                    break;

                case 1000:
                    wmem_strbuf_append(strbuf, " (milliseconds)");
                    break;

                case 10000:
                    wmem_strbuf_append(strbuf, " (.1 milliseconds)");
                    break;

                case 100000:
                    wmem_strbuf_append(strbuf, " (.01 milliseconds)");
                    break;

                case 1000000:
                    wmem_strbuf_append(strbuf, " (microseconds)");
                    break;

                case 10000000:
                    wmem_strbuf_append(strbuf, " (.1 microseconds)");
                    break;

                case 100000000:
                    wmem_strbuf_append(strbuf, " (.01 microseconds)");
                    break;

                case 1000000000:
                    wmem_strbuf_append(strbuf, " (nanoseconds)");
                    break;

                case 10000000000:
                    wmem_strbuf_append(strbuf, " (.1 nanoseconds)");
                    break;

                case 100000000000:
                    wmem_strbuf_append(strbuf, " (.01 nanoseconds)");
                    break;

                case 1000000000000:
                    wmem_strbuf_append(strbuf, " (picoseconds)");
                    break;

                case 10000000000000:
                    wmem_strbuf_append(strbuf, " (.1 picoseconds)");
                    break;

                case 100000000000000:
                    wmem_strbuf_append(strbuf, " (.01 picoseconds)");
                    break;
                }
                proto_item_append_text(option_item, " = %s",
                    wmem_strbuf_finalize(strbuf));
                break;
            }
            case 10:
                if (option_length != 4) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

/* TODO: Better timezone decoding */
                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_interface_timezone, tvb, offset, 4, encoding, &value_u32);
                offset += 4;

                proto_item_append_text(option_item, " = %u", value_u32);

                break;
            case 11:
                if (option_length == 0) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    break;
                }


                /* Get filter type (0 is libpcap, 1 is BPF program, others are unspecified.) */
                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_interface_filter_type, tvb, offset, 1, ENC_NA, &if_filter_type);
                offset++;
                switch (if_filter_type) {

                case 0:
                    proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_interface_filter_string, tvb, offset, option_length - 1, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                    proto_item_append_text(option_item, " = %s", str);
                    break;

                case 1:
                    proto_tree_add_item(option_tree, hf_pcapng_option_data_interface_filter_bpf_program, tvb, offset, option_length - 1, ENC_NA);
                    proto_item_append_text(option_item, " = {BPF program}");
                    break;

                default:
                    proto_tree_add_item(option_tree, hf_pcapng_option_data_interface_filter_unknown, tvb, offset, option_length - 1, ENC_NA);
                    proto_item_append_text(option_item, " = unknown (type %u)", if_filter_type);
                    break;
		}
                offset += option_length - 1;

                break;
            case 12:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_interface_os, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;

                break;
            case 13:
                if (option_length != 1) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_interface_fcs_length, tvb, offset, 1, ENC_NA, &value_u32);
                offset += 1;
                proto_item_append_text(option_item, " = %u", value_u32);

                break;
            case 14:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_interface_timestamp_offset, tvb, offset, 8, encoding, &value_u64);
                offset += 8;
                proto_item_append_text(option_item, " = %"PRIu64, value_u64);

                if (interface_description) {
                    interface_description->timestamp_offset = value_u64;
                }

                break;
            case 15:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_interface_hardware, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;

                break;
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
            }
            }
            break;
        case BLOCK_TYPE_PB:
            switch (option_code) {
            case 2:
                if (option_length != 4) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                if (encoding == ENC_LITTLE_ENDIAN) {
                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags, ett_pcapng_option, hfx_pcapng_option_data_packet_flags, encoding);
                    offset += 2;

                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags_link_layer_errors, ett_pcapng_option, hfx_pcapng_option_data_packet_flags_link_layer_errors, encoding);
                    offset += 2;
                } else {
                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags_link_layer_errors, ett_pcapng_option, hfx_pcapng_option_data_packet_flags_link_layer_errors, encoding);
                    offset += 2;

                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags, ett_pcapng_option, hfx_pcapng_option_data_packet_flags, encoding);
                    offset += 2;
                }

                break;
            case 3:
                proto_tree_add_item(option_tree, hf_pcapng_option_data_packet_hash_algorithm, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(option_tree, hf_pcapng_option_data_packet_hash_data, tvb, offset, option_length - 1, ENC_NA);
                offset += option_length - 1;

                break;
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
            }

            break;
        case BLOCK_TYPE_NRB:
            switch (option_code) {
            case 2:
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_data_dns_name, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                proto_item_append_text(option_item, " = %s", str);
                offset += option_length;

                break;
            case 3:
                if (option_length != 4) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                set_address_tvb(&addr, AT_IPv4, 4, tvb, offset);
                offset += 4;

                proto_item_append_text(option_item, " = %s",
                    address_to_display(pinfo->pool, &addr));

                break;
            case 4:
                if (option_length != 16) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_ipv6, tvb, offset, 16, ENC_NA);
                set_address_tvb(&addr, AT_IPv6, 16, tvb, offset);
                offset += 16;

                proto_item_append_text(option_item, " = %s",
                    address_to_display(pinfo->pool,  &addr));

                break;
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
            }

            break;
        case BLOCK_TYPE_ISB:
            switch (option_code) {
            case 2:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_start_time, tvb, offset, 8, encoding);
                offset += 8;

                break;
            case 3:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_end_time, tvb, offset, 8, encoding);
                offset += 8;

                break;
            case 4:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_interface_received, tvb, offset, 8, encoding, &value_u64);
                proto_item_append_text(option_item, " = %"PRIu64, value_u64);
                offset += 8;

                break;
            case 5:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_interface_dropped, tvb, offset, 8, encoding, &value_u64);
                proto_item_append_text(option_item, " = %"PRIu64, value_u64);
                offset += 8;

                break;
            case 6:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_interface_accepted_by_filter, tvb, offset, 8, encoding, &value_u64);
                proto_item_append_text(option_item, " = %"PRIu64, value_u64);
                offset += 8;

                break;
            case 7:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_interface_dropped_by_os, tvb, offset, 8, encoding, &value_u64);
                proto_item_append_text(option_item, " = %"PRIu64, value_u64);
                offset += 8;

                break;
            case 8:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_interface_delivered_to_user, tvb, offset, 8, encoding, &value_u64);
                proto_item_append_text(option_item, " = %"PRIu64, value_u64);
                offset += 8;

                break;
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
            }

            break;
        case BLOCK_TYPE_EPB:
            switch (option_code) {
            case 2:
                if (option_length != 4) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                if (encoding == ENC_LITTLE_ENDIAN) {
                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags, ett_pcapng_option, hfx_pcapng_option_data_packet_flags, encoding);
                    offset += 2;

                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags_link_layer_errors, ett_pcapng_option, hfx_pcapng_option_data_packet_flags_link_layer_errors, encoding);
                    offset += 2;
                } else {
                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags_link_layer_errors, ett_pcapng_option, hfx_pcapng_option_data_packet_flags_link_layer_errors, encoding);
                    offset += 2;

                    proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_flags, ett_pcapng_option, hfx_pcapng_option_data_packet_flags, encoding);
                    offset += 2;
                }

                break;
            case 3:
                proto_tree_add_item(option_tree, hf_pcapng_option_data_packet_hash_algorithm, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(option_tree, hf_pcapng_option_data_packet_hash_data, tvb, offset, option_length - 1, ENC_NA);
                offset += option_length - 1;

                break;
            case 4:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_packet_drop_count, tvb, offset, 8, encoding, &value_u64);
                proto_item_append_text(option_item, " = %"PRIu64, value_u64);
                offset += 8;

                break;
            case 5:
                if (option_length != 8) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint64(option_tree, hf_pcapng_option_data_packet_id, tvb, offset, 8, encoding, &value_u64);
                proto_item_append_text(option_item, " = 0x%016"PRIx64, value_u64);
                offset += 8;

                break;
            case 6:
                if (option_length != 4) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_packet_queue, tvb, offset, 4, encoding, &value_u32);
                proto_item_append_text(option_item, " = %u", value_u32);
                offset += 4;

                break;
            case 7:
                if (option_length < 1) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    break;
                }

                switch (tvb_get_uint8(tvb, offset)) {
                case 1:
                case 2:
                    if (option_length != 9) {
                        expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    }
                    break;
                default:
                    break;
                }

                proto_tree_add_item(option_tree, hf_pcapng_option_data_packet_verdict_type, tvb, offset, 1, ENC_NA);
                if (option_length > 1)
                    proto_tree_add_item(option_tree, hf_pcapng_option_data_packet_verdict_data, tvb, offset + 1, option_length - 1, ENC_NA);
                offset += option_length;

                break;
            case 32769: /* Darwin DPEB ID */
                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_packet_darwin_dpeb_id, tvb, offset, option_length, encoding, &value_u32);
                offset += option_length;

                proto_item_append_text(option_item, " = %u", value_u32);

                break;
            case 32770: /* Darwin Service Type */
                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_packet_darwin_svc_class, tvb, offset, option_length, encoding, &value_u32);
                offset += option_length;

                proto_item_append_text(option_item, " = %s", val_to_str_const(value_u32, option_code_darwin_svc_class_vals, "Unknown"));

                break;
            case 32771: /* Darwin Effective DPEB ID */
                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_packet_darwin_edpeb_id, tvb, offset, option_length, encoding, &value_u32);
                offset += option_length;

                proto_item_append_text(option_item, " = %u", value_u32);

                break;
            case 32772: /* Darwin Flags */
                proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_packet_darwin_flags, ett_pcapng_option, hfx_pcapng_option_data_packet_darwin_flags, encoding);
                offset += option_length;

                break;
            case 32773: /* Darwin Flow ID */
                proto_tree_add_item_ret_uint(option_tree, hf_pcapng_option_data_packet_darwin_flow_id, tvb, offset, option_length, encoding, &value_u32);
                offset += option_length;

                proto_item_append_text(option_item, " = %u", value_u32);

                break;
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
            }

            break;

        default:
            /* Use local block handling if available */
            if (p_local_block_callback) {
                 p_local_block_callback->option_dissector(option_tree, option_item, pinfo, tvb, offset,
                                                          hf_pcapng_option_data, option_code, option_length, encoding);
            }
            else {
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
            }
            offset += option_length;
        }

        /* Pad this option out to next 4 bytes */
        if ((option_length % 4) != 0) {
            proto_item_set_len(option_item, option_length + 2 * 2 + (4 - option_length % 4));
            option_length = 4 - option_length % 4;
            proto_tree_add_item(option_tree, hf_pcapng_option_padding, tvb, offset, option_length, ENC_NA);
            offset += option_length;
        } else
            proto_item_set_len(option_item, option_length + 2 * 2);
    }
    proto_item_set_end(options_item, tvb, offset);

    return offset;
}

static void
pcapng_add_timestamp(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
        int offset, unsigned encoding,
        struct interface_description *interface_description)
{
    proto_tree_add_item(tree, hf_pcapng_timestamp_high, tvb, offset, 4, encoding);
    proto_tree_add_item(tree, hf_pcapng_timestamp_low, tvb, offset + 4, 4, encoding);

    if (interface_description != NULL) {
        nstime_t    timestamp;
        uint64_t    ts;
        proto_item *ti;

        ts = ((uint64_t)(tvb_get_uint32(tvb, offset, encoding))) << 32 |
                        tvb_get_uint32(tvb, offset + 4, encoding);

        ts += interface_description->timestamp_offset;

        if (interface_description->timestamp_resolution == 0) {
            /* This overflowed, so we can't calculate the time stamp */
            pinfo->presence_flags &= ~PINFO_HAS_TS;
        } else {
            timestamp.secs  = (time_t)(ts / interface_description->timestamp_resolution);
            timestamp.nsecs = (int)(((ts % interface_description->timestamp_resolution) * 1000000000) / interface_description->timestamp_resolution);

            ti = proto_tree_add_time(tree, hf_pcapng_timestamp, tvb, offset, 8, &timestamp);
            proto_item_set_generated(ti);

            pinfo->abs_ts = timestamp;
        }
    }
}

static struct interface_description *
get_interface_description(struct info *info, unsigned interface_id,
    packet_info *pinfo, proto_tree *tree)
{
    if (interface_id >= wmem_array_get_count(info->interfaces)) {
        expert_add_info(pinfo, tree, &ei_missing_idb);
        return NULL;
    }
    return (struct interface_description *) wmem_array_index(info->interfaces, interface_id);
}

/*
 * This is tricky - for most blocks, we can dissect this first, but, for
 * a Section Header Block, we must dissect it *after* determining the
 * byte order.
 *
 * So we extract it into a routine and call it at the appropriate time.
 */
static tvbuff_t *
process_block_length(proto_tree *block_tree, packet_info *pinfo,
                     tvbuff_t *tvb, int offset, proto_tree **block_data_tree_p,
                     proto_item **block_length_item_p, uint32_t *block_length_p,
                     unsigned encoding)
{
    proto_item      *block_data_item;
    uint32_t         block_data_length;

    *block_length_item_p = proto_tree_add_item_ret_uint(block_tree, hf_pcapng_block_length, tvb, offset, 4, encoding, block_length_p);
    if (*block_length_p < 3*4) {
        expert_add_info(pinfo, *block_length_item_p, &ei_block_length_below_block_minimum);
        return NULL;
    }
    /*
     * To quote the current pcapng spec, "Block Total Length (32 bits) ...
     * This value MUST be a multiple of 4."
     */
    if ((*block_length_p % 4) != 0) {
        expert_add_info(pinfo, *block_length_item_p, &ei_block_length_not_multiple_of_4);
        return NULL;
    }

    /*
     * Subtract the per-block overhead (block type, block length, trailing
     * block length) to give the length of the block data.
     * block.
     */
    block_data_length = *block_length_p - 3*4;

    /*
     * Now that we know the block data length, create an item for its
     * tree, and provide the tree to our caller.
     */
    offset += 4;
    block_data_item = proto_tree_add_item(block_tree, hf_pcapng_block_data, tvb, offset, block_data_length, ENC_NA);
    *block_data_tree_p = proto_item_add_subtree(block_data_item, ett_pcapng_block_data);

    /*
     * Create a tvbuff for the block data, and provide it to our caller.
     */
    return tvb_new_subset_length(tvb, offset, block_data_length);
}



static bool
dissect_shb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 bool byte_order_magic_bad, block_data_arg *argp)
{
    int offset = 0;
    proto_item      *byte_order_magic_item;

    byte_order_magic_item = proto_tree_add_item(tree, hf_pcapng_section_header_byte_order_magic, tvb, offset, 4, ENC_NA);
    if (byte_order_magic_bad) {
        expert_add_info(pinfo, byte_order_magic_item, &ei_invalid_byte_order_magic);
        return false;
    }
    if (argp->info->encoding == ENC_BIG_ENDIAN)
        proto_item_append_text(byte_order_magic_item, " (Big-endian)");
    else
        proto_item_append_text(byte_order_magic_item, " (Little-endian)");
    offset += 4;

    proto_tree_add_item(tree, hf_pcapng_section_header_major_version, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    proto_tree_add_item(tree, hf_pcapng_section_header_minor_version, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    proto_tree_add_item(tree, hf_pcapng_section_header_section_length, tvb, offset, 8, argp->info->encoding);
    offset += 8;

    dissect_options(tree, pinfo, BLOCK_TYPE_SHB, tvb, offset, argp->info->encoding, NULL);

    return true;
}

static void
dissect_idb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    int offset = 0;
    struct interface_description  interface_description;

    memset(&interface_description, 0, sizeof(struct interface_description));
    interface_description.timestamp_resolution = 1000000; /* 1 microsecond resolution is the default */

    proto_item_append_text(argp->block_item, " %u", argp->info->interface_number);
    argp->info->interface_number += 1;

    proto_tree_add_item(tree, hf_pcapng_interface_description_link_type, tvb, offset, 2, argp->info->encoding);
    interface_description.link_type = tvb_get_uint16(tvb, offset, argp->info->encoding);
    offset += 2;

    proto_tree_add_item(tree, hf_pcapng_interface_description_reserved, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    proto_tree_add_item(tree, hf_pcapng_interface_description_snap_length, tvb, offset, 4, argp->info->encoding);
    interface_description.snap_len = tvb_get_uint32(tvb, offset, argp->info->encoding);
    offset += 4;

    dissect_options(tree, pinfo, BLOCK_TYPE_IDB, tvb, offset, argp->info->encoding, &interface_description);

    wmem_array_append_one(argp->info->interfaces, interface_description);
}

static void
dissect_pb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                block_data_arg *argp)
{
    volatile int offset = 0;
    uint32_t interface_id;
    struct interface_description *interface_description;
    uint32_t captured_length;
    uint32_t original_length;
    proto_item *packet_data_item;

    proto_item_append_text(argp->block_item, " %u", argp->info->frame_number);

    proto_tree_add_item(tree, hf_pcapng_packet_block_interface_id, tvb, offset, 2, argp->info->encoding);
    interface_id = tvb_get_uint16(tvb, offset, argp->info->encoding);
    offset += 2;
    interface_description = get_interface_description(argp->info, interface_id,
                                                      pinfo, argp->block_tree);

    proto_tree_add_item(tree, hf_pcapng_packet_block_drops_count, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    pcapng_add_timestamp(tree, pinfo, tvb, offset, argp->info->encoding, interface_description);
    offset += 8;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_captured_length, tvb, offset, 4, argp->info->encoding, &captured_length);
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_original_length, tvb, offset, 4, argp->info->encoding, &original_length);
    offset += 4;

    packet_data_item = proto_tree_add_item(tree, hf_pcapng_packet_data, tvb, offset, captured_length, argp->info->encoding);

    if (pref_dissect_next_layer && interface_description != NULL) {
        proto_tree *packet_data_tree = proto_item_add_subtree(packet_data_item, ett_pcapng_packet_data);

        pinfo->num = argp->info->frame_number;

        TRY {
            call_dissector_with_data(pcap_pktdata_handle, tvb_new_subset_length_caplen(tvb, offset, captured_length, original_length),
                                     pinfo, packet_data_tree, &interface_description->link_type);
        }
        CATCH_BOUNDS_ERRORS {
            show_exception(tvb, pinfo, packet_data_tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
    }
    argp->info->frame_number += 1;
    offset += captured_length;

    if (captured_length % 4) {
        proto_tree_add_item(tree, hf_pcapng_packet_padding, tvb, offset, ((captured_length % 4) ? (4 - (captured_length % 4)) : 0), ENC_NA);
        offset += ((captured_length % 4) ?(4 - (captured_length % 4)):0);
    }

    dissect_options(tree, pinfo, BLOCK_TYPE_PB, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_spb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    volatile int offset = 0;
    struct interface_description *interface_description;
    proto_item *ti;
    volatile uint32_t captured_length;
    uint32_t original_length;
    proto_item *packet_data_item;

    interface_description = get_interface_description(argp->info, 0,
                                                      pinfo, argp->block_tree);

    proto_item_append_text(argp->block_item, " %u", argp->info->frame_number);

    proto_tree_add_item_ret_uint(tree, hf_pcapng_original_length, tvb, offset, 4, argp->info->encoding, &original_length);
    offset += 4;

    captured_length = original_length;
    if (interface_description && interface_description->snap_len != 0) {
        captured_length = MIN(original_length, interface_description->snap_len);
    }
    ti = proto_tree_add_uint(tree, hf_pcapng_captured_length, tvb, 0, 0, captured_length);
    proto_item_set_generated(ti);

    packet_data_item = proto_tree_add_item(tree, hf_pcapng_packet_data, tvb, offset, captured_length, argp->info->encoding);

    if (pref_dissect_next_layer && interface_description != NULL) {
        proto_tree *packet_data_tree = proto_item_add_subtree(packet_data_item, ett_pcapng_packet_data);

        pinfo->num = argp->info->frame_number;

        TRY {
            call_dissector_with_data(pcap_pktdata_handle, tvb_new_subset_length(tvb, offset, captured_length),
                                     pinfo, packet_data_tree, &interface_description->link_type);
        }
        CATCH_BOUNDS_ERRORS {
            show_exception(tvb, pinfo, packet_data_tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
    }
    argp->info->frame_number += 1;
    offset += captured_length;

    if (captured_length % 4) {
        proto_tree_add_item(tree, hf_pcapng_packet_padding, tvb, offset, ((captured_length % 4)?(4 - (captured_length % 4)):0), ENC_NA);
        offset += ((captured_length % 4) ? (4 - (captured_length % 4)):0);
    }
}

static void
dissect_nrb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    int offset = 0;
    proto_tree  *records_tree;
    proto_item  *records_item;
    proto_tree  *record_tree;
    proto_item  *record_item;
    proto_item  *record_length_item;
    int          offset_string_start;
    uint32_t     record_code;
    uint32_t     record_length;
    int          string_length;
    char        *str = NULL;
    address      addr;

    records_item = proto_tree_add_item(tree, hf_pcapng_records, tvb, offset, -1, ENC_NA);
    records_tree = proto_item_add_subtree(records_item, ett_pcapng_records);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        record_item = proto_tree_add_item(records_tree, hf_pcapng_record, tvb, offset, -1, ENC_NA);
        record_tree = proto_item_add_subtree(record_item, ett_pcapng_record);

        proto_tree_add_item_ret_uint(record_tree, hf_pcapng_record_code, tvb, offset, 2, argp->info->encoding, &record_code);
        proto_item_append_text(record_item, ": %s", val_to_str_const(record_code, record_code_vals, "Unknown"));
        offset += 2;

        record_length_item = proto_tree_add_item_ret_uint(record_tree, hf_pcapng_record_length, tvb, offset, 2, argp->info->encoding, &record_length);
        offset += 2;

        if (record_code == 0) {
            if (record_length != 0)
                expert_add_info(pinfo, record_length_item, &ei_invalid_record_length);
            proto_item_set_len(record_item, record_length + 2 * 2);
            break;
        } else switch (record_code) {
        case 0x0001: /* IPv4 Record */
            if (record_length < 5) {
                expert_add_info(pinfo, record_length_item, &ei_invalid_record_length);
                offset += record_length;
                break;
            }

            proto_tree_add_item(record_tree, hf_pcapng_record_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            set_address_tvb(&addr, AT_IPv4, 4, tvb, offset);
            offset += 4;

            offset_string_start = offset;
            while ((unsigned)(offset - offset_string_start) < record_length - 4) {
                string_length = tvb_strnlen(tvb, offset, (offset - offset_string_start) + record_length - 4);
                if (string_length >= 0) {
                    proto_tree_add_item(record_tree, hf_pcapng_record_name, tvb, offset, string_length + 1, argp->info->encoding);
                    offset += string_length + 1;
                } else {
                    /*
                     * XXX - flag with an error, as this means we didn't
                     * see a terminating NUL, but the spec says "zero
                     * or more zero-terminated UTF-8 strings containing
                     * the DNS entries for that address".
                     */
                    proto_tree_add_item(record_tree, hf_pcapng_record_data, tvb, offset, (record_length - 4) - (offset - offset_string_start), argp->info->encoding);
                    offset += (record_length - 4) - (offset - offset_string_start);
                }
            }

            str = address_to_display(pinfo->pool, &addr);
            break;
        case 0x0002: /* IPv6 Record */
            if (record_length < 17) {
                expert_add_info(pinfo, record_length_item, &ei_invalid_record_length);
                offset += record_length;
                break;
            }

            proto_tree_add_item(record_tree, hf_pcapng_record_ipv6, tvb, offset, 16, ENC_NA);
            set_address_tvb(&addr, AT_IPv6, 16, tvb, offset);
            offset += 16;

            offset_string_start = offset;
            while ((unsigned)(offset - offset_string_start) < record_length - 16) {
                string_length = tvb_strnlen(tvb, offset, (offset - offset_string_start) + record_length - 16);
                if (string_length >= 0) {
                    proto_tree_add_item(record_tree, hf_pcapng_record_name, tvb, offset, string_length + 1, argp->info->encoding);
                    offset += string_length + 1;
                } else {
                    /*
                     * XXX - flag with an error, as this means we didn't
                     * see a terminating NUL, but the spec says "zero
                     * or more zero-terminated UTF-8 strings containing
                     * the DNS entries for that address".
                     */
                    proto_tree_add_item(record_tree, hf_pcapng_record_data, tvb, offset, (record_length - 16) - (offset - offset_string_start), argp->info->encoding);
                    offset += (record_length - 16) - (offset - offset_string_start);
                }
            }

            str = address_to_display(pinfo->pool, &addr);

            break;
        default:
            proto_tree_add_item(record_tree, hf_pcapng_record_data, tvb, offset, record_length, ENC_NA);
            offset += record_length;
        }

        if (record_code != 0 && record_length % 4) {
            proto_item_set_len(record_item, record_length + 2 * 2 + (4 - record_length % 4));
            record_length = 4 - record_length % 4;
            proto_tree_add_item(record_tree, hf_pcapng_record_padding, tvb, offset, record_length, ENC_NA);
            offset += record_length;
        } else
            proto_item_set_len(record_item, record_length + 2 * 2);

        if (str)
            proto_item_append_text(record_item, " = %s", str);
    }
    proto_item_set_end(records_item, tvb, offset);

    dissect_options(tree, pinfo, BLOCK_TYPE_NRB, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_isb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    int offset = 0;
    uint32_t interface_id;
    struct interface_description *interface_description;

    proto_tree_add_item(tree, hf_pcapng_interface_id, tvb, offset, 4, argp->info->encoding);
    interface_id = tvb_get_uint32(tvb, offset, argp->info->encoding);
    offset += 4;
    interface_description = get_interface_description(argp->info, interface_id,
                                                      pinfo, argp->block_tree);

    pcapng_add_timestamp(tree, pinfo, tvb, offset, argp->info->encoding, interface_description);
    offset += 8;

    dissect_options(tree, pinfo, BLOCK_TYPE_ISB, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_epb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    volatile int offset = 0;
    uint32_t interface_id;
    struct interface_description *interface_description;
    uint32_t captured_length;
    uint32_t original_length;
    proto_item *packet_data_item;

    proto_item_append_text(argp->block_item, " %u", argp->info->frame_number);

    proto_tree_add_item(tree, hf_pcapng_interface_id, tvb, offset, 4, argp->info->encoding);
    interface_id = tvb_get_uint32(tvb, offset, argp->info->encoding);
    offset += 4;
    interface_description = get_interface_description(argp->info, interface_id,
                                                      pinfo, argp->block_tree);

    pcapng_add_timestamp(tree, pinfo, tvb, offset, argp->info->encoding, interface_description);
    offset += 8;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_captured_length, tvb, offset, 4, argp->info->encoding, &captured_length);
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_original_length, tvb, offset, 4, argp->info->encoding, &original_length);
    offset += 4;

    packet_data_item = proto_tree_add_item(tree, hf_pcapng_packet_data, tvb, offset, captured_length, argp->info->encoding);

    if (pref_dissect_next_layer && interface_description != NULL) {
        proto_tree *packet_data_tree = proto_item_add_subtree(packet_data_item, ett_pcapng_packet_data);

        pinfo->num = argp->info->frame_number;

        TRY {
            call_dissector_with_data(pcap_pktdata_handle, tvb_new_subset_length_caplen(tvb, offset, captured_length, original_length),
                                     pinfo, packet_data_tree, &interface_description->link_type);
        }
        CATCH_BOUNDS_ERRORS {
            show_exception(tvb, pinfo, packet_data_tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
    }
    argp->info->frame_number += 1;
    offset += captured_length;

    if (captured_length % 4) {
        proto_tree_add_item(tree, hf_pcapng_packet_padding, tvb, offset, ((captured_length % 4)? (4 - (captured_length % 4)):0), ENC_NA);
        offset += ((captured_length % 4) ?(4 - (captured_length % 4)):0);
    }

    dissect_options(tree, pinfo, BLOCK_TYPE_EPB, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_dsb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    int offset = 0;
    uint32_t secrets_length;

    proto_tree_add_item(tree, hf_pcapng_dsb_secrets_type, tvb, offset, 4, argp->info->encoding);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_pcapng_dsb_secrets_length, tvb, offset, 4, argp->info->encoding, &secrets_length);
    offset += 4;
    proto_tree_add_item(tree, hf_pcapng_dsb_secrets_data, tvb, offset, secrets_length, argp->info->encoding);
    offset += secrets_length;

    uint32_t padlen = (4 - (secrets_length & 3)) & 3;
    if (padlen) {
        proto_tree_add_item(tree, hf_pcapng_record_padding, tvb, offset, padlen, ENC_NA);
        offset += padlen;
    }

    dissect_options(tree, pinfo, BLOCK_TYPE_DSB, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_cb_data(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb,
                block_data_arg *argp)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_pcapng_cb_pen, tvb, offset, 4, argp->info->encoding);
    offset += 4;

    /* Todo: Add known PEN custom data dissection. */
    proto_tree_add_item(tree, hf_pcapng_cb_data, tvb, offset, tvb_reported_length(tvb) - offset, argp->info->encoding);

    /*
     * The pcapng spec does not tell the size of the custom data without knowing the data content,
     * so it's not possible to dissect options.
     *
     * dissect_options(tree, pinfo, BLOCK_CB_COPY, tvb, offset, argp->info->encoding, NULL);
     */
}

#define BLOCK_BAD_SHB_SIZE 12

int dissect_block(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, struct info *info)
{
    proto_tree      *block_tree, *block_type_tree;
    proto_item      *block_item, *block_type_item;
    proto_tree      *block_data_tree;
    proto_item      *block_length_item;
    proto_item      *block_length_trailer_item;
    int              offset = 0;
    uint32_t         block_type;
    uint32_t         block_length, block_length_trailer;
    uint32_t         length;
    tvbuff_t        *volatile next_tvb = NULL;
    block_data_arg   arg;
    volatile bool stop_dissecting = false;
    volatile bool byte_order_magic_bad = false;

    block_type = tvb_get_uint32(tvb, offset + 0, info->encoding);
    length     = tvb_get_uint32(tvb, offset + 4, info->encoding);

    /* Lookup handlers for known local block type */
    local_block_callback_info_t *volatile p_local_block_callback = NULL;
    if (block_type >= 0x80000000) {
        p_local_block_callback = (local_block_callback_info_t*)g_hash_table_lookup(s_local_block_callback_table, GUINT_TO_POINTER(block_type));
    }

    /* Create block tree */
    block_item = proto_tree_add_item(tree, hf_pcapng_block, tvb, offset, length, ENC_NA);
    block_tree = proto_item_add_subtree(block_item, ett_pcapng_section_header_block);

    /* Block type */
    block_type_item = proto_tree_add_item(block_tree, hf_pcapng_block_type, tvb, offset, 4, info->encoding);
    block_type_tree = proto_item_add_subtree(block_type_item, ett_pcapng_block_type);

    proto_tree_add_item(block_type_tree, hf_pcapng_block_type_vendor, tvb, offset, 4, info->encoding);
    proto_item *block_type_value_item = proto_tree_add_item(block_type_tree, hf_pcapng_block_type_value, tvb, offset, 4, info->encoding);
    offset += 4;

    /* Name is either from local 'name', or from fixed block_type_vals */
    if (p_local_block_callback) {
        proto_item_append_text(block_item, " %u: %s", info->block_number, p_local_block_callback->name);
        proto_item_append_text(block_type_item, ": (%s)", p_local_block_callback->name);
        proto_item_append_text(block_type_value_item, ": (%s)", p_local_block_callback->name);
    }
    else {
        proto_item_append_text(block_item, " %u: %s", info->block_number, val_to_str_const(block_type, block_type_vals, "Unknown"));
        proto_item_append_text(block_type_item, ": (%s)", val_to_str_const(block_type, block_type_vals, "Unknown"));
        proto_item_append_text(block_type_value_item, ": (%s)", val_to_str_const(block_type, block_type_vals, "Unknown"));
    }
    info->block_number += 1;

    arg.block_item = block_item;
    arg.block_tree = block_tree;
    arg.info = info;

    if (block_type == BLOCK_TYPE_SHB && tvb_captured_length(tvb) == BLOCK_BAD_SHB_SIZE) {
        /*
         * dissect_pcapng() gave us a short SHB because its byte-order magic is bad.
         * process_block_length() would fail, so generate an abbreviated TVB
         * to pass to dissect_shb_data() which will flag up the bad magic.
         */
        byte_order_magic_bad = true;
        next_tvb = tvb_new_subset_length(tvb, 8, 4);
        block_data_tree = block_tree;
        block_length_item = NULL;
    }
    else {
        next_tvb = process_block_length(block_tree, pinfo, tvb, offset, &block_data_tree, &block_length_item, &block_length, info->encoding);
        if (next_tvb == NULL) {
            /* The length was invalid, so we can't dissect any further */
            return -1;
        }
    }
    offset += 4;

    /*
     * Dissect the block data.
     * Catch exceptions; ReportedBoundsError means that the body
     * doesn't fit in the block.
     */
    TRY {
        switch (block_type) {
        case BLOCK_TYPE_SHB:
            proto_item_append_text(block_item, " %u", info->section_number);
            if (!dissect_shb_data(block_data_tree, pinfo, next_tvb, byte_order_magic_bad, &arg)) {
                stop_dissecting = true;
            }
            break;
        case BLOCK_TYPE_IDB:
            dissect_idb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_PB:
            dissect_pb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_SPB:
            dissect_spb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_NRB:
            dissect_nrb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_ISB:
            dissect_isb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_EPB:
            dissect_epb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_DSB:
            dissect_dsb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_CB_COPY:
        case BLOCK_TYPE_CB_NO_COPY:
            dissect_cb_data(block_data_tree, pinfo, next_tvb, &arg);
            break;
        case BLOCK_TYPE_IRIG_TS:
        case BLOCK_TYPE_ARINC_429:
            break;

        default:
            /* Use local block type handling if available */
            if (p_local_block_callback) {
                p_local_block_callback->dissector(block_data_tree, pinfo, next_tvb, &arg);
            }
            break;
        }
    }
    CATCH(ReportedBoundsError) {
        /*
            * The body didn't fit in the block.
            * Mark the length as being too small.
            */
        expert_add_info(pinfo, block_length_item, &ei_block_length_below_block_content_length);
    }
    CATCH_ALL {
        /*
            * Just rethrow other exceptions to the ultimate handler.
            */
        RETHROW;
    }
    ENDTRY;

    if (stop_dissecting) {
        /* We found a fatal problem with the file. */
        return -1;
    }

    /*
     * Skip past the block data.
     */
    offset += tvb_reported_length(next_tvb);

    block_length_trailer_item = proto_tree_add_item_ret_uint(block_tree, hf_pcapng_block_length_trailer, tvb, offset, 4, info->encoding, &block_length_trailer);
    if (block_length != block_length_trailer)
        expert_add_info(pinfo, block_length_trailer_item, &ei_block_lengths_dont_match);
    offset += 4;

    return offset;
}

#define BLOCK_TYPE_SIZE        4

static int
dissect_pcapng(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static const uint8_t pcapng_premagic[BLOCK_TYPE_SIZE] = {
        0x0A, 0x0D, 0x0D, 0x0A
    };
    int              offset = 0;
    uint32_t         length;
    uint32_t         block_type;
    proto_tree      *main_tree;
    proto_item      *main_item;
    struct info      info;
    volatile bool byte_order_magic_bad = false;

    if (tvb_memeql(tvb, 0, pcapng_premagic, BLOCK_TYPE_SIZE) != 0)
        return 0;

    info.encoding = ENC_BIG_ENDIAN;
    info.block_number = 1;
    info.section_number = 0;
    info.interface_number = 0;
    info.darwin_process_event_number = 0;
    info.frame_number = 1;
    info.interfaces = NULL;
    info.darwin_process_events = wmem_array_new(pinfo->pool, sizeof(struct darwin_process_event_description));

    main_item = proto_tree_add_item(tree, proto_pcapng, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_pcapng);

    while (tvb_captured_length_remaining(tvb, offset) > 8) {
        tvbuff_t  *next_tvb;
        int       block_length;

        block_type = tvb_get_uint32(tvb, offset, info.encoding);
        if (block_type == BLOCK_TYPE_SHB) {
            info.section_number += 1;
            info.interface_number = 0;
            info.darwin_process_event_number = 0;
            info.frame_number = 1;
            if (info.interfaces != NULL) {
                wmem_free(pinfo->pool, info.interfaces);
            }
            info.interfaces = wmem_array_new(pinfo->pool, sizeof(struct interface_description));

            /* Byte order may change from that of previous SHB [#19371] */
            if (tvb_memeql(tvb, offset + 8, pcapng_big_endian_magic, BYTE_ORDER_MAGIC_SIZE) == 0) {
                info.encoding = ENC_BIG_ENDIAN;
            } else if (tvb_memeql(tvb, offset + 8, pcapng_little_endian_magic, BYTE_ORDER_MAGIC_SIZE) == 0) {
                info.encoding = ENC_LITTLE_ENDIAN;
            } else {
                byte_order_magic_bad = true;
                if (offset == 0) {
                    return 0;
                }
            }
        }

        if (G_UNLIKELY(byte_order_magic_bad)) {
            /* Pass a shortened TVB that's just big enough to let
             * dissect_block() mark the SHB's byte order magic as bad.
             */
            length = BLOCK_BAD_SHB_SIZE;
        }
        else {
            length = tvb_get_uint32(tvb, offset + 4, info.encoding);
        }
        next_tvb = tvb_new_subset_length(tvb, offset, length);

        block_length = dissect_block(main_tree, pinfo, next_tvb, &info);
        if (block_length == -1) {
            /* Fatal error. */
            break;
        }
        offset += block_length;
    }

    return offset;
}

static void pcapng_shutdown_protocol(void)
{
    /* Create table for local block dissectors */
    g_hash_table_destroy(s_local_block_callback_table);
    s_local_block_callback_table = NULL;
}

static bool
dissect_pcapng_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_pcapng(tvb, pinfo, tree, data) > 0;
}

/* Expected to be called by an external dissector.  For an in-tree example, please see file-pcap-darwin.c */
void register_pcapng_local_block_dissector(uint32_t block_number, local_block_callback_info_t *block_callback_info)
{
    /* Add this entry into table. */
    g_hash_table_insert(s_local_block_callback_table, GUINT_TO_POINTER(block_number), block_callback_info);
}

void
proto_register_pcapng(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_pcapng_block,
            { "Block",                                     "pcapng.block",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_block_type,
            { "Block Type",                                "pcapng.block.type",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_block_type_vendor,
            { "Block Type Vendor",                         "pcapng.block.type.vendor",
            FT_BOOLEAN, 32, NULL, 0x80000000,
            NULL, HFILL }
        },
        { &hf_pcapng_block_type_value,
            { "Block Type Value",                          "pcapng.block.type.value",
            FT_UINT32, BASE_HEX, NULL, 0x7FFFFFFF,
            NULL, HFILL }
        },
        { &hf_pcapng_block_length,
            { "Block Length",                              "pcapng.block.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_block_length_trailer,
            { "Block Length (trailer)",                    "pcapng.block.length_trailer",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_block_data,
            { "Block Data",                                "pcapng.block.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_options,
            { "Options",                                   "pcapng.options",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option,
            { "Option",                                    "pcapng.options.option",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_interface_description,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_interface_description_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_enhanced_packet,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_enhanced_packet_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_packet,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_packet_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_name_resolution,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_name_resolution_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_interface_statistics,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_interface_statistics_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_length,
            { "Length",                                    "pcapng.options.option.length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data,
            { "Option Data",                               "pcapng.options.option.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_padding,
            { "Option Padding",                            "pcapng.options.option.padding",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_comment,
            { "Comment",                                   "pcapng.options.option.data.comment",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_section_header_byte_order_magic,
            { "Byte Order Magic",                          "pcapng.section_header.byte_order_magic",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_section_header_major_version,
            { "Major Version",                             "pcapng.section_header.version.major",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_section_header_minor_version,
            { "Minor Version",                             "pcapng.section_header.version.minor",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_section_header_section_length,
            { "Section Length",                            "pcapng.section_header.section_length",
            FT_INT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_section_header,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_section_header_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_section_header_hardware,
            { "Hardware",                                  "pcapng.options.option.data.hardware",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_section_header_os,
            { "OS",                                        "pcapng.options.option.data.os",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_section_header_user_application,
            { "User Application",                          "pcapng.options.option.data.user_application",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_description_name,
            { "Name",                                      "pcapng.options.option.data.interface.name",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_description_description,
            { "Description",                               "pcapng.options.option.data.interface.description",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_ipv4,
            { "IPv4",                                      "pcapng.options.option.data.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_ipv4_mask,
            { "IPv4 Mask",                                 "pcapng.options.option.data.ipv4_mask",
            FT_IPv4, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_ipv6,
            { "IPv6",                                      "pcapng.options.option.data.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_ipv6_mask,
            { "IPv6 Mask",                                 "pcapng.options.option.data.ipv6_mask",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_mac_address,
            { "MAC Address",                               "pcapng.options.option.data.mac",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_eui_address,
            { "EUI Address",                               "pcapng.options.option.data.eui",
            FT_EUI64, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_speed,
            { "Speed",                                     "pcapng.options.option.data.interface.speed",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_timestamp_resolution,
            { "Timestamp Resolution",                      "pcapng.options.option.data.interface.timestamp_resolution",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_timestamp_resolution_base,
            { "Base",                                      "pcapng.options.option.data.interface.timestamp_resolution.base",
            FT_UINT8, BASE_HEX, VALS(timestamp_resolution_base_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_timestamp_resolution_value,
            { "Value",                                     "pcapng.options.option.data.interface.timestamp_resolution.value",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_timezone,
            { "Timezone",                                  "pcapng.options.option.data.interface.timezone",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_filter_type,
            { "Filter type",                               "pcapng.options.option.data.interface.filter.type",
            FT_UINT8, BASE_DEC, VALS(interface_filter_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_filter_string,
            { "Filter string",                             "pcapng.options.option.data.interface.filter.string",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_filter_bpf_program,
            { "Filter BPF program",                        "pcapng.options.option.data.interface.filter.bpf_program",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_filter_unknown,
            { "Filter data",                               "pcapng.options.option.data.interface.filter.unknown",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_os,
            { "OS",                                        "pcapng.options.option.data.interface.os",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_hardware,
            { "Hardware",                                  "pcapng.options.option.data.interface.hardware",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_fcs_length,
            { "FCS Length",                                "pcapng.options.option.data.interface.fcs_length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_timestamp_offset,
            { "Timestamp Offset",                          "pcapng.options.option.data.interface.timestamp_offset",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_verdict_type,
            { "Verdict type",                              "pcapng.options.option.data.packet.verdict.type",
            FT_UINT8, BASE_DEC, VALS(packet_verdict_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_verdict_data,
            { "Verdict data",                              "pcapng.options.option.data.packet.verdict.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_queue,
            { "Queue",                                     "pcapng.options.option.data.packet.queue",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_id,
            { "Packet ID",                                 "pcapng.options.option.data.packet.id",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_drop_count,
            { "Drop Count",                                "pcapng.options.option.data.packet.drop_count",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_hash_algorithm,
            { "Hash Algorithm",                            "pcapng.options.option.data.packet.hash.algorithm",
            FT_UINT8, BASE_DEC, VALS(packet_hash_algorithm_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_hash_data,
            { "Hash Data",                                 "pcapng.options.option.data.packet.hash.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors,
            { "Link Layer Errors",                         "pcapng.options.option.data.packet.flags.link_layer_errors",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_symbol,
            { "Symbol Error",                              "pcapng.options.option.data.packet.flags.link_layer_errors.symbol",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_preamble,
            { "Preamble Error",                            "pcapng.options.option.data.packet.flags.link_layer_errors.preamble",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_start_frame_delimiter,
            { "Start Frame Delimiter Error",               "pcapng.options.option.data.packet.flags.link_layer_errors.start_frame_delimiter",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_unaligned_frame,
            { "Unaligned Frame Error",                     "pcapng.options.option.data.packet.flags.link_layer_errors.unaligned_frame",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_wrong_inter_frame_gap,
            { "Wrong Inter Frame Gap",                     "pcapng.options.option.data.packet.flags.link_layer_errors.wrong_inter_frame_gap",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_short,
            { "Packet Too Short",                          "pcapng.options.option.data.packet.flags.link_layer_errors.packet_too_short",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_long,
            { "Packet Too Long",                           "pcapng.options.option.data.packet.flags.link_layer_errors.packet_too_long",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_crc_error,
            { "CRC Error",                                 "pcapng.options.option.data.packet.flags.link_layer_errors.crc",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_link_layer_errors_reserved,
            { "Reserved",                                  "pcapng.options.option.data.packet.flags.link_layer_errors.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x00FF,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags,
            { "Flags",                                     "pcapng.options.option.data.packet.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_reserved,
            { "Reserved",                                  "pcapng.options.option.data.packet.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFE00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_fcs_length,
            { "FCS Length",                                "pcapng.options.option.data.packet.flags.fcs_length",
            FT_UINT16, BASE_DEC, NULL, 0x01E0,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_reception_type,
            { "Reception Type",                            "pcapng.options.option.data.packet.flags.reception_type",
            FT_UINT16, BASE_HEX, VALS(flags_reception_type_vals), 0x001C,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_flags_direction,
            { "Direction",                                 "pcapng.options.option.data.packet.flags.direction",
            FT_UINT16, BASE_HEX, VALS(packet_flags_direction_vals), 0x0003,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_dpeb_id,
            { "DPEB ID",                                   "pcapng.options.option.data.packet.darwin.dpeb_id",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_svc_class,
            { "Darwin svc",                                "pcapng.options.option.data.packet.darwin.svc_class",
            FT_UINT32, BASE_DEC, VALS(option_code_darwin_svc_class_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_edpeb_id,
            { "Effective DPED ID",                         "pcapng.options.option.data.packet.darwin.edpeb_id",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags,
            { "Darwin Flags",                              "pcapng.options.option.data.packet.darwin.flags",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_reserved,
            { "Reserved",                                  "pcapng.options.option.data.packet.darwin.flags.reserved",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0xFFFFFFC0,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_wk,
            { "Wake Packet(wk)",                           "pcapng.options.option.data.packet.darwin.flags.wk",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_ch,
            { "Nexus Channel(ch)",                         "pcapng.options.option.data.packet.darwin.flags.ch",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_so,
            { "Socket(so)",                                "pcapng.options.option.data.packet.darwin.flags.so",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_re,
            { "ReXmit(re)",                                "pcapng.options.option.data.packet.darwin.flags.re",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_ka,
            { "Keep Alive(ka)",                            "pcapng.options.option.data.packet.darwin.flags.ka",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_nf,
            { "New Flow(nf)",                              "pcapng.options.option.data.packet.darwin.flags.nf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flow_id,
            { "Flow ID",                                   "pcapng.options.option.data.packet.darwin.flow_id",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_dns_name,
            { "DNS Name",                                  "pcapng.options.option.data.dns_name",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_start_time,
            { "Start Time",                                "pcapng.options.option.data.start_time",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_end_time,
            { "End Time",                                  "pcapng.options.option.data.end_time",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_received,
            { "Number of Received Packets",                "pcapng.options.option.data.interface.received",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_dropped,
            { "Number of Dropped Packets",                 "pcapng.options.option.data.interface.dropped",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_accepted_by_filter,
            { "Number of Accepted by Filter Packets",      "pcapng.options.option.data.interface.accepted_by_filter",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_dropped_by_os,
            { "Number of Dropped Packets by OS",           "pcapng.options.option.data.interface.dropped_by_os",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_interface_delivered_to_user,
            { "Number of Delivered to the User Packets",   "pcapng.options.option.data.interface.delivered_to_user",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_interface_description_link_type,
            { "Link Type",                                 "pcapng.interface_description.link_type",
            FT_UINT16, BASE_DEC_HEX, VALS(link_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_interface_description_reserved,
            { "Reserved",                                  "pcapng.interface_description.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_interface_description_snap_length,
            { "Snap Length",                               "pcapng.interface_description.snap_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_packet_block_interface_id,
            { "Interface",                                 "pcapng.packet.interface_id",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_packet_block_drops_count,
            { "Drops Count",                               "pcapng.packet.drops_count",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_captured_length,
            { "Captured Packet Length",                    "pcapng.packet.captured_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_original_length,
            { "Original Packet Length",                    "pcapng.packet.original_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_packet_data,
            { "Packet Data",                               "pcapng.packet.packet_data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_packet_padding,
            { "Packet Padding",                            "pcapng.packet.padding",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_interface_id,
            { "Interface",                                 "pcapng.interface_id",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_timestamp_high,
            { "Timestamp (High)",                          "pcapng.timestamp_high",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_timestamp_low,
            { "Timestamp (Low)",                           "pcapng.timestamp_low",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_timestamp,
            { "Timestamp",                                 "pcapng.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_records,
            { "Records",                                   "pcapng.records",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record,
            { "Record",                                    "pcapng.records.record",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record_code,
            { "Code",                                      "pcapng.records.record.code",
            FT_UINT16, BASE_DEC, VALS(record_code_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record_length,
            { "Length",                                    "pcapng.records.record.length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record_data,
            { "Record Data",                               "pcapng.records.record.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record_padding,
            { "Record Padding",                            "pcapng.records.record.padding",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record_ipv4,
            { "IPv4",                                      "pcapng.records.record.data.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record_ipv6,
            { "IPv6",                                      "pcapng.records.record.data.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_record_name,
            { "Name",                                      "pcapng.records.record.data.name",
            FT_STRINGZ, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_dsb_secrets_type,
            { "Secrets Type",                              "pcapng.dsb.secrets_type",
            FT_UINT32, BASE_HEX, VALS(dsb_secrets_types_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_dsb_secrets_length,
            { "Secrets Length",                            "pcapng.dsb.secrets_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_dsb_secrets_data,
            { "Secrets Data",                              "pcapng.dsb.secrets_data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_cb_pen,
            { "Private Enterprise Number (PEN)",           "pcapng.cb.pen",
            FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_cb_data,
            { "Custom Data",                               "pcapng.cb.custom_data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_cb_option_string,
            { "Custom Option String",                        "pcapng.cb.custom_option.string",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_cb_option_data,
            { "Custom Option Binary",                        "pcapng.cb.custom_option.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_invalid_byte_order_magic, { "pcapng.invalid_byte_order_magic", PI_PROTOCOL, PI_ERROR, "The byte-order magic number is not valid", EXPFILL }},
        { &ei_block_length_below_block_minimum, { "pcapng.block_length_below_block_minimum", PI_PROTOCOL, PI_ERROR, "Block length is < 12 bytes", EXPFILL }},
        { &ei_block_length_below_block_content_length, { "pcapng.block_length_below_block_content_length", PI_PROTOCOL, PI_ERROR, "Block length is < the length of the contents of the block", EXPFILL }},
        { &ei_block_length_not_multiple_of_4, { "pcapng.block_length_not_multiple_of4", PI_PROTOCOL, PI_ERROR, "Block length is not a multiple of 4", EXPFILL }},
        { &ei_block_lengths_dont_match, { "pcapng.block_lengths_dont_match", PI_PROTOCOL, PI_ERROR, "Block length in trailer differs from block length in header", EXPFILL }},
        { &ei_invalid_option_length, { "pcapng.invalid_option_length", PI_PROTOCOL, PI_ERROR, "Invalid Option Length", EXPFILL }},
        { &ei_invalid_record_length, { "pcapng.invalid_record_length", PI_PROTOCOL, PI_ERROR, "Invalid Record Length", EXPFILL }},
        { &ei_missing_idb, { "pcapng.no_interfaces", PI_PROTOCOL, PI_ERROR, "No Interface Description before block that requires it", EXPFILL }},
    };

    static int *ett[] = {
        &ett_pcapng,
        &ett_pcapng_section_header_block,
        &ett_pcapng_block_data,
        &ett_pcapng_block_type,
        &ett_pcapng_options,
        &ett_pcapng_option,
        &ett_pcapng_records,
        &ett_pcapng_record,
        &ett_pcapng_packet_data
    };

    proto_pcapng = proto_register_protocol("PCAPNG File Format", "File-PCAPNG", "file-pcapng");
    proto_register_field_array(proto_pcapng, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("file-pcapng", dissect_pcapng, proto_pcapng);

    module = prefs_register_protocol(proto_pcapng, NULL);
    prefs_register_static_text_preference(module, "version",
            "PCAPNG version: 1.0",
            "Version of file-format supported by this dissector.");

    prefs_register_bool_preference(module, "dissect_next_layer",
            "Dissect next layer",
            "Dissect next layer",
            &pref_dissect_next_layer);

    expert_module = expert_register_protocol(proto_pcapng);
    expert_register_field_array(expert_module, ei, array_length(ei));

    /* Create table for local block dissectors */
    s_local_block_callback_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* Ensure this table will be deleted */
    register_shutdown_routine(&pcapng_shutdown_protocol);
}

void
proto_reg_handoff_pcapng(void)
{
    heur_dissector_add("wtap_file", dissect_pcapng_heur, "PCAPNG File", "pcapng_wtap", proto_pcapng, HEURISTIC_ENABLE);
    pcap_pktdata_handle = find_dissector_add_dependency("pcap_pktdata", proto_pcapng);
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
