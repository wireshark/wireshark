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
#include <epan/wmem_scopes.h>
#include <wiretap/secrets-types.h>

#include <epan/dissectors/file-pcapng.h>
#include <epan/dissectors/packet-pcap_pktdata.h>

static int proto_pcapng = -1;

static dissector_handle_t  pcap_pktdata_handle;

static int hf_pcapng_block = -1;

static int hf_pcapng_block_type = -1;
static int hf_pcapng_block_type_vendor = -1;
static int hf_pcapng_block_type_value = -1;
static int hf_pcapng_block_length = -1;
static int hf_pcapng_block_length_trailer = -1;
static int hf_pcapng_block_data = -1;

static int hf_pcapng_section_header_byte_order_magic = -1;
static int hf_pcapng_section_header_major_version = -1;
static int hf_pcapng_section_header_minor_version = -1;
static int hf_pcapng_section_header_section_length = -1;
static int hf_pcapng_options = -1;
static int hf_pcapng_option = -1;
static int hf_pcapng_option_code = -1;
static int hf_pcapng_option_code_section_header = -1;
static int hf_pcapng_option_code_interface_description = -1;
static int hf_pcapng_option_code_enhanced_packet = -1;
static int hf_pcapng_option_code_packet = -1;
static int hf_pcapng_option_code_interface_statistics = -1;
static int hf_pcapng_option_code_name_resolution = -1;
static int hf_pcapng_option_length = -1;
static int hf_pcapng_option_data = -1;
static int hf_pcapng_option_data_comment = -1;
static int hf_pcapng_option_data_section_header_hardware = -1;
static int hf_pcapng_option_data_section_header_os = -1;
static int hf_pcapng_option_data_section_header_user_application = -1;
static int hf_pcapng_option_data_interface_description_name = -1;
static int hf_pcapng_option_data_interface_description_description = -1;
static int hf_pcapng_option_data_ipv4 = -1;
static int hf_pcapng_option_data_ipv4_mask = -1;
static int hf_pcapng_option_data_ipv6 = -1;
static int hf_pcapng_option_data_ipv6_mask = -1;
static int hf_pcapng_option_data_mac_address = -1;
static int hf_pcapng_option_data_eui_address = -1;
static int hf_pcapng_option_data_interface_speed = -1;
static int hf_pcapng_option_data_interface_timestamp_resolution = -1;
static int hf_pcapng_option_data_interface_timestamp_resolution_base = -1;
static int hf_pcapng_option_data_interface_timestamp_resolution_value = -1;
static int hf_pcapng_option_data_interface_timezone = -1;
static int hf_pcapng_option_data_interface_filter_type = -1;
static int hf_pcapng_option_data_interface_filter_string = -1;
static int hf_pcapng_option_data_interface_filter_bpf_program = -1;
static int hf_pcapng_option_data_interface_filter_unknown = -1;
static int hf_pcapng_option_data_interface_os = -1;
static int hf_pcapng_option_data_interface_hardware = -1;
static int hf_pcapng_option_data_interface_fcs_length = -1;
static int hf_pcapng_option_data_interface_timestamp_offset = -1;
static int hf_pcapng_option_data_packet_verdict_type = -1;
static int hf_pcapng_option_data_packet_verdict_data = -1;
static int hf_pcapng_option_data_packet_queue = -1;
static int hf_pcapng_option_data_packet_id = -1;
static int hf_pcapng_option_data_packet_drop_count = -1;
static int hf_pcapng_option_data_packet_hash_algorithm = -1;
static int hf_pcapng_option_data_packet_hash_data = -1;
static int hf_pcapng_option_data_packet_flags = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_symbol = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_preamble = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_start_frame_delimiter = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_unaligned_frame = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_wrong_inter_frame_gap = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_short = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_packet_too_long = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_crc_error = -1;
static int hf_pcapng_option_data_packet_flags_link_layer_errors_reserved = -1;
static int hf_pcapng_option_data_packet_flags_reserved = -1;
static int hf_pcapng_option_data_packet_flags_fcs_length = -1;
static int hf_pcapng_option_data_packet_flags_reception_type = -1;
static int hf_pcapng_option_data_packet_flags_direction = -1;
static int hf_pcapng_option_data_dns_name = -1;
static int hf_pcapng_option_data_start_time = -1;
static int hf_pcapng_option_data_end_time = -1;
static int hf_pcapng_option_data_interface_received = -1;
static int hf_pcapng_option_data_interface_dropped = -1;
static int hf_pcapng_option_data_interface_accepted_by_filter = -1;
static int hf_pcapng_option_data_interface_dropped_by_os = -1;
static int hf_pcapng_option_data_interface_delivered_to_user = -1;
static int hf_pcapng_option_padding = -1;
static int hf_pcapng_interface_description_link_type = -1;
static int hf_pcapng_interface_description_reserved = -1;
static int hf_pcapng_interface_description_snap_length = -1;
static int hf_pcapng_packet_block_interface_id = -1;
static int hf_pcapng_packet_block_drops_count = -1;
static int hf_pcapng_captured_length = -1;
static int hf_pcapng_packet_length = -1;
static int hf_pcapng_packet_data = -1;
static int hf_pcapng_packet_padding = -1;
static int hf_pcapng_interface_id = -1;
static int hf_pcapng_timestamp_high = -1;
static int hf_pcapng_timestamp_low = -1;
static int hf_pcapng_timestamp = -1;
static int hf_pcapng_records = -1;
static int hf_pcapng_record = -1;
static int hf_pcapng_record_code = -1;
static int hf_pcapng_record_length = -1;
static int hf_pcapng_record_data = -1;
static int hf_pcapng_record_ipv4 = -1;
static int hf_pcapng_record_ipv6 = -1;
static int hf_pcapng_record_name = -1;
static int hf_pcapng_record_padding = -1;

static int hf_pcapng_dsb_secrets_type = -1;
static int hf_pcapng_dsb_secrets_length = -1;
static int hf_pcapng_dsb_secrets_data = -1;

static int hf_pcapng_darwin_process_id = -1;
static int hf_pcapng_option_code_darwin_process_info = -1;
static int hf_pcapng_option_darwin_process_name = -1;
static int hf_pcapng_option_darwin_process_uuid = -1;
static int hf_pcapng_option_data_packet_darwin_dpeb_id = -1;
static int hf_pcapng_option_data_packet_darwin_svc_class = -1;
static int hf_pcapng_option_data_packet_darwin_edpeb_id = -1;
static int hf_pcapng_option_data_packet_darwin_flags = -1;
static int hf_pcapng_option_data_packet_darwin_flags_reserved = -1;
static int hf_pcapng_option_data_packet_darwin_flags_ch = -1;
static int hf_pcapng_option_data_packet_darwin_flags_so = -1;
static int hf_pcapng_option_data_packet_darwin_flags_re = -1;
static int hf_pcapng_option_data_packet_darwin_flags_ka = -1;
static int hf_pcapng_option_data_packet_darwin_flags_nf = -1;

static expert_field ei_invalid_byte_order_magic = EI_INIT;
static expert_field ei_block_length_below_block_minimum = EI_INIT;
static expert_field ei_block_length_below_block_content_length = EI_INIT;
static expert_field ei_block_length_not_multiple_of_4 = EI_INIT;
static expert_field ei_block_lengths_dont_match = EI_INIT;
static expert_field ei_invalid_option_length = EI_INIT;
static expert_field ei_invalid_record_length = EI_INIT;
static expert_field ei_missing_idb = EI_INIT;

static gint ett_pcapng = -1;
static gint ett_pcapng_section_header_block = -1;
static gint ett_pcapng_block_data = -1;
static gint ett_pcapng_options = -1;
static gint ett_pcapng_option = -1;
static gint ett_pcapng_records = -1;
static gint ett_pcapng_record = -1;
static gint ett_pcapng_packet_data = -1;

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

static int * const hfx_pcapng_block_type[] = {
    &hf_pcapng_block_type_vendor,
    &hf_pcapng_block_type_value,
    NULL
};

static int * const hfx_pcapng_option_data_packet_darwin_flags[] = {
    &hf_pcapng_option_data_packet_darwin_flags_reserved,
    &hf_pcapng_option_data_packet_darwin_flags_ch,
    &hf_pcapng_option_data_packet_darwin_flags_so,
    &hf_pcapng_option_data_packet_darwin_flags_re,
    &hf_pcapng_option_data_packet_darwin_flags_ka,
    &hf_pcapng_option_data_packet_darwin_flags_nf,
    NULL
};

static gboolean pref_dissect_next_layer = FALSE;

#define BLOCK_INTERFACE_DESCRIPTION  0x00000001
#define BLOCK_PACKET                 0x00000002
#define BLOCK_SIMPLE_PACKET          0x00000003
#define BLOCK_NAME_RESOLUTION        0x00000004
#define BLOCK_INTERFACE_STATISTICS   0x00000005
#define BLOCK_ENHANCED_PACKET        0x00000006
#define BLOCK_IRIG_TIMESTAMP         0x00000007
#define BLOCK_ARINC_429              0x00000008
#define BLOCK_SYSTEMD_JOURNAL_EXPORT 0x00000009
#define BLOCK_DSB                    0x0000000a
#define BLOCK_SECTION_HEADER         0x0A0D0D0A
#define BLOCK_DARWIN_PROCESS         0x80000001

static const value_string block_type_vals[] = {
    { 0x00000001,  "Interface Description Block" },
    { 0x00000002,  "Packet Block" },
    { 0x00000003,  "Simple Packet Block" },
    { 0x00000004,  "Name Resolution Block" },
    { 0x00000005,  "Interface Statistics Block" },
    { 0x00000006,  "Enhanced Packet Block" },
    { 0x00000007,  "IRIG Timestamp Block" },
    { 0x00000008,  "Arinc 429 in AFDX Encapsulation Information Block" },
    { 0x00000009,  "systemd Journal Export Block" },
    { 0x0000000A,  "Decryption Secrets Block" },
    { 0x00000204,  "Sysdig Event Block" },
    { 0x00000208,  "Sysdig Event Block with flags" },
    { 0x00000216,  "Sysdig Event Block v2" },
    { 0x00000217,  "Sysdig Event Block with flags v2" },
    { 0x00000221,  "Sysdig Event Block v2 large payload" },
    { 0x00000222,  "Sysdig Event Block with flags v2 large payload" },
    { 0x0A0D0D0A,  "Section Header Block" },
    { 0x80000001,  "Darwin Process Event Block" },
    { 0, NULL }
};

/*
 * Apple's Pcapng Darwin Process Event Block
 *
 *    A Darwin Process Event Block (DPEB) is an Apple defined container
 *    for information describing a Darwin process.
 *
 *    Tools that write / read the capture file associate an incrementing
 *    32-bit number (starting from '0') to each Darwin Process Event Block,
 *    called the DPEB ID for the process in question.  This number is
 *    unique within each Section and identifies a specific DPEB; a DPEB ID
 *    is only unique inside the current section. Two Sections can have different
 *    processes identified by the same DPEB ID values.  DPEB ID are referenced
 *    by Enhanced Packet Blocks that include options to indicate the Darwin
 *    process to which the EPB refers.
 *
 *
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *         +---------------------------------------------------------------+
 *       0 |                   Block Type = 0x80000001                     |
 *         +---------------------------------------------------------------+
 *       4 |                     Block Total Length                        |
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       8 |                          Process ID                           |
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      12 /                                                               /
 *         /                      Options (variable)                       /
 *         /                                                               /
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         |                     Block Total Length                        |
 *         +---------------------------------------------------------------+
 *
 *                   Figure XXX.1: Darwin Process Event Block
 *
 *    The meaning of the fields are:
 *
 *    o  Block Type: The block type of a Darwin Process Event Block is 2147483649.
 *
 *       Note: This specific block type number falls into the range defined
 *       for "local use" but has in fact been available publically since Darwin
 *       13.0 for pcapng files generated by Apple's tcpdump when using the PKTAP
 *       enhanced interface.
 *
 *    o  Block Total Length: Total size of this block, as described in
 *       Pcapng Section 3.1 (General Block Structure).
 *
 *    o  Process ID: The process ID (PID) of the process.
 *
 *       Note: It is not known if this field is officially defined as a 32 bits
 *       (4 octets) or something smaller since Darwin PIDs currently appear to
 *       be limited to maximum value of 100000.
 *
 *    o  Options: A list of options (formatted according to the rules defined
 *       in Section 3.5) can be present.
 *
 *    In addition to the options defined in Section 3.5, the following
 *    Apple defined Darwin options are valid within this block:
 *
 *           +------------------+------+----------+-------------------+
 *           | Name             | Code | Length   | Multiple allowed? |
 *           +------------------+------+----------+-------------------+
 *           | darwin_proc_name | 2    | variable | no                |
 *           | darwin_proc_uuid | 4    | 16       | no                |
 *           +------------------+------+----------+-------------------+
 *
 *              Table XXX.1: Darwin Process Description Block Options
 *
 *    darwin_proc_name:
 *            The darwin_proc_name option is a UTF-8 string containing the
 *            name of a process producing or consuming an EPB.
 *
 *            Examples: "mDNSResponder", "GoogleSoftwareU".
 *
 *            Note: It appears that Apple's tcpdump currently truncates process
 *            names to a maximum of 15 octets followed by a NUL character.
 *            Multi-byte UTF-8 sequences in process names might be truncated
 *            resulting in an invalid final UTF-8 character.
 *
 *            This is probably because the process name comes from the
 *            p_comm field in a proc structure in the kernel; that field
 *            is MAXCOMLEN+1 bytes long, with the +1 being for the NUL
 *            terminator.  That would give 16 characters, but the
 *            proc_info kernel interface has a structure with a
 *            process name field of only MAXCOMLEN bytes.
 *
 *            This all ultimately dates back to the "kernel accounting"
 *            mechanism that appeared in V7 UNIX, with an "accounting
 *            file" with entries appended whenever a process exits; not
 *            surprisingly, that code thinks a file name is just a bunch
 *            of "char"s, with no multi-byte encodings (1979 called, they
 *            want their character encoding back), so, yes, this can
 *            mangle UTF-8 file names containing non-ASCII characters.
 *
 *    darwin_proc_uuid:
 *            The darwin_proc_uuid option is a set of 16 octets representing
 *            the process UUID.
 *
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
 *                          |    0x00000010    |  ch  |
 *                          |    0x00000008    |  so  |
 *                          |    0x00000004    |  re  |
 *                          |    0x00000002    |  ka  |
 *                          |    0x00000001    |  nf  |
 *                          +-------------------------+
 *
 *                           Table XXX.4: Darwin Flags
 * nf = New Flow
 * ka = Keep Alive
 * re = ReXmit (I assume this means Re-Transmit)
 * so = Socket
 * ch = Nexus Channel
 */

static const value_string option_code_section_header_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Hardware Description" },
    { 3,  "OS Description" },
    { 4,  "User Application" },
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
    { 0, NULL }
};

static const value_string option_code_enhanced_packet_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Flags" },
    { 3,  "Hash" },
    { 4,  "Drop Count" },
    { 5,  "Packet ID" },
    { 6,  "Queue" },
    { 7,  "Verdict" },
    { 32769,   "Darwin DPEB ID" },
    { 32770,   "Darwin Service Class" },
    { 32771,   "Darwin Effective DPEB ID" },
    { 32772,   "Darwin Flags" },
    { 0, NULL }
};

static const value_string option_code_packet_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Flags" },
    { 3,  "Hash" },
    { 0, NULL }
};

static const value_string option_code_name_resolution_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "DNS Name" },
    { 3,  "DNS IPv4 Address" },
    { 4,  "DNS IPv6 Address" },
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
    { 0, NULL }
};

static const value_string option_code_darwin_process_info_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },

    { 2,  "Darwin Process Name" },
    { 4,  "Darwin Process UUID" },
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
    { 0, "libpcap string" },
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
    { SECRETS_TYPE_TLS,         "TLS Key Log" },
    { SECRETS_TYPE_WIREGUARD,   "WireGuard Key Log" },
    { 0, NULL }
};

void proto_register_pcapng(void);
void proto_reg_handoff_pcapng(void);

#define BYTE_ORDER_MAGIC_SIZE  4

static const guint8 pcapng_big_endian_magic[BYTE_ORDER_MAGIC_SIZE] = {
    0x1A, 0x2B, 0x3C, 0x4D
};
static const guint8 pcapng_little_endian_magic[BYTE_ORDER_MAGIC_SIZE] = {
    0x4D, 0x3C, 0x2B, 0x1A
};

static gint dissect_options(proto_tree *tree, packet_info *pinfo,
        guint32 block_type, tvbuff_t *tvb, int offset, guint encoding,
        void *user_data)
{
    proto_tree   *options_tree;
    proto_item   *options_item;
    proto_tree   *option_tree;
    proto_item   *option_item;
    proto_item   *option_length_item;
    proto_item   *p_item;
    guint32       option_code;
    guint32       option_length;
    gint          hfj_pcapng_option_code;
    char         *str;
    const char   *const_str;
    wmem_strbuf_t *strbuf;
    address       addr;
    address       addr_mask;
    guint32       if_filter_type;
    const value_string  *vals = NULL;
    guint8        value_u8;
    guint32       value_u32;
    guint64       value_u64;
    e_guid_t      uuid;

    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return 0;

    options_item = proto_tree_add_item(tree, hf_pcapng_options, tvb, offset, -1, ENC_NA);
    options_tree = proto_item_add_subtree(options_item, ett_pcapng_options);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        str = NULL;
        option_item = proto_tree_add_item(options_tree, hf_pcapng_option, tvb, offset, -1, ENC_NA);
        option_tree = proto_item_add_subtree(option_item, ett_pcapng_option);

        switch (block_type) {
        case BLOCK_SECTION_HEADER:
            hfj_pcapng_option_code = hf_pcapng_option_code_section_header;
            vals = option_code_section_header_vals;
            break;
        case BLOCK_INTERFACE_DESCRIPTION:
            hfj_pcapng_option_code = hf_pcapng_option_code_interface_description;
            vals = option_code_interface_description_vals;
            break;
        case BLOCK_ENHANCED_PACKET:
            hfj_pcapng_option_code = hf_pcapng_option_code_enhanced_packet;
            vals = option_code_enhanced_packet_vals;
            break;
        case BLOCK_PACKET:
            hfj_pcapng_option_code = hf_pcapng_option_code_packet;
            vals = option_code_packet_vals;
            break;
        case BLOCK_NAME_RESOLUTION:
            hfj_pcapng_option_code = hf_pcapng_option_code_name_resolution;
            vals = option_code_name_resolution_vals;
            break;
        case BLOCK_INTERFACE_STATISTICS:
            hfj_pcapng_option_code = hf_pcapng_option_code_interface_statistics;
            vals = option_code_interface_statistics_vals;
            break;
        case BLOCK_DARWIN_PROCESS:
            hfj_pcapng_option_code = hf_pcapng_option_code_darwin_process_info;
            vals = option_code_darwin_process_info_vals;
            break;
        default:
            hfj_pcapng_option_code = hf_pcapng_option_code;
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
        } else switch (block_type) {
        case BLOCK_SECTION_HEADER:
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
        case BLOCK_INTERFACE_DESCRIPTION: {
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

                break;;
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
                guint32     base;
                guint32     exponent;
                guint32     i;
                guint64     resolution;

                if (option_length != 1) {
                    expert_add_info(pinfo, option_length_item, &ei_invalid_option_length);
                    offset += option_length;
                    break;
                }

                proto_tree_add_bitmask(option_tree, tvb, offset, hf_pcapng_option_data_interface_timestamp_resolution, ett_pcapng_option, hfx_pcapng_option_data_interface_timestamp_resolution, ENC_NA);
                value_u8 = tvb_get_guint8(tvb, offset);
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
        case BLOCK_PACKET:
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
        case BLOCK_NAME_RESOLUTION:
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
        case BLOCK_INTERFACE_STATISTICS:
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
        case BLOCK_ENHANCED_PACKET:
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

                switch (tvb_get_guint8(tvb, offset)) {
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
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
            }

            break;
        case BLOCK_DARWIN_PROCESS:
            switch (option_code) {
            case 2: /* Darwin Process Name */
                proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_darwin_process_name, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
                offset += option_length;
                break;

            case 4: /* Darwin Process UUID */
                proto_tree_add_item(option_tree, hf_pcapng_option_darwin_process_uuid, tvb, offset, option_length, ENC_BIG_ENDIAN);
                tvb_get_guid(tvb, offset, &uuid, ENC_BIG_ENDIAN);
                offset += option_length;

                proto_item_append_text(option_item, " = %s",
                    guid_to_str(pinfo->pool, &uuid));

                break;
            default:
                proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
                offset += option_length;
                break;
            }

            break;
        default:
            proto_tree_add_item(option_tree, hf_pcapng_option_data, tvb, offset, option_length, ENC_NA);
            offset += option_length;
        }

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
        int offset, guint encoding,
        struct interface_description *interface_description)
{
    proto_tree_add_item(tree, hf_pcapng_timestamp_high, tvb, offset, 4, encoding);
    proto_tree_add_item(tree, hf_pcapng_timestamp_low, tvb, offset + 4, 4, encoding);

    if (interface_description != NULL) {
        nstime_t    timestamp;
        guint64     ts;
        proto_item *ti;

        ts = ((guint64)(tvb_get_guint32(tvb, offset, encoding))) << 32 |
                        tvb_get_guint32(tvb, offset + 4, encoding);

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
get_interface_description(struct info *info, guint interface_id,
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
                     proto_item **block_length_item_p, guint32 *block_length_p,
                     guint encoding)
{
    proto_item      *block_data_item;
    guint32          block_data_length;

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

/*
 * Structure to pass to block data dissectors.
 */
typedef struct {
    proto_item *block_item;
    proto_tree *block_tree;
    struct info *info;
} block_data_arg;

static gboolean
dissect_shb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 gboolean byte_order_magic_bad, block_data_arg *argp)
{
    int offset = 0;
    proto_item      *byte_order_magic_item;

    byte_order_magic_item = proto_tree_add_item(tree, hf_pcapng_section_header_byte_order_magic, tvb, offset, 4, ENC_NA);
    if (byte_order_magic_bad) {
        expert_add_info(pinfo, byte_order_magic_item, &ei_invalid_byte_order_magic);
        return FALSE;
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

    dissect_options(tree, pinfo, BLOCK_SECTION_HEADER, tvb, offset, argp->info->encoding, NULL);

    return TRUE;
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
    interface_description.link_type = tvb_get_guint16(tvb, offset, argp->info->encoding);
    offset += 2;

    proto_tree_add_item(tree, hf_pcapng_interface_description_reserved, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    proto_tree_add_item(tree, hf_pcapng_interface_description_snap_length, tvb, offset, 4, argp->info->encoding);
    interface_description.snap_len = tvb_get_guint32(tvb, offset, argp->info->encoding);
    offset += 4;

    dissect_options(tree, pinfo, BLOCK_INTERFACE_DESCRIPTION, tvb, offset, argp->info->encoding, &interface_description);

    wmem_array_append_one(argp->info->interfaces, interface_description);
}

static void
dissect_pb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                block_data_arg *argp)
{
    volatile int offset = 0;
    guint32 interface_id;
    struct interface_description *interface_description;
    guint32 captured_length;
    guint32 reported_length;
    proto_item *packet_data_item;

    proto_item_append_text(argp->block_item, " %u", argp->info->frame_number);

    proto_tree_add_item(tree, hf_pcapng_packet_block_interface_id, tvb, offset, 2, argp->info->encoding);
    interface_id = tvb_get_guint16(tvb, offset, argp->info->encoding);
    offset += 2;
    interface_description = get_interface_description(argp->info, interface_id,
                                                      pinfo, argp->block_tree);

    proto_tree_add_item(tree, hf_pcapng_packet_block_drops_count, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    pcapng_add_timestamp(tree, pinfo, tvb, offset, argp->info->encoding, interface_description);
    offset += 8;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_captured_length, tvb, offset, 4, argp->info->encoding, &captured_length);
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_packet_length, tvb, offset, 4, argp->info->encoding, &reported_length);
    offset += 4;

    packet_data_item = proto_tree_add_item(tree, hf_pcapng_packet_data, tvb, offset, captured_length, argp->info->encoding);

    if (pref_dissect_next_layer && interface_description != NULL) {
        proto_tree *packet_data_tree = proto_item_add_subtree(packet_data_item, ett_pcapng_packet_data);

        pinfo->num = argp->info->frame_number;

        TRY {
            call_dissector_with_data(pcap_pktdata_handle, tvb_new_subset_length_caplen(tvb, offset, captured_length, reported_length),
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

    dissect_options(tree, pinfo, BLOCK_PACKET, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_spb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    volatile int offset = 0;
    struct interface_description *interface_description;
    proto_item *ti;
    volatile guint32 captured_length;
    guint32 reported_length;
    proto_item *packet_data_item;

    interface_description = get_interface_description(argp->info, 0,
                                                      pinfo, argp->block_tree);

    proto_item_append_text(argp->block_item, " %u", argp->info->frame_number);

    proto_tree_add_item_ret_uint(tree, hf_pcapng_packet_length, tvb, offset, 4, argp->info->encoding, &reported_length);
    offset += 4;

    captured_length = reported_length;
    if (interface_description && interface_description->snap_len != 0) {
        captured_length = MIN(reported_length, interface_description->snap_len);
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
    gint         offset_string_start;
    guint32      record_code;
    guint32      record_length;
    gint         string_length;
    gchar       *str = NULL;
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
            while ((guint)(offset - offset_string_start) < record_length - 4) {
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
            while ((guint)(offset - offset_string_start) < record_length - 16) {
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

    dissect_options(tree, pinfo, BLOCK_NAME_RESOLUTION, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_isb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    int offset = 0;
    guint32 interface_id;
    struct interface_description *interface_description;

    proto_tree_add_item(tree, hf_pcapng_interface_id, tvb, offset, 4, argp->info->encoding);
    interface_id = tvb_get_guint32(tvb, offset, argp->info->encoding);
    offset += 4;
    interface_description = get_interface_description(argp->info, interface_id,
                                                      pinfo, argp->block_tree);

    pcapng_add_timestamp(tree, pinfo, tvb, offset, argp->info->encoding, interface_description);
    offset += 8;

    dissect_options(tree, pinfo, BLOCK_INTERFACE_STATISTICS, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_epb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    volatile int offset = 0;
    guint32 interface_id;
    struct interface_description *interface_description;
    guint32 captured_length;
    guint32 reported_length;
    proto_item *packet_data_item;

    proto_item_append_text(argp->block_item, " %u", argp->info->frame_number);

    proto_tree_add_item(tree, hf_pcapng_interface_id, tvb, offset, 4, argp->info->encoding);
    interface_id = tvb_get_guint32(tvb, offset, argp->info->encoding);
    offset += 4;
    interface_description = get_interface_description(argp->info, interface_id,
                                                      pinfo, argp->block_tree);

    pcapng_add_timestamp(tree, pinfo, tvb, offset, argp->info->encoding, interface_description);
    offset += 8;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_captured_length, tvb, offset, 4, argp->info->encoding, &captured_length);
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_pcapng_packet_length, tvb, offset, 4, argp->info->encoding, &reported_length);
    offset += 4;

    packet_data_item = proto_tree_add_item(tree, hf_pcapng_packet_data, tvb, offset, captured_length, argp->info->encoding);

    if (pref_dissect_next_layer && interface_description != NULL) {
        proto_tree *packet_data_tree = proto_item_add_subtree(packet_data_item, ett_pcapng_packet_data);

        pinfo->num = argp->info->frame_number;

        TRY {
            call_dissector_with_data(pcap_pktdata_handle, tvb_new_subset_length_caplen(tvb, offset, captured_length, reported_length),
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

    dissect_options(tree, pinfo, BLOCK_ENHANCED_PACKET, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_dsb_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                 block_data_arg *argp)
{
    int offset = 0;
    guint32 secrets_length;

    proto_tree_add_item(tree, hf_pcapng_dsb_secrets_type, tvb, offset, 4, argp->info->encoding);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_pcapng_dsb_secrets_length, tvb, offset, 4, argp->info->encoding, &secrets_length);
    offset += 4;
    proto_tree_add_item(tree, hf_pcapng_dsb_secrets_data, tvb, offset, secrets_length, argp->info->encoding);
    offset += secrets_length;

    guint32 padlen = (4 - (secrets_length & 3)) & 3;
    if (padlen) {
        proto_tree_add_item(tree, hf_pcapng_record_padding, tvb, offset, padlen, ENC_NA);
        offset += padlen;
    }

    dissect_options(tree, pinfo, BLOCK_DSB, tvb, offset, argp->info->encoding, NULL);
}

static void
dissect_darwin_process_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                            block_data_arg *argp)
{
    int offset = 0;

    proto_item_append_text(argp->block_item, " %u", argp->info->darwin_process_event_number);
    argp->info->darwin_process_event_number += 1;

    proto_tree_add_item(tree, hf_pcapng_darwin_process_id, tvb, offset, 4, argp->info->encoding);
    offset += 4;

    dissect_options(tree, pinfo, BLOCK_DARWIN_PROCESS, tvb, offset, argp->info->encoding, NULL);
}

gint dissect_block(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, struct info *info)
{
    proto_tree      *block_tree;
    proto_item      *block_item;
    proto_tree      *block_data_tree;
    proto_item      *block_length_item;
    proto_item      *block_length_trailer_item;
    gint             offset = 0;
    guint32          block_type;
    guint32          block_length, block_length_trailer;
    guint32          length;
    tvbuff_t        *volatile next_tvb = NULL;
    block_data_arg   arg;
    volatile gboolean stop_dissecting = FALSE;

    block_type = tvb_get_guint32(tvb, offset + 0, info->encoding);
    length     = tvb_get_guint32(tvb, offset + 4, info->encoding);

    block_item = proto_tree_add_item(tree, hf_pcapng_block, tvb, offset, length, ENC_NA);
    block_tree = proto_item_add_subtree(block_item, ett_pcapng_section_header_block);
    proto_item_append_text(block_item, ": %s", val_to_str_const(block_type, block_type_vals, "Unknown"));

    proto_tree_add_bitmask_with_flags(block_tree, tvb, offset, hf_pcapng_block_type, ett_pcapng_option, hfx_pcapng_block_type, info->encoding, BMT_NO_APPEND);
    offset += 4;

    arg.block_item = block_item;
    arg.block_tree = block_tree;
    arg.info = info;

    if (block_type == BLOCK_SECTION_HEADER) {
        /* Section Header Block - this needs special byte-order handling */
        volatile gboolean byte_order_magic_bad = FALSE;

        proto_item_append_text(block_item, " %u", info->section_number);
        info->section_number += 1;
        info->interface_number = 0;
        info->darwin_process_event_number = 0;
        info->frame_number = 1;
        if (info->interfaces != NULL) {
            wmem_free(pinfo->pool, info->interfaces);
        }
        info->interfaces = wmem_array_new(pinfo->pool, sizeof(struct interface_description));

        if (tvb_memeql(tvb, 8, pcapng_big_endian_magic, BYTE_ORDER_MAGIC_SIZE) == 0) {
            info->encoding = ENC_BIG_ENDIAN;
        } else if (tvb_memeql(tvb, 8, pcapng_little_endian_magic, BYTE_ORDER_MAGIC_SIZE) == 0) {
            info->encoding = ENC_LITTLE_ENDIAN;
        } else {
            byte_order_magic_bad = TRUE;
        }

        next_tvb = process_block_length(block_tree, pinfo, tvb, offset, &block_data_tree, &block_length_item, &block_length, info->encoding);
        if (next_tvb == NULL) {
            /* The length was invalid, so we can't dissect any further */
            return -1;
        }
        offset += 4;

	/*
	 * Dissect the block data as an SHB's content.
	 * Catch exceptions; ReportedBoundsError means that the body
	 * doesn't fit in the block.
	 */
	TRY {
            if (!dissect_shb_data(block_data_tree, pinfo, next_tvb,
                                  byte_order_magic_bad, &arg)) {
                /*
                 * We can't dissect any further.
                 */
                stop_dissecting = TRUE;
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
    } else {
        /*
         * Not an SHB, so we know the byte order.
         */
        next_tvb = process_block_length(block_tree, pinfo, tvb, offset, &block_data_tree, &block_length_item, &block_length, info->encoding);
        if (next_tvb == NULL) {
            /* The length was invalid, so we can't dissect any further */
            return -1;
        }
        offset += 4;

	/*
	 * Dissect the block data.
	 * Catch exceptions; ReportedBoundsError means that the body
	 * doesn't fit in the block.
	 */
	TRY {
            switch (block_type) {
            case BLOCK_INTERFACE_DESCRIPTION:
                dissect_idb_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_PACKET:
                dissect_pb_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_SIMPLE_PACKET:
                dissect_spb_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_NAME_RESOLUTION:
                dissect_nrb_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_INTERFACE_STATISTICS:
                dissect_isb_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_ENHANCED_PACKET:
                dissect_epb_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_DSB:
                dissect_dsb_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_DARWIN_PROCESS:
                dissect_darwin_process_data(block_data_tree, pinfo, next_tvb, &arg);
                break;
            case BLOCK_IRIG_TIMESTAMP:
            case BLOCK_ARINC_429:
            default:
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
    }

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
    static const guint8 pcapng_premagic[BLOCK_TYPE_SIZE] = {
        0x0A, 0x0D, 0x0D, 0x0A
    };
    gint             offset = 0;
    guint32          length;
    guint32          encoding;
    proto_tree      *main_tree;
    proto_item      *main_item;
    struct info      info;

    if (tvb_memeql(tvb, 0, pcapng_premagic, BLOCK_TYPE_SIZE) != 0)
        return 0;

    if (tvb_memeql(tvb, 8, pcapng_big_endian_magic, BYTE_ORDER_MAGIC_SIZE) == 0) {
        encoding = ENC_BIG_ENDIAN;
    } else if (tvb_memeql(tvb, 8, pcapng_little_endian_magic, BYTE_ORDER_MAGIC_SIZE) == 0) {
        encoding = ENC_LITTLE_ENDIAN;
    } else {
        return 0;
    }

    info.section_number = 1;
    info.interface_number = 0;
    info.darwin_process_event_number = 0;
    info.frame_number = 1;
    info.encoding = encoding;
    info.interfaces = wmem_array_new(pinfo->pool, sizeof(struct interface_description));
    info.darwin_process_events = wmem_array_new(pinfo->pool, sizeof(struct darwin_process_event_description));

    main_item = proto_tree_add_item(tree, proto_pcapng, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_pcapng);

    while (tvb_captured_length_remaining(tvb, offset)) {
        tvbuff_t  *next_tvb;
        int       block_length;

        length = tvb_get_guint32(tvb, offset + 4, encoding);
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

static gboolean
dissect_pcapng_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_pcapng(tvb, pinfo, tree, NULL) > 0;
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
            FT_UINT32, BASE_HEX, VALS(block_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_block_type_vendor,
            { "Block Type Vendor",                         "pcapng.block.type.vendor",
            FT_BOOLEAN, 32, NULL, 0x80000000,
            NULL, HFILL }
        },
        { &hf_pcapng_block_type_value,
            { "Block Type Value",                          "pcapng.block.type.value",
            FT_UINT32, BASE_HEX, VALS(block_type_vals), 0x7FFFFFFF,
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
        { &hf_pcapng_option_code_darwin_process_info,
            { "Code",                                      "pcapng.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_darwin_process_info_vals), 0x00,
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
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0xFFFFFFE0,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_ch,
            { "Nexus Channel(ch)",                                        "pcapng.options.option.data.packet.darwin.flags.ch",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_so,
            { "Socket(so)",                                        "pcapng.options.option.data.packet.darwin.flags.so",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_re,
            { "ReXmit(re)",                                        "pcapng.options.option.data.packet.darwin.flags.re",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_ka,
            { "Keep Alive(ka)",                                        "pcapng.options.option.data.packet.darwin.flags.ka",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
            NULL, HFILL }
        },
        { &hf_pcapng_option_data_packet_darwin_flags_nf,
            { "New Flow(nf)",                                        "pcapng.options.option.data.packet.darwin.flags.nf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
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
            { "Captured Length",                           "pcapng.packet.captured_length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_packet_length,
            { "Packet Length",                             "pcapng.packet.packet_length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
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
        { &hf_pcapng_darwin_process_id,
            { "Darwin Process ID",                         "pcapng.darwin.process_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_darwin_process_name,
            { "Darwin Process Name",                       "pcapng.darwin.process_name",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcapng_option_darwin_process_uuid,
            { "Darwin Process UUID",                       "pcapng.darwin.process_uuid",
            FT_GUID, BASE_NONE, NULL, 0x00,
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

    static gint *ett[] = {
        &ett_pcapng,
        &ett_pcapng_section_header_block,
        &ett_pcapng_block_data,
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
