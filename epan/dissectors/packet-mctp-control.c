/* packet-mctp-control.c
 * Routines for Management Component Transport Protocol (MCTP) control
 * protocol disassembly
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MCTP control protocol provides transport-layer initialisation and
 * management for MCTP endpoints; typically for device discovery, enumeration
 * and address assigment.
 *
 * MCTP Control protocol is defined by DMTF standard DSP0236:
 * https://www.dmtf.org/dsp/DSP0236
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>
#include "packet-mctp.h"

#define MCTP_CTRL_MIN_LENGTH 3

void proto_register_mctp_control(void);
void proto_reg_handoff_mctp_control(void);

static int proto_mctp_ctrl;
static dissector_handle_t mctp_ctrl_handle;

static int hf_mctp_ctrl_command;
static int hf_mctp_ctrl_rq;
static int hf_mctp_ctrl_d;
static int hf_mctp_ctrl_rsvd;
static int hf_mctp_ctrl_instance;
static int hf_mctp_ctrl_cc;
static int hf_mctp_ctrl_data;
static int hf_mctp_ctrl_excess;

/* Set Endpoint ID (DSP0236 1.3.3, Table 14) */
static int hf_mctp_ctrl_set_eid_rsvd;
static int hf_mctp_ctrl_set_eid_op;
static int hf_mctp_ctrl_set_eid_eid;
static int hf_mctp_ctrl_set_eid_rsvd_hi;
static int hf_mctp_ctrl_set_eid_status;
static int hf_mctp_ctrl_set_eid_rsvd_lo;
static int hf_mctp_ctrl_set_eid_alloc_status;
static int hf_mctp_ctrl_set_eid_setting;
static int hf_mctp_ctrl_set_eid_pool_size;

/* Get Endpoint ID (DSP0236 1.3.3, Table 15) */
static int hf_mctp_ctrl_get_eid_eid;
static int hf_mctp_ctrl_get_eid_rsvd_hi;
static int hf_mctp_ctrl_get_eid_endpoint_type;
static int hf_mctp_ctrl_get_eid_rsvd_lo;
static int hf_mctp_ctrl_get_eid_eid_type;
static int hf_mctp_ctrl_get_eid_medium_info;
static int hf_mctp_ctrl_get_eid_medium_rsvd;
static int hf_mctp_ctrl_get_eid_medium_fairness;

/* Get Endpoint UUID (DSP0236 1.3.3, Table 16) */
static int hf_mctp_ctrl_uuid;

/* Get MCTP Version Support (DSP0236 1.3.3, Table 18) */
static int hf_mctp_ctrl_get_ver_msg_type;
static int hf_mctp_ctrl_get_ver_count;
static int hf_mctp_ctrl_get_ver_entry;
static int hf_mctp_ctrl_get_ver_major;
static int hf_mctp_ctrl_get_ver_minor;
static int hf_mctp_ctrl_get_ver_update;
static int hf_mctp_ctrl_get_ver_alpha;

/* Get Message Type Support (DSP0236 1.3.3, Table 19) */
static int hf_mctp_ctrl_msg_type_count;
static int hf_mctp_ctrl_msg_type;

/* Allocate Endpoint IDs (DSP0236 1.3.3, Table 23) */
static int hf_mctp_ctrl_alloc_eids_rsvd;
static int hf_mctp_ctrl_alloc_eids_op;
static int hf_mctp_ctrl_alloc_eids_count;
static int hf_mctp_ctrl_alloc_eids_start;
static int hf_mctp_ctrl_alloc_eids_status;
static int hf_mctp_ctrl_alloc_eids_pool_size;
static int hf_mctp_ctrl_alloc_eids_first;

/* Get Routing Table Entries (DSP0236 1.3.3, Tables 26 and 27) */
static int hf_mctp_ctrl_get_routing_handle;
static int hf_mctp_ctrl_get_routing_next_handle;
static int hf_mctp_ctrl_get_routing_count;
static int hf_mctp_ctrl_get_routing_entry;
static int hf_mctp_ctrl_get_routing_range_size;
static int hf_mctp_ctrl_get_routing_start_eid;
static int hf_mctp_ctrl_get_routing_entry_type;
static int hf_mctp_ctrl_get_routing_static;
static int hf_mctp_ctrl_get_routing_port;
static int hf_mctp_ctrl_get_routing_binding_id;
static int hf_mctp_ctrl_get_routing_media_type;
static int hf_mctp_ctrl_get_routing_addr_size;
static int hf_mctp_ctrl_get_routing_addr;

/* Additional command payloads (DSP0236 1.3.3, Tables 20-39). */
static int hf_mctp_ctrl_vendor_selector;
static int hf_mctp_ctrl_vendor_next_selector;
static int hf_mctp_ctrl_vendor_format;
static int hf_mctp_ctrl_vendor_pci;
static int hf_mctp_ctrl_vendor_iana;
static int hf_mctp_ctrl_vendor_command_set;
static int hf_mctp_ctrl_resolve_eid_target;
static int hf_mctp_ctrl_resolve_eid_bridge;
static int hf_mctp_ctrl_resolve_eid_addr;
static int hf_mctp_ctrl_resolve_eid_slave_addr;
static int hf_mctp_ctrl_resolve_eid_addr_rsvd;
static int hf_mctp_ctrl_routing_update_count;
static int hf_mctp_ctrl_routing_update_entry;
static int hf_mctp_ctrl_routing_update_rsvd;
static int hf_mctp_ctrl_routing_update_type;
static int hf_mctp_ctrl_routing_update_range_size;
static int hf_mctp_ctrl_routing_update_eid;
static int hf_mctp_ctrl_routing_update_slave_addr;
static int hf_mctp_ctrl_routing_update_addr_rsvd;
static int hf_mctp_ctrl_routing_update_data;
static int hf_mctp_ctrl_network_uuid;
static int hf_mctp_ctrl_query_hop_target;
static int hf_mctp_ctrl_query_hop_bridge;
static int hf_mctp_ctrl_query_hop_msg_type;
static int hf_mctp_ctrl_query_hop_response_type;
static int hf_mctp_ctrl_query_hop_tu_data;
static int hf_mctp_ctrl_query_hop_in_tu;
static int hf_mctp_ctrl_query_hop_out_tu;
static int hf_mctp_ctrl_resolve_uuid;
static int hf_mctp_ctrl_resolve_uuid_handle;
static int hf_mctp_ctrl_resolve_uuid_next_handle;
static int hf_mctp_ctrl_resolve_uuid_count;
static int hf_mctp_ctrl_resolve_uuid_entry;
static int hf_mctp_ctrl_resolve_uuid_eid;
static int hf_mctp_ctrl_resolve_uuid_binding;
static int hf_mctp_ctrl_resolve_uuid_media;
static int hf_mctp_ctrl_resolve_uuid_addr_size;
static int hf_mctp_ctrl_resolve_uuid_addr;
static int hf_mctp_ctrl_rate_rx_buffer;
static int hf_mctp_ctrl_rate_rx_rate;
static int hf_mctp_ctrl_rate_max_tx_rate;
static int hf_mctp_ctrl_rate_min_tx_rate;
static int hf_mctp_ctrl_rate_max_burst;
static int hf_mctp_ctrl_rate_burst;
static int hf_mctp_ctrl_rate_tx_rate;
static int hf_mctp_ctrl_rate_rsvd;
static int hf_mctp_ctrl_rate_non_requested;
static int hf_mctp_ctrl_rate_supported;
static int hf_mctp_ctrl_rate_requested_burst;
static int hf_mctp_ctrl_rate_requested_rate;
static int hf_mctp_ctrl_rate_granted_burst;
static int hf_mctp_ctrl_interfaces_count;
static int hf_mctp_ctrl_interfaces_media;
static int hf_mctp_ctrl_interfaces_eid;
static int hf_mctp_ctrl_transport_binding;
static int hf_mctp_ctrl_transport_media;
static int hf_mctp_ctrl_transport_iana;
static int hf_mctp_ctrl_phys_smbus_addr;
static int hf_mctp_ctrl_phys_i3c_addr;
static int hf_mctp_ctrl_phys_addr_rsvd;
static int hf_mctp_ctrl_phys_segment;
static int hf_mctp_ctrl_phys_bus;
static int hf_mctp_ctrl_phys_device;
static int hf_mctp_ctrl_phys_function;
static int hf_mctp_ctrl_phys_ari_function;
static int hf_mctp_ctrl_response_in;
static int hf_mctp_ctrl_response_to;
static int hf_mctp_ctrl_response_time;

static int ett_mctp_ctrl;
static int ett_mctp_ctrl_phys_addr;
static int ett_mctp_ctrl_hdr;
static int ett_mctp_ctrl_get_routing_entry;
static int ett_mctp_ctrl_get_ver_entry;
static int ett_mctp_ctrl_resolve_uuid_entry;
static int ett_mctp_ctrl_routing_update_entry;

static expert_field ei_mctp_ctrl_ver_bcd;
static expert_field ei_mctp_ctrl_ver_alpha;
static expert_field ei_mctp_ctrl_length;
static expert_field ei_mctp_ctrl_ic;
static expert_field ei_mctp_ctrl_phys_addr_size;
static expert_field ei_mctp_ctrl_unmatched_response;
static expert_field ei_mctp_ctrl_reserved_class;
static expert_field ei_mctp_ctrl_invalid_value;
static expert_field ei_mctp_ctrl_oversized;

/* Outstanding requests, keyed on the requester's view of the exchange. */
static wmem_map_t *mctp_ctrl_requests;

/* Every member is a uint32_t, so the key hashes as plain bytes. */
typedef struct {
    mctp_ingress_scope scope;
    uint32_t requester;     /* the request's source EID */
    uint32_t responder;     /* its destination EID, or a wildcard below */
    /* Null-EID requests on SMBus/I2C only: the 7-bit slave addresses that
     * route them (DSP0236 Table 2, DSP0237 Table 1), as MCTP_CTRL_PHYS(),
     * so concurrent requests to unassigned endpoints stay apart. */
    uint32_t phys_requester;
    uint32_t phys_responder;
    uint32_t tag;           /* message tag, without TO */
    uint32_t iid;           /* Instance ID (Table 10) */
    uint32_t cmd;
} mctp_ctrl_key;

typedef struct {
    uint32_t req_frame;
    uint32_t resp_frame;
    nstime_t req_time;
    bool broadcast;          /* sent to the broadcast EID */
    wmem_map_t *responders;  /* broadcast: the responders already paired */
    bool has_ver_selector;   /* Get Version request's message type */
    uint8_t ver_selector;
} mctp_ctrl_transaction;

/* DSP0236 1.3.3 Table 12 - MCTP control command numbers. */
static const range_string command_vals[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Set Endpoint ID" },
    { 0x02, 0x02, "Get Endpoint ID" },
    { 0x03, 0x03, "Get Endpoint UUID" },
    { 0x04, 0x04, "Get MCTP Version Support" },
    { 0x05, 0x05, "Get Message Type Support" },
    { 0x06, 0x06, "Get Vendor Defined Message Support" },
    { 0x07, 0x07, "Resolve Endpoint ID" },
    { 0x08, 0x08, "Allocate Endpoint IDs" },
    { 0x09, 0x09, "Routing Information Update" },
    { 0x0a, 0x0a, "Get Routing Table Entries" },
    { 0x0b, 0x0b, "Prepare for Endpoint Discovery" },
    { 0x0c, 0x0c, "Endpoint Discovery" },
    { 0x0d, 0x0d, "Discovery Notify" },
    { 0x0e, 0x0e, "Get Network ID" },
    { 0x0f, 0x0f, "Query Hop" },
    { 0x10, 0x10, "Resolve UUID" },
    { 0x11, 0x11, "Query Rate Limit" },
    { 0x12, 0x12, "Request TX Rate Limit" },
    { 0x13, 0x13, "Update Rate Limit" },
    { 0x14, 0x14, "Query Supported Interfaces" },
    { 0x15, 0xef, "Reserved" },
    { 0xf0, 0xff, "Transport Specific" },
    { 0,    0,    NULL },
};

/* DSP0236 1.3.3 Table 13 - MCTP control message completion codes. */
static const range_string cc_vals[] = {
    { 0x00, 0x00, "Success" },
    { 0x01, 0x01, "Error" },
    { 0x02, 0x02, "Error: invalid data" },
    { 0x03, 0x03, "Error: invalid length" },
    { 0x04, 0x04, "Error: not ready" },
    { 0x05, 0x05, "Error: unsupported command" },
    { 0x06, 0x7F, "Reserved" },
    { 0x80, 0xFF, "Command Specific" },
    { 0,    0,    NULL },
};

static const true_false_string tfs_rq = { "Request", "Response" };

#define MCTP_CTRL_CMD_SET_EID           0x01
#define MCTP_CTRL_CMD_GET_EID           0x02
#define MCTP_CTRL_CMD_GET_UUID          0x03
#define MCTP_CTRL_CMD_GET_VERSION       0x04
#define MCTP_CTRL_CMD_GET_MSG_TYPES     0x05
#define MCTP_CTRL_CMD_GET_VENDOR        0x06
#define MCTP_CTRL_CMD_RESOLVE_EID       0x07
#define MCTP_CTRL_CMD_ALLOCATE_EIDS     0x08
#define MCTP_CTRL_CMD_ROUTING_UPDATE    0x09
#define MCTP_CTRL_CMD_GET_ROUTING_TABLE 0x0a
#define MCTP_CTRL_CMD_GET_NETWORK_ID    0x0e
#define MCTP_CTRL_CMD_QUERY_HOP         0x0f
#define MCTP_CTRL_CMD_RESOLVE_UUID      0x10
#define MCTP_CTRL_CMD_QUERY_RATE        0x11
#define MCTP_CTRL_CMD_REQUEST_TX_RATE   0x12
#define MCTP_CTRL_CMD_UPDATE_RATE       0x13
#define MCTP_CTRL_CMD_QUERY_INTERFACES  0x14

/* DSP0236 1.3.3 Table 2: the broadcast EID. */
#define MCTP_CTRL_EID_BROADCAST 0xFF
/* DSP0236 1.3.3 Table 2: the null EID. */
#define MCTP_CTRL_EID_NULL      0x00
/* DSP0236 1.3.3 Table 2: 01h-07h are reserved. */
#define MCTP_CTRL_EID_RESERVED_MAX 0x07

/* Fixed portion of a routing table entry, before the variable-length physical
 * address (DSP0236 1.3.3, Table 27 bytes 1-6). */
#define MCTP_CTRL_ROUTING_ENTRY_HDR_LEN 6

/* Fixed message-body length including the headers, or 0 if the layout is
 * open (DSP0236 1.3.3 Tables 14-39; Table 32's TU fields overlap). */
static unsigned
mctp_ctrl_fixed_length(unsigned cmd, bool rq, unsigned cc)
{
    static const unsigned request_lengths[] = {
        0, 5, 3, 3, 4, 3, 4, 4, 6, 0, 4, 3, 3, 3, 3, 5, 20, 3, 10, 10, 3
    };
    static const unsigned success_lengths[] = {
        0, 7, 7, 20, 0, 0, 0, 0, 7, 4, 0, 4, 4, 4, 20, 0, 0, 31, 12, 4, 0
    };

    /* Section 12.3: errors carry no parametric data unless the command
     * explicitly defines it. Neither Table 18 nor Table 24's 80h does. */
    if (!rq && cc != 0)
        return 4;
    if (cmd < array_length(request_lengths))
        return rq ? request_lengths[cmd] : success_lengths[cmd];
    /* Table 39 leaves the request data to the binding, but its response
     * contains only a completion code. */
    if (!rq && cmd >= 0xf0)
        return 4;
    return 0;
}

/* Whether a successful response's length is fully given by its count or
 * format byte: Get Version (Table 18), Get Message Types (Table 19), Get
 * Vendor Defined Message Support with ID format 0 or 1 (Tables 20/21), Get
 * Routing Table Entries (Tables 26/27), Resolve UUID (Tables 33/34) and
 * Query Supported Interfaces (Table 38).  Transport-specific and reserved
 * commands' data is opaque. */
static bool
mctp_ctrl_count_delimited(tvbuff_t *tvb, unsigned cmd)
{
    switch (cmd) {
    case MCTP_CTRL_CMD_GET_VERSION:
    case MCTP_CTRL_CMD_GET_MSG_TYPES:
    case MCTP_CTRL_CMD_GET_ROUTING_TABLE:
    case MCTP_CTRL_CMD_RESOLVE_UUID:
    case MCTP_CTRL_CMD_QUERY_INTERFACES:
        return true;
    case MCTP_CTRL_CMD_GET_VENDOR:
        /* Byte 3 of the response data: the vendor ID format. */
        return tvb_bytes_exist(tvb, 5, 1) && tvb_get_uint8(tvb, 5) <= 1;
    default:
        return false;
    }
}

/* Command-specific meaning of completion code 0x80, or NULL. */
static const char *
mctp_ctrl_cc_specific_name(unsigned cmd, unsigned cc)
{
    if (cc == 0x80) {
        if (cmd == MCTP_CTRL_CMD_GET_VERSION)
            return "Message type number not supported";
        if (cmd == MCTP_CTRL_CMD_ROUTING_UPDATE)
            return "Insufficient routing-table space";
    }
    return NULL;
}

/* DSP0236 1.3.3, Table 14 - Set Endpoint ID request byte 1 [1:0] */
static const value_string set_eid_op_vals[] = {
    { 0x0, "Set EID" },
    { 0x1, "Force EID" },
    { 0x2, "Reset EID" },
    { 0x3, "Set Discovered Flag" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 14 - Set Endpoint ID response byte 2 [5:4] */
static const value_string set_eid_status_vals[] = {
    { 0x0, "EID assignment accepted" },
    { 0x1, "EID assignment rejected" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 14 - Set Endpoint ID response byte 2 [1:0] */
static const value_string set_eid_alloc_status_vals[] = {
    { 0x0, "Device does not use an EID pool" },
    { 0x1, "Endpoint requires EID pool allocation" },
    { 0x2, "Endpoint has already received an EID pool allocation" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 15 - Get Endpoint ID response byte 3 [5:4] */
static const value_string get_eid_endpoint_type_vals[] = {
    { 0x0, "Simple endpoint" },
    { 0x1, "Bus owner/bridge" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 15 - Get Endpoint ID response byte 3 [1:0] */
static const value_string get_eid_eid_type_vals[] = {
    { 0x0, "Dynamic EID" },
    { 0x1, "Static EID supported" },
    { 0x2, "Static EID supported, present EID matches static EID" },
    { 0x3, "Static EID supported, present EID does not match static EID" },
    { 0,   NULL },
};

/* MCTP message type numbers 0x00-0x7f, DSP0239 1.12.0 Table 1. */
#define MCTP_CTRL_MSG_TYPE_RVALS \
    { 0x00, 0x00, "MCTP control protocol" }, \
    { 0x01, 0x01, "PLDM" }, \
    { 0x02, 0x02, "NC-SI over MCTP" }, \
    { 0x03, 0x03, "Ethernet over MCTP" }, \
    { 0x04, 0x04, "NVMe-MI over MCTP" }, \
    { 0x05, 0x05, "SPDM" }, \
    { 0x06, 0x06, "Secured Messages" }, \
    { 0x07, 0x07, "CXL FM API" }, \
    { 0x08, 0x08, "CXL CCI" }, \
    { 0x09, 0x09, "PCIe-MI" }, \
    { 0x0a, 0x7d, "Reserved" }, \
    { 0x7e, 0x7e, "Vendor Defined - PCI" }, \
    { 0x7f, 0x7f, "Vendor Defined - IANA" }

/* DSP0236 1.3.3 Table 18 - Get MCTP Version Support message type numbers. */
static const range_string get_ver_msg_type_vals[] = {
    MCTP_CTRL_MSG_TYPE_RVALS,
    { 0x80, 0xfe, "Reserved" },
    { 0xff, 0xff, "MCTP base specification" },
    { 0, 0, NULL },
};

/* MCTP message type numbers per DSP0239 1.12.0 Table 1, for the Get Message
 * Type Support response list (DSP0236 1.3.3, Table 19). */
static const range_string msg_type_vals[] = {
    MCTP_CTRL_MSG_TYPE_RVALS,
    { 0x80, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* Table 32 gives FFh a meaning distinct from the Table 19 type list. */
static const range_string query_hop_response_type_vals[] = {
    MCTP_CTRL_MSG_TYPE_RVALS,
    { 0x80, 0xfe, "Reserved" },
    { 0xff, 0xff, "All supported message types" },
    { 0, 0, NULL },
};

/* DSP0236 1.3.3, Table 21 - Vendor ID formats.  Only these two rows exist;
 * section 5.3 reserves every other value for future definition. */
static const range_string vendor_format_vals[] = {
    { 0x00, 0x00, "PCI Vendor ID" },
    { 0x01, 0x01, "IANA Enterprise Number" },
    { 0x02, 0xff, "Reserved" },
    { 0,    0,    NULL },
};

static const true_false_string tfs_rate_non_requested = {
    "Only non-requested messages", "Requested and non-requested messages"
};

/* DSP0236 1.3.3, Table 23 - Allocate Endpoint IDs request byte 1 [1:0] */
static const value_string alloc_eids_op_vals[] = {
    { 0x0, "Allocate EIDs" },
    { 0x1, "Force allocation" },
    { 0x2, "Get allocation information" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 23 - Allocate Endpoint IDs response byte 2 [1:0] */
static const value_string alloc_eids_status_vals[] = {
    { 0x0, "Allocation accepted" },
    { 0x1, "Allocation rejected" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 27 - Routing table entry byte 3 [7:6] */
static const value_string get_routing_entry_type_vals[] = {
    { 0x0, "Single endpoint, not an MCTP bridge" },
    { 0x1, "EID range for a bridge, starting EID is the bridge itself" },
    { 0x2, "Single endpoint serving as an MCTP bridge" },
    { 0x3, "EID range for a bridge, excluding the EID of the bridge itself" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 27 - Routing table entry byte 3 [5] */
static const true_false_string tfs_get_routing_static = {
    "Statically configured", "Dynamically created"
};

/* MCTP physical transport binding identifiers per DSP0239 1.12.0, Table 3 */
static const range_string get_routing_binding_id_vals[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "MCTP over SMBus (DSP0237)" },
    { 0x02, 0x02, "MCTP over PCIe VDM (DSP0238)" },
    { 0x03, 0x03, "MCTP over USB (DSP0283)" },
    { 0x04, 0x04, "MCTP over KCS (DSP0254)" },
    { 0x05, 0x05, "MCTP over Serial (DSP0253)" },
    { 0x06, 0x06, "MCTP over I3C (DSP0233)" },
    { 0x07, 0x07, "MCTP over MMBI (DSP0284)" },
    { 0x08, 0x08, "MCTP over PCC (DSP0292)" },
    { 0x09, 0x09, "MCTP over UCIe (DSP0290)" },
    { 0x0a, 0xfe, "Reserved" },
    { 0xff, 0xff, "Vendor defined" },
    { 0, 0, NULL },
};

/* MCTP physical medium identifiers per DSP0239 1.12.0, Table 2. */
static const range_string get_routing_media_type_vals[] = {
    { 0x00, 0x00, "Unspecified" },
    { 0x01, 0x01, "SMBus 2.0 100 kHz compatible" },
    { 0x02, 0x02, "SMBus 2.0 or I2C 100 kHz compatible" },
    { 0x03, 0x03, "I2C 100 kHz compatible (Standard-mode)" },
    { 0x04, 0x04, "SMBus 3.0 or I2C 400 kHz compatible (Fast-mode)" },
    { 0x05, 0x05, "SMBus 3.0 or I2C 1 MHz compatible (Fast-mode Plus)" },
    { 0x06, 0x06, "I2C 3.4 MHz compatible (High-speed mode)" },
    { 0x07, 0x07, "Reserved" },
    { 0x08, 0x08, "PCIe revision 1.1 compatible" },
    { 0x09, 0x09, "PCIe revision 2.0 compatible" },
    { 0x0a, 0x0a, "PCIe revision 2.1 compatible" },
    { 0x0b, 0x0b, "PCIe revision 3.x compatible" },
    { 0x0c, 0x0c, "PCIe revision 4.x compatible" },
    { 0x0d, 0x0d, "PCIe revision 5.x or CXL 1.x/2.x compatible" },
    { 0x0e, 0x0e, "PCIe revision 6.x Non-Flit Mode compatible" },
    { 0x0f, 0x0f, "PCI compatible" },
    { 0x10, 0x10, "USB 1.1 compatible" },
    { 0x11, 0x11, "USB 2.0 compatible" },
    { 0x12, 0x12, "USB 3.0 compatible" },
    { 0x13, 0x17, "Reserved" },
    { 0x18, 0x18, "NC-SI over RBT" },
    { 0x19, 0x19, "UCIe (DSP0290)" },
    { 0x1a, 0x1a, "PCC (DSP0292)" },
    { 0x1b, 0x1f, "Reserved" },
    { 0x20, 0x20, "KCS Legacy (fixed address decoding)" },
    { 0x21, 0x21, "KCS over PCI" },
    { 0x22, 0x22, "Serial Host Legacy (fixed address decoding)" },
    { 0x23, 0x23, "Serial Host over PCI" },
    { 0x24, 0x24, "Asynchronous Serial" },
    { 0x25, 0x2f, "Reserved" },
    { 0x30, 0x30, "I3C Basic compatible" },
    { 0x31, 0x3f, "Reserved" },
    { 0x40, 0x40, "PCIe revision 6.x Flit Mode or CXL 3.x compatible" },
    { 0x41, 0x41, "PCIe revision 7.x or CXL 4.x compatible" },
    { 0x42, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* Whether a version byte is valid BCD (DSP0236 1.3.3 12.7.2). */
static bool
mctp_ctrl_bcd_byte_valid(uint8_t bcd)
{
    return (bcd & 0x0f) <= 9 && ((bcd >> 4) <= 9 || (bcd >> 4) == 0x0f);
}

/* Format one BCD version byte (DSP0236 1.3.3 12.7.2). */
static void
mctp_ctrl_fmt_version_bcd(char *buf, size_t size, uint8_t bcd)
{
    if (!mctp_ctrl_bcd_byte_valid(bcd))
        snprintf(buf, size, "[invalid 0x%02x]", bcd);
    else if ((bcd & 0xf0) == 0xf0)
        snprintf(buf, size, "%u", bcd & 0x0f);
    else
        snprintf(buf, size, "%u%u", bcd >> 4, bcd & 0x0f);
}

/* BASE_CUSTOM formatters for the four version entry bytes. */
static void
mctp_ctrl_fmt_version_major_minor(char *buf, uint32_t value)
{
    mctp_ctrl_fmt_version_bcd(buf, ITEM_LABEL_LENGTH, (uint8_t)value);
}

static void
mctp_ctrl_fmt_version_update(char *buf, uint32_t value)
{
    /* 12.7.2: 0xFF in the update field means "ignore". */
    if ((value & 0xff) == 0xff)
        snprintf(buf, ITEM_LABEL_LENGTH, "Not present (0xff)");
    else
        mctp_ctrl_fmt_version_bcd(buf, ITEM_LABEL_LENGTH, (uint8_t)value);
}

static void
mctp_ctrl_fmt_version_alpha(char *buf, uint32_t value)
{
    uint8_t alpha = (uint8_t)value;

    if (alpha == 0x00)
        snprintf(buf, ITEM_LABEL_LENGTH, "Not used (0x00)");
    else if ((alpha >= 'a' && alpha <= 'z') ||
             (alpha >= 'A' && alpha <= 'Z'))
        snprintf(buf, ITEM_LABEL_LENGTH, "%c (0x%02x)", alpha, alpha);
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "[invalid 0x%02x]", alpha);
}

/* Table 32 TU size: 0000h = the 64-byte baseline, then 16-byte steps. */
static void
mctp_ctrl_fmt_tu(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u bytes (0x%04x)", 64 + 16 * value, value);
}

/* Format a version number entry (DSP0236 1.3.3 12.7.2), e.g. "1.0a". */
static void
mctp_ctrl_fmt_version(char *buf, uint32_t ver)
{
    char major[16], minor[16], update[17] = "", alpha[2] = "";

    mctp_ctrl_fmt_version_bcd(major, sizeof(major), (ver >> 24) & 0xff);
    mctp_ctrl_fmt_version_bcd(minor, sizeof(minor), (ver >> 16) & 0xff);
    if (((ver >> 8) & 0xff) != 0xff) {
        update[0] = '.';
        mctp_ctrl_fmt_version_bcd(update + 1, sizeof(update) - 1,
                                  (ver >> 8) & 0xff);
    }
    /* The alpha byte is 0 (unused) or one of [a-zA-Z] (section 12.7.2);
     * don't copy other, possibly unprintable, octets into the label. */
    if (g_ascii_isalpha(ver & 0xff)) {
        alpha[0] = ver & 0xff;
        alpha[1] = '\0';
    }
    snprintf(buf, ITEM_LABEL_LENGTH, "%s.%s%s%s (0x%08x)",
             major, minor, update, alpha, ver);
}

/* Whether this message came over SMBus/I2C (DSP0237 6.8/6.9). */
static bool
mctp_ctrl_ingress_is_smbus(const packet_info *pinfo)
{
    mctp_ingress_scope scope;

    mctp_ingress_scope_get(pinfo, &scope);
    return scope.kind == MCTP_SCOPE_I2C_BUS;
}

/* The physical address size the media type's binding defines, or 0 when
 * no media binding defines one: DSP0237 6.7/6.8 Tables 2/3 (SMBus/I2C media
 * 01h-05h), DSP0238 6.3/6.4 Tables 3-5 (PCIe 08h-0Eh non-Flit, 40h/41h
 * Flit) and DSP0233 5.5/5.6 Table 5 (I3C 30h).  DSP0237 does not list
 * 06h (I2C high-speed), so that stays raw. */
static unsigned
mctp_ctrl_phys_addr_len(unsigned media)
{
    if (media >= 0x01 && media <= 0x05)
        return 1;
    if (media >= 0x08 && media <= 0x0e)
        return 2;
    if (media == 0x40 || media == 0x41)
        return 3;
    if (media == 0x30)
        return 1;
    return 0;
}

/* A Table 27 / Table 34 physical address, MSB first, laid out per the
 * media type's binding; other media and mismatched sizes stay raw. */
static void
dissect_mctp_ctrl_phys_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            int hf_raw, unsigned offset, unsigned media,
                            unsigned size)
{
    proto_item *pi;
    proto_tree *addr_tree;
    unsigned expected;

    if (!size)
        return;
    pi = proto_tree_add_item(tree, hf_raw, tvb, offset, size, ENC_NA);
    expected = mctp_ctrl_phys_addr_len(media);
    if (!expected)
        return;
    if (size != expected) {
        expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_phys_addr_size,
            "Physical address size %u differs from the %u byte%s that media "
            "type 0x%02x's transport binding defines", size, expected,
            plurality(expected, "", "s"), media);
        return;
    }
    addr_tree = proto_item_add_subtree(pi, ett_mctp_ctrl_phys_addr);
    if (expected == 1) {
        proto_tree_add_item(addr_tree, media == 0x30 ?
                            hf_mctp_ctrl_phys_i3c_addr : hf_mctp_ctrl_phys_smbus_addr,
                            tvb, offset, 1, ENC_NA);
        proto_tree_add_item(addr_tree, hf_mctp_ctrl_phys_addr_rsvd,
                            tvb, offset, 1, ENC_NA);
        return;
    }
    /* DSP0238 Table 5 prefixes the Flit Mode address with the segment. */
    if (expected == 3)
        proto_tree_add_item(addr_tree, hf_mctp_ctrl_phys_segment,
                            tvb, offset++, 1, ENC_NA);
    proto_tree_add_item(addr_tree, hf_mctp_ctrl_phys_bus, tvb, offset++, 1, ENC_NA);
    /* The address does not say whether it is a BDF or an ARI ID. */
    proto_tree_add_item(addr_tree, hf_mctp_ctrl_phys_device, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(addr_tree, hf_mctp_ctrl_phys_function, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(addr_tree, hf_mctp_ctrl_phys_ari_function,
                        tvb, offset, 1, ENC_NA);
}

/* A reported endpoint EID: Table 2 reserves 01h-07h and FFh is the
 * broadcast EID; 00h is "not yet assigned" (Table 15). */
static void
mctp_ctrl_check_reported_eid(packet_info *pinfo, proto_item *pi,
                             const char *name, uint32_t eid)
{
    if ((eid != MCTP_CTRL_EID_NULL && eid <= MCTP_CTRL_EID_RESERVED_MAX) ||
        eid == MCTP_CTRL_EID_BROADCAST)
        expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_invalid_value,
            "%s 0x%02x is %s, not available for assignment (DSP0236 special endpoint IDs)",
            name, eid,
            eid == MCTP_CTRL_EID_BROADCAST ? "the broadcast EID" : "reserved");
}

static unsigned
dissect_mctp_ctrl_set_eid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          bool rq, unsigned offset)
{
    if (rq) {
        proto_item *pi;
        uint32_t op, eid;

        proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_rsvd, tvb, offset, 1, ENC_NA);
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_set_eid_op, tvb, offset, 1,
                                     ENC_NA, &op);
        offset++;
        pi = proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_set_eid_eid, tvb,
                                          offset, 1, ENC_NA, &eid);
        /* Table 14: 00h and FFh are illegal for Set and Force EID; Table 2
         * reserves 01h-07h.  Reset EID and Set Discovered Flag ignore the
         * byte. */
        if (op <= 1) {
            if (eid == MCTP_CTRL_EID_NULL || eid == MCTP_CTRL_EID_BROADCAST)
                expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_invalid_value,
                    "Endpoint ID 0x%02x is illegal for %s (DSP0236 Set Endpoint ID message)",
                    eid, op == 0 ? "Set EID" : "Force EID");
            else if (eid <= MCTP_CTRL_EID_RESERVED_MAX)
                expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_invalid_value,
                    "Endpoint ID 0x%02x is reserved, not available for "
                    "assignment, for %s (DSP0236 special endpoint IDs)",
                    eid, op == 0 ? "Set EID" : "Force EID");
        }
        offset++;
    } else {
        proto_item *pi;
        uint32_t eid;

        proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_rsvd_hi, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_status,
                            tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_rsvd_lo, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_alloc_status,
                            tvb, offset, 1, ENC_NA);
        offset++;
        pi = proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_set_eid_setting,
                                          tvb, offset, 1, ENC_NA, &eid);
        mctp_ctrl_check_reported_eid(pinfo, pi, "EID setting", eid);
        offset++;
        proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_pool_size,
                            tvb, offset, 1, ENC_NA);
        offset++;
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_get_eid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          bool rq, unsigned offset)
{
    if (!rq) {
        proto_item *pi;
        uint32_t eid;

        pi = proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_get_eid_eid,
                                          tvb, offset, 1, ENC_NA, &eid);
        mctp_ctrl_check_reported_eid(pinfo, pi, "Endpoint ID", eid);
        offset++;
        proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_rsvd_hi, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_endpoint_type,
                            tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_rsvd_lo, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_eid_type,
                            tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_medium_info,
                            tvb, offset, 1, ENC_NA);
        /* DSP0237 6.9 Table 4 defines this byte for SMBus/I2C. */
        if (mctp_ctrl_ingress_is_smbus(pinfo)) {
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_medium_rsvd, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_medium_fairness,
                                tvb, offset, 1, ENC_NA);
        }
        offset++;
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_get_uuid(tvbuff_t *tvb, proto_tree *tree,
                           unsigned cmd, bool rq, unsigned offset)
{
    if (!rq) {
        /* RFC4122 byte order, MSB first (Table 17) */
        proto_tree_add_item(tree, cmd == MCTP_CTRL_CMD_GET_UUID ?
                            hf_mctp_ctrl_uuid : hf_mctp_ctrl_network_uuid,
                            tvb, offset, 16, ENC_BIG_ENDIAN);
        offset += 16;
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_get_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              bool rq, unsigned offset)
{
    unsigned count;
    unsigned i;

    if (rq) {
        proto_tree_add_item(tree, hf_mctp_ctrl_get_ver_msg_type,
                            tvb, offset, 1, ENC_NA);
        offset += 1;
    } else {
        const mctp_ctrl_transaction *trans;
        proto_item *count_item;

        count_item = proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_get_ver_count,
                                     tvb, offset, 1, ENC_NA, &count);
        offset += 1;
        /* 7Eh/7Fh responses are vendor-defined (Table 18). */
        trans = (const mctp_ctrl_transaction *)p_get_proto_data(
                    wmem_file_scope(), pinfo, proto_mctp_ctrl, 0);
        if (count == 0 && trans && trans->has_ver_selector &&
            trans->ver_selector != 0x7e && trans->ver_selector != 0x7f)
            expert_add_info_format(pinfo, count_item, &ei_mctp_ctrl_invalid_value,
                "Version Number Entry count is 1-based; 0 is invalid (DSP0236 Get MCTP Version Support message)");
        for (i = 0; i < count; i++) {
            proto_item *pi;
            proto_tree *entry_tree;
            uint32_t ver;

            pi = proto_tree_add_item_ret_uint(tree,
                                hf_mctp_ctrl_get_ver_entry,
                                tvb, offset, 4, ENC_BIG_ENDIAN, &ver);
            /* The four entry bytes (12.7.2). */
            entry_tree = proto_item_add_subtree(pi,
                                ett_mctp_ctrl_get_ver_entry);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_get_ver_major,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_get_ver_minor,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_get_ver_update,
                                tvb, offset + 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_get_ver_alpha,
                                tvb, offset + 3, 1, ENC_NA);
            /* Major/minor must be valid BCD; the update byte may be 0xff
             * ("no update"), otherwise it too must be valid BCD (12.7.2). */
            if (!mctp_ctrl_bcd_byte_valid((ver >> 24) & 0xff) ||
                !mctp_ctrl_bcd_byte_valid((ver >> 16) & 0xff) ||
                (((ver >> 8) & 0xff) != 0xff &&
                 !mctp_ctrl_bcd_byte_valid((ver >> 8) & 0xff)))
                expert_add_info(pinfo, pi, &ei_mctp_ctrl_ver_bcd);
            /* The alpha byte is 00h or an ASCII letter (12.7.2). */
            if ((ver & 0xff) != 0 && !g_ascii_isalpha(ver & 0xff))
                expert_add_info(pinfo, pi, &ei_mctp_ctrl_ver_alpha);
            offset += 4;
        }
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_get_msg_types(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, bool rq, unsigned offset)
{
    unsigned count;
    unsigned i;

    if (!rq) {
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_msg_type_count,
                                     tvb, offset, 1, ENC_NA, &count);
        offset += 1;
        for (i = 0; i < count; i++) {
            proto_item *pi;
            uint32_t type;

            pi = proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_msg_type,
                                              tvb, offset, 1, ENC_NA, &type);
            if (type == MCTP_TYPE_CONTROL)
                expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_invalid_value,
                    "MCTP control is implied and excluded from the additional"
                    " message types (DSP0236 Get Message Type Support message)");
            offset += 1;
        }
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_allocate_eids(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, bool rq, unsigned offset)
{
    if (rq) {
        proto_item *start_pi;
        uint32_t op, count, start;

        proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_rsvd, tvb, offset, 1, ENC_NA);
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_alloc_eids_op,
                                     tvb, offset, 1, ENC_NA, &op);
        offset++;
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_alloc_eids_count,
                                     tvb, offset, 1, ENC_NA, &count);
        offset++;
        start_pi = proto_tree_add_item_ret_uint(tree,
                hf_mctp_ctrl_alloc_eids_start, tvb, offset, 1, ENC_NA, &start);
        /* Table 23: a non-empty Allocate or Force pool must lie in Table 2's
         * assignable range 08h-FEh.  Count 0 is legal; Get allocation
         * information ignores both fields. */
        if (op <= 1 && count > 0) {
            if (start <= MCTP_CTRL_EID_RESERVED_MAX)
                expert_add_info_format(pinfo, start_pi,
                    &ei_mctp_ctrl_invalid_value,
                    "Starting Endpoint ID 0x%02x: the pool 0x%02x-0x%02x "
                    "includes null or reserved EIDs 00h-07h, not available "
                    "for allocation (DSP0236 special endpoint IDs)",
                    start, start, MIN(start + count - 1, 0xff));
            if (start + count - 1 >= MCTP_CTRL_EID_BROADCAST)
                expert_add_info_format(pinfo, start_pi,
                    &ei_mctp_ctrl_invalid_value,
                    "Starting Endpoint ID 0x%02x with %u EIDs runs past FEh, "
                    "the last assignable EID (DSP0236 special endpoint IDs)", start, count);
        }
        offset++;
    } else {
        proto_item *first_pi;
        uint32_t first;

        proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_rsvd, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_status,
                            tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_pool_size,
                            tvb, offset, 1, ENC_NA);
        offset++;
        first_pi = proto_tree_add_item_ret_uint(tree,
                hf_mctp_ctrl_alloc_eids_first, tvb, offset, 1, ENC_NA, &first);
        /* Table 23: 00h means no pool; Table 2 reserves 01h-07h and FFh. */
        if ((first != MCTP_CTRL_EID_NULL && first <= MCTP_CTRL_EID_RESERVED_MAX) ||
            first == MCTP_CTRL_EID_BROADCAST)
            expert_add_info_format(pinfo, first_pi, &ei_mctp_ctrl_invalid_value,
                "First Endpoint ID 0x%02x is %s, not available for allocation "
                "(DSP0236 special endpoint IDs)", first,
                first == MCTP_CTRL_EID_BROADCAST ? "the broadcast EID" : "reserved");
        offset++;
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_get_vendor(tvbuff_t *tvb, proto_tree *tree,
                             bool rq, unsigned offset)
{
    if (rq) {
        proto_tree_add_item(tree, hf_mctp_ctrl_vendor_selector,
                            tvb, offset, 1, ENC_NA);
        offset++;
    } else {
        unsigned format, id_size;
        proto_tree_add_item(tree, hf_mctp_ctrl_vendor_next_selector,
                            tvb, offset++, 1, ENC_NA);
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_vendor_format,
                            tvb, offset++, 1, ENC_NA, &format);
        /* Reserved formats have no known ID length (Tables 20/21). */
        if (format > 1)
            return offset;
        id_size = format == 0 ? 2 : 4;
        proto_tree_add_item(tree, format == 0 ? hf_mctp_ctrl_vendor_pci :
                            hf_mctp_ctrl_vendor_iana,
                            tvb, offset, id_size, ENC_BIG_ENDIAN);
        offset += id_size;
        proto_tree_add_item(tree, hf_mctp_ctrl_vendor_command_set,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_resolve_eid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              bool rq, unsigned offset)
{
    unsigned remaining;

    if (rq) {
        proto_tree_add_item(tree, hf_mctp_ctrl_resolve_eid_target,
                            tvb, offset++, 1, ENC_NA);
    } else {
        proto_tree_add_item(tree, hf_mctp_ctrl_resolve_eid_bridge,
                            tvb, offset++, 1, ENC_NA);
        remaining = tvb_reported_length_remaining(tvb, offset);
        /* Table 22: one-byte SMBus address tail (DSP0237 Table 3). */
        if (mctp_ctrl_ingress_is_smbus(pinfo) && remaining == 1) {
            proto_tree_add_item(tree, hf_mctp_ctrl_resolve_eid_slave_addr,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_resolve_eid_addr_rsvd, tvb, offset, 1, ENC_NA);
        } else if (remaining) {
            proto_tree_add_item(tree, hf_mctp_ctrl_resolve_eid_addr,
                                tvb, offset, remaining, ENC_NA);
        }
        offset += remaining;
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_routing_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 bool rq, unsigned offset)
{
    unsigned count, remaining;
    unsigned i;
    bool smbus;

    if (rq) {
        proto_item *count_item;

        count_item = proto_tree_add_item_ret_uint(tree,
                            hf_mctp_ctrl_routing_update_count,
                            tvb, offset++, 1, ENC_NA, &count);
        if (count == 0) {
            expert_add_info_format(pinfo, count_item, &ei_mctp_ctrl_invalid_value,
                "Count of update entries is 1-based; 0 is invalid (DSP0236 Routing Information Update message)");
            return offset;
        }
        /* Table 25 records are walkable only with a binding address size
         * (DSP0237 6.8: one byte). */
        smbus = mctp_ctrl_ingress_is_smbus(pinfo);
        for (i = 0; i < (smbus ? count : 1); i++) {
            proto_item *entry, *type_item;
            proto_tree *entry_tree;
            unsigned need = smbus ? 4 : 3;
            uint32_t type;

            entry = proto_tree_add_item(tree, hf_mctp_ctrl_routing_update_entry,
                                tvb, offset, need, ENC_NA);
            proto_item_append_text(entry, " %u", i + 1);
            entry_tree = proto_item_add_subtree(entry,
                                ett_mctp_ctrl_routing_update_entry);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_routing_update_rsvd, tvb, offset, 1, ENC_NA);
            type_item = proto_tree_add_item_ret_uint(entry_tree,
                                hf_mctp_ctrl_routing_update_type,
                                tvb, offset++, 1, ENC_NA, &type);
            if (type > 3)
                expert_add_info_format(pinfo, type_item, &ei_mctp_ctrl_invalid_value,
                    "Undefined entry type %u (DSP0236 Routing Information Update entry format defines 0-3)", type);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_routing_update_range_size,
                                tvb, offset++, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_routing_update_eid,
                                tvb, offset++, 1, ENC_NA);
            if (smbus) {
                proto_tree_add_item(entry_tree,
                                hf_mctp_ctrl_routing_update_slave_addr,
                                tvb, offset, 1, ENC_NA);
                proto_tree_add_item(entry_tree, hf_mctp_ctrl_routing_update_addr_rsvd, tvb, offset, 1, ENC_NA);
                offset++;
            }
        }
        /* The rest is not walkable without the binding's address size. */
        if (!smbus) {
            remaining = tvb_reported_length_remaining(tvb, offset);
            if (remaining)
                proto_tree_add_item(tree, hf_mctp_ctrl_routing_update_data,
                                    tvb, offset, remaining, ENC_NA);
            offset += remaining;
        }
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_query_hop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            bool rq, unsigned offset)
{
    unsigned remaining;

    if (rq) {
        proto_item *pi;
        uint32_t target;

        pi = proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_query_hop_target,
                                          tvb, offset++, 1, ENC_NA, &target);
        if (target == MCTP_CTRL_EID_NULL || target == MCTP_CTRL_EID_BROADCAST)
            expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_invalid_value,
                "Target Endpoint ID 0x%02x is reserved (DSP0236 Query Hop message)", target);
        proto_tree_add_item(tree, hf_mctp_ctrl_query_hop_msg_type,
                            tvb, offset++, 1, ENC_NA);
    } else {
        proto_tree_add_item(tree, hf_mctp_ctrl_query_hop_bridge,
                            tvb, offset++, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_query_hop_response_type,
                            tvb, offset++, 1, ENC_NA);
        /* Table 32 prints the TU fields at bytes 4:5 and 5:6; two
         * 2-byte fields can only be 4:5 and 6:7 (MSB first, 5.2). */
        remaining = tvb_reported_length_remaining(tvb, offset);
        if (remaining >= 4) {
            proto_tree_add_item(tree, hf_mctp_ctrl_query_hop_in_tu,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_mctp_ctrl_query_hop_out_tu,
                                tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            offset += 4;
            if (remaining > 4) {
                proto_item *pi = proto_tree_add_item(tree, hf_mctp_ctrl_excess,
                                    tvb, offset, remaining - 4, ENC_NA);
                expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_length,
                    "Query Hop response has %u bytes beyond its 4-byte "
                    "transmission unit fields (DSP0236 Query Hop message)", remaining - 4);
                offset += remaining - 4;
            }
        } else {
            if (remaining)
                proto_tree_add_item(tree, hf_mctp_ctrl_query_hop_tu_data,
                                    tvb, offset, remaining, ENC_NA);
            proto_tree_add_expert_format(tree, pinfo, &ei_mctp_ctrl_length,
                tvb, offset, remaining,
                "Query Hop response transmission unit fields take 4 bytes, "
                "but %u are present (DSP0236 Query Hop message)", remaining);
            offset += remaining;
        }
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_resolve_uuid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               bool rq, unsigned offset)
{
    unsigned count;
    unsigned i;

    if (rq) {
        proto_tree_add_item(tree, hf_mctp_ctrl_resolve_uuid,
                            tvb, offset, 16, ENC_BIG_ENDIAN);
        offset += 16;
        proto_tree_add_item(tree, hf_mctp_ctrl_resolve_uuid_handle,
                            tvb, offset++, 1, ENC_NA);
    } else {
        proto_tree_add_item(tree, hf_mctp_ctrl_resolve_uuid_next_handle,
                            tvb, offset++, 1, ENC_NA);
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_resolve_uuid_count,
                            tvb, offset++, 1, ENC_NA, &count);
        for (i = 0; i < count; i++) {
            proto_item *entry;
            proto_tree *entry_tree;
            unsigned addr_size, media;

            entry = proto_tree_add_item(tree, hf_mctp_ctrl_resolve_uuid_entry,
                            tvb, offset, 4, ENC_NA);
            entry_tree = proto_item_add_subtree(entry, ett_mctp_ctrl_resolve_uuid_entry);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_resolve_uuid_eid,
                                tvb, offset++, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_resolve_uuid_binding,
                                tvb, offset++, 1, ENC_NA);
            proto_tree_add_item_ret_uint(entry_tree, hf_mctp_ctrl_resolve_uuid_media,
                                tvb, offset++, 1, ENC_NA, &media);
            proto_tree_add_item_ret_uint(entry_tree, hf_mctp_ctrl_resolve_uuid_addr_size,
                                tvb, offset++, 1, ENC_NA, &addr_size);
            dissect_mctp_ctrl_phys_addr(tvb, pinfo, entry_tree,
                                        hf_mctp_ctrl_resolve_uuid_addr,
                                        offset, media, addr_size);
            offset += addr_size;
            proto_item_set_end(entry, tvb, offset);
        }
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_query_rate(tvbuff_t *tvb, proto_tree *tree,
                             bool rq, unsigned offset)
{
    unsigned i;

    if (!rq) {
        const int fields[] = {
            hf_mctp_ctrl_rate_rx_buffer, hf_mctp_ctrl_rate_rx_rate,
            hf_mctp_ctrl_rate_max_tx_rate, hf_mctp_ctrl_rate_min_tx_rate,
            hf_mctp_ctrl_rate_max_burst, hf_mctp_ctrl_rate_burst,
            hf_mctp_ctrl_rate_tx_rate
        };
        const unsigned sizes[] = { 4, 4, 4, 4, 3, 3, 4 };
        for (i = 0; i < array_length(fields); i++) {
            proto_tree_add_item(tree, fields[i], tvb, offset, sizes[i], ENC_BIG_ENDIAN);
            offset += sizes[i];
        }
        proto_tree_add_item(tree, hf_mctp_ctrl_rate_rsvd, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mctp_ctrl_rate_non_requested,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mctp_ctrl_rate_supported,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_tx_rate(tvbuff_t *tvb, proto_tree *tree,
                          unsigned cmd, bool rq, unsigned offset)
{
    if (rq || cmd == MCTP_CTRL_CMD_REQUEST_TX_RATE) {
        unsigned burst_size = rq ? 3 : 4;
        int burst_field = !rq ? hf_mctp_ctrl_rate_granted_burst :
            cmd == MCTP_CTRL_CMD_REQUEST_TX_RATE ?
            hf_mctp_ctrl_rate_requested_burst : hf_mctp_ctrl_rate_burst;
        /* Tables 36/37: request bursts are 24-bit; Table 36's
         * successful response burst is explicitly 32-bit. */
        proto_tree_add_item(tree, burst_field, tvb, offset, burst_size, ENC_BIG_ENDIAN);
        offset += burst_size;
        proto_tree_add_item(tree, rq && cmd == MCTP_CTRL_CMD_REQUEST_TX_RATE ?
                            hf_mctp_ctrl_rate_requested_rate : hf_mctp_ctrl_rate_tx_rate,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_query_interfaces(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   bool rq, unsigned offset)
{
    unsigned count;
    unsigned i;

    if (!rq) {
        proto_item *pi;

        pi = proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_interfaces_count,
                            tvb, offset++, 1, ENC_NA, &count);
        if (count == 0)
            expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_invalid_value,
                "Supported Interfaces Count shall be at least 1 (DSP0236 Query Supported Interfaces)");
        for (i = 0; i < count; i++) {
            proto_tree_add_item(tree, hf_mctp_ctrl_interfaces_media,
                                tvb, offset++, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_interfaces_eid,
                                tvb, offset++, 1, ENC_NA);
        }
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_get_routing_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                    bool rq, unsigned offset)
{
    unsigned count;
    unsigned i;

    if (rq) {
        proto_tree_add_item(tree, hf_mctp_ctrl_get_routing_handle,
                            tvb, offset, 1, ENC_NA);
        offset += 1;
    } else {
        proto_tree_add_item(tree, hf_mctp_ctrl_get_routing_next_handle,
                            tvb, offset, 1, ENC_NA);
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_get_routing_count,
                                     tvb, offset + 1, 1, ENC_NA, &count);
        offset += 2;
        for (i = 0; i < count; i++) {
            proto_item *pi;
            proto_tree *entry_tree;
            unsigned range_size, start_eid, addr_size, media;

            pi = proto_tree_add_item(tree, hf_mctp_ctrl_get_routing_entry,
                                     tvb, offset, MCTP_CTRL_ROUTING_ENTRY_HDR_LEN, ENC_NA);
            entry_tree = proto_item_add_subtree(pi,
                                    ett_mctp_ctrl_get_routing_entry);

            proto_tree_add_item_ret_uint(entry_tree,
                                hf_mctp_ctrl_get_routing_range_size,
                                tvb, offset, 1, ENC_NA, &range_size);
            proto_tree_add_item_ret_uint(entry_tree,
                                hf_mctp_ctrl_get_routing_start_eid,
                                tvb, offset + 1, 1, ENC_NA, &start_eid);
            proto_tree_add_item(entry_tree,
                                hf_mctp_ctrl_get_routing_entry_type,
                                tvb, offset + 2, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_get_routing_static,
                                tvb, offset + 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(entry_tree, hf_mctp_ctrl_get_routing_port,
                                tvb, offset + 2, 1, ENC_NA);
            proto_tree_add_item(entry_tree,
                                hf_mctp_ctrl_get_routing_binding_id,
                                tvb, offset + 3, 1, ENC_NA);
            proto_tree_add_item_ret_uint(entry_tree,
                                hf_mctp_ctrl_get_routing_media_type,
                                tvb, offset + 4, 1, ENC_NA, &media);
            proto_tree_add_item_ret_uint(entry_tree,
                                hf_mctp_ctrl_get_routing_addr_size,
                                tvb, offset + 5, 1, ENC_NA, &addr_size);
            offset += MCTP_CTRL_ROUTING_ENTRY_HDR_LEN;
            proto_item_append_text(pi, ": EID 0x%02x, range size %u",
                                   start_eid, range_size);

            dissect_mctp_ctrl_phys_addr(tvb, pinfo, entry_tree,
                                        hf_mctp_ctrl_get_routing_addr,
                                        offset, media, addr_size);
            offset += addr_size;
            proto_item_set_end(pi, tvb, offset);
        }
    }
    return offset;

}

static unsigned
dissect_mctp_ctrl_transport_specific(tvbuff_t *tvb, proto_tree *tree,
                                     unsigned cmd, bool rq, unsigned offset)
{
    if (rq && cmd >= 0xf0) {
        unsigned binding;
        proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_transport_binding,
                            tvb, offset++, 1, ENC_NA, &binding);
        proto_tree_add_item(tree, hf_mctp_ctrl_transport_media,
                            tvb, offset++, 1, ENC_NA);
        if (binding == 0xff) {
            proto_tree_add_item(tree, hf_mctp_ctrl_transport_iana,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        /* Only the remainder after Table 39's envelope is opaque. */
    }
    return offset;
}

/* Dissect the command payload; return the offset past it
 * (DSP0236 1.3.3 clause 12; 0x0b-0x0d carry no payload). */
static unsigned
dissect_mctp_ctrl_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        unsigned cmd, bool rq, unsigned offset)
{
    switch (cmd) {
    case MCTP_CTRL_CMD_SET_EID:
        return dissect_mctp_ctrl_set_eid(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_GET_EID:
        return dissect_mctp_ctrl_get_eid(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_GET_UUID:
    case MCTP_CTRL_CMD_GET_NETWORK_ID:
        return dissect_mctp_ctrl_get_uuid(tvb, tree, cmd, rq, offset);
    case MCTP_CTRL_CMD_GET_VERSION:
        return dissect_mctp_ctrl_get_version(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_GET_MSG_TYPES:
        return dissect_mctp_ctrl_get_msg_types(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_ALLOCATE_EIDS:
        return dissect_mctp_ctrl_allocate_eids(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_GET_VENDOR:
        return dissect_mctp_ctrl_get_vendor(tvb, tree, rq, offset);
    case MCTP_CTRL_CMD_RESOLVE_EID:
        return dissect_mctp_ctrl_resolve_eid(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_ROUTING_UPDATE:
        return dissect_mctp_ctrl_routing_update(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_QUERY_HOP:
        return dissect_mctp_ctrl_query_hop(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_RESOLVE_UUID:
        return dissect_mctp_ctrl_resolve_uuid(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_QUERY_RATE:
        return dissect_mctp_ctrl_query_rate(tvb, tree, rq, offset);
    case MCTP_CTRL_CMD_REQUEST_TX_RATE:
    case MCTP_CTRL_CMD_UPDATE_RATE:
        return dissect_mctp_ctrl_tx_rate(tvb, tree, cmd, rq, offset);
    case MCTP_CTRL_CMD_QUERY_INTERFACES:
        return dissect_mctp_ctrl_query_interfaces(tvb, pinfo, tree, rq, offset);
    case MCTP_CTRL_CMD_GET_ROUTING_TABLE:
        return dissect_mctp_ctrl_get_routing_table(tvb, pinfo, tree, rq, offset);
    default:
        return dissect_mctp_ctrl_transport_specific(tvb, tree, cmd, rq, offset);
    }
}

/* A key responder for a request any endpoint may answer: one sent to the
 * null or broadcast EID.  Outside the 8-bit EID space. */
#define MCTP_CTRL_ANY_RESPONDER 0x100
/* A key physical address: 0 when absent, else flagged above the 7 bits. */
#define MCTP_CTRL_PHYS(addr)    (0x100 | (addr))

/* The 7-bit SMBus/I2C slave address packet-mctp-smbus.c put in addr, as a
 * key physical address, or 0 on other transports. */
static uint32_t
mctp_ctrl_phys_addr_key(const packet_info *pinfo, const address *addr)
{
    uint8_t slave;

    if (!mctp_smbus_slave_addr(addr, &slave) ||
        !mctp_ctrl_ingress_is_smbus(pinfo))
        return 0;
    return MCTP_CTRL_PHYS(slave);
}

static unsigned
mctp_ctrl_key_hash(const void *key)
{
    return wmem_strong_hash((const uint8_t *)key, sizeof(mctp_ctrl_key));
}

static gboolean
mctp_ctrl_key_equal(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(mctp_ctrl_key)) == 0;
}

/* Pair a response with its request: it echoes the request's command and
 * Instance ID (Table 10, 12.3) on the request's tag with TO clear (8.5),
 * from the endpoint the request went to.  Decided on the first pass. */
static mctp_ctrl_transaction *
mctp_ctrl_track(packet_info *pinfo, bool rq, unsigned cmd, unsigned iid)
{
    mctp_ctrl_transaction *trans;
    mctp_ctrl_key key;
    uint8_t src, dst;

    if (PINFO_FD_VISITED(pinfo))
        return (mctp_ctrl_transaction *)p_get_proto_data(wmem_file_scope(),
                                                         pinfo, proto_mctp_ctrl, 0);

    src = *(const uint8_t *)pinfo->src.data;
    dst = *(const uint8_t *)pinfo->dst.data;
    memset(&key, 0, sizeof(key));
    mctp_ingress_scope_get(pinfo, &key.scope);
    key.tag = pinfo->srcport & 0x07;
    key.iid = iid;
    key.cmd = cmd;

    if (rq) {
        key.requester = src;
        if (dst == MCTP_CTRL_EID_NULL || dst == MCTP_CTRL_EID_BROADCAST) {
            key.responder = MCTP_CTRL_ANY_RESPONDER;
            /* Null-EID requests are routed by physical address alone
             * (DSP0236 Table 2), so tell their targets apart by it. */
            if (dst == MCTP_CTRL_EID_NULL) {
                key.phys_requester = mctp_ctrl_phys_addr_key(pinfo, &pinfo->net_src);
                key.phys_responder = mctp_ctrl_phys_addr_key(pinfo, &pinfo->net_dst);
            }
        } else {
            mctp_ctrl_key any = key;

            key.responder = dst;
            /* The requester reused the tag and Instance ID, so its earlier
             * broadcast or null-EID request is no longer outstanding. */
            any.responder = MCTP_CTRL_ANY_RESPONDER;
            wmem_map_remove(mctp_ctrl_requests, &any);
        }
        trans = wmem_new0(wmem_file_scope(), mctp_ctrl_transaction);
        trans->req_frame = pinfo->num;
        trans->req_time = pinfo->abs_ts;
        trans->broadcast = dst == MCTP_CTRL_EID_BROADCAST;
        /* A newer request with the same identity supersedes the old one. */
        wmem_map_insert(mctp_ctrl_requests,
                        wmem_memdup(wmem_file_scope(), &key, sizeof(key)), trans);
    } else {
        uint32_t phys_src = mctp_ctrl_phys_addr_key(pinfo, &pinfo->net_src);
        uint32_t phys_dst = mctp_ctrl_phys_addr_key(pinfo, &pinfo->net_dst);

        key.requester = dst;
        key.responder = src;
        /* A unicast request takes one response. */
        trans = (mctp_ctrl_transaction *)wmem_map_remove(mctp_ctrl_requests, &key);
        /* So does a null-EID request, from the physical address it went to. */
        if (!trans && phys_src && phys_dst) {
            key.responder = MCTP_CTRL_ANY_RESPONDER;
            key.phys_requester = phys_dst;
            key.phys_responder = phys_src;
            trans = (mctp_ctrl_transaction *)wmem_map_remove(mctp_ctrl_requests,
                                                             &key);
        }
        if (!trans) {
            key.responder = MCTP_CTRL_ANY_RESPONDER;
            key.phys_requester = 0;
            key.phys_responder = 0;
            trans = (mctp_ctrl_transaction *)wmem_map_lookup(mctp_ctrl_requests,
                                                             &key);
            if (trans && !trans->broadcast) {
                /* A null-EID request with no physical addresses to tell
                 * its targets apart: the first response takes it. */
                wmem_map_remove(mctp_ctrl_requests, &key);
            } else if (trans) {
                /* Each endpoint answers a broadcast request once. */
                void *responder = GUINT_TO_POINTER(0x80000000U |
                                                   (phys_src << 8) | src);

                if (!trans->responders)
                    trans->responders = wmem_map_new(wmem_file_scope(),
                                                      g_direct_hash,
                                                      g_direct_equal);
                if (wmem_map_contains(trans->responders, responder))
                    trans = NULL;
                else
                    wmem_map_insert(trans->responders, responder, responder);
            }
        }
        if (trans && !trans->resp_frame)
            trans->resp_frame = pinfo->num;
    }
    if (trans)
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mctp_ctrl, 0, trans);
    return trans;
}

static void
mctp_ctrl_add_pairing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      proto_item *ti, bool rq, unsigned cmd, unsigned iid,
                      const nstime_t *start_time)
{
    mctp_ctrl_transaction *trans = mctp_ctrl_track(pinfo, rq, cmd, iid);
    proto_item *pi;

    if (rq && trans && !PINFO_FD_VISITED(pinfo) &&
        cmd == MCTP_CTRL_CMD_GET_VERSION && tvb_bytes_exist(tvb, 3, 1)) {
        trans->has_ver_selector = true;
        trans->ver_selector = tvb_get_uint8(tvb, 3);
    }

    if (rq) {
        if (trans && trans->resp_frame) {
            pi = proto_tree_add_uint(tree, hf_mctp_ctrl_response_in,
                                     tvb, 0, 0, trans->resp_frame);
            proto_item_set_generated(pi);
        }
    } else if (trans) {
        nstime_t delta;

        pi = proto_tree_add_uint(tree, hf_mctp_ctrl_response_to,
                                 tvb, 0, 0, trans->req_frame);
        proto_item_set_generated(pi);
        nstime_delta(&delta, start_time, &trans->req_time);
        pi = proto_tree_add_time(tree, hf_mctp_ctrl_response_time,
                                 tvb, 0, 0, &delta);
        proto_item_set_generated(pi);
    } else {
        expert_add_info(pinfo, ti, &ei_mctp_ctrl_unmatched_response);
    }
}

static int
dissect_mctp_ctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    proto_tree *mctp_ctrl_tree, *mctp_ctrl_hdr_tree;
    unsigned len, expected, payload_start, cmd, iid, cc = 0;
    proto_item *ti, *hti, *cmd_item;
    tvbuff_t *payload_tvb = tvb;
    bool rq, d, to, discard, broadcast, transport;
    const char *msg_class = NULL;
    const char *cmd_str, *cmd_name;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCTP Control");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_reported_length(tvb);
    ti = proto_tree_add_item(tree, proto_mctp_ctrl, tvb, 0, -1, ENC_NA);
    mctp_ctrl_tree = proto_item_add_subtree(ti, ett_mctp_ctrl);
    if (len > 64)
        expert_add_info_format(pinfo, ti, &ei_mctp_ctrl_oversized,
            "MCTP control message payload of %u bytes exceeds the 64-byte"
            " baseline transmission unit (DSP0236 11.6)", len);

    /* The header proper is Figure 20 bytes 2-3; byte 1 is packet-mctp.c's
     * and the completion code goes to the parent tree. */
    mctp_ctrl_hdr_tree = proto_tree_add_subtree(mctp_ctrl_tree, tvb, MIN(1, len),
        len > 1 ? MIN(2, len - 1) : 0, ett_mctp_ctrl_hdr, &hti,
        "MCTP Control Protocol header");

    if (len < MCTP_CTRL_MIN_LENGTH) {
        if (len > 1) {
            proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_rq, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_d, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_rsvd, tvb, 1, 1, ENC_NA);
            proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_instance, tvb, 1, 1, ENC_NA);
        }
        expert_add_info_format(pinfo, hti, &ei_mctp_ctrl_length,
            "MCTP Control header requires 3 bytes, but only %u bytes are reported", len);
        col_set_str(pinfo->cinfo, COL_INFO, "MCTP Control, incomplete header");
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item_ret_boolean(mctp_ctrl_hdr_tree, hf_mctp_ctrl_rq,
                                    tvb, 1, 1, ENC_BIG_ENDIAN, &rq);

    proto_tree_add_item_ret_boolean(mctp_ctrl_hdr_tree, hf_mctp_ctrl_d,
                                    tvb, 1, 1, ENC_BIG_ENDIAN, &d);

    proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_rsvd, tvb, 1, 1, ENC_NA);

    proto_tree_add_item_ret_uint(mctp_ctrl_hdr_tree, hf_mctp_ctrl_instance,
                                 tvb, 1, 1, ENC_NA, &iid);

    /* 11.4.2: IC shall be 0b for a control message. */
    if (tvb_get_uint8(tvb, 0) & 0x80)
        proto_tree_add_expert(mctp_ctrl_tree, pinfo, &ei_mctp_ctrl_ic, tvb, 0, 1);

    cmd_item = proto_tree_add_item_ret_uint(mctp_ctrl_hdr_tree, hf_mctp_ctrl_command,
                                 tvb, 2, 1, ENC_NA, &cmd);
    /* command_vals covers 0x00-0xff, so the fallback is never used. */
    cmd_str = rval_to_str_const(cmd, command_vals, "MCTP Control");
    cmd_name = (cmd == 0 || (cmd >= 0x15 && cmd <= 0xef))
        ? wmem_strdup_printf(pinfo->pool, "Reserved command 0x%02x", cmd)
        : cmd_str;

    /* Message class from (destination, TO, Rq, D) (DSP0236 11.7, Table 11).
     * TO and the destination come from packet-mctp.c's header; without
     * it (a call by name) take TO from Rq, as Table 11 pairs them. */
    transport = pinfo->ptype == PT_MCTP && pinfo->dst.type == AT_MCTP &&
                pinfo->dst.len == 1 && pinfo->src.type == AT_MCTP &&
                pinfo->src.len == 1;
    to = transport ? (pinfo->srcport & 0x08) != 0 : rq;
    broadcast = transport &&
                *(const uint8_t *)pinfo->dst.data == MCTP_CTRL_EID_BROADCAST;
    discard = false;
    switch ((to ? 0x4 : 0) | (rq ? 0x2 : 0) | (d ? 0x1 : 0)) {
    case 0x0:   /* (0b, 0b, 0b) */
        /* The Response row names the Target EID, so a response addressed to
         * the broadcast EID is not that row. */
        if (broadcast)
            discard = true;
        else
            msg_class = "Response";
        break;
    case 0x6:   /* (1b, 1b, 0b) */
        msg_class = broadcast ? "Broadcast Request" : "Request";
        break;
    case 0x7:   /* (1b, 1b, 1b) */
        msg_class = broadcast ? "Broadcast Datagram" : "Datagram";
        break;
    default:
        discard = true;
        break;
    }

    payload_start = 3;

    if (discard) {
        expert_add_info(pinfo, hti, &ei_mctp_ctrl_reserved_class);
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "MCTP %s discarded, reserved destination/TO/Rq/D "
                     "combination",
                     cmd_name);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "MCTP %s %s",
                     cmd_name,
                     msg_class);

        /* Table 11: requests are tracked by Instance ID; datagrams are not. */
        if (transport && !d)
            mctp_ctrl_add_pairing(tvb, pinfo, mctp_ctrl_tree, ti, rq, cmd, iid,
                                  data ? (const nstime_t *)data : &pinfo->abs_ts);

        if (!rq) {
            proto_item *cc_item;
            const char *cc_name;
            if (len < 4) {
                expert_add_info_format(pinfo, cmd_item, &ei_mctp_ctrl_length,
                    "%s response requires a completion code (minimum 4 bytes), but %u bytes are reported",
                    cmd_str, len);
                col_append_str(pinfo->cinfo, COL_INFO, ", missing completion code");
                return tvb_captured_length(tvb);
            }
            cc_item = proto_tree_add_item_ret_uint(mctp_ctrl_tree, hf_mctp_ctrl_cc,
                                         tvb, 3, 1, ENC_NA, &cc);
            cc_name = mctp_ctrl_cc_specific_name(cmd, cc);
            if (cc_name)
                proto_item_set_text(cc_item, "Completion code: %s (0x%02x)",
                                    cc_name, cc);
            else
                cc_name = rval_to_str_const(cc, cc_vals, "Unknown");
            payload_start++;
            /* The completion code is the response's result (DSP0236 12.3). */
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s (0x%02x)",
                            cc_name, cc);
        }

        expected = mctp_ctrl_fixed_length(cmd, rq, cc);
        if (expected && len != expected) {
            proto_item *length_item = cmd_item;
            if (len > expected)
                length_item = proto_tree_add_item(mctp_ctrl_tree, hf_mctp_ctrl_excess,
                    tvb, expected, -1, ENC_NA);
            expert_add_info_format(pinfo, length_item, &ei_mctp_ctrl_length,
                "%s %s%s requires exactly %u bytes, but %u bytes are reported",
                cmd_str,
                rq ? "request" : "response", !rq && cc ? " (non-success)" : "",
                expected, len);
        }
        /* Closed layouts never parse the excess bytes. */
        if (expected)
            payload_tvb = tvb_new_subset_length(tvb, 0, MIN(len, expected));

        /* Error completions carry no data (DSP0236 1.3.3 section 12.3). */
        if (rq || cc == 0)
            payload_start = dissect_mctp_ctrl_payload(payload_tvb, pinfo,
                                                      mctp_ctrl_tree, cmd, rq,
                                                      payload_start);

        if (!rq && cc == 0 && len > payload_start &&
            mctp_ctrl_count_delimited(tvb, cmd)) {
            proto_item *pi = proto_tree_add_item(mctp_ctrl_tree,
                                hf_mctp_ctrl_excess, tvb, payload_start,
                                len - payload_start, ENC_NA);
            expert_add_info_format(pinfo, pi, &ei_mctp_ctrl_length,
                "%s response has %u bytes beyond the data its count or "
                "format gives", cmd_str, len - payload_start);
            payload_start = len;
        }
    }

    if (tvb_reported_length(payload_tvb) > payload_start) {
        proto_tree_add_item(mctp_ctrl_tree, hf_mctp_ctrl_data, payload_tvb, payload_start,
                            tvb_reported_length_remaining(payload_tvb, payload_start), ENC_NA);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mctp_control(void)
{
    /* *INDENT-OFF* */
    /* Field definitions */
    static hf_register_info hf[] = {
        { &hf_mctp_ctrl_command,
          { "Command", "mctpc.command",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(command_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_rq,
          { "Rq", "mctpc.rq",
            FT_BOOLEAN, 8, TFS(&tfs_rq), 0x80,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_d,
          { "Datagram", "mctpc.d",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_rsvd,
          { "Reserved", "mctpc.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_instance,
          { "Instance ID", "mctpc.instance",
            FT_UINT8, BASE_HEX, NULL, 0x1f,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_cc,
          { "Completion code", "mctpc.cc",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(cc_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_data,
          { "Data", "mctpc.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_excess,
          { "Excess data", "mctpc.excess",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Bytes beyond the command's closed layout", HFILL },
        },
        /* Set Endpoint ID (DSP0236 1.3.3, Table 14) */
        { &hf_mctp_ctrl_set_eid_rsvd,
          { "Reserved", "mctpc.set_eid.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xfc,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_op,
          { "Operation", "mctpc.set_eid.op",
            FT_UINT8, BASE_HEX, VALS(set_eid_op_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_eid,
          { "Endpoint ID", "mctpc.set_eid.eid",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_rsvd_hi,
          { "Reserved", "mctpc.set_eid.rsvd_hi",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_status,
          { "EID assignment status", "mctpc.set_eid.status",
            FT_UINT8, BASE_HEX, VALS(set_eid_status_vals), 0x30,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_rsvd_lo,
          { "Reserved", "mctpc.set_eid.rsvd_lo",
            FT_UINT8, BASE_HEX, NULL, 0x0c,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_alloc_status,
          { "EID allocation status", "mctpc.set_eid.alloc_status",
            FT_UINT8, BASE_HEX, VALS(set_eid_alloc_status_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_setting,
          { "EID setting", "mctpc.set_eid.eid_setting",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_pool_size,
          { "EID pool size", "mctpc.set_eid.pool_size",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Size of the dynamic EID pool; 0 = no dynamic EID pool", HFILL },
        },
        /* Get Endpoint ID (DSP0236 1.3.3, Table 15) */
        { &hf_mctp_ctrl_get_eid_eid,
          { "Endpoint ID", "mctpc.get_eid.eid",
            FT_UINT8, BASE_HEX, NULL, 0,
            "0x00 = EID not yet assigned", HFILL },
        },
        { &hf_mctp_ctrl_get_eid_rsvd_hi,
          { "Reserved", "mctpc.get_eid.rsvd_hi",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_endpoint_type,
          { "Endpoint type", "mctpc.get_eid.endpoint_type",
            FT_UINT8, BASE_HEX, VALS(get_eid_endpoint_type_vals), 0x30,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_rsvd_lo,
          { "Reserved", "mctpc.get_eid.rsvd_lo",
            FT_UINT8, BASE_HEX, NULL, 0x0c,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_eid_type,
          { "Endpoint ID type", "mctpc.get_eid.eid_type",
            FT_UINT8, BASE_HEX, VALS(get_eid_eid_type_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_medium_info,
          { "Medium-specific information", "mctpc.get_eid.medium_info",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        /* DSP0237 1.2.0 Table 4, for an SMBus/I2C ingress only. */
        { &hf_mctp_ctrl_get_eid_medium_rsvd,
          { "Reserved", "mctpc.get_eid.medium_info.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_medium_fairness,
          { "Fairness arbitration", "mctpc.get_eid.medium_info.fairness",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "SMBus/I2C fairness arbitration support (DSP0237 6.13)", HFILL },
        },
        /* Get Endpoint UUID (DSP0236 1.3.3, Table 16) */
        { &hf_mctp_ctrl_uuid,
          { "Endpoint UUID", "mctpc.uuid",
            FT_GUID, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        /* Get MCTP Version Support (DSP0236 1.3.3, Table 18) */
        { &hf_mctp_ctrl_get_ver_msg_type,
          { "Message type number", "mctpc.get_ver.msg_type",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_ver_msg_type_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_ver_count,
          { "Version number entry count", "mctpc.get_ver.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_ver_entry,
          { "Version number entry", "mctpc.get_ver.entry",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(mctp_ctrl_fmt_version), 0,
            NULL, HFILL },
        },
        /* The entry's four bytes (DSP0236 1.3.3 section 12.7.2). */
        { &hf_mctp_ctrl_get_ver_major,
          { "Major version", "mctpc.get_ver.entry.major",
            FT_UINT8, BASE_CUSTOM,
            CF_FUNC(mctp_ctrl_fmt_version_major_minor), 0,
            "BCD-encoded; an upper nibble of Fh means a single digit, and"
            " 0xFF is not allowed here", HFILL },
        },
        { &hf_mctp_ctrl_get_ver_minor,
          { "Minor version", "mctpc.get_ver.entry.minor",
            FT_UINT8, BASE_CUSTOM,
            CF_FUNC(mctp_ctrl_fmt_version_major_minor), 0,
            "BCD-encoded; an upper nibble of Fh means a single digit, and"
            " 0xFF is not allowed here", HFILL },
        },
        { &hf_mctp_ctrl_get_ver_update,
          { "Update version", "mctpc.get_ver.entry.update",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(mctp_ctrl_fmt_version_update), 0,
            "BCD-encoded; 0xFF means the field is to be ignored", HFILL },
        },
        { &hf_mctp_ctrl_get_ver_alpha,
          { "Alpha", "mctpc.get_ver.entry.alpha",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(mctp_ctrl_fmt_version_alpha), 0,
            "0x00 when the field is not used, otherwise one of the US-ASCII"
            " alphabetic characters [a-z, A-Z]", HFILL },
        },
        /* Get Message Type Support (DSP0236 1.3.3, Table 19) */
        { &hf_mctp_ctrl_msg_type_count,
          { "Message type count", "mctpc.get_msg_types.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Number of message types supported in addition to MCTP control",
            HFILL },
        },
        { &hf_mctp_ctrl_msg_type,
          { "Message type", "mctpc.get_msg_types.type",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(msg_type_vals), 0,
            NULL, HFILL },
        },
        /* Allocate Endpoint IDs (DSP0236 1.3.3, Table 23) */
        { &hf_mctp_ctrl_alloc_eids_rsvd,
          { "Reserved", "mctpc.alloc_eids.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xfc,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_op,
          { "Operation", "mctpc.alloc_eids.op",
            FT_UINT8, BASE_HEX, VALS(alloc_eids_op_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_count,
          { "Number of Endpoint IDs", "mctpc.alloc_eids.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Number of EIDs in the pool being allocated", HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_start,
          { "Starting Endpoint ID", "mctpc.alloc_eids.start",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_status,
          { "Allocation status", "mctpc.alloc_eids.status",
            FT_UINT8, BASE_HEX, VALS(alloc_eids_status_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_pool_size,
          { "Endpoint ID pool size", "mctpc.alloc_eids.pool_size",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Size of the dynamic EID pool used by this endpoint", HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_first,
          { "First Endpoint ID", "mctpc.alloc_eids.first",
            FT_UINT8, BASE_HEX, NULL, 0,
            "First EID assigned to the pool; 0x00 = no EIDs assigned", HFILL },
        },
        /* Get Routing Table Entries (DSP0236 1.3.3, Tables 26 and 27) */
        { &hf_mctp_ctrl_get_routing_handle,
          { "Entry handle", "mctpc.get_routing.handle",
            FT_UINT8, BASE_HEX, NULL, 0,
            "0x00 = access the first entries in the table", HFILL },
        },
        { &hf_mctp_ctrl_get_routing_next_handle,
          { "Next entry handle", "mctpc.get_routing.next_handle",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Handle for the next request; 0xff = no more entries", HFILL },
        },
        { &hf_mctp_ctrl_get_routing_count,
          { "Number of entries", "mctpc.get_routing.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Number of routing table entries returned in this response",
            HFILL },
        },
        { &hf_mctp_ctrl_get_routing_entry,
          { "Routing table entry", "mctpc.get_routing.entry",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_range_size,
          { "Size of EID range", "mctpc.get_routing.range_size",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_start_eid,
          { "Starting EID", "mctpc.get_routing.start_eid",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_entry_type,
          { "Entry type", "mctpc.get_routing.entry_type",
            FT_UINT8, BASE_HEX, VALS(get_routing_entry_type_vals), 0xc0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_static,
          { "Entry configuration", "mctpc.get_routing.static",
            FT_BOOLEAN, 8, TFS(&tfs_get_routing_static), 0x20,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_port,
          { "Port number", "mctpc.get_routing.port",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            "Vendor-chosen bus connection that the physical address is defined"
            " under", HFILL },
        },
        { &hf_mctp_ctrl_get_routing_binding_id,
          { "Physical transport binding ID", "mctpc.get_routing.binding_id",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_routing_binding_id_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_media_type,
          { "Physical media type ID", "mctpc.get_routing.media_type",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_routing_media_type_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_addr_size,
          { "Physical address size", "mctpc.get_routing.addr_size",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_routing_addr,
          { "Physical address", "mctpc.get_routing.addr",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "Binding-specific physical address, MSB first", HFILL },
        },
        /* Get Vendor Defined Message Support (Tables 20/21, section 5.2). */
        { &hf_mctp_ctrl_vendor_selector,
          { "Vendor ID set selector", "mctpc.vendor.selector",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_vendor_next_selector,
          { "Next vendor ID set selector", "mctpc.vendor.next_selector",
            FT_UINT8, BASE_HEX, NULL, 0, "0xff = no more capability sets", HFILL },
        },
        { &hf_mctp_ctrl_vendor_format,
          { "Vendor ID format", "mctpc.vendor.format",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(vendor_format_vals), 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_vendor_pci,
          { "PCI vendor ID", "mctpc.vendor.pci",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_vendor_iana,
          { "IANA enterprise number", "mctpc.vendor.iana",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_vendor_command_set,
          { "Vendor-defined command set", "mctpc.vendor.command_set",
            FT_UINT16, BASE_HEX, NULL, 0, "Vendor-defined numeric value or bit field", HFILL },
        },
        /* Resolve Endpoint ID (Table 22). */
        { &hf_mctp_ctrl_resolve_eid_target,
          { "Target Endpoint ID", "mctpc.resolve_eid.target",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_eid_bridge,
          { "Bridge Endpoint ID", "mctpc.resolve_eid.bridge",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_eid_addr,
          { "Physical address", "mctpc.resolve_eid.addr",
            FT_BYTES, SEP_SPACE, NULL, 0, "Binding-defined address tail", HFILL },
        },
        /* DSP0237 1.2.0 Table 3, for an SMBus/I2C ingress only. */
        { &hf_mctp_ctrl_resolve_eid_slave_addr,
          { "Slave Address", "mctpc.resolve_eid.slave_addr",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            "7-bit SMBus slave address (DSP0237 physical address format)", HFILL },
        },
        { &hf_mctp_ctrl_resolve_eid_addr_rsvd,
          { "Reserved", "mctpc.resolve_eid.addr_rsvd",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            "The DSP0237 physical address format defines this bit as 0b", HFILL },
        },
        /* Routing Information Update (Tables 24/25). */
        { &hf_mctp_ctrl_routing_update_count,
          { "Count of update entries", "mctpc.routing_update.count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_routing_update_entry,
          { "Update entry", "mctpc.routing_update.entry",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_routing_update_rsvd,
          { "Entry reserved bits", "mctpc.routing_update.entry.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_routing_update_type,
          { "Entry type", "mctpc.routing_update.entry.type",
            FT_UINT8, BASE_HEX, VALS(get_routing_entry_type_vals), 0x0f, NULL, HFILL },
        },
        { &hf_mctp_ctrl_routing_update_range_size,
          { "Entry EID range size", "mctpc.routing_update.entry.range_size",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_routing_update_eid,
          { "Entry starting EID", "mctpc.routing_update.entry.eid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        /* DSP0237 1.2.0 Table 3, for an SMBus/I2C ingress only. */
        { &hf_mctp_ctrl_routing_update_slave_addr,
          { "Slave Address", "mctpc.routing_update.entry.slave_addr",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            "7-bit SMBus slave address (DSP0237 physical address format)", HFILL },
        },
        { &hf_mctp_ctrl_routing_update_addr_rsvd,
          { "Reserved", "mctpc.routing_update.entry.addr_rsvd",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            "The DSP0237 physical address format defines this bit as 0b", HFILL },
        },
        { &hf_mctp_ctrl_routing_update_data,
          { "Undelimited address and remaining update records", "mctpc.routing_update.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "Binding address size is unavailable; subsequent records cannot be located", HFILL },
        },
        { &hf_mctp_ctrl_network_uuid,
          { "Network UUID", "mctpc.network_uuid",
            FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        /* Query Hop (Table 32): the overlapping TU layout remains unresolved. */
        { &hf_mctp_ctrl_query_hop_target,
          { "Target Endpoint ID", "mctpc.query_hop.target",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_query_hop_bridge,
          { "Next bridge Endpoint ID", "mctpc.query_hop.bridge",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_query_hop_msg_type,
          { "Requested message type", "mctpc.query_hop.msg_type",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(msg_type_vals), 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_query_hop_response_type,
          { "Message type", "mctpc.query_hop.response_type",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(query_hop_response_type_vals), 0, "0xff = all supported message types", HFILL },
        },
        { &hf_mctp_ctrl_query_hop_tu_data,
          { "Transmission unit data", "mctpc.query_hop.tu_data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "Fewer than the four bytes of the two TU size fields (DSP0236 Query Hop message)", HFILL },
        },
        { &hf_mctp_ctrl_query_hop_in_tu,
          { "Maximum incoming transmission unit", "mctpc.query_hop.in_tu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(mctp_ctrl_fmt_tu), 0,
            "In 16-byte increments above the 64-byte baseline (DSP0236 Query Hop message)", HFILL },
        },
        { &hf_mctp_ctrl_query_hop_out_tu,
          { "Maximum outgoing transmission unit", "mctpc.query_hop.out_tu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(mctp_ctrl_fmt_tu), 0,
            "In 16-byte increments above the 64-byte baseline (DSP0236 Query Hop message)", HFILL },
        },
        /* Resolve UUID (Tables 33/34). */
        { &hf_mctp_ctrl_resolve_uuid,
          { "Requested UUID", "mctpc.resolve_uuid.uuid",
            FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_handle,
          { "Entry handle", "mctpc.resolve_uuid.handle",
            FT_UINT8, BASE_HEX, NULL, 0, "0x00 = access first entries", HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_next_handle,
          { "Next entry handle", "mctpc.resolve_uuid.next_handle",
            FT_UINT8, BASE_HEX, NULL, 0, "0xff = no more entries", HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_count,
          { "Number of EID entries", "mctpc.resolve_uuid.count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_entry,
          { "EID entry", "mctpc.resolve_uuid.entry",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_eid,
          { "Endpoint ID", "mctpc.resolve_uuid.eid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_binding,
          { "Physical transport binding ID", "mctpc.resolve_uuid.binding",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_routing_binding_id_vals), 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_media,
          { "Physical media type ID", "mctpc.resolve_uuid.media",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_routing_media_type_vals), 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_addr_size,
          { "Physical address size", "mctpc.resolve_uuid.addr_size",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_resolve_uuid_addr,
          { "Physical address", "mctpc.resolve_uuid.addr",
            FT_BYTES, SEP_SPACE, NULL, 0, "Binding-defined physical address", HFILL },
        },
        /* Rate limiting (Tables 35-37). */
        { &hf_mctp_ctrl_rate_rx_buffer,
          { "Receive buffer size (bytes)", "mctpc.rate.rx_buffer",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_rate_rx_rate,
          { "Maximum receive data rate (packets/sec)", "mctpc.rate.rx_rate",
            FT_UINT32, BASE_DEC, NULL, 0, "Baseline transmission unit packets per second", HFILL },
        },
        { &hf_mctp_ctrl_rate_max_tx_rate,
          { "Maximum supported transmit rate limit (packets/sec)", "mctpc.rate.max_tx_rate",
            FT_UINT32, BASE_DEC, NULL, 0, "Baseline transmission unit packets per second", HFILL },
        },
        { &hf_mctp_ctrl_rate_min_tx_rate,
          { "Minimum supported transmit rate limit (packets/sec)", "mctpc.rate.min_tx_rate",
            FT_UINT32, BASE_DEC, NULL, 0, "Baseline transmission unit packets per second", HFILL },
        },
        { &hf_mctp_ctrl_rate_max_burst,
          { "Maximum supported burst size (packets)", "mctpc.rate.max_burst",
            FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_rate_burst,
          { "Present transmit burst size (packets)", "mctpc.rate.burst",
            FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_rate_tx_rate,
          { "Present transmit data rate limit (packets/sec)", "mctpc.rate.tx_rate",
            FT_UINT32, BASE_DEC, NULL, 0, "Baseline transmission unit packets per second", HFILL },
        },
        { &hf_mctp_ctrl_rate_rsvd,
          { "Reserved", "mctpc.rate.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL },
        },
        { &hf_mctp_ctrl_rate_non_requested,
          { "Transmit rate limiting operation", "mctpc.rate.non_requested",
            FT_BOOLEAN, 8, TFS(&tfs_rate_non_requested), 0x02, NULL, HFILL },
        },
        { &hf_mctp_ctrl_rate_supported,
          { "Transmit rate limiting supported", "mctpc.rate.supported",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL },
        },
        { &hf_mctp_ctrl_rate_requested_burst,
          { "Requested transmit maximal burst size (packets)", "mctpc.rate.requested_burst",
            FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_rate_requested_rate,
          { "Requested transmit maximal data rate (packets/sec)", "mctpc.rate.requested_rate",
            FT_UINT32, BASE_DEC, NULL, 0, "Baseline transmission unit packets per second", HFILL },
        },
        { &hf_mctp_ctrl_rate_granted_burst,
          { "Present transmit burst size (packets)", "mctpc.rate.granted_burst",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        /* Query Supported Interfaces (Table 38). */
        { &hf_mctp_ctrl_interfaces_count,
          { "Supported interfaces count", "mctpc.interfaces.count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_interfaces_media,
          { "Interface physical medium type", "mctpc.interfaces.media",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_routing_media_type_vals), 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_interfaces_eid,
          { "Interface Endpoint ID", "mctpc.interfaces.eid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL },
        },
        /* Transport Specific (Table 39). */
        { &hf_mctp_ctrl_transport_binding,
          { "Physical transport binding ID", "mctpc.transport.binding",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_routing_binding_id_vals), 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_transport_media,
          { "Physical media ID", "mctpc.transport.media",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(get_routing_media_type_vals), 0, NULL, HFILL },
        },
        { &hf_mctp_ctrl_transport_iana,
          { "IANA enterprise number", "mctpc.transport.iana",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL },
        },
        /* Physical addresses by media type (Tables 27/34). */
        { &hf_mctp_ctrl_phys_smbus_addr,
          { "SMBus/I2C slave address", "mctpc.phys_addr.smbus",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            "7-bit address (DSP0237 physical address format)", HFILL },
        },
        { &hf_mctp_ctrl_phys_i3c_addr,
          { "I3C address", "mctpc.phys_addr.i3c",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            "7-bit address; 00h is the I3C Controller (DSP0233 physical address format)", HFILL },
        },
        { &hf_mctp_ctrl_phys_addr_rsvd,
          { "Reserved", "mctpc.phys_addr.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            "The DSP0237 and DSP0233 physical address formats define this bit as 0b", HFILL },
        },
        { &hf_mctp_ctrl_phys_segment,
          { "PCIe segment", "mctpc.phys_addr.segment",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Flit Mode address (DSP0238 physical address format)", HFILL },
        },
        { &hf_mctp_ctrl_phys_bus,
          { "PCIe bus", "mctpc.phys_addr.bus",
            FT_UINT8, BASE_HEX, NULL, 0,
            "DSP0238 physical address formats (Non-Flit and Flit Mode)", HFILL },
        },
        { &hf_mctp_ctrl_phys_device,
          { "PCIe device (BDF)", "mctpc.phys_addr.device",
            FT_UINT8, BASE_HEX, NULL, 0xf8,
            "Device number of a BDF ID (DSP0238 physical address formats)", HFILL },
        },
        { &hf_mctp_ctrl_phys_function,
          { "PCIe function (BDF)", "mctpc.phys_addr.function",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            "Function number of a BDF ID (DSP0238 physical address formats)", HFILL },
        },
        { &hf_mctp_ctrl_phys_ari_function,
          { "PCIe function (ARI)", "mctpc.phys_addr.ari_function",
            FT_UINT8, BASE_HEX, NULL, 0,
            "The same byte read as an ARI ID's function number (DSP0238 physical address formats)", HFILL },
        },
        /* Request/response pairing (Table 10 Instance ID). */
        { &hf_mctp_ctrl_response_in,
          { "Response In", "mctpc.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
            "The response to this request is in this frame", HFILL },
        },
        { &hf_mctp_ctrl_response_to,
          { "Request In", "mctpc.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
            "This is a response to the request in this frame", HFILL },
        },
        { &hf_mctp_ctrl_response_time,
          { "Response Time", "mctpc.response_time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
            "From the end of the request to the start of the response", HFILL },
        },
    };

    /* protocol subtree */
    static int *ett[] = {
        &ett_mctp_ctrl,
        &ett_mctp_ctrl_hdr,
        &ett_mctp_ctrl_get_routing_entry,
        &ett_mctp_ctrl_get_ver_entry,
        &ett_mctp_ctrl_resolve_uuid_entry,
        &ett_mctp_ctrl_routing_update_entry,
        &ett_mctp_ctrl_phys_addr,
    };

    static ei_register_info ei[] = {
        { &ei_mctp_ctrl_length,
          { "mctpc.length.invalid", PI_MALFORMED, PI_ERROR,
            "MCTP Control message length does not match its command layout", EXPFILL }
        },
        { &ei_mctp_ctrl_ver_bcd,
          { "mctpc.get_ver.entry.invalid_bcd", PI_PROTOCOL, PI_WARN,
            "Invalid BCD version encoding: each nibble must be 0-9 (an upper"
            " nibble of Fh marks a single digit), and 0xff is only defined for"
            " the update byte (DSP0236 section 12.7.2)", EXPFILL }
        },
        { &ei_mctp_ctrl_ver_alpha,
          { "mctpc.get_ver.entry.invalid_alpha", PI_PROTOCOL, PI_WARN,
            "Invalid version alpha byte: it must be 00h or an ASCII letter"
            " (DSP0236 section 12.7.2)", EXPFILL }
        },
        { &ei_mctp_ctrl_ic,
          { "mctpc.ic_set", PI_PROTOCOL, PI_WARN,
            "Integrity Check bit set on an MCTP control message; DSP0236"
            " section 11.4.2 requires 0b", EXPFILL }
        },
        { &ei_mctp_ctrl_phys_addr_size,
          { "mctpc.phys_addr.size_mismatch", PI_PROTOCOL, PI_WARN,
            "Physical address size differs from the media type's transport"
            " binding", EXPFILL }
        },
        { &ei_mctp_ctrl_reserved_class,
          { "mctpc.reserved_class", PI_PROTOCOL, PI_WARN,
            "Reserved destination/TO/Rq/D combination; the receiver discards "
            "the message (DSP0236 11.7)", EXPFILL }
        },
        { &ei_mctp_ctrl_invalid_value,
          { "mctpc.invalid_value", PI_PROTOCOL, PI_WARN,
            "Value the command does not allow", EXPFILL }
        },
        { &ei_mctp_ctrl_oversized,
          { "mctpc.oversized", PI_PROTOCOL, PI_WARN,
            "MCTP control message payload exceeds the 64-byte baseline"
            " transmission unit (DSP0236 11.6)", EXPFILL }
        },
        { &ei_mctp_ctrl_unmatched_response,
          { "mctpc.response.unmatched", PI_SEQUENCE, PI_NOTE,
            "No request with this source, tag, Instance ID and command was"
            " seen (DSP0236 MCTP control message fields)", EXPFILL }
        },
    };

    expert_module_t *expert_mctp_ctrl;

    proto_mctp_ctrl = proto_register_protocol("MCTP Control Protocol",
                                              "MCTP-Control", "mctpc");

    mctp_ctrl_requests = wmem_map_new_autoreset(wmem_epan_scope(),
                                                wmem_file_scope(),
                                                mctp_ctrl_key_hash,
                                                mctp_ctrl_key_equal);

    proto_register_field_array(proto_mctp_ctrl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mctp_ctrl = expert_register_protocol(proto_mctp_ctrl);
    expert_register_field_array(expert_mctp_ctrl, ei, array_length(ei));
    mctp_ctrl_handle = register_dissector_with_description(
        "mctp-control", "MCTP Control Protocol", dissect_mctp_ctrl, proto_mctp_ctrl);
}

void
proto_reg_handoff_mctp_control(void)
{
    dissector_add_uint("mctp.type", MCTP_TYPE_CONTROL, mctp_ctrl_handle);
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
