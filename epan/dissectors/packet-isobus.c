/* packet-isobus.c
 * Routines for ISObus dissection (Based on CANOpen Dissector)
 * Copyright 2016, Jeroen Sack <jeroen@jeroensack.nl>
 * ISO 11783
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/reassemble.h>
#include "packet-socketcan.h"
#include <epan/wmem_scopes.h>
#include "packet-isobus.h"
#include "packet-isobus-parameters.h"

void proto_register_isobus(void);
void proto_reg_handoff_isobus(void);

static dissector_handle_t isobus_handle;
static dissector_table_t subdissector_table_pdu_format;
static dissector_table_t subdissector_table_pgn;

/* Initialize the protocol and registered fields */
static int proto_isobus;
static int hf_isobus_can_id;
static int hf_isobus_priority;
static int hf_isobus_ext_data_page;
static int hf_isobus_data_page;
static int hf_isobus_pdu_format_dp0;
static int hf_isobus_pdu_format_dp1;
static int hf_isobus_group_extension;
static int hf_isobus_src_addr;
static int hf_isobus_dst_addr;
static int hf_isobus_pgn;
static int hf_isobus_payload;

static int hf_isobus_req_requested_pgn;
static int hf_isobus_ac_name;
static int hf_isobus_ac_name_id_number;
static int hf_isobus_ac_name_manufacturer;
static int hf_isobus_ac_name_ecu_instance;
static int hf_isobus_ac_name_function_instance;
static int hf_isobus_ac_name_function;
static int hf_isobus_ac_name_reserved;
static int hf_isobus_ac_name_vehicle_system;
static int hf_isobus_ac_name_vehicle_system_instance;
static int hf_isobus_ac_name_industry_group;
static int hf_isobus_ac_name_arbitrary_address_capable;

static int hf_isobus_transportprotocol_controlbyte;
static int hf_isobus_transportprotocol_requesttosend_totalsize;
static int hf_isobus_transportprotocol_requesttosend_numberofpackets;
static int hf_isobus_transportprotocol_requesttosend_maximumpackets;
static int hf_isobus_transportprotocol_requesttosend_pgn;
static int hf_isobus_transportprotocol_cleartosend_numberofpacketscanbesent;
static int hf_isobus_transportprotocol_cleartosend_nextpacketnumber;
static int hf_isobus_transportprotocol_cleartosend_pgn;
static int hf_isobus_transportprotocol_endofmsgack_totalsize;
static int hf_isobus_transportprotocol_endofmsgack_numberofpackets;
static int hf_isobus_transportprotocol_endofmsgack_pgn;
static int hf_isobus_transportprotocol_connabort_abortreason;
static int hf_isobus_transportprotocol_connabort_pgn;
static int hf_isobus_transportprotocol_broadcastannouncemessage_totalsize;
static int hf_isobus_transportprotocol_broadcastannouncemessage_numberofpackets;
static int hf_isobus_transportprotocol_broadcastannouncemessage_pgn;
static int hf_isobus_transportprotocol_reserved;

static int hf_msg_fragments;
static int hf_msg_fragment;
static int hf_msg_fragment_overlap;
static int hf_msg_fragment_overlap_conflicts;
static int hf_msg_fragment_multiple_tails;
static int hf_msg_fragment_too_long_fragment;
static int hf_msg_fragment_error;
static int hf_msg_fragment_count;
static int hf_msg_reassembled_in;
static int hf_msg_reassembled_length;
static int hf_msg_reassembled_data;

/* Desegmentation of isobus transport protocol streams */
static reassembly_table isobus_reassembly_table;
static unsigned int reassembly_total_size;
static unsigned int reassembly_current_size;

#define VT_TO_ECU 230
#define ECU_TO_VT 231
#define REQUEST 234
#define ADDRESS_CLAIM 238
#define ETP_DATA_TRANSFER 199
#define ETP_DATA_MANAGEMENT 200
#define TP_DATA_TRANSFER 235
#define TP_DATA_MANAGEMENT 236

static const value_string pdu_format_dp0[] = {
    { 7  , "General-purpose valve load sense pressure" },
    { 147, "NAME management" },
    { 170, "Client to File Server" },
    { 171, "File Server to Client" },
    { 172, "Guidance machine status" },
    { 173, "Guidance system command" },
    { 196, "General-purpose valve command" },
    { 197, "General-purpose valve measured flow" },
    { 198, "General-purpose valve estimated flow" },
    { ETP_DATA_TRANSFER, "EXTENDED TRANSPORT PROTOCOL - DATA TRANSFER" },
    { ETP_DATA_MANAGEMENT, "EXTENDED TRANSPORT PROTOCOL - CONNECTION MANAGEMENT" },
    { 201, "REQUEST2" },
    { 202, "TRANSFER" },
    { VT_TO_ECU, "VT to ECU" },
    { ECU_TO_VT, "ECU to VT" },
    { 232, "ACKNOWLEDGEMENT" },
    { REQUEST, "REQUEST" },
    { TP_DATA_TRANSFER, "TRANSPORT PROTOCOL - DATA TRANSFER" },
    { TP_DATA_MANAGEMENT, "TRANSPORT PROTOCOL - CONNECTION MANAGEMENT" },
    { ADDRESS_CLAIM, "ADDRESS CLAIM" },
    { 239, "PROPRIETARY A" },
    { 253, "Certification / Operating state" },
    { 254, "Parameter groups" },
    { 255, "PROPRIETARY B" },
    { 0, NULL }
};

static const value_string pdu_format_dp0_short[] = {
    { 7  , "GPV.LSP" },
    { 147, "NM" },
    { 170, "C2FS" },
    { 171, "FS2C" },
    { 172, "G.MS" },
    { 173, "G.SC" },
    { 196, "GPV.C" },
    { 197, "GPV.MF" },
    { 198, "GPV.EF" },
    { ETP_DATA_TRANSFER, "ETP.DT" },
    { ETP_DATA_MANAGEMENT, "ETP.CM" },
    { 201, "REQ2" },
    { 202, "TRANS" },
    { VT_TO_ECU, "VT2ECU" },
    { ECU_TO_VT, "ECU2VT" },
    { 232, "ACK" },
    { REQUEST, "REQ" },
    { TP_DATA_TRANSFER, "TP.DT" },
    { TP_DATA_MANAGEMENT, "TP.CM" },
    { ADDRESS_CLAIM, "AC" },
    { 239, "PR.A" },
    { 253, "Cert/OS" },
    { 254, "PAR.G" },
    { 255, "PR.B" },
    { 0, NULL }
};

static const value_string pdu_format_dp1[] = {
    { 239, "PROPRIETARY A2" },
    { 0, NULL }
};

static const value_string pdu_format_dp1_short[] = {
    { 239, "PR.A2" },
    { 0, NULL }
};

static const range_string address_range[] = {
    { 0  , 127, "Preferred Address" },
    { 128, 247, "Self-configurable Address" },
    { 248, 253, "Preferred Address" },
    { 254, 254, "NULL Address" },
    { 255, 255, "Global Address" },
    { 0, 0, NULL }
};

static const range_string connection_abort_reasons[] = {
    { 1, 1, "Already in one or more connection-managed sessions and cannot support another" },
    { 2, 2, "System resources were needed for another task so this connection managed session was terminated" },
    { 3, 3, "A timeout occurred and this is the connection abort to close the session" },
    { 4, 4, "CTS messages received when data transfer is in progress" },
    { 5, 5, "Maximum retransmit request limit reached" },
    { 6, 6, "Unexpected data transfer packet" },
    { 7, 7, "Bad sequence number (and software is not able to recover)" },
    { 8, 8, "Duplicate sequence number (and software is not able to recover)" },
    { 9, 250, "Reserved for assignment in a future International Standard" },
    { 251, 255, "According to ISO 11783-7 definitions" },
    { 0, 0, NULL }
};

static const value_string transport_protocol_control_byte[] = {
    { 16, "Request To Send" },
    { 17, "Clear To Send" },
    { 19, "End of Message Acknowledgment" },
    { 255, "Connection Abort" },
    { 32, "Broadcast Announce Message" },
    { 0, NULL }
};


static int ett_isobus;
static int ett_isobus_can_id;
static int ett_isobus_name;
static int ett_isobus_fragment;
static int ett_isobus_fragments;

static const fragment_items isobus_frag_items = {
    &ett_isobus_fragment,
    &ett_isobus_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    &hf_msg_reassembled_data,
    /* Tag */
    "Message fragments"
};

struct address_combination {
    uint8_t src_address;
    uint8_t dst_address;
};

struct reassemble_identifier {
    uint32_t startFrameId;
    uint32_t endFrameId;
    uint32_t identifier;
};

struct address_reassemble_table {
    wmem_list_t *reassembleIdentifierTable;
    uint32_t identifierCounter;
};

static wmem_map_t *addressIdentifierTable;

static struct reassemble_identifier * findIdentifierFor(wmem_list_t *reassembleIdentifierTable, uint32_t frameIndex) {
    wmem_list_frame_t *currentItem = wmem_list_head(reassembleIdentifierTable);

    while (currentItem != NULL) {
        struct reassemble_identifier *currentData = (struct reassemble_identifier *)wmem_list_frame_data(currentItem);
        if (frameIndex <= currentData->endFrameId && frameIndex >= currentData->startFrameId)
        {
            return currentData;
        } else {
            currentItem = wmem_list_frame_next(currentItem);
        }
    }
    return NULL;
}

static gboolean
address_combination_equal(const void *p1, const void *p2) {
    const struct address_combination *addr_combi1 = (const struct address_combination *)p1;
    const struct address_combination *addr_combi2 = (const struct address_combination *)p2;

    if (addr_combi1->src_address == addr_combi2->src_address && addr_combi1->dst_address == addr_combi2->dst_address) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static unsigned
address_combination_hash(const void *p) {
    const struct address_combination *addr_combi = (const struct address_combination *)p;
    return (addr_combi->src_address * 256) + (addr_combi->dst_address);
}

static struct address_reassemble_table * findAddressIdentifierFor(uint8_t src_address, uint8_t dst_address) {
    struct address_combination *addrCombi = wmem_new(wmem_file_scope(), struct address_combination);
    struct address_reassemble_table *foundItem;

    addrCombi->src_address = src_address;
    addrCombi->dst_address = dst_address;

    foundItem = (struct address_reassemble_table *)wmem_map_lookup(addressIdentifierTable, addrCombi);

    if (foundItem != NULL) {
        return foundItem;
    } else {
        /* nothing found so create a new one */
        struct address_reassemble_table *newItem;
        newItem = wmem_new(wmem_file_scope(), struct address_reassemble_table);
        newItem->identifierCounter = 0;
        newItem->reassembleIdentifierTable = wmem_list_new(wmem_file_scope());
        wmem_map_insert(addressIdentifierTable, addrCombi, newItem);
        return newItem;
    }
}

static const char *
isobus_lookup_function(uint32_t industry_group, uint32_t vehicle_system, uint32_t function) {
    if (function < 128) {
        return try_val_to_str_ext((uint32_t)function, &isobus_global_name_functions_ext);
    }

    uint32_t new_id = industry_group << 16 | vehicle_system << 8 | function;
    return try_val_to_str_ext((uint32_t)new_id, &isobus_ig_specific_name_functions_ext);
}

static const char *
isobus_lookup_pgn(uint32_t pgn) {
    /* TODO: add configuration option via UAT? */

    return try_val_to_str_ext(pgn, &isobus_pgn_names_ext);
}

static void
proto_item_append_conditional(proto_item *ti, const char *str) {
    if (str != NULL && ti != NULL) {
        proto_item_append_text(ti, " (%s)", str);
    }
}

static int
call_isobus_subdissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bool add_proto_name,
                         uint8_t priority, uint8_t pdu_format, unsigned pgn, uint8_t source_addr, void *data) {
    can_info_t *can_info = (can_info_t *)data;

    isobus_info_t isobus_info;
    isobus_info.can_id = can_info->id;
    isobus_info.bus_id = can_info->bus_id;
    isobus_info.pdu_format = pdu_format;
    isobus_info.pgn = pgn;
    isobus_info.priority = priority;
    isobus_info.source_addr = source_addr;

    /* try PGN */
    int ret = dissector_try_uint_new(subdissector_table_pgn, pgn, tvb, pinfo, tree, add_proto_name, &isobus_info);
    if (ret > 0) {
        return ret;
    }

    /* try PDU Format */
    return dissector_try_uint_new(subdissector_table_pdu_format, pdu_format, tvb, pinfo, tree, add_proto_name, &isobus_info);
}

/* Code to actually dissect the packets */
static int
dissect_isobus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    uint8_t      priority;
    /* unsigned     ext_data_page; */
    unsigned     src_addr;
    unsigned     data_page;
    uint8_t      pdu_format;
    uint8_t      pdu_specific;
    unsigned     pgn;
    struct can_info can_info;
    char str_dst[10];
    char str_src[4];

    static unsigned seqnr = 0;

    int data_offset = 0;

    proto_item *ti, *can_id_ti;
    proto_tree *isobus_tree;
    proto_tree *isobus_can_id_tree;

    struct reassemble_identifier *identifier = NULL;
    struct address_reassemble_table *address_reassemble_table_item = NULL;

    DISSECTOR_ASSERT(data);
    can_info = *((struct can_info*)data);

    if ((can_info.id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) || !(can_info.id & CAN_EFF_FLAG)) {
        /* Error, RTR and frames with standard ids are not for us. */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISObus");
    col_clear(pinfo->cinfo, COL_INFO);

    priority      = (can_info.id >> 26) & 0x07;
    /*ext_data_page = (can_info.id >> 25) & 0x01;*/
    data_page     = (can_info.id >> 24) & 0x01;
    pdu_format    = (can_info.id >> 16) & 0xff;
    pdu_specific  = (can_info.id >> 8) & 0xff;
    src_addr      = (can_info.id >> 0 ) & 0xff;

    if (pdu_format < 240) {
        pgn = (can_info.id >> 8) & 0x03ff00;
    } else {
        pgn = (can_info.id >> 8) & 0x03ffff;
    }

    ti = proto_tree_add_item(tree, proto_isobus, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    isobus_tree = proto_item_add_subtree(ti, ett_isobus);

    /* add COB-ID with function code and node id */
    can_id_ti = proto_tree_add_uint(isobus_tree, hf_isobus_can_id, tvb, 0, 0, can_info.id);
    isobus_can_id_tree = proto_item_add_subtree(can_id_ti, ett_isobus_can_id);

    /* add priority */
    ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_priority, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);

    /* add extended data page */
    ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_ext_data_page, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);

    /* add data page */
    ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_data_page, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);

    /* add pdu format */
    switch(data_page) {
    case 0:
        ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_pdu_format_dp0, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        break;
    case 1:
        ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_pdu_format_dp1, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        break;
    }

    /* add pdu specific */
    if (pdu_format <= 239) {
        ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_dst_addr, tvb, 0, 0, can_info.id);
            proto_item_set_generated(ti);
    } else {
        ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_group_extension, tvb, 0, 0, can_info.id);
            proto_item_set_generated(ti);
    }

    /* add source address */
    ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_src_addr, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);

    /* put source address in source field */
    snprintf(str_src, 4, "%d", src_addr);
    alloc_address_wmem(pinfo->pool, &pinfo->src, AT_STRINGZ, (int)strlen(str_src) + 1, str_src);

    if (pdu_format <= 239) {
        /* put destination address in address field */
        snprintf(str_dst, 4, "%d", pdu_specific);
        alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_STRINGZ, (int)strlen(str_dst) + 1, str_dst);
    } else {
        /* put group destination address in address field and add (grp) to it */
        snprintf(str_dst, 10, "%d (grp)", pdu_specific);
        alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_STRINGZ, (int)strlen(str_dst) + 1, str_dst);
    }

    proto_tree_add_uint(isobus_tree, hf_isobus_pgn, tvb, 0, 0, pgn);

    switch(data_page) {
    case 0:
        col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] ", val_to_str_const(pdu_format, pdu_format_dp0_short, "Unknown"));
        break;
    case 1:
        col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] ", val_to_str_const(pdu_format, pdu_format_dp1_short, "Unknown"));
        break;
    }

    if (pdu_format == TP_DATA_MANAGEMENT  || pdu_format == TP_DATA_TRANSFER || pdu_format == ETP_DATA_MANAGEMENT || pdu_format == ETP_DATA_TRANSFER) {
        bool isReply = false;

        if (pdu_format == TP_DATA_MANAGEMENT) {
            uint8_t control_byte = tvb_get_uint8(tvb, data_offset);
            switch(control_byte) {
                case 17:
                case 19:
                    isReply = true;
                    break;
                case 16:
                default:
                    isReply = false;
                    break;
            }
        }

        if (isReply) {
            address_reassemble_table_item = findAddressIdentifierFor(pdu_specific, src_addr);
        } else {
            address_reassemble_table_item = findAddressIdentifierFor(src_addr, pdu_specific);
        }

        identifier = findIdentifierFor(address_reassemble_table_item->reassembleIdentifierTable, pinfo->num);
    }

    if (pdu_format == TP_DATA_MANAGEMENT) {
        uint32_t control_byte;
        proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_controlbyte, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &control_byte);
        data_offset += 1;

        if (control_byte == 16) {
            uint32_t total_size, number_of_packets;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_requesttosend_totalsize, tvb, data_offset, 2, ENC_LITTLE_ENDIAN, &total_size);
            data_offset += 2;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_requesttosend_numberofpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_requesttosend_maximumpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_requesttosend_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            if (identifier) {
                seqnr = identifier->identifier;
            } else {
                struct reassemble_identifier *reassembleIdentifierTableEntry = wmem_new(wmem_file_scope(), struct reassemble_identifier);
                seqnr = ++address_reassemble_table_item->identifierCounter;
                reassembleIdentifierTableEntry->identifier = seqnr;
                reassembleIdentifierTableEntry->startFrameId = pinfo->num;
                reassembleIdentifierTableEntry->endFrameId = pinfo->num;

                wmem_list_append(address_reassemble_table_item->reassembleIdentifierTable, reassembleIdentifierTableEntry);
            }

            fragment_add_seq(&isobus_reassembly_table, tvb, 5, pinfo, seqnr, NULL, 0, 3, true, 0);
            fragment_set_tot_len(&isobus_reassembly_table, pinfo, seqnr, NULL, number_of_packets);
            reassembly_current_size = 3;
            reassembly_total_size = total_size + 3;

            col_append_fstr(pinfo->cinfo, COL_INFO, "Request to send message of %u bytes in %u fragments", total_size, number_of_packets);
        } else if (control_byte == 17) {
            uint32_t number_of_packets_can_be_sent, next_packet_number;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_cleartosend_numberofpacketscanbesent, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets_can_be_sent);
            data_offset += 1;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_cleartosend_nextpacketnumber, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &next_packet_number);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_reserved, tvb, data_offset, 2, ENC_NA);
            data_offset += 2;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_cleartosend_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Clear to send, can receive %u packets, next packet is %u", number_of_packets_can_be_sent, next_packet_number);
        } else if (control_byte == 19) {
            uint32_t total_size, number_of_packets;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_endofmsgack_totalsize, tvb, data_offset, 2, ENC_LITTLE_ENDIAN, &total_size);
            data_offset += 2;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_endofmsgack_numberofpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_reserved, tvb, data_offset, 1, ENC_NA);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_endofmsgack_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "End of Message Acknowledgment, %u bytes sent in %u packets", total_size, number_of_packets);
        } else if (control_byte == 255) {
            uint32_t connection_abort_reason;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_connabort_abortreason, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &connection_abort_reason);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_reserved, tvb, data_offset, 3, ENC_NA);
            data_offset += 3;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_connabort_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Connection Abort, %s", rval_to_str_const(connection_abort_reason, connection_abort_reasons, "unknown reason"));
        } else if (control_byte == 32) {
            uint32_t total_size, number_of_packets;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_broadcastannouncemessage_totalsize, tvb, data_offset, 2, ENC_LITTLE_ENDIAN, &total_size);
            data_offset += 2;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_broadcastannouncemessage_numberofpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_reserved, tvb, data_offset, 1, ENC_NA);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_broadcastannouncemessage_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Broadcast Announcement Message, %u bytes sent in %u packets", total_size, number_of_packets);
        }
    }

    /* if reassemble has not started yet don't parse the message */
    else if (pdu_format == TP_DATA_TRANSFER && address_reassemble_table_item->reassembleIdentifierTable != NULL)
    {
        tvbuff_t *reassembled_data;
        uint16_t fragment_size = 0;
        bool lastPacket;
        uint8_t sequenceId = tvb_get_uint8(tvb, 0);
        fragment_head *fg_head;

        if (identifier == NULL) {
            wmem_list_frame_t *lastItem = wmem_list_tail(address_reassemble_table_item->reassembleIdentifierTable);

            if (lastItem != NULL) {
                struct reassemble_identifier *lastIdentifier = (struct reassemble_identifier *)wmem_list_frame_data(lastItem);
                lastIdentifier->endFrameId = pinfo->num;
                identifier = lastIdentifier;
            }
        }

        if (identifier != NULL) {
            if (reassembly_total_size > reassembly_current_size + 7) {
                fragment_size = 7;
                lastPacket = false;
            } else {
                fragment_size = reassembly_total_size - reassembly_current_size;
                lastPacket = true;
            }

            fg_head = fragment_add_seq(&isobus_reassembly_table, tvb, 1, pinfo, identifier->identifier, NULL, sequenceId, fragment_size, !lastPacket, 0);
            reassembly_current_size += fragment_size;

            reassembled_data = process_reassembled_data(tvb, 0, pinfo, "Reassembled data", fg_head, &isobus_frag_items, NULL, isobus_tree);

            if (reassembled_data) {
                uint32_t id_reassembled = tvb_get_uint24(reassembled_data, 0, ENC_BIG_ENDIAN);
                uint8_t pdu_format_reassembled = (uint8_t)((id_reassembled >> 8) & 0xff);

                uint32_t pgn_reassembled;
                if (pdu_format < 240) {
                    pgn_reassembled = id_reassembled & 0x03ff00;
                } else {
                    pgn_reassembled = id_reassembled & 0x03ffff;
                }

                proto_tree_add_uint(isobus_tree, hf_isobus_pgn, reassembled_data, 0, 3, pgn_reassembled);

                if (call_isobus_subdissector(tvb_new_subset_remaining(reassembled_data, 3), pinfo, isobus_tree, false, 0, pdu_format_reassembled,
                    pgn_reassembled, src_addr, data) == 0) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Protocol not yet supported");
                }
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Fragment number %u", sequenceId);
            }
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "ERROR: Transport protocol was not initialized");
        }
    } else if (pdu_format == REQUEST) {
        uint32_t req_pgn;
        proto_tree_add_item_ret_uint(isobus_tree, hf_isobus_req_requested_pgn, tvb, 0, 3, ENC_LITTLE_ENDIAN, &req_pgn);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Requesting PGN: %u", req_pgn);
        const char *tmp = isobus_lookup_pgn(req_pgn);

        if (tmp != NULL) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", tmp);
        }
    } else if (pdu_format == ADDRESS_CLAIM) {
        proto_tree *name_tree;
        ti = proto_tree_add_item(isobus_tree, hf_isobus_ac_name, tvb, 0, 8, ENC_NA);
        name_tree = proto_item_add_subtree(ti, ett_isobus_name);

        /* we cannot directly use the value strings as they depend on other parameters */
        uint64_t industry_group, vehicle_system, function, manufacturer;
        proto_tree_add_item(name_tree, hf_isobus_ac_name_arbitrary_address_capable, tvb, 0, 8, ENC_LITTLE_ENDIAN);
        ti = proto_tree_add_item_ret_uint64(name_tree, hf_isobus_ac_name_industry_group, tvb, 0, 8, ENC_LITTLE_ENDIAN, &industry_group);
        proto_item_append_conditional(ti, try_val_to_str_ext((uint32_t)industry_group, &isobus_industry_groups_ext));

        proto_tree_add_item(name_tree, hf_isobus_ac_name_vehicle_system_instance, tvb, 0, 8, ENC_LITTLE_ENDIAN);
        ti = proto_tree_add_item_ret_uint64(name_tree, hf_isobus_ac_name_vehicle_system, tvb, 0, 8, ENC_LITTLE_ENDIAN, &vehicle_system);
        proto_item_append_conditional(ti, try_val_to_str_ext((uint16_t)industry_group * 256 + (uint8_t)vehicle_system, &isobus_vehicle_systems_ext));

        proto_tree_add_item(name_tree, hf_isobus_ac_name_reserved, tvb, 0, 8, ENC_LITTLE_ENDIAN);
        ti = proto_tree_add_item_ret_uint64(name_tree, hf_isobus_ac_name_function, tvb, 0, 8, ENC_LITTLE_ENDIAN, &function);
        proto_item_append_conditional(ti, isobus_lookup_function((uint32_t)industry_group, (uint32_t)vehicle_system, (uint32_t)function));

        proto_tree_add_item(name_tree, hf_isobus_ac_name_function_instance, tvb, 0, 8, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(name_tree, hf_isobus_ac_name_ecu_instance, tvb, 0, 8, ENC_LITTLE_ENDIAN);
        ti = proto_tree_add_item_ret_uint64(name_tree, hf_isobus_ac_name_manufacturer, tvb, 0, 8, ENC_LITTLE_ENDIAN, &manufacturer);
        proto_item_append_conditional(ti, try_val_to_str_ext((uint32_t)manufacturer, &isobus_manufacturers_ext));

        proto_tree_add_item(name_tree, hf_isobus_ac_name_id_number, tvb, 0, 8, ENC_LITTLE_ENDIAN);

        unsigned address_claimed = can_info.id & 0xff;
        switch (address_claimed) {
        case 255:
            /* This seems to be not allowed. Create ticket, if this is not correct. */
            col_append_fstr(pinfo->cinfo, COL_INFO, "Trying to claim global destination address!? This seems wrong!");
            break;
        case 254:
            col_append_fstr(pinfo->cinfo, COL_INFO, "Cannot claim address");
            break;
        default:
            col_append_fstr(pinfo->cinfo, COL_INFO, "Address claimed %u", address_claimed);
        }
    } else if (call_isobus_subdissector(tvb, pinfo, isobus_tree, false, priority, pdu_format, pgn, src_addr, data) == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Protocol not yet supported");
        proto_tree_add_item(isobus_tree, hf_isobus_payload, tvb, 0, tvb_captured_length(tvb), ENC_NA);
    }

    return tvb_reported_length(tvb);
}

static void
isobus_init(void) {
    reassembly_table_init(&isobus_reassembly_table, &addresses_reassembly_table_functions);
}

static void
isobus_cleanup(void) {
    reassembly_table_destroy(&isobus_reassembly_table);
}

/* Register the protocol with Wireshark */
void
proto_register_isobus(void) {
    static hf_register_info hf[] = {
        { &hf_isobus_can_id, {
            "CAN-ID", "isobus.can_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_priority, {
            "Priority", "isobus.priority", FT_UINT32, BASE_HEX, NULL, 0x1C000000, NULL, HFILL } },
        { &hf_isobus_ext_data_page, {
            "Ext data page", "isobus.edp", FT_UINT32, BASE_HEX, NULL, 0x02000000, NULL, HFILL } },
        { &hf_isobus_data_page, {
            "Data page", "isobus.datapage", FT_UINT32, BASE_HEX, NULL, 0x01000000, NULL, HFILL } },
        { &hf_isobus_pdu_format_dp0, {
            "PDU Format", "isobus.pdu_format", FT_UINT32, BASE_DEC, VALS(pdu_format_dp0), 0xff0000, NULL, HFILL } },
        { &hf_isobus_pdu_format_dp1, {
            "PDU Format", "isobus.pdu_format", FT_UINT32, BASE_DEC, VALS(pdu_format_dp1), 0xff0000, NULL, HFILL } },
        { &hf_isobus_group_extension, {
            "Group Extension", "isobus.grp_ext", FT_UINT32, BASE_DEC, NULL, 0xff00, NULL, HFILL } },
        { &hf_isobus_dst_addr, {
            "Destination Address", "isobus.dst_addr", FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(address_range), 0xff00, NULL, HFILL } },
        { &hf_isobus_src_addr, {
            "Source Address", "isobus.src_addr", FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(address_range), 0xff, NULL, HFILL } },
        { &hf_isobus_pgn, {
            "PGN", "isobus.pgn", FT_UINT24, BASE_DEC_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&isobus_pgn_names_ext), 0x0, NULL, HFILL } },
        { &hf_isobus_payload, {
            "Payload", "isobus.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_isobus_req_requested_pgn, {
            "Requested PGN", "isobus.req.requested_pgn", FT_UINT24, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&isobus_pgn_names_ext), 0x0, NULL, HFILL } },

        { &hf_isobus_ac_name, {
            "Name", "isobus.ac.name", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_ac_name_id_number, {
            "Identity Number", "isobus.ac.name.identity_number", FT_UINT64, BASE_DEC, NULL, 0x00000000001fffff, NULL, HFILL } },
        { &hf_isobus_ac_name_manufacturer, {
            "Manufacturer", "isobus.ac.name.manufacturer", FT_UINT64, BASE_DEC, NULL, 0x00000000ffe00000, NULL, HFILL } },
        { &hf_isobus_ac_name_function_instance, {
            "Function Instance", "isobus.ac.name.function_instance", FT_UINT64, BASE_DEC, NULL, 0x000000f000000000, NULL, HFILL } },
        { &hf_isobus_ac_name_ecu_instance, {
            "ECU Instance", "isobus.ac.name.ecu_instance", FT_UINT64, BASE_DEC, NULL, 0x0000000f00000000, NULL, HFILL } },
        { &hf_isobus_ac_name_function, {
            "Function", "isobus.ac.name.function", FT_UINT64, BASE_DEC, NULL, 0x0000ff0000000000, NULL, HFILL } },
        { &hf_isobus_ac_name_reserved, {
            "Reserved", "isobus.ac.name.reserved", FT_UINT64, BASE_HEX, NULL, 0x0001000000000000, NULL, HFILL } },
        { &hf_isobus_ac_name_vehicle_system,
          { "Vehicle System", "isobus.ac.name.vehicle_system", FT_UINT64, BASE_DEC, NULL, 0x00fe000000000000, NULL, HFILL } },
        { &hf_isobus_ac_name_vehicle_system_instance, {
            "System Instance", "isobus.ac.name.system_instance", FT_UINT64, BASE_DEC, NULL, 0x0f00000000000000, NULL, HFILL } },
        { &hf_isobus_ac_name_industry_group, {
            "Industry Group", "isobus.ac.name.industry_group", FT_UINT64, BASE_DEC, NULL, 0x7000000000000000, NULL, HFILL } },
        { &hf_isobus_ac_name_arbitrary_address_capable, {
            "Arbitrary Address Capable", "isobus.ac.name.arbitrary_address_capable", FT_UINT64, BASE_DEC, NULL, 0x8000000000000000, NULL, HFILL } },

        { &hf_isobus_transportprotocol_controlbyte, {
            "Control Byte", "isobus.transport_protocol.control_byte", FT_UINT8, BASE_DEC, VALS(transport_protocol_control_byte), 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_requesttosend_totalsize, {
            "Total message size", "isobus.transport_protocol.request_to_send.total_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_requesttosend_numberofpackets, {
            "Number of Packets", "isobus.transport_protocol.request_to_send.number_of_packets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_requesttosend_maximumpackets, {
            "Maximum Packets", "isobus.transport_protocol.request_to_send.maximum_packets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_requesttosend_pgn, {
            "PGN", "isobus.transport_protocol.request_to_send.pgn", FT_UINT24, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&isobus_pgn_names_ext), 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_cleartosend_numberofpacketscanbesent, {
            "Number of packets that can be sent", "isobus.transport_protocol.request_to_send.number_of_packets_that_can_be_sent", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_cleartosend_nextpacketnumber, {
            "Next packet number", "isobus.transport_protocol.request_to_send.next_packet_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_cleartosend_pgn, {
            "PGN", "isobus.transport_protocol.clear_to_send.pgn", FT_UINT24, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&isobus_pgn_names_ext), 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_endofmsgack_totalsize, {
            "Total Size", "isobus.transport_protocol.end_of_message_acknowledgement.total_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_endofmsgack_numberofpackets, {
            "Number of Packets", "isobus.transport_protocol.end_of_message_acknowledgement.number_of_packets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_endofmsgack_pgn, {
            "PGN", "isobus.transport_protocol.end_of_message_acknowledgement.pgn", FT_UINT24, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&isobus_pgn_names_ext), 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_connabort_abortreason, {
            "Connection Abort reason", "isobus.transport_protocol.connection_abort.abort_reason", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(connection_abort_reasons), 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_connabort_pgn, {
            "PGN", "isobus.transport_protocol.connection_abort.pgn", FT_UINT24, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&isobus_pgn_names_ext), 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_broadcastannouncemessage_totalsize, {
            "Total Message Size", "isobus.transport_protocol.broadcast_announce_message.total_message_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_broadcastannouncemessage_numberofpackets, {
            "Total Number of Packets", "isobus.transport_protocol.broadcast_announce_message.total_number_of_packets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_broadcastannouncemessage_pgn, {
            "PGN", "isobus.transport_protocol.broadcast_announce_message.pgn", FT_UINT24, BASE_HEX | BASE_EXT_STRING, VALS_EXT_PTR(&isobus_pgn_names_ext), 0x0, NULL, HFILL } },
        { &hf_isobus_transportprotocol_reserved, {
            "Reserved", "isobus.transport_protocol.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_msg_fragments, {
            "Message fragments", "isobus.fragments", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment, {
            "Message fragment", "isobus.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_overlap, {
            "Message fragment overlap", "isobus.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_overlap_conflicts, {
            "Message fragment overlapping with conflicting data", "isobus.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_multiple_tails, {
            "Message has multiple tail fragments", "isobus.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_too_long_fragment, {
            "Message fragment too long", "isobus.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_error, {
            "Message defragmentation error", "isobus.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_fragment_count, {
            "Message fragment count", "isobus.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_reassembled_in, {
            "Reassembled in", "isobus.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_reassembled_length, {
            "Reassembled length", "isobus.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_msg_reassembled_data, {
                "Reassembled data", "isobus.reassembled.data", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } }
    };

    static int *ett[] = {
        &ett_isobus,
        &ett_isobus_can_id,
        &ett_isobus_name,
        &ett_isobus_fragment,
        &ett_isobus_fragments
    };

    /* Register protocol init routine */
    register_init_routine(&isobus_init);
    register_cleanup_routine(&isobus_cleanup);

    proto_isobus = proto_register_protocol("ISObus", "ISOBUS", "isobus");

    proto_register_field_array(proto_isobus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    addressIdentifierTable = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), address_combination_hash, address_combination_equal);

    subdissector_table_pdu_format = register_dissector_table("isobus.pdu_format", "PDU format", proto_isobus, FT_UINT8, BASE_DEC);
    subdissector_table_pgn = register_dissector_table("isobus.pgn", "PGN", proto_isobus, FT_UINT32, BASE_DEC);

    isobus_handle = register_dissector("isobus",  dissect_isobus, proto_isobus );
}

void
proto_reg_handoff_isobus(void) {
   dissector_add_for_decode_as("can.subdissector", isobus_handle );
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
