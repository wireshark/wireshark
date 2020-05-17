/* packet-isobus.c
 * Routines for ISObus dissection (Based on CANOpen Dissector)
 * Copyright 2016, Jeroen Sack <jsack@lely.com>
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
#include <epan/dissectors/packet-socketcan.h>
#include <epan/wmem/wmem_map.h>

void proto_register_isobus(void);
void proto_reg_handoff_isobus(void);

/* Initialize the protocol and registered fields */
static int proto_isobus = -1;
static int hf_isobus_can_id = -1;
static int hf_isobus_priority = -1;
static int hf_isobus_ext_data_page = -1;
static int hf_isobus_src_addr = -1;
static int hf_isobus_data_page = -1;
static int hf_isobus_pdu_format_dp0 = -1;
static int hf_isobus_pdu_format_dp1 = -1;
static int hf_isobus_dst_addr = -1;
static int hf_isobus_group_extension = -1;
static int hf_isobus_transportprotocol_controlbyte = -1;
static int hf_isobus_transportprotocol_requesttosend_totalsize = -1;
static int hf_isobus_transportprotocol_requesttosend_numberofpackets = -1;
static int hf_isobus_transportprotocol_requesttosend_maximumpackets = -1;
static int hf_isobus_transportprotocol_requesttosend_pgn = -1;
static int hf_isobus_transportprotocol_cleartosend_numberofpacketscanbesent = -1;
static int hf_isobus_transportprotocol_cleartosend_nextpacketnumber = -1;
static int hf_isobus_transportprotocol_cleartosend_pgn = -1;
static int hf_isobus_transportprotocol_endofmsgack_totalsize = -1;
static int hf_isobus_transportprotocol_endofmsgack_numberofpackets = -1;
static int hf_isobus_transportprotocol_endofmsgack_pgn = -1;
static int hf_isobus_transportprotocol_connabort_abortreason = -1;
static int hf_isobus_transportprotocol_connabort_pgn = -1;
static int hf_isobus_transportprotocol_broadcastannouncemessage_totalsize = -1;
static int hf_isobus_transportprotocol_broadcastannouncemessage_numberofpackets = -1;
static int hf_isobus_transportprotocol_broadcastannouncemessage_pgn = -1;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;
static int hf_msg_reassembled_data = -1;

/* Desegmentation of isobus transport protocol streams */
static reassembly_table isobus_reassembly_table;
static unsigned int reassembly_total_size;
static unsigned int reassembly_current_size;

static dissector_table_t subdissector_table;

#define VT_TO_ECU 230
#define ECU_TO_VT 231
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
    { 234, "REQUEST" },
    { TP_DATA_TRANSFER, "TRANSPORT PROTOCOL - DATA TRANSFER" },
    { TP_DATA_MANAGEMENT, "TRANSPORT PROTOCOL - CONNECTION MANAGEMENT" },
    { 238, "ADDRESS CLAIM" },
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
    { 234, "REQ" },
    { TP_DATA_TRANSFER, "TP.DT" },
    { TP_DATA_MANAGEMENT, "TP.CM" },
    { 238, "AC" },
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
    { 19, "End of Message Acknowledgement" },
    { 255, "Connection Abort" },
    { 32, "Broadcast Announce Message" },
    { 0, NULL }
};

static gint ett_isobus = -1;
static gint ett_isobus_can_id = -1;
static gint ett_isobus_fragment = -1;
static gint ett_isobus_fragments = -1;

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

struct address_combination
{
    guint8 src_address;
    guint8 dst_address;
};

struct reassemble_identifier
{
    guint32 startFrameId;
    guint32 endFrameId;
    guint32 identifier;
};

struct address_reassemble_table
{
    wmem_list_t* reassembleIdentifierTable;
    guint32 identifierCounter;
};

static wmem_map_t *addressIdentifierTable = NULL;

static struct reassemble_identifier* findIdentifierFor(wmem_list_t* reassembleIdentifierTable, guint32 frameIndex)
{
    wmem_list_frame_t* currentItem = wmem_list_head(reassembleIdentifierTable);

    while (currentItem != NULL)
    {
        struct reassemble_identifier* currentData = (struct reassemble_identifier*)wmem_list_frame_data(currentItem);
        if (frameIndex <= currentData->endFrameId && frameIndex >= currentData->startFrameId)
        {
            return currentData;
        }
        else
        {
            currentItem = wmem_list_frame_next(currentItem);
        }
    }
    return NULL;
}

static gboolean
address_combination_equal(gconstpointer p1, gconstpointer p2)
{
    const struct address_combination* addr_combi1 = (const struct address_combination*)p1;
    const struct address_combination* addr_combi2 = (const struct address_combination*)p2;

    if (addr_combi1->src_address == addr_combi2->src_address &&
        addr_combi1->dst_address == addr_combi2->dst_address)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static guint
address_combination_hash(gconstpointer p)
{
    const struct address_combination* addr_combi = (const struct address_combination*)p;
    return (addr_combi->src_address * 256) + (addr_combi->dst_address);
}

static struct address_reassemble_table* findAddressIdentifierFor(guint8 src_address, guint8 dst_address)
{
    struct address_combination* addrCombi = wmem_new(wmem_file_scope(), struct address_combination);

    struct address_reassemble_table* foundItem;

    addrCombi->src_address = src_address;
    addrCombi->dst_address = dst_address;

    foundItem = (struct address_reassemble_table*)wmem_map_lookup(addressIdentifierTable, addrCombi);

    if(foundItem != NULL)
    {
        return foundItem;
    }
    else
    {
        /* nothing found so create a new one */
        struct address_reassemble_table* newItem;
        newItem = wmem_new(wmem_file_scope(), struct address_reassemble_table);
        newItem->identifierCounter = 0;
        newItem->reassembleIdentifierTable = wmem_list_new(wmem_file_scope());
        wmem_map_insert(addressIdentifierTable, addrCombi, newItem);
        return newItem;
    }
}

/* Code to actually dissect the packets */
static int
dissect_isobus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    /* guint        priority; */
    /* guint        ext_data_page; */
    guint        src_addr;
    guint        data_page;
    guint        pdu_format;
    guint        pdu_specific;
    struct can_info can_info;
    char str_dst[10];
    char str_src[4];

    static guint seqnr = 0;

    int data_offset = 0;

    proto_item *ti, *can_id_ti;
    proto_tree *isobus_tree;
    proto_tree *isobus_can_id_tree;

    struct reassemble_identifier* identifier = NULL;
    struct address_reassemble_table* address_reassemble_table_item = NULL;

    DISSECTOR_ASSERT(data);
    can_info = *((struct can_info*)data);

    if ((can_info.id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) ||
        !(can_info.id & CAN_EFF_FLAG))
    {
        /* Error, RTR and frames with standard ids are not for us. */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISObus");
    col_clear(pinfo->cinfo, COL_INFO);

    /*priority      = (can_info.id >> 26) & 0x07;*/
    /*ext_data_page = (can_info.id >> 25) & 0x01;*/
    data_page     = (can_info.id >> 24) & 0x01;
    pdu_format    = (can_info.id >> 16) & 0xff;
    pdu_specific  = (can_info.id >> 8) & 0xff;
    src_addr      = (can_info.id >> 0 ) & 0xff;

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
    switch(data_page)
    {
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
    if(pdu_format <= 239)
    {
        ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_dst_addr, tvb, 0, 0, can_info.id);
            proto_item_set_generated(ti);
    }
    else
    {
        ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_group_extension, tvb, 0, 0, can_info.id);
            proto_item_set_generated(ti);
    }

    /* add source address */
    ti = proto_tree_add_uint(isobus_can_id_tree, hf_isobus_src_addr, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);

    /* put source address in source field */
    g_snprintf(str_src, 4, "%d", src_addr);
    alloc_address_wmem(pinfo->pool, &pinfo->src, AT_STRINGZ, (int)strlen(str_src) + 1, str_src);

    if(pdu_format <= 239) /* PDU1 format */
    {
        /* put destination address in address field */
        g_snprintf(str_dst, 4, "%d", pdu_specific);
        alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_STRINGZ, (int)strlen(str_dst) + 1, str_dst);
    }
    else
    {
        /* put group destination address in address field and add (grp) to it */
        g_snprintf(str_dst, 10, "%d (grp)", pdu_specific);
        alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_STRINGZ, (int)strlen(str_dst) + 1, str_dst);
    }

    switch(data_page)
    {
    case 0:
        col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] ",
            val_to_str(pdu_format, pdu_format_dp0_short, "Unknown"));
        break;
    case 1:
        col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] ",
            val_to_str(pdu_format, pdu_format_dp1_short, "Unknown"));
        break;
    }

    if (pdu_format == TP_DATA_MANAGEMENT  || pdu_format == TP_DATA_TRANSFER ||
        pdu_format == ETP_DATA_MANAGEMENT || pdu_format == ETP_DATA_TRANSFER)
    {
        gboolean isReply = FALSE;
        if(pdu_format == TP_DATA_MANAGEMENT)
        {
            guint8 control_byte = tvb_get_guint8(tvb, data_offset);
            switch(control_byte)
            {
                case 17:
                case 19:
                    isReply = TRUE;
                    break;
                case 16:
                default:
                    isReply = FALSE;
                    break;
            }
        }
        if(isReply)
        {
            address_reassemble_table_item =
                findAddressIdentifierFor(pdu_specific, src_addr);
        }
        else
        {
            address_reassemble_table_item =
                findAddressIdentifierFor(src_addr, pdu_specific);
        }
        identifier = findIdentifierFor(
            address_reassemble_table_item->reassembleIdentifierTable,
            pinfo->num);
    }

    if(pdu_format == TP_DATA_MANAGEMENT)
    {
        guint32 control_byte;
        proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_controlbyte, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &control_byte);
        data_offset += 1;

        if (control_byte == 16)
        {
            guint32 total_size, number_of_packets;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_requesttosend_totalsize, tvb, data_offset, 2, ENC_LITTLE_ENDIAN, &total_size);
            data_offset += 2;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_requesttosend_numberofpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_requesttosend_maximumpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN);
            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_requesttosend_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            if (identifier)
            {
                seqnr = identifier->identifier;
            }
            else
            {
                struct reassemble_identifier* reassembleIdentifierTableEntry =
                    wmem_new(wmem_file_scope(), struct reassemble_identifier);
                seqnr = ++address_reassemble_table_item->identifierCounter;
                reassembleIdentifierTableEntry->identifier = seqnr;
                reassembleIdentifierTableEntry->startFrameId = pinfo->num;
                reassembleIdentifierTableEntry->endFrameId = pinfo->num;

                wmem_list_append(address_reassemble_table_item->reassembleIdentifierTable, reassembleIdentifierTableEntry);
            }

            fragment_add_seq(&isobus_reassembly_table, tvb, 5, pinfo,
                seqnr, NULL, 0, 3, TRUE, 0);
            fragment_set_tot_len(&isobus_reassembly_table, pinfo,
                seqnr, NULL, number_of_packets);
            reassembly_current_size = 3;
            reassembly_total_size = total_size + 3;


            col_append_fstr(pinfo->cinfo, COL_INFO, "Request to send message of %u bytes in %u fragments", total_size, number_of_packets);
        }
        else if (control_byte == 17)
        {
            guint32 number_of_packets_can_be_sent, next_packet_number;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_cleartosend_numberofpacketscanbesent, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets_can_be_sent);
            data_offset += 1;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_cleartosend_nextpacketnumber, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &next_packet_number);
            data_offset += 1;

            data_offset += 2;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_cleartosend_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Clear to send, can receive %u packets, next packet is %u", number_of_packets_can_be_sent, next_packet_number);
        }
        else if (control_byte == 19)
        {
            guint32 total_size, number_of_packets;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_endofmsgack_totalsize, tvb, data_offset, 2, ENC_LITTLE_ENDIAN, &total_size);
            data_offset += 2;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_endofmsgack_numberofpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets);
            data_offset += 1;

            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_endofmsgack_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "End of Message Acknowledgement, %u bytes sent in %u packets", total_size, number_of_packets);
        }
        else if (control_byte == 255)
        {
            guint32 connection_abort_reason;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_connabort_abortreason, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &connection_abort_reason);
            data_offset += 1;

            data_offset += 3;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_connabort_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Connection Abort, %s", rval_to_str(connection_abort_reason, connection_abort_reasons, "unknown reason"));
        }
        else if (control_byte == 32)
        {
            guint32 total_size, number_of_packets;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_broadcastannouncemessage_totalsize, tvb, data_offset, 2, ENC_LITTLE_ENDIAN, &total_size);
            data_offset += 2;

            proto_tree_add_item_ret_uint(tree, hf_isobus_transportprotocol_broadcastannouncemessage_numberofpackets, tvb, data_offset, 1, ENC_LITTLE_ENDIAN, &number_of_packets);
            data_offset += 1;

            data_offset += 1;

            proto_tree_add_item(tree, hf_isobus_transportprotocol_broadcastannouncemessage_pgn, tvb, data_offset, 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Broadcast Announcement Message, %u bytes sent in %u packets", total_size, number_of_packets);
        }
    }

    //if reassemble has not started yet don't parse the message
    else if (pdu_format == TP_DATA_TRANSFER && address_reassemble_table_item->reassembleIdentifierTable != NULL)
    {
        tvbuff_t *reassembled_data;
        guint16 fragment_size = 0;
        gboolean lastPacket;
        guint8 sequenceId = tvb_get_guint8(tvb, 0);
        fragment_head *fg_head;
        if (identifier == NULL)
        {
            wmem_list_frame_t* lastItem = wmem_list_tail(address_reassemble_table_item->reassembleIdentifierTable);
            if(lastItem != NULL)
            {
                struct reassemble_identifier* lastIdentifier = (struct reassemble_identifier*)wmem_list_frame_data(lastItem);
                lastIdentifier->endFrameId = pinfo->num;
                identifier = lastIdentifier;
            }
        }

        if(identifier != NULL)
        {
            if(reassembly_total_size > reassembly_current_size + 7)
            {
                fragment_size = 7;
                lastPacket = FALSE;
            }
            else
            {
                fragment_size = reassembly_total_size - reassembly_current_size;
                lastPacket = TRUE;
            }

            fg_head = fragment_add_seq(&isobus_reassembly_table, tvb, 1, pinfo,
                identifier->identifier, NULL, sequenceId, fragment_size, !lastPacket, 0);
            reassembly_current_size += fragment_size;

            reassembled_data = process_reassembled_data(tvb, 0, pinfo, "Reassembled data",
                fg_head, &isobus_frag_items, NULL, tree);
            if (reassembled_data)
            {
                guint8 pdu_format_reassembled = tvb_get_guint8(reassembled_data, 1);

                if (dissector_try_uint_new(subdissector_table, pdu_format_reassembled,
                    tvb_new_subset_remaining(reassembled_data, 3), pinfo,
                    isobus_tree, FALSE, NULL) == 0)
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Protocol not yet supported");
                }
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Fragment number %u", sequenceId);
            }
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "ERROR: Transport protocol was not initialized");
        }
    }
    else if(dissector_try_uint_new(subdissector_table, pdu_format, tvb, pinfo, isobus_tree, FALSE, data) == 0)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Protocol not yet supported");
    }

    return tvb_reported_length(tvb);
}

static void
isobus_init(void)
{
    reassembly_table_init(&isobus_reassembly_table, &addresses_reassembly_table_functions);
}

static void
isobus_cleanup(void)
{
    reassembly_table_destroy(&isobus_reassembly_table);
}

/* Register the protocol with Wireshark */
void
proto_register_isobus(void)
{
    static hf_register_info hf[] = {
        { &hf_isobus_can_id,
          { "CAN-ID", "isobus.can_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_priority,
          { "Priority", "isobus.priority",
            FT_UINT32, BASE_HEX, NULL, 0x1C000000,
            NULL, HFILL }
        },
        { &hf_isobus_ext_data_page,
          { "Ext data page", "isobus.edp",
            FT_UINT32, BASE_HEX, NULL, 0x2000000,
            NULL, HFILL }
        },
        { &hf_isobus_data_page,
          { "Data page", "isobus.datapage",
            FT_UINT32, BASE_HEX, NULL, 0x1000000,
            NULL, HFILL }
        },
        { &hf_isobus_pdu_format_dp0,
          { "PDU Format", "isobus.pdu_format",
            FT_UINT32, BASE_DEC, VALS(pdu_format_dp0), 0xff0000,
            NULL, HFILL }
        },
        { &hf_isobus_pdu_format_dp1,
          { "PDU Format", "isobus.pdu_format",
            FT_UINT32, BASE_DEC, VALS(pdu_format_dp1), 0xff0000,
            NULL, HFILL }
        },
        { &hf_isobus_group_extension,
          { "Group Extension", "isobus.grp_ext",
            FT_UINT32, BASE_DEC, NULL, 0xff00,
            NULL, HFILL }
        },
        { &hf_isobus_dst_addr,
          { "Destination Address", "isobus.dst_addr",
            FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(address_range), 0xff00,
            NULL, HFILL }
        },
        { &hf_isobus_src_addr,
          { "Source Address", "isobus.src_addr",
            FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(address_range), 0xff,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_controlbyte,
          { "Control Byte", "isobus.transport_protocol.control_byte",
            FT_UINT8, BASE_DEC, VALS(transport_protocol_control_byte), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_requesttosend_totalsize,
          { "Total message size", "isobus.transport_protocol.request_to_send.total_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_requesttosend_numberofpackets,
          { "Number of Packets", "isobus.transport_protocol.request_to_send.number_of_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_requesttosend_maximumpackets,
          { "Maximum Packets", "isobus.transport_protocol.request_to_send.maximum_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_requesttosend_pgn,
          { "PGN", "isobus.transport_protocol.request_to_send.pgn",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_cleartosend_numberofpacketscanbesent,
          { "Number of packets that can be sent", "isobus.transport_protocol.request_to_send.number_of_packets_that_can_be_sent",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_cleartosend_nextpacketnumber,
          { "Next packet number", "isobus.transport_protocol.request_to_send.next_packet_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_cleartosend_pgn,
          { "PGN", "isobus.transport_protocol.clear_to_send.pgn",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_endofmsgack_totalsize,
          { "Total Size", "isobus.transport_protocol.end_of_message_acknowledgement.total_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_endofmsgack_numberofpackets,
          { "Number of Packets",           "isobus.transport_protocol.end_of_message_acknowledgement.number_of_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_endofmsgack_pgn,
          { "PGN", "isobus.transport_protocol.end_of_message_acknowledgement.pgn",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_connabort_abortreason,
          { "Connection Abort reason", "isobus.transport_protocol.connection_abort.abort_reason",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(connection_abort_reasons), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_connabort_pgn,
          { "PGN", "isobus.transport_protocol.connection_abort.pgn",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_broadcastannouncemessage_totalsize,
          { "Total Message Size", "isobus.transport_protocol.broadcast_announce_message.total_message_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_broadcastannouncemessage_numberofpackets,
          { "Total Number of Packets", "isobus.transport_protocol.broadcast_announce_message.total_number_of_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_transportprotocol_broadcastannouncemessage_pgn,
          { "PGN", "isobus.transport_protocol.broadcast_announce_message.pgn",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_msg_fragments,
          { "Message fragments", "isobus.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_fragment,
          { "Message fragment", "isobus.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_fragment_overlap,
          { "Message fragment overlap", "isobus.fragment.overlap",
            FT_BOOLEAN, 0, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_fragment_overlap_conflicts,
          { "Message fragment overlapping with conflicting data", "isobus.fragment.overlap.conflicts",
            FT_BOOLEAN, 0, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_fragment_multiple_tails,
          { "Message has multiple tail fragments", "isobus.fragment.multiple_tails",
            FT_BOOLEAN, 0, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_fragment_too_long_fragment,
          { "Message fragment too long", "isobus.fragment.too_long_fragment",
            FT_BOOLEAN, 0, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_fragment_error,
          { "Message defragmentation error", "isobus.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_fragment_count,
          { "Message fragment count", "isobus.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_reassembled_in,
          { "Reassembled in", "isobus.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_reassembled_length,
          { "Reassembled length", "isobus.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_msg_reassembled_data,
          { "Reassembled data", "isobus.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_isobus,
        &ett_isobus_can_id,
        &ett_isobus_fragment,
        &ett_isobus_fragments
    };

    /* Register protocol init routine */
    register_init_routine(&isobus_init);
    register_cleanup_routine(&isobus_cleanup);

    proto_isobus = proto_register_protocol("ISObus",
                                           "ISOBUS",
                                           "isobus");

    proto_register_field_array(proto_isobus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    addressIdentifierTable = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), address_combination_hash, address_combination_equal);

    subdissector_table = register_dissector_table("isobus.pdu_format",
        "PDU format", proto_isobus, FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_isobus(void)
{
   dissector_handle_t isobus_handle;

   isobus_handle = create_dissector_handle( dissect_isobus, proto_isobus );
   dissector_add_for_decode_as("can.subdissector", isobus_handle );
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:+
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
