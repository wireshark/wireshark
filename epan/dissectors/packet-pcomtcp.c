/* packet-pcomtcp.c
 * Routines for PCOM/TCP dissection
 * Copyright 2018, Luis Rosa <lmrosa@dei.uc.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * PCOM is a protocol to communicate with Unitronics PLCs either by serial or TCP.
 * Two modes are available, ASCII and Binary.
 *
 * See https://unitronicsplc.com/Download/SoftwareUtilities/Unitronics%20PCOM%20Protocol.pdf
 *
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>

void proto_reg_handoff_pcomtcp(void);
void proto_register_pcomtcp(void);

/* Initialize the protocol and registered fields */
static int proto_pcomtcp = -1;
static int proto_pcomascii = -1;
static int proto_pcombinary = -1;

static int hf_pcomtcp_transid = -1;
static int hf_pcomtcp_protocol = -1;
static int hf_pcomtcp_reserved = -1;
static int hf_pcomtcp_length = -1;

static int hf_pcomascii_stx = -1;
static int hf_pcomascii_unitid = -1;
static int hf_pcomascii_command_code = -1;
static int hf_pcomascii_address = -1;
static int hf_pcomascii_length = -1;
static int hf_pcomascii_address_value = -1;
static int hf_pcomascii_command = -1;
static int hf_pcomascii_checksum = -1;
static int hf_pcomascii_etx = -1;

static int hf_pcombinary_stx = -1;
static int hf_pcombinary_id = -1;
static int hf_pcombinary_reserved1 = -1;
static int hf_pcombinary_reserved2 = -1;
static int hf_pcombinary_reserved3 = -1;
static int hf_pcombinary_command = -1;
static int hf_pcombinary_reserved4 = -1;
static int hf_pcombinary_command_specific = -1;
static int hf_pcombinary_data_length = -1;
static int hf_pcombinary_header_checksum = -1;
static int hf_pcombinary_data = -1;
static int hf_pcombinary_footer_checksum = -1;
static int hf_pcombinary_etx = -1;

static expert_field ei_pcomtcp_reserved_bad_value = EI_INIT;
static expert_field ei_pcomascii_command_unsupported = EI_INIT;
static expert_field ei_pcombinary_reserved1_bad_value = EI_INIT;
static expert_field ei_pcombinary_reserved2_bad_value = EI_INIT;
static expert_field ei_pcombinary_reserved3_bad_value = EI_INIT;
static expert_field ei_pcombinary_reserved4_bad_value = EI_INIT;
static expert_field ei_pcombinary_command_unsupported = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_pcomtcp = -1;
static gint ett_pcomascii = -1;
static gint ett_pcombinary = -1;

static dissector_handle_t pcomtcp_handle;
static dissector_handle_t pcomascii_handle;
static dissector_handle_t pcombinary_handle;

/* PCOM/TCP definitions */
#define PCOMTCP_MIN_LENGTH 6
#define PCOMTCP_TCP_PORT 20256
#define PCOM_ASCII 101
#define PCOM_BINARY 102

static range_t *global_pcomtcp_tcp_ports = NULL; /* Port 20256, by default */

/* Translate pcomp_protocol to string */
static const value_string pcomp_protocol_vals[] = {
    { PCOM_ASCII,          "ASCII mode" },
    { PCOM_BINARY,         "Binary mode" },
    { 0,                    NULL },
};

#define PCOMASCII_ID_COMMAND                0x4944    // "ID"
#define PCOMASCII_START_COMMAND             0x434352  // "CCR"
#define PCOMASCII_STOP_COMMAND              0x434353  // "CCS"
#define PCOMASCII_RESET_COMMAND             0x434345  // "CCE"
#define PCOMASCII_INIT_COMMAND              0x434349  // "CCI"
#define PCOMASCII_REPLY_ADMIN_COMMAND       0x4343    // "CC"
#define PCOMASCII_GET_UNITID                0x5547    // "UG"
#define PCOMASCII_SET_UNITID                0x5553    // "US"
#define PCOMASCII_GET_RTC                   0x5243    // "RC"
#define PCOMASCII_SET_RTC                   0x5343    // "SC"
#define PCOMASCII_READ_INPUTS               0x5245    // "RE"
#define PCOMASCII_READ_OUTPUTS              0x5241    // "RA"
#define PCOMASCII_READ_SYSTEM_BITS          0x4753    // "GS"
#define PCOMASCII_READ_SYSTEM_INTEGERS      0x4746    // "GF"
#define PCOMASCII_READ_SYSTEM_LONGS         0x524e48  // "RNH"
#define PCOMASCII_READ_SYSTEM_DOUBLE_WORDS  0x524e4a  // "RNJ"
#define PCOMASCII_READ_MEMORY_BITS          0x5242    // "RB"
#define PCOMASCII_READ_MEMORY_INTEGERS      0x5257    // "RW"
#define PCOMASCII_READ_MEMORY_LONGS         0x524e4c  // "RNL"
#define PCOMASCII_READ_MEMORY_DOUBLE_WORDS  0x524e44  // "RND"
#define PCOMASCII_READ_LONGS                0x524e    // "RN"
#define PCOMASCII_WRITE_OUTPUTS             0x5341    // "SA"
#define PCOMASCII_WRITE_SYSTEM_BITS         0x5353    // "SS"
#define PCOMASCII_WRITE_SYSTEM_INTEGERS     0x5346    // "SF"
#define PCOMASCII_WRITE_SYSTEM_LONGS        0x534e48  // "SNH"
#define PCOMASCII_WRITE_SYSTEM_DOUBLE_WORDS 0x534e4a  // "SNJ"
#define PCOMASCII_WRITE_MEMORY_BITS         0x5342    // "SB"
#define PCOMASCII_WRITE_MEMORY_INTEGERS     0x5357    // "SW"
#define PCOMASCII_WRITE_MEMORY_LONGS        0x534e4c  // "SNL"
#define PCOMASCII_WRITE_MEMORY_DOUBLE_WORDS 0x534e44  // "SND"
#define PCOMASCII_WRITE_LONGS               0x534e    // "SN"

#define PCOMBINARY_GET_PLC_NAME_REQUEST     0x0c
#define PCOMBINARY_GET_PLC_NAME_REPLY       0x8c
#define PCOMBINARY_READ_OPERANDS_REQUEST    0x4d
#define PCOMBINARY_READ_OPERANDS_REPLY      0xcd
#define PCOMBINARY_READ_DATA_TABLE_REQUEST  0x04
#define PCOMBINARY_READ_DATA_TABLE_REPLY    0x84
#define PCOMBINARY_WRITE_DATA_TABLE_REQUEST 0x44
#define PCOMBINARY_WRITE_DATA_TABLE_REPLY   0xc4

/* Translate pcomascii_command_code to string */
static const value_string pcomascii_cc_vals[] = {
    { PCOMASCII_ID_COMMAND,               "Send Identification Command" },
    { PCOMASCII_START_COMMAND,            "Send Start Command" },
    { PCOMASCII_STOP_COMMAND,             "Send Stop Command" },
    { PCOMASCII_RESET_COMMAND,            "Send Reset Command" },
    { PCOMASCII_INIT_COMMAND,             "Send Init Command" },
    { PCOMASCII_REPLY_ADMIN_COMMAND,      "Reply of Admin Commands (CC*)" },
    { PCOMASCII_GET_UNITID,               "Get UnitID" },
    { PCOMASCII_SET_UNITID,               "Set UnitID" },
    { PCOMASCII_GET_RTC,                  "Get RTC" },
    { PCOMASCII_SET_RTC,                  "Set RTC" },
    { PCOMASCII_READ_INPUTS,              "Read Inputs" },
    { PCOMASCII_READ_OUTPUTS,             "Read Outputs" },
    { PCOMASCII_READ_SYSTEM_BITS,         "Read System Bits" },
    { PCOMASCII_READ_SYSTEM_INTEGERS,     "Read System Integers" },
    { PCOMASCII_READ_SYSTEM_LONGS,        "Read System Longs" },
    { PCOMASCII_READ_SYSTEM_DOUBLE_WORDS, "Read System Double Words" },
    { PCOMASCII_READ_MEMORY_BITS,         "Read Memory Bits" },
    { PCOMASCII_READ_MEMORY_INTEGERS,     "Read Memory Integers" },
    { PCOMASCII_READ_MEMORY_LONGS,        "Read Memory Longs" },
    { PCOMASCII_READ_MEMORY_DOUBLE_WORDS, "Read Memory Double Words" },
    { PCOMASCII_READ_LONGS,               "Read Longs / Double Words" },
    { PCOMASCII_WRITE_OUTPUTS,            "Write Outputs" },
    { PCOMASCII_WRITE_SYSTEM_BITS,        "Write System Bits" },
    { PCOMASCII_WRITE_SYSTEM_INTEGERS,    "Write System Integers" },
    { PCOMASCII_WRITE_SYSTEM_LONGS,       "Write System Longs" },
    { PCOMASCII_WRITE_SYSTEM_DOUBLE_WORDS,"Write System Double Words" },
    { PCOMASCII_WRITE_MEMORY_BITS,        "Write Memory Bits" },
    { PCOMASCII_WRITE_MEMORY_INTEGERS,    "Write Memory Integers" },
    { PCOMASCII_WRITE_MEMORY_LONGS,       "Write Memory Longs" },
    { PCOMASCII_WRITE_MEMORY_DOUBLE_WORDS,"Write Memory Double Words" },
    { PCOMASCII_WRITE_LONGS,              "Write Longs / Double Words" },
    { 0,                        NULL },
};

/* Translate pcombinary_command requests to string */
static const value_string pcombinary_command_vals_request[] = {
    { PCOMBINARY_GET_PLC_NAME_REQUEST,            "Get PLC Name Request" },
    { PCOMBINARY_READ_OPERANDS_REQUEST,           "Read Operands Request" },
    { PCOMBINARY_READ_DATA_TABLE_REQUEST,         "Read Data Table Request" },
    { PCOMBINARY_WRITE_DATA_TABLE_REQUEST,        "Write Data Table Request" },
    { 0,                        NULL },
};

/* Translate pcombinary_command reply to string */
static const value_string pcombinary_command_vals_reply[] = {
    { PCOMBINARY_GET_PLC_NAME_REPLY,            "Get PLC Name Reply" },
    { PCOMBINARY_READ_OPERANDS_REPLY,           "Read Operands Reply" },
    { PCOMBINARY_READ_DATA_TABLE_REPLY,         "Read Data Table Reply" },
    { PCOMBINARY_WRITE_DATA_TABLE_REPLY,        "Write Data Table Reply" },
    { 0,                        NULL },
};


/* Code to actually dissect the packets */
static int
dissect_pcomtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item  *ti;
    proto_tree  *pcomtcp_tree;

    tvbuff_t    *next_tvb;

    guint        offset = 0;
    const char   *pkt_type = "";
    guint8       pcom_mode;
    const char   *pcom_mode_str = "";

    proto_item    *hf_pcomtcp_reserved_item = NULL;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < PCOMTCP_MIN_LENGTH)
        return 0;

    pcom_mode = tvb_get_guint8(tvb, 2);
    if ( pcom_mode != PCOM_ASCII && pcom_mode != PCOM_BINARY )
        return 0;

    pcom_mode_str = val_to_str(pcom_mode, pcomp_protocol_vals, "Unknown mode (%d)");

    if (value_is_in_range(global_pcomtcp_tcp_ports, pinfo->srcport))
        pkt_type = "Reply";
    else
        pkt_type = "Query";

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCOM/TCP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s in %s",
            pkt_type, pcom_mode_str);


    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_pcomtcp, tvb, 0, -1, ENC_NA);
    pcomtcp_tree = proto_item_add_subtree(ti, ett_pcomtcp);

    proto_tree_add_item(pcomtcp_tree, hf_pcomtcp_transid, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(pcomtcp_tree, hf_pcomtcp_protocol, tvb,
            offset, 1, ENC_NA);
    offset += 1;
    hf_pcomtcp_reserved_item = proto_tree_add_item(pcomtcp_tree, hf_pcomtcp_reserved, tvb,
            offset, 1, ENC_NA);
    if(tvb_get_guint8(tvb, offset) !=0){
            expert_add_info_format(pinfo, hf_pcomtcp_reserved_item,
                    &ei_pcomtcp_reserved_bad_value,"Isn't 0");
    }
    offset += 1;
    proto_tree_add_item(pcomtcp_tree, hf_pcomtcp_length, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);

    /* dissect the PCOM Data */
    offset += 2;
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if( tvb_reported_length_remaining(tvb, offset) > 0 ){
        if ( pcom_mode == PCOM_ASCII)
            call_dissector_with_data(pcomascii_handle, next_tvb, pinfo, tree, &pcom_mode);
        else
            call_dissector_with_data(pcombinary_handle, next_tvb, pinfo, tree, &pcom_mode);
    }

    return tvb_reported_length(tvb);
}

static int
dissect_pcomascii(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item  *ti;
    proto_tree  *pcomascii_tree;
    proto_item    *hf_pcomascii_command_item = NULL;

    guint        offset = 0;
    guint16      nvalues;
    guint8       i;
    guint8       cc_len;
    guint32      cc;
    const gchar* cc_str;
    const gchar* cc_str2;
    guint8       op_type;
    guint8       op_size;

    /* Create protocol tree */
    ti = proto_tree_add_item(tree, proto_pcomascii, tvb, offset, -1, ENC_NA);
    pcomascii_tree = proto_item_add_subtree(ti, ett_pcomascii);

    if (value_is_in_range(global_pcomtcp_tcp_ports, pinfo->srcport)) { // Reply
        proto_tree_add_item(pcomascii_tree, hf_pcomascii_stx, tvb,
                offset, 2, ENC_ASCII); // "/A"
        offset += 2;
    }else{
        proto_tree_add_item(pcomascii_tree, hf_pcomascii_stx, tvb,
                offset, 1, ENC_ASCII); // "/"
        offset += 1;
    }

    proto_tree_add_item(pcomascii_tree, hf_pcomascii_unitid, tvb,
            offset, 2, ENC_ASCII|ENC_NA);
    offset += 2;

    // CCs can be 2 or 3 hex chars
    cc = tvb_get_ntoh24(tvb, offset);
    cc_str = try_val_to_str(cc, pcomascii_cc_vals);
    if ( cc_str != NULL && !value_is_in_range(global_pcomtcp_tcp_ports, pinfo->srcport)) {
        cc_len = 3;
    }else {
        cc = tvb_get_ntohs(tvb, offset);
        cc_str = try_val_to_str(cc, pcomascii_cc_vals);
        if (cc_str != NULL ){
            cc_len = 2;
        }else{
            cc_len = 0;
        }
    }
    if ( cc_len > 0 ){
        cc_str2 = tvb_get_string_enc(pinfo->pool, tvb, offset, cc_len, ENC_ASCII);
        proto_tree_add_string_format_value(pcomascii_tree,
                hf_pcomascii_command_code, tvb, offset, cc_len,
                cc_str2, "%s (%s)", cc_str, cc_str2);
        offset += cc_len;
        switch(cc)
        {
            case PCOMASCII_READ_INPUTS:
            case PCOMASCII_READ_OUTPUTS:
            case PCOMASCII_READ_SYSTEM_BITS:
            case PCOMASCII_READ_MEMORY_BITS:
               op_type = 1; // read operation
               op_size = 1; // 1 char per operand
               break;
            case PCOMASCII_READ_SYSTEM_INTEGERS:
            case PCOMASCII_READ_MEMORY_INTEGERS:
               op_type = 1; // read operation
               op_size = 4; // 4 chars per operand
               break;
            case PCOMASCII_READ_SYSTEM_LONGS:
            case PCOMASCII_READ_MEMORY_LONGS:
            case PCOMASCII_READ_SYSTEM_DOUBLE_WORDS:
            case PCOMASCII_READ_MEMORY_DOUBLE_WORDS:
            case PCOMASCII_READ_LONGS:
               op_type = 1; // read operation
               op_size = 8; // 8 chars per operand
               break;
            case PCOMASCII_WRITE_OUTPUTS:
            case PCOMASCII_WRITE_SYSTEM_BITS:
            case PCOMASCII_WRITE_MEMORY_BITS:
               op_type = 2; // write operation
               op_size = 1; // 1 char per operand
               break;
            case PCOMASCII_WRITE_SYSTEM_INTEGERS:
            case PCOMASCII_WRITE_MEMORY_INTEGERS:
               op_type = 2; // write operation
               op_size = 4; // 4 chars per operand
               break;
            case PCOMASCII_WRITE_MEMORY_LONGS:
            case PCOMASCII_WRITE_SYSTEM_LONGS:
            case PCOMASCII_WRITE_SYSTEM_DOUBLE_WORDS:
            case PCOMASCII_WRITE_MEMORY_DOUBLE_WORDS:
            case PCOMASCII_WRITE_LONGS:
               op_type = 2; // write operation
               op_size = 8; // 8 chars per operand
               break;
            default:
               op_type = 0;
               op_size = 0;
               break;
        }
        if (value_is_in_range(global_pcomtcp_tcp_ports, pinfo->destport)) { // Request
            if(op_type == 1 || op_type == 2) { // read & write op
                proto_tree_add_item(pcomascii_tree, hf_pcomascii_address,
                                tvb, offset, 4, ENC_ASCII);
                offset += 4;
                proto_tree_add_item(pcomascii_tree, hf_pcomascii_length,
                            tvb, offset, 2, ENC_ASCII);
                offset += 2;
            }
            if(op_type == 2) { // write only
                nvalues = (tvb_reported_length(tvb)-3-offset) / op_size;
                for (i = 0; i < nvalues; i++) {
                    proto_tree_add_item(pcomascii_tree, hf_pcomascii_address_value,
                             tvb, offset, op_size , ENC_ASCII);
                    offset += op_size;
                }
            }
        } else { // reply
             if(op_type == 1) { // read only
                nvalues = (tvb_reported_length(tvb)-offset-3) / op_size;
                for (i = 0; i < nvalues; i++) {
                    proto_tree_add_item(pcomascii_tree, hf_pcomascii_address_value,
                             tvb, offset, op_size , ENC_ASCII);
                    offset += op_size;
                }
            }
        }

    }

    if (tvb_reported_length(tvb)-offset-3 > 0){ // remaining (variable) bytes between CC and checksum
        hf_pcomascii_command_item = proto_tree_add_item(pcomascii_tree, hf_pcomascii_command, tvb,
                offset, tvb_reported_length(tvb)-offset-3, ENC_ASCII);
        offset += (tvb_reported_length(tvb)-offset-3); //-3 from checksum and etx
        if(cc_len <= 0){
            expert_add_info_format(pinfo, hf_pcomascii_command_item,
                    &ei_pcomascii_command_unsupported, "Unsupported Command");
        }
    }

    proto_tree_add_item(pcomascii_tree, hf_pcomascii_checksum, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(pcomascii_tree, hf_pcomascii_etx, tvb,
            offset, 1, ENC_ASCII);

    return tvb_reported_length(tvb);
}

static int
dissect_pcombinary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item  *ti;
    proto_tree  *pcombinary_tree;

    guint        offset = 0;
    proto_item    *hf_pcombinary_reserved1_item = NULL;
    proto_item    *hf_pcombinary_reserved2_item = NULL;
    proto_item    *hf_pcombinary_reserved3_item = NULL;
    proto_item    *hf_pcombinary_reserved4_item = NULL;
    proto_item    *hf_pcombinary_command_item = NULL;

    guint8 command;
    const gchar* command_str;

    /* Create protocol tree */
    ti = proto_tree_add_item(tree, proto_pcombinary, tvb, offset, -1, ENC_NA);
    pcombinary_tree = proto_item_add_subtree(ti, ett_pcombinary);

    proto_tree_add_item(pcombinary_tree, hf_pcombinary_stx, tvb,
            offset, 6, ENC_ASCII);

    offset += 6;
    if (value_is_in_range(global_pcomtcp_tcp_ports, pinfo->srcport)) { // these bytes are transposed
        hf_pcombinary_reserved1_item = proto_tree_add_item(pcombinary_tree,
                hf_pcombinary_reserved1, tvb, offset, 1, ENC_NA);
        if(tvb_get_guint8(tvb, offset) !=254){
            expert_add_info_format(pinfo, hf_pcombinary_reserved1_item,
                    &ei_pcombinary_reserved1_bad_value,"Isn't 0xfe");
        }
        offset += 1;
        proto_tree_add_item(pcombinary_tree, hf_pcombinary_id, tvb,
                offset, 1, ENC_NA);
        offset += 1;
    }else{
        proto_tree_add_item(pcombinary_tree, hf_pcombinary_id, tvb,
                offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(pcombinary_tree, hf_pcombinary_reserved1, tvb,
                offset, 1, ENC_NA);
        offset += 1;
    }
    hf_pcombinary_reserved2_item = proto_tree_add_item(pcombinary_tree,
            hf_pcombinary_reserved2, tvb, offset, 1, ENC_NA);
    if( tvb_get_guint8(tvb, offset) !=1)
        expert_add_info_format(pinfo, hf_pcombinary_reserved2_item,
                &ei_pcombinary_reserved2_bad_value,"Isn't 1");
    offset += 1;
    hf_pcombinary_reserved3_item = proto_tree_add_item(pcombinary_tree,
            hf_pcombinary_reserved3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    if( tvb_get_letoh24(tvb,offset) != 0)
        expert_add_info_format(pinfo, hf_pcombinary_reserved3_item,
                &ei_pcombinary_reserved3_bad_value,"Isn't 0");
    offset += 3;

    command = tvb_get_guint8(tvb, offset);
    if (value_is_in_range(global_pcomtcp_tcp_ports, pinfo->srcport)) { // reply
        command_str = try_val_to_str(command, pcombinary_command_vals_reply);
    }else{
        command_str = try_val_to_str(command, pcombinary_command_vals_request);
    }
    if ( command_str != NULL ) {
        proto_tree_add_uint_format_value(pcombinary_tree,
            hf_pcombinary_command, tvb, offset, 1,
                command, "%s (%02x)", command_str, command);
    }else{
        hf_pcombinary_command_item = proto_tree_add_item(pcombinary_tree, hf_pcombinary_command, tvb,
                offset, 1, ENC_NA);
        expert_add_info_format(pinfo, hf_pcombinary_command_item,
                &ei_pcombinary_command_unsupported,"Unsupported Command");}
    offset += 1;

    hf_pcombinary_reserved4_item = proto_tree_add_item(pcombinary_tree,
            hf_pcombinary_reserved4, tvb, offset, 1, ENC_NA);
    if( tvb_get_guint8(tvb, offset) !=0)
        expert_add_info_format(pinfo, hf_pcombinary_reserved4_item,
                &ei_pcombinary_reserved4_bad_value,"Isn't 0");
    offset += 1;
    proto_tree_add_item(pcombinary_tree, hf_pcombinary_command_specific, tvb,
            offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(pcombinary_tree, hf_pcombinary_data_length, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(pcombinary_tree, hf_pcombinary_header_checksum, tvb,
            offset, 2, ENC_NA);
    offset += 2;
    if ((tvb_reported_length(tvb) - 27) > 0) // ( -3 footer - 24 header)
        proto_tree_add_item(pcombinary_tree, hf_pcombinary_data, tvb,
                offset, tvb_reported_length(tvb)-27, ENC_NA);
    offset += (tvb_reported_length(tvb)-27);
    proto_tree_add_item(pcombinary_tree, hf_pcombinary_footer_checksum, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(pcombinary_tree, hf_pcombinary_etx, tvb,
            offset, 1, ENC_ASCII);

    return tvb_reported_length(tvb);
}

static void
apply_pcomtcp_prefs(void)
{
    global_pcomtcp_tcp_ports = prefs_get_range_value("pcomtcp", "tcp.port");
}

void
proto_register_pcomtcp(void)
{
    static hf_register_info hf_pcomtcp[] = {
        { &hf_pcomtcp_transid,
            { "Transaction Identifier", "pcomtcp.trans_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomtcp_protocol,
            { "Protocol Mode", "pcomtcp.protocol",
                FT_UINT8, BASE_DEC, VALS(pcomp_protocol_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_pcomtcp_reserved,
            { "Reserved", "pcomtcp.reserved",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomtcp_length,
            { "Length (bytes)", "pcomtcp.length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
    };


    static hf_register_info hf_pcomascii[] = {
        { &hf_pcomascii_stx,
            { "STX", "pcomascii.stx",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_unitid,
            { "Unit Identifier", "pcomascii.unitid",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_command_code,
            { "Command Code", "pcomascii.command_code",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_address,
            { "Address", "pcomascii.address",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_length,
            { "Length", "pcomascii.length",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_address_value,
            { "Address Value", "pcomascii.address_value",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_command,
            { "Command", "pcomascii.command",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_checksum,
            { "Checksum", "pcomascii.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcomascii_etx,
            { "ETX", "pcomascii.etx",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
    };


    static hf_register_info hf_pcombinary[] = {
        { &hf_pcombinary_stx,
            { "STX", "pcombinary.stx",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_id,
            { "ID (CANBUS or RS485)", "pcombinary.id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_reserved1,
            { "Reserved", "pcombinary.reserved1",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_reserved2,
            { "Reserved", "pcombinary.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_reserved3,
            { "Reserved", "pcombinary.reserved3",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_command,
            { "Command", "pcombinary.command",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_reserved4,
            { "Reserved", "pcombinary.reserved0",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_command_specific,
            { "Command Details", "pcombinary.command_specific",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_data_length,
            { "Data Length", "pcombinary.data_length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_header_checksum,
            { "(Header) Checksum", "pcombinary.header_checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_data,
            { "Data", "pcombinary.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_footer_checksum,
            { "(Footer) Checksum", "pcombinary.footer_checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_pcombinary_etx,
            { "ETX", "pcombinary.etx",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_pcomtcp,
        &ett_pcomascii,
        &ett_pcombinary
    };

    static ei_register_info pcomtcp_ei[] = {
        { &ei_pcomtcp_reserved_bad_value,
          { "pcombinary.reserved.bad_value", PI_PROTOCOL, PI_WARN,
            "Isn't 0", EXPFILL }
        },
    };

    static ei_register_info pcombinary_ei[] = {
        { &ei_pcombinary_reserved1_bad_value,
          { "pcombinary.reserved1.bad_value", PI_PROTOCOL, PI_WARN,
            "Isn't  0xfe", EXPFILL }
        },
        { &ei_pcombinary_reserved2_bad_value,
          { "pcombinary.reserved2.bad_value", PI_PROTOCOL, PI_WARN,
            "Isn't  1", EXPFILL }
        },
        { &ei_pcombinary_reserved3_bad_value,
          { "pcombinary.reserved3.bad_value", PI_PROTOCOL, PI_WARN,
            "Isn't  0", EXPFILL }
        },
        { &ei_pcombinary_reserved4_bad_value,
          { "pcombinary.reserved4.bad_value", PI_PROTOCOL, PI_WARN,
            "Isn't  0", EXPFILL }
        },
        { &ei_pcombinary_command_unsupported,
          { "pcombinary.command.unsupported", PI_PROTOCOL, PI_WARN,
            "Unsupported Command", EXPFILL }
        },
    };
    static ei_register_info pcomascii_ei[] = {
        { &ei_pcomascii_command_unsupported,
          { "pcomascii.command.unsupported", PI_PROTOCOL, PI_WARN,
            "Unsupported Command", EXPFILL }
        },
    };

    expert_module_t* expert_pcomtcp;
    expert_module_t* expert_pcomascii;
    expert_module_t* expert_pcombinary;

    /* Register the protocol name and description */
    proto_pcomtcp = proto_register_protocol("PCOM/TCP","PCOM/TCP", "pcomtcp");
    proto_pcomascii = proto_register_protocol("PCOM ASCII","PCOM ASCII", "pcomascii");
    proto_pcombinary = proto_register_protocol("PCOM BINARY","PCOM BINARY", "pcombinary");

    pcomtcp_handle = register_dissector("pcomtcp", dissect_pcomtcp, proto_pcomtcp);
    pcomascii_handle = register_dissector("pcomascii", dissect_pcomascii, proto_pcomascii);
    pcombinary_handle = register_dissector("pcombinary", dissect_pcombinary, proto_pcombinary);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_pcomtcp, hf_pcomtcp, array_length(hf_pcomtcp));
    proto_register_field_array(proto_pcomascii, hf_pcomascii, array_length(hf_pcomascii));
    proto_register_field_array(proto_pcombinary, hf_pcombinary, array_length(hf_pcombinary));

    proto_register_subtree_array(ett, array_length(ett));
    expert_pcomtcp = expert_register_protocol(proto_pcomtcp);
    expert_pcomascii = expert_register_protocol(proto_pcomascii);
    expert_pcombinary = expert_register_protocol(proto_pcombinary);

    expert_register_field_array(expert_pcomtcp, pcomtcp_ei, array_length(pcomtcp_ei));
    expert_register_field_array(expert_pcomascii, pcomascii_ei, array_length(pcomascii_ei));
    expert_register_field_array(expert_pcombinary, pcombinary_ei, array_length(pcombinary_ei));

    prefs_register_protocol(proto_pcomtcp, apply_pcomtcp_prefs);

}

void
proto_reg_handoff_pcomtcp(void)
{
    dissector_add_uint_with_preference("tcp.port", PCOMTCP_TCP_PORT, pcomtcp_handle);
    apply_pcomtcp_prefs();
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
