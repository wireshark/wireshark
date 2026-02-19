/* packet-5co-legacy.c
 * Routines for FiveCo's Legacy Register Access Protocol dissector
 * Copyright 2021, Antoine Gardiol <antoine.gardiol@fiveco.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This protocol allows access to FiveCo's Ethernet products registers with old legacy
 * protocol. Product list can be found under https://www.fiveco.ch/bus-converter-products.html.
 * Protocol description can be found (by example) in FMod-TCP xx manual that can be dowloaded from
 * https://www.fiveco.ch/product-fmod-tcp-db.html.
 * Note that this protocol is a question-answer protocol. It's header is composed of:
 * - 16 bits type
 * - 16 bits frame id
 * - 16 bits length of parameters (n)
 * - n bytes of parameters (depends upon packet type)
 * - 16 bits IP like checksum
 *
 * This build-in dissector is replacing a plugin dissector available from Wireshark 1.8.
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/in_cksum.h>
#include <wsutil/array.h>
#include "packet-tcp.h"
#include "packet-udp.h"

/* Prototypes */
void proto_reg_handoff_FiveCoLegacy(void);
void proto_register_FiveCoLegacy(void);

static dissector_handle_t FiveCoLegacy_tcp_handle;
static dissector_handle_t FiveCoLegacy_udp_handle;

/****************************************************************************/
/* Definition declaration */
/****************************************************************************/

// Protocol header length and frame minimum length
#define FIVECO_LEGACY_HEADER_LENGTH 6
#define FIVECO_LEGACY_MIN_LENGTH FIVECO_LEGACY_HEADER_LENGTH + 2 // Checksum is 16 bits

/* Global sample ports preferences */
#define FIVECO_TCP_PORTS "8010,8004"    /* TCP ports of the FiveCo protocol + web page upload */
#define FIVECO_UDP_PORTS "7010"         /* UDP port of the FiveCo protocol */

/* 16 bits type known available functions */
enum fiveco_functions
{
    I2C_READ = 0x0001,
    I2C_WRITE,
    I2C_READ_ANSWER,
    I2C_WRITE_ANSWER,
    I2C_SCAN,
    I2C_SCAN_ANSWER,
    I2C_READ_WRITE_ACK,
    I2C_READ_WRITE_ACK_ANSWER,
    I2C_READ_WRITE_ACK_ERROR,
    READ_REGISTER = 0x0021,
    WRITE_REGISTER,
    READ_REGISTER_ANSWER,
    WRITE_REGISTER_ANSWER,
    WRITE_REGISTER_QUIET,
    EASY_IP_ADDRESS_CONFIG = 0x002A,
    EASY_IP_ADDRESS_CONFIG_ANSWER,
    FLASH_AREA_ERASE = 0x0031,
    FLASH_AREA_LOAD,
    FLASH_AREA_ANSWER
};

/* Initialize the protocol and registered fields */
static int proto_FiveCoLegacy; /* Wireshark ID of the FiveCo protocol */

/* static dissector_handle_t data_handle = NULL; */
static int hf_fiveco_header;       /* The following hf_* variables are used to hold the Wireshark IDs of */
static int hf_fiveco_fct;          /* our header fields; they are filled out when we call */
static int hf_fiveco_id;           /* proto_register_field_array() in proto_register_fiveco() */
static int hf_fiveco_length;
static int hf_fiveco_data;
static int hf_fiveco_cks;
static int hf_fiveco_cks_status;
static int hf_fiveco_i2cadd;
static int hf_fiveco_i2c2write;
static int hf_fiveco_i2cwrite;
static int hf_fiveco_i2c2read;
static int hf_fiveco_i2c2scan;
static int hf_fiveco_i2canswer;
static int hf_fiveco_i2cwriteanswer;
static int hf_fiveco_i2cscaned;
static int hf_fiveco_i2cerror;
static int hf_fiveco_i2cack;
static int hf_fiveco_regread;
static int hf_fiveco_regwrite;
static int hf_fiveco_regreaduk;
static int hf_fiveco_regwriteuk;
static int hf_fiveco_EasyIPMAC;
static int hf_fiveco_EasyIPIP;
static int hf_fiveco_EasyIPSM;
static int hf_fiveco_flash_offset;
static int hf_fiveco_flash_size;
static int hf_fiveco_flash_answer;


static int ett_fiveco_header; /* These are the ids of the subtrees that we may be creating */
static int ett_fiveco_data;   /* for the header fields. */
static int ett_fiveco;
static int ett_fiveco_checksum;

static expert_field ei_fiveco_regread;
static expert_field ei_fiveco_interpretation;
static expert_field ei_fiveco_cks;
static expert_field ei_fiveco_answer_already_found;
static expert_field ei_fiveco_no_data_expected;

/* Constants declaration */
static const value_string packettypenames[] = {
    {I2C_READ, "I2C Read (deprecated)"},
    {I2C_READ_ANSWER, "I2C Read Answer (deprecated)"},
    {I2C_WRITE, "I2C Write (deprecated)"},
    {I2C_WRITE_ANSWER, "I2C Write Answer (deprecated)"},
    {I2C_SCAN, "I2C Scan"},
    {I2C_SCAN_ANSWER, "I2C Scan Answer"},
    {I2C_READ_WRITE_ACK, "I2C Read and write with ack"},
    {I2C_READ_WRITE_ACK_ANSWER, "I2C Read and write with ack Answer"},
    {I2C_READ_WRITE_ACK_ERROR, "I2C Read and write error"},
    {READ_REGISTER, "Read register"},
    {READ_REGISTER_ANSWER, "Read register Answer"},
    {WRITE_REGISTER, "Write register"},
    {WRITE_REGISTER_ANSWER, "Write register Answer"},
    {WRITE_REGISTER_QUIET, "Write register (no answer wanted)"},
    {EASY_IP_ADDRESS_CONFIG, "Easy IP address config"},
    {EASY_IP_ADDRESS_CONFIG_ANSWER, "Easy IP address config Acknowledge"},
    {FLASH_AREA_ERASE, "Flash area Erase"},
    {FLASH_AREA_LOAD, "Flash area Upload"},
    {FLASH_AREA_ANSWER, "Flash area Answer"},
    {0, NULL}
};

/* Conversation request key structure */
typedef struct
{
    uint32_t conversation;
    uint64_t unInternalID;
    uint16_t usExpCmd;
} FCOSConvRequestKey;

/* Conversation request value structure */
typedef struct
{
    uint16_t usParaLen;
    uint16_t isReplied;
    uint8_t *pDataBuffer;
} FCOSConvRequestVal;

/* Conversation hash tables */
static wmem_map_t *FiveCo_requests_hash;

/* Internal unique ID (used to match answer with question
   since some software set always 0 as packet ID in protocol header)
*/
static uint64_t g_unInternalID;


static int hf_fiveco_reg_type_model;
static int hf_fiveco_reg_version;
static int hf_fiveco_reg_reset;
static int hf_fiveco_reg_save;
static int hf_fiveco_reg_restore;
static int hf_fiveco_reg_restore_factory;
static int hf_fiveco_save_factory;
static int hf_fiveco_reg_comm_option;
static int hf_fiveco_reg_mac_address;
static int hf_fiveco_reg_ip_address;
static int hf_fiveco_reg_ip_subnet_mask;
static int hf_fiveco_reg_tcp_timeout;
static int hf_fiveco_reg_name;

static const value_string register_name_vals[] = {
    {0x00, "Register Type/Model"},
    {0x01, "Register Version"},
    {0x02, "Function Reset device"},
    {0x03, "Function Save user parameters"},
    {0x04, "Function Restore user parameters"},
    {0x05, "Function Restore factory parameters"},
    {0x06, "Function Save factory parameters"},
    {0x07, "Register unknown"},
    {0x08, "Register unknown"},
    {0x09, "Register unknown"},
    {0x0A, "Register unknown"},
    {0x0B, "Register unknown"},
    {0x0C, "Register unknown"},
    {0x0D, "Register unknown"},
    {0x0E, "Register unknown"},
    {0x0F, "Register unknown"},
    {0x10, "Register Communication options"},
    {0x11, "Register Ethernet MAC Address"},
    {0x12, "Register IP Address"},
    {0x13, "Register IP Mask"},
    {0x14, "Register TCP Timeout"},
    {0x15, "Register Module name"},
    { 0, NULL }
};

/* Dissect the dynamic register data */
static int
dissect_FiveCoLegacy_registers(uint32_t reg_num, proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb, int offset, int data_length, int unknownhf)
{
    switch (reg_num)
    {
    case 0x00:
        proto_tree_add_item(tree, hf_fiveco_reg_type_model, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case 0x01:
        proto_tree_add_item(tree, hf_fiveco_reg_version, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case 0x02:
        proto_tree_add_item(tree, hf_fiveco_reg_reset, tvb, offset, 0, ENC_NA);
        break;

    case 0x03:
        proto_tree_add_item(tree, hf_fiveco_reg_save, tvb, offset, 0, ENC_NA);
        break;

    case 0x04:
        proto_tree_add_item(tree, hf_fiveco_reg_restore, tvb, offset, 0, ENC_NA);
        break;

    case 0x05:
        proto_tree_add_item(tree, hf_fiveco_reg_restore_factory, tvb, offset, 0, ENC_NA);
        break;

    case 0x06:
        proto_tree_add_item(tree, hf_fiveco_save_factory, tvb, offset, 0, ENC_NA);
        break;

    case 0x10:
        proto_tree_add_item(tree, hf_fiveco_reg_comm_option, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case 0x11:
        proto_tree_add_item(tree, hf_fiveco_reg_mac_address, tvb, offset, 6, ENC_NA);
        offset += 6;
        break;

    case 0x12:
        proto_tree_add_item(tree, hf_fiveco_reg_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case 0x13:
        proto_tree_add_item(tree, hf_fiveco_reg_ip_subnet_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case 0x14:
        proto_tree_add_item(tree, hf_fiveco_reg_tcp_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case 0x15:
        proto_tree_add_item(tree, hf_fiveco_reg_name, tvb, offset, 16, ENC_ASCII);
        offset += 16;
        break;
    default:
    {
        // Else tell user that data cannot be interpreted
        proto_item* ti = proto_tree_add_item(tree, unknownhf, tvb, offset, data_length, ENC_NA);
        expert_add_info(pinfo, ti, &ei_fiveco_interpretation);
        offset += data_length;
        break;
    }
    }

    return offset;
}

/*****************************************************************************/
/* Code to actually dissect the packets                                      */
/* Callback function for reassembled packet                                  */
/*****************************************************************************/
static int
dissect_FiveCoLegacy_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint16_t header_type = 0;
    uint16_t header_id = 0;
    uint16_t header_data_length = 0;
    uint8_t data_i2c_length = 0;
    proto_item *fiveco_item = NULL;
    proto_item *fiveco_header_item = NULL;
    proto_item *fiveco_data_item = NULL;
    proto_tree *fiveco_tree = NULL;
    proto_tree *fiveco_header_tree = NULL;
    proto_tree *fiveco_data_tree = NULL;
    conversation_t *conversation;
    bool isRequest = false;
    uint64_t *pulInternalID = NULL;
    FCOSConvRequestKey requestKey, *pNewRequestKey;
    FCOSConvRequestVal *pRequestVal = NULL;
    tvbuff_t *request_tvb = NULL;
    uint32_t ucAdd, ucBytesToWrite, ucBytesToRead, ucRegAdd;
    int offset = 0, request_offset = 0;
    const char* str_packet_type;

    /* Display fiveco in protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "5co-legacy");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Look for all future TCP conversations between the
    * requestiong server and the FiveCo device using the
    * same src & dest addr and ports.
    */
    conversation = find_or_create_conversation(pinfo);
    requestKey.conversation = conversation->conv_index;

    /* Check that header type is correct */
    header_type = tvb_get_ntohs(tvb, 0);
    if (try_val_to_str(header_type, packettypenames) == NULL)
        return 0;

    /* Read packet ID */
    header_id = tvb_get_ntohs(tvb, 2);
    header_data_length = tvb_get_ntohs(tvb, 4);

    /* Get/Set internal ID for this packet number */
    pulInternalID = (uint64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_FiveCoLegacy, pinfo->num);
    /* If internal ID is not set (null), create it */
    if (!pulInternalID)
    {
        /* If it is a new request, increment internal ID */
        switch(header_type)
        {
        case I2C_READ:
        case I2C_WRITE:
        case I2C_SCAN:
        case I2C_READ_WRITE_ACK:
        case READ_REGISTER:
        case WRITE_REGISTER:
            isRequest = true;
            g_unInternalID++;   // Increment unique request ID and record it in the new request
            /* Note: Since some software do not increment packet id located in frame header
            we use an internal ID to match answers to request. */
            break;
        }
        pulInternalID = wmem_new(wmem_file_scope(), uint64_t);
        *pulInternalID = g_unInternalID;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_FiveCoLegacy, pinfo->num, pulInternalID);
    }

    /* Get info about the request */
    requestKey.usExpCmd = header_type;
    requestKey.unInternalID = *pulInternalID;
    pRequestVal = (FCOSConvRequestVal *)wmem_map_lookup(FiveCo_requests_hash, &requestKey);
    if ((!pinfo->fd->visited) && (!pRequestVal) && (isRequest))
    {
        /* If unknown and if it is a request, allocate new hash element that we want to handle later in answer */
        pNewRequestKey = wmem_new(wmem_file_scope(), FCOSConvRequestKey);
        *pNewRequestKey = requestKey;
        pNewRequestKey->unInternalID = g_unInternalID;
        switch (header_type)
        {
        case I2C_READ:
            pNewRequestKey->usExpCmd = I2C_READ_ANSWER;
            break;
        case I2C_WRITE:
            pNewRequestKey->usExpCmd = I2C_WRITE_ANSWER;
            break;
        case I2C_SCAN:
            pNewRequestKey->usExpCmd = I2C_SCAN_ANSWER;
            break;
        case I2C_READ_WRITE_ACK:
            pNewRequestKey->usExpCmd = I2C_READ_WRITE_ACK_ANSWER;
            break;
        case READ_REGISTER:
            pNewRequestKey->usExpCmd = READ_REGISTER_ANSWER;
            break;
        }

        pRequestVal = wmem_new(wmem_file_scope(), FCOSConvRequestVal);
        pRequestVal->usParaLen = header_data_length;
        pRequestVal->isReplied = false;
        pRequestVal->pDataBuffer = (uint8_t *)wmem_alloc(wmem_file_scope(), header_data_length);
        tvb_memcpy(tvb, pRequestVal->pDataBuffer, 6, header_data_length);

        wmem_map_insert(FiveCo_requests_hash, pNewRequestKey, pRequestVal);
    }

    if (pRequestVal) {
        request_tvb = tvb_new_child_real_data(tvb, pRequestVal->pDataBuffer, pRequestVal->usParaLen, pRequestVal->usParaLen);
    }

    str_packet_type = val_to_str(pinfo->pool, header_type, packettypenames, "Unknown Type:0x%02x");

    /* Add text to info column */
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s ID=%d Len=%d", str_packet_type, header_id, header_data_length);
    col_set_fence(pinfo->cinfo, COL_INFO);

    /* Add FiveCo protocol in tree (after TCP or UDP entry) */
    fiveco_item = proto_tree_add_item(tree, proto_FiveCoLegacy, tvb, 0, -1, ENC_NA);
    fiveco_tree = proto_item_add_subtree(fiveco_item, ett_fiveco);

    proto_item_append_text(fiveco_item, " (%s)", str_packet_type);

    /* Add fiveco Protocol tree and sub trees for Header, Data and Checksum */
    fiveco_header_item = proto_tree_add_item(fiveco_tree, hf_fiveco_header, tvb, 0, 6, ENC_NA); // Header tree
    fiveco_header_tree = proto_item_add_subtree(fiveco_header_item, ett_fiveco_header);
    proto_tree_add_item(fiveco_header_tree, hf_fiveco_fct, tvb, 0, 2, ENC_BIG_ENDIAN); // Packet type (function) in Header
    proto_tree_add_item(fiveco_header_tree, hf_fiveco_id, tvb, 2, 2, ENC_BIG_ENDIAN); // Packet ID in Header
    proto_tree_add_item(fiveco_header_tree, hf_fiveco_length, tvb, 4, 2, ENC_BIG_ENDIAN); // Length of para in Header

    offset = 6; // put offset on start of data (parameters)

    // If there are parameters (data) in packet, display them in data sub tree
    if (header_data_length > 0)
    {
        fiveco_data_item = proto_tree_add_item(fiveco_tree, hf_fiveco_data, tvb, offset, header_data_length, ENC_NA);
        fiveco_data_tree = proto_item_add_subtree(fiveco_data_item, ett_fiveco_data);
        switch (header_type)
        {
        case I2C_READ:
        case I2C_READ_WRITE_ACK:
            while (offset < header_data_length + FIVECO_LEGACY_HEADER_LENGTH)
            {
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cadd, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                data_i2c_length = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2write, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cwrite, tvb, offset, data_i2c_length, ENC_NA);
                offset += data_i2c_length;
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2read, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
        case I2C_WRITE:
            while (offset < header_data_length + FIVECO_LEGACY_HEADER_LENGTH)
            {
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cadd, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                data_i2c_length = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2write, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cwrite, tvb, offset, data_i2c_length, ENC_NA);
                offset += data_i2c_length;
            }
            break;
        case I2C_SCAN:
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2scan, tvb, offset, header_data_length, ENC_NA);
            break;
        case I2C_SCAN_ANSWER:
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cscaned, tvb, offset, header_data_length, ENC_NA);
            break;
        case I2C_READ_WRITE_ACK_ERROR:
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cerror, tvb, offset, 1, ENC_NA);
            break;
        case READ_REGISTER:
            // List registers asked for read
            for (; offset < header_data_length + FIVECO_LEGACY_HEADER_LENGTH; offset++)
            {
                fiveco_data_item = proto_tree_add_item_ret_uint(fiveco_data_tree, hf_fiveco_regread,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &ucRegAdd);
                if (try_val_to_str(ucRegAdd, register_name_vals) == NULL)
                    expert_add_info(pinfo, fiveco_data_item, &ei_fiveco_regread);
            }
            break;
        case WRITE_REGISTER:
        case WRITE_REGISTER_QUIET:
            // For each request stored in the last read request of the conversation
            while (offset < header_data_length + FIVECO_LEGACY_HEADER_LENGTH)
            {
                // Register address in first byte of request
                proto_tree_add_item_ret_uint(fiveco_data_tree, hf_fiveco_regwrite, tvb, offset++, 1, ENC_NA, &ucRegAdd);
                offset = dissect_FiveCoLegacy_registers(ucRegAdd, fiveco_data_tree, pinfo, tvb, offset, header_data_length + FIVECO_LEGACY_HEADER_LENGTH - offset, hf_fiveco_regwriteuk);
            }
            break;
        case EASY_IP_ADDRESS_CONFIG:
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_EasyIPMAC, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_EasyIPIP, tvb, offset + 6, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_EasyIPSM, tvb, offset + 10, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case I2C_READ_ANSWER:
        case I2C_WRITE_ANSWER:
        case I2C_READ_WRITE_ACK_ANSWER:
            if (pRequestVal == NULL)
            {
                expert_add_info(pinfo, fiveco_data_item, &ei_fiveco_interpretation);
                break;
            }

            if (pRequestVal->isReplied != 0)
            {
                expert_add_info(pinfo, fiveco_data_item, &ei_fiveco_answer_already_found);
                break;
            }

            while ((request_offset < pRequestVal->usParaLen) && (offset < header_data_length + FIVECO_LEGACY_HEADER_LENGTH))
            {
                // I2C address in first byte of request
                proto_tree_add_item_ret_uint(fiveco_data_tree, hf_fiveco_i2cadd, request_tvb, request_offset++, 1, ENC_NA, &ucAdd);
                // Read number of bytes to write
                proto_tree_add_item_ret_uint(fiveco_data_tree, hf_fiveco_i2c2write, request_tvb, request_offset, 1, ENC_NA, &ucBytesToWrite);
                // Skip number of bytes to write and those bytes
                request_offset += 1 + ucBytesToWrite;
                // Read number of bytes to read
                proto_tree_add_item_ret_uint(fiveco_data_tree, hf_fiveco_i2c2read, request_tvb, request_offset++, 1, ENC_NA, &ucBytesToRead);

                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2canswer, tvb, offset, ucBytesToRead, ENC_NA);
                offset += ucBytesToRead;

                if (header_type == I2C_READ_WRITE_ACK_ANSWER)
                    proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cack, tvb, offset++, 1, ENC_BIG_ENDIAN);
            }
            break;
        case READ_REGISTER_ANSWER:
            if (pRequestVal == NULL)
                break;

            if (pRequestVal->isReplied != 0)
            {
                expert_add_info(pinfo, fiveco_data_item, &ei_fiveco_answer_already_found);
                break;
            }

            // For each request stored in the last read request of the conversation
            while (offset < header_data_length + FIVECO_LEGACY_HEADER_LENGTH)
            {
                // Register address in first byte of request
                proto_tree_add_item_ret_uint(fiveco_data_tree, hf_fiveco_regread, tvb, offset++, 1, ENC_NA, &ucRegAdd);
                offset = dissect_FiveCoLegacy_registers(ucRegAdd, fiveco_data_tree, pinfo, tvb, offset, header_data_length + FIVECO_LEGACY_HEADER_LENGTH - offset, hf_fiveco_regreaduk);
            }
            break;
        case FLASH_AREA_LOAD:
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_flash_offset, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            proto_tree_add_item(fiveco_data_tree, hf_fiveco_flash_size, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            break;
        case FLASH_AREA_ANSWER:
            if ( header_data_length > 1 ) {
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_flash_answer, tvb, offset, header_data_length - 1, ENC_ASCII);
                offset += (header_data_length - 1);
            }
            break;

        case WRITE_REGISTER_ANSWER:
        case FLASH_AREA_ERASE:
        case EASY_IP_ADDRESS_CONFIG_ANSWER:
            expert_add_info(pinfo, fiveco_data_item, &ei_fiveco_no_data_expected);
            break;

        default:
            expert_add_info(pinfo, fiveco_data_item, &ei_fiveco_interpretation);
            break;
        }
    }

    // Checksum validation and sub tree
    proto_tree_add_checksum(fiveco_tree, tvb, offset, hf_fiveco_cks, hf_fiveco_cks_status, &ei_fiveco_cks, pinfo,
        ip_checksum_tvb(tvb, 0, header_data_length + 6), ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);

    return tvb_captured_length(tvb);
}

/*****************************************************************************/
/* Compute an unique hash value                                              */
/*****************************************************************************/
static unsigned fiveco_hash(const void *v)
{
    const FCOSConvRequestKey *key = (const FCOSConvRequestKey *)v;
    unsigned val;

    val = key->conversation + (((key->usExpCmd) & 0xFFFF) << 16) +
            (key->unInternalID & 0xFFFFFFFF) + ((key->unInternalID >>32) & 0xFFFFFFFF);

    return val;
}

/*****************************************************************************/
/* Check hash equal                                                          */
/*****************************************************************************/
static int fiveco_hash_equal(const void *v, const void *w)
{
    const FCOSConvRequestKey *v1 = (const FCOSConvRequestKey *)v;
    const FCOSConvRequestKey *v2 = (const FCOSConvRequestKey *)w;

    if (v1->conversation == v2->conversation &&
        v1->usExpCmd == v2->usExpCmd &&
        v1->unInternalID == v2->unInternalID)
    {
        return 1;
    }
    return 0;
}

static bool
check_FiveCoLegacy_header(tvbuff_t* tvb)
{
    /* Check that header type is correct */
    uint16_t header_type = tvb_get_ntohs(tvb, 0);
    return (try_val_to_str(header_type, packettypenames) != NULL);
}

static unsigned
dissect_FiveCoLegacy_pdu_len(packet_info* pinfo _U_, tvbuff_t* tvb,
    int offset, void* data _U_)
{
    return tvb_get_ntohs(tvb, offset+4) + FIVECO_LEGACY_MIN_LENGTH;
}

static int
dissect_FiveCoLegacy_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    if (!check_FiveCoLegacy_header(tvb))
        return 0;

    tcp_dissect_pdus(tvb, pinfo, tree, true, FIVECO_LEGACY_MIN_LENGTH,
        dissect_FiveCoLegacy_pdu_len, dissect_FiveCoLegacy_pdu, data);
    return tvb_captured_length(tvb);
}

static bool
FiveCoLegacy_udp_check_header(packet_info* pinfo _U_, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    return check_FiveCoLegacy_header(tvb);
}

static int
dissect_FiveCoLegacy_udp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    udp_dissect_pdus(tvb, pinfo, tree, FIVECO_LEGACY_MIN_LENGTH, FiveCoLegacy_udp_check_header,
        dissect_FiveCoLegacy_pdu_len, dissect_FiveCoLegacy_pdu, data);
    return tvb_captured_length(tvb);
}

/*****************************************************************************/
/* Registers decoding functions                                              */
/*****************************************************************************/
static void
dispType(char* result, uint32_t type)
{
    int nValueH = (type >> 16) & 0xFFFF;
    int nValueL = (type & 0xFFFF);
    snprintf(result, ITEM_LABEL_LENGTH, "%d.%d (%.4X.%.4X)", nValueH, nValueL, nValueH, nValueL);
}

static void
dispVersion(char* result, uint32_t version)
{
    if ((version & 0xFF000000) == 0)
    {
        int nValueH = (version >> 16) & 0xFFFF;
        int nValueL = (version & 0xFFFF);
        snprintf(result, ITEM_LABEL_LENGTH, "FW: %d.%d", nValueH, nValueL);
    }
    else
    {
        int nHWHigh = (version >> 24) & 0xFF;
        int nHWLow = (version >> 16) & 0xFF;
        int nFWHigh = (version >> 8) & 0xFF;
        int nFWLow = (version >> 8) & 0xFF;
        snprintf(result, ITEM_LABEL_LENGTH, "HW: %d.%d / FW: %d.%d", nHWHigh, nHWLow, nFWHigh, nFWLow);
    }
}

static void dispTimeout(char* result, uint32_t timeout)
{
    if (timeout != 0)
        snprintf(result, ITEM_LABEL_LENGTH, "%d seconds", timeout);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "Disabled");
}

/*****************************************************************************/
/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
/*****************************************************************************/
void proto_register_FiveCoLegacy(void)
{
    static hf_register_info hf[] = {
        /* List of static header fields */
        {&hf_fiveco_header, {"Header", "5co_legacy.header",
            FT_NONE, BASE_NONE, NULL, 0x0, "Header of the packet", HFILL}},
        {&hf_fiveco_fct, {"Function", "5co_legacy.fct",
            FT_UINT16, BASE_HEX, VALS(packettypenames), 0x0, "Function type", HFILL}},
        {&hf_fiveco_id, {"Frame ID", "5co_legacy.id",
            FT_UINT16, BASE_DEC, NULL, 0x0, "Packet ID", HFILL}},
        {&hf_fiveco_length, {"Data length", "5co_legacy.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, "Parameters length of the packet", HFILL}},
        {&hf_fiveco_data, {"Data", "5co_legacy.data",
            FT_NONE, BASE_NONE, NULL, 0x0, "Data (parameters)", HFILL}},
        {&hf_fiveco_cks, {"Checksum", "5co_legacy.checksum",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_cks_status, {"Checksum Status", "5co_legacy.checksum.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL}},
        {&hf_fiveco_i2cadd, {"I2C Address", "5co_legacy.i2cadd",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2c2write, {"I2C number of bytes to write", "5co_legacy.i2c2write",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2cwrite, {"I2C bytes to write", "5co_legacy.i2cwrite",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2c2read, {"I2C number of bytes to read", "5co_legacy.i2c2read",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2canswer, {"I2C bytes read", "5co_legacy.i2cread",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2cwriteanswer, {"I2C bytes write", "5co_legacy.i2writeanswer",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2cack, {"I2C ack state", "5co_legacy.i2cack",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2c2scan, {"I2C addresses to scan", "5co_legacy.i2c2scan",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2cscaned, {"I2C addresses present", "5co_legacy.i2cscaned",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_i2cerror, {"I2C error", "5co_legacy.i2cerror",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_regread, {"Read", "5co_legacy.regread",
            FT_UINT8, BASE_HEX, VALS(register_name_vals), 0x0, NULL, HFILL}},
        {&hf_fiveco_regreaduk, {"Data not decoded", "5co_legacy.regreaduk",
            FT_BYTES, BASE_NONE, NULL, 0x0, "Data not decoded because there are unable to map to a known register", HFILL}},
        {&hf_fiveco_regwrite, {"Write", "5co_legacy.regwrite",
            FT_UINT8, BASE_HEX, VALS(register_name_vals), 0x0, NULL, HFILL}},
        {&hf_fiveco_regwriteuk, {"Data not decoded", "5co_legacy.regwriteuk",
            FT_BYTES, BASE_NONE, NULL, 0x0, "Data not decoded because there are unable to map to a known register", HFILL}},
        {&hf_fiveco_EasyIPMAC, {"MAC address", "5co_legacy.EasyIPMAC",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_EasyIPIP, {"New IP address", "5co_legacy.EasyIPIP",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_EasyIPSM, {"New subnet mask", "5co_legacy.EasyIPSM",
            FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_flash_offset, {"Flash Offset", "5co_legacy.flash_offset",
            FT_UINT24, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_flash_size, {"Flash Size", "5co_legacy.flash_size",
            FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_flash_answer, {"Flash Answer", "5co_legacy.flash_answer",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},


        /* Specific table */
        {&hf_fiveco_reg_type_model, {"Register Type/Model", "5co_legacy.RegTypeModel",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(dispType), 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_version, {"Register Version", "5co_legacy.RegVersion",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(dispVersion), 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_reset, {"Function Reset device", "5co_legacy.RegReset",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_save, {"Function Save user parameters", "5co_legacy.RegSave",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_restore, {"Function Restore user parameters", "5co_legacy.RegRestore",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_restore_factory, {"Function Restore factory parameters", "5co_legacy.RegRestoreFact",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_save_factory, {"Function Save factory parameters", "5co_legacy.SaveFact",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_comm_option, {"Register Communication options", "5co_legacy.RegComOption",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_mac_address, {"Register Ethernet MAC Address", "5co_legacy.RegMAC",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_ip_address, {"Register IP Address", "5co_legacy.RegIPAdd",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_ip_subnet_mask, {"Register IP Mask", "5co_legacy.RegIPMask",
            FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_tcp_timeout, {"Register TCP Timeout", "5co_legacy.RegTCPTimeout",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(dispTimeout), 0x0, NULL, HFILL}},
        {&hf_fiveco_reg_name, {"Register Module name", "5co_legacy.RegName",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_fiveco_header,
        &ett_fiveco_data,
        &ett_fiveco,
        &ett_fiveco_checksum
    };

    static ei_register_info ei[] =
    {
        { &ei_fiveco_regread, { "5co_legacy.hf_fiveco_regreadunknown", PI_PROTOCOL, PI_WARN, "Read Register unknown", EXPFILL } },
        { &ei_fiveco_interpretation, { "5co_legacy.interpretation", PI_UNDECODED, PI_NOTE, "Interpretation depends on product type", EXPFILL } },
        { &ei_fiveco_cks, { "5co_legacy.bad_checksum", PI_CHECKSUM, PI_WARN, "Bad packet checksum", EXPFILL } },
        { &ei_fiveco_answer_already_found, { "5co_legacy.answer_already_found", PI_PROTOCOL, PI_WARN, "Answer already found! Maybe packets ID not incremented", EXPFILL } },
        { &ei_fiveco_no_data_expected, { "5co_legacy.no_data_expected", PI_PROTOCOL, PI_ERROR, "No data should be present with that packet type", EXPFILL } },
    };

    expert_module_t* expert_FiveCoLegacy;

    /* Register the protocol name and description */
    proto_FiveCoLegacy = proto_register_protocol("FiveCo's Legacy Register Access Protocol",
                                                 "5co-legacy", "5co_legacy");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_FiveCoLegacy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_FiveCoLegacy = expert_register_protocol(proto_FiveCoLegacy);
    expert_register_field_array(expert_FiveCoLegacy, ei, array_length(ei));

    /* Register the dissector */
    FiveCoLegacy_tcp_handle = register_dissector("5co_legacy", dissect_FiveCoLegacy_tcp, proto_FiveCoLegacy);
    FiveCoLegacy_udp_handle = register_dissector("5co_legacy_udp", dissect_FiveCoLegacy_udp, proto_FiveCoLegacy);

    FiveCo_requests_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), fiveco_hash, fiveco_hash_equal);
}

void proto_reg_handoff_FiveCoLegacy(void)
{
    dissector_add_uint_range_with_preference("tcp.port", FIVECO_TCP_PORTS, FiveCoLegacy_tcp_handle);
    dissector_add_uint_range_with_preference("udp.port", FIVECO_UDP_PORTS, FiveCoLegacy_udp_handle);
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
