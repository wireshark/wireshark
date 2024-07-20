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
#include <epan/proto_data.h>
#include <string.h>
#include "packet-tcp.h"

/* Prototypes */
void proto_reg_handoff_FiveCoLegacy(void);
void proto_register_FiveCoLegacy(void);

static dissector_handle_t FiveCoLegacy_handle;

/****************************************************************************/
/* Definition declaration */
/****************************************************************************/

// Protocol header length and frame minimum length
#define FIVECO_LEGACY_HEADER_LENGTH 6
#define FIVECO_LEGACY_MIN_LENGTH FIVECO_LEGACY_HEADER_LENGTH + 2 // Checksum is 16 bits

#define PSNAME "5co-legacy"

/* Global sample ports preferences */
#define FIVECO_PORT1 8010     /* TCP port of the FiveCo protocol */
#define FIVECO_PORT2 8004     /* TCP port of the FiveCo protocol for web page upload */
#define FIVECO_UDP_PORT1 7010 /* UDP port of the FiveCo protocol */

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

/* Forward references to functions */
static uint16_t
checksum_fiveco(tvbuff_t * byte_tab, uint16_t start_offset, uint16_t size);
static int fiveco_hash_equal(const void *v, const void *w);

/* Register decoding functions prototypes */
static void dispType( char *result, uint32_t type);
static void dispVersion( char *result, uint32_t type);
static void dispMAC( char *result, uint64_t type);
static void dispIP( char *result, uint32_t type);
static void dispMask( char *result, uint32_t type);
static void dispTimeout( char *result, uint32_t type);

/* Initialize the protocol and registered fields */
static int proto_FiveCoLegacy; /* Wireshark ID of the FiveCo protocol */

/* static dissector_handle_t data_handle = NULL; */
static int hf_fiveco_header;       /* The following hf_* variables are used to hold the Wireshark IDs of */
static int hf_fiveco_fct;          /* our header fields; they are filled out when we call */
static int hf_fiveco_id;           /* proto_register_field_array() in proto_register_fiveco() */
static int hf_fiveco_length;
static int hf_fiveco_data;
static int hf_fiveco_cks;
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
static int hf_fiveco_regreadunknown;
static int hf_fiveco_regreaduk;
static int hf_fiveco_EasyIPMAC;
static int hf_fiveco_EasyIPIP;
static int hf_fiveco_EasyIPSM;

static int ett_fiveco_header; /* These are the ids of the subtrees that we may be creating */
static int ett_fiveco_data;   /* for the header fields. */
static int ett_fiveco;
static int ett_fiveco_checksum;

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
    {0, NULL}};

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

/* Register definition structure (used to detect known registers when it is possible) */
typedef struct
{
    uint32_t unValue;                                        // Register address
    uint32_t unSize;                                         // Register size (in bytes)
    const char *name;                                       // Register name
    const char *abbrev;                                     // Abbreviation for header fill
    const enum ftenum ft;                                   // Field type
    int nsWsHeaderID;                                      // Wireshark ID for header fill
    const void *pFct;                                       // Conversion function
} FCOSRegisterDef;

/* Known (common on every product) registers */
static FCOSRegisterDef aRegisters[] = {
    {0x00, 4, "Register Type/Model", "5co_legacy.RegTypeModel", FT_UINT32, -1, CF_FUNC(dispType)},
    {0x01, 4, "Register Version", "5co_legacy.RegVersion", FT_UINT32, -1, CF_FUNC(dispVersion)},
    {0x02, 0, "Function Reset device", "5co_legacy.RegReset", FT_NONE, -1, NULL},
    {0x03, 0, "Function Save user parameters", "5co_legacy.RegSave", FT_NONE, -1, NULL},
    {0x04, 0, "Function Restore user parameters", "5co_legacy.RegRestore", FT_NONE, -1, NULL},
    {0x05, 0, "Function Restore factory parameters", "5co_legacy.RegRestoreFact", FT_NONE, -1, NULL},
    {0x06, 0, "Function Save factory parameters", "5co_legacy.SaveFact", FT_NONE, -1, NULL},
    {0x07, 0, "Register unknown", "5co_legacy.RegUnknown07", FT_NONE, -1, NULL},
    {0x08, 0, "Register unknown", "5co_legacy.RegUnknown08", FT_NONE, -1, NULL},
    {0x09, 0, "Register unknown", "5co_legacy.RegUnknown09", FT_NONE, -1, NULL},
    {0x0A, 0, "Register unknown", "5co_legacy.RegUnknown0A", FT_NONE, -1, NULL},
    {0x0B, 0, "Register unknown", "5co_legacy.RegUnknown0B", FT_NONE, -1, NULL},
    {0x0C, 0, "Register unknown", "5co_legacy.RegUnknown0C", FT_NONE, -1, NULL},
    {0x0D, 0, "Register unknown", "5co_legacy.RegUnknown0D", FT_NONE, -1, NULL},
    {0x0E, 0, "Register unknown", "5co_legacy.RegUnknown0E", FT_NONE, -1, NULL},
    {0x0F, 0, "Register unknown", "5co_legacy.RegUnknown0F", FT_NONE, -1, NULL},
    {0x10, 4, "Register Communication options", "5co_legacy.RegComOption", FT_UINT32, -1, NULL},
    {0x11, 6, "Register Ethernet MAC Address", "5co_legacy.RegMAC", FT_UINT48, -1, CF_FUNC(dispMAC)},
    {0x12, 4, "Register IP Address", "5co_legacy.RegIPAdd", FT_UINT32, -1, CF_FUNC(dispIP)},
    {0x13, 4, "Register IP Mask", "5co_legacy.RegIPMask", FT_UINT32, -1, CF_FUNC(dispMask)},
    {0x14, 1, "Register TCP Timeout", "5co_legacy.RegTCPTimeout", FT_UINT8, -1, CF_FUNC(dispTimeout)},
    {0x15, 16, "Register Module name", "5co_legacy.RegName", FT_STRING, -1, NULL}};

    /* List of static header fields */
static hf_register_info hf_base[] = {
    {&hf_fiveco_header, {"Header", "5co_legacy.header", FT_NONE, BASE_NONE, NULL, 0x0, "Header of the packet", HFILL}},
    {&hf_fiveco_fct, {"Function", "5co_legacy.fct", FT_UINT16, BASE_HEX, VALS(packettypenames), 0x0, "Function type", HFILL}},
    {&hf_fiveco_id, {"Frame ID", "5co_legacy.id", FT_UINT16, BASE_DEC, NULL, 0x0, "Packet ID", HFILL}},
    {&hf_fiveco_length, {"Data length", "5co_legacy.length", FT_UINT16, BASE_DEC, NULL, 0x0, "Parameters length of the packet", HFILL}},
    {&hf_fiveco_data, {"Data", "5co_legacy.data", FT_NONE, BASE_NONE, NULL, 0x0, "Data (parameters)", HFILL}},
    {&hf_fiveco_cks, {"Checksum", "5co_legacy.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, "Checksum of the packet", HFILL}},
    {&hf_fiveco_i2cadd, {"I2C Address", "5co_legacy.i2cadd", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2c2write, {"I2C number of bytes to write", "5co_legacy.i2c2write", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2cwrite, {"I2C bytes to write", "5co_legacy.i2cwrite", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2c2read, {"I2C number of bytes to read", "5co_legacy.i2c2read", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2canswer, {"I2C bytes read", "5co_legacy.i2cread", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2cwriteanswer, {"I2C bytes write", "5co_legacy.i2writeanswer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2cack, {"I2C ack state", "5co_legacy.i2cack", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2c2scan, {"I2C addresses to scan", "5co_legacy.i2c2scan", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2cscaned, {"I2C addresses present", "5co_legacy.i2cscaned", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_i2cerror, {"I2C error", "5co_legacy.i2cerror", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_regread, {"Read", "5co_legacy.regread", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_regreadunknown, {"Read Register unknown", "5co_legacy.hf_fiveco_regreadunknown", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_regreaduk, {"Data not decoded", "5co_legacy.regreaduk", FT_NONE, BASE_NONE, NULL, 0x0, "Data not decoded because there are unable to map to a known register", HFILL}},
    {&hf_fiveco_EasyIPMAC, {"MAC address", "5co_legacy.EasyIPMAC", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_EasyIPIP, {"New IP address", "5co_legacy.EasyIPIP", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_fiveco_EasyIPSM, {"New subnet mask", "5co_legacy.EasyIPSM", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}}
 };

/*****************************************************************************/
/* Code to actually dissect the packets                                      */
/* Callback function for reassembled packet                                  */
/*****************************************************************************/
static int
dissect_FiveCoLegacy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint16_t checksum_cal, checksum_rx;
    uint16_t i, j, y;
    uint16_t tcp_data_offset = 0;
    uint32_t tcp_data_length = 0;
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
    tvbuff_t *pRequestTvb = NULL;
    uint8_t ucAdd, ucBytesToWrite, ucBytesToRead;
    uint8_t ucRegAdd, ucRegSize;
    uint32_t unOffset;
    uint32_t unSize;

    /* Load protocol payload length (including checksum) */
    tcp_data_length = tvb_captured_length(tvb);
    if (tcp_data_length < FIVECO_LEGACY_MIN_LENGTH) // Check checksum presence
        return 0;

    /* Display fiveco in protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Look for all future TCP conversations between the
    * requestiong server and the FiveCo device using the
    * same src & dest addr and ports.
    */
    conversation = find_or_create_conversation(pinfo);
    requestKey.conversation = conversation->conv_index;

    /* Loop because several fiveco packets can be present in one TCP packet */
    while (tcp_data_offset < tcp_data_length) {

        /* Check that header type is correct */
        header_type = tvb_get_ntohs(tvb, tcp_data_offset + 0);
        if (try_val_to_str(header_type, packettypenames) == NULL)
            return 0;

        /* Read packet ID */
        header_id = tvb_get_ntohs(tvb, tcp_data_offset + 2);

        /* Check that there's enough data versus prot data header_data_length */
        header_data_length = tvb_get_ntohs(tvb, tcp_data_offset + 4);
        if (header_data_length > tcp_data_length - tcp_data_offset - 8) {
            return 0;
        }

        /* Get/Set internal ID for this packet number */
        pulInternalID = (uint64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_FiveCoLegacy, pinfo->num);
        /* If internal ID is not set (null), create it */
        if (!pulInternalID)
        {
            /* If it is a new request, increment internal ID */
            if ((header_type == I2C_READ) || (header_type == I2C_WRITE) || (header_type == I2C_SCAN) ||
                (header_type == I2C_READ_WRITE_ACK) || (header_type == READ_REGISTER) || (header_type == WRITE_REGISTER))
            {
                isRequest = true;
                g_unInternalID++;   // Increment unique request ID and record it in the new request
                /* Note: Since some software do not increment packet id located in frame header
                we use an internal ID to match answers to request. */
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
            tvb_memcpy(tvb, pRequestVal->pDataBuffer, tcp_data_offset + 6, header_data_length);

            wmem_map_insert(FiveCo_requests_hash, pNewRequestKey, pRequestVal);
        }

        if (pRequestVal) {
            pRequestTvb = tvb_new_child_real_data(tvb, pRequestVal->pDataBuffer, pRequestVal->usParaLen, pRequestVal->usParaLen);
        }

        /* Compute checksum of the packet and read one received */
        checksum_cal = checksum_fiveco(tvb, tcp_data_offset, header_data_length + 6);
        checksum_rx = tvb_get_ntohs(tvb, tcp_data_offset + header_data_length + 6);

        /* Add text to info column */
        /* If the offset != 0 (not first fiveco frame in tcp packet) add a comma in info column */
        if (tcp_data_offset != 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s ID=%d Len=%d",
                val_to_str(header_type, packettypenames, "Unknown Type:0x%02x"), header_id, header_data_length);
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ID=%d Len=%d",
                val_to_str(header_type, packettypenames, "Unknown Type:0x%02x"), header_id, header_data_length);
        }

        if (checksum_rx != checksum_cal)
        {
            col_append_str(pinfo->cinfo, COL_INFO, " [BAD CHECKSUM !!]");
        }

        /* Add FiveCo protocol in tree (after TCP or UDP entry) */
        fiveco_item = proto_tree_add_item(tree, proto_FiveCoLegacy, tvb, tcp_data_offset + 0,
                                        header_data_length + 8, ENC_NA); /* Add a new entry inside tree display */
        proto_item_append_text(fiveco_item, " (%s)", val_to_str(header_type, packettypenames, "Unknown Type:0x%02x"));

        /* Add fiveco Protocol tree and sub trees for Header, Data and Checksum */
        fiveco_tree = proto_item_add_subtree(fiveco_item, ett_fiveco); // FiveCo prot tree
        fiveco_header_item = proto_tree_add_item(fiveco_tree, hf_fiveco_header,
                                                tvb, tcp_data_offset + 0, 6, ENC_NA); // Header tree
        fiveco_header_tree = proto_item_add_subtree(fiveco_header_item, ett_fiveco_header);
        proto_tree_add_item(fiveco_header_tree, hf_fiveco_fct,
                                    tvb, tcp_data_offset + 0, 2, ENC_BIG_ENDIAN); // Packet type (function) in Header
        proto_tree_add_item(fiveco_header_tree, hf_fiveco_id,
                                    tvb, tcp_data_offset + 2, 2, ENC_BIG_ENDIAN); // Packet ID in Header
        proto_tree_add_item(fiveco_header_tree, hf_fiveco_length,
                                    tvb, tcp_data_offset + 4, 2, ENC_BIG_ENDIAN); // Length of para in Header

        tcp_data_offset += 6; // put offset on start of data (parameters)

        // If there are parameters (data) in packet, display them in data sub tree
        if (header_data_length > 0)
        {
            fiveco_data_item = proto_tree_add_item(fiveco_tree, hf_fiveco_data, tvb, tcp_data_offset,
                                                header_data_length, ENC_NA); // Data tree
            fiveco_data_tree = proto_item_add_subtree(fiveco_data_item, ett_fiveco_data);
            switch (header_type)
            {
            case I2C_READ:
            case I2C_READ_WRITE_ACK:
                i = 0;
                while (i < header_data_length)
                {
                    proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cadd, tvb, tcp_data_offset + i, 1, ENC_BIG_ENDIAN);
                    i += 1;
                    data_i2c_length = tvb_get_uint8(tvb, tcp_data_offset + i);
                    proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2write, tvb, tcp_data_offset + i, 1, ENC_BIG_ENDIAN);
                    i += 1;
                    fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cwrite,
                                                        tvb, tcp_data_offset + i, data_i2c_length, ENC_NA);
                    proto_item_append_text(fiveco_data_item, ": ");
                    for (j = 0; j < data_i2c_length; j++)
                    {
                        proto_item_append_text(fiveco_data_item, "0x%.2X ",
                                            tvb_get_uint8(tvb, tcp_data_offset + i));
                        i += 1;
                    }
                    proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2read, tvb, tcp_data_offset + i, 1, ENC_BIG_ENDIAN);
                    i += 1;
                }
                break;
            case I2C_WRITE:
                i = 0;
                while (i < header_data_length)
                {
                    proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cadd, tvb, tcp_data_offset + i, 1, ENC_BIG_ENDIAN);
                    i += 1;
                    data_i2c_length = tvb_get_uint8(tvb, tcp_data_offset + i);
                    proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2write, tvb, tcp_data_offset + i, 1, ENC_BIG_ENDIAN);
                    i += 1;
                    fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cwrite,
                                                        tvb, tcp_data_offset + i, data_i2c_length, ENC_NA);
                    proto_item_append_text(fiveco_data_item, ": ");
                    for (j = 0; j < data_i2c_length; j++)
                    {
                        proto_item_append_text(fiveco_data_item, "0x%.2X ",
                                            tvb_get_uint8(tvb, tcp_data_offset + i));
                        i += 1;
                    }
                }
                break;
            case I2C_SCAN:
                fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2c2scan,
                                                    tvb, tcp_data_offset + 0, header_data_length, ENC_NA);
                proto_item_append_text(fiveco_data_item, ": ");
                // If specific address exists in packet, display them
                for (i = 0; i < header_data_length; i++)
                {
                    proto_item_append_text(fiveco_data_item, "0x%.2X ",
                                        tvb_get_uint8(tvb, tcp_data_offset + i));
                }
                break;
            case I2C_SCAN_ANSWER:
                fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cscaned,
                                                    tvb, tcp_data_offset + 0, header_data_length, ENC_NA);
                proto_item_append_text(fiveco_data_item, ": ");
                // Display slave address presents in answer
                for (i = 0; i < header_data_length; i++)
                {
                    proto_item_append_text(fiveco_data_item, "0x%.2X ",
                                        tvb_get_uint8(tvb, tcp_data_offset + i));
                }
                break;
            case I2C_READ_WRITE_ACK_ERROR:
                fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cerror,
                                                    tvb, tcp_data_offset + 0, header_data_length, ENC_NA);
                proto_item_append_text(fiveco_data_item, ": ");
                proto_item_append_text(fiveco_data_item, "0x%.2X ",
                                    tvb_get_uint8(tvb, tcp_data_offset));
                break;
            case READ_REGISTER:
                // List registers asked for read
                for (i = 0; i < header_data_length; i++)
                {
                    ucRegAdd = tvb_get_uint8(tvb, tcp_data_offset + i);
                    if ((ucRegAdd < array_length(aRegisters)) &&
                        (aRegisters[ucRegAdd].unValue == ucRegAdd))
                    {
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regread,
                                                                tvb, tcp_data_offset + i, 0, ENC_NA);
                        proto_item_append_text(fiveco_data_item, " %s", aRegisters[ucRegAdd].name);
                    }
                    else
                    {
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regreadunknown,
                            tvb, tcp_data_offset + i, 0, ENC_NA);
                    }
                    proto_item_append_text(fiveco_data_item, " (0x%.2X)", ucRegAdd);
                }
                break;
            case WRITE_REGISTER:
            case WRITE_REGISTER_QUIET:
                // List register asked to write with data to fill in until an unknown one is found
                for (i = tcp_data_offset; i < tcp_data_offset + header_data_length;)
                {
                    ucRegAdd = tvb_get_uint8(tvb, i++);
                    // If register address is known & found
                    if ((ucRegAdd < array_length(aRegisters)) &&
                        (aRegisters[ucRegAdd].unValue == ucRegAdd))
                    {
                        ucRegSize = aRegisters[ucRegAdd].unSize;
                        // If a display function is defined, call it
                        if (aRegisters[ucRegAdd].pFct != NULL)
                        {
                            proto_tree_add_item(fiveco_data_tree, aRegisters[ucRegAdd].nsWsHeaderID,
                                                    tvb, i, ucRegSize, ENC_NA);
                            i += ucRegSize;
                        }
                        // else if register type is string, display it as string
                        else if (aRegisters[ucRegAdd].ft == FT_STRING)
                        {
                            fiveco_data_item = proto_tree_add_item(fiveco_data_tree,
                                aRegisters[ucRegAdd].nsWsHeaderID,
                                tvb, i, ucRegSize,
                                ENC_NA);
                            proto_item_append_text(fiveco_data_item, ": %s", tvb_format_text(pinfo->pool, tvb, i, ucRegSize));
                            i += ucRegSize;
                        }
                        // else display raw data in hex
                        else
                        {
                            fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regread,
                                tvb, i, ucRegSize, ENC_NA);
                            proto_item_append_text(fiveco_data_item, " %s (Add: 0x%.2X, Size: %d bytes): ",
                                aRegisters[ucRegAdd].name, ucRegAdd, ucRegSize);
                            for (j = 0; j < ucRegSize; j++)
                            {
                                proto_item_append_text(fiveco_data_item, "0x%.2X ", tvb_get_uint8(tvb, i++));
                            }
                        }
                    }
                    // Else tell user that data cannot be interpreted
                    else
                    {
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regreaduk,
                                                            tvb, i, tcp_data_offset + header_data_length - i, ENC_NA);
                        proto_item_append_text(fiveco_data_item, " (Interpretation depends on product type)");
                        break;
                    }
                }
                break;
            case EASY_IP_ADDRESS_CONFIG:
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_EasyIPMAC, tvb, tcp_data_offset + 0, 6, ENC_NA);
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_EasyIPIP, tvb, tcp_data_offset + 6, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(fiveco_data_tree, hf_fiveco_EasyIPSM, tvb, tcp_data_offset + 10, 4, ENC_BIG_ENDIAN);
                break;
            case I2C_READ_ANSWER:
            case I2C_WRITE_ANSWER:
            case I2C_READ_WRITE_ACK_ANSWER:
                if (pRequestVal)
                {
                    if (pRequestVal->isReplied != 0)
                    {
                        proto_item_append_text(fiveco_data_item,
                                            " WARNING : Answer already found ! Maybe packets ID not incremented.");
                    }
                    else
                    {
                        i = tcp_data_offset; // Answer index
                        y = 0;               // Request index
                        while ((y < pRequestVal->usParaLen) && (i < tcp_data_offset + header_data_length))
                        {
                            // I2C address in first byte of request
                            ucAdd = tvb_get_uint8(pRequestTvb, y++);
                            // Read number of bytes to write
                            ucBytesToWrite = tvb_get_uint8(pRequestTvb, y);
                            // Skip number of bytes to write and those bytes
                            y += 1 + ucBytesToWrite;
                            // Read number of bytes to read
                            ucBytesToRead = tvb_get_uint8(pRequestTvb, y++);
                            if (ucBytesToRead > 0)
                            {
                                fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2canswer,
                                                                    tvb, i, ucBytesToRead, ENC_NA);
                                proto_item_append_text(fiveco_data_item,
                                                    " from address %d (%d bytes written) : ",
                                                    ucAdd, ucBytesToWrite);
                                for (j = 0; j < ucBytesToRead; j++)
                                {
                                    proto_item_append_text(fiveco_data_item, "0x%.2X ",
                                                        tvb_get_uint8(tvb, i++));
                                }
                                if (header_type == 0x08)
                                    proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cack, tvb, i++, 1, ENC_BIG_ENDIAN);
                            }
                            else if (header_type == I2C_READ_WRITE_ACK_ANSWER)
                            {
                                // if it's an answer to a write but with ack, display it
                                fiveco_data_item = proto_tree_add_item(fiveco_data_tree,
                                                                    hf_fiveco_i2cwriteanswer, tvb, i,
                                                                    ucBytesToRead, ENC_NA);
                                proto_item_append_text(fiveco_data_item, " to address %d (%d bytes written)",
                                                    ucAdd, ucBytesToWrite);
                                proto_tree_add_item(fiveco_data_tree, hf_fiveco_i2cack, tvb, i++, 1, ENC_BIG_ENDIAN);
                            }
                        }
                    }
                    break;
                }
                else {
                    proto_item_append_text(fiveco_data_item, " (Interpretation depends on product type)");
                }
                break;
            case READ_REGISTER_ANSWER:
                if (pRequestVal)
                {
                    if (pRequestVal->isReplied != 0)
                    {
                        proto_item_append_text(fiveco_data_item,
                                            " WARNING : Answer already found ! Maybe packets ID not incremented.");
                    }
                    else
                    {
                        i = tcp_data_offset; // Answer index
                        y = 0;               // Request index
                        // For each request stored in the last read request of the conversation
                        while ((y < pRequestVal->usParaLen) && (i < tcp_data_offset + header_data_length))
                        {
                            // Register address in first byte of request
                            ucRegAdd = tvb_get_uint8(pRequestTvb, y++);
                            // If register address is known & found in answer
                            if ((ucRegAdd < array_length(aRegisters)) &&
                                (aRegisters[ucRegAdd].unValue == ucRegAdd) &&
                                (ucRegAdd == tvb_get_uint8(tvb, i++)))
                            {
                                // Retrieve register size and display it with address
                                ucRegSize = aRegisters[ucRegAdd].unSize;
                                // If a display function is defined, call it
                                if (aRegisters[ucRegAdd].pFct != NULL)
                                {
									proto_tree_add_item(fiveco_data_tree, aRegisters[ucRegAdd].nsWsHeaderID,
														    tvb, i, ucRegSize, ENC_NA);
                                    i += ucRegSize;
                                }
                                // else if register type is string, display it as string
                                else if (aRegisters[ucRegAdd].ft == FT_STRING)
                                {
									fiveco_data_item = proto_tree_add_item(fiveco_data_tree,
														    aRegisters[ucRegAdd].nsWsHeaderID,
														    tvb, i, ucRegSize,
                                                            ENC_NA);
                                    proto_item_append_text(fiveco_data_item, ": %s", tvb_format_text(pinfo->pool, tvb, i, ucRegSize));
                                    i += ucRegSize;
                                }
                                // else display raw data in hex
                                else
                                {
									fiveco_data_item = proto_tree_add_item(fiveco_data_tree,
															hf_fiveco_regread, tvb, i, ucRegSize, ENC_NA);
                                    proto_item_append_text(fiveco_data_item,
                                                        " %s (Add: 0x%.2X, Size: %d bytes): ",
                                                        aRegisters[ucRegAdd].name, ucRegAdd, ucRegSize);
                                    for (j = 0; j < ucRegSize; j++)
                                    {
                                        proto_item_append_text(fiveco_data_item,
                                                            "0x%.2X ", tvb_get_uint8(tvb, i++));
                                    }
                                }
                            }
                            // Else tell user that data cannot be interpreted
                            else
                            {
                                fiveco_data_item = proto_tree_add_item(fiveco_data_tree,
                                                                    hf_fiveco_regreaduk, tvb, i,
                                                                    tcp_data_offset + header_data_length - i,
                                                                    ENC_NA);
                                proto_item_append_text(fiveco_data_item,
                                                    " (Interpretation depends on product type)");
                                break;
                            }
                        }
                    }
                }
                break;
            case FLASH_AREA_LOAD:
                unOffset = tvb_get_uint24(tvb, tcp_data_offset, ENC_BIG_ENDIAN);
                unSize = tvb_get_uint24(tvb, tcp_data_offset + 3, ENC_BIG_ENDIAN);
                proto_item_append_text(fiveco_data_item,
                                    " (%d bytes to load into flash at offset %d)", unSize, unOffset);
                break;
            case FLASH_AREA_ANSWER:
                if ( header_data_length > 1 ) {
                    proto_item_append_text(fiveco_data_item, " (%s)", tvb_format_text(pinfo->pool, tvb, tcp_data_offset, header_data_length - 1));
                }
                break;

            case WRITE_REGISTER_ANSWER:
            case FLASH_AREA_ERASE:
            case EASY_IP_ADDRESS_CONFIG_ANSWER:
                proto_item_append_text(fiveco_data_item, " (ERROR: No data should be present with that packet type !!)");
                break;

            default:
                proto_item_append_text(fiveco_data_item, " (Interpretation depends on product type)");
                break;
            }
        }

        // Checksum validation and sub tree
        proto_tree_add_checksum(fiveco_tree, tvb, tcp_data_offset + header_data_length, hf_fiveco_cks, -1, NULL, NULL,
            checksum_cal, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

        tcp_data_offset += header_data_length + 2 ; /* jump to next packet if exists */
    } /*while (tcp_data_offset < tcp_data_length) */

    return tvb_captured_length(tvb);
}

/*****************************************************************************/
/* This function returns the calculated checksum (IP based)                  */
/*****************************************************************************/
static uint16_t checksum_fiveco(tvbuff_t *byte_tab, uint16_t start_offset, uint16_t size)
{
	uint32_t Sum			= 0;
	uint8_t	AddHighByte = 1;
	uint32_t ChecksumCalculated;
	uint16_t i;
	uint8_t	temp;

	for (i = 0; i < size; i++)
    {
        tvb_memcpy(byte_tab, (uint8_t *)&temp, start_offset + i, 1);
        if (AddHighByte)
        {
            Sum += (temp << 8) ^ 0xFF00;
            AddHighByte = 0;
        }
        else
        {
            Sum += (temp) ^ 0x00FF;
            AddHighByte = 1;
        }
    }

    if (AddHighByte == 0)
        Sum += 0xFF;

    ChecksumCalculated = ((Sum >> 16) & 0xFFFF) + (Sum & 0xFFFF);
    ChecksumCalculated = ((ChecksumCalculated >> 16) & 0xFFFF) + (ChecksumCalculated & 0xFFFF);
    return (uint16_t)ChecksumCalculated;
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

/*****************************************************************************/
/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
/*****************************************************************************/
void proto_register_FiveCoLegacy(void)
{
    /* Setup list of header fields (based on static table and specific table) */
    static hf_register_info hf[array_length(hf_base) + array_length(aRegisters)];
    for (uint32_t i = 0; i < array_length(hf_base); i++) {
        hf[i] = hf_base[i];
    }
    for (uint32_t i = 0; i < array_length(aRegisters); i++) {
        if (aRegisters[i].pFct != NULL){
            hf_register_info hfx = { &(aRegisters[i].nsWsHeaderID),{aRegisters[i].name, aRegisters[i].abbrev, aRegisters[i].ft, BASE_CUSTOM, aRegisters[i].pFct, 0x0, NULL, HFILL}};
            hf[array_length(hf_base) + i] = hfx;
        } else {
            hf_register_info hfx = { &(aRegisters[i].nsWsHeaderID),{aRegisters[i].name, aRegisters[i].abbrev, FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}};
            hf[array_length(hf_base) + i] = hfx;
        }
    }

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_fiveco_header,
        &ett_fiveco_data,
        &ett_fiveco,
        &ett_fiveco_checksum};

    /* Register the protocol name and description */
    proto_FiveCoLegacy = proto_register_protocol("FiveCo's Legacy Register Access Protocol",
                                                 PSNAME, "5co_legacy");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_FiveCoLegacy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissector */
    FiveCoLegacy_handle = register_dissector("5co_legacy", dissect_FiveCoLegacy,
                                                    proto_FiveCoLegacy);

    FiveCo_requests_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), fiveco_hash, fiveco_hash_equal);

    /* Set preference callback to NULL since it is not used */
    prefs_register_protocol(proto_FiveCoLegacy, NULL);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * Simpler form of proto_reg_handoff_FiveCoLegacy which can be used if there are
 * no prefs-dependent registration function calls. */
void proto_reg_handoff_FiveCoLegacy(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        dissector_add_uint("tcp.port", FIVECO_PORT1, FiveCoLegacy_handle);
        dissector_add_uint("tcp.port", FIVECO_PORT2, FiveCoLegacy_handle);
        dissector_add_uint("udp.port", FIVECO_UDP_PORT1, FiveCoLegacy_handle);
        initialized = true;
    }
}

/*****************************************************************************/
/* Registers decoding functions                                              */
/*****************************************************************************/
static void
dispType( char *result, uint32_t type)
{
    int nValueH = (type>>16) & 0xFFFF;
    int nValueL = (type & 0xFFFF);
    snprintf( result, ITEM_LABEL_LENGTH, "%d.%d (%.4X.%.4X)", nValueH, nValueL, nValueH, nValueL);
}

static void
dispVersion( char *result, uint32_t version)
{
    if ((version & 0xFF000000) == 0)
    {
        int nValueH = (version>>16) & 0xFFFF;
        int nValueL = (version & 0xFFFF);
        snprintf( result, ITEM_LABEL_LENGTH, "FW: %d.%d", nValueH, nValueL);
    }
    else
    {
        int nHWHigh = (version>>24) & 0xFF;
        int nHWLow = (version>>16) & 0xFF;
        int nFWHigh = (version>>8) & 0xFF;
        int nFWLow = (version>>8) & 0xFF;
        snprintf( result, ITEM_LABEL_LENGTH, "HW: %d.%d / FW: %d.%d", nHWHigh, nHWLow, nFWHigh, nFWLow);
    }
}

static void dispMAC( char *result, uint64_t mac)
{
    uint8_t *pData = (uint8_t*)(&mac);

    snprintf( result, ITEM_LABEL_LENGTH, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", pData[5], pData[4], pData[3], pData[2],
                           pData[1], pData[0]);
}

static void dispIP( char *result, uint32_t ip)
{
    uint8_t *pData = (uint8_t*)(&ip);

    snprintf( result, ITEM_LABEL_LENGTH, "%d.%d.%d.%d", pData[3], pData[2], pData[1], pData[0]);
}

static void dispMask( char *result, uint32_t mask)
{
    uint8_t *pData = (uint8_t*)(&mask);

    snprintf( result, ITEM_LABEL_LENGTH, "%d.%d.%d.%d", pData[3], pData[2], pData[1], pData[0]);
}

static void dispTimeout( char *result, uint32_t timeout)
{
    if (timeout != 0)
        snprintf( result, ITEM_LABEL_LENGTH, "%d seconds", timeout);
    else
        snprintf( result, ITEM_LABEL_LENGTH, "Disabled");
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
