/* packet-5co-rap.c
 * Routines for FiveCo's Register Access Protocol dissector
 * Copyright 2021, Antoine Gardiol <antoine.gardiol@fiveco.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This protocol allows access to FiveCo's Ethernet products registers with FRAP
 * protocol. Product list can be found under https://www.fiveco.ch/5-stars-products.
 * Protocol description can be found (by example) in FMod-I2C485ECMOT DB 48/10 manual that can
 * be dowloaded from https://www.fiveco.ch/sites/default/files/2021-09/FiveCo_MotorCtrl_UserManual_1_9.pdf.
 * Note that this protocol is a question-answer protocol. It's header is composed of:
 * - 1 byte for destination address (useless over IP)
 * - 1 byte for source address (useless over IP)
 * - x bytes for data length of parameters (high bits set tells that a supplementary byte is used)
 * The header is followed by n bytes of data (including checksum)
 */

//#define DEBUG_5co-rap

#include <config.h>
#define WS_LOG_DOMAIN "5co-rap"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <wsutil/utf8_entities.h>
#include <string.h>
#include "packet-tcp.h"

/* Prototypes */
void proto_reg_handoff_FiveCoRAP(void);
void proto_register_FiveCoRAP(void);

/****************************************************************************/
/* Definition declaration */
/****************************************************************************/

// Protocol header length and frame minimum length
#define FIVECO_RAP_HEADER_LENGTH 3
#define FIVECO_RAP_MIN_LENGTH FIVECO_RAP_HEADER_LENGTH + 2 // Checksum is 2 bytes
#define MAX_LENGTH_BYTES 4 // Max number of bytes for data length
#define MAX_SUB_DEVICES 10

#define PROTO_TAG_FIVECO "5co-rap"

/* Global sample ports preferences */
#define FIVECO_TCP_PORT1 8030     /* TCP port of the FiveCo protocol (N.B. unassigned by IANA) */
#define FIVECO_UDP_PORT1 7030     /* UDP port of the FiveCo protocol (N.B. assigned to "op-probe" by IANA) */

/* 16 bits type known available functions */
enum fiveco_functions
{
    READ_REGISTER = 0x00,
    READ_REGISTER_ANSWER = 0x20,
    WRITE_REGISTER = 0x40,
    SUBDEVICE_ROUTING = 0xC0,
    SUBDEVICE_ROUTING_ANSWER = 0xD0,
    EXT_REGISTER_ACCESS_ERR = 0xE0,
    EXT_FRAME_ID,
    EXT_FRAME_ID_ANSWER,
    EXT_EOF,
    EXT_FRAME_ERROR,
    EXT_EOF_MULTI_PACKETS,
    EXT_EOF_MULTI_PACKETS_END,
    EXT_EASY_IP_ADDRESS_CHANGE
};

/* Forward references to functions */
static uint8_t
checksum_fiveco(tvbuff_t * byte_tab, uint16_t start_offset, uint16_t size);
static int fiveco_hash_equal(const void *v, const void *w);

/* Register decoding functions prototypes */
static void disp_type( char *result, uint32_t type);
static void disp_version( char *result, uint32_t type);
static void disp_voltage( char *result, uint32_t type);
static void disp_mac( char *result, uint64_t type);
static void disp_ip( char *result, uint32_t type);
static void disp_mask( char *result, uint32_t type);
static void disp_timeout( char *result, uint32_t type);

/* Initialize the protocol and registered fields */
static int proto_FiveCoRAP; /* Wireshark ID of the FiveCo protocol */

 /* The following hf_* variables are used to hold the Wireshark IDs of */
 /* our header fields; they are filled out when we call */
 /* proto_register_field_array() in proto_register_fiveco() */
static int hf_fiveco_source_addr;
static int hf_fiveco_dest_addr;
static int hf_fiveco_data;
static int hf_fiveco_regread;
static int hf_fiveco_regread_answer;
static int hf_fiveco_regwrite;
static int hf_fiveco_regcall;
static int hf_fiveco_routing;
static int hf_fiveco_routing_answer;
static int hf_fiveco_routing_interface;
static int hf_fiveco_routing_timeout;
static int hf_fiveco_routing_size;
static int hf_fiveco_ext_regerror;
static int hf_fiveco_ext_frameid;
static int hf_fiveco_ext_eof;
static int hf_fiveco_ext_frameerror;
static int hf_fiveco_ext_easyip;
static int hf_fiveco_ext_easyip_version;
static int hf_fiveco_ext_easyip_interface;
static int hf_fiveco_ext_easyip_mac;
static int hf_fiveco_ext_easyip_ip;
static int hf_fiveco_ext_easyip_mask;
static int hf_fiveco_ext_unsupported;
static int hf_fiveco_cks;

/* These are the ids of the subtrees that we may be creating */
/* for the header fields. */
static int ett_fiveco[MAX_SUB_DEVICES];
static int ett_fiveco_data[MAX_SUB_DEVICES];
static int ett_fiveco_easyip[MAX_SUB_DEVICES];
static int ett_fiveco_sub[MAX_SUB_DEVICES];
static int ett_fiveco_sub_details[MAX_SUB_DEVICES];

/* Conversation request key structure */
typedef struct
{
    uint32_t conversation;
} FCOSConvKey;

/* Conversation device type structure */
typedef struct
{
    uint32_t device_type[MAX_SUB_DEVICES];
    uint32_t device_version[MAX_SUB_DEVICES];
} FCOSConvDevices;

/* Conversation hash table (conversation-id -> FCOSConvDevices*) */
/* TODO: could just have FCOSConvDevices* as conversation data type? */
static GHashTable *fiveco_types_models_hash;

enum FCOERegistersType {
    REGISTER,
    FUNCTION
};

/* Register definition structure (used to detect known registers when it is possible) */
typedef struct
{
    const uint32_t reg_size;                                 // Register size (in bytes)
    const uint32_t reg_type;                                 // Register type (register, function)
    const char *name;                                       // Register name
    const char *abbrev;                                     // Abbreviation base for header fill
    const enum ftenum ft;                                   // Field type
    const int32_t base;                                      // Base display type
    const unsigned encoding;                                   // Field encoding
    int hf_id_w;                                           // Wireshark ID for header fill in write mode
    int hf_id_r_a;                                         // Wireshark ID for header fill in read answer mode
    const void *cf_func;                                    // Conversion function
} FCOSRegisterDef;

/* Known (common on every product) registers */
static FCOSRegisterDef registers_def[] = {
    /*0x00*/ { 4,  REGISTER, "Type/Model", "5co_rap.RegTypeModel", FT_UINT32, BASE_CUSTOM, ENC_LITTLE_ENDIAN, -1, -1, CF_FUNC(disp_type)},
    /*0x01*/ { 4,  REGISTER, "Version", "5co_rap.RegVersion", FT_UINT32, BASE_CUSTOM, ENC_LITTLE_ENDIAN, -1, -1, CF_FUNC(disp_version)},
    /*0x02*/ { 0,  FUNCTION, "Reset device", "5co_rap.RegReset", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x03*/ { 0,  FUNCTION, "Save user parameters", "5co_rap.RegSave", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x04*/ { 0,  FUNCTION, "Restore user parameters", "5co_rap.RegRestore", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x05*/ { 0,  FUNCTION, "Restore factory parameters", "5co_rap.RegRestoreFact", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x06*/ { 0,  FUNCTION, "Save factory parameters", "5co_rap.SaveFact", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x07*/ { 4,  REGISTER, "Voltage", "5co_rap.Voltage", FT_UINT32, BASE_CUSTOM, ENC_LITTLE_ENDIAN, -1, -1, CF_FUNC(disp_voltage)},
    /*0x08*/ { 4,  REGISTER, "Warnings", "5co_rap.Warnings", FT_UINT32, BASE_HEX, ENC_LITTLE_ENDIAN, -1, -1, NULL},
    /*0x09*/ { 8,  REGISTER, "Time Read", "5co_rap.TimeR", FT_UINT64, BASE_HEX, ENC_NA, -1, -1, NULL},
    /*0x0A*/ { 8,  REGISTER, "Time Write", "5co_rap.TimeW", FT_UINT64, BASE_HEX, ENC_NA, -1, -1, NULL},
    /*0x0B*/ { 4,  REGISTER, "Number of power up", "5co_rap.NbPowerUp", FT_UINT32, BASE_DEC, ENC_LITTLE_ENDIAN, -1, -1, NULL},
    /*0x0C*/ { 4,  REGISTER, "Service time (seconds)", "5co_rap.ServiceTime", FT_UINT32, BASE_DEC, ENC_LITTLE_ENDIAN, -1, -1, NULL},
    /*0x0D*/ { 0,  REGISTER, "Unknown", "5co_rap.RegUnknown0D", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x0E*/ { 8,  REGISTER, "CPU usage", "5co_rap.CPUUsage", FT_UINT64, BASE_HEX, ENC_NA, -1, -1, NULL},
    /*0x0F*/ { 0,  REGISTER, "Unknown", "5co_rap.RegUnknown0F", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x10*/ { 4,  REGISTER, "Communication options", "5co_rap.RegComOption", FT_UINT32, BASE_HEX, ENC_LITTLE_ENDIAN, -1, -1, NULL},
    /*0x11*/ { 6,  REGISTER, "Ethernet MAC Address", "5co_rap.RegMAC", FT_UINT48, BASE_CUSTOM, ENC_NA, -1, -1, CF_FUNC(disp_mac)},
    /*0x12*/ { 4,  REGISTER, "IP Address / Com ID", "5co_rap.RegIPAdd", FT_UINT32, BASE_CUSTOM, ENC_NA, -1, -1, CF_FUNC(disp_ip)},
    /*0x13*/ { 4,  REGISTER, "IP Mask", "5co_rap.RegIPMask", FT_UINT32, BASE_CUSTOM, ENC_NA, -1, -1, CF_FUNC(disp_mask)},
    /*0x14*/ { 1,  REGISTER, "TCP Timeout", "5co_rap.RegTCPTimeout", FT_UINT8, BASE_CUSTOM, ENC_LITTLE_ENDIAN, -1, -1, CF_FUNC(disp_timeout)},
    /*0x15*/ { 16, REGISTER, "Module name", "5co_rap.RegName", FT_STRING, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x16*/ { 0,  REGISTER, "Unknown", "5co_rap.RegUnknown15", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x17*/ { 0,  REGISTER, "Unknown", "5co_rap.RegUnknown16", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL},
    /*0x18*/ {16,  REGISTER, "FW upgrade flash data 0", "5co_rap.FwUpgFlashData0", FT_BYTES, SEP_SPACE, ENC_NA, -1, -1, NULL},
    /*0x19*/ {16,  REGISTER, "FW upgrade flash data 1", "5co_rap.FwUpgFlashData1", FT_BYTES, SEP_SPACE, ENC_NA, -1, -1, NULL},
    /*0x1A*/ {16,  REGISTER, "FW upgrade flash data 2", "5co_rap.FwUpgFlashData2", FT_BYTES, SEP_SPACE, ENC_NA, -1, -1, NULL},
    /*0x1B*/ {16,  REGISTER, "FW upgrade flash data 3", "5co_rap.FwUpgFlashData3", FT_BYTES, SEP_SPACE, ENC_NA, -1, -1, NULL},
    /*0x1C*/ { 6,  REGISTER, "FW upgrade flash pointer", "5co_rap.FwUpgFlashPointer", FT_BYTES, SEP_SPACE, ENC_NA, -1, -1, NULL},
    /*0x1D*/ { 0,  FUNCTION, "FW upgrade execute", "5co_rap.FwForceExecute", FT_NONE, BASE_NONE, ENC_NA, -1, -1, NULL}
};

    /* List of static header fields */
static hf_register_info hf_base[] = {
        {&hf_fiveco_source_addr, {"Source address", "5co_rap.src_addr", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, "FRAP source address", HFILL}},
        {&hf_fiveco_dest_addr, {"Destination address", "5co_rap.dest_addr", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, "FRAP destination address", HFILL}},
        {&hf_fiveco_data, {"Data", "5co_rap.data", FT_NONE, BASE_NONE, NULL, 0x0, "Data (parameters)", HFILL}},
        {&hf_fiveco_regread, {"Read register", "5co_rap.regread", FT_NONE, BASE_NONE, NULL, 0x0, "Read register at index", HFILL}},
        {&hf_fiveco_regread_answer, {"Read answer register", "5co_rap.regreadans", FT_NONE, BASE_NONE, NULL, 0x0, "Answer to a read register", HFILL}},
        {&hf_fiveco_regwrite, {"Write register", "5co_rap.regwrite", FT_NONE, BASE_NONE, NULL, 0x0, "Write register at index", HFILL}},
        {&hf_fiveco_regcall, {"Call function", "5co_rap.regcall", FT_NONE, BASE_NONE, NULL, 0x0, "Call function at index", HFILL}},
        {&hf_fiveco_routing, {"Routing to subdevice", "5co_rap.routing", FT_NONE, BASE_NONE, NULL, 0x0, "Frame to be routed to a sub device", HFILL}},
        {&hf_fiveco_routing_answer, {"Answer from subdevice", "5co_rap.routinganswer", FT_NONE, BASE_NONE, NULL, 0x0, "Answer from a subdevice", HFILL}},
        {&hf_fiveco_routing_interface, {"Interface", "5co_rap.routinginterface", FT_NONE, BASE_NONE, NULL, 0x0, "Device routing interface for sub device", HFILL}},
        {&hf_fiveco_routing_timeout, {"Timeout", "5co_rap.routingtimeout", FT_UINT8, BASE_HEX, NULL, 0x0, "Answer timeout from the sub device", HFILL}},
        {&hf_fiveco_routing_size, {"Size of frame to route", "5co_rap.routingsize", FT_NONE, BASE_NONE, NULL, 0x0, "Size of frame to be routed to a sub device", HFILL}},
        {&hf_fiveco_ext_regerror, {"Register access error", "5co_rap.regerror", FT_NONE, BASE_NONE, NULL, 0x0, "Error while accessing a register", HFILL}},
        {&hf_fiveco_ext_frameid, {"Frame ID", "5co_rap.frameid", FT_NONE, BASE_NONE, NULL, 0x0, "ID of the frame", HFILL}},
        {&hf_fiveco_ext_eof, {"End of frame", "5co_rap.eof", FT_NONE, BASE_NONE, NULL, 0x0, "End of the frame", HFILL}},
        {&hf_fiveco_cks, {"Checksum", "5co_rap.checksum", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "Checksum of the frame", HFILL}},
        {&hf_fiveco_ext_frameerror, {"Frame error", "5co_rap.frameerror", FT_NONE, BASE_NONE, NULL, 0x0, "Frame error occurred", HFILL}},
        {&hf_fiveco_ext_easyip, {"Easy IP configuration", "5co_rap.easyip", FT_NONE, BASE_NONE, NULL, 0x0, "Change IP config easily by broadcast", HFILL}},
        {&hf_fiveco_ext_easyip_version, {"Extension version", "5co_rap.easyipversion", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_ext_easyip_interface, {"Destination FRAP interface", "5co_rap.easyipinterface", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_ext_easyip_mac, {"Destination MAC address", "5co_rap.easyipmac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_ext_easyip_ip, {"New IP address", "5co_rap.easyipip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_ext_easyip_mask, {"New subnet mask", "5co_rap.easyipmask", FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL}},
        {&hf_fiveco_ext_unsupported, {"Unsupported function", "5co_rap.frameunsupported", FT_NONE, BASE_NONE, NULL, 0x0, "Function ignored by this dissector", HFILL}},
};

/*****************************************************************************/
/* Code to actually compute a data size                                      */
/* This function compute a datasize with from a packet.                      */
/* Data size in this protocol is one or more bytes based. Seven lower bits   */
/* are used for size and if higher bit is set, the next byte is also used and*/
/* so on until a byte with higher bit is not set.                            */
/*****************************************************************************/
static int
get_data_size(tvbuff_t *tvb, uint32_t first_index, uint32_t *p_header_len) {

    uint8_t size8;
    uint32_t data_size = 0;
    uint32_t max_len = MAX_LENGTH_BYTES + *p_header_len;
    uint32_t size_len = 0; // Length of size area minus 1

    for (; *p_header_len < max_len; (*p_header_len)++) {
        size8 = tvb_get_uint8(tvb, first_index + *p_header_len);
        if (size8 & 0x80) {
            data_size |= (size8 & 0x7F) << (7 * size_len);
            size_len++;
        } else {
            data_size |= size8 << (7 * size_len);
            (*p_header_len)++;
            break;
        }
    }
    return data_size;
}

/*****************************************************************************/
/* Code to dissect data from the packets                                     */
/* Recursive function !!                                                     */
/*****************************************************************************/
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_frame(tvbuff_t *tvb, packet_info* pinfo, proto_tree* fiveco_frame_tree, FCOSConvDevices *types_models_p,
                uint32_t frame_index, uint32_t frame_size, uint32_t *sub_index_p)
{
    uint8_t checksum_cal, checksum_rx;
    uint32_t i, j;
    uint8_t dest_addr;
    uint8_t source_addr;
    uint32_t data_size;
    uint32_t header_len;
    proto_item *fiveco_item = NULL;
    proto_item *fiveco_header_item = NULL;
    proto_item* fiveco_data_item = NULL;
    proto_item* fiveco_routing_item = NULL;
    proto_tree *fiveco_tree = NULL;
    proto_tree* fiveco_data_tree = NULL;
    proto_tree* fiveco_easyip_tree = NULL;
    proto_tree* fiveco_routing_details_tree = NULL;
    proto_tree* fiveco_routing_tree = NULL;
    uint8_t data_type;
    uint8_t reg_size;
    uint8_t reg_addr;
    char* sz_mac;
    char* sz_new_ip;
    uint8_t routing_interface;
    uint8_t routing_timeout;
    uint32_t routing_size;
    uint32_t routing_size_pos;
    uint32_t routing_header_len;

    /* Retrieve header info */
    dest_addr = tvb_get_uint8(tvb, frame_index + 0);
    source_addr = tvb_get_uint8(tvb, frame_index + 1);
    header_len = 2;
    data_size = get_data_size(tvb, frame_index, &header_len);
        /* If data size is null or greater than captured data, abort */
    if (data_size == 0)
        return 0;
    if (data_size > frame_size - frame_index - header_len) {
        return 0;
    }

    /* Compute checksum of the packet and read one received */
    checksum_cal = checksum_fiveco(tvb, frame_index, header_len + data_size - 1);
    checksum_rx = tvb_get_uint8(tvb, frame_index + header_len + data_size - 1);

    /* Add text to info column */
    /* If the offset != 0 (not first fiveco frame in tcp packet) add a comma in info column */
    if (frame_index != 0)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %d " UTF8_RIGHTWARDS_ARROW " %d Len=%d", source_addr, dest_addr, data_size);
    }
    else
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%d " UTF8_RIGHTWARDS_ARROW " %d Len=%d", source_addr, dest_addr, data_size);
    }

    if (checksum_rx != checksum_cal)
    {
        col_append_str(pinfo->cinfo, COL_INFO, " [BAD CHECKSUM !!]");
    }

    /* Add FiveCo protocol in tree (after TCP or UDP entry) */
    fiveco_item = proto_tree_add_item(fiveco_frame_tree, proto_FiveCoRAP, tvb, frame_index + 0,
                                    header_len + data_size, ENC_NA); /* Add a new entry inside tree display */
    proto_item_append_text(fiveco_item, ", Src Addr: %d, Dst Addr: %d, Len: %d", source_addr, dest_addr, data_size);

    /* Add fiveco Protocol tree and sub trees for Header, Data and Checksum */
    fiveco_tree = proto_item_add_subtree(fiveco_item, ett_fiveco[*sub_index_p]); // FiveCo prot tree
    fiveco_header_item = proto_tree_add_item(fiveco_tree, hf_fiveco_dest_addr,
                                                tvb, frame_index + 0, 1, ENC_NA);

    // Add destination address in the tree plus information about the device
    if (dest_addr == 0)
    {
        proto_item_append_text(fiveco_header_item, " Broadcast message");
    }
    if (types_models_p->device_type[*sub_index_p] != 0)
    {
        proto_item_append_text(fiveco_header_item, ", Detected device: %d.%d",
                                    (types_models_p->device_type[*sub_index_p]>>16),
                                    (types_models_p->device_type[*sub_index_p] & 0xFFFF));
    }
    if (types_models_p->device_version[*sub_index_p] != 0)
    {
        if (((types_models_p->device_version[*sub_index_p] & 0xFF000000) == 0) &&
                ((types_models_p->device_version[*sub_index_p] & 0x0000FF00) == 0))
            proto_item_append_text(fiveco_header_item, ", Version: %d.%d",
                                    (types_models_p->device_version[*sub_index_p]>>16),
                                    (types_models_p->device_version[*sub_index_p] & 0xFFFF));
        else
            proto_item_append_text(fiveco_header_item, ", Version: HW=%d.%d FW=%d.%d",
                                    (types_models_p->device_version[*sub_index_p]>>24) & 0xFF,
                                    (types_models_p->device_version[*sub_index_p]>>16) & 0xFF,
                                    (types_models_p->device_version[*sub_index_p]>>8) & 0xFF,
                                    (types_models_p->device_version[*sub_index_p] & 0xFF));
    }
    /*  Add source address in the tree */
    proto_tree_add_item(fiveco_tree, hf_fiveco_source_addr, tvb, frame_index + 1, 1, ENC_NA);
    /*  Add data length in the tree */
    fiveco_header_item = proto_tree_add_item(fiveco_tree, hf_fiveco_data, tvb, frame_index + header_len,
                                        data_size, ENC_NA);
    proto_item_append_text(fiveco_header_item, " (%d bytes)", data_size);
    /*  Add subtree for dissected data */
    fiveco_data_tree = proto_item_add_subtree(fiveco_header_item, ett_fiveco_data[*sub_index_p]);

    /*  Start data dissection */
    frame_index += header_len; /*  put offset on start of data (parameters) */

    for (i = frame_index; i < frame_index + data_size;)
    {
        /* Get type of next data */
        data_type = tvb_get_uint8(tvb, i);

        /* Handle data type (mask since only 3 high bits are relevant) */
        switch (data_type & 0xE0)
        {
            /* Handle read register command (data type = 0) */
            case READ_REGISTER:
                /* 5 lower bits give the register length between 0 and 31 */
                reg_size = data_type & 0x1F;
                /* Next byte give the register address */
                reg_addr = tvb_get_uint8(tvb, i + 1);
                /* Add read register entry in the tree including its name (if known) and size */
                fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regread, tvb,
                                        i, 2, ENC_NA);
                if ((reg_addr < array_length(registers_def)) && (registers_def[reg_addr].reg_size == reg_size))
                {
                    proto_item_append_text(fiveco_data_item, " 0x%.2X (Name: %s, Size: %d)",
                                                reg_addr, registers_def[reg_addr].name, reg_size);
                }
                else
                {
                    proto_item_append_text(fiveco_data_item, " 0x%.2X (Name: Unknown, Size: %d)",
                                                reg_addr, reg_size);
                }
                i += 2;
                break;

            /* Handle an answer to a read register command (data type = 32) */
            case READ_REGISTER_ANSWER:
                /* 5 lower bits give the register length between 0 and 31 */
                reg_size = data_type & 0x1F;
                /* Next byte give the register address */
                reg_addr = tvb_get_uint8(tvb, i + 1);

                /*  If type register is found, remember it into types_models_p list */
                if (reg_addr == 0x00)
                {
                    types_models_p->device_type[*sub_index_p] = tvb_get_uint32(tvb, i + 2, ENC_LITTLE_ENDIAN);
                }
                else if (reg_addr == 0x01)
                {
                    types_models_p->device_version[*sub_index_p] = tvb_get_uint32(tvb, i + 2, ENC_LITTLE_ENDIAN);
                }

                /* If register is in the registers_def array */
                if ((reg_addr < array_length(registers_def)) && (registers_def[reg_addr].reg_size == reg_size))
                {
                    /* If display type is not defined, display raw data manually */
                    if (registers_def[reg_addr].ft == FT_NONE)
                    {
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree,
                                                registers_def[reg_addr].hf_id_r_a,
                                                tvb, i+2, reg_size, registers_def[reg_addr].encoding);
                        proto_item_append_text(fiveco_data_item, ": ");
                        for (j = 0; j < reg_size; j++)
                        {
                            proto_item_append_text(fiveco_data_item, "%.2X ",
                                                tvb_get_uint8(tvb, i + 2 + j));
                        }
                    }
                    /* else display based on predefined type */
                    else {
                        proto_tree_add_item(fiveco_data_tree, registers_def[reg_addr].hf_id_r_a,
                                                tvb, i+2, reg_size, registers_def[reg_addr].encoding);
                    }
                }
                /*  else display raw data in hex manually */
                else
                {
                    fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regread_answer, tvb,
                        i, 2 + reg_size, ENC_NA);
                    proto_item_append_text(fiveco_data_item, " 0x%.2X (Name: Unknown, Size: %d): ",
                                                reg_addr, reg_size);
                    for (j = 0; j < reg_size; j++)
                    {
                        proto_item_append_text(fiveco_data_item, "%.2X ",
                                            tvb_get_uint8(tvb, i + 2 + j));
                    }
                }
                i += (2 + reg_size);
                break;
            /* Handle a write register command */
            case WRITE_REGISTER:
                /* 5 lower bits give the register length between 0 and 31 */
                reg_size = data_type & 0x1F;
                /* Next byte give the register address */
                reg_addr = tvb_get_uint8(tvb, i + 1);

                /* If register is in the registers_def array */
                if ((reg_addr < array_length(registers_def)) && (registers_def[reg_addr].reg_size == reg_size))
                {
                    /* If display type is not defined, display raw data manually (nothing for functions) */
                    if (registers_def[reg_addr].ft == FT_NONE)
                    {
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree,
                                                registers_def[reg_addr].hf_id_w,
                                                tvb, i+2, reg_size, registers_def[reg_addr].encoding);
                        /* Add data for register write */
                        if (registers_def[reg_addr].reg_type == REGISTER) {
                            proto_item_append_text(fiveco_data_item, ": ");
                            for (j = 0; j < reg_size; j++)
                            {
                                proto_item_append_text(fiveco_data_item, "0x%.2X ",
                                                    tvb_get_uint8(tvb, i + 2 + j));
                            }
                        }
                    }
                    /* else display based on predefined type */
                    else {
                        proto_tree_add_item(fiveco_data_tree, registers_def[reg_addr].hf_id_w,
                                                tvb, i+2, reg_size, registers_def[reg_addr].encoding);
                    }
                }
                /*  else display raw data in hex manually */
                else
                {
                    /* If size is > 0 then it is a write with data */
                    if (reg_size > 0) {
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regwrite, tvb,
                            i, 2 + reg_size, ENC_NA);
                        proto_item_append_text(fiveco_data_item, " 0x%.2X (Name: Unknown, Size: %d): ",
                                                    reg_addr, reg_size);
                        for (j = 0; j < reg_size; j++)
                        {
                            proto_item_append_text(fiveco_data_item, "%.2X ",
                                                tvb_get_uint8(tvb, i + 2 + j));
                        }
                    }
                    /* else it is a function call */
                    else {
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_regcall, tvb,
                            i, 2 + reg_size, ENC_NA);
                        proto_item_append_text(fiveco_data_item, " 0x%.2X (Name: Unknown, Size: %d)",
                                                    reg_addr, reg_size);
                    }
                }
                i += (2 + reg_size);
                break;

            case EXT_REGISTER_ACCESS_ERR:
                /* Handle extensions data type */
                switch (data_type)
                {
                    case EXT_REGISTER_ACCESS_ERR:
                        reg_addr = tvb_get_uint8(tvb, i + 1);
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_ext_regerror, tvb,
                                                i, 2, ENC_NA);
                        proto_item_append_text(fiveco_data_item, ": Index 0x%.2X", reg_addr);
                        i += 2;
                        break;

                    case EXT_FRAME_ID:
                    case EXT_FRAME_ID_ANSWER:
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_ext_frameid, tvb,
                                            i, 2, ENC_NA);
                        proto_item_append_text(fiveco_data_item, ": %d",
                                                    tvb_get_uint8(tvb, i + 1));
                        i += 2;
                        break;

                    case EXT_EOF:
                        proto_tree_add_item(fiveco_data_tree, hf_fiveco_ext_eof, tvb,
                                            i, 1, ENC_NA);
                        proto_tree_add_checksum(fiveco_tree, tvb, i + 1, hf_fiveco_cks, -1, NULL, NULL,
                            checksum_cal, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
                        i += 2;
                        break;

                    case EXT_FRAME_ERROR:
                        proto_tree_add_item(fiveco_data_tree, hf_fiveco_ext_frameerror, tvb,
                                                i, 1, ENC_NA);
                        i += 1;
                        break;
                    case EXT_EOF_MULTI_PACKETS:
                    case EXT_EOF_MULTI_PACKETS_END:
                        proto_tree_add_item(fiveco_data_tree, hf_fiveco_ext_unsupported, tvb,
                                                i, 2, ENC_NA);
                        i += 2;
                        break;
                    case EXT_EASY_IP_ADDRESS_CHANGE:
                        fiveco_data_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_ext_easyip, tvb,
                                                i, 17, ENC_NA);

                        sz_mac = tvb_ether_to_str(pinfo->pool, tvb, i+3);
                        sz_new_ip = tvb_ip_to_str(pinfo->pool, tvb, i+9);
                        proto_item_append_text(fiveco_data_item, ": New IP: %s for %s", sz_new_ip, sz_mac);
                        fiveco_easyip_tree = proto_item_add_subtree(fiveco_data_item, ett_fiveco_easyip[*sub_index_p]);
                        proto_tree_add_item(fiveco_easyip_tree, hf_fiveco_ext_easyip_version, tvb,
                                                i + 1, 1, ENC_NA);
                        proto_tree_add_item(fiveco_easyip_tree, hf_fiveco_ext_easyip_interface, tvb,
                                                i + 2, 1, ENC_NA);
                        proto_tree_add_item(fiveco_easyip_tree, hf_fiveco_ext_easyip_mac, tvb,
                                                i + 3, 6, ENC_NA);
                        proto_tree_add_item(fiveco_easyip_tree, hf_fiveco_ext_easyip_ip, tvb,
                                                i + 9, 4, ENC_NA);
                        proto_tree_add_item(fiveco_easyip_tree, hf_fiveco_ext_easyip_mask, tvb,
                                                i + 13, 4, ENC_NA);
                        i += 17;
                        break;

                    default:
                        /* If type is still unknown, stop handling the packet */
                        i = frame_index + data_size;
                        break;
                }
                break;

            default:
                /* Handle data type with 4 high bits relevant */
                switch (data_type & 0xF0)
                {
                    case SUBDEVICE_ROUTING:
                    case SUBDEVICE_ROUTING_ANSWER:
                        /* Handle routed frames by recursive call of this function */
                        routing_interface = (data_type & 0x0F);
                        if ((data_type & 0xF0) == SUBDEVICE_ROUTING)
                        {
                            routing_size_pos = 2;
                            routing_header_len = 2;
                            routing_size = get_data_size(tvb, i, &routing_header_len);
                            routing_timeout = tvb_get_uint8(tvb, i + 1);
                            fiveco_routing_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_routing, tvb,
                                                    i, routing_header_len + routing_size, ENC_NA);
                            proto_item_append_text(fiveco_routing_item, " (Interface: %d, Timeout: %d, Frame size: %d)",
                                                routing_interface, routing_timeout, routing_size);
                        }
                        else
                        {
                            routing_size_pos = 1;
                            routing_header_len = 1;
                            routing_size = get_data_size(tvb, i, &routing_header_len);
                            fiveco_routing_item = proto_tree_add_item(fiveco_data_tree, hf_fiveco_routing_answer, tvb,
                                                    i, routing_header_len + routing_size, ENC_NA);
                            proto_item_append_text(fiveco_routing_item, " (Interface: %d, Frame size: %d)",
                                                routing_interface, routing_size);
                        }

                        /* Recursive call !! */
                        if (*sub_index_p < (MAX_SUB_DEVICES-1)) {
                            (*sub_index_p)++;
                            fiveco_routing_details_tree = proto_item_add_subtree(fiveco_routing_item, ett_fiveco_sub_details[*sub_index_p]);
                            fiveco_data_item = proto_tree_add_item(fiveco_routing_details_tree, hf_fiveco_routing_interface, tvb, i, 1, ENC_NA);
                            proto_item_append_text(fiveco_data_item, " %d", routing_interface);
                            if ((data_type & 0xF0) == SUBDEVICE_ROUTING) {
                                proto_tree_add_item(fiveco_routing_details_tree, hf_fiveco_routing_timeout, tvb, i + 1, 1, ENC_LITTLE_ENDIAN);
                            }
                            fiveco_data_item = proto_tree_add_item(fiveco_routing_details_tree, hf_fiveco_routing_size, tvb,
                                                i + routing_size_pos, routing_header_len - routing_size_pos, ENC_NA);
                            proto_item_append_text(fiveco_data_item, " %d", routing_size);
                            i += routing_header_len;
                            fiveco_routing_tree = proto_item_add_subtree(fiveco_routing_item, ett_fiveco_sub[*sub_index_p]);
                            dissect_frame(tvb, pinfo, fiveco_routing_tree, types_models_p, i, frame_size, sub_index_p);
                        } else {
                            proto_item_append_text(fiveco_routing_item,
                                " Sub frame cannot be displayed because max number of subdevices that can be dissected is exceeded !");
                        }
                        i += routing_size;
                        break;
                    default :
                        /* If type is still unknown, stop handling the packet */
                        i = frame_index + data_size;
                        break;
                }
                break;
        }
    }

    return i;
}

/*****************************************************************************/
/* Code to actually dissect the packets                                      */
/* Callback function for reassembled packet                                  */
/*****************************************************************************/
static int
dissect_FiveCoRAP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint32_t i;
    uint32_t tcp_data_offset = 0;
    uint32_t tcp_data_length = 0;
    uint32_t sub_devices_count = 0;
    conversation_t *conversation;
    FCOSConvKey conversation_key, *new_conversation_key_p;
    FCOSConvDevices *types_models_p;
#ifdef DEBUG_5CORAP
    uint32_t types_models_count = 0;
#endif

    /* Load protocol payload length (including checksum) */
    tcp_data_length = tvb_captured_length(tvb);
    if (tcp_data_length < FIVECO_RAP_MIN_LENGTH) /*  Check checksum presence */
        return 0;

    /* Display fiveco in protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_FIVECO);
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Look for all future TCP conversations between the
     * requesting server and the FiveCo device using the
     * same src & dest addr and ports.
     */
    conversation = find_or_create_conversation(pinfo);
    conversation_key.conversation = conversation->conv_index;

    /* Retrieve current types/model structure of the conversation */
    types_models_p = (FCOSConvDevices *)g_hash_table_lookup(fiveco_types_models_hash, &conversation_key);
    if (!types_models_p)
    {
#ifdef DEBUG_5CORAP
        ws_message("Adding conversation %d in hash table", conversation_key.conversation);
#endif

        new_conversation_key_p = wmem_new(wmem_file_scope(), FCOSConvKey);
        *new_conversation_key_p = conversation_key;

        types_models_p = wmem_new(wmem_file_scope(), FCOSConvDevices);
        for (i = 0; i < MAX_SUB_DEVICES; i++)
        {
            types_models_p->device_type[i] = 0;  /*  Set device type of all (sub-)devices to unknown */
            types_models_p->device_version[i] = 0;  /*  Set device version of all (sub-)devices to unknown */
        }
        g_hash_table_insert(fiveco_types_models_hash, new_conversation_key_p, types_models_p);
    }
#ifdef DEBUG_5CORAP
    else
    {
        for (i = 0; i < MAX_SUB_DEVICES; i++)
        {
            if (types_models_p->device_type[i] != 0)
                types_models_count++;
        }
        ws_message("Found %d types/models in conversation %d from hash table",
                        types_models_count, conversation_key.conversation);
    }
#endif

    /* Loop because several fiveco packets can be present in one TCP packet */
    while (tcp_data_offset < tcp_data_length) {

        /* Handle data and jump to next packet if exists */
        tcp_data_offset = dissect_frame(tvb, pinfo, tree, types_models_p,
                                        tcp_data_offset, tcp_data_length, &sub_devices_count);
        if (tcp_data_offset == 0)   /* If no FRAP frame is found, abort */
            return 0;

    } /*while (tcp_data_offset < tcp_data_length) */

    return tvb_captured_length(tvb);
}

/*****************************************************************************/
/* This function returns the calculated checksum (IP based)                  */
/*****************************************************************************/
static uint8_t checksum_fiveco(tvbuff_t *byte_tab, uint16_t start_offset, uint16_t size)
{
	uint32_t sum			= 0;
    uint32_t i;

	for (i = 0; i < size; i++)
    {
        sum += tvb_get_uint8(byte_tab, start_offset + i);
    }

    return (uint8_t)(sum & 0xFF);
}

/*****************************************************************************/
/* Compute an unique hash value                                              */
/*****************************************************************************/
static unsigned fiveco_hash(const void *v)
{
    const FCOSConvKey *key = (const FCOSConvKey *)v;
    return key->conversation;
}

/*****************************************************************************/
/* Check hash equal                                                          */
/*****************************************************************************/
static int fiveco_hash_equal(const void *v, const void *w)
{
    const FCOSConvKey *v1 = (const FCOSConvKey *)v;
    const FCOSConvKey *v2 = (const FCOSConvKey *)w;

    return (v1->conversation == v2->conversation);
}

/*****************************************************************************/
/* Protocol initialization function                                          */
/*****************************************************************************/
static void fiveco_protocol_init(void)
{
    if (fiveco_types_models_hash)
        g_hash_table_destroy(fiveco_types_models_hash);
    fiveco_types_models_hash = g_hash_table_new(fiveco_hash, fiveco_hash_equal);
}

/*****************************************************************************/
/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
/*****************************************************************************/
void proto_register_FiveCoRAP(void)
{
    uint32_t i;

    /* Following variables are used to allocate string buffer to store
       name and abbreviations strings for the hf table  */
    wmem_strbuf_t* hf_name_read_answer_buf = NULL;
    wmem_strbuf_t* hf_name_write_buf = NULL;
    wmem_strbuf_t* hf_abbrev_read_answer_buf = NULL;
    wmem_strbuf_t* hf_abbrev_write_buf = NULL;

    /* Setup list of header fields (based on static table and specific table) */
    static hf_register_info hf[array_length(hf_base) + 2*array_length(registers_def)];
    for (i = 0; i < array_length(hf_base); i++) {
        hf[i] = hf_base[i];
    }

    for (i = 0; i < array_length(registers_def); i++) {

        /* Create string buffer for current row in registers_def */
        hf_name_read_answer_buf = wmem_strbuf_new(wmem_epan_scope(), "");
        hf_name_write_buf = wmem_strbuf_new(wmem_epan_scope(), "");
        hf_abbrev_read_answer_buf = wmem_strbuf_new(wmem_epan_scope(), "");
        hf_abbrev_write_buf = wmem_strbuf_new(wmem_epan_scope(), "");

        /* Construct read answer and write hf abbreviations for the current row in registers_def */
        wmem_strbuf_append_printf(hf_abbrev_read_answer_buf, "%s.readanswer", registers_def[i].abbrev);
        wmem_strbuf_append_printf(hf_abbrev_write_buf, "%s.write", registers_def[i].abbrev);

        /* Construct read answer and write hf name for the current row in registers_def */
        if (registers_def[i].reg_type == REGISTER) {
            wmem_strbuf_append_printf(hf_name_read_answer_buf, "Read answer register 0x%.2X (Name: %s, Size: %d)", i, registers_def[i].name, registers_def[i].reg_size);
            wmem_strbuf_append_printf(hf_name_write_buf, "Write register 0x%.2X (Name: %s, Size: %d)", i, registers_def[i].name, registers_def[i].reg_size);
        }
        else {
            wmem_strbuf_append_printf(hf_name_read_answer_buf, "Invalid read answer register 0x%.2X (Name: %s): A function cannot have a read answer", i, registers_def[i].name);
            wmem_strbuf_append_printf(hf_name_write_buf, "Call function 0x%.2X (Name: %s)", i, registers_def[i].name);
        }

        if (registers_def[i].cf_func != NULL) {
            hf_register_info hfxw = { &(registers_def[i].hf_id_w),{wmem_strbuf_get_str(hf_name_write_buf), wmem_strbuf_get_str(hf_abbrev_write_buf), registers_def[i].ft, registers_def[i].base, registers_def[i].cf_func, 0x0, NULL, HFILL} };
            hf[array_length(hf_base) + i] = hfxw;
            hf_register_info hfxra = { &(registers_def[i].hf_id_r_a),{wmem_strbuf_get_str(hf_name_read_answer_buf), wmem_strbuf_get_str(hf_abbrev_read_answer_buf), registers_def[i].ft, registers_def[i].base, registers_def[i].cf_func, 0x0, NULL, HFILL} };
            hf[array_length(hf_base) + array_length(registers_def) + i] = hfxra;
        }
        else {
            hf_register_info hfxw = { &(registers_def[i].hf_id_w),{wmem_strbuf_get_str(hf_name_write_buf), wmem_strbuf_get_str(hf_abbrev_write_buf), registers_def[i].ft, registers_def[i].base, NULL, 0x0, NULL, HFILL} };
            hf[array_length(hf_base) + i] = hfxw;
            hf_register_info hfxra = { &(registers_def[i].hf_id_r_a),{wmem_strbuf_get_str(hf_name_read_answer_buf), wmem_strbuf_get_str(hf_abbrev_read_answer_buf), registers_def[i].ft, registers_def[i].base, NULL, 0x0, NULL, HFILL} };
            hf[array_length(hf_base) + array_length(registers_def) + i] = hfxra;
        }
    }

    /* Setup protocol subtree array for each possible nested devices */
    static int *ett[5 * MAX_SUB_DEVICES];
    for (i = 0; i < MAX_SUB_DEVICES; i++)
    {
        ett[5*i + 0] = &ett_fiveco[i];
        ett[5*i + 1] = &ett_fiveco_data[i];
        ett[5*i + 2] = &ett_fiveco_easyip[i];
        ett[5*i + 3] = &ett_fiveco_sub[i];
        ett[5*i + 4] = &ett_fiveco_sub_details[i];
    }

    /* Register the dissector */
    /* Register the protocol name and description */
    proto_FiveCoRAP = proto_register_protocol("FiveCo RAP Register Access Protocol",
                                                 PROTO_TAG_FIVECO, "5co_rap");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_FiveCoRAP, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register hash init function
    * Protocol hash is used to follow types/models of devices in a conversation.
    */
    register_init_routine(&fiveco_protocol_init);

    /* Set preference callback to NULL since it is not used */
    prefs_register_protocol(proto_FiveCoRAP, NULL);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * Simpler form of proto_reg_handoff_FiveCoRAP which can be used if there are
 * no prefs-dependent registration function calls. */
void proto_reg_handoff_FiveCoRAP(void)
{
    static bool initialized = false;
    static dissector_handle_t FiveCoRAP_handle;

    if (!initialized)
    {
        /* Use create_dissector_handle() to indicate that
         * dissect_FiveCoRAP() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to PROTONAME).
         */
        FiveCoRAP_handle = create_dissector_handle(dissect_FiveCoRAP,
                                                   proto_FiveCoRAP);
        dissector_add_uint("tcp.port", FIVECO_TCP_PORT1, FiveCoRAP_handle);
        dissector_add_uint("udp.port", FIVECO_UDP_PORT1, FiveCoRAP_handle);
        initialized = true;
    }
}

/*****************************************************************************/
/* Registers decoding function                                               */
/*****************************************************************************/
static void
disp_type( char *result, uint32_t type)
{
    unsigned nValueH = (type>>16) & 0xFFFF;
    unsigned nValueL = (type & 0xFFFF);
    snprintf( result, ITEM_LABEL_LENGTH, "%u.%u (%.4X.%.4X)", nValueH, nValueL, nValueH, nValueL);
}

static void
disp_version( char *result, uint32_t version)
{
    if ((version & 0xFF000000) == 0)
    {
        unsigned nValueH = (version>>16) & 0xFFFF;
        unsigned nValueL = (version & 0xFFFF);
        snprintf( result, ITEM_LABEL_LENGTH, "FW: %u.%u", nValueH, nValueL);
    }
    else
    {
        unsigned nHWHigh = (version>>24) & 0xFF;
        unsigned nHWLow = (version>>16) & 0xFF;
        unsigned nFWHigh = (version>>8) & 0xFF;
        unsigned nFWLow = version & 0xFF;
        snprintf( result, ITEM_LABEL_LENGTH, "HW: %u.%u / FW: %u.%u", nHWHigh, nHWLow, nFWHigh, nFWLow);
    }
}

static void disp_voltage(char *result, uint32_t voltage)
{
    unsigned nValueH = (voltage>>16) & 0xFFFF;
    unsigned nValueL = (voltage & 0xFFFF);
    snprintf( result, ITEM_LABEL_LENGTH, "%u.%u V", nValueH, nValueL);
}

static void disp_mac( char *result, uint64_t mac)
{
    uint8_t *pData = (uint8_t*)(&mac);

    snprintf( result, ITEM_LABEL_LENGTH, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", pData[5], pData[4], pData[3], pData[2],
                           pData[1], pData[0]);
}

static void disp_ip( char *result, uint32_t ip)
{
    uint8_t *pData = (uint8_t*)(&ip);

    snprintf( result, ITEM_LABEL_LENGTH, "%u.%u.%u.%u", pData[3], pData[2], pData[1], pData[0]);
}

static void disp_mask( char *result, uint32_t mask)
{
    uint8_t *pData = (uint8_t*)(&mask);

    snprintf( result, ITEM_LABEL_LENGTH, "%u.%u.%u.%u", pData[3], pData[2], pData[1], pData[0]);
}

static void disp_timeout( char *result, uint32_t timeout)
{
    if (timeout != 0)
        snprintf( result, ITEM_LABEL_LENGTH, "%u%s",
                  timeout, unit_name_string_get_value(timeout, &units_second_seconds));
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
