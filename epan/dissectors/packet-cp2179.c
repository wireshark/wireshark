/* packet-cp2179.c
 * Routines for Communication Protocol 2179 (aka "Cooper 2179") Dissection
 * By Qiaoyin Yang (qiaoyin[DOT]yang[AT]gmail.com
 * Copyright 2014-2015,Schweitzer Engineering Laboratories
 *
 * Enhancements by Chris Bontje (cbontje<at>gmail<dot>com, Aug 2018
 ************************************************************************************************
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 ************************************************************************************************
CP2179 protocol is a serial based protocol. The 2179 protocol is implemented with minor variations between vendors.
The RTAC implemented the 2179 client supporting a limited function codes and command codes. The RTAC doesn't support
multiple function codes in a single request and the dissector also doesn't support decoding these or corresponding responses.
 * Dissector Notes:
 A brief explanation of how a request and response messages are formulated in 2179 protocol.
 The CP2179 request messages will follow the pattern below:
AA AA BB CC DD DD XX XX .... XX EE EE

A = 16-bit address field. The Most significant 5 bit is the Client address, the 11 bits for RTU address.
B = 8-bit Function code
C = 8-bit Command code
D = 16-bit Number of characters in the data field.
X = data field
E = 16-bit CRC

AA AA BB CC DD EE EE XX XX ... XX FF FF

A = 16-bit address field. The Most significant 5 bit is the Client address, the 11 bits for RTU address.
B = 8-bit Function code
C = 8-bit Status
D = 8-bit Port Status
E = 16-bit Number of characters
X = data field
F = 16-bit CRC
 ************************************************************************************************/

#include "config.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

void proto_reg_handoff_cp2179(void);
void proto_register_cp2179(void);

/* Message Length Constants */
#define CP2179_MIN_LENGTH                  7
#define RESPONSE_HEADER_SIZE               7  /*includes addr, addr, function, status, port status, number of characters */
#define BASIC_SCAN_REQ_LEN                 8
#define SPECIAL_CALC_REQ_ALL_LEN           8
#define SBO_OPERATE_REQ_LEN                8
#define SPECIAL_CALC_REQ_RANGE_LEN         9
#define SBO_SELECT_REQ_LEN                 9
#define SBO_OPERATE_REPLY_LEN              9
#define SBO_SELECT_REPLY_LEN               10

static bool cp2179_telnet_clean = true;

/* Message Types */
#define BASIC_SCAN_REQUEST                 1
#define BASIC_SCAN_RESPONSE                2
#define SPECIAL_CALC_REQUEST_ALL           3
#define SPECIAL_CALC_RESPONSE_ALL          4
#define SPECIAL_CALC_REQUEST_RANGE         5
#define SPECIAL_CALC_RESPONSE_RANGE        6
#define SPECIAL_CALC_RESPONSE              7
#define SCAN_INCLUSIVE_16_ANALOG_REQUEST   8
#define SCAN_INCLUSIVE_16_ANALOG_RESPONSE  9
#define SBO_SELECT_REQUEST                 10
#define SBO_SELECT_RESPONSE                11
#define SBO_OPERATE_REQUEST                12
#define SBO_OPERATE_RESPONSE               13
#define INIT_RTU_REQUEST                   14
#define INIT_RTU_RESPONSE                  15
#define RESET_ACC_REQUEST                  16
#define RESET_ACC_RESPONSE                 17
#define TIMETAG_INFO_REQUEST               18
#define TIMETAG_INFO_RESPONSE              19
#define RST_RESPONSE                       20

/* Message type Lookup */
static const value_string cp2179_messagetype_vals[] = {
{BASIC_SCAN_REQUEST,                    "Basic Scan Request"},
{BASIC_SCAN_RESPONSE,                   "Basic Scan Response"},
{SPECIAL_CALC_REQUEST_ALL,              "Special Calc Request All"},
{SPECIAL_CALC_RESPONSE_ALL,             "Special Calc Response All"},
{SPECIAL_CALC_REQUEST_RANGE,            "Special Calc Request a Range"},
{SPECIAL_CALC_RESPONSE_RANGE,           "Special Calc Response a Range"},
{SPECIAL_CALC_RESPONSE,                 "Special Calc Response"},
{SCAN_INCLUSIVE_16_ANALOG_REQUEST,      "Scan Inclusive Request"},
{SCAN_INCLUSIVE_16_ANALOG_RESPONSE,     "Scan Inclusive Response"},
{SBO_SELECT_REQUEST,                    "SBO Select Request"},
{SBO_SELECT_RESPONSE,                   "SBO Select Response"},
{SBO_OPERATE_REQUEST,                   "SBO Operate Request"},
{SBO_OPERATE_RESPONSE,                  "SBO Operate Response"},
{INIT_RTU_REQUEST,                      "INIT RTU Request"},
{INIT_RTU_RESPONSE,                     "INIT RTU Response"},
{RESET_ACC_REQUEST,                     "RESET Accumulator Request"},
{RESET_ACC_RESPONSE,                    "RESET Accumulator Response"},
{TIMETAG_INFO_REQUEST,                  "Time-Tagged Information Request"},
{TIMETAG_INFO_RESPONSE,                 "Time-Tagged Information Response"},
{RST_RESPONSE,                          "RST Response - Out of Sequence SBO"},
{ 0,                                    NULL }

};

static value_string_ext cp2179_messagetype_vals_ext = VALUE_STRING_EXT_INIT(cp2179_messagetype_vals);

/* List contains request data  */
typedef struct {
    wmem_list_t *request_frame_data;
} cp2179_conversation;

/* CP2179 function codes */
#define BASIC_SCAN                          0x00
#define SCAN_INCLUSIVE                      0x01
#define SCAN_FOR_SPECIAL_CALC               0x03
#define RETRIEVE_TIME_TAGGED_INFO           0x04   /* not supported by the RTAC */
#define SCAN_BY_TABLE                       0x0A
#define SUPERVISORY_CONTROL                 0x10
#define RTU_CONFIG                          0x20
#define RETURN_RTU_CONFIG                   0x25
#define REPORT_EXCEPTION_DATA               0x0D
#define RST_RESPONSE_CODE                   0x80

/* Function code Lookup */
static const value_string FunctionCodenames[] = {
{ BASIC_SCAN,                     "Basic Scan" },
{ SCAN_INCLUSIVE,                 "Scan Inclusive"},
{ SCAN_FOR_SPECIAL_CALC,          "Scan Floating Points" },
{ RETRIEVE_TIME_TAGGED_INFO,      "Retrieve Time Tagged Information" },
{ SCAN_BY_TABLE,                  "Scan by Table" },
{ SUPERVISORY_CONTROL,            "Supervisory Control" },
{ RTU_CONFIG,                     "RTU Internal Control" },
{ RETURN_RTU_CONFIG,              "Return RTU Config"},
{ REPORT_EXCEPTION_DATA,          "Report Exception data"},
{ RST_RESPONSE_CODE,              "RST Response"},
{ 0,                              NULL }
};

/* Function Code 0x00 (Basic Scan) Command Codes */
#define SIMPLE_STATUS_DATA                 0x01
#define ALWAYS_RESERVED                    0x02
#define TWO_BIT_STATUS                     0x04
#define ANALOG_16_BIT                      0x08
#define SS_AND_ANA16                       0x09
#define ACCUMULATOR_16_BIT                 0x40

/* Function Code 0x03 (Special Calc / Floating Point) Command Codes */
#define SPECIAL_CALC_ALL                   0x80
#define SPECIAL_CALC_RANGE                 0x00

/* Function Code 0x10 (Supervisory Control) Command Codes */
#define SBO_SELECT_OPEN                    0x10
#define SBO_SELECT_CLOSE                   0x11
#define SBO_OPERATE                        0x20

static const value_string cp2179_CommandCodeNames [] = {
{ SPECIAL_CALC_RANGE,             "Request a Range of Special Calc"},
{ SIMPLE_STATUS_DATA,             "Simple Status" },
{ ALWAYS_RESERVED,                "Reserved" },
{ TWO_BIT_STATUS,                 "2 Bit Data Status" },
{ ANALOG_16_BIT,                  "16 Bit Analog" },
{ SS_AND_ANA16,                   "Simple Status and 16-bit Analog" },
{ SBO_SELECT_OPEN,                "SBO Open" },
{ SBO_SELECT_CLOSE,               "SBO Close" },
{ SBO_OPERATE,                    "SBO Operate" },
{ ACCUMULATOR_16_BIT,             "16 Bit Pulsed Accumulator" },
{ SPECIAL_CALC_ALL,               "Request All Special Calc Data"},
{ 0,                              NULL }
};

static value_string_ext cp2179_CommandCodeNames_ext = VALUE_STRING_EXT_INIT(cp2179_CommandCodeNames);

/* Function Code 0x04 (Retrieve Time Tagged Information) Command Codes */
#define TIMETAG_INFO_RETRYLAST_SINGLEREC   0x00
#define TIMETAG_INFO_RETRYLAST_DUMP        0x20
#define TIMETAG_INFO_SINGLEREC             0x40
#define TIMETAG_INFO_DUMP                  0x60

static const value_string cp2179_FC04_CommandCodeNames [] = {
{ TIMETAG_INFO_RETRYLAST_SINGLEREC,         "Retransmit Last Single Record" },
{ TIMETAG_INFO_RETRYLAST_DUMP,              "Retransmit Last Dump All Records" },
{ TIMETAG_INFO_SINGLEREC,                   "Return Single Record" },
{ TIMETAG_INFO_DUMP,                        "Dump All Records" },
{ 0,                              NULL }
};


/* Function Code 0x20 (RTU Control) Command Codes */
#define INIT_RTU_CONFIGURATION             0x00
#define RESET_ACCUMULATOR                  0x11

/* Function Code 0x20 Command Code Lookup */
static const value_string cp2179_FC20_CommandCodeNames [] = {
{ INIT_RTU_CONFIGURATION,         "Initialize RTU Config" },
{ RESET_ACCUMULATOR,              "Accumulator Reset" },
{ 0,                              NULL }
};

/* Holds Request information required to later decode a response  */
typedef struct {
   uint32_t fnum;  /* frame number */
   uint16_t address_word;
   uint8_t  function_code;
   uint8_t  commmand_code;
   uint16_t numberofcharacters;
   uint8_t  *requested_points;
} request_frame;


static int proto_cp2179;

/* Initialize the subtree pointers */
static int ett_cp2179;
static int ett_cp2179_header;
static int ett_cp2179_addr;
static int ett_cp2179_fc;
static int ett_cp2179_data;
static int ett_cp2179_subdata;
static int ett_cp2179_event;

/* Initialize the protocol and registered fields */
static int hf_cp2179_request_frame;
static int hf_cp2179_rtu_address;
static int hf_cp2179_master_address;
static int hf_cp2179_function_code;
static int hf_cp2179_nop_flag;
static int hf_cp2179_rst_flag;
static int hf_cp2179_reserved;
static int hf_cp2179_command_code;
static int hf_cp2179_command_code_fc04;
static int hf_cp2179_command_code_fc20;
static int hf_cp2179_sbo_request_point;
static int hf_cp2179_resetacc_request_point;
static int hf_cp2179_speccalc_request_point;
static int hf_cp2179_scaninc_startreq_point;
static int hf_cp2179_scaninc_stopreq_point;
static int hf_cp2179_number_characters;
static int hf_cp2179_analog_16bit;
static int hf_cp2179_accumulator;
static int hf_cp2179_crc;
/* static int hf_cp2179_data_field; */
static int hf_cp2179_status_byte;
static int hf_cp2179_port_status_byte;
static int hf_cp2179_simplestatusbit;
static int hf_cp2179_simplestatusbit0;
static int hf_cp2179_simplestatusbit1;
static int hf_cp2179_simplestatusbit2;
static int hf_cp2179_simplestatusbit3;
static int hf_cp2179_simplestatusbit4;
static int hf_cp2179_simplestatusbit5;
static int hf_cp2179_simplestatusbit6;
static int hf_cp2179_simplestatusbit7;
static int hf_cp2179_simplestatusbit8;
static int hf_cp2179_simplestatusbit9;
static int hf_cp2179_simplestatusbit10;
static int hf_cp2179_simplestatusbit11;
static int hf_cp2179_simplestatusbit12;
static int hf_cp2179_simplestatusbit13;
static int hf_cp2179_simplestatusbit14;
static int hf_cp2179_simplestatusbit15;
static int hf_cp2179_specialcalc;
static int hf_cp2179_2bitstatus;
static int hf_cp2179_2bitstatuschg0;
static int hf_cp2179_2bitstatuschg1;
static int hf_cp2179_2bitstatuschg2;
static int hf_cp2179_2bitstatuschg3;
static int hf_cp2179_2bitstatuschg4;
static int hf_cp2179_2bitstatuschg5;
static int hf_cp2179_2bitstatuschg6;
static int hf_cp2179_2bitstatuschg7;
static int hf_cp2179_2bitstatusstatus0;
static int hf_cp2179_2bitstatusstatus1;
static int hf_cp2179_2bitstatusstatus2;
static int hf_cp2179_2bitstatusstatus3;
static int hf_cp2179_2bitstatusstatus4;
static int hf_cp2179_2bitstatusstatus5;
static int hf_cp2179_2bitstatusstatus6;
static int hf_cp2179_2bitstatusstatus7;
static int hf_cp2179_timetag_moredata;
static int hf_cp2179_timetag_numsets;
static int hf_cp2179_timetag_event_type;
static int hf_cp2179_timetag_event_date_hundreds;
static int hf_cp2179_timetag_event_date_tens;
static int hf_cp2179_timetag_event_hour;
static int hf_cp2179_timetag_event_minute;
static int hf_cp2179_timetag_event_second;


static dissector_handle_t cp2179_handle;

static int * const cp2179_simplestatus_bits[] = {
  &hf_cp2179_simplestatusbit0,
  &hf_cp2179_simplestatusbit1,
  &hf_cp2179_simplestatusbit2,
  &hf_cp2179_simplestatusbit3,
  &hf_cp2179_simplestatusbit4,
  &hf_cp2179_simplestatusbit5,
  &hf_cp2179_simplestatusbit6,
  &hf_cp2179_simplestatusbit7,
  &hf_cp2179_simplestatusbit8,
  &hf_cp2179_simplestatusbit9,
  &hf_cp2179_simplestatusbit10,
  &hf_cp2179_simplestatusbit11,
  &hf_cp2179_simplestatusbit12,
  &hf_cp2179_simplestatusbit13,
  &hf_cp2179_simplestatusbit14,
  &hf_cp2179_simplestatusbit15,
  NULL
};

static int * const cp2179_2bitstatus_bits[] = {
  &hf_cp2179_2bitstatuschg0,
  &hf_cp2179_2bitstatuschg1,
  &hf_cp2179_2bitstatuschg2,
  &hf_cp2179_2bitstatuschg3,
  &hf_cp2179_2bitstatuschg4,
  &hf_cp2179_2bitstatuschg5,
  &hf_cp2179_2bitstatuschg6,
  &hf_cp2179_2bitstatuschg7,
  &hf_cp2179_2bitstatusstatus0,
  &hf_cp2179_2bitstatusstatus1,
  &hf_cp2179_2bitstatusstatus2,
  &hf_cp2179_2bitstatusstatus3,
  &hf_cp2179_2bitstatusstatus4,
  &hf_cp2179_2bitstatusstatus5,
  &hf_cp2179_2bitstatusstatus6,
  &hf_cp2179_2bitstatusstatus7,
  NULL
};


/**********************************************************************************************************/
/* Clean all instances of 0xFFFF from Telnet payload to compensate for IAC control code (replace w/ 0xFF) */
/* Function Duplicated from packet-telnet.c (unescape_and_tvbuffify_telnet_option)                        */
/**********************************************************************************************************/
static tvbuff_t *
clean_telnet_iac(packet_info *pinfo, tvbuff_t *tvb, int offset, int len)
{
  tvbuff_t     *telnet_tvb;
  uint8_t      *buf;
  const uint8_t *spos;
  uint8_t      *dpos;
  int           skip_byte, len_remaining;

  spos=tvb_get_ptr(tvb, offset, len);
  buf = (uint8_t *)wmem_alloc(pinfo->pool, len);
  dpos = buf;
  skip_byte = 0;
  len_remaining = len;
  while(len_remaining > 0){

    /* Only analyze two sequential bytes of source tvb if we have at least two bytes left */
    if (len_remaining > 1) {
        /* If two sequential 0xFF's exist, increment skip_byte counter, decrement  */
        /* len_remaining by 2 and copy a single 0xFF to dest tvb. */
        if((spos[0]==0xff) && (spos[1]==0xff)){
            skip_byte++;
            len_remaining -= 2;
            *(dpos++) = 0xff;
            spos += 2;
            continue;
        }
    }
    /* If we only have a single byte left, or there were no sequential 0xFF's, copy byte from src tvb to dest tvb */
    *(dpos++) = *(spos++);
    len_remaining--;
  }
  telnet_tvb = tvb_new_child_real_data(tvb, buf, len-skip_byte, len-skip_byte);
  add_new_data_source(pinfo, telnet_tvb, "Processed Telnet Data");

  return telnet_tvb;
}

/******************************************************************************************************/
/* Code to Dissect Request frames */
/******************************************************************************************************/
static int
dissect_request_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, uint16_t message_type )
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_tree *cp2179_proto_tree = NULL;
    proto_tree *cp2179_addr_tree = NULL;
    proto_tree *cp2179_fc_tree = NULL;

    proto_item *cp2179_proto_item = NULL;

    uint8_t req_command_code = 0;
    uint8_t function_code = 0;

    uint16_t address_word = -1;
    uint16_t requestnumberofcharacters = 0;

    cp2179_proto_item = proto_tree_add_item(tree, proto_cp2179, tvb, 0, -1, ENC_NA);
    cp2179_proto_tree = proto_item_add_subtree(cp2179_proto_item, ett_cp2179_header);

    /* RTU & Master Address are encoded into a 16-bit word */
    address_word = tvb_get_letohs(tvb, offset);
    cp2179_addr_tree = proto_tree_add_subtree_format(cp2179_proto_tree, tvb, offset, 2, ett_cp2179_addr, NULL,
               "RTU Address: %d, Master Address: %d", (address_word & 0x7FF), ((address_word & 0xF800) >> 11) );

    proto_tree_add_item(cp2179_addr_tree, hf_cp2179_rtu_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cp2179_addr_tree, hf_cp2179_master_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Report the function code */
    function_code = tvb_get_uint8(tvb, offset) & 0x3f;
    cp2179_fc_tree = proto_tree_add_subtree_format(cp2179_proto_tree, tvb, offset, 1, ett_cp2179_fc, NULL,
               "Function Code: %s (0x%02x)", val_to_str_const(function_code, FunctionCodenames, "Unknown Function Code"), function_code);

    proto_tree_add_item(cp2179_fc_tree, hf_cp2179_function_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cp2179_fc_tree, hf_cp2179_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* The command-byte interpretation is dependent on the function code.  */
    switch(message_type)
    {
        case INIT_RTU_REQUEST:
        case RESET_ACC_REQUEST:
            proto_tree_add_item(cp2179_proto_tree,  hf_cp2179_command_code_fc20 , tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;

        case BASIC_SCAN_REQUEST:
        case SCAN_INCLUSIVE_16_ANALOG_REQUEST:
            req_command_code = tvb_get_uint8(tvb, offset);
            /* Update Info column with useful information of Command Code Type */
            col_append_fstr(pinfo->cinfo, COL_INFO, " [ %s ]", val_to_str_ext_const(req_command_code, &cp2179_CommandCodeNames_ext, "Unknown Command Code"));
            proto_tree_add_item(cp2179_proto_tree, hf_cp2179_command_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;

        case TIMETAG_INFO_REQUEST:
            proto_tree_add_item(cp2179_proto_tree,  hf_cp2179_command_code_fc04 , tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;

        default:
            proto_tree_add_item(cp2179_proto_tree, hf_cp2179_command_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
    }
    offset += 1;

    requestnumberofcharacters = tvb_get_letohs(tvb, 4);
    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_number_characters, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* If request number is greater than 0, there is data field present in the request */
    if ( requestnumberofcharacters > 0 ){
        /*Depends on the packet type, the data field should be dissect differently*/
        switch (message_type)
        {
            case SBO_SELECT_REQUEST:
                proto_tree_add_item(cp2179_proto_tree, hf_cp2179_sbo_request_point, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                break;

            /*Reset Accumulator request data field will always only has 1 byte. The Sequence ID of the Accumulator that it wants to reset*/
            case RESET_ACC_REQUEST:
                proto_tree_add_item(cp2179_proto_tree, hf_cp2179_resetacc_request_point, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                break;

            /* A special calculation that requests for a range of points will have a list of sequence ID of the Special Calculation points */
            case SPECIAL_CALC_REQUEST_RANGE:
                do{
                    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_speccalc_request_point, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                }while(tvb_reported_length_remaining(tvb, offset) > 2);
                break;

            /*Scan Inclusive will have a starting sequence ID and a ending sequence ID in the data field.*/
            case SCAN_INCLUSIVE_16_ANALOG_REQUEST:
                do{
                    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_scaninc_startreq_point, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_scaninc_stopreq_point, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }while(tvb_reported_length_remaining(tvb, offset) > 2);
                break;
        }
    }

    /* The last two bytes of the message are a 16-bit CRC */
    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_crc, tvb, offset, 2, ENC_BIG_ENDIAN);

    return tvb_reported_length(tvb);
}


/******************************************************************************************************/
/* Code to dissect Response frames  */
/******************************************************************************************************/
static int
dissect_response_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, uint16_t message_type)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *response_item = NULL;
    proto_item *cp2179_proto_item = NULL;
    proto_item *cp2179_subdata_item = NULL;

    proto_tree *cp2179_proto_tree = NULL;
    proto_tree *cp2179_addr_tree = NULL;
    proto_tree *cp2179_fc_tree = NULL;
    proto_tree *cp2179_data_tree = NULL;
    proto_tree *cp2179_event_tree = NULL;

    cp2179_conversation  *conv;
    uint32_t req_frame_num;
    uint16_t req_address_word;
    uint8_t req_command_code;
    bool request_found = false;
    request_frame *request_data;

    int analogtestvalue = 0;
    int analog16_num = 0;
    int point_num = 0;

    unsigned function_code;
    unsigned simplestatusseq = 0x30;

    uint16_t address_word = 0;
    uint16_t numberofcharacters = -1;

    float specialcalvalue = 0;

    int x, y, num_records = 0, recordsize = 0, num_values = 0;

    cp2179_proto_item = proto_tree_add_item(tree, proto_cp2179, tvb, 0, -1, ENC_NA);
    cp2179_proto_tree = proto_item_add_subtree(cp2179_proto_item, ett_cp2179_header);

    /* RTU & Master Address are encoded into a 16-bit word */
    address_word = tvb_get_letohs(tvb, offset);

    cp2179_addr_tree = proto_tree_add_subtree_format(cp2179_proto_tree, tvb, offset, 2, ett_cp2179_addr, NULL,
                   "RTU Address: %d, Master Address: %d", (address_word & 0x7FF), ((address_word & 0xF800) >> 11) );

    proto_tree_add_item(cp2179_addr_tree, hf_cp2179_rtu_address, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cp2179_addr_tree, hf_cp2179_master_address, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /*The response always echos the function code in request, except when the RTU can't perform the required function.
    It may set the NOP or RST bit. Bit 0 to bit 5 is the field for function codes. Bit 6 is NOP bit. Bit 7 is RST bit. */
    function_code = tvb_get_uint8(tvb, offset);

    cp2179_fc_tree = proto_tree_add_subtree_format(cp2179_proto_tree, tvb, offset, 1, ett_cp2179_fc, NULL,
               "Function Code: %s (0x%02x)", val_to_str_const(function_code, FunctionCodenames, "Unknown Function Code"), function_code);

    proto_tree_add_item(cp2179_fc_tree, hf_cp2179_function_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cp2179_fc_tree, hf_cp2179_nop_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cp2179_fc_tree, hf_cp2179_rst_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    offset += 1;

    /* Status Byte & Port Status */
    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_status_byte, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_port_status_byte, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Number of characters */
    numberofcharacters = tvb_get_letohs(tvb, 5);
    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_number_characters, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* get the conversation data */
    conv = (cp2179_conversation *)p_get_proto_data(wmem_file_scope(), pinfo, proto_cp2179, 0);

    if (conv) {
        wmem_list_frame_t *frame = wmem_list_head(conv->request_frame_data);
        /* Cycle through all logged instances of request frames, looking for request frame number that occurred immediately
           prior to current frame number that has a matching address word */
        while (frame && !request_found) {
            request_data = (request_frame *)wmem_list_frame_data(frame);
            req_frame_num = request_data->fnum;
            req_command_code = request_data->commmand_code;
            req_address_word = request_data->address_word;
                if ((pinfo->num > req_frame_num) && (req_address_word == address_word)) {
                    response_item = proto_tree_add_uint(cp2179_proto_tree, hf_cp2179_request_frame, tvb, 0, 0, req_frame_num);
                    proto_item_set_generated(response_item);
                    request_found = true;
                }
                frame = wmem_list_frame_next(frame);
        }

        if (request_found)
        {
            switch (message_type)
            {
                case SBO_SELECT_RESPONSE:
                case SBO_OPERATE_RESPONSE:
                case RESET_ACC_RESPONSE:
                case INIT_RTU_RESPONSE:

                    if ( numberofcharacters > 0 ){
                        /* Based on the message type, process the next byte differently */
                        if ( message_type == SBO_SELECT_RESPONSE ){
                            proto_tree_add_item(cp2179_proto_tree, hf_cp2179_sbo_request_point, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            offset += 1;
                        }
                        if ( message_type == RESET_ACC_RESPONSE ){
                            proto_tree_add_item(cp2179_proto_tree, hf_cp2179_resetacc_request_point, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            offset += 1;
                        }
                    }
                    break;

                case SPECIAL_CALC_RESPONSE:
                    /* Based on the command code from the corresponding request, dissect the data field differently.
                       If required a range of Special calculation, display the requested sequence ID and corresponding
                       values. The requested sequence number is obtained from the previous request frame.  */
                    cp2179_data_tree = proto_tree_add_subtree(cp2179_proto_tree, tvb, offset, numberofcharacters, ett_cp2179_data, NULL, "CP2179 Data Field");

                    if (req_command_code == SPECIAL_CALC_ALL ){
                        do{
                            specialcalvalue = tvb_get_letohieee_float(tvb, offset );
                            proto_tree_add_float_format(cp2179_data_tree, hf_cp2179_specialcalc, tvb, offset, 4, specialcalvalue,
                                "Special Calculation %u : %f", point_num, specialcalvalue);
                            point_num += 1;
                            offset += 4;
                        }while(tvb_reported_length_remaining(tvb, offset) > 2);
                    }
                    /*If it request all the special calculation data, dissect all of them and associated a sequence ID with it.*/
                    else if (req_command_code == SPECIAL_CALC_RANGE ){
                        do{
                            specialcalvalue = tvb_get_letohieee_float(tvb, offset );
                            proto_tree_add_float_format(cp2179_data_tree, hf_cp2179_specialcalc, tvb, offset, 4, specialcalvalue,
                                "Special Calculation %u : %f",  request_data->requested_points[point_num], specialcalvalue);
                            point_num += 1;
                            offset += 4;
                        }while(tvb_reported_length_remaining(tvb, offset) > 2);
                    }
                    break;

                case SCAN_INCLUSIVE_16_ANALOG_RESPONSE:

                    cp2179_data_tree = proto_tree_add_subtree(cp2179_proto_tree, tvb, offset, numberofcharacters, ett_cp2179_data, NULL, "CP2179 Data Field");

                    /* Update Info column with useful information of Command Code Type */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " [ %s ]", val_to_str_ext_const(req_command_code, &cp2179_CommandCodeNames_ext, "Unknown Command Code"));

                    /*Report the values of the requested SCAN inclusive data. To figure out which sequence ID the values in the response associated with,
                      we read the request_frame information and show the corresponding sequence ID of the data in response frame.*/
                    do{
                        analogtestvalue = tvb_get_letohis(tvb, offset);
                        proto_tree_add_int_format(cp2179_data_tree, hf_cp2179_analog_16bit, tvb, offset, 2, request_data->requested_points[point_num],
                                                   "Analog (16 bit) %u : %d",  request_data->requested_points[point_num], analogtestvalue);
                        point_num += 1;
                        offset += 2;
                    }while(tvb_reported_length_remaining(tvb, offset) > 2);

                    break;

                case BASIC_SCAN_RESPONSE:
                {
                    cp2179_data_tree = proto_tree_add_subtree(cp2179_proto_tree, tvb, offset, numberofcharacters, ett_cp2179_data, NULL, "CP2179 Data Field");

                    /* Update Info column with useful information of Command Code Type */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " [ %s ]", val_to_str_ext_const(req_command_code, &cp2179_CommandCodeNames_ext, "Unknown Command Code"));

                    switch (req_command_code)
                    {
                        /* Based the command code from the request frame, we dissect the response data differently.
                           For example, if the request packet has command byte as ANALOG_16_BIT, the
                           the data field in the response should be dissected as 16-bit signed integer(s). */
                        case ACCUMULATOR_16_BIT:
                            do{
                                analogtestvalue = tvb_get_letohs(tvb, offset);
                                proto_tree_add_uint_format(cp2179_data_tree, hf_cp2179_accumulator, tvb, offset, 2, analog16_num,
                                                           "Accumulator %u : %u", analog16_num, analogtestvalue);
                                analog16_num += 1;
                                offset += 2;
                            }while(tvb_reported_length_remaining(tvb, offset) > 2);

                            break;

                        case ANALOG_16_BIT:
                            do{
                                analogtestvalue = tvb_get_letohis(tvb, offset);
                                proto_tree_add_int_format(cp2179_data_tree, hf_cp2179_analog_16bit, tvb, offset, 2, analog16_num,
                                                           "Analog (16 bit) %u : %i", analog16_num, analogtestvalue);
                                analog16_num += 1;
                                offset += 2;
                            }while(tvb_reported_length_remaining(tvb, offset) > 2);

                            break;

                        case SIMPLE_STATUS_DATA:
                            do{
                                cp2179_subdata_item = proto_tree_add_bitmask(cp2179_data_tree, tvb, offset, hf_cp2179_simplestatusbit,
                                                       ett_cp2179_subdata, cp2179_simplestatus_bits, ENC_LITTLE_ENDIAN);
                                proto_item_set_text(cp2179_subdata_item, "Simple Status Point 0x%x", simplestatusseq);

                                simplestatusseq += 1;
                                offset += 2;
                            }while(tvb_reported_length_remaining(tvb, offset) > 2);

                            break;

                        case TWO_BIT_STATUS:
                            do{
                                cp2179_subdata_item = proto_tree_add_bitmask(cp2179_data_tree, tvb, offset, hf_cp2179_2bitstatus,
                                                       ett_cp2179_subdata, cp2179_2bitstatus_bits, ENC_LITTLE_ENDIAN);
                                proto_item_set_text(cp2179_subdata_item, "2 Bit Status Point 0x%x", simplestatusseq);

                                simplestatusseq += 1;
                                offset += 2;
                            }while(tvb_reported_length_remaining(tvb, offset) > 2);

                            break;
                    } /* end of command code switch */

                    break;

                } /* end of basic scan response switch */

                case TIMETAG_INFO_RESPONSE:
                {
                    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_timetag_moredata, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(cp2179_proto_tree, hf_cp2179_timetag_numsets, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                    num_records = tvb_get_uint8(tvb, offset) & 0x7F;
                    offset += 1;

                    if (num_records == 0 || numberofcharacters <= 1)
                        break;

                    recordsize = (numberofcharacters-1) / num_records;
                    num_values = (recordsize-6) / 2;      /* Determine how many 16-bit analog values are present in each event record */

                    for (x = 0; x < num_records; x++)
                    {
                        cp2179_event_tree = proto_tree_add_subtree_format(cp2179_proto_tree, tvb, offset, recordsize, ett_cp2179_event, NULL, "Event Record # %d", x+1);
                        proto_tree_add_item(cp2179_event_tree, hf_cp2179_timetag_event_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(cp2179_event_tree, hf_cp2179_timetag_event_date_hundreds, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(cp2179_event_tree, hf_cp2179_timetag_event_date_tens, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(cp2179_event_tree, hf_cp2179_timetag_event_hour, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(cp2179_event_tree, hf_cp2179_timetag_event_minute, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(cp2179_event_tree, hf_cp2179_timetag_event_second, tvb, offset+5, 1, ENC_LITTLE_ENDIAN);
                        offset += 6;

                        for (y = 0; y < num_values; y++)
                        {
                            analogtestvalue = tvb_get_letohis(tvb, offset);
                            proto_tree_add_int_format(cp2179_event_tree, hf_cp2179_analog_16bit, tvb, offset, 2, analogtestvalue,
                                                       "Analog Value (16 bit) %u : %d",  y+1, analogtestvalue);
                            offset += 2;
                        }
                    }
                    break;
                }
                break;

            } /* end of message type switch */

            proto_tree_add_item(cp2179_proto_tree, hf_cp2179_crc, tvb, offset, 2, ENC_BIG_ENDIAN);

        } /* request found */

    } /* conversation data found */

    if (!request_found) {
        proto_item_append_text(response_item, ", No Request found");
        return 0;
    }

    return tvb_reported_length(tvb);
}

/******************************************************************************************************/
/* Load Request information into bs request struct */
/******************************************************************************************************/
static request_frame* copy_request_frame(tvbuff_t *tvb  )
{
 /* Set up structures needed to add the protocol request and use it for dissecting response packet */
    unsigned offset = 0;
    uint8_t idx=0 ;
    request_frame *frame;
    uint16_t num_objects=0;

    /* get a new frame and initialize it */
    frame = wmem_new(wmem_file_scope(), request_frame);

    /* update the data within the structure frame */
    frame->address_word = tvb_get_letohs(tvb, offset); offset +=2;
    frame->function_code = tvb_get_uint8(tvb, offset); offset +=1;
    frame->commmand_code = tvb_get_uint8(tvb, offset); offset +=1;
    frame->numberofcharacters = tvb_get_letohs(tvb, offset);offset +=2;

    /*Keep track of the request data field in a request.
      Such as SCAN INCLUSIVE request contains a Start Sequence Number and an Ending Sequence Number. */
    if (frame->function_code == SCAN_INCLUSIVE) {
        uint8_t startpt, endpt;
        startpt = tvb_get_uint8(tvb, offset);
        endpt = tvb_get_uint8(tvb, offset+1);
        num_objects = (endpt - startpt) + 1;
        frame->requested_points = (uint8_t *)wmem_alloc(wmem_file_scope(), num_objects * sizeof(uint8_t));

        /* We have a range of 'request' points */
        for (idx = 0; idx < num_objects; idx++) {
            frame->requested_points[idx] = startpt;
            startpt++;
        }
        /* offset += 2; */
    }
    /* Get Details for all Requested Points */
    else {
        num_objects = frame->numberofcharacters;
        frame->requested_points = (uint8_t *)wmem_alloc(wmem_file_scope(), num_objects * sizeof(uint8_t));
        for (idx = 0; idx < num_objects; idx++) {
            frame->requested_points[idx] = tvb_get_uint8(tvb, offset);
            offset += 1;
        }

    }

    return frame;
}



/******************************************************************************************************/
/* Classify the different packet type  */
/******************************************************************************************************/
static int
classify_message_type(tvbuff_t *tvb)
{
    int message_type = -1;
    uint8_t function_code;
    uint8_t command_code;
    uint16_t requestnumberofcharacters = 0;
    uint16_t responsenumberofcharacters = 0;
    uint16_t message_length = 0;


    message_length = tvb_reported_length(tvb);

    /* The response always echos the function code from the request, except when the RTU can't perform the required function.
       It may set the NOP or RST bit. Bit 0 to bit 5 is the field for function codes. Bit 6 is NOP bit. Bit 7 is RST bit. */
    function_code = tvb_get_uint8(tvb, 2);
    command_code = tvb_get_uint8(tvb, 3);

    /* We still don't know what type of message this is, request or response                       */
    /* Get the 'number of characters' value, for both request frames (offset 4) and response frames (offset 5) */
    requestnumberofcharacters = tvb_get_letohs(tvb, 4);
    responsenumberofcharacters = tvb_get_letohs(tvb, 5);

    /* 2179 protocol messages do not have a flag that tells you whether it is a request or a response.
       Use various values within the message (function code, command code, message length) to determine this */
    switch (function_code ){
        /* Basic Scan Operation (Function code 0x00), supported by the RTAC */
        case BASIC_SCAN:
            /* Basic Scan Request Message */
            if ( (requestnumberofcharacters == 0) && (message_length == BASIC_SCAN_REQ_LEN) ) {
                message_type = BASIC_SCAN_REQUEST ;
            }
            /* Basic Scan Response Message */
            else if ( (responsenumberofcharacters > 0) && (message_length > BASIC_SCAN_REQ_LEN) ) {
                message_type = BASIC_SCAN_RESPONSE;
            }

            break;

        /* Supervisory Control (Function code 0x10), supported by the RTAC */
        case SUPERVISORY_CONTROL:
            /* SBO Select Request */
            if ( (requestnumberofcharacters == 1) && (message_length == SBO_SELECT_REQ_LEN) ) {
                message_type = SBO_SELECT_REQUEST;
            }
            /* SBO Select Response */
            else if ( (responsenumberofcharacters == 1) && (message_length == SBO_SELECT_REPLY_LEN) ) {
                message_type = SBO_SELECT_RESPONSE;
            }
            /* SBO Operate Request */
            else if (requestnumberofcharacters == 0) {
                if ( (message_length == SBO_OPERATE_REQ_LEN) && (command_code == SBO_OPERATE) ) {
                    message_type = SBO_OPERATE_REQUEST;
                }
            }
            /* SBO Operate Response */
            else if (responsenumberofcharacters == 0) {
                if (message_length == SBO_OPERATE_REPLY_LEN) {
                    message_type = SBO_OPERATE_RESPONSE;
                }
            }

            break;

        /* Scan for floating point (aka: special calculations) (Function code 0x03), supported by the RTAC */
        case SCAN_FOR_SPECIAL_CALC:
            /* Special Calc Request All */
            if ( (requestnumberofcharacters == 0) && (command_code == SPECIAL_CALC_ALL ) ) {
                message_type = SPECIAL_CALC_REQUEST_ALL;
            }
            /* Special Calc Request Range */
            else if ( (requestnumberofcharacters > 0) && (command_code == SPECIAL_CALC_RANGE ) ) {
                message_type = SPECIAL_CALC_REQUEST_RANGE;
            }
            /* Special Calc Response */
            else if ( (responsenumberofcharacters > 0) && (message_length == (responsenumberofcharacters + 9) ) ) {
                message_type = SPECIAL_CALC_RESPONSE;
            }

            break;

        /* Retrieve Time-tagged information (Function code 0x04), not supported by RTAC */
        case RETRIEVE_TIME_TAGGED_INFO:

            if (requestnumberofcharacters == 0) {
                message_type = TIMETAG_INFO_REQUEST;
            }
            else {
                message_type = TIMETAG_INFO_RESPONSE;
            }

            break;

        /* Scan Inclusive (Function Code 0x01), supported by the RTAC */
        case SCAN_INCLUSIVE:
            /* Scan Inclusive Response */
            if ( (responsenumberofcharacters > 0) ) {
                message_type = SCAN_INCLUSIVE_16_ANALOG_RESPONSE;
            }

            /* Scan Inclusive Request */
            if( (command_code == ANALOG_16_BIT) && (requestnumberofcharacters == 2) ) {
                message_type = SCAN_INCLUSIVE_16_ANALOG_REQUEST;
            }

            break;

        /* RTU Internal Control and Configuration (Function Code 0x20) */
        case RTU_CONFIG:
            if (responsenumberofcharacters == 0) {
                message_type = INIT_RTU_RESPONSE;
            }
            if ( (requestnumberofcharacters == 0) && (command_code == INIT_RTU_CONFIGURATION) ) {
                message_type = INIT_RTU_REQUEST;
            }

            if (responsenumberofcharacters == 1) {
                message_type = RESET_ACC_RESPONSE;
            }
            if ( (requestnumberofcharacters == 1) && (command_code == RESET_ACCUMULATOR) ) {
                message_type = RESET_ACC_REQUEST;
            }
            break;
        case RST_RESPONSE_CODE:
            message_type = RST_RESPONSE;
            break;
        default :
            message_type = -99;
            break;
    }

    return message_type;
}



/******************************************************************************************************/
/* Code to dissect CP2179 protocol packets */
/******************************************************************************************************/
static int
dissect_cp2179_pdu(tvbuff_t *cp2179_tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    int16_t message_type;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CP2179");
    col_clear(pinfo->cinfo,COL_INFO);

    message_type = classify_message_type(cp2179_tvb);
    /* set information for Information column for CP2179 */
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(message_type, &cp2179_messagetype_vals_ext, "Unknown Message Type"));

    if (!pinfo->fd->visited){
        conversation_t           *conversation = NULL;
        cp2179_conversation      *conv_data = NULL;

        /* Find a conversation, create a new if no one exists */
        conversation = find_or_create_conversation(pinfo);
        conv_data = (cp2179_conversation *)conversation_get_proto_data(conversation, proto_cp2179);

        if (conv_data == NULL){
           conv_data = wmem_new(wmem_file_scope(), cp2179_conversation);
           conv_data->request_frame_data = wmem_list_new(wmem_file_scope());
           conversation_add_proto_data(conversation, proto_cp2179, (void *)conv_data);
        }

        p_add_proto_data(wmem_file_scope(), pinfo, proto_cp2179, 0, conv_data);

        if ((message_type == BASIC_SCAN_REQUEST) || (message_type == SBO_SELECT_REQUEST)
           ||(message_type == SPECIAL_CALC_REQUEST_ALL)||(message_type == SBO_OPERATE_REQUEST)
           ||(message_type == SPECIAL_CALC_REQUEST_RANGE)||(message_type == INIT_RTU_REQUEST)
           ||(message_type == RESET_ACC_REQUEST)||(message_type == SCAN_INCLUSIVE_16_ANALOG_REQUEST)) {

            /*fill the request frame. It holds the request information, to be used later when dissecting the response. */
            request_frame    *frame_ptr = NULL;
            frame_ptr = copy_request_frame(cp2179_tvb);

            /*also hold the current frame number*/
            frame_ptr->fnum = pinfo->num;
            wmem_list_prepend(conv_data->request_frame_data, frame_ptr);
        }
    } /* !visited */

    if (tvb_reported_length_remaining(cp2179_tvb, offset) > 0){
        switch (message_type){
            case BASIC_SCAN_REQUEST:
            case TIMETAG_INFO_REQUEST:
            case SBO_SELECT_REQUEST:
            case SBO_OPERATE_REQUEST:
            case SPECIAL_CALC_REQUEST_ALL:
            case SPECIAL_CALC_REQUEST_RANGE:
            case SCAN_INCLUSIVE_16_ANALOG_REQUEST:
            case RESET_ACC_REQUEST:
            case INIT_RTU_REQUEST:
                dissect_request_frame(cp2179_tvb, tree, pinfo, offset, message_type);
                break;

            case BASIC_SCAN_RESPONSE:
            case TIMETAG_INFO_RESPONSE:
            case SBO_SELECT_RESPONSE:
            case SBO_OPERATE_RESPONSE:
            case SPECIAL_CALC_RESPONSE:
            case SCAN_INCLUSIVE_16_ANALOG_RESPONSE:
            case INIT_RTU_RESPONSE:
            case RESET_ACC_RESPONSE:
            case RST_RESPONSE:
                dissect_response_frame(cp2179_tvb, tree, pinfo, offset, message_type);
                break;
            default:
                break;
        } /* packet type */
    } /* length remaining */

    return tvb_reported_length(cp2179_tvb);
}


/******************************************************************************************************/
/* Dissect (and possibly Re-assemble) CP2179 protocol payload data */
/******************************************************************************************************/
static int
dissect_cp2179(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tvbuff_t *cp2179_tvb;
    int length = tvb_reported_length(tvb);

   /* Check for the packet length, a 2179 Message is at least 7 byte long*/
    if(length < CP2179_MIN_LENGTH){
        return 0;
    }

    if((pinfo->srcport) && cp2179_telnet_clean){
        cp2179_tvb = clean_telnet_iac(pinfo, tvb, 0, length);
    }
    else{
        cp2179_tvb = tvb_new_subset_length( tvb, 0, length);
    }

    dissect_cp2179_pdu(cp2179_tvb, pinfo, tree, data);

    return length;
}

void
proto_register_cp2179(void)
{
    static hf_register_info hf[] =
    {
        { &hf_cp2179_request_frame,
            { "Request Frame", "cp2179.request_frame",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_cp2179_rtu_address,
            { "RTU Address", "cp2179.RTUAddress",
            FT_UINT16, BASE_DEC,
            NULL, 0x07FF,
            NULL, HFILL }
        },

       { &hf_cp2179_master_address,
            { "Master Address", "cp2179.MasterAddress",
            FT_UINT16, BASE_DEC,
            NULL, 0xF800,
            NULL, HFILL }
        },
        { &hf_cp2179_function_code,
            { "Function Code", "cp2179.functioncode",
            FT_UINT8, BASE_HEX,
            VALS(FunctionCodenames), 0x3F,
            NULL, HFILL }
        },

        { &hf_cp2179_nop_flag,
            { "NOP Flag", "cp2179.nop_flag",
            FT_UINT8, BASE_DEC,
            NULL, 0x40,
            NULL, HFILL }
        },

        { &hf_cp2179_rst_flag,
            { "RST Flag", "cp2179.rst_flag",
            FT_UINT8, BASE_DEC,
            NULL, 0x80,
            NULL, HFILL }
        },

        { &hf_cp2179_reserved,
            { "Reserved Bits", "cp2179.Reserved",
            FT_UINT8, BASE_DEC,
            NULL, 0xC0,
            NULL, HFILL }
        },

        { &hf_cp2179_command_code,
            { "Command Code", "cp2179.commandcode",
            FT_UINT8, BASE_HEX,
            VALS(cp2179_CommandCodeNames), 0x0,
            NULL, HFILL }
        },

        { &hf_cp2179_command_code_fc04,
            { "Command Code (FC 0x04)", "cp2179.commandcode.fc04",
            FT_UINT8, BASE_HEX,
            VALS(cp2179_FC04_CommandCodeNames), 0x0,
            NULL, HFILL }
        },


        { &hf_cp2179_command_code_fc20,
            { "Command Code (FC 0x20)", "cp2179.commandcode.fc20",
            FT_UINT8, BASE_HEX,
            VALS(cp2179_FC20_CommandCodeNames), 0x0,
            NULL, HFILL }
        },
       { &hf_cp2179_status_byte,
            { "RTU Status", "cp2179.rtustatus",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
       { &hf_cp2179_port_status_byte,
            { "Port Status", "cp2179.portstatus",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
       { &hf_cp2179_sbo_request_point,
            { "SBO Request Point", "cp2179.sbo_requestpoint",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
       { &hf_cp2179_resetacc_request_point,
            { "Reset Accumulator Request Point", "cp2179.resetacc_requestpoint",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
       { &hf_cp2179_speccalc_request_point,
            { "Special Calc Request Point", "cp2179.speccalc_requestpoint",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
       { &hf_cp2179_scaninc_startreq_point,
            { "Start Request Point", "cp2179.scaninc_startreq_point",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
       { &hf_cp2179_scaninc_stopreq_point,
            { "Stop Request Point", "cp2179.scaninc_stopreq_point",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
      { &hf_cp2179_number_characters,
            { "Number of Characters", "cp2179.numberofcharacters",
            FT_UINT16, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
      { &hf_cp2179_crc,
            { "CRC", "cp2179.crc",
            FT_UINT16, BASE_HEX,
            0x0, 0x0,
            NULL, HFILL }
        },
#if 0
      { &hf_cp2179_data_field,
            { "Data Field", "cp2179.datafield",
            FT_UINT8, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },
#endif
      { &hf_cp2179_accumulator,
            { "Accumulator", "cp2179.accumulator",
            FT_UINT16, BASE_DEC,
            0x0, 0x0,
            NULL, HFILL }
        },

      { &hf_cp2179_specialcalc,
            { "Special Calc", "cp2179.specialcalc",
            FT_FLOAT, BASE_NONE,
            0x0, 0x0,
            NULL, HFILL }
        },

      { &hf_cp2179_analog_16bit,
         { "Analog 16-bit", "cp2179.analogdata",
         FT_INT16, BASE_DEC,
         0x0, 0x0,
         NULL, HFILL }
        },
      { &hf_cp2179_simplestatusbit,
         { "Simple Status Bit", "cp2179.simplestatusbit",
         FT_UINT16, BASE_HEX,
         NULL, 0x0,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit0,
         { "Simple Status bit 0", "cp2179.simplestatusbit0",
         FT_BOOLEAN, 16,
         NULL, 0x0001,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit1,
         { "Simple Status bit 1", "cp2179.simplestatusbit1",
         FT_BOOLEAN, 16,
         NULL, 0x0002,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit2,
         { "Simple Status bit 2", "cp2179.simplestatusbit2",
         FT_BOOLEAN, 16,
         NULL, 0x0004,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit3,
         { "Simple Status bit 3", "cp2179.simplestatusbit3",
         FT_BOOLEAN, 16,
         NULL, 0x0008,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit4,
         { "Simple Status bit 4", "cp2179.simplestatusbit4",
         FT_BOOLEAN, 16,
         NULL, 0x0010,
         NULL, HFILL }
      },

      { &hf_cp2179_simplestatusbit5,
         { "Simple Status bit 5", "cp2179.simplestatusbit5",
         FT_BOOLEAN, 16,
         NULL, 0x0020,
         NULL, HFILL }
      },

      { &hf_cp2179_simplestatusbit6,
         { "Simple Status bit 6", "cp2179.simplestatusbit6",
         FT_BOOLEAN, 16,
         NULL, 0x0040,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit7,
         { "Simple Status bit 7", "cp2179.simplestatusbit7",
         FT_BOOLEAN, 16,
         NULL, 0x0080,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit8,
         { "Simple Status bit 8", "cp2179.simplestatusbit8",
         FT_BOOLEAN, 16,
         NULL, 0x0100,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit9,
         { "Simple Status bit 9", "cp2179.simplestatusbit9",
         FT_BOOLEAN, 16,
         NULL, 0x0200,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit10,
         { "Simple Status bit 10", "cp2179.simplestatusbit10",
         FT_BOOLEAN, 16,
         NULL, 0x0400,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit11,
         { "Simple Status bit 11", "cp2179.simplestatusbit11",
         FT_BOOLEAN, 16,
         NULL, 0x0800,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit12,
         { "Simple Status bit 12", "cp2179.simplestatusbit12",
         FT_BOOLEAN, 16,
         NULL, 0x1000,
         NULL, HFILL }
      },
      { &hf_cp2179_simplestatusbit13,
         { "Simple Status bit 13", "cp2179.simplestatusbit13",
         FT_BOOLEAN, 16,
         NULL, 0x2000,
         NULL, HFILL }
      },

      { &hf_cp2179_simplestatusbit14,
         { "Simple Status bit 14", "cp2179.simplestatusbit14",
         FT_BOOLEAN, 16,
         NULL, 0x4000,
         NULL, HFILL }
      },

      { &hf_cp2179_simplestatusbit15,
         { "Simple Status bit 15", "cp2179.simplestatusbit15",
         FT_BOOLEAN, 16,
         NULL, 0x8000,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatus,
         { "2 Bit Status", "cp2179.twobitstatus",
         FT_UINT16, BASE_HEX,
         NULL, 0x0,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatuschg0,
         { "2 Bit Status Change 0", "cp2179.twobitstatuschg0",
         FT_BOOLEAN, 16,
         NULL, 0x0001,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatuschg1,
         { "2 Bit Status Change 1", "cp2179.twobitstatuschg1",
         FT_BOOLEAN, 16,
         NULL, 0x0002,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatuschg2,
         { "2 Bit Status Change 2", "cp2179.twobitstatuschg2",
         FT_BOOLEAN, 16,
         NULL, 0x0004,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatuschg3,
         { "2 Bit Status Change 3", "cp2179.twobitstatuschg3",
         FT_BOOLEAN, 16,
         NULL, 0x0008,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatuschg4,
         { "2 Bit Status Change 4", "cp2179.twobitstatuschg4",
         FT_BOOLEAN, 16,
         NULL, 0x0010,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatuschg5,
         { "2 Bit Status Change 5", "cp2179.twobitstatuschg5",
         FT_BOOLEAN, 16,
         NULL, 0x0020,
         NULL, HFILL }
      },

      { &hf_cp2179_2bitstatuschg6,
         { "2 Bit Status Change 6", "cp2179.twobitstatuschg6",
         FT_BOOLEAN, 16,
         NULL, 0x0040,
         NULL, HFILL }
      },

      { &hf_cp2179_2bitstatuschg7,
         {  "2 Bit Status Change 7", "cp2179.twobitstatuschg7",
         FT_BOOLEAN, 16,
         NULL, 0x0080,
         NULL, HFILL }
      },

      { &hf_cp2179_2bitstatusstatus0,
         { "2 Bit Status bit 0", "cp2179.twobitstatusbit0",
         FT_BOOLEAN, 16,
         NULL, 0x0100,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatusstatus1,
         { "2 Bit Status bit 1", "cp2179.twobitstatusbit1",
         FT_BOOLEAN, 16,
         NULL, 0x0200,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatusstatus2,
         { "2 Bit Status bit 2", "cp2179.twobitstatusbit2",
         FT_BOOLEAN, 16,
         NULL, 0x0400,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatusstatus3,
         { "2 Bit Status bit 3", "cp2179.twobitstatusbit3",
         FT_BOOLEAN, 16,
         NULL, 0x0800,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatusstatus4,
         { "2 Bit Status bit 4", "cp2179.twobitstatusbit4",
         FT_BOOLEAN, 16,
         NULL, 0x1000,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatusstatus5,
         { "2 Bit Status bit 5", "cp2179.twobitstatusbit5",
         FT_BOOLEAN, 16,
         NULL, 0x2000,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatusstatus6,
         { "2 Bit Status bit 6", "cp2179.twobitstatusbit6",
         FT_BOOLEAN, 16,
         NULL, 0x4000,
         NULL, HFILL }
      },
      { &hf_cp2179_2bitstatusstatus7,
         { "2 Bit Status bit 7", "cp2179.twobitstatusbit7",
         FT_BOOLEAN, 16,
         NULL, 0x8000,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_moredata,
         { "Additional Records Available", "cp2179.timetag.moredata",
         FT_UINT8, BASE_DEC,
         NULL, 0x80,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_numsets,
         { "Number of Sets", "cp2179.timetag.numsets",
         FT_UINT8, BASE_DEC,
         NULL, 0x7F,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_event_type,
         { "Event Type", "cp2179.timetag.event.type",
         FT_UINT8, BASE_DEC,
         NULL, 0x0,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_event_date_hundreds,
         { "Julian Date (Hundreds)", "cp2179.timetag.event.date.hundreds",
         FT_UINT8, BASE_DEC,
         NULL, 0x0F,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_event_date_tens,
         { "Julian Date (Tens)", "cp2179.timetag.event.date.tens",
         FT_UINT8, BASE_DEC,
         NULL, 0x0,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_event_hour,
         { "Hour", "cp2179.timetag.event.hour",
         FT_UINT8, BASE_DEC,
         NULL, 0x0,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_event_minute,
         { "Minute", "cp2179.timetag.event.minute",
         FT_UINT8, BASE_DEC,
         NULL, 0x0,
         NULL, HFILL }
      },
      { &hf_cp2179_timetag_event_second,
         { "Second", "cp2179.timetag.event.second",
         FT_UINT8, BASE_DEC,
         NULL, 0x0,
         NULL, HFILL }
      }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
      &ett_cp2179,
      &ett_cp2179_header,
      &ett_cp2179_addr,
      &ett_cp2179_fc,
      &ett_cp2179_data,
      &ett_cp2179_subdata,
      &ett_cp2179_event

    };

    module_t *cp2179_module;

    proto_cp2179 = proto_register_protocol ("CP2179 Protocol", "CP2179", "cp2179");
    cp2179_handle = register_dissector("cp2179", dissect_cp2179, proto_cp2179);
    proto_register_field_array(proto_cp2179, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register required preferences for CP2179 Encapsulated-over-TCP decoding */
    cp2179_module = prefs_register_protocol(proto_cp2179, NULL);

    /* Telnet protocol IAC (0xFF) processing; defaults to true to allow Telnet Encapsulated Data */
    prefs_register_bool_preference(cp2179_module, "telnetclean",
                                  "Remove extra 0xFF (IAC) bytes from Telnet-encapsulated data",
                                  "Whether the SEL Protocol dissector should automatically pre-process Telnet data to remove IAC bytes",
                                  &cp2179_telnet_clean);


}


void
proto_reg_handoff_cp2179(void)
{
    dissector_add_for_decode_as_with_preference("tcp.port", cp2179_handle);
    dissector_add_for_decode_as("rtacser.data", cp2179_handle);
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
