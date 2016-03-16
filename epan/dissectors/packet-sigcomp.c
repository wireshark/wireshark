/* packet-sigcomp.c
 * Routines for Signaling Compression (SigComp) dissection.
 * Copyright 2004-2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * References:
 * http://www.ietf.org/rfc/rfc3320.txt?number=3320
 * http://www.ietf.org/rfc/rfc3321.txt?number=3321
 * http://www.ietf.org/rfc/rfc4077.txt?number=4077
 * Useful links :
 * https://tools.ietf.org/html/draft-ietf-rohc-sigcomp-impl-guide-10
 * http://www.ietf.org/archive/id/draft-ietf-rohc-sigcomp-sip-01.txt
 */

#include "config.h"

#include <math.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/exceptions.h>

#include <wsutil/sha1.h>
#include <wsutil/crc16.h>

void proto_register_sigcomp(void);
void proto_reg_handoff_sigcomp(void);

/* Initialize the protocol and registered fields */
static int proto_sigcomp                            = -1;
static int proto_raw_sigcomp                        = -1;
static int hf_sigcomp_t_bit                         = -1;
static int hf_sigcomp_len                           = -1;
static int hf_sigcomp_returned_feedback_item        = -1;
static int hf_sigcomp_returned_feedback_item_len    = -1;
static int hf_sigcomp_code_len                      = -1;
static int hf_sigcomp_destination                   = -1;
static int hf_sigcomp_partial_state                 = -1;
static int hf_sigcomp_remaining_message_bytes       = -1;
static int hf_sigcomp_compression_ratio             = -1;
static int hf_sigcomp_udvm_bytecode                 = -1;
static int hf_sigcomp_udvm_instr                    = -1;
static int hf_udvm_multitype_bytecode               = -1;
static int hf_udvm_reference_bytecode               = -1;
static int hf_udvm_literal_bytecode                 = -1;
/* static int hf_udvm_operand                          = -1; */
static int hf_udvm_length                           = -1;
static int hf_udvm_addr_length                      = -1;
static int hf_udvm_destination                      = -1;
static int hf_udvm_addr_destination                 = -1;
static int hf_udvm_at_address                       = -1;
static int hf_udvm_address                          = -1;
static int hf_udvm_literal_num                      = -1;
static int hf_udvm_value                            = -1;
static int hf_udvm_addr_value                       = -1;
static int hf_partial_identifier_start              = -1;
static int hf_partial_identifier_length             = -1;
static int hf_state_begin                           = -1;
static int hf_udvm_state_length                     = -1;
static int hf_udvm_state_length_addr                = -1;
static int hf_udvm_state_address                    = -1;
static int hf_udvm_state_address_addr               = -1;
static int hf_udvm_state_instr                      = -1;
static int hf_udvm_operand_1                        = -1;
static int hf_udvm_operand_2                        = -1;
static int hf_udvm_operand_2_addr                   = -1;
static int hf_udvm_j                                = -1;
static int hf_udvm_addr_j                           = -1;
static int hf_udvm_output_start                     = -1;
static int hf_udvm_addr_output_start                = -1;
static int hf_udvm_output_length                    = -1;
static int hf_udvm_output_length_addr               = -1;
static int hf_udvm_req_feedback_loc                 = -1;
static int hf_udvm_min_acc_len                      = -1;
static int hf_udvm_state_ret_pri                    = -1;
static int hf_udvm_ret_param_loc                    = -1;
static int hf_udvm_position                         = -1;
static int hf_udvm_ref_dest                         = -1;
static int hf_udvm_bits                             = -1;
static int hf_udvm_lower_bound                      = -1;
static int hf_udvm_upper_bound                      = -1;
static int hf_udvm_uncompressed                     = -1;
static int hf_udvm_offset                           = -1;
static int hf_udvm_addr_offset                      = -1;
static int hf_udvm_start_value                      = -1;
static int hf_udvm_execution_trace                  = -1;
static int hf_sigcomp_nack_ver                      = -1;
static int hf_sigcomp_nack_reason_code              = -1;
static int hf_sigcomp_nack_failed_op_code           = -1;
static int hf_sigcomp_nack_pc                       = -1;
static int hf_sigcomp_nack_sha1                     = -1;
static int hf_sigcomp_nack_state_id                 = -1;
static int hf_sigcomp_nack_memory_size              = -1;
static int hf_sigcomp_nack_cycles_per_bit           = -1;
static int hf_sigcomp_decompress_instruction        = -1;
static int hf_sigcomp_loading_result                = -1;
static int hf_sigcomp_byte_copy                     = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_sigcomp_accessing_state = -1;
static int hf_sigcomp_getting_value = -1;
static int hf_sigcomp_load_bytecode_into_udvm_start = -1;
static int hf_sigcomp_instruction_code = -1;
static int hf_sigcomp_current_instruction = -1;
static int hf_sigcomp_decompression_failure = -1;
static int hf_sigcomp_wireshark_udvm_diagnostic = -1;
static int hf_sigcomp_calculated_sha_1 = -1;
static int hf_sigcomp_copying_value = -1;
static int hf_sigcomp_storing_value = -1;
static int hf_sigcomp_loading_value = -1;
static int hf_sigcomp_set_hu = -1;
static int hf_sigcomp_loading_h = -1;
static int hf_sigcomp_state_value = -1;
static int hf_sigcomp_output_value = -1;
static int hf_sigcomp_num_state_create = -1;
static int hf_sigcomp_sha1_digest = -1;
static int hf_sigcomp_creating_state = -1;
static int hf_sigcomp_sigcomp_message_decompressed = -1;
static int hf_sigcomp_starting_to_remove_escape_digits = -1;
static int hf_sigcomp_escape_digit_found = -1;
static int hf_sigcomp_illegal_escape_code = -1;
static int hf_sigcomp_end_of_sigcomp_message_indication_found = -1;
static int hf_sigcomp_addr_value = -1;
static int hf_sigcomp_copying_bytes_literally = -1;
static int hf_sigcomp_data_for_sigcomp_dissector = -1;
static int hf_sigcomp_remaining_sigcomp_message = -1;
static int hf_sigcomp_sha1buff = -1;
static int hf_sigcomp_udvm_instruction = -1;
static int hf_sigcomp_remaining_bytes = -1;
static int hf_sigcomp_max_udvm_cycles = -1;
static int hf_sigcomp_used_udvm_cycles = -1;
static int hf_sigcomp_udvm_execution_stated = -1;
static int hf_sigcomp_message_length = -1;
static int hf_sigcomp_byte_code_length = -1;


/* Initialize the subtree pointers */
static gint ett_sigcomp             = -1;
static gint ett_sigcomp_udvm        = -1;
static gint ett_sigcomp_udvm_exe    = -1;
static gint ett_raw_text            = -1;

static expert_field ei_sigcomp_nack_failed_op_code = EI_INIT;
static expert_field ei_sigcomp_invalid_instruction = EI_INIT;
/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_sigcomp_tcp_fragment = EI_INIT;
static expert_field ei_sigcomp_decompression_failure = EI_INIT;
static expert_field ei_sigcomp_failed_to_access_state_wireshark_udvm_diagnostic = EI_INIT;
static expert_field ei_sigcomp_all_remaining_parameters_zero = EI_INIT;
static expert_field ei_sigcomp_sigcomp_message_decompression_failure = EI_INIT;
static expert_field ei_sigcomp_execution_of_this_instruction_is_not_implemented = EI_INIT;

static dissector_handle_t sip_handle;
/* set the udp ports */
static guint SigCompUDPPort1 = 5555;
static guint SigCompUDPPort2 = 6666;

/* set the tcp ports */
static guint SigCompTCPPort1 = 5555;
static guint SigCompTCPPort2 = 6666;

/* Default preference whether to display the bytecode in UDVM operands or not */
static gboolean display_udvm_bytecode = FALSE;
/* Default preference whether to dissect the UDVM code or not */
static gboolean dissect_udvm_code = TRUE;
static gboolean display_raw_txt = FALSE;
/* Default preference whether to decompress the message or not */
static gboolean decompress = TRUE;
/* Default preference whether to print debug info at execution of UDVM
 * 0 = No printout
 * 1 = details level 1
 * 2 = details level 2
 * 3 = details level 3
 * 4 = details level 4
 */
static gint udvm_print_detail_level = 0;

/* Value strings */
static const value_string length_encoding_vals[] = {
    { 0x00, "No partial state (Message type 2)" },
    { 0x01, "(6 bytes)" },
    { 0x02, "(9 bytes)" },
    { 0x03, "(12 bytes)" },
    { 0,    NULL }
};


static const value_string destination_address_encoding_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "128" },
    { 0x02, "192" },
    { 0x03, "256" },
    { 0x04, "320" },
    { 0x05, "384" },
    { 0x06, "448" },
    { 0x07, "512" },
    { 0x08, "576" },
    { 0x09, "640" },
    { 0x0a, "704" },
    { 0x0b, "768" },
    { 0x0c, "832" },
    { 0x0d, "896" },
    { 0x0e, "960" },
    { 0x0F, "1024" },
    { 0,    NULL }
};
static value_string_ext destination_address_encoding_vals_ext =
    VALUE_STRING_EXT_INIT(destination_address_encoding_vals);

    /* RFC3320
     * Figure 10: Bytecode for a multitype (%) operand
     * Bytecode:                       Operand value:      Range:               HEX val
     * 00nnnnnn                        N                   0 - 63               0x00
     * 01nnnnnn                        memory[2 * N]       0 - 65535            0x40
     * 1000011n                        2 ^ (N + 6)        64 , 128              0x86
     * 10001nnn                        2 ^ (N + 8)    256 , ... , 32768         0x88
     * 111nnnnn                        N + 65504       65504 - 65535            0xe0
     * 1001nnnn nnnnnnnn               N + 61440       61440 - 65535            0x90
     * 101nnnnn nnnnnnnn               N                   0 - 8191             0xa0
     * 110nnnnn nnnnnnnn               memory[N]           0 - 65535            0xc0
     * 10000000 nnnnnnnn nnnnnnnn      N                   0 - 65535            0x80
     * 10000001 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535            0x81
     */

static const value_string display_bytecode_vals[] = {
    { 0x00, "00nnnnnn, N, 0 - 63" },
    { 0x40, "01nnnnnn, memory[2 * N],0 - 65535" },
    { 0x86, "1000011n, 2 ^ (N + 6), 64 , 128" },
    { 0x88, "10001nnn, 2 ^ (N + 8), 256,..., 32768" },
    { 0xe0, "111nnnnn N + 65504, 65504 - 65535" },
    { 0x90, "1001nnnn nnnnnnnn, N + 61440, 61440 - 65535" },
    { 0xa0, "101nnnnn nnnnnnnn, N, 0 - 8191" },
    { 0xc0, "110nnnnn nnnnnnnn, memory[N], 0 - 65535" },
    { 0x80, "10000000 nnnnnnnn nnnnnnnn, N, 0 - 65535" },
    { 0x81, "10000001 nnnnnnnn nnnnnnnn, memory[N], 0 - 65535" },
    { 0,    NULL }
};
/* RFC3320
 * 0nnnnnnn                        memory[2 * N]       0 - 65535
 * 10nnnnnn nnnnnnnn               memory[2 * N]       0 - 65535
 * 11000000 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
 */
static const value_string display_ref_bytecode_vals[] = {
    { 0x00, "0nnnnnnn memory[2 * N] 0 - 65535" },
    { 0x80, "10nnnnnn nnnnnnnn memory[2 * N] 0 - 65535" },
    { 0xc0, "11000000 nnnnnnnn nnnnnnnn memory[N] 0 - 65535" },
    { 0,    NULL }
};
 /*  The simplest operand type is the literal (#), which encodes a
  * constant integer from 0 to 65535 inclusive.  A literal operand may
  * require between 1 and 3 bytes depending on its value.
  * Bytecode:                       Operand value:      Range:
  * 0nnnnnnn                        N                   0 - 127
  * 10nnnnnn nnnnnnnn               N                   0 - 16383
  * 11000000 nnnnnnnn nnnnnnnn      N                   0 - 65535
  *
  *            Figure 8: Bytecode for a literal (#) operand
  *
  */

static const value_string display_lit_bytecode_vals[] = {
    { 0x00, "0nnnnnnn N 0 - 127" },
    { 0x80, "10nnnnnn nnnnnnnn N 0 - 16383" },
    { 0xc0, "11000000 nnnnnnnn nnnnnnnn N 0 - 65535" },
    { 0,    NULL }
};

#define SIGCOMP_NACK_STATE_NOT_FOUND              1
#define SIGCOMP_NACK_CYCLES_EXHAUSTED             2
#define SIGCOMP_NACK_BYTECODES_TOO_LARGE         18
#define SIGCOMP_NACK_ID_NOT_UNIQUE               21
#define SIGCOMP_NACK_STATE_TOO_SHORT             23

static const value_string sigcomp_nack_reason_code_vals[] = {
    {  1,   "STATE_NOT_FOUND" },            /*1  State ID (6 - 20 bytes) */
    {  2,   "CYCLES_EXHAUSTED" },           /*2  Cycles Per Bit (1 byte) */
    {  3,   "USER_REQUESTED" },
    {  4,   "SEGFAULT" },
    {  5,   "TOO_MANY_STATE_REQUESTS" },
    {  6,   "INVALID_STATE_ID_LENGTH" },
    {  7,   "INVALID_STATE_PRIORITY" },
    {  8,   "OUTPUT_OVERFLOW" },
    {  9,   "STACK_UNDERFLOW" },
    { 10,   "BAD_INPUT_BITORDER" },
    { 11,   "DIV_BY_ZERO" },
    { 12,   "SWITCH_VALUE_TOO_HIGH" },
    { 13,   "TOO_MANY_BITS_REQUESTED" },
    { 14,   "INVALID_OPERAND" },
    { 15,   "HUFFMAN_NO_MATCH" },
    { 16,   "MESSAGE_TOO_SHORT" },
    { 17,   "INVALID_CODE_LOCATION" },
    { 18,   "BYTECODES_TOO_LARGE" },        /*18  Memory size (2 bytes) */
    { 19,   "INVALID_OPCODE" },
    { 20,   "INVALID_STATE_PROBE" },
    { 21,   "ID_NOT_UNIQUE" },              /*21  State ID (6 - 20 bytes) */
    { 22,   "MULTILOAD_OVERWRITTEN" },
    { 23,   "STATE_TOO_SHORT" },            /*23  State ID (6 - 20 bytes) */
    { 24,   "INTERNAL_ERROR" },
    { 25,   "FRAMING_ERROR" },
    { 0,    NULL }
};
static value_string_ext sigcomp_nack_reason_code_vals_ext =
    VALUE_STRING_EXT_INIT(sigcomp_nack_reason_code_vals);


static void dissect_udvm_bytecode(tvbuff_t *udvm_tvb, packet_info* pinfo, proto_tree *sigcomp_udvm_tree, guint destination);

static int dissect_udvm_multitype_operand(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree,
                                          gint offset,gboolean is_addr,gint *start_offset,
                                          guint16 *value, gboolean *is_memory_address );

static int dissect_udvm_literal_operand(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree,
                               gint offset, gint *start_offset, guint16 *value);

static int dissect_udvm_reference_operand(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree,
                               gint offset, gint *start_offset, guint16 *value);
static void tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree);

static int dissect_sigcomp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static proto_tree *top_tree;

#define UDVM_MEMORY_SIZE   65536

/**********************************************************************************************
 *
 *                       SIGCOMP STATE HANDLER
 *
 **********************************************************************************************/
#define STATE_BUFFER_SIZE 20
#define STATE_MIN_ACCESS_LEN 6

/*
 * Defenitions for:
 * The Session Initiation Protocol (SIP) and Session Description Protocol
 *    (SDP) Static Dictionary for Signaling Compression (SigComp)
 * http://www.ietf.org/rfc/rfc3485.txt?number=3485
 */
#define SIP_SDP_STATE_LENGTH 0x12e4

static const guint8 sip_sdp_state_identifier[STATE_BUFFER_SIZE] =
{
   /* -0000, */  0xfb, 0xe5, 0x07, 0xdf, 0xe5, 0xe6, 0xaa, 0x5a, 0xf2, 0xab, 0xb9, 0x14, 0xce, 0xaa, 0x05, 0xf9,
   /* -0010, */  0x9c, 0xe6, 0x1b, 0xa5
};

static const guint8 sip_sdp_static_dictionaty_for_sigcomp[0x12e4] =
{

   /* -0000, */  0x0d, 0x0a, 0x52, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x2d, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74,
   /* -0010, */  0x3a, 0x20, 0x0d, 0x0a, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x2d, 0x49, 0x6e, 0x66, 0x6f, 0x3a, 0x20,
   /* -0020, */  0x0d, 0x0a, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x3a, 0x20, 0x0d, 0x0a, 0x43,
   /* -0030, */  0x61, 0x6c, 0x6c, 0x2d, 0x49, 0x6e, 0x66, 0x6f, 0x3a, 0x20, 0x0d, 0x0a, 0x52, 0x65, 0x70, 0x6c,
   /* -0040, */  0x79, 0x2d, 0x54, 0x6f, 0x3a, 0x20, 0x0d, 0x0a, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x3a,
   /* -0050, */  0x20, 0x0d, 0x0a, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x20, 0x3b, 0x68, 0x61, 0x6e,
   /* -0060, */  0x64, 0x6c, 0x69, 0x6e, 0x67, 0x3d, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x3b, 0x70, 0x75, 0x72, 0x70,
   /* -0070, */  0x6f, 0x73, 0x65, 0x3d, 0x3b, 0x63, 0x61, 0x75, 0x73, 0x65, 0x3d, 0x3b, 0x74, 0x65, 0x78, 0x74,
   /* -0080, */  0x3d, 0x63, 0x61, 0x72, 0x64, 0x33, 0x30, 0x30, 0x20, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x6c,
   /* -0090, */  0x65, 0x20, 0x43, 0x68, 0x6f, 0x69, 0x63, 0x65, 0x73, 0x6d, 0x69, 0x6d, 0x65, 0x73, 0x73, 0x61,
   /* -00A0, */  0x67, 0x65, 0x2f, 0x73, 0x69, 0x70, 0x66, 0x72, 0x61, 0x67, 0x34, 0x30, 0x37, 0x20, 0x50, 0x72,
   /* -00B0, */  0x6f, 0x78, 0x79, 0x20, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69,
   /* -00C0, */  0x6f, 0x6e, 0x20, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74,
   /* -00D0, */  0x2d, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x69, 0x74, 0x79, 0x34, 0x38, 0x34, 0x20, 0x41, 0x64,
   /* -00E0, */  0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x49, 0x6e, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65,
   /* -00F0, */  0x6c, 0x65, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x2d, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x34, 0x39,
   /* -0100, */  0x34, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x41, 0x67, 0x72, 0x65, 0x65,
   /* -0110, */  0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x65, 0x61, 0x63,
   /* -0120, */  0x74, 0x69, 0x76, 0x61, 0x74, 0x65, 0x64, 0x34, 0x38, 0x31, 0x20, 0x43, 0x61, 0x6c, 0x6c, 0x2f,
   /* -0130, */  0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x44, 0x6f, 0x65, 0x73,
   /* -0140, */  0x20, 0x4e, 0x6f, 0x74, 0x20, 0x45, 0x78, 0x69, 0x73, 0x74, 0x61, 0x6c, 0x65, 0x3d, 0x35, 0x30,
   /* -0150, */  0x30, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61,
   /* -0160, */  0x6c, 0x20, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x6f, 0x62, 0x75, 0x73, 0x74, 0x2d, 0x73, 0x6f, 0x72,
   /* -0170, */  0x74, 0x69, 0x6e, 0x67, 0x3d, 0x34, 0x31, 0x36, 0x20, 0x55, 0x6e, 0x73, 0x75, 0x70, 0x70, 0x6f,
   /* -0180, */  0x72, 0x74, 0x65, 0x64, 0x20, 0x55, 0x52, 0x49, 0x20, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x65, 0x72,
   /* -0190, */  0x67, 0x65, 0x6e, 0x63, 0x79, 0x34, 0x31, 0x35, 0x20, 0x55, 0x6e, 0x73, 0x75, 0x70, 0x70, 0x6f,
   /* -01A0, */  0x72, 0x74, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x20, 0x54, 0x79, 0x70, 0x65, 0x6e,
   /* -01B0, */  0x64, 0x69, 0x6e, 0x67, 0x34, 0x38, 0x38, 0x20, 0x4e, 0x6f, 0x74, 0x20, 0x41, 0x63, 0x63, 0x65,
   /* -01C0, */  0x70, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x48, 0x65, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x65,
   /* -01D0, */  0x64, 0x34, 0x32, 0x33, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x20, 0x54, 0x6f,
   /* -01E0, */  0x6f, 0x20, 0x42, 0x72, 0x69, 0x65, 0x66, 0x72, 0x6f, 0x6d, 0x2d, 0x74, 0x61, 0x67, 0x51, 0x2e,
   /* -01F0, */  0x38, 0x35, 0x30, 0x35, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x6f, 0x74,
   /* -0200, */  0x20, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x34, 0x30, 0x33, 0x20, 0x46, 0x6f,
   /* -0210, */  0x72, 0x62, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x6f, 0x6e, 0x2d, 0x75, 0x72, 0x67, 0x65, 0x6e, 0x74,
   /* -0220, */  0x34, 0x32, 0x39, 0x20, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x20, 0x52, 0x65, 0x66, 0x65,
   /* -0230, */  0x72, 0x72, 0x6f, 0x72, 0x20, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x34, 0x32, 0x30,
   /* -0240, */  0x20, 0x42, 0x61, 0x64, 0x20, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x6f, 0x72,
   /* -0250, */  0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x0d, 0x0a, 0x61, 0x3d, 0x6b, 0x65, 0x79, 0x2d, 0x6d,
   /* -0260, */  0x67, 0x6d, 0x74, 0x3a, 0x6d, 0x69, 0x6b, 0x65, 0x79, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53,
   /* -0270, */  0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x35, 0x30, 0x34, 0x20, 0x53,
   /* -0280, */  0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x2d, 0x6f, 0x75, 0x74, 0x6f, 0x2d,
   /* -0290, */  0x74, 0x61, 0x67, 0x0d, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
   /* -02A0, */  0x69, 0x6f, 0x6e, 0x2d, 0x49, 0x6e, 0x66, 0x6f, 0x3a, 0x20, 0x44, 0x65, 0x63, 0x20, 0x33, 0x38,
   /* -02B0, */  0x30, 0x20, 0x41, 0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x53, 0x65,
   /* -02C0, */  0x72, 0x76, 0x69, 0x63, 0x65, 0x35, 0x30, 0x33, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
   /* -02D0, */  0x20, 0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x34, 0x32, 0x31, 0x20,
   /* -02E0, */  0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72,
   /* -02F0, */  0x65, 0x64, 0x34, 0x30, 0x35, 0x20, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x20, 0x4e, 0x6f, 0x74,
   /* -0300, */  0x20, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x34, 0x38, 0x37, 0x20, 0x52, 0x65, 0x71, 0x75,
   /* -0310, */  0x65, 0x73, 0x74, 0x20, 0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x64, 0x61, 0x75,
   /* -0320, */  0x74, 0x68, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6c, 0x65, 0x61, 0x76, 0x69, 0x6e, 0x67, 0x3d,
   /* -0330, */  0x0d, 0x0a, 0x6d, 0x3d, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
   /* -0340, */  0x41, 0x75, 0x67, 0x20, 0x35, 0x31, 0x33, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
   /* -0350, */  0x54, 0x6f, 0x6f, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65, 0x36, 0x38, 0x37, 0x20, 0x44, 0x69, 0x61,
   /* -0360, */  0x6c, 0x6f, 0x67, 0x20, 0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x64, 0x33, 0x30,
   /* -0370, */  0x32, 0x20, 0x4d, 0x6f, 0x76, 0x65, 0x64, 0x20, 0x54, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x61, 0x72,
   /* -0380, */  0x69, 0x6c, 0x79, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f, 0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72,
   /* -0390, */  0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x61, 0x72,
   /* -03A0, */  0x74, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x0d, 0x0a, 0x52, 0x65, 0x74, 0x72, 0x79, 0x2d,
   /* -03B0, */  0x41, 0x66, 0x74, 0x65, 0x72, 0x3a, 0x20, 0x47, 0x4d, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x34, 0x30,
   /* -03C0, */  0x32, 0x20, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72,
   /* -03D0, */  0x65, 0x64, 0x0d, 0x0a, 0x61, 0x3d, 0x6f, 0x72, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x6c, 0x61, 0x6e,
   /* -03E0, */  0x64, 0x73, 0x63, 0x61, 0x70, 0x65, 0x34, 0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52, 0x65,
   /* -03F0, */  0x71, 0x75, 0x65, 0x73, 0x74, 0x72, 0x75, 0x65, 0x34, 0x39, 0x31, 0x20, 0x52, 0x65, 0x71, 0x75,
   /* -0400, */  0x65, 0x73, 0x74, 0x20, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x35, 0x30, 0x31, 0x20, 0x4e,
   /* -0410, */  0x6f, 0x74, 0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x65, 0x64, 0x34, 0x30,
   /* -0420, */  0x36, 0x20, 0x4e, 0x6f, 0x74, 0x20, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x61, 0x62, 0x6c, 0x65,
   /* -0430, */  0x36, 0x30, 0x36, 0x20, 0x4e, 0x6f, 0x74, 0x20, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x61, 0x62,
   /* -0440, */  0x6c, 0x65, 0x0d, 0x0a, 0x61, 0x3d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x62, 0x72, 0x6f, 0x61, 0x64,
   /* -0450, */  0x63, 0x61, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x34, 0x39, 0x33, 0x20, 0x55, 0x6e, 0x64, 0x65, 0x63,
   /* -0460, */  0x69, 0x70, 0x68, 0x65, 0x72, 0x61, 0x62, 0x6c, 0x65, 0x0d, 0x0a, 0x4d, 0x49, 0x4d, 0x45, 0x2d,
   /* -0470, */  0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x34, 0x38, 0x32,
   /* -0480, */  0x20, 0x4c, 0x6f, 0x6f, 0x70, 0x20, 0x44, 0x65, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x0d, 0x0a,
   /* -0490, */  0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x4a, 0x75,
   /* -04A0, */  0x6e, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2d, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2d, 0x6e, 0x65,
   /* -04B0, */  0x69, 0x67, 0x68, 0x62, 0x6f, 0x72, 0x3d, 0x63, 0x72, 0x69, 0x74, 0x69, 0x63, 0x61, 0x6c, 0x65,
   /* -04C0, */  0x72, 0x74, 0x63, 0x70, 0x2d, 0x66, 0x62, 0x34, 0x38, 0x39, 0x20, 0x42, 0x61, 0x64, 0x20, 0x45,
   /* -04D0, */  0x76, 0x65, 0x6e, 0x74, 0x6c, 0x73, 0x0d, 0x0a, 0x55, 0x6e, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72,
   /* -04E0, */  0x74, 0x65, 0x64, 0x3a, 0x20, 0x4a, 0x61, 0x6e, 0x20, 0x35, 0x30, 0x32, 0x20, 0x42, 0x61, 0x64,
   /* -04F0, */  0x20, 0x47, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x6d, 0x6f, 0x64, 0x65, 0x2d, 0x63, 0x68, 0x61,
   /* -0500, */  0x6e, 0x67, 0x65, 0x2d, 0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x3d, 0x0d, 0x0a, 0x61, 0x3d, 0x6f,
   /* -0510, */  0x72, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x73, 0x65, 0x61, 0x73, 0x63, 0x61, 0x70, 0x65, 0x0d, 0x0a,
   /* -0520, */  0x61, 0x3d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x6d, 0x6f, 0x64, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64,
   /* -0530, */  0x34, 0x30, 0x34, 0x20, 0x4e, 0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x30, 0x35,
   /* -0540, */  0x20, 0x55, 0x73, 0x65, 0x20, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x0d, 0x0a, 0x61, 0x3d, 0x74, 0x79,
   /* -0550, */  0x70, 0x65, 0x3a, 0x72, 0x65, 0x63, 0x76, 0x6f, 0x6e, 0x6c, 0x79, 0x0d, 0x0a, 0x61, 0x3d, 0x74,
   /* -0560, */  0x79, 0x70, 0x65, 0x3a, 0x6d, 0x65, 0x65, 0x74, 0x69, 0x6e, 0x67, 0x0d, 0x0a, 0x6b, 0x3d, 0x70,
   /* -0570, */  0x72, 0x6f, 0x6d, 0x70, 0x74, 0x3a, 0x0d, 0x0a, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64,
   /* -0580, */  0x2d, 0x42, 0x79, 0x3a, 0x20, 0x0d, 0x0a, 0x49, 0x6e, 0x2d, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x2d,
   /* -0590, */  0x54, 0x6f, 0x3a, 0x20, 0x54, 0x52, 0x55, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a,
   /* -05A0, */  0x20, 0x31, 0x38, 0x32, 0x20, 0x51, 0x75, 0x65, 0x75, 0x65, 0x64, 0x41, 0x75, 0x74, 0x68, 0x65,
   /* -05B0, */  0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
   /* -05C0, */  0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x66, 0x72, 0x61, 0x6d, 0x65,
   /* -05D0, */  0x72, 0x61, 0x74, 0x65, 0x3a, 0x0d, 0x0a, 0x41, 0x6c, 0x65, 0x72, 0x74, 0x2d, 0x49, 0x6e, 0x66,
   /* -05E0, */  0x6f, 0x3a, 0x20, 0x43, 0x41, 0x4e, 0x43, 0x45, 0x4c, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x6d, 0x61,
   /* -05F0, */  0x78, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x3a, 0x3b, 0x72, 0x65, 0x74, 0x72, 0x79, 0x2d, 0x61, 0x66,
   /* -0600, */  0x74, 0x65, 0x72, 0x3d, 0x75, 0x61, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x73, 0x3d, 0x34,
   /* -0610, */  0x31, 0x30, 0x20, 0x47, 0x6f, 0x6e, 0x65, 0x0d, 0x0a, 0x52, 0x65, 0x66, 0x65, 0x72, 0x2d, 0x54,
   /* -0620, */  0x6f, 0x3a, 0x20, 0x0d, 0x0a, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x3a, 0x20, 0x0d,
   /* -0630, */  0x0a, 0x6d, 0x3d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x71,
   /* -0640, */  0x75, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x3a, 0x0d, 0x0a, 0x61, 0x3d, 0x73, 0x64, 0x70, 0x6c, 0x61,
   /* -0650, */  0x6e, 0x67, 0x3a, 0x0d, 0x0a, 0x61, 0x3d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3a, 0x0d,
   /* -0660, */  0x0a, 0x52, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x73, 0x3a, 0x20, 0x52, 0x45, 0x46, 0x45, 0x52,
   /* -0670, */  0x20, 0x69, 0x70, 0x73, 0x65, 0x63, 0x2d, 0x69, 0x6b, 0x65, 0x3b, 0x74, 0x72, 0x61, 0x6e, 0x73,
   /* -0680, */  0x70, 0x6f, 0x72, 0x74, 0x3d, 0x0d, 0x0a, 0x61, 0x3d, 0x6b, 0x65, 0x79, 0x77, 0x64, 0x73, 0x3a,
   /* -0690, */  0x0d, 0x0a, 0x6b, 0x3d, 0x62, 0x61, 0x73, 0x65, 0x36, 0x34, 0x3a, 0x3b, 0x72, 0x65, 0x66, 0x72,
   /* -06A0, */  0x65, 0x73, 0x68, 0x65, 0x72, 0x3d, 0x0d, 0x0a, 0x61, 0x3d, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x3a,
   /* -06B0, */  0x0d, 0x0a, 0x6b, 0x3d, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x3a, 0x3b, 0x72, 0x65, 0x63, 0x65, 0x69,
   /* -06C0, */  0x76, 0x65, 0x64, 0x3d, 0x3b, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x0d, 0x0a,
   /* -06D0, */  0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x67, 0x72, 0x6f, 0x75,
   /* -06E0, */  0x70, 0x3a, 0x46, 0x41, 0x4c, 0x53, 0x45, 0x3a, 0x20, 0x49, 0x4e, 0x46, 0x4f, 0x20, 0x0d, 0x0a,
   /* -06F0, */  0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x0d, 0x0a, 0x61, 0x3d, 0x6c, 0x61, 0x6e, 0x67, 0x3a,
   /* -0700, */  0x0d, 0x0a, 0x6d, 0x3d, 0x64, 0x61, 0x74, 0x61, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2d, 0x73, 0x65,
   /* -0710, */  0x74, 0x3d, 0x0d, 0x0a, 0x61, 0x3d, 0x74, 0x6f, 0x6f, 0x6c, 0x3a, 0x54, 0x4c, 0x53, 0x75, 0x6e,
   /* -0720, */  0x2c, 0x20, 0x0d, 0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x63, 0x61,
   /* -0730, */  0x74, 0x3a, 0x0d, 0x0a, 0x6b, 0x3d, 0x75, 0x72, 0x69, 0x3a, 0x0d, 0x0a, 0x50, 0x72, 0x6f, 0x78,
   /* -0740, */  0x79, 0x2d, 0x3b, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x3d, 0x3b, 0x6d, 0x65, 0x74, 0x68, 0x6f,
   /* -0750, */  0x64, 0x3d, 0x0d, 0x0a, 0x61, 0x3d, 0x6d, 0x69, 0x64, 0x3a, 0x3b, 0x6d, 0x61, 0x64, 0x64, 0x72,
   /* -0760, */  0x3d, 0x6f, 0x70, 0x61, 0x71, 0x75, 0x65, 0x3d, 0x0d, 0x0a, 0x4d, 0x69, 0x6e, 0x2d, 0x3b, 0x61,
   /* -0770, */  0x6c, 0x67, 0x3d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57, 0x65, 0x64,
   /* -0780, */  0x2c, 0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61, 0x74, 0x2c, 0x20, 0x3b, 0x74, 0x74, 0x6c,
   /* -0790, */  0x3d, 0x61, 0x75, 0x74, 0x73, 0x3d, 0x0d, 0x0a, 0x72, 0x3d, 0x0d, 0x0a, 0x7a, 0x3d, 0x0d, 0x0a,
   /* -07A0, */  0x65, 0x3d, 0x3b, 0x69, 0x64, 0x3d, 0x0d, 0x0a, 0x69, 0x3d, 0x63, 0x72, 0x63, 0x3d, 0x0d, 0x0a,
   /* -07B0, */  0x75, 0x3d, 0x3b, 0x71, 0x3d, 0x75, 0x61, 0x73, 0x34, 0x31, 0x34, 0x20, 0x52, 0x65, 0x71, 0x75,
   /* -07C0, */  0x65, 0x73, 0x74, 0x2d, 0x55, 0x52, 0x49, 0x20, 0x54, 0x6f, 0x6f, 0x20, 0x4c, 0x6f, 0x6e, 0x67,
   /* -07D0, */  0x69, 0x76, 0x65, 0x75, 0x70, 0x72, 0x69, 0x76, 0x61, 0x63, 0x79, 0x75, 0x64, 0x70, 0x72, 0x65,
   /* -07E0, */  0x66, 0x65, 0x72, 0x36, 0x30, 0x30, 0x20, 0x42, 0x75, 0x73, 0x79, 0x20, 0x45, 0x76, 0x65, 0x72,
   /* -07F0, */  0x79, 0x77, 0x68, 0x65, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x34, 0x38, 0x30, 0x20,
   /* -0800, */  0x54, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x61, 0x72, 0x69, 0x6c, 0x79, 0x20, 0x55, 0x6e, 0x61, 0x76,
   /* -0810, */  0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x0d, 0x0a, 0x61, 0x3d, 0x74, 0x79, 0x70, 0x65, 0x3a,
   /* -0820, */  0x48, 0x2e, 0x33, 0x33, 0x32, 0x30, 0x32, 0x20, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x65, 0x64,
   /* -0830, */  0x0d, 0x0a, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65,
   /* -0840, */  0x73, 0x3a, 0x20, 0x0d, 0x0a, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
   /* -0850, */  0x6e, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x4e, 0x6f, 0x76, 0x20, 0x0d, 0x0a, 0x53,
   /* -0860, */  0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x3a, 0x20, 0x53, 0x65,
   /* -0870, */  0x70, 0x20, 0x0d, 0x0a, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x2d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73,
   /* -0880, */  0x3a, 0x20, 0x46, 0x65, 0x62, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69,
   /* -0890, */  0x76, 0x65, 0x52, 0x54, 0x50, 0x2f, 0x53, 0x41, 0x56, 0x50, 0x20, 0x52, 0x54, 0x50, 0x2f, 0x41,
   /* -08A0, */  0x56, 0x50, 0x46, 0x20, 0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x69, 0x70, 0x73,
   /* -08B0, */  0x3a, 0x0d, 0x0a, 0x61, 0x3d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x65, 0x6c,
   /* -08C0, */  0x3a, 0x4d, 0x45, 0x53, 0x53, 0x41, 0x47, 0x45, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x72, 0x65, 0x63,
   /* -08D0, */  0x76, 0x6f, 0x6e, 0x6c, 0x79, 0x0d, 0x0a, 0x61, 0x3d, 0x73, 0x65, 0x6e, 0x64, 0x6f, 0x6e, 0x6c,
   /* -08E0, */  0x79, 0x0d, 0x0a, 0x63, 0x3d, 0x49, 0x4e, 0x20, 0x49, 0x50, 0x34, 0x20, 0x0d, 0x0a, 0x52, 0x65,
   /* -08F0, */  0x61, 0x73, 0x6f, 0x6e, 0x3a, 0x20, 0x0d, 0x0a, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x3a, 0x20, 0x0d,
   /* -0900, */  0x0a, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x0d, 0x0a, 0x50, 0x61, 0x74, 0x68, 0x3a, 0x20,
   /* -0910, */  0x3b, 0x75, 0x73, 0x65, 0x72, 0x3d, 0x0d, 0x0a, 0x62, 0x3d, 0x41, 0x53, 0x20, 0x43, 0x54, 0x20,
   /* -0920, */  0x0d, 0x0a, 0x57, 0x57, 0x57, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
   /* -0930, */  0x74, 0x65, 0x3a, 0x20, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x73,
   /* -0940, */  0x65, 0x6e, 0x64, 0x72, 0x65, 0x63, 0x76, 0x69, 0x64, 0x65, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x2d,
   /* -0950, */  0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
   /* -0960, */  0x6e, 0x2f, 0x73, 0x64, 0x70, 0x61, 0x74, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x70, 0x61,
   /* -0970, */  0x75, 0x74, 0x68, 0x3d, 0x0d, 0x0a, 0x61, 0x3d, 0x6f, 0x72, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x70,
   /* -0980, */  0x6f, 0x72, 0x74, 0x72, 0x61, 0x69, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x74, 0x72, 0x2d,
   /* -0990, */  0x69, 0x6e, 0x74, 0x69, 0x63, 0x6f, 0x6e, 0x63, 0x3d, 0x34, 0x38, 0x33, 0x20, 0x54, 0x6f, 0x6f,
   /* -09A0, */  0x20, 0x4d, 0x61, 0x6e, 0x79, 0x20, 0x48, 0x6f, 0x70, 0x73, 0x6c, 0x69, 0x6e, 0x66, 0x6f, 0x70,
   /* -09B0, */  0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x3d, 0x36, 0x30,
   /* -09C0, */  0x34, 0x20, 0x44, 0x6f, 0x65, 0x73, 0x20, 0x4e, 0x6f, 0x74, 0x20, 0x45, 0x78, 0x69, 0x73, 0x74,
   /* -09D0, */  0x20, 0x41, 0x6e, 0x79, 0x77, 0x68, 0x65, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x3d,
   /* -09E0, */  0x0d, 0x0a, 0x0d, 0x0a, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2d, 0x44, 0x69, 0x73, 0x70,
   /* -09F0, */  0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x4d, 0x44, 0x35, 0x38, 0x30, 0x20, 0x50,
   /* -0A00, */  0x72, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x46, 0x61, 0x69, 0x6c,
   /* -0A10, */  0x75, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x73, 0x34, 0x32, 0x32, 0x20, 0x53, 0x65, 0x73,
   /* -0A20, */  0x73, 0x69, 0x6f, 0x6e, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x20, 0x54, 0x6f,
   /* -0A30, */  0x6f, 0x20, 0x53, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x31, 0x38, 0x31, 0x20, 0x43,
   /* -0A40, */  0x61, 0x6c, 0x6c, 0x20, 0x49, 0x73, 0x20, 0x42, 0x65, 0x69, 0x6e, 0x67, 0x20, 0x46, 0x6f, 0x72,
   /* -0A50, */  0x77, 0x61, 0x72, 0x64, 0x65, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x3d, 0x66, 0x61, 0x69, 0x6c,
   /* -0A60, */  0x75, 0x72, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x3d, 0x53, 0x55, 0x42, 0x53,
   /* -0A70, */  0x43, 0x52, 0x49, 0x42, 0x45, 0x20, 0x70, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69,
   /* -0A80, */  0x6f, 0x6e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x69, 0x70, 0x73, 0x65, 0x63, 0x2d, 0x6d, 0x61, 0x6e,
   /* -0A90, */  0x64, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x34, 0x31, 0x33, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
   /* -0AA0, */  0x74, 0x20, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x54, 0x6f, 0x6f, 0x20, 0x4c, 0x61, 0x72,
   /* -0AB0, */  0x67, 0x65, 0x32, 0x65, 0x31, 0x38, 0x33, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20,
   /* -0AC0, */  0x50, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x63, 0x74, 0x70, 0x34, 0x38, 0x36, 0x20, 0x42,
   /* -0AD0, */  0x75, 0x73, 0x79, 0x20, 0x48, 0x65, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e,
   /* -0AE0, */  0x61, 0x74, 0x65, 0x64, 0x41, 0x4b, 0x41, 0x76, 0x31, 0x2d, 0x4d, 0x44, 0x35, 0x2d, 0x73, 0x65,
   /* -0AF0, */  0x73, 0x73, 0x69, 0x6f, 0x6e, 0x6f, 0x6e, 0x65, 0x0d, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
   /* -0B00, */  0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x36, 0x30, 0x33, 0x20, 0x44, 0x65, 0x63,
   /* -0B10, */  0x6c, 0x69, 0x6e, 0x65, 0x78, 0x74, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x3d, 0x34, 0x38, 0x35, 0x20,
   /* -0B20, */  0x41, 0x6d, 0x62, 0x69, 0x67, 0x75, 0x6f, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3d,
   /* -0B30, */  0x61, 0x75, 0x64, 0x69, 0x6f, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54,
   /* -0B40, */  0x79, 0x70, 0x65, 0x3a, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x0d, 0x0a, 0x52, 0x65, 0x63, 0x6f, 0x72,
   /* -0B50, */  0x64, 0x2d, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x3a, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x34, 0x30, 0x31,
   /* -0B60, */  0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x0d, 0x0a, 0x52,
   /* -0B70, */  0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x3a, 0x20, 0x0d, 0x0a, 0x74, 0x3d, 0x30, 0x20, 0x30, 0x2e,
   /* -0B80, */  0x30, 0x2e, 0x30, 0x2e, 0x30, 0x0d, 0x0a, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x52,
   /* -0B90, */  0x45, 0x47, 0x49, 0x53, 0x54, 0x45, 0x52, 0x20, 0x0d, 0x0a, 0x63, 0x3d, 0x49, 0x4e, 0x20, 0x49,
   /* -0BA0, */  0x50, 0x36, 0x20, 0x31, 0x38, 0x30, 0x20, 0x52, 0x69, 0x6e, 0x67, 0x69, 0x6e, 0x67, 0x31, 0x30,
   /* -0BB0, */  0x30, 0x20, 0x54, 0x72, 0x79, 0x69, 0x6e, 0x67, 0x76, 0x3d, 0x30, 0x0d, 0x0a, 0x6f, 0x3d, 0x55,
   /* -0BC0, */  0x50, 0x44, 0x41, 0x54, 0x45, 0x20, 0x4e, 0x4f, 0x54, 0x49, 0x46, 0x59, 0x20, 0x0d, 0x0a, 0x53,
   /* -0BD0, */  0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77,
   /* -0BE0, */  0x6e, 0x41, 0x4d, 0x52, 0x54, 0x50, 0x2f, 0x41, 0x56, 0x50, 0x20, 0x0d, 0x0a, 0x50, 0x72, 0x69,
   /* -0BF0, */  0x76, 0x61, 0x63, 0x79, 0x3a, 0x20, 0x0d, 0x0a, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
   /* -0C00, */  0x2d, 0x0d, 0x0a, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x3a, 0x20, 0x0d, 0x0a, 0x61, 0x3d,
   /* -0C10, */  0x72, 0x74, 0x70, 0x6d, 0x61, 0x70, 0x3a, 0x0d, 0x0a, 0x6d, 0x3d, 0x76, 0x69, 0x64, 0x65, 0x6f,
   /* -0C20, */  0x20, 0x0d, 0x0a, 0x6d, 0x3d, 0x61, 0x75, 0x64, 0x69, 0x6f, 0x20, 0x0d, 0x0a, 0x73, 0x3d, 0x20,
   /* -0C30, */  0x66, 0x61, 0x6c, 0x73, 0x65, 0x0d, 0x0a, 0x61, 0x3d, 0x63, 0x6f, 0x6e, 0x66, 0x3a, 0x3b, 0x65,
   /* -0C40, */  0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x3d, 0x0d, 0x0a, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x3a, 0x20,
   /* -0C50, */  0x0d, 0x0a, 0x61, 0x3d, 0x66, 0x6d, 0x74, 0x70, 0x3a, 0x0d, 0x0a, 0x61, 0x3d, 0x63, 0x75, 0x72,
   /* -0C60, */  0x72, 0x3a, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79,
   /* -0C70, */  0x3a, 0x20, 0x0d, 0x0a, 0x61, 0x3d, 0x64, 0x65, 0x73, 0x3a, 0x0d, 0x0a, 0x52, 0x41, 0x63, 0x6b,
   /* -0C80, */  0x3a, 0x20, 0x0d, 0x0a, 0x52, 0x53, 0x65, 0x71, 0x3a, 0x20, 0x42, 0x59, 0x45, 0x20, 0x63, 0x6e,
   /* -0C90, */  0x6f, 0x6e, 0x63, 0x65, 0x3d, 0x31, 0x30, 0x30, 0x72, 0x65, 0x6c, 0x75, 0x72, 0x69, 0x3d, 0x71,
   /* -0CA0, */  0x6f, 0x70, 0x3d, 0x54, 0x43, 0x50, 0x55, 0x44, 0x50, 0x71, 0x6f, 0x73, 0x78, 0x6d, 0x6c, 0x3b,
   /* -0CB0, */  0x6c, 0x72, 0x0d, 0x0a, 0x56, 0x69, 0x61, 0x3a, 0x20, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30,
   /* -0CC0, */  0x2f, 0x54, 0x43, 0x50, 0x20, 0x34, 0x30, 0x38, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
   /* -0CD0, */  0x20, 0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x70, 0x73, 0x69, 0x70,
   /* -0CE0, */  0x3a, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74,
   /* -0CF0, */  0x68, 0x3a, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x0d, 0x0a, 0x56, 0x69, 0x61, 0x3a, 0x20, 0x53, 0x49,
   /* -0D00, */  0x50, 0x2f, 0x32, 0x2e, 0x30, 0x2f, 0x55, 0x44, 0x50, 0x20, 0x3b, 0x63, 0x6f, 0x6d, 0x70, 0x3d,
   /* -0D10, */  0x73, 0x69, 0x67, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x6f, 0x62, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61,
   /* -0D20, */  0x63, 0x6b, 0x3b, 0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x3d, 0x7a, 0x39, 0x68, 0x47, 0x34, 0x62,
   /* -0D30, */  0x4b, 0x0d, 0x0a, 0x4d, 0x61, 0x78, 0x2d, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x73, 0x3a,
   /* -0D40, */  0x20, 0x41, 0x70, 0x72, 0x20, 0x53, 0x43, 0x54, 0x50, 0x52, 0x41, 0x43, 0x4b, 0x20, 0x49, 0x4e,
   /* -0D50, */  0x56, 0x49, 0x54, 0x45, 0x20, 0x0d, 0x0a, 0x43, 0x61, 0x6c, 0x6c, 0x2d, 0x49, 0x44, 0x3a, 0x20,
   /* -0D60, */  0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x3a, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f,
   /* -0D70, */  0x4b, 0x0d, 0x0a, 0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x0d, 0x0a, 0x43, 0x53, 0x65, 0x71, 0x3a,
   /* -0D80, */  0x20, 0x0d, 0x0a, 0x54, 0x6f, 0x3a, 0x20, 0x3b, 0x74, 0x61, 0x67, 0x3d, 0x04, 0x10, 0xdd, 0x10,
   /* -0D90, */  0x11, 0x31, 0x0d, 0x11, 0x0a, 0x07, 0x10, 0xb9, 0x0c, 0x10, 0xfe, 0x12, 0x10, 0xe1, 0x06, 0x11,
   /* -0DA0, */  0x4e, 0x07, 0x11, 0x4e, 0x03, 0x11, 0x4a, 0x04, 0x11, 0x4a, 0x07, 0x10, 0xb2, 0x08, 0x11, 0x79,
   /* -0DB0, */  0x06, 0x11, 0x81, 0x0f, 0x11, 0x22, 0x0b, 0x11, 0x55, 0x06, 0x11, 0x6b, 0x0b, 0x11, 0x60, 0x13,
   /* -0DC0, */  0x10, 0xb2, 0x08, 0x11, 0x71, 0x05, 0x11, 0x87, 0x13, 0x10, 0xf7, 0x09, 0x0e, 0x8d, 0x08, 0x0d,
   /* -0DD0, */  0xae, 0x0c, 0x10, 0xb9, 0x07, 0x10, 0x8e, 0x03, 0x0d, 0x96, 0x03, 0x10, 0x8a, 0x04, 0x10, 0x8a,
   /* -0DE0, */  0x09, 0x0d, 0xd7, 0x0a, 0x0f, 0x12, 0x08, 0x0f, 0x8f, 0x09, 0x0f, 0x8f, 0x08, 0x0d, 0x6c, 0x06,
   /* -0DF0, */  0x0e, 0x66, 0x09, 0x0e, 0x6c, 0x0a, 0x0e, 0x6c, 0x06, 0x0f, 0xc6, 0x07, 0x0f, 0xc6, 0x05, 0x11,
   /* -0E00, */  0x48, 0x06, 0x11, 0x48, 0x06, 0x0f, 0xbf, 0x07, 0x0f, 0xbf, 0x07, 0x0e, 0x55, 0x06, 0x0f, 0x16,
   /* -0E10, */  0x04, 0x0e, 0xf4, 0x03, 0x0e, 0xb1, 0x03, 0x10, 0xa6, 0x09, 0x10, 0x50, 0x03, 0x10, 0xa3, 0x0a,
   /* -0E20, */  0x0d, 0xb4, 0x05, 0x0e, 0x36, 0x06, 0x0e, 0xd6, 0x03, 0x0d, 0xf9, 0x11, 0x0e, 0xf8, 0x04, 0x0c,
   /* -0E30, */  0xd9, 0x08, 0x0e, 0xea, 0x04, 0x09, 0x53, 0x03, 0x0a, 0x4b, 0x04, 0x0e, 0xe4, 0x10, 0x0f, 0x35,
   /* -0E40, */  0x09, 0x0e, 0xe4, 0x08, 0x0d, 0x3f, 0x03, 0x0f, 0xe1, 0x0b, 0x10, 0x01, 0x03, 0x10, 0xac, 0x06,
   /* -0E50, */  0x10, 0x95, 0x0c, 0x0e, 0x76, 0x0b, 0x0f, 0xeb, 0x0a, 0x0f, 0xae, 0x05, 0x10, 0x2b, 0x04, 0x10,
   /* -0E60, */  0x2b, 0x08, 0x10, 0x7a, 0x10, 0x0f, 0x49, 0x07, 0x0f, 0xb8, 0x09, 0x10, 0x3e, 0x0b, 0x10, 0x0c,
   /* -0E70, */  0x07, 0x0f, 0x78, 0x0b, 0x0f, 0x6d, 0x09, 0x10, 0x47, 0x08, 0x10, 0x82, 0x0b, 0x0f, 0xf6, 0x08,
   /* -0E80, */  0x10, 0x62, 0x08, 0x0f, 0x87, 0x08, 0x10, 0x6a, 0x04, 0x0f, 0x78, 0x0d, 0x0f, 0xcd, 0x08, 0x0d,
   /* -0E90, */  0xae, 0x10, 0x0f, 0x5d, 0x0b, 0x0f, 0x98, 0x14, 0x0d, 0x20, 0x1b, 0x0d, 0x20, 0x04, 0x0d, 0xe0,
   /* -0EA0, */  0x14, 0x0e, 0xb4, 0x0b, 0x0f, 0xa3, 0x0b, 0x07, 0x34, 0x0f, 0x0d, 0x56, 0x04, 0x0e, 0xf4, 0x03,
   /* -0EB0, */  0x10, 0xaf, 0x07, 0x0d, 0x34, 0x09, 0x0f, 0x27, 0x04, 0x10, 0x9b, 0x04, 0x10, 0x9f, 0x09, 0x10,
   /* -0EC0, */  0x59, 0x08, 0x10, 0x72, 0x09, 0x10, 0x35, 0x0a, 0x10, 0x21, 0x0a, 0x10, 0x17, 0x08, 0x0f, 0xe3,
   /* -0ED0, */  0x03, 0x10, 0xa9, 0x05, 0x0c, 0xac, 0x04, 0x0c, 0xbd, 0x07, 0x0c, 0xc1, 0x08, 0x0c, 0xc1, 0x09,
   /* -0EE0, */  0x0c, 0xf6, 0x10, 0x0c, 0x72, 0x0c, 0x0c, 0x86, 0x04, 0x0d, 0x64, 0x0c, 0x0c, 0xd5, 0x09, 0x0c,
   /* -0EF0, */  0xff, 0x1b, 0x0b, 0xfc, 0x11, 0x0c, 0x5d, 0x13, 0x0c, 0x30, 0x09, 0x0c, 0xa4, 0x0c, 0x0c, 0x24,
   /* -0F00, */  0x0c, 0x0d, 0x3b, 0x03, 0x0d, 0x1a, 0x03, 0x0d, 0x1d, 0x16, 0x0c, 0x43, 0x09, 0x0c, 0x92, 0x09,
   /* -0F10, */  0x0c, 0x9b, 0x0d, 0x0e, 0xcb, 0x04, 0x0d, 0x16, 0x06, 0x0d, 0x10, 0x05, 0x04, 0xf2, 0x0b, 0x0c,
   /* -0F20, */  0xe1, 0x05, 0x0b, 0xde, 0x0a, 0x0c, 0xec, 0x13, 0x0b, 0xe3, 0x07, 0x0b, 0xd4, 0x08, 0x0d, 0x08,
   /* -0F30, */  0x0c, 0x0c, 0xc9, 0x09, 0x0c, 0x3a, 0x04, 0x0a, 0xe5, 0x0c, 0x0a, 0x23, 0x08, 0x0b, 0x3a, 0x0e,
   /* -0F40, */  0x09, 0xab, 0x0f, 0x0e, 0xfa, 0x09, 0x0f, 0x6f, 0x0c, 0x0a, 0x17, 0x0f, 0x09, 0x76, 0x0c, 0x0a,
   /* -0F50, */  0x5f, 0x17, 0x0d, 0xe2, 0x0f, 0x07, 0xa8, 0x0a, 0x0f, 0x85, 0x0f, 0x08, 0xd6, 0x0e, 0x09, 0xb9,
   /* -0F60, */  0x0b, 0x0a, 0x7a, 0x03, 0x0b, 0xdb, 0x03, 0x08, 0xc1, 0x04, 0x0e, 0xc7, 0x03, 0x08, 0xd3, 0x02,
   /* -0F70, */  0x04, 0x8d, 0x08, 0x0b, 0x4a, 0x05, 0x0b, 0x8c, 0x07, 0x0b, 0x61, 0x06, 0x05, 0x48, 0x04, 0x07,
   /* -0F80, */  0xf4, 0x05, 0x10, 0x30, 0x04, 0x07, 0x1e, 0x08, 0x07, 0x1e, 0x05, 0x0b, 0x91, 0x10, 0x04, 0xca,
   /* -0F90, */  0x09, 0x0a, 0x71, 0x09, 0x0e, 0x87, 0x05, 0x04, 0x98, 0x05, 0x0b, 0x6e, 0x0b, 0x04, 0x9b, 0x0f,
   /* -0FA0, */  0x04, 0x9b, 0x07, 0x04, 0x9b, 0x03, 0x04, 0xa3, 0x07, 0x04, 0xa3, 0x10, 0x07, 0x98, 0x09, 0x07,
   /* -0FB0, */  0x98, 0x05, 0x0b, 0x73, 0x05, 0x0b, 0x78, 0x05, 0x0b, 0x7d, 0x05, 0x07, 0xb9, 0x05, 0x0b, 0x82,
   /* -0FC0, */  0x05, 0x0b, 0x87, 0x05, 0x0b, 0x1d, 0x05, 0x08, 0xe4, 0x05, 0x0c, 0x81, 0x05, 0x0f, 0x44, 0x05,
   /* -0FD0, */  0x11, 0x40, 0x05, 0x08, 0x78, 0x05, 0x08, 0x9d, 0x05, 0x0f, 0x58, 0x05, 0x07, 0x3f, 0x05, 0x0c,
   /* -0FE0, */  0x6d, 0x05, 0x10, 0xf2, 0x05, 0x0c, 0x58, 0x05, 0x06, 0xa9, 0x04, 0x07, 0xb6, 0x09, 0x05, 0x8c,
   /* -0FF0, */  0x06, 0x06, 0x1a, 0x06, 0x0e, 0x81, 0x0a, 0x06, 0x16, 0x0a, 0x0a, 0xc4, 0x07, 0x0b, 0x5a, 0x0a,
   /* -1000, */  0x0a, 0xba, 0x03, 0x0b, 0x1b, 0x04, 0x11, 0x45, 0x06, 0x0c, 0x8c, 0x07, 0x05, 0xad, 0x0a, 0x0e,
   /* -1010, */  0xda, 0x08, 0x0b, 0x42, 0x0d, 0x09, 0xf7, 0x0b, 0x05, 0x1c, 0x09, 0x11, 0x16, 0x08, 0x05, 0xc9,
   /* -1020, */  0x07, 0x0d, 0x86, 0x06, 0x0b, 0xcf, 0x0a, 0x06, 0x4d, 0x04, 0x0b, 0xa2, 0x06, 0x06, 0x8d, 0x08,
   /* -1030, */  0x05, 0xe6, 0x08, 0x0e, 0x11, 0x0b, 0x0a, 0x9b, 0x03, 0x0a, 0x04, 0x03, 0x0b, 0xb5, 0x05, 0x10,
   /* -1040, */  0xd7, 0x04, 0x09, 0x94, 0x05, 0x0a, 0xe2, 0x03, 0x0b, 0xb2, 0x06, 0x0d, 0x67, 0x04, 0x0d, 0x11,
   /* -1050, */  0x08, 0x08, 0xb7, 0x1b, 0x0e, 0x3b, 0x0a, 0x09, 0xa1, 0x14, 0x04, 0x85, 0x15, 0x07, 0x83, 0x15,
   /* -1060, */  0x07, 0x6e, 0x0d, 0x09, 0x3d, 0x17, 0x06, 0xae, 0x0f, 0x07, 0xe6, 0x14, 0x07, 0xbe, 0x0d, 0x06,
   /* -1070, */  0x0a, 0x0d, 0x09, 0x30, 0x16, 0x06, 0xf2, 0x12, 0x08, 0x1e, 0x21, 0x04, 0xaa, 0x13, 0x10, 0xc5,
   /* -1080, */  0x08, 0x0a, 0x0f, 0x1c, 0x0e, 0x96, 0x18, 0x0b, 0xb8, 0x1a, 0x05, 0x95, 0x1a, 0x05, 0x75, 0x11,
   /* -1090, */  0x06, 0x3d, 0x16, 0x06, 0xdc, 0x1e, 0x0e, 0x19, 0x16, 0x05, 0xd1, 0x1d, 0x06, 0x20, 0x23, 0x05,
   /* -10A0, */  0x27, 0x11, 0x08, 0x7d, 0x11, 0x0d, 0x99, 0x16, 0x04, 0xda, 0x0d, 0x0f, 0x1c, 0x16, 0x07, 0x08,
   /* -10B0, */  0x17, 0x05, 0xb4, 0x0d, 0x08, 0xc7, 0x13, 0x07, 0xf8, 0x12, 0x08, 0x57, 0x1f, 0x04, 0xfe, 0x19,
   /* -10C0, */  0x05, 0x4e, 0x13, 0x08, 0x0b, 0x0f, 0x08, 0xe9, 0x17, 0x06, 0xc5, 0x13, 0x06, 0x7b, 0x19, 0x05,
   /* -10D0, */  0xf1, 0x15, 0x07, 0x44, 0x18, 0x0d, 0xfb, 0x0b, 0x0f, 0x09, 0x1b, 0x0d, 0xbe, 0x12, 0x08, 0x30,
   /* -10E0, */  0x15, 0x07, 0x59, 0x04, 0x0b, 0xa6, 0x04, 0x0b, 0xae, 0x04, 0x0b, 0x9e, 0x04, 0x0b, 0x96, 0x04,
   /* -10F0, */  0x0b, 0x9a, 0x0a, 0x0a, 0xb0, 0x0b, 0x0a, 0x90, 0x08, 0x0b, 0x32, 0x0b, 0x09, 0x6b, 0x08, 0x0b,
   /* -1100, */  0x2a, 0x0b, 0x0a, 0x85, 0x09, 0x0b, 0x12, 0x0a, 0x0a, 0xa6, 0x0d, 0x09, 0xea, 0x13, 0x0d, 0x74,
   /* -1110, */  0x14, 0x07, 0xd2, 0x13, 0x09, 0x0b, 0x12, 0x08, 0x42, 0x10, 0x09, 0x5b, 0x12, 0x09, 0x1e, 0x0d,
   /* -1120, */  0x0c, 0xb1, 0x0e, 0x0c, 0x17, 0x11, 0x09, 0x4a, 0x0c, 0x0a, 0x53, 0x0c, 0x0a, 0x47, 0x09, 0x0a,
   /* -1130, */  0xf7, 0x0e, 0x09, 0xc7, 0x0c, 0x0a, 0x3b, 0x07, 0x06, 0x69, 0x08, 0x06, 0x69, 0x06, 0x09, 0xe3,
   /* -1140, */  0x08, 0x0b, 0x52, 0x0a, 0x0a, 0xd8, 0x12, 0x06, 0x57, 0x0d, 0x06, 0x57, 0x07, 0x09, 0xe3, 0x04,
   /* -1150, */  0x0a, 0xe9, 0x10, 0x07, 0x30, 0x09, 0x0b, 0x00, 0x0c, 0x0a, 0x2f, 0x05, 0x0a, 0xe9, 0x05, 0x0a,
   /* -1160, */  0x6b, 0x06, 0x0a, 0x6b, 0x0a, 0x0a, 0xce, 0x09, 0x0a, 0xee, 0x03, 0x0b, 0xdb, 0x07, 0x0f, 0x7e,
   /* -1170, */  0x0a, 0x09, 0x97, 0x0a, 0x06, 0x71, 0x0e, 0x09, 0xd5, 0x17, 0x06, 0x93, 0x07, 0x0e, 0x5c, 0x07,
   /* -1180, */  0x0f, 0xda, 0x0a, 0x0f, 0x35, 0x0d, 0x0d, 0xec, 0x0a, 0x09, 0x97, 0x0a, 0x06, 0x71, 0x08, 0x0b,
   /* -1190, */  0x22, 0x0f, 0x09, 0x85, 0x06, 0x0b, 0x68, 0x0c, 0x0d, 0x4a, 0x09, 0x0b, 0x09, 0x13, 0x08, 0xf8,
   /* -11A0, */  0x15, 0x08, 0xa2, 0x04, 0x0b, 0xaa, 0x0f, 0x05, 0x66, 0x0d, 0x07, 0x23, 0x09, 0x0a, 0x06, 0x0b,
   /* -11B0, */  0x0d, 0x4a, 0x0f, 0x04, 0xee, 0x06, 0x04, 0xf8, 0x04, 0x09, 0x2b, 0x04, 0x08, 0x53, 0x07, 0x08,
   /* -11C0, */  0xc0, 0x03, 0x11, 0x1f, 0x04, 0x11, 0x1e, 0x07, 0x0d, 0x8c, 0x03, 0x07, 0x34, 0x04, 0x10, 0xdb,
   /* -11D0, */  0x03, 0x07, 0x36, 0x03, 0x0d, 0xa9, 0x0d, 0x04, 0x20, 0x0b, 0x04, 0x51, 0x0c, 0x04, 0x3a, 0x04,
   /* -11E0, */  0x0b, 0xb8, 0x04, 0x0c, 0x24, 0x04, 0x05, 0x95, 0x04, 0x04, 0x7c, 0x04, 0x05, 0x75, 0x04, 0x04,
   /* -11F0, */  0x85, 0x04, 0x09, 0x6b, 0x04, 0x06, 0x3d, 0x06, 0x04, 0x7b, 0x04, 0x06, 0xdc, 0x04, 0x07, 0x83,
   /* -1200, */  0x04, 0x0e, 0x19, 0x12, 0x04, 0x00, 0x10, 0x08, 0x8e, 0x10, 0x08, 0x69, 0x0e, 0x04, 0x12, 0x0d,
   /* -1210, */  0x04, 0x2d, 0x03, 0x10, 0xb9, 0x04, 0x05, 0xd1, 0x04, 0x07, 0x6e, 0x04, 0x06, 0x20, 0x07, 0x04,
   /* -1220, */  0x74, 0x04, 0x0b, 0xfc, 0x0a, 0x04, 0x5c, 0x04, 0x05, 0x27, 0x04, 0x09, 0x3d, 0x04, 0x08, 0x7d,
   /* -1230, */  0x04, 0x0f, 0xae, 0x04, 0x0d, 0x99, 0x04, 0x06, 0xae, 0x04, 0x04, 0xda, 0x09, 0x04, 0x09, 0x08,
   /* -1240, */  0x11, 0x22, 0x04, 0x0f, 0x1c, 0x04, 0x07, 0xe6, 0x04, 0x0e, 0xcb, 0x05, 0x08, 0xbd, 0x04, 0x07,
   /* -1250, */  0x08, 0x04, 0x0f, 0xa3, 0x04, 0x06, 0x57, 0x04, 0x05, 0xb4, 0x04, 0x0f, 0x5d, 0x04, 0x08, 0xc7,
   /* -1260, */  0x08, 0x0b, 0xf4, 0x04, 0x07, 0xf8, 0x04, 0x07, 0x30, 0x04, 0x07, 0xbe, 0x04, 0x08, 0x57, 0x05,
   /* -1270, */  0x0d, 0x46, 0x04, 0x04, 0xfe, 0x04, 0x06, 0x0a, 0x04, 0x05, 0x4e, 0x04, 0x0e, 0x3b, 0x04, 0x08,
   /* -1280, */  0x0b, 0x04, 0x09, 0x30, 0x04, 0x08, 0xe9, 0x05, 0x05, 0xee, 0x04, 0x06, 0xc5, 0x04, 0x06, 0xf2,
   /* -1290, */  0x04, 0x06, 0x7b, 0x04, 0x09, 0xa1, 0x04, 0x05, 0xf1, 0x04, 0x08, 0x1e, 0x04, 0x07, 0x44, 0x04,
   /* -12A0, */  0x0b, 0xdd, 0x04, 0x0d, 0xfb, 0x04, 0x04, 0xaa, 0x04, 0x0b, 0xe3, 0x07, 0x0e, 0xee, 0x04, 0x0f,
   /* -12B0, */  0x09, 0x04, 0x0e, 0xb4, 0x04, 0x0d, 0xbe, 0x04, 0x10, 0xc5, 0x04, 0x08, 0x30, 0x05, 0x0f, 0x30,
   /* -12C0, */  0x04, 0x07, 0x59, 0x04, 0x0a, 0x0f, 0x06, 0x0e, 0x61, 0x04, 0x04, 0x81, 0x04, 0x0d, 0xab, 0x04,
   /* -12D0, */  0x0d, 0x93, 0x04, 0x11, 0x6b, 0x04, 0x0e, 0x96, 0x05, 0x04, 0x66, 0x09, 0x04, 0x6b, 0x0b, 0x04,
   /* -12E0, */  0x46, 0x04, 0x0c, 0xe1

};

/*
 * Definitions for:
 * The Presence-Specific Static Dictionary for Signaling
 * http://www.ietf.org/rfc/rfc5112.txt?number=5112
 */
#define PRESENCE_STATE_LENGTH 0x0d93

static const guint8 presence_state_identifier[STATE_BUFFER_SIZE] =
{
   /* -0000, */  0xd9, 0x42, 0x29, 0x7d, 0x0b, 0xb3, 0x8f, 0xc0, 0x1d, 0x67, 0x41, 0xd6, 0xb3, 0xb4, 0x81, 0x57,
   /* -0010, */  0xac, 0x8e, 0x1b, 0xe0
};

static const guint8 presence_static_dictionary_for_sigcomp[PRESENCE_STATE_LENGTH] =
{
   /* -0000, */  0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x65, 0x6e, 0x74, 0x65,
   /* -0010, */  0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x64, 0x65, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64,
   /* -0020, */  0x69, 0x73, 0x67, 0x75, 0x73, 0x74, 0x65, 0x64, 0x69, 0x6e, 0x64, 0x75, 0x73, 0x74, 0x72, 0x69,
   /* -0030, */  0x61, 0x6c, 0x61, 0x73, 0x74, 0x2d, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x3d, 0x68, 0x75, 0x6d, 0x69,
   /* -0040, */  0x6c, 0x69, 0x61, 0x74, 0x65, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x3d, 0x61, 0x75, 0x74, 0x6f,
   /* -0050, */  0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x63, 0x75, 0x72, 0x69, 0x6f, 0x75, 0x73, 0x70, 0x69, 0x72,
   /* -0060, */  0x69, 0x74, 0x73, 0x2d, 0x49, 0x4e, 0x44, 0x50, 0x73, 0x65, 0x6e, 0x64, 0x2d, 0x6f, 0x6e, 0x6c,
   /* -0070, */  0x79, 0x70, 0x61, 0x74, 0x68, 0x65, 0x61, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x6c, 0x65, 0x73,
   /* -0080, */  0x73, 0x6c, 0x65, 0x65, 0x70, 0x79, 0x69, 0x6e, 0x2d, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61,
   /* -0090, */  0x6c, 0x6f, 0x6e, 0x65, 0x6c, 0x79, 0x70, 0x6c, 0x61, 0x79, 0x66, 0x75, 0x6c, 0x6f, 0x77, 0x65,
   /* -00A0, */  0x72, 0x74, 0x68, 0x61, 0x6e, 0x6e, 0x6f, 0x79, 0x65, 0x64, 0x75, 0x6e, 0x63, 0x6f, 0x6d, 0x66,
   /* -00B0, */  0x6f, 0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3d, 0x63, 0x6f,
   /* -00C0, */  0x6e, 0x66, 0x75, 0x73, 0x65, 0x64, 0x76, 0x61, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x63, 0x6c,
   /* -00D0, */  0x75, 0x62, 0x75, 0x73, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x69, 0x72, 0x63,
   /* -00E0, */  0x72, 0x61, 0x66, 0x74, 0x68, 0x69, 0x72, 0x73, 0x74, 0x79, 0x63, 0x6f, 0x75, 0x72, 0x69, 0x65,
   /* -00F0, */  0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x68, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x66, 0x6f,
   /* -0100, */  0x66, 0x66, 0x69, 0x63, 0x65, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x3d, 0x61, 0x72, 0x65, 0x6e,
   /* -0110, */  0x61, 0x62, 0x6c, 0x65, 0x64, 0x3d, 0x52, 0x45, 0x46, 0x45, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54,
   /* -0120, */  0x45, 0x52, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6d, 0x70, 0x79, 0x70, 0x72,
   /* -0130, */  0x65, 0x66, 0x69, 0x78, 0x3d, 0x68, 0x61, 0x6c, 0x66, 0x72, 0x65, 0x69, 0x67, 0x68, 0x74, 0x6d,
   /* -0140, */  0x65, 0x61, 0x6e, 0x67, 0x72, 0x79, 0x53, 0x55, 0x42, 0x53, 0x43, 0x52, 0x49, 0x42, 0x45, 0x70,
   /* -0150, */  0x72, 0x6f, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3d,
   /* -0160, */  0x61, 0x70, 0x70, 0x72, 0x6f, 0x76, 0x65, 0x64, 0x68, 0x6f, 0x6c, 0x69, 0x64, 0x61, 0x79, 0x75,
   /* -0170, */  0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x70, 0x61, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x4d, 0x45, 0x53,
   /* -0180, */  0x53, 0x41, 0x47, 0x45, 0x77, 0x6f, 0x72, 0x72, 0x69, 0x65, 0x64, 0x68, 0x75, 0x6d, 0x62, 0x6c,
   /* -0190, */  0x65, 0x64, 0x61, 0x69, 0x72, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x73, 0x68, 0x61, 0x6d, 0x65, 0x64,
   /* -01A0, */  0x70, 0x6c, 0x61, 0x79, 0x69, 0x6e, 0x67, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x68, 0x75,
   /* -01B0, */  0x6e, 0x67, 0x72, 0x79, 0x63, 0x72, 0x61, 0x6e, 0x6b, 0x79, 0x61, 0x6d, 0x61, 0x7a, 0x65, 0x64,
   /* -01C0, */  0x61, 0x66, 0x72, 0x61, 0x69, 0x64, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x4e, 0x4f, 0x54, 0x49,
   /* -01D0, */  0x46, 0x59, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x43, 0x41, 0x4e, 0x43, 0x45, 0x4c, 0x66, 0x72,
   /* -01E0, */  0x69, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x73, 0x74, 0x61, 0x6c, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79,
   /* -01F0, */  0x70, 0x72, 0x69, 0x73, 0x6f, 0x6e, 0x69, 0x6e, 0x5f, 0x61, 0x77, 0x65, 0x62, 0x72, 0x61, 0x76,
   /* -0200, */  0x65, 0x71, 0x75, 0x69, 0x65, 0x74, 0x62, 0x6f, 0x72, 0x65, 0x64, 0x50, 0x52, 0x41, 0x43, 0x4b,
   /* -0210, */  0x70, 0x72, 0x6f, 0x75, 0x64, 0x66, 0x69, 0x78, 0x65, 0x64, 0x68, 0x6f, 0x74, 0x65, 0x6c, 0x68,
   /* -0220, */  0x61, 0x70, 0x70, 0x79, 0x63, 0x61, 0x66, 0x65, 0x63, 0x69, 0x64, 0x3d, 0x62, 0x61, 0x6e, 0x6b,
   /* -0230, */  0x6d, 0x69, 0x6e, 0x3d, 0x61, 0x77, 0x61, 0x79, 0x6d, 0x61, 0x78, 0x3d, 0x6d, 0x65, 0x61, 0x6c,
   /* -0240, */  0x62, 0x75, 0x73, 0x79, 0x77, 0x6f, 0x72, 0x6b, 0x75, 0x72, 0x6e, 0x3d, 0x63, 0x6f, 0x6c, 0x64,
   /* -0250, */  0x68, 0x75, 0x72, 0x74, 0x6a, 0x65, 0x61, 0x6c, 0x6f, 0x75, 0x73, 0x70, 0x69, 0x72, 0x69, 0x74,
   /* -0260, */  0x73, 0x2d, 0x75, 0x73, 0x65, 0x72, 0x2d, 0x70, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65, 0x72, 0x6e,
   /* -0270, */  0x6d, 0x65, 0x6e, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
   /* -0280, */  0x6f, 0x72, 0x65, 0x66, 0x65, 0x72, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x66,
   /* -0290, */  0x6f, 0x72, 0x65, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d,
   /* -02A0, */  0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x73,
   /* -02B0, */  0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x64, 0x3d, 0x68, 0x69, 0x67, 0x68, 0x65, 0x72,
   /* -02C0, */  0x74, 0x68, 0x61, 0x6e, 0x78, 0x69, 0x6f, 0x75, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2d,
   /* -02D0, */  0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x62, 0x72, 0x65, 0x61,
   /* -02E0, */  0x6b, 0x66, 0x61, 0x73, 0x74, 0x61, 0x64, 0x69, 0x75, 0x6d, 0x73, 0x67, 0x2d, 0x74, 0x61, 0x6b,
   /* -02F0, */  0x65, 0x72, 0x65, 0x6d, 0x6f, 0x72, 0x73, 0x65, 0x66, 0x75, 0x6c, 0x6c, 0x3a, 0x63, 0x69, 0x76,
   /* -0300, */  0x69, 0x63, 0x4c, 0x6f, 0x63, 0x6f, 0x6e, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x71, 0x75,
   /* -0310, */  0x61, 0x6c, 0x73, 0x74, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x77, 0x61, 0x74, 0x65, 0x72, 0x63,
   /* -0320, */  0x72, 0x61, 0x66, 0x74, 0x65, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x3a, 0x62, 0x61, 0x73, 0x69, 0x63,
   /* -0330, */  0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x63, 0x6c, 0x65, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79,
   /* -0340, */  0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x64, 0x75, 0x6e, 0x74, 0x69, 0x6c, 0x3d, 0x61, 0x64, 0x64,
   /* -0350, */  0x65, 0x64, 0x75, 0x72, 0x69, 0x3d, 0x77, 0x68, 0x61, 0x74, 0x70, 0x65, 0x72, 0x6d, 0x61, 0x6e,
   /* -0360, */  0x65, 0x6e, 0x74, 0x2d, 0x61, 0x62, 0x73, 0x65, 0x6e, 0x63, 0x65, 0x6d, 0x62, 0x61, 0x72, 0x72,
   /* -0370, */  0x61, 0x73, 0x73, 0x65, 0x64, 0x65, 0x61, 0x63, 0x74, 0x69, 0x76, 0x61, 0x74, 0x65, 0x64, 0x69,
   /* -0380, */  0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x65, 0x64, 0x69, 0x6e, 0x6e, 0x65, 0x72, 0x76, 0x6f, 0x75,
   /* -0390, */  0x73, 0x65, 0x6c, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x65, 0x6c, 0x69, 0x65, 0x76, 0x65, 0x64,
   /* -03A0, */  0x66, 0x6c, 0x69, 0x72, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x75, 0x73, 0x61, 0x67, 0x65, 0x2d, 0x72,
   /* -03B0, */  0x75, 0x6c, 0x65, 0x73, 0x65, 0x72, 0x76, 0x63, 0x61, 0x70, 0x73, 0x70, 0x68, 0x65, 0x72, 0x65,
   /* -03C0, */  0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x65,
   /* -03D0, */  0x3d, 0x62, 0x61, 0x72, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x65, 0x78, 0x74,
   /* -03E0, */  0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2d, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x65, 0x74, 0x69, 0x6d, 0x65,
   /* -03F0, */  0x2d, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x64, 0x69, 0x61, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f,
   /* -0400, */  0x6c, 0x6f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x69, 0x6e, 0x67, 0x2d, 0x77, 0x69, 0x6c, 0x6c,
   /* -0410, */  0x69, 0x6e, 0x67, 0x6e, 0x65, 0x73, 0x73, 0x70, 0x65, 0x63, 0x74, 0x61, 0x74, 0x6f, 0x72, 0x65,
   /* -0420, */  0x73, 0x69, 0x64, 0x65, 0x6e, 0x63, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2d, 0x70, 0x61, 0x63, 0x6b,
   /* -0430, */  0x61, 0x67, 0x65, 0x73, 0x75, 0x70, 0x65, 0x72, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x65, 0x73, 0x74,
   /* -0440, */  0x61, 0x75, 0x72, 0x61, 0x6e, 0x74, 0x72, 0x75, 0x63, 0x6b, 0x70, 0x6c, 0x6d, 0x6f, 0x62, 0x69,
   /* -0450, */  0x6c, 0x69, 0x74, 0x79, 0x6a, 0x6f, 0x69, 0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x70, 0x72, 0x69,
   /* -0460, */  0x61, 0x74, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x65, 0x72, 0x69, 0x6e,
   /* -0470, */  0x67, 0x69, 0x76, 0x65, 0x75, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x61, 0x6e,
   /* -0480, */  0x67, 0x75, 0x61, 0x67, 0x65, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
   /* -0490, */  0x2d, 0x73, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2d, 0x6f, 0x66,
   /* -04A0, */  0x2d, 0x77, 0x6f, 0x72, 0x73, 0x68, 0x69, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2d, 0x74, 0x79, 0x70,
   /* -04B0, */  0x65, 0x3d, 0x3a, 0x74, 0x69, 0x6d, 0x65, 0x64, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2d,
   /* -04C0, */  0x69, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x65, 0x75, 0x74,
   /* -04D0, */  0x72, 0x61, 0x6c, 0x49, 0x4e, 0x46, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x69, 0x65, 0x6d,
   /* -04E0, */  0x65, 0x6e, 0x73, 0x2d, 0x52, 0x54, 0x50, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x73, 0x65, 0x72, 0x76,
   /* -04F0, */  0x69, 0x63, 0x65, 0x2d, 0x69, 0x64, 0x6c, 0x65, 0x2d, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f,
   /* -0500, */  0x6c, 0x64, 0x3d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70,
   /* -0510, */  0x6f, 0x72, 0x74, 0x6f, 0x6f, 0x62, 0x72, 0x69, 0x67, 0x68, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65,
   /* -0520, */  0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x3d, 0x3a, 0x67, 0x65, 0x6f, 0x70, 0x72, 0x69,
   /* -0530, */  0x76, 0x31, 0x30, 0x30, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x68, 0x69, 0x70,
   /* -0540, */  0x6f, 0x63, 0x2d, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x75, 0x72, 0x70, 0x72, 0x69,
   /* -0550, */  0x73, 0x65, 0x64, 0x61, 0x72, 0x6b, 0x75, 0x72, 0x6e, 0x3a, 0x6f, 0x6d, 0x61, 0x3a, 0x78, 0x6d,
   /* -0560, */  0x6c, 0x3a, 0x70, 0x72, 0x73, 0x3a, 0x70, 0x69, 0x64, 0x66, 0x3a, 0x6f, 0x6d, 0x61, 0x2d, 0x70,
   /* -0570, */  0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x6f, 0x69, 0x73, 0x79, 0x3a,
   /* -0580, */  0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x2d, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2d, 0x73, 0x65,
   /* -0590, */  0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x64, 0x6f, 0x6f, 0x72, 0x73, 0x63, 0x68, 0x6f, 0x6f,
   /* -05A0, */  0x6c, 0x70, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d,
   /* -05B0, */  0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6d, 0x65, 0x65, 0x74,
   /* -05C0, */  0x69, 0x6e, 0x67, 0x63, 0x61, 0x6c, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x74, 0x6f, 0x72,
   /* -05D0, */  0x65, 0x74, 0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x65, 0x78, 0x70, 0x69, 0x72, 0x79, 0x3a,
   /* -05E0, */  0x77, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x69, 0x6e, 0x66, 0x6f, 0x66, 0x66, 0x65, 0x6e, 0x64,
   /* -05F0, */  0x65, 0x64, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6f, 0x6f, 0x6b, 0x69, 0x6e, 0x67, 0x2d,
   /* -0600, */  0x66, 0x6f, 0x72, 0x2d, 0x77, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x77, 0x61, 0x74, 0x63, 0x68,
   /* -0610, */  0x65, 0x72, 0x2d, 0x6c, 0x69, 0x73, 0x74, 0x72, 0x65, 0x65, 0x74, 0x70, 0x6c, 0x61, 0x63, 0x65,
   /* -0620, */  0x2d, 0x69, 0x73, 0x66, 0x6f, 0x63, 0x75, 0x73, 0x6f, 0x75, 0x6e, 0x64, 0x65, 0x72, 0x77, 0x61,
   /* -0630, */  0x79, 0x68, 0x6f, 0x6d, 0x65, 0x70, 0x61, 0x67, 0x65, 0x70, 0x72, 0x69, 0x76, 0x61, 0x63, 0x79,
   /* -0640, */  0x77, 0x61, 0x72, 0x65, 0x68, 0x6f, 0x75, 0x73, 0x65, 0x72, 0x2d, 0x69, 0x6e, 0x70, 0x75, 0x74,
   /* -0650, */  0x72, 0x61, 0x76, 0x65, 0x6c, 0x62, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76,
   /* -0660, */  0x65, 0x2d, 0x6f, 0x6e, 0x6c, 0x79, 0x3a, 0x72, 0x6c, 0x6d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x75,
   /* -0670, */  0x65, 0x3d, 0x3a, 0x63, 0x61, 0x70, 0x73, 0x6c, 0x65, 0x65, 0x70, 0x69, 0x6e, 0x67, 0x75, 0x69,
   /* -0680, */  0x6c, 0x74, 0x79, 0x69, 0x6e, 0x76, 0x69, 0x6e, 0x63, 0x69, 0x62, 0x6c, 0x65, 0x76, 0x65, 0x6e,
   /* -0690, */  0x74, 0x3d, 0x6d, 0x6f, 0x6f, 0x64, 0x79, 0x70, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x3d, 0x70,
   /* -06A0, */  0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x76, 0x69, 0x64, 0x65, 0x6f, 0x66, 0x72, 0x6f, 0x6d,
   /* -06B0, */  0x3d, 0x61, 0x75, 0x64, 0x69, 0x6f, 0x63, 0x61, 0x72, 0x64, 0x70, 0x6f, 0x73, 0x3d, 0x61, 0x75,
   /* -06C0, */  0x74, 0x6f, 0x6d, 0x61, 0x74, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
   /* -06D0, */  0x6f, 0x74, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
   /* -06E0, */  0x49, 0x44, 0x69, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x69, 0x73, 0x61, 0x70, 0x70,
   /* -06F0, */  0x6f, 0x69, 0x6e, 0x74, 0x65, 0x64, 0x6e, 0x6f, 0x74, 0x65, 0x2d, 0x77, 0x65, 0x6c, 0x6c, 0x69,
   /* -0700, */  0x62, 0x72, 0x61, 0x72, 0x79, 0x3a, 0x64, 0x61, 0x74, 0x61, 0x2d, 0x6d, 0x6f, 0x64, 0x65, 0x6c,
   /* -0710, */  0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x69, 0x76, 0x69, 0x63, 0x41, 0x64, 0x64, 0x72,
   /* -0720, */  0x65, 0x73, 0x73, 0x61, 0x72, 0x63, 0x61, 0x73, 0x74, 0x69, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
   /* -0730, */  0x74, 0x65, 0x64, 0x69, 0x6e, 0x64, 0x69, 0x67, 0x6e, 0x61, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x72,
   /* -0740, */  0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x73, 0x68, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x63, 0x6c, 0x61,
   /* -0750, */  0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
   /* -0760, */  0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x64, 0x2d, 0x62, 0x79, 0x3a, 0x63, 0x69, 0x70, 0x69, 0x64,
   /* -0770, */  0x66, 0x2d, 0x66, 0x75, 0x6c, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x3d, 0x61, 0x63, 0x74, 0x6f,
   /* -0780, */  0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x64, 0x62, 0x75, 0x73, 0x69, 0x6e, 0x65, 0x73, 0x73, 0x65,
   /* -0790, */  0x72, 0x69, 0x6f, 0x75, 0x73, 0x65, 0x6c, 0x3d, 0x3a, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x78,
   /* -07A0, */  0x76, 0x61, 0x6c, 0x75, 0x65, 0x3d, 0x3a, 0x72, 0x70, 0x69, 0x64, 0x75, 0x72, 0x6e, 0x3a, 0x69,
   /* -07B0, */  0x65, 0x74, 0x66, 0x3a, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x3a, 0x78, 0x6d, 0x6c, 0x2d, 0x70,
   /* -07C0, */  0x61, 0x74, 0x63, 0x68, 0x2d, 0x6f, 0x70, 0x73, 0x65, 0x63, 0x2d, 0x61, 0x67, 0x72, 0x65, 0x65,
   /* -07D0, */  0x61, 0x72, 0x6c, 0x79, 0x2d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x70, 0x61, 0x74,
   /* -07E0, */  0x69, 0x63, 0x69, 0x70, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x74, 0x68, 0x65, 0x2d, 0x70, 0x68,
   /* -07F0, */  0x6f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2d, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62,
   /* -0800, */  0x69, 0x6c, 0x69, 0x74, 0x79, 0x70, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65,
   /* -0810, */  0x78, 0x63, 0x69, 0x74, 0x65, 0x64, 0x70, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69,
   /* -0820, */  0x6f, 0x6e, 0x6f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2d, 0x70, 0x72, 0x69, 0x6f,
   /* -0830, */  0x72, 0x69, 0x74, 0x79, 0x3d, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2d,
   /* -0840, */  0x63, 0x6c, 0x61, 0x73, 0x73, 0x72, 0x6f, 0x6f, 0x6d, 0x75, 0x73, 0x74, 0x55, 0x6e, 0x64, 0x65,
   /* -0850, */  0x72, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x2d, 0x6e, 0x61, 0x6d,
   /* -0860, */  0x65, 0x3d, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
   /* -0870, */  0x6f, 0x6e, 0x73, 0x2d, 0x62, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x73, 0x64, 0x70, 0x2d, 0x61,
   /* -0880, */  0x6e, 0x61, 0x74, 0x74, 0x65, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x72, 0x75, 0x65, 0x3a, 0x70, 0x69,
   /* -0890, */  0x64, 0x66, 0x2d, 0x64, 0x69, 0x66, 0x66, 0x72, 0x75, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x64,
   /* -08A0, */  0x75, 0x70, 0x6c, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x63, 0x6f,
   /* -08B0, */  0x6e, 0x74, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x69, 0x65, 0x73, 0x68, 0x6f, 0x70, 0x70,
   /* -08C0, */  0x69, 0x6e, 0x67, 0x2d, 0x61, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x3d, 0x61, 0x70, 0x70, 0x6f,
   /* -08D0, */  0x69, 0x6e, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x3d, 0x61, 0x73, 0x73, 0x6f, 0x63,
   /* -08E0, */  0x69, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x69, 0x6e, 0x74, 0x65,
   /* -08F0, */  0x72, 0x65, 0x73, 0x74, 0x65, 0x64, 0x65, 0x76, 0x63, 0x61, 0x70, 0x73, 0x74, 0x61, 0x74, 0x75,
   /* -0900, */  0x73, 0x3d, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x77, 0x69,
   /* -0910, */  0x6e, 0x66, 0x6f, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x69, 0x6e, 0x2d, 0x74, 0x72, 0x61,
   /* -0920, */  0x6e, 0x73, 0x69, 0x74, 0x75, 0x70, 0x6c, 0x65, 0x68, 0x6f, 0x73, 0x70, 0x69, 0x74, 0x61, 0x6c,
   /* -0930, */  0x61, 0x6e, 0x67, 0x3d, 0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x6e, 0x73, 0x3d, 0x73, 0x69, 0x63, 0x6b,
   /* -0940, */  0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x63, 0x65, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x3f, 0x3e, 0x63,
   /* -0950, */  0x6c, 0x6f, 0x73, 0x65, 0x64, 0x05, 0x0d, 0x34, 0x08, 0x0d, 0x06, 0x09, 0x0c, 0xe3, 0x07, 0x0d,
   /* -0960, */  0x48, 0x06, 0x0d, 0x36, 0x13, 0x0b, 0xab, 0x05, 0x09, 0x65, 0x07, 0x0c, 0xd4, 0x08, 0x0d, 0x40,
   /* -0970, */  0x05, 0x0d, 0x23, 0x05, 0x0c, 0x35, 0x07, 0x0c, 0xae, 0x05, 0x0d, 0x2f, 0x06, 0x08, 0xb9, 0x05,
   /* -0980, */  0x07, 0x2b, 0x04, 0x0d, 0x12, 0x06, 0x0d, 0x4f, 0x09, 0x0c, 0x2c, 0x04, 0x0c, 0x89, 0x04, 0x0a,
   /* -0990, */  0xf6, 0x09, 0x0b, 0x57, 0x0b, 0x0b, 0x05, 0x08, 0x0a, 0xda, 0x06, 0x0a, 0xda, 0x06, 0x04, 0x89,
   /* -09A0, */  0x05, 0x0b, 0xa6, 0x04, 0x0b, 0x94, 0x06, 0x05, 0x05, 0x07, 0x0b, 0x3f, 0x0e, 0x0b, 0xba, 0x07,
   /* -09B0, */  0x0b, 0x98, 0x0a, 0x0c, 0x8d, 0x09, 0x0b, 0x6d, 0x09, 0x0c, 0x8e, 0x0e, 0x0c, 0x48, 0x0a, 0x0c,
   /* -09C0, */  0xb2, 0x1d, 0x09, 0x56, 0x0d, 0x0c, 0x38, 0x06, 0x07, 0xba, 0x0b, 0x08, 0xb9, 0x0b, 0x07, 0xec,
   /* -09D0, */  0x06, 0x0d, 0x02, 0x0a, 0x0a, 0x46, 0x04, 0x08, 0xf4, 0x06, 0x0b, 0x6a, 0x04, 0x0a, 0xb6, 0x0c,
   /* -09E0, */  0x0c, 0x55, 0x08, 0x0a, 0x31, 0x04, 0x0a, 0x92, 0x08, 0x0a, 0x1b, 0x05, 0x0a, 0xb1, 0x04, 0x08,
   /* -09F0, */  0xc0, 0x05, 0x0a, 0x27, 0x05, 0x0a, 0xa7, 0x05, 0x0a, 0xac, 0x04, 0x0a, 0xba, 0x04, 0x07, 0xdc,
   /* -0A00, */  0x05, 0x08, 0xad, 0x0a, 0x09, 0x29, 0x0a, 0x08, 0xa7, 0x05, 0x0a, 0x56, 0x05, 0x0b, 0x4d, 0x07,
   /* -0A10, */  0x09, 0x2a, 0x0d, 0x09, 0xa7, 0x0b, 0x07, 0xa9, 0x06, 0x09, 0xc6, 0x0b, 0x0b, 0x5f, 0x0c, 0x09,
   /* -0A20, */  0xdf, 0x0b, 0x09, 0xe0, 0x06, 0x07, 0xcb, 0x0c, 0x0a, 0x0b, 0x09, 0x09, 0x20, 0x08, 0x0a, 0x97,
   /* -0A30, */  0x07, 0x09, 0xe0, 0x07, 0x0c, 0xfb, 0x06, 0x0a, 0x8c, 0x0e, 0x09, 0x7f, 0x0a, 0x09, 0x87, 0x0b,
   /* -0A40, */  0x0c, 0x71, 0x0a, 0x0c, 0x71, 0x06, 0x07, 0x93, 0x05, 0x0a, 0x66, 0x04, 0x08, 0x67, 0x04, 0x09,
   /* -0A50, */  0xba, 0x08, 0x09, 0x20, 0x0a, 0x0b, 0x72, 0x05, 0x0a, 0x72, 0x08, 0x07, 0xb3, 0x0b, 0x0a, 0xc5,
   /* -0A60, */  0x07, 0x09, 0xf2, 0x07, 0x08, 0x89, 0x04, 0x08, 0xad, 0x08, 0x0a, 0xbe, 0x06, 0x0c, 0x9f, 0x0b,
   /* -0A70, */  0x06, 0xd0, 0x0e, 0x08, 0x26, 0x08, 0x0a, 0x9f, 0x07, 0x09, 0xc6, 0x0a, 0x0c, 0x69, 0x07, 0x08,
   /* -0A80, */  0x85, 0x05, 0x0b, 0x7c, 0x07, 0x0a, 0x39, 0x0c, 0x09, 0x34, 0x07, 0x0a, 0x21, 0x09, 0x08, 0x7d,
   /* -0A90, */  0x07, 0x0c, 0xf5, 0x0b, 0x0c, 0xa3, 0x14, 0x06, 0xa6, 0x0d, 0x08, 0xb2, 0x0c, 0x07, 0x2a, 0x0c,
   /* -0AA0, */  0x08, 0xb3, 0x04, 0x07, 0x56, 0x07, 0x09, 0x1a, 0x04, 0x07, 0x52, 0x07, 0x07, 0x40, 0x05, 0x07,
   /* -0AB0, */  0x4d, 0x07, 0x0b, 0x80, 0x06, 0x07, 0x47, 0x16, 0x06, 0x91, 0x08, 0x0c, 0x62, 0x10, 0x09, 0xcf,
   /* -0AC0, */  0x10, 0x07, 0xdd, 0x09, 0x0a, 0xf6, 0x09, 0x06, 0xfc, 0x0c, 0x0b, 0x17, 0x07, 0x07, 0x39, 0x04,
   /* -0AD0, */  0x06, 0xf8, 0x07, 0x09, 0xa1, 0x06, 0x06, 0x8d, 0x05, 0x07, 0x21, 0x04, 0x0a, 0x55, 0x09, 0x0a,
   /* -0AE0, */  0xd2, 0x0c, 0x0a, 0xcf, 0x13, 0x06, 0xc8, 0x0a, 0x08, 0xec, 0x07, 0x0d, 0x06, 0x0b, 0x08, 0x0c,
   /* -0AF0, */  0x14, 0x0b, 0xd5, 0x12, 0x07, 0xbe, 0x0d, 0x07, 0xd1, 0x16, 0x08, 0x01, 0x14, 0x0b, 0xf1, 0x06,
   /* -0B00, */  0x05, 0xb4, 0x07, 0x04, 0x56, 0x09, 0x04, 0x17, 0x0c, 0x0a, 0xea, 0x09, 0x04, 0x1f, 0x0a, 0x07,
   /* -0B10, */  0x7e, 0x0b, 0x07, 0x6a, 0x07, 0x0c, 0x0f, 0x0b, 0x07, 0xa0, 0x0a, 0x0c, 0x96, 0x06, 0x05, 0x28,
   /* -0B20, */  0x06, 0x0a, 0x7d, 0x05, 0x06, 0x1f, 0x07, 0x05, 0x8b, 0x0a, 0x04, 0x3c, 0x06, 0x05, 0xae, 0x04,
   /* -0B30, */  0x06, 0x50, 0x09, 0x0a, 0xe2, 0x06, 0x05, 0xf6, 0x07, 0x07, 0xfd, 0x09, 0x0b, 0x33, 0x0a, 0x0c,
   /* -0B40, */  0xec, 0x0a, 0x0a, 0x83, 0x07, 0x06, 0x54, 0x06, 0x04, 0x90, 0x04, 0x05, 0x3f, 0x05, 0x0a, 0x92,
   /* -0B50, */  0x07, 0x07, 0x8a, 0x07, 0x08, 0xcc, 0x08, 0x09, 0xea, 0x07, 0x04, 0x96, 0x05, 0x06, 0x10, 0x08,
   /* -0B60, */  0x07, 0x98, 0x0a, 0x06, 0xf1, 0x08, 0x04, 0x79, 0x09, 0x0b, 0x22, 0x07, 0x0b, 0x8e, 0x07, 0x0b,
   /* -0B70, */  0x46, 0x04, 0x0d, 0x3c, 0x06, 0x04, 0x80, 0x08, 0x07, 0x12, 0x09, 0x09, 0x4a, 0x07, 0x04, 0xe3,
   /* -0B80, */  0x07, 0x05, 0x84, 0x05, 0x09, 0x7a, 0x05, 0x06, 0x01, 0x09, 0x09, 0x12, 0x04, 0x09, 0x52, 0x0d,
   /* -0B90, */  0x04, 0xaa, 0x0d, 0x08, 0x56, 0x08, 0x04, 0xdc, 0x07, 0x05, 0x92, 0x05, 0x05, 0x0c, 0x0a, 0x04,
   /* -0BA0, */  0x4c, 0x04, 0x06, 0x2c, 0x0b, 0x04, 0xd1, 0x04, 0x06, 0x24, 0x09, 0x0c, 0x40, 0x04, 0x04, 0xce,
   /* -0BB0, */  0x0c, 0x08, 0xc1, 0x11, 0x04, 0x00, 0x05, 0x07, 0x34, 0x0a, 0x06, 0x6a, 0x08, 0x0d, 0x28, 0x05,
   /* -0BC0, */  0x06, 0x1a, 0x0a, 0x04, 0x28, 0x07, 0x0a, 0xfe, 0x06, 0x04, 0xff, 0x08, 0x09, 0x94, 0x07, 0x05,
   /* -0BD0, */  0x76, 0x10, 0x08, 0x98, 0x06, 0x05, 0xf0, 0x06, 0x09, 0x03, 0x10, 0x09, 0x03, 0x09, 0x08, 0x1e,
   /* -0BE0, */  0x0a, 0x08, 0x3c, 0x06, 0x09, 0x9b, 0x0d, 0x0c, 0xbb, 0x07, 0x06, 0xe3, 0x05, 0x09, 0xcc, 0x06,
   /* -0BF0, */  0x0a, 0x15, 0x07, 0x04, 0x73, 0x05, 0x06, 0x73, 0x0d, 0x06, 0x73, 0x05, 0x08, 0x45, 0x08, 0x0a,
   /* -0C00, */  0x29, 0x09, 0x0a, 0x40, 0x05, 0x07, 0x1a, 0x0a, 0x07, 0x1a, 0x09, 0x0b, 0x4f, 0x09, 0x0c, 0xdb,
   /* -0C10, */  0x06, 0x05, 0xea, 0x06, 0x05, 0xde, 0x0a, 0x04, 0x0e, 0x0a, 0x0b, 0x0e, 0x09, 0x06, 0x86, 0x08,
   /* -0C20, */  0x05, 0x60, 0x0b, 0x07, 0x74, 0x09, 0x05, 0x4f, 0x08, 0x04, 0xf0, 0x07, 0x09, 0x90, 0x06, 0x08,
   /* -0C30, */  0x70, 0x0a, 0x0c, 0x21, 0x07, 0x05, 0x6f, 0x0b, 0x0c, 0xcc, 0x04, 0x07, 0x90, 0x07, 0x04, 0xea,
   /* -0C40, */  0x0a, 0x08, 0x33, 0x04, 0x06, 0x34, 0x09, 0x06, 0xdc, 0x04, 0x06, 0x40, 0x07, 0x05, 0x2e, 0x04,
   /* -0C50, */  0x06, 0x48, 0x06, 0x07, 0x87, 0x07, 0x05, 0x68, 0x0a, 0x0d, 0x1a, 0x07, 0x04, 0x45, 0x07, 0x05,
   /* -0C60, */  0x05, 0x08, 0x05, 0x0e, 0x08, 0x05, 0x58, 0x08, 0x04, 0xb6, 0x10, 0x09, 0xf8, 0x04, 0x06, 0x3c,
   /* -0C70, */  0x07, 0x09, 0xbc, 0x0c, 0x06, 0xd0, 0x0c, 0x0b, 0xe7, 0x04, 0x06, 0x44, 0x04, 0x0a, 0x31, 0x0b,
   /* -0C80, */  0x0c, 0x05, 0x04, 0x06, 0x28, 0x11, 0x07, 0x5a, 0x07, 0x0c, 0xc5, 0x07, 0x05, 0xa0, 0x0c, 0x09,
   /* -0C90, */  0x6f, 0x08, 0x0c, 0xbb, 0x08, 0x0a, 0x76, 0x09, 0x08, 0x16, 0x08, 0x08, 0x69, 0x06, 0x05, 0xe4,
   /* -0CA0, */  0x09, 0x04, 0x86, 0x07, 0x05, 0x38, 0x06, 0x0a, 0x4f, 0x08, 0x04, 0xc6, 0x0f, 0x08, 0xf4, 0x0b,
   /* -0CB0, */  0x04, 0x31, 0x07, 0x0a, 0x04, 0x07, 0x08, 0xa1, 0x0d, 0x0c, 0x55, 0x06, 0x05, 0xc0, 0x06, 0x05,
   /* -0CC0, */  0xba, 0x05, 0x05, 0x41, 0x08, 0x0b, 0x87, 0x08, 0x04, 0x89, 0x04, 0x05, 0x35, 0x0c, 0x0a, 0x5a,
   /* -0CD0, */  0x09, 0x04, 0x68, 0x09, 0x04, 0x9c, 0x0a, 0x06, 0xba, 0x06, 0x07, 0x0d, 0x05, 0x07, 0x25, 0x09,
   /* -0CE0, */  0x0b, 0x9d, 0x09, 0x0a, 0x69, 0x06, 0x0a, 0x6c, 0x04, 0x06, 0x38, 0x04, 0x06, 0x30, 0x07, 0x0d,
   /* -0CF0, */  0x13, 0x08, 0x08, 0x4c, 0x05, 0x06, 0x15, 0x06, 0x04, 0x50, 0x0a, 0x07, 0x04, 0x06, 0x07, 0xf7,
   /* -0D00, */  0x04, 0x08, 0x49, 0x0f, 0x08, 0x89, 0x0c, 0x09, 0x3f, 0x05, 0x06, 0x81, 0x11, 0x08, 0xdc, 0x0d,
   /* -0D10, */  0x04, 0x5c, 0x11, 0x06, 0x5a, 0x05, 0x0d, 0x0e, 0x06, 0x05, 0xd8, 0x04, 0x08, 0xd3, 0x06, 0x05,
   /* -0D20, */  0xd2, 0x07, 0x05, 0x7d, 0x06, 0x05, 0xcc, 0x07, 0x08, 0xd6, 0x05, 0x06, 0x0b, 0x07, 0x05, 0xa7,
   /* -0D30, */  0x05, 0x05, 0x16, 0x08, 0x05, 0x1a, 0x09, 0x05, 0x46, 0x06, 0x05, 0xc6, 0x06, 0x09, 0x31, 0x0d,
   /* -0D40, */  0x0b, 0xcf, 0x09, 0x08, 0x62, 0x08, 0x04, 0xf8, 0x04, 0x08, 0x54, 0x0a, 0x06, 0x7f, 0x04, 0x04,
   /* -0D50, */  0x71, 0x0c, 0x0c, 0x16, 0x04, 0x05, 0x2e, 0x08, 0x0b, 0x3f, 0x11, 0x0c, 0x23, 0x08, 0x0c, 0x7b,
   /* -0D60, */  0x09, 0x0b, 0xc7, 0x07, 0x07, 0xf6, 0x05, 0x0b, 0x3b, 0x09, 0x08, 0x75, 0x09, 0x0c, 0x81, 0x09,
   /* -0D70, */  0x06, 0xe9, 0x0b, 0x09, 0xb0, 0x07, 0x05, 0x22, 0x07, 0x04, 0xa3, 0x07, 0x06, 0xc2, 0x07, 0x05,
   /* -0D80, */  0x99, 0x05, 0x06, 0x06, 0x05, 0x05, 0xfc, 0x04, 0x09, 0xc3, 0x04, 0x06, 0x4c, 0x08, 0x04, 0xbe,
   /* -0D90, */  0x09, 0x0b, 0x2a
};

static GHashTable *state_buffer_table=NULL;


static void
sigcomp_init_udvm(void) {
    gchar  *partial_state_str;
    guint8 *sip_sdp_buff, *presence_buff;
    state_buffer_table = g_hash_table_new_full(g_str_hash,
                                               g_str_equal,
                                               g_free, /* key_destroy_func */
                                               g_free); /* value_destroy_func */
    /*
     * Store static dictionaries in hash table
     */
    sip_sdp_buff = (guint8 *)g_malloc(SIP_SDP_STATE_LENGTH + 8);

    partial_state_str = bytes_to_str(NULL, sip_sdp_state_identifier, 6);
    memset(sip_sdp_buff, 0, 8);
    sip_sdp_buff[0] = SIP_SDP_STATE_LENGTH >> 8;
    sip_sdp_buff[1] = SIP_SDP_STATE_LENGTH & 0xff;
    memcpy(sip_sdp_buff+8, sip_sdp_static_dictionaty_for_sigcomp, SIP_SDP_STATE_LENGTH);

    g_hash_table_insert(state_buffer_table, g_strdup(partial_state_str), sip_sdp_buff);
    wmem_free(NULL, partial_state_str);

    presence_buff = (guint8 *)g_malloc(PRESENCE_STATE_LENGTH + 8);

    partial_state_str = bytes_to_str(NULL, presence_state_identifier, 6);

    memset(presence_buff, 0, 8);
    presence_buff[0] = PRESENCE_STATE_LENGTH >> 8;
    presence_buff[1] = PRESENCE_STATE_LENGTH & 0xff;
    memcpy(presence_buff+8, presence_static_dictionary_for_sigcomp, PRESENCE_STATE_LENGTH);

    g_hash_table_insert(state_buffer_table, g_strdup(partial_state_str), presence_buff);
    wmem_free(NULL, partial_state_str);
}

static void
sigcomp_cleanup_udvm(void) {
    g_hash_table_destroy(state_buffer_table);
}


static int udvm_state_access(tvbuff_t *tvb, proto_tree *tree,guint8 *buff,guint16 p_id_start, guint16 p_id_length, guint16 state_begin, guint16 *state_length,
                             guint16 *state_address, guint16 *state_instruction,
                             gint hf_id)
{
    int      result_code = 0;
    guint32  n;
    guint16  k;
    guint16  buf_size_real;
    guint16  byte_copy_right;
    guint16  byte_copy_left;
    char     partial_state[STATE_BUFFER_SIZE]; /* Size is 6 - 20 */
    guint8  *state_buff;
    gchar   *partial_state_str;

    /*
     * Perform initial checks on validity of data
     * RFC 3320 :
     * 9.4.5.  STATE-ACCESS
     * :
     * Decompression failure occurs if partial_identifier_length does not
     * lie between 6 and 20 inclusive.  Decompression failure also occurs if
     * no state item matching the partial state identifier can be found, if
     * more than one state item matches the partial identifier, or if
     * partial_identifier_length is less than the minimum_access_length of
     * the matched state item. Otherwise, a state item is returned from the
     * state handler.
     */

    if (( p_id_length < STATE_MIN_ACCESS_LEN ) || ( p_id_length > STATE_BUFFER_SIZE )) {
        result_code = 1;
        return result_code;
    }

    n = 0;
    while ( n < p_id_length && n < STATE_BUFFER_SIZE && p_id_start + n < UDVM_MEMORY_SIZE ) {
        partial_state[n] = buff[p_id_start + n];
        n++;
    }
    partial_state_str = bytes_to_str(wmem_packet_scope(), partial_state, p_id_length);
    proto_tree_add_item(tree, hf_sigcomp_accessing_state, tvb, 0, -1, ENC_NA);
    proto_tree_add_string(tree,hf_id, tvb, 0, 0, partial_state_str);

    /* Debug
     * g_warning("State Access: partial state =%s",partial_state_str);
     * g_warning("g_hash_table_lookup = 0x%x",state_buff);
     * g_warning("State Access: partial state =%s",partial_state_str);
     */
    state_buff = (guint8 *)g_hash_table_lookup(state_buffer_table, partial_state_str);
    if ( state_buff == NULL ) {
        result_code = 2; /* No state match */
        return result_code;
    }
    /*
     * sip_sdp_static_dictionaty
     *
     * 8.4.  Byte copying
     * :
     * The string of bytes is copied in ascending order of memory address,
     * respecting the bounds set by byte_copy_left and byte_copy_right.
     * More precisely, if a byte is copied from/to Address m then the next
     * byte is copied from/to Address n where n is calculated as follows:
     *
     * Set k := m + 1 (modulo 2^16)
     * If k = byte_copy_right then set n := byte_copy_left, else set n := k
     *
     */

    /*
     * buff              = Where "state" will be stored
     * p_id_start        = Partial state identifier start pos in the buffer(buff)
     * p-id_length       = Partial state identifier length
     * state_begin       = Where to start to read state from
     * state_length      = Length of state
     * state_address     = Address where to store the state in the buffer(buff)
     * state_instruction =
     * FALSE             = Indicates that state_* is in the stored state
     */

    buf_size_real = (state_buff[0] << 8) | state_buff[1];

    /*
     * The value of
     * state_length MUST be taken from the returned item of state in the
     * case that the state_length operand is set to 0.
     *
     * The same is true of state_address, state_instruction.
     */
    if (*state_length == 0) {
        *state_length = buf_size_real;
    }
    if ( *state_address == 0 ) {
        *state_address = state_buff[2] << 8;
        *state_address = *state_address | state_buff[3];
    }
    if ( *state_instruction == 0 ) {
        *state_instruction = state_buff[4] << 8;
        *state_instruction = *state_instruction | state_buff[5];
    }

    /*
     * Decompression failure occurs if bytes are copied from beyond the end of
     * the state_value.
     */
    if ((state_begin + *state_length) > buf_size_real) {
        return 3;
    }

    /*
     * Note that decompression failure will always occur if the state_length
     * operand is set to 0 but the state_begin operand is non-zero.
     */
    if (*state_length == 0 && state_begin != 0) {
        return 17;
    }

    n = state_begin + 8;
    k = *state_address;

    /*
     * NOTE: Strictly speaking, byte_copy_left and byte_copy_right should
     *       not be used if this has been called for bytecode referenced in
     *       the message header. However, since the memory is initialised
     *       to zero, the code works OK.
     */
    byte_copy_right = buff[66] << 8;
    byte_copy_right = byte_copy_right | buff[67];
    byte_copy_left = buff[64] << 8;
    byte_copy_left = byte_copy_left | buff[65];
    /* debug
     *g_warning(" state_begin %u state_address %u",state_begin , *state_address);
     */
    while ( (gint32) n < (state_begin + *state_length + 8) && n < UDVM_MEMORY_SIZE ) {
        buff[k] = state_buff[n];
        /*  debug
            g_warning(" Loading 0x%x at address %u",buff[k] , k);
        */
        k = ( k + 1 ) & 0xffff;
        if ( k == byte_copy_right ) {
            k = byte_copy_left;
        }
        n++;
    }
    return 0;
    /*
     * End SIP
     */

}

static void udvm_state_create(guint8 *state_buff,guint8 *state_identifier,guint16 p_id_length) {

    char   partial_state[STATE_BUFFER_SIZE];
    guint  i;
    gchar *partial_state_str;
    gchar *dummy_buff;
    /*
     * Debug
     g_warning("Received items of state,state_length_buff[0]= %u, state_length_buff[1]= %u",
     state_length_buff[0],state_length_buff[1]);

    */
    i = 0;
    while ( i < p_id_length && i < STATE_BUFFER_SIZE ) {
        partial_state[i] = state_identifier[i];
        i++;
    }
    partial_state_str = bytes_to_str(NULL, partial_state, p_id_length);

    dummy_buff = (gchar *)g_hash_table_lookup(state_buffer_table, partial_state_str);
    if ( dummy_buff == NULL ) {
        g_hash_table_insert(state_buffer_table, g_strdup(partial_state_str), state_buff);
    } else {
        /* The buffer allocated by sigcomp-udvm.c wasn't needed so free it
         */
        g_free(state_buff);

    }
    wmem_free(NULL, partial_state_str);
}

#if 1
static void udvm_state_free(guint8 buff[] _U_,guint16 p_id_start _U_,guint16 p_id_length _U_) {
}
#else
void udvm_state_free(guint8 buff[],guint16 p_id_start,guint16 p_id_length) {
    char   partial_state[STATE_BUFFER_SIZE];
    guint  i;
    gchar *partial_state_str;

    gchar *dummy_buff;

    i = 0;
    while ( i < p_id_length && i < STATE_BUFFER_SIZE && p_id_start + i < UDVM_MEMORY_SIZE ) {
        partial_state[i] = buff[p_id_start + i];
        i++;
    }
    partial_state_str = bytes_to_str(NULL, partial_state, p_id_length);
    /* TODO Implement a state create counter before actually freeing states
     * Hmm is it a good idea to free the buffer at all?
     * g_warning("State-free on  %s ",partial_state_str);
     */
    dummy_buff = g_hash_table_lookup(state_buffer_table, partial_state_str);
    if ( dummy_buff != NULL ) {
        g_hash_table_remove (state_buffer_table, partial_state_str);
        g_free(dummy_buff);
    }
    wmem_free(NULL, partial_state_str);
}
#endif

/**********************************************************************************************
 *
 *                       SIGCOMP DECOMPRESSION
 *
 **********************************************************************************************/
#define SIGCOMP_INSTR_DECOMPRESSION_FAILURE     0
#define SIGCOMP_INSTR_AND                       1
#define SIGCOMP_INSTR_OR                        2
#define SIGCOMP_INSTR_NOT                       3
#define SIGCOMP_INSTR_LSHIFT                    4
#define SIGCOMP_INSTR_RSHIFT                    5
#define SIGCOMP_INSTR_ADD                       6
#define SIGCOMP_INSTR_SUBTRACT                  7
#define SIGCOMP_INSTR_MULTIPLY                  8
#define SIGCOMP_INSTR_DIVIDE                    9
#define SIGCOMP_INSTR_REMAINDER                 10
#define SIGCOMP_INSTR_SORT_ASCENDING            11
#define SIGCOMP_INSTR_SORT_DESCENDING           12
#define SIGCOMP_INSTR_SHA_1                     13
#define SIGCOMP_INSTR_LOAD                      14
#define SIGCOMP_INSTR_MULTILOAD                 15
#define SIGCOMP_INSTR_PUSH                      16
#define SIGCOMP_INSTR_POP                       17
#define SIGCOMP_INSTR_COPY                      18
#define SIGCOMP_INSTR_COPY_LITERAL              19
#define SIGCOMP_INSTR_COPY_OFFSET               20
#define SIGCOMP_INSTR_MEMSET                    21
#define SIGCOMP_INSTR_JUMP                      22
#define SIGCOMP_INSTR_COMPARE                   23
#define SIGCOMP_INSTR_CALL                      24
#define SIGCOMP_INSTR_RETURN                    25
#define SIGCOMP_INSTR_SWITCH                    26
#define SIGCOMP_INSTR_CRC                       27
#define SIGCOMP_INSTR_INPUT_BYTES               28
#define SIGCOMP_INSTR_INPUT_BITS                29
#define SIGCOMP_INSTR_INPUT_HUFFMAN             30
#define SIGCOMP_INSTR_STATE_ACCESS              31
#define SIGCOMP_INSTR_STATE_CREATE              32
#define SIGCOMP_INSTR_STATE_FREE                33
#define SIGCOMP_INSTR_OUTPUT                    34
#define SIGCOMP_INSTR_END_MESSAGE               35

static const value_string udvm_instruction_code_vals[] = {
    { SIGCOMP_INSTR_DECOMPRESSION_FAILURE,   "DECOMPRESSION-FAILURE" },
    { SIGCOMP_INSTR_AND,   "AND" },
    { SIGCOMP_INSTR_OR,   "OR" },
    { SIGCOMP_INSTR_NOT,   "NOT" },
    { SIGCOMP_INSTR_LSHIFT,   "LSHIFT" },
    { SIGCOMP_INSTR_RSHIFT,   "RSHIFT" },
    { SIGCOMP_INSTR_ADD,   "ADD" },
    { SIGCOMP_INSTR_SUBTRACT,   "SUBTRACT" },
    { SIGCOMP_INSTR_MULTIPLY,   "MULTIPLY" },
    { SIGCOMP_INSTR_DIVIDE,   "DIVIDE" },
    { SIGCOMP_INSTR_REMAINDER,   "REMAINDER" },
    { SIGCOMP_INSTR_SORT_ASCENDING,   "SORT-ASCENDING" },
    { SIGCOMP_INSTR_SORT_DESCENDING,   "SORT-DESCENDING" },
    { SIGCOMP_INSTR_SHA_1,   "SHA-1" },
    { SIGCOMP_INSTR_LOAD,   "LOAD" },
    { SIGCOMP_INSTR_MULTILOAD,   "MULTILOAD" },
    { SIGCOMP_INSTR_PUSH,   "PUSH" },
    { SIGCOMP_INSTR_POP,   "POP" },
    { SIGCOMP_INSTR_COPY,   "COPY" },
    { SIGCOMP_INSTR_COPY_LITERAL,   "COPY-LITERAL" },
    { SIGCOMP_INSTR_COPY_OFFSET,   "COPY-OFFSET" },
    { SIGCOMP_INSTR_MEMSET,   "MEMSET" },
    { SIGCOMP_INSTR_JUMP,   "JUMP" },
    { SIGCOMP_INSTR_COMPARE,   "COMPARE" },
    { SIGCOMP_INSTR_CALL,   "CALL" },
    { SIGCOMP_INSTR_RETURN,   "RETURN" },
    { SIGCOMP_INSTR_SWITCH,   "SWITCH" },
    { SIGCOMP_INSTR_CRC,   "CRC" },
    { SIGCOMP_INSTR_INPUT_BYTES,   "INPUT-BYTES" },
    { SIGCOMP_INSTR_INPUT_BITS,   "INPUT-BITS" },
    { SIGCOMP_INSTR_INPUT_HUFFMAN,   "INPUT-HUFFMAN" },
    { SIGCOMP_INSTR_STATE_ACCESS,   "STATE-ACCESS" },
    { SIGCOMP_INSTR_STATE_CREATE,   "STATE-CREATE" },
    { SIGCOMP_INSTR_STATE_FREE,   "STATE-FREE" },
    { SIGCOMP_INSTR_OUTPUT,   "OUTPUT" },
    { SIGCOMP_INSTR_END_MESSAGE,   "END-MESSAGE" },
    { 0,    NULL }
};
static value_string_ext udvm_instruction_code_vals_ext =
    VALUE_STRING_EXT_INIT(udvm_instruction_code_vals);

/* Internal result code values of decompression failures */
static const value_string result_code_vals[] = {
    {  0, "No decompression failure" },
    {  1, "Partial state length less than 6 or greater than 20 bytes long" },
    {  2, "No state match" },
    {  3, "state_begin + state_length > size of state" },
    {  4, "Operand_2 is Zero" },
    {  5, "Switch statement failed j >= n" },
    {  6, "Attempt to jump outside of UDVM memory" },
    {  7, "L in input-bits > 16" },
    {  8, "input_bit_order > 7" },
    {  9, "Instruction Decompression failure encountered" },
    { 10, "Input huffman failed j > n" },
    { 11, "Input bits requested beyond end of message" },
    { 12, "more than four state creation requests are made before the END-MESSAGE instruction" },
    { 13, "state_retention_priority is 65535" },
    { 14, "Input bytes requested beyond end of message" },
    { 15, "Maximum number of UDVM cycles reached" },
    { 16, "UDVM stack underflow" },
    { 17, "state_length is 0, but state_begin is non-zero" },
    {255, "This branch isn't coded yet" },
    { 0,    NULL }
};

 /*  The simplest operand type is the literal (#), which encodes a
  * constant integer from 0 to 65535 inclusive.  A literal operand may
  * require between 1 and 3 bytes depending on its value.
  * Bytecode:                       Operand value:      Range:
  * 0nnnnnnn                        N                   0 - 127
  * 10nnnnnn nnnnnnnn               N                   0 - 16383
  * 11000000 nnnnnnnn nnnnnnnn      N                   0 - 65535
  *
  *            Figure 8: Bytecode for a literal (#) operand
  *
  */
static int
decode_udvm_literal_operand(guint8 *buff,guint operand_address, guint16 *value)
{
    guint   bytecode;
    guint16 operand;
    guint   test_bits;
    guint   offset = operand_address;
    guint8  temp_data;

    bytecode = buff[operand_address];
    test_bits = bytecode >> 7;
    if (test_bits == 1) {
        test_bits = bytecode >> 6;
        if (test_bits == 2) {
            /*
             * 10nnnnnn nnnnnnnn               N                   0 - 16383
             */
            temp_data = buff[operand_address] & 0x1f;
            operand = temp_data << 8;
            temp_data = buff[(operand_address + 1) & 0xffff];
            operand = operand | temp_data;
            *value = operand;
            offset = offset + 2;

        } else {
            /*
             * 111000000 nnnnnnnn nnnnnnnn      N                   0 - 65535
             */
            offset ++;
            temp_data = buff[operand_address] & 0x1f;
            operand = temp_data << 8;
            temp_data = buff[(operand_address + 1) & 0xffff];
            operand = operand | temp_data;
            *value = operand;
            offset = offset + 2;

        }
    } else {
        /*
         * 0nnnnnnn                        N                   0 - 127
         */
        operand = ( bytecode & 0x7f);
        *value = operand;
        offset ++;
    }

    return offset;

}

/*
 * The second operand type is the reference ($), which is always used to
 * access a 2-byte value located elsewhere in the UDVM memory.  The
 * bytecode for a reference operand is decoded to be a constant integer
 * from 0 to 65535 inclusive, which is interpreted as the memory address
 * containing the actual value of the operand.
 * Bytecode:                       Operand value:      Range:
 *
 * 0nnnnnnn                        memory[2 * N]       0 - 65535
 * 10nnnnnn nnnnnnnn               memory[2 * N]       0 - 65535
 * 11000000 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
 *
 *            Figure 9: Bytecode for a reference ($) operand
 */
static int
dissect_udvm_reference_operand_memory(guint8 *buff,guint operand_address, guint16 *value,guint *result_dest)
{
    guint   bytecode;
    guint16 operand;
    guint   offset = operand_address;
    guint   test_bits;
    guint8  temp_data;
    guint16 temp_data16;

    bytecode = buff[operand_address];
    test_bits = bytecode >> 7;
    if (test_bits == 1) {
        test_bits = bytecode >> 6;
        if (test_bits == 2) {
            /*
             * 10nnnnnn nnnnnnnn               memory[2 * N]       0 - 65535
             */
            temp_data = buff[operand_address] & 0x3f;
            operand = temp_data << 8;
            temp_data = buff[(operand_address + 1) & 0xffff];
            operand = operand | temp_data;
            operand = (operand * 2);
            *result_dest = operand;
            temp_data16 = buff[operand] << 8;
            temp_data16 = temp_data16 | buff[(operand+1) & 0xffff];
            *value = temp_data16;
            offset = offset + 2;

        } else {
            /*
             * 11000000 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
             */
            operand_address++;
            operand = buff[operand_address] << 8;
            operand = operand | buff[(operand_address + 1) & 0xffff];
            *result_dest = operand;
            temp_data16 = buff[operand] << 8;
            temp_data16 = temp_data16 | buff[(operand+1) & 0xffff];
            *value = temp_data16;
            offset = offset + 3;

        }
    } else {
        /*
         * 0nnnnnnn                        memory[2 * N]       0 - 65535
         */
        operand = ( bytecode & 0x7f);
        operand = (operand * 2);
        *result_dest = operand;
        temp_data16 = buff[operand] << 8;
        temp_data16 = temp_data16 | buff[(operand+1) & 0xffff];
        *value = temp_data16;
        offset ++;
    }

    if (offset >= UDVM_MEMORY_SIZE || *result_dest >= UDVM_MEMORY_SIZE - 1 )
        return 0;

    return offset;
}

/* RFC3320
 * Figure 10: Bytecode for a multitype (%) operand
 * Bytecode:                       Operand value:      Range:           HEX val
 * 00nnnnnn                        N                   0 - 63           0x00
 * 01nnnnnn                        memory[2 * N]       0 - 65535        0x40
 * 1000011n                        2 ^ (N + 6)        64 , 128          0x86
 * 10001nnn                        2 ^ (N + 8)    256 , ... , 32768     0x88
 * 111nnnnn                        N + 65504       65504 - 65535        0xe0
 * 1001nnnn nnnnnnnn               N + 61440       61440 - 65535        0x90
 * 101nnnnn nnnnnnnn               N                   0 - 8191         0xa0
 * 110nnnnn nnnnnnnn               memory[N]           0 - 65535        0xc0
 * 10000000 nnnnnnnn nnnnnnnn      N                   0 - 65535        0x80
 * 10000001 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535        0x81
 */
static int
decode_udvm_multitype_operand(guint8 *buff,guint operand_address, guint16 *value)
{
    guint   test_bits;
    guint   bytecode;
    guint   offset = operand_address;
    guint16 operand;
    guint32 result;
    guint8  temp_data;
    guint16 temp_data16;
    guint16 memmory_addr = 0;

    *value = 0;

    bytecode = buff[operand_address];
    test_bits = ( bytecode & 0xc0 ) >> 6;
    switch (test_bits ) {
    case 0:
        /*
         * 00nnnnnn                        N                   0 - 63
         */
        operand =  buff[operand_address];
        /* debug
         *g_warning("Reading 0x%x From address %u",operand,offset);
         */
        *value = operand;
        offset ++;
        break;
    case 1:
        /*
         * 01nnnnnn                        memory[2 * N]       0 - 65535
         */
        memmory_addr = ( bytecode & 0x3f) * 2;
        temp_data16 = buff[memmory_addr] << 8;
        temp_data16 = temp_data16 | buff[(memmory_addr+1) & 0xffff];
        *value = temp_data16;
        offset ++;
        break;
    case 2:
        /* Check tree most significant bits */
        test_bits = ( bytecode & 0xe0 ) >> 5;
        if ( test_bits == 5 ) {
            /*
             * 101nnnnn nnnnnnnn               N                   0 - 8191
             */
            temp_data = buff[operand_address] & 0x1f;
            operand = temp_data << 8;
            temp_data = buff[(operand_address + 1) & 0xffff];
            operand = operand | temp_data;
            *value = operand;
            offset = offset + 2;
        } else {
            test_bits = ( bytecode & 0xf0 ) >> 4;
            if ( test_bits == 9 ) {
                /*
                 * 1001nnnn nnnnnnnn               N + 61440       61440 - 65535
                 */
                temp_data = buff[operand_address] & 0x0f;
                operand = temp_data << 8;
                temp_data = buff[(operand_address + 1) & 0xffff];
                operand = operand | temp_data;
                operand = operand + 61440;
                *value = operand;
                offset = offset + 2;
            } else {
                test_bits = ( bytecode & 0x08 ) >> 3;
                if ( test_bits == 1) {
                    /*
                     * 10001nnn                        2 ^ (N + 8)    256 , ... , 32768
                     */

                    result = 1 << ((buff[operand_address] & 0x07) + 8);
                    operand = result & 0xffff;
                    *value = operand;
                    offset ++;
                } else {
                    test_bits = ( bytecode & 0x0e ) >> 1;
                    if ( test_bits == 3 ) {
                        /*
                         * 1000 011n                        2 ^ (N + 6)        64 , 128
                         */
                        result = 1 << ((buff[operand_address] & 0x01) + 6);
                        operand = result & 0xffff;
                        *value = operand;
                        offset ++;
                    } else {
                        /*
                         * 1000 0000 nnnnnnnn nnnnnnnn      N                   0 - 65535
                         * 1000 0001 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
                         */
                        offset ++;
                        temp_data16 = buff[(operand_address + 1) & 0xffff] << 8;
                        temp_data16 = temp_data16 | buff[(operand_address + 2) & 0xffff];
                        /*  debug
                         * g_warning("Reading 0x%x From address %u",temp_data16,operand_address);
                         */
                        if ( (bytecode & 0x01) == 1 ) {
                            memmory_addr = temp_data16;
                            temp_data16 = buff[memmory_addr] << 8;
                            temp_data16 = temp_data16 | buff[(memmory_addr+1) & 0xffff];
                        }
                        *value = temp_data16;
                        offset = offset +2;
                    }


                }
            }
        }
        break;

    case 3:
        test_bits = ( bytecode & 0x20 ) >> 5;
        if ( test_bits == 1 ) {
            /*
             * 111nnnnn                        N + 65504       65504 - 65535
             */
            operand = ( buff[operand_address] & 0x1f) + 65504;
            *value = operand;
            offset ++;
        } else {
            /*
             * 110nnnnn nnnnnnnn               memory[N]           0 - 65535
             */
            memmory_addr = buff[operand_address] & 0x1f;
            memmory_addr = memmory_addr << 8;
            memmory_addr = memmory_addr | buff[(operand_address + 1) & 0xffff];
            temp_data16 = buff[memmory_addr] << 8;
            temp_data16 = temp_data16 | buff[(memmory_addr+1) & 0xffff];
            *value = temp_data16;
            /*  debug
             * g_warning("Reading 0x%x From address %u",temp_data16,memmory_addr);
             */
            offset = offset +2;
        }

    default :
        break;
    }
    return offset;
}
/*
 *
 * The fourth operand type is the address (@).  This operand is decoded
 * as a multitype operand followed by a further step: the memory address
 * of the UDVM instruction containing the address operand is added to
 * obtain the correct operand value.  So if the operand value from
 * Figure 10 is D then the actual operand value of an address is
 * calculated as follows:
 *
 * operand_value = (memory_address_of_instruction + D) modulo 2^16
 *
 * Address operands are always used in instructions that control program
 * flow, because they ensure that the UDVM bytecode is position-
 * independent code (i.e., it will run independently of where it is
 * placed in the UDVM memory).
 */
static int
decode_udvm_address_operand(guint8 *buff,guint operand_address, guint16 *value,guint current_address)
{
    guint32 result;
    guint16 value1;
    guint   next_opreand_address;

    next_opreand_address = decode_udvm_multitype_operand(buff, operand_address, &value1);
    result = value1 & 0xffff;
    result = result + current_address;
    *value = result & 0xffff;
    return next_opreand_address;
}


/*
 * This is a lookup table used to reverse the bits in a byte.
 */
static guint8 reverse [] = {
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0,
    0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8,
    0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4,
    0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC,
    0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2,
    0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA,
    0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6,
    0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE,
    0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1,
    0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9,
    0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5,
    0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED,
    0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3,
    0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB,
    0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7,
    0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF,
    0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};


static int
decomp_dispatch_get_bits(
    tvbuff_t   *message_tvb,
    proto_tree *udvm_tree,
    guint8      bit_order,
    guint8     *buff,
    guint16    *old_input_bit_order,
    guint16    *remaining_bits,
    guint16    *input_bits,
    guint      *input_address,
    guint16     length,
    guint16    *result_code,
    guint       msg_end,
    gboolean    print_level_1)
{
    guint16     input_bit_order;
    guint16     bits_still_required   = length;
    guint16     value                 = 0;
    guint8      octet;
    gint        extra_bytes_available = msg_end - *input_address;
    gint        p_bit;
    gint        prev_p_bit            = *old_input_bit_order & 0x0001;
    gint        bits_to_use           = 0;


    input_bit_order = buff[68] << 8;
    input_bit_order = input_bit_order | buff[69];
    *result_code = 0;
    p_bit = (input_bit_order & 0x0001) != 0;

    /*
     * Discard any spare bits.
     * Note: We take care to avoid remaining_bits having the value of 8.
     */
    if (prev_p_bit != p_bit)
    {
        *remaining_bits = 0;
        *old_input_bit_order = input_bit_order;
    }

    /*
     * Check we can supply the required number of bits now, before we alter
     * the input buffer's state.
     */
    if (*remaining_bits + extra_bytes_available * 8 < length)
    {
        *result_code = 11;
        return 0xfbad;
    }

    /* Note: This is never called with length > 16, so the following loop
     *       never loops more than three time. */
    while (bits_still_required > 0)
    {
        /*
         * We only put anything into input_bits if we know we will remove
         * at least one bit. That ensures we can simply discard the spare
         * bits if the P-bit changes.
         */
        if (*remaining_bits == 0)
        {
            octet = tvb_get_guint8(message_tvb, *input_address);
            if (print_level_1 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_getting_value, message_tvb, *input_address, 1, octet,
                                    "               Getting value: %u (0x%x) From Addr: %u", octet, octet, *input_address);
            }
            *input_address = *input_address + 1;

            if (p_bit != 0)
            {
                octet = reverse[octet];
            }
            *input_bits = octet;
            *remaining_bits = 8;
        }

        /* Add some more bits to the accumulated value. */
        bits_to_use = bits_still_required < *remaining_bits ? bits_still_required : *remaining_bits;
        bits_still_required -= bits_to_use;

        *input_bits <<= bits_to_use;           /* Shift bits into MSByte */
        value = (value << bits_to_use)         /* Then add to the accumulated value */
            | ((*input_bits >> 8) & 0xFF);
        *remaining_bits -= bits_to_use;
        *input_bits &= 0x00FF;                 /* Leave just the remaining bits */
    }

    if (bit_order != 0)
    {
        /* Bit reverse the entire word. */
        guint16 lsb = reverse[(value >> 8) & 0xFF];
        guint16 msb = reverse[value & 0xFF];

        value = ((msb << 8) | lsb) >> (16 - length);
    }

    return value;
}

static tvbuff_t*
decompress_sigcomp_message(tvbuff_t *bytecode_tvb, tvbuff_t *message_tvb, packet_info *pinfo,
                           proto_tree *udvm_tree, gint udvm_mem_dest,
                           gint print_flags, gint hf_id,
                           gint header_len,
                           gint byte_code_state_len, gint byte_code_id_len,
                           gint udvm_start_ip)
{
    tvbuff_t      *decomp_tvb;
    /* UDVM memory must be initialised to zero */
    guint8        *buff                       = (guint8 *)wmem_alloc0(wmem_packet_scope(), UDVM_MEMORY_SIZE);
    char           string[2];
    guint8        *out_buff;    /* Largest allowed size for a message is UDVM_MEMORY_SIZE = 65536 */
    guint32        i                          = 0;
    guint16        n                          = 0;
    guint16        m                          = 0;
    guint16        x;
    guint          k                          = 0;
    guint16        H;
    guint16        oldH;
    guint          offset                     = 0;
    guint          start_offset;
    guint          result_dest;
    guint          code_length                = 0;
    guint8         current_instruction;
    guint          current_address;
    guint          operand_address;
    guint          input_address;
    guint16        output_address             = 0;
    guint          next_operand_address;
    guint8         octet;
    guint8         msb;
    guint8         lsb;
    guint16        byte_copy_right;
    guint16        byte_copy_left;
    guint16        input_bit_order;
    guint16        stack_location;
    guint16        stack_fill;
    guint16        result;
    guint          msg_end                    = tvb_reported_length_remaining(message_tvb, 0);
    guint16        result_code                = 0;
    guint16        old_input_bit_order        = 0;
    guint16        remaining_bits             = 0;
    guint16        input_bits                 = 0;
    guint8         bit_order                  = 0;
    gboolean       outside_huffman_boundaries = TRUE;
    gboolean       print_in_loop              = FALSE;
    guint16        instruction_address;
    guint8         no_of_state_create         = 0;
    guint16        state_length_buff[5];
    guint16        state_address_buff[5];
    guint16        state_instruction_buff[5];
    guint16        state_minimum_access_length_buff[5];
    /* guint16        state_state_retention_priority_buff[5]; */
    guint32        used_udvm_cycles           = 0;
    guint          cycles_per_bit;
    guint          maximum_UDVM_cycles;
    guint8        *sha1buff;
    unsigned char  sha1_digest_buf[STATE_BUFFER_SIZE];
    sha1_context   ctx;
    proto_item    *addr_item = NULL;


    /* UDVM operand variables */
    guint16 length;
    guint16 at_address;
    guint16 destination;
    guint16 addr;
    guint16 value;
    guint16 p_id_start;
    guint16 p_id_length;
    guint16 state_begin;
    guint16 state_length;
    guint16 state_address;
    guint16 state_instruction;
    guint16 operand_1;
    guint16 operand_2;
    guint16 value_1;
    guint16 value_2;
    guint16 at_address_1;
    guint16 at_address_2;
    guint16 at_address_3;
    guint16 j;
    guint16 bits_n;
    guint16 lower_bound_n;
    guint16 upper_bound_n;
    guint16 uncompressed_n;
    guint16 position;
    guint16 ref_destination; /* could I have used $destination ? */
    guint16 multy_offset;
    guint16 output_start;
    guint16 output_length;
    guint16 minimum_access_length;
    guint16 state_retention_priority;
    guint16 requested_feedback_location;
    guint16 returned_parameters_location;
    guint16 start_value;

    /* Set print parameters */
    gboolean print_level_1 = FALSE;
    gboolean print_level_2 = FALSE;
    gboolean print_level_3 = FALSE;
    gint show_instr_detail_level = 0;

    switch ( print_flags ) {
    case 0:
        break;

    case 1:
        print_level_1 = TRUE;
        show_instr_detail_level = 1;
        break;
    case 2:
        print_level_1 = TRUE;
        print_level_2 = TRUE;
        show_instr_detail_level = 1;
        break;
    case 3:
        print_level_1 = TRUE;
        print_level_2 = TRUE;
        print_level_3 = TRUE;
        show_instr_detail_level = 2;
        break;
    default:
        print_level_1 = TRUE;
        show_instr_detail_level = 1;
        break;
    }

    /* Set initial UDVM data
     *  The first 32 bytes of UDVM memory are then initialized to special
     *  values as illustrated in Figure 5.
     *
     *                      0             7 8            15
     *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *                     |       UDVM_memory_size        |  0 - 1
     *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *                     |        cycles_per_bit         |  2 - 3
     *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *                     |        SigComp_version        |  4 - 5
     *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *                     |    partial_state_ID_length    |  6 - 7
     *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *                     |         state_length          |  8 - 9
     *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *                     |                               |
     *                     :           reserved            :  10 - 31
     *                     |                               |
     *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     *            Figure 5: Initializing Useful Values in UDVM memory
     */
    /* UDVM_memory_size  */
    buff[0] = (UDVM_MEMORY_SIZE >> 8) & 0x00FF;
    buff[1] = UDVM_MEMORY_SIZE & 0x00FF;
    /* cycles_per_bit */
    buff[2] = 0;
    buff[3] = 16;
    /* SigComp_version */
    buff[4] = 0;
    buff[5] = 1;
    /* partial_state_ID_length */
    buff[6] = (byte_code_id_len >> 8) & 0x00FF;
    buff[7] = byte_code_id_len & 0x00FF;
    /* state_length  */
    buff[8] = (byte_code_state_len >> 8) & 0x00FF;
    buff[9] = byte_code_state_len & 0x00FF;

    code_length = tvb_reported_length_remaining(bytecode_tvb, 0);

    cycles_per_bit = buff[2] << 8;
    cycles_per_bit = cycles_per_bit | buff[3];
    /*
     * maximum_UDVM_cycles = (8 * n + 1000) * cycles_per_bit
     */
    maximum_UDVM_cycles = (( 8 * (header_len + msg_end) ) + 1000) * cycles_per_bit;

    proto_tree_add_uint(udvm_tree, hf_sigcomp_message_length, bytecode_tvb, offset, 1, msg_end);
    proto_tree_add_uint(udvm_tree, hf_sigcomp_byte_code_length, bytecode_tvb, offset, 1, code_length);
    proto_tree_add_uint(udvm_tree, hf_sigcomp_max_udvm_cycles, bytecode_tvb, offset, 1, maximum_UDVM_cycles);

    /* Load bytecode into UDVM starting at "udvm_mem_dest" */
    i = udvm_mem_dest;
    if ( print_level_3 )
        proto_tree_add_uint(udvm_tree, hf_sigcomp_load_bytecode_into_udvm_start, bytecode_tvb, offset, 1, i);
    while ( code_length > offset && i < UDVM_MEMORY_SIZE ) {
        buff[i] = tvb_get_guint8(bytecode_tvb, offset);
        if ( print_level_3 )
            proto_tree_add_uint_format(udvm_tree, hf_sigcomp_instruction_code, bytecode_tvb, offset, 1, buff[i],
                                "              Addr: %u Instruction code(0x%02x) ", i, buff[i]);

        i++;
        offset++;

    }
    /* Start executing code */
    current_address = udvm_start_ip;
    input_address = 0;

    proto_tree_add_uint_format(udvm_tree, hf_sigcomp_udvm_execution_stated, bytecode_tvb, offset, 1, current_address,
                        "UDVM EXECUTION STARTED at Address: %u Message size %u", current_address, msg_end);

    /* Largest allowed size for a message is UDVM_MEMORY_SIZE = 65536  */
    out_buff = (guint8 *)g_malloc(UDVM_MEMORY_SIZE);

    /* Reset offset so proto_tree_add_xxx items below accurately reflect the bytes they represent */
    offset = 0;

execute_next_instruction:

    if ( used_udvm_cycles > maximum_UDVM_cycles ) {
        result_code = 15;
        goto decompression_failure;
    }
    used_udvm_cycles++;
    current_instruction = buff[current_address & 0xffff];

    if (show_instr_detail_level == 2 ) {
        addr_item = proto_tree_add_uint_format(udvm_tree, hf_sigcomp_current_instruction, bytecode_tvb, offset, 1, current_instruction,
                            "Addr: %u ## %s(%d)", current_address,
                            val_to_str_ext_const(current_instruction, &udvm_instruction_code_vals_ext, "INVALID INSTRUCTION"),
                            current_instruction);
    }
    offset++;

    switch ( current_instruction ) {
    case SIGCOMP_INSTR_DECOMPRESSION_FAILURE:
        if ( result_code == 0 )
            result_code = 9;
        proto_tree_add_uint_format(udvm_tree, hf_sigcomp_decompression_failure, NULL, 0, 0,
                            current_address, "Addr: %u ## DECOMPRESSION-FAILURE(0)",
                            current_address);
        proto_tree_add_uint(udvm_tree, hf_sigcomp_wireshark_udvm_diagnostic, NULL, 0, 0, result_code);
        if ( output_address > 0 ) {
            /* At least something got decompressed, show it */
            decomp_tvb = tvb_new_child_real_data(message_tvb, out_buff,output_address,output_address);
            /* Arrange that the allocated packet data copy be freed when the
             * tvbuff is freed.
             */
            tvb_set_free_cb( decomp_tvb, g_free );
            /* Add the tvbuff to the list of tvbuffs to which the tvbuff we
             * were handed refers, so it'll get cleaned up when that tvbuff
             * is cleaned up.
             */
            add_new_data_source(pinfo, decomp_tvb, "Decompressed SigComp message(Incomplete)");
            proto_tree_add_expert(udvm_tree, pinfo, &ei_sigcomp_sigcomp_message_decompression_failure, decomp_tvb, 0, -1);
            return decomp_tvb;
        }
        g_free(out_buff);
        return NULL;
        break;

    case SIGCOMP_INSTR_AND: /* 1 AND ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## AND (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /* execute the instruction */
        result = operand_1 & operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;

        break;

    case SIGCOMP_INSTR_OR: /* 2 OR ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## OR (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /* execute the instruction */
        result = operand_1 | operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;

        break;

    case SIGCOMP_INSTR_NOT: /* 3 NOT ($operand_1) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " ($operand_1)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## NOT (operand_1=%u)",
                                current_address, operand_1);
        }
        /* execute the instruction */
        result = operand_1 ^ 0xffff;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_LSHIFT: /* 4 LSHIFT ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " ($operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## LSHIFT (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /* execute the instruction */
        result = operand_1 << operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;

        break;
    case SIGCOMP_INSTR_RSHIFT: /* 5 RSHIFT ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## RSHIFT (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /* execute the instruction */
        result = operand_1 >> operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_ADD: /* 6 ADD ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## ADD (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /* execute the instruction */
        result = operand_1 + operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "               Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;

    case SIGCOMP_INSTR_SUBTRACT: /* 7 SUBTRACT ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## SUBTRACT (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /* execute the instruction */
        result = operand_1 - operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "               Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_MULTIPLY: /* 8 MULTIPLY ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## MULTIPLY (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /*
         * execute the instruction
         * MULTIPLY (m, n)  := m * n (modulo 2^16)
         */
        if ( operand_2 == 0) {
            result_code = 4;
            goto decompression_failure;
        }
        result = operand_1 * operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_DIVIDE: /* 9 DIVIDE ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## DIVIDE (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /*
         * execute the instruction
         * DIVIDE (m, n)    := floor(m / n)
         * Decompression failure occurs if a DIVIDE or REMAINDER instruction
         * encounters an operand_2 that is zero.
         */
        if ( operand_2 == 0) {
            result_code = 4;
            goto decompression_failure;
        }
        result = operand_1 / operand_2;
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_REMAINDER: /* 10 REMAINDER ($operand_1, %operand_2) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (operand_1, operand_2)");
        }
        start_offset = offset;
        /* $operand_1*/
        operand_address = current_address + 1;
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &operand_1, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_1, bytecode_tvb, offset, (next_operand_address-operand_address), operand_1,
                                "Addr: %u      operand_1 %u", operand_address, operand_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %operand_2*/
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_operand_2, bytecode_tvb, offset, (next_operand_address-operand_address), operand_2,
                                "Addr: %u      operand_2 %u", operand_address, operand_2);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## REMAINDER (operand_1=%u, operand_2=%u)",
                                current_address, operand_1, operand_2);
        }
        /*
         * execute the instruction
         * REMAINDER (m, n) := m - n * floor(m / n)
         * Decompression failure occurs if a DIVIDE or REMAINDER instruction
         * encounters an operand_2 that is zero.
         */
        if ( operand_2 == 0) {
            result_code = 4;
            goto decompression_failure;
        }
        result = operand_1 - operand_2 * (operand_1 / operand_2);
        lsb = result & 0xff;
        msb = result >> 8;
        buff[result_dest] = msb;
        buff[(result_dest+1) & 0xffff] = lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading result %u at %u", result, result_dest);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_SORT_ASCENDING: /* 11 SORT-ASCENDING (%start, %n, %k) */
        /*
         *      used_udvm_cycles =  1 + k * (ceiling(log2(k)) + n)
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (start, n, k))");
        }
        proto_tree_add_expert(udvm_tree, pinfo, &ei_sigcomp_execution_of_this_instruction_is_not_implemented, bytecode_tvb, 0, -1);
        /*
         *      used_udvm_cycles =  1 + k * (ceiling(log2(k)) + n)
         */
        break;

    case SIGCOMP_INSTR_SORT_DESCENDING: /* 12 SORT-DESCENDING (%start, %n, %k) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (start, n, k))");
        }
        proto_tree_add_expert(udvm_tree, pinfo, &ei_sigcomp_execution_of_this_instruction_is_not_implemented, bytecode_tvb, 0, -1);
        /*
         *      used_udvm_cycles =  1 + k * (ceiling(log2(k)) + n)
         */
        break;
    case SIGCOMP_INSTR_SHA_1: /* 13 SHA-1 (%position, %length, %destination) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (position, length, destination)");
        }
        operand_address = current_address + 1;
        /* %position */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
        if (print_level_1 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_position, bytecode_tvb, offset, (next_operand_address-operand_address), position,
                                "Addr: %u      position %u", operand_address, position);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %length */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (print_level_1 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      Length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* $destination */
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &ref_destination, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (print_level_1 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_ref_dest, bytecode_tvb, offset, (next_operand_address-operand_address), ref_destination,
                                "Addr: %u      $destination %u", operand_address, ref_destination);
        }
        offset += (next_operand_address-operand_address);
        used_udvm_cycles = used_udvm_cycles + length;

        n = 0;
        k = position;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];

        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, 0, -1,
                                NULL, "byte_copy_right = %u", byte_copy_right);
        }

        sha1_starts( &ctx );

        while (n<length) {
            guint16 handle_now = length;

            if ( k < byte_copy_right && byte_copy_right <= k + (length-n) ) {
                handle_now = byte_copy_right - position;
            }

            if (k + handle_now >= UDVM_MEMORY_SIZE)
                goto decompression_failure;
            sha1_update( &ctx, &buff[k], handle_now );

            k = ( k + handle_now ) & 0xffff;
            n = ( n + handle_now ) & 0xffff;

            if ( k >= byte_copy_right ) {
                k = byte_copy_left;
            }
        }

        sha1_finish( &ctx, sha1_digest_buf );

        k = ref_destination;

        for ( n=0; n< STATE_BUFFER_SIZE; n++ ) {

            buff[k] = sha1_digest_buf[n];

            k = ( k + 1 ) & 0xffff;
            n++;

            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
        }

        if (print_level_2 ) {
            proto_tree_add_bytes_with_length(udvm_tree, hf_sigcomp_calculated_sha_1, message_tvb, 0, -1,
                                sha1_digest_buf, STATE_BUFFER_SIZE);
        }

        current_address = next_operand_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_LOAD: /* 14 LOAD (%address, %value) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (%%address, %%value)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %address */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &addr);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_address, bytecode_tvb, offset, (next_operand_address-operand_address), addr,
                                "Addr: %u      Address %u", operand_address, addr);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %value */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
        if (show_instr_detail_level == 2)
        {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_value, bytecode_tvb, offset, (next_operand_address-operand_address), value,
                                "Addr: %u      Value %u", operand_address, value);
        }
        offset += (next_operand_address-operand_address);
        lsb = value & 0xff;
        msb = value >> 8;

        buff[addr] = msb;
        buff[(addr + 1) & 0xffff] = lsb;

        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## LOAD (%%address=%u, %%value=%u)",
                                current_address, addr, value);
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                "     Loading bytes at %u Value %u 0x%x", addr, value, value);
        }
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_MULTILOAD: /* 15 MULTILOAD (%address, #n, %value_0, ..., %value_n-1) */
        /* RFC 3320:
         * The MULTILOAD instruction sets a contiguous block of 2-byte words in
         * the UDVM memory to specified values.
         * Hmm what if the value to load only takes one byte ? Chose to always load two bytes.
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (%%address, #n, value_0, ..., value_n-1)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %address */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &addr);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_address, bytecode_tvb, offset, (next_operand_address-operand_address), addr,
                                "Addr: %u      Address %u", operand_address, addr);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* #n */
        next_operand_address = decode_udvm_literal_operand(buff,operand_address, &n);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_literal_num, bytecode_tvb, offset, (next_operand_address-operand_address), n,
                                "Addr: %u      n %u", operand_address, n);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## MULTILOAD (%%address=%u, #n=%u, value_0, ..., value_%d)",
                                current_address, addr, n, n-1);
        }
        operand_address = next_operand_address;
        used_udvm_cycles = used_udvm_cycles + n;
        while ( n > 0) {
            n = n - 1;
            /* %value */
            next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
            lsb = value & 0xff;
            msb = value >> 8;

            if (addr >= UDVM_MEMORY_SIZE - 1)
                goto decompression_failure;

            buff[addr] = msb;
            buff[(addr + 1) & 0xffff] = lsb;
            /* debug
             */
            length = next_operand_address - operand_address;

            if (print_level_1 ) {
                proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, bytecode_tvb, 0, -1,
                                    "Addr: %u      Value %5u      - Loading bytes at %5u Value %5u 0x%x", operand_address, value, addr, value, value);
            }
            addr = addr + 2;
            operand_address = next_operand_address;
        }
        current_address = next_operand_address;
        goto execute_next_instruction;

        break;

    case SIGCOMP_INSTR_PUSH: /* 16 PUSH (%value) */
        if (show_instr_detail_level == 2) {
            proto_item_append_text(addr_item, " (value)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %value */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
        if (show_instr_detail_level == 2) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_value, bytecode_tvb, offset, (next_operand_address-operand_address), value,
                                "Addr: %u      Value %u", operand_address, value);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## PUSH (value=%u)",
                                current_address, value);
        }
        current_address = next_operand_address;

        /* Push the value address onto the stack */
        stack_location = (buff[70] << 8) | buff[71];
        stack_fill = (buff[stack_location] << 8)
            | buff[(stack_location+1) & 0xFFFF];
        addr = (stack_location + stack_fill * 2 + 2) & 0xFFFF;

        if (addr >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;

        buff[addr] = (value >> 8) & 0x00FF;
        buff[(addr+1) & 0xFFFF] = value & 0x00FF;

        if (stack_location >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;

        stack_fill = (stack_fill + 1) & 0xFFFF;
        buff[stack_location] = (stack_fill >> 8) & 0x00FF;
        buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

        goto execute_next_instruction;

        break;

    case SIGCOMP_INSTR_POP: /* 17 POP (%address) */
        if (show_instr_detail_level == 2) {
            proto_item_append_text(addr_item, " (value)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %value */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
        if (show_instr_detail_level == 2) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_address, bytecode_tvb, offset, (next_operand_address-operand_address), destination,
                                "Addr: %u      Value %u", operand_address, destination);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## POP (address=%u)",
                                current_address, destination);
        }
        current_address = next_operand_address;

        /* Pop value from the top of the stack */
        stack_location = (buff[70] << 8) | buff[71];
        stack_fill = (buff[stack_location] << 8)
            | buff[(stack_location+1) & 0xFFFF];
        if (stack_fill == 0)
        {
            result_code = 16;
            goto decompression_failure;
        }

        if (stack_location >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;

        stack_fill = (stack_fill - 1) & 0xFFFF;
        buff[stack_location] = (stack_fill >> 8) & 0x00FF;
        buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

        addr = (stack_location + stack_fill * 2 + 2) & 0xFFFF;

        if (addr >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;

        value = (buff[addr] << 8)
            | buff[(addr+1) & 0xFFFF];

        /* ... and store the popped value. */
        if (destination >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;
        buff[destination] = (value >> 8) & 0x00FF;
        buff[(destination+1) & 0xFFFF] = value & 0x00FF;

        goto execute_next_instruction;

        break;

    case SIGCOMP_INSTR_COPY: /* 18 COPY (%position, %length, %destination) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (position, length, destination)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %position */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_position, bytecode_tvb, offset, (next_operand_address-operand_address), position,
                                "Addr: %u      position %u", operand_address, position);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %length */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      Length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %destination */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_ref_dest, bytecode_tvb, offset, (next_operand_address-operand_address), destination,
                                "Addr: %u      Destination %u", operand_address, destination);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## COPY (position=%u, length=%u, destination=%u)",
                                current_address, position, length, destination);
        }
        current_address = next_operand_address;
        /*
         * 8.4.  Byte copying
         * :
         * The string of bytes is copied in ascending order of memory address,
         * respecting the bounds set by byte_copy_left and byte_copy_right.
         * More precisely, if a byte is copied from/to Address m then the next
         * byte is copied from/to Address n where n is calculated as follows:
         *
         * Set k := m + 1 (modulo 2^16)
         * If k = byte_copy_right then set n := byte_copy_left, else set n := k
         *
         */

        n = 0;
        k = destination;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, input_address, 1,
                                NULL, "               byte_copy_right = %u", byte_copy_right);
        }

        while ( n < length ) {
            buff[k] = buff[position];
            if (print_level_2 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_copying_value, message_tvb, input_address, 1,
                                    buff[position], "               Copying value: %u (0x%x) to Addr: %u",
                                    buff[position], buff[position], k);
            }
            position = ( position + 1 ) & 0xffff;
            k = ( k + 1 ) & 0xffff;
            n++;

            /*
             * Check for circular buffer wrapping after the positions are
             * incremented. If either started at BCR then they should continue
             * to increment beyond BCR.
             */
            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
            if ( position == byte_copy_right ) {
                position = byte_copy_left;
            }
        }
        used_udvm_cycles = used_udvm_cycles + length;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_COPY_LITERAL: /* 19 COPY-LITERAL (%position, %length, $destination) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (position, length, $destination)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %position */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_position, bytecode_tvb, offset, (next_operand_address-operand_address), position,
                                "Addr: %u      position %u", operand_address, position);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %length */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      Length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;


        /* $destination */
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &ref_destination, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_ref_dest, bytecode_tvb, offset, (next_operand_address-operand_address), ref_destination,
                                "Addr: %u      destination %u", operand_address, ref_destination);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## COPY-LITERAL (position=%u, length=%u, $destination=%u)",
                                current_address, position, length, ref_destination);
        }
        current_address = next_operand_address;


        /*
         * 8.4.  Byte copying
         * :
         * The string of bytes is copied in ascending order of memory address,
         * respecting the bounds set by byte_copy_left and byte_copy_right.
         * More precisely, if a byte is copied from/to Address m then the next
         * byte is copied from/to Address n where n is calculated as follows:
         *
         * Set k := m + 1 (modulo 2^16)
         * If k = byte_copy_right then set n := byte_copy_left, else set n := k
         *
         */

        n = 0;
        k = ref_destination;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, input_address, 1,
                                NULL, "               byte_copy_right = %u", byte_copy_right);
        }
        while ( n < length ) {

            buff[k] = buff[position];
            if (print_level_2 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_copying_value, message_tvb, input_address, 1,
                                    buff[position], "               Copying value: %u (0x%x) to Addr: %u",
                                    buff[position], buff[position], k);
            }
            position = ( position + 1 ) & 0xffff;
            k = ( k + 1 ) & 0xffff;
            n++;

            /*
             * Check for circular buffer wrapping after the positions are
             * incremented. It is important that k cannot be left set
             * to BCR. Also, if either started at BCR then they should continue
             * to increment beyond BCR.
             */
            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
            if ( position == byte_copy_right ) {
                position = byte_copy_left;
            }
        }
        buff[result_dest] = k >> 8;
        buff[(result_dest + 1) & 0xffff] = k & 0x00ff;

        used_udvm_cycles = used_udvm_cycles + length;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_COPY_OFFSET: /* 20 COPY-OFFSET (%offset, %length, $destination) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (offset, length, $destination)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %offset */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &multy_offset);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_offset, bytecode_tvb, offset, (next_operand_address-operand_address), multy_offset,
                                "Addr: %u      offset %u", operand_address, multy_offset);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %length */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      Length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;


        /* $destination */
        next_operand_address = dissect_udvm_reference_operand_memory(buff, operand_address, &ref_destination, &result_dest);
        if (next_operand_address < operand_address)
            goto decompression_failure;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_ref_dest, bytecode_tvb, offset, (next_operand_address-operand_address), ref_destination,
                                "Addr: %u      $destination %u", operand_address, ref_destination);
        }
        offset += (next_operand_address-operand_address);

        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## COPY-OFFSET (offset=%u, length=%u, $destination=%u)",
                                current_address, multy_offset, length, result_dest);
        }
        current_address = next_operand_address;

        /* Execute the instruction:
         * To derive the value of the position operand, starting at the memory
         * address specified by destination, the UDVM counts backwards a total
         * of offset memory addresses.
         *
         * If the memory address specified in byte_copy_left is reached, the
         * next memory address is taken to be (byte_copy_right - 1) modulo 2^16.
         */
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];

        /*
         * In order to work out the position, simple arithmetic is tricky
         * to apply because there some nasty corner cases. A simple loop
         * is inefficient but the logic is simple.
         *
         * FUTURE: This could be optimised.
         */
        for (position = ref_destination, i = 0; i < multy_offset; i++)
        {
            if ( position == byte_copy_left )
            {
                position = (byte_copy_right - 1) & 0xffff;
            }
            else
            {
                position = (position - 1) & 0xffff;
            }
        }

        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, input_address, 1,
                                NULL, "               byte_copy_left = %u byte_copy_right = %u position= %u",
                                byte_copy_left, byte_copy_right, position);
        }
        /* The COPY-OFFSET instruction then behaves as a COPY-LITERAL
         * instruction, taking the value of the position operand to be the last
         * memory address reached in the above step.
         */

        /*
         * 8.4.  Byte copying
         * :
         * The string of bytes is copied in ascending order of memory address,
         * respecting the bounds set by byte_copy_left and byte_copy_right.
         * More precisely, if a byte is copied from/to Address m then the next
         * byte is copied from/to Address n where n is calculated as follows:
         *
         * Set k := m + 1 (modulo 2^16)
         * If k = byte_copy_right then set n := byte_copy_left, else set n := k
         *
         */

        n = 0;
        k = ref_destination;
        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, input_address, 1, NULL,
                                "               byte_copy_left = %u byte_copy_right = %u", byte_copy_left, byte_copy_right);
        }
        while ( n < length ) {
            buff[k] = buff[position];
            if (print_level_2 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_copying_value, message_tvb, input_address, 1,
                                    buff[position], "               Copying value: %5u (0x%x) from Addr: %u to Addr: %u",
                                    buff[position], buff[position],(position), k);
            }
            n++;
            k = ( k + 1 ) & 0xffff;
            position = ( position + 1 ) & 0xffff;

            /*
             * Check for circular buffer wrapping after the positions are
             * incremented. It is important that k cannot be left set
             * to BCR. Also, if either started at BCR then they should continue
             * to increment beyond BCR.
             */
            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
            if ( position == byte_copy_right ) {
                position = byte_copy_left;
            }
        }
        buff[result_dest] = k >> 8;
        buff[result_dest + 1] = k & 0x00ff;
        used_udvm_cycles = used_udvm_cycles + length;
        goto execute_next_instruction;

        break;
    case SIGCOMP_INSTR_MEMSET: /* 21 MEMSET (%address, %length, %start_value, %offset) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (address, length, start_value, offset)");
        }
        start_offset = offset;
        operand_address = current_address + 1;

        /* %address */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &addr);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_address, bytecode_tvb, offset, (next_operand_address-operand_address), addr,
                                "Addr: %u      Address %u", operand_address, addr);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /*  %length, */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      Length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %start_value */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &start_value);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_start_value, bytecode_tvb, offset, (next_operand_address-operand_address), start_value,
                                "Addr: %u      start_value %u", operand_address, start_value);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %offset */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &multy_offset);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_offset, bytecode_tvb, offset, (next_operand_address-operand_address), multy_offset,
                                "Addr: %u      offset %u", operand_address, multy_offset);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## MEMSET (address=%u, length=%u, start_value=%u, offset=%u)",
                                current_address, addr, length, start_value, multy_offset);
        }
        current_address = next_operand_address;
        /* execute the instruction
         * The sequence of values used by the MEMSET instruction is specified by
         * the following formula:
         *
         * Seq[n] := (start_value + n * offset) modulo 256
         */
        n = 0;
        k = addr;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, input_address, 1, NULL,
                                "               byte_copy_left = %u byte_copy_right = %u", byte_copy_left, byte_copy_right);
        }
        while ( n < length ) {
            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
            buff[k] = (start_value + ( n * multy_offset)) & 0xff;
            if (print_level_2 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_storing_value, message_tvb, input_address, 1,
                                    buff[k], "     Storing value: %u (0x%x) at Addr: %u",
                                    buff[k], buff[k], k);
            }
            k = ( k + 1 ) & 0xffff;
            n++;
        }/* end while */
        used_udvm_cycles = used_udvm_cycles + length;
        goto execute_next_instruction;
        break;


    case SIGCOMP_INSTR_JUMP: /* 22 JUMP (@address) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (@address)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* @address */
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address,
                                "Addr: %u      @Address %u", operand_address, at_address);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## JUMP (@address=%u)",
                                current_address, at_address);
        }
        current_address = at_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_COMPARE: /* 23 */
        /* COMPARE (%value_1, %value_2, @address_1, @address_2, @address_3)
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (value_1, value_2, @address_1, @address_2, @address_3)");
        }
        start_offset = offset;
        operand_address = current_address + 1;

        /* %value_1 */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value_1);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_value, bytecode_tvb, offset, (next_operand_address-operand_address), value_1,
                                "Addr: %u      Value %u", operand_address, value_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %value_2 */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value_2);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_value, bytecode_tvb, offset, (next_operand_address-operand_address), value_2,
                                "Addr: %u      Value %u", operand_address, value_2);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* @address_1 */
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_1);
        at_address_1 = ( current_address + at_address_1) & 0xffff;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address_1,
                                "Addr: %u      @Address %u", operand_address, at_address_1);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;


        /* @address_2 */
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_2);
        at_address_2 = ( current_address + at_address_2) & 0xffff;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address_2,
                                "Addr: %u      @Address %u", operand_address, at_address_2);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* @address_3 */
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_3);
        at_address_3 = ( current_address + at_address_3) & 0xffff;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address_3,
                                "Addr: %u      @Address %u", operand_address, at_address_3);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## COMPARE (value_1=%u, value_2=%u, @address_1=%u, @address_2=%u, @address_3=%u)",
                                current_address, value_1, value_2, at_address_1, at_address_2, at_address_3);
        }
        /* execute the instruction
         * If value_1 < value_2 then the UDVM continues instruction execution at
         * the memory address specified by address 1. If value_1 = value_2 then
         * it jumps to the address specified by address_2. If value_1 > value_2
         * then it jumps to the address specified by address_3.
         */
        if ( value_1 < value_2 )
            current_address = at_address_1;
        if ( value_1 == value_2 )
            current_address = at_address_2;
        if ( value_1 > value_2 )
            current_address = at_address_3;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_CALL: /* 24 CALL (@address) (PUSH addr )*/
        if (show_instr_detail_level == 2) {
            proto_item_append_text(addr_item, " (@address) (PUSH addr )");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* @address */
        next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address,
                                "Addr: %u      @Address %u", operand_address, at_address);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## CALL (@address=%u)",
                                current_address, at_address);
        }
        current_address = next_operand_address;

        /* Push the current address onto the stack */
        stack_location = (buff[70] << 8) | buff[71];
        stack_fill = (buff[stack_location] << 8)
            | buff[(stack_location+1) & 0xFFFF];
        addr = (stack_location + stack_fill * 2 + 2) & 0xFFFF;
        if (addr >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;
        buff[addr] = (current_address >> 8) & 0x00FF;
        buff[(addr+1) & 0xFFFF] = current_address & 0x00FF;

        stack_fill = (stack_fill + 1) & 0xFFFF;
        if (stack_location >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;
        buff[stack_location] = (stack_fill >> 8) & 0x00FF;
        buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

        /* ... and jump to the destination address */
        current_address = at_address;

        goto execute_next_instruction;

        break;

    case SIGCOMP_INSTR_RETURN: /* 25 POP and return */
        /* Pop value from the top of the stack */
        stack_location = (buff[70] << 8) | buff[71];
        stack_fill = (buff[stack_location] << 8)
            | buff[(stack_location+1) & 0xFFFF];
        if (stack_fill == 0)
        {
            result_code = 16;
            goto decompression_failure;
        }

        stack_fill = (stack_fill - 1) & 0xFFFF;
        if (stack_location >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;
        buff[stack_location] = (stack_fill >> 8) & 0x00FF;
        buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

        addr = (stack_location + stack_fill * 2 + 2) & 0xFFFF;
        at_address = (buff[addr] << 8)
            | buff[(addr+1) & 0xFFFF];

        /* ... and set the PC to the popped value */
        current_address = at_address;

        goto execute_next_instruction;

        break;

    case SIGCOMP_INSTR_SWITCH: /* 26 SWITCH (#n, %j, @address_0, @address_1, ... , @address_n-1) */
        /*
         * When a SWITCH instruction is encountered the UDVM reads the value of
         * j. It then continues instruction execution at the address specified
         * by address j.
         *
         * Decompression failure occurs if j specifies a value of n or more, or
         * if the address lies beyond the overall UDVM memory size.
         */
        instruction_address = current_address;
        if (show_instr_detail_level == 2) {
            proto_item_append_text(addr_item, " (#n, j, @address_0, @address_1, ... , @address_n-1))");
        }
        operand_address = current_address + 1;
        /* #n
         * Number of addresses in the instruction
         */
        next_operand_address = decode_udvm_literal_operand(buff,operand_address, &n);
        if (print_level_2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_literal_num, bytecode_tvb, offset, (next_operand_address-operand_address), n,
                                "Addr: %u      n %u", operand_address, n);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %j */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &j);
        if (print_level_2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_j, bytecode_tvb, offset, (next_operand_address-operand_address), j,
                                "Addr: %u      j %u", operand_address, j);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        m = 0;
        while ( m < n ) {
            /* @address_n-1 */
            /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_1);
            at_address_1 = ( instruction_address + at_address_1) & 0xffff;
            if (print_level_2 ) {
                proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address_1,
                                    "Addr: %u      @Address %u", operand_address, at_address_1);
            }
            offset += (next_operand_address-operand_address);
            if ( j == m ) {
                current_address = at_address_1;
            }
            operand_address = next_operand_address;
            m++;
        }
        /* Check decompression failure */
        if ( ( j == n ) || ( j > n )) {
            result_code = 5;
            goto decompression_failure;
        }
        if ( current_address > UDVM_MEMORY_SIZE ) {
            result_code = 6;
            goto decompression_failure;
        }
        used_udvm_cycles = used_udvm_cycles + n;

        goto execute_next_instruction;

        break;
    case SIGCOMP_INSTR_CRC: /* 27 CRC (%value, %position, %length, @address) */
        if (show_instr_detail_level == 2) {
            proto_item_append_text(addr_item, " (value, position, length, @address)");
        }
        start_offset = offset;

        operand_address = current_address + 1;

        /* %value */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
        if (print_level_2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_value, bytecode_tvb, offset, (next_operand_address-operand_address), value,
                                "Addr: %u      Value %u", operand_address, value);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %position */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
        if (print_level_2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_position, bytecode_tvb, offset, (next_operand_address-operand_address), position,
                                "Addr: %u      position %u", operand_address, position);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %length */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (print_level_2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      Length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* @address */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address);
        at_address = ( current_address + at_address) & 0xffff;
        if (print_level_2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address,
                                "Addr: %u      @Address %u", operand_address, at_address);
        }
        offset += (next_operand_address-operand_address);
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        used_udvm_cycles = used_udvm_cycles + length;

        n = 0;
        k = position;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        result = 0;

        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, 0, -1,
                                NULL, "byte_copy_right = %u", byte_copy_right);
        }

        while (n<length) {

            guint16 handle_now = length - n;

            if ( k < byte_copy_right && byte_copy_right <= k + (length-n) ) {
                handle_now = byte_copy_right - k;
            }

            if (k + handle_now >= UDVM_MEMORY_SIZE)
                goto decompression_failure;
            result = crc16_ccitt_seed(&buff[k], handle_now, (guint16) (result ^ 0xffff));

            k = ( k + handle_now ) & 0xffff;
            n = ( n + handle_now ) & 0xffff;

            if ( k >= byte_copy_right ) {
                k = byte_copy_left;
            }
        }

        result = result ^ 0xffff;

        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                        "Calculated CRC %u", result);
        }
        if (result != value) {
            current_address = at_address;
        }
        else {
            current_address = next_operand_address;
        }
        goto execute_next_instruction;
        break;


    case SIGCOMP_INSTR_INPUT_BYTES: /* 28 INPUT-BYTES (%length, %destination, @address) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " length, destination, @address)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /* %length */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      Length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* %destination */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_destination, bytecode_tvb, offset, (next_operand_address-operand_address), destination,
                                "Addr: %u      Destination %u", operand_address, destination);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* @address */
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address);
        at_address = ( current_address + at_address) & 0xffff;
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address,
                                "Addr: %u      @Address %u", operand_address, at_address);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## INPUT-BYTES length=%u, destination=%u, @address=%u)",
                                current_address, length, destination, at_address);
        }
        /* execute the instruction TODO insert checks
         * RFC 3320 :
         *
         *    0             7 8            15
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |        byte_copy_left         |  64 - 65
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |        byte_copy_right        |  66 - 67
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |        input_bit_order        |  68 - 69
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |        stack_location         |  70 - 71
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         * Figure 7: Memory addresses of the UDVM registers
         * :
         * 8.4.  Byte copying
         * :
         * The string of bytes is copied in ascending order of memory address,
         * respecting the bounds set by byte_copy_left and byte_copy_right.
         * More precisely, if a byte is copied from/to Address m then the next
         * byte is copied from/to Address n where n is calculated as follows:
         *
         * Set k := m + 1 (modulo 2^16)
         * If k = byte_copy_right then set n := byte_copy_left, else set n := k
         *
         */

        n = 0;
        k = destination;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        if (print_level_1 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, input_address, 1,
                                NULL, "               byte_copy_right = %u", byte_copy_right);
        }
        /* clear out remaining bits if any */
        remaining_bits = 0;
        input_bits=0;
        /* operand_address used as dummy */
        while ( n < length ) {
            if (input_address > ( msg_end - 1)) {
                current_address = at_address;
                result_code = 14;
                goto execute_next_instruction;
            }

            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
            octet = tvb_get_guint8(message_tvb, input_address);
            buff[k] = octet;
            if (print_level_1 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_loading_value, message_tvb, input_address, 1,
                                    octet, "               Loading value: %u (0x%x) at Addr: %u", octet, octet, k);
            }
            input_address++;
            /*
             * If the instruction requests data that lies beyond the end of the
             * SigComp message, no data is returned.  Instead the UDVM moves program
             * execution to the address specified by the address operand.
             */


            k = ( k + 1 ) & 0xffff;
            n++;
        }
        used_udvm_cycles = used_udvm_cycles + length;
        current_address = next_operand_address;
        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_INPUT_BITS:/* 29   INPUT-BITS (%length, %destination, @address) */
        /*
         * The length operand indicates the requested number of bits.
         * Decompression failure occurs if this operand does not lie between 0
         * and 16 inclusive.
         *
         * The destination operand specifies the memory address to which the
         * compressed data should be copied.  Note that the requested bits are
         * interpreted as a 2-byte integer ranging from 0 to 2^length - 1, as
         * explained in Section 8.2.
         *
         * If the instruction requests data that lies beyond the end of the
         * SigComp message, no data is returned.  Instead the UDVM moves program
         * execution to the address specified by the address operand.
         */

        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (length, destination, @address)");
        }
        start_offset = offset;
        operand_address = current_address + 1;

        /* %length */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_length, bytecode_tvb, offset, (next_operand_address-operand_address), length,
                                "Addr: %u      length %u", operand_address, length);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* %destination */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_destination, bytecode_tvb, offset, (next_operand_address-operand_address), destination,
                                "Addr: %u      Destination %u", operand_address, destination);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* @address */
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address,
                                "Addr: %u      @Address %u", operand_address, at_address);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## INPUT-BITS length=%u, destination=%u, @address=%u)",
                                current_address, length, destination, at_address);
        }
        current_address = next_operand_address;

        /*
         * Execute actual instr.
         * The input_bit_order register contains the following three flags:
         *
         *            0             7 8            15
         *           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *           |         reserved        |F|H|P|  68 - 69
         *           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        input_bit_order = buff[68] << 8;
        input_bit_order = input_bit_order | buff[69];
        /*
         * If the instruction requests data that lies beyond the end of the
         * SigComp message, no data is returned.  Instead the UDVM moves program
         * execution to the address specified by the address operand.
         */

        if ( length > 16 ) {
            result_code = 7;
            goto decompression_failure;
        }
        if ( input_bit_order > 7 ) {
            result_code = 8;
            goto decompression_failure;
        }

        /*
         * Transfer F bit to bit_order to tell decomp dispatcher which bit order to use
         */
        bit_order = ( input_bit_order & 0x0004 ) >> 2;
        value = decomp_dispatch_get_bits( message_tvb, udvm_tree, bit_order,
                                          buff, &old_input_bit_order, &remaining_bits,
                                          &input_bits, &input_address, length, &result_code, msg_end, print_level_1);
        if ( result_code == 11 ) {
            current_address = at_address;
            goto execute_next_instruction;
        }
        msb = value >> 8;
        lsb = value & 0x00ff;
        if (destination >= UDVM_MEMORY_SIZE - 1)
            goto decompression_failure;
        buff[destination] = msb;
        buff[(destination + 1) & 0xffff]=lsb;
        if (print_level_1 ) {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_loading_result, message_tvb, input_address, 1,
                                "               Loading value: %u (0x%x) at Addr: %u, remaining_bits: %u", value, value, destination, remaining_bits);
        }

        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_INPUT_HUFFMAN: /* 30 */
        /*
         * INPUT-HUFFMAN (%destination, @address, #n, %bits_1, %lower_bound_1,
         *  %upper_bound_1, %uncompressed_1, ... , %bits_n, %lower_bound_n,
         *  %upper_bound_n, %uncompressed_n)
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (destination, @address, #n, bits_1, lower_bound_1,upper_bound_1, uncompressed_1, ... , bits_n, lower_bound_n,upper_bound_n, uncompressed_n)");
        }
        start_offset = offset;
        operand_address = current_address + 1;

        /* %destination */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_destination, bytecode_tvb, offset, (next_operand_address-operand_address), destination,
                                "Addr: %u      Destination %u", operand_address, destination);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* @address */
        /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
        next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_at_address, bytecode_tvb, offset, (next_operand_address-operand_address), at_address,
                                "Addr: %u      @Address %u", operand_address, at_address);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /* #n */
        next_operand_address = decode_udvm_literal_operand(buff,operand_address, &n);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_literal_num, bytecode_tvb, offset, (next_operand_address-operand_address), n,
                                "Addr: %u      n %u", operand_address, n);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## INPUT-HUFFMAN (destination=%u, @address=%u, #n=%u, bits_1, lower_1,upper_1, unc_1, ... , bits_%d, lower_%d,upper_%d, unc_%d)",
                                current_address, destination, at_address, n, n, n, n, n);
        }

        used_udvm_cycles = used_udvm_cycles + n;

        /*
         * Note that if n = 0 then the INPUT-HUFFMAN instruction is ignored and
         * program execution resumes at the following instruction.
         * Decompression failure occurs if (bits_1 + ... + bits_n) > 16.
         *
         * In all other cases, the behavior of the INPUT-HUFFMAN instruction is
         * defined below:
         *
         * 1. Set j := 1 and set H := 0.
         *
         * 2. Request bits_j compressed bits.  Interpret the returned bits as an
         * integer k from 0 to 2^bits_j - 1, as explained in Section 8.2.
         *
         * 3. Set H := H * 2^bits_j + k.
         *
         * 4. If data is requested that lies beyond the end of the SigComp
         * message, terminate the INPUT-HUFFMAN instruction and move program
         * execution to the memory address specified by the address operand.
         *
         * 5. If (H < lower_bound_j) or (H > upper_bound_j) then set j := j + 1.
         * Then go back to Step 2, unless j > n in which case decompression
         * failure occurs.
         *
         * 6. Copy (H + uncompressed_j - lower_bound_j) modulo 2^16 to the
         * memory address specified by the destination operand.
         *
         */
        /*
         * The input_bit_order register contains the following three flags:
         *
         *            0             7 8            15
         *           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *           |         reserved        |F|H|P|  68 - 69
         *           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         * Transfer H bit to bit_order to tell decomp dispatcher which bit order to use
         */
        input_bit_order = buff[68] << 8;
        input_bit_order = input_bit_order | buff[69];
        bit_order = ( input_bit_order & 0x0002 ) >> 1;

        j = 1;
        H = 0;
        m = n;
        outside_huffman_boundaries = TRUE;
        print_in_loop = print_level_3;
        while ( m > 0 ) {
            /* %bits_n */
            next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &bits_n);
            if (print_in_loop ) {
                proto_tree_add_uint_format(udvm_tree, hf_udvm_bits, bytecode_tvb, offset, (next_operand_address-operand_address), bits_n,
                                    "Addr: %u      bits_n %u", operand_address, bits_n);
            }
            offset += (next_operand_address-operand_address);
            operand_address = next_operand_address;

            /* %lower_bound_n */
            next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &lower_bound_n);
            if (print_in_loop ) {
                proto_tree_add_uint_format(udvm_tree, hf_udvm_lower_bound, bytecode_tvb, offset, (next_operand_address-operand_address), lower_bound_n,
                                    "Addr: %u      lower_bound_n %u", operand_address, lower_bound_n);
            }
            offset += (next_operand_address-operand_address);
            operand_address = next_operand_address;
            /* %upper_bound_n */
            next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &upper_bound_n);
            if (print_in_loop ) {
                proto_tree_add_uint_format(udvm_tree, hf_udvm_upper_bound, bytecode_tvb, offset, (next_operand_address-operand_address), upper_bound_n,
                                    "Addr: %u      upper_bound_n %u", operand_address, upper_bound_n);
            }
            offset += (next_operand_address-operand_address);
            operand_address = next_operand_address;
            /* %uncompressed_n */
            next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &uncompressed_n);
            if (print_in_loop ) {
                proto_tree_add_uint_format(udvm_tree, hf_udvm_uncompressed, bytecode_tvb, offset, (next_operand_address-operand_address), uncompressed_n,
                                    "Addr: %u      uncompressed_n %u", operand_address, uncompressed_n);
            }
            offset += (next_operand_address-operand_address);
            operand_address = next_operand_address;
            /* execute instruction */
            if ( outside_huffman_boundaries ) {
                /*
                 * 2. Request bits_j compressed bits.  Interpret the returned bits as an
                 *    integer k from 0 to 2^bits_j - 1, as explained in Section 8.2.
                 */
                k = decomp_dispatch_get_bits( message_tvb, udvm_tree, bit_order,
                                              buff, &old_input_bit_order, &remaining_bits,
                                              &input_bits, &input_address, bits_n, &result_code, msg_end, print_level_1);
                if ( result_code == 11 ) {
                    /*
                     * 4. If data is requested that lies beyond the end of the SigComp
                     * message, terminate the INPUT-HUFFMAN instruction and move program
                     * execution to the memory address specified by the address operand.
                     */
                    current_address = at_address;
                    goto execute_next_instruction;
                }

                /*
                 * 3. Set H := H * 2^bits_j + k.
                 * [In practice is a shift+OR operation.]
                 */
                oldH = H;
                H = (H << bits_n) | k;
                if (print_level_3 ) {
                    proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_set_hu, bytecode_tvb, 0, -1, NULL,
                                        "               Set H(%u) := H(%u) * 2^bits_j(%u) + k(%u)",
                                        H ,oldH, 1<<bits_n,k);
                }

                /*
                 * 5. If (H < lower_bound_j) or (H > upper_bound_j) then set j := j + 1.
                 * Then go back to Step 2, unless j > n in which case decompression
                 * failure occurs.
                 */
                if ((H < lower_bound_n) || (H > upper_bound_n)) {
                    outside_huffman_boundaries = TRUE;
                } else {
                    outside_huffman_boundaries = FALSE;
                    print_in_loop = FALSE;
                    /*
                     * 6. Copy (H + uncompressed_j - lower_bound_j) modulo 2^16 to the
                     * memory address specified by the destination operand.
                     */
                    if (print_level_2 ) {
                        proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_set_hu, bytecode_tvb, 0, -1, NULL,
                                            "               H(%u) = H(%u) + uncompressed_n(%u) - lower_bound_n(%u)",
                                            (H + uncompressed_n - lower_bound_n ),H, uncompressed_n, lower_bound_n);
                    }
                    H = H + uncompressed_n - lower_bound_n;
                    msb = H >> 8;
                    lsb = H & 0x00ff;
                    if (destination >= UDVM_MEMORY_SIZE - 1)
                        goto decompression_failure;
                    buff[destination] = msb;
                    buff[(destination + 1) & 0xffff]=lsb;
                    if (print_level_1 ) {
                        proto_tree_add_uint_format(udvm_tree, hf_sigcomp_loading_h, message_tvb, input_address, 1, H,
                                            "               Loading H: %u (0x%x) at Addr: %u,j = %u remaining_bits: %u",
                                            H, H, destination,( n - m + 1 ), remaining_bits);
                    }

                }


            }
            m = m - 1;
        }
        if ( outside_huffman_boundaries ) {
            result_code = 10;
            goto decompression_failure;
        }

        current_address = next_operand_address;
        goto execute_next_instruction;
        break;

    case SIGCOMP_INSTR_STATE_ACCESS: /* 31 */
        /*   STATE-ACCESS (%partial_identifier_start, %partial_identifier_length,
         * %state_begin, %state_length, %state_address, %state_instruction)
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (partial_identifier_start, partial_identifier_length,state_begin, state_length, state_address, state_instruction)");
        }
        start_offset = offset;
        operand_address = current_address + 1;

        /*
         * %partial_identifier_start
         */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_start);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_partial_identifier_start, bytecode_tvb, offset, (next_operand_address-operand_address), p_id_start,
                                "Addr: %u       partial_identifier_start %u", operand_address, p_id_start);
        }
        offset += (next_operand_address-operand_address);

        /*
         * %partial_identifier_length
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_partial_identifier_length, bytecode_tvb, offset, (next_operand_address-operand_address), p_id_length,
                                "Addr: %u       partial_identifier_length %u", operand_address, p_id_length);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_begin
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_begin);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_state_begin, bytecode_tvb, offset, (next_operand_address-operand_address), state_begin,
                                "Addr: %u       state_begin %u", operand_address, state_begin);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_length
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_length, bytecode_tvb, offset, (next_operand_address-operand_address), state_length,
                                "Addr: %u       state_length %u", operand_address, state_length);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_address
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_address);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_address, bytecode_tvb, offset, (next_operand_address-operand_address), state_address,
                                "Addr: %u       state_address %u", operand_address, state_address);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_instruction
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_instruction);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_instr, bytecode_tvb, offset, (next_operand_address-operand_address), state_instruction,
                                "Addr: %u       state_instruction %u", operand_address, state_instruction);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## STATE-ACCESS(31) (partial_identifier_start=%u, partial_identifier_length=%u,state_begin=%u, state_length=%u, state_address=%u, state_instruction=%u)",
                                current_address, p_id_start, p_id_length, state_begin, state_length, state_address, state_instruction);
        }
        current_address = next_operand_address;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        if (print_level_2 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, message_tvb, input_address, 1, NULL,
                                "               byte_copy_right = %u, byte_copy_left = %u", byte_copy_right,byte_copy_left);
        }

        result_code = udvm_state_access(message_tvb, udvm_tree, buff, p_id_start, p_id_length, state_begin, &state_length,
                                        &state_address, &state_instruction, hf_id);
        if ( result_code != 0 ) {
            goto decompression_failure;
        }
        used_udvm_cycles = used_udvm_cycles + state_length;
        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_STATE_CREATE: /* 32 */
        /*
         * STATE-CREATE (%state_length, %state_address, %state_instruction,
         * %minimum_access_length, %state_retention_priority)
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (state_length, state_address, state_instruction,minimum_access_length, state_retention_priority)");
        }
        start_offset = offset;
        operand_address = current_address + 1;

        /*
         * %state_length
         */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_length, bytecode_tvb, offset, (next_operand_address-operand_address), state_length,
                                "Addr: %u       state_length %u", operand_address, state_length);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_address
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_address);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_address, bytecode_tvb, offset, (next_operand_address-operand_address), state_address,
                                "Addr: %u       state_address %u", operand_address, state_address);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_instruction
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_instruction);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_instr, bytecode_tvb, offset, (next_operand_address-operand_address), state_instruction,
                                "Addr: %u       state_instruction %u", operand_address, state_instruction);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %minimum_access_length
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &minimum_access_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_min_acc_len, bytecode_tvb, offset, (next_operand_address-operand_address), minimum_access_length,
                                "Addr: %u       minimum_access_length %u", operand_address, minimum_access_length);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_retention_priority
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_retention_priority);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_ret_pri, bytecode_tvb, offset, (next_operand_address-operand_address), state_retention_priority,
                                "Addr: %u       state_retention_priority %u", operand_address, state_retention_priority);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## STATE-CREATE(32) (state_length=%u, state_address=%u, state_instruction=%u,minimum_access_length=%u, state_retention_priority=%u)",
                                current_address, state_length, state_address, state_instruction,minimum_access_length, state_retention_priority);
        }
        current_address = next_operand_address;
        /* Execute the instruction
         * TODO Implement the instruction
         * RFC3320:
         *    Note that the new state item cannot be created until a valid
         *    compartment identifier has been returned by the application.
         *    Consequently, when a STATE-CREATE instruction is encountered the UDVM
         *    simply buffers the five supplied operands until the END-MESSAGE
         *    instruction is reached.  The steps taken at this point are described
         *    in Section 9.4.9.
         *
         *   Decompression failure MUST occur if more than four state creation
         *   requests are made before the END-MESSAGE instruction is encountered.
         *   Decompression failure also occurs if the minimum_access_length does
         *   not lie between 6 and 20 inclusive, or if the
         *   state_retention_priority is 65535.
         */
        no_of_state_create++;
        if ( no_of_state_create > 4 ) {
            result_code = 12;
            goto decompression_failure;
        }
        if (( minimum_access_length < 6 ) || ( minimum_access_length > STATE_BUFFER_SIZE )) {
            result_code = 1;
            goto decompression_failure;
        }
        if ( state_retention_priority == 65535 ) {
            result_code = 13;
            goto decompression_failure;
        }
        state_length_buff[no_of_state_create] = state_length;
        state_address_buff[no_of_state_create] = state_address;
        state_instruction_buff[no_of_state_create] = state_instruction;
        state_minimum_access_length_buff[no_of_state_create] = minimum_access_length;
        /* state_state_retention_priority_buff[no_of_state_create] = state_retention_priority; */
        used_udvm_cycles = used_udvm_cycles + state_length;
        /* Debug */
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        n = 0;
        k = state_address;
        while ( n < state_length ) {
            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
            string[0]= buff[k];
            string[1]= '\0';
            if (print_level_3 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_state_value, bytecode_tvb, 0, 0, buff[k],
                                    "               Addr: %5u State value: %u (0x%x) ASCII(%s)",
                                    k,buff[k],buff[k],format_text(string, 1));
            }
            k = ( k + 1 ) & 0xffff;
            n++;
        }
        /* End debug */

        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_STATE_FREE: /* 33 */
        /*
         * STATE-FREE (%partial_identifier_start, %partial_identifier_length)
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (partial_identifier_start, partial_identifier_length)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /*
         * %partial_identifier_start
         */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_start);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_partial_identifier_start, bytecode_tvb, offset, (next_operand_address-operand_address), p_id_start,
                                "Addr: %u       partial_identifier_start %u", operand_address, p_id_start);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;

        /*
         * %partial_identifier_length
         */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_partial_identifier_length, bytecode_tvb, offset, (next_operand_address-operand_address), p_id_length,
                                "Addr: %u       partial_identifier_length %u", operand_address, p_id_length);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## STATE-FREE (partial_identifier_start=%u, partial_identifier_length=%u)",
                                current_address, p_id_start, p_id_length);
        }
        current_address = next_operand_address;

        /* Execute the instruction:
         * TODO implement it
         */
        udvm_state_free(buff,p_id_start,p_id_length);

        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_OUTPUT: /* 34 OUTPUT (%output_start, %output_length) */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (output_start, output_length)");
        }
        start_offset = offset;
        operand_address = current_address + 1;
        /*
         * %output_start
         */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &output_start);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_output_start, bytecode_tvb, offset, (next_operand_address-operand_address), output_start,
                                "Addr: %u      output_start %u", operand_address, output_start);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /*
         * %output_length
         */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &output_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_output_length, bytecode_tvb, offset, (next_operand_address-operand_address), output_length,
                                "Addr: %u      output_length %u", operand_address, output_length);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## OUTPUT (output_start=%u, output_length=%u)",
                                current_address, output_start, output_length);
        }
        current_address = next_operand_address;

        /*
         * Execute instruction
         * 8.4.  Byte copying
         * :
         * The string of bytes is copied in ascending order of memory address,
         * respecting the bounds set by byte_copy_left and byte_copy_right.
         * More precisely, if a byte is copied from/to Address m then the next
         * byte is copied from/to Address n where n is calculated as follows:
         *
         * Set k := m + 1 (modulo 2^16)
         * If k = byte_copy_right then set n := byte_copy_left, else set n := k
         *
         */

        n = 0;
        k = output_start;
        byte_copy_right = buff[66] << 8;
        byte_copy_right = byte_copy_right | buff[67];
        byte_copy_left = buff[64] << 8;
        byte_copy_left = byte_copy_left | buff[65];
        if (print_level_3 ) {
            proto_tree_add_bytes_format(udvm_tree, hf_sigcomp_byte_copy, bytecode_tvb, 0, -1,
                                NULL, "               byte_copy_right = %u", byte_copy_right);
        }
        while ( n < output_length ) {

            if ( k == byte_copy_right ) {
                k = byte_copy_left;
            }
            out_buff[output_address] = buff[k];
            string[0]= buff[k];
            string[1]= '\0';
            if (print_level_3 ) {
                proto_tree_add_uint_format(udvm_tree, hf_sigcomp_output_value, bytecode_tvb, 0, -1, buff[k],
                                    "               Output value: %u (0x%x) ASCII(%s) from Addr: %u ,output to dispatcher position %u",
                                    buff[k],buff[k],format_text(string,1), k,output_address);
            }
            k = ( k + 1 ) & 0xffff;
            output_address ++;
            n++;
        }
        used_udvm_cycles = used_udvm_cycles + output_length;
        goto execute_next_instruction;
        break;
    case SIGCOMP_INSTR_END_MESSAGE: /* 35 */
        /*
         * END-MESSAGE (%requested_feedback_location,
         * %returned_parameters_location, %state_length, %state_address,
         * %state_instruction, %minimum_access_length,
         * %state_retention_priority)
         */
        if (show_instr_detail_level == 2 ) {
            proto_item_append_text(addr_item, " (requested_feedback_location,state_instruction, minimum_access_length,state_retention_priority)");
        }
        start_offset = offset;
        operand_address = current_address + 1;

        /* %requested_feedback_location */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &requested_feedback_location);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_req_feedback_loc, bytecode_tvb, offset, (next_operand_address-operand_address), requested_feedback_location,
                                "Addr: %u      requested_feedback_location %u",
                                operand_address, requested_feedback_location);
        }
        offset += (next_operand_address-operand_address);
        operand_address = next_operand_address;
        /* returned_parameters_location */
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &returned_parameters_location);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_ret_param_loc, bytecode_tvb, offset, (next_operand_address-operand_address), returned_parameters_location,
                                "Addr: %u      returned_parameters_location %u", operand_address, returned_parameters_location);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_length
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_length, bytecode_tvb, offset, (next_operand_address-operand_address), state_length,
                                "Addr: %u      state_length %u", operand_address, state_length);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_address
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_address);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_address, bytecode_tvb, offset, (next_operand_address-operand_address), state_address,
                                "Addr: %u      state_address %u", operand_address, state_address);
        }
        offset += (next_operand_address-operand_address);
        /*
         * %state_instruction
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_instruction);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_instr, bytecode_tvb, offset, (next_operand_address-operand_address), state_instruction,
                                "Addr: %u      state_instruction %u", operand_address, state_instruction);
        }
        offset += (next_operand_address-operand_address);

        /*
         * %minimum_access_length
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &minimum_access_length);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_min_acc_len, bytecode_tvb, offset, (next_operand_address-operand_address), minimum_access_length,
                                "Addr: %u      minimum_access_length %u", operand_address, minimum_access_length);
        }
        offset += (next_operand_address-operand_address);

        /*
         * %state_retention_priority
         */
        operand_address = next_operand_address;
        next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_retention_priority);
        if (show_instr_detail_level == 2 ) {
            proto_tree_add_uint_format(udvm_tree, hf_udvm_state_ret_pri, bytecode_tvb, offset, (next_operand_address-operand_address), state_retention_priority,
                                "Addr: %u      state_retention_priority %u", operand_address, state_retention_priority);
        }
        offset += (next_operand_address-operand_address);
        if (show_instr_detail_level == 1)
        {
            proto_tree_add_none_format(udvm_tree, hf_sigcomp_decompress_instruction, bytecode_tvb, start_offset, offset-start_offset,
                                "Addr: %u ## END-MESSAGE (requested_feedback_location=%u, returned_parameters_location=%u, state_length=%u, state_address=%u, state_instruction=%u, minimum_access_length=%u, state_retention_priority=%u)",
                                current_address, requested_feedback_location, returned_parameters_location, state_length, state_address, state_instruction, minimum_access_length,state_retention_priority);
        }
        /* TODO: This isn't currently totally correct as END_INSTRUCTION might not create state */
        no_of_state_create++;
        if ( no_of_state_create > 4 ) {
            result_code = 12;
            goto decompression_failure;
        }
        state_length_buff[no_of_state_create] = state_length;
        state_address_buff[no_of_state_create] = state_address;
        state_instruction_buff[no_of_state_create] = state_instruction;
        /* Not used ? */
        state_minimum_access_length_buff[no_of_state_create] = minimum_access_length;
        /* state_state_retention_priority_buff[no_of_state_create] = state_retention_priority; */

        /* Execute the instruction
         */
        proto_tree_add_uint(udvm_tree, hf_sigcomp_num_state_create, bytecode_tvb, 0, 0, no_of_state_create);
        if ( no_of_state_create != 0 ) {
            memset(sha1_digest_buf, 0, STATE_BUFFER_SIZE);
            n = 1;
            byte_copy_right = buff[66] << 8;
            byte_copy_right = byte_copy_right | buff[67];
            byte_copy_left = buff[64] << 8;
            byte_copy_left = byte_copy_left | buff[65];
            while ( n < no_of_state_create + 1 ) {
                sha1buff = (guint8 *)g_malloc(state_length_buff[n]+8);
                sha1buff[0] = state_length_buff[n] >> 8;
                sha1buff[1] = state_length_buff[n] & 0xff;
                sha1buff[2] = state_address_buff[n] >> 8;
                sha1buff[3] = state_address_buff[n] & 0xff;
                sha1buff[4] = state_instruction_buff[n] >> 8;
                sha1buff[5] = state_instruction_buff[n] & 0xff;
                sha1buff[6] = state_minimum_access_length_buff[n] >> 8;
                sha1buff[7] = state_minimum_access_length_buff[n] & 0xff;
                if (print_level_3 ) {
                    proto_tree_add_bytes_with_length(udvm_tree, hf_sigcomp_sha1buff, bytecode_tvb, 0, -1, sha1buff, 8);
                }
                k = state_address_buff[n];
                for ( x=0; x < state_length_buff[n]; x++)
                {
                    if ( k == byte_copy_right ) {
                        k = byte_copy_left;
                    }
                    sha1buff[8+x] = buff[k];
                    k = ( k + 1 ) & 0xffff;
                }

                sha1_starts( &ctx );
                sha1_update( &ctx, (guint8 *) sha1buff, state_length_buff[n] + 8);
                sha1_finish( &ctx, sha1_digest_buf );
                if (print_level_3 ) {
                    proto_tree_add_bytes_with_length(udvm_tree, hf_sigcomp_sha1_digest, bytecode_tvb, 0, -1, sha1_digest_buf, STATE_BUFFER_SIZE);

                }
/* begin partial state-id change cco@iptel.org */
#if 0
                udvm_state_create(sha1buff, sha1_digest_buf, state_minimum_access_length_buff[n]);
#endif
                udvm_state_create(sha1buff, sha1_digest_buf, STATE_MIN_ACCESS_LEN);
/* end partial state-id change cco@iptel.org */
                proto_tree_add_item(udvm_tree, hf_sigcomp_creating_state, bytecode_tvb, 0, -1, ENC_NA);
                proto_tree_add_string(udvm_tree,hf_id, bytecode_tvb, 0, 0, bytes_to_str(wmem_packet_scope(), sha1_digest_buf, STATE_MIN_ACCESS_LEN));

                n++;

            }
        }



        /* At least something got decompressed, show it */
        decomp_tvb = tvb_new_child_real_data(message_tvb, out_buff,output_address,output_address);
        /* Arrange that the allocated packet data copy be freed when the
         * tvbuff is freed.
         */
        tvb_set_free_cb( decomp_tvb, g_free );

        add_new_data_source(pinfo, decomp_tvb, "Decompressed SigComp message");
        proto_tree_add_item(udvm_tree, hf_sigcomp_sigcomp_message_decompressed, decomp_tvb, 0, -1, ENC_NA);

        used_udvm_cycles += state_length;
        proto_tree_add_uint(udvm_tree, hf_sigcomp_max_udvm_cycles, bytecode_tvb, 0, 0, maximum_UDVM_cycles);
        proto_tree_add_uint(udvm_tree, hf_sigcomp_used_udvm_cycles, bytecode_tvb, 0, 0, used_udvm_cycles);
        return decomp_tvb;
        break;

    default:
        expert_add_info_format(pinfo, addr_item, &ei_sigcomp_invalid_instruction,
                            "Addr %u Invalid instruction: %u (0x%x)", current_address,current_instruction,current_instruction);
        break;
    }
    g_free(out_buff);
    return NULL;
decompression_failure:

    proto_tree_add_expert_format(udvm_tree, pinfo, &ei_sigcomp_decompression_failure, bytecode_tvb, 0, -1,
                        "DECOMPRESSION FAILURE: %s", val_to_str(result_code, result_code_vals,"Unknown (%u)"));
    g_free(out_buff);
    return NULL;

}

/**********************************************************************************************
 *
 *                       SIGCOMP DISSECTOR
 *
 **********************************************************************************************/


/* Sigcomp over TCP record marking used
 * RFC 3320
 * 4.2.2.  Record Marking
 *
 * For a stream-based transport, the dispatcher delimits messages by
 * parsing the compressed data stream for instances of 0xFF and taking
 * the following actions:
 * Occurs in data stream:     Action:
 *
 *   0xFF 00                    one 0xFF byte in the data stream
 *   0xFF 01                    same, but the next byte is quoted (could
 *                              be another 0xFF)
 *      :                                           :
 *   0xFF 7F                    same, but the next 127 bytes are quoted
 *   0xFF 80 to 0xFF FE         (reserved for future standardization)
 *   0xFF FF                    end of SigComp message
 *   :
 *   In UDVM version 0x01, any occurrence of the combinations 0xFF80 to
 *   0xFFFE that are not protected by quoting causes decompression
 *   failure; the decompressor SHOULD close the stream-based transport in
 *   this case.
 */

/*
 * TODO: Reassembly, handle more than one message in a tcp segment.
 */

static int
dissect_sigcomp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *_data _U_)
{
    proto_item *ti;
    proto_tree *sigcomp_tree;
    tvbuff_t   *unescaped_tvb;

    guint8     *buff;
    int         offset = 0;
    int         length;
    guint8      octet;
    guint16     data;
    int         i;
    int         n;
    gboolean    end_off_message;

    top_tree = tree;

    /* Is this SIGCOMP ? */
    data = tvb_get_ntohs(tvb, offset);
    if (data == 0xffff) {
        /* delimiter */
        offset = offset + 2;
        octet = tvb_get_guint8(tvb,offset);
    } else {
        octet = tvb_get_guint8(tvb,offset);
    }
    if ((octet  & 0xf8) != 0xf8)
     return offset;

    /* Search for delimiter 0xffff in the remain tvb buffer */
    length = tvb_reported_length_remaining(tvb, offset);
    for (i=0; i<(length-1); ++i) {
        /* Loop end criteria is (length-1) because we take 2 bytes each loop */
        data = tvb_get_ntohs(tvb, offset+i);
        if (0xffff == data) break;
    }
    if (i >= (length-1)) {
        /* SIGCOMP may be subdissector of SIP, so we use
         * pinfo->saved_can_desegment to determine whether do desegment
         * as well as pinfo->can_desegment */
        if (pinfo->can_desegment || pinfo->saved_can_desegment) {
            /* Delimiter oxffff was not found, not a complete SIGCOMP PDU */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len=DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIGCOMP");

    col_clear(pinfo->cinfo, COL_INFO);

    length = tvb_captured_length_remaining(tvb,offset);

try_again:
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_sigcomp, tvb, 0, -1, ENC_NA);
    sigcomp_tree = proto_item_add_subtree(ti, ett_sigcomp);
    i=0;
    end_off_message = FALSE;
    buff = (guint8 *)wmem_alloc(pinfo->pool, length-offset);
    if (udvm_print_detail_level>2)
        proto_tree_add_item(sigcomp_tree, hf_sigcomp_starting_to_remove_escape_digits, tvb, offset, -1, ENC_NA);
    while ((offset < length) && (end_off_message == FALSE)) {
        octet = tvb_get_guint8(tvb,offset);
        if ( octet == 0xff ) {
            if ( offset +1 >= length ) {
                /* if the tvb is short don't check for the second escape digit */
                offset++;
                continue;
            }
            if (udvm_print_detail_level>2)
                proto_tree_add_none_format(sigcomp_tree, hf_sigcomp_escape_digit_found, tvb, offset, 2,
                    "              Escape digit found (0xFF)");
            octet = tvb_get_guint8(tvb, offset+1);
            if ( octet == 0) {
                buff[i] = 0xff;
                offset = offset +2;
                i++;
                continue;
            }
            if ((octet > 0x7f) && (octet < 0xff )) {
                if (udvm_print_detail_level>2)
                    proto_tree_add_none_format(sigcomp_tree, hf_sigcomp_illegal_escape_code, tvb, offset, 2,
                        "              Illegal escape code");
                offset += tvb_captured_length_remaining(tvb,offset);
                return offset;
            }
            if ( octet == 0xff) {
                if (udvm_print_detail_level>2)
                    proto_tree_add_none_format(sigcomp_tree, hf_sigcomp_end_of_sigcomp_message_indication_found, tvb, offset, 2,
                        "              End of SigComp message indication found (0xFFFF)");
                end_off_message = TRUE;
                offset = offset+2;
                continue;
            }
            buff[i] = 0xff;
            if (udvm_print_detail_level>2)
                proto_tree_add_uint_format(sigcomp_tree, hf_sigcomp_addr_value, tvb, offset, 1, buff[i],
                            "              Addr: %u tvb value(0x%0x) ", i, buff[i]);
            i++;
            offset = offset+2;
            if (udvm_print_detail_level>2)
            proto_tree_add_bytes_format(sigcomp_tree, hf_sigcomp_copying_bytes_literally, tvb, offset, octet,
                        NULL, "              Copying %u bytes literally",octet);
            if ( offset+octet >= length)
                /* if the tvb is short don't copy further than the end */
                octet = length - offset;
            for ( n=0; n < octet; n++ ) {
                buff[i] = tvb_get_guint8(tvb, offset);
                if (udvm_print_detail_level>2)
                    proto_tree_add_uint_format(sigcomp_tree, hf_sigcomp_addr_value, tvb, offset, 1, buff[i],
                                "                  Addr: %u tvb value(0x%0x) ", i, buff[i]);
                i++;
                offset++;
            }
            continue;
        }
        buff[i] = octet;
        if (udvm_print_detail_level>2)
            proto_tree_add_uint_format(sigcomp_tree, hf_sigcomp_addr_value, tvb, offset, 1, buff[i],
                        "              Addr: %u tvb value(0x%0x) ", i, buff[i]);

        i++;
        offset++;
    }
    unescaped_tvb = tvb_new_child_real_data(tvb, buff,i,i);

    add_new_data_source(pinfo, unescaped_tvb, "Unescaped Data handed to the SigComp dissector");

    proto_tree_add_item(sigcomp_tree, hf_sigcomp_data_for_sigcomp_dissector, unescaped_tvb, 0, -1, ENC_NA);
    if (end_off_message == TRUE) {
        dissect_sigcomp_common(unescaped_tvb, pinfo, sigcomp_tree);
    } else {
        proto_tree_add_expert(sigcomp_tree, pinfo, &ei_sigcomp_tcp_fragment, unescaped_tvb, 0, -1);
    }
    if ( offset < length) {
        goto try_again;
    }

    return offset;
}
/* Code to actually dissect the packets */
static int
dissect_sigcomp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *sigcomp_tree;
    gint        offset = 0;
    gint8       octet;

    /* If we got called from SIP this might be over TCP */
    if ( pinfo->ptype == PT_TCP )
        return dissect_sigcomp_tcp(tvb, pinfo, tree, NULL);

    /* Is this a SigComp message or not ? */
    octet = tvb_get_guint8(tvb, offset);
    if ((octet  & 0xf8) != 0xf8)
     return 0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIGCOMP");

    col_clear(pinfo->cinfo, COL_INFO);

    top_tree = tree;

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_sigcomp, tvb, 0, -1, ENC_NA);
    sigcomp_tree = proto_item_add_subtree(ti, ett_sigcomp);

    return dissect_sigcomp_common(tvb, pinfo, sigcomp_tree);
}
/* Code to actually dissect the packets */
static int
dissect_sigcomp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *sigcomp_tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    tvbuff_t   *udvm_tvb, *msg_tvb, *udvm2_tvb;
    tvbuff_t   *decomp_tvb   = NULL;
    proto_item *udvm_bytecode_item, *udvm_exe_item;
    proto_tree *sigcomp_udvm_tree, *sigcomp_udvm_exe_tree;
    gint        offset       = 0;
    gint        bytecode_offset;
    guint16     partial_state_len;
    guint       octet;
    guint8      returned_feedback_field[128];
    guint8      partial_state[12];
    guint       tbit;
    guint16     len          = 0;
    guint16     bytecode_len = 0;
    guint       destination;
    gint        msg_len      = 0;
    guint8     *buff;
    guint16     p_id_start;
    guint8      i;
    guint16     state_begin;
    guint16     state_length;
    guint16     state_address;
    guint16     state_instruction;
    guint16     result_code;
    gchar      *partial_state_str;
    guint8      nack_version;



/* add an item to the subtree, see section 1.6 for more information */
    octet = tvb_get_guint8(tvb, offset);

/*   A SigComp message takes one of two forms depending on whether it
 *  accesses a state item at the receiving endpoint.  The two variants of
 *  a SigComp message are given in Figure 3.  (The T-bit controls the
 *  format of the returned feedback item and is defined in Section 7.1.)
 *
 *   0   1   2   3   4   5   6   7       0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+---+---+---+---+
 * | 1   1   1   1   1 | T |  len  |   | 1   1   1   1   1 | T |   0   |
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+---+---+---+---+
 * |                               |   |                               |
 * :    returned feedback item     :   :    returned feedback item     :
 * |                               |   |                               |
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+---+---+---+---+
 * |                               |   |           code_len            |
 * :   partial state identifier    :   +---+---+---+---+---+---+---+---+
 *
 * |                               |   |   code_len    |  destination  |
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+---+---+---+---+
 * |                               |   |                               |
 * :   remaining SigComp message   :   :    uploaded UDVM bytecode     :
 * |                               |   |                               |
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+---+---+---+---+
 *                                     |                               |
 *                                     :   remaining SigComp message   :
 *                                     |                               |
 *                                     +---+---+---+---+---+---+---+---+
 *
 * RFC 4077:
 * The format of the NACK message and the use of the fields within it
 * are shown in Figure 1.
 *
 *                     0   1   2   3   4   5   6   7
 *                  +---+---+---+---+---+---+---+---+
 *                  | 1   1   1   1   1 | T |   0   |
 *                  +---+---+---+---+---+---+---+---+
 *                  |                               |
 *                  :    returned feedback item     :
 *                  |                               |
 *                  +---+---+---+---+---+---+---+---+
 *                  |         code_len = 0          |
 *                  +---+---+---+---+---+---+---+---+
 *                  | code_len = 0  |  version = 1  |
 *                  +---+---+---+---+---+---+---+---+
 *                  |          Reason Code          |
 *                  +---+---+---+---+---+---+---+---+
 *                  |  OPCODE of failed instruction |
 *                  +---+---+---+---+---+---+---+---+
 *                  |   PC of failed instruction    |
 *                  |                               |
 *                  +---+---+---+---+---+---+---+---+
 *                  |                               |
 *                  : SHA-1 Hash of failed message  :
 *                  |                               |
 *                  +---+---+---+---+---+---+---+---+
 *                  |                               |
 *                  :         Error Details         :
 *                  |                               |
 *                  +---+---+---+---+---+---+---+---+
 *                  Figure 1: SigComp NACK Message Format
 */

    proto_tree_add_item(sigcomp_tree,hf_sigcomp_t_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sigcomp_tree,hf_sigcomp_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    tbit = ( octet & 0x04)>>2;
    partial_state_len = octet & 0x03;
    offset ++;
    if ( partial_state_len != 0 ) {
        /*
         * The len field encodes the number of transmitted bytes as follows:
         *
         *   Encoding:   Length of partial state identifier
         *
         *   01          6 bytes
         *   10          9 bytes
         *   11          12 bytes
         *
         */
        partial_state_len = partial_state_len * 3 + 3;

        /*
         * Message format 1
         */
        col_set_str(pinfo->cinfo, COL_INFO, "Msg format 1");

        if ( tbit == 1 ) {
            /*
             * Returned feedback item exists
             */
            len = 1;
            octet = tvb_get_guint8(tvb, offset);
            /* 0   1   2   3   4   5   6   7       0   1   2   3   4   5   6   7
             * +---+---+---+---+---+---+---+---+   +---+---+---+---+---+---+---+---+
             * | 0 |  returned_feedback_field  |   | 1 | returned_feedback_length  |
             * +---+---+---+---+---+---+---+---+   +---+---+---+---+---+---+---+---+
             *                                     |                               |
             *                                     :    returned_feedback_field    :
             *                                     |                               |
             *                                     +---+---+---+---+---+---+---+---+
             * Figure 4: Format of returned feedback item
             */

            if ( (octet & 0x80) != 0 ) {
                len = octet & 0x7f;
                proto_tree_add_item(sigcomp_tree,hf_sigcomp_returned_feedback_item_len,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;
                tvb_memcpy(tvb,returned_feedback_field,offset, len);
            } else {
                returned_feedback_field[0] = tvb_get_guint8(tvb, offset) & 0x7f;
            }
            proto_tree_add_bytes(sigcomp_tree,hf_sigcomp_returned_feedback_item,
                                 tvb, offset, len, returned_feedback_field);
            offset = offset + len;
        }
        tvb_memcpy(tvb, partial_state, offset, partial_state_len);
        partial_state_str = bytes_to_str(wmem_packet_scope(), partial_state, partial_state_len);
        proto_tree_add_string(sigcomp_tree,hf_sigcomp_partial_state,
            tvb, offset, partial_state_len, partial_state_str);
        offset = offset + partial_state_len;
        msg_len = tvb_reported_length_remaining(tvb, offset);

        if (msg_len>0) {
            proto_item *ti;
            ti = proto_tree_add_uint(sigcomp_tree, hf_sigcomp_remaining_message_bytes, tvb,
                                     offset, 0, msg_len);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        if ( decompress ) {
            msg_tvb = tvb_new_subset_length(tvb, offset, msg_len);
            /*
             * buff                 = Where "state" will be stored
             * p_id_start           = Partial state identifier start pos in the buffer(buff)
             * partial_state_len    = Partial state identifier length
             * state_begin          = Where to start to read state from
             * state_length         = Length of state
             * state_address            = Address where to store the state in the buffer(buff)
             * state_instruction    =
             * TRUE                 = Indicates that state_* is in the stored state
             */
            /*
             * Note: The allocated buffer must be zeroed or some strange effects might occur.
             */
            buff = (guint8 *)wmem_alloc0(pinfo->pool, UDVM_MEMORY_SIZE);


            p_id_start = 0;
            state_begin = 0;
            /* These values will be loaded from the buffered state in sigcomp_state_hdlr
             */
            state_length = 0;
            state_address = 0;
            state_instruction =0;

            i = 0;
            while ( i < partial_state_len ) {
                buff[i] = partial_state[i];
                i++;
            }

/* begin partial state-id change cco@iptel.org */
#if 0
            result_code = udvm_state_access(tvb, sigcomp_tree, buff, p_id_start, partial_state_len, state_begin, &state_length,
                &state_address, &state_instruction, hf_sigcomp_partial_state);
#endif
            result_code = udvm_state_access(tvb, sigcomp_tree, buff, p_id_start, STATE_MIN_ACCESS_LEN, state_begin, &state_length,
                &state_address, &state_instruction, hf_sigcomp_partial_state);

/* end partial state-id change cco@iptel.org */
            if ( result_code != 0 ) {
                proto_tree_add_expert_format(sigcomp_tree, pinfo, &ei_sigcomp_failed_to_access_state_wireshark_udvm_diagnostic, tvb, 0, -1,
                                                                                         "Failed to Access state Wireshark UDVM diagnostic: %s", val_to_str(result_code, result_code_vals,"Unknown (%u)"));
                return tvb_captured_length(tvb);
            }

            udvm_tvb = tvb_new_child_real_data(tvb, buff,state_length+state_address,state_length+state_address);
            add_new_data_source(pinfo, udvm_tvb, "State/ExecutionTrace");

            udvm2_tvb = tvb_new_subset_length(udvm_tvb, state_address, state_length);
            udvm_exe_item = proto_tree_add_item(sigcomp_tree, hf_udvm_execution_trace,
                                                udvm2_tvb, 0, state_length,
                                                ENC_NA);
            sigcomp_udvm_exe_tree = proto_item_add_subtree( udvm_exe_item, ett_sigcomp_udvm_exe);

            decomp_tvb = decompress_sigcomp_message(udvm2_tvb, msg_tvb, pinfo,
                           sigcomp_udvm_exe_tree, state_address,
                           udvm_print_detail_level, hf_sigcomp_partial_state,
                           offset, state_length, partial_state_len, state_instruction);


            if ( decomp_tvb ) {
                proto_item *ti;
                guint32 compression_ratio =
                    (guint32)(((float)tvb_reported_length(decomp_tvb) / (float)tvb_reported_length(tvb)) * 100);

                /* Show compression ratio achieved */
                ti = proto_tree_add_uint(sigcomp_tree, hf_sigcomp_compression_ratio, decomp_tvb,
                                         0, 0, compression_ratio);
                PROTO_ITEM_SET_GENERATED(ti);

                if ( display_raw_txt )
                    tvb_raw_text_add(decomp_tvb, top_tree);

                col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
                col_set_fence(pinfo->cinfo,COL_PROTOCOL);
                call_dissector(sip_handle, decomp_tvb, pinfo, top_tree);
            }
        }/* if decompress */

    }
    else{
        /*
         * Message format 2
         */
    col_set_str(pinfo->cinfo, COL_INFO, "Msg format 2");
        if ( tbit == 1 ) {
            /*
             * Returned feedback item exists
             */
            len = 1;
            octet = tvb_get_guint8(tvb, offset);
            if ( (octet & 0x80) != 0 ) {
                len = octet & 0x7f;
                proto_tree_add_item(sigcomp_tree,hf_sigcomp_returned_feedback_item_len,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;
            }
            tvb_memcpy(tvb,returned_feedback_field,offset, len);
            proto_tree_add_bytes(sigcomp_tree,hf_sigcomp_returned_feedback_item,
                                 tvb, offset, len, returned_feedback_field);
            offset = offset + len;
        }
        len = tvb_get_ntohs(tvb, offset) >> 4;
        nack_version = tvb_get_guint8(tvb, offset+1) & 0x0f;
        if ((len == 0) && (nack_version == 1)) {
            /* NACK MESSAGE */
            proto_item *reason_ti;
            guint8 opcode;
            offset++;
            proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            octet = tvb_get_guint8(tvb, offset);
            reason_ti = proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            opcode = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_failed_op_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Add expert item for NACK */
            expert_add_info_format(pinfo, reason_ti, &ei_sigcomp_nack_failed_op_code,
                                   "SigComp NACK (reason=%s, opcode=%s)",
                                   val_to_str_ext_const(octet, &sigcomp_nack_reason_code_vals_ext, "Unknown"),
                                   val_to_str_ext_const(opcode, &udvm_instruction_code_vals_ext, "Unknown"));

            proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_pc, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset = offset +2;
            proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_sha1, tvb, offset, SHA1_DIGEST_LEN, ENC_NA);
            offset = offset +SHA1_DIGEST_LEN;

            /* Add NACK info to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, "  NACK reason=%s, opcode=%s",
                            val_to_str_ext_const(octet, &sigcomp_nack_reason_code_vals_ext, "Unknown"),
                            val_to_str_ext_const(opcode, &udvm_instruction_code_vals_ext, "Unknown"));

            switch ( octet) {
            case SIGCOMP_NACK_STATE_NOT_FOUND:
            case SIGCOMP_NACK_ID_NOT_UNIQUE:
            case SIGCOMP_NACK_STATE_TOO_SHORT:
                /* State ID (6 - 20 bytes) */
                proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_state_id, tvb, offset, -1, ENC_NA);
                break;
            case SIGCOMP_NACK_CYCLES_EXHAUSTED:
                /* Cycles Per Bit (1 byte) */
                proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_cycles_per_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case SIGCOMP_NACK_BYTECODES_TOO_LARGE:
                /* Memory size (2 bytes) */
                proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_memory_size, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            default:
                break;
            }
        } else {
            octet = tvb_get_guint8(tvb, (offset + 1));
            destination = (octet & 0x0f);
            if ( destination != 0 )
                destination = 64 + ( destination * 64 );
            proto_tree_add_item(sigcomp_tree,hf_sigcomp_code_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(sigcomp_tree,hf_sigcomp_destination, tvb, (offset+ 1), 1, ENC_BIG_ENDIAN);
            offset = offset +2;

            bytecode_len = len;
            bytecode_offset = offset;
            udvm_bytecode_item = proto_tree_add_item(sigcomp_tree, hf_sigcomp_udvm_bytecode, tvb,
                                                     bytecode_offset, bytecode_len, ENC_NA);
            proto_item_append_text(udvm_bytecode_item,
                                   " %u (0x%x) bytes", bytecode_len, bytecode_len);
            sigcomp_udvm_tree = proto_item_add_subtree( udvm_bytecode_item, ett_sigcomp_udvm);

            udvm_tvb = tvb_new_subset_length(tvb, offset, len);
            if ( dissect_udvm_code )
                dissect_udvm_bytecode(udvm_tvb, pinfo, sigcomp_udvm_tree, destination);

            offset = offset + len;
            msg_len = tvb_reported_length_remaining(tvb, offset);
            if (msg_len>0) {
                proto_item *ti = proto_tree_add_item(sigcomp_tree, hf_sigcomp_remaining_sigcomp_message, tvb, offset, -1, ENC_NA);
                PROTO_ITEM_SET_GENERATED(ti);
            }
            if ( decompress ) {

                msg_tvb = tvb_new_subset_length(tvb, offset, msg_len);

                udvm_exe_item = proto_tree_add_item(sigcomp_tree, hf_udvm_execution_trace,
                                                    tvb, bytecode_offset, bytecode_len,
                                                    ENC_NA);
                sigcomp_udvm_exe_tree = proto_item_add_subtree( udvm_exe_item, ett_sigcomp_udvm_exe);
                decomp_tvb = decompress_sigcomp_message(udvm_tvb, msg_tvb, pinfo,
                           sigcomp_udvm_exe_tree, destination,
                           udvm_print_detail_level, hf_sigcomp_partial_state,
                           offset, 0, 0, destination);
                if ( decomp_tvb ) {
                    proto_item *ti;
                    guint32 compression_ratio =
                        (guint32)(((float)tvb_reported_length(decomp_tvb) / (float)tvb_reported_length(tvb)) * 100);

                    /* Show compression ratio achieved */
                    ti = proto_tree_add_uint(sigcomp_tree, hf_sigcomp_compression_ratio, decomp_tvb,
                                             0, 0, compression_ratio);
                    PROTO_ITEM_SET_GENERATED(ti);

                    if ( display_raw_txt )
                        tvb_raw_text_add(decomp_tvb, top_tree);

                    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
                    col_set_fence(pinfo->cinfo,COL_PROTOCOL);
                    call_dissector(sip_handle, decomp_tvb, pinfo, top_tree);
                }
            } /* if decompress */
        }/*if len==0 */

    }
    return tvb_captured_length(tvb);
}

static void
dissect_udvm_bytecode(tvbuff_t *udvm_tvb, packet_info* pinfo, proto_tree *sigcomp_udvm_tree,guint start_address)
{
    guint       instruction;
    gint        offset         = 0;
    gint        start_offset   = 0;
    gint        len;
    gint        n;
    guint       instruction_no = 0;
    guint16     value          = 0;
    proto_item *item, *item2;
    guint       UDVM_address   = start_address;
    gboolean    is_memory_address;
    guint16     msg_length     = tvb_reported_length_remaining(udvm_tvb, offset);


    while (msg_length > offset) {
        instruction = tvb_get_guint8(udvm_tvb, offset);
        instruction_no ++;
        UDVM_address = start_address + offset;

        item = proto_tree_add_uint_format(sigcomp_udvm_tree, hf_sigcomp_udvm_instruction, udvm_tvb, offset, 1,
                    instruction_no, "######### UDVM instruction %u at UDVM-address %u (0x%x) #########",
                    instruction_no,UDVM_address,UDVM_address);
        PROTO_ITEM_SET_GENERATED(item);
        proto_tree_add_item(sigcomp_udvm_tree, hf_sigcomp_udvm_instr, udvm_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        switch ( instruction ) {

        case SIGCOMP_INSTR_AND: /* 1 AND ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_OR: /* 2 OR ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_NOT: /* 3 NOT ($operand_1) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            break;

        case SIGCOMP_INSTR_LSHIFT: /* 4 LSHIFT ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_RSHIFT: /* 5 RSHIFT ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_ADD: /* 6 ADD ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_SUBTRACT: /* 7 SUBTRACT ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_MULTIPLY: /* 8 MULTIPLY ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_DIVIDE: /* 9 DIVIDE ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_REMAINDER: /* 10 REMAINDER ($operand_1, %operand_2) */
            /* $operand_1*/
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_1,
                udvm_tvb, start_offset, len, value);
            /* %operand_2*/
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2,
                    udvm_tvb, start_offset, len, value);
            }
            break;
        case SIGCOMP_INSTR_SORT_ASCENDING: /* 11 SORT-ASCENDING (%start, %n, %k) */
                        /* while programming stop while loop */
            offset = offset + tvb_reported_length_remaining(udvm_tvb, offset);
            break;

        case SIGCOMP_INSTR_SORT_DESCENDING: /* 12 SORT-DESCENDING (%start, %n, %k) */
            offset = offset + tvb_reported_length_remaining(udvm_tvb, offset);
            break;
        case SIGCOMP_INSTR_SHA_1: /* 13 SHA-1 (%position, %length, %destination) */
            /* %position */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_position,
                udvm_tvb, start_offset, len, value);

            /*  %length, */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* $destination */
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_ref_dest,
                udvm_tvb, start_offset, len, value);
            break;

        case SIGCOMP_INSTR_LOAD: /* 14 LOAD (%address, %value) */
            /* %address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_address,
                udvm_tvb, start_offset, len, value);
            /* %value */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_MULTILOAD: /* 15 MULTILOAD (%address, #n, %value_0, ..., %value_n-1) */
            /* %address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_address,
                udvm_tvb, start_offset, len, value);
            /* #n */
            offset = dissect_udvm_literal_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_literal_num,
                udvm_tvb, start_offset, len, value);
            n = value;
            while ( n > 0) {
                n = n -1;
                /* %value */
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                if ( is_memory_address ) {
                    proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                        udvm_tvb, start_offset, len, value);
                } else {
                    proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                        udvm_tvb, start_offset, len, value);
                }
            }
            break;

        case SIGCOMP_INSTR_PUSH: /* 16 PUSH (%value) */
            /* %value */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_POP: /* 17 POP (%address) */
            /* %address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);

            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_address,
                udvm_tvb, start_offset, len, value);
            break;

        case SIGCOMP_INSTR_COPY: /* 18 COPY (%position, %length, %destination) */
            /* %position */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_position,
                udvm_tvb, start_offset, len, value);

            /*  %length, */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* $destination */
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_ref_dest,
                udvm_tvb, start_offset, len, value);
            break;

        case SIGCOMP_INSTR_COPY_LITERAL: /* 19 COPY-LITERAL (%position, %length, $destination) */
            /* %position */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_position,
                udvm_tvb, start_offset, len, value);

            /*  %length, */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* $destination */
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_ref_dest,
                udvm_tvb, start_offset, len, value);
            break;

        case SIGCOMP_INSTR_COPY_OFFSET: /* 20 COPY-OFFSET (%offset, %length, $destination) */
            /* %offset */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_offset,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_offset,
                    udvm_tvb, start_offset, len, value);
            }

            /*  %length, */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* $destination */
            offset = dissect_udvm_reference_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_ref_dest,
                udvm_tvb, start_offset, len, value);
            break;
        case SIGCOMP_INSTR_MEMSET: /* 21 MEMSET (%address, %length, %start_value, %offset) */

            /* %address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_address,
                udvm_tvb, start_offset, len, value);

            /*  %length, */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* %start_value */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_start_value,
                udvm_tvb, start_offset, len, value);

            /* %offset */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_offset,
                udvm_tvb, start_offset, len, value);
            break;


        case SIGCOMP_INSTR_JUMP: /* 22 JUMP (@address) */
            /* @address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);
            break;

        case SIGCOMP_INSTR_COMPARE: /* 23 */
            /* COMPARE (%value_1, %value_2, @address_1, @address_2, @address_3)
             */
            /* %value_1 */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                    udvm_tvb, start_offset, len, value);
            }

            /* %value_2 */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                    udvm_tvb, start_offset, len, value);
            }

            /* @address_1 */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);

            /* @address_2 */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);

            /* @address_3 */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);
            break;

        case SIGCOMP_INSTR_CALL: /* 24 CALL (@address) (PUSH addr )*/
            /* @address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);
            break;
        case SIGCOMP_INSTR_RETURN: /* 25 POP and return */

        break;

        case SIGCOMP_INSTR_SWITCH: /* 26 SWITCH (#n, %j, @address_0, @address_1, ... , @address_n-1) */
            /* #n */
            offset = dissect_udvm_literal_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_literal_num,
                udvm_tvb, start_offset, len, value);

            /* Number of addresses in the instruction */
            n = value;
            /* %j */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_j,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_j,
                    udvm_tvb, start_offset, len, value);
            }

            while ( n > 0) {
                n = n -1;
                /* @address_n-1 */
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE,&start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
                value = ( value + UDVM_address ) & 0xffff;
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                    udvm_tvb, start_offset, len, value);
            }
            break;
        case SIGCOMP_INSTR_CRC: /* 27 CRC (%value, %position, %length, @address) */
            /* %value */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                    udvm_tvb, start_offset, len, value);
            }

            /* %position */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_position,
                udvm_tvb, start_offset, len, value);

            /* %length */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* @address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);
            break;


        case SIGCOMP_INSTR_INPUT_BYTES: /* 28 INPUT-BYTES (%length, %destination, @address) */
            /* %length */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* %destination */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_destination,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_destination,
                    udvm_tvb, start_offset, len, value);
            }

            /* @address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);
            break;
        case SIGCOMP_INSTR_INPUT_BITS:/* 29   INPUT-BITS (%length, %destination, @address) */
            /* %length */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* %destination */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_destination,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_destination,
                    udvm_tvb, start_offset, len, value);
            }

            /* @address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);
            break;
        case SIGCOMP_INSTR_INPUT_HUFFMAN: /* 30 */
            /*
             * INPUT-HUFFMAN (%destination, @address, #n, %bits_1, %lower_bound_1,
             *  %upper_bound_1, %uncompressed_1, ... , %bits_n, %lower_bound_n,
             *  %upper_bound_n, %uncompressed_n)
             */
            /* %destination */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_destination,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_destination,
                    udvm_tvb, start_offset, len, value);
            }
            /* @address */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
             /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
            value = ( value + UDVM_address ) & 0xffff;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_at_address,
                udvm_tvb, start_offset, len, value);
            /* #n */
            offset = dissect_udvm_literal_operand(udvm_tvb, sigcomp_udvm_tree, offset, &start_offset, &value);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_literal_num,
                udvm_tvb, start_offset, len, value);
            n = value;
            while ( n > 0) {
                n = n -1;
                /* %bits_n */
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_bits,
                    udvm_tvb, start_offset, len, value);
                /* %lower_bound_n*/
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_lower_bound,
                    udvm_tvb, start_offset, len, value);
                /* %upper_bound_n */
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_upper_bound,
                    udvm_tvb, start_offset, len, value);
                /* %uncompressed_n */
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_uncompressed,
                    udvm_tvb, start_offset, len, value);
            }
            break;

        case SIGCOMP_INSTR_STATE_ACCESS: /* 31 */
            /*   STATE-ACCESS (%partial_identifier_start, %partial_identifier_length,
             * %state_begin, %state_length, %state_address, %state_instruction)
             */

            /*
             * %partial_identifier_start
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value ,&is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_partial_identifier_start,
                udvm_tvb, start_offset, len, value);

            /*
             * %partial_identifier_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value ,&is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_partial_identifier_length,
                udvm_tvb, start_offset, len, value);
            /*
             * %state_begin
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_state_begin,
                udvm_tvb, start_offset, len, value);

            /*
             * %state_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_length_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_length,
                    udvm_tvb, start_offset, len, value);
            }
            /*
             * %state_address
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value ,&is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_address_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_address,
                    udvm_tvb, start_offset, len, value);
            }
            /*
             * %state_instruction
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_instr,
                udvm_tvb, start_offset, len, value);
            break;
        case SIGCOMP_INSTR_STATE_CREATE: /* 32 */
            /*
             * STATE-CREATE (%state_length, %state_address, %state_instruction,
             * %minimum_access_length, %state_retention_priority)
             */

            /*
             * %state_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_length_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_length,
                    udvm_tvb, start_offset, len, value);
            }
            /*
             * %state_address
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_address_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_address,
                    udvm_tvb, start_offset, len, value);
            }
            /*
             * %state_instruction
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_instr,
                udvm_tvb, start_offset, len, value);
            /*
             * %minimum_access_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_min_acc_len,
                udvm_tvb, start_offset, len, value);
            /*
             * %state_retention_priority
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_ret_pri,
                udvm_tvb, start_offset, len, value);

            break;
        case SIGCOMP_INSTR_STATE_FREE: /* 33 */
            /*
             * STATE-FREE (%partial_identifier_start, %partial_identifier_length)
             */
            /*
             * %partial_identifier_start
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_partial_identifier_start,
                udvm_tvb, start_offset, len, value);

            /*
             * %partial_identifier_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_partial_identifier_length,
                udvm_tvb, start_offset, len, value);
            break;
        case SIGCOMP_INSTR_OUTPUT: /* 34 OUTPUT (%output_start, %output_length) */
            /*
             * %output_start
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_output_start,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_output_start,
                    udvm_tvb, start_offset, len, value);
            }
            /*
             * %output_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_output_length_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_output_length,
                    udvm_tvb, start_offset, len, value);
            }
            break;
        case SIGCOMP_INSTR_END_MESSAGE: /* 35 */
            /*
             * END-MESSAGE (%requested_feedback_location,
             * %returned_parameters_location, %state_length, %state_address,
             * %state_instruction, %minimum_access_length,
             * %state_retention_priority)
             */
            /* %requested_feedback_location */
            if ((msg_length-1) < offset) {
                proto_tree_add_expert(sigcomp_udvm_tree, pinfo, &ei_sigcomp_all_remaining_parameters_zero, udvm_tvb, 0, -1);
                return;
            }
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_req_feedback_loc,
                udvm_tvb, start_offset, len, value);
            /* returned_parameters_location */
            if ((msg_length-1) < offset) {
                proto_tree_add_expert(sigcomp_udvm_tree, pinfo, &ei_sigcomp_all_remaining_parameters_zero, udvm_tvb, offset-1, -1);
                return;
            }
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_ret_param_loc,
                udvm_tvb, start_offset, len, value);
            /*
             * %state_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_length_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_length,
                    udvm_tvb, start_offset, len, value);
            }
            /*
             * %state_address
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ) {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_address_addr,
                    udvm_tvb, start_offset, len, value);
            } else {
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_address,
                    udvm_tvb, start_offset, len, value);
            }
            /*
             * %state_instruction
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_instr,
                udvm_tvb, start_offset, len, value);
            /*
             * %minimum_access_length
             */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_min_acc_len,
                udvm_tvb, start_offset, len, value);
            /*
             * %state_retention_priority
             */
            if ( tvb_reported_length_remaining(udvm_tvb, offset) != 0 ) {
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_ret_pri,
                    udvm_tvb, start_offset, len, value);
            } else {
                item2 = proto_tree_add_uint_format_value(sigcomp_udvm_tree, hf_udvm_state_ret_pri, udvm_tvb, offset, 1, 0,
                        "0 (Not in the uploaded code as UDVM buffer initialized to Zero");
                PROTO_ITEM_SET_GENERATED(item2);
            }
            if ( tvb_reported_length_remaining(udvm_tvb, offset) != 0 ) {
                len = tvb_reported_length_remaining(udvm_tvb, offset);
                UDVM_address = start_address + offset;
                proto_tree_add_bytes_format(sigcomp_udvm_tree, hf_sigcomp_remaining_bytes, udvm_tvb, offset, len, NULL,
                        "Remaining %u bytes starting at UDVM addr %u (0x%x)- State information ?",len, UDVM_address, UDVM_address);
            }
            offset = offset + tvb_reported_length_remaining(udvm_tvb, offset);
            break;

        default:
            offset = offset + tvb_reported_length_remaining(udvm_tvb, offset);
            break;
        }


    }
    return;
}
 /*  The simplest operand type is the literal (#), which encodes a
  * constant integer from 0 to 65535 inclusive.  A literal operand may
  * require between 1 and 3 bytes depending on its value.
  * Bytecode:                       Operand value:      Range:
  * 0nnnnnnn                        N                   0 - 127
  * 10nnnnnn nnnnnnnn               N                   0 - 16383
  * 11000000 nnnnnnnn nnnnnnnn      N                   0 - 65535
  *
  *            Figure 8: Bytecode for a literal (#) operand
  *
  */
static int
dissect_udvm_literal_operand(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree,
                               gint offset, gint *start_offset, guint16 *value)
{
    guint   bytecode;
    guint16 operand;
    guint   test_bits;
    guint   display_bytecode;

    bytecode = tvb_get_guint8(udvm_tvb, offset);
    test_bits = bytecode >> 7;
    if (test_bits == 1) {
        test_bits = bytecode >> 6;
        if (test_bits == 2) {
            /*
             * 10nnnnnn nnnnnnnn               N                   0 - 16383
             */
            display_bytecode = bytecode & 0xc0;
            if ( display_udvm_bytecode )
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_literal_bytecode,
                    udvm_tvb, offset, 1, display_bytecode);
            operand = tvb_get_ntohs(udvm_tvb, offset) & 0x3fff;
            *value = operand;
            *start_offset = offset;
            offset = offset + 2;

        } else {
            /*
             * 111000000 nnnnnnnn nnnnnnnn      N                   0 - 65535
             */
            display_bytecode = bytecode & 0xc0;
            if ( display_udvm_bytecode )
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_literal_bytecode,
                    udvm_tvb, offset, 1, display_bytecode);
            offset ++;
            operand = tvb_get_ntohs(udvm_tvb, offset);
            *value = operand;
            *start_offset = offset;
            offset = offset + 2;

        }
    } else {
        /*
         * 0nnnnnnn                        N                   0 - 127
         */
        display_bytecode = bytecode & 0xc0;
        if ( display_udvm_bytecode )
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_literal_bytecode,
                udvm_tvb, offset, 1, display_bytecode);
        operand = ( bytecode & 0x7f);
        *value = operand;
        *start_offset = offset;
        offset ++;
    }

    return offset;

}
/*
 * The second operand type is the reference ($), which is always used to
 * access a 2-byte value located elsewhere in the UDVM memory.  The
 * bytecode for a reference operand is decoded to be a constant integer
 * from 0 to 65535 inclusive, which is interpreted as the memory address
 * containing the actual value of the operand.
 * Bytecode:                       Operand value:      Range:
 *
 * 0nnnnnnn                        memory[2 * N]       0 - 65535
 * 10nnnnnn nnnnnnnn               memory[2 * N]       0 - 65535
 * 11000000 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
 *
 *            Figure 9: Bytecode for a reference ($) operand
 */
static int
dissect_udvm_reference_operand(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree,
                               gint offset, gint *start_offset, guint16 *value)
{
    guint   bytecode;
    guint16 operand;
    guint   test_bits;
    guint   display_bytecode;

    bytecode = tvb_get_guint8(udvm_tvb, offset);
    test_bits = bytecode >> 7;
    if (test_bits == 1) {
        test_bits = bytecode >> 6;
        if (test_bits == 2) {
            /*
             * 10nnnnnn nnnnnnnn               memory[2 * N]       0 - 65535
             */
            display_bytecode = bytecode & 0xc0;
            if ( display_udvm_bytecode )
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_reference_bytecode,
                    udvm_tvb, offset, 1, display_bytecode);
            operand = tvb_get_ntohs(udvm_tvb, offset) & 0x3fff;
            *value = (operand * 2);
            *start_offset = offset;
            offset = offset + 2;

        } else {
            /*
             * 11000000 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
             */
            display_bytecode = bytecode & 0xc0;
            if ( display_udvm_bytecode )
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_reference_bytecode,
                    udvm_tvb, offset, 1, display_bytecode);
            offset ++;
            operand = tvb_get_ntohs(udvm_tvb, offset);
            *value = operand;
            *start_offset = offset;
            offset = offset + 2;

        }
    } else {
        /*
         * 0nnnnnnn                        memory[2 * N]       0 - 65535
         */
        display_bytecode = bytecode & 0xc0;
        if ( display_udvm_bytecode )
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_reference_bytecode,
                udvm_tvb, offset, 1, display_bytecode);
        operand = ( bytecode & 0x7f);
        *value = (operand * 2);
        *start_offset = offset;
        offset ++;
    }

    return offset;
}

/*
 *The fourth operand type is the address (@).  This operand is decoded
 * as a multitype operand followed by a further step: the memory address
 * of the UDVM instruction containing the address operand is added to
 * obtain the correct operand value.  So if the operand value from
 * Figure 10 is D then the actual operand value of an address is
 * calculated as follows:
 *
 * operand_value = (is_memory_address_of_instruction + D) modulo 2^16
 * TODO calculate correct value for operand in case of ADDR
 */
static int
dissect_udvm_multitype_operand(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree,
                               gint offset, gboolean is_addr _U_, gint *start_offset, guint16 *value, gboolean *is_memory_address )
{
    guint bytecode;
    guint display_bytecode;
    guint16 operand;
    guint32 result;
    guint test_bits;
    /* RFC3320
     * Figure 10: Bytecode for a multitype (%) operand
     * Bytecode:                       Operand value:      Range:               HEX val
     * 00nnnnnn                        N                   0 - 63               0x00
     * 01nnnnnn                        memory[2 * N]       0 - 65535            0x40
     * 1000011n                        2 ^ (N + 6)        64 , 128              0x86
     * 10001nnn                        2 ^ (N + 8)    256 , ... , 32768         0x88
     * 111nnnnn                        N + 65504       65504 - 65535            0xe0
     * 1001nnnn nnnnnnnn               N + 61440       61440 - 65535            0x90
     * 101nnnnn nnnnnnnn               N                   0 - 8191             0xa0
     * 110nnnnn nnnnnnnn               memory[N]           0 - 65535            0xc0
     * 10000000 nnnnnnnn nnnnnnnn      N                   0 - 65535            0x80
     * 10000001 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535            0x81
     */
    *is_memory_address = FALSE;
    bytecode = tvb_get_guint8(udvm_tvb, offset);
    test_bits = ( bytecode & 0xc0 ) >> 6;
    switch (test_bits ) {
    case 0:
        /*
         * 00nnnnnn                        N                   0 - 63
         */
        display_bytecode = bytecode & 0xc0;
        if ( display_udvm_bytecode )
        proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
            udvm_tvb, offset, 1, display_bytecode);
        operand = ( bytecode & 0x3f);
        *value = operand;
        *start_offset = offset;
        offset ++;
        break;
    case 1:
        /*
         * 01nnnnnn                        memory[2 * N]       0 - 65535
         */
        display_bytecode = bytecode & 0xc0;
        if ( display_udvm_bytecode )
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                udvm_tvb, offset, 1, display_bytecode);
        operand = ( bytecode & 0x3f) * 2;
        *is_memory_address = TRUE;
        *value = operand;
        *start_offset = offset;
        offset ++;
        break;
    case 2:
        /* Check tree most significant bits */
        test_bits = ( bytecode & 0xe0 ) >> 5;
        if ( test_bits == 5 ) {
        /*
         * 101nnnnn nnnnnnnn               N                   0 - 8191
         */
            display_bytecode = bytecode & 0xe0;
            if ( display_udvm_bytecode )
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                    udvm_tvb, offset, 1, display_bytecode);
            operand = tvb_get_ntohs(udvm_tvb, offset) & 0x1fff;
            *value = operand;
            *start_offset = offset;
            offset = offset + 2;
        } else {
            test_bits = ( bytecode & 0xf0 ) >> 4;
            if ( test_bits == 9 ) {
        /*
         * 1001nnnn nnnnnnnn               N + 61440       61440 - 65535
         */
                display_bytecode = bytecode & 0xf0;
                if ( display_udvm_bytecode )
                    proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                            udvm_tvb, offset, 1, display_bytecode);
                operand = (tvb_get_ntohs(udvm_tvb, offset) & 0x0fff) + 61440;
                *start_offset = offset;
                *value = operand;
                offset = offset + 2;
            } else {
                test_bits = ( bytecode & 0x08 ) >> 3;
                if ( test_bits == 1) {
        /*
         * 10001nnn                        2 ^ (N + 8)    256 , ... , 32768
         */
                    display_bytecode = bytecode & 0xf8;
                    if ( display_udvm_bytecode )
                        proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                                udvm_tvb, offset, 1, display_bytecode);
                    result = (guint32)pow(2,( bytecode & 0x07) + 8);
                    operand = result & 0xffff;
                    *start_offset = offset;
                    *value = operand;
                    offset ++;
                } else {
                    test_bits = ( bytecode & 0x0e ) >> 1;
                    if ( test_bits == 3 ) {
                        /*
                         * 1000 011n                        2 ^ (N + 6)        64 , 128
                         */
                        display_bytecode = bytecode & 0xfe;
                        if ( display_udvm_bytecode )
                            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                                udvm_tvb, offset, 1, display_bytecode);
                        result = (guint32)pow(2,( bytecode & 0x01) + 6);
                        operand = result & 0xffff;
                        *start_offset = offset;
                        *value = operand;
                        offset ++;
                    } else {
                    /*
                     * 1000 0000 nnnnnnnn nnnnnnnn      N                   0 - 65535
                     * 1000 0001 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
                     */
                        display_bytecode = bytecode;
                        if ( display_udvm_bytecode )
                            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                                udvm_tvb, offset, 1, display_bytecode);
                        if ( (bytecode & 0x01) == 1 )
                            *is_memory_address = TRUE;
                        offset ++;
                        operand = tvb_get_ntohs(udvm_tvb, offset);
                        *value = operand;
                        *start_offset = offset;
                        offset = offset +2;
                    }


                }
            }
        }
        break;

    case 3:
        test_bits = ( bytecode & 0x20 ) >> 5;
        if ( test_bits == 1 ) {
        /*
         * 111nnnnn                        N + 65504       65504 - 65535
         */
            display_bytecode = bytecode & 0xe0;
            if ( display_udvm_bytecode )
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                        udvm_tvb, offset, 1, display_bytecode);
            operand = ( bytecode & 0x1f) + 65504;
            *start_offset = offset;
            *value = operand;
            offset ++;
        } else {
        /*
         * 110nnnnn nnnnnnnn               memory[N]           0 - 65535
         */
            display_bytecode = bytecode & 0xe0;
            if ( display_udvm_bytecode )
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_multitype_bytecode,
                        udvm_tvb, offset, 1, display_bytecode);
            operand = (tvb_get_ntohs(udvm_tvb, offset) & 0x1fff);
            *is_memory_address = TRUE;
            *start_offset = offset;
            *value = operand;
            offset = offset +2;
        }

    default :
        break;
    }
    return offset;
}

static void
tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree *raw_tree = NULL;
    proto_item *ti = NULL;
    int offset, next_offset, linelen;

    if (tree) {
        ti = proto_tree_add_item(tree, proto_raw_sigcomp, tvb, 0, -1, ENC_NA);
        raw_tree = proto_item_add_subtree(ti, ett_raw_text);
    }

    offset = 0;

    while (tvb_offset_exists(tvb, offset)) {
        tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        linelen = next_offset - offset;
        proto_tree_add_format_text(raw_tree, tvb, offset, linelen);
        offset = next_offset;
    }
}

/* Register the protocol with Wireshark */

void
proto_register_sigcomp(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_sigcomp_t_bit,
            { "T bit", "sigcomp.t.bit",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            "Sigcomp T bit", HFILL }
        },
        { &hf_sigcomp_len,
            { "Partial state id length","sigcomp.length",
            FT_UINT8, BASE_HEX, VALS(length_encoding_vals), 0x03,
            "Sigcomp length", HFILL }
        },
        { &hf_sigcomp_returned_feedback_item,
            { "Returned_feedback item", "sigcomp.returned.feedback.item",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Returned feedback item", HFILL }
        },
        { &hf_sigcomp_partial_state,
            { "Partial state identifier", "sigcomp.partial.state.identifier",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sigcomp_remaining_message_bytes,
            { "Remaining SigComp message bytes", "sigcomp.remaining-bytes",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of bytes remaining in message", HFILL }
        },
        { &hf_sigcomp_compression_ratio,
            { "Compression ratio (%)", "sigcomp.compression-ratio",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Compression ratio (decompressed / compressed) %", HFILL }
        },
        { &hf_sigcomp_returned_feedback_item_len,
            { "Returned feedback item length", "sigcomp.returned.feedback.item.len",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_sigcomp_code_len,
            { "Code length","sigcomp.code.len",
            FT_UINT16, BASE_HEX, NULL, 0xfff0,
            NULL, HFILL }
        },
        { &hf_sigcomp_destination,
            { "Destination","sigcomp.destination",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &destination_address_encoding_vals_ext, 0xf,
            NULL, HFILL }
        },
        { &hf_sigcomp_udvm_bytecode,
            { "Uploaded UDVM bytecode","sigcomp.udvm.byte-code",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sigcomp_udvm_instr,
            { "UDVM instruction code","sigcomp.udvm.instr",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &udvm_instruction_code_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_udvm_execution_trace,
            { "UDVM execution trace","sigcomp.udvm.execution-trace",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_udvm_multitype_bytecode,
            { "UDVM bytecode", "sigcomp.udvm.multyt.bytecode",
            FT_UINT8, BASE_HEX, VALS(display_bytecode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_udvm_reference_bytecode,
            { "UDVM bytecode", "sigcomp.udvm.ref.bytecode",
            FT_UINT8, BASE_HEX, VALS(display_ref_bytecode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_udvm_literal_bytecode,
            { "UDVM bytecode", "sigcomp.udvm.lit.bytecode",
            FT_UINT8, BASE_HEX, VALS(display_lit_bytecode_vals), 0x0,
            NULL, HFILL }
        },
#if 0
        { &hf_udvm_operand,
            { "UDVM operand", "sigcomp.udvm.operand",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#endif
        { &hf_udvm_length,
            { "%Length", "sigcomp.udvm.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length", HFILL }
        },
        { &hf_udvm_addr_length,
            { "%Length[memory address]", "sigcomp.udvm.addr.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length", HFILL }
        },
        { &hf_udvm_destination,
            { "%Destination", "sigcomp.udvm.destination",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Destination", HFILL }
        },
        { &hf_udvm_addr_destination,
            { "%Destination[memory address]", "sigcomp.udvm.addr.destination",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Destination", HFILL }
        },
        { &hf_udvm_at_address,
            { "@Address(mem_add_of_inst + D) mod 2^16)", "sigcomp.udvm.at.address",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Address", HFILL }
        },
        { &hf_udvm_address,
            { "%Address", "sigcomp.udvm.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Address", HFILL }
        },
        { &hf_udvm_literal_num,
            { "#n", "sigcomp.udvm.literal-num",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Literal number", HFILL }
        },
        { &hf_udvm_value,
            { "%Value", "sigcomp.udvm.value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Value", HFILL }
        },
        { &hf_udvm_addr_value,
            { "%Value[memory address]", "sigcomp.udvm.value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Value", HFILL }
        },
        { &hf_partial_identifier_start,
            { "%Partial identifier start", "sigcomp.udvm.partial.identifier.start",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Partial identifier start", HFILL }
        },
        { &hf_partial_identifier_length,
            { "%Partial identifier length", "sigcomp.udvm.partial.identifier.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Partial identifier length", HFILL }
        },
        { &hf_state_begin,
            { "%State begin", "sigcomp.udvm.state.begin",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "State begin", HFILL }
        },
        { &hf_udvm_state_length,
            { "%State length", "sigcomp.udvm.state.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "State length", HFILL }
        },

        { &hf_udvm_state_length_addr,
            { "%State length[memory address]", "sigcomp.udvm.state.length.addr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "State length", HFILL }
        },
        { &hf_udvm_state_address,
            { "%State address", "sigcomp.udvm.start.address",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "State address", HFILL }
        },
        { &hf_udvm_state_address_addr,
            { "%State address[memory address]", "sigcomp.udvm.start.address.addr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "State address", HFILL }
        },
        { &hf_udvm_state_instr,
            { "%State instruction", "sigcomp.udvm.start.instr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "State instruction", HFILL }
        },
        { &hf_udvm_operand_1,
            { "$Operand 1[memory address]", "sigcomp.udvm.operand.1",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Reference $ Operand 1", HFILL }
        },
        { &hf_udvm_operand_2,
            { "%Operand 2", "sigcomp.udvm.operand.2",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Operand 2", HFILL }
        },
        { &hf_udvm_operand_2_addr,
            { "%Operand 2[memory address]", "sigcomp.udvm.operand.2.addr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Operand 2", HFILL }
        },
        { &hf_udvm_j,
            { "%j", "sigcomp.udvm.j",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "j", HFILL }
        },
        { &hf_udvm_addr_j,
            { "%j[memory address]", "sigcomp.udvm.addr.j",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "j", HFILL }
        },
        { &hf_udvm_output_start,
            { "%Output_start", "sigcomp.output.start",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Output start", HFILL }
        },
        { &hf_udvm_addr_output_start,
            { "%Output_start[memory address]", "sigcomp.addr.output.start",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Output start", HFILL }
        },
        { &hf_udvm_output_length,
            { "%Output_length", "sigcomp.output.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Output length", HFILL }
        },
        { &hf_udvm_output_length_addr,
            { "%Output_length[memory address]", "sigcomp.output.length.addr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Output length", HFILL }
        },
        { &hf_udvm_req_feedback_loc,
            { "%Requested feedback location", "sigcomp.req.feedback.loc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Requested feedback location", HFILL }
        },
        { &hf_udvm_min_acc_len,
            { "%Minimum access length", "sigcomp.min.acc.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Minimum access length", HFILL }
        },
        { &hf_udvm_state_ret_pri,
            { "%State retention priority", "sigcomp.udvm.state.ret.pri",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "State retention priority", HFILL }
        },
        { &hf_udvm_ret_param_loc,
            { "%Returned parameters location", "sigcomp.ret.param.loc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Returned parameters location", HFILL }
        },
        { &hf_udvm_position,
            { "%Position", "sigcomp.udvm.position",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Position", HFILL }
        },
        { &hf_udvm_ref_dest,
            { "$Destination[memory address]", "sigcomp.udvm.ref.destination",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "(reference)Destination", HFILL }
        },
        { &hf_udvm_bits,
            { "%Bits", "sigcomp.udvm.bits",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Bits", HFILL }
        },
        { &hf_udvm_lower_bound,
            { "%Lower bound", "sigcomp.udvm.lower.bound",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Lower_bound", HFILL }
        },
        { &hf_udvm_upper_bound,
            { "%Upper bound", "sigcomp.udvm.upper.bound",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Upper bound", HFILL }
        },
        { &hf_udvm_uncompressed,
            { "%Uncompressed", "sigcomp.udvm.uncompressed",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Uncompressed", HFILL }
        },
        { &hf_udvm_start_value,
            { "%Start value", "sigcomp.udvm.start.value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Start value", HFILL }
        },
        { &hf_udvm_offset,
            { "%Offset", "sigcomp.udvm.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Offset", HFILL }
        },
        { &hf_udvm_addr_offset,
            { "%Offset[memory address]", "sigcomp.udvm.addr.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Offset", HFILL }
        },
        { &hf_sigcomp_nack_ver,
            { "NACK Version", "sigcomp.nack.ver",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_sigcomp_nack_reason_code,
            { "Reason Code", "sigcomp.nack.reason",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &sigcomp_nack_reason_code_vals_ext, 0x0,
            "NACK Reason Code", HFILL }
        },
        { &hf_sigcomp_nack_failed_op_code,
            { "OPCODE of failed instruction", "sigcomp.nack.failed_op_code",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &udvm_instruction_code_vals_ext, 0x0,
            "NACK OPCODE of failed instruction", HFILL }
        },
        { &hf_sigcomp_nack_pc,
            { "PC of failed instruction", "sigcomp.nack.pc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "NACK PC of failed instruction", HFILL }
        },
        { &hf_sigcomp_nack_sha1,
            { "SHA-1 Hash of failed message", "sigcomp.nack.sha1",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "NACK SHA-1 Hash of failed message", HFILL }
        },
        { &hf_sigcomp_nack_state_id,
            { "State ID (6 - 20 bytes)", "sigcomp.nack.state_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "NACK State ID (6 - 20 bytes)", HFILL }
        },
        { &hf_sigcomp_nack_cycles_per_bit,
            { "Cycles Per Bit", "sigcomp.nack.cycles_per_bit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "NACK Cycles Per Bit", HFILL }
        },
        { &hf_sigcomp_nack_memory_size,
            { "Memory size", "sigcomp.memory_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sigcomp_decompress_instruction,
            { "Instruction", "sigcomp.decompress_instruction",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sigcomp_loading_result,
            { "Loading result", "sigcomp.loading_result",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sigcomp_byte_copy,
            { "byte copy", "sigcomp.byte_copy",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_sigcomp_accessing_state, { "### Accessing state ###", "sigcomp.accessing_state", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_getting_value, { "Getting value", "sigcomp.getting_value", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_load_bytecode_into_udvm_start, { "Load bytecode into UDVM starting at", "sigcomp.load_bytecode_into_udvm_start", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_instruction_code, { "Instruction code", "sigcomp.instruction_code", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_current_instruction, { "Addr", "sigcomp.current_instruction", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &udvm_instruction_code_vals_ext, 0x0, NULL, HFILL }},
        { &hf_sigcomp_decompression_failure, { "DECOMPRESSION-FAILURE", "sigcomp.decompression_failure", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_wireshark_udvm_diagnostic, { "Wireshark UDVM diagnostic", "sigcomp.wireshark_udvm_diagnostic", FT_UINT32, BASE_DEC, VALS(result_code_vals), 0x0, NULL, HFILL }},
        { &hf_sigcomp_calculated_sha_1, { "Calculated SHA-1", "sigcomp.calculated_sha_1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_copying_value, { "Copying value", "sigcomp.copying_value", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_storing_value, { "Storing value", "sigcomp.storing_value", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_loading_value, { "Loading value", "sigcomp.loading_value", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_set_hu, { "Set Hu", "sigcomp.set_hu", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_loading_h, { "Loading H", "sigcomp.loading_h", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_state_value, { "Addr", "sigcomp.state_value", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_output_value, { "Output value", "sigcomp.output_value", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_num_state_create, { "no_of_state_create", "sigcomp.num_state_create", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_sha1_digest, { "SHA1 digest", "sigcomp.sha1_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_creating_state, { "### Creating state ###", "sigcomp.creating_state", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_sigcomp_message_decompressed, { "SigComp message Decompressed", "sigcomp.message_decompressed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_starting_to_remove_escape_digits, { "Starting to remove escape digits", "sigcomp.starting_to_remove_escape_digits", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_escape_digit_found, { "Escape digit found", "sigcomp.escape_digit_found", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_illegal_escape_code, { "Illegal escape code", "sigcomp.illegal_escape_code", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_end_of_sigcomp_message_indication_found, { "End of SigComp message indication found", "sigcomp.end_of_sigcomp_message_indication_found", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_addr_value, { "Addr", "sigcomp.addr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_copying_bytes_literally, { "Copying bytes literally", "sigcomp.copying_bytes_literally", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_data_for_sigcomp_dissector, { "Data handed to the Sigcomp dissector", "sigcomp.data_for_sigcomp_dissector", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_remaining_sigcomp_message, { "Remaining SigComp message", "sigcomp.remaining_sigcomp_message", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_sha1buff, { "sha1buff", "sigcomp.sha1buff", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_udvm_instruction, { "UDVM instruction", "sigcomp.udvm_instruction", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_remaining_bytes, { "Remaining bytes", "sigcomp.remaining_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_max_udvm_cycles, { "maximum_UDVM_cycles", "sigcomp.max_udvm_cycles", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_used_udvm_cycles, { "used_udvm_cycles", "sigcomp.used_udvm_cycles", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_udvm_execution_stated, { "UDVM EXECUTION STARTED", "sigcomp.udvm_execution_stated", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_message_length, { "Message Length", "sigcomp.message_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_sigcomp_byte_code_length, { "Byte code length", "sigcomp.byte_code_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_sigcomp,
        &ett_sigcomp_udvm,
        &ett_sigcomp_udvm_exe,
    };
    static gint *ett_raw[] = {
        &ett_raw_text,
    };

    static ei_register_info ei[] = {
        { &ei_sigcomp_nack_failed_op_code, { "sigcomp.nack.failed_op_code.expert", PI_SEQUENCE, PI_WARN, "SigComp NACK", EXPFILL }},
        { &ei_sigcomp_invalid_instruction, { "sigcomp.invalid_instruction", PI_PROTOCOL, PI_WARN, "Invalid instruction", EXPFILL }},
        /* Generated from convert_proto_tree_add_text.pl */
        { &ei_sigcomp_sigcomp_message_decompression_failure, { "sigcomp.message_decompression_failure", PI_PROTOCOL, PI_WARN, "SigComp message Decompression failure", EXPFILL }},
        { &ei_sigcomp_execution_of_this_instruction_is_not_implemented, { "sigcomp.execution_of_this_instruction_is_not_implemented", PI_UNDECODED, PI_WARN, "Execution of this instruction is NOT implemented", EXPFILL }},
        { &ei_sigcomp_decompression_failure, { "sigcomp.decompression_failure_expert", PI_PROTOCOL, PI_WARN, "DECOMPRESSION FAILURE", EXPFILL }},
        { &ei_sigcomp_tcp_fragment, { "sigcomp.tcp_fragment", PI_MALFORMED, PI_ERROR, "TCP Fragment", EXPFILL }},
        { &ei_sigcomp_failed_to_access_state_wireshark_udvm_diagnostic, { "sigcomp.failed_to_access_state_wireshark_udvm_diagnostic", PI_PROTOCOL, PI_WARN, "Failed to Access state Wireshark UDVM diagnostic", EXPFILL }},
        { &ei_sigcomp_all_remaining_parameters_zero, { "sigcomp.all_remaining_parameters", PI_PROTOCOL, PI_NOTE, "All remaining parameters = 0(Not in the uploaded code as UDVM buffer initialized to Zero", EXPFILL }},
    };

    module_t *sigcomp_module;
    expert_module_t* expert_sigcomp;

    static const enum_val_t udvm_detail_vals[] = {
        {"no-printout",   "No-Printout", 0},
        {"low-detail",    "Low-detail", 1},
        {"medium-detail", "Medium-detail", 2},
        {"high-detail",   "High-detail", 3},
        {NULL, NULL, -1}
    };


/* Register the protocol name and description */
    proto_sigcomp = proto_register_protocol("Signaling Compression",
                                            "SIGCOMP", "sigcomp");
    proto_raw_sigcomp = proto_register_protocol("Decompressed SigComp message as raw text",
                                                "Raw_SigComp", "raw_sigcomp");

    register_dissector("sigcomp", dissect_sigcomp, proto_sigcomp);

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_sigcomp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_subtree_array(ett_raw, array_length(ett_raw));
    expert_sigcomp = expert_register_protocol(proto_sigcomp);
    expert_register_field_array(expert_sigcomp, ei, array_length(ei));

/* Register a configuration option for port */
    sigcomp_module = prefs_register_protocol(proto_sigcomp,
                                              proto_reg_handoff_sigcomp);

    prefs_register_uint_preference(sigcomp_module, "udp.port",
                                   "Sigcomp UDP Port 1",
                                   "Set UDP port 1 for SigComp messages",
                                   10,
                                   &SigCompUDPPort1);

    prefs_register_uint_preference(sigcomp_module, "udp.port2",
                                   "Sigcomp UDP Port 2",
                                   "Set UDP port 2 for SigComp messages",
                                   10,
                                   &SigCompUDPPort2);
    prefs_register_uint_preference(sigcomp_module, "tcp.port",
                                   "Sigcomp TCP Port 1",
                                   "Set TCP port 1 for SigComp messages",
                                   10,
                                   &SigCompTCPPort1);

    prefs_register_uint_preference(sigcomp_module, "tcp.port2",
                                   "Sigcomp TCP Port 2",
                                   "Set TCP port 2 for SigComp messages",
                                   10,
                                   &SigCompTCPPort2);
    prefs_register_bool_preference(sigcomp_module, "display.udvm.code",
                                   "Dissect the UDVM code",
                                   "Preference whether to Dissect the UDVM code or not",
                                   &dissect_udvm_code);

    prefs_register_bool_preference(sigcomp_module, "display.bytecode",
                                   "Display the bytecode of operands",
                                   "preference whether to display the bytecode in "
                                     "UDVM operands or not",
                                   &display_udvm_bytecode);
    prefs_register_bool_preference(sigcomp_module, "decomp.msg",
                                   "Decompress message",
                                   "preference whether to decompress message or not",
                                   &decompress);
    prefs_register_bool_preference(sigcomp_module, "display.decomp.msg.as.txt",
                                   "Displays the decompressed message as text",
                                   "preference whether to display the decompressed message "
                                     "as raw text or not",
                                   &display_raw_txt);
    prefs_register_enum_preference(sigcomp_module, "show.udvm.execution",
                                   "Level of detail of UDVM execution:",
                                   "'No-Printout' = UDVM executes silently, then increasing detail "
                                     "about execution of UDVM instructions; "
                                     "Warning! CPU intense at high detail",
                                   &udvm_print_detail_level, udvm_detail_vals, FALSE);

    register_init_routine(&sigcomp_init_udvm);
    register_cleanup_routine(&sigcomp_cleanup_udvm);



}

void
proto_reg_handoff_sigcomp(void)
{
    static dissector_handle_t sigcomp_handle;
    static dissector_handle_t sigcomp_tcp_handle;
    static gboolean Initialized = FALSE;
    static guint udp_port1;
    static guint udp_port2;
    static guint tcp_port1;
    static guint tcp_port2;

    if (!Initialized) {
        sigcomp_handle = find_dissector("sigcomp");
        sigcomp_tcp_handle = create_dissector_handle(dissect_sigcomp_tcp,proto_sigcomp);
        sip_handle = find_dissector_add_dependency("sip",proto_sigcomp);
        Initialized=TRUE;
    } else {
        dissector_delete_uint("udp.port", udp_port1, sigcomp_handle);
        dissector_delete_uint("udp.port", udp_port2, sigcomp_handle);
        dissector_delete_uint("tcp.port", tcp_port1, sigcomp_tcp_handle);
        dissector_delete_uint("tcp.port", tcp_port2, sigcomp_tcp_handle);
    }

    udp_port1 = SigCompUDPPort1;
    udp_port2 = SigCompUDPPort2;
    tcp_port1 = SigCompTCPPort1;
    tcp_port2 = SigCompTCPPort2;


    dissector_add_uint("udp.port", SigCompUDPPort1, sigcomp_handle);
    dissector_add_uint("udp.port", SigCompUDPPort2, sigcomp_handle);
    dissector_add_uint("tcp.port", SigCompTCPPort1, sigcomp_tcp_handle);
    dissector_add_uint("tcp.port", SigCompTCPPort2, sigcomp_tcp_handle);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
