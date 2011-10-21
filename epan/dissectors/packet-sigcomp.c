/* packet-sigcomp.c
 * Routines for Signaling Compression (SigComp) dissection.
 * Copyright 2004-2005, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * References:
 * http://www.ietf.org/rfc/rfc3320.txt?number=3320
 * http://www.ietf.org/rfc/rfc3321.txt?number=3321
 * http://www.ietf.org/rfc/rfc4077.txt?number=4077
 * Useful links :
 * http://www.ietf.org/internet-drafts/draft-ietf-rohc-sigcomp-impl-guide-03.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-rohc-sigcomp-sip-01.txt
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <math.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include <epan/sigcomp-udvm.h>
#include <epan/sigcomp_state_hdlr.h>

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
static int hf_udvm_operand                          = -1;
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

/* Initialize the subtree pointers */
static gint ett_sigcomp             = -1;
static gint ett_sigcomp_udvm        = -1;
static gint ett_sigcomp_udvm_exe    = -1;
static gint ett_raw_text            = -1;

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

static const value_string udvm_instruction_code_vals[] = {
    { 0,    "DECOMPRESSION-FAILURE" },
    { 1,    "AND" },
    { 2,    "OR" },
    { 3,    "NOT" },
    { 4,    "LSHIFT" },
    { 5,    "RSHIFT" },
    { 6,    "ADD" },
    { 7,    "SUBTRACT" },
    { 8,    "MULTIPLY" },
    { 9,    "DIVIDE" },
    { 10,   "REMAINDER" },
    { 11,   "SORT-ASCENDING" },
    { 12,   "SORT-DESCENDING" },
    { 13,   "SHA-1" },
    { 14,   "LOAD" },
    { 15,   "MULTILOAD" },
    { 16,   "PUSH" },
    { 17,   "POP" },
    { 18,   "COPY" },
    { 19,   "COPY-LITERAL" },
    { 20,   "COPY-OFFSET" },
    { 21,   "MEMSET" },
    { 22,   "JUMP" },
    { 23,   "COMPARE" },
    { 24,   "CALL" },
    { 25,   "RETURN" },
    { 26,   "SWITCH" },
    { 27,   "CRC" },
    { 28,   "INPUT-BYTES" },
    { 29,   "INPUT-BITS" },
    { 30,   "INPUT-HUFFMAN" },
    { 31,   "STATE-ACCESS" },
    { 32,   "STATE-CREATE" },
    { 33,   "STATE-FREE" },
    { 34,   "OUTPUT" },
    { 35,   "END-MESSAGE" },
    { 0,    NULL }
};
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


static void dissect_udvm_bytecode(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree, guint destination);

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

/* Initialize the state handler
 *
 */
static void
sigcomp_init_protocol(void)
{
    sigcomp_init_udvm();
}
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
dissect_sigcomp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *sigcomp_tree;
    tvbuff_t    *unescaped_tvb;

    guint8      *buff;
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
    if(data == 0xffff){
        /* delimiter */
        offset = offset + 2;
        octet = tvb_get_guint8(tvb,offset);
    }else{
        octet = tvb_get_guint8(tvb,offset);
    }
    if ((octet  & 0xf8) != 0xf8)
     return offset;

    /* Search for delimiter 0xffff in the remain tvb buffer */
    length = tvb_ensure_length_remaining(tvb, offset);
    for(i=0; i<(length-1); ++i){
        /* Loop end criteria is (length-1) because we take 2 bytes each loop */
        data = tvb_get_ntohs(tvb, offset+i);
        if (0xffff == data) break;
    }
    if (i >= (length-1)){
        /* SIGCOMP may be subdissector of SIP, so we use
         * pinfo->saved_can_desegment to determine whether do desegment
         * as well as pinfo->can_desegment */
        if (pinfo->can_desegment || pinfo->saved_can_desegment){
            /* Delimiter oxffff was not found, not a complete SIGCOMP PDU */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len=DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIGCOMP");

    col_clear(pinfo->cinfo, COL_INFO);

    length = tvb_length_remaining(tvb,offset);

try_again:
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_sigcomp, tvb, 0, -1, ENC_NA);
    sigcomp_tree = proto_item_add_subtree(ti, ett_sigcomp);
    i=0;
    end_off_message = FALSE;
    buff = g_malloc(length-offset);
    if (udvm_print_detail_level>2)
        proto_tree_add_text(sigcomp_tree, tvb, offset, -1,"Starting to remove escape digits");
    while ((offset < length) && (end_off_message == FALSE)){
        octet = tvb_get_guint8(tvb,offset);
        if ( octet == 0xff ){
            if ( offset +1 >= length ){
                /* if the tvb is short dont check for the second escape digit */
                offset++;
                continue;
            }
            if (udvm_print_detail_level>2)
                proto_tree_add_text(sigcomp_tree, tvb, offset, 2,
                    "              Escape digit found (0xFF)");
            octet = tvb_get_guint8(tvb, offset+1);
            if ( octet == 0){
                buff[i] = 0xff;
                offset = offset +2;
                i++;
                continue;
            }
            if ((octet > 0x7f) && (octet < 0xff )){
                if (udvm_print_detail_level>2)
                    proto_tree_add_text(sigcomp_tree, tvb, offset, 2,
                        "              Illegal escape code");
                offset = offset + tvb_length_remaining(tvb,offset);
                return offset;
            }
            if ( octet == 0xff){
                if (udvm_print_detail_level>2)
                    proto_tree_add_text(sigcomp_tree, tvb, offset, 2,
                        "              End of SigComp message indication found (0xFFFF)");
                end_off_message = TRUE;
                offset = offset+2;
                continue;
            }
            buff[i] = 0xff;
            if (udvm_print_detail_level>2)
                proto_tree_add_text(sigcomp_tree, tvb, offset, 1,
                            "              Addr: %u tvb value(0x%0x) ", i, buff[i]);
            i++;
            offset = offset+2;
            if (udvm_print_detail_level>2)
            proto_tree_add_text(sigcomp_tree, tvb, offset, octet,
                        "              Copying %u bytes literally",octet);
            if( offset+octet >= length)
                /* if the tvb is short dont copy further than the end */
                octet = length - offset;
            for ( n=0; n < octet; n++ ){
                buff[i] = tvb_get_guint8(tvb, offset);
                if (udvm_print_detail_level>2)
                    proto_tree_add_text(sigcomp_tree, tvb, offset, 1,
                                "                  Addr: %u tvb value(0x%0x) ", i, buff[i]);
                i++;
                offset++;
            }
            continue;
        }
        buff[i] = octet;
        if (udvm_print_detail_level>2)
            proto_tree_add_text(sigcomp_tree, tvb, offset, 1,
                        "              Addr: %u tvb value(0x%0x) ", i, buff[i]);

        i++;
        offset++;
    }
    unescaped_tvb = tvb_new_child_real_data(tvb, buff,i,i);
    /* Arrange that the allocated packet data copy be freed when the
     * tvbuff is freed.
     */
    tvb_set_free_cb( unescaped_tvb, g_free );

    add_new_data_source(pinfo, unescaped_tvb, "Unescaped Data handed to the SigComp dissector");

    proto_tree_add_text(sigcomp_tree, unescaped_tvb, 0, -1,"Data handed to the Sigcomp dissector");
    if (end_off_message == TRUE){
        dissect_sigcomp_common(unescaped_tvb, pinfo, sigcomp_tree);
    }else{
        proto_tree_add_text(sigcomp_tree, unescaped_tvb, 0, -1,"TCP Fragment, no end mark found");
    }
    if ( offset < length){
        goto try_again;
    }

    return offset;
}
/* Code to actually dissect the packets */
static int
dissect_sigcomp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *sigcomp_tree;
    gint        offset = 0;
    gint8       octet;

    /* If we got called from SIP this might be over TCP */
    if ( pinfo->ptype == PT_TCP )
        return dissect_sigcomp_tcp(tvb, pinfo, tree);

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
    tvbuff_t    *udvm_tvb, *msg_tvb, *udvm2_tvb;
    tvbuff_t    *decomp_tvb = NULL;
    proto_item  *udvm_bytecode_item, *udvm_exe_item;
    proto_tree  *sigcomp_udvm_tree, *sigcomp_udvm_exe_tree;
    gint        offset = 0;
    gint        bytecode_offset;
    guint16     partial_state_len;
    guint       octet;
    guint8      returned_feedback_field[128];
    guint8      partial_state[12];
    guint       tbit;
    guint16     len = 0;
    guint16     bytecode_len = 0;
    guint       destination;
    gint        msg_len = 0;
    guint8      *buff;
    guint16     p_id_start;
    guint8      i;
    guint16     state_begin;
    guint16     state_length;
    guint16     state_address;
    guint16     state_instruction;
    guint16     result_code;
    gchar       *partial_state_str;
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
    if ( partial_state_len != 0 ){
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

            if ( (octet & 0x80) != 0 ){
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
        partial_state_str = bytes_to_str(partial_state, partial_state_len);
        proto_tree_add_string(sigcomp_tree,hf_sigcomp_partial_state,
            tvb, offset, partial_state_len, partial_state_str);
        offset = offset + partial_state_len;
        msg_len = tvb_reported_length_remaining(tvb, offset);

        if(msg_len>0){
            proto_item *ti;
            ti = proto_tree_add_uint(sigcomp_tree, hf_sigcomp_remaining_message_bytes, tvb,
                                     offset, 0, msg_len);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        if ( decompress ) {
            msg_tvb = tvb_new_subset(tvb, offset, msg_len, msg_len);
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
             * Note: The allocate buffer must be zeroed or some strange effects might occur.
             */
            buff = g_malloc0(UDVM_MEMORY_SIZE);


            p_id_start = 0;
            state_begin = 0;
            /* These values will be loaded from the buffered state in sigcomp_state_hdlr
             */
            state_length = 0;
            state_address = 0;
            state_instruction =0;

            i = 0;
            while ( i < partial_state_len ){
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
            if ( result_code != 0 ){
                proto_item *ti;
                ti = proto_tree_add_text(sigcomp_tree, tvb, 0, -1,"Failed to Access state Wireshark UDVM diagnostic: %s.",
                                         val_to_str(result_code, result_code_vals,"Unknown (%u)"));
                PROTO_ITEM_SET_GENERATED(ti);
                g_free(buff);
                return tvb_length(tvb);
            }

            udvm_tvb = tvb_new_child_real_data(tvb, buff,state_length+state_address,state_length+state_address);
            /* Arrange that the allocated packet data copy be freed when the
             * tvbuff is freed.
             */
            tvb_set_free_cb( udvm_tvb, g_free );


            udvm2_tvb = tvb_new_subset(udvm_tvb, state_address, state_length, state_length);
            /* TODO Check if buff needs to be free'd */
            udvm_exe_item = proto_tree_add_item(sigcomp_tree, hf_udvm_execution_trace,
                                                udvm2_tvb, 0, state_length,
                                                ENC_NA);
            sigcomp_udvm_exe_tree = proto_item_add_subtree( udvm_exe_item, ett_sigcomp_udvm_exe);

            decomp_tvb = decompress_sigcomp_message(udvm2_tvb, msg_tvb, pinfo,
                           sigcomp_udvm_exe_tree, state_address,
                           udvm_print_detail_level, hf_sigcomp_partial_state,
                           offset, state_length, partial_state_len, state_instruction);


            if ( decomp_tvb ){
                proto_item *ti;
                guint32 compression_ratio =
                    (guint32)(((float)tvb_length(decomp_tvb) / (float)tvb_length(tvb)) * 100);

                /* Celebrate success and show compression ratio achieved */
                proto_tree_add_text(sigcomp_tree, decomp_tvb, 0, -1,"SigComp message Decompressed WOHO!!");
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
            if ( (octet & 0x80) != 0 ){
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
        if ((len == 0) && (nack_version == 1)){
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
            expert_add_info_format(pinfo, reason_ti, PI_SEQUENCE, PI_WARN,
                                   "SigComp NACK (reason=%s, opcode=%s)",
                                   val_to_str(octet, sigcomp_nack_reason_code_vals, "Unknown"),
                                   val_to_str(opcode, udvm_instruction_code_vals, "Unknown"));

            proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_pc, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset = offset +2;
            proto_tree_add_item(sigcomp_tree,hf_sigcomp_nack_sha1, tvb, offset, 20, ENC_NA);
            offset = offset +20;

            /* Add NACK info to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, "  NACK reason=%s, opcode=%s",
                            val_to_str(octet, sigcomp_nack_reason_code_vals, "Unknown"),
                            val_to_str(opcode, udvm_instruction_code_vals, "Unknown"));

            switch ( octet){
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
        }else{
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

            udvm_tvb = tvb_new_subset(tvb, offset, len, len);
            if ( dissect_udvm_code )
                dissect_udvm_bytecode(udvm_tvb, sigcomp_udvm_tree, destination);

            offset = offset + len;
            msg_len = tvb_reported_length_remaining(tvb, offset);
            if (msg_len>0) {
                proto_item *ti = proto_tree_add_text(sigcomp_tree, tvb, offset, -1,
                                                     "Remaining SigComp message %u bytes",
                                                     tvb_reported_length_remaining(tvb, offset));
                PROTO_ITEM_SET_GENERATED(ti);
            }
            if ( decompress ){

                msg_tvb = tvb_new_subset(tvb, offset, msg_len, msg_len);

                udvm_exe_item = proto_tree_add_item(sigcomp_tree, hf_udvm_execution_trace,
                                                    tvb, bytecode_offset, bytecode_len,
                                                    ENC_NA);
                sigcomp_udvm_exe_tree = proto_item_add_subtree( udvm_exe_item, ett_sigcomp_udvm_exe);
                decomp_tvb = decompress_sigcomp_message(udvm_tvb, msg_tvb, pinfo,
                           sigcomp_udvm_exe_tree, destination,
                           udvm_print_detail_level, hf_sigcomp_partial_state,
                           offset, 0, 0, destination);
                if ( decomp_tvb ){
                    proto_item *ti;
                    guint32 compression_ratio =
                        (guint32)(((float)tvb_length(decomp_tvb) / (float)tvb_length(tvb)) * 100);

                    /* Celebrate success and show compression ratio achieved */
                    proto_tree_add_text(sigcomp_tree, decomp_tvb, 0, -1,"SigComp message Decompressed WOHO!!");
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
    return tvb_length(tvb);
}


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


static void
dissect_udvm_bytecode(tvbuff_t *udvm_tvb, proto_tree *sigcomp_udvm_tree,guint start_address)
{
    guint instruction;
    gint offset = 0;
    gint start_offset;
    gint len;
    gint n;
    guint instruction_no = 0;
    guint16 value = 0;
    proto_item *item, *item2;
    guint UDVM_address = start_address;
    gboolean is_memory_address;
    guint16 msg_length = tvb_reported_length_remaining(udvm_tvb, offset);


    while (msg_length > offset) {
        instruction = tvb_get_guint8(udvm_tvb, offset);
        instruction_no ++;
        UDVM_address = start_address + offset;
;

        item = proto_tree_add_text(sigcomp_udvm_tree, udvm_tvb, offset, 1,
                    "######### UDVM instruction %u at UDVM-address %u (0x%x) #########",
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_operand_2_addr,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            }else{
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
                if ( is_memory_address ){
                    proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                        udvm_tvb, start_offset, len, value);
                }else{
                    proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                        udvm_tvb, start_offset, len, value);
                }
            }
            break;

        case SIGCOMP_INSTR_PUSH: /* 16 PUSH (%value) */
            /* %value */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_offset,
                    udvm_tvb, start_offset, len, value);
            }else{
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_offset,
                    udvm_tvb, start_offset, len, value);
            }

            /*  %length, */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            }else{
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_value,
                    udvm_tvb, start_offset, len, value);
            }

            /* %value_2 */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_j,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_value,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* %destination */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_destination,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_length,
                    udvm_tvb, start_offset, len, value);
            }else{
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_length,
                    udvm_tvb, start_offset, len, value);
            }

            /* %destination */
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, FALSE,&start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_destination,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            if ( is_memory_address ){
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_addr_destination,
                    udvm_tvb, start_offset, len, value);
            }else{
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
            }else{
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
            }else{
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
            }else{
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
            }else{
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
            }else{
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
            }else{
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
            if ((msg_length-1) < offset){
                item2 = proto_tree_add_text(sigcomp_udvm_tree, udvm_tvb, 0, -1,
                        "All remaining parameters = 0(Not in the uploaded code as UDVM buffer initialized to Zero");
                PROTO_ITEM_SET_GENERATED(item2);
                return;
            }
            offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
            len = offset - start_offset;
            proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_req_feedback_loc,
                udvm_tvb, start_offset, len, value);
            /* returned_parameters_location */
            if ((msg_length-1) < offset){
                item2 = proto_tree_add_text(sigcomp_udvm_tree, udvm_tvb, offset-1, -1,
                        "All remaining parameters = 0(Not in the uploaded code as UDVM buffer initialized to Zero");
                PROTO_ITEM_SET_GENERATED(item2);
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
            }else{
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
            }else{
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
            if ( tvb_reported_length_remaining(udvm_tvb, offset) != 0 ){
                offset = dissect_udvm_multitype_operand(udvm_tvb, sigcomp_udvm_tree, offset, TRUE, &start_offset, &value, &is_memory_address);
                len = offset - start_offset;
                proto_tree_add_uint(sigcomp_udvm_tree, hf_udvm_state_ret_pri,
                    udvm_tvb, start_offset, len, value);
            }else{
                item2 = proto_tree_add_text(sigcomp_udvm_tree, udvm_tvb, offset, 1,
                        "state_retention_priority = 0(Not in the uploaded code as UDVM buffer initialized to Zero");
                PROTO_ITEM_SET_GENERATED(item2);
            }
            if ( tvb_reported_length_remaining(udvm_tvb, offset) != 0 ){
                len = tvb_reported_length_remaining(udvm_tvb, offset);
                UDVM_address = start_address + offset;
                proto_tree_add_text(sigcomp_udvm_tree, udvm_tvb, offset, len,
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
    guint bytecode;
    guint16 operand;
    guint test_bits;
    guint display_bytecode;

    bytecode = tvb_get_guint8(udvm_tvb, offset);
    test_bits = bytecode >> 7;
    if (test_bits == 1){
        test_bits = bytecode >> 6;
        if (test_bits == 2){
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

        }else{
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
    }else{
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
    guint bytecode;
    guint16 operand;
    guint test_bits;
    guint display_bytecode;

    bytecode = tvb_get_guint8(udvm_tvb, offset);
    test_bits = bytecode >> 7;
    if (test_bits == 1){
        test_bits = bytecode >> 6;
        if (test_bits == 2){
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

        }else{
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
    }else{
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
    switch (test_bits ){
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
        if ( test_bits == 5 ){
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
        }else{
            test_bits = ( bytecode & 0xf0 ) >> 4;
            if ( test_bits == 9 ){
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
            }else{
                test_bits = ( bytecode & 0x08 ) >> 3;
                if ( test_bits == 1){
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
                }else{
                    test_bits = ( bytecode & 0x0e ) >> 1;
                    if ( test_bits == 3 ){
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
                    }else{
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
        if ( test_bits == 1 ){
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
        }else{
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

    if(tree) {
        ti = proto_tree_add_item(tree, proto_raw_sigcomp, tvb, 0, -1, ENC_NA);
        raw_tree = proto_item_add_subtree(ti, ett_raw_text);
    }

    offset = 0;

    while (tvb_offset_exists(tvb, offset)) {
        tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        linelen = next_offset - offset;
        if(raw_tree) {
            proto_tree_add_text(raw_tree, tvb, offset, linelen,
                "%s", tvb_format_text(tvb, offset, linelen));
        }
        offset = next_offset;
    }
}

/* Register the protocol with Wireshark */


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_sigcomp(void)
{
    static dissector_handle_t sigcomp_handle;
    static dissector_handle_t sigcomp_tcp_handle;
    static gboolean Initialized=FALSE;
    static guint udp_port1;
    static guint udp_port2;
    static guint tcp_port1;
    static guint tcp_port2;

    if (!Initialized) {
        sigcomp_handle = find_dissector("sigcomp");
        sigcomp_tcp_handle = new_create_dissector_handle(dissect_sigcomp_tcp,proto_sigcomp);
        sip_handle = find_dissector("sip");
        Initialized=TRUE;
    }else{
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

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

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
            FT_UINT8, BASE_HEX, VALS(destination_address_encoding_vals), 0xf,
            NULL, HFILL }
        },
        { &hf_sigcomp_udvm_bytecode,
            { "Uploaded UDVM bytecode","sigcomp.udvm.byte-code",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sigcomp_udvm_instr,
            { "UDVM instruction code","sigcomp.udvm.instr",
            FT_UINT8, BASE_DEC, VALS(udvm_instruction_code_vals), 0x0,
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
        { &hf_udvm_operand,
            { "UDVM operand", "sigcomp.udvm.operand",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
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
            FT_UINT8, BASE_DEC, VALS(sigcomp_nack_reason_code_vals), 0x0,
            "NACK Reason Code", HFILL }
        },
        { &hf_sigcomp_nack_failed_op_code,
            { "OPCODE of failed instruction", "sigcomp.nack.failed_op_code",
            FT_UINT8, BASE_DEC, VALS(udvm_instruction_code_vals), 0x0,
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

    module_t *sigcomp_module;
    static enum_val_t udvm_detail_vals[] = {
    {"no-printout", "No-Printout", 0},
    {"low-detail", "Low-detail", 1},
    {"medium-detail", "Medium-detail", 2},
    {"high-detail", "High-detail", 3},
    {NULL, NULL, -1}
    };


/* Register the protocol name and description */
    proto_sigcomp = proto_register_protocol("Signaling Compression",
        "SIGCOMP", "sigcomp");
    proto_raw_sigcomp = proto_register_protocol("Decompressed SigComp message as raw text",
        "Raw_SigComp", "raw_sigcomp");

    new_register_dissector("sigcomp", dissect_sigcomp, proto_sigcomp);

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_sigcomp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_subtree_array(ett_raw, array_length(ett_raw));

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

    register_init_routine(&sigcomp_init_protocol);



}
