/* sigcomp-udvm.c
 * Routines making up the Universal Decompressor Virtual Machine (UDVM) used for
 * Signaling Compression (SigComp) dissection.
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Useful links :
 * http://www.ietf.org/internet-drafts/draft-ietf-rohc-sigcomp-impl-guide-05.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-rohc-sigcomp-sip-01.txt
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "packet.h"
#include "strutil.h"
#include "sigcomp-udvm.h"
#include "sigcomp_state_hdlr.h"
#include "sha1.h"
#include "crc16.h"

#define	SIGCOMP_INSTR_DECOMPRESSION_FAILURE     0
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


static gboolean print_level_1;
static gboolean print_level_2;
static gboolean print_level_3;
static gint show_instr_detail_level;

/* Internal result code values of decompression failures */
const value_string result_code_vals[] = {
	{ 0,	"No decomprssion failure" },
	{ 1,	"Partial state length less than 6 or greater than 20 bytes long" },
	{ 2,	"No state match" },
	{ 3,	"state_begin + state_length > size of state" },
	{ 4,	"Operand_2 is Zero" },
	{ 5,	"Switch statement failed j >= n" },
	{ 6,	"Atempt to jump outside of UDVM memory" },
	{ 7,	"L in input-bits > 16" },
	{ 8,	"input_bit_order > 7" },
	{ 9,	"Instruction Decompression failure encountered" },
	{10,	"Input huffman failed j > n" },
	{11,	"Input bits requested beyond end of message" },
	{12,	"more than four state creation requests are made before the END-MESSAGE instruction" },
	{13,	"state_retention_priority is 65535" },
	{14,	"Input bytes requested beond end of message" },
	{15,	"Maximum number of UDVM cycles reached" },
	{16,	"UDVM stack underflow" },
	{ 255,	"This branch isn't coded yet" },
	{ 0,    NULL }
};

static int decode_udvm_literal_operand(guint8 *buff,guint operand_address, guint16 *value);
static int dissect_udvm_reference_operand(guint8 *buff,guint operand_address, guint16 *value, guint *result_dest);
static int decode_udvm_multitype_operand(guint8 *buff,guint operand_address,guint16 *value);
static int decode_udvm_address_operand(guint8 *buff,guint operand_address, guint16 *value,guint current_address);
static int decomp_dispatch_get_bits(tvbuff_t *message_tvb,proto_tree *udvm_tree,guint8 bit_order, 
			guint8 *buff,guint16 *old_input_bit_order, guint16 *remaining_bits,
			guint16	*input_bits, guint *input_address, guint16 length, guint16 *result_code,guint msg_end);


tvbuff_t*
decompress_sigcomp_message(tvbuff_t *bytecode_tvb, tvbuff_t *message_tvb, packet_info *pinfo,
						   proto_tree *udvm_tree, gint udvm_mem_dest, 
						   gint print_flags, gint hf_id,
						   gint header_len,
						   gint byte_code_state_len, gint byte_code_id_len,
						   gint udvm_start_ip)
{
	tvbuff_t	*decomp_tvb;
	guint8		buff[UDVM_MEMORY_SIZE];
	char		string[2],*strp;
	guint8		*out_buff;		/* Largest allowed size for a message is 65535  */
	guint32		i = 0;
	guint16		n = 0;
	guint16		m = 0;
	guint16		x;
	guint		k = 0;
	guint16		H;
	guint16		oldH;
	guint		offset = 0;
	guint		result_dest;
	guint		code_length =0;
	guint8		current_instruction;
	guint		current_address;
	guint		operand_address;
	guint		input_address;
	guint16		output_address = 0;
	guint		next_operand_address;
	guint8		octet;
	guint8		msb;
	guint8		lsb;
	guint16		byte_copy_right;
	guint16		byte_copy_left;
	guint16		input_bit_order;
	guint16		stack_location;
	guint16		stack_fill;
	guint16		result;
	guint 		msg_end = tvb_reported_length_remaining(message_tvb, 0);
	guint16		result_code = 0;
	guint16		old_input_bit_order = 0;
	guint16		remaining_bits = 0;
	guint16		input_bits = 0;
	guint8		bit_order = 0;
	gboolean	outside_huffman_boundaries = TRUE;
	gboolean	print_in_loop = FALSE;
	guint16		instruction_address;
	guint8		no_of_state_create = 0;
	guint16		state_length_buff[5];
	guint16		state_address_buff[5];
	guint16		state_instruction_buff[5];
	guint16		state_minimum_access_length_buff[5];
	guint16		state_state_retention_priority_buff[5];
	guint32		used_udvm_cycles = 0;
	guint		cycles_per_bit;
	guint		maximum_UDVM_cycles;
	guint8		*sha1buff;
	unsigned char sha1_digest_buf[STATE_BUFFER_SIZE];
	sha1_context ctx;


	/* UDVM operand variables */
	guint16 length;
	guint16 at_address;
	guint16 destination;
	guint16 address;
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
	print_level_1 = FALSE;
	print_level_2 = FALSE;
	print_level_3 = FALSE;
	show_instr_detail_level = 0;



	switch( print_flags ) {
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





	/* UDVM memory must be initialised to zero */
	memset(buff, 0, UDVM_MEMORY_SIZE);
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

	proto_tree_add_text(udvm_tree, bytecode_tvb, offset, 1,"maximum_UDVM_cycles(%u) = (( 8 * msg_end(%u) ) + 1000) * cycles_per_bit(%u)",maximum_UDVM_cycles,msg_end,cycles_per_bit);
	proto_tree_add_text(udvm_tree, bytecode_tvb, offset, 1,"Message Length: %u,Byte code length: %u, Maximum UDVM cycles: %u",msg_end,code_length,maximum_UDVM_cycles);

	/* Load bytecode into UDVM starting at "udvm_mem_dest" */
	i = udvm_mem_dest;
	if ( print_level_3 )
		proto_tree_add_text(udvm_tree, bytecode_tvb, offset, 1,"Load bytecode into UDVM starting at %u",i);
	while ( code_length > offset ) {
		buff[i] = tvb_get_guint8(bytecode_tvb, offset);
		if ( print_level_3 )
			proto_tree_add_text(udvm_tree, bytecode_tvb, offset, 1,
						"              Addr: %u Instruction code(0x%0x) ", i, buff[i]);

		i++;
		offset++;

	}
	/* Largest allowed size for a message is 65535  */
	out_buff = g_malloc(65535);
	/* Start executing code */
	current_address = udvm_start_ip;
	input_address = 0;
	operand_address = 0;
	
	proto_tree_add_text(udvm_tree, bytecode_tvb, offset, 1,"UDVM EXECUTION STARTED at Address: %u Message size %u",
		current_address, msg_end);

execute_next_instruction:

	if ( used_udvm_cycles > maximum_UDVM_cycles ){
		result_code = 15;
		goto decompression_failure;
	}
	current_instruction = buff[current_address];

	switch ( current_instruction ) {
	case SIGCOMP_INSTR_DECOMPRESSION_FAILURE:
		used_udvm_cycles++;
		if ( result_code == 0 )
			result_code = 9;
		proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
			"Addr: %u ## DECOMPRESSION-FAILURE(0)",
			current_address);
		proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Ethereal UDVM diagnostic: %s.",
				    val_to_str(result_code, result_code_vals,"Unknown (%u)"));
		if ( output_address > 0 ){
			/* At least something got decompressed, show it */
			decomp_tvb = tvb_new_real_data(out_buff,output_address,output_address);
			/* Arrange that the allocated packet data copy be freed when the
			 * tvbuff is freed. 
			 */
			tvb_set_free_cb( decomp_tvb, g_free );
			/* Add the tvbuff to the list of tvbuffs to which the tvbuff we
			 * were handed refers, so it'll get cleaned up when that tvbuff
			 * is cleaned up. 
			 */
			tvb_set_child_real_data_tvbuff(message_tvb,decomp_tvb);
			add_new_data_source(pinfo, decomp_tvb, "Decompressed SigComp message(Incomplete)");
			proto_tree_add_text(udvm_tree, decomp_tvb, 0, -1,"SigComp message Decompression failure");
		return decomp_tvb;
		}
		g_free(out_buff);
		return NULL;
		break;

	case SIGCOMP_INSTR_AND: /* 1 AND ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## AND(1) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## AND (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* execute the instruction */
		result = operand_1 & operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;

		break;

	case SIGCOMP_INSTR_OR: /* 2 OR ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## OR(2) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## OR (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* execute the instruction */
		result = operand_1 | operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;

		break;

	case SIGCOMP_INSTR_NOT: /* 3 NOT ($operand_1) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## NOT(3) ($operand_1)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## NOT (operand_1=%u)",
				current_address, operand_1);
		}
		/* execute the instruction */
		result = operand_1 ^ 0xffff;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_LSHIFT: /* 4 LSHIFT ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## LSHIFT(4) ($operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## LSHIFT (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* execute the instruction */
		result = operand_1 << operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;

		break;
	case SIGCOMP_INSTR_RSHIFT: /* 5 RSHIFT ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## RSHIFT(5) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## RSHIFT (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* execute the instruction */
		result = operand_1 >> operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;
		break;
	case SIGCOMP_INSTR_ADD: /* 6 ADD ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## ADD(6) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## ADD (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* execute the instruction */
		result = operand_1 + operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"               Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;

	case SIGCOMP_INSTR_SUBTRACT: /* 7 SUBTRACT ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## SUBTRACT(7) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## SUBTRACT (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* execute the instruction */
		result = operand_1 - operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"               Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_MULTIPLY: /* 8 MULTIPLY ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ##MULTIPLY(8) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## MULTIPLY (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* 
		 * execute the instruction
		 * MULTIPLY (m, n)  := m * n (modulo 2^16)
		 */
		if ( operand_2 == 0){
			result_code = 4;
			goto decompression_failure;
		}
		result = operand_1 * operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_DIVIDE: /* 9 DIVIDE ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## DIVIDE(9) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## DIVIDE (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* 
		 * execute the instruction
		 * DIVIDE (m, n)    := floor(m / n)
		 * Decompression failure occurs if a DIVIDE or REMAINDER instruction
 		 * encounters an operand_2 that is zero.
		 */
		if ( operand_2 == 0){
			result_code = 4;
			goto decompression_failure;
		}
		result = operand_1 / operand_2;
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_REMAINDER: /* 10 REMAINDER ($operand_1, %operand_2) */
		used_udvm_cycles++;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## REMAINDER(10) (operand_1, operand_2)",
				current_address);
		}
		/* $operand_1*/
		operand_address = current_address + 1;
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &operand_1, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_1 %u",
				operand_address, operand_1);
		}
		operand_address = next_operand_address; 
		/* %operand_2*/
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &operand_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      operand_2 %u",
				operand_address, operand_2);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## REMAINDER (operand_1=%u, operand_2=%u)",
				current_address, operand_1, operand_2);
		}
		/* 
		 * execute the instruction
		 * REMAINDER (m, n) := m - n * floor(m / n)
		 * Decompression failure occurs if a DIVIDE or REMAINDER instruction
 		 * encounters an operand_2 that is zero.
		 */
		if ( operand_2 == 0){
			result_code = 4;
			goto decompression_failure;
		}
		result = operand_1 - operand_2 * (operand_1 / operand_2);
		lsb = result & 0xff;
		msb = result >> 8;		
		buff[result_dest] = msb;
		buff[result_dest+1] = lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading result %u at %u",
				result, result_dest);
		}
		current_address = next_operand_address; 
		goto execute_next_instruction;
		break;
	case SIGCOMP_INSTR_SORT_ASCENDING: /* 11 SORT-ASCENDING (%start, %n, %k) */
		/*
		 * 	used_udvm_cycles =  1 + k * (ceiling(log2(k)) + n)
		 */
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## SORT-ASCENDING(11) (start, n, k))",
				current_address);
		}
		operand_address = current_address + 1;
		proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Execution of this instruction is NOT implemented");
		/*
		 * 	used_udvm_cycles =  1 + k * (ceiling(log2(k)) + n)
		 */
		break;

	case SIGCOMP_INSTR_SORT_DESCENDING: /* 12 SORT-DESCENDING (%start, %n, %k) */
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## SORT-DESCENDING(12) (start, n, k))",
				current_address);
		}
		operand_address = current_address + 1;
		proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Execution of this instruction is NOT implemented");
		/*
		 * 	used_udvm_cycles =  1 + k * (ceiling(log2(k)) + n)
		 */
		break;
	case SIGCOMP_INSTR_SHA_1: /* 13 SHA-1 (%position, %length, %destination) */
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## SHA-1(13) (position, length, destination)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %position */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      position %u",
				operand_address, position);
		}
		operand_address = next_operand_address; 

		/* %length */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;

		/* $destination */
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &ref_destination, &result_dest);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      $destination %u",
				operand_address, ref_destination);
		}
		current_address = next_operand_address; 
		used_udvm_cycles = used_udvm_cycles + 1 + length;

		n = 0;
		k = position;
		byte_copy_right = buff[66] << 8;
		byte_copy_right = byte_copy_right | buff[67];
		byte_copy_left = buff[64] << 8;
		byte_copy_left = byte_copy_left | buff[65];

		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, 0, -1,
					"byte_copy_right = %u", byte_copy_right);
		}

		sha1_starts( &ctx );

		while (n<length) {
			guint16 handle_now = length;

			if ( k < byte_copy_right && byte_copy_right <= k + (length-n) ){
				handle_now = byte_copy_right - position;
			}

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

			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
		}

		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, 0, -1,
					"Calculated SHA-1: %s",
					bytes_to_str(sha1_digest_buf, STATE_BUFFER_SIZE));
		}

		current_address = next_operand_address;
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_LOAD: /* 14 LOAD (%address, %value) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## LOAD(14) (%%address, %%value)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %address */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Address %u",
				operand_address, address);
		}
		operand_address = next_operand_address; 
		/* %value */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## LOAD (%%address=%u, %%value=%u)",
				current_address, address, value);
		}
		lsb = value & 0xff;
		msb = value >> 8;

		buff[address] = msb;
		buff[address + 1] = lsb;

		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Value %u",
				operand_address, value);
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"     Loading bytes at %u Value %u 0x%x",
					address, value, value);
		}
		used_udvm_cycles++;
		current_address = next_operand_address;
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_MULTILOAD: /* 15 MULTILOAD (%address, #n, %value_0, ..., %value_n-1) */
		/* RFC 3320:
		 * The MULTILOAD instruction sets a contiguous block of 2-byte words in
		 * the UDVM memory to specified values.
		 * Hmm what if the value to load only takes one byte ? Chose to always load two bytes.
		 */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## MULTILOAD(15) (%%address, #n, value_0, ..., value_n-1)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %address */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Address %u",
				operand_address, address);
		}
		operand_address = next_operand_address; 

		/* #n */
		next_operand_address = decode_udvm_literal_operand(buff,operand_address, &n);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      n %u",
				operand_address, n);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## MULTILOAD (%%address=%u, #n=%u, value_0, ..., value_%d)",
				current_address, address, n, n-1);
		}
		operand_address = next_operand_address; 
		used_udvm_cycles = used_udvm_cycles + 1 + n;
		while ( n > 0) {
			n = n - 1;
			/* %value */
			next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
			lsb = value & 0xff;
			msb = value >> 8;

			buff[address] = msb;
			buff[address + 1] = lsb;
			/* debug
			*/
			length = next_operand_address - operand_address;

			if (print_level_1 ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1, "Addr: %u      Value %5u      - Loading bytes at %5u Value %5u 0x%x",
				operand_address, value, address, value, value);
			}
			address = address + 2;
			operand_address = next_operand_address; 
		}
		current_address = next_operand_address;
		goto execute_next_instruction;

		break;
			 
	case SIGCOMP_INSTR_PUSH: /* 16 PUSH (%value) */
		if (show_instr_detail_level == 2){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## PUSH(16) (value)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %value */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
		if (show_instr_detail_level == 2){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Value %u",
				operand_address, value);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## PUSH (value=%u)",
				current_address, value);
		}
		current_address = next_operand_address; 

		/* Push the value address onto the stack */ 
		stack_location = (buff[70] << 8) | buff[71];
		stack_fill = (buff[stack_location] << 8) 
			   | buff[(stack_location+1) & 0xFFFF];
		address = (stack_location + stack_fill * 2 + 2) & 0xFFFF;

		buff[address] = (value >> 8) & 0x00FF;
		buff[(address+1) & 0xFFFF] = value & 0x00FF;
		
		stack_fill = (stack_fill + 1) & 0xFFFF;
		buff[stack_location] = (stack_fill >> 8) & 0x00FF;
		buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

		used_udvm_cycles++;
		goto execute_next_instruction;

		break;

	case SIGCOMP_INSTR_POP: /* 17 POP (%address) */
		if (show_instr_detail_level == 2){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## POP(16) (value)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %value */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
		if (show_instr_detail_level == 2){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Value %u",
				operand_address, destination);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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

		stack_fill = (stack_fill - 1) & 0xFFFF;
		buff[stack_location] = (stack_fill >> 8) & 0x00FF;
		buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

		address = (stack_location + stack_fill * 2 + 2) & 0xFFFF;
		value = (buff[address] << 8) 
			   | buff[(address+1) & 0xFFFF];

		/* ... and store the popped value. */
		buff[destination] = (value >> 8) & 0x00FF;
		buff[(destination+1) & 0xFFFF] = value & 0x00FF;

		used_udvm_cycles++;
		goto execute_next_instruction;

		break;

	case SIGCOMP_INSTR_COPY: /* 18 COPY (%position, %length, %destination) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## COPY(18) (position, length, destination)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %position */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      position %u",
				operand_address, position);
		}
		operand_address = next_operand_address; 

		/* %length */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;

		/* %destination */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Destination %u",
				operand_address, destination);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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
		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
						"               byte_copy_right = %u", byte_copy_right);
		}

		while ( n < length ){
			buff[k] = buff[position];
			if (print_level_2 ){
				proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               Copying value: %u (0x%x) to Addr: %u",
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
			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
			if ( position == byte_copy_right ){
				position = byte_copy_left;
			}
		}
		used_udvm_cycles = used_udvm_cycles + 1 + length;
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_COPY_LITERAL: /* 19 COPY-LITERAL (%position, %length, $destination) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## COPY-LITERAL(19) (position, length, $destination)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %position */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      position %u",
				operand_address, position);
		}
		operand_address = next_operand_address; 

		/* %length */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;


		/* $destination */
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &ref_destination, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      destination %u",
				operand_address, ref_destination);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## COPY-LITERAL (position=%u, length=%u, $destination=%u)",
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
		k = ref_destination; 
		byte_copy_right = buff[66] << 8;
		byte_copy_right = byte_copy_right | buff[67];
		byte_copy_left = buff[64] << 8;
		byte_copy_left = byte_copy_left | buff[65];
		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               byte_copy_right = %u", byte_copy_right);
		}
		while ( n < length ){

			buff[k] = buff[position];
			if (print_level_2 ){
				proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               Copying value: %u (0x%x) to Addr: %u", 
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
			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
			if ( position == byte_copy_right ){
				position = byte_copy_left;
			}
		}
		buff[result_dest] = k >> 8;
		buff[result_dest + 1] = k & 0x00ff;

		used_udvm_cycles = used_udvm_cycles + 1 + length;
		goto execute_next_instruction;
		break;
 
	case SIGCOMP_INSTR_COPY_OFFSET: /* 20 COPY-OFFSET (%offset, %length, $destination) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## COPY-OFFSET(20) (offset, length, $destination)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %offset */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &multy_offset);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      offset %u",
				operand_address, multy_offset);
		}
		operand_address = next_operand_address; 

		/* %length */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;


		/* $destination */
		next_operand_address = dissect_udvm_reference_operand(buff, operand_address, &ref_destination, &result_dest);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      $destination %u",
				operand_address, ref_destination);
		}

		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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

		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               byte_copy_left = %u byte_copy_right = %u position= %u",
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
		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               byte_copy_left = %u byte_copy_right = %u", byte_copy_left, byte_copy_right);
		}
		while ( n < length ){
			buff[k] = buff[position];
			if (print_level_2 ){
				proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               Copying value: %5u (0x%x) from Addr: %u to Addr: %u",
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
			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
			if ( position == byte_copy_right ){
				position = byte_copy_left;
			}
		}
		buff[result_dest] = k >> 8;
		buff[result_dest + 1] = k & 0x00ff;
		used_udvm_cycles = used_udvm_cycles + 1 + length;
		goto execute_next_instruction;

		break;
	case SIGCOMP_INSTR_MEMSET: /* 21 MEMSET (%address, %length, %start_value, %offset) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## MEMSET(21) (address, length, start_value, offset)",
				current_address);
		}
		operand_address = current_address + 1;

		/* %address */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Address %u",
				operand_address, address);
		}
		operand_address = next_operand_address; 

		/*  %length, */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;
		/* %start_value */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &start_value);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      start_value %u",
				operand_address, start_value);
		}
		operand_address = next_operand_address; 

		/* %offset */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &multy_offset);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      offset %u",
				operand_address, multy_offset);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## MEMSET (address=%u, length=%u, start_value=%u, offset=%u)",
				current_address, address, length, start_value, multy_offset);
		}
		current_address = next_operand_address; 
		/* exetute the instruction
		 * The sequence of values used by the MEMSET instruction is specified by
		 * the following formula:
		 * 
		 * Seq[n] := (start_value + n * offset) modulo 256
		 */
		n = 0;
		k = address; 
		byte_copy_right = buff[66] << 8;
		byte_copy_right = byte_copy_right | buff[67];
		byte_copy_left = buff[64] << 8;
		byte_copy_left = byte_copy_left | buff[65];
		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               byte_copy_left = %u byte_copy_right = %u", byte_copy_left, byte_copy_right);
		}
		while ( n < length ){
			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
			buff[k] = (start_value + ( n * multy_offset)) & 0xff;
			if (print_level_2 ){
				proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"     Storing value: %u (0x%x) at Addr: %u",
					buff[k], buff[k], k);
			}
			k = ( k + 1 ) & 0xffff;
			n++;
		}/* end while */
		used_udvm_cycles = used_udvm_cycles + 1 + length;
		goto execute_next_instruction;
		break;


	case SIGCOMP_INSTR_JUMP: /* 22 JUMP (@address) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## JUMP(22) (@address)",
				current_address);
		}
		operand_address = current_address + 1;
		/* @address */
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## JUMP (@address=%u)",
				current_address, at_address);
		}
		current_address = at_address;
		used_udvm_cycles++;
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_COMPARE: /* 23 */
		/* COMPARE (%value_1, %value_2, @address_1, @address_2, @address_3)
		 */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## COMPARE(23) (value_1, value_2, @address_1, @address_2, @address_3)",
				current_address);
		}
		operand_address = current_address + 1;

		/* %value_1 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value_1);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Value %u",
					operand_address, value_1);
		}
		operand_address = next_operand_address;

		/* %value_2 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value_2);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Value %u",
					operand_address, value_2);
		}
		operand_address = next_operand_address;

		/* @address_1 */
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_1);
		at_address_1 = ( current_address + at_address_1) & 0xffff;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address_1);
		}
		operand_address = next_operand_address;


		/* @address_2 */
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_2);
		at_address_2 = ( current_address + at_address_2) & 0xffff;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address_2);
		}
		operand_address = next_operand_address;

		/* @address_3 */
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_3);
		at_address_3 = ( current_address + at_address_3) & 0xffff;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address_3);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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
		used_udvm_cycles++;
		goto execute_next_instruction;
		break;

	case SIGCOMP_INSTR_CALL: /* 24 CALL (@address) (PUSH addr )*/
		if (show_instr_detail_level == 2){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## CALL(24) (@address) (PUSH addr )",
				current_address);
		}
		operand_address = current_address + 1;
		/* @address */
		next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## CALL (@address=%u)",
				current_address, at_address);
		}
		current_address = next_operand_address; 

		/* Push the current address onto the stack */ 
		stack_location = (buff[70] << 8) | buff[71];
		stack_fill = (buff[stack_location] << 8) 
			   | buff[(stack_location+1) & 0xFFFF];
		address = (stack_location + stack_fill * 2 + 2) & 0xFFFF;
		buff[address] = (current_address >> 8) & 0x00FF;
		buff[(address+1) & 0xFFFF] = current_address & 0x00FF;
		
		stack_fill = (stack_fill + 1) & 0xFFFF;
		buff[stack_location] = (stack_fill >> 8) & 0x00FF;
		buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

		/* ... and jump to the destination address */
		current_address = at_address;

		used_udvm_cycles++;
		goto execute_next_instruction;

		break;

	case SIGCOMP_INSTR_RETURN: /* 25 POP and return */
		if (print_level_1 || show_instr_detail_level == 1){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## POP(25) and return",
				current_address);
		}

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
		buff[stack_location] = (stack_fill >> 8) & 0x00FF;
		buff[(stack_location+1) & 0xFFFF] = stack_fill & 0x00FF;

		address = (stack_location + stack_fill * 2 + 2) & 0xFFFF;
		at_address = (buff[address] << 8) 
			   | buff[(address+1) & 0xFFFF];

		/* ... and set the PC to the popped value */
		current_address = at_address;

		used_udvm_cycles++;
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
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## SWITCH (#n, j, @address_0, @address_1, ... , @address_n-1))",
				current_address);
		}
		operand_address = current_address + 1;
		/* #n 
		 * Number of addresses in the instruction
		 */
		next_operand_address = decode_udvm_literal_operand(buff,operand_address, &n);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      n %u",
				operand_address, n);
		}
		operand_address = next_operand_address; 
		/* %j */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &j);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      j %u",
					operand_address, j);
		}
		operand_address = next_operand_address;
		m = 0;
		while ( m < n ){
			/* @address_n-1 */
			/* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
			next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address_1);
			at_address_1 = ( instruction_address + at_address_1) & 0xffff;
			if (print_level_1 ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
					operand_address, at_address_1);
			}
			if ( j == m ){
				current_address = at_address_1;
			}
			operand_address = next_operand_address;
			m++;
		}
		/* Check decompression failure */
		if ( ( j == n ) || ( j > n )){
			result_code = 5;
			goto decompression_failure;
		}
		if ( current_address > UDVM_MEMORY_SIZE ){
			result_code = 6;
			goto decompression_failure;
		}
		used_udvm_cycles = used_udvm_cycles + 1 + n;

		goto execute_next_instruction;

		break;
	case SIGCOMP_INSTR_CRC: /* 27 CRC (%value, %position, %length, @address) */
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## CRC (value, position, length, @address)",
				current_address);
		}

		operand_address = current_address + 1;

		/* %value */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &value);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Value %u",
				operand_address, value);
		}
		operand_address = next_operand_address; 

		/* %position */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &position);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      position %u",
				operand_address, position);
		}
		operand_address = next_operand_address; 

		/* %length */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;

		/* @address */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address);
		at_address = ( current_address + at_address) & 0xffff;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address);
		}
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		used_udvm_cycles = used_udvm_cycles + 1 + length;
		
		n = 0;
		k = position;
		byte_copy_right = buff[66] << 8;
		byte_copy_right = byte_copy_right | buff[67];
		byte_copy_left = buff[64] << 8;
		byte_copy_left = byte_copy_left | buff[65];
		result = 0;

		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, 0, -1,
					"byte_copy_right = %u", byte_copy_right);
		}

		while (n<length) {

			guint16 handle_now = length - n;

			if ( k < byte_copy_right && byte_copy_right <= k + (length-n) ){
				handle_now = byte_copy_right - k;
			}

			result = crc16_ccitt_seed(&buff[k], handle_now, result ^ 0xffff);

			k = ( k + handle_now ) & 0xffff;
			n = ( n + handle_now ) & 0xffff;

			if ( k >= byte_copy_right ) {
				k = byte_copy_left;
			}
		}

		result = result ^ 0xffff;

		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1, "Calculated CRC %u", result);
		}
		if (result != value){
			current_address = at_address;
		}
		else {
			current_address = next_operand_address;
		}
		goto execute_next_instruction;
		break;


	case SIGCOMP_INSTR_INPUT_BYTES: /* 28 INPUT-BYTES (%length, %destination, @address) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## INPUT-BYTES(28) length, destination, @address)",
				current_address);
		}
		operand_address = current_address + 1;
		/* %length */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;

		/* %destination */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Destination %u",
				operand_address, destination);
		}
		operand_address = next_operand_address;

		/* @address */
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &at_address);
		at_address = ( current_address + at_address) & 0xffff;
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               byte_copy_right = %u", byte_copy_right);
		}
		/* clear out remaining bits if any */
		remaining_bits = 0;
		input_bits=0;
		/* operand_address used as dummy */
		while ( n < length ){
			if (input_address > ( msg_end - 1)){
				current_address = at_address;
				result_code = 14;
				goto execute_next_instruction;
			}

			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
			octet = tvb_get_guint8(message_tvb, input_address);
			buff[k] = octet;
			if (print_level_1 ){
				proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               Loading value: %u (0x%x) at Addr: %u", octet, octet, k);
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
		used_udvm_cycles = used_udvm_cycles + 1 + length;
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

		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## INPUT-BITS(29) (length, destination, @address)",
				current_address);
		}
		operand_address = current_address + 1;

		/* %length */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      length %u",
				operand_address, length);
		}
		operand_address = next_operand_address;
		/* %destination */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Destination %u",
				operand_address, destination);
		}
		operand_address = next_operand_address;

		/* @address */
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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

		if ( length > 16 ){
			result_code = 7;
			goto decompression_failure;
		}
		if ( input_bit_order > 7 ){
			result_code = 8;
			goto decompression_failure;
		}

		/* 
		 * Transfer F bit to bit_order to tell decomp dispatcher which bit order to use 
		 */
		bit_order = ( input_bit_order & 0x0004 ) >> 2;
		value = decomp_dispatch_get_bits( message_tvb, udvm_tree, bit_order, 
				buff, &old_input_bit_order, &remaining_bits,
				&input_bits, &input_address, length, &result_code, msg_end);
		if ( result_code == 11 ){
			used_udvm_cycles = used_udvm_cycles + 1;
			current_address = at_address;
			goto execute_next_instruction;
		}
		msb = value >> 8;
		lsb = value & 0x00ff;
		buff[destination] = msb;
		buff[destination + 1]=lsb;
		if (print_level_1 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
			"               Loading value: %u (0x%x) at Addr: %u, remaining_bits: %u", value, value, destination, remaining_bits);
		}

		used_udvm_cycles = used_udvm_cycles + 1;
		goto execute_next_instruction;
		break;
	case SIGCOMP_INSTR_INPUT_HUFFMAN: /* 30 */
		/*
		 * INPUT-HUFFMAN (%destination, @address, #n, %bits_1, %lower_bound_1,
		 *  %upper_bound_1, %uncompressed_1, ... , %bits_n, %lower_bound_n,
		 *  %upper_bound_n, %uncompressed_n)
		 */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## INPUT-HUFFMAN (destination, @address, #n, bits_1, lower_bound_1,upper_bound_1, uncompressed_1, ... , bits_n, lower_bound_n,upper_bound_n, uncompressed_n)",
				current_address);
		}
		operand_address = current_address + 1;

		/* %destination */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &destination);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      Destination %u",
				operand_address, destination);
		}
		operand_address = next_operand_address;

		/* @address */
		 /* operand_value = (memory_address_of_instruction + D) modulo 2^16 */
		next_operand_address = decode_udvm_address_operand(buff,operand_address, &at_address, current_address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      @Address %u",
				operand_address, at_address);
		}
		operand_address = next_operand_address;

		/* #n */
		next_operand_address = decode_udvm_literal_operand(buff,operand_address, &n);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      n %u",
				operand_address, n);
		}
		operand_address = next_operand_address; 
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## INPUT-HUFFMAN (destination=%u, @address=%u, #n=%u, bits_1, lower_1,upper_1, unc_1, ... , bits_%d, lower_%d,upper_%d, unc_%d)",
				current_address, destination, at_address, n, n, n, n, n);
		}

		used_udvm_cycles = used_udvm_cycles + 1 + n;

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
		while ( m > 0 ){
			/* %bits_n */
			next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &bits_n);
			if (print_in_loop ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      bits_n %u",
					operand_address, bits_n);
			}
			operand_address = next_operand_address; 

			/* %lower_bound_n */
			next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &lower_bound_n);
			if (print_in_loop ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      lower_bound_n %u",
					operand_address, lower_bound_n);
			}
			operand_address = next_operand_address; 
			/* %upper_bound_n */
			next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &upper_bound_n);
			if (print_in_loop ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      upper_bound_n %u",
					operand_address, upper_bound_n);
			}
			operand_address = next_operand_address; 
			/* %uncompressed_n */
			next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &uncompressed_n);
			if (print_in_loop ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      uncompressed_n %u",
					operand_address, uncompressed_n);
			}
			operand_address = next_operand_address;
			/* execute instruction */
			if ( outside_huffman_boundaries ) {
				/*
				 * 2. Request bits_j compressed bits.  Interpret the returned bits as an
				 *    integer k from 0 to 2^bits_j - 1, as explained in Section 8.2.
				 */
				k = decomp_dispatch_get_bits( message_tvb, udvm_tree, bit_order, 
						buff, &old_input_bit_order, &remaining_bits,
						&input_bits, &input_address, bits_n, &result_code, msg_end);
				if ( result_code == 11 ){
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
				if (print_level_3 ){
					proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"               Set H(%u) := H(%u) * 2^bits_j(%u) + k(%u)",
						 H ,oldH, 1<<bits_n,k);
				}

				/*
				 * 5. If (H < lower_bound_j) or (H > upper_bound_j) then set j := j + 1.
				 * Then go back to Step 2, unless j > n in which case decompression
				 * failure occurs.
				 */
				if ((H < lower_bound_n) || (H > upper_bound_n)){
					outside_huffman_boundaries = TRUE;
				}else{
					outside_huffman_boundaries = FALSE;
					print_in_loop = FALSE;
					/*
					 * 6. Copy (H + uncompressed_j - lower_bound_j) modulo 2^16 to the
					 * memory address specified by the destination operand.
					 */
					if (print_level_2 ){
						proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
							"               H(%u) = H(%u) + uncompressed_n(%u) - lower_bound_n(%u)",
						(H + uncompressed_n - lower_bound_n ),H, uncompressed_n, lower_bound_n);
					}
					H = H + uncompressed_n - lower_bound_n;
					msb = H >> 8;
					lsb = H & 0x00ff;
					buff[destination] = msb;
					buff[destination + 1]=lsb;
					if (print_level_1 ){
						proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
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
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## STATE-ACCESS(31) (partial_identifier_start, partial_identifier_length,state_begin, state_length, state_address, state_instruction)",
				current_address);
		}
		operand_address = current_address + 1;

		/* 
		 * %partial_identifier_start
		 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_start);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       partial_identifier_start %u",
				operand_address, p_id_start);
		}
		operand_address = next_operand_address;

		/*
		 * %partial_identifier_length
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       partial_identifier_length %u",
				operand_address, p_id_length);
		}
		/*
		 * %state_begin
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_begin);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_begin %u",
				operand_address, state_begin);
		}
		/*
		 * %state_length
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_length %u",
				operand_address, state_length);
		}
		/*
		 * %state_address
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_address %u",
				operand_address, state_address);
		}
		/*
		 * %state_instruction
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_instruction);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_instruction %u",
				operand_address, state_instruction);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## STATE-ACCESS(31) (partial_identifier_start=%u, partial_identifier_length=%u,state_begin=%u, state_length=%u, state_address=%u, state_instruction=%u)",
				current_address, p_id_start, p_id_length, state_begin, state_length, state_address, state_instruction);
		}
		current_address = next_operand_address;
		byte_copy_right = buff[66] << 8;
		byte_copy_right = byte_copy_right | buff[67];
		byte_copy_left = buff[64] << 8;
		byte_copy_left = byte_copy_left | buff[65];
		if (print_level_2 ){
			proto_tree_add_text(udvm_tree, message_tvb, input_address, 1,
					"               byte_copy_right = %u, byte_copy_left = %u", byte_copy_right,byte_copy_left);
		}

		result_code = udvm_state_access(message_tvb, udvm_tree, buff, p_id_start, p_id_length, state_begin, &state_length, 
			&state_address, &state_instruction, hf_id);
		if ( result_code != 0 ){
			goto decompression_failure; 
		}
		used_udvm_cycles = used_udvm_cycles + 1 + state_length;
		goto execute_next_instruction;
		break;
	case SIGCOMP_INSTR_STATE_CREATE: /* 32 */
		/*
		 * STATE-CREATE (%state_length, %state_address, %state_instruction,
		 * %minimum_access_length, %state_retention_priority)
		 */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## STATE-CREATE(32) (state_length, state_address, state_instruction,minimum_access_length, state_retention_priority)",
				current_address);
		}
		operand_address = current_address + 1;

		/*
		 * %state_length
		 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_length %u",
				operand_address, state_length);
		}
		/*
		 * %state_address
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_address %u",
				operand_address, state_address);
		}
		/*
		 * %state_instruction
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_instruction);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_instruction %u",
				operand_address, state_instruction);
		}
		operand_address = next_operand_address;
		/*
		 * %minimum_access_length
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &minimum_access_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       minimum_access_length %u",
				operand_address, minimum_access_length);
		}
		operand_address = next_operand_address;
		/*
		 * %state_retention_priority
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_retention_priority);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       state_retention_priority %u",
				operand_address, state_retention_priority);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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
		if ( no_of_state_create > 4 ){
			result_code = 12;
			goto decompression_failure; 
		}
		if (( minimum_access_length < 6 ) || ( minimum_access_length > STATE_BUFFER_SIZE )){
			result_code = 1;
			goto decompression_failure; 
		}
		if ( state_retention_priority == 65535 ){
			result_code = 13;
			goto decompression_failure; 
		}
		state_length_buff[no_of_state_create] = state_length;
		state_address_buff[no_of_state_create] = state_address;
		state_instruction_buff[no_of_state_create] = state_instruction;
		state_minimum_access_length_buff[no_of_state_create] = minimum_access_length;
		state_state_retention_priority_buff[no_of_state_create] = state_retention_priority;
		used_udvm_cycles = used_udvm_cycles + 1 + state_length;
		/* Debug */
		byte_copy_right = buff[66] << 8;
		byte_copy_right = byte_copy_right | buff[67];
		byte_copy_left = buff[64] << 8;
		byte_copy_left = byte_copy_left | buff[65];
		n = 0;
		k = state_address;
		while ( n < state_length ){
			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
			string[0]= buff[k];
			string[1]= '\0';
			if (print_level_3 ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
					"               Addr: %5u State value: %u (0x%x) ASCII(%s)",
					k,buff[k],buff[k],string);
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
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## STATE-FREE (partial_identifier_start, partial_identifier_length)",
				current_address);
		}
		operand_address = current_address + 1;
		/* 
		 * %partial_identifier_start
		 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_start);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       partial_identifier_start %u",
				operand_address, p_id_start);
		}
		operand_address = next_operand_address;

		/*
		 * %partial_identifier_length
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &p_id_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u       partial_identifier_length %u",
				operand_address, p_id_length);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## STATE-FREE (partial_identifier_start=%u, partial_identifier_length=%u)",
				current_address, p_id_start, p_id_length);
		}
		current_address = next_operand_address;

		/* Execute the instruction:
		 * TODO implement it
		 */
		udvm_state_free(buff,p_id_start,p_id_length);
		used_udvm_cycles++;

		goto execute_next_instruction;
		break;
	case SIGCOMP_INSTR_OUTPUT: /* 34 OUTPUT (%output_start, %output_length) */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## OUTPUT(34) (output_start, output_length)",
				current_address);
		}
		operand_address = current_address + 1;
		/* 
		 * %output_start
		 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &output_start);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      output_start %u",
				operand_address, output_start);
		}
		operand_address = next_operand_address;
		/* 
		 * %output_length
		 */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &output_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      output_length %u",
				operand_address, output_length);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
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
		if (print_level_3 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
					"               byte_copy_right = %u", byte_copy_right);
		}
		while ( n < output_length ){

			if ( k == byte_copy_right ){
				k = byte_copy_left;
			}
			out_buff[output_address] = buff[k];
			string[0]= buff[k];
			string[1]= '\0';
			strp = string;
			if (print_level_3 ){
				proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
					"               Output value: %u (0x%x) ASCII(%s) from Addr: %u ,output to dispatcher position %u",
					buff[k],buff[k],format_text(strp,1), k,output_address);
			}
			k = ( k + 1 ) & 0xffff;
			output_address ++;
			n++;
		}
		used_udvm_cycles = used_udvm_cycles + 1 + output_length;
		goto execute_next_instruction;
		break;
	case SIGCOMP_INSTR_END_MESSAGE: /* 35 */
		/*
		 * END-MESSAGE (%requested_feedback_location,
		 * %returned_parameters_location, %state_length, %state_address,
		 * %state_instruction, %minimum_access_length,
		 * %state_retention_priority)
		 */
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## END-MESSAGE (requested_feedback_location,state_instruction, minimum_access_length,state_retention_priority)",
				current_address);
		}
		operand_address = current_address + 1;

		/* %requested_feedback_location */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &requested_feedback_location);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      requested_feedback_location %u",
				operand_address, requested_feedback_location);
		}
		operand_address = next_operand_address;
		/* returned_parameters_location */
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &returned_parameters_location);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      returned_parameters_location %u",
				operand_address, returned_parameters_location);
		}
		operand_address = next_operand_address;
		/*
		 * %state_length
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      state_length %u",
				operand_address, state_length);
		}
		/*
		 * %state_address
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_address);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      state_address %u",
				operand_address, state_address);
		}
		/*
		 * %state_instruction
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_instruction);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      state_instruction %u",
				operand_address, state_instruction);
		}

		/*
		 * %minimum_access_length
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &minimum_access_length);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      minimum_access_length %u",
				operand_address, minimum_access_length);
		}

		/*
		 * %state_retention_priority
		 */
		operand_address = next_operand_address;
		next_operand_address = decode_udvm_multitype_operand(buff, operand_address, &state_retention_priority);
		if (show_instr_detail_level == 2 ){
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"Addr: %u      state_retention_priority %u",
				operand_address, state_retention_priority);
		}
		if (show_instr_detail_level == 1)
		{
			proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,
				"Addr: %u ## END-MESSAGE (requested_feedback_location=%u, returned_parameters_location=%u, state_length=%u, state_address=%u, state_instruction=%u, minimum_access_length=%u, state_retention_priority=%u)",
				current_address, requested_feedback_location, returned_parameters_location, state_length, state_address, state_instruction, minimum_access_length,state_retention_priority);
		}
		current_address = next_operand_address;
		/* TODO: This isn't currently totaly correct as END_INSTRUCTION might not create state */
		no_of_state_create++;
		if ( no_of_state_create > 4 ){
			result_code = 12;
			goto decompression_failure; 
		}
		state_length_buff[no_of_state_create] = state_length;
		state_address_buff[no_of_state_create] = state_address;
		state_instruction_buff[no_of_state_create] = state_instruction;
		/* Not used ? */
		state_minimum_access_length_buff[no_of_state_create] = minimum_access_length;
		state_state_retention_priority_buff[no_of_state_create] = state_retention_priority;
		
		/* Execute the instruction
		 */
		proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"no_of_state_create %u",no_of_state_create);
		if ( no_of_state_create != 0 ){
			memset(sha1_digest_buf, 0, STATE_BUFFER_SIZE);
			n = 1;
			byte_copy_right = buff[66] << 8;
			byte_copy_right = byte_copy_right | buff[67];
			byte_copy_left = buff[64] << 8;
			byte_copy_left = byte_copy_left | buff[65];
			while ( n < no_of_state_create + 1 ){
				sha1buff = g_malloc(state_length_buff[n]+8);
				sha1buff[0] = state_length_buff[n] >> 8;
				sha1buff[1] = state_length_buff[n] & 0xff;
				sha1buff[2] = state_address_buff[n] >> 8;
				sha1buff[3] = state_address_buff[n] & 0xff;
				sha1buff[4] = state_instruction_buff[n] >> 8;
				sha1buff[5] = state_instruction_buff[n] & 0xff;	
				sha1buff[6] = state_minimum_access_length_buff[n] >> 8;
				sha1buff[7] = state_minimum_access_length_buff[n] & 0xff;
				if (print_level_3 ){
					for( x=0; x < 8; x++){
						proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"sha1buff %u 0x%x",
							x,sha1buff[x]);
					}
				}
				k = state_address_buff[n];
				for( x=0; x < state_length_buff[n]; x++)
					{
					if ( k == byte_copy_right ){
						k = byte_copy_left;
					}
					sha1buff[8+x] = buff[k];
					k = ( k + 1 ) & 0xffff;
					}

				sha1_starts( &ctx );
				sha1_update( &ctx, (guint8 *) sha1buff, state_length_buff[n] + 8);
				sha1_finish( &ctx, sha1_digest_buf );
				if (print_level_3 ){
					proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"SHA1 digest %s",bytes_to_str(sha1_digest_buf, STATE_BUFFER_SIZE));

				}
				udvm_state_create(sha1buff, sha1_digest_buf, state_minimum_access_length_buff[n]);
				proto_tree_add_text(udvm_tree,bytecode_tvb, 0, -1,"### Creating state ###");
				proto_tree_add_string(udvm_tree,hf_id, bytecode_tvb, 0, 0, bytes_to_str(sha1_digest_buf, state_minimum_access_length_buff[n]));

				n++;

			}
		}



		/* At least something got decompressed, show it */
		decomp_tvb = tvb_new_real_data(out_buff,output_address,output_address);
		/* Arrange that the allocated packet data copy be freed when the
		 * tvbuff is freed. 
		 */
		tvb_set_free_cb( decomp_tvb, g_free );

		tvb_set_child_real_data_tvbuff(message_tvb,decomp_tvb);
		add_new_data_source(pinfo, decomp_tvb, "Decompressed SigComp message");
		/*
		proto_tree_add_text(udvm_tree, decomp_tvb, 0, -1,"SigComp message Decompressed");
		*/	
		used_udvm_cycles = used_udvm_cycles + 1 + state_length;
		proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"maximum_UDVM_cycles %u used_udvm_cycles %u",
			maximum_UDVM_cycles, used_udvm_cycles);
		return decomp_tvb;
		break;

	default:
	    proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1," ### Addr %u Invalid instruction: %u (0x%x)",
			current_address,current_instruction,current_instruction);
		break;
		}
		g_free(out_buff);
		return NULL;
decompression_failure:
		
		proto_tree_add_text(udvm_tree, bytecode_tvb, 0, -1,"DECOMPRESSION FAILURE: %s",
				    val_to_str(result_code, result_code_vals,"Unknown (%u)"));
		g_free(out_buff);
		return NULL;

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
decode_udvm_literal_operand(guint8 *buff,guint operand_address, guint16 *value) 
{
	guint	bytecode;
	guint16 operand;
	guint	test_bits;
	guint	offset = operand_address;
	guint8	temp_data;

	bytecode = buff[operand_address];
	test_bits = bytecode >> 7;
	if (test_bits == 1){
		test_bits = bytecode >> 6;
		if (test_bits == 2){
			/*
			 * 10nnnnnn nnnnnnnn               N                   0 - 16383
			 */
			temp_data = buff[operand_address] & 0x1f;
			operand = temp_data << 8;
			temp_data = buff[operand_address + 1];
			operand = operand | temp_data;
			*value = operand;
			offset = offset + 2;

		}else{
			/*
			 * 111000000 nnnnnnnn nnnnnnnn      N                   0 - 65535
			 */
			offset ++;
			temp_data = buff[operand_address] & 0x1f;
			operand = temp_data << 8;
			temp_data = buff[operand_address + 1];
			operand = operand | temp_data;
			*value = operand;
			offset = offset + 2;

		}
	}else{
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
dissect_udvm_reference_operand(guint8 *buff,guint operand_address, guint16 *value,guint *result_dest) 
{
	guint bytecode;
	guint16 operand;
	guint	offset = operand_address;
	guint test_bits;
	guint8	temp_data;
	guint16 temp_data16;

	bytecode = buff[operand_address];
	test_bits = bytecode >> 7;
	if (test_bits == 1){
		test_bits = bytecode >> 6;
		if (test_bits == 2){
			/*
			 * 10nnnnnn nnnnnnnn               memory[2 * N]       0 - 65535
			 */
			temp_data = buff[operand_address] & 0x3f;
			operand = temp_data << 8;
			temp_data = buff[operand_address + 1];
			operand = operand | temp_data;
			operand = (operand * 2);
			*result_dest = operand;
			temp_data16 = buff[operand] << 8;
			temp_data16 = temp_data16 | buff[operand+1];
			*value = temp_data16;
			offset = offset + 2;

		}else{
			/*
			 * 11000000 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
			 */
			operand_address++;
			operand = buff[operand_address] << 8;
			operand = operand | buff[operand_address + 1];
			*result_dest = operand;
			temp_data16 = buff[operand] << 8;
			temp_data16 = temp_data16 | buff[operand+1];
			*value = temp_data16;
			offset = offset + 3;

		}
	}else{
		/*
		 * 0nnnnnnn                        memory[2 * N]       0 - 65535
		 */
		operand = ( bytecode & 0x7f);
		operand = (operand * 2);
		*result_dest = operand;
		temp_data16 = buff[operand] << 8;
		temp_data16 = temp_data16 | buff[operand+1];
		*value = temp_data16;
		offset ++;
	}

	return offset;
}

	/* RFC3320
	 * Figure 10: Bytecode for a multitype (%) operand
	 * Bytecode:                       Operand value:      Range:               HEX val
	 * 00nnnnnn                        N                   0 - 63				0x00
	 * 01nnnnnn                        memory[2 * N]       0 - 65535			0x40
	 * 1000011n                        2 ^ (N + 6)        64 , 128				0x86	
	 * 10001nnn                        2 ^ (N + 8)    256 , ... , 32768			0x88
	 * 111nnnnn                        N + 65504       65504 - 65535			0xe0
	 * 1001nnnn nnnnnnnn               N + 61440       61440 - 65535			0x90
	 * 101nnnnn nnnnnnnn               N                   0 - 8191				0xa0
	 * 110nnnnn nnnnnnnn               memory[N]           0 - 65535			0xc0
	 * 10000000 nnnnnnnn nnnnnnnn      N                   0 - 65535			0x80
	 * 10000001 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535			0x81
	 */
static int
decode_udvm_multitype_operand(guint8 *buff,guint operand_address, guint16 *value)
{
	guint test_bits;
	guint bytecode;
	guint offset = operand_address;
	guint16 operand;
	guint32 result;
	guint8 temp_data;
	guint16 temp_data16;
	guint16 memmory_addr = 0;

	bytecode = buff[operand_address];
	test_bits = ( bytecode & 0xc0 ) >> 6;
	switch (test_bits ){
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
		temp_data16 = temp_data16 | buff[memmory_addr+1];
		*value = temp_data16;
		offset ++;
		break;
	case 2:
		/* Check tree most significant bits */
		test_bits = ( bytecode & 0xe0 ) >> 5;
		if ( test_bits == 5 ){
		/*
		 * 101nnnnn nnnnnnnn               N                   0 - 8191
		 */
			temp_data = buff[operand_address] & 0x1f;
			operand = temp_data << 8;
			temp_data = buff[operand_address + 1];
			operand = operand | temp_data;
			*value = operand;
			offset = offset + 2;
		}else{
			test_bits = ( bytecode & 0xf0 ) >> 4;
			if ( test_bits == 9 ){
		/*
		 * 1001nnnn nnnnnnnn               N + 61440       61440 - 65535
		 */
				temp_data = buff[operand_address] & 0x0f;
				operand = temp_data << 8;
				temp_data = buff[operand_address + 1];
				operand = operand | temp_data;
				operand = operand + 61440;
				*value = operand;
				offset = offset + 2;
			}else{
				test_bits = ( bytecode & 0x08 ) >> 3;
				if ( test_bits == 1){
		/*
		 * 10001nnn                        2 ^ (N + 8)    256 , ... , 32768
		 */

					result = 1 << ((buff[operand_address] & 0x07) + 8);
					operand = result & 0xffff;
					*value = operand;
					offset ++;
				}else{
					test_bits = ( bytecode & 0x0e ) >> 1;
					if ( test_bits == 3 ){
						/*
						 * 1000 011n                        2 ^ (N + 6)        64 , 128
						 */
						result = 1 << ((buff[operand_address] & 0x01) + 6);
						operand = result & 0xffff;
						*value = operand;
						offset ++;
					}else{
					/*
					 * 1000 0000 nnnnnnnn nnnnnnnn      N                   0 - 65535
					 * 1000 0001 nnnnnnnn nnnnnnnn      memory[N]           0 - 65535
					 */
						offset ++;
						temp_data16 = buff[operand_address + 1] << 8;
						temp_data16 = temp_data16 | buff[operand_address + 2];
						/*  debug
						 * g_warning("Reading 0x%x From address %u",temp_data16,operand_address);
						 */
						if ( (bytecode & 0x01) == 1 ){
							memmory_addr = temp_data16;
							temp_data16 = buff[memmory_addr] << 8;
							temp_data16 = temp_data16 | buff[memmory_addr+1];
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
		if ( test_bits == 1 ){
		/*
		 * 111nnnnn                        N + 65504       65504 - 65535
		 */
			operand = ( buff[operand_address] & 0x1f) + 65504;
			*value = operand;
			offset ++;
		}else{
		/*
		 * 110nnnnn nnnnnnnn               memory[N]           0 - 65535
		 */
			memmory_addr = buff[operand_address] & 0x1f;
			memmory_addr = memmory_addr << 8;
			memmory_addr = memmory_addr | buff[operand_address + 1];
			temp_data16 = buff[memmory_addr] << 8;
			temp_data16 = temp_data16 | buff[memmory_addr+1];
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
	guint next_opreand_address;

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
		tvbuff_t *message_tvb,
		proto_tree *udvm_tree,
		guint8 bit_order, 
		guint8 *buff,
		guint16 *old_input_bit_order, 
		guint16 *remaining_bits,
		guint16	*input_bits, 
		guint *input_address, 
		guint16 length, 
		guint16 *result_code,
		guint msg_end)
{
	guint16 input_bit_order;
	guint16 bits_still_required = length;
	guint16 value = 0;
	guint8  octet;
	gint    extra_bytes_available = msg_end - *input_address;
	gint    p_bit;
	gint    prev_p_bit = *old_input_bit_order & 0x0001;
	gint    bits_to_use = 0;


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
	 * Check we can suppy the required number of bits now, before we alter
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
			if (print_level_1 ){
				proto_tree_add_text(udvm_tree, message_tvb, *input_address , 1,
						"               Geting value: %u (0x%x) From Addr: %u", octet, octet, *input_address);
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


/* end udvm */

