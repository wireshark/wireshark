/* packet-wcp.c
 * Routines for Wellfleet Compression frame disassembly
 * Copyright 2001, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 *
 * ToDo:
 *	Add preference to allow/disallow decompression
 *	Calculate and verify check byte (last byte), if only we knew how!
 *	Handle Wellfleet compression over PPP links.
 *		- This will require changing the sub-dissector call
 *		  routine to determine if layer 2 is frame relay or
 *		  or PPP and different sub-dissector routines for each.
 *
 * Based upon information in the Nortel TCL based Pcaptap code.
 *http://www.mynetworkforum.com/tools/PCAPTAP/pcaptap-Win32-3.00.exe
 *
 * And lzss algorithm
 *http://www.rasip.fer.hr/research/compress/algorithms/fund/lz/lzss.html
 */

/*
 * Wellfleet compression is a variation on LZSS encoding.
 *
 * Compression is done by keeping a sliding window of previous
 * data transmited. The sender will use a pattern match to
 * encode repeated data as a data pointer field. Then a stream
 * of pointers and actual data bytes. The pointer values include
 * an offset to previous data in the stream and the length of the
 *  matching data.
 *
 * The data pattern matching is done on the octets.
 *
 * The data is encoded as 8 field blocks with a compression flag
 * byte at the beginning.  If the bit is set in the compression
 * flag, then that field has a compression field. If it isn't set
 * then the byte is raw data.
 *
 * The compression field is either 2 or 3 bytes long. The length
 * is determined by the length of the matching data, for short
 * matches the match length is encoded in the high nibble of the
 * first byte. Otherwise the third byte of the field contains
 * the match length.
 *
 * First byte -
 * lower 4 bits:
 *		High order nibble of the offset
 *
 * upper 4 bits:
 *		1   = length is in 3rd byte
 *		2-F = length of matching data - 1
 *
 * Second byte -
 *  Lower byte of the source offset.
 *
 * Third byte -
 *  Length of match - 1 if First byte upper nibble = 1, otherwise
 *  this byte isn't added to data stream.
 *
 * Example:
 * 	Uncompressed data (hex):  11 22 22 22 22 33 44 55 66 77
 *
 *
 *	Compression data :
 *			Flag bits:	0x20 (third field is compressed)
 *			Data:	11 22 20 00 33 44 55
 *				/  /  /  /
 *		raw data ------+--+  /	/
 *              (Comp length - 1)<<4+  /
 *		Data offset ----------+
 *
 *	Output data (hex):  20 11 22 20 00 33 44 55 66 77
 *
 * In this example the copy src is one byte behind the copy destination
 * so if appears as if output is being loaded with the source byte.
 *
 */



#include "config.h"

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include "packet-frame.h"
#include <epan/circuit.h>
#include <epan/emem.h>
#include <epan/etypes.h>
#include <epan/nlpid.h>

#define MAX_WIN_BUF_LEN 0x7fff		/* storage size for decompressed data */
#define MAX_WCP_BUF_LEN 2048		/* storage size for decompressed data */
#define FROM_DCE	0x80		/* for direction setting */

typedef struct {

	guint8  *buf_cur;
 	guint8  buffer[MAX_WIN_BUF_LEN];

}wcp_window_t;

typedef struct {
	wcp_window_t recv;
	wcp_window_t send;
} wcp_circuit_data_t;

/*XXX do I really want the length in here  */
typedef struct {

 	guint16  len;
 	guint8  buffer[MAX_WCP_BUF_LEN];

}wcp_pdata_t;


static int proto_wcp = -1;
static int hf_wcp_cmd = -1;
static int hf_wcp_ext_cmd = -1;
static int hf_wcp_seq = -1;
static int hf_wcp_chksum = -1;
static int hf_wcp_tid = -1;
static int hf_wcp_rev = -1;
static int hf_wcp_init = -1;
static int hf_wcp_seq_size = -1;
static int hf_wcp_alg = -1;
static int hf_wcp_alg_cnt = -1;
static int hf_wcp_alg_a = -1;
static int hf_wcp_alg_b = -1;
static int hf_wcp_alg_c = -1;
static int hf_wcp_alg_d = -1;
static int hf_wcp_rexmit = -1;

static int hf_wcp_hist_size = -1;
static int hf_wcp_ppc = -1;
static int hf_wcp_pib = -1;

static int hf_wcp_comp_bits = -1;
static int hf_wcp_comp_marker = -1;
static int hf_wcp_short_len = -1;
static int hf_wcp_long_len = -1;
static int hf_wcp_short_run = -1;
static int hf_wcp_long_run = -1;
static int hf_wcp_offset = -1;

static gint ett_wcp = -1;
static gint ett_wcp_field = -1;

static dissector_handle_t fr_uncompressed_handle;

/*
 * Bits in the address field.
 */
#define	WCP_CMD			0xf0	/* WCP Command */
#define	WCP_EXT_CMD		0x0f	/* WCP Extended Command */
#define	WCP_SEQ			0x0fff	/* WCP Sequence number */
#define	WCP_OFFSET_MASK		0x0fff	/* WCP Pattern source offset */

#define PPC_COMPRESSED_IND       	0x0
#define	PPC_UNCOMPRESSED_IND       	0x1
#define	PPC_TPPC_COMPRESSED_IND		0x2
#define	PPC_TPPC_UNCOMPRESSED_IND  	0x3
#define CONNECT_REQ                	0x4
#define	CONNECT_ACK                	0x5
#define	CONNECT_NAK                	0x6
#define	DISCONNECT_REQ           	0x7
#define	DISCONNECT_ACK             	0x8
#define	INIT_REQ                   	0x9
#define	INIT_ACK                   	0xa
#define	RESET_REQ                  	0xb
#define	RESET_ACK                  	0xc
#define	REXMIT_NAK                 	0xd


static const value_string cmd_string[] = {
	{0, "Compressed Data"},
        {1, "Uncompressed Data"},
        {15, "Extended"},
	{ 0,       NULL }
        };

static const value_string ext_cmd_string[] = {
	{0, "Per Packet Compression"},
	{4, "Connect Req"},
	{5, "Connect Ack"},
	{9, "Init Req"},
	{0x0a, "Init Ack"},

	{ 0,       NULL }
        };



static tvbuff_t *wcp_uncompress( tvbuff_t *src_tvb, int offset, packet_info *pinfo, proto_tree *tree);
static wcp_window_t *get_wcp_window_ptr( packet_info *pinfo);

static void
dissect_wcp_con_req(tvbuff_t *tvb, int offset, proto_tree *tree) {

/* WCP connector request message */

	guint alg_cnt = tvb_get_guint8(tvb, 5);

	proto_tree_add_uint(tree, hf_wcp_tid, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	proto_tree_add_uint(tree, hf_wcp_rev, tvb, offset + 2, 1, tvb_get_guint8(tvb, offset + 2));
	proto_tree_add_uint(tree, hf_wcp_init, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
	proto_tree_add_uint(tree, hf_wcp_seq_size, tvb, offset + 4, 1, tvb_get_guint8(tvb, offset + 4));
	proto_tree_add_uint(tree, hf_wcp_alg_cnt, tvb, offset + 5, 1, alg_cnt);
	proto_tree_add_uint(tree, hf_wcp_alg_a, tvb, offset + 6, 1, tvb_get_guint8(tvb, offset + 6));
	if ( alg_cnt > 1)
		proto_tree_add_uint(tree, hf_wcp_alg_b, tvb, offset + 7, 1, tvb_get_guint8(tvb, offset + 7));
	if ( alg_cnt > 2)
		proto_tree_add_uint(tree, hf_wcp_alg_c, tvb, offset + 8, 1, tvb_get_guint8(tvb, offset + 8));
	if ( alg_cnt > 3)
		proto_tree_add_uint(tree, hf_wcp_alg_d, tvb, offset + 9, 1, tvb_get_guint8(tvb, offset + 9));
}

static void
dissect_wcp_con_ack( tvbuff_t *tvb, int offset, proto_tree *tree){

/* WCP connector ack message */

	proto_tree_add_uint(tree, hf_wcp_tid, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	proto_tree_add_uint(tree, hf_wcp_rev, tvb, offset + 2, 1, tvb_get_guint8(tvb, offset + 2));
	proto_tree_add_uint(tree, hf_wcp_seq_size, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
	proto_tree_add_uint(tree, hf_wcp_alg, tvb, offset + 4, 1, tvb_get_guint8(tvb, offset + 4));
}

static void
dissect_wcp_init( tvbuff_t *tvb, int offset, proto_tree *tree){

/* WCP Initiate Request/Ack message */

	proto_tree_add_uint(tree, hf_wcp_tid, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	proto_tree_add_uint(tree, hf_wcp_rev, tvb, offset + 2, 1, tvb_get_guint8(tvb, offset + 2));
	proto_tree_add_uint(tree, hf_wcp_hist_size, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
	proto_tree_add_uint(tree, hf_wcp_ppc, tvb, offset + 4, 1, tvb_get_guint8(tvb, offset + 4));
	proto_tree_add_uint(tree, hf_wcp_pib, tvb, offset + 5, 1, tvb_get_guint8(tvb, offset + 5));
}


static void
dissect_wcp_reset( tvbuff_t *tvb, int offset, proto_tree *tree){

/* Process WCP Reset Request/Ack message */

	proto_tree_add_uint(tree, hf_wcp_tid, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
}


static void wcp_save_data( tvbuff_t *tvb, packet_info *pinfo){

	wcp_window_t *buf_ptr = 0;
	size_t len;

	/* discard first 2 bytes, header and last byte (check byte) */
	len = tvb_reported_length( tvb)-3;
	buf_ptr = get_wcp_window_ptr( pinfo);

	if (( buf_ptr->buf_cur + len) <= (buf_ptr->buffer + MAX_WIN_BUF_LEN)){
		tvb_memcpy( tvb, buf_ptr->buf_cur, 2, len);
		buf_ptr->buf_cur = buf_ptr->buf_cur + len;

	} else {
		guint8 *buf_end = buf_ptr->buffer + MAX_WIN_BUF_LEN;
		tvb_memcpy( tvb, buf_ptr->buf_cur, 2, buf_end - buf_ptr->buf_cur);
		tvb_memcpy( tvb, buf_ptr->buffer, (gint) (buf_end - buf_ptr->buf_cur-2),
			len - (buf_end - buf_ptr->buf_cur));
		buf_ptr->buf_cur = buf_ptr->buf_cur + len - MAX_WIN_BUF_LEN;
	}

}


static void dissect_wcp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	proto_tree	*wcp_tree;
	proto_item	*ti;
	int		wcp_header_len;
	guint16		temp, cmd, ext_cmd, seq;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WCP");
	col_clear(pinfo->cinfo, COL_INFO);

	temp =tvb_get_ntohs(tvb, 0);

	cmd = (temp & 0xf000) >> 12;
	ext_cmd = (temp & 0x0f00) >> 8;

	if ( cmd == 0xf)
		wcp_header_len= 1;
	else
		wcp_header_len= 2;

	seq = temp & 0x0fff;

/*XXX should test seq to be sure it the last + 1 !! */

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd, cmd_string, "Unknown"));
		if ( cmd == 0xf)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str_const(ext_cmd, ext_cmd_string, "Unknown"));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_wcp, tvb, 0, wcp_header_len, ENC_NA);

		wcp_tree = proto_item_add_subtree(ti, ett_wcp);

		proto_tree_add_uint(wcp_tree, hf_wcp_cmd, tvb, 0, 1, tvb_get_guint8( tvb, 0));
		if ( cmd == 0xf){
			proto_tree_add_uint(wcp_tree, hf_wcp_ext_cmd, tvb, 1, 1,
					tvb_get_guint8( tvb, 0));
			switch (ext_cmd){
			case CONNECT_REQ:
				dissect_wcp_con_req( tvb, 1, wcp_tree);
				break;

			case CONNECT_ACK:
				dissect_wcp_con_ack( tvb, 1, wcp_tree);
				break;
			case INIT_REQ:
			case INIT_ACK:
				dissect_wcp_init( tvb, 1, wcp_tree);
				break;
			case RESET_REQ:
			case RESET_ACK:
				dissect_wcp_reset( tvb, 1, wcp_tree);
				break;
			default:
				break;
			}
		}else {
			proto_tree_add_uint(wcp_tree, hf_wcp_seq,  tvb, 0, 2, seq);
		}
	}
	else {
		wcp_tree = NULL;
	}


					/* exit if done */
	if ( cmd != 1 && cmd != 0 && !(cmd == 0xf && ext_cmd == 0))
		return;

	if ( cmd == 1) {		/* uncompressed data */
		if ( !pinfo->fd->flags.visited){	/* if first pass */
			wcp_save_data( tvb, pinfo);
		}
		next_tvb = tvb_new_subset_remaining(tvb, wcp_header_len);
	}
	else { 		/* cmd == 0 || (cmd == 0xf && ext_cmd == 0) */

		next_tvb = wcp_uncompress( tvb, wcp_header_len, pinfo, wcp_tree);

		if ( !next_tvb){
			proto_tree_add_protocol_format(tree, proto_malformed, tvb, 0, 0,
                             		"[Malformed Frame: Bad WCP compressed data]" );
			return;
		}
	}

	if ( tree)	 		/* add the check byte */
		proto_tree_add_uint(wcp_tree, hf_wcp_chksum, tvb,
			tvb_reported_length( tvb)-1, 1,
		 	tvb_get_guint8( tvb, tvb_reported_length(tvb)-1));

	call_dissector(fr_uncompressed_handle, next_tvb, pinfo, tree);

	return;
}


static guint8 *decompressed_entry( guint8 *src, guint8 *dst, int *len, guint8 * buf_start, guint8 *buf_end){

/* do the decompression for one field */

	guint16 data_offset, data_cnt;
	guint8 tmp = *src;

	data_offset = (*(src++) & 0xf) << 8;	/* get high byte */
	data_offset += *(src++);		/* add next byte */

	if (( tmp & 0xf0) == 0x10){		/* 2 byte count */
		data_cnt = *src;
		data_cnt++;

	}else {					/* one byte count */
		data_cnt = tmp >> 4;
		data_cnt++;
	}


	src = (dst - 1 - data_offset);
	if ( src < buf_start)
		src += MAX_WIN_BUF_LEN;


/*XXX could do some fancy memory moves, later if speed is problem */

	while( data_cnt--){
		*dst = *src;
		if ( ++(*len) >MAX_WCP_BUF_LEN){
			printf("decomp failed, len = %d\n",  *len);

			return NULL;	/* end of buffer error */
		}
		if ( dst++ == buf_end)
			dst = buf_start;
		if ( src++ == buf_end)
			src = buf_start;

	}
	return dst;
}


static
wcp_window_t *get_wcp_window_ptr( packet_info *pinfo){

/* find the circuit for this DLCI, create one if needed */
/* and return the wcp_window data structure pointer */
/* for the direction of this packet */

	circuit_t *circuit;
	wcp_circuit_data_t *wcp_circuit_data;

	circuit = find_circuit( pinfo->ctype, pinfo->circuit_id,
	    pinfo->fd->num);
	if ( !circuit){
		circuit = circuit_new( pinfo->ctype, pinfo->circuit_id,
		    pinfo->fd->num);
	}
	wcp_circuit_data = circuit_get_proto_data(circuit, proto_wcp);
	if ( !wcp_circuit_data){
		wcp_circuit_data = se_alloc(sizeof(wcp_circuit_data_t));
		wcp_circuit_data->recv.buf_cur = wcp_circuit_data->recv.buffer;
		wcp_circuit_data->send.buf_cur = wcp_circuit_data->send.buffer;
		circuit_add_proto_data(circuit, proto_wcp, wcp_circuit_data);
	}
	if (pinfo->pseudo_header->x25.flags & FROM_DCE)
		return &wcp_circuit_data->recv;
	else
		return &wcp_circuit_data->send;
}


static tvbuff_t *wcp_uncompress( tvbuff_t *src_tvb, int offset, packet_info *pinfo, proto_tree *tree) {

/* do the packet data uncompression and load it into the dst buffer */

	proto_tree	*sub_tree;
	proto_item	*ti;

	int len=0, i = -1;
	int cnt = tvb_reported_length( src_tvb)-1;	/* don't include check byte */

	guint8 *dst, *src, *buf_start, *buf_end, comp_flag_bits = 0;
	guint8 src_buf[ MAX_WCP_BUF_LEN];
	tvbuff_t *volatile tvb = 0;
	wcp_window_t *buf_ptr = 0;
	wcp_pdata_t *volatile pdata_ptr;
	volatile gboolean bounds_error = FALSE;

	buf_ptr = get_wcp_window_ptr( pinfo);

	buf_start = buf_ptr->buffer;
	buf_end = buf_start + MAX_WIN_BUF_LEN;

	if (cnt - offset > MAX_WCP_BUF_LEN) {
		if (tree)
			proto_tree_add_text( tree, src_tvb, offset, -1,
				"Compressed data exceeds maximum buffer length (%d > %d)",
				cnt - offset, MAX_WCP_BUF_LEN);
		return NULL;
	}

	src = tvb_memcpy(src_tvb, src_buf, offset, cnt - offset);
	dst = buf_ptr->buf_cur;

	while( offset++ < cnt){

		if ( --i >= 0){
			if ( comp_flag_bits & 0x80){	/* if this is a compressed entry */

				if ( !pinfo->fd->flags.visited){	/* if first pass */
					dst = decompressed_entry( src, dst, &len, buf_start, buf_end);
				}
				if ((*src & 0xf0) == 0x10){
					if ( tree) {
						ti = proto_tree_add_item( tree, hf_wcp_long_run, src_tvb,
							 offset-1, 3, ENC_NA);
						sub_tree = proto_item_add_subtree(ti, ett_wcp_field);
						proto_tree_add_uint(sub_tree, hf_wcp_offset, src_tvb,
							 offset-1, 2, pntohs(src));

						proto_tree_add_item( sub_tree, hf_wcp_long_len, src_tvb,
							 offset+1, 1, ENC_BIG_ENDIAN);
					}
					src += 3;
					offset += 2;
				}else{
					if ( tree) {
						ti = proto_tree_add_item( tree, hf_wcp_short_run, src_tvb,
							 offset - 1, 2, ENC_NA);
						sub_tree = proto_item_add_subtree(ti, ett_wcp_field);
						proto_tree_add_uint( sub_tree, hf_wcp_short_len, src_tvb,
							 offset-1, 1, *src);
						proto_tree_add_uint(sub_tree, hf_wcp_offset, src_tvb,
							 offset-1, 2, pntohs(src));
					}
					src += 2;
					offset += 1;
				}
			}else {
				if ( !pinfo->fd->flags.visited){	/* if first pass */
					*dst = *src;
					if ( dst++ == buf_end)
						dst = buf_start;
				}
				++src;
				++len;

			}

			if ( len >MAX_WCP_BUF_LEN){
				return NULL;
			}

			comp_flag_bits <<= 1;

		}else {	/* compressed data flag */

			comp_flag_bits = *src++;
			if (tree)
				proto_tree_add_uint( tree, hf_wcp_comp_bits,  src_tvb, offset-1, 1,
					comp_flag_bits);

			i = 8;
		}
	}

	if ( pinfo->fd->flags.visited){	/* if not first pass */
					/* get uncompressed data */
		pdata_ptr = p_get_proto_data( pinfo->fd, proto_wcp);

		if ( !pdata_ptr)	/* exit if no data */
			return NULL;
		len = pdata_ptr->len;
	} else {

	/* save the new data as per packet data */
		pdata_ptr = se_alloc(sizeof(wcp_pdata_t));
		memcpy( &pdata_ptr->buffer, buf_ptr->buf_cur,  len);
		pdata_ptr->len = len;

		p_add_proto_data( pinfo->fd, proto_wcp, (void*)pdata_ptr);

		buf_ptr->buf_cur = dst;
	}


        TRY {
                tvb = tvb_new_child_real_data(src_tvb,  pdata_ptr->buffer, pdata_ptr->len, pdata_ptr->len);
        }
        CATCH(BoundsError) {
		DISSECTOR_ASSERT_NOT_REACHED();
        }
        CATCH(ReportedBoundsError) {
		bounds_error = TRUE;
        }
        ENDTRY;

	if (bounds_error) return NULL;

	/* Add new data to the data source list */
	add_new_data_source( pinfo, tvb, "Uncompressed WCP");
	return tvb;

}


void
proto_register_wcp(void)
{
    static hf_register_info hf[] = {
	{ &hf_wcp_cmd,
	  { "Command", "wcp.cmd", FT_UINT8, BASE_HEX, VALS(cmd_string), WCP_CMD,
	  	"Compression Command", HFILL }},
	{ &hf_wcp_ext_cmd,
	  { "Extended Command", "wcp.ext_cmd", FT_UINT8, BASE_HEX, VALS(ext_cmd_string), WCP_EXT_CMD,
	  	"Extended Compression Command", HFILL }},
	{ &hf_wcp_seq,
	  { "SEQ", "wcp.seq", FT_UINT16, BASE_HEX, NULL, WCP_SEQ,
	  	"Sequence Number", HFILL }},
	{ &hf_wcp_chksum,
	  { "Checksum", "wcp.checksum", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Packet Checksum", HFILL }},
	{ &hf_wcp_tid,
	  { "TID", "wcp.tid", FT_UINT16, BASE_DEC, NULL, 0,
	  	NULL, HFILL }},
	{ &hf_wcp_rev,
	  { "Revision", "wcp.rev", FT_UINT8, BASE_DEC, NULL, 0,
	  	NULL, HFILL }},
	{ &hf_wcp_init,
	  { "Initiator", "wcp.init", FT_UINT8, BASE_DEC, NULL, 0,
	  	NULL, HFILL }},
	{ &hf_wcp_seq_size,
	  { "Seq Size", "wcp.seq_size", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Sequence Size", HFILL }},
	{ &hf_wcp_alg_cnt,
	  { "Alg Count", "wcp.alg_cnt", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Algorithm Count", HFILL }},
	{ &hf_wcp_alg_a,
	  { "Alg 1", "wcp.alg1", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Algorithm #1", HFILL }},
	{ &hf_wcp_alg_b,
	  { "Alg 2", "wcp.alg2", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Algorithm #2", HFILL }},
	{ &hf_wcp_alg_c,
	  { "Alg 3", "wcp.alg3", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Algorithm #3", HFILL }},
	{ &hf_wcp_alg_d,
	  { "Alg 4", "wcp.alg4", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Algorithm #4", HFILL }},
	{ &hf_wcp_alg,
	  { "Alg", "wcp.alg", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Algorithm", HFILL }},
	{ &hf_wcp_rexmit,
	  { "Rexmit", "wcp.rexmit", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Retransmit", HFILL }},
	{ &hf_wcp_hist_size,
	  { "History", "wcp.hist", FT_UINT8, BASE_DEC, NULL, 0,
	  	"History Size", HFILL }},
	{ &hf_wcp_ppc,
	  { "PerPackComp", "wcp.ppc", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Per Packet Compression", HFILL }},
	{ &hf_wcp_pib,
	  { "PIB", "wcp.pib", FT_UINT8, BASE_DEC, NULL, 0,
	  	NULL, HFILL }},
	{ &hf_wcp_comp_bits,
	  { "Compress Flag", "wcp.flag", FT_UINT8, BASE_HEX, NULL, 0,
	  	"Compressed byte flag", HFILL }},
	{ &hf_wcp_comp_marker,
	  { "Compress Marker", "wcp.mark", FT_UINT8, BASE_DEC, NULL, 0,
	  	"Compressed marker", HFILL }},
	{ &hf_wcp_offset,
	  { "Source offset", "wcp.off", FT_UINT16, BASE_HEX, NULL, WCP_OFFSET_MASK,
	  	"Data source offset", HFILL }},
	{ &hf_wcp_short_len,
	  { "Compress Length", "wcp.short_len", FT_UINT8, BASE_HEX, NULL, 0xf0,
	  	"Compressed length", HFILL }},
	{ &hf_wcp_long_len,
	  { "Compress Length", "wcp.long_len", FT_UINT8, BASE_HEX, NULL, 0,
	  	"Compressed length", HFILL }},
	{ &hf_wcp_long_run,
	  { "Long Compression", "wcp.long_comp", FT_BYTES, BASE_NONE, NULL, 0,
	  	"Long Compression type", HFILL }},
	{ &hf_wcp_short_run,
	  { "Short Compression", "wcp.short_comp", FT_BYTES, BASE_NONE, NULL, 0,
	  	"Short Compression type", HFILL }},

   };


    static gint *ett[] = {
        &ett_wcp,
	&ett_wcp_field,
    };

    proto_wcp = proto_register_protocol ("Wellfleet Compression", "WCP", "wcp");
    proto_register_field_array (proto_wcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_wcp(void) {
    dissector_handle_t wcp_handle;

    /*
     * Get handle for the Frame Relay (uncompressed) dissector.
     */
    fr_uncompressed_handle = find_dissector("fr_uncompressed");

    wcp_handle = create_dissector_handle(dissect_wcp, proto_wcp);
    dissector_add_uint("fr.ietf", NLPID_COMPRESSED, wcp_handle);
    dissector_add_uint("ethertype",  ETHERTYPE_WCP, wcp_handle);
}
