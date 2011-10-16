/* packet-btobex.c
 * Routines for Bluetooth OBEX dissection
 *
 * Copyright 2010, Allan M. Madsen
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/reassemble.h>
#include "packet-btl2cap.h"
#include "packet-btsdp.h"

/* Initialize the protocol and registered fields */
static int proto_btobex = -1;
static int hf_opcode = -1;
static int hf_response_code = -1;
static int hf_final_flag = -1;
static int hf_length = -1;
static int hf_version = -1;
static int hf_flags = -1;
static int hf_constants = -1;
static int hf_max_pkt_len = -1;
static int hf_set_path_flags_0 = -1;
static int hf_set_path_flags_1 = -1;
static int hf_hdr_id = -1;
static int hf_hdr_length = -1;
static int hf_hdr_val_unicode = -1;
static int hf_hdr_val_byte_seq = -1;
static int hf_hdr_val_byte = -1;
static int hf_hdr_val_long = -1;

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_btobex_fragments = -1;
static int hf_btobex_fragment = -1;
static int hf_btobex_fragment_overlap = -1;
static int hf_btobex_fragment_overlap_conflict = -1;
static int hf_btobex_fragment_multiple_tails = -1;
static int hf_btobex_fragment_too_long_fragment = -1;
static int hf_btobex_fragment_error = -1;
static int hf_btobex_fragment_count = -1;
static int hf_btobex_reassembled_in = -1;
static int hf_btobex_reassembled_length = -1;
static gint ett_btobex_fragment = -1;
static gint ett_btobex_fragments = -1;

static GHashTable *fragment_table;
static GHashTable *reassembled_table;

static const fragment_items btobex_frag_items = {
    &ett_btobex_fragment,
    &ett_btobex_fragments,
    &hf_btobex_fragments,
    &hf_btobex_fragment,
    &hf_btobex_fragment_overlap,
    &hf_btobex_fragment_overlap_conflict,
    &hf_btobex_fragment_multiple_tails,
    &hf_btobex_fragment_too_long_fragment,
    &hf_btobex_fragment_error,
    &hf_btobex_fragment_count,
    &hf_btobex_reassembled_in,
    &hf_btobex_reassembled_length,
    "fragments"
};

/* Initialize the subtree pointers */
static gint ett_btobex = -1;
static gint ett_btobex_hdrs = -1;
static gint ett_btobex_hdr = -1;

/* FIXME: Using a static like this is far from safe */
static guint8 last_opcode[2] = { 1, 1 };

static dissector_handle_t xml_handle;
static dissector_handle_t data_handle;

typedef struct _ext_value_string {
  guint8 value[16];
  const gchar *strptr;
} ext_value_string;

static const ext_value_string target_vals[] = {
    {   { 0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09 }, "Folder Browsing" },
    {   { 0x79, 0x61, 0x35, 0xf0, 0xf0, 0xc5, 0x11, 0xd8, 0x09, 0x66, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 }, "Phone Book Access" },
    {   { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x02, 0xEE, 0x00, 0x00, 0x02 }, "SyncML" },
    {   { 0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7, 0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E }, "Basic Imaging Push" },
    {   { 0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, "Basic Imaging Pull" },
    {   { 0x92, 0x35, 0x33, 0x50, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, "Basic Imaging Advanced Printing" },
    {   { 0x94, 0x01, 0x26, 0xC0, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, "Basic Imaging Automativ Archive" },
    {   { 0x94, 0x7E, 0x74, 0x20, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, "Basic Imaging Remote Camera" },
    {   { 0x94, 0xC7, 0xCD, 0x20, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, "Basic Imaging Remote Display" },
    {   { 0x8E, 0x61, 0xF9, 0x5D, 0x1A, 0x79, 0x11, 0xD4, 0x8E, 0xA4, 0x00, 0x80, 0x5F, 0x9B, 0x98, 0x34 }, "Basic Imaging Referenced Objects" },
    {   { 0x8E, 0x61, 0xF9, 0x5D, 0x1A, 0x79, 0x11, 0xD4, 0x8E, 0xA4, 0x00, 0x80, 0x5F, 0x9B, 0x98, 0x34 }, "Basic Imaging Archived Objects" },
    {   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, NULL },
};

static const value_string version_vals[] = {
    { 0x10, "1.0" },
    { 0x11, "1.1" },
    { 0x12, "1.2" },
    { 0x13, "1.3" },
    { 0x20, "2.0" },
    { 0x21, "2.1" },
    { 0,      NULL }
};

static const true_false_string true_false = {
    "True",
    "False"
};

#define BTOBEX_CODE_VALS_CONNECT    0x00
#define BTOBEX_CODE_VALS_DISCONNECT 0x01
#define BTOBEX_CODE_VALS_PUT        0x02
#define BTOBEX_CODE_VALS_GET        0x03
#define BTOBEX_CODE_VALS_SET_PATH   0x05
#define BTOBEX_CODE_VALS_CONTINUE   0x10
#define BTOBEX_CODE_VALS_ABORT      0x7F
#define BTOBEX_CODE_VALS_MASK       0x7F

static const value_string code_vals[] = {
    { BTOBEX_CODE_VALS_CONNECT, "Connect" },
    { BTOBEX_CODE_VALS_DISCONNECT, "Disconnect" },
    { BTOBEX_CODE_VALS_PUT, "Put" },
    { BTOBEX_CODE_VALS_GET, "Get"},
    { BTOBEX_CODE_VALS_SET_PATH, "Set Path" },
    { BTOBEX_CODE_VALS_CONTINUE, "Continue" },
    { 0x20, "Success" },
    { 0x21, "Created" },
    { 0x22, "Accepted" },
    { 0x23, "Non-Authoritative Information" },
    { 0x24, "No Content" },
    { 0x25, "Reset Content" },
    { 0x26, "Partial Content" },
    { 0x30, "Multiple Choices" },
    { 0x31, "Moved Permanently" },
    { 0x32, "Moved Temporarily" },
    { 0x33, "See Other" },
    { 0x34, "Not Modified" },
    { 0x35, "Use Proxy" },
    { 0x40, "Bad Request" },
    { 0x41, "Unauthorised" },
    { 0x42, "Payment Required" },
    { 0x43, "Forbidden" },
    { 0x44, "Not Found" },
    { 0x45, "Method Not Allowed" },
    { 0x46, "Not Acceptable" },
    { 0x47, "Proxy Authentication Required" },
    { 0x48, "Request Timeout" },
    { 0x49, "Conflict" },
    { 0x4a, "Gone" },
    { 0x4b, "Length Required" },
    { 0x4c, "Precondition Failed" },
    { 0x4d, "Requested Entity Too Large" },
    { 0x4e, "Requested URL Too Large" },
    { 0x4f, "Unsupported Media Type" },
    { 0x50, "Internal Server Error" },
    { 0x51, "Not Implemented" },
    { 0x52, "Bad Gateway" },
    { 0x53, "Service Unavailable" },
    { 0x54, "Gateway Timeout" },
    { 0x55, "HTTP Version Not Supported" },
    { 0x60, "Database Full" },
    { 0x61, "Database Locked" },
    { BTOBEX_CODE_VALS_ABORT, "Abort" },
    { 0,      NULL }
};

static const value_string header_id_vals[] = {
    { 0x01, "Name" },
    { 0x05, "Description" },
    { 0x42, "Type" },
    { 0x44, "Time (ISO8601)" },
    { 0x46, "Target" },
    { 0x47, "HTTP" },
    { 0x48, "Body" },
    { 0x49, "End Of Body" },
    { 0x4a, "Who" },
    { 0x4c, "App. Parameters" },
    { 0x4d, "Auth. Challenge" },
    { 0x4e, "Auth. Response" },
    { 0x4f, "Object Class" },
    { 0xc0, "Count" },
    { 0xc3, "Length" },
    { 0xc4, "Time" },
    { 0xcb, "Connection Id" },
    { 0x30, "User Defined" },
    { 0x31, "User Defined" },
    { 0x32, "User Defined" },
    { 0x33, "User Defined" },
    { 0x34, "User Defined" },
    { 0x35, "User Defined" },
    { 0x36, "User Defined" },
    { 0x37, "User Defined" },
    { 0x38, "User Defined" },
    { 0x39, "User Defined" },
    { 0x3a, "User Defined" },
    { 0x3b, "User Defined" },
    { 0x3c, "User Defined" },
    { 0x3d, "User Defined" },
    { 0x3e, "User Defined" },
    { 0x3f, "User Defined" },
    { 0,      NULL }
};

static void
defragment_init(void)
{
	fragment_table_init(&fragment_table);
	reassembled_table_init(&reassembled_table);
}

static int
is_ascii_str(const guint8 *str, int length)
{
	int i;

	if( (length < 1) || (str[length-1] != '\0') )
		return 0;

	for(i=0; i<length-1; i++) {
		if( (str[i] < 0x20) && (str[i] != 0x0a) ) /* not strict ascii */
		break;
	}

	if(i<(length-1))
		return 0;

	return 1;
}

static int
display_unicode_string(tvbuff_t *tvb, proto_tree *tree, int offset, char **data)
{
	char *str, *p;
	int len;
	int charoffset;
	guint16 character;

	/* display a unicode string from the tree and return new offset */
	/*
	* Get the length of the string.
	*/
	len = 0;
	while (tvb_get_ntohs(tvb, offset + len) != '\0')
		len += 2;

	len += 2;   /* count the '\0' too */

	/*
	* Allocate a buffer for the string; "len" is the length in
	* bytes, not the length in characters.
	*/
	str = ep_alloc(len/2);

	/* - this assumes the string is just ISO 8859-1 */
	charoffset = offset;
	p = str;
	while ((character = tvb_get_ntohs(tvb, charoffset)) != '\0') {
		*p++ = (char) character;
		charoffset += 2;
	}
	*p = '\0';

	if(!is_ascii_str(str, len/2)) {
		*str = '\0';
	}

	proto_tree_add_string(tree, hf_hdr_val_unicode, tvb, offset, len, str);

	if (data)
		*data = str;

	return  offset+len;
}


static int
dissect_headers(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
	proto_tree *hdrs_tree=NULL;
	proto_item *hdrs=NULL;
	proto_tree *hdr_tree=NULL;
	proto_item *hdr=NULL;
	proto_item *handle_item;
	gint item_length = -1;
	guint8 hdr_id, i;

	if(tvb_length_remaining(tvb, offset)>0) {
		hdrs = proto_tree_add_text(tree, tvb, offset, item_length, "Headers");
		hdrs_tree=proto_item_add_subtree(hdrs, ett_btobex_hdrs);
	}
	else {
		return offset;
	}

	while(tvb_length_remaining(tvb, offset)>0) {
		hdr_id = tvb_get_guint8(tvb, offset);

		switch(0xC0 & hdr_id)
		{
			case 0x00: /* null terminated unicode */
				item_length = tvb_get_ntohs(tvb, offset+1);
				break;
			case 0x40:  /* byte sequence */
				item_length = tvb_get_ntohs(tvb, offset+1);
				break;
			case 0x80:  /* 1 byte */
				item_length = 2;
				break;
			case 0xc0:  /* 4 bytes */
				item_length = 5;
				break;
		}

		hdr = proto_tree_add_text(hdrs_tree, tvb, offset, item_length, "%s", val_to_str(hdr_id, header_id_vals, "Unknown"));
		hdr_tree=proto_item_add_subtree(hdr, ett_btobex_hdr);

		proto_tree_add_item(hdr_tree, hf_hdr_id, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		switch(0xC0 & hdr_id)
		{
			case 0x00: /* null terminated unicode */
				{
					proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;

					if( (item_length - 3) > 0 ) {
						char *str;

						display_unicode_string(tvb, hdr_tree, offset, &str);
						proto_item_append_text(hdr_tree, " (\"%s\")", str);
						col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", str);
					}
					else {
						col_append_str(pinfo->cinfo, COL_INFO, " \"\"");
					}

					offset += item_length - 3;
				}
				break;
			case 0x40:  /* byte sequence */
				proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;

				handle_item = proto_tree_add_item(hdr_tree, hf_hdr_val_byte_seq, tvb, offset, item_length - 3, ENC_NA);

				if( ((hdr_id == 0x46) || (hdr_id == 0x4a)) && (item_length == 19) ) { /* target or who */
					for( i=0; target_vals[i].strptr != NULL; i++) {
						if( tvb_memeql(tvb, offset, target_vals[i].value, 16) == 0 ) {
							proto_item_append_text(handle_item, ": %s", target_vals[i].strptr);
							proto_item_append_text(hdr_tree, " (%s)", target_vals[i].strptr);
							col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", target_vals[i].strptr);
						}
					}
				}

				if( !tvb_strneql(tvb, offset, "<?xml", 5) )
				{
					tvbuff_t* next_tvb = tvb_new_subset(tvb, offset, -1, -1);

					call_dissector(xml_handle, next_tvb, pinfo, tree);
				}
				else if(is_ascii_str(tvb_get_ptr(tvb, offset,item_length - 3), item_length - 3))
				{
					proto_item_append_text(hdr_tree, " (\"%s\")", tvb_get_ephemeral_string(tvb, offset,item_length - 3));
					col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", tvb_get_ephemeral_string(tvb, offset,item_length - 3));
				}

				offset += item_length - 3;
				break;
			case 0x80:  /* 1 byte */
				proto_item_append_text(hdr_tree, " (%i)", tvb_get_ntohl(tvb, offset));
				proto_tree_add_item(hdr_tree, hf_hdr_val_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				break;
			case 0xc0:  /* 4 bytes */
				proto_item_append_text(hdr_tree, " (%i)", tvb_get_ntohl(tvb, offset));
				proto_tree_add_item(hdr_tree, hf_hdr_val_long, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				break;
			default:
				break;
		}
	}

	return offset;
}

static void
dissect_btobex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *st;
	fragment_data *frag_msg = NULL;
	gboolean   save_fragmented, complete;
	tvbuff_t* new_tvb = NULL;
	tvbuff_t* next_tvb = NULL;
	guint32 no_of_segments = 0;
	int offset=0;

	save_fragmented = pinfo->fragmented;

	frag_msg = NULL;
	complete = FALSE;

	if( fragment_get(pinfo, pinfo->p2p_dir, fragment_table) ) {
		/* not the first fragment */
		frag_msg = fragment_add_seq_next(tvb, 0, pinfo, pinfo->p2p_dir,
		                        fragment_table, reassembled_table, tvb_length(tvb), TRUE);

		new_tvb = process_reassembled_data(tvb, 0, pinfo,
		                "Reassembled Obex packet", frag_msg, &btobex_frag_items, NULL, tree);

		pinfo->fragmented = TRUE;
	}
	else	{
		if(tvb_length(tvb) < tvb_get_ntohs(tvb, offset+1)) {
			/* first fragment in a sequence */
			no_of_segments = tvb_get_ntohs(tvb, offset+1)/tvb_length(tvb);
			if ( tvb_get_ntohs(tvb, offset+1) > (no_of_segments * tvb_length(tvb)))
			    no_of_segments++;

			frag_msg = fragment_add_seq_next(tvb, 0, pinfo, pinfo->p2p_dir,
			                    fragment_table, reassembled_table, tvb_length(tvb), TRUE);

			fragment_set_tot_len(pinfo, pinfo->p2p_dir, fragment_table, no_of_segments-1);

			new_tvb = process_reassembled_data(tvb, 0, pinfo,
			            "Reassembled Obex packet", frag_msg, &btobex_frag_items, NULL, tree);

			pinfo->fragmented = TRUE;
        	}
		else if( tvb_length(tvb) == tvb_get_ntohs(tvb, offset+1) ) {
			/* non-fragmented */
			complete = TRUE;
			pinfo->fragmented = FALSE;
		}
	}

	if (new_tvb) { /* take it all */
		next_tvb = new_tvb;
		complete = TRUE;
	}
	else { /* make a new subset */
		next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	}

	if( complete ) {
		guint8 code, final_flag;

		/* fully dissectable packet ready */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OBEX");

		ti = proto_tree_add_item(tree, proto_btobex, next_tvb, 0, -1, FALSE);
		st = proto_item_add_subtree(ti, ett_btobex);

		/* op/response code */
		code = tvb_get_guint8(next_tvb, offset) & BTOBEX_CODE_VALS_MASK;
		final_flag = tvb_get_guint8(next_tvb, offset) & 0x80;

		switch (pinfo->p2p_dir) {

		case P2P_DIR_SENT:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Sent ");
			break;

		case P2P_DIR_RECV:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Rcvd ");
			break;

		case P2P_DIR_UNKNOWN:
			break;

		default:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
			    pinfo->p2p_dir);
			break;
		}

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
		                val_to_str(code, code_vals, "Unknown"));

		if( (code < BTOBEX_CODE_VALS_CONTINUE) || (code == BTOBEX_CODE_VALS_ABORT)) {
			proto_tree_add_item(st, hf_opcode, next_tvb, offset, 1, ENC_BIG_ENDIAN);
			if (pinfo->p2p_dir == P2P_DIR_SENT || pinfo->p2p_dir == P2P_DIR_RECV) {
				last_opcode[pinfo->p2p_dir] = code;
			}
        	}
		else	{
			proto_tree_add_item(st, hf_response_code, next_tvb, offset, 1, ENC_BIG_ENDIAN);
        	}
		proto_tree_add_item(st, hf_final_flag, next_tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		/* length */
		proto_tree_add_item(st, hf_length, next_tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		switch(code)
		{
		case BTOBEX_CODE_VALS_CONNECT:
			proto_tree_add_item(st, hf_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			proto_tree_add_item(st, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			proto_tree_add_item(st, hf_max_pkt_len, next_tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			break;

		case BTOBEX_CODE_VALS_PUT:
		case BTOBEX_CODE_VALS_GET:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s",	final_flag==0x80?"final":"continue");
			break;

		case BTOBEX_CODE_VALS_SET_PATH:
			proto_tree_add_item(st, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(st, hf_set_path_flags_0, next_tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(st, hf_set_path_flags_1, next_tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			proto_tree_add_item(st, hf_constants, next_tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;

		case BTOBEX_CODE_VALS_DISCONNECT:
		case BTOBEX_CODE_VALS_ABORT:
			break;

		default:
			{
				guint8 response_opcode = last_opcode[(pinfo->p2p_dir + 1) & 0x01];

				if(response_opcode == BTOBEX_CODE_VALS_CONNECT) {
					proto_tree_add_item(st, hf_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;

					proto_tree_add_item(st, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;

					proto_tree_add_item(st, hf_max_pkt_len, next_tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
				}
			}
			break;
		}

		offset = dissect_headers(st, next_tvb, offset, pinfo);
	}
	else
	{
		/* packet fragment */
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s Obex fragment",
		                pinfo->p2p_dir==P2P_DIR_SENT?"Sent":"Rcvd");

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}

	pinfo->fragmented = save_fragmented;
}


void
proto_register_btobex(void)
{
	static hf_register_info hf[] = {
		{&hf_opcode,
			{"Opcode", "btobex.opcode",
			FT_UINT8, BASE_HEX, VALS(code_vals), BTOBEX_CODE_VALS_MASK,
			"Request Opcode", HFILL}
		},
		{&hf_response_code,
			{"Response Code", "btobex.resp_code",
			FT_UINT8, BASE_HEX, VALS(code_vals), BTOBEX_CODE_VALS_MASK,
			NULL, HFILL}
		},
		{&hf_final_flag,
			{"Final Flag", "btobex.final_flag",
			FT_BOOLEAN, BASE_HEX, TFS(&true_false), 0x80,
			NULL, HFILL}
		},
		{&hf_length,
			{"Packet Length", "btobex.pkt_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL}
		},
		{&hf_version,
			{"Version", "btobex.version",
			FT_UINT8, BASE_HEX, VALS(version_vals), 0x00,
			"Obex Protocol Version", HFILL}
		},
		{&hf_flags,
			{"Flags", "btobex.flags",
			FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL}
		},
		{&hf_constants,
			{"Constants", "btobex.constants",
			FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL}
		},
		{&hf_max_pkt_len,
			{"Max. Packet Length", "btobex.max_pkt_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL}
		},
		{&hf_set_path_flags_0,
			{"Go back one folder (../) first", "btobex.set_path_flags_0",
			FT_BOOLEAN, 8, TFS(&true_false), 0x01,
			NULL, HFILL}
		},
		{&hf_set_path_flags_1,
			{"Do not create folder, if not existing", "btobex.set_path_flags_1",
			FT_BOOLEAN, 8, TFS(&true_false), 0x02,
			NULL, HFILL}
		},
		{&hf_hdr_id,
			{"Header Id", "btobex.hdr_id",
			FT_UINT8, BASE_HEX, VALS(header_id_vals), 0x00,
			NULL, HFILL}
		},
		{&hf_hdr_length,
			{"Length", "btobex.pkt_hdr_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Header Length", HFILL}
		},
		{&hf_hdr_val_unicode,
			{ "Value", "btobex.pkt_hdr_val_uc",
			FT_STRING, BASE_NONE, NULL, 0,
			"Unicode Value", HFILL }
		},
		{&hf_hdr_val_byte_seq,
			{"Value", "btobex.hdr_val_byte_seq",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Byte Value", HFILL}
		},
		{&hf_hdr_val_byte,
			{"Value", "btobex.hdr_val_byte",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Byte Sequence Value", HFILL}
		},
		{&hf_hdr_val_long,
			{"Value", "btobex.hdr_val_long",
			FT_UINT32, BASE_DEC, NULL, 0,
			"4-byte Value", HFILL}
		},

		/* for fragmentation */
		{ &hf_btobex_fragment_overlap,
			{ "Fragment overlap",   "btobex.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Fragment overlaps with other fragments", HFILL }
		},
		{ &hf_btobex_fragment_overlap_conflict,
			{ "Conflicting data in fragment overlap",   "btobex.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Overlapping fragments contained conflicting data", HFILL }
		},
		{ &hf_btobex_fragment_multiple_tails,
			{ "Multiple tail fragments found",  "btobex.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Several tails were found when defragmenting the packet", HFILL }
		},
		{ &hf_btobex_fragment_too_long_fragment,
			{ "Fragment too long",  "btobex.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Fragment contained data past end of packet", HFILL }
		},
		{ &hf_btobex_fragment_error,
			{ "Defragmentation error", "btobex.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
				"Defragmentation error due to illegal fragments", HFILL }
		},
		{ &hf_btobex_fragment_count,
			{ "Fragment count", "btobex.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_btobex_fragment,
			{ "OBEX Fragment", "btobex.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
				"btobex Fragment", HFILL }
		},
		{ &hf_btobex_fragments,
			{ "OBEX Fragments", "btobex.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
				"btobex Fragments", HFILL }
		},
		{ &hf_btobex_reassembled_in,
			{ "Reassembled OBEX in frame", "btobex.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			    "This OBEX frame is reassembled in this frame", HFILL }
		},
		{ &hf_btobex_reassembled_length,
			{ "Reassembled OBEX length", "btobex.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
			"The total length of the reassembled payload", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_btobex,
		&ett_btobex_hdrs,
		&ett_btobex_hdr,
		&ett_btobex_fragment,
		&ett_btobex_fragments
	};

	proto_btobex = proto_register_protocol("Bluetooth OBEX Protocol", "OBEX", "btobex");

	register_dissector("btobex", dissect_btobex, proto_btobex);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btobex, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine(&defragment_init);
}

void
proto_reg_handoff_btobex(void)
{
	dissector_handle_t btobex_handle;

	btobex_handle = find_dissector("btobex");

	/* register in rfcomm and l2cap the profiles/services this dissector should handle */
	dissector_add_uint("btrfcomm.service", BTSDP_OPP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_FTP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_BPP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_BPP_STATUS_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_BIP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_BIP_RESPONDER_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_BIP_AUTO_ARCH_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_BIP_REF_OBJ_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_PBAP_PCE_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_PBAP_PSE_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_PBAP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_MAP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_MAP_ACCESS_SRV_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btrfcomm.service", BTSDP_MAP_NOIYFY_SRV_SERVICE_UUID, btobex_handle);

	dissector_add_uint("btl2cap.service", BTSDP_OPP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_FTP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_BPP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_BPP_STATUS_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_BIP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_BIP_RESPONDER_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_BIP_AUTO_ARCH_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_BIP_REF_OBJ_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_PBAP_PCE_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_PBAP_PSE_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_PBAP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_MAP_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_MAP_ACCESS_SRV_SERVICE_UUID, btobex_handle);
	dissector_add_uint("btl2cap.service", BTSDP_MAP_NOIYFY_SRV_SERVICE_UUID, btobex_handle);

	xml_handle = find_dissector("xml");
	data_handle = find_dissector("data");
}

