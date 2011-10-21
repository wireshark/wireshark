/* packet-dsi.c
 * Routines for dsi packet dissection
 * Copyright 2001, Randy McEoin <rmceoin@pe.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/prefs.h>
#include "packet-tcp.h"
#include "packet-afp.h"

/* The information in this module (DSI) comes from:

  AFP 2.1 & 2.2 documentation, in PDF form, at

http://developer.apple.com/DOCUMENTATION/macos8/pdf/ASAppleTalkFiling2.1_2.2.pdf

  The netatalk source code by Wesley Craig & Adrian Sun

  The Data Stream Interface description from
  http://developer.apple.com/documentation/Networking/Conceptual/AFPClient/AFPClient-6.html

(no longer available, apparently)

  Also, AFP 3.3 documents parts of DSI at:
  http://developer.apple.com/mac/library/documentation/Networking/Conceptual/AFP/Introduction/Introduction.html

 * What a Data Stream Interface packet looks like:
 * 0                               32
 * |-------------------------------|
 * |flags  |command| requestID     |
 * |-------------------------------|
 * |error code/enclosed data offset|
 * |-------------------------------|
 * |total data length              |
 * |-------------------------------|
 * |reserved field                 |
 * |-------------------------------|
 */
#define INET6_ADDRLEN  16

static int proto_dsi = -1;
static int hf_dsi_flags = -1;
static int hf_dsi_command = -1;
static int hf_dsi_requestid = -1;
static int hf_dsi_offset = -1;
static int hf_dsi_error = -1;
static int hf_dsi_length = -1;
static int hf_dsi_reserved = -1;

static gint ett_dsi = -1;

static int hf_dsi_open_type     = -1;
static int hf_dsi_open_len      = -1;
static int hf_dsi_open_quantum  = -1;
static int hf_dsi_replay_cache_size = -1;
static int hf_dsi_open_option   = -1;

static int hf_dsi_attn_flag             = -1;
static int hf_dsi_attn_flag_shutdown    = -1;
static int hf_dsi_attn_flag_crash       = -1;
static int hf_dsi_attn_flag_msg         = -1;
static int hf_dsi_attn_flag_reconnect   = -1;
static int hf_dsi_attn_flag_time        = -1;
static int hf_dsi_attn_flag_bitmap      = -1;

static gint ett_dsi_open        = -1;
static gint ett_dsi_attn        = -1;
static gint ett_dsi_attn_flag   = -1;

static const value_string dsi_attn_flag_vals[] = {
	{0x0, "Reserved" },                                           /* 0000 */
	{0x1, "Reserved" },                                           /* 0001 */
	{0x2, "Server message" },                                     /* 0010 */
	{0x3, "Server notification, cf. extended bitmap" },           /* 0011 */
	{0x4, "Server is shutting down, internal error" },            /* 0100 */
	{0x8, "Server is shutting down" },                            /* 1000 */
	{0x9, "Server disconnects user" },                            /* 1001 */
	{0x10,"Server is shutting down, message" },                   /* 1010 */
	{0x11,"Server is shutting down, message,no reconnect"},       /* 1011 */
	{0,                   NULL } };
static value_string_ext dsi_attn_flag_vals_ext = VALUE_STRING_EXT_INIT(dsi_attn_flag_vals);

static const value_string dsi_open_type_vals[] = {
	{0,   "Server quantum" },
	{1,   "Attention quantum" },
	{2,   "Replay cache size" },
	{0,                   NULL } };

/* status stuff same for asp and afp */
static int hf_dsi_server_name = -1;
static int hf_dsi_utf8_server_name_len = -1;
static int hf_dsi_utf8_server_name = -1;
static int hf_dsi_server_type = -1;
static int hf_dsi_server_vers = -1;
static int hf_dsi_server_uams = -1;
static int hf_dsi_server_icon = -1;
static int hf_dsi_server_directory = -1;

static int hf_dsi_server_flag = -1;
static int hf_dsi_server_flag_copyfile = -1;
static int hf_dsi_server_flag_passwd   = -1;
static int hf_dsi_server_flag_no_save_passwd = -1;
static int hf_dsi_server_flag_srv_msg   = -1;
static int hf_dsi_server_flag_srv_sig   = -1;
static int hf_dsi_server_flag_tcpip     = -1;
static int hf_dsi_server_flag_notify    = -1;
static int hf_dsi_server_flag_reconnect = -1;
static int hf_dsi_server_flag_directory = -1;
static int hf_dsi_server_flag_utf8_name = -1;
static int hf_dsi_server_flag_uuid      = -1;
static int hf_dsi_server_flag_ext_sleep = -1;
static int hf_dsi_server_flag_fast_copy = -1;
static int hf_dsi_server_signature      = -1;

static int hf_dsi_server_addr_len       = -1;
static int hf_dsi_server_addr_type      = -1;
static int hf_dsi_server_addr_value     = -1;

static gint ett_dsi_status = -1;
static gint ett_dsi_uams   = -1;
static gint ett_dsi_vers   = -1;
static gint ett_dsi_addr   = -1;
static gint ett_dsi_addr_line = -1;
static gint ett_dsi_directory = -1;
static gint ett_dsi_utf8_name = -1;
static gint ett_dsi_status_server_flag = -1;

static const value_string afp_server_addr_type_vals[] = {
	{1,   "IP address" },
	{2,   "IP+port address" },
	{3,   "DDP address" },
	{4,   "DNS name" },
	{5,   "IP+port ssh tunnel" },
	{6,   "IP6 address" },
	{7,   "IP6+port address" },
	{0,   NULL } };
value_string_ext afp_server_addr_type_vals_ext = VALUE_STRING_EXT_INIT(afp_server_addr_type_vals);

/* end status stuff */

/* desegmentation of DSI */
static gboolean dsi_desegment = TRUE;

static dissector_handle_t data_handle;
static dissector_handle_t afp_handle;

#define TCP_PORT_DSI      548

#define DSI_BLOCKSIZ       16

/* DSI flags */
#define DSIFL_REQUEST    0x00
#define DSIFL_REPLY      0x01
#define DSIFL_MAX        0x01

/* DSI Commands */
#define DSIFUNC_CLOSE   1       /* DSICloseSession */
#define DSIFUNC_CMD     2       /* DSICommand */
#define DSIFUNC_STAT    3       /* DSIGetStatus */
#define DSIFUNC_OPEN    4       /* DSIOpenSession */
#define DSIFUNC_TICKLE  5       /* DSITickle */
#define DSIFUNC_WRITE   6       /* DSIWrite */
#define DSIFUNC_ATTN    8       /* DSIAttention */
#define DSIFUNC_MAX     8       /* largest command */

static const value_string flag_vals[] = {
	{DSIFL_REQUEST,       "Request" },
	{DSIFL_REPLY,         "Reply" },
	{0,                   NULL } };

static const value_string func_vals[] = {
	{DSIFUNC_CLOSE,       "CloseSession" },
	{DSIFUNC_CMD,         "Command" },
	{DSIFUNC_STAT,        "GetStatus" },
	{DSIFUNC_OPEN,        "OpenSession" },
	{DSIFUNC_TICKLE,      "Tickle" },
	{DSIFUNC_WRITE,       "Write" },
	{ 7,                  "Unknown" },
	{DSIFUNC_ATTN,        "Attention" },
	{0,                   NULL } };
static value_string_ext func_vals_ext = VALUE_STRING_EXT_INIT(func_vals);

static gint
dissect_dsi_open_session(tvbuff_t *tvb, proto_tree *dsi_tree, gint offset, gint dsi_length)
{
	proto_tree      *tree;
	proto_item	*ti;
	guint8		type;
	guint8		len;

	ti = proto_tree_add_text(dsi_tree, tvb, offset, -1, "Open Session");
	tree = proto_item_add_subtree(ti, ett_dsi_open);

	while( dsi_length >2 ) {

		type = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_dsi_open_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_dsi_open_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch (type) {
			case 0:
				proto_tree_add_item(tree, hf_dsi_open_quantum, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;
			case 1:
				proto_tree_add_item(tree, hf_dsi_open_quantum, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;
			case 2:
				proto_tree_add_item(tree, hf_dsi_replay_cache_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;
			default:
				proto_tree_add_item(tree, hf_dsi_open_option, tvb, offset, len, ENC_NA);
		}

		dsi_length -= len + 2;

		offset += len;
	}
	return offset;
}

static gint
dissect_dsi_attention(tvbuff_t *tvb, proto_tree *dsi_tree, gint offset)
{
	proto_tree      *tree;
	proto_item	*ti;
	guint16		flag;

	if (!tvb_reported_length_remaining(tvb,offset))
		return offset;

	flag = tvb_get_ntohs(tvb, offset);
	ti = proto_tree_add_text(dsi_tree, tvb, offset, -1, "Attention");
	tree = proto_item_add_subtree(ti, ett_dsi_attn);

	ti = proto_tree_add_item(tree, hf_dsi_attn_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
	tree = proto_item_add_subtree(ti, ett_dsi_attn_flag);
	proto_tree_add_item(tree, hf_dsi_attn_flag_shutdown, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsi_attn_flag_crash, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsi_attn_flag_msg, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsi_attn_flag_reconnect, tvb, offset, 2, ENC_BIG_ENDIAN);
	/* FIXME */
	if ((flag & 0xf000) != 0x3000)
		proto_tree_add_item(tree, hf_dsi_attn_flag_time, tvb, offset, 2, ENC_BIG_ENDIAN);
	else
		proto_tree_add_item(tree, hf_dsi_attn_flag_bitmap, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	return offset;
}

/* -----------------------------
	from netatalk/etc/afpd/status.c
*/
static gint
dissect_dsi_reply_get_status(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	proto_tree      *sub_tree;
	proto_item	*ti;

	guint16 ofs;
	guint16 flag;
	guint16 sign_ofs = 0;
	guint16 adr_ofs = 0;
	guint16 dir_ofs = 0;
	guint16 utf_ofs = 0;
	guint8	nbe;
	guint8  len;
	guint8  i;

	if (!tree)
		return offset;

	ti = proto_tree_add_text(tree, tvb, offset, -1, "Get Status");
	tree = proto_item_add_subtree(ti, ett_dsi_status);

	ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_MACHOFF);
	proto_tree_add_text(tree, tvb, offset +AFPSTATUS_MACHOFF, 2, "Machine offset: %d", ofs);

	ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_VERSOFF);
	proto_tree_add_text(tree, tvb, offset +AFPSTATUS_VERSOFF, 2, "Version offset: %d", ofs);

	ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_UAMSOFF);
	proto_tree_add_text(tree, tvb, offset +AFPSTATUS_UAMSOFF, 2, "UAMS offset: %d", ofs);

	ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_ICONOFF);
	proto_tree_add_text(tree, tvb, offset +AFPSTATUS_ICONOFF, 2, "Icon offset: %d", ofs);

	ofs = offset +AFPSTATUS_FLAGOFF;
	ti = proto_tree_add_item(tree, hf_dsi_server_flag, tvb, ofs, 2, ENC_BIG_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_dsi_status_server_flag);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_copyfile      , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_passwd        , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_no_save_passwd, tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_srv_msg       , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_srv_sig       , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_tcpip         , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_notify        , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_reconnect     , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_directory     , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_utf8_name     , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_uuid          , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_ext_sleep     , tvb, ofs, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_dsi_server_flag_fast_copy     , tvb, ofs, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_dsi_server_name, tvb, offset +AFPSTATUS_PRELEN, 1, ENC_ASCII|ENC_BIG_ENDIAN);

	flag = tvb_get_ntohs(tvb, ofs);
	if ((flag & AFPSRVRINFO_SRVSIGNATURE)) {
		ofs = offset +AFPSTATUS_PRELEN +tvb_get_guint8(tvb, offset +AFPSTATUS_PRELEN) +1;
		if ((ofs & 1))
			ofs++;

		sign_ofs = tvb_get_ntohs(tvb, ofs);
		proto_tree_add_text(tree, tvb, ofs, 2, "Signature offset: %d", sign_ofs);
		sign_ofs += offset;

		if ((flag & AFPSRVRINFO_TCPIP)) {
			ofs += 2;
			adr_ofs =  tvb_get_ntohs(tvb, ofs);
			proto_tree_add_text(tree, tvb, ofs, 2, "Network address offset: %d", adr_ofs);
			adr_ofs += offset;
		}

		if ((flag & AFPSRVRINFO_SRVDIRECTORY)) {
			ofs += 2;
			dir_ofs =  tvb_get_ntohs(tvb, ofs);
			proto_tree_add_text(tree, tvb, ofs, 2, "Directory services offset: %d", dir_ofs);
			dir_ofs += offset;
		}
		if ((flag & AFPSRVRINFO_SRVUTF8)) {
			ofs += 2;
			utf_ofs =  tvb_get_ntohs(tvb, ofs);
			proto_tree_add_text(tree, tvb, ofs, 2, "UTF8 server name offset: %d", utf_ofs);
			utf_ofs += offset;
		}
	}

	ofs = offset +tvb_get_ntohs(tvb, offset +AFPSTATUS_MACHOFF);
	if (ofs)
		proto_tree_add_item(tree, hf_dsi_server_type, tvb, ofs, 1, ENC_ASCII|ENC_BIG_ENDIAN);

	ofs = offset +tvb_get_ntohs(tvb, offset +AFPSTATUS_VERSOFF);
	if (ofs) {
		nbe = tvb_get_guint8(tvb, ofs);
		ti = proto_tree_add_text(tree, tvb, ofs, 1, "Version list: %d", nbe);
		ofs++;
		sub_tree = proto_item_add_subtree(ti, ett_dsi_vers);
		for (i = 0; i < nbe; i++) {
			len = tvb_get_guint8(tvb, ofs);
			proto_tree_add_item(sub_tree, hf_dsi_server_vers, tvb, ofs, 1, ENC_ASCII|ENC_BIG_ENDIAN);
			ofs += len + 1;
		}
	}

	ofs = offset +tvb_get_ntohs(tvb, offset +AFPSTATUS_UAMSOFF);
	if (ofs) {
		nbe = tvb_get_guint8(tvb, ofs);
		ti = proto_tree_add_text(tree, tvb, ofs, 1, "UAMS list: %d", nbe);
		ofs++;
		sub_tree = proto_item_add_subtree(ti, ett_dsi_uams);
		for (i = 0; i < nbe; i++) {
			len = tvb_get_guint8(tvb, ofs);
			proto_tree_add_item(sub_tree, hf_dsi_server_uams, tvb, ofs, 1, ENC_ASCII|ENC_BIG_ENDIAN);
			ofs += len + 1;
		}
	}

	ofs = offset +tvb_get_ntohs(tvb, offset +AFPSTATUS_ICONOFF);
	if (ofs)
		proto_tree_add_item(tree, hf_dsi_server_icon, tvb, ofs, 256, ENC_NA);

	if (sign_ofs) {
		proto_tree_add_item(tree, hf_dsi_server_signature, tvb, sign_ofs, 16, ENC_NA);
	}

	if (adr_ofs) {
		proto_tree *adr_tree;
		unsigned char *tmp;
		guint16 net;
		guint8  node;
		guint16 port;

		ofs = adr_ofs;
		nbe = tvb_get_guint8(tvb, ofs);
		ti = proto_tree_add_text(tree, tvb, ofs, 1, "Address list: %d", nbe);
		ofs++;
		adr_tree = proto_item_add_subtree(ti, ett_dsi_addr);
		for (i = 0; i < nbe; i++) {
			guint8 type;

			len = tvb_get_guint8(tvb, ofs);
			type =  tvb_get_guint8(tvb, ofs +1);
			switch (type) {
			case 1:	/* IP */
				ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ip: %s", tvb_ip_to_str(tvb, ofs+2));
				break;
			case 2: /* IP + port */
				port = tvb_get_ntohs(tvb, ofs+6);
				ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ip %s:%d", tvb_ip_to_str(tvb, ofs+2), port);
				break;
			case 3: /* DDP, atalk_addr_to_str want host order not network */
				net  = tvb_get_ntohs(tvb, ofs+2);
				node = tvb_get_guint8(tvb, ofs +4);
				port = tvb_get_guint8(tvb, ofs +5);
				ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ddp: %u.%u:%u",
					net, node, port);
				break;
			case 4: /* DNS */
			case 5: /* SSH tunnel */
				if (len > 2) {
					tmp = tvb_get_ephemeral_string(tvb, ofs +2, len -2);
					ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "%s: %s",
								(type==4)?"dns":"ssh tunnel", tmp);
					break;
				}
				else {
					ti = proto_tree_add_text(adr_tree, tvb, ofs, len,"Malformed address type %d", type);
				}
				break;
			case 6: /* IP6 */
				ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ip6: %s",
				                tvb_ip6_to_str(tvb, ofs+2));
				break;
			case 7: /* IP6 + 2bytes port */
				port = tvb_get_ntohs(tvb, ofs+ 2+INET6_ADDRLEN);
				ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ip6 %s:%d",
						tvb_ip6_to_str(tvb, ofs+2), port);
				break;
			default:
				ti = proto_tree_add_text(adr_tree, tvb, ofs, len,"Unknown type : %d", type);
				break;
			}
			len -= 2;
			sub_tree = proto_item_add_subtree(ti,ett_dsi_addr_line);
			proto_tree_add_item(sub_tree, hf_dsi_server_addr_len, tvb, ofs, 1, ENC_BIG_ENDIAN);
			ofs++;
			proto_tree_add_item(sub_tree, hf_dsi_server_addr_type, tvb, ofs, 1, ENC_BIG_ENDIAN);
			ofs++;
			proto_tree_add_item(sub_tree, hf_dsi_server_addr_value,tvb, ofs, len, ENC_NA);
			ofs += len;
		}
	}

	if (dir_ofs) {
		ofs = dir_ofs;
		nbe = tvb_get_guint8(tvb, ofs);
		ti = proto_tree_add_text(tree, tvb, ofs, 1, "Directory services list: %d", nbe);
		ofs++;
		sub_tree = proto_item_add_subtree(ti, ett_dsi_directory);
		for (i = 0; i < nbe; i++) {
			len = tvb_get_guint8(tvb, ofs);
			proto_tree_add_item(sub_tree, hf_dsi_server_directory, tvb, ofs, 1, ENC_ASCII|ENC_BIG_ENDIAN);
			ofs += len + 1;
		}
	}
	if (utf_ofs) {
		guint16 ulen;
		char *tmp;

		ofs = utf_ofs;
		ulen = tvb_get_ntohs(tvb, ofs);
		tmp = tvb_get_ephemeral_string(tvb, ofs + 2, ulen);
		ti = proto_tree_add_text(tree, tvb, ofs, ulen + 2, "UTF8 server name: %s", tmp);
		sub_tree = proto_item_add_subtree(ti, ett_dsi_utf8_name);
		proto_tree_add_uint(sub_tree, hf_dsi_utf8_server_name_len, tvb, ofs, 2, ulen);
		ofs += 2;
		proto_tree_add_string(sub_tree, hf_dsi_utf8_server_name, tvb, ofs, ulen, tmp);
		ofs += ulen;
	}

	return offset;
}

static void
dissect_dsi_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *dsi_tree;
	proto_item	*ti;
	guint8		dsi_flags,dsi_command;
	guint16		dsi_requestid;
	gint32		dsi_code;
	guint32		dsi_length;
	guint32		dsi_reserved;
	struct		aspinfo aspinfo;
	gint            col_info;


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSI");
	col_info = check_col(pinfo->cinfo, COL_INFO);
	if (col_info)
		col_clear(pinfo->cinfo, COL_INFO);

	dsi_flags = tvb_get_guint8(tvb, 0);
	dsi_command = tvb_get_guint8(tvb, 1);
	dsi_requestid = tvb_get_ntohs(tvb, 2);
	dsi_code = tvb_get_ntohl(tvb, 4);
	dsi_length = tvb_get_ntohl(tvb, 8);
	dsi_reserved = tvb_get_ntohl(tvb, 12);

	if (col_info) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s (%u)",
			val_to_str(dsi_flags, flag_vals,
				   "Unknown flag (0x%02x)"),
			val_to_str_ext(dsi_command, &func_vals_ext,
				   "Unknown function (0x%02x)"),
			dsi_requestid);
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_dsi, tvb, 0, -1, ENC_NA);
		dsi_tree = proto_item_add_subtree(ti, ett_dsi);

		proto_tree_add_uint(dsi_tree, hf_dsi_flags, tvb,
			0, 1, dsi_flags);
		proto_tree_add_uint(dsi_tree, hf_dsi_command, tvb,
			1, 1, dsi_command);
		proto_tree_add_uint(dsi_tree, hf_dsi_requestid, tvb,
			2, 2, dsi_requestid);
		switch (dsi_flags) {

		case DSIFL_REQUEST:
			proto_tree_add_int(dsi_tree, hf_dsi_offset, tvb,
				4, 4, dsi_code);
			break;

		case DSIFL_REPLY:
			proto_tree_add_int(dsi_tree, hf_dsi_error, tvb,
				4, 4, dsi_code);
			break;
		}
		proto_tree_add_uint_format(dsi_tree, hf_dsi_length, tvb,
			8, 4, dsi_length,
			"Length: %u bytes", dsi_length);
		proto_tree_add_uint(dsi_tree, hf_dsi_reserved, tvb,
			12, 4, dsi_reserved);
	}
	else
		dsi_tree = tree;
	switch (dsi_command) {
	case DSIFUNC_OPEN:
		if (tree) {
			dissect_dsi_open_session(tvb, dsi_tree, DSI_BLOCKSIZ, dsi_length);
		}
		break;
	case DSIFUNC_ATTN:
		if (tree) {
			dissect_dsi_attention(tvb, dsi_tree, DSI_BLOCKSIZ);
		}
		break;
	case DSIFUNC_STAT:
		if (tree && (dsi_flags == DSIFL_REPLY)) {
			dissect_dsi_reply_get_status(tvb, dsi_tree, DSI_BLOCKSIZ);
		}
		break;
	case DSIFUNC_CMD:
	case DSIFUNC_WRITE:
		{
			tvbuff_t   *new_tvb;
			void* pd_save;
			int len = tvb_reported_length_remaining(tvb,DSI_BLOCKSIZ);

			aspinfo.reply = (dsi_flags == DSIFL_REPLY);
			aspinfo.command = dsi_command;
			aspinfo.seq = dsi_requestid;
			aspinfo.code = dsi_code;
			pd_save = pinfo->private_data;
			pinfo->private_data = &aspinfo;
	  		proto_item_set_len(dsi_tree, DSI_BLOCKSIZ);

			new_tvb = tvb_new_subset(tvb, DSI_BLOCKSIZ,-1,len);
			call_dissector(afp_handle, new_tvb, pinfo, tree);
			pinfo->private_data = pd_save;
		}
		break;
	default:
		if (tree) {
			call_dissector(data_handle,
				       tvb_new_subset_remaining(tvb, DSI_BLOCKSIZ),
				       pinfo, dsi_tree);
		}
		break;
	}
}

static guint
get_dsi_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 plen;
	guint8	dsi_flags,dsi_command;

	dsi_flags = tvb_get_guint8(tvb, offset);
	dsi_command = tvb_get_guint8(tvb, offset+ 1);
	if ( dsi_flags > DSIFL_MAX || !dsi_command || dsi_command > DSIFUNC_MAX)
	{
	    /* it's not a known dsi pdu start sequence */
	    return tvb_length_remaining(tvb, offset);
	}

	/*
	 * Get the length of the DSI packet.
	 */
	plen = tvb_get_ntohl(tvb, offset+8);

	/*
	 * That length doesn't include the length of the header itself;
	 * add that in.
	 */
	return plen + 16;
}

static void
dissect_dsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, dsi_desegment, 12,
	    get_dsi_pdu_len, dissect_dsi_packet);
}

void
proto_register_dsi(void)
{

	static hf_register_info hf[] = {
		{ &hf_dsi_flags,
		  { "Flags",            "dsi.flags",
		    FT_UINT8, BASE_HEX, VALS(flag_vals), 0x0,
		    "Indicates request or reply.", HFILL }},

		{ &hf_dsi_command,
		  { "Command",          "dsi.command",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &func_vals_ext, 0x0,
		    "Represents a DSI command.", HFILL }},

		{ &hf_dsi_requestid,
		  { "Request ID",       "dsi.requestid",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Keeps track of which request this is.  Replies must match a Request.  IDs must be generated in sequential order.", HFILL }},

		{ &hf_dsi_offset,
		  { "Data offset",      "dsi.data_offset",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_error,
		  { "Error code",       "dsi.error_code",
		    FT_INT32, BASE_DEC|BASE_EXT_STRING, &asp_error_vals_ext, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_length,
		  { "Length",           "dsi.length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Total length of the data that follows the DSI header.", HFILL }},

		{ &hf_dsi_reserved,
		  { "Reserved",         "dsi.reserved",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Reserved for future use.  Should be set to zero.", HFILL }},
		/* asp , afp */
		{ &hf_dsi_utf8_server_name_len,
		  { "Length",          "dsi.utf8_server_name_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "UTF8 server name length.", HFILL }},
		{ &hf_dsi_utf8_server_name,
		  { "UTF8 Server name",         "dsi.utf8_server_name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_server_name,
		  { "Server name",         "dsi.server_name",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_server_type,
		  { "Server type",         "dsi.server_type",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_server_vers,
		  { "AFP version",         "dsi.server_vers",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_server_uams,
		  { "UAM",         "dsi.server_uams",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_server_icon,
		  { "Icon bitmap",         "dsi.server_icon",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Server icon bitmap", HFILL }},

		{ &hf_dsi_server_directory,
		  { "Directory service",         "dsi.server_directory",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "Server directory service", HFILL }},

		{ &hf_dsi_server_signature,
		  { "Server signature",         "dsi.server_signature",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_server_flag,
		  { "Flag",         "dsi.server_flag",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    "Server capabilities flag", HFILL }},
		{ &hf_dsi_server_flag_copyfile,
		  { "Support copyfile",      "dsi.server_flag.copyfile",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_COPY,
		    "Server support copyfile", HFILL }},
		{ &hf_dsi_server_flag_passwd,
		  { "Support change password",      "dsi.server_flag.passwd",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_PASSWD,
		    "Server support change password", HFILL }},
		{ &hf_dsi_server_flag_no_save_passwd,
		  { "Don't allow save password",      "dsi.server_flag.no_save_passwd",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_NOSAVEPASSWD,
		    NULL, HFILL }},
		{ &hf_dsi_server_flag_srv_msg,
		  { "Support server message",      "dsi.server_flag.srv_msg",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVMSGS,
		    NULL, HFILL }},
		{ &hf_dsi_server_flag_srv_sig,
		  { "Support server signature",      "dsi.server_flag.srv_sig",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVSIGNATURE,
		    NULL, HFILL }},
		{ &hf_dsi_server_flag_tcpip,
		  { "Support TCP/IP",      "dsi.server_flag.tcpip",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_TCPIP,
		    "Server support TCP/IP", HFILL }},
		{ &hf_dsi_server_flag_notify,
		  { "Support server notifications",      "dsi.server_flag.notify",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVNOTIFY,
		    "Server support notifications", HFILL }},
		{ &hf_dsi_server_flag_reconnect,
		  { "Support server reconnect",      "dsi.server_flag.reconnect",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVRECONNECT,
		    "Server support reconnect", HFILL }},
		{ &hf_dsi_server_flag_directory,
		  { "Support directory services",      "dsi.server_flag.directory",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVDIRECTORY,
		    "Server support directory services", HFILL }},
		{ &hf_dsi_server_flag_utf8_name,
		  { "Support UTF8 server name",      "dsi.server_flag.utf8_name",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVUTF8,
		    "Server support UTF8 server name", HFILL }},
		{ &hf_dsi_server_flag_uuid,
		  { "Support UUIDs",      "dsi.server_flag.uuids",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_UUID,
		    "Server supports UUIDs", HFILL }},
		{ &hf_dsi_server_flag_ext_sleep,
		  { "Support extended sleep",      "dsi.server_flag.ext_sleep",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_EXT_SLEEP,
		    "Server supports extended sleep", HFILL }},
		{ &hf_dsi_server_flag_fast_copy,
		  { "Support fast copy",      "dsi.server_flag.fast_copy",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_FASTBOZO,
		    "Server support fast copy", HFILL }},


		{ &hf_dsi_server_addr_len,
		  { "Length",          "dsi.server_addr.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Address length.", HFILL }},

		{ &hf_dsi_server_addr_type,
		  { "Type",          "dsi.server_addr.type",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &afp_server_addr_type_vals_ext, 0x0,
		    "Address type.", HFILL }},

		{ &hf_dsi_server_addr_value,
		  { "Value",          "dsi.server_addr.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Address value", HFILL }},

		{ &hf_dsi_open_type,
		  { "Option",          "dsi.open_type",
		    FT_UINT8, BASE_DEC, VALS(dsi_open_type_vals), 0x0,
		    "Open session option type.", HFILL }},

		{ &hf_dsi_open_len,
		  { "Length",          "dsi.open_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Open session option len", HFILL }},

		{ &hf_dsi_open_quantum,
		  { "Quantum",       "dsi.open_quantum",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Server/Attention quantum", HFILL }},

		{ &hf_dsi_replay_cache_size,
		  { "Replay",       "dsi.replay_cache",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Replay cache size", HFILL }},

		{ &hf_dsi_open_option,
		  { "Option",          "dsi.open_option",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Open session options (undecoded)", HFILL }},

		{ &hf_dsi_attn_flag,
		  { "Flags",          "dsi.attn_flag",
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dsi_attn_flag_vals_ext, 0xf000,
		    "Server attention flag", HFILL }},
		{ &hf_dsi_attn_flag_shutdown,
		  { "Shutdown",      "dsi.attn_flag.shutdown",
		    FT_BOOLEAN, 16, NULL, 1<<15,
		    "Attention flag, server is shutting down", HFILL }},
		{ &hf_dsi_attn_flag_crash,
		  { "Crash",      "dsi.attn_flag.crash",
		    FT_BOOLEAN, 16, NULL, 1<<14,
		    "Attention flag, server crash bit", HFILL }},
		{ &hf_dsi_attn_flag_msg,
		  { "Message",      "dsi.attn_flag.msg",
		    FT_BOOLEAN, 16, NULL, 1<<13,
		    "Attention flag, server message bit", HFILL }},
		{ &hf_dsi_attn_flag_reconnect,
		  { "Don't reconnect",      "dsi.attn_flag.reconnect",
		    FT_BOOLEAN, 16, NULL, 1<<12,
		    "Attention flag, don't reconnect bit", HFILL }},
		{ &hf_dsi_attn_flag_time,
		  { "Minutes",          "dsi.attn_flag.time",
		    FT_UINT16, BASE_DEC, NULL, 0xfff,
		    "Number of minutes", HFILL }},
		{ &hf_dsi_attn_flag_bitmap,
		  { "Bitmap",          "dsi.attn_flag.time",
		    FT_UINT16, BASE_HEX, NULL, 0xfff,
		    "Attention extended bitmap", HFILL }},

	};

	static gint *ett[] = {
		&ett_dsi,
		&ett_dsi_open,
		&ett_dsi_attn,
		&ett_dsi_attn_flag,
		/* asp afp */
		&ett_dsi_status,
		&ett_dsi_status_server_flag,
		&ett_dsi_vers,
		&ett_dsi_uams,
		&ett_dsi_addr,
		&ett_dsi_addr_line,
		&ett_dsi_directory,
		&ett_dsi_utf8_name,
	};
	module_t *dsi_module;

	proto_dsi = proto_register_protocol("Data Stream Interface", "DSI", "dsi");
	proto_register_field_array(proto_dsi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	dsi_module = prefs_register_protocol(proto_dsi, NULL);
	prefs_register_bool_preference(dsi_module, "desegment",
				       "Reassemble DSI messages spanning multiple TCP segments",
				       "Whether the DSI dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &dsi_desegment);
}

void
proto_reg_handoff_dsi(void)
{
	dissector_handle_t dsi_handle;

	dsi_handle = create_dissector_handle(dissect_dsi, proto_dsi);
	dissector_add_uint("tcp.port", TCP_PORT_DSI, dsi_handle);

	data_handle = find_dissector("data");
	afp_handle = find_dissector("afp");
}
