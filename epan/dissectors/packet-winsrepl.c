/*
 * packet-winsrepl.c
 *
 * Routines for WINS Replication packet dissection
 *
 * Copyright 2005 Stefan Metzmacher <metze@samba.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <time.h>
#include <glib.h>
#include <ctype.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#include "packet-windows-common.h"
#include "packet-netbios.h"

#include "packet-tcp.h"

static gboolean winsrepl_reassemble = TRUE;

static int proto_winsrepl = -1;

static int hf_winsrepl_size = -1;
static int hf_winsrepl_opcode = -1;
static int hf_winsrepl_assoc_ctx = -1;
static int hf_winsrepl_mess_type = -1;

static int hf_winsrepl_start_minor_version = -1;
static int hf_winsrepl_start_major_version = -1;

static int hf_winsrepl_stop_reason = -1;

static int hf_winsrepl_replication_command = -1;

static int hf_winsrepl_owner_address = -1;
static int hf_winsrepl_owner_max_version = -1;
static int hf_winsrepl_owner_min_version = -1;
static int hf_winsrepl_owner_type = -1;

static int hf_winsrepl_table_partner_count = -1;
static int hf_winsrepl_table_initiator = -1;

static int hf_winsrepl_ip_owner = -1;
static int hf_winsrepl_ip_ip = -1;
static int hf_winsrepl_addr_list_num_ips = -1;

static int hf_winsrepl_name_len = -1;
static int hf_winsrepl_name_flags = -1;
static int hf_winsrepl_name_flags_rectype = -1;
static int hf_winsrepl_name_flags_recstate = -1;
static int hf_winsrepl_name_flags_local = -1;
static int hf_winsrepl_name_flags_hosttype = -1;
static int hf_winsrepl_name_flags_static = -1;
static int hf_winsrepl_name_group_flag = -1;
static int hf_winsrepl_name_version_id = -1;
static int hf_winsrepl_name_unknown = -1;

static int hf_winsrepl_reply_num_names = -1;

static gint ett_winsrepl = -1;

static gint ett_winsrepl_start = -1;
static gint ett_winsrepl_stop = -1;
static gint ett_winsrepl_replication = -1;

static gint ett_winsrepl_owner = -1;
static gint ett_winsrepl_table_reply = -1;

static gint ett_winsrepl_ip = -1;
static gint ett_winsrepl_addr_list = -1;

static gint ett_winsrepl_name = -1;
static gint ett_winsrepl_send_reply = -1;

static gint ett_winsrepl_flags = -1;

#define WINS_REPLICATION_PORT	( 42 )
#define WREPL_OPCODE_BITS	( 0x7800 )

enum wrepl_replication_cmd {
	WREPL_REPL_TABLE_QUERY=0,
	WREPL_REPL_TABLE_REPLY=1,
	WREPL_REPL_SEND_REQUEST=2,
	WREPL_REPL_SEND_REPLY=3,
	WREPL_REPL_UPDATE=4,
	WREPL_REPL_UPDATE2=5,
	WREPL_REPL_INFORM=8,
	WREPL_REPL_INFORM2=9
};

enum wrepl_mess_type {
	WREPL_START_ASSOCIATION=0,
	WREPL_START_ASSOCIATION_REPLY=1,
	WREPL_STOP_ASSOCIATION=2,
	WREPL_REPLICATION=3
};

static unsigned int glb_winsrepl_tcp_port = WINS_REPLICATION_PORT;

static const value_string replication_cmd_vals[] = {
	{WREPL_REPL_TABLE_QUERY,	"WREPL_REPL_TABLE_QUERY"},
	{WREPL_REPL_TABLE_REPLY,	"WREPL_REPL_TABLE_REPLY"},
	{WREPL_REPL_SEND_REQUEST,	"WREPL_REPL_SEND_REQUEST"},
	{WREPL_REPL_SEND_REPLY,		"WREPL_REPL_SEND_REPLY"},
	{WREPL_REPL_UPDATE,		"WREPL_REPL_UPDATE"},
	{WREPL_REPL_UPDATE2,		"WREPL_REPL_UPDATE2"},
	{WREPL_REPL_INFORM,		"WREPL_REPL_INFORM"},
	{WREPL_REPL_INFORM2,		"WREPL_REPL_INFORM2"},
	{0, NULL}
};

static const value_string message_type_vals[] = {
	{WREPL_START_ASSOCIATION,	"WREPL_START_ASSOCIATION"},
	{WREPL_START_ASSOCIATION_REPLY,	"WREPL_START_ASSOCIATION_REPLY"},
	{WREPL_STOP_ASSOCIATION,	"WREPL_STOP_ASSOCIATION"},
	{WREPL_REPLICATION,		"WREPL_REPLICATION"},
	{0, NULL}
};

#define WREPL_NAME_TYPE_MASK		0x03

#define WREPL_NAME_TYPE_UNIQUE		0x00
#define WREPL_NAME_TYPE_NORMAL_GROUP	0x01
#define WREPL_NAME_TYPE_SPECIAL_GROUP	0x02
#define WREPL_NAME_TYPE_MULTIHOMED	0x03

static const value_string rectype_vals[] = {
	{WREPL_NAME_TYPE_UNIQUE,	"Unique"},
	{WREPL_NAME_TYPE_NORMAL_GROUP,	"Normal group"},
	{WREPL_NAME_TYPE_SPECIAL_GROUP,	"Special group"},
	{WREPL_NAME_TYPE_MULTIHOMED,	"Multihomed"},
	{0, NULL}
};

static const value_string recstate_vals[] = {
	{0x00,	"Active"},
	{0x01,	"Released"},
	{0x02,	"Tombstoned"},
	{0x03,	"Deleted"},
	{0, NULL}
};

static const value_string hosttype_vals[] = {
	{0x00,	"B-node"},
	{0x01,	"P-node"},
	{0x02,	"M-node"},
	{0x03,	"H-node"},
	{0, NULL}
};

static int
dissect_winsrepl_start(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
		       int winsrepl_offset, proto_tree *winsrepl_tree)
{
	proto_item *start_item = NULL;
	proto_tree *start_tree = NULL;

	if (winsrepl_tree) {
		start_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_START_ASSOCIATION");
		start_tree = proto_item_add_subtree(start_item, ett_winsrepl_start);
	}

	/* ASSOC_CTX */
	proto_tree_add_item(start_tree, hf_winsrepl_assoc_ctx, winsrepl_tvb, winsrepl_offset, 4, ENC_BIG_ENDIAN);
	winsrepl_offset += 4;

	/* MINOR VERSION */
	proto_tree_add_item(start_tree, hf_winsrepl_start_minor_version, winsrepl_tvb, winsrepl_offset, 2, ENC_BIG_ENDIAN);
	winsrepl_offset += 2;

	/* MAJOR VERSION */
	proto_tree_add_item(start_tree, hf_winsrepl_start_major_version, winsrepl_tvb, winsrepl_offset, 2, ENC_BIG_ENDIAN);
	winsrepl_offset += 2;

	return winsrepl_offset;
}

static int
dissect_winsrepl_stop(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
		      int winsrepl_offset, proto_tree *winsrepl_tree)
{
	guint32 reason;
	proto_item *stop_item = NULL;
	proto_tree *stop_tree = NULL;

	if (winsrepl_tree) {
		stop_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_STOP_ASSOCIATION");
		stop_tree = proto_item_add_subtree(stop_item, ett_winsrepl_stop);
	}

	/* REASON */
	reason = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(stop_tree, hf_winsrepl_stop_reason, winsrepl_tvb, winsrepl_offset, 4, reason);
	winsrepl_offset += 4;

	proto_item_append_text(stop_item, ", Reason: 0x%08X", reason);

	return winsrepl_offset;
}

static int
dissect_winsrepl_table_query(tvbuff_t *winsrepl_tvb _U_, packet_info *pinfo _U_,
			     int winsrepl_offset, proto_tree *winsrepl_tree _U_)
{
	/* Nothing to do here */
	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_owner(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
			    int winsrepl_offset, proto_tree *winsrepl_tree,
			    proto_tree *sub_tree, guint32 idx)
{
	proto_item *owner_item = NULL;
	proto_tree *owner_tree = NULL;

	if (sub_tree) {
		owner_item = proto_tree_add_text(sub_tree, winsrepl_tvb, winsrepl_offset, 24 , "WINS Owner [%u]", idx);
		owner_tree = proto_item_add_subtree(owner_item, ett_winsrepl_owner);
	} else if (winsrepl_tree) {
		owner_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, 24 , "WINS Owner");
		owner_tree = proto_item_add_subtree(owner_item, ett_winsrepl_owner);
	}

	/* ADDRESS */
	proto_tree_add_item(owner_tree, hf_winsrepl_owner_address, winsrepl_tvb, winsrepl_offset, 4, ENC_BIG_ENDIAN);
	winsrepl_offset += 4;

	/* MAX_VERSION */
	proto_tree_add_item(owner_tree, hf_winsrepl_owner_max_version, winsrepl_tvb, winsrepl_offset, 8, ENC_BIG_ENDIAN);
	winsrepl_offset += 8;

	/* MIN_VERSION */
	proto_tree_add_item(owner_tree, hf_winsrepl_owner_min_version, winsrepl_tvb, winsrepl_offset, 8, ENC_BIG_ENDIAN);
	winsrepl_offset += 8;

	/* TYPE */
	proto_tree_add_item(owner_tree, hf_winsrepl_owner_type, winsrepl_tvb, winsrepl_offset, 4, ENC_BIG_ENDIAN);
	winsrepl_offset += 4;

	return winsrepl_offset;
}

static int
dissect_winsrepl_table_reply(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			     int winsrepl_offset, proto_tree *winsrepl_tree)
{
	proto_item *table_item = NULL;
	proto_tree *table_tree = NULL;
	guint32 partner_count;
	guint32 i;

	if (winsrepl_tree) {
		table_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_REPL_TABLE_REPLY");
		table_tree = proto_item_add_subtree(table_item, ett_winsrepl_table_reply);
	}

	/* PARTNER COUNT */
	partner_count = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(table_tree, hf_winsrepl_table_partner_count, winsrepl_tvb, winsrepl_offset, 4, partner_count);
	winsrepl_offset += 4;

	for (i=0; i < partner_count; i++) {
		winsrepl_offset = dissect_winsrepl_wins_owner(winsrepl_tvb, pinfo,
							      winsrepl_offset, table_tree,
							      table_tree, i);
	}

	/* INITIATOR */
	proto_tree_add_item(table_tree, hf_winsrepl_table_initiator, winsrepl_tvb, winsrepl_offset, 4, ENC_BIG_ENDIAN);
	winsrepl_offset += 4;

	return winsrepl_offset;
}

static int
dissect_winsrepl_send_request(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			     int winsrepl_offset, proto_tree *winsrepl_tree)
{
	winsrepl_offset = dissect_winsrepl_wins_owner(winsrepl_tvb, pinfo,
						      winsrepl_offset, winsrepl_tree,
						      NULL, 0);

	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_ip(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
			 int winsrepl_offset, proto_tree *winsrepl_tree,
			 guint32 *addr, proto_tree *sub_tree, guint32 idx)
{
	proto_item *ip_item = NULL;
	proto_tree *ip_tree = NULL;

	if (sub_tree) {
		ip_item = proto_tree_add_text(sub_tree, winsrepl_tvb, winsrepl_offset, 8 , "WINS IP [%u]", idx);
		ip_tree = proto_item_add_subtree(ip_item, ett_winsrepl_ip);
	} else if (winsrepl_tree) {
		ip_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, 8 , "WINS IP");
		ip_tree = proto_item_add_subtree(ip_item, ett_winsrepl_ip);
	}

	/* OWNER */
	proto_tree_add_item(ip_tree, hf_winsrepl_ip_owner, winsrepl_tvb, winsrepl_offset, 4, ENC_BIG_ENDIAN);
	winsrepl_offset += 4;

	/* IP */
	*addr = tvb_get_ipv4(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_ipv4(ip_tree, hf_winsrepl_ip_ip, winsrepl_tvb, winsrepl_offset, 4, *addr);
	proto_item_append_text(ip_item, ": %s", ip_to_str((guint8 *)addr));
	winsrepl_offset += 4;

	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_address_list(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
				   int winsrepl_offset, proto_tree *winsrepl_tree,
				   proto_item *parent_item)
{
	proto_item *addr_list_item = NULL;
	proto_tree *addr_list_tree = NULL;
	int old_offset = winsrepl_offset;
	guint32 num_ips;
	guint32 ip;
	guint32 i;

	if (winsrepl_tree) {
		addr_list_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WINS Address List");
		addr_list_tree = proto_item_add_subtree(addr_list_item, ett_winsrepl_addr_list);
	}

	/* NUM_IPS */
	num_ips = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(addr_list_tree, hf_winsrepl_addr_list_num_ips, winsrepl_tvb, winsrepl_offset, 4, num_ips);
	winsrepl_offset += 4;

	for (i=0; i < num_ips; i++) {
		winsrepl_offset = dissect_winsrepl_wins_ip(winsrepl_tvb, pinfo,
							   winsrepl_offset, addr_list_tree,
							   &ip, addr_list_tree, i);
		if (i == 0) {
			proto_item_append_text(parent_item, ": %s", ip_to_str((guint8 *)&ip));
			proto_item_append_text(addr_list_item, ": %s", ip_to_str((guint8 *)&ip));
		} else {
			proto_item_append_text(parent_item, ", %s", ip_to_str((guint8 *)&ip));
			proto_item_append_text(addr_list_item, ", %s", ip_to_str((guint8 *)&ip));
		}
	}

	proto_item_set_len(addr_list_item, winsrepl_offset - old_offset);

	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_name(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			   int winsrepl_offset, proto_tree *winsrepl_tree,
			   proto_tree *sub_tree, guint32 idx)
{
	proto_item *name_item = NULL;
	proto_tree *name_tree = NULL;
	proto_item *flags_item;
	proto_tree *flags_tree;
	int old_offset = winsrepl_offset;
	tvbuff_t *name_tvb = NULL;
	guint32 name_len;
	char  name_str[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int   name_type;
	guint32 flags;
	guint32 addr;

	if (sub_tree) {
		name_item = proto_tree_add_text(sub_tree, winsrepl_tvb, winsrepl_offset, -1 , "WINS Name [%u]", idx);
		name_tree = proto_item_add_subtree(name_item, ett_winsrepl_name);
	} else if (winsrepl_tree) {
		name_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WINS Name");
		name_tree = proto_item_add_subtree(name_item, ett_winsrepl_name);
	}

	/* NAME_LEN */
	name_len = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	if ((gint) name_len < 1) {
		proto_tree_add_text(name_tree, winsrepl_tvb, winsrepl_offset,
			4, "Bad name length: %u", name_len);
		THROW(ReportedBoundsError);
	}
	proto_tree_add_uint(name_tree, hf_winsrepl_name_len, winsrepl_tvb, winsrepl_offset, 4, name_len);
	winsrepl_offset += 4;

	/* NAME: TODO! */
	/*
	 * XXX - apparently, according to the Samba code for handling
	 * WINS replication, there's a bug in a lot of versions of Windows,
	 * including W2K SP2, wherein the first and last bytes of the
	 * name (the last byte being the name type) are swapped if
	 * the type is 0x1b.  I think I've seen this in at least
	 * one capture.
	 */
	name_tvb = tvb_new_subset(winsrepl_tvb, winsrepl_offset, name_len, name_len);
	netbios_add_name("Name", name_tvb, 0, name_tree);
	name_type = get_netbios_name(name_tvb, 0, name_str, (NETBIOS_NAME_LEN - 1)*4 + 1);
	proto_item_append_text(name_item, ": %s<%02x>", name_str, name_type);
	winsrepl_offset += name_len;

	/* ALIGN to 4 Byte */
	/* winsrepl_offset += ((winsrepl_offset & (4-1)) == 0 ? 0 : (4 - (winsrepl_offset & (4-1)))); */
	/* Windows including w2k8 add 4 padding bytes, when it's already 4 byte
	 * alligned... This happens when the name has a "scope" part
	 */
	winsrepl_offset += 4 - (winsrepl_offset & (4-1));

	/* FLAGS */
	/*
	 * XXX - there appear to be more flag bits, but I didn't see
	 * anything in the Samba code about them.
	 */
	flags = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	flags_item = proto_tree_add_uint(name_tree, hf_winsrepl_name_flags, winsrepl_tvb, winsrepl_offset, 4, flags);
	flags_tree = proto_item_add_subtree(flags_item, ett_winsrepl_flags);
	proto_tree_add_uint(flags_tree, hf_winsrepl_name_flags_rectype, winsrepl_tvb, winsrepl_offset, 4, flags);
	proto_tree_add_uint(flags_tree, hf_winsrepl_name_flags_recstate, winsrepl_tvb, winsrepl_offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_winsrepl_name_flags_local, winsrepl_tvb, winsrepl_offset, 4, flags);
	proto_tree_add_uint(flags_tree, hf_winsrepl_name_flags_hosttype, winsrepl_tvb, winsrepl_offset, 4, flags);
	proto_tree_add_boolean(flags_tree, hf_winsrepl_name_flags_static, winsrepl_tvb, winsrepl_offset, 4, flags);
	winsrepl_offset += 4;

	/* GROUP_FLAG */
	/* XXX - is this just a Boolean? */
	proto_tree_add_item(name_tree, hf_winsrepl_name_group_flag, winsrepl_tvb, winsrepl_offset, 4, ENC_LITTLE_ENDIAN);
	winsrepl_offset += 4;

	/* Version ID */
	proto_tree_add_item(name_tree, hf_winsrepl_name_version_id, winsrepl_tvb, winsrepl_offset, 8, ENC_BIG_ENDIAN);
	winsrepl_offset += 8;

	switch (flags & WREPL_NAME_TYPE_MASK) {

	case WREPL_NAME_TYPE_UNIQUE:
	case WREPL_NAME_TYPE_NORMAL_GROUP:
		/* Single address */
		addr = tvb_get_ipv4(winsrepl_tvb, winsrepl_offset);
		proto_tree_add_ipv4(name_tree, hf_winsrepl_ip_ip, winsrepl_tvb, winsrepl_offset, 4, addr);
		proto_item_append_text(name_item, ": %s", ip_to_str((guint8 *)&addr));
		winsrepl_offset += 4;
		break;

	case WREPL_NAME_TYPE_SPECIAL_GROUP:
	case WREPL_NAME_TYPE_MULTIHOMED:
		/* Address list */
		winsrepl_offset = dissect_winsrepl_wins_address_list(winsrepl_tvb, pinfo,
								     winsrepl_offset, name_tree,
			 					     name_item);
		break;
	}

	/* UNKNOWN, little or big endian??? */
	proto_tree_add_item(name_tree, hf_winsrepl_name_unknown, winsrepl_tvb, winsrepl_offset, 4, ENC_BIG_ENDIAN);
	winsrepl_offset += 4;

	proto_item_set_len(name_item, winsrepl_offset - old_offset);

	return winsrepl_offset;
}

static int
dissect_winsrepl_send_reply(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			    int winsrepl_offset, proto_tree *winsrepl_tree)
{
	proto_item *rep_item = NULL;
	proto_tree *rep_tree = NULL;
	guint32 num_names;
	guint32 i;

	if (winsrepl_tree) {
		rep_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_REPL_SEND_REPLY");
		rep_tree = proto_item_add_subtree(rep_item, ett_winsrepl_send_reply);
	}

	/* NUM NAMES */
	num_names = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(rep_tree, hf_winsrepl_reply_num_names, winsrepl_tvb, winsrepl_offset, 4, num_names);
	winsrepl_offset += 4;

	for (i=0; i < num_names; i++) {
		winsrepl_offset = dissect_winsrepl_wins_name(winsrepl_tvb, pinfo,
							     winsrepl_offset, rep_tree,
							     rep_tree, i);
	}

	return winsrepl_offset;
}

static int
dissect_winsrepl_update(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			int winsrepl_offset, proto_tree *winsrepl_tree)
{
	winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
						       winsrepl_offset, winsrepl_tree);
	return winsrepl_offset;
}

static int
dissect_winsrepl_update2(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			 int winsrepl_offset, proto_tree *winsrepl_tree)
{
	winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
						       winsrepl_offset, winsrepl_tree);
	return winsrepl_offset;
}

static int
dissect_winsrepl_inform(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			int winsrepl_offset, proto_tree *winsrepl_tree)
{
	winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
						       winsrepl_offset, winsrepl_tree);
	return winsrepl_offset;
}

static int
dissect_winsrepl_inform2(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			 int winsrepl_offset, proto_tree *winsrepl_tree)
{
	winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
						       winsrepl_offset, winsrepl_tree);
	return winsrepl_offset;
}

static int
dissect_winsrepl_replication(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			     int winsrepl_offset, proto_item *winsrepl_item, proto_tree *winsrepl_tree)
{
	proto_item *repl_item = NULL;
	proto_tree *repl_tree = NULL;
	enum wrepl_replication_cmd command;

	if (winsrepl_tree) {
		repl_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_REPLICATION");
		repl_tree = proto_item_add_subtree(repl_item, ett_winsrepl_replication);
	}

	/* REPLIICATION_CMD */
	command = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(repl_tree, hf_winsrepl_replication_command, winsrepl_tvb, winsrepl_offset, 4, command);
	winsrepl_offset += 4;

	switch (command) {
		case WREPL_REPL_TABLE_QUERY:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_TABLE_QUERY");
			proto_item_append_text(winsrepl_item, ", WREPL_REPL_TABLE_QUERY");
			proto_item_append_text(repl_item, ", WREPL_REPL_TABLE_QUERY");
			winsrepl_offset = dissect_winsrepl_table_query(winsrepl_tvb, pinfo,
								       winsrepl_offset, repl_tree);
			break;
		case WREPL_REPL_TABLE_REPLY:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_TABLE_REPLY");
			proto_item_append_text(winsrepl_item, ", WREPL_REPL_TABLE_REPLY");
			proto_item_append_text(repl_item, ", WREPL_REPL_TABLE_REPLY");
			winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
								       winsrepl_offset, repl_tree);
			break;
		case WREPL_REPL_SEND_REQUEST:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_SEND_REQUEST");
			proto_item_append_text(winsrepl_item, ", WREPL_REPL_SEND_REQUEST");
			proto_item_append_text(repl_item, ", WREPL_REPL_SEND_REQUEST");
			winsrepl_offset = dissect_winsrepl_send_request(winsrepl_tvb, pinfo,
									winsrepl_offset, repl_tree);
			break;
		case WREPL_REPL_SEND_REPLY:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_SEND_REPLY");
			proto_item_append_text(winsrepl_item, ", WREPL_REPL_SEND_REPLY");
			proto_item_append_text(repl_item, ", WREPL_REPL_SEND_REPLY");
			winsrepl_offset = dissect_winsrepl_send_reply(winsrepl_tvb, pinfo,
								      winsrepl_offset, repl_tree);
			break;
		case WREPL_REPL_UPDATE:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_UPDATE");
			proto_item_append_text(winsrepl_item, ", WREPL_REPL_UPDATE");
			proto_item_append_text(repl_item, ", WREPL_REPL_UPDATE");
			winsrepl_offset = dissect_winsrepl_update(winsrepl_tvb, pinfo,
								  winsrepl_offset, repl_tree);
			break;
		case WREPL_REPL_UPDATE2:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_UPDATE2");
			proto_item_append_text(winsrepl_item, ",WREPL_REPL_UPDATE2");
			proto_item_append_text(repl_item, ",WREPL_REPL_UPDATE2");
			winsrepl_offset = dissect_winsrepl_update2(winsrepl_tvb, pinfo,
								   winsrepl_offset, repl_tree);
			break;
		case WREPL_REPL_INFORM:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_INFORM");
			proto_item_append_text(winsrepl_item, ", WREPL_REPL_INFORM");
			proto_item_append_text(repl_item, ", WREPL_REPL_INFORM");
			winsrepl_offset = dissect_winsrepl_inform(winsrepl_tvb, pinfo,
								  winsrepl_offset, repl_tree);
			break;
		case WREPL_REPL_INFORM2:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_REPL_INFORM2");
			proto_item_append_text(winsrepl_item, ", WREPL_REPL_INFORM2");
			proto_item_append_text(repl_item, ", WREPL_REPL_INFORM2");
			winsrepl_offset = dissect_winsrepl_inform2(winsrepl_tvb, pinfo,
								   winsrepl_offset, repl_tree);
			break;
	}

	return winsrepl_offset;
}

static void
dissect_winsrepl_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item *winsrepl_item = NULL;
	proto_tree *winsrepl_tree = NULL;
	enum wrepl_mess_type mess_type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WINS-Replication");
	col_clear(pinfo->cinfo, COL_INFO);

	if (parent_tree) {
		winsrepl_item = proto_tree_add_item(parent_tree, proto_winsrepl, tvb, offset, -1, ENC_NA);
		winsrepl_tree = proto_item_add_subtree(winsrepl_item, ett_winsrepl);
	}

	/* SIZE */
	proto_tree_add_item(winsrepl_tree, hf_winsrepl_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* OPCODE */
	proto_tree_add_item(winsrepl_tree, hf_winsrepl_opcode, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* ASSOC_CTX */
	proto_tree_add_item(winsrepl_tree, hf_winsrepl_assoc_ctx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* MESSAGE_TYPE */
	mess_type = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(winsrepl_tree, hf_winsrepl_mess_type, tvb, offset, 4, mess_type);
	offset += 4;

	switch (mess_type) {
		case WREPL_START_ASSOCIATION:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_START_ASSOCIATION");
			proto_item_append_text(winsrepl_item, ", WREPL_START_ASSOCIATION");
			dissect_winsrepl_start(tvb, pinfo,
							offset, winsrepl_tree);
			break;
		case WREPL_START_ASSOCIATION_REPLY:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_START_ASSOCIATION_REPLY");
			proto_item_append_text(winsrepl_item, ", WREPL_START_ASSOCIATION_REPLY");
			dissect_winsrepl_start(tvb, pinfo,
							offset, winsrepl_tree);
			break;
		case WREPL_STOP_ASSOCIATION:
			col_set_str(pinfo->cinfo, COL_INFO, "WREPL_STOP_ASSOCIATION");
			proto_item_append_text(winsrepl_item, ", WREPL_STOP_ASSOCIATION");
			dissect_winsrepl_stop(tvb, pinfo,
						       offset, winsrepl_tree);
			break;
		case WREPL_REPLICATION:
			dissect_winsrepl_replication(tvb, pinfo,
							      offset, winsrepl_item, winsrepl_tree);
			break;
	}

	return;
}

static guint
get_winsrepl_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    guint pdu_len;

    pdu_len=tvb_get_ntohl(tvb, offset);
    return pdu_len+4;
}

static void
dissect_winsrepl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	tcp_dissect_pdus(tvb, pinfo, parent_tree, winsrepl_reassemble, 4, get_winsrepl_pdu_len, dissect_winsrepl_pdu);
}

void
proto_register_winsrepl(void)
{
	static hf_register_info hf[] = {
		{ &hf_winsrepl_size, {
			"Packet Size", "winsrepl.size",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"WINS Replication Packet Size", HFILL }},

		{ &hf_winsrepl_opcode, {
			"Opcode", "winsrepl.opcode",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"WINS Replication Opcode", HFILL }},

		{ &hf_winsrepl_assoc_ctx, {
			"Assoc_Ctx", "winsrepl.assoc_ctx",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"WINS Replication Assoc_Ctx", HFILL }},

		{ &hf_winsrepl_mess_type, {
			"Message_Type", "winsrepl.message_type",
			FT_UINT32, BASE_DEC, VALS(message_type_vals), 0x0,
			"WINS Replication Message_Type", HFILL }},

		{ &hf_winsrepl_start_minor_version, {
			"Minor Version", "winsrepl.minor_version",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"WINS Replication Minor Version", HFILL }},

		{ &hf_winsrepl_start_major_version, {
			"Major Version", "winsrepl.major_version",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"WINS Replication Major Version", HFILL }},

		{ &hf_winsrepl_stop_reason, {
			"Reason", "winsrepl.reason",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"WINS Replication Reason", HFILL }},

		{ &hf_winsrepl_replication_command, {
			"Replication Command", "winsrepl.repl_cmd",
			FT_UINT32, BASE_HEX, VALS(replication_cmd_vals), 0x0,
			"WINS Replication Command", HFILL }},

		{ &hf_winsrepl_owner_address, {
			"Owner Address", "winsrepl.owner_address",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"WINS Replication Owner Address", HFILL }},

		{ &hf_winsrepl_owner_max_version, {
			"Max Version", "winsrepl.max_version",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"WINS Replication Max Version", HFILL }},

		{ &hf_winsrepl_owner_min_version, {
			"Min Version", "winsrepl.min_version",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"WINS Replication Min Version", HFILL }},

		{ &hf_winsrepl_owner_type, {
			"Owner Type", "winsrepl.owner_type",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"WINS Replication Owner Type", HFILL }},

		{ &hf_winsrepl_table_partner_count, {
			"Partner Count", "winsrepl.partner_count",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"WINS Replication Partner Count", HFILL }},

		{ &hf_winsrepl_table_initiator, {
			"Initiator", "winsrepl.initiator",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"WINS Replication Initiator", HFILL }},

		{ &hf_winsrepl_ip_owner, {
			"IP Owner", "winsrepl.ip_owner",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"WINS Replication IP Owner", HFILL }},

		{ &hf_winsrepl_ip_ip, {
			"IP Address", "winsrepl.ip_address",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"WINS Replication IP Address", HFILL }},

		{ &hf_winsrepl_addr_list_num_ips, {
			"Num IPs", "winsrepl.num_ips",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"WINS Replication Num IPs", HFILL }},

		{ &hf_winsrepl_name_len, {
			"Name Len", "winsrepl.name_len",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"WINS Replication Name Len", HFILL }},

		{ &hf_winsrepl_name_flags, {
			"Name Flags", "winsrepl.name_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"WINS Replication Name Flags", HFILL }},

		{ &hf_winsrepl_name_flags_rectype, {
			"Record Type", "winsrepl.name_flags.rectype",
			FT_UINT32, BASE_HEX, VALS(rectype_vals), 0x00000003,
			"WINS Replication Name Flags Record Type", HFILL }},

		{ &hf_winsrepl_name_flags_recstate, {
			"Record State", "winsrepl.name_flags.recstate",
			FT_UINT32, BASE_HEX, VALS(recstate_vals), 0x0000000C,
			"WINS Replication Name Flags Record State", HFILL }},

		{ &hf_winsrepl_name_flags_local, {
			"Local", "winsrepl.name_flags.local",
			FT_BOOLEAN, 32, NULL, 0x00000010,
			"WINS Replication Name Flags Local Flag", HFILL }},

		{ &hf_winsrepl_name_flags_hosttype, {
			"Host Type", "winsrepl.name_flags.hosttype",
			FT_UINT32, BASE_HEX, VALS(hosttype_vals), 0x00000060,
			"WINS Replication Name Flags Host Type", HFILL }},

		{ &hf_winsrepl_name_flags_static, {
			"Static", "winsrepl.name_flags.static",
			FT_BOOLEAN, 32, NULL, 0x00000080,
			"WINS Replication Name Flags Static Flag", HFILL }},

		{ &hf_winsrepl_name_group_flag, {
			"Name Group Flag", "winsrepl.name_group_flag",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"WINS Replication Name Group Flag", HFILL }},

		{ &hf_winsrepl_name_version_id, {
			"Name Version Id", "winsrepl.name_version_id",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"WINS Replication Name Version Id", HFILL }},

		{ &hf_winsrepl_name_unknown, {
			"Unknown IP", "winsrepl.unknown",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"WINS Replication Unknown IP", HFILL }},

		{ &hf_winsrepl_reply_num_names, {
			"Num Names", "winsrepl.num_names",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"WINS Replication Num Names", HFILL }},
	};

	static gint *ett[] = {
		&ett_winsrepl,
		&ett_winsrepl_start,
		&ett_winsrepl_stop,
		&ett_winsrepl_replication,
		&ett_winsrepl_owner,
		&ett_winsrepl_table_reply,
		&ett_winsrepl_ip,
		&ett_winsrepl_addr_list,
		&ett_winsrepl_name,
		&ett_winsrepl_send_reply,
		&ett_winsrepl_flags,
	};

	module_t *winsrepl_module;

	proto_winsrepl = proto_register_protocol("WINS (Windows Internet Name Service) Replication",
						 "WINS-Replication", "winsrepl");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_winsrepl, hf, array_length(hf));

	winsrepl_module = prefs_register_protocol(proto_winsrepl, NULL);
	prefs_register_bool_preference(winsrepl_module, "reassemble",
		"Reassemble WINS-Replication messages spanning multiple TCP segments",
		"Whether the WINS-Replication dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&winsrepl_reassemble);
}

void
proto_reg_handoff_winsrepl(void)
{
	dissector_handle_t winsrepl_handle;

	winsrepl_handle = create_dissector_handle(dissect_winsrepl, proto_winsrepl);
	dissector_add_uint("tcp.port", glb_winsrepl_tcp_port, winsrepl_handle);
}
