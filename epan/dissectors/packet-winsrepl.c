/*
 * packet-winsrepl.c
 * 
 * Routines for WINS Replication packet dissection
 *
 * Copyright 2005 Stefan Metzmacher <metze@samba.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-windows-common.h"
#include "packet-netbios.h"

#include "packet-winsrepl.h"
#include "packet-tcp.h"

static gboolean winsrepl_reassemble = TRUE;

struct winsrepl_frame_data {
	struct wrepl_wrap w;
};

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
static int hf_winsrepl_name_group_flag = -1;
static int hf_winsrepl_name_id = -1;
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

dissector_handle_t winsrepl_handle;

static unsigned int glb_winsrepl_tcp_port = WINS_REPLICATION_PORT;

static const value_string replication_cmd_vals[] = {
	{WREPL_REPL_TABLE_QUERY,	"WREPL_REPL_TABLE_QUERY"},
	{WREPL_REPL_TABLE_REPLY,	"WREPL_REPL_TABLE_REPLY"},
	{WREPL_REPL_SEND_REQUEST,	"WREPL_REPL_SEND_REQUEST"},
	{WREPL_REPL_SEND_REPLY,	"WREPL_REPL_SEND_REPLY"},
	{WREPL_REPL_UPDATE,	"WREPL_REPL_UPDATE"},
	{WREPL_REPL_INFORM,	"WREPL_REPL_INFORM"},
	{0, NULL}
};

static const value_string message_type_vals[] = {
	{WREPL_START_ASSOCIATION,	"WREPL_START_ASSOCIATION"},
	{WREPL_START_ASSOCIATION_REPLY,	"WREPL_START_ASSOCIATION_REPLY"},
	{WREPL_STOP_ASSOCIATION,	"WREPL_STOP_ASSOCIATION"},
	{WREPL_REPLICATION,	"WREPL_REPLICATION"},
	{0, NULL}
};

static int
dissect_winsrepl_start(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
		       int winsrepl_offset, proto_tree *winsrepl_tree,
		       struct winsrepl_frame_data *winsrepl)
{
	struct wrepl_start *start = &winsrepl->w.packet.message.start;
	proto_item *start_item = NULL;
	proto_tree *start_tree = NULL;

	if (winsrepl_tree) {
		start_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_START_ASSOCIATION");
		start_tree = proto_item_add_subtree(start_item, ett_winsrepl_start);
	}

	/* ASSOC_CTX */
	start->assoc_ctx = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(start_tree, hf_winsrepl_assoc_ctx, winsrepl_tvb, winsrepl_offset, 4, start->assoc_ctx);
	winsrepl_offset += 4;

	/* MINOR VERSION */
	start->minor_version = tvb_get_ntohs(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(start_tree, hf_winsrepl_start_minor_version, winsrepl_tvb, winsrepl_offset, 2, start->minor_version);
	winsrepl_offset += 2;

	/* MAJOR VERSION */
	start->major_version = tvb_get_ntohs(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(start_tree, hf_winsrepl_start_major_version, winsrepl_tvb, winsrepl_offset, 2, start->major_version);
	winsrepl_offset += 2;

	return winsrepl_offset;
}

static int
dissect_winsrepl_stop(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
		      int winsrepl_offset, proto_tree *winsrepl_tree,
		      struct winsrepl_frame_data *winsrepl)
{
	struct wrepl_stop *stop = &winsrepl->w.packet.message.stop;
	proto_item *stop_item = NULL;
	proto_tree *stop_tree = NULL;

	if (winsrepl_tree) {
		stop_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_STOP_ASSOCIATION");
		stop_tree = proto_item_add_subtree(stop_item, ett_winsrepl_stop);
	}

	/* REASON */
	stop->reason = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(stop_tree, hf_winsrepl_stop_reason, winsrepl_tvb, winsrepl_offset, 4, stop->reason);
	winsrepl_offset += 4;

	return winsrepl_offset;
}

static int
dissect_winsrepl_table_query(tvbuff_t *winsrepl_tvb _U_, packet_info *pinfo _U_,
			     int winsrepl_offset, proto_tree *winsrepl_tree _U_,
			     struct winsrepl_frame_data *winsrepl _U_)
{
	/* Nothing to do here */
	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_owner(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
			    int winsrepl_offset, proto_tree *winsrepl_tree,
			    _U_ struct winsrepl_frame_data *winsrepl,
			    struct wrepl_wins_owner *owner,
			    proto_tree *sub_tree,
			    guint32 index)
{
	proto_item *owner_item = NULL;
	proto_tree *owner_tree = NULL;
	const guint8 *addr_ptr;
	guint32 addr;

	if (sub_tree) {
		owner_item = proto_tree_add_text(sub_tree, winsrepl_tvb, winsrepl_offset, 24 , "WINS Owner [%u]", index);
		owner_tree = proto_item_add_subtree(owner_item, ett_winsrepl_owner);
	} else if (winsrepl_tree) {
		owner_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, 24 , "WINS Owner");
		owner_tree = proto_item_add_subtree(owner_item, ett_winsrepl_owner);
	}

	/* ADDRESS */
	addr_ptr = tvb_get_ptr(winsrepl_tvb, winsrepl_offset, 4);
	addr = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	SET_ADDRESS(&owner->address, AT_IPv4, 4, addr_ptr);
	proto_tree_add_ipv4(owner_tree, hf_winsrepl_owner_address, winsrepl_tvb, winsrepl_offset, 4, addr);
	winsrepl_offset += 4;

	/* MAX_VERSION */
	owner->max_version = tvb_get_ntoh64(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint64(owner_tree, hf_winsrepl_owner_max_version, winsrepl_tvb, winsrepl_offset, 8, owner->max_version);
	winsrepl_offset += 8;

	/* MIN_VERSION */
	owner->min_version = tvb_get_ntoh64(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint64(owner_tree, hf_winsrepl_owner_min_version, winsrepl_tvb, winsrepl_offset, 8, owner->min_version);
	winsrepl_offset += 8;

	/* TYPE */
	owner->type = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(owner_tree, hf_winsrepl_owner_type, winsrepl_tvb, winsrepl_offset, 4, owner->type);
	winsrepl_offset += 4;

	return winsrepl_offset;
}

static int
dissect_winsrepl_table_reply(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			     int winsrepl_offset, proto_tree *winsrepl_tree,
			     struct winsrepl_frame_data *winsrepl)
{
	struct wrepl_table *table = &winsrepl->w.packet.message.replication.info.table;
	struct wrepl_wins_owner owner;
	proto_item *table_item = NULL;
	proto_tree *table_tree = NULL;
	const guint8 *initiator_ptr;
	guint32 initiator;
	guint32 i;

	if (winsrepl_tree) {
		table_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_REPL_TABLE_REPLY");
		table_tree = proto_item_add_subtree(table_item, ett_winsrepl_table_reply);
	}

	/* PARTNER COUNT */
	table->partner_count = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(table_tree, hf_winsrepl_table_partner_count, winsrepl_tvb, winsrepl_offset, 4, table->partner_count);
	winsrepl_offset += 4;

	for (i=0; i < table->partner_count; i++) {
		winsrepl_offset = dissect_winsrepl_wins_owner(winsrepl_tvb, pinfo,
							      winsrepl_offset, table_tree,
							      winsrepl, &owner, table_tree, i);
	}

	/* INITIATOR */
	initiator_ptr= tvb_get_ptr(winsrepl_tvb, winsrepl_offset, 4);
	initiator = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	SET_ADDRESS(&table->initiator, AT_IPv4, 4, initiator_ptr);
	proto_tree_add_ipv4(table_tree, hf_winsrepl_table_initiator, winsrepl_tvb, winsrepl_offset, 4, initiator);
	winsrepl_offset += 4;

	return winsrepl_offset;
}

static int
dissect_winsrepl_send_request(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			     int winsrepl_offset, proto_tree *winsrepl_tree,
			     struct winsrepl_frame_data *winsrepl)
{
	struct wrepl_wins_owner *owner = &winsrepl->w.packet.message.replication.info.owner;

	winsrepl_offset = dissect_winsrepl_wins_owner(winsrepl_tvb, pinfo,
						      winsrepl_offset, winsrepl_tree,
						      winsrepl, owner, NULL, 0);

	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_ip(tvbuff_t *winsrepl_tvb, _U_ packet_info *pinfo,
			 int winsrepl_offset, proto_tree *winsrepl_tree,
			 _U_ struct winsrepl_frame_data *winsrepl,
			 struct wrepl_ip *ip,
			 proto_tree *sub_tree,
			 guint32 index)
{
	proto_item *ip_item = NULL;
	proto_tree *ip_tree = NULL;
	const guint8 *addr_ptr;
	guint32 addr;

	if (sub_tree) {
		ip_item = proto_tree_add_text(sub_tree, winsrepl_tvb, winsrepl_offset, 8 , "WINS IP [%u]", index);
		ip_tree = proto_item_add_subtree(ip_item, ett_winsrepl_ip);
	} else if (winsrepl_tree) {
		ip_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, 8 , "WINS IP");
		ip_tree = proto_item_add_subtree(ip_item, ett_winsrepl_ip);
	}

	/* OWNER */
	addr_ptr= tvb_get_ptr(winsrepl_tvb, winsrepl_offset, 4);
	addr = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	SET_ADDRESS(&ip->owner, AT_IPv4, 4, addr_ptr);
	proto_tree_add_ipv4(ip_tree, hf_winsrepl_ip_owner, winsrepl_tvb, winsrepl_offset, 4, addr);
	winsrepl_offset += 4;

	/* IP */
	addr_ptr= tvb_get_ptr(winsrepl_tvb, winsrepl_offset, 4);
	addr = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	SET_ADDRESS(&ip->ip, AT_IPv4, 4, addr_ptr);
	proto_tree_add_ipv4(ip_tree, hf_winsrepl_ip_ip, winsrepl_tvb, winsrepl_offset, 4, addr);
	proto_item_append_text(ip_item, ": %s", ip_to_str(ip->ip.data));
	winsrepl_offset += 4;

	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_address_list(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
				   int winsrepl_offset, proto_tree *winsrepl_tree,
				   struct winsrepl_frame_data *winsrepl,
				   struct wrepl_address_list *addresses,
				   proto_item *parent_item)
{
	proto_item *addr_list_item = NULL;
	proto_tree *addr_list_tree = NULL;
	int old_offset = winsrepl_offset;
	struct wrepl_ip ip;
	guint32 i;

	if (winsrepl_tree) {
		addr_list_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WINS Address LIst");
		addr_list_tree = proto_item_add_subtree(addr_list_item, ett_winsrepl_addr_list);
	}

	/* NUM_IPS */
	addresses->num_ips = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(addr_list_tree, hf_winsrepl_addr_list_num_ips, winsrepl_tvb, winsrepl_offset, 4, addresses->num_ips);
	winsrepl_offset += 4;

	for (i=0; i < addresses->num_ips; i++) {
		winsrepl_offset = dissect_winsrepl_wins_ip(winsrepl_tvb, pinfo,
							   winsrepl_offset, addr_list_tree,
							   winsrepl, &ip, addr_list_tree, i);
		if (i == 0) {
			proto_item_append_text(parent_item, ": %s", ip_to_str(ip.ip.data));
			proto_item_append_text(addr_list_item, ": %s", ip_to_str(ip.ip.data));
		} else {
			proto_item_append_text(parent_item, ", %s", ip_to_str(ip.ip.data));
			proto_item_append_text(addr_list_item, ", %s", ip_to_str(ip.ip.data));
		}
	}

	proto_item_set_len(addr_list_item, winsrepl_offset - old_offset);

	return winsrepl_offset;
}

static int
dissect_winsrepl_wins_name(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			   int winsrepl_offset, proto_tree *winsrepl_tree,
			   struct winsrepl_frame_data *winsrepl,
			   struct wrepl_wins_name *name,
			   proto_tree *sub_tree,
			   guint32 index)
{
	proto_item *name_item = NULL;
	proto_tree *name_tree = NULL;
	int old_offset = winsrepl_offset;
	tvbuff_t *name_tvb = NULL;
	char  name_str[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int   name_type;
	const guint8 *addr_ptr;
	guint32 addr;

	if (sub_tree) {
		name_item = proto_tree_add_text(sub_tree, winsrepl_tvb, winsrepl_offset, -1 , "WINS Name [%u]", index);
		name_tree = proto_item_add_subtree(name_item, ett_winsrepl_name);
	} else if (winsrepl_tree) {
		name_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WINS Name");
		name_tree = proto_item_add_subtree(name_item, ett_winsrepl_name);
	}

	/* NAME_LEN */
	name->name_len = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(name_tree, hf_winsrepl_name_len, winsrepl_tvb, winsrepl_offset, 4, name->name_len);
	winsrepl_offset += 4;

	/* NAME: TODO! */
	name_tvb = tvb_new_subset(winsrepl_tvb, winsrepl_offset, name->name_len, name->name_len);
	netbios_add_name("Name", name_tvb, 0, name_tree);
	name_type = get_netbios_name(name_tvb, 0, name_str);
	proto_item_append_text(name_item, ": %s<%02x>", name_str, name_type);
	winsrepl_offset += name->name_len;

	/* ALIGN to 4 Byte */
	winsrepl_offset += ((winsrepl_offset & (4-1)) == 0 ? 0 : (4 - (winsrepl_offset & (4-1))));

	/* FLAGS */
	name->flags = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(name_tree, hf_winsrepl_name_flags, winsrepl_tvb, winsrepl_offset, 4, name->flags);
	winsrepl_offset += 4;

	/* GROUP_FLAG */
	name->group_flag = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(name_tree, hf_winsrepl_name_group_flag, winsrepl_tvb, winsrepl_offset, 4, name->group_flag);
	winsrepl_offset += 4;

	/* ID */
	name->id = tvb_get_ntoh64(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint64(name_tree, hf_winsrepl_name_id, winsrepl_tvb, winsrepl_offset, 8, name->id);
	winsrepl_offset += 8;

	switch (name->flags & 2) {
		case 0:
			/* IP */
			addr_ptr= tvb_get_ptr(winsrepl_tvb, winsrepl_offset, 4);
			addr = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
			SET_ADDRESS(&name->addresses.ip, AT_IPv4, 4, addr_ptr);
			proto_tree_add_ipv4(name_tree, hf_winsrepl_ip_ip, winsrepl_tvb, winsrepl_offset, 4, addr);
			proto_item_append_text(name_item, ": %s", ip_to_str(name->addresses.ip.data));
			winsrepl_offset += 4;
			break;
		case 2:
			winsrepl_offset = dissect_winsrepl_wins_address_list(winsrepl_tvb, pinfo,
									     winsrepl_offset, name_tree,
			 						     winsrepl, &name->addresses.addresses, name_item);
			break;
	}


	/* UNKNOWN, little or big endian??? */
	addr_ptr= tvb_get_ptr(winsrepl_tvb, winsrepl_offset, 4);
	addr = tvb_get_letohl(winsrepl_tvb, winsrepl_offset);
	SET_ADDRESS(&name->unknown, AT_IPv4, 4, addr_ptr);
	proto_tree_add_ipv4(name_tree, hf_winsrepl_name_unknown, winsrepl_tvb, winsrepl_offset, 4, addr);
	winsrepl_offset += 4;

	proto_item_set_len(name_item, winsrepl_offset - old_offset);

	return winsrepl_offset;
}

static int
dissect_winsrepl_send_reply(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			    int winsrepl_offset, proto_tree *winsrepl_tree,
			    struct winsrepl_frame_data *winsrepl)
{
	struct wrepl_send_reply *reply = &winsrepl->w.packet.message.replication.info.reply;
	struct wrepl_wins_name name;
	proto_item *rep_item = NULL;
	proto_tree *rep_tree = NULL;
	guint32 i;

	if (winsrepl_tree) {
		rep_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_REPL_SEND_REPLY");
		rep_tree = proto_item_add_subtree(rep_item, ett_winsrepl_send_reply);
	}

	/* NUM NAMES */
	reply->num_names = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(rep_tree, hf_winsrepl_reply_num_names, winsrepl_tvb, winsrepl_offset, 4, reply->num_names);
	winsrepl_offset += 4;

	for (i=0; i < reply->num_names; i++) {
		winsrepl_offset = dissect_winsrepl_wins_name(winsrepl_tvb, pinfo,
							     winsrepl_offset, rep_tree,
							     winsrepl, &name, rep_tree, i);
	}

	return winsrepl_offset;
}

static int
dissect_winsrepl_update(tvbuff_t *winsrepl_tvb _U_, packet_info *pinfo _U_,
			int winsrepl_offset, proto_tree *winsrepl_tree _U_,
			struct winsrepl_frame_data *winsrepl _U_)
{
	return winsrepl_offset;
}

static int
dissect_winsrepl_inform(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			int winsrepl_offset, proto_tree *winsrepl_tree,
			struct winsrepl_frame_data *winsrepl)
{
	winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
						       winsrepl_offset, winsrepl_tree,
						       winsrepl);
	return winsrepl_offset;
}

static int
dissect_winsrepl_5_or_9(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			int winsrepl_offset, proto_tree *winsrepl_tree,
			struct winsrepl_frame_data *winsrepl)
{
	winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
						       winsrepl_offset, winsrepl_tree,
						       winsrepl);
	return winsrepl_offset;
}

static int
dissect_winsrepl_replication(tvbuff_t *winsrepl_tvb, packet_info *pinfo,
			     int winsrepl_offset, proto_tree *winsrepl_tree,
			     struct winsrepl_frame_data *winsrepl)
{
	struct wrepl_replication *repl = &winsrepl->w.packet.message.replication;
	proto_item *repl_item = NULL;
	proto_tree *repl_tree = NULL;

	if (winsrepl_tree) {
		repl_item = proto_tree_add_text(winsrepl_tree, winsrepl_tvb, winsrepl_offset, -1 , "WREPL_REPLICATION");
		repl_tree = proto_item_add_subtree(repl_item, ett_winsrepl_replication);
	}
	
	/* REPLIICATION_CMD */
	repl->command = tvb_get_ntohl(winsrepl_tvb, winsrepl_offset);
	proto_tree_add_uint(repl_tree, hf_winsrepl_replication_command, winsrepl_tvb, winsrepl_offset, 4, repl->command);
	winsrepl_offset += 4;

	switch (repl->command) {
		case WREPL_REPL_TABLE_QUERY:
			winsrepl_offset = dissect_winsrepl_table_query(winsrepl_tvb, pinfo,
								       winsrepl_offset, repl_tree,
								       winsrepl);
			break;
		case WREPL_REPL_TABLE_REPLY:
			winsrepl_offset = dissect_winsrepl_table_reply(winsrepl_tvb, pinfo,
								       winsrepl_offset, repl_tree,
								       winsrepl);
			break;
		case WREPL_REPL_SEND_REQUEST:
			winsrepl_offset = dissect_winsrepl_send_request(winsrepl_tvb, pinfo,
									winsrepl_offset, repl_tree,
									winsrepl);
			break;
		case WREPL_REPL_SEND_REPLY:
			winsrepl_offset = dissect_winsrepl_send_reply(winsrepl_tvb, pinfo,
								      winsrepl_offset, repl_tree,
								      winsrepl);
			break;
		case WREPL_REPL_UPDATE:
			winsrepl_offset = dissect_winsrepl_update(winsrepl_tvb, pinfo,
								  winsrepl_offset, repl_tree,
								  winsrepl);
			break;
		case WREPL_REPL_5:
		case WREPL_REPL_9:
			winsrepl_offset = dissect_winsrepl_5_or_9(winsrepl_tvb, pinfo,
								  winsrepl_offset, repl_tree,
								  winsrepl);
			break;
		case WREPL_REPL_INFORM:
			winsrepl_offset = dissect_winsrepl_inform(winsrepl_tvb, pinfo,
								  winsrepl_offset, repl_tree,
								  winsrepl);
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
	struct winsrepl_frame_data *winsrepl;


	winsrepl = ep_alloc(sizeof(struct winsrepl_frame_data));

	winsrepl->w.size = tvb_get_ntohl(tvb, offset);


	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "WINS-Replication");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	if (parent_tree) {
		winsrepl_item = proto_tree_add_item(parent_tree, proto_winsrepl, tvb, offset, winsrepl->w.size+4, FALSE);
		winsrepl_tree = proto_item_add_subtree(winsrepl_item, ett_winsrepl);
	}

	/* SIZE */
	proto_tree_add_uint(winsrepl_tree, hf_winsrepl_size, tvb, offset, 4, winsrepl->w.size);
	offset += 4;

	/* OPCODE */
	winsrepl->w.packet.opcode = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(winsrepl_tree, hf_winsrepl_opcode, tvb, offset, 4, winsrepl->w.packet.opcode);
	offset += 4;

	/* ASSOC_CTX */
	winsrepl->w.packet.assoc_ctx = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(winsrepl_tree, hf_winsrepl_assoc_ctx, tvb, offset, 4, winsrepl->w.packet.assoc_ctx);
	offset += 4;

	/* MESSAGE_TYPE */
	winsrepl->w.packet.mess_type = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(winsrepl_tree, hf_winsrepl_mess_type, tvb, offset, 4, winsrepl->w.packet.mess_type);
	offset += 4;

	switch (winsrepl->w.packet.mess_type) {
		case WREPL_START_ASSOCIATION:
			offset = dissect_winsrepl_start(tvb, pinfo,
								 offset, winsrepl_tree,
								 winsrepl);
			break;
		case WREPL_START_ASSOCIATION_REPLY:
			offset = dissect_winsrepl_start(tvb, pinfo,
								 offset, winsrepl_tree,
								 winsrepl);
			break;
		case WREPL_STOP_ASSOCIATION:
			offset = dissect_winsrepl_stop(tvb, pinfo,
								offset, winsrepl_tree,
								winsrepl);
			break;
		case WREPL_REPLICATION:
			offset = dissect_winsrepl_replication(tvb, pinfo,
								       offset, winsrepl_tree,
								       winsrepl);
			break;
	}

	return;
}

static guint
get_winsrepl_pdu_len(tvbuff_t *tvb, int offset)
{
    guint pdu_len;
 
    pdu_len=tvb_get_ntohl(tvb, offset);
    return pdu_len+4;
}

static int
dissect_winsrepl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	tcp_dissect_pdus(tvb, pinfo, parent_tree, winsrepl_reassemble, 4, get_winsrepl_pdu_len, dissect_winsrepl_pdu);

	return tvb_length(tvb);
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
			"Assoc_Ctx", "winsrepl.message_type",
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

		{ &hf_winsrepl_name_group_flag, {
			"Name Group Flag", "winsrepl.name_group_flag",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"WINS Replication Name Group Flag", HFILL }},

		{ &hf_winsrepl_name_id, {
			"Name Id", "winsrepl.name_id",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"WINS Replication Name Id", HFILL }},

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
	winsrepl_handle = new_create_dissector_handle(dissect_winsrepl, proto_winsrepl);
	dissector_add("tcp.port", glb_winsrepl_tcp_port, winsrepl_handle);
}
