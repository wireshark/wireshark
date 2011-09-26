/* packet-armagetronad.c
 * Routines for the Armagetronad packet dissection
 * Copyright 2005, Guillaume Chazarain <guichaz@yahoo.fr>
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

/* Initialize the protocol and registered fields */
static int proto_armagetronad = -1;
static int hf_armagetronad_descriptor_id = -1;
static int hf_armagetronad_message_id = -1;
static int hf_armagetronad_data_len = -1;
static int hf_armagetronad_data = -1;
static int hf_armagetronad_sender_id = -1;
static int hf_armagetronad_msg_subtree = -1;

/* Initialize the subtree pointers */
static gint ett_armagetronad = -1;
static gint ett_message = -1;

#define UDP_PORT_ARMAGETRONAD 4534
#define UDP_PORT_MASTER 4533

/*
 * The ACK packet is so common that we treat it
 * differently: it has no MessageID
 */
#define ACK 1

/*
 * armagetronad-0.2.8.2.1
 * The numbers and names were retrieved at runtime using the
 * 'nDescriptor* descriptors[MAXDESCRIPTORS]' array
 */
static const value_string descriptors[] = {
	{1, "ack"},
	{2, "req_info"},
	{3, "login_deny"},
	{4, "login_ignore"},
	{5, "login_accept"},
	{6, "login1"},
	{7, "logout"},
	{8, "sn_ConsoleOut"},
	{9, "client_cen"},
	{10, "version"},
	{11, "login2"},
	{20, "req_id"},
	{21, "id_req_handler"},
	{22, "net_destroy"},
	{23, "net_control"},
	{24, "net_sync"},
	{25, "ready to get objects"},
	{26, "net_clear"},
	{27, "sync_ack"},
	{28, "sync_msg"},
	{40, "password_request"},
	{41, "password_answer"},
	{50, "small_server"},
	{51, "big_server"},
	{52, "small_request"},
	{53, "big_request"},
	{54, "big_server_master"},
	{55, "big_request_master"},
	{60, "transfer config"},
	{200, "Chat"},
	{201, "ePlayerNetID"},
	{202, "player_removed_from_game"},
	{203, "Chat Client"},
	{210, "eTimer"},
	{220, "eTeam"},
	{230, "vote cast"},
	{231, "Kick vote"},
	{232, "Server controlled vote"},
	{233, "Server controlled vote expired"},
	{300, "gNetPlayerWall"},
	{310, "game"},
	{311, "client_gamestate"},
	{320, "cycle"},
	{321, "destination"},
	{330, "gAIPlayer"},
	{331, "gAITeam"},
	{340, "zone"},
	{0, NULL}
};

static gboolean
is_armagetronad_packet(tvbuff_t * tvb)
{
	gint offset = 0;

	/* For each message in the frame */
	while (tvb_length_remaining(tvb, offset) > 2) {
		gint data_len = tvb_get_ntohs(tvb, offset + 4) * 2;

#if 0
		/*
		 * If the descriptor_id is not in the table it's possibly
		 * because the protocol evoluated, losing synchronization
		 * with the table, that's why we don't consider that as
		 * a heuristic
		 */
		if (!match_strval(tvb_get_ntohs(tvb, offset), descriptors))
			/* DescriptorID not found in the table */
			return FALSE;
#endif

		if (!tvb_bytes_exist(tvb, offset + 6, data_len))
			/* Advertised length too long */
			return FALSE;

		offset += 6 + data_len;
	}

	/* The packed should end with a 2 bytes ID */
	return tvb_length_remaining(tvb, offset) == 2;
}

static void
add_message_data(tvbuff_t * tvb, gint offset, gint data_len, proto_tree * tree)
{
	gchar *data = NULL;
	gchar tmp;
	int i;

	if (!tree)
		return;

	data = tvb_memcpy(tvb, ep_alloc(data_len + 1), offset, data_len);
	data[data_len] = '\0';

	for (i = 0; i < data_len; i += 2) {
		/*
		 * There must be a better way to tell
		 * Wireshark not to stop on null bytes
		 * as the length is known
		 */
		if (!data[i])
			data[i] = ' ';

		if (!data[i+1])
			data[i+1] = ' ';

		/* Armagetronad swaps unconditionally */
		tmp = data[i];
		data[i] = data[i+1];
		data[i+1] = tmp;
	}

	proto_tree_add_string(tree, hf_armagetronad_data, tvb, offset,
			      data_len, (gchar *) data);
}

static gint
add_message(tvbuff_t * tvb, gint offset, proto_tree * tree, GString * info)
{
	guint16 descriptor_id, message_id;
	gint data_len;
	proto_item *msg;
	proto_tree *msg_tree;
	const gchar *descriptor;

	descriptor_id = tvb_get_ntohs(tvb, offset);
	message_id = tvb_get_ntohs(tvb, offset + 2);
	data_len = tvb_get_ntohs(tvb, offset + 4) * 2;

	/* Message subtree */
	descriptor = val_to_str(descriptor_id, descriptors, "Unknown (%u)");
	if (descriptor_id == ACK)
		msg = proto_tree_add_none_format(tree,
						 hf_armagetronad_msg_subtree,
						 tvb, offset, data_len + 6,
						 "ACK %d messages",
						 data_len / 2);
	else
		msg = proto_tree_add_none_format(tree,
						 hf_armagetronad_msg_subtree,
						 tvb, offset, data_len + 6,
						 "Message 0x%04x [%s]",
						 message_id, descriptor);

	msg_tree = proto_item_add_subtree(msg, ett_message);

	/* DescriptorID field */
	proto_tree_add_item(msg_tree, hf_armagetronad_descriptor_id, tvb,
			    offset, 2, ENC_BIG_ENDIAN);
	if (info)
		g_string_append_printf(info, "%s, ", descriptor);

	/* MessageID field */
	proto_tree_add_item(msg_tree, hf_armagetronad_message_id, tvb,
			    offset + 2, 2, ENC_BIG_ENDIAN);

	/* DataLen field */
	proto_tree_add_item(msg_tree, hf_armagetronad_data_len, tvb,
			    offset + 4, 2, ENC_BIG_ENDIAN);

	/* Data field */
	add_message_data(tvb, offset + 6, data_len, msg_tree);

	return data_len + 6;
}

/* Code to actually dissect the packets */
static gint
dissect_armagetronad(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	proto_item *ti;
	proto_tree *armagetronad_tree;
	guint16 sender;
	gint offset = 0;
	GString *info;

	if (!is_armagetronad_packet(tvb))
		return 0;

	info = g_string_new("");

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Armagetronad");

	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_armagetronad, tvb, 0, -1, ENC_BIG_ENDIAN);
	armagetronad_tree = proto_item_add_subtree(ti, ett_armagetronad);

	/* For each message in the frame */
	while (tvb_length_remaining(tvb, offset) > 2)
		offset += add_message(tvb, offset, armagetronad_tree, info);

	/* After the messages, comes the SenderID */
	sender = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(ti, hf_armagetronad_sender_id, tvb, offset, 2,
			    ENC_BIG_ENDIAN);

	gsize new_len = info->len - 2;	/* Remove the trailing ", " */
	if (new_len > 0)
		g_string_truncate(info, new_len);
	else
		g_string_assign(info, "No message");

	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] from 0x%04x",
		     info->str, sender);
	g_string_free(info, TRUE);

	return offset + 2;
}

void proto_register_armagetronad(void)
{
	static hf_register_info hf[] = {
		{&hf_armagetronad_descriptor_id,
		 {"Descriptor", "armagetronad.descriptor_id",
		  FT_UINT16, BASE_DEC, VALS(descriptors), 0x0,
		  "The ID of the descriptor (the command)", HFILL}
		 },
		{&hf_armagetronad_message_id,
		 {"MessageID", "armagetronad.message_id",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "The ID of the message (to ack it)", HFILL}
		 },
		{&hf_armagetronad_data_len,
		 {"DataLen", "armagetronad.data_len",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "The length of the data (in shorts)", HFILL}
		 },
		{&hf_armagetronad_data,
		 {"Data", "armagetronad.data",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  "The actual data (array of shorts in network order)", HFILL}
		 },
		{&hf_armagetronad_sender_id,
		 {"SenderID", "armagetronad.sender_id",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "The ID of the sender (0x0000 for the server)", HFILL}
		 },
		{&hf_armagetronad_msg_subtree,
		 {"Message", "armagetronad.message",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  "A message", HFILL}
		 }
	};

	static gint *ett[] = {
		&ett_armagetronad,
		&ett_message
	};

	proto_armagetronad =
	    proto_register_protocol("The Armagetron Advanced OpenGL Tron clone",
				    "Armagetronad", "armagetronad");

	proto_register_field_array(proto_armagetronad, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	new_register_dissector("armagetronad", dissect_armagetronad,
			       proto_armagetronad);
}

void proto_reg_handoff_armagetronad(void)
{
	dissector_handle_t armagetronad_handle;

	armagetronad_handle = find_dissector("armagetronad");

	dissector_add_uint("udp.port", UDP_PORT_ARMAGETRONAD, armagetronad_handle);
	dissector_add_uint("udp.port", UDP_PORT_MASTER, armagetronad_handle);
}
