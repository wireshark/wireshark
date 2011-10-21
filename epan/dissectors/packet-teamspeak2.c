/* packet-teamspeak2.c
 * Routines for TeamSpeak2 protocol packet disassembly
 * By brooss <brooss.teambb@gmail.com>
 * Copyright 2008 brooss
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <wsutil/crc32.h>
#include <epan/crc32-tvb.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <stdlib.h>


/* Packet Classes */
#define TS2C_STANDARD			0xbef0
#define TS2C_ACK			0xbef1
#define TS2C_CLIENT_VOICE		0xbef2
#define TS2C_SERVER_VOICE		0xbef3
#define TS2C_CONNECTION			0xbef4

/* Packet Types */
#define TS2T_PING			0x0001
#define TS2T_PINGREPLY			0x0002
#define TS2T_LOGINREQUEST		0x0003
#define TS2T_LOGINREPLY			0x0004
#define TS2T_LOGINPART2			0x0005
#define TS2T_CHANNELLIST		0x0006
#define TS2T_PLAYERLIST			0x0007
#define TS2T_LOGINEND			0x0008

#define TS2T_TEXTMESSAGE		0x0082
#define TS2T_CHANNEL_PLAYERLIST		0x006c
#define TS2T_CHANNELCHANGE		0x0067
#define TS2T_CHANNELLISTUPDATE		0x006e
#define TS2T_PLAYERKICKED		0x0066
#define TS2T_PLAYERLEFT			0x0065
#define TS2T_NEWPLAYERJOINED		0x0064
#define TS2T_KNOWNPLAYERUPDATE		0x0068
#define TS2T_CHANNELDELETED		0x0073
#define TS2T_CHANNELNAMECHANGED		0x006f
#define TS2T_CHANNELTOPICCHANGED	0x0070
#define TS2T_CHANNELPASSWORDCHANGED	0x0071
#define TS2T_CREATECHANNEL		0x00c9
#define TS2T_DISCONNECT			0x012c
#define TS2T_SWITCHCHANNEL		0x012f
#define TS2T_CHANGESTATUS		0x0130
#define TS2T_CHATMESSAGEBOUNCE		0xfc0f

#define TS2T_VOICE_DATA_CELP_5_1	0x0000
#define TS2T_VOICE_DATA_CELP_6_3	0x0100
#define TS2T_VOICE_DATA_GSM_14_8	0x0200
#define TS2T_VOICE_DATA_GSM_16_4	0x0300
#define TS2T_VOICE_DATA_CELP_WINDOWS_5_2	0x0400
#define TS2T_VOICE_DATA_SPEEX_3_4	0x0500
#define TS2T_VOICE_DATA_SPEEX_5_2	0x0600
#define TS2T_VOICE_DATA_SPEEX_7_2	0x0700
#define TS2T_VOICE_DATA_SPEEX_9_3	0x0800
#define TS2T_VOICE_DATA_SPEEX_12_3	0x0900
#define TS2T_VOICE_DATA_SPEEX_16_3	0x0a00
#define TS2T_VOICE_DATA_SPEEX_19_5	0x0b00
#define TS2T_VOICE_DATA_SPEEX_25_9	0x0c00

/* Codec Types */
#define TS2T_CODEC_CELP_5_1		0x0000
#define TS2T_CODEC_CELP_6_3		0x0001
#define TS2T_CODEC_GSM_14_8		0x0002
#define TS2T_CODEC_GSM_16_4		0x0003
#define TS2T_CODEC_CELP_WINDOWS_5_2	0x0004
#define TS2T_CODEC_SPEEX_3_4		0x0005
#define TS2T_CODEC_SPEEX_5_2		0x0006
#define TS2T_CODEC_SPEEX_7_2		0x0007
#define TS2T_CODEC_SPEEX_9_3		0x0008
#define TS2T_CODEC_SPEEX_12_3		0x0009
#define TS2T_CODEC_SPEEX_16_3		0x000a
#define TS2T_CODEC_SPEEX_19_5		0x000b
#define TS2T_CODEC_SPEEX_25_9		0x000c

/* Player Status Flags */
#define TS2_STATUS_CHANNELCOMMANDER	1
#define TS2_STATUS_BLOCKWHISPERS	4
#define TS2_STATUS_AWAY			8
#define TS2_STATUS_MUTEMICROPHONE	16
#define TS2_STATUS_MUTE			32


static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static const fragment_items msg_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment,
	&ett_msg_fragments,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	/* Reassembled in field */
	&hf_msg_reassembled_in,
	/* Reassembled length field */
	&hf_msg_reassembled_length,
	/* Tag */
	"Message fragments"
};

/* Class names */
static const value_string classnames[] =
{
	{ TS2C_CONNECTION, "Connection" },
	{ TS2C_ACK, "ACK"},
	{ TS2C_STANDARD, "Standard (reliable)"},
	{ TS2C_SERVER_VOICE, "Voice"},
	{ TS2C_CLIENT_VOICE, "Voice"},
	{ 0, NULL }
};

/* Type names */
static const value_string typenames[] = {
	{ TS2T_PING, 		"Ping" },
	{ TS2T_PINGREPLY, 	"Ping Reply" },
	{ TS2T_LOGINREQUEST,	"Login Request" },
	{ TS2T_LOGINREPLY,	"Login Reply" },
	{ TS2T_LOGINPART2,	"Login Part 2" },
	{ TS2T_CHANNELLIST,	 "Channel List" },
	{ TS2T_PLAYERLIST, 	"Player List" },
	{ TS2T_LOGINEND,	"Login End" },
	{ TS2T_TEXTMESSAGE, "Text Message" },


	{ TS2T_CHANNEL_PLAYERLIST, "Channel Player List" },
	{ TS2T_CHANNELCHANGE, "Channel Change" },

	{ TS2T_CHANNELLISTUPDATE, "Channel List Update" },
	{ TS2T_PLAYERKICKED, "Player Kicked" },
	{ TS2T_PLAYERLEFT, "Player Left" },
	{ TS2T_NEWPLAYERJOINED, "New Player Joined" },
	{ TS2T_KNOWNPLAYERUPDATE, "Known Player Update" },
	{ TS2T_CHANNELDELETED, "Channel Deleted" },
	{ TS2T_CHANNELNAMECHANGED, "Channel Name Change" },
	{ TS2T_CHANNELTOPICCHANGED, "Channel Topic Change" },
	{ TS2T_CHANNELPASSWORDCHANGED, "Channel Password Change" },
	{ TS2T_CREATECHANNEL, "Create Channel" },
	{ TS2T_DISCONNECT, "Disconnect" },
	{ TS2T_SWITCHCHANNEL, "Switch Channel"},
	{ TS2T_CHANGESTATUS, "Change Status" },

	{ TS2T_CHATMESSAGEBOUNCE, "Chat Message Bounce" },

	{ TS2T_VOICE_DATA_CELP_5_1, "TS2T_VOICE_DATA_CELP_5_1" },
	{ TS2T_VOICE_DATA_CELP_6_3, "TS2T_VOICE_DATA_CELP_6_3" },
	{ TS2T_VOICE_DATA_GSM_14_8, "TS2T_VOICE_DATA_GSM_14_8" },
	{ TS2T_VOICE_DATA_GSM_16_4, "TS2T_VOICE_DATA_GSM_16_4" },
	{ TS2T_VOICE_DATA_CELP_WINDOWS_5_2, "TS2T_VOICE_DATA_CELP_WINDOWS_5_2" },
	{ TS2T_VOICE_DATA_SPEEX_3_4, "TS2T_VOICE_DATA_SPEEX_3_4" },
	{ TS2T_VOICE_DATA_SPEEX_5_2, "TS2T_VOICE_DATA_SPEEX_5_2" },
	{ TS2T_VOICE_DATA_SPEEX_7_2, "TS2T_VOICE_DATA_SPEEX_7_2" },
	{ TS2T_VOICE_DATA_SPEEX_9_3, "TS2T_VOICE_DATA_SPEEX_9_3" },
	{ TS2T_VOICE_DATA_SPEEX_12_3, "TS2T_VOICE_DATA_SPEEX_12_3" },
	{ TS2T_VOICE_DATA_SPEEX_16_3, "TS2T_VOICE_DATA_SPEEX_16_3" },
	{ TS2T_VOICE_DATA_SPEEX_19_5, "TS2T_VOICE_DATA_SPEEX_19_5" },
	{ TS2T_VOICE_DATA_SPEEX_25_9, "TS2T_VOICE_DATA_SPEEX_25_9" },

	{ 0, NULL }
};

/* Codec Names */
static const value_string codecnames[] =
{
	{ TS2T_CODEC_CELP_5_1, "CELP 5.1" },
	{ TS2T_CODEC_CELP_6_3, "CELP 6.3" },
	{ TS2T_CODEC_GSM_14_8, "GSM 14.8" },
	{ TS2T_CODEC_GSM_16_4, "GSM 16.4" },
	{ TS2T_CODEC_CELP_WINDOWS_5_2, "CELP Windows 5.2" },
	{ TS2T_CODEC_SPEEX_3_4, "Speex 3.4" },
	{ TS2T_CODEC_SPEEX_5_2, "Speex 5.2" },
	{ TS2T_CODEC_SPEEX_7_2, "Speex 7.2" },
	{ TS2T_CODEC_SPEEX_9_3, "Speex 9.3" },
	{ TS2T_CODEC_SPEEX_12_3, "Speex 12.3" },
	{ TS2T_CODEC_SPEEX_16_3, "Speex 16.3" },
	{ TS2T_CODEC_SPEEX_19_5, "Speex 19.5" },
	{ TS2T_CODEC_SPEEX_25_9, "Speex 25.9" },
	{ 0, NULL }
};

#define TS2_PORT 8767

static int proto_ts2 = -1;

static int hf_ts2_type = -1;
static int hf_ts2_class = -1;
static int hf_ts2_clientid = -1;
static int hf_ts2_sessionkey = -1;
static int hf_ts2_crc32 = -1;
static int hf_ts2_ackto = -1;
static int hf_ts2_seqnum = -1;
static int hf_ts2_protocol_string = -1;
static int hf_ts2_string = -1;
static int hf_ts2_registeredlogin = -1;
static int hf_ts2_name = -1;
static int hf_ts2_password = -1;
static int hf_ts2_nick = -1;
static int hf_ts2_badlogin = -1;
static int hf_ts2_unknown = -1;
static int hf_ts2_channel = -1;
static int hf_ts2_subchannel = -1;
static int hf_ts2_channelpassword = -1;
static int hf_ts2_emptyspace = -1;
static int hf_ts2_fragmentnumber = -1;
static int hf_ts2_platform_string = -1;
static int hf_ts2_server_name = -1;
static int hf_ts2_server_welcome_message = -1;
static int hf_ts2_parent_channel_id = -1;
static int hf_ts2_codec = -1;
static int hf_ts2_channel_flags = -1;
static int hf_ts2_channel_id = -1;
static int hf_ts2_channel_name = -1;
static int hf_ts2_channel_topic = -1;
static int hf_ts2_channel_description = -1;
static int hf_ts2_player_id = -1;
static int hf_ts2_player_status_flags = -1;
static int hf_ts2_number_of_players = -1;
static int hf_ts2_number_of_channels = -1;
static int hf_ts2_resend_count = -1;
static int hf_ts2_status_channelcommander = -1;
static int hf_ts2_status_blockwhispers = -1;
static int hf_ts2_status_away = -1;
static int hf_ts2_status_mutemicrophone = -1;
static int hf_ts2_status_mute = -1;
static int hf_ts2_channel_unregistered = -1;
static int hf_ts2_channel_moderated = -1;
static int hf_ts2_channel_password = -1;
static int hf_ts2_channel_subchannels = -1;
static int hf_ts2_channel_default = -1;
static int hf_ts2_channel_order = -1;
static int hf_ts2_max_users = -1;

static gint ett_ts2 = -1;
static gint ett_ts2_channel_flags = -1;

/* Conversation Variables */
typedef struct
{
	guint32 last_inorder_server_frame;
	guint32 last_inorder_client_frame;
	address server_addr;
	guint32 server_port;
	guint32 server_frag_size;
	guint32 server_frag_num;
	guint32 client_frag_size;
	guint32 client_frag_num;

} ts2_conversation;

/* Packet Variables */
typedef struct
{
	guint32 frag_num;
	guint32 frag_size;
	gboolean fragmented;
	gboolean outoforder;
} ts2_frag;

#define my_init_count 5

static GHashTable *msg_fragment_table = NULL;
static GHashTable *msg_reassembled_table = NULL;

/* forward reference */
static gboolean ts2_add_checked_crc32(proto_tree *tree, int hf_item, tvbuff_t *tvb, guint16 offset, guint32 icrc32);
static void ts2_parse_playerlist(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_channellist(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_newplayerjoined(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_knownplayerupdate(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_playerleft(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_loginend(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_changestatus(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_switchchannel(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_add_statusflags(tvbuff_t *tvb, proto_tree *ts2_tree, guint32 offset);
static void ts2_parse_channelchange(tvbuff_t *tvb, proto_tree *ts2_tree);
static void ts2_parse_loginpart2(tvbuff_t *tvb, proto_tree *ts2_tree);

/*
 * Check if a packet is in order and if it is set its fragmentation details into the passed pointers.
 * Returns TRUE if the packet is fragmented.
 * Must be run sequentially
 * */
static gboolean ts2_standard_find_fragments(tvbuff_t *tvb, guint32 *last_inorder_frame, guint32 *frag_size, guint32 *frag_num, gboolean *outoforder)
{
	guint32 frag_count;
	gboolean ret;
	frag_count=tvb_get_letohs(tvb, 18);
	ret=FALSE;
	*outoforder=FALSE;

	/* if last_inorder_frame is zero, then this is the first reliable packet */
	if(*last_inorder_frame==0)
	{
		*last_inorder_frame=tvb_get_letohl(tvb, 12);
		*frag_size=tvb_get_letohs(tvb, 18);
		*frag_num=0;
		if(*frag_size>0)
			ret=TRUE;
		else
			ret=FALSE;
	}
	/* This packet is in order */
	else if(*last_inorder_frame==tvb_get_letohl(tvb, 12)-1)
	{
		if(*frag_size>0)
		{
			*frag_num=*frag_size-frag_count;
			if(frag_count==0)
			{
				*frag_size=0;
			}
			ret=TRUE;
		}
		else
		{
			*frag_size=tvb_get_letohs(tvb, 18);
			*frag_num=*frag_size-frag_count;
			if(*frag_size>0)
				ret=TRUE;
			else
				ret=FALSE;
		}
		*last_inorder_frame=tvb_get_letohl(tvb, 12);
	}
	else /* out of order */
		*outoforder=TRUE;
	return ret;
}



/*
 * Dissect a standard (reliable) ts2 packet, reassembling if required.
 */
static void ts2_standard_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ts2_tree, ts2_conversation *conversation_data)
{
	guint8 save_fragmented;
	tvbuff_t *new_tvb, *next_tvb;
	fragment_data *frag_msg ;
	guint16 fragment_number;
	ts2_frag *frag;
	gboolean outoforder;

	guint16 type = tvb_get_letohs(tvb, 2);
	/*guint16 klass = tvb_get_letohs(tvb, 0);*/
	proto_tree_add_item(ts2_tree, hf_ts2_seqnum, tvb, 12, 4, ENC_LITTLE_ENDIAN);

	/* XXX: Following fragmentation stuff should be separate from the GUI stuff ??    */
	/* Get our stored fragmentation data or create one! */
	if ( ! ( frag = p_get_proto_data(pinfo->fd, proto_ts2) ) ) {
		frag = se_alloc(sizeof(ts2_frag));
		frag->frag_num=0;
	}

	/* decide if the packet is server to client or client to server
	 * then check its fragmentation
	 */
	if(!(pinfo->fd->flags.visited))
	{
		if(conversation_data->server_port == pinfo->srcport)
		{
			frag->fragmented = ts2_standard_find_fragments(tvb, &conversation_data->last_inorder_server_frame, &conversation_data->server_frag_size, &conversation_data->server_frag_num, &outoforder);
			frag->frag_num=conversation_data->server_frag_num;
			frag->frag_size=conversation_data->server_frag_size;
		}
		else
		{

			frag->fragmented = ts2_standard_find_fragments(tvb, &conversation_data->last_inorder_client_frame, &conversation_data->client_frag_size, &conversation_data->client_frag_num, &outoforder);
			frag->frag_num=conversation_data->client_frag_num;
			frag->frag_size=conversation_data->client_frag_size;
		}
		frag->outoforder=outoforder;
		p_add_proto_data(pinfo->fd, proto_ts2, frag);
	}

	/* Get our stored fragmentation data */
	frag = p_get_proto_data(pinfo->fd, proto_ts2);

	proto_tree_add_item(ts2_tree, hf_ts2_resend_count, tvb, 16, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ts2_tree, hf_ts2_fragmentnumber, tvb, 18, 2, ENC_LITTLE_ENDIAN);
	ts2_add_checked_crc32(ts2_tree, hf_ts2_crc32, tvb, 20, tvb_get_letohl(tvb, 20));

	/* Reassemble the packet if its fragmented */
	new_tvb = NULL;
	if(frag->fragmented)
	{
		save_fragmented = pinfo->fragmented;
		frag_msg = NULL;
		pinfo->fragmented = TRUE;
		fragment_number = tvb_get_letohs(tvb, 18);
		frag_msg = fragment_add_seq_check(tvb, 24, pinfo, type,	msg_fragment_table, msg_reassembled_table, frag->frag_num, tvb_length_remaining(tvb, 24), fragment_number);
		new_tvb = process_reassembled_data(tvb, 24, pinfo,"Reassembled TeamSpeak2", frag_msg, &msg_frag_items, NULL, ts2_tree);
		if (frag_msg)
		{ /* Reassembled */
			col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
		}
		else
		{ /* Not last packet of reassembled Short Message */
			if (check_col(pinfo->cinfo, COL_INFO))col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", frag->frag_num);
		}
		if (new_tvb)
			next_tvb = new_tvb;
		else
			next_tvb = tvb_new_subset_remaining(tvb, 24);
		pinfo->fragmented = save_fragmented;
	}
	else
		next_tvb = tvb_new_subset_remaining(tvb, 24);

	/* If we have a full packet now dissect it */
	if((new_tvb || !frag->fragmented) && !frag->outoforder)
	{
		switch(type)
		{
			case TS2T_LOGINPART2:
				ts2_parse_loginpart2(next_tvb, ts2_tree);
				break;
			case TS2T_CHANNELLIST:
				ts2_parse_channellist(next_tvb, ts2_tree);
				break;
			case TS2T_PLAYERLIST:
				ts2_parse_playerlist(next_tvb, ts2_tree);
				break;
			case TS2T_NEWPLAYERJOINED:
				ts2_parse_newplayerjoined(next_tvb, ts2_tree);
				break;
			case TS2T_KNOWNPLAYERUPDATE:
				ts2_parse_knownplayerupdate(next_tvb, ts2_tree);
				break;
			case TS2T_PLAYERLEFT:
				ts2_parse_playerleft(next_tvb, ts2_tree);
				break;
			case TS2T_PLAYERKICKED:
				ts2_parse_playerleft(next_tvb, ts2_tree);
				break;
			case TS2T_LOGINEND:
				ts2_parse_loginend(next_tvb, ts2_tree);
				break;
			case TS2T_CHANGESTATUS:
				ts2_parse_changestatus(next_tvb, ts2_tree);
				break;
			case TS2T_SWITCHCHANNEL:
				ts2_parse_switchchannel(next_tvb, ts2_tree);
				break;
			case TS2T_CHANNELCHANGE:
				ts2_parse_channelchange(next_tvb, ts2_tree);
				break;
		}
	}
	/* The packet is out of order, update the cinfo and ignore the packet */
	if(frag->outoforder)
		col_append_str(pinfo->cinfo, COL_INFO, " (Out Of Order, ignored)");
}


/* Parses a ts2 new player joined (TS2_NEWPLAYERJOINED) packet and adds it to the tree */
static void ts2_parse_newplayerjoined(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_player_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(ts2_tree, hf_ts2_nick, tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
	offset+=30;
}

/* Parses TS2_LOGINEND packet and adds it to the tree */
static void ts2_parse_loginend(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
}

/* Parses a ts2 known player joined (TS2_KNOWNPLAYERUPDATE) packet and adds it to the tree */
static void ts2_parse_knownplayerupdate(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_player_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_player_status_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	ts2_add_statusflags(tvb, ts2_tree, offset);
}

/* Parses a ts2 switch channel (TS2_SWITCHCHANNEL) packet and adds it to the tree */
static void ts2_parse_switchchannel(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_password, tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
	offset+=30;
}

/* Parses a ts2 channel change (TS2T_CHANNELCHANGE) packet and adds it to the tree */
static void ts2_parse_channelchange(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_player_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, 2, ENC_NA);

}

/* Parses a ts2 change status (TS2_CHANGESTATUS) packet and adds it to the tree */
static void ts2_parse_changestatus(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_player_status_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	ts2_add_statusflags(tvb, ts2_tree, offset);

}

/* Parses a ts2 known player left (TS2_PLAYERLEFT) packet and adds it to the tree */
static void ts2_parse_playerleft(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_player_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, 4, ENC_NA);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, 4, ENC_NA);
	offset+=4;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
}

/* Parses a ts2 login part 2 (TS2T_LOGINPART2) packet and adds it to the tree */
static void ts2_parse_loginpart2(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, 0, 2, ENC_NA);
	offset+=2;
	proto_tree_add_item(ts2_tree, hf_ts2_channel, tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
	offset+=30;
	proto_tree_add_item(ts2_tree, hf_ts2_subchannel, tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
	offset+=30;
	proto_tree_add_item(ts2_tree, hf_ts2_channelpassword, tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
	offset+=30;
	proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, 4, ENC_NA);

}
/* Parses a ts2 channel list (TS2T_CHANNELLIST) and adds it to the tree */
static void ts2_parse_channellist(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	guint32 string_len;
	proto_tree	*subtree;
	proto_item	*item;

	offset=0;
	proto_tree_add_item(ts2_tree, hf_ts2_number_of_channels, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;
	while(offset<tvb_length_remaining(tvb, 0))
	{
		proto_tree_add_item(ts2_tree, hf_ts2_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset+=4;

		/* Channel flags */
		item = proto_tree_add_item(ts2_tree, hf_ts2_channel_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		subtree = proto_item_add_subtree(item, ett_ts2_channel_flags);
		proto_tree_add_item(subtree, hf_ts2_channel_unregistered, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_ts2_channel_moderated, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_ts2_channel_password, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_ts2_channel_subchannels, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_ts2_channel_default, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;

		proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, 1, ENC_NA);
		offset+=1;
		proto_tree_add_item(ts2_tree, hf_ts2_codec, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset+=2;
		proto_tree_add_item(ts2_tree, hf_ts2_parent_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset+=4;
		proto_tree_add_item(ts2_tree, hf_ts2_channel_order, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset+=2;
		proto_tree_add_item(ts2_tree, hf_ts2_max_users, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset+=2;
		tvb_get_ephemeral_stringz(tvb, offset, &string_len);
		proto_tree_add_item(ts2_tree, hf_ts2_channel_name, tvb, offset,string_len , ENC_ASCII|ENC_NA);
		offset+=string_len;
		tvb_get_ephemeral_stringz(tvb, offset, &string_len);
		proto_tree_add_item(ts2_tree, hf_ts2_channel_topic, tvb, offset,string_len ,ENC_ASCII|ENC_NA);
		offset+=string_len;
		tvb_get_ephemeral_stringz(tvb, offset, &string_len);
		proto_tree_add_item(ts2_tree, hf_ts2_channel_description, tvb, offset,string_len , ENC_ASCII|ENC_NA);
		offset+=string_len;
	}
}

static void ts2_add_statusflags(tvbuff_t *tvb, proto_tree *ts2_tree, guint32 offset)
{
	proto_tree_add_item(ts2_tree, hf_ts2_status_channelcommander, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ts2_tree, hf_ts2_status_blockwhispers, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ts2_tree, hf_ts2_status_away, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ts2_tree, hf_ts2_status_mutemicrophone, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ts2_tree, hf_ts2_status_mute, tvb, offset, 2, ENC_LITTLE_ENDIAN);

}

/* Parses a ts2 player list (TS2T_PLAYERLIST) and adds it to the tree */
static void ts2_parse_playerlist(tvbuff_t *tvb, proto_tree *ts2_tree)
{
	gint32 offset;
	gint32 number_of_players;
	gint32 x;
	offset=0;
	x=0;
	proto_tree_add_item(ts2_tree, hf_ts2_number_of_players, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	number_of_players = tvb_get_letohl(tvb, 0);
	offset+=4;
	while(offset<tvb_length_remaining(tvb, 0) && x<number_of_players)
	{
		proto_tree_add_item(ts2_tree, hf_ts2_player_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset+=4;
		proto_tree_add_item(ts2_tree, hf_ts2_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset+=4;
		proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, offset, 4, ENC_NA);
		offset+=4;
		proto_tree_add_item(ts2_tree, hf_ts2_player_status_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		ts2_add_statusflags(tvb, ts2_tree, offset);
		offset+=2;
		proto_tree_add_item(ts2_tree, hf_ts2_nick, tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
		offset+=30;
		x++;
	}
	proto_tree_add_item(ts2_tree, hf_ts2_emptyspace, tvb, offset, tvb_length_remaining(tvb, 0), ENC_NA);
}



/* Find the current conversation or make a new one if required */
static ts2_conversation* ts2_get_conversation(packet_info *pinfo)
{
	conversation_t *conversation;
	ts2_conversation *conversation_data;
	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	if(conversation)
	{

		conversation_data = (ts2_conversation*)conversation_get_proto_data(conversation, proto_ts2);
	}
	else
	{
		conversation_data = se_alloc(sizeof(*conversation_data));
		conversation_data->last_inorder_server_frame=0; /* sequence number should never be zero so we can use this as an initial number */
		conversation_data->last_inorder_client_frame=0;
		conversation_data->server_port=pinfo->srcport;
		conversation_data->server_frag_size=0;
		conversation_data->server_frag_num=0;
		conversation_data->client_frag_size=0;
		conversation_data->client_frag_num=0;
		conversation = conversation_new(pinfo->fd->num,  &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
		conversation_add_proto_data(conversation, proto_ts2, (void *)conversation_data);
	}
	return conversation_data;
}



/* Dissect a TS2 packet */
static void dissect_ts2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	ts2_conversation *conversation_data;
	guint16 type = tvb_get_letohs(tvb, 2);
	guint16 klass = tvb_get_letohs(tvb, 0);

	conversation_data = ts2_get_conversation(pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TS2");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		if(klass==TS2C_ACK)
			col_add_fstr(pinfo->cinfo, COL_INFO, "Class: %s", val_to_str(klass, classnames, "Unknown (0x%02x)"));
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s, Class: %s", val_to_str(type, typenames, "Unknown (0x%02x)"), val_to_str(klass, classnames, "Unknown (0x%02x)"));
	}

	/* XXX: We need to do all the non GUI stuff whether or not if(tree) */
        /*      Do only once by checking visited ?                          */
        /*      ToDo: Rewrite ??                                            */
	if (!tree) {
		switch(klass) {
			case TS2C_CONNECTION:
				switch(type) {
					case TS2T_LOGINREQUEST:
						conversation_data->server_port=pinfo->destport;
						conversation_data->server_addr=pinfo->dst;
						break;
				}
				break;
			case TS2C_STANDARD:
				ts2_standard_dissect(tvb, pinfo, tree, conversation_data);
				break;
		}
	}

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *ts2_tree = NULL;

		ti = proto_tree_add_item(tree, proto_ts2, tvb, 0, -1, ENC_NA);
		ts2_tree = proto_item_add_subtree(ti, ett_ts2);

		proto_tree_add_item(ts2_tree, hf_ts2_class, tvb, 0, 2, ENC_LITTLE_ENDIAN);
		if(klass==TS2C_ACK)
			proto_tree_add_item(ts2_tree, hf_ts2_resend_count, tvb, 2, 2, ENC_LITTLE_ENDIAN);
		else
			proto_tree_add_item(ts2_tree, hf_ts2_type, tvb, 2, 2, ENC_LITTLE_ENDIAN);

		proto_tree_add_item(ts2_tree, hf_ts2_sessionkey, tvb, 4, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ts2_tree, hf_ts2_clientid, tvb, 8, 4, ENC_LITTLE_ENDIAN);
		switch(klass)
		{
			case TS2C_CONNECTION:
				proto_tree_add_item(ts2_tree, hf_ts2_seqnum, tvb, 12, 4, ENC_LITTLE_ENDIAN);
				ts2_add_checked_crc32(ts2_tree, hf_ts2_crc32, tvb, 16, tvb_get_letohl(tvb, 16));

				switch(type)
				{
					case TS2T_PING:
						break;
					case TS2T_PINGREPLY:
						proto_tree_add_item(ts2_tree, hf_ts2_ackto, tvb, 20, 4, ENC_LITTLE_ENDIAN);
						break;
					case TS2T_LOGINREQUEST:
						proto_tree_add_item(ts2_tree, hf_ts2_protocol_string, tvb, 20, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_platform_string, tvb, 50, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, 80, 9, ENC_NA);
						proto_tree_add_item(ts2_tree, hf_ts2_registeredlogin, tvb, 90, 1, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_name, tvb, 90, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_password, tvb, 120, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_nick, tvb, 150, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);

						conversation_data->server_port=pinfo->destport;
						conversation_data->server_addr=pinfo->dst;

						break;
					case TS2T_LOGINREPLY:
						proto_tree_add_item(ts2_tree, hf_ts2_server_name, tvb, 20, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_platform_string, tvb, 50, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, 80, 9, ENC_NA);
						proto_tree_add_item(ts2_tree, hf_ts2_badlogin, tvb, 89, 3, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, 92, 80, ENC_NA);
						proto_tree_add_item(ts2_tree, hf_ts2_sessionkey, tvb, 172, 4, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(ts2_tree, hf_ts2_unknown, tvb, 178, 3, ENC_NA);
						proto_tree_add_item(ts2_tree, hf_ts2_server_welcome_message, tvb, 180, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
                                                break;
				}
				break;
			case TS2C_ACK:
				/* Ignore the type for ACK, its always zero and clashes with CELP_5_1 */

				proto_tree_add_item(ts2_tree, hf_ts2_seqnum, tvb, 12, 4, ENC_LITTLE_ENDIAN);
				break;
			case TS2C_STANDARD:
				ts2_standard_dissect(tvb, pinfo, ts2_tree, conversation_data);
				break;
		}
	} /* if (tree) */
}



/* Calculates a CRC32 checksum from the tvb zeroing out four bytes at the offset and checks it with the given crc32 and adds the result to the tree
 * Returns true if the calculated CRC32 matches the passed CRC32.
 * */
static gboolean ts2_add_checked_crc32(proto_tree *tree, int hf_item, tvbuff_t *tvb, guint16 offset, guint32 icrc32 )
{
	guint8 *zero;
	guint32 ocrc32;
	zero = ep_alloc0(4);
	ocrc32 = crc32_ccitt_tvb(tvb, offset);
	ocrc32 = crc32_ccitt_seed(zero, 4, 0xffffffff-ocrc32);
	ocrc32 = crc32_ccitt_tvb_offset_seed(tvb, offset+4, tvb_reported_length_remaining(tvb, offset+4), 0xffffffff-ocrc32);
	if(icrc32==ocrc32)
	{
		proto_tree_add_uint_format(tree, hf_item, tvb, offset, 4, tvb_get_letohl(tvb, 16), "crc32: 0x%04x [correct]", tvb_get_letohl(tvb, offset));
		return TRUE;
	}
	else
	{
		proto_tree_add_uint_format(tree, hf_item, tvb, offset, 4, tvb_get_letohl(tvb,16), "crc32: 0x%04x [incorrect, should be 0x%04x]", tvb_get_letohl(tvb, offset),ocrc32);
		return FALSE;
	}
}

static void ts2_init(void)
{
	fragment_table_init(&msg_fragment_table);
	reassembled_table_init(&msg_reassembled_table);
}

/*
 * proto_register_ts2()
 * */
void proto_register_ts2(void)
{
	static hf_register_info hf[] = {
		{ &hf_ts2_class,
		  { "Class", "ts2.class",
		    FT_UINT16, BASE_HEX,
		    VALS(classnames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_type,
		  { "Type", "ts2.type",
		    FT_UINT16, BASE_HEX,
		    VALS(typenames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_clientid,
		  { "Client id", "ts2.clientid",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_sessionkey,
		  { "Session Key", "ts2.sessionkey",
		    FT_UINT32, BASE_HEX,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_ackto,
		  { "Ping Reply To", "ts2.ping_ackto",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_crc32,
		  { "CRC32 Checksum", "ts2.crc32",
		    FT_UINT32, BASE_HEX,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_seqnum,
		  { "Sequence Number", "ts2.sequencenum",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_protocol_string,
		  { "Protocol String", "ts2.protocolstring",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_string,
		  { "String", "ts2.string",
		    FT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_registeredlogin,
		  { "Registered Login", "ts2.registeredlogin",
		    FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_name,
		  { "Name", "ts2.name",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_password,
		  { "Password", "ts2.password",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_nick,
		  { "Nick", "ts2.nick",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_badlogin,
		  { "Bad Login", "ts2.badlogin",
		    FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_unknown,
		  { "Unknown", "ts2.unknown",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel,
		  { "Channel", "ts2.channel",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_subchannel,
		  { "Sub-Channel", "ts2.subchannel",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_channelpassword,
		  { "Channel Password", "ts2.channelpassword",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_emptyspace,
		  { "Empty Space", "ts2.emptyspace",
		    FT_NONE, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_fragmentnumber,
		  { "Fragment Number", "ts2.fragmentnumber",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_platform_string,
		  { "Platform String", "ts2.platformstring",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_server_name,
		  { "Server Name", "ts2.servername",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_server_welcome_message,
		  { "Server Welcome Message", "ts2.serverwelcomemessage",
		    FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_parent_channel_id,
		  { "Parent Channel ID", "ts2.parentchannelid",
		    FT_UINT32, BASE_HEX,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_codec,
		  { "Codec", "ts2.codec",
		    FT_UINT16, BASE_HEX,
		    VALS(codecnames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_flags,
		  { "Channel Flags", "ts2.channelflags",
		    FT_UINT8, BASE_HEX,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_id,
		  { "Channel Id", "ts2.chanelid",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_name,
		  { "Channel Name", "ts2.chanelname",
		    FT_STRINGZ, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_topic,
		  { "Channel Topic", "ts2.chaneltopic",
		    FT_STRINGZ, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_description,
		  { "Channel Description", "ts2.chaneldescription",
		    FT_STRINGZ, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_player_id,
		  { "Player Id", "ts2.playerid",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_player_status_flags,
		  { "Player Status Flags", "ts2.playerstatusflags",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_number_of_players,
		  { "Number Of Players", "ts2.numberofplayers",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_number_of_channels,
		  { "Number Of Channels", "ts2.numberofchannels",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_resend_count,
		  { "Resend Count", "ts2.resendcount",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ts2_status_channelcommander,
		  { "Channel Commander", "ts2.playerstatusflags.channelcommander",
		    FT_BOOLEAN, 8,
		    NULL, TS2_STATUS_CHANNELCOMMANDER,
		    NULL, HFILL }
		},
		{ &hf_ts2_status_blockwhispers,
		  { "Block Whispers", "ts2.playerstatusflags.blockwhispers",
		    FT_BOOLEAN, 8,
		    NULL, TS2_STATUS_BLOCKWHISPERS,
		    NULL, HFILL }
		},
		{ &hf_ts2_status_away,
		  { "Away", "ts2.playerstatusflags.away",
		    FT_BOOLEAN, 8,
		    NULL, TS2_STATUS_AWAY,
		    NULL, HFILL }
		},
		{ &hf_ts2_status_mutemicrophone,
		  { "Mute Microphone", "ts2.playerstatusflags.mutemicrophone",
		    FT_BOOLEAN, 8,
		    NULL, TS2_STATUS_MUTEMICROPHONE,
		    NULL, HFILL }
		},
		{ &hf_ts2_status_mute,
		  { "Mute", "ts2.playerstatusflags.mute",
		    FT_BOOLEAN, 8,
		    NULL, TS2_STATUS_MUTE,
		    NULL, HFILL }
		},
		{ &hf_msg_fragments,
		  {"Message fragments", "ts2.fragments",
		   FT_NONE, BASE_NONE,
		   NULL, 0x00,
		   NULL, HFILL }
		},
		{ &hf_msg_fragment,
		  {"Message fragment", "ts2.fragment",
		   FT_FRAMENUM, BASE_NONE,
		   NULL, 0x00,
		   NULL, HFILL }
		},
		{ &hf_msg_fragment_overlap,
		  {"Message fragment overlap", "ts2.fragment.overlap",
		   FT_BOOLEAN, BASE_NONE,
		   NULL, 0x0,
		   NULL, HFILL }
		},
		{ &hf_msg_fragment_overlap_conflicts,
		  {"Message fragment overlapping with conflicting data",
		   "ts2.fragment.overlap.conflicts",
		   FT_BOOLEAN, BASE_NONE,
		   NULL, 0x0,
		   NULL, HFILL }
		},
		{ &hf_msg_fragment_multiple_tails,
		  {"Message has multiple tail fragments",
		   "ts2.fragment.multiple_tails",
		   FT_BOOLEAN, BASE_NONE,
		   NULL, 0x0,
		   NULL, HFILL }
		},
		{ &hf_msg_fragment_too_long_fragment,
		  {"Message fragment too long", "ts2.fragment.too_long_fragment",
		   FT_BOOLEAN, BASE_NONE,
		   NULL, 0x0,
		   NULL, HFILL }
		},
		{ &hf_msg_fragment_error,
		  {"Message defragmentation error", "ts2.fragment.error",
		   FT_FRAMENUM, BASE_NONE,
		   NULL, 0x00,
		   NULL, HFILL }
		},
		{ &hf_msg_fragment_count,
		  {"Message fragment count", "ts2.fragment.count",
		   FT_UINT32, BASE_DEC,
		   NULL, 0x00,
		   NULL, HFILL }
		},
		{ &hf_msg_reassembled_in,
		  {"Reassembled in", "ts2.reassembled.in",
		   FT_FRAMENUM, BASE_NONE,
		   NULL, 0x00,
		   NULL, HFILL }
		},
		{ &hf_msg_reassembled_length,
		  {"Reassembled TeamSpeak2 length", "ts2.reassembled.length",
		   FT_UINT32, BASE_DEC,
		   NULL, 0x00,
		   NULL, HFILL }
		},
		{ &hf_ts2_channel_unregistered,
		  { "Unregistered", "ts2.channelflags.unregistered",
		    FT_BOOLEAN, 8,
		    NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_moderated,
		  { "Moderated", "ts2.channelflags.moderated",
		    FT_BOOLEAN, 8,
		    NULL, 0x02,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_password,
		  { "Has password", "ts2.channelflags.has_password",
		    FT_BOOLEAN, 8,
		    NULL, 0x04,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_subchannels,
		  { "Has subchannels", "ts2.channelflags.has_subchannels",
		    FT_BOOLEAN, 8,
		    NULL, 0x08,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_default,
		  { "Default", "ts2.channelflags.default",
		    FT_BOOLEAN, 8,
		    NULL, 0x10,
		    NULL, HFILL }
		},
		{ &hf_ts2_channel_order,
		  { "Channel order", "ts2.channelorder",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_ts2_max_users,
		  { "Max users", "ts2.maxusers",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x00,
		    NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_ts2,
		&ett_msg_fragment,
		&ett_msg_fragments,
		&ett_ts2_channel_flags
	};

	/* Setup protocol subtree array */
	proto_ts2 = proto_register_protocol (
		"Teamspeak2 Protocol",	/* name */
		"TeamSpeak2",		/* short name */
		"ts2"			/* abbrev */
		);
	proto_register_field_array(proto_ts2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine(ts2_init);
}

/*
 * proto_reg_handoff_ts2()
 * */
void proto_reg_handoff_ts2(void)
{
	dissector_handle_t ts2_handle;
	ts2_handle = create_dissector_handle(dissect_ts2, proto_ts2);
	dissector_add_uint("udp.port", TS2_PORT, ts2_handle);
}

