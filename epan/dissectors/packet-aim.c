/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2004, Devin Heitmueller <dheitmueller@netilla.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>

#include "packet-tcp.h"
#include "packet-tls.h"
#include <epan/prefs.h>
#include <epan/expert.h>

void proto_register_aim(void);
void proto_reg_handoff_aim(void);

#define TCP_PORTS_AIM_DEFAULT "5190"

#define STRIP_TAGS 1

/* SNAC families */
#define FAMILY_GENERIC    0x0001
#define FAMILY_LOCATION   0x0002
#define FAMILY_BUDDYLIST  0x0003
#define FAMILY_MESSAGING  0x0004
#define FAMILY_ADVERTS    0x0005
#define FAMILY_INVITATION 0x0006
#define FAMILY_ADMIN      0x0007
#define FAMILY_POPUP      0x0008
#define FAMILY_BOS        0x0009
#define FAMILY_USERLOOKUP 0x000A
#define FAMILY_STATS      0x000B
#define FAMILY_TRANSLATE  0x000C
#define FAMILY_CHAT_NAV   0x000D
#define FAMILY_CHAT       0x000E
#define FAMILY_DIRECTORY  0x000F
#define FAMILY_SST        0x0010
#define FAMILY_SSI        0x0013
#define FAMILY_ICQ        0x0015
#define FAMILY_SIGNON     0x0017
#define FAMILY_EMAIL      0x0018
#define FAMILY_OFT        0xfffe

/* channels */
#define CHANNEL_NEW_CONN    0x01
#define CHANNEL_SNAC_DATA   0x02
#define CHANNEL_FLAP_ERR    0x03
#define CHANNEL_CLOSE_CONN  0x04
#define CHANNEL_KEEP_ALIVE  0x05

#define FAMILY_ALL_ERROR_INVALID_HEADER                0x0001
#define FAMILY_ALL_ERROR_SERVER_RATE_LIMIT_EXCEEDED    0x0002
#define FAMILY_ALL_ERROR_CLIENT_RATE_LIMIT_EXCEEDED    0x0003
#define FAMILY_ALL_ERROR_RECIPIENT_NOT_LOGGED_IN       0x0004
#define FAMILY_ALL_ERROR_REQUESTED_SERVICE_UNAVAILABLE 0x0005
#define FAMILY_ALL_ERROR_REQUESTED_SERVICE_NOT_DEFINED 0x0006
#define FAMILY_ALL_ERROR_OBSOLETE_SNAC                 0x0007
#define FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_SERVER       0x0008
#define FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_CLIENT       0x0009
#define FAMILY_ALL_ERROR_REFUSED_BY_CLIENT             0x000a
#define FAMILY_ALL_ERROR_REPLY_TOO_BIG                 0x000b
#define FAMILY_ALL_ERROR_RESPONSES_LOST                0x000c
#define FAMILY_ALL_ERROR_REQUEST_DENIED                0x000d
#define FAMILY_ALL_ERROR_INCORRECT_SNAC_FORMAT         0x000e
#define FAMILY_ALL_ERROR_INSUFFICIENT_RIGHTS           0x000f
#define FAMILY_ALL_ERROR_RECIPIENT_BLOCKED             0x0010
#define FAMILY_ALL_ERROR_SENDER_TOO_EVIL               0x0011
#define FAMILY_ALL_ERROR_RECEIVER_TOO_EVIL             0x0012
#define FAMILY_ALL_ERROR_USER_TEMP_UNAVAILABLE         0x0013
#define FAMILY_ALL_ERROR_NO_MATCH                      0x0014
#define FAMILY_ALL_ERROR_LIST_OVERFLOW                 0x0015
#define FAMILY_ALL_ERROR_REQUEST_AMBIGUOUS             0x0016
#define FAMILY_ALL_ERROR_SERVER_QUEUE_FULL             0x0017
#define FAMILY_ALL_ERROR_NOT_WHILE_ON_AOL              0x0018

static const value_string aim_flap_channels[] = {
	{ CHANNEL_NEW_CONN,   "New Connection" },
	{ CHANNEL_SNAC_DATA,  "SNAC Data" },
	{ CHANNEL_FLAP_ERR,   "FLAP-Level Error" },
	{ CHANNEL_CLOSE_CONN, "Close Connection" },
	{ CHANNEL_KEEP_ALIVE, "Keep Alive" },
	{ 0, NULL }
};

static const value_string aim_snac_errors[] = {
	{ FAMILY_ALL_ERROR_INVALID_HEADER,		  "Invalid SNAC Header" },
	{ FAMILY_ALL_ERROR_SERVER_RATE_LIMIT_EXCEEDED,	  "Server rate limit exceeded" },
	{ FAMILY_ALL_ERROR_CLIENT_RATE_LIMIT_EXCEEDED,	  "Client rate limit exceeded" },
	{ FAMILY_ALL_ERROR_RECIPIENT_NOT_LOGGED_IN,	  "Recipient not logged in" },
	{ FAMILY_ALL_ERROR_REQUESTED_SERVICE_UNAVAILABLE, "Requested service unavailable" },
	{ FAMILY_ALL_ERROR_REQUESTED_SERVICE_NOT_DEFINED, "Requested service not defined" },
	{ FAMILY_ALL_ERROR_OBSOLETE_SNAC,		  "Obsolete SNAC issued" },
	{ FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_SERVER,	  "Not supported by server" },
	{ FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_CLIENT,	  "Not supported by client" },
	{ FAMILY_ALL_ERROR_REFUSED_BY_CLIENT,		  "Refused by client" },
	{ FAMILY_ALL_ERROR_REPLY_TOO_BIG,		  "Reply too big" },
	{ FAMILY_ALL_ERROR_RESPONSES_LOST,		  "Responses lost" },
	{ FAMILY_ALL_ERROR_REQUEST_DENIED,		  "Request denied" },
	{ FAMILY_ALL_ERROR_INCORRECT_SNAC_FORMAT,	  "Incorrect SNAC format" },
	{ FAMILY_ALL_ERROR_INSUFFICIENT_RIGHTS,		  "Insufficient rights" },
	{ FAMILY_ALL_ERROR_RECIPIENT_BLOCKED,		  "Recipient blocked" },
	{ FAMILY_ALL_ERROR_SENDER_TOO_EVIL,		  "Sender too evil" },
	{ FAMILY_ALL_ERROR_RECEIVER_TOO_EVIL,		  "Receiver too evil" },
	{ FAMILY_ALL_ERROR_USER_TEMP_UNAVAILABLE,	  "User temporarily unavailable" },
	{ FAMILY_ALL_ERROR_NO_MATCH,			  "No match" },
	{ FAMILY_ALL_ERROR_LIST_OVERFLOW,		  "List overflow" },
	{ FAMILY_ALL_ERROR_REQUEST_AMBIGUOUS,		  "Request ambiguous" },
	{ FAMILY_ALL_ERROR_SERVER_QUEUE_FULL,		  "Server queue full" },
	{ FAMILY_ALL_ERROR_NOT_WHILE_ON_AOL,		  "Not while on AOL" },
	{ 0, NULL }
};

static int dissect_aim_tlv_value_userstatus(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_);
static int dissect_aim_tlv_value_dcinfo(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_);
static int dissect_aim_tlv_value_client_short_capabilities(proto_item *ti, uint16_t, tvbuff_t *, packet_info *);


#define DC_DISABLED		0x0000
#define DC_HTTPS		0x0001
#define DC_SOCKS		0x0002
#define DC_NORMAL		0x0003
#define DC_IMPOSSIBLE	0x0004

static const value_string dc_types[] = {
	{ DC_DISABLED,	 "DC disabled" },
	{ DC_HTTPS,	 "DC thru firewall or HTTPS proxy" },
	{ DC_SOCKS,	 "DC thru SOCKS proxy" },
	{ DC_NORMAL,	 "Regular connection" },
	{ DC_IMPOSSIBLE, "DC not possible " },
	{ 0, NULL },
};

#define PROTO_VERSION_ICQ98	0x0004
#define PROTO_VERSION_ICQ99	0x0006
#define PROTO_VERSION_ICQ2K	0x0007
#define PROTO_VERSION_ICQ2K1	0x0008
#define PROTO_VERSION_ICQLITE	0x0009
#define PROTO_VERSION_ICQ2K3B	0x000A

static const value_string protocol_versions[] = {
	{ PROTO_VERSION_ICQ98,	 "ICQ '98" },
	{ PROTO_VERSION_ICQ99,	 "ICQ '99" },
	{ PROTO_VERSION_ICQ2K,	 "ICQ 2000" },
	{ PROTO_VERSION_ICQ2K1,	 "ICQ 2001" },
	{ PROTO_VERSION_ICQLITE, "ICQ Lite" },
	{ PROTO_VERSION_ICQ2K3B, "ICQ 2003B" },
	{ 0, NULL },
};

#define CONFIRM_STATUS_EMAIL_SENT 		 0x00
#define CONFIRM_STATUS_ALREADY_CONFIRMED 0x1E
#define CONFIRM_STATUS_SERVER_ERROR	     0x23

static const value_string confirm_statusses[] = {
	{ CONFIRM_STATUS_EMAIL_SENT, "A confirmation email has been sent" },
	{ CONFIRM_STATUS_ALREADY_CONFIRMED, "Account was already confirmed" },
	{ CONFIRM_STATUS_SERVER_ERROR, "Server couldn't start confirmation process" },
	{ 0, NULL }
};

#define CLASS_UNCONFIRMED            0x00000001
#define CLASS_ADMINISTRATOR          0x00000002
#define CLASS_AOL                    0x00000004
#define CLASS_COMMERCIAL             0x00000008
#define CLASS_AIM                    0x00000010
#define CLASS_AWAY                   0x00000020
#define CLASS_ICQ                    0x00000040
#define CLASS_WIRELESS               0x00000080
#define CLASS_UNKNOWN100             0x00000100
#define CLASS_IMF                    0x00000200
#define CLASS_BOT                    0x00000400
#define CLASS_UNKNOWN800             0x00000800
#define CLASS_ONE_WAY_WIRELESS       0x00001000
#define CLASS_UNKNOWN2000            0x00002000
#define CLASS_UNKNOWN4000            0x00004000
#define CLASS_UNKNOWN8000            0x00008000
#define CLASS_UNKNOWN10000           0x00010000
#define CLASS_UNKNOWN20000           0x00020000
#define CLASS_NO_KNOCK_KNOCK         0x00040000
#define CLASS_FORWARD_MOBILE         0x00080000

#define FNAC_FLAG_NEXT_IS_RELATED 	 0x0001
#define FNAC_FLAG_CONTAINS_VERSION	 0x8000


#define SSI_OP_RESULT_SUCCESS             0
#define SSI_OP_RESULT_DB_ERROR            1
#define SSI_OP_RESULT_NOT_FOUND           2
#define SSI_OP_RESULT_ALREADY_EXISTS      3
#define SSI_OP_RESULT_UNAVAILABLE         5
#define SSI_OP_RESULT_BAD_REQUEST        10
#define SSI_OP_RESULT_DB_TIME_OUT        11
#define SSI_OP_RESULT_OVER_ROW_LIMIT     12
#define SSI_OP_RESULT_NOT_EXECUTED       13
#define SSI_OP_RESULT_AUTH_REQUIRED      14
#define SSI_OP_RESULT_BAD_LOGINID        16
#define SSI_OP_RESULT_OVER_BUDDY_LIMIT   17
#define SSI_OP_RESULT_INSERT_SMART_GROUP 20
#define SSI_OP_RESULT_TIMEOUT            26

static const value_string aim_ssi_result_codes[] = {
	{ SSI_OP_RESULT_SUCCESS,	    "Success" },
	{ SSI_OP_RESULT_DB_ERROR,	    "Some kind of database error" },
	{ SSI_OP_RESULT_NOT_FOUND,	    "Item was not found for an update or delete" },
	{ SSI_OP_RESULT_ALREADY_EXISTS,	    "Item already exists for an insert" },
	{ SSI_OP_RESULT_UNAVAILABLE,	    "Server or database is not available" },
	{ SSI_OP_RESULT_BAD_REQUEST,	    "Request was not formed well" },
	{ SSI_OP_RESULT_DB_TIME_OUT,	    "Database timed out" },
	{ SSI_OP_RESULT_OVER_ROW_LIMIT,	    "Too many items of this class for an insert" },
	{ SSI_OP_RESULT_NOT_EXECUTED,	    "Not executed due to other error in same request" },
	{ SSI_OP_RESULT_AUTH_REQUIRED,	    "Buddy List authorization required" },
	{ SSI_OP_RESULT_BAD_LOGINID,	    "Bad loginId" },
	{ SSI_OP_RESULT_OVER_BUDDY_LIMIT,   "Too many buddies" },
	{ SSI_OP_RESULT_INSERT_SMART_GROUP, "Attempt to added a Buddy to a smart group" },
	{ SSI_OP_RESULT_TIMEOUT,	    "General timeout" },
	{ 0, NULL }
};

#define FAMILY_SSI_TYPE_BUDDY         0x0000
#define FAMILY_SSI_TYPE_GROUP         0x0001
#define FAMILY_SSI_TYPE_PERMIT        0x0002
#define FAMILY_SSI_TYPE_DENY          0x0003
#define FAMILY_SSI_TYPE_PDINFO        0x0004
#define FAMILY_SSI_TYPE_PRESENCEPREFS 0x0005
#define FAMILY_SSI_TYPE_ICONINFO      0x0014

static const value_string aim_fnac_family_ssi_types[] = {
	{ FAMILY_SSI_TYPE_BUDDY,	 "Buddy" },
	{ FAMILY_SSI_TYPE_GROUP,	 "Group" },
	{ FAMILY_SSI_TYPE_PERMIT,	 "Permit" },
	{ FAMILY_SSI_TYPE_DENY,		 "Deny" },
	{ FAMILY_SSI_TYPE_PDINFO,	 "PDINFO" },
	{ FAMILY_SSI_TYPE_PRESENCEPREFS, "Presence Preferences" },
	{ FAMILY_SSI_TYPE_ICONINFO,	 "Icon Info" },
	{ 0, NULL }
};

typedef struct _aim_tlv {
	uint16_t valueid;
	const char *desc;
	int (*dissector) (proto_item *ti, uint16_t value_id, tvbuff_t *tvb, packet_info *);
} aim_tlv;

typedef struct _aim_subtype {
	uint16_t id;
	const char *name;
	int (*dissector) (tvbuff_t *, packet_info *, proto_tree *);
} aim_subtype;

typedef struct _aim_family {
	int ett;
	int proto_id;
	protocol_t *proto;
	uint16_t family;
	const char *name;
	const aim_subtype *subtypes;
} aim_family;

static int dissect_aim_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, const aim_tlv *);

static int dissect_aim_tlv_value_uint16(proto_item *ti, uint16_t, tvbuff_t *, packet_info *);


static int proto_aim;
static int proto_aim_admin;
static int proto_aim_adverts;
static int proto_aim_bos;
static int proto_aim_buddylist;
static int proto_aim_chat;
static int proto_aim_chatnav;
static int proto_aim_directory;
static int proto_aim_email;
static int proto_aim_generic;
static int proto_aim_icq;
static int proto_aim_invitation;
static int proto_aim_location;
static int proto_aim_messaging;
static int proto_aim_popup;
static int proto_aim_signon;
static int proto_aim_ssi;
static int proto_aim_sst;
static int proto_aim_stats;
static int proto_aim_translate;
static int proto_aim_userlookup;


static int hf_aim_cmd_start;
static int hf_aim_channel;
static int hf_aim_seqno;
static int hf_aim_data;
static int hf_aim_data_len;
static int hf_aim_tlv_length;
static int hf_aim_tlv_value_id;
static int hf_aim_fnac_family;
static int hf_aim_fnac_subtype;
static int hf_aim_fnac_flags;
static int hf_aim_fnac_flag_next_is_related;
static int hf_aim_fnac_flag_contains_version;
static int hf_aim_fnac_id;
static int hf_aim_buddyname_len;
static int hf_aim_buddyname;
static int hf_aim_userinfo_warninglevel;
static int hf_aim_snac_error;
static int hf_aim_ssi_result_code;
static int hf_aim_tlvcount;
static int hf_aim_version;
static int hf_aim_userclass_unconfirmed;
static int hf_aim_userclass_administrator;
static int hf_aim_userclass_aol;
static int hf_aim_userclass_commercial;
static int hf_aim_userclass_aim;
static int hf_aim_userclass_away;
static int hf_aim_userclass_icq;
static int hf_aim_userclass_wireless;
static int hf_aim_userclass_unknown100;
static int hf_aim_userclass_imf;
static int hf_aim_userclass_bot;
static int hf_aim_userclass_unknown800;
static int hf_aim_userclass_one_way_wireless;
static int hf_aim_userclass_unknown2000;
static int hf_aim_userclass_unknown4000;
static int hf_aim_userclass_unknown8000;
static int hf_aim_userclass_unknown10000;
static int hf_aim_userclass_unknown20000;
static int hf_aim_userclass_no_knock_knock;
static int hf_aim_userclass_forward_mobile;
static int hf_aim_nickinfo_caps;
static int hf_aim_nickinfo_short_caps;
static int hf_aim_messageblock_featuresdes;
static int hf_aim_messageblock_featureslen;
static int hf_aim_messageblock_features;
static int hf_aim_messageblock_info;
static int hf_aim_messageblock_len;
static int hf_aim_messageblock_charset;
static int hf_aim_messageblock_charsubset;
static int hf_aim_messageblock_message;

static int hf_aim_dcinfo_ip;
static int hf_aim_dcinfo_tcpport;
static int hf_aim_dcinfo_type;
static int hf_aim_dcinfo_proto_version;
static int hf_aim_dcinfo_auth_cookie;
static int hf_aim_dcinfo_webport;
static int hf_aim_dcinfo_client_future;
static int hf_aim_dcinfo_last_info_update;
static int hf_aim_dcinfo_last_ext_info_update;
static int hf_aim_dcinfo_last_ext_status_update;
static int hf_aim_dcinfo_unknown;
static int hf_aim_string08;

static int hf_admin_acctinfo_code;
static int hf_admin_acctinfo_unknown;
static int hf_admin_acctinfo_permissions;
static int hf_admin_confirm_status;

/* static int hf_aim_bos_data; */
static int hf_aim_bos_class;

static int hf_aim_buddylist_userinfo_warninglevel;

static int hf_aim_chat_screen_name;

static int hf_generic_motd_motdtype;
static int hf_generic_family;
static int hf_generic_version;
static int hf_generic_dll_version;
static int hf_generic_servicereq_service;
static int hf_generic_rateinfo_numclasses;
static int hf_generic_rateinfo_windowsize;
static int hf_generic_rateinfo_clearlevel;
static int hf_generic_rateinfo_alertlevel;
static int hf_generic_rateinfo_limitlevel;
static int hf_generic_rateinfo_disconnectlevel;
static int hf_generic_rateinfo_currentlevel;
static int hf_generic_rateinfo_maxlevel;
static int hf_generic_rateinfo_lasttime;
static int hf_generic_rateinfo_curstate;
static int hf_generic_rateinfo_classid;
static int hf_generic_rateinfo_numpairs;
static int hf_generic_rateinfoack_group;
static int hf_generic_ratechange_msg;
static int hf_generic_migration_numfams;
static int hf_generic_priv_flags;
static int hf_generic_allow_idle_see;
static int hf_generic_allow_member_see;
static int hf_generic_selfinfo_warninglevel;
static int hf_generic_evil_new_warn_level;
static int hf_generic_idle_time;
static int hf_generic_client_ver_req_offset;
static int hf_generic_client_ver_req_length;
static int hf_generic_client_ver_req_hash;
static int hf_generic_ext_status_type;
static int hf_generic_ext_status_length;
static int hf_generic_ext_status_flags;
static int hf_generic_ext_status_data;

static int hf_icq_tlv_data_chunk_size;
static int hf_icq_tlv_request_owner_uid;
static int hf_icq_tlv_request_type;
static int hf_icq_meta_subtype;
static int hf_icq_tlv_request_seq_num;
static int hf_icq_dropped_msg_flag;

static int hf_aim_snac_location_request_user_info_infotype;
static int hf_aim_location_userinfo_warninglevel;
static int hf_aim_location_buddyname_len;
static int hf_aim_location_buddyname;

static int hf_aim_icbm_channel;
static int hf_aim_icbm_cookie;
static int hf_aim_icbm_msg_flags;
static int hf_aim_icbm_max_sender_warnlevel;
static int hf_aim_icbm_max_receiver_warnlevel;
static int hf_aim_icbm_max_snac_size;
static int hf_aim_icbm_min_msg_interval;
static int hf_aim_icbm_notification_cookie;
static int hf_aim_icbm_notification_channel;
static int hf_aim_icbm_notification_type;
static int hf_aim_icbm_rendezvous_nak;
static int hf_aim_icbm_rendezvous_nak_length;
static int hf_aim_message_channel_id;
static int hf_aim_icbm_evil;
static int hf_aim_evil_warn_level;
static int hf_aim_evil_new_warn_level;
static int hf_aim_rendezvous_msg_type;
static int hf_aim_icbm_client_err_reason;
static int hf_aim_icbm_client_err_protocol_version;
static int hf_aim_icbm_client_err_client_caps_flags;
static int hf_aim_rendezvous_extended_data_message_type;
static int hf_aim_rendezvous_extended_data_message_flags;
static int hf_aim_rendezvous_extended_data_message_flags_normal;
static int hf_aim_rendezvous_extended_data_message_flags_auto;
static int hf_aim_rendezvous_extended_data_message_flags_multi;
static int hf_aim_rendezvous_extended_data_message_status_code;
static int hf_aim_rendezvous_extended_data_message_priority_code;
static int hf_aim_rendezvous_extended_data_message_text_length;
static int hf_aim_rendezvous_extended_data_message_text;

static int hf_aim_messaging_plugin;
static int hf_aim_icbm_client_err_length;
static int hf_aim_messaging_unknown_uint8;
static int hf_aim_messaging_unknown_uint16;
static int hf_aim_icbm_client_err_downcounter;
static int hf_aim_messaging_unknown_data;
static int hf_aim_messaging_plugin_specific_data;

static int hf_aim_infotype;
static int hf_aim_signon_challenge_len;
static int hf_aim_signon_challenge;

static int hf_aim_fnac_subtype_ssi_version;
static int hf_aim_fnac_subtype_ssi_numitems;
static int hf_aim_fnac_subtype_ssi_last_change_time;
static int hf_aim_fnac_subtype_ssi_buddyname_len;
static int hf_aim_fnac_subtype_ssi_buddyname_len8;
static int hf_aim_fnac_subtype_ssi_buddyname;
static int hf_aim_fnac_subtype_ssi_gid;
static int hf_aim_fnac_subtype_ssi_bid;
static int hf_aim_fnac_subtype_ssi_type;
static int hf_aim_fnac_subtype_ssi_tlvlen;
/* static int hf_aim_fnac_subtype_ssi_data; */
static int hf_aim_fnac_subtype_ssi_reason_str_len;
static int hf_aim_fnac_subtype_ssi_reason_str;
static int hf_aim_fnac_subtype_ssi_grant_auth_unkn;
static int hf_aim_fnac_subtype_ssi_allow_auth;

static int hf_aim_sst_unknown;
static int hf_aim_sst_md5_hash;
static int hf_aim_sst_md5_hash_size;
static int hf_aim_sst_ref_num;
static int hf_aim_sst_icon_size;
static int hf_aim_sst_icon;

static int hf_aim_userlookup_email;

/* Initialize the subtree pointers */
static int ett_aim;
static int ett_aim_dcinfo;
static int ett_aim_buddyname;
static int ett_aim_fnac;
static int ett_aim_fnac_flags;
static int ett_aim_tlv;
static int ett_aim_tlv_value;
static int ett_aim_userclass;
static int ett_aim_messageblock;
static int ett_aim_nickinfo_caps;
static int ett_aim_nickinfo_short_caps;
static int ett_aim_string08_array;

static int ett_aim_admin;
static int ett_aim_adverts;
static int ett_aim_bos;
static int ett_aim_buddylist;
static int ett_aim_chat;
static int ett_aim_chatnav;
static int ett_aim_directory;
static int ett_aim_email;

static int ett_generic_clientready;
static int ett_generic_migratefamilies;
static int ett_generic_clientready_item;
static int ett_generic_serverready;
static int ett_generic;
static int ett_generic_priv_flags;
static int ett_generic_rateinfo_class;
static int ett_generic_rateinfo_classes;
static int ett_generic_rateinfo_groups;
static int ett_generic_rateinfo_group;

static int ett_aim_invitation;
static int ett_aim_icq;
static int ett_aim_icq_tlv;
static int ett_aim_location;
static int ett_aim_messaging;
static int ett_aim_rendezvous_data;
static int ett_aim_extended_data;
static int ett_aim_extended_data_message_flags;
static int ett_aim_popup;
static int ett_aim_signon;
static int ett_aim_ssi;
static int ett_ssi;
static int ett_aim_sst;
static int ett_aim_stats;
static int ett_aim_translate;
static int ett_aim_userlookup;

static expert_field ei_aim_messageblock_len;

/* desegmentation of AIM over TCP */
static bool aim_desegment = true;

static dissector_handle_t aim_handle;

static GList *families;

static const aim_subtype
*aim_get_subtype( uint16_t famnum, uint16_t subtype )
{
	GList *gl = families;
	while(gl) {
		aim_family *fam = (aim_family *)gl->data;
		if(fam->family == famnum) {
			int i;
			for(i = 0; fam->subtypes[i].name; i++) {
				if(fam->subtypes[i].id == subtype) return &(fam->subtypes[i]);
			}
		}
		gl = gl->next;
	}

	return NULL;

}

static const aim_family
*aim_get_family( uint16_t famnum )
{
	GList *gl = families;
	while(gl) {
		aim_family *fam = (aim_family *)gl->data;
		if(fam->family == famnum) return fam;
		gl = gl->next;
	}

	return NULL;
}

static int
aim_get_buddyname(wmem_allocator_t *pool, uint8_t **name, tvbuff_t *tvb, int offset)
{
	uint8_t buddyname_length;

	buddyname_length = tvb_get_uint8(tvb, offset);

	*name = tvb_get_string_enc(pool, tvb, offset + 1, buddyname_length, ENC_UTF_8|ENC_NA);

	return buddyname_length;
}


static void
aim_get_message( unsigned char *msg, tvbuff_t *tvb, int msg_offset, int msg_length)
{
	int i,j,c;
	int bracket = false;
	int max, tagchars = 0;
	int new_offset = msg_offset;
	int new_length = msg_length;


	/* make sure nothing bigger than 1000 bytes is printed */
	if( msg_length > 999 ) return;

	memset( msg, '\0', 1000);
	i = 0;
	c = 0;

	/* loop until HTML tag is reached - quick&dirty way to find start of message
	 * (it is nearly impossible to find the correct start offset for all client versions) */
	while( (tagchars < 6) && (new_length > 5) )
	{
		j = tvb_get_uint8(tvb, new_offset);
		if( ( (j == '<') && (tagchars == 0) ) ||
		    ( (j == 'h') && (tagchars == 1) ) ||
		    ( (j == 'H') && (tagchars == 1) ) ||
		    ( (j == 't') && (tagchars == 2) ) ||
		    ( (j == 'T') && (tagchars == 2) ) ||
		    ( (j == 'm') && (tagchars == 3) ) ||
		    ( (j == 'M') && (tagchars == 3) ) ||
		    ( (j == 'l') && (tagchars == 4) ) ||
		    ( (j == 'L') && (tagchars == 4) ) ||
		    ( (j == '>') && (tagchars == 5) ) ) tagchars++;
		new_offset++;
		new_length--;
	}

	/* set offset and length of message to after the first HTML tag */
	msg_offset = new_offset;
	msg_length = new_length;
	max = msg_length - 1;
	tagchars = 0;

	/* find the rest of the message until either a </html> is reached or the end of the frame.
	 * All other HTML tags are stripped to display only the raw message (printable characters) */
	while( (c < max) && (tagchars < 7) )
	{
		j = tvb_get_uint8(tvb, msg_offset+c);


		/* make sure this is an HTML tag by checking the order of the chars */
		if( ( (j == '<') && (tagchars == 0) ) ||
		    ( (j == '/') && (tagchars == 1) ) ||
		    ( (j == 'h') && (tagchars == 2) ) ||
		    ( (j == 'H') && (tagchars == 2) ) ||
		    ( (j == 't') && (tagchars == 3) ) ||
		    ( (j == 'T') && (tagchars == 3) ) ||
		    ( (j == 'm') && (tagchars == 4) ) ||
		    ( (j == 'M') && (tagchars == 4) ) ||
		    ( (j == 'l') && (tagchars == 5) ) ||
		    ( (j == 'L') && (tagchars == 5) ) ||
		    ( (j == '>') && (tagchars == 6) ) ) tagchars++;

#ifdef STRIP_TAGS
		if( j == '<' ) bracket = true;
		if( j == '>' ) bracket = false;
		if( (g_ascii_isprint(j) ) && (bracket == false) && (j != '>'))
#else
			if( g_ascii_isprint(j) )
#endif
			{
				msg[i] = j;
				i++;
			}
		c++;
	}
}

static void
aim_init_family(int proto, int ett, uint16_t family, const aim_subtype *subtypes)
{
	aim_family *fam = g_new(aim_family, 1);
	fam->proto = find_protocol_by_id(proto);
	fam->name = proto_get_protocol_short_name(fam->proto);
	fam->family = family;
	fam->subtypes = subtypes;
	families = g_list_append(families, fam);

	fam->proto_id = proto;
	fam->ett = ett;
}

static int
dissect_aim_ssi_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aim_tree)
{
	col_add_str(pinfo->cinfo, COL_INFO,
	    val_to_str(tvb_get_ntohs(tvb, 0), aim_ssi_result_codes, "Unknown SSI result code 0x%02x"));

	proto_tree_add_item (aim_tree, hf_aim_ssi_result_code, tvb, 0, 2, ENC_BIG_ENDIAN);

	return 2;
}

#define FNAC_TLV_FAMILY_VERSION  0x0001

static const aim_tlv aim_fnac_tlvs[] = {
	{ FNAC_TLV_FAMILY_VERSION, "SNAC Family Version", dissect_aim_tlv_value_uint16 },
	{ 0, NULL, NULL }
};

static void
dissect_aim_snac(tvbuff_t *tvb, packet_info *pinfo, int offset,
		 proto_tree *aim_tree, proto_tree *root_tree)
{
	uint16_t family_id;
	uint16_t subtype_id;
	uint16_t flags;
	uint32_t id;
	proto_tree *aim_tree_fnac = NULL;
	tvbuff_t *subtvb;
	int orig_offset;
	const aim_subtype *subtype;
	proto_tree *family_tree = NULL;
	const aim_family *family;

	orig_offset = offset;
	family_id = tvb_get_ntohs(tvb, offset);
	family = aim_get_family(family_id);
	offset += 2;
	subtype_id = tvb_get_ntohs(tvb, offset);
	subtype = aim_get_subtype(family_id, subtype_id);
	offset += 2;
	flags = tvb_get_ntohs(tvb, offset);
	offset += 2;
	id = tvb_get_ntohl(tvb, offset);
	offset += 4;

	if( aim_tree && subtype != NULL )
	{
		static int * const fnac_flags[] = {
			&hf_aim_fnac_flag_next_is_related,
			&hf_aim_fnac_flag_contains_version,
			NULL
		};

		offset = orig_offset;
		aim_tree_fnac = proto_tree_add_subtree_format(aim_tree, tvb, 6, 10, ett_aim_fnac, NULL,
					  "FNAC: Family: %s (0x%04x), Subtype: %s (0x%04x)",
					  family ? family->name : "Unknown", family_id,
					  (subtype && subtype->name) ? subtype->name : "Unknown", subtype_id);

		proto_tree_add_uint_format_value (aim_tree_fnac, hf_aim_fnac_family,
						  tvb, offset, 2, family_id, "%s (0x%04x)",
						  family ? family->name : "Unknown", family_id);
		offset += 2;

		proto_tree_add_uint_format_value (aim_tree_fnac, hf_aim_fnac_subtype,
						  tvb, offset, 2, subtype_id, "%s (0x%04x)",
						  (subtype && subtype->name) ? subtype->name : "Unknown", subtype_id);

		offset += 2;

		proto_tree_add_bitmask(aim_tree_fnac, tvb, offset, hf_aim_fnac_flags,
			       ett_aim_fnac_flags, fnac_flags, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_id, tvb, offset,
				    4, id);
		offset += 4;
	}

	if(flags & FNAC_FLAG_CONTAINS_VERSION)
	{
		uint16_t len = tvb_get_ntohs(tvb, offset);
		int oldoffset;
		offset+=2;
		oldoffset = offset;

		while(offset < oldoffset + len) {
			offset = dissect_aim_tlv(tvb, pinfo, offset, aim_tree, aim_fnac_tlvs);
		}
	}

	subtvb = tvb_new_subset_remaining(tvb, offset);

	if (family)
		col_set_str(pinfo->cinfo, COL_PROTOCOL, family->name);

	if(subtype != NULL && family != NULL)
	{
		col_set_str(pinfo->cinfo, COL_INFO, family->name);
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", subtype->name);
	} else {
		col_set_str(pinfo->cinfo, COL_INFO, "SNAC data");

		if(family)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", family->name);
	 	else
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Family: 0x%04x", family_id);

	 	col_append_fstr(pinfo->cinfo, COL_INFO, ", Subtype: 0x%04x", subtype_id);
	}

	if(aim_tree && family != NULL)
	{
		proto_item *ti = proto_tree_add_item(root_tree, family->proto_id, subtvb, 0, -1, ENC_NA);
		family_tree = proto_item_add_subtree(ti, family->ett);
		if(subtype)
			proto_item_append_text(ti, ", %s", subtype->name);
	}

	if((tvb_reported_length_remaining(tvb, offset) > 0) && (subtype != NULL) && subtype->dissector)
	{
		subtype->dissector(subtvb, pinfo, family_tree);
	}
}

static void
dissect_aim_flap_err(tvbuff_t *tvb, packet_info *pinfo, int offset,
		     proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_INFO, "FLAP error");

	/* Show the undissected payload */
	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, ENC_NA);
}

static void
dissect_aim_keep_alive(tvbuff_t *tvb, packet_info *pinfo, int offset,
		       proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_INFO, "Keep Alive");

	/* Show the undissected payload */
	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, ENC_NA);
}

static void
dissect_aim_unknown_channel(tvbuff_t *tvb, packet_info *pinfo, int offset,
			    proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_INFO, "Unknown Channel");

	/* Show the undissected payload */
	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, ENC_NA);
}

static int
dissect_aim_buddyname(tvbuff_t *tvb, packet_info *pinfo _U_, int offset,
		      proto_tree *tree)
{
	uint8_t buddyname_length = 0;
	proto_tree *buddy_tree;

	buddyname_length = tvb_get_uint8(tvb, offset);
	offset++;

	if(tree)
	{
		buddy_tree = proto_tree_add_subtree_format(tree, tvb, offset-1, 1+buddyname_length,
					 ett_aim_buddyname, NULL, "Buddy: %s",
					 tvb_format_text(pinfo->pool, tvb, offset, buddyname_length));
		proto_tree_add_item(buddy_tree, hf_aim_buddyname_len, tvb, offset-1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(buddy_tree, hf_aim_buddyname, tvb, offset, buddyname_length, ENC_UTF_8);
	}

	return offset+buddyname_length;
}

typedef struct _aim_client_capability
{
	const char *name;
	e_guid_t clsid;
} aim_client_capability;

static const aim_client_capability known_client_caps[] = {
	{ "Send File",
	  {0x09461343, 0x4c7f, 0x11d1,
	    { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Recv File",
	    { 0x09461348, 0x4c7f, 0x11d1,
		   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Short Caps",
	 {0x09460000, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Secure IM",
	 {0x09460001, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "XHTML IM",
	 {0x09460002, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Video Chat",
	 {0x09460100, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Live Video",
	 {0x09460101, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Camera",
	 {0x09460102, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Microphone",
	 {0x09460103, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Live Audio",
	 {0x09460104, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "iChatAV info",
	 {0x09460105, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x45, 0x53, 0x54, 0x00}}},

	{ "Host Status Text Aware",
	 {0x0946010A, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x45, 0x53, 0x54, 0x00}}},

	{ "Realtime IM",
	 {0x0946010B, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x45, 0x53, 0x54, 0x00}}},

	{ "Smart Caps",
	 {0x094601FF, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x45, 0x53, 0x54, 0x00}}},

	{ "Hiptop",
	 {0x09461323, 0x4c7f, 0x11d1,
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Voice Chat",
	 {0x09461341, 0x4c7f, 0x11d1,
		 { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "File Transfer",
	 {0x09461343, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Direct ICQ Communication",
	 {0x09461344, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Direct ICBM",
	 {0x09461345, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Buddy Icon",
	 {0x09461346, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Add-Ins",
	 {0x09461347, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "File Sharing",
	 {0x09461348, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "ICQ Server Relaying",
	 {0x09461349, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Games",
	 {0x0946134a, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Games",
	 {0x0946134a, 0x4c7f, 0x11d1,
		 {0x22, 0x82, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Send Buddy List",
	 {0x0946134b, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "AIM/ICQ Interoperability",
	 {0x0946134d, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "ICQ UTF8 Support",
	 {0x0946134e, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Old ICQ UTF8 Support",
	 {0x2e7a6475, 0xfadf, 0x4dc8,
		 {0x88, 0x6f, 0xea, 0x35, 0x95, 0xfd, 0xb6, 0xdf}}},

	{ "Chat",
	 {0x748f2420, 0x6287, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "ICQ Rich Text Format Messages",
	 {0x97b12751, 0x243c, 0x4334,
		 {0xad, 0x22, 0xd6, 0xab, 0xf7, 0x3f, 0x14, 0x92}}},

	{ "AP User",
	 {0xaa4a32b5, 0xf884, 0x48c6,
		 {0xa3, 0xd7, 0x8c, 0x50, 0x97, 0x19, 0xfd, 0x5b}}},

	{ "Trillian Encryption",
	 {0xf2e7c7f4, 0xfead, 0x4dfb,
		 {0xb2, 0x35, 0x36, 0x79, 0x8b, 0xdf, 0x00, 0x00}}},

	{ NULL, {0x0, 0x0, 0x0, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } } }
};

static const aim_client_capability *
aim_find_capability (e_guid_t clsid)
{
	int i;

	for(i = 0; known_client_caps[i].name; i++)
	{
		const aim_client_capability *caps = &(known_client_caps[i]);

		if(memcmp(&(caps->clsid), &clsid, sizeof(e_guid_t)) == 0)
			return caps;
	}

	return NULL;
}

static const aim_client_capability *
aim_find_short_capability(uint16_t shortid)
{
	e_guid_t clsid = {0x09460000, 0x4c7f, 0x11d1, {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};
	clsid.data1 |= shortid;

	return aim_find_capability(clsid);
}

static int
dissect_aim_capability(proto_tree *entry, tvbuff_t *tvb, int offset)
{
	const aim_client_capability *caps;
	e_guid_t clsid;

	tvb_get_ntohguid(tvb, offset, &clsid);
	caps = aim_find_capability(clsid);

	proto_tree_add_guid_format(entry, hf_aim_nickinfo_caps, tvb, offset, 16,
		&clsid,
		"%s {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		caps?caps->name:"Unknown", clsid.data1, clsid.data2,
		clsid.data3, clsid.data4[0], clsid.data4[1], clsid.data4[2],
		clsid.data4[3], clsid.data4[4],	clsid.data4[5], clsid.data4[6],
		clsid.data4[7]
	);

	return offset+16;
}

static int
dissect_aim_short_capability(proto_tree *entry, tvbuff_t *tvb, int offset)
{
	const aim_client_capability *caps;
	uint16_t shortid;

	shortid = tvb_get_ntohs(tvb, offset);
	caps = aim_find_short_capability(shortid);

	proto_tree_add_uint_format(entry, hf_aim_nickinfo_short_caps, tvb, offset, 2,
		shortid,
		"%s (0x%04x)",
		caps?caps->name:"Unknown", shortid
	);

	return offset+2;
}

static int
dissect_aim_tlv_value_client_capabilities(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	proto_tree *entry;

	proto_item_set_text(ti, "Client Capabilities List");

	entry = proto_item_add_subtree(ti, ett_aim_nickinfo_caps);

 	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_capability(entry, tvb, offset);
	}

	return tvb_reported_length(tvb);
}

static int
dissect_aim_tlv_value_client_short_capabilities(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	proto_tree *entry;

	proto_item_set_text(ti, "Short Client Capabilities List");

	entry = proto_item_add_subtree(ti, ett_aim_nickinfo_short_caps);

 	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_short_capability(entry, tvb, offset);
	}

	return tvb_reported_length(tvb);
}

static int
dissect_aim_tlv_value_time(proto_item *ti _U_, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	/* FIXME */
	return tvb_reported_length(tvb);
}

static int
dissect_aim_userclass(tvbuff_t *tvb, int offset, int len, proto_item *ti, uint32_t value)
{
	proto_tree *entry;
	static int * const flags[] = {
		&hf_aim_userclass_unconfirmed,
		&hf_aim_userclass_administrator,
		&hf_aim_userclass_aol,
		&hf_aim_userclass_commercial,
		&hf_aim_userclass_aim,
		&hf_aim_userclass_away,
		&hf_aim_userclass_icq,
		&hf_aim_userclass_wireless,
		&hf_aim_userclass_unknown100,
		&hf_aim_userclass_imf,
		&hf_aim_userclass_bot,
		&hf_aim_userclass_unknown800,
		&hf_aim_userclass_one_way_wireless,
		&hf_aim_userclass_unknown2000,
		&hf_aim_userclass_unknown4000,
		&hf_aim_userclass_unknown8000,
		&hf_aim_userclass_unknown10000,
		&hf_aim_userclass_unknown20000,
		&hf_aim_userclass_no_knock_knock,
		&hf_aim_userclass_forward_mobile,
		NULL
	};

	entry = proto_item_add_subtree(ti, ett_aim_userclass);
	proto_tree_add_bitmask_list_value(entry, tvb, offset, len, flags, value);

	return offset+len;
}

static int
dissect_aim_tlv_value_userclass(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	uint16_t value16 = tvb_get_ntohs(tvb, 0);
	proto_item_set_text(ti, "Value: 0x%04x", value16);
	return dissect_aim_userclass(tvb, 0, 2, ti, value16);
}

static int
dissect_aim_tlv_value_userstatus(proto_item *ti _U_, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	/* FIXME */
	return tvb_reported_length(tvb);
}

static int
dissect_aim_tlv_value_dcinfo(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;

	proto_tree *dctree = proto_item_add_subtree(ti, ett_aim_dcinfo);

 	proto_tree_add_item(dctree, hf_aim_dcinfo_ip , tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_tcpport, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
	proto_tree_add_item(dctree, hf_aim_dcinfo_proto_version, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(dctree, hf_aim_dcinfo_auth_cookie, tvb, offset, 4, ENC_NA); offset+=2;
	proto_tree_add_item(dctree, hf_aim_dcinfo_webport, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_client_future, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_last_info_update, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_last_ext_info_update, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_last_ext_status_update, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_unknown, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

	return offset;
}

static int
dissect_aim_tlv_value_string (proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo)
{
	uint8_t *buf;
	int string_len;

	string_len = tvb_reported_length(tvb);
	buf = tvb_get_string_enc(pinfo->pool, tvb, 0, string_len, ENC_UTF_8|ENC_NA);
	proto_item_set_text(ti, "Value: %s", format_text(pinfo->pool, buf, string_len));

	return string_len;
}

static int
dissect_aim_tlv_value_string08_array (proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	proto_tree *entry;
	int offset=0;

	entry = proto_item_add_subtree(ti, ett_aim_string08_array);

	while (tvb_reported_length_remaining(tvb, offset) > 1)
	{
		uint8_t string_len = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(entry, hf_aim_string08, tvb, offset, 1, ENC_UTF_8|ENC_NA);
		offset += (string_len+1);
	}

	return offset;
}

static int
dissect_aim_tlv_value_bytes (proto_item *ti _U_, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	return tvb_reported_length(tvb);
}

static int
dissect_aim_tlv_value_uint8 (proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	uint8_t value8 = tvb_get_uint8(tvb, 0);
	proto_item_set_text(ti, "Value: %d", value8);
	return 1;
}

static int
dissect_aim_tlv_value_uint16 (proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	uint16_t value16 = tvb_get_ntohs(tvb, 0);
	proto_item_set_text(ti, "Value: %d", value16);
	return 2;
}

static int
dissect_aim_tlv_value_ipv4 (proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	proto_item_set_text(ti, "Value: %s", tvb_ip_to_str(pinfo->pool, tvb, 0));
	return 4;
}

static int
dissect_aim_tlv_value_uint32 (proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	uint32_t value32 = tvb_get_ntohl(tvb, 0);
	proto_item_set_text(ti, "Value: %d", value32);
	return 4;
}

static int
dissect_aim_tlv_value_messageblock (proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo)
{
	proto_tree *entry;
	uint8_t *buf;
	uint16_t featurelen;
	uint32_t blocklen;
	proto_item* len_item;
	int offset=0;

	/* Setup a new subtree */
	entry = proto_item_add_subtree(ti, ett_aim_messageblock);

	/* Features descriptor */
	proto_tree_add_item(entry, hf_aim_messageblock_featuresdes, tvb, offset,
			    2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Features Length */
	featurelen = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(entry, hf_aim_messageblock_featureslen, tvb, offset,
			    2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Features (should be expanded further @@@@@@@ ) */
	proto_tree_add_item(entry, hf_aim_messageblock_features, tvb, offset,
			    featurelen, ENC_NA);
	offset += featurelen;

	/* There can be multiple messages in this message block */
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		/* Info field */
		proto_tree_add_item(entry, hf_aim_messageblock_info, tvb,
				    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Block length (includes charset and charsubset) */
		len_item = proto_tree_add_item_ret_uint(entry, hf_aim_messageblock_len, tvb, offset,
				    2, ENC_BIG_ENDIAN, &blocklen);
		if (blocklen <= 4)
		{
			expert_add_info(pinfo, len_item, &ei_aim_messageblock_len);
			break;
		}
		offset += 2;

		/* Character set */
		proto_tree_add_item(entry, hf_aim_messageblock_charset, tvb,
				    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Character subset */
		proto_tree_add_item(entry, hf_aim_messageblock_charsubset, tvb,
				    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* The actual message */
		buf = tvb_get_string_enc(pinfo->pool, tvb, offset, blocklen - 4, ENC_ASCII|ENC_NA);
		proto_item_append_text(ti, "Message: %s ",
				    format_text(pinfo->pool, buf, blocklen - 4));
		proto_tree_add_item(entry, hf_aim_messageblock_message, tvb,
				    offset, blocklen-4, ENC_ASCII);

		offset += blocklen-4;
	}

	return offset;
}

/* Dissect a TLV value */
static int
dissect_aim_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset,
		proto_tree *tree, const aim_tlv *tlv)
{
	uint16_t valueid;
	uint16_t length;
	int i = 0;
	const aim_tlv *tmp;
	const char *desc;
	proto_item *ti1;
	proto_tree *tlv_tree;

	/* Get the value ID */
	valueid = tvb_get_ntohs(tvb, offset);

	/* Figure out which entry applies from the tlv list */
	tmp = tlv;
	while (tmp[i].valueid) {
		if (tmp[i].valueid == valueid) {
			/* We found a match */
			break;
		}
		i++;
	}

	/* At this point, we are either pointing at the correct record, or
	   we didn't find the record, and are pointing at the last item in the
	   list */

	length = tvb_get_ntohs(tvb, offset+2);

	if (tmp[i].desc != NULL)
		desc = tmp[i].desc;
	else
		desc = "Unknown";

	tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, length + 4,
												ett_aim_tlv, NULL, "TLV: %s", desc);

	proto_tree_add_uint_format_value(tlv_tree, hf_aim_tlv_value_id, tvb, offset, 2,
				    valueid, "%s (0x%04x)", desc, valueid);
	offset += 2;

	proto_tree_add_uint(tlv_tree, hf_aim_tlv_length, tvb, offset, 2, length);
	offset += 2;

	proto_tree_add_subtree(tlv_tree, tvb, offset, length, ett_aim_tlv_value, &ti1, "Value");

	if (tmp[i].dissector) {
		tmp[i].dissector(ti1, valueid, tvb_new_subset_length(tvb, offset, length), pinfo);
	}

	offset += length;

	/* Return the new length */
	return offset;
}

static int
dissect_aim_tlv_sequence(tvbuff_t *tvb, packet_info *pinfo, int offset,
			 proto_tree *tree, const aim_tlv *tlv_table)
{
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, tlv_table);
	}

	return offset;
}

static int
dissect_aim_tlv_list(tvbuff_t *tvb, packet_info *pinfo, int offset,
		     proto_tree *tree, const aim_tlv *tlv_table)
{
	uint16_t i, tlv_count = tvb_get_ntohs(tvb, offset);

	proto_tree_add_item(tree, hf_aim_tlvcount, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	for(i = 0; i < tlv_count; i++) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, tlv_table);
	}

	return offset;
}

#define AIM_CLIENT_TLV_SCREEN_NAME             0x0001
#define AIM_CLIENT_TLV_NEW_ROASTED_PASSWORD    0x0002
#define AIM_CLIENT_TLV_CLIENT_ID_STRING        0x0003
#define AIM_CLIENT_TLV_ERRORURL                0x0004
#define AIM_CLIENT_TLV_BOS_SERVER_STRING       0x0005
#define AIM_CLIENT_TLV_AUTH_COOKIE             0x0006
#define AIM_CLIENT_TLV_ERRORCODE               0x0008
#define AIM_CLIENT_TLV_DISCONNECT_REASON       0x0009
#define AIM_CLIENT_TLV_RECONNECT_HOST          0x000a
#define AIM_CLIENT_TLV_URL                     0x000b
#define AIM_CLIENT_TLV_DEBUG_DATA              0x000c
#define AIM_CLIENT_TLV_FAMILY_ID               0x000d
#define AIM_CLIENT_TLV_CLIENT_COUNTRY          0x000e
#define AIM_CLIENT_TLV_CLIENT_LANGUAGE         0x000f
#define AIM_CLIENT_TLV_EMAILADDR               0x0011
#define AIM_CLIENT_TLV_OLD_ROASTED_PASSWORD    0x0012
#define AIM_CLIENT_TLV_REGSTATUS               0x0013
#define AIM_CLIENT_TLV_CLIENT_DISTRIBUTION_NUM 0x0014
#define AIM_CLIENT_TLV_INVITEMESSAGE           0x0015
#define AIM_CLIENT_TLV_CLIENT_ID               0x0016
#define AIM_CLIENT_TLV_CLIENT_MAJOR_VERSION    0x0017
#define AIM_CLIENT_TLV_CLIENT_MINOR_VERSION    0x0018
#define AIM_CLIENT_TLV_CLIENT_LESSER_VERSION   0x0019
#define AIM_CLIENT_TLV_CLIENT_BUILD_NUMBER     0x001a
#define AIM_CLIENT_TLV_PASSWORD_MD5            0x0025
#define AIM_CLIENT_TLV_LATESTBETABUILD         0x0040
#define AIM_CLIENT_TLV_LATESTBETAURL           0x0041
#define AIM_CLIENT_TLV_LATESTBETAINFO          0x0042
#define AIM_CLIENT_TLV_LATESTBETANAME          0x0043
#define AIM_CLIENT_TLV_LATESTRELEASEBUILD      0x0044
#define AIM_CLIENT_TLV_LATESTRELEASEURL        0x0045
#define AIM_CLIENT_TLV_LATESTRELEASEINFO       0x0046
#define AIM_CLIENT_TLV_LATESTRELEASENAME       0x0047
#define AIM_CLIENT_TLV_BETA_DIGEST_SIG         0x0048
#define AIM_CLIENT_TLV_RELEASE_DIGEST_SIG      0x0049
#define AIM_CLIENT_TLV_CLIENTUSESSI            0x004a
#define AIM_CLIENT_TLV_CHANGE_PASSWORD_URL     0x0054
#define AIM_CLIENT_TLV_AWAITING_AUTH           0x0066
#define AIM_CLIENT_TLV_MEMBERS                 0x00c8
#define AIM_CLIENT_TLV_VISIBILITY_BITS         0x00c9
#define AIM_CLIENT_TLV_PRIVACY                 0x00ca
#define AIM_CLIENT_TLV_VISIBLE_CLASS           0x00cb
#define AIM_CLIENT_TLV_VISIBLE_MISC            0x00cc
#define AIM_CLIENT_TLV_ICQ2K_SHORTCUT          0x00cd
#define AIM_CLIENT_TLV_FIRST_LOADED_TIME       0x00d4
#define AIM_CLIENT_TLV_BUDDY_ICON_MD5SUM       0x00d5
#define AIM_CLIENT_TLV_GIVEN_NAME              0x0131
#define AIM_CLIENT_TLV_LOCAL_EMAIL             0x0137
#define AIM_CLIENT_TLV_LOCAL_SMS               0x013a
#define AIM_CLIENT_TLV_LOCAL_COMMENT           0x013c
#define AIM_CLIENT_TLV_LOCAL_PERSONAL_ALERT    0x013d
#define AIM_CLIENT_TLV_LOCAL_PERSONAL_SOUND    0x013e
#define AIM_CLIENT_TLV_FIRST_MESSAGE_SENT      0x0145

static const aim_tlv aim_client_tlvs[] = {
	{ AIM_CLIENT_TLV_SCREEN_NAME,		  "Screen name",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_NEW_ROASTED_PASSWORD,	  "Roasted password array",			       dissect_aim_tlv_value_bytes  },
	{ AIM_CLIENT_TLV_OLD_ROASTED_PASSWORD,	  "Old roasted password array",			       dissect_aim_tlv_value_bytes  },
	{ AIM_CLIENT_TLV_CLIENT_ID_STRING,	  "Client id string (name, version)",		       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_CLIENT_ID,		  "Client id number",				       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_CLIENT_MAJOR_VERSION,	  "Client major version",			       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_CLIENT_MINOR_VERSION,	  "Client minor version",			       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_CLIENT_LESSER_VERSION,	  "Client lesser version",			       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_CLIENT_BUILD_NUMBER,	  "Client build number",			       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_PASSWORD_MD5,		  "Password Hash (MD5)",			       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_CLIENT_DISTRIBUTION_NUM, "Client distribution number",			       dissect_aim_tlv_value_uint32 },
	{ AIM_CLIENT_TLV_CLIENT_LANGUAGE,	  "Client language",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_CLIENT_COUNTRY,	  "Client country",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_BOS_SERVER_STRING,	  "BOS server string",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_AUTH_COOKIE,		  "Authorization cookie",			       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_ERRORURL,		  "Error URL",					       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_ERRORCODE,		  "Error Code",					       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_DISCONNECT_REASON,	  "Disconnect Reason",				       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_RECONNECT_HOST,	  "Reconnect Hostname",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_URL,			  "URL",					       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_DEBUG_DATA,		  "Debug Data",					       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_EMAILADDR,		  "Account Email address",			       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_REGSTATUS,		  "Registration Status",			       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_LATESTBETABUILD,	  "Latest Beta Build",				       dissect_aim_tlv_value_uint32 },
	{ AIM_CLIENT_TLV_LATESTBETAURL,		  "Latest Beta URL",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LATESTBETAINFO,	  "Latest Beta Info",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LATESTBETANAME,	  "Latest Beta Name",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LATESTRELEASEBUILD,	  "Latest Release Build",			       dissect_aim_tlv_value_uint32 },
	{ AIM_CLIENT_TLV_LATESTRELEASEURL,	  "Latest Release URL",				       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LATESTRELEASEINFO,	  "Latest Release Info",			       dissect_aim_tlv_value_string  },
	{ AIM_CLIENT_TLV_LATESTRELEASENAME,	  "Latest Release Name",			       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_BETA_DIGEST_SIG,	  "Beta Digest Signature (MD5)" ,		       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_RELEASE_DIGEST_SIG,	  "Release Digest Signature (MD5)",		       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_CLIENTUSESSI,		  "Use SSI",					       dissect_aim_tlv_value_uint8 },
	{ AIM_CLIENT_TLV_FAMILY_ID,		  "Service (SNAC Family) ID",			       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_CHANGE_PASSWORD_URL,	  "Change password url",			       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_AWAITING_AUTH,		  "Awaiting Authorization",			       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_MEMBERS,		  "Members of this Group",			       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_VISIBILITY_BITS,	  "Bitfield",					       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_PRIVACY,		  "Privacy Settings" ,				       dissect_aim_tlv_value_uint8 },
	{ AIM_CLIENT_TLV_VISIBLE_CLASS,		  "Visible To Classes",				       dissect_aim_tlv_value_userclass },
	{ AIM_CLIENT_TLV_VISIBLE_MISC,		  "Allow Others to See Data",			       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_ICQ2K_SHORTCUT,	  "ICQ2K Shortcut List",			       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_FIRST_LOADED_TIME,	  "First Time Buddy Was Added (Unix Timestamp)" ,      dissect_aim_tlv_value_uint32 },
	{ AIM_CLIENT_TLV_BUDDY_ICON_MD5SUM,	  "MD5SUM of Current Buddy Icon",		       dissect_aim_tlv_value_bytes },
	{ AIM_CLIENT_TLV_GIVEN_NAME,		  "Locally Specified Buddy Name",		       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LOCAL_EMAIL,		  "Locally Specified Buddy Email",		       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LOCAL_SMS,		  "Locally Specified Buddy SMS",		       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LOCAL_COMMENT,		  "Locally Specified Buddy Comment",		       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_LOCAL_PERSONAL_ALERT,	  "Personal Alert for Buddy",			       dissect_aim_tlv_value_uint16 },
	{ AIM_CLIENT_TLV_LOCAL_PERSONAL_SOUND,	  "Personal Sound for Buddy",			       dissect_aim_tlv_value_string },
	{ AIM_CLIENT_TLV_FIRST_MESSAGE_SENT,	  "First Time Message Sent to Buddy (Unix Timestamp)", dissect_aim_tlv_value_uint32 },
	{ 0, NULL, NULL }
};

static void
dissect_aim_close_conn(tvbuff_t *tvb, packet_info *pinfo, int offset,
		       proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_INFO, "Close Connection");

	dissect_aim_tlv_sequence(tvb, pinfo, offset, tree, aim_client_tlvs);
}

static void
dissect_aim_newconn(tvbuff_t *tvb, packet_info *pinfo, int offset,
		    proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_INFO, "New Connection");

	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(tree, hf_aim_version, tvb, offset, 4, ENC_NA);
		offset+=4;
		offset = dissect_aim_tlv_sequence(tvb, pinfo, offset, tree, aim_client_tlvs);
	}

	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, ENC_NA);
}


static int
dissect_aim_snac_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aim_tree)
{
	col_add_str(pinfo->cinfo, COL_INFO,
	    val_to_str(tvb_get_ntohs(tvb, 0), aim_snac_errors, "Unknown SNAC error 0x%02x"));

	proto_tree_add_item (aim_tree, hf_aim_snac_error, tvb, 0, 2, ENC_BIG_ENDIAN);

	return dissect_aim_tlv_sequence(tvb, pinfo, 2, aim_tree, aim_client_tlvs);
}

static unsigned
get_aim_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint16_t plen;

	/*
	* Get the length of the AIM packet.
	*/
	plen = tvb_get_ntohs(tvb, offset + 4);

	/*
	* That length doesn't include the length of the header itself; add that in.
	*/
	return plen + 6;
}

static int
dissect_aim_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Header fields */
	unsigned char  hdr_channel;           /* channel ID */
	unsigned short hdr_sequence_no;       /* Internal frame sequence number, not needed */
	unsigned short hdr_data_field_length; /* length of data within frame */

	int offset=0;

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *aim_tree = NULL;

/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIM");

	col_set_str(pinfo->cinfo, COL_INFO, "AOL Instant Messenger");

	/* get relevant header information */
	offset += 1;          /* XXX - put the identifier into the tree? */
	hdr_channel           = tvb_get_uint8(tvb, offset);
	offset += 1;
	hdr_sequence_no       = tvb_get_ntohs(tvb, offset);
	offset += 2;
	hdr_data_field_length = tvb_get_ntohs(tvb, offset);
	offset += 2;

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_aim, tvb, 0, -1, ENC_NA);
		aim_tree = proto_item_add_subtree(ti, ett_aim);
		proto_tree_add_uint(aim_tree, hf_aim_cmd_start, tvb, 0, 1, '*');
		proto_tree_add_item(aim_tree, hf_aim_channel, tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(aim_tree, hf_aim_seqno, tvb, 2, 2, hdr_sequence_no);
		proto_tree_add_uint(aim_tree, hf_aim_data_len, tvb, 4, 2, hdr_data_field_length);

	}

	switch(hdr_channel)
	{
	case CHANNEL_NEW_CONN:
		dissect_aim_newconn(tvb, pinfo, offset, aim_tree);
		break;
	case CHANNEL_SNAC_DATA:
		dissect_aim_snac(tvb, pinfo, offset, aim_tree, tree);
		break;
	case CHANNEL_FLAP_ERR:
		dissect_aim_flap_err(tvb, pinfo, offset, aim_tree);
		break;
	case CHANNEL_CLOSE_CONN:
		dissect_aim_close_conn(tvb, pinfo, offset, aim_tree);
		break;
	case CHANNEL_KEEP_ALIVE:
		dissect_aim_keep_alive(tvb, pinfo, offset, aim_tree);
		break;
	default:
		dissect_aim_unknown_channel(tvb, pinfo, offset, aim_tree);
		break;
	}

	return tvb_reported_length(tvb);
}

/* Code to actually dissect the packets */
static int
dissect_aim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	/* check, if this is really an AIM packet, they start with 0x2a */
	/* XXX - I've seen some stuff starting with 0x5a followed by 0x2a */

	if(tvb_reported_length(tvb) >= 1 && tvb_get_uint8(tvb, 0) != 0x2a)
	{
		/* Not an instant messenger packet, just happened to use the
		 * same port
		 *
		 * XXX - if desegmentation disabled, this might be a continuation
		 * packet, not a non-AIM packet
		 */
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, tree, aim_desegment, 6, get_aim_pdu_len,
			 dissect_aim_pdu, data);
	return tvb_reported_length(tvb);
}

static bool
dissect_aim_ssl_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct tlsinfo *tlsinfo = (struct tlsinfo *) data;
	/* XXX improve heuristics */
	if (tvb_reported_length(tvb) < 1 || tvb_get_uint8(tvb, 0) != 0x2a) {
		return false;
	}
	dissect_aim(tvb, pinfo, tree, NULL);
	*(tlsinfo->app_handle) = aim_handle;
	return true;
}

/***********************************************************************************************************
 * AIM ADMIN
 ***********************************************************************************************************/
static int dissect_aim_admin_accnt_info_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *admin_tree)
{
	proto_tree_add_item(admin_tree, hf_admin_acctinfo_code, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(admin_tree, hf_admin_acctinfo_unknown, tvb, 2, 2, ENC_BIG_ENDIAN);
	return 4;
}

static int dissect_aim_admin_accnt_info_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree)
{
	int offset = 0;
	proto_tree_add_item(admin_tree, hf_admin_acctinfo_permissions, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	return dissect_aim_tlv_list(tvb, pinfo, offset, admin_tree, aim_client_tlvs);
}

static int dissect_aim_admin_info_change_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, admin_tree, aim_client_tlvs);
}

static int dissect_aim_admin_cfrm_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree)
{
	int offset = 0;
	proto_tree_add_item(admin_tree, hf_admin_confirm_status, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	return dissect_aim_tlv_sequence(tvb, pinfo, offset, admin_tree, aim_client_tlvs);
}

static const aim_subtype aim_fnac_family_admin[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Request Account Information", dissect_aim_admin_accnt_info_req },
	{ 0x0003, "Requested Account Information", dissect_aim_admin_accnt_info_repl },
	{ 0x0004, "Infochange Request", dissect_aim_admin_info_change_req },
	{ 0x0005, "Infochange Reply", dissect_aim_admin_accnt_info_repl },
	{ 0x0006, "Account Confirm Request", NULL },
	{ 0x0007, "Account Confirm Reply", dissect_aim_admin_cfrm_repl},
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM ADVERTS
 ***********************************************************************************************************/
static const aim_subtype aim_fnac_family_adverts[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Request", NULL },
	/* FIXME: */
	/* From other sources, I understand this response contains
	 * a GIF file, haven't actually seen one though. And this
	 * family appears to be deprecated, so we might never find out.. */
	{ 0x0003, "Data (GIF)", NULL },
	{ 0, NULL, NULL }
};


/***********************************************************************************************************
 * AIM BOS
 ***********************************************************************************************************/

/* Family BOS (Misc) */

#define AIM_PRIVACY_TLV_MAX_VISIB_LIST_SIZE     0x001
#define AIM_PRIVACY_TLV_MAX_INVISIB_LIST_SIZE   0x002

static const aim_tlv aim_privacy_tlvs[] = {
	{ AIM_PRIVACY_TLV_MAX_VISIB_LIST_SIZE,   "Max visible list size", dissect_aim_tlv_value_uint16 },
	{ AIM_PRIVACY_TLV_MAX_INVISIB_LIST_SIZE, "Max invisible list size", dissect_aim_tlv_value_uint16 },
	{ 0, NULL, NULL },
};

static int dissect_aim_bos_set_group_perm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bos_tree)
{
	int offset = 0;
	uint32_t userclass = tvb_get_ntohl(tvb, offset);
	proto_item *ti = proto_tree_add_uint(bos_tree, hf_aim_bos_class, tvb, offset, 4, userclass);
	return dissect_aim_userclass(tvb, offset, 4, ti, userclass);
}

static int dissect_aim_bos_rights(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bos_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, bos_tree, aim_privacy_tlvs);
}

static int dissect_aim_bos_buddyname(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bos_tree)
{
	int offset = 0;
	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_buddyname(tvb, pinfo, offset, bos_tree);
	}
	return offset;
}

static const aim_subtype aim_fnac_family_bos[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Rights Query", NULL },
	{ 0x0003, "Rights" , dissect_aim_bos_rights },
	{ 0x0004, "Set Group Permissions Mask", dissect_aim_bos_set_group_perm },
	{ 0x0005, "Add To Visible List", dissect_aim_bos_buddyname },
	{ 0x0006, "Delete From Visible List", dissect_aim_bos_buddyname },
	{ 0x0007, "Add To Invisible List", dissect_aim_bos_buddyname },
	{ 0x0008, "Delete From Invisible List", dissect_aim_bos_buddyname },
	{ 0, NULL, NULL }
};


/***********************************************************************************************************
 * AIM BUDDYLIST
 ***********************************************************************************************************/
#define AIM_ONLINEBUDDY_USERCLASS      0x0001
#define AIM_ONLINEBUDDY_ONSINCE        0x0003
#define AIM_ONLINEBUDDY_IDLETIME       0x0004
#define AIM_ONLINEBUDDY_MEMBERSINCE    0x0005
#define AIM_ONLINEBUDDY_STATUS         0x0006
#define AIM_ONLINEBUDDY_IPADDR         0x000a
#define AIM_ONLINEBUDDY_DCINFO         0x000c
#define AIM_ONLINEBUDDY_CAPINFO        0x000d
#define AIM_ONLINEBUDDY_SESSIONLEN     0x000f
#define AIM_ONLINEBUDDY_ICQSESSIONLEN  0x0010
#define AIM_ONLINEBUDDY_TIMEUPDATE     0x0011
#define AIM_ONLINEBUDDY_MYINSTANCENUM  0x0014
#define AIM_ONLINEBUDDY_SHORTCAPS      0x0019
#define AIM_ONLINEBUDDY_BARTINFO       0x001d
#define AIM_ONLINEBUDDY_NICKFLAGS2     0x001f
#define AIM_ONLINEBUDDY_BUDDYFEEDTIME  0x0023
#define AIM_ONLINEBUDDY_SIGTIME        0x0026
#define AIM_ONLINEBUDDY_AWAYTIME       0x0027
#define AIM_ONLINEBUDDY_GEOCOUNTRY     0x002a

static const aim_tlv aim_onlinebuddy_tlvs[] = {
	{ AIM_ONLINEBUDDY_USERCLASS,	 "User class", dissect_aim_tlv_value_userclass },
	{ AIM_ONLINEBUDDY_ONSINCE,	 "Online since", dissect_aim_tlv_value_uint32 },
	{ AIM_ONLINEBUDDY_IDLETIME,	 "Idle time (sec)", dissect_aim_tlv_value_uint16 },
	{ AIM_ONLINEBUDDY_MEMBERSINCE,	 "Member since", dissect_aim_tlv_value_time },
	{ AIM_ONLINEBUDDY_STATUS,	 "Online status", dissect_aim_tlv_value_userstatus },
	{ AIM_ONLINEBUDDY_IPADDR,	 "User IP Address", dissect_aim_tlv_value_ipv4 },
	{ AIM_ONLINEBUDDY_DCINFO,	 "DC Info", dissect_aim_tlv_value_dcinfo},
	{ AIM_ONLINEBUDDY_CAPINFO,	 "Capability Info", dissect_aim_tlv_value_client_capabilities },
	{ AIM_ONLINEBUDDY_TIMEUPDATE,	 "Time update", dissect_aim_tlv_value_bytes },
	{ AIM_ONLINEBUDDY_SESSIONLEN,	 "Session Length (sec)", dissect_aim_tlv_value_uint32 },
	{ AIM_ONLINEBUDDY_ICQSESSIONLEN, "ICQ Session Length (sec)", dissect_aim_tlv_value_uint32 },
	{ AIM_ONLINEBUDDY_MYINSTANCENUM, "Client instance number", dissect_aim_tlv_value_uint8 },
	{ AIM_ONLINEBUDDY_SHORTCAPS,	 "Short Capabilities", dissect_aim_tlv_value_client_short_capabilities },
	{ AIM_ONLINEBUDDY_BARTINFO,	 "BART Info", dissect_aim_tlv_value_bytes },
	{ AIM_ONLINEBUDDY_NICKFLAGS2,	 "Upper bytes of Nick Flags", dissect_aim_tlv_value_bytes },
	{ AIM_ONLINEBUDDY_BUDDYFEEDTIME, "Last Buddy Feed update", dissect_aim_tlv_value_time },
	{ AIM_ONLINEBUDDY_SIGTIME,	 "Profile set time", dissect_aim_tlv_value_time },
	{ AIM_ONLINEBUDDY_AWAYTIME,	 "Away set time", dissect_aim_tlv_value_time },
	{ AIM_ONLINEBUDDY_GEOCOUNTRY,	 "Country code", dissect_aim_tlv_value_string },
	{ 0, NULL, NULL }
};

#define AIM_BUDDYLIST_TLV_MAX_CONTACT_ENTRIES 		0x0001
#define AIM_BUDDYLIST_TLV_MAX_WATCHER_ENTRIES 		0x0002
#define AIM_BUDDYLIST_TLV_MAX_ONLINE_NOTIFICATIONS 	0x0003

static const aim_tlv aim_buddylist_tlvs[] = {
	{ AIM_BUDDYLIST_TLV_MAX_CONTACT_ENTRIES, "Max number of contact list entries", dissect_aim_tlv_value_uint16 },
	{ AIM_BUDDYLIST_TLV_MAX_WATCHER_ENTRIES, "Max number of watcher list entries", dissect_aim_tlv_value_uint16 },
	{ AIM_BUDDYLIST_TLV_MAX_ONLINE_NOTIFICATIONS, "Max online notifications", dissect_aim_tlv_value_uint16 },
	{0, NULL, NULL }
};

static int
dissect_aim_userinfo(tvbuff_t *tvb, packet_info *pinfo,
		     int offset, proto_tree *tree)
{
	offset = dissect_aim_buddyname(tvb, pinfo, offset, tree);

	proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return dissect_aim_tlv_list(tvb, pinfo, offset, tree, aim_onlinebuddy_tlvs);
}

/* Initialize the protocol and registered fields */

static int dissect_aim_buddylist_buddylist(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{
	int offset = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_buddyname( tvb, pinfo, offset, buddy_tree);
	}
	return offset;
}

static int dissect_aim_buddylist_rights_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, buddy_tree, aim_buddylist_tlvs);
}

static int dissect_aim_buddylist_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{
	return dissect_aim_buddyname(tvb, pinfo, 0, buddy_tree);
}

static int dissect_aim_buddylist_oncoming(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{
	uint8_t *buddyname;
	int    offset           = 0;
	int    buddyname_length = aim_get_buddyname( pinfo->pool, &buddyname, tvb, offset );

	col_set_str(pinfo->cinfo, COL_INFO, "Oncoming Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					format_text(pinfo->pool, buddyname, buddyname_length));

	offset += dissect_aim_buddyname(tvb, pinfo, offset, buddy_tree);

	/* Warning level */
	proto_tree_add_item(buddy_tree, hf_aim_buddylist_userinfo_warninglevel, tvb, offset,
						2, ENC_BIG_ENDIAN);
	offset += 2;

	offset = dissect_aim_tlv_list(tvb, pinfo, offset, buddy_tree, aim_onlinebuddy_tlvs);

	return offset;
}

static int dissect_aim_buddylist_offgoing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{

	uint8_t *buddyname;
	int    offset           = 0;
	int    buddyname_length = aim_get_buddyname( pinfo->pool, &buddyname, tvb, offset );

	col_set_str(pinfo->cinfo, COL_INFO, "Offgoing Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					format_text(pinfo->pool, buddyname, buddyname_length));

	offset += dissect_aim_buddyname(tvb, pinfo, offset, buddy_tree);

	/* Warning level */
	proto_tree_add_item(buddy_tree, hf_aim_buddylist_userinfo_warninglevel, tvb, offset,
						2, ENC_BIG_ENDIAN);
	offset += 2;

	return dissect_aim_tlv_list(tvb, pinfo, offset, buddy_tree, aim_onlinebuddy_tlvs);
}

static const aim_subtype aim_fnac_family_buddylist[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Rights Request", NULL },
	{ 0x0003, "Rights Reply", dissect_aim_buddylist_rights_repl },
	{ 0x0004, "Add Buddy", dissect_aim_buddylist_buddylist },
	{ 0x0005, "Remove Buddy", dissect_aim_buddylist_buddylist },
	{ 0x0006, "Watchers List Request", NULL },
	{ 0x0007, "Watchers List Reply", dissect_aim_buddylist_buddylist },
	{ 0x000a, "Reject Buddy", dissect_aim_buddylist_reject },
	{ 0x000b, "Oncoming Buddy", dissect_aim_buddylist_oncoming },
	{ 0x000c, "Offgoing Buddy", dissect_aim_buddylist_offgoing },
	{ 0, NULL, NULL }
};


/***********************************************************************************************************
 * AIM CHAT
 ***********************************************************************************************************/

/* SNAC families */

#define AIM_CHAT_TLV_BROWSABLE_TREE 		0x001
#define AIM_CHAT_TLV_CLASS_EXCLUSIVE		0x002
#define AIM_CHAT_TLV_MAX_CONCURRENT_ROOMS	0x003
#define AIM_CHAT_TLV_MAX_ROOM_NAME_LEN		0x004
#define AIM_CHAT_TLV_ROOT_ROOMS			0x005
#define AIM_CHAT_TLV_SEARCH_TAGS		0x006
#define AIM_CHAT_TLV_CHILD_ROOMS		0x065
#define AIM_CHAT_TLV_CONTAINS_USER_CLASS	0x066
#define AIM_CHAT_TLV_CONTAINS_USER_ARRAY	0x067

#if 0
static const aim_tlv aim_chat_tlvs[] _U_ = {
	{ AIM_CHAT_TLV_BROWSABLE_TREE,	     "Browsable tree",			dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CLASS_EXCLUSIVE,	     "Exclusively for class",		dissect_aim_tlv_value_userclass },
	{ AIM_CHAT_TLV_MAX_CONCURRENT_ROOMS, "Max. number of concurrent rooms", dissect_aim_tlv_value_uint8 },
	{ AIM_CHAT_TLV_MAX_ROOM_NAME_LEN,    "Max. length of room name",	dissect_aim_tlv_value_uint8 },
	{ AIM_CHAT_TLV_ROOT_ROOMS,	     "Root Rooms",			dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_SEARCH_TAGS,	     "Search Tags",			dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CHILD_ROOMS,	     "Child Rooms",			dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CONTAINS_USER_CLASS,  "Contains User Class",		dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CONTAINS_USER_ARRAY,  "Contains User Array",		dissect_aim_tlv_value_bytes },
	{ 0, NULL, NULL }
};
#endif


static int dissect_aim_chat_userinfo_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *chat_tree)
{
	int offset = 0;
	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_userinfo(tvb, pinfo, offset, chat_tree);
	}
	return offset;
}

static int dissect_aim_chat_outgoing_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *chat_tree _U_)
{
	uint8_t *buddyname;
	unsigned char *msg;
	int buddyname_length;

	msg=(unsigned char *)wmem_alloc(pinfo->pool, 1000);
	buddyname_length = aim_get_buddyname( pinfo->pool, &buddyname, tvb, 30 );

	/* channel message from client */
	aim_get_message( msg, tvb, 40 + buddyname_length, tvb_reported_length(tvb)
					 - 40 - buddyname_length );

	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);

	return tvb_reported_length(tvb);
}


static int dissect_aim_chat_incoming_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *chat_tree)
{
	uint8_t *buddyname;
	unsigned char *msg;
	/* channel message to client */
	int buddyname_length;

	msg=(unsigned char *)wmem_alloc(pinfo->pool, 1000);
	buddyname_length = aim_get_buddyname( pinfo->pool, &buddyname, tvb, 30 );

	aim_get_message( msg, tvb, 36 + buddyname_length, tvb_reported_length(tvb)
					 - 36 - buddyname_length );

	col_append_fstr(pinfo->cinfo, COL_INFO, "from: %s", buddyname);
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);

	proto_tree_add_string(chat_tree, hf_aim_chat_screen_name, tvb, 31, buddyname_length, buddyname);

	return tvb_reported_length(tvb);
}

static const aim_subtype aim_fnac_family_chat[] = {
	{ 0x0001, "Error",	      dissect_aim_snac_error },
	{ 0x0002, "Room Info Update", NULL },
	{ 0x0003, "User Join",	      dissect_aim_chat_userinfo_list },
	{ 0x0004, "User Leave",	      dissect_aim_chat_userinfo_list },
	{ 0x0005, "Outgoing Message", dissect_aim_chat_outgoing_msg },
	{ 0x0006, "Incoming Message", dissect_aim_chat_incoming_msg },
	{ 0x0007, "Evil Request",     NULL },
	{ 0x0008, "Evil Reply",       NULL },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM CHATNAV
 ***********************************************************************************************************/

static const aim_subtype aim_fnac_family_chatnav[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Request Limits", NULL },
	{ 0x0003, "Request Exchange", NULL },
	{ 0x0004, "Request Room Information", NULL },
	{ 0x0005, "Request Extended Room Information", NULL },
	{ 0x0006, "Request Member List", NULL },
	{ 0x0007, "Search Room", NULL },
	{ 0x0008, "Create", NULL },
	{ 0x0009, "Info", NULL },
	{ 0, NULL, NULL }
};


/***********************************************************************************************************
 * AIM DIRECTORY
 ***********************************************************************************************************/
static int dissect_aim_directory_user_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, aim_client_tlvs);
	}
	return offset;
}

static const aim_subtype aim_fnac_family_directory[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Client search for user request", NULL },
	{ 0x0003, "Server reply for search request (found users)", dissect_aim_directory_user_repl },
	{ 0x0004, "Request interests list from server", NULL },
	{ 0x0005, "Interests list", NULL },
	{ 0, NULL, NULL },
};


/***********************************************************************************************************
 * AIM EMAIL
 ***********************************************************************************************************/
static const aim_subtype aim_fnac_family_email[] = {
	{ 0x0006, "Email Status Request", NULL },
	{ 0x0007, "Email Status Reply", NULL },
	{ 0x0016, "Activate Email", NULL },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM GENERIC
 ***********************************************************************************************************/
#define STRIP_TAGS 1



#define FAMILY_GENERIC_MOTD_MOTDTYPE_MDT_UPGRADE       0x0001
#define FAMILY_GENERIC_MOTD_MOTDTYPE_ADV_UPGRADE       0x0002
#define FAMILY_GENERIC_MOTD_MOTDTYPE_SYS_BULLETIN      0x0003
#define FAMILY_GENERIC_MOTD_MOTDTYPE_NORMAL            0x0004
#define FAMILY_GENERIC_MOTD_MOTDTYPE_NEWS              0x0006

static const value_string aim_snac_generic_motd_motdtypes[] = {
	{ FAMILY_GENERIC_MOTD_MOTDTYPE_MDT_UPGRADE,  "Mandatory Upgrade Needed Notice" },
	{ FAMILY_GENERIC_MOTD_MOTDTYPE_ADV_UPGRADE,  "Advisable Upgrade Notice" },
	{ FAMILY_GENERIC_MOTD_MOTDTYPE_SYS_BULLETIN, "AIM/ICQ Service System Announcements" },
	{ FAMILY_GENERIC_MOTD_MOTDTYPE_NORMAL,       "Standard Notice" },
	{ FAMILY_GENERIC_MOTD_MOTDTYPE_NEWS,         "News from AOL service" },
	{ 0, NULL }
};

#define RATEINFO_STATE_LIMITED          0x01
#define RATEINFO_STATE_ALERT            0x02
#define RATEINFO_STATE_CLEAR            0x03

static const value_string rateinfo_states[] = {
	{ RATEINFO_STATE_LIMITED, "Limited" },
	{ RATEINFO_STATE_ALERT,   "Alert" },
	{ RATEINFO_STATE_CLEAR,   "Clear" },
	{ 0, NULL }
};

#define RATECHANGE_MSG_LIMIT_PARAMS_CHANGED      0x0001
#define RATECHANGE_MSG_LIMIT_WARN                0x0002
#define RATECHANGE_MSG_LIMIT_HIT                 0x0003
#define RATECHANGE_MSG_LIMIT_CLEAR               0x0004

static const value_string ratechange_msgs[] = {
	{ RATECHANGE_MSG_LIMIT_PARAMS_CHANGED, "Rate limits parameters changed" },
	{ RATECHANGE_MSG_LIMIT_WARN,           "Rate limits warning (current level < alert level)" },
	{ RATECHANGE_MSG_LIMIT_HIT,            "Rate limit hit (current level < limit level)" },
	{ RATECHANGE_MSG_LIMIT_CLEAR,          "Rate limit clear (current level now > clear level)" },
	{ 0, NULL },
};

#define EXT_STATUS_TYPE_BUDDY_ICON_0 0
#define EXT_STATUS_TYPE_BUDDY_ICON_1 1
#define EXT_STATUS_TYPE_AVAIL_MSG    2
#define EXT_STATUS_TYPE_UNKNOWN      6

static const value_string ext_status_types[] = {
	{ EXT_STATUS_TYPE_BUDDY_ICON_0, "Request to send buddy icon" },
	{ EXT_STATUS_TYPE_BUDDY_ICON_1, "Request to send buddy icon" },
	{ EXT_STATUS_TYPE_AVAIL_MSG,    "Extended Status Update" },
	{ 0, NULL },
};

#define EXT_STATUS_FLAG_INITIAL_SEND    0x41
#define EXT_STATUS_FLAG_RESEND      0x81

static const value_string ext_status_flags[] = {
	{ EXT_STATUS_FLAG_INITIAL_SEND, "First Send Request" },
	{ EXT_STATUS_FLAG_RESEND,       "Request To Re-Send" },
	{ 0, NULL },
};

static int dissect_rate_class(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *class_tree)
{
	proto_tree_add_item(class_tree, hf_generic_rateinfo_classid, tvb, offset, 2, ENC_BIG_ENDIAN);offset+=2;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_windowsize, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_clearlevel, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_alertlevel, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_limitlevel, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_disconnectlevel, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_currentlevel, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_maxlevel, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_lasttime, tvb, offset, 4, ENC_BIG_ENDIAN);offset+=4;
	proto_tree_add_item(class_tree, hf_generic_rateinfo_curstate, tvb, offset, 1, ENC_BIG_ENDIAN);offset+=1;
	return offset;
}

static int dissect_generic_rateinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	uint16_t i;
	uint16_t numclasses = tvb_get_ntohs(tvb, 0);
	proto_tree *classes_tree = NULL, *groups_tree, *group_tree;
	proto_tree_add_uint(tree, hf_generic_rateinfo_numclasses, tvb, 0, 2, numclasses );
	offset+=2;

	if(tree) {
		/* sizeof(rate_class_struct) = 35 ! */
		classes_tree = proto_tree_add_subtree(tree, tvb, offset, 35 * numclasses,
								ett_generic_rateinfo_classes, NULL, "Available Rate Classes");
	}

	for(i = 0; i < numclasses; i++) {
		uint16_t myid = tvb_get_ntohs(tvb, offset);
		proto_tree *class_tree = proto_tree_add_subtree_format(classes_tree, tvb, offset, 35,
		                ett_generic_rateinfo_class, NULL, "Rate Class 0x%02x", myid);
		offset = dissect_rate_class(tvb, pinfo, offset, class_tree);
	}

	groups_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_generic_rateinfo_groups, NULL, "Rate Groups");

	for(i = 0; i < numclasses; i++) {
		uint16_t j;
		uint16_t myid = tvb_get_ntohs(tvb, offset);
		uint16_t numpairs = tvb_get_ntohs(tvb, offset + 2);
		/*
		 * sizeof(rate_group) = sizeof(class_id) + sizeof(numpairs) + numpairs * 2 * sizeof(uint16_t)
		 *                    = 2 + 2 + numpairs * 4
		 */
		group_tree = proto_tree_add_subtree_format(groups_tree, tvb, offset, 4 + 4 * numpairs,
		                            ett_generic_rateinfo_group, NULL, "Rate Group 0x%02x", myid);
		proto_tree_add_uint(group_tree, hf_generic_rateinfo_classid, tvb, offset, 2, myid);offset+=2;
		proto_tree_add_uint(group_tree, hf_generic_rateinfo_numpairs, tvb, offset, 2, numpairs); offset+=2;
		for(j = 0; j < numpairs; j++) {
			uint16_t family_id;
			uint16_t subtype_id;
			const aim_family *family;
			const aim_subtype *subtype;
			family_id = tvb_get_ntohs(tvb, offset);
			subtype_id = tvb_get_ntohs(tvb, offset+2);

			family = aim_get_family(family_id);
			subtype = aim_get_subtype(family_id, subtype_id);

			proto_tree_add_uint_format_value(group_tree, hf_generic_family, tvb, offset, 4, family_id,
			            "%s (0x%04x), Subtype: %s (0x%04x)", family?family->name:"Unknown", family_id, subtype?subtype->name:"Unknown", subtype_id);
			offset+=4;
		}
	}

	return offset;
}

static int dissect_aim_generic_clientready(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree *entry = proto_tree_add_subtree(gen_tree, tvb, 0, -1, ett_generic_clientready, NULL, "Supported services");

	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_item *ti;
		proto_tree *subtree;

		ti = proto_tree_add_item(entry, hf_generic_family, tvb, offset, 2, ENC_BIG_ENDIAN);
		subtree = proto_item_add_subtree(ti, ett_generic_clientready_item);
		offset+=2;

		proto_tree_add_item(subtree, hf_generic_version, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(subtree, hf_generic_dll_version, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* Padding byte? */
		offset += 4;
		proto_item_set_len(ti, 8);
	}
	return offset;
}


static int dissect_aim_generic_serverready(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree *entry = proto_tree_add_subtree(gen_tree, tvb, offset, -1, ett_generic_clientready, NULL, "Supported services");

	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(entry, hf_generic_family, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
	}
	return offset;
}


static int dissect_aim_generic_service_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	const aim_family *family = aim_get_family( tvb_get_ntohs(tvb, offset) );

	proto_tree_add_uint_format(gen_tree, hf_generic_servicereq_service, tvb, offset, 2, tvb_get_ntohs(tvb, offset), "%s (0x%04x)", family?family->name:"Unknown", tvb_get_ntohs(tvb, offset) );
	offset+=2;
	return offset;
}

static int dissect_aim_generic_redirect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gen_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, gen_tree, aim_client_tlvs);
}

static int dissect_aim_generic_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree *entry = proto_tree_add_subtree(gen_tree, tvb, offset, -1, ett_generic_clientready, NULL, "Requested services");

	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(entry, hf_generic_family, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		proto_tree_add_item(entry, hf_generic_version, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
	}
	return offset;
}

static int dissect_aim_generic_capack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree *entry = proto_tree_add_subtree(gen_tree, tvb, offset, -1, ett_generic_clientready, NULL, "Accepted requested services");

	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(entry, hf_generic_family, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		proto_tree_add_item(entry, hf_generic_version, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
	}
	return offset;
}

#define AIM_MOTD_TLV_MOTD					   0x000B

static const aim_tlv aim_motd_tlvs[] = {
	{ AIM_MOTD_TLV_MOTD, "Message of the day message", dissect_aim_tlv_value_string },
	{ 0, NULL, NULL }
};

static int dissect_aim_generic_motd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree_add_item(gen_tree, hf_generic_motd_motdtype, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	return dissect_aim_tlv_sequence(tvb, pinfo, offset, gen_tree, aim_motd_tlvs);
}

static int dissect_aim_generic_rateinfoack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(gen_tree, hf_generic_rateinfoack_group, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
	}
	return offset;
}

static int dissect_aim_generic_ratechange(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree_add_item(gen_tree, hf_generic_ratechange_msg, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	offset = dissect_rate_class(tvb, pinfo, offset, gen_tree);
	return offset;
}


static int dissect_aim_generic_clientpauseack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(gen_tree, hf_generic_family, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	return offset;
}

static int dissect_aim_generic_migration_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gen_tree)
{
	int offset = 0;
	uint32_t n, i;
	proto_tree *entry;

	n = tvb_get_ntohs(tvb, offset);offset+=2;
	proto_tree_add_uint(gen_tree, hf_generic_migration_numfams, tvb, offset, 2, n);
	entry = proto_tree_add_subtree(gen_tree, tvb, offset, 2 * n,
	        ett_generic_migratefamilies, NULL, "Families to migrate");
	for(i = 0; i < n; i++) {
		proto_tree_add_item(entry, hf_generic_family, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, gen_tree, aim_client_tlvs);
}

static int dissect_aim_generic_setprivflags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	static int * const flags[] = {
		&hf_generic_allow_idle_see,
		&hf_generic_allow_member_see,
		NULL
	};

	proto_tree_add_bitmask(gen_tree, tvb, 0, hf_generic_priv_flags, ett_generic_priv_flags, flags, ENC_BIG_ENDIAN);
	return 4;
}

static int dissect_aim_generic_selfinfo_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gen_tree)
{
	int offset = dissect_aim_buddyname(tvb, pinfo, 0, gen_tree);
	proto_tree_add_item(gen_tree, hf_generic_selfinfo_warninglevel, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	return dissect_aim_tlv_list(tvb, pinfo, offset, gen_tree, aim_onlinebuddy_tlvs);
}

static int dissect_aim_generic_evil(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree_add_item(gen_tree, hf_generic_evil_new_warn_level, tvb, offset, 2, ENC_BIG_ENDIAN);
	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_userinfo(tvb, pinfo, offset, gen_tree);
	}
	return offset;
}

static int dissect_aim_generic_setidle(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	proto_tree_add_item(gen_tree, hf_generic_idle_time, tvb, 0, 2, ENC_BIG_ENDIAN);
	return 2;
}

static int dissect_aim_generic_ext_status_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gen_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, gen_tree, aim_onlinebuddy_tlvs);
}

static int dissect_aim_generic_clientver_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	int offset = 0;
	proto_tree_add_item(gen_tree, hf_generic_client_ver_req_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(gen_tree, hf_generic_client_ver_req_length, tvb, offset, 4, ENC_BIG_ENDIAN);
	return offset+4;
}

static int dissect_aim_generic_clientver_repl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	proto_tree_add_item(gen_tree, hf_generic_client_ver_req_hash, tvb, 0, 16, ENC_NA);
	return 16;
}

static int dissect_aim_generic_ext_status_repl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gen_tree)
{
	uint8_t length;
	int offset = 0;
	proto_tree_add_item(gen_tree, hf_generic_ext_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(gen_tree, hf_generic_ext_status_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(gen_tree, hf_generic_ext_status_length, tvb, offset, 1, ENC_BIG_ENDIAN);
	length = tvb_get_uint8(tvb, offset);
	offset += 1;
	proto_tree_add_item(gen_tree, hf_generic_ext_status_data, tvb, offset, length, ENC_NA);
	offset += 1;
	return offset;
}

static void
aim_generic_family( char *result, uint32_t famnum )
{
	const aim_family *family = aim_get_family(famnum);

	snprintf( result, ITEM_LABEL_LENGTH, "%s (0x%x)", family?family->name:"Unknown", famnum);
}

static const aim_subtype aim_fnac_family_generic[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Client Ready", dissect_aim_generic_clientready },
	{ 0x0003, "Server Ready", dissect_aim_generic_serverready  },
	{ 0x0004, "Service Request", dissect_aim_generic_service_req },
	{ 0x0005, "Redirect", dissect_aim_generic_redirect },
	{ 0x0006, "Rate Info Request", NULL},
	{ 0x0007, "Rate Info", dissect_generic_rateinfo },
	{ 0x0008, "Rate Info Ack", dissect_aim_generic_rateinfoack },
	{ 0x000a, "Rate Change", dissect_aim_generic_ratechange },
	{ 0x000b, "Server Pause", NULL },
	{ 0x000c, "Client Pause Ack", dissect_aim_generic_clientpauseack },
	{ 0x000d, "Server Resume", NULL },
	{ 0x000e, "Self Info Request", NULL },
	{ 0x000f, "Self Info Reply", dissect_aim_generic_selfinfo_repl },
	{ 0x0010, "Evil", dissect_aim_generic_evil },
	{ 0x0011, "Set Idle", dissect_aim_generic_setidle },
	{ 0x0012, "Migration Request", dissect_aim_generic_migration_req },
	{ 0x0013, "Message Of The Day", dissect_aim_generic_motd },
	{ 0x0014, "Set Privilege Flags", dissect_aim_generic_setprivflags },
	{ 0x0015, "Well Known URL", NULL }, /* FIXME */
	{ 0x0016, "noop", NULL },
	{ 0x0017, "Capabilities",  dissect_aim_generic_capabilities },
	{ 0x0018, "Capabilities Ack", dissect_aim_generic_capack },
	{ 0x001e, "Set Extended Status Request", dissect_aim_generic_ext_status_req },
	{ 0x001f, "Client Verification Request",  dissect_aim_generic_clientver_req },
	{ 0x0020, "Client Verification Reply", dissect_aim_generic_clientver_repl },
	{ 0x0021, "Set Extended Status Reply", dissect_aim_generic_ext_status_repl },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM ICQ
 ***********************************************************************************************************/
#define ICQ_CLI_OFFLINE_MESSAGE_REQ 	0x003c
#define ICQ_CLI_DELETE_OFFLINE_MSGS	0x003e
#define ICQ_SRV_OFFLINE_MSGS		0x0041
#define ICQ_SRV_END_OF_OFFLINE_MSGS	0x0042
#define ICQ_CLI_META_INFO_REQ		0x07d0
#define ICQ_SRV_META_INFO_REPL		0x07da

static const value_string aim_icq_data_types[] = {
	{ ICQ_CLI_OFFLINE_MESSAGE_REQ, "Offline Message Request" },
	{ ICQ_SRV_OFFLINE_MSGS,        "Offline Messages Reply" },
	{ ICQ_SRV_END_OF_OFFLINE_MSGS, "End Of Offline Messages Reply" },
	{ ICQ_CLI_DELETE_OFFLINE_MSGS, "Delete Offline Messages Request" },
	{ ICQ_CLI_META_INFO_REQ,       "Metainfo Request" },
	{ ICQ_SRV_META_INFO_REPL,      "Metainfo Reply" },
	{ 0, NULL }
};


static int dissect_aim_tlv_value_icq(proto_item *ti, uint16_t subtype, tvbuff_t *tvb, packet_info *pinfo);

#define TLV_ICQ_META_DATA 			  0x0001

static const aim_tlv icq_tlv[] = {
	{ TLV_ICQ_META_DATA, "Encapsulated ICQ Meta Data", dissect_aim_tlv_value_icq },
	{ 0, NULL, NULL },
};


static struct
{
	uint16_t subtype;
	const char *name;
	int (*dissector) (tvbuff_t *, packet_info *, proto_tree *);
} icq_calls [] = {
	{ 0x0001, "Server Error Reply",			  NULL },
	{ 0x0064, "Set User Home Info Reply",		  NULL },
	{ 0x006e, "Set User Work Info Reply",		  NULL },
	{ 0x0078, "Set User More Info Reply",		  NULL },
	{ 0x0082, "Set User Notes Info Reply",		  NULL },
	{ 0x0087, "Set User Email Info Reply",		  NULL },
	{ 0x008c, "Set User Interests Info Reply",	  NULL },
	{ 0x0096, "Set User Affiliations Info Reply",	  NULL },
	{ 0x00a0, "Set User Permissions Reply",		  NULL },
	{ 0x00aa, "Set User Password Reply",		  NULL },
	{ 0x00b4, "Unregister Account Reply",		  NULL },
	{ 0x00be, "Set User Homepage Category Reply",	  NULL },
	{ 0x00c8, "User Basic Info Reply",		  NULL },
	{ 0x00d2, "User Work Info Reply",		  NULL },
	{ 0x00dc, "User More Info Reply",		  NULL },
	{ 0x00e6, "User Notes Info Reply",		  NULL },
	{ 0x00eb, "User Extended Email Reply",		  NULL },
	{ 0x00f0, "User Interests Info Reply",		  NULL },
	{ 0x00fa, "User Affiliations Info Reply",	  NULL },
	{ 0x0104, "Short User Info Reply",		  NULL },
	{ 0x010e, "User Homepage Category Reply",	  NULL },
	{ 0x01a4, "Search: User found",			  NULL },
	{ 0x0302, "Registration Stats Reply",		  NULL },
	{ 0x0366, "Random Search Server Reply",		  NULL },
	{ 0x03ea, "Set User Home Info Request",		  NULL },
	{ 0x03f3, "Set User Work Info Request",		  NULL },
	{ 0x03fd, "Set User More Info Request",		  NULL },
	{ 0x0406, "Set User Notes Request",		  NULL },
	{ 0x040b, "Set User Extended Email Info Request", NULL },
	{ 0x0410, "Set User Interests Info Request",	  NULL },
	{ 0x041a, "Set User Affiliations Info Request",	  NULL },
	{ 0x0424, "Set User Permissions Info Request",	  NULL },
	{ 0x042e, "Change User Password Request",	  NULL },
	{ 0x0442, "Set User Homepage Category Request",	  NULL },
	{ 0x04b2, "Fullinfo Request",			  NULL },
	{ 0x04ba, "Short User Info Request",		  NULL },
	{ 0x04c4, "Unregister User Request",		  NULL },
	{ 0x0515, "Search By Details Request",		  NULL },
	{ 0x0569, "Search By UIN Request",		  NULL },
	{ 0x055f, "Whitepages Search Request",		  NULL },
	{ 0x0573, "Search By Email Request",		  NULL },
	{ 0x074e, "Random Chat User Search Request",	  NULL },
	{ 0x0898, "Server Variable Request (XML)",	  NULL },
	{ 0x0aa5, "Registration Report Request",	  NULL },
	{ 0x0aaf, "Shortcut Bar Stats Report Request",	  NULL },
	{ 0x0c3a, "Save Info Request",			  NULL },
	{ 0x1482, "Send SMS Request",			  NULL },
	{ 0x2008, "Spam Report Request",		  NULL },
	{ 0x08a2, "Server Variable Reply (XML)",	  NULL },
	{ 0x0c3f, "Set Fullinfo Reply",			  NULL },
	{ 0x2012, "User Spam Report Reply",		  NULL },
	{ 0, NULL, NULL },
};


static int dissect_aim_tlv_value_icq(proto_item *ti, uint16_t subtype _U_, tvbuff_t *tvb, packet_info *pinfo)
{
	int         offset = 0;
	int         i;
	proto_item *subtype_item;
	uint16_t    req_type, req_subtype;
	proto_tree *t      = proto_item_add_subtree(ti, ett_aim_icq_tlv);

	proto_tree_add_item(t, hf_icq_tlv_data_chunk_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(t, hf_icq_tlv_request_owner_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(t, hf_icq_tlv_request_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	req_type = tvb_get_letohs(tvb, offset);
	offset += 2;

	proto_tree_add_item(t, hf_icq_tlv_request_seq_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	switch (req_type) {
	case ICQ_CLI_OFFLINE_MESSAGE_REQ: return offset;
	case ICQ_CLI_DELETE_OFFLINE_MSGS: return offset;
	case ICQ_SRV_OFFLINE_MSGS:
		/* FIXME */
		break;
	case ICQ_SRV_END_OF_OFFLINE_MSGS:
		proto_tree_add_item(t, hf_icq_dropped_msg_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		return offset+1;
	case ICQ_CLI_META_INFO_REQ:
	case ICQ_SRV_META_INFO_REPL:
		req_subtype = tvb_get_letohs(tvb, offset);
		subtype_item = proto_tree_add_item(t, hf_icq_meta_subtype, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset+=2;

		for (i = 0; icq_calls[i].name; i++) {
			if (icq_calls[i].subtype == req_subtype) break;
		}

		col_set_str(pinfo->cinfo, COL_INFO, icq_calls[i].name?icq_calls[i].name:"Unknown ICQ Meta Call");

		proto_item_append_text(subtype_item, " (%s)", icq_calls[i].name?icq_calls[i].name:"Unknown");

		if (icq_calls[i].dissector)
			return icq_calls[i].dissector(tvb_new_subset_remaining(tvb, offset), pinfo, t);

	default:
		break;
	}

	return offset;
}

static int dissect_aim_icq_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_aim_tlv(tvb, pinfo, 0, tree, icq_tlv);
}

static const aim_subtype aim_fnac_family_icq[] = {
	{ 0x0001, "Error",         dissect_aim_snac_error },
	{ 0x0002, "ICQ Request",   dissect_aim_icq_tlv },
	{ 0x0003, "ICQ Response",  dissect_aim_icq_tlv },
	{ 0x0006, "Auth Request",  NULL },
	{ 0x0007, "Auth Response", NULL },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM INVITATION
 ***********************************************************************************************************/
static int dissect_aim_invitation_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *invite_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, invite_tree, aim_onlinebuddy_tlvs);
}

static const aim_subtype aim_fnac_family_invitation[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Invite a friend to join AIM", dissect_aim_invitation_req },
	{ 0x0003, "Invitation Ack", NULL },
	{ 0, NULL, NULL }
};


/***********************************************************************************************************
 * AIM LOCATION
 ***********************************************************************************************************/
#define AIM_LOCATION_RIGHTS_TLV_MAX_PROFILE_LENGTH 	0x0001
#define AIM_LOCATION_RIGHTS_TLV_MAX_CAPABILITIES 	0x0002

static const aim_tlv aim_location_rights_tlvs[] = {
	{ AIM_LOCATION_RIGHTS_TLV_MAX_PROFILE_LENGTH, "Max Profile Length", dissect_aim_tlv_value_uint16 },
	{ AIM_LOCATION_RIGHTS_TLV_MAX_CAPABILITIES, "Max capabilities", dissect_aim_tlv_value_uint16 },
	{ 0, NULL, NULL }
};

#define AIM_LOCATE_TAG_TLV_SIG_TYPE			0x0001
#define AIM_LOCATE_TAG_TLV_SIG_DATA			0x0002
#define AIM_LOCATE_TAG_TLV_UNAVAILABLE_TYPE		0x0003
#define AIM_LOCATE_TAG_TLV_UNAVAILABLE_DATA		0x0004
#define AIM_LOCATE_TAG_TLV_CAPABILITIES			0x0005
#define AIM_LOCATE_TAG_TLV_SIG_TIME			0x000A
#define AIM_LOCATE_TAG_TLV_UNAVAILABLE_TIME		0x000B
#define AIM_LOCATE_TAG_TLV_SUPPORT_HOST_SIG		0x000C
#define AIM_LOCATE_TAG_TLV_HTML_INFO_TYPE		0x000D
#define AIM_LOCATE_TAG_TLV_HTML_INFO_DATA		0x000E

static const aim_tlv aim_locate_tags_tlvs[] = {
	{ AIM_LOCATE_TAG_TLV_SIG_TYPE,	       "Signature MIME Type"	      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_SIG_DATA,	       "Signature Data"		      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_UNAVAILABLE_TYPE, "Away Message MIME Type"	      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_UNAVAILABLE_DATA, "Away Message Data"	      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_CAPABILITIES,     "Client Capabilities"	      , dissect_aim_tlv_value_client_capabilities },
	{ AIM_LOCATE_TAG_TLV_SIG_TIME,	       "Signature Time"		      , dissect_aim_tlv_value_time },
	{ AIM_LOCATE_TAG_TLV_UNAVAILABLE_TIME, "Away Message Time"	      , dissect_aim_tlv_value_time },
	{ AIM_LOCATE_TAG_TLV_SUPPORT_HOST_SIG, "Enable Server Based Profiles" , dissect_aim_tlv_value_uint8 },
	{ AIM_LOCATE_TAG_TLV_HTML_INFO_TYPE,   "Host Based Buddy MIME Type"   , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_HTML_INFO_DATA,   "Host Bases Buddy Data"	      , dissect_aim_tlv_value_string },
	{ 0, NULL, NULL }
};

#define FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO  0x0001
#define FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG      0x0003
#define FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS         0x0005

static const value_string aim_snac_location_request_user_info_infotypes[] = {
	{ FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO, "Request General Info" },
	{ FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG,	 "Request Away Message" },
	{ FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS,	 "Request Capabilities" },
	{ 0, NULL }
};

static int dissect_aim_location_rightsinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, loc_tree, aim_location_rights_tlvs);
}

static int dissect_aim_location_setuserinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, loc_tree, aim_locate_tags_tlvs);
}

static int dissect_aim_location_watcher_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	int offset = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_buddyname(tvb, pinfo, offset, loc_tree);
	}
	return offset;
}

static int dissect_aim_location_user_info_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	return dissect_aim_buddyname(tvb, pinfo, 4, loc_tree);
}

static int dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int    offset		= 0;
	uint8_t buddyname_length = 0;

	/* Info Type */
	proto_tree_add_item(tree, hf_aim_snac_location_request_user_info_infotype,
						tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Buddy Name length */
	buddyname_length = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_location_buddyname_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Buddy name */
	proto_tree_add_item(tree, hf_aim_location_buddyname, tvb, offset, buddyname_length, ENC_UTF_8);
	offset += buddyname_length;

	return offset;
}

static int dissect_aim_snac_location_user_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int    offset		= 0;
	uint8_t buddyname_length = 0;

	/* Buddy Name length */
	buddyname_length = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_location_buddyname_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Buddy name */
	proto_tree_add_item(tree, hf_aim_location_buddyname, tvb, offset, buddyname_length, ENC_UTF_8);
	offset += buddyname_length;

	/* Warning level */
	proto_tree_add_item(tree, hf_aim_location_userinfo_warninglevel, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	offset = dissect_aim_tlv_list(tvb, pinfo, offset, tree, aim_onlinebuddy_tlvs);

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, tree, aim_locate_tags_tlvs);
}

static const aim_subtype aim_fnac_family_location[] = {
	{ 0x0001, "Error"		 , dissect_aim_snac_error },
	{ 0x0002, "Request Rights"       , NULL },
	{ 0x0003, "Rights Info"		 , dissect_aim_location_rightsinfo },
	{ 0x0004, "Set User Info"	 , dissect_aim_location_setuserinfo },
	{ 0x0005, "Request User Info"	 , dissect_aim_snac_location_request_user_information },
	{ 0x0006, "User Info"		 , dissect_aim_snac_location_user_information },
	{ 0x0007, "Watcher Subrequest"   , NULL },
	{ 0x0008, "Watcher Notification" , dissect_aim_location_watcher_notification },
	{ 0x0015, "User Info Query"	 , dissect_aim_location_user_info_query },
	{ 0, NULL, NULL }
};


/***********************************************************************************************************
 * AIM MESSAGING
 ***********************************************************************************************************/


#define INCOMING_CH1_MESSAGE_BLOCK     0x0002
#define INCOMING_CH1_SERVER_ACK_REQ    0x0003
#define INCOMING_CH1_MESSAGE_AUTH_RESP 0x0004
#define INCOMING_CH1_MESSAGE_OFFLINE   0x0006
#define INCOMING_CH1_ICON_PRESENT      0x0008
#define INCOMING_CH1_BUDDY_REQ         0x0009
#define INCOMING_CH1_TYPING            0x000b

static const aim_tlv aim_messaging_incoming_ch1_tlvs[] = {
	{ INCOMING_CH1_MESSAGE_BLOCK,	  "Message Block", dissect_aim_tlv_value_messageblock },
	{ INCOMING_CH1_SERVER_ACK_REQ,	  "Server Ack Requested", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_MESSAGE_AUTH_RESP, "Message is Auto Response", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_MESSAGE_OFFLINE,	  "Message was received offline", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_ICON_PRESENT,	  "Icon present", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_BUDDY_REQ,	  "Buddy Req", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_TYPING,		  "Non-direct connect typing notification", dissect_aim_tlv_value_bytes },
	{ 0, NULL, NULL },
};

static int dissect_aim_tlv_value_rendezvous(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo);

#define ICBM_CHANNEL_IM		0x0001
#define ICBM_CHANNEL_RENDEZVOUS	0x0002

static const value_string icbm_channel_types[] = {
	{ ICBM_CHANNEL_IM,	   "IM" },
	{ ICBM_CHANNEL_RENDEZVOUS, "Rendezvous" },
	{ 0, NULL },
};

#define INCOMING_CH2_SERVER_ACK_REQ    	   0x0003
#define INCOMING_CH2_RENDEZVOUS_DATA       0x0005

static const aim_tlv aim_messaging_incoming_ch2_tlvs[] = {
	{ INCOMING_CH2_SERVER_ACK_REQ, "Server Ack Requested", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH2_RENDEZVOUS_DATA, "Rendez Vous Data", dissect_aim_tlv_value_rendezvous },
	{ 0, NULL, NULL },
};

#define RENDEZVOUS_TLV_CHANNEL				0x0001
#define RENDEZVOUS_TLV_IP_ADDR				0x0002
#define RENDEZVOUS_TLV_INT_IP				0x0003
#define RENDEZVOUS_TLV_EXT_IP				0x0004
#define RENDEZVOUS_TLV_EXT_PORT				0x0005
#define RENDEZVOUS_TLV_DOWNLOAD_URL			0x0006
#define RENDEZVOUS_TLV_VERIFIED_DOWNLOAD_URL		0x0008
#define RENDEZVOUS_TLV_SEQ_NUM				0x000A
#define RENDEZVOUS_TLV_CANCEL_REASON			0x000B
#define RENDEZVOUS_TLV_INVITATION			0x000C
#define RENDEZVOUS_TLV_INVITE_MIME_CHARSET		0x000D
#define RENDEZVOUS_TLV_INVITE_MIME_LANG			0x000E
#define RENDEZVOUS_TLV_REQ_HOST_CHECK			0x000F
#define RENDEZVOUS_TLV_REQ_USE_ARS			0x0010
#define RENDEZVOUS_TLV_REQ_SECURE			0x0011
#define RENDEZVOUS_TLV_MAX_PROTOCOL_VER			0x0012
#define RENDEZVOUS_TLV_MIN_PROTOCOL_VER			0x0013
#define RENDEZVOUS_TLV_COUNTER_REASON			0x0014
#define RENDEZVOUS_TLV_INVITE_MIME_TYPE			0x0015
#define RENDEZVOUS_TLV_IP_ADDR_XOR			0x0016
#define RENDEZVOUS_TLV_PORT_XOR				0x0017
#define RENDEZVOUS_TLV_ADDR_LIST			0x0018
#define RENDEZVOUS_TLV_SESSION_ID			0x0019
#define RENDEZVOUS_TLV_ROLLOVER_ID			0x001A
#define RENDEZVOUS_TLV_EXTENDED_DATA			0x2711
#define RENDEZVOUS_TLV_ICHAT_INVITEES_DATA		0x277E

static const aim_tlv aim_rendezvous_tlvs[] = {
	{ RENDEZVOUS_TLV_CHANNEL,		"Rendezvous ICBM Channel", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_IP_ADDR,		"Rendezvous IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_INT_IP,		"Internal IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_EXT_IP,		"External IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_EXT_PORT,		"External Port", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_DOWNLOAD_URL,		"Service Support Download URL", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_VERIFIED_DOWNLOAD_URL, "Verified Service Support Download URL", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_SEQ_NUM,		"Sequence Number", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_CANCEL_REASON,		"Cancel Reason", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_INVITATION,		"Invitation Text", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_INVITE_MIME_CHARSET,	"Data MIME Type", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_INVITE_MIME_LANG,	"Data Language", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_REQ_HOST_CHECK,	"Request Host Check", NULL },
	{ RENDEZVOUS_TLV_REQ_USE_ARS,		"Request Data via Rendezvous Server", NULL },
	{ RENDEZVOUS_TLV_REQ_SECURE,		"Request SSL Connection", NULL },
	{ RENDEZVOUS_TLV_MAX_PROTOCOL_VER,	"Maximum Protocol Version", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_MIN_PROTOCOL_VER,	"Minimum Protocol Version", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_COUNTER_REASON,	"Counter Proposal Reason", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_INVITE_MIME_TYPE,	"Data MIME Type", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_IP_ADDR_XOR,		"XORed Rendezvous IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_PORT_XOR,		"XORed Port", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_ADDR_LIST,		"Address/Port List", dissect_aim_tlv_value_string08_array },
	{ RENDEZVOUS_TLV_SESSION_ID,		"Session ID", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_ROLLOVER_ID,		"Rollover ID", dissect_aim_tlv_value_string },
/*
	The dissect_aim_tlv_value_extended_data function does not work for iChat generated rendezvous data
	{ RENDEZVOUS_TLV_EXTENDED_DATA,		"Extended Data", dissect_aim_tlv_value_extended_data },
*/
	{ RENDEZVOUS_TLV_EXTENDED_DATA,		"Extended Data", NULL },
	{ RENDEZVOUS_TLV_ICHAT_INVITEES_DATA,	"iChat Invitees Data", NULL },
	{ 0, NULL, NULL },
};

#define MINITYPING_FINISHED_SIGN			0x0000
#define MINITYPING_TEXT_TYPED_SIGN			0x0001
#define MINITYPING_BEGUN_SIGN				0x0002

static const value_string minityping_type[] _U_ = {
	{MINITYPING_FINISHED_SIGN,   "Typing finished sign" },
	{MINITYPING_TEXT_TYPED_SIGN, "Text typed sign" },
	{MINITYPING_BEGUN_SIGN,	     "Typing begun sign" },
	{0, NULL }
};

#define RENDEZVOUS_MSG_REQUEST 		0
#define RENDEZVOUS_MSG_CANCEL		1
#define RENDEZVOUS_MSG_ACCEPT 		2

static const value_string rendezvous_msg_types[] = {
	{ RENDEZVOUS_MSG_REQUEST, "Request" },
	{ RENDEZVOUS_MSG_CANCEL,  "Cancel" },
	{ RENDEZVOUS_MSG_ACCEPT,  "Accept" },
	{ 0, NULL },
};

#define CLIENT_ERR__REASON_UNSUPPORTED_CHANNEL	1
#define CLIENT_ERR__REASON_BUSTED_PAYLOAD	2
#define CLIENT_ERR__REASON_CHANNEL_SPECIFIC	3

static const value_string client_err_reason_types[] = {
	{ CLIENT_ERR__REASON_UNSUPPORTED_CHANNEL, "Unsupported Channel" },
	{ CLIENT_ERR__REASON_BUSTED_PAYLOAD,	  "Busted Payload" },
	{ CLIENT_ERR__REASON_CHANNEL_SPECIFIC,	  "Channel Specific Error" },
	{ 0, NULL },
};

#define RENDEZVOUS_NAK_PROPOSAL_UNSUPPORTED 0
#define RENDEZVOUS_NAK_PROPOSAL_DENIED 1
#define RENDEZVOUS_NAK_PROPOSAL_IGNORED 2
#define RENDEZVOUS_NAK_BUSTED_PARAMETERS 3
#define RENDEZVOUS_NAK_PROPOSAL_TIMED_OUT 4
#define RENDEZVOUS_NAK_ONLINE_BUT_NOT_AVAILABLE 5
#define RENDEZVOUS_NAK_INSUFFICIENT_RESOURCES 6
#define RENDEZVOUS_NAK_RATE_LIMITED 7
#define RENDEZVOUS_NAK_NO_DATA 8
#define RENDEZVOUS_NAK_VERSION_MISMATCH 9
#define RENDEZVOUS_NAK_SECURITY_MISMATCH 10
#define RENDEZVOUS_NAK_SERVICE_SPECIFIC_REASON 15

static const value_string rendezvous_nak_reason_types[] = {
	{ RENDEZVOUS_NAK_PROPOSAL_UNSUPPORTED,	   "Proposal UUID not supported" },
	{ RENDEZVOUS_NAK_PROPOSAL_DENIED,	   "Not authorized, or user declined" },
	{ RENDEZVOUS_NAK_PROPOSAL_IGNORED,	   "Proposal ignored" },
	{ RENDEZVOUS_NAK_BUSTED_PARAMETERS,	   "Proposal malformed" },
	{ RENDEZVOUS_NAK_PROPOSAL_TIMED_OUT,	   "Attempt to act on proposal (e.g. connect) timed out" },
	{ RENDEZVOUS_NAK_ONLINE_BUT_NOT_AVAILABLE, "Recipient away or busy" },
	{ RENDEZVOUS_NAK_INSUFFICIENT_RESOURCES,   "Recipient had internal error" },
	{ RENDEZVOUS_NAK_RATE_LIMITED,		   "Recipient was ratelimited" },
	{ RENDEZVOUS_NAK_NO_DATA,		   "Recipient had nothing to send" },
	{ RENDEZVOUS_NAK_VERSION_MISMATCH,	   "Incompatible versions" },
	{ RENDEZVOUS_NAK_SECURITY_MISMATCH,	   "Incompatible security settings" },
	{ RENDEZVOUS_NAK_SERVICE_SPECIFIC_REASON,  "Service-specific reject defined by client" },
	{ 0, NULL },
};

#define EXTENDED_DATA_MTYPE_PLAIN 0x01
#define EXTENDED_DATA_MTYPE_CHAT 0x02
#define EXTENDED_DATA_MTYPE_FILEREQ 0x03
#define EXTENDED_DATA_MTYPE_URL 0x04
#define EXTENDED_DATA_MTYPE_AUTHREQ 0x06
#define EXTENDED_DATA_MTYPE_AUTHDENY 0x07
#define EXTENDED_DATA_MTYPE_AUTHOK 0x08
#define EXTENDED_DATA_MTYPE_SERVER 0x09
#define EXTENDED_DATA_MTYPE_ADDED 0x0C
#define EXTENDED_DATA_MTYPE_WWP 0x0D
#define EXTENDED_DATA_MTYPE_EEXPRESS 0x0E
#define EXTENDED_DATA_MTYPE_CONTACTS 0x13
#define EXTENDED_DATA_MTYPE_PLUGIN 0x1A
#define EXTENDED_DATA_MTYPE_AUTOAWAY 0xE8
#define EXTENDED_DATA_MTYPE_AUTOBUSY 0xE9
#define EXTENDED_DATA_MTYPE_AUTONA 0xEA
#define EXTENDED_DATA_MTYPE_AUTODND 0xEB
#define EXTENDED_DATA_MTYPE_AUTOFFC 0xEC

static const value_string extended_data_message_types[] = {
	{EXTENDED_DATA_MTYPE_PLAIN,    "Plain text (simple) message"},
	{EXTENDED_DATA_MTYPE_CHAT,     "Chat request message"},
	{EXTENDED_DATA_MTYPE_FILEREQ,  "File request / file ok message"},
	{EXTENDED_DATA_MTYPE_URL,      "URL message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHREQ,  "Authorization request message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHDENY, "Authorization denied message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHOK,   "Authorization given message (empty)"},
	{EXTENDED_DATA_MTYPE_SERVER,   "Message from OSCAR server (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_ADDED,    "\"You-were-added\" message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_WWP,      "Web pager message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_EEXPRESS, "Email express message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_CONTACTS, "Contact list message"},
	{EXTENDED_DATA_MTYPE_PLUGIN,   "Plugin message described by text string"},
	{EXTENDED_DATA_MTYPE_AUTOAWAY, "Auto away message"},
	{EXTENDED_DATA_MTYPE_AUTOBUSY, "Auto occupied message"},
	{EXTENDED_DATA_MTYPE_AUTONA,   "Auto not available message"},
	{EXTENDED_DATA_MTYPE_AUTODND,  "Auto do not disturb message"},
	{EXTENDED_DATA_MTYPE_AUTOFFC,  "Auto free for chat message"},
	{ 0, NULL },
};

#define EXTENDED_DATA_MFLAG_NORMAL 0x01
#define EXTENDED_DATA_MFLAG_AUTO   0x02
#define EXTENDED_DATA_MFLAG_MULTI  0x80

#define EVIL_ORIGIN_ANONYMOUS		1
#define EVIL_ORIGIN_NONANONYMOUS 	2

static const value_string evil_origins[] = {
	{EVIL_ORIGIN_ANONYMOUS,	   "Anonymous"},
	{EVIL_ORIGIN_NONANONYMOUS, "Non-Anonymous"},
	{0, NULL },
};

/* Initialize the protocol and registered fields */

static int
dissect_aim_tlv_value_rendezvous(proto_item *ti, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo)
{
	int offset = 0;
	proto_tree *entry = proto_item_add_subtree(ti, ett_aim_rendezvous_data);
	proto_tree_add_item(entry, hf_aim_rendezvous_msg_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(entry, hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA);
	offset += 8;

	offset = dissect_aim_capability(entry, tvb, offset);

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, entry,
					aim_rendezvous_tlvs);
}

static int
dissect_aim_msg_outgoing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	const aim_tlv *aim_ch_tlvs = NULL;
	uint16_t channel_id;
	uint8_t *buddyname;
	int buddyname_length;

	/* ICBM Cookie */
	proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA);
	offset += 8;

	/* Message Channel ID */
	channel_id = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;

	/* Add the outgoing username to the info column */
	buddyname_length = aim_get_buddyname(pinfo->pool, &buddyname, tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " to: %s",
			format_text(pinfo->pool, buddyname, buddyname_length));

	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);

	switch(channel_id) {
	case ICBM_CHANNEL_IM: aim_ch_tlvs = aim_messaging_incoming_ch1_tlvs; break;
	case ICBM_CHANNEL_RENDEZVOUS: aim_ch_tlvs = aim_messaging_incoming_ch2_tlvs; break;
	default: return offset;
	}

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, msg_tree, aim_ch_tlvs);
}


static int
dissect_aim_msg_incoming(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	const aim_tlv *aim_ch_tlvs;
	uint16_t channel_id;

	/* ICBM Cookie */
	proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA);
	offset += 8;

	/* Message Channel ID */
	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	channel_id = tvb_get_ntohs(tvb, offset);
	offset += 2;

	offset = dissect_aim_userinfo(tvb, pinfo, offset, msg_tree);

	switch(channel_id) {
	case ICBM_CHANNEL_IM: aim_ch_tlvs = aim_messaging_incoming_ch1_tlvs; break;
	case ICBM_CHANNEL_RENDEZVOUS: aim_ch_tlvs = aim_messaging_incoming_ch2_tlvs; break;
	default: return offset;
	}

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, msg_tree, aim_ch_tlvs);
}

static int
dissect_aim_msg_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_icbm_channel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_msg_flags, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_snac_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_sender_warnlevel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_receiver_warnlevel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_min_msg_interval, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	return offset;
}

static int
dissect_aim_msg_evil_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_icbm_evil, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	return dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
}


static int
dissect_aim_msg_evil_repl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_evil_warn_level, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_evil_new_warn_level, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	return offset;
}

static int
dissect_aim_msg_minityping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_cookie, tvb, offset, 8, ENC_NA); offset+=8;
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_channel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_type, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	return offset;
}

typedef struct _aim_client_plugin
{
	const char *name;
	e_guid_t uuid;
} aim_client_plugin;

static const aim_client_plugin known_client_plugins[] = {
	{ "None",
	 {0x0, 0x0, 0x0,
	 {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}},

	{ "Status Manager",
	 {0xD140CF10, 0xE94F, 0x11D3,
	 {0xBC, 0xD2, 0x00, 0x04, 0xAC, 0x96, 0xDD, 0x96}}},

	{ NULL, {0x0, 0x0, 0x0, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } } }
};

static const
aim_client_plugin *aim_find_plugin ( e_guid_t uuid)
{
	int i;

	for(i = 0; known_client_plugins[i].name; i++)
	{
		const aim_client_plugin *plugin = &(known_client_plugins[i]);

		if(memcmp(&(plugin->uuid), &uuid, sizeof(e_guid_t)) == 0)
			return plugin;
	}

	return NULL;
}

static int
dissect_aim_plugin(proto_tree *entry, tvbuff_t *tvb, int offset, e_guid_t* out_plugin_uuid)
{
	const aim_client_plugin *plugin = NULL;
	e_guid_t uuid;
	proto_item* ti;

	uuid.data1 = tvb_get_ntohl(tvb, offset);
	uuid.data2 = tvb_get_ntohs(tvb, offset+4);
	uuid.data3 = tvb_get_ntohs(tvb, offset+6);
	tvb_memcpy(tvb, uuid.data4, offset+8, 8);
	if (out_plugin_uuid)
		*out_plugin_uuid = uuid;

	plugin = aim_find_plugin(uuid);

	ti = proto_tree_add_item(entry, hf_aim_messaging_plugin, tvb, offset, 16, ENC_NA);
	proto_item_append_text(ti, " (%s)", plugin ? plugin->name:"Unknown");

	return offset+16;
}

static int
dissect_aim_rendezvous_extended_message(tvbuff_t *tvb, proto_tree *msg_tree)
{
	int offset = 0;
	uint32_t text_length;
	static int * const flags[] = {
		&hf_aim_rendezvous_extended_data_message_flags_normal,
		&hf_aim_rendezvous_extended_data_message_flags_auto,
		&hf_aim_rendezvous_extended_data_message_flags_multi,
		NULL
	};

	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
	proto_tree_add_bitmask(msg_tree, tvb, offset, hf_aim_rendezvous_extended_data_message_flags,
			       ett_aim_extended_data_message_flags, flags, ENC_NA);
	offset+=1;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_status_code, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_priority_code, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	text_length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item_ret_uint(msg_tree, hf_aim_rendezvous_extended_data_message_text_length, tvb, offset, 2, ENC_BIG_ENDIAN, &text_length); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_text, tvb, offset, text_length, ENC_ASCII); /* offset+=text_length; */

	offset = tvb_reported_length(tvb);

	return offset;
}

static int
is_uuid_null(e_guid_t uuid)
{
	return (uuid.data1 == 0) &&
	       (uuid.data2 == 0) &&
	       (uuid.data3 == 0) &&
	       (uuid.data4[0] == 0) &&
	       (uuid.data4[1] == 0) &&
	       (uuid.data4[2] == 0) &&
	       (uuid.data4[3] == 0) &&
	       (uuid.data4[4] == 0) &&
	       (uuid.data4[5] == 0) &&
	       (uuid.data4[6] == 0) &&
	       (uuid.data4[7] == 0);
}

static int
dissect_aim_tlv_value_extended_data(proto_tree *entry, uint16_t valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	uint16_t length/*, protocol_version*/;
	int start_offset;
	e_guid_t plugin_uuid;

	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(entry, hf_aim_icbm_client_err_length, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset+=2;
	start_offset = offset;

	proto_tree_add_item(entry, hf_aim_icbm_client_err_protocol_version, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

	offset = dissect_aim_plugin(entry, tvb, offset, &plugin_uuid);
	proto_tree_add_item(entry, hf_aim_messaging_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(entry, hf_aim_icbm_client_err_client_caps_flags, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(entry, hf_aim_messaging_unknown_uint8, tvb, offset, 1, ENC_NA);	offset += 1;
	proto_tree_add_item(entry, hf_aim_icbm_client_err_downcounter, tvb, offset, 2, ENC_LITTLE_ENDIAN); /* offset += 2;*/

	offset = start_offset + length;

	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(entry, hf_aim_icbm_client_err_length, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset+=2;
	start_offset = offset;
	proto_tree_add_item(entry, hf_aim_icbm_client_err_downcounter, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(entry, hf_aim_messaging_unknown_data, tvb, offset, length-2, ENC_NA);
	offset = start_offset + length;

	if (is_uuid_null(plugin_uuid))
	{
		/* a message follows */
		tvbuff_t *subtvb = tvb_new_subset_remaining(tvb, offset);
		/* offset += */ dissect_aim_rendezvous_extended_message(subtvb, entry);
	}
	else
	{
		/* plugin-specific data follows */
		proto_tree_add_item(entry, hf_aim_messaging_plugin_specific_data, tvb, offset, -1, ENC_NA);
	}
	offset = tvb_reported_length(tvb);

	return offset;
}

static int
dissect_aim_msg_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;

	proto_tree_add_item(msg_tree,hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA); offset+=8;

	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			    ENC_BIG_ENDIAN); offset += 2;

	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);

	return offset;
}

static int
dissect_aim_msg_client_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	uint16_t channel, reason;

	proto_tree_add_item(msg_tree,hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA); offset+=8;
	channel = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree,hf_aim_icbm_channel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
	reason = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_icbm_client_err_reason, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

	if (reason == CLIENT_ERR__REASON_CHANNEL_SPECIFIC && tvb_reported_length_remaining(tvb, offset) > 0)
	{
		switch (channel)
		{
		case ICBM_CHANNEL_RENDEZVOUS:
			proto_tree_add_item(msg_tree, hf_aim_icbm_rendezvous_nak_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
			proto_tree_add_item(msg_tree, hf_aim_icbm_rendezvous_nak, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
			break;

		default:
		    {
			tvbuff_t *subtvb = tvb_new_subset_remaining(tvb, offset);
			proto_tree *extended_tree = proto_tree_add_subtree(msg_tree, tvb, offset, -1, ett_aim_extended_data, NULL, "Extended Data");
			dissect_aim_tlv_value_extended_data(extended_tree, 0, subtvb, pinfo);
			break;
		    }
		}
	}

	return offset;
}

static const aim_subtype aim_fnac_family_messaging[] = {
	{ 0x0001, "Error",			     dissect_aim_snac_error },
	{ 0x0002, "Set ICBM Parameter",		     dissect_aim_msg_params },
	{ 0x0003, "Reset ICBM Parameter",	     NULL },
	{ 0x0004, "Request Parameter Info",	     NULL},
	{ 0x0005, "Parameter Info",		     dissect_aim_msg_params },
	{ 0x0006, "Outgoing",			     dissect_aim_msg_outgoing },
	{ 0x0007, "Incoming",			     dissect_aim_msg_incoming },
	{ 0x0008, "Evil Request",		     dissect_aim_msg_evil_req },
	{ 0x0009, "Evil Response",		     dissect_aim_msg_evil_repl  },
	{ 0x000a, "Missed Call", 		     NULL },
	{ 0x000b, "Client Error",		     dissect_aim_msg_client_err },
	{ 0x000c, "Acknowledge",		     dissect_aim_msg_ack },
	{ 0x0014, "Mini Typing Notifications (MTN)", dissect_aim_msg_minityping },
	{ 0, NULL, NULL }
};



/***********************************************************************************************************
 * AIM POPUP
 ***********************************************************************************************************/


#define AIM_POPUP_TLV_MESSAGE_TEXT		0x001
#define AIM_POPUP_TLV_URL_STRING		0x002
#define AIM_POPUP_TLV_WINDOW_WIDTH		0x003
#define AIM_POPUP_TLV_WINDOW_HEIGHT		0x004
#define AIM_POPUP_TLV_AUTOHIDE_DELAY	0x005

static const aim_tlv aim_popup_tlvs[] = {
	{ AIM_POPUP_TLV_MESSAGE_TEXT, "Message text (html)", dissect_aim_tlv_value_string },
	{ AIM_POPUP_TLV_URL_STRING, "URL string", dissect_aim_tlv_value_string },
	{ AIM_POPUP_TLV_WINDOW_WIDTH, "Window Width (pixels)", dissect_aim_tlv_value_uint16 },
	{ AIM_POPUP_TLV_WINDOW_HEIGHT, "Window Height (pixels)", dissect_aim_tlv_value_uint16 },
	{ AIM_POPUP_TLV_AUTOHIDE_DELAY, "Autohide delay (seconds)", dissect_aim_tlv_value_uint16 },
	{ 0, NULL, NULL }
};

static int dissect_aim_popup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *popup_tree)
{
	return dissect_aim_tlv(tvb, pinfo, 0, popup_tree, aim_popup_tlvs);
}

static const aim_subtype aim_fnac_family_popup[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Display Popup Message Server Command" , dissect_aim_popup },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM SIGNON
 ***********************************************************************************************************/

static int dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree)
{
	int offset = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, aim_client_tlvs);
	}
	return offset;
}

static int dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb,
					       packet_info *pinfo,
					       proto_tree *tree)
{
	int offset = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, aim_client_tlvs);
	}
	return offset;
}

static int dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree)
{
	uint8_t buddyname_length = 0;
	int offset = 0;
	uint8_t *buddyname;

	/* Info Type */
	proto_tree_add_item(tree, hf_aim_infotype, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Unknown */
	offset += 1;

	/* Buddy Name */
	buddyname_length = aim_get_buddyname( pinfo->pool, &buddyname, tvb, offset );

	col_append_fstr(pinfo->cinfo, COL_INFO, " Username: %s",
			format_text(pinfo->pool, buddyname, buddyname_length));

	if(tree) {
		offset+=dissect_aim_buddyname(tvb, pinfo, offset, tree);
	}

	return offset;
}

static int dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb,
						packet_info *pinfo _U_,
						proto_tree *tree)
{
	int offset = 0;
	uint16_t challenge_length = 0;

	/* Logon Challenge Length */
	challenge_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_aim_signon_challenge_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Challenge */
	proto_tree_add_item(tree, hf_aim_signon_challenge, tvb, offset, challenge_length, ENC_UTF_8);
	offset += challenge_length;
	return offset;
}

static int dissect_aim_tlv_value_registration(proto_item *ti _U_, uint16_t value_id _U_, tvbuff_t *tvb _U_, packet_info *pinfo _U_)
{
	/* FIXME */
	return 0;
}

#define REG_TLV_REGISTRATION_INFO 	0x0001

static const aim_tlv aim_registration_tlvs[] = {
	{ REG_TLV_REGISTRATION_INFO, "Registration Info", dissect_aim_tlv_value_registration },
	{ 0, NULL, NULL },
};

static int dissect_aim_snac_register (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_aim_tlv(tvb, pinfo, 0, tree, aim_registration_tlvs);
}

static const aim_subtype aim_fnac_family_signon[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Logon", dissect_aim_snac_signon_logon },
	{ 0x0003, "Logon Reply", dissect_aim_snac_signon_logon_reply },
	{ 0x0004, "Request UIN", dissect_aim_snac_register },
	{ 0x0005, "New UIN response", dissect_aim_snac_register },
	{ 0x0006, "Sign-on", dissect_aim_snac_signon_signon },
	{ 0x0007, "Sign-on Reply", dissect_aim_snac_signon_signon_reply },
	{ 0x000a, "Server SecureID Request", NULL },
	{ 0x000b, "Client SecureID Reply", NULL },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM SSI
 ***********************************************************************************************************/
#define SSI_RIGHTSINFO_TLV_MAX_ITEMS	0x0004

static const aim_tlv aim_ssi_rightsinfo_tlvs[] = {
	{ SSI_RIGHTSINFO_TLV_MAX_ITEMS, "Maximums For Items", dissect_aim_tlv_value_bytes },
	{ 0, NULL, NULL },
};

/* Initialize the protocol and registered fields */

/** Calculate size of SSI entry
 * Size of SSI entry can be calculated as:
 *   sizeof(buddy name length field) = sizeof(uint16_t) = 2
 * + sizeof(buddy name string) = buddy name length field = N
 * + sizeof(group ID) = sizeof(uint16_t) = 2
 * + sizeof(buddy ID) = sizeof(uint16_t) = 2
 * + sizeof(buddy type) = sizeof(uint16_t) = 2
 * + sizeof(TLV length) = sizeof(uint16_t) = 2
 * + sizeof(TLVs) = TLV length = M
 * = 2 + N + 2 * 4 + M
 */
static int calc_ssi_entry_size(tvbuff_t *tvb, int offset)
{
	int ssi_entry_size = 2 + tvb_get_ntohs(tvb, offset) + 2 * 3;
	ssi_entry_size += tvb_get_ntohs(tvb, offset + ssi_entry_size) + 2;
	return ssi_entry_size;
}

static int dissect_ssi_item(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *ssi_entry)
{
	uint16_t buddyname_length = 0;
	int endoffset;
	uint16_t tlv_len = 0;

	/* Buddy Name Length */
	buddyname_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Buddy Name */
	if (buddyname_length > 0) {
		proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname, tvb, offset, buddyname_length, ENC_UTF_8);
		offset += buddyname_length;
	}

	/* Buddy group ID */
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_gid, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Buddy ID */
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_bid, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Buddy Type */
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Size of the following TLV in bytes (as opposed to the number of
	   TLV objects in the chain) */
	tlv_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_tlvlen, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	endoffset = offset;
	/* For now, we just dump the TLV contents as-is, since there is not a
	   TLV dissection utility that works based on total chain length */
	while(endoffset < offset+tlv_len) {
		endoffset = dissect_aim_tlv(tvb, pinfo, endoffset, ssi_entry, aim_client_tlvs);
	}
	return endoffset;
}

static int dissect_ssi_ssi_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ssi_entry)
{
	return dissect_ssi_item(tvb, pinfo, 0, ssi_entry);
}

static int dissect_ssi_ssi_items(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	int ssi_entry_size;
	proto_tree *ssi_entry = NULL;
	int size = tvb_reported_length(tvb);
	while (size > offset)
	{
		ssi_entry_size = calc_ssi_entry_size(tvb, offset);
		ssi_entry = proto_tree_add_subtree(tree, tvb, offset, ssi_entry_size, ett_aim_ssi, NULL, "SSI Entry");
		offset = dissect_ssi_item(tvb, pinfo, offset, ssi_entry);
	}
	return offset;
}

static int dissect_aim_ssi_rightsinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ssi_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, ssi_tree, aim_ssi_rightsinfo_tlvs);
}

static int dissect_aim_ssi_was_added(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ssi_tree)
{
	return dissect_aim_buddyname(tvb, pinfo, 0, ssi_tree);
}

static int dissect_aim_snac_ssi_time_and_items_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;

	/* get timestamp */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_last_change_time, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
	offset += 4;

	/* get number of SSI items */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_numitems, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

static int dissect_aim_snac_ssi_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_tree *ssi_entry = NULL;
	uint16_t num_items, i;
	int ssi_entry_size;

	/* SSI Version */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Number of items */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_numitems, tvb, offset, 2, ENC_BIG_ENDIAN);
	num_items = tvb_get_ntohs(tvb, offset);
	offset += 2;

	for(i = 0; i < num_items; i++) {
		ssi_entry_size = calc_ssi_entry_size(tvb, offset);
		ssi_entry = proto_tree_add_subtree_format(tree, tvb, offset, ssi_entry_size,
				ett_aim_ssi, NULL, "SSI Entry %u", i);
		offset = dissect_ssi_item(tvb, pinfo, offset, ssi_entry);
	}
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_last_change_time, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);

	return offset;
}

static int dissect_aim_snac_ssi_auth_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	uint16_t reason_length;
	/*uint16_t unknown;*/

	/* get buddy length (1 byte) */
	uint8_t buddyname_length = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname_len8, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* show buddy name */
	if (buddyname_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname, tvb, offset, buddyname_length, ENC_UTF_8);
		offset += buddyname_length;
	}
	/* get reason message length (2 bytes) */
	reason_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* show reason message if present */
	if (reason_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str, tvb, offset, reason_length, ENC_UTF_8);
		offset += reason_length;
	}

	/* unknown (always 0x0000 ???) */
	/*unknown = tvb_get_ntohs(tvb, offset);*/
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_grant_auth_unkn, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

static int dissect_aim_snac_ssi_auth_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	uint16_t reason_length;

	/* get buddy length (1 byte) */
	uint8_t buddyname_length = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname_len8, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* show buddy name */
	if (buddyname_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname, tvb, offset, buddyname_length, ENC_UTF_8);
		offset += buddyname_length;
	}

	/* accept/reject authorization flag */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_allow_auth, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* get reason message length (2 bytes) */
	reason_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* show reason message if present */
	if (reason_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str, tvb, offset, reason_length, ENC_UTF_8);
		offset += reason_length;
	}

	return offset;
}

static const aim_subtype aim_fnac_family_ssi[] = {
	{ 0x0001, "Error",				 dissect_aim_snac_error },
	{ 0x0002, "Request Rights",			 NULL },
	{ 0x0003, "Rights Info",			 dissect_aim_ssi_rightsinfo },
	{ 0x0004, "Request List (first time)",		 NULL },
	{ 0x0005, "Request List",			 dissect_aim_snac_ssi_time_and_items_num },
	{ 0x0006, "List",				 dissect_aim_snac_ssi_list },
	{ 0x0007, "Activate",				 NULL },
	{ 0x0008, "Add Buddy",				 dissect_ssi_ssi_item },
	{ 0x0009, "Modify Buddy",			 dissect_ssi_ssi_items },
	{ 0x000a, "Delete Buddy",			 dissect_ssi_ssi_item },
	{ 0x000e, "Server Ack",				 dissect_aim_ssi_result },
	{ 0x000f, "No List",				 dissect_aim_snac_ssi_time_and_items_num },
	{ 0x0011, "Edit Start",				 NULL },
	{ 0x0012, "Edit Stop",				 NULL },
	{ 0x0014, "Grant Future Authorization to Buddy", dissect_aim_snac_ssi_auth_request },
	{ 0x0015, "Future Authorization Granted",	 dissect_aim_snac_ssi_auth_request },
	{ 0x0018, "Send Authentication Request",	 dissect_aim_snac_ssi_auth_request },
	{ 0x0019, "Authentication Request",		 dissect_aim_snac_ssi_auth_request },
	{ 0x001a, "Send Authentication Reply",		 dissect_aim_snac_ssi_auth_reply },
	{ 0x001b, "Authentication Reply",		 dissect_aim_snac_ssi_auth_reply },
	{ 0x001c, "Remote User Added Client To List",	 dissect_aim_ssi_was_added },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM SST
 ***********************************************************************************************************/
static int dissect_aim_sst_buddy_down_req (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = dissect_aim_buddyname(tvb, pinfo, 0, tree);
	uint8_t md5_size;

	proto_tree_add_item(tree, hf_aim_sst_unknown, tvb, offset, 4, ENC_NA);
	offset+=4;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	md5_size = tvb_get_uint8(tvb, offset);
	offset++;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash, tvb, offset, md5_size, ENC_NA);

	offset+=md5_size;
	return offset;
}

static int dissect_aim_sst_buddy_down_repl (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = dissect_aim_buddyname(tvb, pinfo, 0, tree);
	uint8_t md5_size;
	uint16_t icon_size;

	proto_tree_add_item(tree, hf_aim_sst_unknown, tvb, offset, 3, ENC_NA);
	offset+=3;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	md5_size = tvb_get_uint8(tvb, offset);
	offset++;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash, tvb, offset, md5_size, ENC_NA);

	offset+=md5_size;

	proto_tree_add_item(tree, hf_aim_sst_icon_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	icon_size = tvb_get_ntohs(tvb, offset);
	offset+=2;

	if (icon_size)
	{
		proto_tree_add_item(tree, hf_aim_sst_icon, tvb, offset, icon_size, ENC_NA);
	}

	offset+=icon_size;

	return offset;
}

static int dissect_aim_sst_buddy_up_repl (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	uint8_t md5_size;

	proto_tree_add_item(tree, hf_aim_sst_unknown, tvb, offset, 4, ENC_NA);
	offset+=4;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	md5_size = tvb_get_uint8(tvb, offset);
	offset++;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash, tvb, offset, md5_size, ENC_NA);

	offset+=md5_size;
	return offset;
}

static int dissect_aim_sst_buddy_up_req (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	uint16_t icon_size;

	proto_tree_add_item(tree, hf_aim_sst_ref_num, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	proto_tree_add_item(tree, hf_aim_sst_icon_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	icon_size = tvb_get_ntohs(tvb, offset);
	offset+=2;

	if (icon_size)
	{
		proto_tree_add_item(tree, hf_aim_sst_icon, tvb, offset, icon_size, ENC_NA);
	}

	offset+=icon_size;
	return offset;
}

static const aim_subtype aim_fnac_family_sst[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Upload Buddy Icon Request", dissect_aim_sst_buddy_up_req },
	{ 0x0003, "Upload Buddy Icon Reply", dissect_aim_sst_buddy_up_repl },
	{ 0x0004, "Download Buddy Icon Request", dissect_aim_sst_buddy_down_req },
	{ 0x0005, "Download Buddy Icon Reply", dissect_aim_sst_buddy_down_repl },
	{ 0, NULL, NULL }
};

static const aim_subtype aim_fnac_family_stats[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Set Report Interval", NULL },
	{ 0x0003, "Report Request", NULL },
	{ 0x0004, "Report Ack", NULL },
	{ 0, NULL, NULL }
};

static const aim_subtype aim_fnac_family_translate[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Translate Request", NULL },
	{ 0x0003, "Translate Reply", NULL },
	{ 0, NULL, NULL }
};

/***********************************************************************************************************
 * AIM USER LOOKUP
 ***********************************************************************************************************/
static int dissect_aim_userlookup_search(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *lookup_tree)
{
	proto_tree_add_item(lookup_tree, hf_aim_userlookup_email, tvb, 0, tvb_reported_length(tvb), ENC_UTF_8);
	return tvb_reported_length(tvb);
}


static int dissect_aim_userlookup_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lookup_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, lookup_tree, aim_client_tlvs);
}

static const aim_subtype aim_fnac_family_userlookup[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Search for user by email address", dissect_aim_userlookup_search },
	{ 0x0003, "Search results", dissect_aim_userlookup_result },
	{ 0, NULL, NULL }
};

static void
family_free(void *p, void *user_data _U_)
{
	g_free(p);
}

static void
aim_shutdown(void)
{
	g_list_foreach(families, family_free, NULL);
	g_list_free(families);
}

void
proto_register_aim(void)
{

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_cmd_start,
		  { "Command Start", "aim.cmd_start", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_channel,
		  { "Channel ID", "aim.channel", FT_UINT8, BASE_HEX, VALS(aim_flap_channels), 0x0, NULL, HFILL }
		},
		{ &hf_aim_seqno,
		  { "Sequence Number", "aim.seqno", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_version,
		  { "Protocol Version", "aim.version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_data_len,
		  { "Data Field Length", "aim.datalen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_tlv_length,
		  { "Length", "aim.tlv.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_tlv_value_id,
		  { "Value ID", "aim.tlv.value_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_data,
		  { "Data", "aim.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_family,
		  { "FNAC Family ID", "aim.fnac.family", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype,
		  { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_flags,
		  { "FNAC Flags", "aim.fnac.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_id,
		  { "FNAC ID", "aim.fnac.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_buddyname_len,
		  { "Buddyname len", "aim.buddynamelen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_buddyname,
		  { "Buddy Name", "aim.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_tlvcount,
		  { "TLV Count", "aim.tlvcount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_snac_error,
		  { "SNAC Error", "aim.snac.error", FT_UINT16, BASE_HEX, VALS(aim_snac_errors), 0x0, NULL, HFILL },
		},
		{ &hf_aim_userclass_unconfirmed,
		  { "AOL Unconfirmed account flag", "aim.userclass.unconfirmed", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNCONFIRMED, NULL, HFILL },
		},
		{ &hf_aim_userclass_administrator,
		  { "AOL Administrator flag", "aim.userclass.administrator", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_ADMINISTRATOR, NULL, HFILL },
		},
		{ &hf_aim_userclass_aol,
		  { "AOL Staff User Flag", "aim.userclass.staff", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_AOL, NULL, HFILL },
		},
		{ &hf_aim_userclass_commercial,
		  { "AOL commercial account flag", "aim.userclass.commercial", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_COMMERCIAL, NULL, HFILL },
		},
		{ &hf_aim_userclass_aim,
		  { "AIM user flag", "aim.userclass.free", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_AIM, NULL, HFILL },
		},
		{ &hf_aim_userclass_away,
		  { "AOL away status flag", "aim.userclass.away", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_AWAY, NULL, HFILL },
		},
		{ &hf_aim_userclass_icq,
		  { "ICQ user sign", "aim.userclass.icq", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_ICQ, NULL, HFILL },
		},
		{ &hf_aim_userclass_wireless,
		  { "AOL wireless user", "aim.userclass.wireless", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_WIRELESS, NULL, HFILL },
		},
		{ &hf_aim_userclass_unknown100,
		  { "Unknown bit", "aim.userclass.unknown100", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNKNOWN100, NULL, HFILL },
		},
		{ &hf_aim_userclass_imf,
		  { "Using IM Forwarding", "aim.userclass.imf", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_IMF, NULL, HFILL },
		},
		{ &hf_aim_userclass_bot,
		  { "Bot User", "aim.userclass.bot", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_BOT, NULL, HFILL },
		},
		{ &hf_aim_userclass_unknown800,
		  { "Unknown bit", "aim.userclass.unknown800", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNKNOWN800, NULL, HFILL },
		},
		{ &hf_aim_userclass_one_way_wireless,
		  { "One Way Wireless Device", "aim.userclass.one_way_wireless", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_ONE_WAY_WIRELESS, NULL, HFILL },
		},
		{ &hf_aim_userclass_unknown2000,
		  { "Unknown bit", "aim.userclass.unknown2000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNKNOWN2000, NULL, HFILL },
		},
		{ &hf_aim_userclass_unknown4000,
		  { "Unknown bit", "aim.userclass.unknown4000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNKNOWN4000, NULL, HFILL },
		},
		{ &hf_aim_userclass_unknown8000,
		  { "Unknown bit", "aim.userclass.unknown8000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNKNOWN8000, NULL, HFILL },
		},
		{ &hf_aim_userclass_unknown10000,
		  { "Unknown bit", "aim.userclass.unknown10000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNKNOWN10000, NULL, HFILL },
		},
		{ &hf_aim_userclass_unknown20000,
		  { "Unknown bit", "aim.userclass.unknown20000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_UNKNOWN20000, NULL, HFILL },
		},
		{ &hf_aim_userclass_no_knock_knock,
		  { "Do not display the 'not on Buddy List' knock-knock", "aim.userclass.no_knock_knock", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_NO_KNOCK_KNOCK, NULL, HFILL },
		},
		{ &hf_aim_userclass_forward_mobile,
		  { "Forward to mobile if not active", "aim.userclass.forward_mobile", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CLASS_FORWARD_MOBILE, NULL, HFILL },
		},
		{ &hf_aim_nickinfo_caps,
		  { "Client capabilities", "aim.nickinfo.caps", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_nickinfo_short_caps,
		  { "Short client capabilities", "aim.nickinfo.short_caps", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_fnac_flag_next_is_related,
		  { "Followed By SNAC with related information", "aim.fnac.flags.next_is_related", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FNAC_FLAG_NEXT_IS_RELATED, NULL, HFILL },
		},
		{ &hf_aim_fnac_flag_contains_version,
		  { "Contains Version of Family this SNAC is in", "aim.fnac.flags.contains_version", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FNAC_FLAG_CONTAINS_VERSION, NULL, HFILL },
		},
		{ &hf_aim_userinfo_warninglevel,
		  { "Warning Level", "aim.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_featuresdes,
		  { "Features", "aim.messageblock.featuresdes", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_featureslen,
		  { "Features Length", "aim.messageblock.featureslen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_features,
		  { "Features", "aim.messageblock.features", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_info,
		  { "Block info", "aim.messageblock.info", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_len,
		  { "Block length", "aim.messageblock.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_charset,
		  { "Block Character set", "aim.messageblock.charset", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_charsubset,
		  { "Block Character subset", "aim.messageblock.charsubset", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_messageblock_message,
		  { "Message", "aim.messageblock.message", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_ip,
		  { "Internal IP address", "aim.dcinfo.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_tcpport,
		  { "TCP Port", "aim.dcinfo.tcpport", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_type,
		  { "Type", "aim.dcinfo.type", FT_UINT8, BASE_HEX, VALS(dc_types), 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_proto_version,
		  { "Protocol Version", "aim.dcinfo.proto_version", FT_UINT16, BASE_DEC, VALS(protocol_versions), 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_auth_cookie,
		  { "Authorization Cookie", "aim.dcinfo.auth_cookie", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_webport,
		  { "Web Front Port", "aim.dcinfo.webport", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_client_future,
		  { "Client Futures", "aim.dcinfo.client_futures", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_last_info_update,
		  { "Last Info Update", "aim.dcinfo.last_info_update", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_last_ext_info_update,
		  { "Last Extended Info Update", "aim.dcinfo.last_ext_info_update", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_last_ext_status_update,
		  { "Last Extended Status Update", "aim.dcinfo.last_ext_status_update", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_dcinfo_unknown,
		  { "Unknown", "aim.dcinfo.unknown", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_ssi_result_code,
		  { "Last SSI operation result code", "aim.ssi.code", FT_UINT16, BASE_HEX, VALS(aim_ssi_result_codes), 0x0, NULL, HFILL },
		},
		{ &hf_aim_string08,
		  { "Address/Port List", "aim.string08", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf_admin[] = {
		{ &hf_admin_acctinfo_code,
		  { "Account Information Request Code", "aim_admin.acctinfo.code", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_admin_acctinfo_unknown,
		  { "Unknown", "aim_admin.acctinfo.unknown", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_admin_acctinfo_permissions,
		  { "Account Permissions", "aim_admin.acctinfo.permissions", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_admin_confirm_status,
		  { "Confirmation status", "aim_admin.confirm_status", FT_UINT16, BASE_HEX, VALS(confirm_statusses), 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf_bos[] = {
#if 0
		{ &hf_aim_bos_data,
		  { "Data", "aim_bos.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
#endif
		{ &hf_aim_bos_class,
		  { "User class", "aim_bos.userclass", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf_buddylist[] = {
		{ &hf_aim_buddylist_userinfo_warninglevel,
		  { "Warning Level", "aim_buddylist.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf_chat[] = {
		{ &hf_aim_chat_screen_name,
		  { "Screen Name", "aim_chat.screen_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf_generic[] = {
		{ &hf_generic_servicereq_service,
		  { "Requested Service", "aim_generic.servicereq.service", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_motd_motdtype,
		  { "MOTD Type", "aim_generic.motd.motdtype", FT_UINT16, BASE_HEX, VALS(aim_snac_generic_motd_motdtypes), 0x0, NULL, HFILL },
		},
		{ &hf_generic_family,
		  { "Family", "aim_generic.family", FT_UINT16, BASE_CUSTOM, CF_FUNC(aim_generic_family), 0x0, NULL, HFILL },
		},
		{ &hf_generic_version,
		  { "Version", "aim_generic.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_dll_version,
		  { "DLL Version", "aim_generic.dll_version", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_numclasses,
		  { "Number of Rateinfo Classes", "aim_generic.rateinfo.numclasses", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_windowsize,
		  { "Window Size", "aim_generic.rateinfo.class.window_size", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_clearlevel,
		  { "Clear Level", "aim_generic.rateinfo.class.clearlevel", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_alertlevel,
		  { "Alert Level", "aim_generic.rateinfo.class.alertlevel", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_limitlevel,
		  { "Limit Level", "aim_generic.rateinfo.class.limitlevel", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_disconnectlevel,
		  { "Disconnect Level", "aim_generic.rateinfo.class.disconnectlevel", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_currentlevel,
		  { "Current Level", "aim_generic.rateinfo.class.currentlevel", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_maxlevel,
		  { "Max Level", "aim_generic.rateinfo.class.maxlevel", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_lasttime,
		  { "Last Time", "aim_generic.rateinfo.class.lasttime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_curstate,
		  { "Current State", "aim_generic.rateinfo.class.curstate", FT_UINT8, BASE_HEX, VALS(rateinfo_states), 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_classid,
		  { "Class ID", "aim_generic.rateinfo.class.id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfo_numpairs,
		  { "Number of Family/Subtype pairs", "aim_generic.rateinfo.class.numpairs", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_rateinfoack_group,
		  { "Acknowledged Rate Class", "aim_generic.rateinfoack.class", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_ratechange_msg,
		  { "Rate Change Message", "aim_generic.ratechange.msg", FT_UINT16, BASE_HEX, VALS(ratechange_msgs), 0x0, NULL, HFILL },
		},
		{ &hf_generic_migration_numfams,
		  { "Number of families to migrate", "aim_generic.migrate.numfams", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_priv_flags,
		  { "Privilege flags", "aim_generic.privilege_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_allow_idle_see,
		  { "Allow other users to see idle time", "aim_generic.privilege_flags.allow_idle", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL },
		},
		{ &hf_generic_allow_member_see,
		  { "Allow other users to see how long account has been a member", "aim_generic.privilege_flags.allow_member", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL },
		},
		{ &hf_generic_selfinfo_warninglevel,
		    { "Warning level", "aim_generic.selfinfo.warn_level", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_evil_new_warn_level,
		    { "New warning level", "aim_generic.evil.new_warn_level", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_idle_time,
		    { "Idle time (seconds)", "aim_generic.idle_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_client_ver_req_offset,
		    { "Client Verification Request Offset", "aim_generic.client_verification.offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_client_ver_req_length,
		    { "Client Verification Request Length", "aim_generic.client_verification.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_client_ver_req_hash,
		    { "Client Verification MD5 Hash", "aim_generic.client_verification.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_generic_ext_status_type,
		    { "Extended Status Type", "aim_generic.ext_status.type", FT_UINT16, BASE_DEC, VALS(ext_status_types), 0x0, NULL, HFILL },
		},
		{ &hf_generic_ext_status_flags,
		    { "Extended Status Flags", "aim_generic.ext_status.flags", FT_UINT8, BASE_HEX, VALS(ext_status_flags), 0x0, NULL, HFILL },
		},
		{ &hf_generic_ext_status_length,
		    { "Extended Status Length", "aim_generic.ext_status.length", FT_UINT8, BASE_HEX, NULL, 0x0, NULL , HFILL },
		},
		{ &hf_generic_ext_status_data,
		    { "Extended Status Data", "aim_generic.ext_status.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL , HFILL },
		},
	};

	static hf_register_info hf_icq[] = {
		{ &hf_icq_tlv_data_chunk_size,
		  { "Data chunk size", "aim_icq.chunk_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_icq_tlv_request_owner_uid,
		  { "Owner UID", "aim_icq.owner_uid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL},
		},
		{ &hf_icq_tlv_request_type,
		  {"Request Type", "aim_icq.request_type", FT_UINT16, BASE_DEC, VALS(aim_icq_data_types), 0x0, NULL, HFILL},
		},
		{ &hf_icq_tlv_request_seq_num,
		  {"Request Sequence Number", "aim_icq.request_seq_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL},
		},
		{ &hf_icq_dropped_msg_flag,
		  {"Dropped messages flag", "aim_icq.offline_msgs.dropped_flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_icq_meta_subtype,
		  {"Meta Request Subtype", "aim_icq.subtype", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf_location[] = {
		{ &hf_aim_location_buddyname_len,
		  { "Buddyname len", "aim_location.buddynamelen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_location_buddyname,
		  { "Buddy Name", "aim_location.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_location_userinfo_warninglevel,
		  { "Warning Level", "aim_location.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_snac_location_request_user_info_infotype,
		  { "Infotype", "aim_location.snac.request_user_info.infotype", FT_UINT16, BASE_HEX, VALS(aim_snac_location_request_user_info_infotypes), 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_messaging[] = {
		{ &hf_aim_icbm_channel,
		  { "Channel", "aim_messaging.icbm.channel",
		  FT_UINT16, BASE_HEX, VALS(icbm_channel_types), 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_msg_flags,
		  { "Message Flags", "aim_messaging.icbm.flags",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_max_snac_size,
		  { "Max SNAC Size", "aim_messaging.icbm.max_snac",
		  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_max_sender_warnlevel,
		  { "Max sender warn level", "aim_messaging.icbm.max_sender_warn-level",
		  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_max_receiver_warnlevel,
		  { "max receiver warn level", "aim_messaging.icbm.max_receiver_warnlevel",
		  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_min_msg_interval,
		  { "Minimum message interval (milliseconds)", "aim_messaging.icbm.min_msg_interval",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_cookie,
		  { "ICBM Cookie", "aim_messaging.icbmcookie",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_message_channel_id,
		  { "Message Channel ID", "aim_messaging.channelid",
		  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_evil,
		  { "Send Evil Bit As", "aim_messaging.evilreq.origin",
		  FT_UINT16, BASE_DEC, VALS(evil_origins), 0x0, NULL, HFILL }
		},
		{ &hf_aim_evil_warn_level,
		  { "Old warning level", "aim_messaging.evil.warn_level",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_evil_new_warn_level,
		  { "New warning level", "aim_messaging.evil.new_warn_level",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_notification_cookie,
		  { "Notification Cookie", "aim_messaging.notification.cookie",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_notification_channel,
		  { "Notification Channel", "aim_messaging.notification.channel",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_notification_type,
		  { "Notification Type", "aim_messaging.notification.type",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_rendezvous_nak,
		  { "Rendezvous NAK reason", "aim_messaging.rendezvous_nak",
		  FT_UINT16, BASE_HEX, VALS(rendezvous_nak_reason_types), 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_rendezvous_nak_length,
		  { "Rendezvous NAK reason length", "aim_messaging.rendezvous_nak_length",
		  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_msg_type,
		  { "Message Type", "aim_messaging.rendezvous.msg_type",
		  FT_UINT16, BASE_HEX, VALS(rendezvous_msg_types), 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_client_err_reason,
		  { "Reason", "aim_messaging.clienterr.reason",
		  FT_UINT16, BASE_DEC, VALS(client_err_reason_types), 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_client_err_protocol_version,
		  { "Version", "aim_messaging.clienterr.protocol_version",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_icbm_client_err_client_caps_flags,
		  { "Client Capabilities Flags", "aim_messaging.clienterr.client_caps_flags",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_type,
		  { "Message Type", "aim_messaging.icbm.extended_data.message.type",
		  FT_UINT8, BASE_HEX, VALS(extended_data_message_types), 0x0, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags,
		  { "Message Flags", "aim_messaging.icbm.extended_data.message.flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_normal,
		  { "Normal Message", "aim_messaging.icbm.extended_data.message.flags.normal",
		  FT_BOOLEAN, 16, TFS(&tfs_set_notset), EXTENDED_DATA_MFLAG_NORMAL, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_auto,
		  { "Auto Message", "aim_messaging.icbm.extended_data.message.flags.auto",
		  FT_BOOLEAN, 16, TFS(&tfs_set_notset), EXTENDED_DATA_MFLAG_AUTO, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_multi,
		  { "Multiple Recipients Message", "aim_messaging.icbm.rendezvous.extended_data.message.flags.multi",
		  FT_BOOLEAN, 16, TFS(&tfs_set_notset), EXTENDED_DATA_MFLAG_MULTI, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_status_code,
		  { "Status Code", "aim_messaging.icbm.extended_data.message.status_code",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_priority_code,
		  { "Priority Code", "aim_messaging.icbm.extended_data.message.priority_code",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_text_length,
		  { "Text Length", "aim_messaging.icbm.extended_data.message.text_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_text,
		  { "Text", "aim_messaging.icbm.extended_data.message.text",
		  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* Generated from convert_proto_tree_add_text.pl */
		{ &hf_aim_messaging_plugin, { "Plugin", "aim_messaging.plugin", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_icbm_client_err_length, { "Length", "aim_messaging.clienterr.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_messaging_unknown_uint8, { "Unknown", "aim_messaging.unknown_uint8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_messaging_unknown_uint16, { "Unknown", "aim_messaging.unknown_uint16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_icbm_client_err_downcounter, { "Downcounter?", "aim_messaging.clienterr.downcounter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_messaging_unknown_data, { "Unknown", "aim_messaging.unknown_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_messaging_plugin_specific_data, { "Plugin-specific data", "aim_messaging.plugin_specific_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static hf_register_info hf_signon[] = {
		{ &hf_aim_infotype,
		  { "Infotype", "aim_signon.infotype", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_signon_challenge_len,
		  { "Signon challenge length", "aim_signon.challengelen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_signon_challenge,
		  { "Signon challenge", "aim_signon.challenge", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_ssi[] = {
		{ &hf_aim_fnac_subtype_ssi_version,
		  { "SSI Version", "aim_ssi.fnac.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_numitems,
		  { "SSI Object count", "aim_ssi.fnac.numitems", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_last_change_time,
		  { "SSI Last Change Time", "aim_ssi.fnac.last_change_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_buddyname_len,
		  { "SSI Buddy Name length", "aim_ssi.fnac.buddyname_len", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_buddyname,
		  { "Buddy Name", "aim_ssi.fnac.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_gid,
		  { "SSI Buddy Group ID", "aim_ssi.fnac.gid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_bid,
		  { "SSI Buddy ID", "aim_ssi.fnac.bid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_type,
		  { "SSI Buddy type", "aim_ssi.fnac.type", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_ssi_types), 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_tlvlen,
		  { "SSI TLV Len", "aim_ssi.fnac.tlvlen", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
#if 0
		{ &hf_aim_fnac_subtype_ssi_data,
		  { "SSI Buddy Data", "aim_ssi.fnac.data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
#endif
		{ &hf_aim_fnac_subtype_ssi_buddyname_len8,
		  { "SSI Buddy Name length", "aim_ssi.fnac.buddyname_len8", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_reason_str_len,
		  { "Reason Message length", "aim_ssi.fnac.reason_len", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_reason_str,
		  { "Reason Message", "aim_ssi.fnac.reason", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_grant_auth_unkn,
		  { "Unknown", "aim_ssi.fnac.auth_unkn", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_allow_auth,
		  { "Allow flag", "aim_ssi.fnac.allow_auth_flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_sst[] = {
		{ &hf_aim_sst_md5_hash,
		  { "MD5 Hash", "aim_sst.md5", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_md5_hash_size,
		  { "MD5 Hash Size", "aim_sst.md5.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_unknown,
		  { "Unknown Data", "aim_sst.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_ref_num,
		  { "Reference Number", "aim_sst.ref_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_icon_size,
		  { "Icon Size", "aim_sst.icon_size", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_icon,
		  { "Icon", "aim_sst.icon", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf_userlookup[] = {
		{ &hf_aim_userlookup_email,
		  { "Email address looked for", "aim_lookup.email", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_aim,
		&ett_aim_dcinfo,
		&ett_aim_fnac,
		&ett_aim_fnac_flags,
		&ett_aim_tlv,
		&ett_aim_tlv_value,
		&ett_aim_buddyname,
		&ett_aim_userclass,
		&ett_aim_messageblock,
		&ett_aim_nickinfo_caps,
		&ett_aim_nickinfo_short_caps,
		&ett_aim_string08_array,

		&ett_aim_admin,
		&ett_aim_adverts,
		&ett_aim_bos,
		&ett_aim_buddylist,
		&ett_aim_chat,
		&ett_aim_chatnav,
		&ett_aim_directory,
		&ett_aim_email,

		&ett_generic_clientready,
		&ett_generic_migratefamilies,
		&ett_generic_clientready_item,
		&ett_generic_serverready,
		&ett_generic,
		&ett_generic_priv_flags,
		&ett_generic_rateinfo_class,
		&ett_generic_rateinfo_classes,
		&ett_generic_rateinfo_groups,
		&ett_generic_rateinfo_group,

		&ett_aim_icq,
		&ett_aim_icq_tlv,
		&ett_aim_invitation,
		&ett_aim_location,
		&ett_aim_messaging,
		&ett_aim_rendezvous_data,
		&ett_aim_extended_data,
		&ett_aim_extended_data_message_flags,
		&ett_aim_popup,
		&ett_aim_signon,
		&ett_aim_ssi,
		&ett_ssi,
		&ett_aim_sst,
		&ett_aim_stats,
		&ett_aim_translate,
		&ett_aim_userlookup,

	};

	static ei_register_info ei[] = {
		{ &ei_aim_messageblock_len, { "aim.messageblock.length.invalid", PI_PROTOCOL, PI_WARN, "Invalid block length", EXPFILL }},
	};

	module_t *aim_module;
	expert_module_t *expert_aim;

	/* Register the protocol name and description */
	proto_aim = proto_register_protocol("AOL Instant Messenger", "AIM", "aim");
	proto_aim_admin = proto_register_protocol("AIM Administrative", "AIM Administration", "aim_admin");
	proto_aim_adverts = proto_register_protocol("AIM Advertisements", "AIM Advertisements", "aim_adverts");
	proto_aim_bos = proto_register_protocol("AIM Privacy Management Service", "AIM BOS", "aim_bos");
	proto_aim_buddylist = proto_register_protocol("AIM Buddylist Service", "AIM Buddylist", "aim_buddylist");
	proto_aim_chat = proto_register_protocol("AIM Chat Service", "AIM Chat", "aim_chat");
	proto_aim_chatnav = proto_register_protocol("AIM Chat Navigation", "AIM ChatNav", "aim_chatnav");
	proto_aim_directory = proto_register_protocol("AIM Directory Search", "AIM Directory", "aim_dir");
	proto_aim_email = proto_register_protocol("AIM E-mail", "AIM Email", "aim_email");
	proto_aim_generic = proto_register_protocol("AIM Generic Service", "AIM Generic", "aim_generic");
	proto_aim_icq = proto_register_protocol("AIM ICQ", "AIM ICQ", "aim_icq");
	proto_aim_invitation = proto_register_protocol("AIM Invitation Service", "AIM Invitation", "aim_invitation");
	proto_aim_location = proto_register_protocol("AIM Location", "AIM Location", "aim_location");
	proto_aim_messaging = proto_register_protocol("AIM Messaging", "AIM Messaging", "aim_messaging");
	proto_aim_popup = proto_register_protocol("AIM Popup", "AIM Popup", "aim_popup");
	proto_aim_signon = proto_register_protocol("AIM Signon", "AIM Signon", "aim_signon");
	proto_aim_ssi = proto_register_protocol("AIM Server Side Info", "AIM SSI", "aim_ssi");
	proto_aim_sst = proto_register_protocol("AIM Server Side Themes", "AIM SST", "aim_sst");
	proto_aim_stats = proto_register_protocol("AIM Statistics", "AIM Stats", "aim_stats");
	proto_aim_translate = proto_register_protocol("AIM Translate", "AIM Translate", "aim_translate");
	proto_aim_userlookup = proto_register_protocol("AIM User Lookup", "AIM User Lookup", "aim_lookup");

	proto_register_field_array(proto_aim, hf, array_length(hf));
	proto_register_field_array(proto_aim_admin, hf_admin, array_length(hf_admin));
	proto_register_field_array(proto_aim_bos, hf_bos, array_length(hf_bos));
	proto_register_field_array(proto_aim_buddylist, hf_buddylist, array_length(hf_buddylist));
	proto_register_field_array(proto_aim_chat, hf_chat, array_length(hf_chat));
	proto_register_field_array(proto_aim_generic, hf_generic, array_length(hf_generic));
	proto_register_field_array(proto_aim_icq, hf_icq, array_length(hf_icq));
	proto_register_field_array(proto_aim_location, hf_location, array_length(hf_location));
	proto_register_field_array(proto_aim_messaging, hf_messaging, array_length(hf_messaging));
	proto_register_field_array(proto_aim_signon, hf_signon, array_length(hf_signon));
	proto_register_field_array(proto_aim_ssi, hf_ssi, array_length(hf_ssi));
	proto_register_field_array(proto_aim_sst, hf_sst, array_length(hf_sst));
	proto_register_field_array(proto_aim_userlookup, hf_userlookup, array_length(hf_userlookup));

	proto_register_subtree_array(ett, array_length(ett));

	expert_aim = expert_register_protocol(proto_aim);
	expert_register_field_array(expert_aim, ei, array_length(ei));

	aim_handle = register_dissector("aim", dissect_aim, proto_aim);

	aim_module = prefs_register_protocol(proto_aim, NULL);


	prefs_register_bool_preference(aim_module, "desegment",
				       "Reassemble AIM messages spanning multiple TCP segments",
				       "Whether the AIM dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &aim_desegment);

	register_shutdown_routine(aim_shutdown);
}

void
proto_reg_handoff_aim(void)
{
	/* TCP ports preference */
	dissector_add_uint_range_with_preference("tcp.port", TCP_PORTS_AIM_DEFAULT, aim_handle);

	ssl_dissector_add(0, aim_handle);
	/* Heuristics disabled by default, it is really weak... */
	heur_dissector_add("tls", dissect_aim_ssl_heur, "AIM over TLS", "aim_tls", proto_aim, HEURISTIC_DISABLE);


	aim_init_family(proto_aim_admin, ett_aim_admin, FAMILY_ADMIN, aim_fnac_family_admin);
	aim_init_family(proto_aim_adverts, ett_aim_adverts, FAMILY_ADVERTS, aim_fnac_family_adverts);
	aim_init_family(proto_aim_bos, ett_aim_bos, FAMILY_BOS, aim_fnac_family_bos);
	aim_init_family(proto_aim_buddylist, ett_aim_buddylist, FAMILY_BUDDYLIST, aim_fnac_family_buddylist);
	aim_init_family(proto_aim_chat, ett_aim_chat, FAMILY_CHAT, aim_fnac_family_chat);
	aim_init_family(proto_aim_chatnav, ett_aim_chatnav, FAMILY_CHAT_NAV, aim_fnac_family_chatnav);
	aim_init_family(proto_aim_directory, ett_aim_directory, FAMILY_DIRECTORY, aim_fnac_family_directory);
	aim_init_family(proto_aim_email, ett_aim_email, FAMILY_EMAIL, aim_fnac_family_email);
	aim_init_family(proto_aim_generic, ett_generic, FAMILY_GENERIC, aim_fnac_family_generic);
	aim_init_family(proto_aim_icq, ett_aim_icq, FAMILY_ICQ, aim_fnac_family_icq);
	aim_init_family(proto_aim_invitation, ett_aim_invitation, FAMILY_INVITATION, aim_fnac_family_invitation);
	aim_init_family(proto_aim_location, ett_aim_location, FAMILY_LOCATION, aim_fnac_family_location);
	aim_init_family(proto_aim_messaging, ett_aim_messaging, FAMILY_MESSAGING, aim_fnac_family_messaging);
	aim_init_family(proto_aim_popup, ett_aim_popup, FAMILY_POPUP, aim_fnac_family_popup);
	aim_init_family(proto_aim_signon, ett_aim_signon, FAMILY_SIGNON, aim_fnac_family_signon);
	aim_init_family(proto_aim_ssi, ett_aim_ssi, FAMILY_SSI, aim_fnac_family_ssi);
	aim_init_family(proto_aim_sst, ett_aim_sst, FAMILY_SST, aim_fnac_family_sst);
	aim_init_family(proto_aim_stats, ett_aim_stats, FAMILY_STATS, aim_fnac_family_stats);
	aim_init_family(proto_aim_translate, ett_aim_translate, FAMILY_TRANSLATE, aim_fnac_family_translate);
	aim_init_family(proto_aim_userlookup, ett_aim_userlookup, FAMILY_USERLOOKUP, aim_fnac_family_userlookup);
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
