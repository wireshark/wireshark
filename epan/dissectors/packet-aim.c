/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2004, Devin Heitmueller <dheitmueller@netilla.com>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "isprint.h"

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-tcp.h"
#include "packet-aim.h"
#include <epan/prefs.h>

#define TCP_PORT_AIM 5190

#define STRIP_TAGS 1

/* channels */
#define CHANNEL_NEW_CONN    0x01
#define CHANNEL_SNAC_DATA   0x02
#define CHANNEL_FLAP_ERR    0x03
#define CHANNEL_CLOSE_CONN  0x04
#define CHANNEL_KEEP_ALIVE  0x05

#define FAMILY_ALL_ERROR_INVALID_HEADER				   0x0001
#define FAMILY_ALL_ERROR_SERVER_RATE_LIMIT_EXCEEDED    0x0002
#define FAMILY_ALL_ERROR_CLIENT_RATE_LIMIT_EXCEEDED    0x0003
#define FAMILY_ALL_ERROR_RECIPIENT_NOT_LOGGED_IN       0x0004
#define FAMILY_ALL_ERROR_REQUESTED_SERVICE_UNAVAILABLE 0x0005
#define FAMILY_ALL_ERROR_REQUESTED_SERVICE_NOT_DEFINED 0x0006
#define FAMILY_ALL_ERROR_OBSOLETE_SNAC				   0x0007
#define FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_SERVER	   0x0008
#define FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_CLIENT	   0x0009
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
    { CHANNEL_NEW_CONN, "New Connection" },
    { CHANNEL_SNAC_DATA, "SNAC Data" },
    { CHANNEL_FLAP_ERR, "FLAP-Level Error" },
    { CHANNEL_CLOSE_CONN, "Close Connection" },
    { CHANNEL_KEEP_ALIVE, "Keep Alive" },
    { 0, NULL }
};

static const value_string aim_snac_errors[] = {
  { FAMILY_ALL_ERROR_INVALID_HEADER, "Invalid SNAC Header" },
  { FAMILY_ALL_ERROR_SERVER_RATE_LIMIT_EXCEEDED, "Server rate limit exceeded" },
  { FAMILY_ALL_ERROR_CLIENT_RATE_LIMIT_EXCEEDED, "Client rate limit exceeded" },
  { FAMILY_ALL_ERROR_RECIPIENT_NOT_LOGGED_IN, "Recipient not logged in" },
  { FAMILY_ALL_ERROR_REQUESTED_SERVICE_UNAVAILABLE, "Requested service unavailable" },
  { FAMILY_ALL_ERROR_REQUESTED_SERVICE_NOT_DEFINED, "Requested service not defined" },
  { FAMILY_ALL_ERROR_OBSOLETE_SNAC, "Obsolete SNAC issued" },
  { FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_SERVER, "Not supported by server" },
  { FAMILY_ALL_ERROR_NOT_SUPPORTED_BY_CLIENT, "Not supported by client" },
  { FAMILY_ALL_ERROR_REFUSED_BY_CLIENT, "Refused by client" },
  { FAMILY_ALL_ERROR_REPLY_TOO_BIG, "Reply too big" },
  { FAMILY_ALL_ERROR_RESPONSES_LOST, "Responses lost" },
  { FAMILY_ALL_ERROR_REQUEST_DENIED, "Request denied" },
  { FAMILY_ALL_ERROR_INCORRECT_SNAC_FORMAT, "Incorrect SNAC format" },
  { FAMILY_ALL_ERROR_INSUFFICIENT_RIGHTS, "Insufficient rights" },
  { FAMILY_ALL_ERROR_RECIPIENT_BLOCKED, "Recipient blocked" },
  { FAMILY_ALL_ERROR_SENDER_TOO_EVIL, "Sender too evil" },
  { FAMILY_ALL_ERROR_RECEIVER_TOO_EVIL, "Receiver too evil" },
  { FAMILY_ALL_ERROR_USER_TEMP_UNAVAILABLE, "User temporarily unavailable" },
  { FAMILY_ALL_ERROR_NO_MATCH, "No match" },
  { FAMILY_ALL_ERROR_LIST_OVERFLOW, "List overflow" },
  { FAMILY_ALL_ERROR_REQUEST_AMBIGUOUS, "Request ambiguous" },
  { FAMILY_ALL_ERROR_SERVER_QUEUE_FULL, "Server queue full" },
  { FAMILY_ALL_ERROR_NOT_WHILE_ON_AOL, "Not while on AOL" },
  { 0, NULL }
};

#define AIM_CLIENT_TLV_SCREEN_NAME				0x0001
#define AIM_CLIENT_TLV_NEW_ROASTED_PASSWORD        			0x0002
#define AIM_CLIENT_TLV_CLIENT_ID_STRING       			0x0003
#define AIM_CLIENT_TLV_ERRORURL                                 0x0004
#define AIM_CLIENT_TLV_BOS_SERVER_STRING       0x0005
#define AIM_CLIENT_TLV_AUTH_COOKIE             0x0006
#define AIM_CLIENT_TLV_ERRORCODE			    0x0008
#define AIM_CLIENT_TLV_DISCONNECT_REASON		0x0009
#define AIM_CLIENT_TLV_RECONNECT_HOST		   0x000a
#define AIM_CLIENT_TLV_URL					   0x000b
#define AIM_CLIENT_TLV_DEBUG_DATA			   0x000c
#define AIM_CLIENT_TLV_FAMILY_ID		       0x000d
#define AIM_CLIENT_TLV_CLIENT_COUNTRY          0x000e
#define AIM_CLIENT_TLV_CLIENT_LANGUAGE         0x000f
#define AIM_CLIENT_TLV_EMAILADDR			    0x0011
#define AIM_CLIENT_TLV_OLD_ROASTED_PASSWORD	0x0012
#define AIM_CLIENT_TLV_REGSTATUS			    0x0013
#define AIM_CLIENT_TLV_CLIENT_DISTRIBUTION_NUM 0x0014
#define AIM_CLIENT_TLV_INVITEMESSAGE			0x0015
#define AIM_CLIENT_TLV_CLIENT_ID               0x0016
#define AIM_CLIENT_TLV_CLIENT_MAJOR_VERSION    0x0017
#define AIM_CLIENT_TLV_CLIENT_MINOR_VERSION    0x0018
#define AIM_CLIENT_TLV_CLIENT_LESSER_VERSION   0x0019
#define AIM_CLIENT_TLV_CLIENT_BUILD_NUMBER     0x001a
#define AIM_CLIENT_TLV_PASSWORD_MD5 			0x0025
#define AIM_CLIENT_TLV_LATESTBETABUILD     	0x0040
#define AIM_CLIENT_TLV_LATESTBETAURL       	0x0041
#define AIM_CLIENT_TLV_LATESTBETAINFO      	0x0042
#define AIM_CLIENT_TLV_LATESTBETANAME      	0x0043
#define AIM_CLIENT_TLV_LATESTRELEASEBUILD  	0x0044
#define AIM_CLIENT_TLV_LATESTRELEASEURL    	0x0045
#define AIM_CLIENT_TLV_LATESTRELEASEINFO   	0x0046
#define AIM_CLIENT_TLV_LATESTRELEASENAME   	0x0047
#define AIM_CLIENT_TLV_BETA_DIGEST_SIG		0x0048
#define AIM_CLIENT_TLV_RELEASE_DIGEST_SIG   0x0049
#define AIM_CLIENT_TLV_CLIENTUSESSI   			0x004a
#define AIM_CLIENT_TLV_CHANGE_PASSWORD_URL		0x0054
#define AIM_CLIENT_TLV_AWAITING_AUTH		0x0066
#define AIM_CLIENT_TLV_MEMBERS				0x00c8
#define AIM_CLIENT_TLV_VISIBILITY_BITS		0x00c9
#define AIM_CLIENT_TLV_PRIVACY				0x00ca
#define AIM_CLIENT_TLV_VISIBLE_CLASS		0x00cb
#define AIM_CLIENT_TLV_VISIBLE_MISC			0x00cc
#define AIM_CLIENT_TLV_ICQ2K_SHORTCUT		0x00cd
#define AIM_CLIENT_TLV_FIRST_LOADED_TIME	0x00d4
#define AIM_CLIENT_TLV_BUDDY_ICON_MD5SUM	0x00d5
#define AIM_CLIENT_TLV_GIVEN_NAME			0x0131
#define AIM_CLIENT_TLV_LOCAL_EMAIL			0x0137
#define AIM_CLIENT_TLV_LOCAL_SMS			0x013a
#define AIM_CLIENT_TLV_LOCAL_COMMENT		0x013c
#define AIM_CLIENT_TLV_LOCAL_PERSONAL_ALERT 0x013d
#define AIM_CLIENT_TLV_LOCAL_PERSONAL_SOUND	0x013e
#define AIM_CLIENT_TLV_FIRST_MESSAGE_SENT	0x0145

const aim_tlv client_tlvs[] = {
  {  AIM_CLIENT_TLV_SCREEN_NAME, "Screen name", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_NEW_ROASTED_PASSWORD, "Roasted password array", dissect_aim_tlv_value_bytes  },
  {  AIM_CLIENT_TLV_OLD_ROASTED_PASSWORD, "Old roasted password array", dissect_aim_tlv_value_bytes  },
  {  AIM_CLIENT_TLV_CLIENT_ID_STRING, "Client id string (name, version)", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_CLIENT_ID, "Client id number", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_CLIENT_MAJOR_VERSION, "Client major version", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_CLIENT_MINOR_VERSION, "Client minor version", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_CLIENT_LESSER_VERSION, "Client lesser version", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_CLIENT_BUILD_NUMBER, "Client build number", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_PASSWORD_MD5, "Password Hash (MD5)", dissect_aim_tlv_value_bytes },
  {  AIM_CLIENT_TLV_CLIENT_DISTRIBUTION_NUM, "Client distribution number", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_CLIENT_LANGUAGE, "Client language", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_CLIENT_COUNTRY, "Client country", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_BOS_SERVER_STRING, "BOS server string", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_AUTH_COOKIE, "Authorization cookie", dissect_aim_tlv_value_bytes },
  {  AIM_CLIENT_TLV_ERRORURL, "Error URL", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_ERRORCODE, "Error Code", dissect_aim_tlv_value_uint16 }, 
  {  AIM_CLIENT_TLV_DISCONNECT_REASON, "Disconnect Reason", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_RECONNECT_HOST, "Reconnect Hostname", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_URL, "URL", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_DEBUG_DATA, "Debug Data", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_EMAILADDR, "Account Email address", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_REGSTATUS, "Registration Status", dissect_aim_tlv_value_uint16 },
  {  AIM_CLIENT_TLV_LATESTBETABUILD, "Latest Beta Build", dissect_aim_tlv_value_uint32 },
  {  AIM_CLIENT_TLV_LATESTBETAURL, "Latest Beta URL", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_LATESTBETAINFO, "Latest Beta Info", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_LATESTBETANAME, "Latest Beta Name", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_LATESTRELEASEBUILD, "Latest Release Build", dissect_aim_tlv_value_uint32 },
  {  AIM_CLIENT_TLV_LATESTRELEASEURL, "Latest Release URL", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_LATESTRELEASEINFO, "Latest Release Info", dissect_aim_tlv_value_string  },
  {  AIM_CLIENT_TLV_LATESTRELEASENAME, "Latest Release Name", dissect_aim_tlv_value_string },
  {  AIM_CLIENT_TLV_BETA_DIGEST_SIG, "Beta Digest Signature (MD5)" , dissect_aim_tlv_value_bytes },
  {  AIM_CLIENT_TLV_RELEASE_DIGEST_SIG, "Release Digest Signature (MD5)", dissect_aim_tlv_value_bytes },
  {  AIM_CLIENT_TLV_CLIENTUSESSI, "Use SSI", dissect_aim_tlv_value_uint8 },
  {  AIM_CLIENT_TLV_FAMILY_ID, "Service (SNAC Family) ID", dissect_aim_tlv_value_uint16 },
  { AIM_CLIENT_TLV_CHANGE_PASSWORD_URL, "Change password url", dissect_aim_tlv_value_string },
  { AIM_CLIENT_TLV_AWAITING_AUTH, "Awaiting Authorization", dissect_aim_tlv_value_bytes },
  { AIM_CLIENT_TLV_MEMBERS, "Members of this Group", dissect_aim_tlv_value_bytes },
  { AIM_CLIENT_TLV_VISIBILITY_BITS, "Bitfield", dissect_aim_tlv_value_bytes },
  { AIM_CLIENT_TLV_PRIVACY, "Privacy Settings" , dissect_aim_tlv_value_uint8 },
  { AIM_CLIENT_TLV_VISIBLE_CLASS, "Visible To Classes", dissect_aim_tlv_value_userclass },
  { AIM_CLIENT_TLV_VISIBLE_MISC, "Allow Others to See Data", dissect_aim_tlv_value_bytes },
  { AIM_CLIENT_TLV_ICQ2K_SHORTCUT, "ICQ2K Shortcut List", dissect_aim_tlv_value_string },
  { AIM_CLIENT_TLV_FIRST_LOADED_TIME, "First Time Buddy Was Added (Unix Timestamp)" , dissect_aim_tlv_value_uint32 },
  { AIM_CLIENT_TLV_BUDDY_ICON_MD5SUM, "MD5SUM of Current Buddy Icon", dissect_aim_tlv_value_bytes },
  { AIM_CLIENT_TLV_GIVEN_NAME, "Locally Specified Buddy Name", dissect_aim_tlv_value_string },
  { AIM_CLIENT_TLV_LOCAL_EMAIL, "Locally Specified Buddy Email", dissect_aim_tlv_value_string },
  { AIM_CLIENT_TLV_LOCAL_SMS, "Locally Specified Buddy SMS", dissect_aim_tlv_value_string },
  { AIM_CLIENT_TLV_LOCAL_COMMENT, "Locally Specified Buddy Comment", dissect_aim_tlv_value_string },
  { AIM_CLIENT_TLV_LOCAL_PERSONAL_ALERT, "Personal Alert for Buddy", dissect_aim_tlv_value_uint16 },
  { AIM_CLIENT_TLV_LOCAL_PERSONAL_SOUND, "Personal Sound for Buddy", dissect_aim_tlv_value_string },
  { AIM_CLIENT_TLV_FIRST_MESSAGE_SENT, " First Time Message Sent to Buddy (Unix Timestamp)", dissect_aim_tlv_value_uint32 },
  { 0, NULL, NULL },
};


static int dissect_aim_tlv_value_userstatus(proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_);
static int dissect_aim_tlv_value_dcinfo(proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_);

#define AIM_ONLINEBUDDY_USERCLASS      0x0001
#define AIM_ONLINEBUDDY_ONSINCE        0x0003
#define AIM_ONLINEBUDDY_IDLETIME       0x0004
#define AIM_ONLINEBUDDY_MEMBERSINCE	   0x0005
#define AIM_ONLINEBUDDY_STATUS         0x0006
#define AIM_ONLINEBUDDY_TIMEUPDATE	   0x0011
#define AIM_ONLINEBUDDY_IPADDR         0x000a
#define AIM_ONLINEBUDDY_DCINFO		   0x000c
#define AIM_ONLINEBUDDY_CAPINFO        0x000d
#define AIM_ONLINEBUDDY_UNKNOWN        0x000e
#define AIM_ONLINEBUDDY_SESSIONLEN     0x000f
#define AIM_ONLINEBUDDY_ICQSESSIONLEN  0x0010
#define AIM_ONLINEBUDDY_AVAILMSG	   0x001d

const aim_tlv onlinebuddy_tlvs[] = {
  { AIM_ONLINEBUDDY_USERCLASS, "User class", dissect_aim_tlv_value_userclass },
  { AIM_ONLINEBUDDY_ONSINCE, "Online since", dissect_aim_tlv_value_uint32 },
  { AIM_ONLINEBUDDY_IDLETIME, "Idle time (sec)", dissect_aim_tlv_value_uint16 },
  { AIM_ONLINEBUDDY_STATUS, "Online status", dissect_aim_tlv_value_userstatus },
  { AIM_ONLINEBUDDY_IPADDR, "User IP Address", dissect_aim_tlv_value_ipv4 },
  { AIM_ONLINEBUDDY_DCINFO, "DC Info", dissect_aim_tlv_value_dcinfo},
  { AIM_ONLINEBUDDY_CAPINFO, "Capability Info", dissect_aim_tlv_value_client_capabilities },
  { AIM_ONLINEBUDDY_MEMBERSINCE, "Member since", dissect_aim_tlv_value_time },
  { AIM_ONLINEBUDDY_UNKNOWN, "Unknown", dissect_aim_tlv_value_uint16 },
  { AIM_ONLINEBUDDY_TIMEUPDATE, "Time update", dissect_aim_tlv_value_bytes },
  { AIM_ONLINEBUDDY_SESSIONLEN, "Session Length (sec)", dissect_aim_tlv_value_uint32 },
  { AIM_ONLINEBUDDY_ICQSESSIONLEN, "ICQ Session Length (sec)", dissect_aim_tlv_value_uint32 },
  { AIM_ONLINEBUDDY_AVAILMSG, "Available Message", dissect_aim_tlv_value_bytes },
  { 0, NULL, NULL }
};

#define DC_DISABLED		0x0000
#define DC_HTTPS		0x0001
#define DC_SOCKS		0x0002
#define DC_NORMAL		0x0003
#define DC_IMPOSSIBLE	0x0004

static const value_string dc_types[] = {
	{ DC_DISABLED, "DC disabled" },
	{ DC_HTTPS, "DC thru firewall or HTTPS proxy" },
	{ DC_SOCKS, "DC thru SOCKS proxy" },
	{ DC_NORMAL, "Regular connection" },
	{ DC_IMPOSSIBLE, "DC not possible " },
	{ 0, NULL },
};

#define PROTO_VERSION_ICQ98		0x0004
#define PROTO_VERSION_ICQ99		0x0006
#define PROTO_VERSION_ICQ2K		0x0007
#define PROTO_VERSION_ICQ2K1	0x0008
#define PROTO_VERSION_ICQLITE	0x0009
#define PROTO_VERSION_ICQ2K3B	0x000A

static const value_string protocol_versions[] = {
	{ PROTO_VERSION_ICQ98, "ICQ '98" },
	{ PROTO_VERSION_ICQ99, "ICQ '99" },
	{ PROTO_VERSION_ICQ2K, "ICQ 2000" },
	{ PROTO_VERSION_ICQ2K1, "ICQ 2001" },
	{ PROTO_VERSION_ICQLITE, "ICQ Lite" },
	{ PROTO_VERSION_ICQ2K3B, "ICQ 2003B" },
	{ 0, NULL },
};

static GList *families = NULL;

#define AIM_MOTD_TLV_MOTD					   0x000B

const aim_tlv motd_tlvs[] = {
  { AIM_MOTD_TLV_MOTD, "Message of the day message", dissect_aim_tlv_value_string },
  { 0, NULL, NULL }
};

#define CLASS_UNCONFIRMED            0x0001
#define CLASS_ADMINISTRATOR          0x0002
#define CLASS_AOL                    0x0004
#define CLASS_COMMERCIAL             0x0008
#define CLASS_FREE                   0x0010
#define CLASS_AWAY                   0x0020
#define CLASS_ICQ                    0x0040
#define CLASS_WIRELESS               0x0080
#define CLASS_UNKNOWN100             0x0100
#define CLASS_UNKNOWN200             0x0200
#define CLASS_UNKNOWN400             0x0400
#define CLASS_UNKNOWN800             0x0800

#define FNAC_FLAG_NEXT_IS_RELATED 	 0x0001
#define FNAC_FLAG_CONTAINS_VERSION	 0x8000

#define FNAC_TLV_FAMILY_VERSION  0x0001

static const aim_tlv fnac_tlvs[] = {
  { FNAC_TLV_FAMILY_VERSION, "SNAC Family Version", dissect_aim_tlv_value_uint16 },
  { 0, NULL, NULL }
};

static int dissect_aim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint get_aim_pdu_len(tvbuff_t *tvb, int offset);
static void dissect_aim_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_aim_newconn(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac(tvbuff_t *tvb, packet_info *pinfo, 
			     int offset, proto_tree *tree, proto_tree *root_tree);
static void dissect_aim_flap_err(tvbuff_t *tvb, packet_info *pinfo, 
				 int offset, proto_tree *tree);
static void dissect_aim_keep_alive(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree);
static void dissect_aim_close_conn(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree);
static void dissect_aim_unknown_channel(tvbuff_t *tvb, packet_info *pinfo, 
					int offset, proto_tree *tree);

static dissector_table_t subdissector_table;

/* Initialize the protocol and registered fields */
static int proto_aim = -1;
static int hf_aim_cmd_start = -1;
static int hf_aim_channel = -1;
static int hf_aim_seqno = -1;
static int hf_aim_data = -1;
static int hf_aim_data_len = -1;
static int hf_aim_signon_challenge_len = -1;
static int hf_aim_signon_challenge = -1;
static int hf_aim_fnac_family = -1;
static int hf_aim_fnac_subtype = -1;
static int hf_aim_fnac_flags = -1;
static int hf_aim_fnac_flag_next_is_related = -1;
static int hf_aim_fnac_flag_contains_version = -1;
static int hf_aim_fnac_id = -1;
static int hf_aim_infotype = -1;
static int hf_aim_buddyname_len = -1;
static int hf_aim_buddyname = -1;
static int hf_aim_userinfo_warninglevel = -1;
static int hf_aim_snac_error = -1;
static int hf_aim_tlvcount = -1;
static int hf_aim_version = -1;
static int hf_aim_userclass_unconfirmed = -1;
static int hf_aim_userclass_administrator = -1;
static int hf_aim_userclass_aol = -1;
static int hf_aim_userclass_commercial = -1;
static int hf_aim_userclass_free = -1;
static int hf_aim_userclass_away = -1;
static int hf_aim_userclass_icq = -1;
static int hf_aim_userclass_wireless = -1;
static int hf_aim_userclass_unknown100 = -1;
static int hf_aim_userclass_unknown200 = -1;
static int hf_aim_userclass_unknown400 = -1;
static int hf_aim_userclass_unknown800 = -1;
static int hf_aim_messageblock_featuresdes = -1;
static int hf_aim_messageblock_featureslen = -1;
static int hf_aim_messageblock_features = -1;
static int hf_aim_messageblock_info = -1;
static int hf_aim_messageblock_len = -1;
static int hf_aim_messageblock_charset = -1;
static int hf_aim_messageblock_charsubset = -1;
static int hf_aim_messageblock_message = -1;

static int hf_aim_dcinfo_ip = -1;
static int hf_aim_dcinfo_tcpport = -1;
static int hf_aim_dcinfo_type = -1;
static int hf_aim_dcinfo_proto_version = -1;
static int hf_aim_dcinfo_auth_cookie = -1;
static int hf_aim_dcinfo_webport = -1;
static int hf_aim_dcinfo_client_future = -1;
static int hf_aim_dcinfo_last_info_update = -1;
static int hf_aim_dcinfo_last_ext_info_update = -1;
static int hf_aim_dcinfo_last_ext_status_update = -1;
static int hf_aim_dcinfo_unknown = -1;

/* Initialize the subtree pointers */
static gint ett_aim          = -1;
static gint ett_aim_dcinfo	 = -1;
static gint ett_aim_buddyname= -1;
static gint ett_aim_fnac     = -1;
static gint ett_aim_fnac_flags = -1;
static gint ett_aim_tlv      = -1;
static gint ett_aim_userclass = -1;
static gint ett_aim_messageblock = -1;
static gint ett_aim_client_capabilities = -1;

/* desegmentation of AIM over TCP */
static gboolean aim_desegment = TRUE;

/* Code to actually dissect the packets */
static int dissect_aim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* check, if this is really an AIM packet, they start with 0x2a */
/* XXX - I've seen some stuff starting with 0x5a followed by 0x2a */

  if(tvb_bytes_exist(tvb, 0, 1) && tvb_get_guint8(tvb, 0) != 0x2a) {
    /* Not an instant messenger packet, just happened to use the same port */
    /* XXX - if desegmentation disabled, this might be a continuation
       packet, not a non-AIM packet */
    return 0;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, aim_desegment, 6, get_aim_pdu_len,
	dissect_aim_pdu);
  return tvb_length(tvb);
}

static guint get_aim_pdu_len(tvbuff_t *tvb, int offset)
{
  guint16 plen;

  /*
   * Get the length of the AIM packet.
   */
  plen = tvb_get_ntohs(tvb, offset + 4);

  /*
   * That length doesn't include the length of the header itself; add that in.
   */
  return plen + 6;
}

static void dissect_aim_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIM");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, "AOL Instant Messenger");

  /* get relevant header information */
  offset += 1;          /* XXX - put the identifier into the tree? */	
  hdr_channel           = tvb_get_guint8(tvb, offset);
  offset += 1;
  hdr_sequence_no       = tvb_get_ntohs(tvb, offset);
  offset += 2;
  hdr_data_field_length = tvb_get_ntohs(tvb, offset);
  offset += 2;

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_aim, tvb, 0, -1, FALSE);
    aim_tree = proto_item_add_subtree(ti, ett_aim);
    proto_tree_add_uint(aim_tree, hf_aim_cmd_start, tvb, 0, 1, '*');
    proto_tree_add_item(aim_tree, hf_aim_channel, tvb, 1, 1, FALSE);
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

}
const aim_subtype *aim_get_subtype( guint16 famnum, guint16 subtype )
{
	GList *gl = families;
	while(gl) {
		aim_family *fam = gl->data;
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

const aim_family *aim_get_family( guint16 famnum ) 
{
	GList *gl = families;
	while(gl) {
		aim_family *fam = gl->data;
		if(fam->family == famnum) return fam;
		gl = gl->next;
	}

	return NULL;
}

int aim_get_buddyname( char *name, tvbuff_t *tvb, int len_offset, int name_offset)
{
  guint8 buddyname_length;

  buddyname_length = tvb_get_guint8(tvb, len_offset);

  if(buddyname_length > MAX_BUDDYNAME_LENGTH ) buddyname_length = MAX_BUDDYNAME_LENGTH;
  tvb_get_nstringz0(tvb, name_offset, buddyname_length + 1, name);

  return buddyname_length;
}


void aim_get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length)
{
  int i,j,c;
  int bracket = FALSE;
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
     j = tvb_get_guint8(tvb, new_offset);
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
     j = tvb_get_guint8(tvb, msg_offset+c);


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
     if( j == '<' ) bracket = TRUE;
     if( j == '>' ) bracket = FALSE;
     if( (isprint(j) ) && (bracket == FALSE) && (j != '>'))
#else
     if( isprint(j) )
#endif
     {
       msg[i] = j;
       i++;
     }
     c++;
  }
}

void aim_init_family(int proto, int ett, guint16 family, const aim_subtype *subtypes) 
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

static void dissect_aim_newconn(tvbuff_t *tvb, packet_info *pinfo, 
				int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_add_fstr(pinfo->cinfo, COL_INFO, "New Connection");

  if (tvb_length_remaining(tvb, offset) > 0) {
	  proto_tree_add_item(tree, hf_aim_version, tvb, offset, 4, FALSE);
	  offset+=4;
	  offset = dissect_aim_tlv_sequence(tvb, pinfo, offset, tree, client_tlvs);
  }

  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}


int dissect_aim_snac_error(tvbuff_t *tvb, packet_info *pinfo, 
			     proto_tree *aim_tree)
{
  const char *name;

  if ((name = match_strval(tvb_get_ntohs(tvb, 0), aim_snac_errors)) != NULL) {
     if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, name);
  }

  proto_tree_add_item (aim_tree, hf_aim_snac_error,
			   tvb, 0, 2, FALSE);
  
  return dissect_aim_tlv_sequence(tvb, pinfo, 2, aim_tree, client_tlvs);
}

int dissect_aim_userinfo(tvbuff_t *tvb, packet_info *pinfo, 
				 int offset, proto_tree *tree) 
{
    offset = dissect_aim_buddyname(tvb, pinfo, offset, tree);

    proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 2, FALSE);
    offset += 2;

    return dissect_aim_tlv_list(tvb, pinfo, offset, tree, onlinebuddy_tlvs);
}

static int dissect_aim_fnac_flags(tvbuff_t *tvb, int offset, int len, proto_item *ti, guint16 flags)
{
	proto_tree *entry = proto_item_add_subtree(ti, ett_aim_fnac_flags);
	proto_tree_add_boolean(entry, hf_aim_fnac_flag_next_is_related, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_fnac_flag_contains_version, tvb, offset, len, flags);
	return offset + len;
}

static void dissect_aim_snac(tvbuff_t *tvb, packet_info *pinfo, 
			     int offset, proto_tree *aim_tree, proto_tree *root_tree)
{
  guint16 family_id;
  guint16 subtype_id;
  guint16 flags;
  guint32 id;
  proto_item *ti1;
  struct aiminfo aiminfo;
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
  
 
  if( aim_tree )
    {
      offset = orig_offset;
      ti1 = proto_tree_add_text(aim_tree, tvb, 6, 10, "FNAC: Family: %s (0x%04x), Subtype: %s (0x%04x)",
			        family?family->name:"Unknown", family_id,
			        (subtype && subtype->name)?subtype->name:"Unknown", subtype_id);
      aim_tree_fnac = proto_item_add_subtree(ti1, ett_aim_fnac);

      proto_tree_add_text (aim_tree_fnac, 
			   tvb, offset, 2, "Family: %s (0x%04x)", family?family->name:"Unknown", family_id);
      offset += 2;

      proto_tree_add_text (aim_tree_fnac, 
			   tvb, offset, 2, "Subtype: %s (0x%04x)", (subtype && subtype->name)?subtype->name:"Unknown", subtype_id);
      offset += 2;

      ti1 = proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_flags, tvb, offset, 
			  2, flags);

	  offset = dissect_aim_fnac_flags(tvb, offset, 2, ti1, flags);

      proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_id, tvb, offset,
			  4, id);
      offset += 4;
    }
  
  if(flags & FNAC_FLAG_CONTAINS_VERSION) {
	guint16 len = tvb_get_ntohs(tvb, offset); 
	int oldoffset;
	offset+=2;
	oldoffset = offset;
	
	while(offset < oldoffset + len) {
	  offset = dissect_aim_tlv(tvb, pinfo, offset, aim_tree, fnac_tlvs);
	}
  }

  subtvb = tvb_new_subset(tvb, offset, -1, -1);
  aiminfo.tcpinfo = pinfo->private_data;
  aiminfo.family = family_id;
  aiminfo.subtype = subtype_id;
  pinfo->private_data = &aiminfo;

  if (check_col(pinfo->cinfo, COL_PROTOCOL) && family) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, family->name);
  }
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
	 if(subtype && family) {
		 col_set_str(pinfo->cinfo, COL_INFO, family->name);
		 col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", subtype->name);
	 } else {
	    col_set_str(pinfo->cinfo, COL_INFO, "SNAC data");
	  
     	if(family) col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", family->name);
	 	else col_append_fstr(pinfo->cinfo, COL_INFO, ", Family: 0x%04x", family_id);

	 	col_append_fstr(pinfo->cinfo, COL_INFO, ", Subtype: 0x%04x", subtype_id);
	 }
  }

  if(aim_tree && family) 
  {
	proto_item *ti = proto_tree_add_item(root_tree, family->proto_id, subtvb, 0, -1, FALSE); 
	family_tree = proto_item_add_subtree(ti, family->ett);
	if(subtype) proto_item_append_text(ti, ", %s", subtype->name);
  }

  if(tvb_length_remaining(tvb, offset) > 0 && subtype && subtype->dissector) {
	  subtype->dissector(subtvb, pinfo, family_tree);	 
  }
}

static void dissect_aim_flap_err(tvbuff_t *tvb, packet_info *pinfo, 
				 int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "FLAP error");
  }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_keep_alive(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Keep Alive");
  }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_close_conn(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Close Connection");
  }	  
  
  offset = dissect_aim_tlv_sequence(tvb, pinfo, offset, tree, client_tlvs);
}

static void dissect_aim_unknown_channel(tvbuff_t *tvb, packet_info *pinfo, 
					int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Channel");
  }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

int dissect_aim_buddyname(tvbuff_t *tvb, packet_info *pinfo _U_, int offset,
                       proto_tree *tree)
{
  guint8 buddyname_length = 0;
  proto_item *ti = NULL;
  proto_tree *buddy_tree = NULL;

  buddyname_length = tvb_get_guint8(tvb, offset);
  offset++;

  if(tree) {
      ti = proto_tree_add_text(tree, tvb, offset-1, 1+buddyname_length,
                               "Buddy: %s",
                               tvb_format_text(tvb, offset, buddyname_length));
      buddy_tree = proto_item_add_subtree(ti, ett_aim_buddyname);
      proto_tree_add_item(buddy_tree, hf_aim_buddyname_len, tvb, offset-1, 1, FALSE);
      proto_tree_add_item(buddy_tree, hf_aim_buddyname, tvb, offset, buddyname_length, FALSE);
  }

   return offset+buddyname_length;
}

typedef struct _aim_client_capability
{
	const char *name;
	e_uuid_t clsid;	
} aim_client_capability;

static const aim_client_capability known_client_caps[] = {
	{ "Send File", 
	  {0x09461343, 0x4c7f, 0x11d1,
	    { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Recv File",
	    { 0x09461348, 0x4c7f, 0x11d1,
		   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},
	
	{ "iChat",
	 {0x09460000, 0x4c7f, 0x11d1, 
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Security",
	 {0x09460001, 0x4c7f, 0x11d1, 
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

	{ "iChatAV info",
	 {0x09460105, 0x4c7f, 0x11d1, 
	   { 0x82, 0x22, 0x44, 0x45, 0x45, 0x53, 0x54, 0x00}}},

	{ "Hiptop",
	 {0x09461323, 0x4c7f, 0x11d1, 
	   { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Voice Chat",
	 {0x09461341, 0x4c7f, 0x11d1, 
		 { 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Direct ICQ Communication",
	 {0x09461344, 0x4c7f, 0x11d1, 
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Direct Instant Messaging",
	 {0x09461345, 0x4c7f, 0x11d1, 
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Buddy Icon",
	 {0x09461346, 0x4c7f, 0x11d1, 
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Add-Ins",
	 {0x09461347, 0x4c7f, 0x11d1,
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

	{ "Unknown 1", 
	 {0x0946f004, 0x4c7f, 0x11d1, 
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Unknown 2", 
	 {0x0946f004, 0x4c7f, 0x11d1, 
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Unknown 3",
	 {0x09460103, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ "Unknown 4",
	 {0x0946f003, 0x4c7f, 0x11d1,
		 {0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}},

	{ NULL, {0x0, 0x0, 0x0, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } } }
};

static const aim_client_capability *aim_find_capability ( e_uuid_t clsid)
{
	int i;

	for(i = 0; known_client_caps[i].name; i++) 
	{
		const aim_client_capability *caps = &(known_client_caps[i]);

		if(memcmp(&(caps->clsid), &clsid, sizeof(e_uuid_t)) == 0)
			return caps;
	}

	return NULL;
}

int dissect_aim_capability(proto_tree *entry, tvbuff_t *tvb, int offset)
{
	const aim_client_capability *caps = NULL;
	e_uuid_t clsid;

	clsid.Data1 = tvb_get_ntohl(tvb, offset);
	clsid.Data2 = tvb_get_ntohs(tvb, offset+4);
	clsid.Data3 = tvb_get_ntohs(tvb, offset+6);
	tvb_memcpy(tvb, clsid.Data4, offset+8, 8);

	caps = aim_find_capability(clsid);

	proto_tree_add_text(entry, tvb, offset, 16, 
		"%s {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", 
		caps?caps->name:"Unknown", clsid.Data1, clsid.Data2, 
		clsid.Data3, clsid.Data4[0], clsid.Data4[1], clsid.Data4[2], 
		clsid.Data4[3], clsid.Data4[4],	clsid.Data4[5], clsid.Data4[6], 
			clsid.Data4[7]
	);

	return offset+16;
}

int dissect_aim_tlv_value_client_capabilities(proto_item *ti _U_, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	proto_tree *entry;

	proto_item_set_text(ti, "Client Capabilities List");

	entry = proto_item_add_subtree(ti, ett_aim_client_capabilities);
	
  	while (tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_capability(entry, tvb, offset);
	}

	return tvb_length(tvb);
}

int dissect_aim_tlv_value_time(proto_item *ti _U_, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	/* FIXME */
	return tvb_length(tvb);
}

int dissect_aim_userclass(tvbuff_t *tvb, int offset, int len, proto_item *ti, guint32 flags)
{
	proto_tree *entry;

	entry = proto_item_add_subtree(ti, ett_aim_userclass);
	proto_tree_add_boolean(entry, hf_aim_userclass_unconfirmed, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_administrator, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_aol, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_commercial, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_free, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_away, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_icq, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_wireless, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_unknown100, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_unknown200, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_unknown400, tvb, offset, len, flags);
	proto_tree_add_boolean(entry, hf_aim_userclass_unknown800, tvb, offset, len, flags);
	return offset+len;
}

int dissect_aim_tlv_value_userclass(proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	guint16 value16 = tvb_get_ntohs(tvb, 0);
	proto_item_set_text(ti, "Value: 0x%04x", value16);
	return dissect_aim_userclass(tvb, 0, 2, ti, value16);
}

static int dissect_aim_tlv_value_userstatus(proto_item *ti _U_, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	/* FIXME */
	return tvb_length(tvb);
}

static int dissect_aim_tlv_value_dcinfo(proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	
	proto_tree *dctree = proto_item_add_subtree(ti, ett_aim_dcinfo);
	
  	proto_tree_add_item(dctree, hf_aim_dcinfo_ip , tvb, offset, 4, FALSE); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_tcpport, tvb, offset, 4, FALSE); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_type, tvb, offset, 1, FALSE); offset+=1;
	proto_tree_add_item(dctree, hf_aim_dcinfo_proto_version, tvb, offset, 2, FALSE); offset+=2;
	proto_tree_add_item(dctree, hf_aim_dcinfo_auth_cookie, tvb, offset, 4, FALSE); offset+=2;
	proto_tree_add_item(dctree, hf_aim_dcinfo_webport, tvb, offset, 4, FALSE); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_client_future, tvb, offset, 4, FALSE); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_last_info_update, tvb, offset, 4, FALSE); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_last_ext_info_update, tvb, offset, 4, FALSE); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_last_ext_status_update, tvb, offset, 4, FALSE); offset+=4;
	proto_tree_add_item(dctree, hf_aim_dcinfo_unknown, tvb, offset, 2, FALSE); offset+=2;

	return offset;
}

int dissect_aim_tlv_value_string (proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
   guint8 *buf;
   gint string_len;

   string_len = tvb_length(tvb);
   buf = tvb_get_ephemeral_string(tvb, 0, string_len);
   proto_item_set_text(ti, "Value: %s", format_text(buf, string_len));
   return string_len;
}

int dissect_aim_tlv_value_bytes (proto_item *ti _U_, guint16 valueid _U_, tvbuff_t *tvb _U_, packet_info *pinfo _U_)
{
   return tvb_length(tvb);
}

int dissect_aim_tlv_value_uint8 (proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_){
  guint8 value8 = tvb_get_guint8(tvb, 0);
  proto_item_set_text(ti, "Value: %d", value8);
  return 1;
}

int dissect_aim_tlv_value_uint16 (proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_){
  guint16 value16 = tvb_get_ntohs(tvb, 0);
  proto_item_set_text(ti, "Value: %d", value16);
  return 2;
}

int dissect_aim_tlv_value_ipv4 (proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_){
  /* FIXME: Somewhat more readable format ? */
  guint32 value32 = tvb_get_ntoh24(tvb, 0);
  proto_item_set_text(ti, "Value: %d", value32);
  return 4;
}

int dissect_aim_tlv_value_uint32 (proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_){
  guint32 value32 = tvb_get_ntoh24(tvb, 0);
  proto_item_set_text(ti, "Value: %d", value32);
  return 4;
}

int dissect_aim_tlv_value_messageblock (proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_){
  proto_tree *entry;
  guint8 *buf;
  guint16 featurelen;
  guint16 blocklen;
  int offset=0;

  /* Setup a new subtree */
  entry = proto_item_add_subtree(ti, ett_aim_messageblock);

  /* Features descriptor */
  proto_tree_add_item(entry, hf_aim_messageblock_featuresdes, tvb, offset, 2,
		      FALSE);
  offset += 2;

  /* Features Length */
  featurelen = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(entry, hf_aim_messageblock_featureslen, tvb, offset, 2,
		      FALSE);
  offset += 2;

  /* Features (should be expanded further @@@@@@@ ) */
  proto_tree_add_item(entry, hf_aim_messageblock_features, tvb, offset, 
		      featurelen, FALSE);
  offset += featurelen;

  /* There can be multiple messages in this message block */
  while (tvb_length_remaining(tvb, offset) > 0) {
    /* Info field */
    proto_tree_add_item(entry, hf_aim_messageblock_info, tvb, offset, 2,
			FALSE);
    offset += 2;
    
    /* Block length (includes charset and charsubset) */
    blocklen = tvb_get_ntohs(tvb, offset);
    if (blocklen <= 4) {
      proto_tree_add_text(entry, tvb, offset, 2, "Invalid block length: %d",
        blocklen);
      break;
    }
    proto_tree_add_item(entry, hf_aim_messageblock_len, tvb, offset, 2,
			FALSE);
    offset += 2;
    
    /* Character set */
    proto_tree_add_item(entry, hf_aim_messageblock_charset, tvb, offset, 2,
			FALSE);
    offset += 2;
    
    /* Character subset */
    proto_tree_add_item(entry, hf_aim_messageblock_charsubset, tvb, offset, 2,
			FALSE);
    offset += 2;

    /* The actual message */
    buf = tvb_get_ephemeral_string(tvb, offset, blocklen - 4 );
    proto_item_set_text(ti, "Message: %s",
                        format_text(buf, blocklen - 4));
    proto_tree_add_item(entry, hf_aim_messageblock_message, tvb, offset, 
			blocklen-4,
			FALSE);
    offset += tvb_length_remaining(tvb, offset);
  }

  return offset;
}

/* Dissect a TLV value */
int dissect_aim_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, 
			   int offset, proto_tree *tree, const aim_tlv *tlv)
{
  guint16 valueid;
  guint16 length;
  int i = 0;
  const aim_tlv *tmp;
  const char *desc;
  proto_item *ti1;
  proto_tree *tlv_tree;
  int orig_offset;

  /* Record the starting offset so we can reuse it at the second pass */
  orig_offset = offset;

  /* Get the value ID */
  valueid = tvb_get_ntohs(tvb, offset);
  offset += 2;

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

  length = tvb_get_ntohs(tvb, offset);
  offset += 2;
  offset += length;

  if (tree) {
    offset = orig_offset;

    if (tmp[i].desc != NULL)
      desc = tmp[i].desc;
    else
      desc = "Unknown";
    
    ti1 = proto_tree_add_text(tree, tvb, offset, length + 4, "TLV: %s", desc);

    tlv_tree = proto_item_add_subtree(ti1, ett_aim_tlv);

    proto_tree_add_text(tlv_tree, tvb, offset, 2,
			"Value ID: %s (0x%04x)", desc, valueid);
    offset += 2;
    
    proto_tree_add_text(tlv_tree, tvb, offset, 2,
			"Length: %d", length);
    offset += 2;

    ti1 = proto_tree_add_text(tlv_tree, tvb, offset, length,
			      "Value");
	
    if (tmp[i].dissector) {
      tmp[i].dissector(ti1, valueid, tvb_new_subset(tvb, offset, length, length), pinfo);
    } 

    offset += length;
  }

  /* Return the new length */
  return offset;
}

int dissect_aim_tlv_sequence(tvbuff_t *tvb, packet_info *pinfo, 
							 int offset, proto_tree *tree, const aim_tlv *tlv_table)
{
	while (tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, tlv_table);
	}
	return offset;
}

int dissect_aim_tlv_list(tvbuff_t *tvb, packet_info *pinfo, 
			   int offset, proto_tree *tree, const aim_tlv *tlv_table)
{
    guint16 i, tlv_count = tvb_get_ntohs(tvb, offset);

    proto_tree_add_item(tree, hf_aim_tlvcount, tvb, offset, 2, FALSE);
    offset += 2;

    for(i = 0; i < tlv_count; i++) {
      offset = dissect_aim_tlv(tvb, pinfo, offset, tree, tlv_table);
    }
    return offset;
}

/* Register the protocol with Ethereal */
void
proto_register_aim(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_aim_cmd_start,
      { "Command Start", "aim.cmd_start", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_channel,
      { "Channel ID", "aim.channel", FT_UINT8, BASE_HEX, VALS(aim_flap_channels), 0x0, "", HFILL }
    },
    { &hf_aim_seqno,
      { "Sequence Number", "aim.seqno", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
	{ &hf_aim_version,
	  { "Protocol Version", "aim.version", FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_data_len,
      { "Data Field Length", "aim.datalen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_data,
      { "Data", "aim.data", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_signon_challenge_len,
      { "Signon challenge length", "aim.signon.challengelen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_signon_challenge,
      { "Signon challenge", "aim.signon.challenge", FT_STRING, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_family,
      { "FNAC Family ID", "aim.fnac.family", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_flags,
      { "FNAC Flags", "aim.fnac.flags", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_id,
      { "FNAC ID", "aim.fnac.id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_infotype,
      { "Infotype", "aim.infotype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_buddyname_len,
      { "Buddyname len", "aim.buddynamelen", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_buddyname,
      { "Buddy Name", "aim.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_tlvcount,
      { "TLV Count", "aim.tlvcount", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
	{ &hf_aim_snac_error,
	  { "SNAC Error", "aim.snac.error", FT_UINT16,
		  BASE_HEX, VALS(aim_snac_errors), 0x0, "", HFILL },
	},
	{ &hf_aim_userclass_unconfirmed,
		{ "AOL Unconfirmed user flag", "aim.userclass.unconfirmed", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNCONFIRMED, "", HFILL },
	},
	{ &hf_aim_userclass_administrator,
		{ "AOL Administrator flag", "aim.userclass.administrator", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_ADMINISTRATOR, "", HFILL },
	},
	{ &hf_aim_userclass_aol,
		{ "AOL Staff User Flag", "aim.userclass.staff", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_AOL, "", HFILL },
	},
	{ &hf_aim_userclass_commercial,
		{ "AOL commercial account flag", "aim.userclass.commercial", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_COMMERCIAL, "", HFILL },
	},
	{ &hf_aim_userclass_free,
		{ "ICQ non-commercial account flag", "aim.userclass.noncommercial", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_FREE, "", HFILL },
	},
	{ &hf_aim_userclass_away,
		{ "AOL away status flag", "aim.userclass.away", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_AWAY, "", HFILL },
	},
	{ &hf_aim_userclass_icq,
		{ "ICQ user sign", "aim.userclass.icq", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_ICQ, "", HFILL },
	},
	{ &hf_aim_userclass_wireless,
		{ "AOL wireless user", "aim.userclass.wireless", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_WIRELESS, "", HFILL },
	},
	{ &hf_aim_userclass_unknown100,
		{ "Unknown bit", "aim.userclass.unknown100", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN100, "", HFILL },
	},
	{ &hf_aim_userclass_unknown200,
		{ "Unknown bit", "aim.userclass.unknown200", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN200, "", HFILL },
	},
	{ &hf_aim_userclass_unknown400,
		{ "Unknown bit", "aim.userclass.unknown400", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN400, "", HFILL },
	},
	{ &hf_aim_userclass_unknown800,
		{ "Unknown bit", "aim.userclass.unknown800", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN800, "", HFILL },
	},
	{ &hf_aim_fnac_flag_next_is_related,
		{ "Followed By SNAC with related information", "aim.fnac.flags.next_is_related", FT_BOOLEAN, 16, TFS(&flags_set_truth), FNAC_FLAG_NEXT_IS_RELATED, "", HFILL },
	},
	{ &hf_aim_fnac_flag_contains_version,
		{ "Contains Version of Family this SNAC is in", "aim.fnac.flags.contains_version", FT_BOOLEAN, 16, TFS(&flags_set_truth), FNAC_FLAG_CONTAINS_VERSION, "", HFILL },
	},
	{ &hf_aim_userinfo_warninglevel,
		{ "Warning Level", "aim.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_featuresdes,
		{ "Features", "aim.messageblock.featuresdes", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_featureslen,
		{ "Features Length", "aim.messageblock.featureslen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_features,
		{ "Features", "aim.messageblock.features", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_info,
		{ "Block info", "aim.messageblock.info", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_len,
		{ "Block length", "aim.messageblock.length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_charset,
		{ "Block Character set", "aim.messageblock.charset", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_charsubset,
		{ "Block Character subset", "aim.messageblock.charsubset", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	},
    { &hf_aim_messageblock_message,
		{ "Message", "aim.messageblock.message", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_ip,
		{ "Internal IP address", "aim.dcinfo.addr", FT_IPv4, BASE_NONE, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_tcpport,
		{ "TCP Port", "aim.dcinfo.tcpport", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_type,
		{ "Type", "aim.dcinfo.type", FT_UINT8, BASE_HEX, VALS(dc_types), 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_proto_version,
		{ "Protocol Version", "aim.dcinfo.proto_version", FT_UINT16, BASE_DEC, VALS(protocol_versions), 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_auth_cookie,
		{ "Authorization Cookie", "aim.dcinfo.auth_cookie", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_webport,
		{ "Web Front Port", "aim.dcinfo.webport", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_client_future,
		{ "Client Futures", "aim.dcinfo.client_futures", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_last_info_update,
		{ "Last Info Update", "aim.dcinfo.last_info_update", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_last_ext_info_update,
		{ "Last Extended Info Update", "aim.dcinfo.last_ext_info_update", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_last_ext_status_update,
		{ "Last Extended Status Update", "aim.dcinfo.last_ext_status_update", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL },
	},
	{ &hf_aim_dcinfo_unknown,
		{ "Unknown", "aim.dcinfo.unknown", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
	},

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
	  &ett_aim,
	  &ett_aim_dcinfo,
	  &ett_aim_fnac,
	  &ett_aim_fnac_flags,
	  &ett_aim_tlv,
	  &ett_aim_buddyname,
	  &ett_aim_userclass,
	  &ett_aim_messageblock,
	  &ett_aim_client_capabilities
  };
  module_t *aim_module;

  /* Register the protocol name and description */
  proto_aim = proto_register_protocol("AOL Instant Messenger", "AIM", "aim");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  aim_module = prefs_register_protocol(proto_aim, NULL);
  prefs_register_bool_preference(aim_module, "desegment",
    "Reassemble AIM messages spanning multiple TCP segments",
    "Whether the AIM dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &aim_desegment);

  subdissector_table = register_dissector_table("aim.family", 
		"Family ID", FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_aim(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim, proto_aim);
  dissector_add("tcp.port", TCP_PORT_AIM, aim_handle);
}
