/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-aim.c,v 1.28 2003/05/11 02:40:36 guy Exp $
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

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-tcp.h"
#include "prefs.h"

#define TCP_PORT_AIM 5190
#define MAX_BUDDYNAME_LENGTH 30

#define STRIP_TAGS 1

typedef struct _aim_tlv {
  guint16 valueid;
  char *desc;
  int datatype;
} aim_tlv;

/* channels */
#define CHANNEL_NEW_CONN    0x01
#define CHANNEL_SNAC_DATA   0x02
#define CHANNEL_FLAP_ERR    0x03
#define CHANNEL_CLOSE_CONN  0x04

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
#define FAMILY_SSI        0x0013
#define FAMILY_ICQ        0x0015
#define FAMILY_SIGNON     0x0017
#define FAMILY_OFT        0xfffe

/* Family Signon */
#define FAMILY_SIGNON_LOGON          0x0002
#define FAMILY_SIGNON_LOGON_REPLY    0x0003
#define FAMILY_SIGNON_SIGNON         0x0006
#define FAMILY_SIGNON_SIGNON_REPLY   0x0007

/* Family Generic */
#define FAMILY_GENERIC_ERROR          0x0001
#define FAMILY_GENERIC_CLIENTREADY    0x0002
#define FAMILY_GENERIC_SERVERREADY    0x0003
#define FAMILY_GENERIC_SERVICEREQ     0x0004
#define FAMILY_GENERIC_REDIRECT       0x0005
#define FAMILY_GENERIC_RATEINFOREQ    0x0006
#define FAMILY_GENERIC_RATEINFO       0x0007
#define FAMILY_GENERIC_RATEINFOACK    0x0008
#define FAMILY_GENERIC_UNKNOWNx09     0x0009
#define FAMILY_GENERIC_RATECHANGE     0x000a
#define FAMILY_GENERIC_SERVERPAUSE    0x000b
#define FAMILY_GENERIC_SERVERRESUME   0x000d
#define FAMILY_GENERIC_REQSELFINFO    0x000e
#define FAMILY_GENERIC_SELFINFO       0x000f
#define FAMILY_GENERIC_EVIL           0x0010
#define FAMILY_GENERIC_SETIDLE        0x0011
#define FAMILY_GENERIC_MIGRATIONREQ   0x0012
#define FAMILY_GENERIC_MOTD           0x0013
#define FAMILY_GENERIC_SETPRIVFLAGS   0x0014
#define FAMILY_GENERIC_WELLKNOWNURL   0x0015
#define FAMILY_GENERIC_NOP            0x0016
#define FAMILY_GENERIC_DEFAULT        0xffff

/* Family Location Services */
#define FAMILY_LOCATION_ERROR         0x0001
#define FAMILY_LOCATION_REQRIGHTS     0x0002
#define FAMILY_LOCATION_RIGHTSINFO    0x0003
#define FAMILY_LOCATION_SETUSERINFO   0x0004
#define FAMILY_LOCATION_REQUSERINFO   0x0005
#define FAMILY_LOCATION_USERINFO      0x0006
#define FAMILY_LOCATION_WATCHERSUBREQ 0x0007
#define FAMILY_LOCATION_WATCHERNOT    0x0008
#define FAMILY_LOCATION_DEFAULT       0xffff

/* Family Buddy List */
#define FAMILY_BUDDYLIST_ERROR        0x0001
#define FAMILY_BUDDYLIST_REQRIGHTS    0x0002
#define FAMILY_BUDDYLIST_RIGHTSINFO   0x0003
#define FAMILY_BUDDYLIST_ADDBUDDY     0x0004
#define FAMILY_BUDDYLIST_REMBUDDY     0x0005
#define FAMILY_BUDDYLIST_REJECT       0x000a
#define FAMILY_BUDDYLIST_ONCOMING     0x000b
#define FAMILY_BUDDYLIST_OFFGOING     0x000c
#define FAMILY_BUDDYLIST_DEFAULT      0xffff

/* Family Messaging Service */
#define FAMILY_MESSAGING_ERROR          0x0001
#define FAMILY_MESSAGING_PARAMINFO      0x0005
#define FAMILY_MESSAGING_OUTGOING       0x0006
#define FAMILY_MESSAGING_INCOMING       0x0007
#define FAMILY_MESSAGING_EVIL           0x0009
#define FAMILY_MESSAGING_MISSEDCALL     0x000a
#define FAMILY_MESSAGING_CLIENTAUTORESP 0x000b
#define FAMILY_MESSAGING_ACK            0x000c
#define FAMILY_MESSAGING_DEFAULT        0xffff

/* Family Advertising */
#define FAMILY_ADVERTS_ERROR          0x0001
#define FAMILY_ADVERTS_REQUEST        0x0002
#define FAMILY_ADVERTS_DATA           0x0003
#define FAMILY_ADVERTS_DEFAULT        0xffff

/* Family Invitation */
#define FAMILY_INVITATION_ERROR       0x0001
#define FAMILY_INVITATION_DEFAULT     0xffff

/* Family Admin */
#define FAMILY_ADMIN_ERROR            0x0001
#define FAMILY_ADMIN_INFOCHANGEREPLY  0x0005
#define FAMILY_ADMIN_DEFAULT          0xffff

/* Family Popup */
#define FAMILY_POPUP_ERROR            0x0001
#define FAMILY_POPUP_DEFAULT          0xffff

/* Family BOS (Misc) */
#define FAMILY_BOS_ERROR              0x0001
#define FAMILY_BOS_RIGHTSQUERY        0x0002
#define FAMILY_BOS_RIGHTS             0x0003
#define FAMILY_BOS_DEFAULT            0xffff

/* Family User Lookup */
#define FAMILY_USERLOOKUP_ERROR        0x0001
#define FAMILY_USERLOOKUP_SEARCHEMAIL  0x0002
#define FAMILY_USERLOOKUP_SEARCHRESULT 0x0003
#define FAMILY_USERLOOKUP_DEFAULT      0xffff

/* Family User Stats */
#define FAMILY_STATS_ERROR             0x0001
#define FAMILY_STATS_SETREPORTINTERVAL 0x0002
#define FAMILY_STATS_REPORTACK         0x0004
#define FAMILY_STATS_DEFAULT           0xffff

/* Family Translation */
#define FAMILY_TRANSLATE_ERROR        0x0001
#define FAMILY_TRANSLATE_DEFAULT      0xffff

/* Family Chat Navigation */
#define FAMILY_CHATNAV_ERROR          0x0001
#define FAMILY_CHATNAV_CREATE         0x0008
#define FAMILY_CHATNAV_INFO           0x0009
#define FAMILY_CHATNAV_DEFAULT        0xffff

/* Family Chat */
#define FAMILY_CHAT_ERROR             0x0001
#define FAMILY_CHAT_ROOMINFOUPDATE    0x0002
#define FAMILY_CHAT_USERJOIN          0x0003
#define FAMILY_CHAT_USERLEAVE         0x0004
#define FAMILY_CHAT_OUTGOINGMSG       0x0005
#define FAMILY_CHAT_INCOMINGMSG       0x0006
#define FAMILY_CHAT_DEFAULT           0xffff

/* Family Server-Stored Buddy Lists */
#define FAMILY_SSI_ERROR              0x0001
#define FAMILY_SSI_REQRIGHTS          0x0002
#define FAMILY_SSI_RIGHTSINFO         0x0003
#define FAMILY_SSI_REQLIST            0x0005
#define FAMILY_SSI_LIST               0x0006
#define FAMILY_SSI_ACTIVATE           0x0007
#define FAMILY_SSI_ADD                0x0008
#define FAMILY_SSI_MOD                0x0009
#define FAMILY_SSI_DEL                0x000a
#define FAMILY_SSI_SRVACK             0x000e
#define FAMILY_SSI_NOLIST             0x000f
#define FAMILY_SSI_EDITSTART          0x0011
#define FAMILY_SSI_EDITSTOP           0x0012

/* Family ICQ */
#define FAMILY_ICQ_ERROR              0x0001
#define FAMILY_ICQ_LOGINREQUEST       0x0002
#define FAMILY_ICQ_LOGINRESPONSE      0x0003
#define FAMILY_ICQ_AUTHREQUEST        0x0006
#define FAMILY_ICQ_AUTHRESPONSE       0x0007

static const value_string aim_fnac_family_ids[] = {
  { FAMILY_GENERIC, "Generic" }, 
  { FAMILY_LOCATION, "Location" },
  { FAMILY_BUDDYLIST, "Buddy List" },
  { FAMILY_MESSAGING, "Messaging" },
  { FAMILY_ADVERTS, "Advertisement" },
  { FAMILY_INVITATION, "Invitation" },
  { FAMILY_ADMIN, "Admin" },
  { FAMILY_POPUP, "Popup" },
  { FAMILY_BOS, "Bos" },
  { FAMILY_USERLOOKUP, "User Lookup" },
  { FAMILY_STATS, "Stats" },
  { FAMILY_TRANSLATE, "Translate" },
  { FAMILY_CHAT_NAV, "Chat Nav" },
  { FAMILY_CHAT, "Chat" },
  { FAMILY_SSI, "Server Stored Info" },
  { FAMILY_ICQ, "ICQ" },
  { FAMILY_SIGNON, "Sign-on" },
  { FAMILY_OFT, "OFT/Rvous" },
  { 0, NULL }
};

static const value_string aim_fnac_family_signon[] = {
  { FAMILY_SIGNON_LOGON, "Logon" },
  { FAMILY_SIGNON_LOGON_REPLY, "Logon Reply" },
  { FAMILY_SIGNON_SIGNON, "Sign-on" },
  { FAMILY_SIGNON_SIGNON_REPLY, "Sign-on Reply" },
  { 0, NULL }
};

static const value_string aim_fnac_family_generic[] = {
  { FAMILY_GENERIC_ERROR, "Error" },
  { FAMILY_GENERIC_CLIENTREADY , "Client Ready" },
  { FAMILY_GENERIC_SERVERREADY, "Server Ready" },
  { FAMILY_GENERIC_SERVICEREQ, "Service Req" },
  { FAMILY_GENERIC_REDIRECT, "Redirect" },
  { FAMILY_GENERIC_RATEINFOREQ, "Rate Info Req" },
  { FAMILY_GENERIC_RATEINFO, "Rate Info" },
  { FAMILY_GENERIC_RATEINFOACK, "Rate Info Ack" },
  { FAMILY_GENERIC_UNKNOWNx09, "Unknown" },
  { FAMILY_GENERIC_RATECHANGE, "Rate Change" },
  { FAMILY_GENERIC_SERVERPAUSE, "Server Pause" },
  { FAMILY_GENERIC_SERVERRESUME, "Server Resume" },
  { FAMILY_GENERIC_REQSELFINFO, "Self Info Req" },
  { FAMILY_GENERIC_SELFINFO, "Self Info" },
  { FAMILY_GENERIC_EVIL, "Evil" },
  { FAMILY_GENERIC_SETIDLE, "Set Idle" },
  { FAMILY_GENERIC_MIGRATIONREQ, "Migration Req" },
  { FAMILY_GENERIC_MOTD, "MOTD" },
  { FAMILY_GENERIC_SETPRIVFLAGS, "Set Privilege Flags" },
  { FAMILY_GENERIC_WELLKNOWNURL, "Well Known URL" },
  { FAMILY_GENERIC_NOP, "noop" },
  { FAMILY_GENERIC_DEFAULT, "Generic Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_location[] = {
  { FAMILY_LOCATION_ERROR, "Error" },
  { FAMILY_LOCATION_REQRIGHTS, "Request Rights" },
  { FAMILY_LOCATION_RIGHTSINFO, "Rights Info" },
  { FAMILY_LOCATION_SETUSERINFO, "Set User Info" },
  { FAMILY_LOCATION_REQUSERINFO, "Request User Info" },
  { FAMILY_LOCATION_USERINFO, "User Info" },
  { FAMILY_LOCATION_WATCHERSUBREQ, "Watcher Subrequest" },
  { FAMILY_LOCATION_WATCHERNOT, "Watcher Notification" },
  { FAMILY_LOCATION_DEFAULT, "Location Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_buddylist[] = {
  { FAMILY_BUDDYLIST_ERROR, "Error" },
  { FAMILY_BUDDYLIST_REQRIGHTS, "Request Rights" },
  { FAMILY_BUDDYLIST_RIGHTSINFO, "Rights Info" },
  { FAMILY_BUDDYLIST_ADDBUDDY, "Add Buddy" },
  { FAMILY_BUDDYLIST_REMBUDDY, "Remove Buddy" },
  { FAMILY_BUDDYLIST_REJECT, "Reject Buddy" }, 
  { FAMILY_BUDDYLIST_ONCOMING, "Oncoming Buddy" },
  { FAMILY_BUDDYLIST_OFFGOING, "Offgoing Buddy" },
  { FAMILY_BUDDYLIST_DEFAULT, "Buddy Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_messaging[] = {
  { FAMILY_MESSAGING_ERROR, "Error" },
  { FAMILY_MESSAGING_PARAMINFO, "Parameter Info" },
  { FAMILY_MESSAGING_INCOMING, "Incoming" },
  { FAMILY_MESSAGING_EVIL, "Evil" },
  { FAMILY_MESSAGING_MISSEDCALL, "Missed Call" },
  { FAMILY_MESSAGING_CLIENTAUTORESP, "Client Auto Response" },
  { FAMILY_MESSAGING_ACK, "Acknowledge" },
  { FAMILY_MESSAGING_DEFAULT, "Messaging Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_adverts[] = {
  { FAMILY_ADVERTS_ERROR, "Error" },
  { FAMILY_ADVERTS_REQUEST, "Request" },
  { FAMILY_ADVERTS_DATA, "Data (GIF)" },
  { FAMILY_ADVERTS_DEFAULT, "Adverts Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_invitation[] = {
  { FAMILY_INVITATION_ERROR, "Error" },
  { FAMILY_INVITATION_DEFAULT, "Invitation Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_admin[] = {
  { FAMILY_ADMIN_ERROR, "Error" },
  { FAMILY_ADMIN_INFOCHANGEREPLY, "Infochange reply" },
  { FAMILY_ADMIN_DEFAULT, "Adminstrative Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_popup[] = {
  { FAMILY_POPUP_ERROR, "Error" },
  { FAMILY_POPUP_DEFAULT, "Popup Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_bos[] = {
  { FAMILY_BOS_ERROR, "Error" },
  { FAMILY_BOS_RIGHTSQUERY, "Rights Query" },
  { FAMILY_BOS_RIGHTS, "Rights" },
  { FAMILY_BOS_DEFAULT, "BOS Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_userlookup[] = {
  { FAMILY_USERLOOKUP_ERROR, "Error" },
  { FAMILY_USERLOOKUP_DEFAULT, "Userlookup Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_stats[] = {
  { FAMILY_STATS_ERROR, "Error" },
  { FAMILY_STATS_SETREPORTINTERVAL, "Set Report Interval" },
  { FAMILY_STATS_REPORTACK, "Report Ack" },
  { FAMILY_STATS_DEFAULT, "Stats Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_translate[] = {
  { FAMILY_TRANSLATE_ERROR, "Error" },
  { FAMILY_TRANSLATE_DEFAULT, "Translate Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_chatnav[] = {
  { FAMILY_CHATNAV_ERROR, "Error" },
  { FAMILY_CHATNAV_CREATE, "Create" },
  { FAMILY_CHATNAV_INFO, "Info" },
  { FAMILY_CHATNAV_DEFAULT, "ChatNav Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_chat[] = {
  { FAMILY_CHAT_ERROR, "Error" },
  { FAMILY_CHAT_USERJOIN, "User Join" },
  { FAMILY_CHAT_USERLEAVE, "User Leave" },
  { FAMILY_CHAT_OUTGOINGMSG, "Outgoing Message" },
  { FAMILY_CHAT_INCOMINGMSG, "Incoming Message" },
  { FAMILY_CHAT_DEFAULT, "Chat Default" },
  { 0, NULL }
};

static const value_string aim_fnac_family_ssi[] = {
  { FAMILY_SSI_ERROR, "Error" },
  { FAMILY_SSI_REQRIGHTS, "Request Rights" },
  { FAMILY_SSI_RIGHTSINFO, "Rights Info" },
  { FAMILY_SSI_REQLIST, "Request List" },
  { FAMILY_SSI_LIST, "List" },
  { FAMILY_SSI_ACTIVATE, "Activate" },
  { FAMILY_SSI_ADD, "Add Buddy" },
  { FAMILY_SSI_MOD, "Modify Buddy" },
  { FAMILY_SSI_DEL, "Delete Buddy" },
  { FAMILY_SSI_SRVACK, "Server Ack" },
  { FAMILY_SSI_NOLIST, "No List" },
  { FAMILY_SSI_EDITSTART, "Edit Start" },
  { FAMILY_SSI_EDITSTOP, "Edit Stop" },
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
  { FAMILY_SSI_TYPE_BUDDY, "Buddy" },
  { FAMILY_SSI_TYPE_GROUP, "Group" },
  { FAMILY_SSI_TYPE_PERMIT, "Permit" },
  { FAMILY_SSI_TYPE_DENY, "Deny" },
  { FAMILY_SSI_TYPE_PDINFO, "PDINFO" },
  { FAMILY_SSI_TYPE_PRESENCEPREFS, "Presence Preferences" },
  { FAMILY_SSI_TYPE_ICONINFO, "Icon Info" },
  { 0, NULL }
};

static const value_string aim_fnac_family_icq[] = {
  { FAMILY_ICQ_ERROR, "Error" },
  { FAMILY_ICQ_LOGINREQUEST, "Login Request" },
  { FAMILY_ICQ_LOGINRESPONSE, "Login Response" },
  { FAMILY_ICQ_AUTHREQUEST, "Auth Request" },
  { FAMILY_ICQ_AUTHRESPONSE, "Auth Response" },
  { 0, NULL }
};

#define SIGNON_SCREENNAME     0x0001
#define SIGNON_PASSWORD       0x0025
#define SIGNON_CLIENTSTRING   0x0003
#define SIGNON_CLIENTMAJOR    0x0017
#define SIGNON_CLIENTMINOR    0x0018
#define SIGNON_CLIENTPOINT    0x0019
#define SIGNON_CLIENTBUILD    0x001a
#define SIGNON_CLIENTCOUNTRY  0x000e
#define SIGNON_CLIENTLANGUAGE 0x000f
#define SIGNON_CLIENTUSESSI   0x004a

static const aim_tlv aim_signon_signon_tlv[] = {
  { SIGNON_SCREENNAME, "Screen Name", FT_STRING },
  { SIGNON_PASSWORD, "Signon Challenge Response", FT_BYTES },
  { SIGNON_CLIENTSTRING, "Login Request", FT_STRING },
  { SIGNON_CLIENTMAJOR, "Client Major Version", FT_UINT16 },
  { SIGNON_CLIENTMINOR, "Client Minor Version", FT_UINT16 },
  { SIGNON_CLIENTPOINT, "Client Point", FT_UINT16 },
  { SIGNON_CLIENTBUILD, "Client Build", FT_UINT16 },
  { SIGNON_CLIENTCOUNTRY, "Client Country", FT_STRING },
  { SIGNON_CLIENTLANGUAGE, "Client Language", FT_STRING },
  { SIGNON_CLIENTUSESSI, "Use SSI", FT_UINT8 },
  { 0, "Unknown", 0 }
};

#define SIGNON_LOGON_REPLY_SCREENNAME          0x0001
#define SIGNON_LOGON_REPLY_ERRORURL            0x0004
#define SIGNON_LOGON_REPLY_BOSADDR             0x0005
#define SIGNON_LOGON_REPLY_AUTHCOOKIE          0x0006
#define SIGNON_LOGON_REPLY_ERRORCODE           0x0008
#define SIGNON_LOGON_REPLY_EMAILADDR           0x0011
#define SIGNON_LOGON_REPLY_REGSTATUS           0x0013
#define SIGNON_LOGON_REPLY_LATESTBETABUILD     0x0040
#define SIGNON_LOGON_REPLY_LATESTBETAURL       0x0041
#define SIGNON_LOGON_REPLY_LATESTBETAINFO      0x0042
#define SIGNON_LOGON_REPLY_LATESTBETANAME      0x0043
#define SIGNON_LOGON_REPLY_LATESTRELEASEBUILD  0x0044
#define SIGNON_LOGON_REPLY_LATESTRELEASEURL    0x0045
#define SIGNON_LOGON_REPLY_LATESTRELEASEINFO   0x0046
#define SIGNON_LOGON_REPLY_LATESTRELEASENAME   0x0047

static const aim_tlv aim_signon_logon_reply_tlv[] = {
  { SIGNON_LOGON_REPLY_SCREENNAME, "Screen Name", FT_STRING },
  { SIGNON_LOGON_REPLY_ERRORURL, "Error URL", FT_STRING },
  { SIGNON_LOGON_REPLY_BOSADDR, "BOS Server Address", FT_STRING },
  { SIGNON_LOGON_REPLY_AUTHCOOKIE, "Authorization Cookie", FT_BYTES },
  { SIGNON_LOGON_REPLY_ERRORCODE, "Error Code", FT_UINT16 },
  { SIGNON_LOGON_REPLY_EMAILADDR, "Account Email Address", FT_STRING },
  { SIGNON_LOGON_REPLY_REGSTATUS, "Registration Status", FT_UINT16 },
  { SIGNON_LOGON_REPLY_LATESTBETABUILD, "Latest Beta Build", FT_UINT32 },
  { SIGNON_LOGON_REPLY_LATESTBETAURL, "Latest Beta URL", FT_STRING },
  { SIGNON_LOGON_REPLY_LATESTBETAINFO, "Latest Beta Info", FT_STRING },
  { SIGNON_LOGON_REPLY_LATESTBETANAME, "Latest Beta Name", FT_STRING },
  { SIGNON_LOGON_REPLY_LATESTRELEASEBUILD, "Latest Release Build", FT_UINT32 },
  { SIGNON_LOGON_REPLY_LATESTRELEASEURL, "Latest Release URL", FT_STRING },
  { SIGNON_LOGON_REPLY_LATESTRELEASEINFO, "Latest Release Info", FT_STRING },
  { SIGNON_LOGON_REPLY_LATESTRELEASENAME, "Latest Release Name", FT_STRING },
  { 0, "Unknown", 0 }
};

#define FAMILY_BUDDYLIST_USERFLAGS      0x0001
#define FAMILY_BUDDYLIST_MEMBERSINCE    0x0002
#define FAMILY_BUDDYLIST_ONSINCE        0x0003
#define FAMILY_BUDDYLIST_IDLETIME       0x0004
#define FAMILY_BUDDYLIST_ICQSTATUS      0x0006
#define FAMILY_BUDDYLIST_ICQIPADDR      0x000a
#define FAMILY_BUDDYLIST_ICQSTUFF       0x000c
#define FAMILY_BUDDYLIST_CAPINFO        0x000d
#define FAMILY_BUDDYLIST_UNKNOWN        0x000e
#define FAMILY_BUDDYLIST_SESSIONLEN     0x000f
#define FAMILY_BUDDYLIST_ICQSESSIONLEN  0x0010

static const aim_tlv aim_fnac_family_buddylist_oncoming_tlv[] = {
  { FAMILY_BUDDYLIST_USERFLAGS, "User flags", FT_UINT16 },
  { FAMILY_BUDDYLIST_MEMBERSINCE, "Member since date", FT_UINT32 },
  { FAMILY_BUDDYLIST_ONSINCE, "Online since", FT_UINT32 },
  { FAMILY_BUDDYLIST_IDLETIME, "Idle time (sec)", FT_UINT16 },
  { FAMILY_BUDDYLIST_ICQSTATUS, "ICQ Online status", FT_UINT16 },
  { FAMILY_BUDDYLIST_ICQIPADDR, "ICQ User IP Address", FT_UINT16 },
  { FAMILY_BUDDYLIST_ICQSTUFF, "ICQ Info", FT_BYTES },
  { FAMILY_BUDDYLIST_CAPINFO, "Capability Info", FT_BYTES },
  { FAMILY_BUDDYLIST_UNKNOWN, "Unknown", FT_UINT16 },
  { FAMILY_BUDDYLIST_SESSIONLEN, "Session Length (sec)", FT_UINT32 },
  { FAMILY_BUDDYLIST_SESSIONLEN, "ICQ Session Length (sec)", FT_UINT32 },
  { 0, "Unknown", 0 }
};


#define FAMILY_LOCATION_USERINFO_INFOENCODING  0x0001
#define FAMILY_LOCATION_USERINFO_INFOMSG       0x0002
#define FAMILY_LOCATION_USERINFO_AWAYENCODING  0x0003
#define FAMILY_LOCATION_USERINFO_AWAYMSG       0x0004
#define FAMILY_LOCATION_USERINFO_CAPS          0x0005

static const aim_tlv aim_fnac_family_location_userinfo_tlv[] = {
  { FAMILY_LOCATION_USERINFO_INFOENCODING, "Info Msg Encoding", FT_STRING },
  { FAMILY_LOCATION_USERINFO_INFOMSG, "Info Message", FT_STRING },
  { FAMILY_LOCATION_USERINFO_AWAYENCODING, "Away Msg Encoding", FT_STRING },
  { FAMILY_LOCATION_USERINFO_AWAYMSG, "Away Message", FT_STRING },
  { FAMILY_LOCATION_USERINFO_CAPS, "Capabilities", FT_BYTES },
  { 0, "Unknown", 0 }
};

#define FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO  0x0001
#define FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG      0x0003
#define FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS         0x0005

static const value_string aim_snac_location_request_user_info_infotypes[] = {
  { FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO, "Request General Info" },
  { FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG, "Request Away Message" },
  { FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS, "Request Capabilities" },
  { 0, NULL }
};

static int dissect_aim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint get_aim_pdu_len(tvbuff_t *tvb, int offset);
static void dissect_aim_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length);
static int get_buddyname( char *name, tvbuff_t *tvb, int len_offset, int name_offset);
static void dissect_aim_newconn(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac(tvbuff_t *tvb, packet_info *pinfo, 
			     int offset, proto_tree *tree);
static void dissect_aim_snac_fnac_subtype(tvbuff_t *tvb, int offset, 
					  proto_tree *tree, guint16 family);
static void dissect_aim_snac_signon(tvbuff_t *tvb, packet_info *pinfo, 
				    int offset, proto_tree *tree, 
				    guint16 subtype);
static void dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_generic(tvbuff_t *tvb, packet_info *pinfo, 
				     int offset, proto_tree *tree, 
				     guint16 subtype);
static void dissect_aim_snac_buddylist(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype);
static void dissect_aim_snac_location(tvbuff_t *tvb, packet_info *pinfo, 
				      int offset, proto_tree *tree, 
				      guint16 subtype);
static void dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_aim_snac_location_user_information(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_adverts(tvbuff_t *tvb, packet_info *pinfo, 
				     int offset, proto_tree *tree, 
				     guint16 subtype);
static void dissect_aim_snac_userlookup(tvbuff_t *tvb, packet_info *pinfo, 
					int offset, proto_tree *tree, 
					guint16 subtype);
static void dissect_aim_snac_chat(tvbuff_t *tvb, packet_info *pinfo, 
				  int offset, proto_tree *tree, 
				  guint16 subtype);
static void dissect_aim_snac_messaging(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype);
static void dissect_aim_snac_ssi(tvbuff_t *tvb, packet_info *pinfo, 
				 int offset, proto_tree *tree, 
				 guint16 subtype);
static void dissect_aim_snac_ssi_list(tvbuff_t *tvb, packet_info *pinfo _U_, 
				      int offset, proto_tree *tree, 
				      guint16 subtype _U_);
static void dissect_aim_flap_err(tvbuff_t *tvb, packet_info *pinfo, 
				 int offset, proto_tree *tree);
static void dissect_aim_close_conn(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree);
static void dissect_aim_unknown_channel(tvbuff_t *tvb, packet_info *pinfo, 
					int offset, proto_tree *tree);
static int dissect_aim_tlv(tvbuff_t *tvb, packet_info *pinfo, 
			   int offset, proto_tree *tree, const aim_tlv *tlv);

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
static int hf_aim_fnac_subtype_signon = -1;
static int hf_aim_fnac_subtype_generic = -1;
static int hf_aim_fnac_subtype_location = -1;
static int hf_aim_fnac_subtype_buddylist = -1;
static int hf_aim_fnac_subtype_messaging = -1;
static int hf_aim_fnac_subtype_adverts = -1;
static int hf_aim_fnac_subtype_invitation = -1;
static int hf_aim_fnac_subtype_admin = -1;
static int hf_aim_fnac_subtype_popup = -1;
static int hf_aim_fnac_subtype_bos = -1;
static int hf_aim_fnac_subtype_userlookup = -1;
static int hf_aim_fnac_subtype_stats = -1;
static int hf_aim_fnac_subtype_translate = -1;
static int hf_aim_fnac_subtype_chatnav = -1;
static int hf_aim_fnac_subtype_chat = -1;
static int hf_aim_fnac_subtype_ssi = -1;
static int hf_aim_fnac_subtype_ssi_version = -1;
static int hf_aim_fnac_subtype_ssi_numitems = -1;
static int hf_aim_fnac_subtype_ssi_buddyname_len = -1;
static int hf_aim_fnac_subtype_ssi_buddyname = -1;
static int hf_aim_fnac_subtype_ssi_gid = -1;
static int hf_aim_fnac_subtype_ssi_bid = -1;
static int hf_aim_fnac_subtype_ssi_type = -1;
static int hf_aim_fnac_subtype_ssi_tlvlen = -1;
static int hf_aim_fnac_subtype_ssi_data = -1;
static int hf_aim_fnac_subtype_icq = -1;
static int hf_aim_fnac_flags = -1;
static int hf_aim_fnac_id = -1;
static int hf_aim_infotype = -1;
static int hf_aim_snac_location_request_user_info_infotype = -1;
static int hf_aim_buddyname_len = -1;
static int hf_aim_buddyname = -1;
static int hf_aim_userinfo_warninglevel = -1;
static int hf_aim_userinfo_tlvcount = -1;

/* Initialize the subtree pointers */
static gint ett_aim          = -1;
static gint ett_aim_fnac     = -1;
static gint ett_aim_tlv      = -1;
static gint ett_aim_ssi      = -1;

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
    proto_tree_add_uint(aim_tree, hf_aim_channel, tvb, 1, 1, hdr_channel);
    proto_tree_add_uint(aim_tree, hf_aim_seqno, tvb, 2, 2, hdr_sequence_no);
    proto_tree_add_uint(aim_tree, hf_aim_data_len, tvb, 4, 2, hdr_data_field_length);

  }

  switch(hdr_channel)
  {
    /* New connection request */
    case CHANNEL_NEW_CONN:
      dissect_aim_newconn(tvb, pinfo, offset, aim_tree);
      break;
    case CHANNEL_SNAC_DATA:
      dissect_aim_snac(tvb, pinfo, offset, aim_tree);
      break;
    case CHANNEL_FLAP_ERR:
      dissect_aim_flap_err(tvb, pinfo, offset, aim_tree);
      break;
    case CHANNEL_CLOSE_CONN:
      dissect_aim_close_conn(tvb, pinfo, offset, aim_tree);
      break;
    default:
      dissect_aim_unknown_channel(tvb, pinfo, offset, aim_tree);
      break;
  }

}


static int get_buddyname( char *name, tvbuff_t *tvb, int len_offset, int name_offset)
{
  guint8 buddyname_length;

  buddyname_length = tvb_get_guint8(tvb, len_offset);

  if(buddyname_length > MAX_BUDDYNAME_LENGTH ) buddyname_length = MAX_BUDDYNAME_LENGTH;
  tvb_get_nstringz0(tvb, name_offset, buddyname_length + 1, name);

  return buddyname_length;
}


static void get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length)
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

static void dissect_aim_newconn(tvbuff_t *tvb, packet_info *pinfo, 
				int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_add_fstr(pinfo->cinfo, COL_INFO, "New Connection");
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_snac(tvbuff_t *tvb, packet_info *pinfo, 
			     int offset, proto_tree *aim_tree)
{
  guint16 family;
  guint16 subtype;
  guint16 flags;
  guint32 id;
  proto_item *ti1;
  proto_tree *aim_tree_fnac = NULL;
  int orig_offset;

  orig_offset = offset;
  family = tvb_get_ntohs(tvb, offset);
  offset += 2;
  subtype = tvb_get_ntohs(tvb, offset);
  offset += 2;
  flags = tvb_get_ntohs(tvb, offset);
  offset += 2;
  id = tvb_get_ntohl(tvb, offset);
  offset += 4;
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "SNAC data");
  }
  if( aim_tree )
    {
      offset = orig_offset;
      ti1 = proto_tree_add_text(aim_tree, tvb, 6, 10, "FNAC");
      aim_tree_fnac = proto_item_add_subtree(ti1, ett_aim_fnac);

      proto_tree_add_item (aim_tree_fnac, hf_aim_fnac_family,
			   tvb, offset, 2, FALSE);
      offset += 2;

      /* Dissect the subtype based on the family */
      dissect_aim_snac_fnac_subtype(tvb, offset, aim_tree_fnac, family);
      offset += 2;

      proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_flags, tvb, offset, 
			  2, flags);
      offset += 2;
      proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_id, tvb, offset,
			  4, id);
      offset += 4;
    }

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Family: %s",
		    val_to_str(family, aim_fnac_family_ids,
			       "Unknown Family ID=0x%04x"));
  
  switch(family)
    {
    case FAMILY_SIGNON:
      dissect_aim_snac_signon(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_GENERIC:
      dissect_aim_snac_generic(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_BUDDYLIST:
      dissect_aim_snac_buddylist(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_LOCATION:
      dissect_aim_snac_location(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_ADVERTS:
      dissect_aim_snac_adverts(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_USERLOOKUP:
      dissect_aim_snac_userlookup(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_CHAT:
      dissect_aim_snac_chat(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_MESSAGING:
      dissect_aim_snac_messaging(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_SSI:
      dissect_aim_snac_ssi(tvb, pinfo, offset, aim_tree, subtype);
      break;
    }
}

static void dissect_aim_snac_signon(tvbuff_t *tvb, packet_info *pinfo, 
				    int offset, proto_tree *tree, 
				    guint16 subtype)
{
  switch(subtype)
    {
    case FAMILY_SIGNON_LOGON:
      dissect_aim_snac_signon_logon(tvb, pinfo, offset, tree);
      break;
    case FAMILY_SIGNON_LOGON_REPLY:
      dissect_aim_snac_signon_logon_reply(tvb, pinfo, offset, tree);
      break;
    case FAMILY_SIGNON_SIGNON:
      dissect_aim_snac_signon_signon(tvb, pinfo, offset, tree);
      break;
    case FAMILY_SIGNON_SIGNON_REPLY:
      dissect_aim_snac_signon_signon_reply(tvb, pinfo, offset, tree);
      break;
    }
}

static void dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo, 
					  int offset, proto_tree *tree)
{
  while (tvb_length_remaining(tvb, offset) > 0) {
    offset = dissect_aim_tlv(tvb, pinfo, offset, tree, aim_signon_signon_tlv);
  }
}

static void dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb, 
						packet_info *pinfo, 
						int offset, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_INFO)) 
      col_append_fstr(pinfo->cinfo, COL_INFO, ", Login information reply");

    while (tvb_length_remaining(tvb, offset) > 0) {
      offset = dissect_aim_tlv(tvb, pinfo, offset, tree, 
			       aim_signon_logon_reply_tlv);
    }
}

static void dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo, 
					   int offset, proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];

  /* Info Type */
  proto_tree_add_item(tree, hf_aim_infotype, tvb, offset, 2, FALSE);
  offset += 2;

  /* Unknown */
  offset += 1;

  /* Buddy Name */
  buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Username: %s", buddyname);
  }
  
  if(tree) {
    proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			"Screen Name: %s", buddyname);
  }
  
  offset += buddyname_length + 1;
}

static void dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb, 
						 packet_info *pinfo, 
						 int offset, proto_tree *tree)
{
  guint16 challenge_length = 0;

  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Sign-on reply");

  /* Logon Challenge Length */
  challenge_length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_aim_signon_challenge_len, tvb, offset, 2, FALSE);
  offset += 2;

  /* Challenge */
  proto_tree_add_item(tree, hf_aim_signon_challenge, tvb, offset, challenge_length, FALSE);
  offset += challenge_length;
}

static void dissect_aim_snac_generic(tvbuff_t *tvb, packet_info *pinfo, 
				    int offset, proto_tree *tree, 
				    guint16 subtype)
{
  switch(subtype)
    {
    case FAMILY_GENERIC_ERROR:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Generic Error");
      break;
    case FAMILY_GENERIC_CLIENTREADY:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Client is now online and ready for normal function");
      break;
    case FAMILY_GENERIC_SERVERREADY:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Server is now ready for normal functions");
      break;
    case FAMILY_GENERIC_SERVICEREQ:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Request for new service (server will redirect client)");
      break;
    case FAMILY_GENERIC_REDIRECT:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Redirect response");
      break;
    case FAMILY_GENERIC_RATEINFOREQ:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rate Information");
      break;
    case FAMILY_GENERIC_RATEINFO:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rate information response");
      break;
    case FAMILY_GENERIC_RATEINFOACK:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rate Information Response Ack");
      break;
    case FAMILY_GENERIC_RATECHANGE:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rate Change");
      break;
    case FAMILY_GENERIC_SERVERPAUSE:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Server Pause");
      break;
    case FAMILY_GENERIC_SERVERRESUME:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Server Resume");
      break;
    case FAMILY_GENERIC_REQSELFINFO:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Self Info");
      break;
    case FAMILY_GENERIC_SELFINFO:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Self Info");
      break;
    case FAMILY_GENERIC_EVIL:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Evil");
      break;
    case FAMILY_GENERIC_SETIDLE:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Set Idle");
      break;
    case FAMILY_GENERIC_MIGRATIONREQ:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Migration");
      break;
    case FAMILY_GENERIC_MOTD:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "MOTD");
      break;
    case FAMILY_GENERIC_SETPRIVFLAGS:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Set Privilege Flags");
      break;
    case FAMILY_GENERIC_WELLKNOWNURL:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Well Known URL");
      break;
    case FAMILY_GENERIC_NOP:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "No-op");
      break;
    case FAMILY_GENERIC_DEFAULT:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Generic Default");
      break;
    }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_snac_buddylist(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];
  guint16 tlv_count = 0;

  switch(subtype)
    {
    case FAMILY_BUDDYLIST_ERROR:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Buddylist - Error");
      break;
       
   case FAMILY_BUDDYLIST_REQRIGHTS:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rights information");
      break;
      
    case FAMILY_BUDDYLIST_RIGHTSINFO:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rights information");
      break;
      
    case FAMILY_BUDDYLIST_ADDBUDDY:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Add to Buddylist");
      break;
      
    case FAMILY_BUDDYLIST_REMBUDDY:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Remove from Buddylist");
      break;
      
    case FAMILY_BUDDYLIST_ONCOMING:
      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );

      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Oncoming Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
      }
      
      if (tree) {
	proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      offset += buddyname_length + 1;

      /* Warning level */
      proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 
			  2, FALSE);
      offset += 2;
      
      /* TLV Count */
      tlv_count = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(tree, hf_aim_userinfo_tlvcount, tvb, offset, 
			  2, FALSE);
      offset += 2;

      while (tvb_length_remaining(tvb, offset) > 0) {
	offset = dissect_aim_tlv(tvb, pinfo, offset, tree, 
				 aim_fnac_family_buddylist_oncoming_tlv);
      }

      break;
      
    case FAMILY_BUDDYLIST_OFFGOING:
      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Offgoing Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
      }
      
      if (tree) {
	proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      offset += buddyname_length + 1;

      /* Warning level */
      proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 
			  2, FALSE);
      offset += 2;
      
      /* TLV Count */
      tlv_count = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(tree, hf_aim_userinfo_tlvcount, tvb, offset, 
			  2, FALSE);
      offset += 2;

      break;
    }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_snac_location(tvbuff_t *tvb, packet_info *pinfo, 
				      int offset, proto_tree *tree, 
				      guint16 subtype)
{
  switch(subtype)
    {
    case FAMILY_LOCATION_ERROR:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Location - Error");
      break;
    case FAMILY_LOCATION_REQRIGHTS:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rights Information");
      break;
    case FAMILY_LOCATION_RIGHTSINFO:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rights Information");
      break;
    case FAMILY_LOCATION_SETUSERINFO:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Set User Information");
      break;
    case FAMILY_LOCATION_REQUSERINFO:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request User Information");
      dissect_aim_snac_location_request_user_information(tvb, offset, tree);
      break;
    case FAMILY_LOCATION_USERINFO:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "User Information");
      dissect_aim_snac_location_user_information(tvb, pinfo, offset, tree);
      break;
    case FAMILY_LOCATION_WATCHERSUBREQ:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Watcher Subrequest");
      break;
    case FAMILY_LOCATION_WATCHERNOT:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Watcher Notification");
      break;
    case FAMILY_LOCATION_DEFAULT:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Location Default");
      break;
    }
}

static void dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, 
							  int offset,
							  proto_tree *tree)
{
  guint8 buddyname_length = 0;

  /* Info Type */
  proto_tree_add_item(tree, hf_aim_snac_location_request_user_info_infotype, 
		      tvb, offset, 2, FALSE);
  offset += 2;

  /* Buddy Name length */
  buddyname_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, FALSE);
  offset += 1;
  
  /* Buddy name */
  proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, FALSE);
  offset += buddyname_length;

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_snac_location_user_information(tvbuff_t *tvb, 
						       packet_info *pinfo _U_, 
						  int offset, proto_tree *tree)
{
  guint8 buddyname_length = 0;
  guint16 tlv_count = 0;
  guint16 i = 0;

  /* Buddy Name length */
  buddyname_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, FALSE);
  offset += 1;
  
  /* Buddy name */
  proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, FALSE);
  offset += buddyname_length;

  /* Warning level */
  proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 2, FALSE);
  offset += 2;

  /* TLV Count */
  tlv_count = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_aim_userinfo_tlvcount, tvb, offset, 2, FALSE);
  offset += 2;

  /* Dissect the TLV array containing general user status  */
  while (i++ < tlv_count) {
    offset = dissect_aim_tlv(tvb, pinfo, offset, tree, 
			     aim_fnac_family_buddylist_oncoming_tlv);
  }

  /* Dissect the TLV array containing the away message (or whatever info was
     specifically requested) */
  while (tvb_length_remaining(tvb, offset) > 0) {
    offset = dissect_aim_tlv(tvb, pinfo, offset, tree, 
			     aim_fnac_family_location_userinfo_tlv);
  }
}

static void dissect_aim_snac_adverts(tvbuff_t *tvb _U_, 
				     packet_info *pinfo _U_, 
				     int offset _U_, proto_tree *tree _U_, 
				     guint16 subtype)
{
  switch(subtype)
    {
    case FAMILY_ADVERTS_ERROR:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisements - Error");
      break;
    case FAMILY_ADVERTS_REQUEST:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisement Request");
      break;
    case FAMILY_ADVERTS_DATA:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisement data (GIF)");
      break;
    }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_snac_userlookup(tvbuff_t *tvb _U_, packet_info *pinfo, 
					int offset _U_, proto_tree *tree _U_, 
					guint16 subtype)
{
  switch(subtype)
    {
    case FAMILY_USERLOOKUP_ERROR:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Search - Error (could be: not found)");
      break;
    case FAMILY_USERLOOKUP_SEARCHEMAIL:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Search for Screen Name by e-mail");
      break;
    case FAMILY_USERLOOKUP_SEARCHRESULT:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Screen Name Search Result");
      break;
    }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
}

static void dissect_aim_snac_chat(tvbuff_t *tvb, packet_info *pinfo, 
				  int offset _U_, proto_tree *tree, 
				  guint16 subtype)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];
  guchar msg[1000];

  switch(subtype)
    {
    case FAMILY_CHAT_OUTGOINGMSG:
      /* channel message from client */
      get_message( msg, tvb, 40 + buddyname_length, tvb_length(tvb) 
		   - 40 - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Chat Message ");
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      break;
      
    case FAMILY_CHAT_INCOMINGMSG:
      /* channel message to client */
      buddyname_length = get_buddyname( buddyname, tvb, 30, 31 );
      get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) 
		   - 36 - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Chat Message ");
	col_append_fstr(pinfo->cinfo, COL_INFO, "from: %s", buddyname);
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 31, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      break;
    }
}

static void dissect_aim_snac_messaging(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];
  guchar msg[1000];

  switch(subtype)
    {    
    case FAMILY_MESSAGING_OUTGOING:

      /* Unknown */
      offset += 10;

      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* djh - My test suggest that this is broken.  Need to give this a
	 closer look @@@@@@@@@ */
      get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) - 36
		   - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Message ");
	col_append_fstr(pinfo->cinfo, COL_INFO, "to: %s", buddyname);
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 27, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      
      break;
      
    case FAMILY_MESSAGING_INCOMING:

      /* Unknown */
      offset += 10;

      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* djh - My test suggest that this is broken.  Need to give this a
	 closer look @@@@@@@@@ */      
      get_message( msg, tvb, 36 + buddyname_length,  tvb_length(tvb) - 36
		   - buddyname_length);
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Message");
	col_append_fstr(pinfo->cinfo, COL_INFO, " from: %s", buddyname);
	
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 27, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      break;
    }
}

static void dissect_aim_snac_ssi(tvbuff_t *tvb, packet_info *pinfo _U_, 
				 int offset, proto_tree *tree, 
				 guint16 subtype _U_)
{
  switch(subtype)
    {    
    case FAMILY_SSI_LIST:
      dissect_aim_snac_ssi_list(tvb, pinfo, offset, tree, subtype);
      break;
    default:
      /* Show the undissected payload */
      if (tvb_length_remaining(tvb, offset) > 0)
	proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
    }
}

static void dissect_aim_snac_ssi_list(tvbuff_t *tvb, packet_info *pinfo _U_, 
				      int offset, proto_tree *tree, 
				      guint16 subtype _U_)
{
  guint16 buddyname_length = 0;
  guint16 tlv_len = 0;
  proto_item *ti;
  proto_tree *ssi_entry = NULL;

  /* SSI Version */
  proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_version, tvb, offset, 1,
		      FALSE);
  offset += 1;
  
  /* Number of items */
  proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_numitems, tvb, offset, 2,
		      FALSE);
  offset += 2;
  
  while (tvb_length_remaining(tvb, offset) > 4) {
    ti = proto_tree_add_text(tree, tvb, offset, 0, "SSI Entry");
    ssi_entry = proto_item_add_subtree(ti, ett_aim_ssi);
    
    /* Buddy Name Length */
    buddyname_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname_len, 
			tvb, offset, 2, FALSE);
    offset += 2;
    
    /* Buddy Name */
    if (buddyname_length > 0) {
      proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname, tvb, 
			  offset, buddyname_length, FALSE);
      offset += buddyname_length;
    }
    
    /* Buddy group ID */
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_gid, tvb, offset, 
			2, FALSE);
    offset += 2;
    
    /* Buddy ID */
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_bid, tvb, offset, 
			2, FALSE);
    offset += 2;
    
    /* Buddy Type */
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_type, tvb, offset,
			2, FALSE);
    offset += 2;
    
    /* Size of the following TLV in bytes (as opposed to the number of 
       TLV objects in the chain) */
    tlv_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_tlvlen, tvb, 
			offset, 2, FALSE);
    offset += 2;
    
    /* For now, we just dump the TLV contents as-is, since there is not a
       TLV dissection utility that works based on total chain length */
    if (tlv_len > 0) {
      proto_tree_add_item(ssi_entry, hf_aim_data, tvb, offset, tlv_len, 
			  FALSE);
      offset += tlv_len;
    }
  }
}

static void dissect_aim_snac_fnac_subtype(tvbuff_t *tvb, int offset, 
				     proto_tree *tree, guint16 family)
{
  /* Since the subtypes differ by family, we need to display the correct
     subtype based on the family.  If we don't know the family, or we do
     not have the subtypes enumerated for a known family, we just dump the
     subtype as-is */

  switch (family)
    {
    case FAMILY_GENERIC:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_generic,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_LOCATION:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_location,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_BUDDYLIST:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_buddylist,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_MESSAGING:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_messaging,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_ADVERTS:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_adverts,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_INVITATION:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_invitation,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_ADMIN:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_admin,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_POPUP:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_popup,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_BOS:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_bos,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_USERLOOKUP:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_userlookup,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_STATS:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_stats,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_TRANSLATE:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_translate,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_CHAT_NAV:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_chatnav,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_CHAT:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_chat,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_SSI:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_ssi,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_ICQ:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_icq,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_SIGNON:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_signon,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_OFT:
    default:
      proto_tree_add_item(tree, hf_aim_fnac_subtype, tvb, offset, 2, FALSE);
      break;

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

static void dissect_aim_close_conn(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Close Connection");
  }

  /* Show the undissected payload */
  if (tvb_length_remaining(tvb, offset) > 0)
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, -1, FALSE);
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

/* Dissect a TLV value */
static int dissect_aim_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, 
			   int offset, proto_tree *tree, const aim_tlv *tlv)
{
  guint16 valueid;
  guint16 length;
  int i = 0;
  const aim_tlv *tmp;
  proto_item *ti1;
  proto_tree *tlv_tree;
  int orig_offset;
  guint16 value16;
  guint32 value32;

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
    
    /* Show the info in the top of the tree if it's one of the standard
       data types */
    if (tmp[i].datatype == FT_STRING) {
      guint8 *buf;      
      buf = g_malloc(length);
      tvb_get_nstringz0(tvb, offset + 4, length, buf);
      ti1 = proto_tree_add_text(tree, tvb, offset, length + 4, 
				"%s: %s", tmp[i].desc, buf);
      g_free(buf);
    }
    else if (tmp[i].datatype == FT_UINT16) {
      value16 = tvb_get_ntohs(tvb, offset + 4);
      ti1 = proto_tree_add_text(tree, tvb, offset, length + 4, 
				"%s: %d", tmp[i].desc, value16);
    }
    else if (tmp[i].datatype == FT_UINT32) {
      value32 = tvb_get_ntohl(tvb, offset + 4);
      ti1 = proto_tree_add_text(tree, tvb, offset, length + 4, 
				"%s: %d", tmp[i].desc, value32);
    }
    else {
      ti1 = proto_tree_add_text(tree, tvb, offset, length + 4, 
				"%s", tmp[i].desc);
    }

    tlv_tree = proto_item_add_subtree(ti1, ett_aim_tlv);

    proto_tree_add_text(tlv_tree, tvb, offset, 2,
			"Value ID: %s (0x%04x)", tmp[i].desc, valueid);
    offset += 2;
    
    proto_tree_add_text(tlv_tree, tvb, offset, 2,
			"Length: %d", length);
    offset += 2;

    ti1 = proto_tree_add_text(tlv_tree, tvb, offset, length,
			      "Value");
    offset += length;
  }

  /* Return the new length */
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
      { "Channel ID", "aim.channel", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_seqno,
      { "Sequence Number", "aim.seqno", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
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
      { "FNAC Family ID", "aim.fnac.family", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_ids), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_signon,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_signon), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_generic,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_generic), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_location,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_location), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_buddylist,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_buddylist), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_messaging,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_messaging), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_adverts,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_adverts), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_invitation,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_invitation), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_admin,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_admin), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_popup,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_popup), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_bos,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_bos), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_userlookup,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_userlookup), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_stats,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_stats), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_translate,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_translate), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_chatnav,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_chatnav), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_chat,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_chat), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_ssi), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_version,
      { "SSI Version", "aim.fnac.ssi.version", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_numitems,
      { "SSI Object count", "aim.fnac.ssi.numitems", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_buddyname_len,
      { "SSI Buddy Name length", "aim.fnac.ssi.buddyname_len", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_buddyname,
      { "Buddy Name", "aim.fnac.ssi.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_gid,
      { "SSI Buddy Group ID", "aim.fnac.ssi.gid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_bid,
      { "SSI Buddy ID", "aim.fnac.ssi.bid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_type,
      { "SSI Buddy type", "aim.fnac.ssi.type", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_ssi_types), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_tlvlen,
      { "SSI TLV Len", "aim.fnac.ssi.tlvlen", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_data,
      { "SSI Buddy Data", "aim.fnac.ssi.data", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_icq,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_icq), 0x0, "", HFILL }
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
    { &hf_aim_snac_location_request_user_info_infotype,
      { "Infotype", "aim.snac.location.request_user_info.infotype", FT_UINT16,
	BASE_HEX, VALS(aim_snac_location_request_user_info_infotypes), 0x0,
	"", HFILL }
    },
    { &hf_aim_buddyname_len,
      { "Buddyname len", "aim.buddynamelen", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_buddyname,
      { "Buddy Name", "aim.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_userinfo_warninglevel,
      { "Warning Level", "aim.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_userinfo_tlvcount,
      { "TLV Count", "aim.userinfo.tlvcount", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim,
    &ett_aim_fnac,
    &ett_aim_tlv,
    &ett_aim_ssi,
  };
  module_t *aim_module;

/* Register the protocol name and description */
  proto_aim = proto_register_protocol("AOL Instant Messenger", "AIM", "aim");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  aim_module = prefs_register_protocol(proto_aim, NULL);
  prefs_register_bool_preference(aim_module, "desegment",
    "Desegment all AIM messages spanning multiple TCP segments",
    "Whether the AIM dissector should desegment all messages spanning multiple TCP segments",
    &aim_desegment);
};

void
proto_reg_handoff_aim(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim, proto_aim);
  dissector_add("tcp.port", TCP_PORT_AIM, aim_handle);
}
