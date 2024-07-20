/* packet-ymsg.c
 * Routines for Yahoo Messenger YMSG protocol packet version 13 dissection
 * Copyright 2003, Wayne Parrott <wayne_p@pacific.net.au>
 * Copied from packet-yhoo.c and updated
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-tcp.h"
#include <epan/prefs.h>
#include <wsutil/strtoi.h>

void proto_register_ymsg(void);
void proto_reg_handoff_ymsg(void);

static int proto_ymsg;
static int hf_ymsg_version;
static int hf_ymsg_vendor;
static int hf_ymsg_len;
static int hf_ymsg_command;
static int hf_ymsg_status;
static int hf_ymsg_session_id;

static int hf_ymsg_content;
static int hf_ymsg_content_line;
static int hf_ymsg_content_line_key;
static int hf_ymsg_content_line_value;

static int ett_ymsg;
static int ett_ymsg_content;
static int ett_ymsg_content_line;

#define TCP_PORT_YMSG     23    /* XXX - this is Telnet! */
#define TCP_PORT_YMSG_2   25    /* And this is SMTP! */
#define TCP_PORT_YMSG_3 5050    /* This, however, is regular Yahoo Messenger */

/* desegmentation of YMSG over TCP */
static bool ymsg_desegment = true;

/*
 * This is based on libyahoo2's yahoolib2.c and enums reversed from Y!M 9.0.0.2162 DLLs
 *
 * See also
 *
 *    http://libyahoo2.sourceforge.net/ymsg-9.txt
 *    Snapshot: https://web.archive.org/web/20230726025458/http://libyahoo2.sourceforge.net/ymsg-9.txt
 *
 * and
 *
 *    http://www.venkydude.com/articles/yahoo.htm
 *    Snapshot: https://web.archive.org/web/20100407060623/http://www.venkydude.com/articles/yahoo.htm
 *
 * and
 *
 *    http://www.cse.iitb.ac.in/~varunk/YahooProtocol.htm
 *    Snapshot: https://web.archive.org/web/20040214071503/http://www.cse.iitb.ac.in/~varunk/YahooProtocol.htm
 *
 * and
 *
 *    http://www.geocrawler.com/archives/3/4893/2002/1/0/7459037/
 *    Snapshot: N/A
 *
 * and
 *
 *    http://www.geocities.com/ziggycubbe/ym.html
 *    Snapshot: https://web.archive.org/web/20091026045625/http://www.geocities.com/ziggycubbe/ym.html
 *
 * and
 *
 *    https://gitlab.com/escargot-chat/server/-/wikis/YMSG-Protocol
 *    Snapshot: https://web.archive.org/web/20220818055244/https://gitlab.com/escargot-chat/server/-/wikis/YMSG-Protocol
 */

/* The size of the below struct minus 6 bytes of content */
#define YAHOO_HEADER_SIZE 20

#if 0
struct yahoo_rawpacket
{
    char ymsg[4];                /* Packet identification string (YMSG) */
    unsigned char version[2];    /* 2 bytes, little endian */
    unsigned char vendor[2];     /* 2 bytes, little endian */
    unsigned char len[2];        /* length - little endian */
    unsigned char command[2];    /* command - little endian */
    unsigned char status[4];     /* Status - ok, notify etc. */
    unsigned char session_id[4]; /* Session ID */
    char content[6];             /* 6 is the minimum size of the content */
};
#endif

/*
 * Commands
 *
 * Extracted from ymsglite.dll -> YMSGMessage::commandToString(void *outString, uint command)
 */
enum yahoo_command {
    YAHOO_CMD_USER_LOGIN                 = 1,
    YAHOO_CMD_USER_LOGOFF                = 2,
    YAHOO_CMD_USER_AWAY                  = 3,
    YAHOO_CMD_USER_BACK                  = 4,
    YAHOO_CMD_USER_GET_MSGS              = 5,
    YAHOO_CMD_USER_HAS_MSG               = 6,
    YAHOO_CMD_ACTIVATE_ID                = 7,
    YAHOO_CMD_DEACTIVATE_ID              = 8,
    YAHOO_CMD_GET_USER_STATUS            = 0xa,
    YAHOO_CMD_USER_HAS_MAIL              = 0xb,
    YAHOO_CMD_START_CONFERENCE           = 0xc,
    YAHOO_CMD_CALENDAR_ALERT             = 0xd,
    YAHOO_CMD_USER_PERSONAL_MESSAGE      = 0xe,
    YAHOO_CMD_UPDATE_BUDDY_LIST          = 0xf,
    YAHOO_CMD_UPDATE_ID_LIST             = 0x10,
    YAHOO_CMD_UPDATE_IGNORE_LIST         = 0x11,
    YAHOO_CMD_PING                       = 0x12,
    YAHOO_CMD_UPDATE_GROUP               = 0x13,
    YAHOO_CMD_SYSTEM_MESSAGE             = 0x14,
    YAHOO_CMD_CLIENT_STATS               = 0x15,
    YAHOO_CMD_CLIENT_ALERT_STATS         = 0x16,
    YAHOO_CMD_GROUP_MESSAGE              = 0x17,
    YAHOO_CMD_HOST_CONFERENCE            = 0x18,
    YAHOO_CMD_JOIN_CONFERENCE            = 0x19,
    YAHOO_CMD_DECLINE_CONFERENCE         = 0x1a,
    YAHOO_CMD_LEAVE_CONFERENCE           = 0x1b,
    YAHOO_CMD_INVITE_CONFERENCE          = 0x1c,
    YAHOO_CMD_SAY_CONFERENCE             = 0x1d,
    YAHOO_CMD_CHAT_LOGIN                 = 0x1e,
    YAHOO_CMD_CHAT_LOGOFF                = 0x1f,
    YAHOO_CMD_CHAT_MSG                   = 0x20,
    YAHOO_CMD_GAMES_USER_LOGIN           = 0x28,
    YAHOO_CMD_GAMES_USER_LOGOFF          = 0x29,
    YAHOO_CMD_GAMES_USER_HAS_MSG         = 0x2a,
    YAHOO_CMD_NET2PHONE_STATS            = 0x2c,
    YAHOO_CMD_ADDRESS_BOOK_ALERT         = 0x33,
    YAHOO_CMD_AUCTION_ALERT              = 0x3c,
    YAHOO_CMD_USER_FT                    = 0x46,
    YAHOO_CMD_USER_FT_REPLY              = 0x47,
    YAHOO_CMD_USER_CONVERSE              = 0x48,
    YAHOO_CMD_USER_WEB_TOUR              = 0x49,
    YAHOO_CMD_IM_ENABLE_VOICE            = 0x4a,
    YAHOO_CMD_USER_SEND_MSG              = 0x4b,
    YAHOO_CMD_SEND_PORT_CHECK            = 0x4c,
    YAHOO_CMD_SEND_DATA_THRU             = 0x4d,
    YAHOO_CMD_P2P_START                  = 0x4f,
    YAHOO_CMD_MSGR_WEBCAM_TOKEN          = 0x50,
    YAHOO_CMD_STATS                      = 0x51,
    YAHOO_CMD_USER_LOGIN2                = 0x54,
    YAHOO_CMD_PRE_LOGIN_DATA             = 0x55,
    YAHOO_CMD_GET_COOKIE_DATA            = 0x56,
    YAHOO_CMD_HELO                       = 0x57,
    YAHOO_CMD_FEATURE_NOT_SUPPORTED      = 0x58,
    YAHOO_CMD_ADD_BUDDY                  = 0x83,
    YAHOO_CMD_REMOVE_BUDDY               = 0x84,
    YAHOO_CMD_MODIFY_IGNORE_LIST         = 0x85,
    YAHOO_CMD_DENY_BUDDY_ADD             = 0x86,
    YAHOO_CMD_RENAME_GROUP               = 0x89,
    YAHOO_CMD_KEEP_ALIVE                 = 0x8a,
    YAHOO_CMD_YPC_ADD_FRIEND_APPROVAL    = 0x8b,
    YAHOO_CMD_CHALLENGE                  = 0x8c,
    YAHOO_CMD_ADD_BUDDY_INSTANT_APPROVAL = 0x8d,
    YAHOO_CMD_CHAT_MSGR_USER_LOGIN       = 0x96,
    YAHOO_CMD_CHAT_GOTO_USER             = 0x97,
    YAHOO_CMD_CHAT_ROOM_JOIN             = 0x98,
    YAHOO_CMD_CHAT_ROOM_PART             = 0x9b,
    YAHOO_CMD_CHAT_ROOM_INVITE           = 0x9d,
    YAHOO_CMD_CHAT_MSGR_USER_LOGOFF      = 0xa0,
    YAHOO_CMD_CHAT_PING                  = 0xa1,
    YAHOO_CMD_CHAT_WEBCAM_TOKEN          = 0xa7,
    YAHOO_CMD_CHAT_PUBLIC_MSG            = 0xa8,
    YAHOO_CMD_CHAT_ROOM_CREATE           = 0xa9,
    YAHOO_CMD_GAMES_INVITE               = 0xb7,
    YAHOO_CMD_GAMES_SEND_DATA            = 0xb8,
    YAHOO_CMD_EDIT_INVISIBLE_TO_LIST     = 0xb9,
    YAHOO_CMD_EDIT_VISIBLE_TO_LIST       = 0xba,
    YAHOO_CMD_ANTI_BOT                   = 0xbb,
    YAHOO_CMD_AVATAR_CHANGED             = 0xbc,
    YAHOO_CMD_FRIEND_ICON                = 0xbd,
    YAHOO_CMD_FRIEND_ICON_DOWNLOAD       = 0xbe,
    YAHOO_CMD_AVATAR_GET_FILE            = 0xbf,
    YAHOO_CMD_AVATAR_GET_HASH            = 0xc0,
    YAHOO_CMD_DISPLAY_TYPE_CHANGED       = 0xc1,
    YAHOO_CMD_FRIEND_ICON_FT             = 0xc2,
    YAHOO_CMD_GET_COOKIE                 = 0xc3,
    YAHOO_CMD_ADDRESS_BOOK_CHANGED       = 0xc4,
    YAHOO_CMD_SET_VISIBILITY             = 0xc5,
    YAHOO_CMD_SET_AWAY_STATUS            = 0xc6,
    YAHOO_CMD_DISPLAY_IMAGE_PREFS        = 0xc7,
    YAHOO_CMD_VERIFY_USER                = 0xc8,
    YAHOO_CMD_AUDIBLE                    = 0xd0,
    YAHOO_CMD_IM_PANEL_FEATURE           = 0xd2,
    YAHOO_CMD_SHARE_CONTACTS             = 0xd3,
    YAHOO_CMD_IM_SESSION                 = 0xd4,
    YAHOO_CMD_SUBSCRIPTION               = 0xd5,
    YAHOO_CMD_BUDDY_AUTHORIZE            = 0xd6,
    YAHOO_CMD_PHOTO_ADD                  = 0xd7,
    YAHOO_CMD_PHOTO_SELECT               = 0xd8,
    YAHOO_CMD_PHOTO_DELETE               = 0xd9,
    YAHOO_CMD_PHOTO_FILE_REQUEST         = 0xda,
    YAHOO_CMD_PHOTO_POINTER              = 0xdb,
    YAHOO_CMD_FXFER_INVITE               = 0xdc,
    YAHOO_CMD_FXFER_SEND                 = 0xdd,
    YAHOO_CMD_FXFER_RECEIVE              = 0xde,
    YAHOO_CMD_UPDATE_CAPABILITY          = 0xdf,
    YAHOO_CMD_REPORT_SPAM                = 0xe0,
    YAHOO_CMD_MINGLE_DATA                = 0xe1,
    YAHOO_CMD_ALERT                      = 0xe2,
    YAHOO_CMD_APP_REGISTRY               = 0xe3,
    YAHOO_CMD_NEW_USER                   = 0xe4,
    YAHOO_CMD_ACCEPT_MSGR_INVITE         = 0xe5,
    YAHOO_CMD_MSGR_USAGE                 = 0xe6,
    YAHOO_CMD_BUDDY_MOVE                 = 0xe7,
    YAHOO_CMD_GET_VOICE_CRUMB            = 0xe8,
    YAHOO_CMD_PLUGIN_SESSION_INITIATION  = 0xe9,
    YAHOO_CMD_APPLICATION_MESSAGE        = 0xea,
    YAHOO_CMD_APPLICATION_PRESENCE       = 0xeb,
    YAHOO_CMD_FXFER_PLUGIN_INVITE        = 0xec,
    YAHOO_CMD_PC2MOBILE_FXFER            = 0xed,
    YAHOO_CMD_PREFERENCE                 = 0xef,
    YAHOO_CMD_BUDDY_INFO                 = 0xf0,
    YAHOO_CMD_BUDDY_LIST                 = 0xf1,
    YAHOO_CMD_CHECK_PREMIUM_SMS_BALANCE  = 0xf2,
    YAHOO_CMD_WIDGET_BUDDY_LIST          = 0xfc,
    YAHOO_CMD_WIDGET_BUDDY_INFO          = 0xfd,
    YAHOO_CMD_WIDGET_ACTION              = 0xfe,
    YAHOO_CMD_NEWS_ALERTS                = 0xff,
    YAHOO_CMD_CORP_USER_LOGIN            = 0x1c2,
    YAHOO_CMD_MSG_RE_LOGIN               = 0x1c3,
    YAHOO_CMD_CORP_ID_COPR_P2P_INIT      = 0x1c4,
    YAHOO_CMD_CORP_CHAT_MSG              = 0x1c5,
    YAHOO_CMD_CORP_GAMES_USER_HAS_MSG    = 0x1c6,
    YAHOO_CMD_SECURE_USER_LOGIN          = 0x1cc,
    YAHOO_CMD_SECURE_IM_MSG              = 0x1cd,
    YAHOO_CMD_SECURE_CHAT_SAY_MSG        = 0x1cf,
    YAHOO_CMD_SECURE_GAMES_USER_HAS_MSG  = 0x1d0,
    YAHOO_CMD_SYMANTEC_MSGS              = 0x1f4,
    YAHOO_CMD_MOBILE_SEND_SMS_MESSAGE    = 0x1f5,
    YAHOO_CMD_MOBILE_SMS_LOGIN           = 0x2ec,
    YAHOO_CMD_MOBILE_SMS_NUMBER          = 0x2ed,
    YAHOO_CMD_ANON_LOGOFF                = 0x322,
    YAHOO_CMD_ANON_HAS_MSG               = 0x326,
    YAHOO_CMD_CLIENT_NETSTAT             = 0x327,
    YAHOO_CMD_P2P_USER                   = 0x3e9,
    YAHOO_CMD_P2P_STATE                  = 0x3ea,
    YAHOO_CMD_LWM_LOGIN                  = 0x44c,
    YAHOO_CMD_LWM_LOGOFF                 = 0x44d,
    YAHOO_CMD_OPI_LOGIN                  = 0x44e,
    YAHOO_CMD_OPI_LOGOFF                 = 0x44f,
    YAHOO_CMD_OPI_IM                     = 0x450,
    YAHOO_CMD_USER_HAS_OPI_MESSAGE       = 0x451,
    YAHOO_CMD_LWMOPI_CHECK_LOGIN         = 0x452,
    YAHOO_CMD_LWMOPI_START_OPI           = 0x453,
    YAHOO_CMD_LWMOPI_STOP_OPI            = 0x454,
};

/*
 * Command Statuses
 *
 * Extracted from ymsglite.dll -> YMSGMessage::statusToString(void *outString, int status)
 */
enum yahoo_status {
    YAHOO_STATUS_DUPLICATE              = -3,
    YAHOO_STATUS_ERR                    = -1,
    YAHOO_STATUS_OK                     = 0,
    YAHOO_STATUS_NOTIFY                 = 1,
    YAHOO_STATUS_NOT_AVAILABLE          = 2,
    YAHOO_STATUS_NEW_BUDDYOF            = 3,
    YAHOO_STATUS_PARTIAL_LIST           = 5,
    YAHOO_STATUS_SAVED_MSG              = 6,
    YAHOO_STATUS_BUDDYOF_DENIED         = 7,
    YAHOO_STATUS_INVALID_USER           = 8,
    YAHOO_STATUS_CHUNKING               = 9,
    YAHOO_STATUS_INVITED                = 0xb,
    YAHOO_STATUS_DONT_DISTURB           = 0xc,
    YAHOO_STATUS_DISTURB_ME             = 0xd,
    YAHOO_STATUS_NEW_BUDDYOF_AUTH       = 0xf,
    YAHOO_STATUS_WEB_MSG                = 0x10,
    YAHOO_STATUS_ACK                    = 0x12,
    YAHOO_STATUS_RE_LOGIN               = 0x13,
    YAHOO_STATUS_SPECIFIC_SNDR          = 0x16,
    YAHOO_STATUS_INCOMP_VERSION         = 0x18,
    YAHOO_STATUS_REQUEST                = 0x1a,
    YAHOO_STATUS_SMS_CARRIER            = 0x1d,
    YAHOO_STATUS_IS_GROUP_IM            = 0x21,
    YAHOO_STATUS_PRE_LOGIN_SUCCEEDED    = 0x64,
    YAHOO_STATUS_SERVER_CONNECTED       = 0x65,
    YAHOO_STATUS_FD_CONNECT_SUCCESS     = 0x66,
    YAHOO_STATUS_CMD_SENT_ACK           = 0x67,
    YAHOO_STATUS_UNKNOWN_USER           = 0x5a55aa55,
    YAHOO_STATUS_KNOWN_USER             = 0x5a55aa56,
};

/*
 * Content Fields
 *
 * Extracted from ymsglite.dll -> YMSGMessage::fieldToString(void *param_1, int field)
 */
enum yahoo_field {
    YAHOO_FLD_USERNAME                      = 0,
    YAHOO_FLD_CURRENT_ID                    = 1,
    YAHOO_FLD_ACTIVE_ID                     = 2,
    YAHOO_FLD_USER_ID                       = 3,
    YAHOO_FLD_SENDER                        = 4,
    YAHOO_FLD_TARGET_USER                   = 5,
    YAHOO_FLD_PASSWORD                      = 6,
    YAHOO_FLD_BUDDY                         = 7,
    YAHOO_FLD_NUM_BUDDIES                   = 8,
    YAHOO_FLD_NUM_EMAILS                    = 9,
    YAHOO_FLD_AWAY_STATUS                   = 10,
    YAHOO_FLD_SESSION_ID                    = 0xb,
    YAHOO_FLD_IP_ADDRESS                    = 0xc,
    YAHOO_FLD_FLAG                          = 0xd,
    YAHOO_FLD_MSG                           = 0xe,
    YAHOO_FLD_TIME                          = 0xf,
    YAHOO_FLD_ERR_MSG                       = 0x10,
    YAHOO_FLD_PORT                          = 0x11,
    YAHOO_FLD_MAIL_SUBJECT                  = 0x12,
    YAHOO_FLD_AWAY_MSG                      = 0x13,
    YAHOO_FLD_URL                           = 0x14,
    YAHOO_FLD_ALERT_TIME                    = 0x15,
    YAHOO_FLD_NEWS                          = 0x16,
    YAHOO_FLD_DEV_SPEED                     = 0x17,
    YAHOO_FLD_WEB_ID                        = 0x18,
    YAHOO_FLD_USER_ALERT_STATS              = 0x19,
    YAHOO_FLD_STATS_DATA                    = 0x1a,
    YAHOO_FLD_FILE_NAME                     = 0x1b,
    YAHOO_FLD_FILE_SIZE                     = 0x1c,
    YAHOO_FLD_FILE_DATA                     = 0x1d,
    YAHOO_FLD_SYMANTEC_IPADDR               = 0x1e,
    YAHOO_FLD_COMMAND                       = 0x1f,
    YAHOO_FLD_STATUS                        = 0x20,
    YAHOO_FLD_NUM_NEWS                      = 0x21,
    YAHOO_FLD_NUM_MSGS                      = 0x22,
    YAHOO_FLD_ITEM                          = 0x23,
    YAHOO_FLD_OLD_GRP_NAME                  = 0x24,
    YAHOO_FLD_NEW_GRP_NAME                  = 0x25,
    YAHOO_FLD_EXPIRATION_TIME               = 0x26,
    YAHOO_FLD_NUM_PERSONAL_MSGS             = 0x27,
    YAHOO_FLD_SYS_MSG_CODE                  = 0x28,
    YAHOO_FLD_MSG_NUM_DUMMY                 = 0x29,
    YAHOO_FLD_FROM_EMAIL                    = 0x2a,
    YAHOO_FLD_FROM_NAME                     = 0x2b,
    YAHOO_FLD_ADD_ID                        = 0x2c,
    YAHOO_FLD_DELETE_ID                     = 0x2d,
    YAHOO_FLD_DEBUG_INFO                    = 0x2e,
    YAHOO_FLD_CUSTOM_DND_STATUS             = 0x2f,
    YAHOO_FLD_CONTAINS_TAGS                 = 0x30,
    YAHOO_FLD_APP_NAME                      = 0x31,
    YAHOO_FLD_INVITOR_NAME                  = 0x32,
    YAHOO_FLD_NET2PHONE_CALL_LEN            = 0x32,
    YAHOO_FLD_INVITEE_NAME                  = 0x33,
    YAHOO_FLD_AD_SPACE_ID                   = 0x33,
    YAHOO_FLD_INVITED_USER                  = 0x34,
    YAHOO_FLD_USES_IMIP_CLIENT              = 0x34,
    YAHOO_FLD_JOINED_USER                   = 0x35,
    YAHOO_FLD_SHORTCUT                      = 0x35,
    YAHOO_FLD_DECLINED_USER                 = 0x36,
    YAHOO_FLD_FEED_VER                      = 0x36,
    YAHOO_FLD_UNAVAILABLE_USER              = 0x37,
    YAHOO_FLD_LEFT_USER                     = 0x38,
    YAHOO_FLD_ROOM_NAME                     = 0x39,
    YAHOO_FLD_CONF_TOPIC                    = 0x3a,
    YAHOO_FLD_COOKIE                        = 0x3b,
    YAHOO_FLD_DEVICE_TYPE                   = 0x3c,
    YAHOO_FLD_USER_TYPE                     = 0x3c,
    YAHOO_FLD_WEBCAM_TOKEN                  = 0x3d,
    YAHOO_FLD_TIMED_P2P_CONN_FLG            = 0x3d,
    YAHOO_FLD_WEBCAM_STATUS                 = 0x3e,
    YAHOO_FLD_IMV_ID                        = 0x3f,
    YAHOO_FLD_IMV_FLAG                      = 0x40,
    YAHOO_FLD_BUDDY_GRP_NAME                = 0x41,
    YAHOO_FLD_ERROR_CODE                    = 0x42,
    YAHOO_FLD_NEW_BUDDY_GRP_NAME            = 0x43,
    YAHOO_FLD_PHONE_CARRIER_CODE            = 0x44,
    YAHOO_FLD_SCREEN_NAME                   = 0x45,
    YAHOO_FLD_CONVERSE_COMMAND              = 0x46,
    YAHOO_FLD_SMS_PHONE                     = 0x46,
    YAHOO_FLD_CONVERSE_IDENTITY             = 0x47,
    YAHOO_FLD_CONVERSE_OTHER_GUY            = 0x48,
    YAHOO_FLD_CONVERSE_TOPIC                = 0x49,
    YAHOO_FLD_CONVERSE_COMMENT              = 0x4a,
    YAHOO_FLD_CONVERSE_MAX                  = 0x4b,
    YAHOO_FLD_CONVERSE_URL                  = 0x4c,
    YAHOO_FLD_CONVERSE_YOUR_COMMENT         = 0x4d,
    YAHOO_FLD_STAT_TYPE                     = 0x4e,
    YAHOO_FLD_IMIP_SERVICE                  = 0x4f,
    YAHOO_FLD_IMIP_LOGIN                    = 0x50,
    YAHOO_FLD_ALERT_TYPE_ID                 = 0x51,
    YAHOO_FLD_ALERT_SUBTYPE_ID              = 0x52,
    YAHOO_FLD_ALERT_DOC_TITLE               = 0x53,
    YAHOO_FLD_ALERT_PRIO_LEVEL              = 0x54,
    YAHOO_FLD_ALERT_TYPE                    = 0x55,
    YAHOO_FLD_ALERT_COUNTRY                 = 0x56,
    YAHOO_FLD_BUDDY_LIST                    = 0x57,
    YAHOO_FLD_IGNORE_LIST                   = 0x58,
    YAHOO_FLD_IDENTITY_LIST                 = 0x59,
    YAHOO_FLD_HAS_MAIL                      = 0x5a,
    YAHOO_FLD_CONVERSE_CMD_DEC_TEXT         = 0x5a,
    YAHOO_FLD_ANON_NAME                     = 0x5b,
    YAHOO_FLD_ANON_ID                       = 0x5c,
    YAHOO_FLD_T_COOKIE_EXPIRE               = 0x5d,
    YAHOO_FLD_CHALLENGE                     = 0x5e,
    YAHOO_FLD_OLD_PASSWORD                  = 0x60,
    YAHOO_FLD_UTF8_FLAG                     = 0x61,
    YAHOO_FLD_COUNTRY_CODE                  = 0x62,
    YAHOO_FLD_CO_BRAND_CODE                 = 0x63,
    YAHOO_FLD_DATE                          = 0x64,
    YAHOO_FLD_IMV_DATA                      = 0x65,
    YAHOO_FLD_WEBCAM_FARM                   = 0x66,
    YAHOO_FLD_CHAT_IGNORE_USER              = 0x67,
    YAHOO_FLD_CHAT_ROOM_NAME                = 0x68,
    YAHOO_FLD_CHAT_ROOM_TOPIC               = 0x69,
    YAHOO_FLD_CHAT_ROOM_URL                 = 0x6a,
    YAHOO_FLD_CHAT_ROOM_PARAMETER           = 0x6b,
    YAHOO_FLD_CHAT_NUM_USERS                = 0x6c,
    YAHOO_FLD_CHAT_ROOM_USERNAME            = 0x6d,
    YAHOO_FLD_CHAT_ROOM_USER_AGE            = 0x6e,
    YAHOO_FLD_CHAT_ROOM_USER_GENDER         = 0x6f,
    YAHOO_FLD_CHAT_ROOM_USER_TIMESTAMP      = 0x70,
    YAHOO_FLD_CHAT_ROOM_USER_FLAG           = 0x71,
    YAHOO_FLD_CHAT_ERR_NO                   = 0x72,
    YAHOO_FLD_CHAT_SIMILAR_ROOM             = 0x73,
    YAHOO_FLD_CHAT_EMOT_MSG                 = 0x74,
    YAHOO_FLD_CHAT_MSG                      = 0x75,
    YAHOO_FLD_CHAT_INVITED_USER             = 0x76,
    YAHOO_FLD_CHAT_INVITER                  = 0x77,
    YAHOO_FLD_CHAT_EXTENDED_DATA_ID         = 0x78,
    YAHOO_FLD_CHAT_EXTENDED_DATA            = 0x79,
    YAHOO_FLD_CHAT_USER_SETTINGS            = 0x7a,
    YAHOO_FLD_CHAT_LOGOFF_MSG               = 0x7b,
    YAHOO_FLD_CHAT_MSG_TYPE                 = 0x7c,
    YAHOO_FLD_CHAT_FRAME_NAME               = 0x7d,
    YAHOO_FLD_CHAT_FLG                      = 0x7e,
    YAHOO_FLD_CHAT_ROOM_TYPE                = 0x7f,
    YAHOO_FLD_CHAT_ROOM_CATEGORY            = 0x80,
    YAHOO_FLD_CHAT_ROOM_SPACE_ID            = 0x81,
    YAHOO_FLD_CHAT_VOICE_AUTH               = 0x82,
    YAHOO_FLD_ALERT_BUTTON_LABEL            = 0x83,
    YAHOO_FLD_ALERT_BUTTON_LINK             = 0x84,
    YAHOO_FLD_ALERT_MIN_DIMENSION           = 0x85,
    YAHOO_FLD_BIZ_MAIL_TEXT                 = 0x86,
    YAHOO_FLD_VERSION                       = 0x87,
    YAHOO_FLD_CO_BRAND_ROOM_INFO            = 0x88,
    YAHOO_FLD_IDLE_TIME                     = 0x89,
    YAHOO_FLD_NO_IDLE_TIME                  = 0x8a,
    YAHOO_FLD_CHAT_USER_NICKNAME            = 0x8d,
    YAHOO_FLD_CHAT_USER_LOCATION            = 0x8e,
    YAHOO_FLD_PING_INTERVAL                 = 0x8f,
    YAHOO_FLD_KEEP_ALIVE_INTERVAL           = 0x90,
    YAHOO_FLD_CPU_TYPE                      = 0x91,
    YAHOO_FLD_OS_VERSION                    = 0x92,
    YAHOO_FLD_TIME_ZONE                     = 0x93,
    YAHOO_FLD_TIME_BIAS                     = 0x94,
    YAHOO_FLD_BLINDED_USER_ID               = 0x95,
    YAHOO_FLD_CACHE_CRYPTO_KEY              = 0x96,
    YAHOO_FLD_LOCAL_CRYPTO_KEY              = 0x97,
    YAHOO_FLD_YPC_PREFS                     = 0x99,
    YAHOO_FLD_PARENT_ID                     = 0x9a,
    YAHOO_FLD_MSG_NUM                       = 0x9f,
    YAHOO_FLD_EE_CONFIRM_DELIVERY           = 0xa0,
    YAHOO_FLD_EE_SENDER                     = 0xa1,
    YAHOO_FLD_EE_NONCE                      = 0xa2,
    YAHOO_FLD_GAME_ID                       = 0xb4,
    YAHOO_FLD_GAME_NAME                     = 0xb5,
    YAHOO_FLD_GAME_DATA                     = 0xb6,
    YAHOO_FLD_GAME_URL                      = 0xb7,
    YAHOO_FLD_STATUS_DATA                   = 0xb8,
    YAHOO_FLD_INVISIBLE_TO                  = 0xb9,
    YAHOO_FLD_VISIBLE_TO                    = 0xba,
    YAHOO_FLD_STATUS_LINK_TYPE              = 0xbb,
    YAHOO_FLD_AVATAR_FLAG                   = 0xbe,
    YAHOO_FLD_AVATAR_MOOD_ID                = 0xbf,
    YAHOO_FLD_ICON_CHECKSUM                 = 0xc0,
    YAHOO_FLD_ICON_DATA                     = 0xc1,
    YAHOO_FLD_SEQUENCE_NO                   = 0xc2,
    YAHOO_FLD_MAX_SEQUENCE_NO               = 0xc3,
    YAHOO_FLD_ANTI_BOT_TEXT                 = 0xc4,
    YAHOO_FLD_AVATAR_HASH                   = 0xc5,
    YAHOO_FLD_AVATAR_USER                   = 0xc6,
    YAHOO_FLD_WIDTH                         = 0xc7,
    YAHOO_FLD_HEIGHT                        = 0xc8,
    YAHOO_FLD_ALERT_DATA                    = 0xcb,
    YAHOO_FLD_AVATAR_DEF_MOOD               = 0xcc,
    YAHOO_FLD_AVATAR_ZOOM                   = 0xcd,
    YAHOO_FLD_DISPLAY_TYPE                  = 0xce,
    YAHOO_FLD_BT_USER_ID                    = 0xcf,
    YAHOO_FLD_T_COOKIE                      = 0xd0,
    YAHOO_FLD_STATS_BUFFER                  = 0xd3,
    YAHOO_FLD_APPLY_TO_ALL                  = 0xd4,
    YAHOO_FLD_SHOW_MY_AVATAR_IN_FRIEND_TREE = 0xd5,
    YAHOO_FLD_GAME_PROWLER_PREF             = 0xd6,
    YAHOO_FLD_VAS_USER                      = 0xd7,
    YAHOO_FLD_FIRSTNAME                     = 0xd8,
    YAHOO_FLD_YPM_KEY                       = 0xd9,
    YAHOO_FLD_COOKIE_CUTTER                 = 0xdb, /* Not defined in ymsglite.dll, but it's always sent right after a YAHOO_FLD_COOKIE */
    YAHOO_FLD_FEATURE_ID                    = 0xdd,
    YAHOO_FLD_ACTION_TYPE                   = 0xde,
    YAHOO_FLD_UNAUTH                        = 0xdf,
    YAHOO_FLD_GROUP                         = 0xe0,
    YAHOO_FLD_ANTI_BOT_URL                  = 0xe1,
    YAHOO_FLD_ANTI_BOT_SECRET               = 0xe2,
    YAHOO_FLD_ANTI_BOT_RESPONSE             = 0xe3,
    YAHOO_FLD_AUDIBLE_ID                    = 0xe6,
    YAHOO_FLD_AUDIBLE_TEXT                  = 0xe7,
    YAHOO_FLD_AUDIBLE_HASH                  = 0xe8,
    YAHOO_FLD_IGNORED_USER                  = 0xec,
    YAHOO_FLD_PROFILE_ID                    = 0xed,
    YAHOO_FLD_INVISIBLE_TO_FRIEND           = 0xee,
    YAHOO_FLD_VISIBLE_TO_FRIEND             = 0xef,
    YAHOO_FLD_CONTACT_INFO                  = 0xf0,
    YAHOO_FLD_CLOUD_ID                      = 0xf1,
    YAHOO_FLD_BRANDING_ID                   = 0xf2,
    YAHOO_FLD_NUM_ATTRIBUTED_BUDDIES        = 0xf3,
    YAHOO_FLD_CAPABILITY_MATRIX             = 0xf4,
    YAHOO_FLD_OBJECT_ID                     = 0xf5,
    YAHOO_FLD_OBJECT_NAME                   = 0xf6,
    YAHOO_FLD_META_DATA                     = 0xf7,
    YAHOO_FLD_OBJECT_SIZE                   = 0xf8,
    YAHOO_FLD_TRANSFER_TYPE                 = 0xf9,
    YAHOO_FLD_TRANSFER_TAG                  = 0xfa,
    YAHOO_FLD_TOKEN                         = 0xfb,
    YAHOO_FLD_HASH                          = 0xfc,
    YAHOO_FLD_CHECKSUM                      = 0xfd,
    YAHOO_FLD_LASTNAME                      = 0xfe,
    YAHOO_FLD_DATA                          = 0x101,
    YAHOO_FLD_APP_ID                        = 0x102,
    YAHOO_FLD_INSTANCE_ID                   = 0x103,
    YAHOO_FLD_ALERT_ID                      = 0x104,
    YAHOO_FLD_OPI_STATUS                    = 0x105,
    YAHOO_FLD_APP_REGISTER                  = 0x106,
    YAHOO_FLD_CHECK_LOGIN_STATUS            = 0x107,
    YAHOO_FLD_TARGET_GROUP                  = 0x108,
    YAHOO_FLD_FT_SESSION_ID                 = 0x109,
    YAHOO_FLD_TOTAL_FILE_COUNT              = 0x10a,
    YAHOO_FLD_THUMBNAIL                     = 0x10b,
    YAHOO_FLD_FILE_INFO                     = 0x10c,
    YAHOO_FLD_SPAMMER_ID                    = 0x10d,
    YAHOO_FLD_INITIATOR                     = 0x10e,
    YAHOO_FLD_FT_ONE_FILE_DONE              = 0x10f,
    YAHOO_FLD_X_POS                         = 0x110,
    YAHOO_FLD_Y_POS                         = 0x111,
    YAHOO_FLD_MSG_RECORD                    = 0x112,
    YAHOO_FLD_FLAG_MINGLE_USER              = 0x113,
    YAHOO_FLD_ABUSE_SIGNATURE               = 0x114,
    YAHOO_FLD_LOGIN_Y_COOKIE                = 0x115,
    YAHOO_FLD_LOGIN_T_COOKIE                = 0x116,
    YAHOO_FLD_LOGIN_CRUMB                   = 0x117,
    YAHOO_FLD_BUDDY_DETAIL                  = 0x118,
    YAHOO_FLD_VALID_CLIENT_COOKIES          = 0x119,
    YAHOO_FLD_NUM_LCS_BUDDIES               = 0x11a,
    YAHOO_FLD_IS_RELOGIN                    = 0x11b,
    YAHOO_FLD_START_OF_RECORD               = 0x12c,
    YAHOO_FLD_END_OF_RECORD                 = 0x12d,
    YAHOO_FLD_START_OF_LIST                 = 0x12e,
    YAHOO_FLD_END_OF_LIST                   = 0x12f,
    YAHOO_FLD_COUNTRYCODE                   = 0x130,
    YAHOO_FLD_PSTN_DID                      = 0x131,
    YAHOO_FLD_PSTN_PREMIUM_FLAG             = 0x132,
    YAHOO_FLD_CRUMB_HASH                    = 0x133,
    YAHOO_FLD_LOCALE                        = 0x136,
    YAHOO_FLD_PREFERENCES                   = 0x138,
    YAHOO_FLD_PREF_CATEGORY                 = 0x139,
    YAHOO_FLD_PREF_MASK                     = 0x13a,
    YAHOO_FLD_BUDDY_INFO                    = 0x13b,
    YAHOO_FLD_PLUGIN_INFO                   = 0x13c,
    YAHOO_FLD_VISIBILITY_FLAG               = 0x13d,
    YAHOO_FLD_GROUPS_RECORD_LIST            = 0x13e,
    YAHOO_FLD_BUDDIES_RECORD_LIST           = 0x13f,
    YAHOO_FLD_IGNORED_BUDDIES_RECORD_LIST   = 0x140,
    YAHOO_FLD_PREMIUM_SMS_RATE              = 0x141,
    YAHOO_FLD_PREMIUM_SMS_BALANCE           = 0x142,
    YAHOO_FLD_PREMIUM_SMS_SYMBOL            = 0x143,
    YAHOO_FLD_PREMIUM_SMS_SYMBOL_POS        = 0x144,
    YAHOO_FLD_PREMIUM_SMS_MAX_MSGS          = 0x145,
    YAHOO_FLD_NETSTAT_MSG                   = 0x3e8,
    YAHOO_FLD_SERVER_TYPE                   = 0x3e9,
    YAHOO_FLD_TRY_P2P                       = 0x3ea,
    YAHOO_FLD_P2P_CONN_STATE                = 0x3eb,
    YAHOO_FLD_INTERNET_CONN_TYPE            = 0x3ec,
    YAHOO_FLD_NEED_CMD_RETURN               = 0x3ed,
};

static const value_string ymsg_command_vals[] = {
    {YAHOO_CMD_USER_LOGIN,                "User Login"},
    {YAHOO_CMD_USER_LOGOFF,               "User Logoff"},
    {YAHOO_CMD_USER_AWAY,                 "User Away"},
    {YAHOO_CMD_USER_BACK,                 "User Back"},
    {YAHOO_CMD_USER_GET_MSGS,             "User Get Msgs"},
    {YAHOO_CMD_USER_HAS_MSG,              "User Has Msg"},
    {YAHOO_CMD_ACTIVATE_ID,               "Activate Id"},
    {YAHOO_CMD_DEACTIVATE_ID,             "Deactivate Id"},
    {YAHOO_CMD_GET_USER_STATUS,           "Get User Status"},
    {YAHOO_CMD_USER_HAS_MAIL,             "User Has Mail"},
    {YAHOO_CMD_START_CONFERENCE,          "Start Conference"},
    {YAHOO_CMD_CALENDAR_ALERT,            "Calendar Alert"},
    {YAHOO_CMD_USER_PERSONAL_MESSAGE,     "User Personal Message"},
    {YAHOO_CMD_UPDATE_BUDDY_LIST,         "Update Buddy List"},
    {YAHOO_CMD_UPDATE_ID_LIST,            "Update Id List"},
    {YAHOO_CMD_UPDATE_IGNORE_LIST,        "Update Ignore List"},
    {YAHOO_CMD_PING,                      "Ping"},
    {YAHOO_CMD_UPDATE_GROUP,              "Update Group"},
    {YAHOO_CMD_SYSTEM_MESSAGE,            "System Message"},
    {YAHOO_CMD_CLIENT_STATS,              "Client Stats"},
    {YAHOO_CMD_CLIENT_ALERT_STATS,        "Client Alert Stats"},
    {YAHOO_CMD_GROUP_MESSAGE,             "Group Message"},
    {YAHOO_CMD_HOST_CONFERENCE,           "Host Conference"},
    {YAHOO_CMD_JOIN_CONFERENCE,           "Join Conference"},
    {YAHOO_CMD_DECLINE_CONFERENCE,        "Decline Conference"},
    {YAHOO_CMD_LEAVE_CONFERENCE,          "Leave Conference"},
    {YAHOO_CMD_INVITE_CONFERENCE,         "Invite Conference"},
    {YAHOO_CMD_SAY_CONFERENCE,            "Say Conference"},
    {YAHOO_CMD_CHAT_LOGIN,                "Chat Login"},
    {YAHOO_CMD_CHAT_LOGOFF,               "Chat Logoff"},
    {YAHOO_CMD_CHAT_MSG,                  "Chat Message"},
    {YAHOO_CMD_GAMES_USER_LOGIN,          "Games User Login"},
    {YAHOO_CMD_GAMES_USER_LOGOFF,         "Games User Logoff"},
    {YAHOO_CMD_GAMES_USER_HAS_MSG,        "Games User Has Msg"},
    {YAHOO_CMD_NET2PHONE_STATS,           "Net2Phone Stats"},
    {YAHOO_CMD_ADDRESS_BOOK_ALERT,        "Address Book Alert"},
    {YAHOO_CMD_AUCTION_ALERT,             "Auction Alert"},
    {YAHOO_CMD_USER_FT,                   "User File Transfer"},
    {YAHOO_CMD_USER_FT_REPLY,             "User File Transfer Reply"},
    {YAHOO_CMD_USER_CONVERSE,             "User Converse"},
    {YAHOO_CMD_USER_WEB_TOUR,             "User Web Tour"},
    {YAHOO_CMD_IM_ENABLE_VOICE,           "IM Enable Voice"},
    {YAHOO_CMD_USER_SEND_MSG,             "User Send Msg"},
    {YAHOO_CMD_SEND_PORT_CHECK,           "Send Port Check"},
    {YAHOO_CMD_SEND_DATA_THRU,            "Send Data Thru"},
    {YAHOO_CMD_P2P_START,                 "P2P Start"},
    {YAHOO_CMD_MSGR_WEBCAM_TOKEN,         "Msgr Webcam Token"},
    {YAHOO_CMD_STATS,                     "Stats"},
    {YAHOO_CMD_USER_LOGIN2,               "User Login2"},
    {YAHOO_CMD_PRE_LOGIN_DATA,            "PreLogin Data"},
    {YAHOO_CMD_GET_COOKIE_DATA,           "Get Cookie Data"},
    {YAHOO_CMD_HELO,                      "HELO"},
    {YAHOO_CMD_FEATURE_NOT_SUPPORTED,     "Feature Not Supported"},
    {YAHOO_CMD_ADD_BUDDY,                 "Add Buddy"},
    {YAHOO_CMD_REMOVE_BUDDY,              "Remove Buddy"},
    {YAHOO_CMD_MODIFY_IGNORE_LIST,        "Modify Ignore List"},
    {YAHOO_CMD_DENY_BUDDY_ADD,            "Deny Buddy Add"},
    {YAHOO_CMD_RENAME_GROUP,              "Rename Group"},
    {YAHOO_CMD_KEEP_ALIVE,                "Keep Alive"},
    {YAHOO_CMD_YPC_ADD_FRIEND_APPROVAL,   "YPC Add Friend Approval"},
    {YAHOO_CMD_CHALLENGE,                 "Challenge"},
    {YAHOO_CMD_ADD_BUDDY_INSTANT_APPROVAL,"Add Buddy Instant Approval"},
    {YAHOO_CMD_CHAT_MSGR_USER_LOGIN,      "Chat Msgr User Login"},
    {YAHOO_CMD_CHAT_GOTO_USER,            "Chat Goto User"},
    {YAHOO_CMD_CHAT_ROOM_JOIN,            "Chat Room Join"},
    {YAHOO_CMD_CHAT_ROOM_PART,            "Chat Room Part"},
    {YAHOO_CMD_CHAT_ROOM_INVITE,          "Chat Room Invite"},
    {YAHOO_CMD_CHAT_MSGR_USER_LOGOFF,     "Chat Msgr User Logoff"},
    {YAHOO_CMD_CHAT_PING,                 "Chat Ping"},
    {YAHOO_CMD_CHAT_WEBCAM_TOKEN,         "Chat Webcam Token"},
    {YAHOO_CMD_CHAT_PUBLIC_MSG,           "Chat Public Msg"},
    {YAHOO_CMD_CHAT_ROOM_CREATE,          "Chat Room Create"},
    {YAHOO_CMD_GAMES_INVITE,              "Games Invite"},
    {YAHOO_CMD_GAMES_SEND_DATA,           "Games Send Data"},
    {YAHOO_CMD_EDIT_INVISIBLE_TO_LIST,    "Edit Invisible To List"},
    {YAHOO_CMD_EDIT_VISIBLE_TO_LIST,      "Edit Visible To List"},
    {YAHOO_CMD_ANTI_BOT,                  "Anti Bot"},
    {YAHOO_CMD_AVATAR_CHANGED,            "Avatar Changed"},
    {YAHOO_CMD_FRIEND_ICON,               "Friend Icon"},
    {YAHOO_CMD_FRIEND_ICON_DOWNLOAD,      "Friend Icon Download"},
    {YAHOO_CMD_AVATAR_GET_FILE,           "Avatar Get File"},
    {YAHOO_CMD_AVATAR_GET_HASH,           "Avatar Get Hash"},
    {YAHOO_CMD_DISPLAY_TYPE_CHANGED,      "Display Type Changed"},
    {YAHOO_CMD_FRIEND_ICON_FT,            "Friend Icon File Transfer"},
    {YAHOO_CMD_GET_COOKIE,                "Get Cookie"},
    {YAHOO_CMD_ADDRESS_BOOK_CHANGED,      "Address Book Changed"},
    {YAHOO_CMD_SET_VISIBILITY,            "Set Visibility"},
    {YAHOO_CMD_SET_AWAY_STATUS,           "Set Away Status"},
    {YAHOO_CMD_DISPLAY_IMAGE_PREFS,       "Display Image Prefs"},
    {YAHOO_CMD_VERIFY_USER,               "Verify User"},
    {YAHOO_CMD_AUDIBLE,                   "Audible"},
    {YAHOO_CMD_IM_PANEL_FEATURE,          "IM Panel Feature"},
    {YAHOO_CMD_SHARE_CONTACTS,            "Share Contacts"},
    {YAHOO_CMD_IM_SESSION,                "IM Session"},
    {YAHOO_CMD_SUBSCRIPTION,              "Subscription"},
    {YAHOO_CMD_BUDDY_AUTHORIZE,           "Buddy Authorize"},
    {YAHOO_CMD_PHOTO_ADD,                 "Photo Add"},
    {YAHOO_CMD_PHOTO_SELECT,              "Photo Select"},
    {YAHOO_CMD_PHOTO_DELETE,              "Photo Delete"},
    {YAHOO_CMD_PHOTO_FILE_REQUEST,        "Photo File Request"},
    {YAHOO_CMD_PHOTO_POINTER,             "Photo Pointer"},
    {YAHOO_CMD_FXFER_INVITE,              "File Transfer Invite"},
    {YAHOO_CMD_FXFER_SEND,                "File Transfer Send"},
    {YAHOO_CMD_FXFER_RECEIVE,             "File Transfer Receive"},
    {YAHOO_CMD_UPDATE_CAPABILITY,         "Update Capability"},
    {YAHOO_CMD_REPORT_SPAM,               "Report Spam"},
    {YAHOO_CMD_MINGLE_DATA,               "Mingle Data"},
    {YAHOO_CMD_ALERT,                     "Alert"},
    {YAHOO_CMD_APP_REGISTRY,              "App Registry"},
    {YAHOO_CMD_NEW_USER,                  "New User"},
    {YAHOO_CMD_ACCEPT_MSGR_INVITE,        "Accept Msgr Invite"},
    {YAHOO_CMD_MSGR_USAGE,                "Msgr Usage"},
    {YAHOO_CMD_BUDDY_MOVE,                "Buddy Move"},
    {YAHOO_CMD_GET_VOICE_CRUMB,           "Get Voice Crumb"},
    {YAHOO_CMD_PLUGIN_SESSION_INITIATION, "Plugin Session Initiation"},
    {YAHOO_CMD_APPLICATION_MESSAGE,       "Application Message"},
    {YAHOO_CMD_APPLICATION_PRESENCE,      "Application Presence"},
    {YAHOO_CMD_FXFER_PLUGIN_INVITE,       "File Transfer Plugin Invite"},
    {YAHOO_CMD_PC2MOBILE_FXFER,           "PC2Mobile File Transfer"},
    {YAHOO_CMD_PREFERENCE,                "Preference"},
    {YAHOO_CMD_BUDDY_INFO,                "Buddy Info"},
    {YAHOO_CMD_BUDDY_LIST,                "Buddy List"},
    {YAHOO_CMD_CHECK_PREMIUM_SMS_BALANCE, "Check Premium SMS Balance"},
    {YAHOO_CMD_WIDGET_BUDDY_LIST,         "Widget Buddy List"},
    {YAHOO_CMD_WIDGET_BUDDY_INFO,         "Widget Buddy Info"},
    {YAHOO_CMD_WIDGET_ACTION,             "Widget Action"},
    {YAHOO_CMD_NEWS_ALERTS,               "News Alerts"},
    {YAHOO_CMD_CORP_USER_LOGIN,           "Corp User Login"},
    {YAHOO_CMD_MSG_RE_LOGIN,              "Msgr ReLogin"},
    {YAHOO_CMD_CORP_ID_COPR_P2P_INIT,     "Corp Id Copr P2P Init"},
    {YAHOO_CMD_CORP_CHAT_MSG,             "Corp Chat Msg"},
    {YAHOO_CMD_CORP_GAMES_USER_HAS_MSG,   "Corp Games User Has Msg"},
    {YAHOO_CMD_SECURE_USER_LOGIN,         "Secure User Login"},
    {YAHOO_CMD_SECURE_IM_MSG,             "Secure IM Msg"},
    {YAHOO_CMD_SECURE_CHAT_SAY_MSG,       "Secure Chat Say Msg"},
    {YAHOO_CMD_SECURE_GAMES_USER_HAS_MSG, "Secure Games User Has Msg"},
    {YAHOO_CMD_SYMANTEC_MSGS,             "Symantec Msgs"},
    {YAHOO_CMD_MOBILE_SEND_SMS_MESSAGE,   "Mobile Send SMS Message"},
    {YAHOO_CMD_MOBILE_SMS_LOGIN,          "Mobile SMS Login"},
    {YAHOO_CMD_MOBILE_SMS_NUMBER,         "Mobile SMS Number"},
    {YAHOO_CMD_ANON_LOGOFF,               "Anon Logoff"},
    {YAHOO_CMD_ANON_HAS_MSG,              "Anon Has Msg"},
    {YAHOO_CMD_CLIENT_NETSTAT,            "Client Netstat"},
    {YAHOO_CMD_P2P_USER,                  "P2P User"},
    {YAHOO_CMD_P2P_STATE,                 "P2P State"},
    {YAHOO_CMD_LWM_LOGIN,                 "LWM Login"},
    {YAHOO_CMD_LWM_LOGOFF,                "LWM Logoff"},
    {YAHOO_CMD_OPI_LOGIN,                 "OPI Login"},
    {YAHOO_CMD_OPI_LOGOFF,                "OPI Logoff"},
    {YAHOO_CMD_OPI_IM,                    "OPI IM"},
    {YAHOO_CMD_USER_HAS_OPI_MESSAGE,      "User Has OPI Message"},
    {YAHOO_CMD_LWMOPI_CHECK_LOGIN,        "LWM OPI Check Login"},
    {YAHOO_CMD_LWMOPI_START_OPI,          "LWM OPI Start OPI"},
    {YAHOO_CMD_LWMOPI_STOP_OPI,           "LWM OPI Stop OPI"},
    {0, NULL},
};

static const value_string ymsg_status_vals[] = {
    {YAHOO_STATUS_DUPLICATE,            "Duplicate"},
    {YAHOO_STATUS_ERR,                  "Error"},
    {YAHOO_STATUS_OK,                   "Ok"},
    {YAHOO_STATUS_NOTIFY,               "Notify"},
    {YAHOO_STATUS_NOT_AVAILABLE,        "Not Available"},
    {YAHOO_STATUS_NEW_BUDDYOF,          "New BuddyOf"},
    {YAHOO_STATUS_PARTIAL_LIST,         "Partial List"},
    {YAHOO_STATUS_SAVED_MSG,            "Saved Msg"},
    {YAHOO_STATUS_BUDDYOF_DENIED,       "BuddyOf Denied"},
    {YAHOO_STATUS_INVALID_USER,         "Invalid User"},
    {YAHOO_STATUS_CHUNKING,             "Chunking"},
    {YAHOO_STATUS_INVITED,              "Invited"},
    {YAHOO_STATUS_DONT_DISTURB,         "Do Not Disturb"},
    {YAHOO_STATUS_DISTURB_ME,           "Disturb Me"},
    {YAHOO_STATUS_NEW_BUDDYOF_AUTH,     "New BuddyOf Auth"},
    {YAHOO_STATUS_WEB_MSG,              "Web Msg"},
    {YAHOO_STATUS_ACK,                  "Ack"},
    {YAHOO_STATUS_RE_LOGIN,             "ReLogin"},
    {YAHOO_STATUS_SPECIFIC_SNDR,        "Specific Sender"},
    {YAHOO_STATUS_INCOMP_VERSION,       "Incompatible Version"},
    {YAHOO_STATUS_REQUEST,              "Request"},
    {YAHOO_STATUS_SMS_CARRIER,          "SMS Carrier"},
    {YAHOO_STATUS_IS_GROUP_IM,          "Is Group IM"},
    {YAHOO_STATUS_PRE_LOGIN_SUCCEEDED,  "PreLogin Succeeded"},
    {YAHOO_STATUS_SERVER_CONNECTED,     "Server Connected"},
    {YAHOO_STATUS_FD_CONNECT_SUCCESS,   "FD Connect Success"},
    {YAHOO_STATUS_CMD_SENT_ACK,         "CMD Sent Ack"},
    {YAHOO_STATUS_UNKNOWN_USER,         "Unknown User"},
    {YAHOO_STATUS_KNOWN_USER,           "Known User"},
    {0, NULL},
};

static const value_string ymsg_field_vals[] = {
    {YAHOO_FLD_USERNAME,                      "Username"},
    {YAHOO_FLD_CURRENT_ID,                    "CurrentId"},
    {YAHOO_FLD_ACTIVE_ID,                     "ActiveId"},
    {YAHOO_FLD_USER_ID,                       "UserId"},
    {YAHOO_FLD_SENDER,                        "Sender"},
    {YAHOO_FLD_TARGET_USER,                   "TargetUser"},
    {YAHOO_FLD_PASSWORD,                      "Password"},
    {YAHOO_FLD_BUDDY,                         "Buddy"},
    {YAHOO_FLD_NUM_BUDDIES,                   "NumBuddies"},
    {YAHOO_FLD_NUM_EMAILS,                    "NumEmails"},
    {YAHOO_FLD_AWAY_STATUS,                   "AwayStatus"},
    {YAHOO_FLD_SESSION_ID,                    "SessionId"},
    {YAHOO_FLD_IP_ADDRESS,                    "IPAddress"},
    {YAHOO_FLD_FLAG,                          "Flag"},
    {YAHOO_FLD_MSG,                           "Msg"},
    {YAHOO_FLD_TIME,                          "Time"},
    {YAHOO_FLD_ERR_MSG,                       "ErrMsg"},
    {YAHOO_FLD_PORT,                          "Port"},
    {YAHOO_FLD_MAIL_SUBJECT,                  "MailSubject"},
    {YAHOO_FLD_AWAY_MSG,                      "AwayMsg"},
    {YAHOO_FLD_URL,                           "URL"},
    {YAHOO_FLD_ALERT_TIME,                    "AlertTime"},
    {YAHOO_FLD_NEWS,                          "News"},
    {YAHOO_FLD_DEV_SPEED,                     "DevSpeed"},
    {YAHOO_FLD_WEB_ID,                        "WebId"},
    {YAHOO_FLD_USER_ALERT_STATS,              "UserAlertStats"},
    {YAHOO_FLD_STATS_DATA,                    "StatsData"},
    {YAHOO_FLD_FILE_NAME,                     "FileName"},
    {YAHOO_FLD_FILE_SIZE,                     "FileSize"},
    {YAHOO_FLD_FILE_DATA,                     "FileData"},
    {YAHOO_FLD_SYMANTEC_IPADDR,               "SymantecIPAddr"},
    {YAHOO_FLD_COMMAND,                       "Command"},
    {YAHOO_FLD_STATUS,                        "Status"},
    {YAHOO_FLD_NUM_NEWS,                      "NumNews"},
    {YAHOO_FLD_NUM_MSGS,                      "NumMsgs"},
    {YAHOO_FLD_ITEM,                          "Item"},
    {YAHOO_FLD_OLD_GRP_NAME,                  "OldGrpName"},
    {YAHOO_FLD_NEW_GRP_NAME,                  "NewGrpName"},
    {YAHOO_FLD_EXPIRATION_TIME,               "ExpirationTime"},
    {YAHOO_FLD_NUM_PERSONAL_MSGS,             "NumPersonalMsgs"},
    {YAHOO_FLD_SYS_MSG_CODE,                  "SysMsgCode"},
    {YAHOO_FLD_MSG_NUM_DUMMY,                 "MsgNumDummy"},
    {YAHOO_FLD_FROM_EMAIL,                    "FromEmail"},
    {YAHOO_FLD_FROM_NAME,                     "FromName"},
    {YAHOO_FLD_ADD_ID,                        "AddId"},
    {YAHOO_FLD_DELETE_ID,                     "DeleteId"},
    {YAHOO_FLD_DEBUG_INFO,                    "DebugInfo"},
    {YAHOO_FLD_CUSTOM_DND_STATUS,             "CustomDndStatus"},
    {YAHOO_FLD_CONTAINS_TAGS,                 "ContainsTags"},
    {YAHOO_FLD_APP_NAME,                      "AppName"},
    {YAHOO_FLD_INVITOR_NAME,                  "InvitorName"},
    {YAHOO_FLD_NET2PHONE_CALL_LEN,            "Net2PhoneCallLen"},
    {YAHOO_FLD_INVITEE_NAME,                  "InviteeName"},
    {YAHOO_FLD_AD_SPACE_ID,                   "AdSpaceId"},
    {YAHOO_FLD_INVITED_USER,                  "InvitedUser"},
    {YAHOO_FLD_USES_IMIP_CLIENT,              "UsesIMIPClient"},
    {YAHOO_FLD_JOINED_USER,                   "JoinedUser"},
    {YAHOO_FLD_SHORTCUT,                      "Shortcut"},
    {YAHOO_FLD_DECLINED_USER,                 "DeclinedUser"},
    {YAHOO_FLD_FEED_VER,                      "FeedVer"},
    {YAHOO_FLD_UNAVAILABLE_USER,              "UnavailableUser"},
    {YAHOO_FLD_LEFT_USER,                     "LeftUser"},
    {YAHOO_FLD_ROOM_NAME,                     "RoomName"},
    {YAHOO_FLD_CONF_TOPIC,                    "ConfTopic"},
    {YAHOO_FLD_COOKIE,                        "Cookie"},
    {YAHOO_FLD_DEVICE_TYPE,                   "DeviceType"},
    {YAHOO_FLD_USER_TYPE,                     "UserType"},
    {YAHOO_FLD_WEBCAM_TOKEN,                  "WebcamToken"},
    {YAHOO_FLD_TIMED_P2P_CONN_FLG,            "TimedP2PConnFlg"},
    {YAHOO_FLD_WEBCAM_STATUS,                 "WebcamStatus"},
    {YAHOO_FLD_IMV_ID,                        "IMVId"},
    {YAHOO_FLD_IMV_FLAG,                      "IMVFlag"},
    {YAHOO_FLD_BUDDY_GRP_NAME,                "BuddyGrpName"},
    {YAHOO_FLD_ERROR_CODE,                    "ErrorCode"},
    {YAHOO_FLD_NEW_BUDDY_GRP_NAME,            "NewBuddyGrpName"},
    {YAHOO_FLD_PHONE_CARRIER_CODE,            "PhoneCarrierCode"},
    {YAHOO_FLD_SCREEN_NAME,                   "ScreenName"},
    {YAHOO_FLD_CONVERSE_COMMAND,              "ConverseCommand"},
    {YAHOO_FLD_SMS_PHONE,                     "SmsPhone"},
    {YAHOO_FLD_CONVERSE_IDENTITY,             "ConverseIdentity"},
    {YAHOO_FLD_CONVERSE_OTHER_GUY,            "ConverseOtherGuy"},
    {YAHOO_FLD_CONVERSE_TOPIC,                "ConverseTopic"},
    {YAHOO_FLD_CONVERSE_COMMENT,              "ConverseComment"},
    {YAHOO_FLD_CONVERSE_MAX,                  "ConverseMax"},
    {YAHOO_FLD_CONVERSE_URL,                  "ConverseUrl"},
    {YAHOO_FLD_CONVERSE_YOUR_COMMENT,         "ConverseYourComment"},
    {YAHOO_FLD_STAT_TYPE,                     "StatType"},
    {YAHOO_FLD_IMIP_SERVICE,                  "IMIPService"},
    {YAHOO_FLD_IMIP_LOGIN,                    "IMIPLogin"},
    {YAHOO_FLD_ALERT_TYPE_ID,                 "AlertTypeId"},
    {YAHOO_FLD_ALERT_SUBTYPE_ID,              "AlertSubtypeId"},
    {YAHOO_FLD_ALERT_DOC_TITLE,               "AlertDocTitle"},
    {YAHOO_FLD_ALERT_PRIO_LEVEL,              "AlertPrioLevel"},
    {YAHOO_FLD_ALERT_TYPE,                    "AlertType"},
    {YAHOO_FLD_ALERT_COUNTRY,                 "AlertCountry"},
    {YAHOO_FLD_BUDDY_LIST,                    "BuddyList"},
    {YAHOO_FLD_IGNORE_LIST,                   "IgnoreList"},
    {YAHOO_FLD_IDENTITY_LIST,                 "IdentityList"},
    {YAHOO_FLD_HAS_MAIL,                      "HasMail"},
    {YAHOO_FLD_CONVERSE_CMD_DEC_TEXT,         "ConverseCmdDecText"},
    {YAHOO_FLD_ANON_NAME,                     "AnonName"},
    {YAHOO_FLD_ANON_ID,                       "AnonId"},
    {YAHOO_FLD_T_COOKIE_EXPIRE,               "TCookieExpire"},
    {YAHOO_FLD_CHALLENGE,                     "Challenge"},
    {YAHOO_FLD_OLD_PASSWORD,                  "OldPassword"},
    {YAHOO_FLD_UTF8_FLAG,                     "Utf8Flag"},
    {YAHOO_FLD_COUNTRY_CODE,                  "CountryCode"},
    {YAHOO_FLD_CO_BRAND_CODE,                 "CoBrandCode"},
    {YAHOO_FLD_DATE,                          "Date"},
    {YAHOO_FLD_IMV_DATA,                      "ImvData"},
    {YAHOO_FLD_WEBCAM_FARM,                   "WebcamFarm"},
    {YAHOO_FLD_CHAT_IGNORE_USER,              "ChatIgnoreUser"},
    {YAHOO_FLD_CHAT_ROOM_NAME,                "ChatRoomName"},
    {YAHOO_FLD_CHAT_ROOM_TOPIC,               "ChatRoomTopic"},
    {YAHOO_FLD_CHAT_ROOM_URL,                 "ChatRoomUrl"},
    {YAHOO_FLD_CHAT_ROOM_PARAMETER,           "ChatRoomParameter"},
    {YAHOO_FLD_CHAT_NUM_USERS,                "ChatNumUsers"},
    {YAHOO_FLD_CHAT_ROOM_USERNAME,            "ChatRoomUsername"},
    {YAHOO_FLD_CHAT_ROOM_USER_AGE,            "ChatRoomUserAge"},
    {YAHOO_FLD_CHAT_ROOM_USER_GENDER,         "ChatRoomUserGender"},
    {YAHOO_FLD_CHAT_ROOM_USER_TIMESTAMP,      "ChatRoomUserTimestamp"},
    {YAHOO_FLD_CHAT_ROOM_USER_FLAG,           "ChatRoomUserFlag"},
    {YAHOO_FLD_CHAT_ERR_NO,                   "ChatErrNo"},
    {YAHOO_FLD_CHAT_SIMILAR_ROOM,             "ChatSimilarRoom"},
    {YAHOO_FLD_CHAT_EMOT_MSG,                 "ChatEmotMsg"},
    {YAHOO_FLD_CHAT_MSG,                      "ChatMsg"},
    {YAHOO_FLD_CHAT_INVITED_USER,             "ChatInvitedUser"},
    {YAHOO_FLD_CHAT_INVITER,                  "ChatInviter"},
    {YAHOO_FLD_CHAT_EXTENDED_DATA_ID,         "ChatExtendedDataId"},
    {YAHOO_FLD_CHAT_EXTENDED_DATA,            "ChatExtendedData"},
    {YAHOO_FLD_CHAT_USER_SETTINGS,            "ChatUserSettings"},
    {YAHOO_FLD_CHAT_LOGOFF_MSG,               "ChatLogoffMsg"},
    {YAHOO_FLD_CHAT_MSG_TYPE,                 "ChatMsgType"},
    {YAHOO_FLD_CHAT_FRAME_NAME,               "ChatFrameName"},
    {YAHOO_FLD_CHAT_FLG,                      "ChatFlag"},
    {YAHOO_FLD_CHAT_ROOM_TYPE,                "ChatRoomType"},
    {YAHOO_FLD_CHAT_ROOM_CATEGORY,            "ChatRoomCategory"},
    {YAHOO_FLD_CHAT_ROOM_SPACE_ID,            "ChatRoomSpaceId"},
    {YAHOO_FLD_CHAT_VOICE_AUTH,               "ChatVoiceAuth"},
    {YAHOO_FLD_ALERT_BUTTON_LABEL,            "AlertButtonLabel"},
    {YAHOO_FLD_ALERT_BUTTON_LINK,             "AlertButtonLink"},
    {YAHOO_FLD_ALERT_MIN_DIMENSION,           "AlertMinDimension"},
    {YAHOO_FLD_BIZ_MAIL_TEXT,                 "BizMailText"},
    {YAHOO_FLD_VERSION,                       "Version"},
    {YAHOO_FLD_CO_BRAND_ROOM_INFO,            "CoBrandRoomInfo"},
    {YAHOO_FLD_IDLE_TIME,                     "IdleTime"},
    {YAHOO_FLD_NO_IDLE_TIME,                  "NoIdleTime"},
    {YAHOO_FLD_CHAT_USER_NICKNAME,            "ChatUserNickname"},
    {YAHOO_FLD_CHAT_USER_LOCATION,            "ChatUserLocation"},
    {YAHOO_FLD_PING_INTERVAL,                 "PingInterval"},
    {YAHOO_FLD_KEEP_ALIVE_INTERVAL,           "KeepAliveInterval"},
    {YAHOO_FLD_CPU_TYPE,                      "CPUType"},
    {YAHOO_FLD_OS_VERSION,                    "OsVersion"},
    {YAHOO_FLD_TIME_ZONE,                     "TimeZone"},
    {YAHOO_FLD_TIME_BIAS,                     "TimeBias"},
    {YAHOO_FLD_BLINDED_USER_ID,               "BlindedUserId"},
    {YAHOO_FLD_CACHE_CRYPTO_KEY,              "CacheCryptoKey"},
    {YAHOO_FLD_LOCAL_CRYPTO_KEY,              "LocalCryptoKey"},
    {YAHOO_FLD_YPC_PREFS,                     "YPCPrefs"},
    {YAHOO_FLD_PARENT_ID,                     "ParentId"},
    {YAHOO_FLD_MSG_NUM,                       "MsgNum"},
    {YAHOO_FLD_EE_CONFIRM_DELIVERY,           "EeConfirmDelivery"},
    {YAHOO_FLD_EE_SENDER,                     "EeSender"},
    {YAHOO_FLD_EE_NONCE,                      "EeNonce"},
    {YAHOO_FLD_GAME_ID,                       "GameId"},
    {YAHOO_FLD_GAME_NAME,                     "GameName"},
    {YAHOO_FLD_GAME_DATA,                     "GameData"},
    {YAHOO_FLD_GAME_URL,                      "GameUrl"},
    {YAHOO_FLD_STATUS_DATA,                   "StatusData"},
    {YAHOO_FLD_INVISIBLE_TO,                  "InvisibleTo"},
    {YAHOO_FLD_VISIBLE_TO,                    "VisibleTo"},
    {YAHOO_FLD_STATUS_LINK_TYPE,              "StatusLinkType"},
    {YAHOO_FLD_AVATAR_FLAG,                   "AvatarFlag"},
    {YAHOO_FLD_AVATAR_MOOD_ID,                "AvatarMoodId"},
    {YAHOO_FLD_ICON_CHECKSUM,                 "IconChecksum"},
    {YAHOO_FLD_ICON_DATA,                     "IconData"},
    {YAHOO_FLD_SEQUENCE_NO,                   "SequenceNo"},
    {YAHOO_FLD_MAX_SEQUENCE_NO,               "MaxSequenceNo"},
    {YAHOO_FLD_ANTI_BOT_TEXT,                 "AntiBotText"},
    {YAHOO_FLD_AVATAR_HASH,                   "AvatarHash"},
    {YAHOO_FLD_AVATAR_USER,                   "AvatarUser"},
    {YAHOO_FLD_WIDTH,                         "Width"},
    {YAHOO_FLD_HEIGHT,                        "Height"},
    {YAHOO_FLD_ALERT_DATA,                    "AlertData"},
    {YAHOO_FLD_AVATAR_DEF_MOOD,               "AvatarDefMood"},
    {YAHOO_FLD_AVATAR_ZOOM,                   "AvatarZoom"},
    {YAHOO_FLD_DISPLAY_TYPE,                  "DisplayType"},
    {YAHOO_FLD_BT_USER_ID,                    "BTUserId"},
    {YAHOO_FLD_T_COOKIE,                      "TCookie"},
    {YAHOO_FLD_STATS_BUFFER,                  "StatsBuffer"},
    {YAHOO_FLD_APPLY_TO_ALL,                  "ApplyToAll"},
    {YAHOO_FLD_SHOW_MY_AVATAR_IN_FRIEND_TREE, "ShowMyAvatarInFriendTree"},
    {YAHOO_FLD_GAME_PROWLER_PREF,             "GameProwlerPref"},
    {YAHOO_FLD_VAS_USER,                      "VASUser"},
    {YAHOO_FLD_FIRSTNAME,                     "Firstname"},
    {YAHOO_FLD_YPM_KEY,                       "YPMKey"},
    {YAHOO_FLD_COOKIE_CUTTER,                 "CookieCutter"},
    {YAHOO_FLD_FEATURE_ID,                    "FeatureId"},
    {YAHOO_FLD_ACTION_TYPE,                   "ActionType"},
    {YAHOO_FLD_UNAUTH,                        "UnAuth"},
    {YAHOO_FLD_GROUP,                         "Group"},
    {YAHOO_FLD_ANTI_BOT_URL,                  "AntiBotUrl"},
    {YAHOO_FLD_ANTI_BOT_SECRET,               "AntiBotSecret"},
    {YAHOO_FLD_ANTI_BOT_RESPONSE,             "AntiBotResponse"},
    {YAHOO_FLD_AUDIBLE_ID,                    "AudibleId"},
    {YAHOO_FLD_AUDIBLE_TEXT,                  "AudibleText"},
    {YAHOO_FLD_AUDIBLE_HASH,                  "AudibleHash"},
    {YAHOO_FLD_IGNORED_USER,                  "IgnoredUser"},
    {YAHOO_FLD_PROFILE_ID,                    "ProfileId"},
    {YAHOO_FLD_INVISIBLE_TO_FRIEND,           "InvisibleToFriend"},
    {YAHOO_FLD_VISIBLE_TO_FRIEND,             "VisibleToFriend"},
    {YAHOO_FLD_CONTACT_INFO,                  "ContactInfo"},
    {YAHOO_FLD_CLOUD_ID,                      "CloudId"},
    {YAHOO_FLD_BRANDING_ID,                   "BrandingId"},
    {YAHOO_FLD_NUM_ATTRIBUTED_BUDDIES,        "NumAttributedBuddies"},
    {YAHOO_FLD_CAPABILITY_MATRIX,             "CapabilityMatrix"},
    {YAHOO_FLD_OBJECT_ID,                     "ObjectId"},
    {YAHOO_FLD_OBJECT_NAME,                   "ObjectName"},
    {YAHOO_FLD_META_DATA,                     "MetaData"},
    {YAHOO_FLD_OBJECT_SIZE,                   "ObjectSize"},
    {YAHOO_FLD_TRANSFER_TYPE,                 "TransferType"},
    {YAHOO_FLD_TRANSFER_TAG,                  "TransferTag"},
    {YAHOO_FLD_TOKEN,                         "Token"},
    {YAHOO_FLD_HASH,                          "Hash"},
    {YAHOO_FLD_CHECKSUM,                      "Checksum"},
    {YAHOO_FLD_LASTNAME,                      "Lastname"},
    {YAHOO_FLD_DATA,                          "Data"},
    {YAHOO_FLD_APP_ID,                        "AppId"},
    {YAHOO_FLD_INSTANCE_ID,                   "InstanceId"},
    {YAHOO_FLD_ALERT_ID,                      "AlertId"},
    {YAHOO_FLD_OPI_STATUS,                    "OpiStatus"},
    {YAHOO_FLD_APP_REGISTER,                  "AppRegister"},
    {YAHOO_FLD_CHECK_LOGIN_STATUS,            "CheckLoginStatus"},
    {YAHOO_FLD_TARGET_GROUP,                  "TargetGroup"},
    {YAHOO_FLD_FT_SESSION_ID,                 "FtSessionId"},
    {YAHOO_FLD_TOTAL_FILE_COUNT,              "TotalFileCount"},
    {YAHOO_FLD_THUMBNAIL,                     "Thumbnail"},
    {YAHOO_FLD_FILE_INFO,                     "FileInfo"},
    {YAHOO_FLD_SPAMMER_ID,                    "SpammerId"},
    {YAHOO_FLD_INITIATOR,                     "Initiator"},
    {YAHOO_FLD_FT_ONE_FILE_DONE,              "FtOneFileDone"},
    {YAHOO_FLD_X_POS,                         "XPos"},
    {YAHOO_FLD_Y_POS,                         "YPos"},
    {YAHOO_FLD_MSG_RECORD,                    "MsgRecord"},
    {YAHOO_FLD_FLAG_MINGLE_USER,              "FlagMingleUser"},
    {YAHOO_FLD_ABUSE_SIGNATURE,               "AbuseSignature"},
    {YAHOO_FLD_LOGIN_Y_COOKIE,                "LoginYCookie"},
    {YAHOO_FLD_LOGIN_T_COOKIE,                "LoginTCookie"},
    {YAHOO_FLD_LOGIN_CRUMB,                   "LoginCrumb"},
    {YAHOO_FLD_BUDDY_DETAIL,                  "BuddyDetail"},
    {YAHOO_FLD_VALID_CLIENT_COOKIES,          "ValidClientCookies"},
    {YAHOO_FLD_NUM_LCS_BUDDIES,               "NumLcsBuddies"},
    {YAHOO_FLD_IS_RELOGIN,                    "IsReLogin"},
    {YAHOO_FLD_START_OF_RECORD,               "StartOfRecord"},
    {YAHOO_FLD_END_OF_RECORD,                 "EndOfRecord"},
    {YAHOO_FLD_START_OF_LIST,                 "StartOfList"},
    {YAHOO_FLD_END_OF_LIST,                   "EndOfList"},
    {YAHOO_FLD_COUNTRYCODE,                   "Countrycode"},
    {YAHOO_FLD_PSTN_DID,                      "PSTNDid"},
    {YAHOO_FLD_PSTN_PREMIUM_FLAG,             "PSTNPremiumFlag"},
    {YAHOO_FLD_CRUMB_HASH,                    "CrumbHash"},
    {YAHOO_FLD_LOCALE,                        "Locale"},
    {YAHOO_FLD_PREFERENCES,                   "Preferences"},
    {YAHOO_FLD_PREF_CATEGORY,                 "PrefCategory"},
    {YAHOO_FLD_PREF_MASK,                     "PrefMask"},
    {YAHOO_FLD_BUDDY_INFO,                    "BuddyInfo"},
    {YAHOO_FLD_PLUGIN_INFO,                   "PluginInfo"},
    {YAHOO_FLD_VISIBILITY_FLAG,               "VisibilityFlag"},
    {YAHOO_FLD_GROUPS_RECORD_LIST,            "GroupsRecordList"},
    {YAHOO_FLD_BUDDIES_RECORD_LIST,           "BuddiesRecordList"},
    {YAHOO_FLD_IGNORED_BUDDIES_RECORD_LIST,   "IgnoredBuddiesRecordList"},
    {YAHOO_FLD_PREMIUM_SMS_RATE,              "PremiumSmsRate"},
    {YAHOO_FLD_PREMIUM_SMS_BALANCE,           "PremiumSmsBalance"},
    {YAHOO_FLD_PREMIUM_SMS_SYMBOL,            "PremiumSmsSymbol"},
    {YAHOO_FLD_PREMIUM_SMS_SYMBOL_POS,        "PremiumSmsSymbolPos"},
    {YAHOO_FLD_PREMIUM_SMS_MAX_MSGS,          "PremiumSmsMaxMsgs"},
    {YAHOO_FLD_NETSTAT_MSG,                   "NetstatMsg"},
    {YAHOO_FLD_SERVER_TYPE,                   "ServerType"},
    {YAHOO_FLD_TRY_P2P,                       "TryP2P"},
    {YAHOO_FLD_P2P_CONN_STATE,                "P2PConnState"},
    {YAHOO_FLD_INTERNET_CONN_TYPE,            "InternetConnType"},
    {YAHOO_FLD_NEED_CMD_RETURN,               "NeedCmdReturn"},
    {0, NULL},
};

/*
 * These fields' values are themselves fields. Possible values are:
 *  - YAHOO_FLD_GROUPS_RECORD_LIST,
 *  - YAHOO_FLD_BUDDIES_RECORD_LIST,
 *  - YAHOO_FLD_IGNORED_BUDDIES_RECORD_LIST,
 *  - YAHOO_FLD_PREFERENCES,
 */
static const int yahoo_fields_with_field_values[] = {
    YAHOO_FLD_START_OF_LIST,
    YAHOO_FLD_END_OF_LIST,
    YAHOO_FLD_START_OF_RECORD,
    YAHOO_FLD_END_OF_RECORD,
};

/* Find the end of the current content line and return its length */
static int get_content_item_length(tvbuff_t *tvb, int offset)
{
    int origoffset = offset;

    /* Keep reading until the magic delimiter (or end of tvb) is found */
    while (tvb_captured_length_remaining(tvb, offset) >= 2) {
        if (tvb_get_ntohs(tvb, offset) == 0xc080) {
            break;
        }
        offset += 1;
    }
    return offset - origoffset;
}

static unsigned
get_ymsg_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    unsigned plen;

    /*
     * Get the length of the YMSG packet.
     */
    plen = tvb_get_ntohs(tvb, offset + 8);

    /*
     * That length doesn't include the length of the header itself; add that in.
     */
    return plen + YAHOO_HEADER_SIZE;
}

static bool is_field_with_field_value(int key)
{
    for (unsigned i = 0; i < G_N_ELEMENTS(yahoo_fields_with_field_values); i++) {
        if (key == yahoo_fields_with_field_values[i]) {
            return true;
        }
    }

    return false;
}

static int
dissect_ymsg_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ymsg_tree, *ti;
    proto_item *content_item;
    proto_tree *content_tree;
    const char *val_buf;
    int         val_len;
    int         val_key;
    int         key_len;
    int         key;
    bool        key_valid;
    int         content_len;
    int         offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "YMSG");

    col_add_fstr(pinfo->cinfo, COL_INFO,
            "%s (status=%s)   ",
            val_to_str(tvb_get_ntohs(tvb, offset + 10),
                 ymsg_command_vals, "Unknown Command: %u"),
            val_to_str(tvb_get_ntohl(tvb, offset + 12),
                 ymsg_status_vals, "Unknown Status: %u")
        );

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ymsg, tvb, offset, -1, ENC_NA);
        ymsg_tree = proto_item_add_subtree(ti, ett_ymsg);

        offset += 4; /* skip the YMSG string */

        /* Version */
        proto_tree_add_item(ymsg_tree, hf_ymsg_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Vendor ID */
        proto_tree_add_item(ymsg_tree, hf_ymsg_vendor, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Length */
        content_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(ymsg_tree, hf_ymsg_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Command */
        proto_item_append_text(ti, " (%s)",
                               val_to_str_const(tvb_get_ntohs(tvb, offset),
                               ymsg_command_vals,
                               "Unknown"));

        proto_tree_add_item(ymsg_tree, hf_ymsg_command, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Status */
        proto_tree_add_item(ymsg_tree, hf_ymsg_status, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* Session id */
        proto_tree_add_item(ymsg_tree, hf_ymsg_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* Contents */
        if (content_len) {
            /* Create content subtree */
            content_item = proto_tree_add_item(ymsg_tree, hf_ymsg_content, tvb,
                                               offset, -1, ENC_NA);
            content_tree = proto_item_add_subtree(content_item, ett_ymsg_content);

            /* Each entry consists of:
               <key int32> <delimiter> <value string> <delimiter>
            */

            /* Parse and show each line of the contents */
            for (;;)
            {
                proto_item  *ti_2;
                proto_tree  *content_line_tree;

                /* Don't continue unless there is room for another whole item.
                   (including 2 2-byte delimiters */
                if (offset >= (YAHOO_HEADER_SIZE + content_len - 4))
                {
                    break;
                }

                /* Get the length of the key */
                key_len = get_content_item_length(tvb, offset);
                /* Extract the key */
                key_valid = ws_strtoi32(tvb_format_text(pinfo->pool, tvb, offset, key_len), NULL, &key);
                if (!key_valid) {
                    key = -1;
                }

                /* Get the length of the value */
                val_len = get_content_item_length(tvb, offset + key_len + 2);
                /* Extract the value */
                val_buf = tvb_format_text(pinfo->pool, tvb, offset + key_len + 2, val_len);

                /* If the key is a field with field values, convert the value to an int and get its field name */
                if (is_field_with_field_value(key) && ws_strtoi32(val_buf, NULL, &val_key)) {
                    val_buf = val_to_str(val_key, ymsg_field_vals, "Unknown(%u)");
                }

                /* Add a text item with the key... */
                ti_2 =  proto_tree_add_string_format(content_tree, hf_ymsg_content_line, tvb,
                                                     offset, key_len + 2 + val_len + 2,
                                                     "", "%s: %s", val_to_str(key, ymsg_field_vals, "Unknown(%u)"),
                                                     val_buf);
                content_line_tree = proto_item_add_subtree(ti_2, ett_ymsg_content_line);

                /* And add the key and value separately inside */
                proto_tree_add_item(content_line_tree, hf_ymsg_content_line_key, tvb,
                                    offset, key_len, ENC_ASCII);
                proto_tree_add_item(content_line_tree, hf_ymsg_content_line_value, tvb,
                                    offset + key_len + 2, val_len, ENC_ASCII);

                /* Move beyond key and value lines */
                offset += key_len + 2 + val_len + 2;
            }
        }
    }

    col_set_fence(pinfo->cinfo, COL_INFO);

    return tvb_captured_length(tvb);
}


static bool
dissect_ymsg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < 4) {
        return false;
    }
    if (tvb_memeql(tvb, 0, (const uint8_t*)"YMSG", 4) == -1) {
        /* Not a Yahoo Messenger packet. */
        return false;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, ymsg_desegment, 10, get_ymsg_pdu_len,
             dissect_ymsg_pdu, data);
    return true;
}

void
proto_register_ymsg(void)
{
    static hf_register_info hf[] = {
        { &hf_ymsg_version, {
                "Version", "ymsg.version", FT_UINT16, BASE_DEC,
                NULL, 0, "Packet version identifier", HFILL }},
        { &hf_ymsg_vendor, {
                "Vendor ID", "ymsg.vendor", FT_UINT16, BASE_DEC,
                NULL, 0, "Vendor identifier", HFILL }},
        { &hf_ymsg_len, {
                "Packet Length", "ymsg.len", FT_UINT16, BASE_DEC,
                NULL, 0, NULL, HFILL }},
        { &hf_ymsg_command, {
                "Command", "ymsg.command", FT_UINT16, BASE_DEC,
                VALS(ymsg_command_vals), 0, "Command Type", HFILL }},
        { &hf_ymsg_status, {
                "Status", "ymsg.status", FT_UINT32, BASE_DEC,
                VALS(ymsg_status_vals), 0, "Message Type Flags", HFILL }},
        { &hf_ymsg_session_id, {
                "Session ID", "ymsg.session_id", FT_UINT32, BASE_HEX,
                NULL, 0, "Connection ID", HFILL }},

        { &hf_ymsg_content, {
                "Content", "ymsg.content", FT_BYTES, BASE_NONE,
                NULL, 0, "Data portion of the packet", HFILL }},
        { &hf_ymsg_content_line, {
                "Content-line", "ymsg.content-line", FT_STRING, BASE_NONE,
                NULL, 0, "Content line", HFILL }},
        { &hf_ymsg_content_line_key, {
                "Key", "ymsg.content-line.key", FT_STRING, BASE_NONE,
                NULL, 0, "Content line key", HFILL }},
        { &hf_ymsg_content_line_value, {
                "Value", "ymsg.content-line.value", FT_STRING, BASE_NONE,
                NULL, 0, "Content line value", HFILL }}
    };
    static int *ett[] = {
        &ett_ymsg,
        &ett_ymsg_content,
        &ett_ymsg_content_line
    };
    module_t *ymsg_module;

    proto_ymsg = proto_register_protocol("Yahoo YMSG Messenger Protocol",
        "YMSG", "ymsg");

    proto_register_field_array(proto_ymsg, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    ymsg_module = prefs_register_protocol(proto_ymsg, NULL);
    prefs_register_bool_preference(ymsg_module, "desegment",
                       "Reassemble YMSG messages spanning multiple TCP segments",
                       "Whether the YMSG dissector should reassemble messages spanning multiple TCP segments. "
                       "To use this option, you must also enable"
                       " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                       &ymsg_desegment);
}

void
proto_reg_handoff_ymsg(void)
{
    /*
     * DO NOT register for port 23, as that's Telnet, or for port
     * 25, as that's SMTP.
     *
     * Also, DO NOT register for port 5050, as that's used by the
     * old and new Yahoo messenger protocols.
     *
     * Just register as a heuristic TCP dissector, and reject stuff
     * that doesn't begin with a YMSG signature.
     */
    heur_dissector_add("tcp", dissect_ymsg, "Yahoo YMSG Messenger over TCP", "ymsg_tcp", proto_ymsg, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
