/* packet-afp.c
 * Routines for afp packet dissection
 * Copyright 2002, Didier Gautheron <dgautheron@magic.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 * Copied from packet-dsi.c
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
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
/* #include <epan/strutil.h> */
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/tap.h>

#include "packet-afp.h"

/* The information in this module (AFP) comes from:

  AFP 2.1 & 2.2.pdf contained in AppleShare_IP_6.3_SDK
  available from http://www.apple.com

  AFP3.0.pdf from http://www.apple.com (still available?)
  AFP3.1.pdf from

   http://developer.apple.com/documentation/Networking/Conceptual/AFP/AFP3_1.pdf

  AFP 3.1 in HTML from

http://developer.apple.com/documentation/Networking/Conceptual/AFP/index.html

  The netatalk source code by Wesley Craig & Adrian Sun
	http://netatalk.sf.net
*/
/* from netatalk/include/afp.h */
#define AFPTRANS_NONE          0
#define AFPTRANS_DDP          (1 << 0)
#define AFPTRANS_TCP          (1 << 1)
#define AFPTRANS_ALL          (AFPTRANS_DDP | AFPTRANS_TCP)

/* AFP Attention Codes -- 4 bits */
#define AFPATTN_SHUTDOWN     (1 << 15)            /* shutdown/disconnect */
#define AFPATTN_CRASH        (1 << 14)            /* server crashed */
#define AFPATTN_MESG         (1 << 13)            /* server has message */
#define AFPATTN_NORECONNECT  (1 << 12)            /* don't reconnect */
/* server notification */
#define AFPATTN_NOTIFY       (AFPATTN_MESG | AFPATTN_NORECONNECT)

/* extended bitmap -- 12 bits. volchanged is only useful w/ a server
 * notification, and time is only useful for shutdown. */
#define AFPATTN_VOLCHANGED   (1 << 0)             /* volume has changed */
#define AFPATTN_TIME(x)      ((x) & 0xfff)        /* time in minutes */

/* AFP functions */
#define AFP_BYTELOCK	     1
#define AFP_CLOSEVOL     	 2
#define AFP_CLOSEDIR     	 3
#define AFP_CLOSEFORK	 	 4
#define AFP_COPYFILE 	 	 5
#define AFP_CREATEDIR		 6
#define AFP_CREATEFILE		 7
#define AFP_DELETE	 	     8
#define AFP_ENUMERATE	 	 9
#define AFP_FLUSH		    10
#define AFP_FLUSHFORK		11
#define AFP_GETFORKPARAM	14
#define AFP_GETSRVINFO  	15
#define AFP_GETSRVPARAM 	16
#define AFP_GETVOLPARAM		17
#define AFP_LOGIN       	18
#define AFP_LOGINCONT		19
#define AFP_LOGOUT      	20
#define AFP_MAPID		    21
#define AFP_MAPNAME		    22
#define AFP_MOVE		    23
#define AFP_OPENVOL     	24
#define AFP_OPENDIR		    25
#define AFP_OPENFORK		26
#define AFP_READ		    27
#define AFP_RENAME		    28
#define AFP_SETDIRPARAM		29
#define AFP_SETFILEPARAM	30
#define AFP_SETFORKPARAM	31
#define AFP_SETVOLPARAM		32
#define AFP_WRITE		    33
#define AFP_GETFLDRPARAM	34
#define AFP_SETFLDRPARAM	35
#define AFP_CHANGEPW    	36
#define AFP_GETUSERINFO		37
#define AFP_GETSRVRMSG		38
#define AFP_CREATEID		39
#define AFP_DELETEID		40
#define AFP_RESOLVEID		41
#define AFP_EXCHANGEFILE	42
#define AFP_CATSEARCH		43
#define AFP_OPENDT		    48
#define AFP_CLOSEDT		    49
#define AFP_GETICON         51
#define AFP_GTICNINFO       52
#define AFP_ADDAPPL         53
#define AFP_RMVAPPL         54
#define AFP_GETAPPL         55
#define AFP_ADDCMT          56
#define AFP_RMVCMT          57
#define AFP_GETCMT          58
#define AFP_ZZZ            122
#define AFP_ADDICON        192

/* AFP 3.0 new calls */
#define AFP_BYTELOCK_EXT	59
#define AFP_CATSEARCH_EXT	67
#define AFP_ENUMERATE_EXT	66
#define AFP_READ_EXT		60
#define AFP_WRITE_EXT		61
#define AFP_LOGIN_EXT		63
#define AFP_GETSESSTOKEN	64
#define AFP_DISCTOLDSESS        65

/* AFP 3.1 new calls */
#define AFP_ENUMERATE_EXT2	68

/* AFP 3.2 new calls */
#define AFP_GETEXTATTR		69
#define AFP_SETEXTATTR		70
#define AFP_REMOVEATTR		71
#define AFP_LISTEXTATTR		72
#define AFP_GETACL		73
#define AFP_SETACL		74
#define AFP_ACCESS		75

/* ----------------------------- */
static int proto_afp = -1;
static int hf_afp_reserved = -1;

static int hf_afp_command = -1;		/* CommandCode */
static int hf_afp_AFPVersion = -1;
static int hf_afp_UAM = -1;
static int hf_afp_user = -1;
static int hf_afp_passwd = -1;
static int hf_afp_random = -1;

static int hf_afp_response_to = -1;
static int hf_afp_time = -1;
static int hf_afp_response_in = -1;

static int hf_afp_login_flags = -1;
static int hf_afp_pad = -1;

static int hf_afp_user_type = -1;
static int hf_afp_user_len = -1;
static int hf_afp_user_name = -1;

static int hf_afp_vol_flag_passwd 	 = -1;
static int hf_afp_vol_flag_unix_priv = -1;
static int hf_afp_server_time		 = -1;

static int hf_afp_vol_bitmap = -1;
static int hf_afp_vol_name_offset = -1;
static int hf_afp_vol_id = -1;
static int hf_afp_vol_attribute = -1;
static int hf_afp_vol_name = -1;
static int hf_afp_vol_signature = -1;
static int hf_afp_vol_creation_date = -1;
static int hf_afp_vol_modification_date = -1;
static int hf_afp_vol_backup_date = -1;
static int hf_afp_vol_bytes_free = -1;
static int hf_afp_vol_bytes_total = -1;
static int hf_afp_vol_ex_bytes_free = -1;
static int hf_afp_vol_ex_bytes_total = -1;
static int hf_afp_vol_block_size = -1;

/* desktop stuff */
static int hf_afp_comment 		= -1;
static int hf_afp_file_creator 	= -1;
static int hf_afp_file_type 	= -1;
static int hf_afp_icon_type 	= -1;
static int hf_afp_icon_length 	= -1;
static int hf_afp_icon_tag		= -1;
static int hf_afp_icon_index	= -1;
static int hf_afp_appl_index	= -1;
static int hf_afp_appl_tag		= -1;

static int hf_afp_did 				  = -1;
static int hf_afp_file_id 			  = -1;
static int hf_afp_file_DataForkLen    = -1;
static int hf_afp_file_RsrcForkLen    = -1;
static int hf_afp_file_ExtDataForkLen = -1;
static int hf_afp_file_ExtRsrcForkLen = -1;

static int hf_afp_dir_bitmap 	 = -1;
static int hf_afp_dir_offspring  = -1;
static int hf_afp_dir_OwnerID    = -1;
static int hf_afp_dir_GroupID    = -1;

static int hf_afp_file_bitmap = -1;
static int hf_afp_req_count = -1;
static int hf_afp_start_index = -1;
static int hf_afp_start_index32 = -1;
static int hf_afp_max_reply_size = -1;
static int hf_afp_max_reply_size32 = -1;
static int hf_afp_file_flag = -1;
static int hf_afp_create_flag = -1;
static int hf_afp_struct_size = -1;
static int hf_afp_struct_size16 = -1;

static int hf_afp_request_bitmap = -1;

static int hf_afp_cat_count 		= -1;
static int hf_afp_cat_req_matches   = -1;
static int hf_afp_cat_position		= -1;

static int hf_afp_creation_date = -1;
static int hf_afp_modification_date = -1;
static int hf_afp_backup_date = -1;
static int hf_afp_finder_info = -1;
static int hf_afp_long_name_offset = -1;
static int hf_afp_short_name_offset = -1;
static int hf_afp_unicode_name_offset = -1;
static int hf_afp_unix_privs_uid = -1;
static int hf_afp_unix_privs_gid = -1;
static int hf_afp_unix_privs_permissions = -1;
static int hf_afp_unix_privs_ua_permissions = -1;

static int hf_afp_path_type = -1;
static int hf_afp_path_len = -1;
static int hf_afp_path_name = -1;
static int hf_afp_path_unicode_hint = -1;
static int hf_afp_path_unicode_len = -1;

static int hf_afp_flag		= -1;
static int hf_afp_dt_ref	= -1;
static int hf_afp_ofork		= -1;
static int hf_afp_ofork_len	= -1;
static int hf_afp_offset	= -1;
static int hf_afp_rw_count	= -1;
static int hf_afp_newline_mask	= -1;
static int hf_afp_newline_char	= -1;
static int hf_afp_last_written	= -1;
static int hf_afp_actual_count	= -1;

static int hf_afp_fork_type			= -1;
static int hf_afp_access_mode		= -1;
static int hf_afp_access_read		= -1;
static int hf_afp_access_write		= -1;
static int hf_afp_access_deny_read  = -1;
static int hf_afp_access_deny_write = -1;

static gint hf_afp_lock_op			= -1;
static gint hf_afp_lock_from		= -1;
static gint hf_afp_lock_offset  	= -1;
static gint hf_afp_lock_len     	= -1;
static gint hf_afp_lock_range_start = -1;

static gint ett_afp = -1;

static gint ett_afp_vol_attribute = -1;
static gint ett_afp_enumerate = -1;
static gint ett_afp_enumerate_line = -1;
static gint ett_afp_access_mode = -1;

static gint ett_afp_vol_bitmap = -1;
static gint ett_afp_dir_bitmap = -1;
static gint ett_afp_dir_attribute = -1;
static gint ett_afp_file_attribute = -1;
static gint ett_afp_file_bitmap = -1;
static gint ett_afp_unix_privs = -1;
static gint ett_afp_path_name = -1;
static gint ett_afp_lock_flags = -1;
static gint ett_afp_dir_ar = -1;

static gint ett_afp_server_vol		= -1;
static gint ett_afp_vol_list		= -1;
static gint ett_afp_vol_flag		= -1;
static gint ett_afp_cat_search 		= -1;
static gint ett_afp_cat_r_bitmap	= -1;
static gint ett_afp_cat_spec		= -1;
static gint ett_afp_vol_did	= -1;

/* AFP 3.0 parameters */
static gint hf_afp_lock_offset64	= -1;
static gint hf_afp_lock_len64   	= -1;
static gint hf_afp_lock_range_start64	= -1;

static int hf_afp_offset64		= -1;
static int hf_afp_rw_count64		= -1;
static int hf_afp_reqcount64		= -1;

static int hf_afp_last_written64	= -1;

static int hf_afp_ofork_len64           = -1;
static int hf_afp_session_token_type	= -1;
static int hf_afp_session_token_len	= -1;
static int hf_afp_session_token		= -1;
static int hf_afp_session_token_timestamp = -1;

/* AFP 3.2 */

static int hf_afp_extattr_bitmap	  = -1;
static int hf_afp_extattr_bitmap_NoFollow = -1;
static int hf_afp_extattr_bitmap_Create   = -1;
static int hf_afp_extattr_bitmap_Replace  = -1;
static int ett_afp_extattr_bitmap	  = -1;
static int hf_afp_extattr_namelen	  = -1;
static int hf_afp_extattr_name		  = -1;
static int hf_afp_extattr_len		  = -1;
static int hf_afp_extattr_data		  = -1;
static int hf_afp_extattr_req_count	  = -1;
static int hf_afp_extattr_start_index	  = -1;
static int hf_afp_extattr_reply_size	  = -1;
static int ett_afp_extattr_names	  = -1;

static int afp_tap = -1;

static dissector_handle_t data_handle;

static const value_string vol_signature_vals[] = {
	{1, "Flat"},
	{2, "Fixed Directory ID"},
	{3, "Variable Directory ID (deprecated)"},
	{0, NULL }
};

const value_string CommandCode_vals[] = {
  {AFP_BYTELOCK,	"FPByteRangeLock" },
  {AFP_CLOSEVOL,	"FPCloseVol" },
  {AFP_CLOSEDIR,	"FPCloseDir" },
  {AFP_CLOSEFORK,	"FPCloseFork" },
  {AFP_COPYFILE,	"FPCopyFile" },
  {AFP_CREATEDIR,	"FPCreateDir" },
  {AFP_CREATEFILE,	"FPCreateFile" },
  {AFP_DELETE,		"FPDelete" },
  {AFP_ENUMERATE,	"FPEnumerate" },
  {AFP_FLUSH,		"FPFlush" },
  {AFP_FLUSHFORK,	"FPFlushFork" },
  {AFP_GETFORKPARAM,	"FPGetForkParms" },
  {AFP_GETSRVINFO,	"FPGetSrvrInfo" },
  {AFP_GETSRVPARAM,	"FPGetSrvrParms" },
  {AFP_GETVOLPARAM,	"FPGetVolParms" },
  {AFP_LOGIN,		"FPLogin" },
  {AFP_LOGINCONT,	"FPLoginCont" },
  {AFP_LOGOUT,		"FPLogout" },
  {AFP_MAPID,		"FPMapID" },
  {AFP_MAPNAME,		"FPMapName" },
  {AFP_MOVE,		"FPMoveAndRename" },
  {AFP_OPENVOL,		"FPOpenVol" },
  {AFP_OPENDIR,		"FPOpenDir" },
  {AFP_OPENFORK,	"FPOpenFork" },
  {AFP_READ,		"FPRead" },
  {AFP_RENAME,		"FPRename" },
  {AFP_SETDIRPARAM,	"FPSetDirParms" },
  {AFP_SETFILEPARAM,	"FPSetFileParms" },
  {AFP_SETFORKPARAM,	"FPSetForkParms" },
  {AFP_SETVOLPARAM,	"FPSetVolParms" },
  {AFP_WRITE,		"FPWrite" },
  {AFP_GETFLDRPARAM,	"FPGetFileDirParms" },
  {AFP_SETFLDRPARAM,	"FPSetFileDirParms" },
  {AFP_CHANGEPW,	"FPChangePassword" },
  {AFP_GETUSERINFO,     "FPGetUserInfo" },
  {AFP_GETSRVRMSG,	"FPGetSrvrMsg" },
  {AFP_CREATEID,	"FPCreateID" },
  {AFP_DELETEID,	"FPDeleteID" },
  {AFP_RESOLVEID,	"FPResolveID" },
  {AFP_EXCHANGEFILE,	"FPExchangeFiles" },
  {AFP_CATSEARCH,	"FPCatSearch" },
  {AFP_OPENDT,		"FPOpenDT" },
  {AFP_CLOSEDT,		"FPCloseDT" },
  {AFP_GETICON,		"FPGetIcon" },
  {AFP_GTICNINFO,	"FPGetIconInfo" },
  {AFP_ADDAPPL,		"FPAddAPPL" },
  {AFP_RMVAPPL,		"FPRemoveAPPL" },
  {AFP_GETAPPL,		"FPGetAPPL" },
  {AFP_ADDCMT,		"FPAddComment" },
  {AFP_RMVCMT,		"FPRemoveComment" },
  {AFP_GETCMT,		"FPGetComment" },
  {AFP_BYTELOCK_EXT,	"FPByteRangeLockExt" },
  {AFP_CATSEARCH_EXT,	"FPCatSearchExt" },
  {AFP_ENUMERATE_EXT,	"FPEnumerateExt" },
  {AFP_ENUMERATE_EXT2,	"FPEnumerateExt2" },
  {AFP_READ_EXT,	"FPReadExt" },
  {AFP_WRITE_EXT,	"FPWriteExt" },
  {AFP_LOGIN_EXT,	"FPLoginExt" },
  {AFP_GETSESSTOKEN,	"FPGetSessionToken" },
  {AFP_DISCTOLDSESS,    "FPDisconnectOldSession" },
  {AFP_ZZZ,             "FPZzzzz" },
  {AFP_ADDICON,		"FPAddIcon" },
  {AFP_GETEXTATTR,	"FPGetExtAttr" },
  {AFP_SETEXTATTR,	"FPSetExtAttr" },
  {AFP_REMOVEATTR,	"FPRemoveExtAttr" },
  {AFP_LISTEXTATTR,	"FPListExtAttrs" },
  {AFP_GETACL,		"FPGetACL" },
  {AFP_SETACL,		"FPSetACL" },
  {AFP_ACCESS,		"FPAccess" },
  {0,			 NULL }
};

static const value_string unicode_hint_vals[] = {
   { 0,	   "MacRoman" },
   { 1,	   "MacJapanese" },
   { 2,	   "MacChineseTrad" },
   { 3,	   "MacKorean" },
   { 4,	   "MacArabic" },
   { 5,	   "MacHebrew" },
   { 6,	   "MacGreek" },
   { 7,	   "MacCyrillic" },
   { 9,	   "MacDevanagari" },
   { 10,   "MacGurmukhi" },
   { 11,   "MacGujarati" },
   { 12,   "MacOriya" },
   { 13,   "MacBengali" },
   { 14,   "MacTamil" },
   { 15,   "MacTelugu" },
   { 16,   "MacKannada" },
   { 17,   "MacMalayalam" },
   { 18,   "MacSinhalese" },
   { 19,   "MacBurmese" },
   { 20,   "MacKhmer" },
   { 21,   "MacThai" },
   { 22,   "MacLaotian" },
   { 23,   "MacGeorgian" },
   { 24,   "MacArmenian" },
   { 25,   "MacChineseSimp" },
   { 26,   "MacTibetan" },
   { 27,   "MacMongolian" },
   { 28,   "MacEthiopic" },
   { 29,   "MacCentralEurRoman" },
   { 30,   "MacVietnamese" },
   { 31,   "MacExtArabic" },
   { 33,   "MacSymbol" },
   { 34,   "MacDingbats" },
   { 35,   "MacTurkish" },
   { 36,   "MacCroatian" },
   { 37,   "MacIcelandic" },
   { 38,   "MacRomanian" },
   { 39,   "MacCeltic" },
   { 40,   "MacGaelic" },
   { 41,   "MacKeyboardGlyphs" },
   { 126,  "MacUnicode" },
   { 140,  "MacFarsi" },
   { 152,  "MacUkrainian" },
   { 236,  "MacInuit" },
   { 252,  "MacVT100" },
   { 255,  "MacHFS" },
   { 256,  "UnicodeDefault" },
/* { 257,  "UnicodeV1_1" },  */
   { 257,  "ISO10646_1993" },
   { 259,  "UnicodeV2_0" },
   { 259,  "UnicodeV2_1" },
   { 260,  "UnicodeV3_0" },
   { 513,  "ISOLatin1" },
   { 514,  "ISOLatin2" },
   { 515,  "ISOLatin3" },
   { 516,  "ISOLatin4" },
   { 517,  "ISOLatinCyrillic" },
   { 518,  "ISOLatinArabic" },
   { 519,  "ISOLatinGreek" },
   { 520,  "ISOLatinHebrew" },
   { 521,  "ISOLatin5" },
   { 522,  "ISOLatin6" },
   { 525,  "ISOLatin7" },
   { 526,  "ISOLatin8" },
   { 527,  "ISOLatin9" },
   { 1024, "DOSLatinUS" },
   { 1029, "DOSGreek" },
   { 1030, "DOSBalticRim" },
   { 1040, "DOSLatin1" },
   { 1041, "DOSGreek1" },
   { 1042, "DOSLatin2" },
   { 1043, "DOSCyrillic" },
   { 1044, "DOSTurkish" },
   { 1045, "DOSPortuguese" },
   { 1046, "DOSIcelandic" },
   { 1047, "DOSHebrew" },
   { 1048, "DOSCanadianFrench" },
   { 1049, "DOSArabic" },
   { 1050, "DOSNordic" },
   { 1051, "DOSRussian" },
   { 1052, "DOSGreek2" },
   { 1053, "DOSThai" },
   { 1056, "DOSJapanese" },
   { 1057, "DOSChineseSimplif" },
   { 1058, "DOSKorean" },
   { 1059, "DOSChineseTrad" },
   { 1280, "WindowsLatin1" },
/* { 1280, "WindowsANSI" }, */
   { 1281, "WindowsLatin2" },
   { 1282, "WindowsCyrillic" },
   { 1283, "WindowsGreek" },
   { 1284, "WindowsLatin5" },
   { 1285, "WindowsHebrew" },
   { 1286, "WindowsArabic" },
   { 1287, "WindowsBalticRim" },
   { 1288, "WindowsVietnamese" },
   { 1296, "WindowsKoreanJohab" },
   { 1536, "US_ASCII" },
   { 1568, "JIS_X0201_76" },
   { 1569, "JIS_X0208_83" },
   { 1570, "JIS_X0208_90" },
   { 0,	   NULL }
};

/* volume bitmap
  from Apple AFP3.0.pdf
  Table 1-2 p. 20
*/
#define kFPVolAttributeBit 		(1 << 0)
#define kFPVolSignatureBit 		(1 << 1)
#define kFPVolCreateDateBit	 	(1 << 2)
#define kFPVolModDateBit 		(1 << 3)
#define kFPVolBackupDateBit 		(1 << 4)
#define kFPVolIDBit 			(1 << 5)
#define kFPVolBytesFreeBit	  	(1 << 6)
#define kFPVolBytesTotalBit	 	(1 << 7)
#define kFPVolNameBit 			(1 << 8)
#define kFPVolExtBytesFreeBit 		(1 << 9)
#define kFPVolExtBytesTotalBit		(1 << 10)
#define kFPVolBlockSizeBit 	  	(1 << 11)

static int hf_afp_vol_bitmap_Attributes 	= -1;
static int hf_afp_vol_bitmap_Signature 		= -1;
static int hf_afp_vol_bitmap_CreateDate 	= -1;
static int hf_afp_vol_bitmap_ModDate 		= -1;
static int hf_afp_vol_bitmap_BackupDate 	= -1;
static int hf_afp_vol_bitmap_ID 		= -1;
static int hf_afp_vol_bitmap_BytesFree 		= -1;
static int hf_afp_vol_bitmap_BytesTotal 	= -1;
static int hf_afp_vol_bitmap_Name 		= -1;
static int hf_afp_vol_bitmap_ExtBytesFree 	= -1;
static int hf_afp_vol_bitmap_ExtBytesTotal 	= -1;
static int hf_afp_vol_bitmap_BlockSize 		= -1;

static int hf_afp_vol_attribute_ReadOnly			= -1;
static int hf_afp_vol_attribute_HasVolumePassword		= -1;
static int hf_afp_vol_attribute_SupportsFileIDs			= -1;
static int hf_afp_vol_attribute_SupportsCatSearch		= -1;
static int hf_afp_vol_attribute_SupportsBlankAccessPrivs	= -1;
static int hf_afp_vol_attribute_SupportsUnixPrivs		= -1;
static int hf_afp_vol_attribute_SupportsUTF8Names		= -1;
static int hf_afp_vol_attribute_NoNetworkUserID			= -1;
static int hf_afp_vol_attribute_DefaultPrivsFromParent		= -1;
static int hf_afp_vol_attribute_NoExchangeFiles			= -1;
static int hf_afp_vol_attribute_SupportsExtAttrs		= -1;
static int hf_afp_vol_attribute_SupportsACLs			= -1;

static int hf_afp_dir_bitmap_Attributes     = -1;
static int hf_afp_dir_bitmap_ParentDirID    = -1;
static int hf_afp_dir_bitmap_CreateDate     = -1;
static int hf_afp_dir_bitmap_ModDate        = -1;
static int hf_afp_dir_bitmap_BackupDate     = -1;
static int hf_afp_dir_bitmap_FinderInfo     = -1;
static int hf_afp_dir_bitmap_LongName       = -1;
static int hf_afp_dir_bitmap_ShortName      = -1;
static int hf_afp_dir_bitmap_NodeID         = -1;
static int hf_afp_dir_bitmap_OffspringCount = -1;
static int hf_afp_dir_bitmap_OwnerID        = -1;
static int hf_afp_dir_bitmap_GroupID        = -1;
static int hf_afp_dir_bitmap_AccessRights   = -1;
static int hf_afp_dir_bitmap_UTF8Name       = -1;
static int hf_afp_dir_bitmap_UnixPrivs      = -1;

static int hf_afp_dir_attribute_Invisible     = -1;
static int hf_afp_dir_attribute_IsExpFolder   = -1;

static int hf_afp_dir_attribute_System        = -1;
static int hf_afp_dir_attribute_Mounted       = -1;
static int hf_afp_dir_attribute_InExpFolder   = -1;

static int hf_afp_dir_attribute_BackUpNeeded  = -1;
static int hf_afp_dir_attribute_RenameInhibit = -1;
static int hf_afp_dir_attribute_DeleteInhibit = -1;
static int hf_afp_dir_attribute_SetClear      = -1;

static int hf_afp_file_bitmap_Attributes     = -1;
static int hf_afp_file_bitmap_ParentDirID    = -1;
static int hf_afp_file_bitmap_CreateDate     = -1;
static int hf_afp_file_bitmap_ModDate        = -1;
static int hf_afp_file_bitmap_BackupDate     = -1;
static int hf_afp_file_bitmap_FinderInfo     = -1;
static int hf_afp_file_bitmap_LongName       = -1;
static int hf_afp_file_bitmap_ShortName      = -1;
static int hf_afp_file_bitmap_NodeID         = -1;
static int hf_afp_file_bitmap_DataForkLen    = -1;
static int hf_afp_file_bitmap_RsrcForkLen    = -1;
static int hf_afp_file_bitmap_ExtDataForkLen = -1;
static int hf_afp_file_bitmap_LaunchLimit    = -1;

static int hf_afp_file_bitmap_UTF8Name       = -1;
static int hf_afp_file_bitmap_ExtRsrcForkLen = -1;
static int hf_afp_file_bitmap_UnixPrivs      = -1;

static int hf_afp_file_attribute_Invisible     = -1;
static int hf_afp_file_attribute_MultiUser     = -1;
static int hf_afp_file_attribute_System        = -1;
static int hf_afp_file_attribute_DAlreadyOpen  = -1;
static int hf_afp_file_attribute_RAlreadyOpen  = -1;
static int hf_afp_file_attribute_WriteInhibit  = -1;
static int hf_afp_file_attribute_BackUpNeeded  = -1;
static int hf_afp_file_attribute_RenameInhibit = -1;
static int hf_afp_file_attribute_DeleteInhibit = -1;
static int hf_afp_file_attribute_CopyProtect   = -1;
static int hf_afp_file_attribute_SetClear      = -1;

static int hf_afp_map_name_type = -1;
static int hf_afp_map_name	= -1;
static int hf_afp_map_id	= -1;
static int hf_afp_map_id_type	= -1;

static int hf_afp_request_bitmap_Attributes     = -1;
static int hf_afp_request_bitmap_ParentDirID    = -1;
static int hf_afp_request_bitmap_CreateDate     = -1;
static int hf_afp_request_bitmap_ModDate        = -1;
static int hf_afp_request_bitmap_BackupDate     = -1;
static int hf_afp_request_bitmap_FinderInfo     = -1;
static int hf_afp_request_bitmap_LongName       = -1;
static int hf_afp_request_bitmap_DataForkLen    = -1;
static int hf_afp_request_bitmap_OffspringCount = -1;
static int hf_afp_request_bitmap_RsrcForkLen    = -1;
static int hf_afp_request_bitmap_ExtDataForkLen = -1;
static int hf_afp_request_bitmap_UTF8Name       = -1;
static int hf_afp_request_bitmap_ExtRsrcForkLen = -1;
static int hf_afp_request_bitmap_PartialNames   = -1;

static const value_string flag_vals[] = {
  {0,	"Start" },
  {1,	"End" },
  {0,	NULL } };

static const value_string path_type_vals[] = {
  {1,	"Short names" },
  {2,	"Long names" },
  {3,	"Unicode names" },
  {0,	NULL } };

static const value_string map_name_type_vals[] = {
  {1,	"Unicode user name to a user ID" },
  {2,	"Unicode group name to a group ID" },
  {3,	"Macintosh roman user name to a user ID" },
  {4,	"Macintosh roman group name to a group ID" },
  {5,	"Unicode user name to a user UUID" },
  {6,	"Unicode group name to a group UUID" },
  {0,	NULL } };

static const value_string map_id_type_vals[] = {
  {1,	"User ID to a Macintosh roman user name" },
  {2,	"Group ID to a Macintosh roman group name" },
  {3,	"User ID to a unicode user name" },
  {4,	"Group ID to a unicode group name" },
  {5,	"User UUID to a unicode user name" },
  {6,	"Group UUID to a unicode group name" },
  {0,	NULL } };

/*
  volume attribute from Apple AFP3.0.pdf
  Table 1-3 p. 22
*/
#define kReadOnly 				(1 << 0)
#define kHasVolumePassword 			(1 << 1)
#define kSupportsFileIDs 			(1 << 2)
#define kSupportsCatSearch 			(1 << 3)
#define kSupportsBlankAccessPrivs 		(1 << 4)
#define kSupportsUnixPrivs 			(1 << 5)
#define kSupportsUTF8Names 			(1 << 6)
/* AFP3.1 */
#define kNoNetworkUserIDs 			(1 << 7)
/* AFP3.2 */
#define kDefaultPrivsFromParent			(1 << 8)
#define kNoExchangeFiles			(1 << 9)
#define kSupportsExtAttrs			(1 << 10)
#define kSupportsACLs				(1 << 11)

/*
  directory bitmap from Apple AFP3.1.pdf
  Table 1-5 pp. 25-26
*/
#define kFPAttributeBit 		(1 << 0)
#define kFPParentDirIDBit 		(1 << 1)
#define kFPCreateDateBit 		(1 << 2)
#define kFPModDateBit 			(1 << 3)
#define kFPBackupDateBit 		(1 << 4)
#define kFPFinderInfoBit 		(1 << 5)
#define kFPLongNameBit			(1 << 6)
#define kFPShortNameBit 		(1 << 7)
#define kFPNodeIDBit 			(1 << 8)
#define kFPOffspringCountBit	 	(1 << 9)
#define kFPOwnerIDBit 			(1 << 10)
#define kFPGroupIDBit 			(1 << 11)
#define kFPAccessRightsBit 		(1 << 12)
#define kFPUTF8NameBit 			(1 << 13)

/* FIXME AFP3.0 bit 14, AFP3.1 bit 15 */

#define kFPUnixPrivsBit 		(1 << 15)

/*
	directory Access Rights parameter AFP3.1.pdf
	table 1-7 p. 28
*/

#define AR_O_SEARCH	(1 << 0)	/* owner has search access */
#define AR_O_READ	(1 << 1)    /* owner has read access */
#define AR_O_WRITE	(1 << 2)    /* owner has write access */

#define AR_G_SEARCH	(1 << 8)    /* group has search access */
#define AR_G_READ	(1 << 9)    /* group has read access */
#define AR_G_WRITE	(1 << 10)   /* group has write access */

#define AR_E_SEARCH	(1 << 16)	/* everyone has search access */
#define AR_E_READ	(1 << 17)   /* everyone has read access */
#define AR_E_WRITE	(1 << 18)   /* everyone has write access */

#define AR_U_SEARCH	(1 << 24)   /* user has search access */
#define AR_U_READ  	(1 << 25)   /* user has read access */
#define AR_U_WRITE 	(1 << 26)	/* user has write access */

#define AR_BLANK	(1 << 28)	/* Blank Access Privileges (use parent dir privileges) */
#define AR_U_OWN 	(1UL << 31)	/* user is the owner */

static int hf_afp_dir_ar          = -1;
static int hf_afp_dir_ar_o_search = -1;
static int hf_afp_dir_ar_o_read   = -1;
static int hf_afp_dir_ar_o_write  = -1;
static int hf_afp_dir_ar_g_search = -1;
static int hf_afp_dir_ar_g_read   = -1;
static int hf_afp_dir_ar_g_write  = -1;
static int hf_afp_dir_ar_e_search = -1;
static int hf_afp_dir_ar_e_read   = -1;
static int hf_afp_dir_ar_e_write  = -1;
static int hf_afp_dir_ar_u_search = -1;
static int hf_afp_dir_ar_u_read   = -1;
static int hf_afp_dir_ar_u_write  = -1;
static int hf_afp_dir_ar_blank    = -1;
static int hf_afp_dir_ar_u_own    = -1;

static int hf_afp_user_flag       = -1;
static int hf_afp_user_ID         = -1;
static int hf_afp_group_ID        = -1;
static int hf_afp_UUID      = -1;
static int hf_afp_GRPUUID      = -1;
static int hf_afp_user_bitmap     = -1;
static int hf_afp_user_bitmap_UID = -1;
static int hf_afp_user_bitmap_GID = -1;
static int hf_afp_user_bitmap_UUID= -1;

static gint ett_afp_user_bitmap   = -1;

static const value_string user_flag_vals[] = {
  {0,	"Use user ID" },
  {1,	"Default user" },
  {0,	NULL } };

static int hf_afp_message        = -1;
static int hf_afp_message_type    = -1;
static int hf_afp_message_bitmap  = -1;
static int hf_afp_message_bitmap_REQ = -1;
static int hf_afp_message_bitmap_UTF = -1;
static int hf_afp_message_len	 = -1;

static gint ett_afp_message_bitmap = -1;

static const value_string server_message_type[] = {
  {0,   "Login message" },
  {1,   "Server message" },
  {0,   NULL } };

/*
  file bitmap AFP3.1.pdf
  Table 1-8 p. 29
same as dir
kFPAttributeBit 		(bit 0)
kFPParentDirIDBit 		(bit 1)
kFPCreateDateBit 		(bit 2)
kFPModDateBit 			(bit 3)
kFPBackupDateBit 		(bit 4)
kFPFinderInfoBit 		(bit 5)
kFPLongNameBit 			(bit 6)
kFPShortNameBit 		(bit 7)
kFPNodeIDBit 			(bit 8)

kFPUTF8NameBit 			(bit 13)
*/

#define kFPDataForkLenBit 		(1 << 9)
#define kFPRsrcForkLenBit 		(1 << 10)
#define kFPExtDataForkLenBit 		(1 << 11)
#define kFPLaunchLimitBit 		(1 << 12)

#define kFPExtRsrcForkLenBit 		(1 << 14)

/*
  file attribute AFP3.1.pdf
  Table 1-9 pp. 29-31
*/
#define kFPInvisibleBit 			(1 << 0)
#define kFPMultiUserBit 			(1 << 1)
#define kFPSystemBit 				(1 << 2)
#define kFPDAlreadyOpenBit 			(1 << 3)
#define kFPRAlreadyOpenBit 			(1 << 4)
#define kFPWriteInhibitBit 			(1 << 5)
#define kFPBackUpNeededBit 			(1 << 6)
#define kFPRenameInhibitBit 			(1 << 7)
#define kFPDeleteInhibitBit 			(1 << 8)
#define kFPCopyProtectBit 			(1 << 10)
#define kFPSetClearBit 				(1 << 15)

/* dir attribute */
#define kIsExpFolder 	(1 << 1)
#define kMounted 	(1 << 3)
#define kInExpFolder 	(1 << 4)

/* AFP 3.1 getsession token type */
#define kLoginWithoutID         0
#define kLoginWithID            1
#define kReconnWithID           2
#define kLoginWithTimeAndID     3
#define kReconnWithTimeAndID    4

/* modified AFP 3.1 token type cf. page 327 */
#define kRecon1Login            5
#define kRecon1ReconnectLogin   6
#define kRecon1Refresh          7
#define kGetKerberosSessionKey  8

static const value_string token_type_vals[] = {
  {kLoginWithoutID,		"LoginWithoutID"},
  {kLoginWithID,                "LoginWithID"},
  {kReconnWithID,               "ReconnWithID"},
  {kLoginWithTimeAndID,         "LoginWithTimeAndID"},
  {kReconnWithTimeAndID,        "ReconnWithTimeAndID"},
  {kRecon1Login,                "Recon1Login"},
  {kRecon1ReconnectLogin,       "Recon1ReconnectLogin"},
  {kRecon1Refresh,              "Recon1Refresh"},
  {kGetKerberosSessionKey,      "GetKerberosSessionKey"},

  {0,				 NULL } };

/* AFP 3.2 ACL bitmap */
#define kFileSec_UUID		(1 << 0)
#define kFileSec_GRPUUID	(1 << 1)
#define kFileSec_ACL		(1 << 2)
#define kFileSec_REMOVEACL	(1 << 3)
#define kFileSec_Inherit	(1 << 4)

static int hf_afp_acl_list_bitmap		= -1;
static int hf_afp_acl_list_bitmap_UUID		= -1;
static int hf_afp_acl_list_bitmap_GRPUUID	= -1;
static int hf_afp_acl_list_bitmap_ACL		= -1;
static int hf_afp_acl_list_bitmap_REMOVEACL	= -1;
static int hf_afp_acl_list_bitmap_Inherit	= -1;
static int ett_afp_acl_list_bitmap		= -1;

static int hf_afp_access_bitmap		= -1;

static int hf_afp_acl_entrycount	= -1;
static int hf_afp_acl_flags		= -1;

static int hf_afp_ace_applicable	= -1;
static int hf_afp_ace_flags		= -1;
static int hf_afp_ace_rights		= -1;

static int ett_afp_ace_flags		= -1;
static int hf_afp_ace_flags_allow	= -1;
static int hf_afp_ace_flags_deny	= -1;
static int hf_afp_ace_flags_inherited	= -1;
static int hf_afp_ace_flags_fileinherit	= -1;
static int hf_afp_ace_flags_dirinherit	= -1;
static int hf_afp_ace_flags_limitinherit= -1;
static int hf_afp_ace_flags_onlyinherit = -1;

/* AFP 3.2 ACE flags */
#define ACE_ALLOW	 (1 << 0)
#define ACE_DENY	 (1 << 1)
#define ACE_INHERITED	 (1 << 4)
#define ACE_FILE_INHERIT (1 << 5)
#define ACE_DIR_INHERIT	 (1 << 6)
#define ACE_LIMIT_INHERIT (1 << 7)
#define ACE_ONLY_INHERIT (1 << 8)

static int ett_afp_ace_entries		= -1;
static int ett_afp_ace_entry		= -1;

/* AFP 3.2 ACL access right cf page 248*/
#define KAUTH_VNODE_READ_DATA		(1 << 1)
#define KAUTH_VNODE_LIST_DIRECTORY	KAUTH_VNODE_READ_DATA
#define KAUTH_VNODE_WRITE_DATA		(1 << 2)
#define KAUTH_VNODE_ADD_FILE		KAUTH_VNODE_WRITE_DATA
#define KAUTH_VNODE_EXECUTE		(1 << 3)
#define KAUTH_VNODE_SEARCH		KAUTH_VNODE_EXECUTE
#define KAUTH_VNODE_DELETE		(1 << 4)
#define KAUTH_VNODE_APPEND_DATA		(1 << 5)
#define KAUTH_VNODE_ADD_SUBDIRECTORY	KAUTH_VNODE_APPEND_DATA
#define KAUTH_VNODE_DELETE_CHILD	(1 << 6)
#define KAUTH_VNODE_READ_ATTRIBUTES	(1 << 7)
#define KAUTH_VNODE_WRITE_ATTRIBUTES	(1 << 8)
#define KAUTH_VNODE_READ_EXTATTRIBUTES	(1 << 9)
#define KAUTH_VNODE_WRITE_EXTATTRIBUTES	(1 << 10)
#define KAUTH_VNODE_READ_SECURITY	(1 << 11)
#define KAUTH_VNODE_WRITE_SECURITY	(1 << 12)
#define KAUTH_VNODE_CHANGE_OWNER	(1 << 13)
#define KAUTH_VNODE_SYNCHRONIZE		(1 << 20)
#define KAUTH_VNODE_GENERIC_ALL		(1 << 21)
#define KAUTH_VNODE_GENERIC_EXECUTE	(1 << 22)
#define KAUTH_VNODE_GENERIC_WRITE	(1 << 23)
#define KAUTH_VNODE_GENERIC_READ	(1 << 24)


static int hf_afp_acl_access_bitmap		= -1;
static int ett_afp_acl_access_bitmap		= -1;
static int hf_afp_acl_access_bitmap_read_data	= -1;
static int hf_afp_acl_access_bitmap_write_data	= -1;
static int hf_afp_acl_access_bitmap_execute	= -1;
static int hf_afp_acl_access_bitmap_delete	= -1;
static int hf_afp_acl_access_bitmap_append_data	= -1;
static int hf_afp_acl_access_bitmap_delete_child= -1;
static int hf_afp_acl_access_bitmap_read_attrs	= -1;
static int hf_afp_acl_access_bitmap_write_attrs	= -1;
static int hf_afp_acl_access_bitmap_read_extattrs  = -1;
static int hf_afp_acl_access_bitmap_write_extattrs = -1;
static int hf_afp_acl_access_bitmap_read_security  = -1;
static int hf_afp_acl_access_bitmap_write_security = -1;
static int hf_afp_acl_access_bitmap_change_owner   = -1;
static int hf_afp_acl_access_bitmap_synchronize	= -1;
static int hf_afp_acl_access_bitmap_generic_all	= -1;
static int hf_afp_acl_access_bitmap_generic_execute = -1;
static int hf_afp_acl_access_bitmap_generic_write   = -1;
static int hf_afp_acl_access_bitmap_generic_read    = -1;


#define hash_init_count 20

/* Hash functions */
static gint  afp_equal (gconstpointer v, gconstpointer v2);
static guint afp_hash  (gconstpointer v);

typedef struct {
	guint32 conversation;
	guint16	seq;
} afp_request_key;

static GHashTable *afp_request_hash = NULL;

static guint Vol;      /* volume */
static guint Did;      /* parent directory ID */

/* Hash Functions */
static gint  afp_equal (gconstpointer v, gconstpointer v2)
{
	const afp_request_key *val1 = (const afp_request_key*)v;
	const afp_request_key *val2 = (const afp_request_key*)v2;

	if (val1->conversation == val2->conversation &&
			val1->seq == val2->seq) {
		return 1;
	}
	return 0;
}

static guint afp_hash  (gconstpointer v)
{
        const afp_request_key *afp_key = (const afp_request_key*)v;
        return afp_key->seq;
}

/* --------------------------
*/
#define PAD(x)      { proto_tree_add_item(tree, hf_afp_pad, tvb, offset,  x, FALSE); offset += x; }

static guint16
decode_vol_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint16  bitmap;

	bitmap = tvb_get_ntohs(tvb, offset);
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_vol_bitmap, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_vol_bitmap);
	}

	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_Attributes,	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_Signature, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_CreateDate, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_ModDate, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_BackupDate, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_ID, 		tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_BytesFree, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_BytesTotal, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_Name, 		tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_ExtBytesFree, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_ExtBytesTotal, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_BlockSize , 	tvb, offset, 2,FALSE);

	return bitmap;
}

/* -------------------------- */
static guint16
decode_vol_attribute (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint16  bitmap;

	bitmap = tvb_get_ntohs(tvb, offset);
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_vol_attribute, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_vol_attribute);
	}
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_ReadOnly                ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_HasVolumePassword       ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_SupportsFileIDs         ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_SupportsCatSearch       ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_SupportsBlankAccessPrivs,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_SupportsUnixPrivs       ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_SupportsUTF8Names       ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_NoNetworkUserID         ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_DefaultPrivsFromParent  ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_NoExchangeFiles         ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_SupportsExtAttrs        ,tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_attribute_SupportsACLs            ,tvb, offset, 2,FALSE);

	return bitmap;
}

/* --------------------------
	cf AFP3.0.pdf page 38
	date  are number of seconds from 12:00am on 01.01.2000 GMT
	backup : 0x8000000 not set
	from netatalk adouble.h
*/
#define DATE_NOT_SET         0x80000000
#define AD_DATE_DELTA         946684800
#define AD_DATE_TO_UNIX(x)    (x + AD_DATE_DELTA)
static guint32
print_date(proto_tree *tree,int id, tvbuff_t *tvb, gint offset)
{
	time_t date = tvb_get_ntohl(tvb, offset);
	nstime_t tv;

	tv.secs = AD_DATE_TO_UNIX(date);
	tv.nsecs = 0;
	proto_tree_add_time(tree, id, tvb, offset, 4, &tv);

	return date;
}

/* -------------------------- */
static gint
parse_vol_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	guint16 nameoff = 0;

	if ((bitmap & kFPVolAttributeBit)) {
		decode_vol_attribute(tree,tvb,offset);
		offset += 2;
	}
	if ((bitmap & kFPVolSignatureBit)) {
		proto_tree_add_item(tree, hf_afp_vol_signature,tvb, offset, 2, FALSE);
		offset += 2;
	}
	if ((bitmap & kFPVolCreateDateBit)) {
		print_date(tree, hf_afp_vol_creation_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPVolModDateBit)) {
		print_date(tree, hf_afp_vol_modification_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPVolBackupDateBit)) {
		print_date(tree, hf_afp_vol_backup_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPVolIDBit)) {
		proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
		offset += 2;
	}
	if ((bitmap & kFPVolBytesFreeBit)) {
		proto_tree_add_item(tree, hf_afp_vol_bytes_free,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPVolBytesTotalBit)) {
		proto_tree_add_item(tree, hf_afp_vol_bytes_total,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPVolNameBit)) {
		nameoff = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_vol_name_offset,tvb, offset, 2, FALSE);
		offset += 2;
	}
	if ((bitmap & kFPVolExtBytesFreeBit)) {
		proto_tree_add_item(tree, hf_afp_vol_ex_bytes_free,tvb, offset, 8, FALSE);
		offset += 8;
	}
	if ((bitmap & kFPVolExtBytesTotalBit)) {
		proto_tree_add_item(tree, hf_afp_vol_ex_bytes_total,tvb, offset, 8, FALSE);
		offset += 8;
	}
	if ((bitmap & kFPVolBlockSizeBit)) {
		proto_tree_add_item(tree, hf_afp_vol_block_size,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if (nameoff) {
		guint8 len;

		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_afp_vol_name, tvb, offset, 1,FALSE);
		offset += len +1;

	}
	return offset;
}

/* -------------------------- */
static guint16
decode_file_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint16		bitmap;

	bitmap = tvb_get_ntohs(tvb, offset);
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_file_bitmap, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_file_bitmap);
	}
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_Attributes      , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ParentDirID    , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_CreateDate     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ModDate        , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_BackupDate     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_FinderInfo     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_LongName       , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ShortName      , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_NodeID         , tvb, offset, 2,FALSE);

	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_DataForkLen   	, tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_RsrcForkLen   	, tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ExtDataForkLen	, tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_LaunchLimit   	, tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_UTF8Name	    , tvb, offset, 2,FALSE);

	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ExtRsrcForkLen	, tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_UnixPrivs      , tvb, offset, 2,FALSE);

	return bitmap;
}

/* -------------------------- */
static guint16
decode_file_attribute(proto_tree *tree, tvbuff_t *tvb, gint offset, int shared)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint16		attribute;

	attribute = tvb_get_ntohs(tvb, offset);
	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, 2,
					"File Attributes: 0x%04x", attribute);
		sub_tree = proto_item_add_subtree(item, ett_afp_file_attribute);
	}
	proto_tree_add_item(sub_tree, hf_afp_file_attribute_Invisible    , tvb, offset, 2,FALSE);
	if (!shared)
		proto_tree_add_item(sub_tree, hf_afp_file_attribute_MultiUser    , tvb, offset, 2,FALSE);

	proto_tree_add_item(sub_tree, hf_afp_file_attribute_System       , tvb, offset, 2,FALSE);

	if (!shared) {
		proto_tree_add_item(sub_tree, hf_afp_file_attribute_DAlreadyOpen , tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_file_attribute_RAlreadyOpen , tvb, offset, 2,FALSE);
	}
	/* writeinhibit is file only but Macs are setting it with FPSetFileDirParms too */
	proto_tree_add_item(sub_tree, hf_afp_file_attribute_WriteInhibit , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_attribute_BackUpNeeded , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_attribute_RenameInhibit, tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_attribute_DeleteInhibit, tvb, offset, 2,FALSE);

	if (!shared)
		proto_tree_add_item(sub_tree, hf_afp_file_attribute_CopyProtect  , tvb, offset, 2,FALSE);

	proto_tree_add_item(sub_tree, hf_afp_file_attribute_SetClear     , tvb, offset, 2,FALSE);

	return(attribute);
}

static void
decode_access_rights (proto_tree *tree, tvbuff_t *tvb, int hf, gint offset)
{
  	proto_tree *sub_tree;
  	proto_item *item;

	if (tree) {
		item = proto_tree_add_item(tree, hf, tvb, offset, 4, FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_dir_ar);

		proto_tree_add_item(sub_tree, hf_afp_dir_ar_o_search, tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_o_read  , tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_o_write , tvb, offset, 4,	FALSE);

		proto_tree_add_item(sub_tree, hf_afp_dir_ar_g_search, tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_g_read  , tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_g_write , tvb, offset, 4,	FALSE);

		proto_tree_add_item(sub_tree, hf_afp_dir_ar_e_search, tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_e_read  , tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_e_write , tvb, offset, 4,	FALSE);

		proto_tree_add_item(sub_tree, hf_afp_dir_ar_u_search, tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_u_read  , tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_u_write , tvb, offset, 4,	FALSE);

		proto_tree_add_item(sub_tree, hf_afp_dir_ar_blank   , tvb, offset, 4,	FALSE);
		proto_tree_add_item(sub_tree, hf_afp_dir_ar_u_own   , tvb, offset, 4,	FALSE);
	}
}

static void
decode_unix_privs (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
  	proto_tree *sub_tree;
  	proto_item *item;

	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, 16,
		    "UNIX privileges");
		sub_tree = proto_item_add_subtree(item, ett_afp_unix_privs);

		proto_tree_add_item(sub_tree, hf_afp_unix_privs_uid, tvb, offset, 4, FALSE);
		proto_tree_add_item(sub_tree, hf_afp_unix_privs_gid, tvb, offset+4, 4, FALSE);
		proto_tree_add_item(sub_tree, hf_afp_unix_privs_permissions, tvb, offset+8, 4, FALSE);
		decode_access_rights(sub_tree, tvb, hf_afp_unix_privs_ua_permissions, offset+12);
	}
}

/* -------------------------- */
static gint
parse_long_filename(proto_tree *tree, tvbuff_t *tvb, gint offset, gint org_offset)
{
	guint16 lnameoff;
	gint tp_ofs = 0;
	guint8 len;

	lnameoff = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_long_name_offset,tvb, offset, 2, FALSE);
	if (lnameoff) {
		tp_ofs = lnameoff +org_offset;
		len = tvb_get_guint8(tvb, tp_ofs);
		proto_tree_add_item(tree, hf_afp_path_len, tvb, tp_ofs,  1,FALSE);
		tp_ofs++;
		proto_tree_add_item(tree, hf_afp_path_name, tvb, tp_ofs, len,FALSE);
		tp_ofs += len;
	}
	return tp_ofs;
}

/* -------------------------- */
static gint
parse_UTF8_filename(proto_tree *tree, tvbuff_t *tvb, gint offset, gint org_offset)
{
	guint16 unameoff;
	gint tp_ofs = 0;
	guint16 len;

	unameoff = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_unicode_name_offset,tvb, offset, 2, FALSE);
	offset += 2;
	if (unameoff) {
	      /* FIXME AFP3.x reuses PDINFO bit for UTF8.
	       * In enumerate_ext it's pad with 4 bytes, PDINFO was 6 bytes,
	       * but not in catsearch_ext.
	       * Last but not least there's a bug in OSX catsearch_ext for spec2
	       * offset is off by 2 bytes.
	       */

		tp_ofs = unameoff +org_offset;
	       if (tp_ofs > offset) {
	           PAD(4);
	        }
	        else if (tp_ofs < offset) {
	            tp_ofs = offset;
	        }
		proto_tree_add_item( tree, hf_afp_path_unicode_hint, tvb, tp_ofs, 4,FALSE);
		tp_ofs += 4;

		len = tvb_get_ntohs(tvb, tp_ofs);
		proto_tree_add_item( tree, hf_afp_path_unicode_len, tvb, tp_ofs, 2,FALSE);
		tp_ofs += 2;

		proto_tree_add_item(tree, hf_afp_path_name, tvb, tp_ofs, len,FALSE);
		tp_ofs += len;
	}
	return tp_ofs;
}

/* -------------------------- */
static gint
parse_file_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 bitmap, int shared)
{
	/* guint16 snameoff = 0; */
	gint 	max_offset = 0;

	gint 	org_offset = offset;

	if ((bitmap & kFPAttributeBit)) {
		decode_file_attribute(tree, tvb, offset, shared);
		offset += 2;
	}
	if ((bitmap & kFPParentDirIDBit)) {
		proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
		offset += 4;
	}
	if ((bitmap & kFPCreateDateBit)) {
		print_date(tree, hf_afp_creation_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPModDateBit)) {
		print_date(tree, hf_afp_modification_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPBackupDateBit)) {
		print_date(tree, hf_afp_backup_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPFinderInfoBit)) {
		proto_tree_add_item(tree, hf_afp_finder_info,tvb, offset, 32, FALSE);
		offset += 32;
	}
	if ((bitmap & kFPLongNameBit)) {
		gint tp_ofs;

		tp_ofs = parse_long_filename(tree, tvb, offset, org_offset);
		max_offset = (tp_ofs >max_offset)?tp_ofs:max_offset;

		offset += 2;

	}
	if ((bitmap & kFPShortNameBit)) {
		/* snameoff = tvb_get_ntohs(tvb, offset); */
		proto_tree_add_item(tree, hf_afp_short_name_offset,tvb, offset, 2, FALSE);
		offset += 2;
	}
	if ((bitmap & kFPNodeIDBit)) {
		proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4,FALSE);
		offset += 4;
	}

	if ((bitmap & kFPDataForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_file_DataForkLen, tvb, offset, 4,FALSE);
		offset += 4;
	}

	if ((bitmap & kFPRsrcForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_file_RsrcForkLen, tvb, offset, 4,FALSE);
		offset += 4;
	}

	if ((bitmap & kFPExtDataForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_file_ExtDataForkLen, tvb, offset, 8,FALSE);
		offset += 8;
	}

	if ((bitmap & kFPLaunchLimitBit)) {
		offset += 2;	/* ? */
	}

	if ((bitmap & kFPUTF8NameBit)) {
		gint tp_ofs;

		tp_ofs = parse_UTF8_filename(tree, tvb, offset, org_offset);
		max_offset = (tp_ofs >max_offset)?tp_ofs:max_offset;
		offset += 6;
	}

	if ((bitmap & kFPExtRsrcForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_file_ExtRsrcForkLen, tvb, offset, 8,FALSE);
		offset += 8;
	}

	if ((bitmap & kFPUnixPrivsBit)) {
		/*
		 * XXX - the AFP 3.0 spec says this is "Four bytes", but
		 * also says the privileges are "stored in an FPUnixPrivs
		 * structure", which is 16 bytes long.
		 *
		 * We assume, for now, that the latter is true.
		 */
		decode_unix_privs(tree, tvb, offset);
		offset += 16;
	}

	return (max_offset)?max_offset:offset;
}

/* -------------------------- */
static guint16
decode_dir_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint16		bitmap;

	bitmap = tvb_get_ntohs(tvb, offset);
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_dir_bitmap, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_dir_bitmap);
	}

	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_Attributes      , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_ParentDirID    , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_CreateDate     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_ModDate        , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_BackupDate     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_FinderInfo     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_LongName       , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_ShortName      , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_NodeID         , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_OffspringCount , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_OwnerID        , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_GroupID        , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_AccessRights   , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_UTF8Name	   , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_UnixPrivs      , tvb, offset, 2,FALSE);

	return bitmap;
}

/* -------------------------- */
static guint16
decode_dir_attribute(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint16		attribute;

	attribute = tvb_get_ntohs(tvb, offset);
	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, 2,
					"Directory Attributes: 0x%04x", attribute);
		sub_tree = proto_item_add_subtree(item, ett_afp_dir_attribute);
	}
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_Invisible    , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_IsExpFolder  , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_System       , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_Mounted      , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_InExpFolder  , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_BackUpNeeded , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_RenameInhibit, tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_dir_attribute_DeleteInhibit, tvb, offset, 2,FALSE);

	return(attribute);
}

/* -------------------------- */
static gint
parse_dir_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	/* guint16 snameoff = 0; */
	gint 	max_offset = 0;

	gint 	org_offset = offset;

	if ((bitmap & kFPAttributeBit)) {
		decode_dir_attribute(tree, tvb, offset);
		offset += 2;
	}
	if ((bitmap & kFPParentDirIDBit)) {
		proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
		offset += 4;
	}
	if ((bitmap & kFPCreateDateBit)) {
		print_date(tree, hf_afp_creation_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPModDateBit)) {
		print_date(tree, hf_afp_modification_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPBackupDateBit)) {
		print_date(tree, hf_afp_backup_date,tvb, offset);
		offset += 4;
	}
	if ((bitmap & kFPFinderInfoBit)) {
		proto_tree_add_item(tree, hf_afp_finder_info,tvb, offset, 32, FALSE);
		offset += 32;
	}
	if ((bitmap & kFPLongNameBit)) {
		gint tp_ofs;

		tp_ofs = parse_long_filename(tree, tvb, offset, org_offset);
		max_offset = (tp_ofs >max_offset)?tp_ofs:max_offset;

		offset += 2;
	}
	if ((bitmap & kFPShortNameBit)) {
		/* snameoff = tvb_get_ntohs(tvb, offset); */
		proto_tree_add_item(tree, hf_afp_short_name_offset,tvb, offset, 2, FALSE);
		offset += 2;
	}
	if ((bitmap & kFPNodeIDBit)) {
		proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4,FALSE);
		offset += 4;
	}
	if ((bitmap & kFPOffspringCountBit)) {
		proto_tree_add_item(tree, hf_afp_dir_offspring, tvb, offset, 2,FALSE);
		offset += 2;		/* error in AFP3.0.pdf */
	}
	if ((bitmap & kFPOwnerIDBit)) {
		proto_tree_add_item(tree, hf_afp_dir_OwnerID, tvb, offset, 4,	FALSE);
		offset += 4;
	}
	if ((bitmap & kFPGroupIDBit)) {
		proto_tree_add_item(tree, hf_afp_dir_GroupID, tvb, offset, 4,	FALSE);
		offset += 4;
	}
	if ((bitmap & kFPAccessRightsBit)) {
		decode_access_rights(tree, tvb, hf_afp_dir_ar, offset);
		offset += 4;
	}
	if ((bitmap & kFPUTF8NameBit)) {
		gint tp_ofs;

		tp_ofs = parse_UTF8_filename(tree, tvb, offset, org_offset);
		max_offset = (tp_ofs >max_offset)?tp_ofs:max_offset;
		offset += 6;
	}
	if ((bitmap & kFPUnixPrivsBit)) {
		/*
		 * XXX - the AFP 3.0 spec says this is "Four bytes", but
		 * also says the privileges are "stored in an FPUnixPrivs
		 * structure", which is 16 bytes long.
		 *
		 * We assume, for now, that the latter is true.
		 */
		decode_unix_privs(tree, tvb, offset);
		offset += 16;
	}
	return (max_offset)?max_offset:offset;
}

/* -------------------------- */
static gchar *
name_in_bitmap(tvbuff_t *tvb, gint offset, guint16 bitmap, int isdir)
{
	gchar *name;
	gint 	org_offset = offset;
	guint16 nameoff;
	guint8  len;
	guint16 len16;
	gint	tp_ofs;

	if ((bitmap & kFPAttributeBit))		/* 0 */
		offset += 2;
	if ((bitmap & kFPParentDirIDBit))	/* 1 */
		offset += 4;
	if ((bitmap & kFPCreateDateBit))	/* 2 */
		offset += 4;
	if ((bitmap & kFPModDateBit))		/* 3 */
		offset += 4;
	if ((bitmap & kFPBackupDateBit))	/* 4 */
		offset += 4;
	if ((bitmap & kFPFinderInfoBit))	/* 5 */
		offset += 32;

	if ((bitmap & kFPLongNameBit)) {	/* 6 */
		nameoff = tvb_get_ntohs(tvb, offset);
		if (nameoff) {
			tp_ofs = nameoff +org_offset;
			len = tvb_get_guint8(tvb, tp_ofs);
			tp_ofs++;
			name = tvb_get_ephemeral_string(tvb, tp_ofs, len);
			return name;
		}
		offset += 2;
	}

	if ((bitmap & kFPShortNameBit)) 	/* 7 */
		offset += 2;
	if ((bitmap & kFPNodeIDBit)) 		/* 8 */
		offset += 4;

        if (isdir) {
		if ((bitmap & kFPOffspringCountBit))	/* 9 */
			offset += 2;
		if ((bitmap & kFPOwnerIDBit)) 		/* 10*/
			offset += 4;
		if ((bitmap & kFPGroupIDBit)) 		/* 11*/
			offset += 4;
		if ((bitmap & kFPAccessRightsBit))	/* 12*/
			offset += 4;
        }
        else {
		if ((bitmap & kFPDataForkLenBit))	/* 9 */
			offset += 4;
		if ((bitmap & kFPRsrcForkLenBit)) 	/* 10*/
			offset += 4;
		if ((bitmap & kFPExtDataForkLenBit)) 	/* 11*/
			offset += 8;
		if ((bitmap & kFPLaunchLimitBit))	/* 12*/
			offset += 2; /* FIXME ? */
        }

	if ((bitmap & kFPUTF8NameBit)) {		/* 13 */
		nameoff = tvb_get_ntohs(tvb, offset);
		if (nameoff) {
			tp_ofs = nameoff +org_offset +4;
			len16 = tvb_get_ntohs(tvb, tp_ofs);
			tp_ofs += 2;
			name = tvb_get_ephemeral_string(tvb, tp_ofs, len16);
			return name;
		}
	}
	return NULL;
}

/* -------------------------- */
static gchar *
name_in_dbitmap(tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	gchar *name;

	name = name_in_bitmap(tvb, offset, bitmap, 1);
	if (name != NULL)
		return name;
	/*
		check UTF8 name
	*/

	return name;
}

/* -------------------------- */
static gchar *
name_in_fbitmap(tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	gchar *name;

	name = name_in_bitmap(tvb, offset, bitmap, 0);
	if (name != NULL)
		return name;
	/*
		check UTF8 name
	*/

	return name;
}

/* -------------------------- */
static gint
decode_vol_did(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	Vol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;

	Did = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;
	return offset;
}

/* -------------------------- */
static gint
decode_vol_did_file_dir_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	offset = decode_vol_did(tree, tvb, offset);

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	decode_dir_bitmap(tree, tvb, offset);
	offset += 2;

	return offset;
}

/* ------------------------ */
static const gchar *
get_name(tvbuff_t *tvb, int offset, int type)
{
  	int   len;
  	const gchar *string;

	switch (type) {
	case 1:
	case 2:
		len = tvb_get_guint8(tvb, offset);
		offset++;
		string = tvb_format_text(tvb,offset, len);
		break;
	case 3:
		len = tvb_get_ntohs(tvb, offset +4);
		offset += 6;
		string = tvb_format_text(tvb,offset, len);
    		break;
	default:
		string = "Unknown type";
		break;
    	}
	return string;
}
/* -------------------------- */
static gint
decode_name_label (proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, const gchar *label)
{
	int len;
	int header;
	const gchar *name;
	guint8 type;
  	proto_tree *sub_tree = NULL;
  	proto_item *item;

	type = tvb_get_guint8(tvb, offset);
	if (type == 3) {
	   	header = 7;
		len = tvb_get_ntohs(tvb, offset +5);
	}
	else {
		header = 2;
	   	len = tvb_get_guint8(tvb, offset +1);
	}
	name = get_name(tvb, offset +1, type);

	if (pinfo && check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Vol=%u Did=%u", Vol, Did);
		if (len) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " Name=%s", name);
		}
	}

	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, len +header, label, name);
		sub_tree = proto_item_add_subtree(item, ett_afp_path_name);

		proto_tree_add_item(  sub_tree, hf_afp_path_type, tvb, offset,   1,FALSE);
		offset++;
		if (type == 3) {
			proto_tree_add_item( sub_tree, hf_afp_path_unicode_hint,  tvb, offset,  4,FALSE);
			offset += 4;
			proto_tree_add_item( sub_tree, hf_afp_path_unicode_len,  tvb, offset,   2,FALSE);
			offset += 2;
		}
		else {
			proto_tree_add_item( sub_tree, hf_afp_path_len,  tvb, offset,   1,FALSE);
			offset++;
		}

		proto_tree_add_string(sub_tree, hf_afp_path_name, tvb, offset, len,name);
	}
	else
		offset += header;

	return offset +len;
}

/* -------------------------- */
static gint
decode_name (proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	return decode_name_label(tree, pinfo, tvb, offset, "Path: %s");
}

/* -------------------------- */
static void
add_info_fork(tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint16 ofork;

	ofork = tvb_get_ntohs(tvb, offset);
	if (ofork && check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Fork=%u", ofork);
	}
}

/* -------------------------- */
static void
add_info_vol(tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint16 vol;

	vol = tvb_get_ntohs(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Vol=%u", vol);
	}
}

/* ************************** */
static gint
dissect_query_afp_open_vol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	int len;

	PAD(1);

	decode_vol_bitmap(tree, tvb, offset);
	offset += 2;

	len = tvb_get_guint8(tvb, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		const gchar *rep;
		rep = get_name(tvb, offset, 2);
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", rep);
	}

	if (!tree)
		return offset;

	proto_tree_add_item(tree, hf_afp_vol_name, tvb, offset, 1,FALSE);
	offset += len +1;

  	len = tvb_reported_length_remaining(tvb,offset);
  	if (len >= 8) {
		/* optionnal password */
		proto_tree_add_item(tree, hf_afp_passwd, tvb, offset, 8,FALSE);
		offset += 8;
	}
	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_open_vol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	if (!tree)
		return offset;
	bitmap = decode_vol_bitmap(tree, tvb, offset);
	offset += 2;
	offset = parse_vol_bitmap(tree, tvb, offset, bitmap);

	return offset;
}

/* ************************** */
static gint
dissect_reply_afp_get_server_param(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint8 num;
	guint8 len;
	guint8 flag;
	guint8 i;
  	proto_tree *sub_tree = NULL;
  	proto_tree *flag_tree;
  	proto_item *item;
  	proto_item *ti;

	if (!tree)
		return offset;

	print_date(tree, hf_afp_server_time,tvb, offset);
	offset += 4;

	num = tvb_get_guint8(tvb, offset);
	item = proto_tree_add_text(tree, tvb, offset, 1, "Volumes : %d", num);
	sub_tree = proto_item_add_subtree(item, ett_afp_server_vol);
	offset++;

	for (i = 0; i < num; i++) {
		const gchar *rep;

		item = proto_tree_add_text(sub_tree, tvb, offset, -1,"Volume");
		tree = proto_item_add_subtree(item, ett_afp_vol_list);

		flag = tvb_get_guint8(tvb, offset);

		ti = proto_tree_add_text(tree, tvb, offset , 1,"Flags : 0x%02x", flag);
		flag_tree = proto_item_add_subtree(ti, ett_afp_vol_flag);
		proto_tree_add_item(flag_tree, hf_afp_vol_flag_passwd, tvb, offset, 1,FALSE);
		proto_tree_add_item(flag_tree, hf_afp_vol_flag_unix_priv ,tvb, offset, 1,FALSE);
		offset++;

		len  = tvb_get_guint8(tvb, offset) +1;
		rep = get_name(tvb, offset, 2);
		proto_item_set_text(item, "%s", rep);
		proto_item_set_len(item, len +1);

		proto_tree_add_item(tree, hf_afp_vol_name, tvb, offset, 1,FALSE);

		offset += len;
	}
	return offset;
}

/* **************************
	next calls use the same format :
		1 pad byte
		volume id
	AFP_FLUSH
	AFP_CLOSEVOL
	AFP_OPENDT
*/
static gint
dissect_query_afp_with_vol_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	if (!tree)
		return offset;
	PAD(1);

	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;
	return offset;
}

/* ************************** */
static gint
dissect_query_afp_open_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;

	proto_tree_add_item(tree, hf_afp_fork_type, tvb, offset, 1,FALSE);
	offset++;

	offset = decode_vol_did(tree, tvb, offset);

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_access_mode, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_access_mode);

		proto_tree_add_item(sub_tree, hf_afp_access_read      , tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_access_write     , tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_access_deny_read , tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_access_deny_write, tvb, offset, 2,FALSE);
	}
	offset += 2;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_open_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16 f_bitmap;

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	offset = parse_file_bitmap(tree, tvb, offset, f_bitmap,0);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_enumerate_ext2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_vol_did_file_dir_bitmap(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_req_count, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_start_index32, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_max_reply_size32, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_enumerate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_vol_did_file_dir_bitmap(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_req_count, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_start_index, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_max_reply_size, tvb, offset, 2,FALSE);
	offset += 2;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* -------------------------- */
static int
loop_record(tvbuff_t *tvb, proto_tree *ptree, gint offset,
		int count, guint16 d_bitmap, guint16 f_bitmap, int add, int ext)
{
  	proto_tree *tree = NULL;
  	proto_item *item;
	gchar 	*name;
	guint8	flags;
	guint	size;
	gint	org;
	int i;
	int decal;

	for (i = 0; i < count; i++) {
		org = offset;
		if (ext) {
			size = tvb_get_ntohs(tvb, offset) +add *2;
			decal = 2;
		}
		else {
			size = tvb_get_guint8(tvb, offset) +add;
			decal = 1;
		}
		if (!size)
			return offset;	/* packet is malformed */
		flags = tvb_get_guint8(tvb, offset +decal);

		decal += (ext)?2:1;

		if (ptree) {
			if (flags) {
				name = name_in_dbitmap(tvb, offset +decal, d_bitmap);
			}
			else {
				name = name_in_fbitmap(tvb, offset +decal, f_bitmap);
			}
			if (name) {
				item = proto_tree_add_text(ptree, tvb, offset, size, "%s", name);
			}
			else {
				item = proto_tree_add_text(ptree, tvb, offset, size, "line %d", i+1);
			}
			tree = proto_item_add_subtree(item, ett_afp_enumerate_line);
		}
		if (ext) {
			proto_tree_add_item(tree, hf_afp_struct_size16, tvb, offset, 2,FALSE);
			offset += 2;
		}
		else {
			proto_tree_add_item(tree, hf_afp_struct_size, tvb, offset, 1,FALSE);
			offset++;
		}

		proto_tree_add_item(tree, hf_afp_file_flag, tvb, offset, 1,FALSE);
		offset++;
		if (ext) {
			PAD(1);
		}
		if (flags) {
			offset = parse_dir_bitmap(tree, tvb, offset, d_bitmap);
		}
		else {
			offset = parse_file_bitmap(tree, tvb, offset, f_bitmap,0);
		}
		if ((offset & 1))
			PAD(1);
		offset = org +size;		/* play safe */
	}
	return offset;
}
/* ------------------------- */
static gint
reply_enumerate(tvbuff_t *tvb, proto_tree *tree, gint offset, int ext)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	int count;
	guint16 f_bitmap;
	guint16 d_bitmap;

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	d_bitmap = decode_dir_bitmap(tree, tvb, offset);
	offset += 2;

	count = tvb_get_ntohs(tvb, offset);
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_req_count, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_enumerate);
	}
	offset += 2;

	return loop_record(tvb,sub_tree, offset, count, d_bitmap, f_bitmap,0, ext);
}

/* ------------------------- */
static gint
dissect_reply_afp_enumerate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	return reply_enumerate(tvb, tree, offset, 0);
}

/* **************************/
static gint
dissect_reply_afp_enumerate_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	return reply_enumerate(tvb, tree, offset, 1);
}

/* **************************/
static gint
catsearch_spec(tvbuff_t *tvb, proto_tree *ptree, gint offset, int ext, guint32	bitmap, const gchar *label)
{
  	proto_tree *tree = NULL;
  	proto_item *item;
	guint16	size;
	gint	org;

	org = offset;

	if (ext) {
		size = tvb_get_ntohs(tvb, offset) +2;
	}
	else {
		size = tvb_get_guint8(tvb, offset) +2;
	}

	item = proto_tree_add_text(ptree, tvb, offset, size, label);
	tree = proto_item_add_subtree(item, ett_afp_cat_spec);

	if (ext) {
		proto_tree_add_item(tree, hf_afp_struct_size16, tvb, offset, 2,FALSE);
		offset += 2;
	}
	else {
		proto_tree_add_item(tree, hf_afp_struct_size, tvb, offset, 1,FALSE);
		offset++;
		PAD(1);
	}

	offset = parse_file_bitmap(tree, tvb, offset, (guint16) bitmap,0);
	offset = org +size;

	return offset;
}

/* ------------------------- */
static gint
query_catsearch(tvbuff_t *tvb, proto_tree *ptree, gint offset, int ext)
{
  	proto_tree *tree = NULL, *sub_tree;
  	proto_item *item;
	guint16 f_bitmap;
	guint16 d_bitmap;
	guint32	r_bitmap;

	if (!ptree)
		return offset;
	PAD(1);

	proto_tree_add_item(ptree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(ptree, hf_afp_cat_req_matches, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(ptree, hf_afp_reserved, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(ptree, hf_afp_cat_position, tvb, offset, 16,FALSE);
	offset += 16;

	f_bitmap = decode_file_bitmap(ptree, tvb, offset);
	offset += 2;

	d_bitmap = decode_dir_bitmap(ptree, tvb, offset);
	offset += 2;

	r_bitmap = tvb_get_ntohl(tvb, offset);
	/* Already checked this above: if (ptree) */ {
		item = proto_tree_add_item(ptree, hf_afp_file_bitmap, tvb, offset, 4,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_cat_r_bitmap);

		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_Attributes      , tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ParentDirID    , tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_CreateDate     , tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ModDate        , tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_BackupDate     , tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_FinderInfo     , tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_LongName       , tvb, offset, 4,FALSE);

		if (d_bitmap == 0) {
			/* Only for file-only searches */
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_DataForkLen   	, tvb, offset, 4,FALSE);
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_RsrcForkLen   	, tvb, offset, 4,FALSE);
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ExtDataForkLen	, tvb, offset, 4,FALSE);
		}
		if (f_bitmap == 0) {
			/* Only for directory-only searches */
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_OffspringCount   	, tvb, offset, 4,FALSE);
		}

		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_UTF8Name	    , tvb, offset, 4,FALSE);

		if (d_bitmap == 0) {
			/* Only for file-only searches */
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ExtRsrcForkLen	, tvb, offset, 4,FALSE);
		}
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_PartialNames	, tvb, offset, 4,FALSE);
	}
	offset += 4;

	/* spec 1 */
	offset = catsearch_spec(tvb, ptree, offset, ext, r_bitmap, "Spec 1");

	/* spec 2 */
	offset = catsearch_spec(tvb, ptree, offset, ext, r_bitmap, "Spec 2");

	return offset;
}

/* ------------------------- */
static gint
dissect_query_afp_cat_search(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ptree, gint offset)
{
	return query_catsearch(tvb, ptree, offset, 0);

}
/* **************************/
static gint
dissect_query_afp_cat_search_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ptree, gint offset)
{
	return query_catsearch(tvb, ptree, offset, 1);

}

/* **************************/
static gint
reply_catsearch(tvbuff_t *tvb, proto_tree *tree, gint offset, int ext)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint16 f_bitmap;
	guint16 d_bitmap;
	int count;

	proto_tree_add_item(tree, hf_afp_cat_position, tvb, offset, 16,FALSE);
	offset += 16;

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	d_bitmap = decode_dir_bitmap(tree, tvb, offset);
	offset += 2;

	count = tvb_get_ntohl(tvb, offset);
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_cat_count, tvb, offset, 4,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_cat_search);
	}
	offset += 4;

	return loop_record(tvb,sub_tree, offset, count, d_bitmap, f_bitmap, 2, ext);
}

/* -------------------------- */
static gint
dissect_reply_afp_cat_search(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	return reply_catsearch(tvb, tree, offset, 0);
}

/* **************************/
static gint
dissect_reply_afp_cat_search_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	return reply_catsearch(tvb, tree, offset, 1);
}

/* **************************/
static gint
dissect_query_afp_get_vol_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1)
        add_info_vol(tvb, pinfo, offset);

	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;

	decode_vol_bitmap(tree, tvb, offset);
	offset += 2;

	return offset;
}

/* ------------------------ */
static gint
dissect_reply_afp_get_vol_param(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	bitmap = decode_vol_bitmap(tree, tvb, offset);
	offset += 2;

	offset = parse_vol_bitmap(tree, tvb, offset, bitmap);

	return offset;
}

/* **************************/
static gint
dissect_query_afp_set_vol_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	PAD(1)

        add_info_vol(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;

	bitmap = decode_vol_bitmap(tree, tvb, offset);
	offset += 2;

	offset = parse_vol_bitmap(tree, tvb, offset, bitmap);

	return offset;
}

/* ***************************/
static gint
decode_uam_parameters(const char *uam, int len_uam, tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	int len;

	if (!strncasecmp(uam, "Cleartxt passwrd", len_uam)) {
		if ((offset & 1))
			PAD(1);

		len = 8; /* tvb_strsize(tvb, offset);*/
		proto_tree_add_item(tree, hf_afp_passwd, tvb, offset, len,FALSE);
		offset += len;
	}
	else if (!strncasecmp(uam, "DHCAST128", len_uam)) {
		if ((offset & 1))
			PAD(1);

		len = 16;
		proto_tree_add_item(tree, hf_afp_random, tvb, offset, len,FALSE);
		offset += len;
        }
	else if (!strncasecmp(uam, "2-Way Randnum exchange", len_uam)) {
		/* nothing */
		return offset;
	}
	return offset;
}

/* ---------------- */
static gint
dissect_query_afp_login(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	int len;
	int len_uam;
	const char *uam;

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_AFPVersion, tvb, offset, 1,FALSE);
	offset += len +1;
	len_uam = tvb_get_guint8(tvb, offset);
	uam = tvb_get_ptr(tvb, offset +1, len_uam);
	proto_tree_add_item(tree, hf_afp_UAM, tvb, offset, 1,FALSE);
	offset += len_uam +1;

	if (!strncasecmp(uam, "No User Authent", len_uam)) {
		return offset;
	}

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_user, tvb, offset, 1,FALSE);
	offset += len +1;

	return decode_uam_parameters(uam, len_uam, tvb, tree, offset);
}

/* ***************************/
static gint
dissect_query_afp_login_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	int len;
	int len_uam;
	const char *uam;
	guint8 type;

	type = tvb_get_guint8(tvb, offset);

	PAD(1);
	proto_tree_add_item(tree, hf_afp_login_flags, tvb, offset, 2,FALSE);
	offset += 2;

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_AFPVersion, tvb, offset, 1,FALSE);
	offset += len +1;

	len_uam = tvb_get_guint8(tvb, offset);
	uam = tvb_get_ptr(tvb, offset +1, len_uam);
	proto_tree_add_item(tree, hf_afp_UAM, tvb, offset, 1,FALSE);
	offset += len_uam +1;

	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_user_type, tvb, offset, 1,FALSE);
	offset++;
	/* only type 3 */
	len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_user_len, tvb, offset, 2,FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_user_name, tvb, offset, len,FALSE);
	offset += len;

	/* directory service */
	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_path_type, tvb, offset, 1,FALSE);
	offset++;
	/* FIXME use 16 bit len + unicode from smb dissector */
	switch (type) {
	case 1:
	case 2:
		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_afp_path_len, tvb, offset,  1,FALSE);
		offset++;
		proto_tree_add_item(tree, hf_afp_path_name, tvb, offset, len,FALSE);
		offset += len;
		break;
	case 3:
		len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item( tree, hf_afp_path_unicode_len, tvb, offset, 2,FALSE);
		offset += 2;
		proto_tree_add_item(tree, hf_afp_path_name, tvb, offset, len,FALSE);
		offset += len;
    		break;
	default:
		break;
    	}

	return decode_uam_parameters(uam, len_uam, tvb, tree, offset);
}

/* ************************** */
static gint
dissect_query_afp_write(tvbuff_t *tvb, packet_info *pinfo , proto_tree *tree, gint offset)
{
	int  param;
	gint col_info = check_col(pinfo->cinfo, COL_INFO);


	proto_tree_add_item(tree, hf_afp_flag, tvb, offset, 1,FALSE);
	offset += 1;

        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset, tvb, offset, 4,FALSE);
	if (col_info) {
		param = tvb_get_ntohl(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, " Offset=%d", param);
	}
	offset += 4;

	proto_tree_add_item(tree, hf_afp_rw_count, tvb, offset, 4,FALSE);
	if (col_info) {
		param = tvb_get_ntohl(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, " Size=%d", param);
	}
	offset += 4;

	return offset;
}

static gint
dissect_reply_afp_write(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_last_written, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_write_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_flag, tvb, offset, 1,FALSE);
	offset += 1;

        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8,FALSE);
	offset += 8;

	proto_tree_add_item(tree, hf_afp_rw_count64, tvb, offset, 8,FALSE);
	offset += 8;

	return offset;
}

static gint
dissect_reply_afp_write_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_last_written64, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_read(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	int param;
	gint col_info = check_col(pinfo->cinfo, COL_INFO);

	PAD(1);

        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset, tvb, offset, 4,FALSE);
	if (col_info) {
		param = tvb_get_ntohl(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, " Offset=%d", param);
	}
	offset += 4;

	proto_tree_add_item(tree, hf_afp_rw_count, tvb, offset, 4,FALSE);
	if (col_info) {
		param = tvb_get_ntohl(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, " Size=%d", param);
	}
	offset += 4;

	proto_tree_add_item(tree, hf_afp_newline_mask, tvb, offset, 1,FALSE);
	offset++;

	proto_tree_add_item(tree, hf_afp_newline_char, tvb, offset, 1,FALSE);
	offset++;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_read_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	PAD(1);

        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8,FALSE);
	offset += 8;

	proto_tree_add_item(tree, hf_afp_rw_count64, tvb, offset, 8,FALSE);
	offset += 8;

	return offset;
}

/* **************************
   Open desktop call
   query is the same than 	AFP_FLUSH, AFP_CLOSEVOL

*/
static gint
dissect_reply_afp_open_dt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;

	return offset;
}

/* **************************
	no reply
*/
static gint
dissect_query_afp_close_dt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;

	return offset;
}

/* **************************
	calls using the same format :
		1 pad byte
		fork number
	AFP_FLUSHFORK
	AFP_CLOSEFORK
*/
static gint
dissect_query_afp_with_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_fldr_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did_file_dir_bitmap(tree, tvb, offset);

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_fldr_param(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint8	flags;
	guint16 f_bitmap, d_bitmap;

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	d_bitmap = decode_dir_bitmap(tree, tvb, offset);
	offset += 2;

	flags = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_file_flag, tvb, offset, 1,FALSE);
	offset++;
	PAD(1);
	if (flags) {
		offset = parse_dir_bitmap(tree, tvb, offset, d_bitmap);
	}
	else {
		offset = parse_file_bitmap(tree, tvb, offset, f_bitmap,0);
	}
	return offset;
}

/* **************************
	no reply
*/
static gint
dissect_query_afp_set_fldr_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16	f_bitmap;

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	offset = decode_name(tree, pinfo, tvb, offset);

	if ((offset & 1))
		PAD(1);
	/* did:name can be a file or a folder but only the intersection between
	 * file bitmap and dir bitmap can be set.
	 * Well it's in afp spec, but clients (Mac) are setting 'file only' bits with this call
	 * (WriteInhibit for example).
	 */
	offset = parse_file_bitmap(tree, tvb, offset, f_bitmap, 1);

	return offset;
}

/* **************************
	no reply
*/
static gint
dissect_query_afp_set_file_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16	f_bitmap;

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	offset = decode_name(tree, pinfo, tvb, offset);

	if ((offset & 1))
		PAD(1);
	offset = parse_file_bitmap(tree, tvb, offset, f_bitmap, 0);

	return offset;
}

/* **************************
	no reply
*/
static gint
dissect_query_afp_set_dir_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16	d_bitmap;

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	d_bitmap = decode_dir_bitmap(tree, tvb, offset);
	offset += 2;

	offset = decode_name(tree, pinfo, tvb, offset);

	if ((offset & 1))
		PAD(1);
	offset = parse_dir_bitmap(tree, tvb, offset, d_bitmap);

	offset += 4;
	return offset;
}

/* **************************
	AFP_DELETE
	AFP_CREATE_DIR
 */
static gint
dissect_query_afp_create_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	offset = decode_name(tree, pinfo, tvb, offset);
	return offset;
}

/* --------------------------
	AFP_MOVE
*/
static gint
dissect_reply_afp_create_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4,FALSE);
	offset += 4;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_create_dir(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;

	return offset;
}

/* **************************
	no reply
*/
static gint
dissect_query_afp_delete_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	PAD(1);
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4,FALSE);
	offset += 4;

	return offset;
}

/* **************************
	same reply as get_fork_param
*/
static gint
dissect_query_afp_resolve_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	PAD(1);
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4,FALSE);
	offset += 4;

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_fork_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;
	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_fork_param(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16 f_bitmap;

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	offset = parse_file_bitmap(tree, tvb, offset, f_bitmap,0);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_set_fork_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16 bitmap;
	int param;

	PAD(1);
        add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	if ((bitmap & kFPExtDataForkLenBit) || (bitmap & kFPExtRsrcForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_ofork_len64, tvb, offset, 8, FALSE);
		offset += 8;
	}
	else {
		proto_tree_add_item(tree, hf_afp_ofork_len, tvb, offset, 4,FALSE);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			param = tvb_get_ntohl(tvb, offset);
			col_append_fstr(pinfo->cinfo, COL_INFO, " Size=%d", param);
		}
		offset += 4;
	}
	return offset;
}

/* ************************** */
static gint
dissect_query_afp_move(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name_label(tree, pinfo, tvb, offset, "Source path: %s");
	offset = decode_name_label(tree, NULL, tvb, offset,  "Dest dir:    %s");
	offset = decode_name_label(tree, NULL, tvb, offset,  "New name:    %s");

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_exchange_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name_label(tree, pinfo, tvb, offset, "Source path: %s");
	offset = decode_name_label(tree, NULL, tvb, offset,  "Dest path:   %s");

	return offset;
}
/* ************************** */
static gint
dissect_query_afp_copy_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;

	PAD(1);
	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, 6,"Source volume");
		sub_tree = proto_item_add_subtree(item, ett_afp_vol_did);
	}
	offset = decode_vol_did(sub_tree, tvb, offset);

	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, 6,"Dest volume");
		sub_tree = proto_item_add_subtree(item, ett_afp_vol_did);
	}
	offset = decode_vol_did(sub_tree, tvb, offset);

	offset = decode_name_label(tree, pinfo, tvb, offset, "Source path: %s");
	offset = decode_name_label(tree, NULL, tvb, offset,  "Dest dir:    %s");
	offset = decode_name_label(tree, NULL, tvb, offset,  "New name:    %s");

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_rename(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	offset = decode_name_label(tree, pinfo, tvb, offset, "Old name: %s");
	offset = decode_name_label(tree, NULL, tvb, offset,  "New name: %s");

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_byte_lock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint8 flag;

	flag = tvb_get_guint8(tvb, offset);
	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, 1, "Flags: 0x%02x", flag);
		sub_tree = proto_item_add_subtree(item, ett_afp_lock_flags);
	}

	proto_tree_add_item(sub_tree, hf_afp_lock_op, tvb, offset, 1,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_lock_from, tvb, offset, 1,FALSE);
	offset += 1;

	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_lock_offset, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_lock_len, tvb, offset, 4,FALSE);
	offset += 4;
	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_byte_lock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_lock_range_start, tvb, offset, 4,FALSE);
	offset += 4;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_byte_lock_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	guint8 flag;

	flag = tvb_get_guint8(tvb, offset);
	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, 1, "Flags: 0x%02x", flag);
		sub_tree = proto_item_add_subtree(item, ett_afp_lock_flags);
	}

	proto_tree_add_item(sub_tree, hf_afp_lock_op, tvb, offset, 1,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_lock_from, tvb, offset, 1,FALSE);
	offset += 1;

	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_lock_offset64, tvb, offset, 8,FALSE);
	offset += 8;

	proto_tree_add_item(tree, hf_afp_lock_len64, tvb, offset, 8,FALSE);
	offset += 8;
	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_byte_lock_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_lock_range_start64, tvb, offset, 8,FALSE);
	offset += 8;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_add_cmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint8 len;

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	if ((offset & 1))
		PAD(1);

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_comment, tvb, offset, 1,FALSE);
	offset += len +1;

	return offset;
}


/* ************************** */
static gint
dissect_query_afp_get_cmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);
	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_cmt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint8 len;

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_comment, tvb, offset, 1,FALSE);
	offset += len +1;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_icon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_file_type, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_type, tvb, offset, 1,FALSE);
	offset += 1;
	PAD(1);

	proto_tree_add_item(tree, hf_afp_icon_length, tvb, offset, 2,FALSE);
	offset += 2;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_icon_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_index, tvb, offset, 2,FALSE);
	offset += 2;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_icon_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	proto_tree_add_item(tree, hf_afp_icon_tag, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_file_type, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_type, tvb, offset, 1,FALSE);
	offset += 1;

	PAD(1);
	proto_tree_add_item(tree, hf_afp_icon_length, tvb, offset, 2,FALSE);
	offset += 2;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_add_icon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_file_type, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_type, tvb, offset, 1,FALSE);
	offset += 1;

	PAD(1);
	proto_tree_add_item(tree, hf_afp_icon_tag, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_length, tvb, offset, 2,FALSE);
	offset += 2;

	return offset;
}

/* **************************
	no reply
*/
static gint
decode_dt_did(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	/* FIXME it's not volume but dt cf decode_name*/
	Vol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;

	Did = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;
	return offset;
}

/* -------------------------- */
static gint
dissect_query_afp_add_appl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_dt_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_appl_tag, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* **************************
	no reply
*/
static gint
dissect_query_afp_rmv_appl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_dt_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_appl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_appl_index, tvb, offset, 2,FALSE);
	offset += 2;

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_appl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_appl_tag, tvb, offset, 4,FALSE);
	offset += 4;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_create_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_create_flag, tvb, offset, 1,FALSE);
	offset++;

	offset = decode_vol_did(tree, tvb, offset);

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_map_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint8 type;

	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_map_id_type, tvb, offset, 1,FALSE);
	offset++;

	if ( type < 5) {
		proto_tree_add_item(tree, hf_afp_map_id, tvb, offset, 4,FALSE);
		offset += 4;
	}
	else {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16,FALSE);
		offset += 16;
	}

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_map_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
int len;

	len = tvb_get_guint8(tvb, offset);
	/* for type 3 and 4 len is 16 bits but we don't keep the type from the request
	 * XXX assume name < 256, ie the first byte is zero.
	*/
	if (!len) {
		gint remain = tvb_reported_length_remaining(tvb,offset);
		if (remain && remain == (len = tvb_get_guint8(tvb, offset +1)) +2) {
			offset++;
		}
		else {
			/* give up */
			len = 0;
		}
	}
	proto_tree_add_item(tree, hf_afp_map_name, tvb, offset, 1,FALSE);
	offset += len +1;
	return offset;
}

/* ************************** */
static gint
dissect_query_afp_map_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
int len;
	proto_tree_add_item(tree, hf_afp_map_name_type, tvb, offset, 1,FALSE);
	offset++;

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_map_name, tvb, offset, 1,FALSE);
	offset += len +1;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_map_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	gint remain;

	/* We don't keep the type from the request */
	/* If remain == 16, assume UUID */
	remain =  tvb_reported_length_remaining(tvb,0);
	if (remain == 16) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, FALSE);
		offset += 16;
	}
	else {
		proto_tree_add_item(tree, hf_afp_map_id, tvb, offset, 4, FALSE);
		offset += 4;
	}

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_disconnect_old_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
int len, orig_offset = offset;

	PAD(1);

	proto_tree_add_item(tree, hf_afp_session_token_type, tvb, offset, 2,FALSE);
	offset += 2;

	len = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_session_token_len, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_session_token, tvb, offset, len,FALSE);
	offset += len;

	if (offset <= orig_offset)
		THROW(ReportedBoundsError);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_session_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
guint16	token;
int len, orig_offset = offset;

	PAD(1);
	token = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_session_token_type, tvb, offset, 2,FALSE);
	offset += 2;
	if (token == kLoginWithoutID || token == kGetKerberosSessionKey) /* 0 || 8 */
		return offset;

	len = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_session_token_len, tvb, offset, 4,FALSE);
	offset += 4;

	switch (token) {
	case kLoginWithTimeAndID:
	case kReconnWithTimeAndID:
		proto_tree_add_item(tree, hf_afp_session_token_timestamp, tvb, offset, 4,FALSE);
		offset += 4;
	}

	proto_tree_add_item(tree, hf_afp_session_token, tvb, offset, len,FALSE);
	offset += len;

	if (offset <= orig_offset)
		THROW(ReportedBoundsError);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_session_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
int len, orig_offset = offset;
int size;

	/* FIXME spec and capture disagree : or it's 4 bytes with no token type, or it's 2 bytes */
	size = 4;
	/* [cm]: FIXME continued:  Since size is set to 4, this test is never true.
	if (size == 2) {
		proto_tree_add_item(tree, hf_afp_session_token_type, tvb, offset, 2,FALSE);
		offset += 2;
	}
	*/
	len = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_session_token_len, tvb, offset, size,FALSE);
	offset += size;

	proto_tree_add_item(tree, hf_afp_session_token, tvb, offset, len,FALSE);
	offset += len;

	if (offset <= orig_offset)
		THROW(ReportedBoundsError);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_server_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
        proto_tree_add_item(tree, hf_afp_message_type, tvb, offset, 2, FALSE);
        offset += 2;

        if (tree) {
	  	proto_tree *sub_tree;
  		proto_item *item;

        	item = proto_tree_add_item(tree, hf_afp_message_bitmap, tvb, offset, 2, FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_message_bitmap);
		proto_tree_add_item(sub_tree, hf_afp_message_bitmap_REQ, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_message_bitmap_UTF, tvb, offset, 2,FALSE);
	}
        offset += 2;

        return offset;
}

/* ************************** */
static gint
dissect_reply_afp_get_server_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16  bitmap;
	guint16 len = 0;

	/* FIXME: APF 3.1 specs also specify a long reply format, yet unused */

        proto_tree_add_item(tree, hf_afp_message_type, tvb, offset, 2, FALSE);
        offset += 2;

        bitmap = tvb_get_ntohs(tvb, offset);
        if (tree) {
	  	proto_tree *sub_tree;
  		proto_item *item;

        	item = proto_tree_add_item(tree, hf_afp_message_bitmap, tvb, offset, 2, FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_message_bitmap);
		proto_tree_add_item(sub_tree, hf_afp_message_bitmap_REQ, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_message_bitmap_UTF, tvb, offset, 2,FALSE);
	}
        offset += 2;

	/* FIXME: Not in the specs, but for UTF8 message length is 2 bytes */
        if ((bitmap & 3) == 3) {
		len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_message_len, tvb, offset, 2,FALSE);
		offset += 2;
	}
	else if ((bitmap & 1)) {
		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_afp_message_len, tvb, offset, 1,FALSE);
		offset += 1;
	}

	if (len) {
		proto_tree_add_item(tree, hf_afp_message, tvb, offset, len ,FALSE);
		offset += len;
	}

        return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_user_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	proto_tree_add_item(tree, hf_afp_user_flag, tvb, offset, 1,FALSE);
	offset++;

	proto_tree_add_item(tree, hf_afp_user_ID, tvb, offset, 4,FALSE);
	offset += 4;

	if (tree) {
  		proto_tree *sub_tree;
  		proto_item *item;

		item = proto_tree_add_item(tree, hf_afp_user_bitmap, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_user_bitmap);
		proto_tree_add_item(sub_tree, hf_afp_user_bitmap_UID, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_user_bitmap_GID, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_user_bitmap_UUID, tvb, offset, 2,FALSE);
	}
	offset += 2;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_user_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16  bitmap;

	bitmap = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree *sub_tree;
		proto_item *item;

		item = proto_tree_add_item(tree, hf_afp_user_bitmap, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_user_bitmap);
		proto_tree_add_item(sub_tree, hf_afp_user_bitmap_UID, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_user_bitmap_GID, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_user_bitmap_UUID, tvb, offset, 2,FALSE);
	}

	offset += 2;
	if ((bitmap & 1)) {
		proto_tree_add_item(tree, hf_afp_user_ID, tvb, offset, 4,FALSE);
		offset += 4;
	}

	if ((bitmap & 2)) {
		proto_tree_add_item(tree, hf_afp_group_ID, tvb, offset, 4,FALSE);
		offset += 4;
	}

	if ((bitmap & 4)) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16,FALSE);
		offset += 16;
	}
	return offset;
}


/* ************************** */
static gint
decode_attr_name (proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, gint offset, const gchar *label)
{
	int len;

	if ((offset & 1))
		PAD(1);

	len = tvb_get_ntohs(tvb, offset);

	if (tree) {
		gchar *name;
		proto_tree *sub_tree;
		proto_item *item;

		name = tvb_format_text(tvb,offset+2, len);
		item = proto_tree_add_text(tree, tvb, offset, len + 2, label, name);
		sub_tree = proto_item_add_subtree(item, ett_afp_extattr_names);

		proto_tree_add_item(sub_tree, hf_afp_extattr_namelen, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_extattr_name, tvb, offset +2, len, FALSE);
	}
	offset += 2 +len;

	return offset;
}

/* ************************** */
static gint
decode_attr_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{

	if (tree) {
		proto_tree *sub_tree;
		proto_item *item;

		item = proto_tree_add_item(tree, hf_afp_extattr_bitmap, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_extattr_bitmap);
		proto_tree_add_item(sub_tree, hf_afp_extattr_bitmap_NoFollow, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_extattr_bitmap_Create, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_extattr_bitmap_Replace, tvb, offset, 2,FALSE);
	}
	offset += 2;
	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_ext_attr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	offset = decode_attr_bitmap(tree, tvb, offset);

	/* 8byte offset */
	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8,FALSE);
	offset += 8;
	/* 8byte reqcount */
	proto_tree_add_item(tree, hf_afp_reqcount64, tvb, offset, 8,FALSE);
	offset += 8;

        /* maxreply */
	proto_tree_add_item(tree, hf_afp_extattr_reply_size, tvb, offset, 4, FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	offset = decode_attr_name(tree, pinfo, tvb, offset, "Attribute: %s");

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_ext_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint32  len;
	guint	 remain;
	int	 orig_offset = offset;

	offset = decode_attr_bitmap(tree, tvb, offset);

	len = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_extattr_len, tvb, offset, 4,FALSE);
	offset += 4;

	remain =  tvb_reported_length_remaining(tvb, offset);
	if (len && remain >= len ) {
		proto_tree_add_item(tree, hf_afp_extattr_data, tvb, offset, len, FALSE);
		offset += len;
	}

	if (offset <= orig_offset)
		THROW(ReportedBoundsError);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_set_ext_attr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16  len;

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	offset = decode_attr_bitmap(tree, tvb, offset);

	/* 8byte offset */
	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8,FALSE);
	offset += 8;

	offset = decode_name(tree, pinfo, tvb, offset);

	offset = decode_attr_name(tree, pinfo, tvb, offset, "Attribute: %s");

	len = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_extattr_len, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_extattr_data, tvb, offset, len, FALSE);
	offset += len;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_list_ext_attrs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	/* for this command only kXAttrNoFollow is valid */
	offset = decode_attr_bitmap(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_extattr_req_count, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_extattr_start_index, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_extattr_reply_size, tvb, offset, 4, FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_list_ext_attrs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_item *item;
	proto_tree *sub_tree;
	gint length = 0, orig_offset = offset;
	int remain;

	offset = decode_attr_bitmap(tree, tvb, offset);

	length = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_extattr_reply_size, tvb, offset, 4, FALSE);
	offset += 4;

	/* If reply_size was 0 on request, server only reports the size of
           the entries without actually adding any entries */
	remain =  tvb_reported_length_remaining(tvb, offset);
	if (remain >= length) {

		item = proto_tree_add_text(tree, tvb, offset, remain , "Attributes");
		sub_tree = proto_item_add_subtree(item, ett_afp_extattr_names);
		while ( remain > 0) {
			tvb_get_ephemeral_stringz(tvb, offset, &length);
 			proto_tree_add_item(sub_tree, hf_afp_extattr_name, tvb, offset, length, FALSE);
			offset += length;
			remain -= length;
		}

	}

	if (offset <= orig_offset)
		THROW(ReportedBoundsError);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_remove_ext_attr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	offset = decode_attr_bitmap(tree, tvb, offset);

	offset = decode_name(tree, pinfo, tvb, offset);

	offset = decode_attr_name(tree, pinfo, tvb, offset, "Attribute: %s");

	return offset;
}

/* ************************** */
static gint
decode_acl_access_bitmap(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	guint32	bitmap;

	bitmap = tvb_get_ntohl(tvb, offset);
	if (tree) {
		proto_tree *sub_tree;
		proto_item *item;

		item = proto_tree_add_item(tree, hf_afp_acl_access_bitmap, tvb, offset, 4, FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_acl_access_bitmap);

        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_read_data   , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_write_data  , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_execute     , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_delete      , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_append_data , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_delete_child, tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_read_attrs  , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_write_attrs , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_read_extattrs , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_write_extattrs, tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_read_security , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_write_security, tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_change_owner  , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_synchronize   , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_generic_all   , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_generic_execute, tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_generic_write , tvb, offset, 4,FALSE);
        	proto_tree_add_item(sub_tree, hf_afp_acl_access_bitmap_generic_read  , tvb, offset, 4,FALSE);
	}

        return bitmap;
}

/* ************************** */
static gint
dissect_query_afp_access(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_access_bitmap, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, FALSE);
	offset += 16;

	decode_acl_access_bitmap(tvb, tree, offset);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* ************************** */
static guint16
decode_acl_list_bitmap(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	bitmap = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree *sub_tree;
		proto_item *item;

		item = proto_tree_add_item(tree, hf_afp_acl_list_bitmap, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_acl_list_bitmap);
		proto_tree_add_item(sub_tree, hf_afp_acl_list_bitmap_UUID, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_acl_list_bitmap_GRPUUID, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_acl_list_bitmap_ACL, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_acl_list_bitmap_REMOVEACL, tvb, offset, 2,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_acl_list_bitmap_Inherit, tvb, offset, 2,FALSE);
	}

	return bitmap;
}


/* ************************** */
static guint32
decode_ace_flags_bitmap(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	guint32 bitmap;

	bitmap = tvb_get_ntohl(tvb, offset);
	if (tree) {
		proto_tree *sub_tree;
		proto_item *item;

		item = proto_tree_add_item(tree, hf_afp_ace_flags, tvb, offset, 4,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_ace_flags);
		proto_tree_add_item(sub_tree, hf_afp_ace_flags_allow, tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_ace_flags_deny, tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_ace_flags_inherited, tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_ace_flags_fileinherit, tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_ace_flags_dirinherit, tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_ace_flags_limitinherit, tvb, offset, 4,FALSE);
		proto_tree_add_item(sub_tree, hf_afp_ace_flags_onlyinherit, tvb, offset, 4,FALSE);
	}

	return bitmap;
}

static gint
decode_kauth_ace(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	/* FIXME: preliminary decoding... */
	if (tree) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16,FALSE);
		offset += 16;

		decode_ace_flags_bitmap(tvb, tree, offset);
		offset += 4;

		decode_acl_access_bitmap(tvb, tree, offset);
		offset += 4;
	}
	else {
		offset += 24;
	}
	return offset;
}

static gint
decode_kauth_acl(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	int entries;
	int i;
  	proto_tree *sub_tree;
  	proto_tree *ace_tree;
  	proto_item *item;

	/* FIXME: preliminary decoding... */
	entries = tvb_get_ntohl(tvb, offset);

	item = proto_tree_add_text(tree, tvb, offset, 4, "ACEs : %d", entries);
	sub_tree = proto_item_add_subtree(item, ett_afp_ace_entries);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_acl_flags, tvb, offset, 4,FALSE);
	offset += 4;

	for (i = 0; i < entries; i++) {
		item = proto_tree_add_text(sub_tree, tvb, offset, 24, "ACE: %u", i);
		ace_tree = proto_item_add_subtree(item, ett_afp_ace_entry);

		offset = decode_kauth_ace(tvb, ace_tree, offset);
	}

	return offset;
}

static gint
decode_uuid_acl(tvbuff_t *tvb, proto_tree *tree, gint offset, guint16 bitmap)
{
	if ((offset & 1))
		PAD(1);

	if ((bitmap & kFileSec_UUID)) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, FALSE);
		offset += 16;
	}

	if ((bitmap & kFileSec_GRPUUID)) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, FALSE);
		offset += 16;
	}

	if ((bitmap & kFileSec_ACL)) {
		offset = decode_kauth_acl(tvb, tree, offset);
	}

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_set_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	bitmap = decode_acl_list_bitmap(tvb, tree, offset);
	offset += 2;

	offset = decode_name(tree, pinfo, tvb, offset);

	offset = decode_uuid_acl(tvb, tree, offset, bitmap);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	decode_acl_list_bitmap(tvb, tree, offset);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_max_reply_size32, tvb, offset, 4,FALSE);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_acl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	bitmap = decode_acl_list_bitmap(tvb, tree, offset);
	offset += 2;

	offset = decode_uuid_acl(tvb, tree, offset, bitmap);

	return offset;
}

/* ************************** */
static void
dissect_afp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct aspinfo	*aspinfo = pinfo->private_data;
	proto_tree	*afp_tree = NULL;
	proto_item	*ti;
	conversation_t	*conversation;
	gint		offset = 0;
	afp_request_key request_key, *new_request_key;
	afp_request_val *request_val;
	guint8		afp_command;
	nstime_t	delta_ts;

	int     len =  tvb_reported_length_remaining(tvb,0);
	gint col_info = check_col(pinfo->cinfo, COL_INFO);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AFP");
	if (col_info)
		col_clear(pinfo->cinfo, COL_INFO);

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	if (conversation == NULL)
	{
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}

	request_key.conversation = conversation->index;
	request_key.seq = aspinfo->seq;

	request_val = (afp_request_val *) g_hash_table_lookup(
								afp_request_hash, &request_key);

	if (!request_val && !aspinfo->reply)  {
		afp_command = tvb_get_guint8(tvb, offset);
		new_request_key = se_alloc(sizeof(afp_request_key));
		*new_request_key = request_key;

		request_val = se_alloc(sizeof(afp_request_val));
		request_val->command = afp_command;
		request_val->frame_req = pinfo->fd->num;
		request_val->frame_res = 0;
		request_val->req_time=pinfo->fd->abs_ts;

		g_hash_table_insert(afp_request_hash, new_request_key,
								request_val);
	}

	if (!request_val) {	/* missing request */
		if (col_info)
			col_add_fstr(pinfo->cinfo, COL_INFO, "[Reply without query?]");
		return;
	}

	afp_command = request_val->command;
	if (col_info) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			     val_to_str(afp_command, CommandCode_vals,
					"Unknown command (%u)"),
			     aspinfo->reply ? "reply" : "request");
		if (aspinfo->reply && aspinfo->code != 0) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ": %s (%d)",
			     	val_to_str(aspinfo->code, asp_error_vals,
					"Unknown error (%u)"), aspinfo->code);
		}
	}

	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_afp, tvb, offset, -1,FALSE);
		afp_tree = proto_item_add_subtree(ti, ett_afp);
	}
	if (!aspinfo->reply)  {

		proto_tree_add_uint(afp_tree, hf_afp_command, tvb,offset, 1, afp_command);
	        if (afp_command != tvb_get_guint8(tvb, offset))
	        {
	        	/* we have the same conversation for different connections eg:
			 * ip1:2048 --> ip2:548
	        	 * ip1:2048 --> ip2:548 <RST>
	        	 * ....
	        	 * ip1:2048 --> ip2:548 <SYN> use the same port but it's a new session!
	        	 */
			if (col_info) {
				col_add_fstr(pinfo->cinfo, COL_INFO,
			          "[Error!IP port reused, you need to split the capture file]");
				return;
			}
		}

		/*
		 * Put in a field for the frame number of the frame to which
		 * this is a response if we know that frame number (i.e.,
		 * it's not 0).
		 */
		if (request_val->frame_res != 0) {
			ti = proto_tree_add_uint(afp_tree, hf_afp_response_in,
			    tvb, 0, 0, request_val->frame_res);
			PROTO_ITEM_SET_GENERATED(ti);
		}

		offset++;
		switch(afp_command) {
		case AFP_BYTELOCK:
			offset = dissect_query_afp_byte_lock(tvb, pinfo, afp_tree, offset);break;
		case AFP_BYTELOCK_EXT:
			offset = dissect_query_afp_byte_lock_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_OPENDT: 	/* same as close vol */
		case AFP_FLUSH:
		case AFP_CLOSEVOL:
			offset = dissect_query_afp_with_vol_id(tvb, pinfo, afp_tree, offset);break;
		case AFP_CLOSEDIR:
			/* offset = dissect_query_afp_close_dir(tvb, pinfo, afp_tree, offset);break; */
			break;
		case AFP_CLOSEDT:
			offset = dissect_query_afp_close_dt(tvb, pinfo, afp_tree, offset);break;
		case AFP_FLUSHFORK: /* same packet as closefork */
		case AFP_CLOSEFORK:
			offset = dissect_query_afp_with_fork(tvb, pinfo, afp_tree, offset);break;
		case AFP_COPYFILE:
			offset = dissect_query_afp_copy_file(tvb, pinfo, afp_tree, offset);break;
		case AFP_CREATEFILE:
			offset = dissect_query_afp_create_file(tvb, pinfo, afp_tree, offset);break;
		case AFP_DISCTOLDSESS:
			offset = dissect_query_afp_disconnect_old_session(tvb, pinfo, afp_tree, offset);break;
		case AFP_ENUMERATE_EXT2:
			offset = dissect_query_afp_enumerate_ext2(tvb, pinfo, afp_tree, offset);break;
		case AFP_ENUMERATE_EXT:
		case AFP_ENUMERATE:
			offset = dissect_query_afp_enumerate(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETFORKPARAM:
			offset = dissect_query_afp_get_fork_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETSESSTOKEN:
			offset = dissect_query_afp_get_session_token(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETUSERINFO:
			offset = dissect_query_afp_get_user_info(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETSRVINFO:
			/* offset = dissect_query_afp_get_server_info(tvb, pinfo, afp_tree, offset);break; */
		case AFP_GETSRVPARAM:
			break;					/* no parameters */
		case AFP_GETVOLPARAM:
			offset = dissect_query_afp_get_vol_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_LOGIN_EXT:
			offset = dissect_query_afp_login_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_LOGIN:
			offset = dissect_query_afp_login(tvb, pinfo, afp_tree, offset);break;
		case AFP_LOGINCONT:
		case AFP_LOGOUT:
			break;
		case AFP_MAPID:
			offset = dissect_query_afp_map_id(tvb, pinfo, afp_tree, offset);break;
		case AFP_MAPNAME:
			offset = dissect_query_afp_map_name(tvb, pinfo, afp_tree, offset);break;
		case AFP_MOVE:
			offset = dissect_query_afp_move(tvb, pinfo, afp_tree, offset);break;
		case AFP_OPENVOL:
			offset = dissect_query_afp_open_vol(tvb, pinfo, afp_tree, offset);break;
		case AFP_OPENDIR:
			break;
		case AFP_OPENFORK:
			offset = dissect_query_afp_open_fork(tvb, pinfo, afp_tree, offset);break;
		case AFP_READ:
			offset = dissect_query_afp_read(tvb, pinfo, afp_tree, offset);break;
		case AFP_READ_EXT:
			offset = dissect_query_afp_read_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_RENAME:
			offset = dissect_query_afp_rename(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETDIRPARAM:
			offset = dissect_query_afp_set_dir_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETFILEPARAM:
			offset = dissect_query_afp_set_file_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETFORKPARAM:
			offset = dissect_query_afp_set_fork_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETVOLPARAM:
			offset = dissect_query_afp_set_vol_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_WRITE:
			offset = dissect_query_afp_write(tvb, pinfo, afp_tree, offset);break;
		case AFP_WRITE_EXT:
			offset = dissect_query_afp_write_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETFLDRPARAM:
			offset = dissect_query_afp_get_fldr_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETFLDRPARAM:
			offset = dissect_query_afp_set_fldr_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_CHANGEPW:
			break;
		case AFP_GETSRVRMSG:
			offset = dissect_query_afp_get_server_message(tvb, pinfo, afp_tree, offset);break;
		case AFP_DELETE:	/* same as create_id */
		case AFP_CREATEDIR:
		case AFP_CREATEID:
			offset = dissect_query_afp_create_id(tvb, pinfo, afp_tree, offset);break;
		case AFP_DELETEID:
			offset = dissect_query_afp_delete_id(tvb, pinfo, afp_tree, offset);break;
		case AFP_RESOLVEID:
			offset = dissect_query_afp_resolve_id(tvb, pinfo, afp_tree, offset);break;
		case AFP_EXCHANGEFILE:
			offset = dissect_query_afp_exchange_file(tvb, pinfo, afp_tree, offset);break;
		case AFP_CATSEARCH_EXT:
			offset = dissect_query_afp_cat_search_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_CATSEARCH:
			offset = dissect_query_afp_cat_search(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETICON:
			offset = dissect_query_afp_get_icon(tvb, pinfo, afp_tree, offset);break;
		case AFP_GTICNINFO:
			offset = dissect_query_afp_get_icon_info(tvb, pinfo, afp_tree, offset);break;
		case AFP_ADDAPPL:
			offset = dissect_query_afp_add_appl(tvb, pinfo, afp_tree, offset);break;
		case AFP_RMVAPPL:
			offset = dissect_query_afp_rmv_appl(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETAPPL:
			offset = dissect_query_afp_get_appl(tvb, pinfo, afp_tree, offset);break;
		case AFP_ADDCMT:
			offset = dissect_query_afp_add_cmt(tvb, pinfo, afp_tree, offset);break;
		case AFP_RMVCMT: /* same as get_cmt */
		case AFP_GETCMT:
			offset = dissect_query_afp_get_cmt(tvb, pinfo, afp_tree, offset);break;
		case AFP_ADDICON:
			offset = dissect_query_afp_add_icon(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETEXTATTR:
			offset = dissect_query_afp_get_ext_attr(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETEXTATTR:
			offset = dissect_query_afp_set_ext_attr(tvb, pinfo, afp_tree, offset);break;
		case AFP_LISTEXTATTR:
			offset = dissect_query_afp_list_ext_attrs(tvb, pinfo, afp_tree, offset);break;
		case AFP_REMOVEATTR:
			offset = dissect_query_afp_remove_ext_attr(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETACL:
			offset = dissect_query_afp_get_acl(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETACL:
			offset = dissect_query_afp_set_acl(tvb, pinfo, afp_tree, offset);break;
		case AFP_ACCESS:
			offset = dissect_query_afp_access(tvb, pinfo, afp_tree, offset);break;
 		}
	}
 	else {
		proto_tree_add_uint(afp_tree, hf_afp_command, tvb, 0, 0, afp_command);

		/*
		 * Put in fields for the frame with the response to this
		 * frame - if we know the frame number (i.e., it's not 0).
		 */
		if (request_val->frame_req != 0) {
			ti = proto_tree_add_uint(afp_tree, hf_afp_response_to,
			    tvb, 0, 0, request_val->frame_req);
			PROTO_ITEM_SET_GENERATED(ti);
			nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &request_val->req_time);
			ti = proto_tree_add_time(afp_tree, hf_afp_time, tvb,
			    0, 0, &delta_ts);
			PROTO_ITEM_SET_GENERATED(ti);
		}

		/*
		 * Set "frame_res" if it's not already known.
		 */
		if (request_val->frame_res == 0)
			request_val->frame_res = pinfo->fd->num;

		/*
		 * Tap the packet before the dissectors are called so we
		 * still get the tap listener called even if there is an
		 * exception.
		 */
		tap_queue_packet(afp_tap, pinfo, request_val);

 		if (!len) {
 			/* for some calls if the reply is an error there's no data
 			*/
 			return;
 		}

 		switch(afp_command) {
		case AFP_BYTELOCK:
			offset = dissect_reply_afp_byte_lock(tvb, pinfo, afp_tree, offset);break;
		case AFP_BYTELOCK_EXT:
			offset = dissect_reply_afp_byte_lock_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_ENUMERATE_EXT2:
		case AFP_ENUMERATE_EXT:
 			offset = dissect_reply_afp_enumerate_ext(tvb, pinfo, afp_tree, offset);break;
 		case AFP_ENUMERATE:
 			offset = dissect_reply_afp_enumerate(tvb, pinfo, afp_tree, offset);break;
 		case AFP_OPENVOL:
 			offset = dissect_reply_afp_open_vol(tvb, pinfo, afp_tree, offset);break;
		case AFP_OPENFORK:
			offset = dissect_reply_afp_open_fork(tvb, pinfo, afp_tree, offset);break;
		case AFP_RESOLVEID:
		case AFP_GETFORKPARAM:
			offset =dissect_reply_afp_get_fork_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETUSERINFO:
			offset = dissect_reply_afp_get_user_info(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETSRVPARAM:
			offset = dissect_reply_afp_get_server_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETSRVRMSG:
			offset = dissect_reply_afp_get_server_message(tvb, pinfo, afp_tree, offset);break;
		case AFP_CREATEDIR:
			offset = dissect_reply_afp_create_dir(tvb, pinfo, afp_tree, offset);break;
		case AFP_MAPID:
			offset = dissect_reply_afp_map_id(tvb, pinfo, afp_tree, offset);break;
		case AFP_MAPNAME:
			offset = dissect_reply_afp_map_name(tvb, pinfo, afp_tree, offset);break;
		case AFP_MOVE:		/* same as create_id */
		case AFP_CREATEID:
			offset = dissect_reply_afp_create_id(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETSESSTOKEN:
			offset = dissect_reply_afp_get_session_token(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETVOLPARAM:
			offset = dissect_reply_afp_get_vol_param(tvb, pinfo, afp_tree, offset);break;
 		case AFP_GETFLDRPARAM:
 			offset = dissect_reply_afp_get_fldr_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_OPENDT:
			offset = dissect_reply_afp_open_dt(tvb, pinfo, afp_tree, offset);break;
		case AFP_CATSEARCH_EXT:
			offset = dissect_reply_afp_cat_search_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_CATSEARCH:
			offset = dissect_reply_afp_cat_search(tvb, pinfo, afp_tree, offset);break;
		case AFP_GTICNINFO:
			offset = dissect_reply_afp_get_icon_info(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETAPPL:
			offset = dissect_reply_afp_get_appl(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETCMT:
			offset = dissect_reply_afp_get_cmt(tvb, pinfo, afp_tree, offset);break;
		case AFP_WRITE:
			offset = dissect_reply_afp_write(tvb, pinfo, afp_tree, offset);break;
		case AFP_WRITE_EXT:
			offset = dissect_reply_afp_write_ext(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETEXTATTR:
			offset = dissect_reply_afp_get_ext_attr(tvb, pinfo, afp_tree, offset);break;
		case AFP_LISTEXTATTR:
			offset = dissect_reply_afp_list_ext_attrs(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETACL:
			offset = dissect_reply_afp_get_acl(tvb, pinfo, afp_tree, offset);break;
		}
	}
	if (tree && offset < len) {
		call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1),
		    pinfo, afp_tree);
	}
}

static void afp_reinit( void)
{

	if (afp_request_hash)
		g_hash_table_destroy(afp_request_hash);

	afp_request_hash = g_hash_table_new(afp_hash, afp_equal);

}

void
proto_register_afp(void)
{

  static hf_register_info hf[] = {
    { &hf_afp_command,
      { "Command",      "afp.command",
		FT_UINT8, BASE_DEC, VALS(CommandCode_vals), 0x0,
      	"AFP function", HFILL }},

    { &hf_afp_pad,
      { "Pad",    	"afp.pad",
		FT_NONE,   BASE_NONE, NULL, 0,
	"Pad Byte",	HFILL }},

    { &hf_afp_AFPVersion,
      { "AFP Version",  "afp.AFPVersion",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"Client AFP version", HFILL }},

    { &hf_afp_UAM,
      { "UAM",          "afp.UAM",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"User Authentication Method", HFILL }},

    { &hf_afp_user,
      { "User",         "afp.user",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"User", HFILL }},

    { &hf_afp_user_type,
      { "Type",         "afp.user_type",
		FT_UINT8, BASE_HEX, VALS(path_type_vals), 0,
      	"Type of user name", HFILL }},
    { &hf_afp_user_len,
      { "Len",  "afp.user_len",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"User name length (unicode)", HFILL }},
    { &hf_afp_user_name,
      { "User",  "afp.user_name",
		FT_STRING, BASE_NONE, NULL, 0x0,
      	"User name (unicode)", HFILL }},

    { &hf_afp_passwd,
      { "Password",     "afp.passwd",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
      	"Password", HFILL }},

    { &hf_afp_random,
      { "Random number",         "afp.random",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"UAM random number", HFILL }},

    { &hf_afp_response_to,
      { "Response to",	"afp.response_to",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This packet is a response to the packet in this frame", HFILL }},

    { &hf_afp_time,
      { "Time from request",	"afp.time",
		FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Time between Request and Response for AFP cmds", HFILL }},

    { &hf_afp_response_in,
      { "Response in",	"afp.response_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "The response to this packet is in this packet", HFILL }},

    { &hf_afp_login_flags,
      { "Flags",         "afp.afp_login_flags",
		FT_UINT16, BASE_HEX, NULL, 0 /* 0x0FFF*/,
      	"Login flags", HFILL }},

    { &hf_afp_vol_bitmap,
      { "Bitmap",         "afp.vol_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0 /* 0x0FFF*/,
      	"Volume bitmap", HFILL }},

    { &hf_afp_vol_bitmap_Attributes,
      { "Attributes",      "afp.vol_bitmap.attributes",
		FT_BOOLEAN, 16, NULL, kFPVolAttributeBit,
      	"Volume attributes", HFILL }},

    { &hf_afp_vol_attribute,
      { "Attributes",         "afp.vol_attributes",
		FT_UINT16, BASE_HEX, NULL, 0,
	"Volume attributes", HFILL }},

    { &hf_afp_vol_attribute_ReadOnly,
      { "Read only",         "afp.vol_attribute.read_only",
		 FT_BOOLEAN, 16, NULL, kReadOnly,
        "Read only volume", HFILL }},

    { &hf_afp_vol_attribute_HasVolumePassword,
      { "Volume password",         "afp.vol_attribute.passwd",
		 FT_BOOLEAN, 16, NULL, kHasVolumePassword,
      	"Has a volume password", HFILL }},

    { &hf_afp_vol_attribute_SupportsFileIDs,
      { "File IDs",         "afp.vol_attribute.fileIDs",
		 FT_BOOLEAN, 16, NULL, kSupportsFileIDs,
	"Supports file IDs", HFILL }},

    { &hf_afp_vol_attribute_SupportsCatSearch,
      { "Catalog search",         "afp.vol_attribute.cat_search",
		 FT_BOOLEAN, 16, NULL, kSupportsCatSearch,
      	"Supports catalog search operations", HFILL }},

    { &hf_afp_vol_attribute_SupportsBlankAccessPrivs,
      { "Blank access privileges",         "afp.vol_attribute.blank_access_privs",
		 FT_BOOLEAN, 16, NULL, kSupportsBlankAccessPrivs,
        "Supports blank access privileges", HFILL }},

    { &hf_afp_vol_attribute_SupportsUnixPrivs,
      { "UNIX access privileges",         "afp.vol_attribute.unix_privs",
		 FT_BOOLEAN, 16, NULL, kSupportsUnixPrivs,
      	"Supports UNIX access privileges", HFILL }},

    { &hf_afp_vol_attribute_SupportsUTF8Names,
      { "UTF-8 names",         "afp.vol_attribute.utf8_names",
		 FT_BOOLEAN, 16, NULL, kSupportsUTF8Names,
      	"Supports UTF-8 names", HFILL }},

    { &hf_afp_vol_attribute_NoNetworkUserID,
      { "No Network User ID",         "afp.vol_attribute.network_user_id",
		 FT_BOOLEAN, 16, NULL, kNoNetworkUserIDs,
      	"No Network User ID", HFILL }},

    { &hf_afp_vol_attribute_DefaultPrivsFromParent,
      { "Inherit parent privileges",         "afp.vol_attribute.inherit_parent_privs",
		 FT_BOOLEAN, 16, NULL, kDefaultPrivsFromParent,
      	"Inherit parent privileges", HFILL }},

    { &hf_afp_vol_attribute_NoExchangeFiles,
      { "No exchange files",         "afp.vol_attribute.no_exchange_files",
		 FT_BOOLEAN, 16, NULL, kNoExchangeFiles,
      	"Exchange files not supported", HFILL }},

    { &hf_afp_vol_attribute_SupportsExtAttrs,
      { "Extended Attributes",         "afp.vol_attribute.extended_attributes",
		 FT_BOOLEAN, 16, NULL, kSupportsExtAttrs,
      	"Supports Extended Attributes", HFILL }},

    { &hf_afp_vol_attribute_SupportsACLs,
      { "ACLs",         "afp.vol_attribute.acls",
		 FT_BOOLEAN, 16, NULL, kSupportsACLs,
      	"Supports access control lists", HFILL }},

    { &hf_afp_vol_bitmap_Signature,
      { "Signature",         "afp.vol_bitmap.signature",
		FT_BOOLEAN, 16, NULL, kFPVolSignatureBit,
      	"Volume signature", HFILL }},

    { &hf_afp_vol_bitmap_CreateDate,
      { "Creation date",      "afp.vol_bitmap.create_date",
		FT_BOOLEAN, 16, NULL, kFPVolCreateDateBit,
      	"Volume creation date", HFILL }},

    { &hf_afp_vol_bitmap_ModDate,
      { "Modification date",  "afp.vol_bitmap.mod_date",
		FT_BOOLEAN, 16, NULL, kFPVolModDateBit,
      	"Volume modification date", HFILL }},

    { &hf_afp_vol_bitmap_BackupDate,
      { "Backup date",        "afp.vol_bitmap.backup_date",
		FT_BOOLEAN, 16, NULL, kFPVolBackupDateBit,
      	"Volume backup date", HFILL }},

    { &hf_afp_vol_bitmap_ID,
      { "ID",         "afp.vol_bitmap.id",
		FT_BOOLEAN, 16, NULL,  kFPVolIDBit,
      	"Volume ID", HFILL }},

    { &hf_afp_vol_bitmap_BytesFree,
      { "Bytes free",         "afp.vol_bitmap.bytes_free",
		FT_BOOLEAN, 16, NULL,  kFPVolBytesFreeBit,
      	"Volume free bytes", HFILL }},

    { &hf_afp_vol_bitmap_BytesTotal,
      { "Bytes total",         "afp.vol_bitmap.bytes_total",
		FT_BOOLEAN, 16, NULL,  kFPVolBytesTotalBit,
      	"Volume total bytes", HFILL }},

    { &hf_afp_vol_bitmap_Name,
      { "Name",         "afp.vol_bitmap.name",
		FT_BOOLEAN, 16, NULL,  kFPVolNameBit,
      	"Volume name", HFILL }},

    { &hf_afp_vol_bitmap_ExtBytesFree,
      { "Extended bytes free",         "afp.vol_bitmap.ex_bytes_free",
		FT_BOOLEAN, 16, NULL,  kFPVolExtBytesFreeBit,
      	"Volume extended (>2GB) free bytes", HFILL }},

    { &hf_afp_vol_bitmap_ExtBytesTotal,
      { "Extended bytes total",         "afp.vol_bitmap.ex_bytes_total",
		FT_BOOLEAN, 16, NULL,  kFPVolExtBytesTotalBit,
      	"Volume extended (>2GB) total bytes", HFILL }},

    { &hf_afp_vol_bitmap_BlockSize,
      { "Block size",         "afp.vol_bitmap.block_size",
		FT_BOOLEAN, 16, NULL,  kFPVolBlockSizeBit,
      	"Volume block size", HFILL }},

    { &hf_afp_dir_bitmap_Attributes,
      { "Attributes",         "afp.dir_bitmap.attributes",
	    FT_BOOLEAN, 16, NULL,  kFPAttributeBit,
      	"Return attributes if directory", HFILL }},

    { &hf_afp_dir_bitmap_ParentDirID,
      { "DID",         "afp.dir_bitmap.did",
    	FT_BOOLEAN, 16, NULL,  kFPParentDirIDBit,
      	"Return parent directory ID if directory", HFILL }},

    { &hf_afp_dir_bitmap_CreateDate,
      { "Creation date",         "afp.dir_bitmap.create_date",
	    FT_BOOLEAN, 16, NULL,  kFPCreateDateBit,
      	"Return creation date if directory", HFILL }},

    { &hf_afp_dir_bitmap_ModDate,
      { "Modification date",         "afp.dir_bitmap.mod_date",
    	FT_BOOLEAN, 16, NULL,  kFPModDateBit,
      	"Return modification date if directory", HFILL }},

    { &hf_afp_dir_bitmap_BackupDate,
      { "Backup date",         "afp.dir_bitmap.backup_date",
	    FT_BOOLEAN, 16, NULL,  kFPBackupDateBit,
      	"Return backup date if directory", HFILL }},

    { &hf_afp_dir_bitmap_FinderInfo,
      { "Finder info",         "afp.dir_bitmap.finder_info",
    	FT_BOOLEAN, 16, NULL,  kFPFinderInfoBit,
      	"Return finder info if directory", HFILL }},

    { &hf_afp_dir_bitmap_LongName,
      { "Long name",         "afp.dir_bitmap.long_name",
	    FT_BOOLEAN, 16, NULL,  kFPLongNameBit,
      	"Return long name if directory", HFILL }},

    { &hf_afp_dir_bitmap_ShortName,
      { "Short name",         "afp.dir_bitmap.short_name",
    	FT_BOOLEAN, 16, NULL,  kFPShortNameBit,
      	"Return short name if directory", HFILL }},

    { &hf_afp_dir_bitmap_NodeID,
      { "File ID",         "afp.dir_bitmap.fid",
	    FT_BOOLEAN, 16, NULL,  kFPNodeIDBit,
      	"Return file ID if directory", HFILL }},

    { &hf_afp_dir_bitmap_OffspringCount,
      { "Offspring count",         "afp.dir_bitmap.offspring_count",
    	FT_BOOLEAN, 16, NULL,  kFPOffspringCountBit,
      	"Return offspring count if directory", HFILL }},

    { &hf_afp_dir_bitmap_OwnerID,
      { "Owner id",         "afp.dir_bitmap.owner_id",
	    FT_BOOLEAN, 16, NULL,  kFPOwnerIDBit,
      	"Return owner id if directory", HFILL }},

    { &hf_afp_dir_bitmap_GroupID,
      { "Group id",         "afp.dir_bitmap.group_id",
    	FT_BOOLEAN, 16, NULL,  kFPGroupIDBit,
      	"Return group id if directory", HFILL }},

    { &hf_afp_dir_bitmap_AccessRights,
      { "Access rights",         "afp.dir_bitmap.access_rights",
	    FT_BOOLEAN, 16, NULL,  kFPAccessRightsBit,
      	"Return access rights if directory", HFILL }},

    { &hf_afp_dir_bitmap_UTF8Name,
      { "UTF-8 name",         "afp.dir_bitmap.UTF8_name",
    	FT_BOOLEAN, 16, NULL,  kFPUTF8NameBit,
      	"Return UTF-8 name if directory", HFILL }},

    { &hf_afp_dir_bitmap_UnixPrivs,
      { "UNIX privileges",         "afp.dir_bitmap.unix_privs",
	    FT_BOOLEAN, 16, NULL,  kFPUnixPrivsBit,
      	"Return UNIX privileges if directory", HFILL }},

    { &hf_afp_dir_attribute_Invisible,
      { "Invisible",         "afp.dir_attribute.invisible",
	    FT_BOOLEAN, 16, NULL,  kFPInvisibleBit,
      	"Directory is not visible", HFILL }},

    { &hf_afp_dir_attribute_IsExpFolder,
      { "Share point",         "afp.dir_attribute.share",
	    FT_BOOLEAN, 16, NULL,  kFPMultiUserBit,
      	"Directory is a share point", HFILL }},

    { &hf_afp_dir_attribute_System,
      { "System",         	 "afp.dir_attribute.system",
	    FT_BOOLEAN, 16, NULL,  kFPSystemBit,
      	"Directory is a system directory", HFILL }},

    { &hf_afp_dir_attribute_Mounted,
      { "Mounted",         "afp.dir_attribute.mounted",
	    FT_BOOLEAN, 16, NULL,  kFPDAlreadyOpenBit,
      	"Directory is mounted", HFILL }},

    { &hf_afp_dir_attribute_InExpFolder,
      { "Shared area",         "afp.dir_attribute.in_exported_folder",
	    FT_BOOLEAN, 16, NULL,  kFPRAlreadyOpenBit,
      	"Directory is in a shared area", HFILL }},

    { &hf_afp_dir_attribute_BackUpNeeded,
      { "Backup needed",         "afp.dir_attribute.backup_needed",
	    FT_BOOLEAN, 16, NULL,  kFPBackUpNeededBit,
      	"Directory needs to be backed up", HFILL }},

    { &hf_afp_dir_attribute_RenameInhibit,
      { "Rename inhibit",         "afp.dir_attribute.rename_inhibit",
	    FT_BOOLEAN, 16, NULL,  kFPRenameInhibitBit,
      	"Rename inhibit", HFILL }},

    { &hf_afp_dir_attribute_DeleteInhibit,
      { "Delete inhibit",         "afp.dir_attribute.delete_inhibit",
	    FT_BOOLEAN, 16, NULL,  kFPDeleteInhibitBit,
      	"Delete inhibit", HFILL }},

    { &hf_afp_dir_attribute_SetClear,
      { "Set",         "afp.dir_attribute.set_clear",
	    FT_BOOLEAN, 16, NULL,  kFPSetClearBit,
      	"Clear/set attribute", HFILL }},

    { &hf_afp_file_bitmap_Attributes,
      { "Attributes",         "afp.file_bitmap.attributes",
	    FT_BOOLEAN, 16, NULL,  kFPAttributeBit,
      	"Return attributes if file", HFILL }},

    { &hf_afp_file_bitmap_ParentDirID,
      { "DID",         "afp.file_bitmap.did",
    	FT_BOOLEAN, 16, NULL,  kFPParentDirIDBit,
      	"Return parent directory ID if file", HFILL }},

    { &hf_afp_file_bitmap_CreateDate,
      { "Creation date",         "afp.file_bitmap.create_date",
	    FT_BOOLEAN, 16, NULL,  kFPCreateDateBit,
      	"Return creation date if file", HFILL }},

    { &hf_afp_file_bitmap_ModDate,
      { "Modification date",         "afp.file_bitmap.mod_date",
    	FT_BOOLEAN, 16, NULL,  kFPModDateBit,
      	"Return modification date if file", HFILL }},

    { &hf_afp_file_bitmap_BackupDate,
      { "Backup date",         "afp.file_bitmap.backup_date",
	    FT_BOOLEAN, 16, NULL,  kFPBackupDateBit,
      	"Return backup date if file", HFILL }},

    { &hf_afp_file_bitmap_FinderInfo,
      { "Finder info",         "afp.file_bitmap.finder_info",
    	FT_BOOLEAN, 16, NULL,  kFPFinderInfoBit,
      	"Return finder info if file", HFILL }},

    { &hf_afp_file_bitmap_LongName,
      { "Long name",         "afp.file_bitmap.long_name",
	    FT_BOOLEAN, 16, NULL,  kFPLongNameBit,
      	"Return long name if file", HFILL }},

    { &hf_afp_file_bitmap_ShortName,
      { "Short name",         "afp.file_bitmap.short_name",
    	FT_BOOLEAN, 16, NULL,  kFPShortNameBit,
      	"Return short name if file", HFILL }},

    { &hf_afp_file_bitmap_NodeID,
      { "File ID",         "afp.file_bitmap.fid",
	    FT_BOOLEAN, 16, NULL,  kFPNodeIDBit,
      	"Return file ID if file", HFILL }},

    { &hf_afp_file_bitmap_DataForkLen,
      { "Data fork size",         "afp.file_bitmap.data_fork_len",
	    FT_BOOLEAN, 16, NULL,  kFPDataForkLenBit,
      	"Return data fork size if file", HFILL }},

    { &hf_afp_file_bitmap_RsrcForkLen,
      { "Resource fork size",         "afp.file_bitmap.resource_fork_len",
	    FT_BOOLEAN, 16, NULL,  kFPRsrcForkLenBit,
      	"Return resource fork size if file", HFILL }},

    { &hf_afp_file_bitmap_ExtDataForkLen,
      { "Extended data fork size",         "afp.file_bitmap.ex_data_fork_len",
	    FT_BOOLEAN, 16, NULL,  kFPExtDataForkLenBit,
      	"Return extended (>2GB) data fork size if file", HFILL }},

    { &hf_afp_file_bitmap_LaunchLimit,
      { "Launch limit",         "afp.file_bitmap.launch_limit",
	    FT_BOOLEAN, 16, NULL,  kFPLaunchLimitBit,
      	"Return launch limit if file", HFILL }},

    { &hf_afp_file_bitmap_UTF8Name,
      { "UTF-8 name",         "afp.file_bitmap.UTF8_name",
    	FT_BOOLEAN, 16, NULL,  kFPUTF8NameBit,
      	"Return UTF-8 name if file", HFILL }},

    { &hf_afp_file_bitmap_ExtRsrcForkLen,
      	{ "Extended resource fork size",         "afp.file_bitmap.ex_resource_fork_len",
	    FT_BOOLEAN, 16, NULL,  kFPExtRsrcForkLenBit,
      	"Return extended (>2GB) resource fork size if file", HFILL }},

    { &hf_afp_file_bitmap_UnixPrivs,
      { "UNIX privileges",    "afp.file_bitmap.unix_privs",
	    FT_BOOLEAN, 16, NULL,  kFPUnixPrivsBit,
      	"Return UNIX privileges if file", HFILL }},

	/* ---------- */
    { &hf_afp_file_attribute_Invisible,
      { "Invisible",         "afp.file_attribute.invisible",
	    FT_BOOLEAN, 16, NULL,  kFPInvisibleBit,
      	"File is not visible", HFILL }},

    { &hf_afp_file_attribute_MultiUser,
      { "Multi user",         "afp.file_attribute.multi_user",
	    FT_BOOLEAN, 16, NULL,  kFPMultiUserBit,
      	"multi user", HFILL }},

    { &hf_afp_file_attribute_System,
      { "System",         	 "afp.file_attribute.system",
	    FT_BOOLEAN, 16, NULL,  kFPSystemBit,
      	"File is a system file", HFILL }},

    { &hf_afp_file_attribute_DAlreadyOpen,
      { "Data fork open",         "afp.file_attribute.df_open",
	    FT_BOOLEAN, 16, NULL,  kFPDAlreadyOpenBit,
      	"Data fork already open", HFILL }},

    { &hf_afp_file_attribute_RAlreadyOpen,
      { "Resource fork open",         "afp.file_attribute.rf_open",
	    FT_BOOLEAN, 16, NULL,  kFPRAlreadyOpenBit,
      	"Resource fork already open", HFILL }},

    { &hf_afp_file_attribute_WriteInhibit,
      { "Write inhibit",         "afp.file_attribute.write_inhibit",
	    FT_BOOLEAN, 16, NULL,  kFPWriteInhibitBit,
      	"Write inhibit", HFILL }},

    { &hf_afp_file_attribute_BackUpNeeded,
      { "Backup needed",         "afp.file_attribute.backup_needed",
	    FT_BOOLEAN, 16, NULL,  kFPBackUpNeededBit,
      	"File needs to be backed up", HFILL }},

    { &hf_afp_file_attribute_RenameInhibit,
      { "Rename inhibit",         "afp.file_attribute.rename_inhibit",
	    FT_BOOLEAN, 16, NULL,  kFPRenameInhibitBit,
      	"rename inhibit", HFILL }},

    { &hf_afp_file_attribute_DeleteInhibit,
      { "Delete inhibit",         "afp.file_attribute.delete_inhibit",
	    FT_BOOLEAN, 16, NULL,  kFPDeleteInhibitBit,
      	"delete inhibit", HFILL }},

    { &hf_afp_file_attribute_CopyProtect,
      { "Copy protect",         "afp.file_attribute.copy_protect",
	    FT_BOOLEAN, 16, NULL,  kFPCopyProtectBit,
      	"copy protect", HFILL }},

    { &hf_afp_file_attribute_SetClear,
      { "Set",         "afp.file_attribute.set_clear",
	    FT_BOOLEAN, 16, NULL,  kFPSetClearBit,
      	"Clear/set attribute", HFILL }},
	/* ---------- */

    { &hf_afp_vol_name,
      { "Volume",         "afp.vol_name",
	FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"Volume name", HFILL }},

    { &hf_afp_vol_flag_passwd,
      { "Password",         "afp.vol_flag_passwd",
	    FT_BOOLEAN, 8, NULL,  1,
      	"Volume is password-protected", HFILL }},

    { &hf_afp_vol_flag_unix_priv,
      { "Unix privs",         "afp.vol_flag_unix_priv",
	    FT_BOOLEAN, 8, NULL,  2,
      	"Volume has unix privileges", HFILL }},

    { &hf_afp_vol_id,
      { "Volume id",         "afp.vol_id",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Volume id", HFILL }},

    { &hf_afp_vol_signature,
      { "Signature",         "afp.vol_signature",
		FT_UINT16, BASE_DEC, VALS(vol_signature_vals), 0x0,
      	"Volume signature", HFILL }},

    { &hf_afp_vol_name_offset,
      { "Volume name offset","afp.vol_name_offset",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Volume name offset in packet", HFILL }},

    { &hf_afp_vol_creation_date,
      { "Creation date",         "afp.vol_creation_date",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
      	"Volume creation date", HFILL }},

    { &hf_afp_vol_modification_date,
      { "Modification date",         "afp.vol_modification_date",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
      	"Volume modification date", HFILL }},

    { &hf_afp_vol_backup_date,
      { "Backup date",         "afp.vol_backup_date",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
      	"Volume backup date", HFILL }},

    { &hf_afp_vol_bytes_free,
      { "Bytes free",         "afp.vol_bytes_free",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Free space", HFILL }},

    { &hf_afp_vol_bytes_total,
      { "Bytes total",         "afp.vol_bytes_total",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Volume size", HFILL }},

    { &hf_afp_vol_ex_bytes_free,
      { "Extended bytes free",         "afp.vol_ex_bytes_free",
		FT_UINT64, BASE_DEC, NULL, 0x0,
      	"Extended (>2GB) free space", HFILL }},

    { &hf_afp_vol_ex_bytes_total,
      { "Extended bytes total",         "afp.vol_ex_bytes_total",
		FT_UINT64, BASE_DEC, NULL, 0x0,
      	"Extended (>2GB) volume size", HFILL }},

    { &hf_afp_vol_block_size,
      { "Block size",         "afp.vol_block_size",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Volume block size", HFILL }},

    { &hf_afp_did,
      { "DID",         "afp.did",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Parent directory ID", HFILL }},

    { &hf_afp_dir_bitmap,
      { "Directory bitmap",         "afp.dir_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0x0,
      	"Directory bitmap", HFILL }},

    { &hf_afp_dir_offspring,
      { "Offspring",         "afp.dir_offspring",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Directory offspring", HFILL }},

    { &hf_afp_dir_OwnerID,
      { "Owner ID",         "afp.dir_owner_id",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"Directory owner ID", HFILL }},

    { &hf_afp_dir_GroupID,
      { "Group ID",         "afp.dir_group_id",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"Directory group ID", HFILL }},

    { &hf_afp_creation_date,
      { "Creation date",         "afp.creation_date",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
      	"Creation date", HFILL }},

    { &hf_afp_modification_date,
      { "Modification date",         "afp.modification_date",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
      	"Modification date", HFILL }},

    { &hf_afp_backup_date,
      { "Backup date",         "afp.backup_date",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
      	"Backup date", HFILL }},

    { &hf_afp_finder_info,
      { "Finder info",         "afp.finder_info",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"Finder info", HFILL }},

    { &hf_afp_long_name_offset,
      { "Long name offset",    "afp.long_name_offset",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Long name offset in packet", HFILL }},

    { &hf_afp_short_name_offset,
      { "Short name offset",   "afp.short_name_offset",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Short name offset in packet", HFILL }},

    { &hf_afp_unicode_name_offset,
      { "Unicode name offset", "afp.unicode_name_offset",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Unicode name offset in packet", HFILL }},

    { &hf_afp_unix_privs_uid,
      { "UID",             "afp.unix_privs.uid",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"User ID", HFILL }},

    { &hf_afp_unix_privs_gid,
      { "GID",             "afp.unix_privs.gid",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Group ID", HFILL }},

    { &hf_afp_unix_privs_permissions,
      { "Permissions",     "afp.unix_privs.permissions",
		FT_UINT32, BASE_OCT, NULL, 0x0,
      	"Permissions", HFILL }},

    { &hf_afp_unix_privs_ua_permissions,
      { "User's access rights",     "afp.unix_privs.ua_permissions",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"User's access rights", HFILL }},

    { &hf_afp_file_id,
      { "File ID",         "afp.file_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"File/directory ID", HFILL }},

    { &hf_afp_file_DataForkLen,
      { "Data fork size",         "afp.data_fork_len",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Data fork size", HFILL }},

    { &hf_afp_file_RsrcForkLen,
      { "Resource fork size",         "afp.resource_fork_len",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Resource fork size", HFILL }},

    { &hf_afp_file_ExtDataForkLen,
      { "Extended data fork size",         "afp.ext_data_fork_len",
		FT_UINT64, BASE_DEC, NULL, 0x0,
      	"Extended (>2GB) data fork length", HFILL }},

    { &hf_afp_file_ExtRsrcForkLen,
      { "Extended resource fork size",         "afp.ext_resource_fork_len",
		FT_UINT64, BASE_DEC, NULL, 0x0,
      	"Extended (>2GB) resource fork length", HFILL }},

    { &hf_afp_file_bitmap,
      { "File bitmap",         "afp.file_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0x0,
      	"File bitmap", HFILL }},

    { &hf_afp_req_count,
      { "Req count",         "afp.req_count",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Maximum number of structures returned", HFILL }},

    { &hf_afp_start_index,
      { "Start index",         "afp.start_index",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"First structure returned", HFILL }},

    { &hf_afp_max_reply_size,
      { "Reply size",         "afp.reply_size",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Reply size", HFILL }},

    { &hf_afp_start_index32,
      { "Start index",         "afp.start_index32",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"First structure returned", HFILL }},

    { &hf_afp_max_reply_size32,
      { "Reply size",         "afp.reply_size32",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Reply size", HFILL }},

    { &hf_afp_file_flag,
      { "Dir",         "afp.file_flag",
		FT_BOOLEAN, 8, NULL, 0x80,
      	"Is a dir", HFILL }},

    { &hf_afp_create_flag,
      { "Hard create",         "afp.create_flag",
		FT_BOOLEAN, 8, NULL, 0x80,
      	"Soft/hard create file", HFILL }},

    { &hf_afp_request_bitmap_Attributes,
      { "Attributes",         "afp.request_bitmap.attributes",
	    FT_BOOLEAN, 32, NULL,  kFPAttributeBit,
      	"Search attributes", HFILL }},

    { &hf_afp_request_bitmap_ParentDirID,
      { "DID",         "afp.request_bitmap.did",
    	FT_BOOLEAN, 32, NULL,  kFPParentDirIDBit,
      	"Search parent directory ID", HFILL }},

    { &hf_afp_request_bitmap_CreateDate,
      { "Creation date",         "afp.request_bitmap.create_date",
	    FT_BOOLEAN, 32, NULL,  kFPCreateDateBit,
      	"Search creation date", HFILL }},

    { &hf_afp_request_bitmap_ModDate,
      { "Modification date",         "afp.request_bitmap.mod_date",
    	FT_BOOLEAN, 32, NULL,  kFPModDateBit,
      	"Search modification date", HFILL }},

    { &hf_afp_request_bitmap_BackupDate,
      { "Backup date",         "afp.request_bitmap.backup_date",
	    FT_BOOLEAN, 32, NULL,  kFPBackupDateBit,
      	"Search backup date", HFILL }},

    { &hf_afp_request_bitmap_FinderInfo,
      { "Finder info",         "afp.request_bitmap.finder_info",
    	FT_BOOLEAN, 32, NULL,  kFPFinderInfoBit,
      	"Search finder info", HFILL }},

    { &hf_afp_request_bitmap_LongName,
      { "Long name",         "afp.request_bitmap.long_name",
	    FT_BOOLEAN, 32, NULL,  kFPLongNameBit,
      	"Search long name", HFILL }},

    { &hf_afp_request_bitmap_DataForkLen,
      { "Data fork size",         "afp.request_bitmap.data_fork_len",
	    FT_BOOLEAN, 32, NULL,  kFPDataForkLenBit,
      	"Search data fork size", HFILL }},

    { &hf_afp_request_bitmap_OffspringCount,
      { "Offspring count",         "afp.request_bitmap.offspring_count",
    	FT_BOOLEAN, 32, NULL,  kFPOffspringCountBit,
      	"Search offspring count", HFILL }},

    { &hf_afp_request_bitmap_RsrcForkLen,
      { "Resource fork size",         "afp.request_bitmap.resource_fork_len",
	    FT_BOOLEAN, 32, NULL,  kFPRsrcForkLenBit,
      	"Search resource fork size", HFILL }},

    { &hf_afp_request_bitmap_ExtDataForkLen,
      { "Extended data fork size",         "afp.request_bitmap.ex_data_fork_len",
	    FT_BOOLEAN, 32, NULL,  kFPExtDataForkLenBit,
      	"Search extended (>2GB) data fork size", HFILL }},

    { &hf_afp_request_bitmap_UTF8Name,
      { "UTF-8 name",         "afp.request_bitmap.UTF8_name",
    	FT_BOOLEAN, 32, NULL,  kFPUTF8NameBit,
      	"Search UTF-8 name", HFILL }},

    { &hf_afp_request_bitmap_ExtRsrcForkLen,
      	{ "Extended resource fork size",         "afp.request_bitmap.ex_resource_fork_len",
	    FT_BOOLEAN, 32, NULL,  kFPExtRsrcForkLenBit,
      	"Search extended (>2GB) resource fork size", HFILL }},

    { &hf_afp_request_bitmap_PartialNames,
      	{ "Match on partial names",         "afp.request_bitmap.partial_names",
	    FT_BOOLEAN, 32, NULL,  0x80000000,
      	"Match on partial names", HFILL }},

    { &hf_afp_request_bitmap,
      { "Request bitmap",         "afp.request_bitmap",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"Request bitmap", HFILL }},

    { &hf_afp_struct_size,
      { "Struct size",         "afp.struct_size",
		FT_UINT8, BASE_DEC, NULL,0,
      	"Sizeof of struct", HFILL }},

    { &hf_afp_struct_size16,
      { "Struct size",         "afp.struct_size16",
		FT_UINT16, BASE_DEC, NULL,0,
      	"Sizeof of struct", HFILL }},

    { &hf_afp_flag,
      { "From",         "afp.flag",
		FT_UINT8, BASE_HEX, VALS(flag_vals), 0x80,
      	"Offset is relative to start/end of the fork", HFILL }},

    { &hf_afp_dt_ref,
      { "DT ref",         "afp.dt_ref",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Desktop database reference num", HFILL }},

    { &hf_afp_ofork,
      { "Fork",         "afp.ofork",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Open fork reference number", HFILL }},

    { &hf_afp_offset,
      { "Offset",         "afp.offset",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"Offset", HFILL }},

    { &hf_afp_rw_count,
      { "Count",         "afp.rw_count",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"Number of bytes to be read/written", HFILL }},

    { &hf_afp_newline_mask,
      { "Newline mask",  "afp.newline_mask",
		FT_UINT8, BASE_HEX, NULL, 0x0,
      	"Value to AND bytes with when looking for newline", HFILL }},

    { &hf_afp_newline_char,
      { "Newline char",  "afp.newline_char",
		FT_UINT8, BASE_HEX, NULL, 0x0,
      	"Value to compare ANDed bytes with when looking for newline", HFILL }},

    { &hf_afp_last_written,
      { "Last written",  "afp.last_written",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Offset of the last byte written", HFILL }},

    { &hf_afp_actual_count,
      { "Count",         "afp.actual_count",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"Number of bytes returned by read/write", HFILL }},

    { &hf_afp_ofork_len,
      { "New length",         "afp.ofork_len",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"New length", HFILL }},

    { &hf_afp_path_type,
      { "Type",         "afp.path_type",
		FT_UINT8, BASE_HEX, VALS(path_type_vals), 0,
      	"Type of names", HFILL }},

    { &hf_afp_path_len,
      { "Len",  "afp.path_len",
		FT_UINT8, BASE_DEC, NULL, 0x0,
      	"Path length", HFILL }},

    { &hf_afp_path_unicode_len,
      { "Len",  "afp.path_unicode_len",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Path length (unicode)", HFILL }},

    { &hf_afp_path_unicode_hint,
      { "Unicode hint",  "afp.path_unicode_hint",
		FT_UINT32, BASE_HEX, VALS(unicode_hint_vals), 0x0,
      	"Unicode hint", HFILL }},

    { &hf_afp_path_name,
      { "Name",  "afp.path_name",
		FT_STRING, BASE_NONE, NULL, 0x0,
      	"Path name", HFILL }},

    { &hf_afp_fork_type,
      { "Resource fork",         "afp.fork_type",
		FT_BOOLEAN, 8, NULL, 0x80,
      	"Data/resource fork", HFILL }},

    { &hf_afp_access_mode,
      { "Access mode",         "afp.access",
		FT_UINT8, BASE_HEX, NULL, 0x0,
      	"Fork access mode", HFILL }},

    { &hf_afp_access_read,
      { "Read",         "afp.access.read",
    	FT_BOOLEAN, 8, NULL,  1,
      	"Open for reading", HFILL }},

    { &hf_afp_access_write,
      { "Write",         "afp.access.write",
    	FT_BOOLEAN, 8, NULL,  2,
      	"Open for writing", HFILL }},

    { &hf_afp_access_deny_read,
      { "Deny read",         "afp.access.deny_read",
    	FT_BOOLEAN, 8, NULL,  0x10,
      	"Deny read", HFILL }},

    { &hf_afp_access_deny_write,
      { "Deny write",         "afp.access.deny_write",
    	FT_BOOLEAN, 8, NULL,  0x20,
      	"Deny write", HFILL }},

    { &hf_afp_comment,
      { "Comment",         "afp.comment",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"File/folder comment", HFILL }},

    { &hf_afp_file_creator,
      { "File creator",         "afp.file_creator",
		FT_STRING, BASE_NONE, NULL, 0x0,
      	"File creator", HFILL }},

    { &hf_afp_file_type,
      { "File type",         "afp.file_type",
		FT_STRING, BASE_NONE, NULL, 0x0,
      	"File type", HFILL }},

    { &hf_afp_icon_type,
      { "Icon type",         "afp.icon_type",
		FT_UINT8, BASE_HEX, NULL , 0,
      	"Icon type", HFILL }},

    { &hf_afp_icon_length,
      { "Size",         "afp.icon_length",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Size for icon bitmap", HFILL }},

    { &hf_afp_icon_index,
      { "Index",         "afp.icon_index",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Icon index in desktop database", HFILL }},

    { &hf_afp_icon_tag,
      { "Tag",         "afp.icon_tag",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"Icon tag", HFILL }},

    { &hf_afp_appl_index,
      { "Index",         "afp.appl_index",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Application index", HFILL }},

    { &hf_afp_appl_tag,
      { "Tag",         "afp.appl_tag",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"Application tag", HFILL }},

    { &hf_afp_lock_op,
      { "unlock",         "afp.lock_op",
		FT_BOOLEAN, 8, NULL, 0x1,
      	"Lock/unlock op", HFILL }},

    { &hf_afp_lock_from,
      { "End",         "afp.lock_from",
		FT_BOOLEAN, 8, NULL, 0x80,
      	"Offset is relative to the end of the fork", HFILL }},

    { &hf_afp_lock_offset,
      { "Offset",         "afp.lock_offset",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"First byte to be locked", HFILL }},

    { &hf_afp_lock_len,
      { "Length",         "afp.lock_len",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"Number of bytes to be locked/unlocked", HFILL }},

    { &hf_afp_lock_range_start,
      { "Start",         "afp.lock_range_start",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"First byte locked/unlocked", HFILL }},

    { &hf_afp_dir_ar,
      { "Access rights",         "afp.dir_ar",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"Directory access rights", HFILL }},

    { &hf_afp_dir_ar_o_search,
      { "Owner has search access",      "afp.dir_ar.o_search",
		FT_BOOLEAN, 32, NULL, AR_O_SEARCH,
      	"Owner has search access", HFILL }},

    { &hf_afp_dir_ar_o_read,
      { "Owner has read access",        "afp.dir_ar.o_read",
		FT_BOOLEAN, 32, NULL, AR_O_READ,
      	"Owner has read access", HFILL }},

    { &hf_afp_dir_ar_o_write,
      { "Owner has write access",       "afp.dir_ar.o_write",
		FT_BOOLEAN, 32, NULL, AR_O_WRITE,
      	"Gwner has write access", HFILL }},

    { &hf_afp_dir_ar_g_search,
      { "Group has search access",      "afp.dir_ar.g_search",
		FT_BOOLEAN, 32, NULL, AR_G_SEARCH,
      	"Group has search access", HFILL }},

    { &hf_afp_dir_ar_g_read,
      { "Group has read access",        "afp.dir_ar.g_read",
		FT_BOOLEAN, 32, NULL, AR_G_READ,
      	"Group has read access", HFILL }},

    { &hf_afp_dir_ar_g_write,
      { "Group has write access",       "afp.dir_ar.g_write",
		FT_BOOLEAN, 32, NULL, AR_G_WRITE,
      	"Group has write access", HFILL }},

    { &hf_afp_dir_ar_e_search,
      { "Everyone has search access",   "afp.dir_ar.e_search",
		FT_BOOLEAN, 32, NULL, AR_E_SEARCH,
      	"Everyone has search access", HFILL }},

    { &hf_afp_dir_ar_e_read,
      { "Everyone has read access",     "afp.dir_ar.e_read",
		FT_BOOLEAN, 32, NULL, AR_E_READ,
      	"Everyone has read access", HFILL }},

    { &hf_afp_dir_ar_e_write,
      { "Everyone has write access",    "afp.dir_ar.e_write",
		FT_BOOLEAN, 32, NULL, AR_E_WRITE,
      	"Everyone has write access", HFILL }},

    { &hf_afp_dir_ar_u_search,
      { "User has search access",   "afp.dir_ar.u_search",
		FT_BOOLEAN, 32, NULL, AR_U_SEARCH,
      	"User has search access", HFILL }},

    { &hf_afp_dir_ar_u_read,
      { "User has read access",     "afp.dir_ar.u_read",
		FT_BOOLEAN, 32, NULL, AR_U_READ,
      	"User has read access", HFILL }},

    { &hf_afp_dir_ar_u_write,
      { "User has write access",     "afp.dir_ar.u_write",
		FT_BOOLEAN, 32, NULL, AR_U_WRITE,
      	"User has write access", HFILL }},

    { &hf_afp_dir_ar_blank,
      { "Blank access right",     "afp.dir_ar.blank",
		FT_BOOLEAN, 32, NULL, AR_BLANK,
      	"Blank access right", HFILL }},

    { &hf_afp_dir_ar_u_own,
      { "User is the owner",     "afp.dir_ar.u_owner",
		FT_BOOLEAN, 32, NULL, AR_U_OWN,
      	"Current user is the directory owner", HFILL }},

    { &hf_afp_server_time,
      { "Server time",         "afp.server_time",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
      	"Server time", HFILL }},

    { &hf_afp_cat_req_matches,
      { "Max answers",         "afp.cat_req_matches",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"Maximum number of matches to return.", HFILL }},

    { &hf_afp_reserved,
      { "Reserved",         "afp.reserved",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"Reserved", HFILL }},

    { &hf_afp_cat_count,
      { "Cat count",         "afp.cat_count",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Number of structures returned", HFILL }},

    { &hf_afp_cat_position,
      { "Position",         "afp.cat_position",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"Reserved", HFILL }},


    { &hf_afp_map_name_type,
      { "Type",      "afp.map_name_type",
		FT_UINT8, BASE_DEC, VALS(map_name_type_vals), 0x0,
      	"Map name type", HFILL }},

    { &hf_afp_map_id_type,
      { "Type",      "afp.map_id_type",
		FT_UINT8, BASE_DEC, VALS(map_id_type_vals), 0x0,
      	"Map ID type", HFILL }},

    { &hf_afp_map_id,
      { "ID",             "afp.map_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"User/Group ID", HFILL }},

    { &hf_afp_map_name,
      { "Name",             "afp.map_name",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"User/Group name", HFILL }},

    /* AFP 3.0 */
    { &hf_afp_lock_offset64,
      { "Offset",         "afp.lock_offset64",
		FT_INT64, BASE_DEC, NULL, 0x0,
      	"First byte to be locked (64 bits)", HFILL }},

    { &hf_afp_lock_len64,
      { "Length",         "afp.lock_len64",
		FT_INT64, BASE_DEC, NULL, 0x0,
      	"Number of bytes to be locked/unlocked (64 bits)", HFILL }},

    { &hf_afp_lock_range_start64,
      { "Start",         "afp.lock_range_start64",
		FT_INT64, BASE_DEC, NULL, 0x0,
      	"First byte locked/unlocked (64 bits)", HFILL }},

    { &hf_afp_offset64,
      { "Offset",         "afp.offset64",
		FT_INT64, BASE_DEC, NULL, 0x0,
      	"Offset (64 bits)", HFILL }},

    { &hf_afp_rw_count64,
      { "Count",         "afp.rw_count64",
		FT_INT64, BASE_DEC, NULL, 0x0,
      	"Number of bytes to be read/written (64 bits)", HFILL }},

    { &hf_afp_last_written64,
      { "Last written",  "afp.last_written64",
		FT_UINT64, BASE_DEC, NULL, 0x0,
      	"Offset of the last byte written (64 bits)", HFILL }},

    { &hf_afp_ofork_len64,
      { "New length",         "afp.ofork_len64",
		FT_INT64, BASE_DEC, NULL, 0x0,
      	"New length (64 bits)", HFILL }},

    { &hf_afp_session_token_type,
      { "Type",         "afp.session_token_type",
		FT_UINT16, BASE_HEX, VALS(token_type_vals), 0x0,
      	"Session token type", HFILL }},

    /* FIXME FT_UINT32 in specs */
    { &hf_afp_session_token_len,
      { "Len",         "afp.session_token_len",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Session token length", HFILL }},

    { &hf_afp_session_token_timestamp,
      { "Time stamp",         "afp.session_token_timestamp",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"Session time stamp", HFILL }},

    { &hf_afp_session_token,
      { "Token",         "afp.session_token",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"Session token", HFILL }},

    { &hf_afp_user_flag,
      { "Flag",         "afp.user_flag",
		FT_UINT8, BASE_HEX, VALS(user_flag_vals), 0x01,
      	"User Info flag", HFILL }},

    { &hf_afp_user_ID,
      { "User ID",         "afp.user_ID",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"User ID", HFILL }},

    { &hf_afp_group_ID,
      { "Group ID",         "afp.group_ID",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Group ID", HFILL }},

    { &hf_afp_UUID,
      { "UUID",         "afp.uuid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"UUID", HFILL }},

    { &hf_afp_GRPUUID,
      { "GRPUUID",         "afp.grpuuid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"Group UUID", HFILL }},

    { &hf_afp_user_bitmap,
      { "Bitmap",         "afp.user_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0,
      	"User Info bitmap", HFILL }},

    { &hf_afp_user_bitmap_UID,
      { "User ID",         "afp.user_bitmap.UID",
		FT_BOOLEAN, 16, NULL, 0x01,
      	"User ID", HFILL }},

    { &hf_afp_user_bitmap_GID,
      { "Primary group ID",         "afp.user_bitmap.GID",
		FT_BOOLEAN, 16, NULL, 0x02,
      	"Primary group ID", HFILL }},

    { &hf_afp_user_bitmap_UUID,
      { "UUID",         "afp.user_bitmap.UUID",
		FT_BOOLEAN, 16, NULL, 0x04,
      	"UUID", HFILL }},

    { &hf_afp_message_type,
      { "Type",         "afp.message_type",
		FT_UINT16, BASE_HEX, VALS(server_message_type), 0,
      	"Type of server message", HFILL }},

    { &hf_afp_message_bitmap,
      { "Bitmap",         "afp.message_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0,
      	"Message bitmap", HFILL }},

    { &hf_afp_message_bitmap_REQ,
      { "Request message",         "afp.message_bitmap.requested",
		FT_BOOLEAN, 16, NULL, 0x01,
        "Message Requested", HFILL }},

    { &hf_afp_message_bitmap_UTF,
      { "Message is UTF8",         "afp.message_bitmap.utf8",
		FT_BOOLEAN, 16, NULL, 0x02,
        "Message is UTF8", HFILL }},

    { &hf_afp_message_len,
      { "Len",         "afp.message_length",
		FT_UINT32, BASE_DEC, NULL, 0x0,
        "Message length", HFILL }},

    { &hf_afp_message,
      { "Message",  "afp.message",
		FT_STRING, BASE_NONE, NULL, 0x0,
      	"Message", HFILL }},

    { &hf_afp_reqcount64,
      { "Count",         "afp.reqcount64",
		FT_INT64, BASE_DEC, NULL, 0x0,
      	"Request Count (64 bits)", HFILL }},

    { &hf_afp_extattr_bitmap,
      { "Bitmap",         "afp.extattr_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0,
      	"Extended attributes bitmap", HFILL }},

    { &hf_afp_extattr_bitmap_NoFollow,
      { "No follow symlinks",         "afp.extattr_bitmap.nofollow",
		FT_BOOLEAN, 16, NULL, 0x01,
        "Do not follow symlink", HFILL }},

    { &hf_afp_extattr_bitmap_Create,
      { "Create",         "afp.extattr_bitmap.create",
		FT_BOOLEAN, 16, NULL, 0x02,
        "Create extended attribute", HFILL }},

    { &hf_afp_extattr_bitmap_Replace,
      { "Replace",         "afp.extattr_bitmap.replace",
		FT_BOOLEAN, 16, NULL, 0x04,
        "Replace extended attribute", HFILL }},

    { &hf_afp_extattr_namelen,
      { "Length",         "afp.extattr.namelen",
		FT_UINT16, BASE_DEC, NULL, 0x0,
        "Extended attribute name length", HFILL }},

    { &hf_afp_extattr_name,
      { "Name",             "afp.extattr.name",
		FT_STRING, BASE_NONE, NULL, 0x0,
      	"Extended attribute name", HFILL }},

    { &hf_afp_extattr_len,
      { "Length",         "afp.extattr.len",
		FT_UINT32, BASE_DEC, NULL, 0x0,
        "Extended attribute length", HFILL }},

    { &hf_afp_extattr_data,
      { "Data",         "afp.extattr.data",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"Extendend attribute data", HFILL }},

    { &hf_afp_extattr_req_count,
      { "Request Count",         "afp.extattr.req_count",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Request Count.", HFILL }},

    { &hf_afp_extattr_start_index,
      { "Index",         "afp.extattr.start_index",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Start index", HFILL }},

    { &hf_afp_extattr_reply_size,
      { "Reply size",         "afp.extattr.reply_size",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Reply size", HFILL }},

	/* ACL control list bitmap */
    { &hf_afp_access_bitmap,
      { "Bitmap",         "afp.access_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0,
      	"Bitmap (reserved)", HFILL }},

    { &hf_afp_acl_list_bitmap,
      { "ACL bitmap",         "afp.acl_list_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0,
      	"ACL control list bitmap", HFILL }},

    { &hf_afp_acl_list_bitmap_UUID,
      { "UUID",         "afp.acl_list_bitmap.UUID",
		FT_BOOLEAN, 16, NULL, kFileSec_UUID,
      	"User UUID", HFILL }},

    { &hf_afp_acl_list_bitmap_GRPUUID,
      { "GRPUUID",         "afp.acl_list_bitmap.GRPUUID",
		FT_BOOLEAN, 16, NULL, kFileSec_GRPUUID,
      	"Group UUID", HFILL }},

    { &hf_afp_acl_list_bitmap_ACL,
      { "ACL",         "afp.acl_list_bitmap.ACL",
		FT_BOOLEAN, 16, NULL, kFileSec_ACL,
      	"ACL", HFILL }},

    { &hf_afp_acl_list_bitmap_REMOVEACL,
      { "Remove ACL",         "afp.acl_list_bitmap.REMOVEACL",
		FT_BOOLEAN, 16, NULL, kFileSec_REMOVEACL,
      	"Remove ACL", HFILL }},

    { &hf_afp_acl_list_bitmap_Inherit,
      { "Inherit",         "afp.acl_list_bitmap.Inherit",
		FT_BOOLEAN, 16, NULL, kFileSec_Inherit,
      	"Inherit ACL", HFILL }},

    { &hf_afp_acl_entrycount,
      { "Count",         "afp.acl_entrycount",
		FT_UINT32, BASE_HEX, NULL, 0,
      	"Number of ACL entries", HFILL }},

    { &hf_afp_acl_flags,
      { "ACL flags",         "afp.acl_flags",
		FT_UINT32, BASE_HEX, NULL, 0,
      	"ACL flags", HFILL }},

    { &hf_afp_ace_applicable,
      { "ACE",         "afp.ace_applicable",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"ACE applicable", HFILL }},

    { &hf_afp_ace_rights,
      { "Rights",         "afp.ace_rights",
		FT_UINT32, BASE_HEX, NULL, 0,
      	"ACE flags", HFILL }},

    { &hf_afp_acl_access_bitmap,
      { "Bitmap",         "afp.acl_access_bitmap",
		FT_UINT32, BASE_HEX, NULL, 0,
      	"ACL access bitmap", HFILL }},

    { &hf_afp_acl_access_bitmap_read_data,
      { "Read/List",         "afp.acl_access_bitmap.read_data",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_DATA,
      	"Read data / list directory", HFILL }},

    { &hf_afp_acl_access_bitmap_write_data,
      { "Write/Add file",         "afp.acl_access_bitmap.write_data",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_DATA,
      	"Write data to a file / add a file to a directory", HFILL }},

    { &hf_afp_acl_access_bitmap_execute,
      { "Execute/Search",         "afp.acl_access_bitmap.execute",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_EXECUTE,
      	"Execute a program", HFILL }},

    { &hf_afp_acl_access_bitmap_delete,
      { "Delete",         "afp.acl_access_bitmap.delete",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_DELETE,
      	"Delete", HFILL }},

    { &hf_afp_acl_access_bitmap_append_data,
      { "Append data/create subdir",         "afp.acl_access_bitmap.append_data",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_APPEND_DATA,
      	"Append data to a file / create a subdirectory", HFILL }},

    { &hf_afp_acl_access_bitmap_delete_child,
      { "Delete dir",         "afp.acl_access_bitmap.delete_child",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_DELETE_CHILD,
      	"Delete directory", HFILL }},

    { &hf_afp_acl_access_bitmap_read_attrs,
      { "Read attributes",         "afp.acl_access_bitmap.read_attrs",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_ATTRIBUTES,
      	"Read attributes", HFILL }},

    { &hf_afp_acl_access_bitmap_write_attrs,
      { "Write attributes",         "afp.acl_access_bitmap.write_attrs",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_ATTRIBUTES,
      	"Write attributes", HFILL }},

    { &hf_afp_acl_access_bitmap_read_extattrs,
      { "Read extended attributes", "afp.acl_access_bitmap.read_extattrs",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES,
      	"Read extended attributes", HFILL }},

    { &hf_afp_acl_access_bitmap_write_extattrs,
      { "Write extended attributes", "afp.acl_access_bitmap.write_extattrs",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES,
      	"Write extended attributes", HFILL }},

    { &hf_afp_acl_access_bitmap_read_security,
      { "Read security",         "afp.acl_access_bitmap.read_security",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_SECURITY,
      	"Read access rights", HFILL }},

    { &hf_afp_acl_access_bitmap_write_security,
      { "Write security",         "afp.acl_access_bitmap.write_security",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_SECURITY,
      	"Write access rights", HFILL }},

    { &hf_afp_acl_access_bitmap_change_owner,
      { "Change owner",         "afp.acl_access_bitmap.change_owner",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_CHANGE_OWNER,
      	"Change owner", HFILL }},

    { &hf_afp_acl_access_bitmap_synchronize,
      { "Synchronize",         "afp.acl_access_bitmap.synchronize",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_SYNCHRONIZE,
      	"Synchronize", HFILL }},

    { &hf_afp_acl_access_bitmap_generic_all,
      { "Generic all",         "afp.acl_access_bitmap.generic_all",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_ALL,
      	"Generic all", HFILL }},

    { &hf_afp_acl_access_bitmap_generic_execute,
      { "Generic execute",         "afp.acl_access_bitmap.generic_execute",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_EXECUTE,
      	"Generic execute", HFILL }},

    { &hf_afp_acl_access_bitmap_generic_write,
      { "Generic write",         "afp.acl_access_bitmap.generic_write",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_WRITE,
      	"Generic write", HFILL }},

    { &hf_afp_acl_access_bitmap_generic_read,
      { "Generic read",         "afp.acl_access_bitmap.generic_read",
		FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_READ,
      	"Generic read", HFILL }},

    { &hf_afp_ace_flags,
      { "Flags",         "afp.ace_flags",
		FT_UINT32, BASE_HEX, NULL, 0,
      	"ACE flags", HFILL }},

    { &hf_afp_ace_flags_allow,
      { "Allow",         "afp.ace_flags.allow",
		FT_BOOLEAN, 32, NULL, ACE_ALLOW,
      	"Allow rule", HFILL }},

    { &hf_afp_ace_flags_deny,
      { "Deny",         "afp.ace_flags.deny",
		FT_BOOLEAN, 32, NULL, ACE_DENY,
      	"Deny rule", HFILL }},

    { &hf_afp_ace_flags_inherited,
      { "Inherited",         "afp.ace_flags.inherited",
		FT_BOOLEAN, 32, NULL, ACE_INHERITED,
      	"Inherited", HFILL }},

    { &hf_afp_ace_flags_fileinherit,
      { "File inherit",         "afp.ace_flags.file_inherit",
		FT_BOOLEAN, 32, NULL, ACE_FILE_INHERIT,
      	"File inherit", HFILL }},

    { &hf_afp_ace_flags_dirinherit,
      { "Dir inherit",         "afp.ace_flags.directory_inherit",
		FT_BOOLEAN, 32, NULL, ACE_DIR_INHERIT,
      	"Dir inherit", HFILL }},

    { &hf_afp_ace_flags_limitinherit,
      { "Limit inherit",         "afp.ace_flags.limit_inherit",
		FT_BOOLEAN, 32, NULL, ACE_LIMIT_INHERIT,
      	"Limit inherit", HFILL }},

    { &hf_afp_ace_flags_onlyinherit,
      { "Only inherit",         "afp.ace_flags.only_inherit",
		FT_BOOLEAN, 32, NULL, ACE_ONLY_INHERIT,
      	"Only inherit", HFILL }},
  };

  static gint *ett[] = {
	&ett_afp,
	&ett_afp_server_vol,
	&ett_afp_vol_list,
	&ett_afp_vol_flag,
	&ett_afp_vol_bitmap,
	&ett_afp_vol_attribute,
	&ett_afp_dir_bitmap,
	&ett_afp_file_bitmap,
	&ett_afp_unix_privs,
	&ett_afp_enumerate,
	&ett_afp_enumerate_line,
	&ett_afp_access_mode,
	&ett_afp_dir_attribute,
	&ett_afp_file_attribute,
	&ett_afp_path_name,
	&ett_afp_lock_flags,
	&ett_afp_dir_ar,
	&ett_afp_cat_search,
	&ett_afp_cat_r_bitmap,
	&ett_afp_cat_spec,
	&ett_afp_vol_did,
	&ett_afp_user_bitmap,
	&ett_afp_message_bitmap,
	&ett_afp_extattr_bitmap,
	&ett_afp_extattr_names,
	&ett_afp_acl_list_bitmap,
	&ett_afp_acl_access_bitmap,
	&ett_afp_ace_entries,
	&ett_afp_ace_entry,
	&ett_afp_ace_flags,
  };

  proto_afp = proto_register_protocol("Apple Filing Protocol", "AFP", "afp");
  proto_register_field_array(proto_afp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_init_routine(afp_reinit);

  register_dissector("afp", dissect_afp, proto_afp);
  data_handle = find_dissector("data");

  afp_tap = register_tap("afp");
}

void
proto_reg_handoff_afp(void)
{
  data_handle = find_dissector("data");
}

/* -------------------------------
   end
*/
