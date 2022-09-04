/* packet-afp.c
 * Routines for afp packet dissection
 * Copyright 2002, Didier Gautheron <dgautheron@magic.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 * Copied from packet-dsi.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/expert.h>

#include "packet-afp.h"

/* The information in this module (AFP) comes from:

  AFP 2.1 & 2.2 documentation, in PDF form, at

http://mirror.informatimago.com/next/developer.apple.com/documentation/macos8/pdf/ASAppleTalkFiling2.1_2.2.pdf

  formerly at

http://developer.apple.com/DOCUMENTATION/macos8/pdf/ASAppleTalkFiling2.1_2.2.pdf

  AFP3.0.pdf from http://www.apple.com (still available?)

  AFP 3.1 programming guide, in PDF form, at

https://web.archive.org/web/20040721011424/http://developer.apple.com/documentation/Networking/Conceptual/AFP/AFP3_1.pdf

  and, in HTML form, at

https://web.archive.org/web/20041010010846/http://developer.apple.com/documentation/Networking/Conceptual/AFP/index.html

  AFP 3.2 programming guide, in PDF form, at

https://web.archive.org/web/20060207231337/http://developer.apple.com/documentation/Networking/Conceptual/AFP/AFP3_1.pdf

  and, in HTML form, at

https://web.archive.org/web/20080514131536/http://developer.apple.com/documentation/Networking/Conceptual/AFP/Introduction/chapter_1_section_1.html

  AFP 3.x specification, as of 2012, in PDF form, at
https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.363.9481&rep=rep1&type=pdf

  Current AFP 3.x programming guide, in HTML form, at
https://developer.apple.com/library/archive/documentation/Networking/Conceptual/AFP/Introduction/Introduction.html

  The netatalk source code by Wesley Craig & Adrian Sun
	http://netatalk.sf.net

  XXX - distinguish between UTF-8 and Mac proprietary encodings for strings?
  Does that need a preference in case we didn't see the client and server
  negotiate that?
*/
/* Forward declarations */
void proto_register_afp(void);
void proto_reg_handoff_afp(void);

/* from netatalk/include/afp.h */
#define AFPTRANS_NONE          0
#define AFPTRANS_DDP          (1U << 0)
#define AFPTRANS_TCP          (1U << 1)
#define AFPTRANS_ALL          (AFPTRANS_DDP | AFPTRANS_TCP)

/* AFP Attention Codes -- 4 bits */
#define AFPATTN_SHUTDOWN     (1U << 15)           /* shutdown/disconnect */
#define AFPATTN_CRASH        (1U << 14)           /* server crashed */
#define AFPATTN_MESG         (1U << 13)           /* server has message */
#define AFPATTN_NORECONNECT  (1U << 12)           /* don't reconnect */
/* server notification */
#define AFPATTN_NOTIFY       (AFPATTN_MESG | AFPATTN_NORECONNECT)

/* extended bitmap -- 12 bits. volchanged is only useful w/ a server
 * notification, and time is only useful for shutdown. */
#define AFPATTN_VOLCHANGED   (1U << 0)            /* volume has changed */
#define AFPATTN_TIME(x)      ((x) & 0xfff)        /* time in minutes */

/* AFP functions */
#define AFP_BYTELOCK		 1
#define AFP_CLOSEVOL		 2
#define AFP_CLOSEDIR		 3
#define AFP_CLOSEFORK		 4
#define AFP_COPYFILE		 5
#define AFP_CREATEDIR		 6
#define AFP_CREATEFILE		 7
#define AFP_DELETE		 8
#define AFP_ENUMERATE		 9
#define AFP_FLUSH		10
#define AFP_FLUSHFORK		11
#define AFP_GETFORKPARAM	14
#define AFP_GETSRVINFO		15
#define AFP_GETSRVPARAM		16
#define AFP_GETVOLPARAM		17
#define AFP_LOGIN		18
#define AFP_LOGINCONT		19
#define AFP_LOGOUT		20
#define AFP_MAPID		21
#define AFP_MAPNAME		22
#define AFP_MOVE		23
#define AFP_OPENVOL		24
#define AFP_OPENDIR		25
#define AFP_OPENFORK		26
#define AFP_READ		27
#define AFP_RENAME		28
#define AFP_SETDIRPARAM		29
#define AFP_SETFILEPARAM	30
#define AFP_SETFORKPARAM	31
#define AFP_SETVOLPARAM		32
#define AFP_WRITE		33
#define AFP_GETFLDRPARAM	34
#define AFP_SETFLDRPARAM	35
#define AFP_CHANGEPW		36
#define AFP_GETUSERINFO		37
#define AFP_GETSRVRMSG		38
#define AFP_CREATEID		39
#define AFP_DELETEID		40
#define AFP_RESOLVEID		41
#define AFP_EXCHANGEFILE	42
#define AFP_CATSEARCH		43
#define AFP_OPENDT		48
#define AFP_CLOSEDT		49
#define AFP_GETICON		51
#define AFP_GTICNINFO		52
#define AFP_ADDAPPL		53
#define AFP_RMVAPPL		54
#define AFP_GETAPPL		55
#define AFP_ADDCMT		56
#define AFP_RMVCMT		57
#define AFP_GETCMT		58

#define AFP_ZZZ			122
#define AFP_ADDICON		192

/* AFP 3.0 new calls */
#define AFP_BYTELOCK_EXT	59
#define AFP_READ_EXT		60
#define AFP_WRITE_EXT		61
#define AFP_LOGIN_EXT		63
#define AFP_GETSESSTOKEN	64
#define AFP_DISCTOLDSESS	65
#define AFP_ENUMERATE_EXT	66
#define AFP_CATSEARCH_EXT	67

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

/* AFP 3.2 calls added in 10.5 */
#define AFP_SPOTLIGHTRPC	76
#define AFP_SYNCDIR		78
#define AFP_SYNCFORK		79

/* FPSpotlightRPC subcommand codes */
#define SPOTLIGHT_CMD_GET_VOLPATH 4
#define SPOTLIGHT_CMD_GET_VOLID   2
#define SPOTLIGHT_CMD_GET_THREE   3

/* Spotlight epoch is UNIX epoch minus SPOTLIGHT_TIME_DELTA */
#define SPOTLIGHT_TIME_DELTA G_GUINT64_CONSTANT(280878921600)

/* ----------------------------- */
static int proto_afp			    = -1;
static int hf_afp_reserved		    = -1;
static int hf_afp_unknown		    = -1;

static int hf_afp_command		    = -1;		/* CommandCode */
static int hf_afp_Version		    = -1;
static int hf_afp_UAM			    = -1;
static int hf_afp_user			    = -1;
static int hf_afp_passwd		    = -1;
static int hf_afp_random		    = -1;

static int hf_afp_response_to		    = -1;
static int hf_afp_time			    = -1;
static int hf_afp_response_in		    = -1;

static int hf_afp_login_flags		    = -1;
static int hf_afp_pad			    = -1;

static int hf_afp_user_type		    = -1;
static int hf_afp_user_len		    = -1;
static int hf_afp_user_name		    = -1;

static int hf_afp_vol_flag		    = -1;
static int hf_afp_vol_flag_passwd	    = -1;
static int hf_afp_vol_flag_has_config	    = -1;
static int hf_afp_server_time		    = -1;

static int hf_afp_vol_bitmap		    = -1;
static int hf_afp_vol_name_offset	    = -1;
static int hf_afp_vol_id		    = -1;
static int hf_afp_vol_attribute		    = -1;
static int hf_afp_vol_name		    = -1;
static int hf_afp_vol_signature		    = -1;
static int hf_afp_vol_creation_date	    = -1;
static int hf_afp_vol_modification_date	    = -1;
static int hf_afp_vol_backup_date	    = -1;
static int hf_afp_vol_bytes_free	    = -1;
static int hf_afp_vol_bytes_total	    = -1;
static int hf_afp_vol_ex_bytes_free	    = -1;
static int hf_afp_vol_ex_bytes_total	    = -1;
static int hf_afp_vol_block_size	    = -1;

/* desktop stuff */
static int hf_afp_comment		    = -1;
static int hf_afp_file_creator		    = -1;
static int hf_afp_file_type		    = -1;
static int hf_afp_icon_type		    = -1;
static int hf_afp_icon_length		    = -1;
static int hf_afp_icon_tag		    = -1;
static int hf_afp_icon_index		    = -1;
static int hf_afp_appl_index		    = -1;
static int hf_afp_appl_tag		    = -1;

static int hf_afp_did			    = -1;
static int hf_afp_file_id		    = -1;
static int hf_afp_file_DataForkLen	    = -1;
static int hf_afp_file_RsrcForkLen	    = -1;
static int hf_afp_file_ExtDataForkLen	    = -1;
static int hf_afp_file_ExtRsrcForkLen	    = -1;

static int hf_afp_dir_bitmap		    = -1;
static int hf_afp_dir_offspring		    = -1;
static int hf_afp_dir_OwnerID		    = -1;
static int hf_afp_dir_GroupID		    = -1;

static int hf_afp_req_count		    = -1;
static int hf_afp_start_index		    = -1;
static int hf_afp_start_index32		    = -1;
static int hf_afp_max_reply_size	    = -1;
static int hf_afp_max_reply_size32	    = -1;
static int hf_afp_file_flag		    = -1;
static int hf_afp_create_flag		    = -1;
static int hf_afp_struct_size		    = -1;
static int hf_afp_struct_size16		    = -1;

static int hf_afp_cat_count		    = -1;
static int hf_afp_cat_req_matches	    = -1;
static int hf_afp_cat_position		    = -1;

static int hf_afp_creation_date		    = -1;
static int hf_afp_modification_date	    = -1;
static int hf_afp_backup_date		    = -1;
static int hf_afp_finder_info		    = -1;
static int hf_afp_long_name_offset	    = -1;
static int hf_afp_short_name_offset	    = -1;
static int hf_afp_unicode_name_offset	    = -1;
static int hf_afp_unix_privs_uid	    = -1;
static int hf_afp_unix_privs_gid	    = -1;
static int hf_afp_unix_privs_permissions    = -1;
static int hf_afp_unix_privs_ua_permissions = -1;

static int hf_afp_path_type		    = -1;
static int hf_afp_path_len		    = -1;
static int hf_afp_path_name		    = -1;
static int hf_afp_path_unicode_hint	    = -1;
static int hf_afp_path_unicode_len	    = -1;

static int hf_afp_flag			    = -1;
static int hf_afp_dt_ref		    = -1;
static int hf_afp_ofork			    = -1;
static int hf_afp_ofork_len		    = -1;
static int hf_afp_offset		    = -1;
static int hf_afp_rw_count		    = -1;
static int hf_afp_newline_mask		    = -1;
static int hf_afp_newline_char		    = -1;
static int hf_afp_last_written		    = -1;

static int hf_afp_fork_type		    = -1;
static int hf_afp_access_mode		    = -1;
static int hf_afp_access_read		    = -1;
static int hf_afp_access_write		    = -1;
static int hf_afp_access_deny_read	    = -1;
static int hf_afp_access_deny_write	    = -1;

static gint hf_afp_lock_op		    = -1;
static gint hf_afp_lock_from		    = -1;
static gint hf_afp_lock_offset		    = -1;
static gint hf_afp_lock_len		    = -1;
static gint hf_afp_lock_range_start	    = -1;

static gint ett_afp			    = -1;

static gint ett_afp_vol_attribute	    = -1;
static gint ett_afp_enumerate		    = -1;
static gint ett_afp_enumerate_line	    = -1;
static gint ett_afp_access_mode		    = -1;

static gint ett_afp_vol_bitmap		    = -1;
static gint ett_afp_dir_bitmap		    = -1;
static gint ett_afp_dir_attribute	    = -1;
static gint ett_afp_file_attribute	    = -1;
static gint ett_afp_file_bitmap		    = -1;
static gint ett_afp_unix_privs		    = -1;
static gint ett_afp_path_name		    = -1;
static gint ett_afp_lock_flags		    = -1;
static gint ett_afp_dir_ar		    = -1;

static gint ett_afp_server_vol		    = -1;
static gint ett_afp_vol_list		    = -1;
static gint ett_afp_vol_flag		    = -1;
static gint ett_afp_cat_search		    = -1;
static gint ett_afp_cat_r_bitmap	    = -1;
static gint ett_afp_cat_spec		    = -1;
static gint ett_afp_vol_did		    = -1;

/* AFP 3.0 parameters */
static gint hf_afp_lock_offset64	    = -1;
static gint hf_afp_lock_len64		    = -1;
static gint hf_afp_lock_range_start64	    = -1;

static int hf_afp_offset64		    = -1;
static int hf_afp_rw_count64		    = -1;
static int hf_afp_reqcount64		    = -1;

static int hf_afp_last_written64	    = -1;

static int hf_afp_ofork_len64		    = -1;
static int hf_afp_session_token_type	    = -1;
static int hf_afp_session_token_len	    = -1;
static int hf_afp_session_token		    = -1;
static int hf_afp_session_token_timestamp   = -1;

/* AFP 3.2 */

static int hf_afp_extattr_bitmap	    = -1;
static int hf_afp_extattr_bitmap_NoFollow   = -1;
static int hf_afp_extattr_bitmap_Create	    = -1;
static int hf_afp_extattr_bitmap_Replace    = -1;
static int ett_afp_extattr_bitmap	    = -1;
static int hf_afp_extattr_namelen	    = -1;
static int hf_afp_extattr_name		    = -1;
static int hf_afp_extattr_len		    = -1;
static int hf_afp_extattr_data		    = -1;
static int hf_afp_extattr_req_count	    = -1;
static int hf_afp_extattr_start_index	    = -1;
static int hf_afp_extattr_reply_size	    = -1;
static int ett_afp_extattr_names	    = -1;

static expert_field ei_afp_subquery_count_over_safety_limit = EI_INIT;
static expert_field ei_afp_subquery_count_over_query_count = EI_INIT;
static expert_field ei_afp_abnormal_num_subqueries = EI_INIT;
static expert_field ei_afp_too_many_acl_entries = EI_INIT;
static expert_field ei_afp_ip_port_reused = EI_INIT;
static expert_field ei_afp_toc_offset = EI_INIT;


static int afp_tap			    = -1;

static dissector_handle_t spotlight_handle;

static const value_string vol_signature_vals[] = {
	{1, "Flat"},
	{2, "Fixed Directory ID"},
	{3, "Variable Directory ID (deprecated)"},
	{0, NULL }
};

static const value_string CommandCode_vals[] = {
	{AFP_BYTELOCK,		"FPByteRangeLock" },
	{AFP_CLOSEVOL,		"FPCloseVol" },
	{AFP_CLOSEDIR,		"FPCloseDir" },
	{AFP_CLOSEFORK,		"FPCloseFork" },
	{AFP_COPYFILE,		"FPCopyFile" },
	{AFP_CREATEDIR,		"FPCreateDir" },
	{AFP_CREATEFILE,	"FPCreateFile" },
	{AFP_DELETE,		"FPDelete" },
	{AFP_ENUMERATE,		"FPEnumerate" },
	{AFP_FLUSH,		"FPFlush" },
	{AFP_FLUSHFORK,		"FPFlushFork" },
	{AFP_GETFORKPARAM,	"FPGetForkParms" },
	{AFP_GETSRVINFO,	"FPGetSrvrInfo" },
	{AFP_GETSRVPARAM,	"FPGetSrvrParms" },
	{AFP_GETVOLPARAM,	"FPGetVolParms" },
	{AFP_LOGIN,		"FPLogin" },
	{AFP_LOGINCONT,		"FPLoginCont" },
	{AFP_LOGOUT,		"FPLogout" },
	{AFP_MAPID,		"FPMapID" },
	{AFP_MAPNAME,		"FPMapName" },
	{AFP_MOVE,		"FPMoveAndRename" },
	{AFP_OPENVOL,		"FPOpenVol" },
	{AFP_OPENDIR,		"FPOpenDir" },
	{AFP_OPENFORK,		"FPOpenFork" },
	{AFP_READ,		"FPRead" },
	{AFP_RENAME,		"FPRename" },
	{AFP_SETDIRPARAM,	"FPSetDirParms" },
	{AFP_SETFILEPARAM,	"FPSetFileParms" },
	{AFP_SETFORKPARAM,	"FPSetForkParms" },
	{AFP_SETVOLPARAM,	"FPSetVolParms" },
	{AFP_WRITE,		"FPWrite" },
	{AFP_GETFLDRPARAM,	"FPGetFileDirParms" },
	{AFP_SETFLDRPARAM,	"FPSetFileDirParms" },
	{AFP_CHANGEPW,		"FPChangePassword" },
	{AFP_GETUSERINFO,	"FPGetUserInfo" },
	{AFP_GETSRVRMSG,	"FPGetSrvrMsg" },
	{AFP_CREATEID,		"FPCreateID" },
	{AFP_DELETEID,		"FPDeleteID" },
	{AFP_RESOLVEID,		"FPResolveID" },
	{AFP_EXCHANGEFILE,	"FPExchangeFiles" },
	{AFP_CATSEARCH,		"FPCatSearch" },
	{AFP_OPENDT,		"FPOpenDT" },
	{AFP_CLOSEDT,		"FPCloseDT" },
	{AFP_GETICON,		"FPGetIcon" },
	{AFP_GTICNINFO,		"FPGetIconInfo" },
	{AFP_ADDAPPL,		"FPAddAPPL" },
	{AFP_RMVAPPL,		"FPRemoveAPPL" },
	{AFP_GETAPPL,		"FPGetAPPL" },
	{AFP_ADDCMT,		"FPAddComment" },
	{AFP_RMVCMT,		"FPRemoveComment" },
	{AFP_GETCMT,		"FPGetComment" },
	{AFP_BYTELOCK_EXT,	"FPByteRangeLockExt" },
	{AFP_READ_EXT,		"FPReadExt" },
	{AFP_WRITE_EXT,		"FPWriteExt" },
	{AFP_LOGIN_EXT,		"FPLoginExt" },
	{AFP_GETSESSTOKEN,	"FPGetSessionToken" },
	{AFP_DISCTOLDSESS,	"FPDisconnectOldSession" },
	{AFP_ENUMERATE_EXT,	"FPEnumerateExt" },
	{AFP_CATSEARCH_EXT,	"FPCatSearchExt" },
	{AFP_ENUMERATE_EXT2,	"FPEnumerateExt2" },
	{AFP_GETEXTATTR,	"FPGetExtAttr" },
	{AFP_SETEXTATTR,	"FPSetExtAttr" },
	{AFP_REMOVEATTR,	"FPRemoveExtAttr" },
	{AFP_LISTEXTATTR,	"FPListExtAttrs" },
	{AFP_GETACL,		"FPGetACL" },
	{AFP_SETACL,		"FPSetACL" },
	{AFP_ACCESS,		"FPAccess" },
	{AFP_SPOTLIGHTRPC,	"FPSpotlightRPC" },
	{AFP_SYNCDIR,		"FPSyncDir" },
	{AFP_SYNCFORK,		"FPSyncFork" },
	{AFP_ZZZ,		"FPZzzzz" },
	{AFP_ADDICON,		"FPAddIcon" },
	{0,			 NULL }
};
value_string_ext CommandCode_vals_ext = VALUE_STRING_EXT_INIT(CommandCode_vals);

static const value_string unicode_hint_vals[] = {
	{    0,	"MacRoman" },
	{    1,	"MacJapanese" },
	{    2,	"MacChineseTrad" },
	{    3,	"MacKorean" },
	{    4,	"MacArabic" },
	{    5,	"MacHebrew" },
	{    6,	"MacGreek" },
	{    7,	"MacCyrillic" },
	{    9,	"MacDevanagari" },
	{   10,	"MacGurmukhi" },
	{   11,	"MacGujarati" },
	{   12,	"MacOriya" },
	{   13,	"MacBengali" },
	{   14,	"MacTamil" },
	{   15,	"MacTelugu" },
	{   16,	"MacKannada" },
	{   17,	"MacMalayalam" },
	{   18,	"MacSinhalese" },
	{   19,	"MacBurmese" },
	{   20,	"MacKhmer" },
	{   21,	"MacThai" },
	{   22,	"MacLaotian" },
	{   23,	"MacGeorgian" },
	{   24,	"MacArmenian" },
	{   25,	"MacChineseSimp" },
	{   26,	"MacTibetan" },
	{   27,	"MacMongolian" },
	{   28,	"MacEthiopic" },
	{   29,	"MacCentralEurRoman" },
	{   30,	"MacVietnamese" },
	{   31,	"MacExtArabic" },
	{   33,	"MacSymbol" },
	{   34,	"MacDingbats" },
	{   35,	"MacTurkish" },
	{   36,	"MacCroatian" },
	{   37,	"MacIcelandic" },
	{   38,	"MacRomanian" },
	{   39,	"MacCeltic" },
	{   40,	"MacGaelic" },
	{   41,	"MacKeyboardGlyphs" },
	{  126,	"MacUnicode" },
	{  140,	"MacFarsi" },
	{  152,	"MacUkrainian" },
	{  236,	"MacInuit" },
	{  252,	"MacVT100" },
	{  255,	"MacHFS" },
	{  256,	"UnicodeDefault" },
/* ??	{  257,	"UnicodeV1_1" }, */
	{  257,	"ISO10646_1993" },
	{  259,	"UnicodeV2_0" },
/* ??	{  259,	"UnicodeV2_1" }, */
	{  260,	"UnicodeV3_0" },
	{  513,	"ISOLatin1" },
	{  514,	"ISOLatin2" },
	{  515,	"ISOLatin3" },
	{  516,	"ISOLatin4" },
	{  517,	"ISOLatinCyrillic" },
	{  518,	"ISOLatinArabic" },
	{  519,	"ISOLatinGreek" },
	{  520,	"ISOLatinHebrew" },
	{  521,	"ISOLatin5" },
	{  522,	"ISOLatin6" },
	{  525,	"ISOLatin7" },
	{  526,	"ISOLatin8" },
	{  527,	"ISOLatin9" },
	{ 1024,	"DOSLatinUS" },
	{ 1029,	"DOSGreek" },
	{ 1030,	"DOSBalticRim" },
	{ 1040,	"DOSLatin1" },
	{ 1041,	"DOSGreek1" },
	{ 1042,	"DOSLatin2" },
	{ 1043,	"DOSCyrillic" },
	{ 1044,	"DOSTurkish" },
	{ 1045,	"DOSPortuguese" },
	{ 1046,	"DOSIcelandic" },
	{ 1047,	"DOSHebrew" },
	{ 1048,	"DOSCanadianFrench" },
	{ 1049,	"DOSArabic" },
	{ 1050,	"DOSNordic" },
	{ 1051,	"DOSRussian" },
	{ 1052,	"DOSGreek2" },
	{ 1053,	"DOSThai" },
	{ 1056,	"DOSJapanese" },
	{ 1057,	"DOSChineseSimplif" },
	{ 1058,	"DOSKorean" },
	{ 1059,	"DOSChineseTrad" },
	{ 1280,	"WindowsLatin1" },
/*	{ 1280, "WindowsANSI" }, */
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
static value_string_ext unicode_hint_vals_ext = VALUE_STRING_EXT_INIT(unicode_hint_vals);

/* volume bitmap
  from Apple AFP3.0.pdf
  Table 1-2 p. 20
*/
#define kFPVolAttributeBit 		(1U << 0)
#define kFPVolSignatureBit 		(1U << 1)
#define kFPVolCreateDateBit	 	(1U << 2)
#define kFPVolModDateBit 		(1U << 3)
#define kFPVolBackupDateBit 		(1U << 4)
#define kFPVolIDBit 			(1U << 5)
#define kFPVolBytesFreeBit	  	(1U << 6)
#define kFPVolBytesTotalBit	 	(1U << 7)
#define kFPVolNameBit 			(1U << 8)
#define kFPVolExtBytesFreeBit 		(1U << 9)
#define kFPVolExtBytesTotalBit		(1U << 10)
#define kFPVolBlockSizeBit 	  	(1U << 11)

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

static int hf_afp_vol_attribute_ReadOnly		    = -1;
static int hf_afp_vol_attribute_HasVolumePassword	    = -1;
static int hf_afp_vol_attribute_SupportsFileIDs		    = -1;
static int hf_afp_vol_attribute_SupportsCatSearch	    = -1;
static int hf_afp_vol_attribute_SupportsBlankAccessPrivs    = -1;
static int hf_afp_vol_attribute_SupportsUnixPrivs	    = -1;
static int hf_afp_vol_attribute_SupportsUTF8Names	    = -1;
static int hf_afp_vol_attribute_NoNetworkUserID		    = -1;
static int hf_afp_vol_attribute_DefaultPrivsFromParent	    = -1;
static int hf_afp_vol_attribute_NoExchangeFiles		    = -1;
static int hf_afp_vol_attribute_SupportsExtAttrs	    = -1;
static int hf_afp_vol_attribute_SupportsACLs		    = -1;
static int hf_afp_vol_attribute_CaseSensitive		    = -1;
static int hf_afp_vol_attribute_SupportsTMLockSteal	    = -1;

static int hf_afp_dir_bitmap_Attributes			     = -1;
static int hf_afp_dir_bitmap_ParentDirID		     = -1;
static int hf_afp_dir_bitmap_CreateDate			     = -1;
static int hf_afp_dir_bitmap_ModDate			     = -1;
static int hf_afp_dir_bitmap_BackupDate			     = -1;
static int hf_afp_dir_bitmap_FinderInfo			     = -1;
static int hf_afp_dir_bitmap_LongName			     = -1;
static int hf_afp_dir_bitmap_ShortName			     = -1;
static int hf_afp_dir_bitmap_NodeID			     = -1;
static int hf_afp_dir_bitmap_OffspringCount		     = -1;
static int hf_afp_dir_bitmap_OwnerID			     = -1;
static int hf_afp_dir_bitmap_GroupID			     = -1;
static int hf_afp_dir_bitmap_AccessRights		     = -1;
static int hf_afp_dir_bitmap_UTF8Name			     = -1;
static int hf_afp_dir_bitmap_UnixPrivs			     = -1;

static int hf_afp_dir_attribute				     = -1;
static int hf_afp_dir_attribute_Invisible		     = -1;
static int hf_afp_dir_attribute_IsExpFolder		     = -1;
static int hf_afp_dir_attribute_System			     = -1;
static int hf_afp_dir_attribute_Mounted			     = -1;
static int hf_afp_dir_attribute_InExpFolder		     = -1;
static int hf_afp_dir_attribute_BackUpNeeded		     = -1;
static int hf_afp_dir_attribute_RenameInhibit		     = -1;
static int hf_afp_dir_attribute_DeleteInhibit		     = -1;

static int hf_afp_file_bitmap				     = -1;
static int hf_afp_file_bitmap_Attributes		     = -1;
static int hf_afp_file_bitmap_ParentDirID		     = -1;
static int hf_afp_file_bitmap_CreateDate		     = -1;
static int hf_afp_file_bitmap_ModDate			     = -1;
static int hf_afp_file_bitmap_BackupDate		     = -1;
static int hf_afp_file_bitmap_FinderInfo		     = -1;
static int hf_afp_file_bitmap_LongName			     = -1;
static int hf_afp_file_bitmap_ShortName			     = -1;
static int hf_afp_file_bitmap_NodeID			     = -1;
static int hf_afp_file_bitmap_DataForkLen		     = -1;
static int hf_afp_file_bitmap_RsrcForkLen		     = -1;
static int hf_afp_file_bitmap_ExtDataForkLen		     = -1;
static int hf_afp_file_bitmap_LaunchLimit	 	     = -1;

static int hf_afp_file_bitmap_UTF8Name			     = -1;
static int hf_afp_file_bitmap_ExtRsrcForkLen	 	     = -1;
static int hf_afp_file_bitmap_UnixPrivs			     = -1;

static int hf_afp_file_attribute			     = -1;
static int hf_afp_file_attribute_Invisible		     = -1;
static int hf_afp_file_attribute_MultiUser		     = -1;
static int hf_afp_file_attribute_System			     = -1;
static int hf_afp_file_attribute_DAlreadyOpen		     = -1;
static int hf_afp_file_attribute_RAlreadyOpen		     = -1;
static int hf_afp_file_attribute_WriteInhibit		     = -1;
static int hf_afp_file_attribute_BackUpNeeded		     = -1;
static int hf_afp_file_attribute_RenameInhibit		     = -1;
static int hf_afp_file_attribute_DeleteInhibit		     = -1;
static int hf_afp_file_attribute_CopyProtect		     = -1;
static int hf_afp_file_attribute_SetClear		     = -1;

static int hf_afp_map_name_type				     = -1;
static int hf_afp_map_name				     = -1;
static int hf_afp_map_id				     = -1;
static int hf_afp_map_id_type				     = -1;
static int hf_afp_map_id_reply_type			     = -1;

/* catsearch stuff */
static int hf_afp_request_bitmap			     = -1;
static int hf_afp_request_bitmap_Attributes		     = -1;
static int hf_afp_request_bitmap_ParentDirID		     = -1;
static int hf_afp_request_bitmap_CreateDate		     = -1;
static int hf_afp_request_bitmap_ModDate		     = -1;
static int hf_afp_request_bitmap_BackupDate		     = -1;
static int hf_afp_request_bitmap_FinderInfo		     = -1;
static int hf_afp_request_bitmap_LongName		     = -1;
static int hf_afp_request_bitmap_DataForkLen		     = -1;
static int hf_afp_request_bitmap_OffspringCount		     = -1;
static int hf_afp_request_bitmap_RsrcForkLen		     = -1;
static int hf_afp_request_bitmap_ExtDataForkLen		     = -1;
static int hf_afp_request_bitmap_UTF8Name		     = -1;
static int hf_afp_request_bitmap_ExtRsrcForkLen		     = -1;
static int hf_afp_request_bitmap_PartialNames		     = -1;

/* Spotlight stuff */
static int ett_afp_spotlight_queries			     = -1;
static int ett_afp_spotlight_query_line			     = -1;
static int ett_afp_spotlight_query			     = -1;
static int ett_afp_spotlight_data			     = -1;
static int ett_afp_spotlight_toc			     = -1;

static int hf_afp_spotlight_request_flags		     = -1;
static int hf_afp_spotlight_request_command		     = -1;
static int hf_afp_spotlight_request_reserved		     = -1;
static int hf_afp_spotlight_reply_reserved		     = -1;
static int hf_afp_spotlight_volpath_server		     = -1;
static int hf_afp_spotlight_volpath_client		     = -1;
static int hf_afp_spotlight_returncode			     = -1;
static int hf_afp_spotlight_volflags			     = -1;
static int hf_afp_spotlight_reqlen			     = -1;
static int hf_afp_spotlight_uuid			     = -1;
static int hf_afp_spotlight_date			     = -1;

/* Status stuff from ASP or DSI */
static int ett_afp_status				     = -1;
static int ett_afp_uams					     = -1;
static int ett_afp_vers					     = -1;
static int ett_afp_server_addr				     = -1;
static int ett_afp_server_addr_line			     = -1;
static int ett_afp_directory				     = -1;
static int ett_afp_utf8_name				     = -1;
static int ett_afp_status_server_flag			     = -1;

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
static value_string_ext map_name_type_vals_ext = VALUE_STRING_EXT_INIT(map_name_type_vals);

static const value_string map_id_type_vals[] = {
	{1,	"User ID to a Macintosh roman user name" },
	{2,	"Group ID to a Macintosh roman group name" },
	{3,	"User ID to a unicode user name" },
	{4,	"Group ID to a unicode group name" },
	{5,	"User UUID to a unicode user name" },
	{6,	"Group UUID to a unicode group name" },
	{0,	NULL } };
static value_string_ext map_id_type_vals_ext = VALUE_STRING_EXT_INIT(map_id_type_vals);

/* map_id subfunctions 5,6: reply type */
static const value_string map_id_reply_type_vals[] = {
	{1,	"user name" },
	{2,	"group name" },
	{0,	NULL } };

/*
  volume attribute from Apple AFP3.0.pdf
  Table 1-3 p. 22
*/
#define kReadOnly 				(1U << 0)
#define kHasVolumePassword 			(1U << 1)
#define kSupportsFileIDs 			(1U << 2)
#define kSupportsCatSearch 			(1U << 3)
#define kSupportsBlankAccessPrivs 		(1U << 4)
#define kSupportsUnixPrivs 			(1U << 5)
#define kSupportsUTF8Names 			(1U << 6)
/* AFP3.1 */
#define kNoNetworkUserIDs 			(1U << 7)
/* AFP3.2 */
#define kDefaultPrivsFromParent			(1U << 8)
#define kNoExchangeFiles			(1U << 9)
#define kSupportsExtAttrs			(1U << 10)
#define kSupportsACLs				(1U << 11)
/* AFP3.2+ */
#define kCaseSensitive 				(1U << 12)
#define kSupportsTMLockSteal			(1U << 13)

/*
  directory bitmap from Apple AFP3.1.pdf
  Table 1-5 pp. 25-26
*/
#define kFPAttributeBit 		(1U << 0)
#define kFPParentDirIDBit 		(1U << 1)
#define kFPCreateDateBit 		(1U << 2)
#define kFPModDateBit 			(1U << 3)
#define kFPBackupDateBit 		(1U << 4)
#define kFPFinderInfoBit 		(1U << 5)
#define kFPLongNameBit			(1U << 6)
#define kFPShortNameBit 		(1U << 7)
#define kFPNodeIDBit 			(1U << 8)
#define kFPOffspringCountBit	 	(1U << 9)
#define kFPOwnerIDBit 			(1U << 10)
#define kFPGroupIDBit 			(1U << 11)
#define kFPAccessRightsBit 		(1U << 12)
#define kFPUTF8NameBit 			(1U << 13)

/* FIXME AFP3.0 bit 14, AFP3.1 bit 15 */

#define kFPUnixPrivsBit 		(1U << 15)

/*
	directory Access Rights parameter AFP3.1.pdf
	table 1-7 p. 28
*/

#define AR_O_SEARCH     (1U << 0)   /* owner has search access */
#define AR_O_READ       (1U << 1)   /* owner has read access */
#define AR_O_WRITE      (1U << 2)   /* owner has write access */

#define AR_G_SEARCH     (1U << 8)   /* group has search access */
#define AR_G_READ       (1U << 9)   /* group has read access */
#define AR_G_WRITE      (1U << 10)  /* group has write access */

#define AR_E_SEARCH     (1U << 16)  /* everyone has search access */
#define AR_E_READ       (1U << 17)  /* everyone has read access */
#define AR_E_WRITE      (1U << 18)  /* everyone has write access */

#define AR_U_SEARCH     (1U << 24)  /* user has search access */
#define AR_U_READ       (1U << 25)  /* user has read access */
#define AR_U_WRITE      (1U << 26)  /* user has write access */

#define AR_BLANK        (1U << 28)  /* Blank Access Privileges (use parent dir privileges) */
#define AR_U_OWN        (1U << 31)  /* user is the owner */

static int hf_afp_dir_ar           = -1;
static int hf_afp_dir_ar_o_search  = -1;
static int hf_afp_dir_ar_o_read    = -1;
static int hf_afp_dir_ar_o_write   = -1;
static int hf_afp_dir_ar_g_search  = -1;
static int hf_afp_dir_ar_g_read    = -1;
static int hf_afp_dir_ar_g_write   = -1;
static int hf_afp_dir_ar_e_search  = -1;
static int hf_afp_dir_ar_e_read    = -1;
static int hf_afp_dir_ar_e_write   = -1;
static int hf_afp_dir_ar_u_search  = -1;
static int hf_afp_dir_ar_u_read    = -1;
static int hf_afp_dir_ar_u_write   = -1;
static int hf_afp_dir_ar_blank     = -1;
static int hf_afp_dir_ar_u_own     = -1;

static int hf_afp_user_flag        = -1;
static int hf_afp_user_ID          = -1;
static int hf_afp_group_ID         = -1;
static int hf_afp_UUID      	   = -1;
static int hf_afp_GRPUUID          = -1;
static int hf_afp_user_bitmap      = -1;
static int hf_afp_user_bitmap_UID  = -1;
static int hf_afp_user_bitmap_GID  = -1;
static int hf_afp_user_bitmap_UUID = -1;

static gint ett_afp_user_bitmap    = -1;

static const value_string user_flag_vals[] = {
	{0,	"Use user ID" },
	{1,	"Default user" },
	{0,	NULL } };

static int hf_afp_message            = -1;
static int hf_afp_message_type       = -1;
static int hf_afp_message_bitmap     = -1;
static int hf_afp_message_bitmap_REQ = -1;
static int hf_afp_message_bitmap_UTF = -1;
static int hf_afp_message_len	     = -1;

static gint ett_afp_message_bitmap   = -1;

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

#define kFPDataForkLenBit 	(1U << 9)
#define kFPRsrcForkLenBit 	(1U << 10)
#define kFPExtDataForkLenBit 	(1U << 11)
#define kFPLaunchLimitBit 	(1U << 12)

#define kFPExtRsrcForkLenBit 	(1U << 14)

/*
  file attribute AFP3.1.pdf
  Table 1-9 pp. 29-31
*/
#define kFPInvisibleBit 	(1U << 0)
#define kFPMultiUserBit 	(1U << 1)
#define kFPSystemBit 		(1U << 2)
#define kFPDAlreadyOpenBit 	(1U << 3)
#define kFPRAlreadyOpenBit 	(1U << 4)
#define kFPWriteInhibitBit 	(1U << 5)
#define kFPBackUpNeededBit 	(1U << 6)
#define kFPRenameInhibitBit 	(1U << 7)
#define kFPDeleteInhibitBit 	(1U << 8)
#define kFPCopyProtectBit 	(1U << 10)
#define kFPSetClearBit 		(1U << 15)

/* dir attribute */
#define kIsExpFolder 		(1U << 1)
#define kMounted 		(1U << 3)
#define kInExpFolder 		(1U << 4)

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
	{kLoginWithoutID,             "LoginWithoutID"},
	{kLoginWithID,                "LoginWithID"},
	{kReconnWithID,               "ReconnWithID"},
	{kLoginWithTimeAndID,         "LoginWithTimeAndID"},
	{kReconnWithTimeAndID,        "ReconnWithTimeAndID"},
	{kRecon1Login,                "Recon1Login"},
	{kRecon1ReconnectLogin,       "Recon1ReconnectLogin"},
	{kRecon1Refresh,              "Recon1Refresh"},
	{kGetKerberosSessionKey,      "GetKerberosSessionKey"},

	{0,			       NULL } };
static value_string_ext token_type_vals_ext = VALUE_STRING_EXT_INIT(token_type_vals);

/* AFP 3.2 ACL bitmap */
#define kFileSec_UUID		(1U << 0)
#define kFileSec_GRPUUID	(1U << 1)
#define kFileSec_ACL		(1U << 2)
#define kFileSec_REMOVEACL	(1U << 3)
#define kFileSec_Inherit	(1U << 4)

static int hf_afp_acl_list_bitmap		= -1;
static int hf_afp_acl_list_bitmap_UUID		= -1;
static int hf_afp_acl_list_bitmap_GRPUUID	= -1;
static int hf_afp_acl_list_bitmap_ACL		= -1;
static int hf_afp_acl_list_bitmap_REMOVEACL	= -1;
static int hf_afp_acl_list_bitmap_Inherit	= -1;
static int ett_afp_acl_list_bitmap		= -1;

static int hf_afp_access_bitmap			= -1;

static int hf_afp_acl_entrycount	 = -1;
static int hf_afp_acl_flags		 = -1;

static int hf_afp_ace_flags		 = -1;

static int ett_afp_ace_flags		 = -1;
static int hf_afp_ace_flags_allow	 = -1;
static int hf_afp_ace_flags_deny	 = -1;
static int hf_afp_ace_flags_inherited	 = -1;
static int hf_afp_ace_flags_fileinherit	 = -1;
static int hf_afp_ace_flags_dirinherit	 = -1;
static int hf_afp_ace_flags_limitinherit = -1;
static int hf_afp_ace_flags_onlyinherit  = -1;

/* AFP 3.2 ACE flags */
#define ACE_ALLOW	  (1U << 0)
#define ACE_DENY	  (1U << 1)
#define ACE_INHERITED	  (1U << 4)
#define ACE_FILE_INHERIT  (1U << 5)
#define ACE_DIR_INHERIT	  (1U << 6)
#define ACE_LIMIT_INHERIT (1U << 7)
#define ACE_ONLY_INHERIT  (1U << 8)

static int ett_afp_ace_entries		 = -1;
static int ett_afp_ace_entry		 = -1;

/* AFP 3.2 ACL access right cf page 248*/
#define KAUTH_VNODE_READ_DATA		(1U << 1)
#define KAUTH_VNODE_LIST_DIRECTORY	KAUTH_VNODE_READ_DATA
#define KAUTH_VNODE_WRITE_DATA		(1U << 2)
#define KAUTH_VNODE_ADD_FILE		KAUTH_VNODE_WRITE_DATA
#define KAUTH_VNODE_EXECUTE		(1U << 3)
#define KAUTH_VNODE_SEARCH		KAUTH_VNODE_EXECUTE
#define KAUTH_VNODE_DELETE		(1U << 4)
#define KAUTH_VNODE_APPEND_DATA		(1U << 5)
#define KAUTH_VNODE_ADD_SUBDIRECTORY	KAUTH_VNODE_APPEND_DATA
#define KAUTH_VNODE_DELETE_CHILD	(1U << 6)
#define KAUTH_VNODE_READ_ATTRIBUTES	(1U << 7)
#define KAUTH_VNODE_WRITE_ATTRIBUTES	(1U << 8)
#define KAUTH_VNODE_READ_EXTATTRIBUTES	(1U << 9)
#define KAUTH_VNODE_WRITE_EXTATTRIBUTES	(1U << 10)
#define KAUTH_VNODE_READ_SECURITY	(1U << 11)
#define KAUTH_VNODE_WRITE_SECURITY	(1U << 12)
#define KAUTH_VNODE_CHANGE_OWNER	(1U << 13)
#define KAUTH_VNODE_SYNCHRONIZE		(1U << 20)
#define KAUTH_VNODE_GENERIC_ALL		(1U << 21)
#define KAUTH_VNODE_GENERIC_EXECUTE	(1U << 22)
#define KAUTH_VNODE_GENERIC_WRITE	(1U << 23)
#define KAUTH_VNODE_GENERIC_READ	(1U << 24)


static int hf_afp_acl_access_bitmap		    = -1;
static int ett_afp_acl_access_bitmap		    = -1;
static int hf_afp_acl_access_bitmap_read_data	    = -1;
static int hf_afp_acl_access_bitmap_write_data	    = -1;
static int hf_afp_acl_access_bitmap_execute	    = -1;
static int hf_afp_acl_access_bitmap_delete	    = -1;
static int hf_afp_acl_access_bitmap_append_data	    = -1;
static int hf_afp_acl_access_bitmap_delete_child    = -1;
static int hf_afp_acl_access_bitmap_read_attrs	    = -1;
static int hf_afp_acl_access_bitmap_write_attrs	    = -1;
static int hf_afp_acl_access_bitmap_read_extattrs   = -1;
static int hf_afp_acl_access_bitmap_write_extattrs  = -1;
static int hf_afp_acl_access_bitmap_read_security   = -1;
static int hf_afp_acl_access_bitmap_write_security  = -1;
static int hf_afp_acl_access_bitmap_change_owner    = -1;
static int hf_afp_acl_access_bitmap_synchronize	    = -1;
static int hf_afp_acl_access_bitmap_generic_all	    = -1;
static int hf_afp_acl_access_bitmap_generic_execute = -1;
static int hf_afp_acl_access_bitmap_generic_write   = -1;
static int hf_afp_acl_access_bitmap_generic_read    = -1;

/* Status stuff from ASP or DSI */
static int hf_afp_server_name = -1;
static int hf_afp_utf8_server_name_len = -1;
static int hf_afp_utf8_server_name = -1;
static int hf_afp_server_type = -1;
static int hf_afp_server_vers = -1;
static int hf_afp_server_uams = -1;
static int hf_afp_server_icon = -1;
static int hf_afp_server_directory = -1;

static int hf_afp_server_flag = -1;
static int hf_afp_server_flag_copyfile = -1;
static int hf_afp_server_flag_passwd   = -1;
static int hf_afp_server_flag_no_save_passwd = -1;
static int hf_afp_server_flag_srv_msg   = -1;
static int hf_afp_server_flag_srv_sig   = -1;
static int hf_afp_server_flag_tcpip     = -1;
static int hf_afp_server_flag_notify    = -1;
static int hf_afp_server_flag_reconnect = -1;
static int hf_afp_server_flag_directory = -1;
static int hf_afp_server_flag_utf8_name = -1;
static int hf_afp_server_flag_uuid      = -1;
static int hf_afp_server_flag_ext_sleep = -1;
static int hf_afp_server_flag_fast_copy = -1;
static int hf_afp_server_signature      = -1;

static int hf_afp_server_addr_len       = -1;
static int hf_afp_server_addr_type      = -1;
static int hf_afp_server_addr_value     = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_afp_int64 = -1;
static int hf_afp_float = -1;
static int hf_afp_unknown16 = -1;
static int hf_afp_unknown32 = -1;
static int hf_afp_cnid = -1;
static int hf_afp_null = -1;
static int hf_afp_string = -1;
static int hf_afp_utf_16_string = -1;
static int hf_afp_bool = -1;
static int hf_afp_query_type = -1;
static int hf_afp_toc_offset = -1;
static int hf_afp_toc_entry = -1;
static int hf_afp_endianness = -1;
static int hf_afp_query_len = -1;
static int hf_afp_num_toc_entries = -1;
static int hf_afp_machine_offset = -1;
static int hf_afp_version_offset = -1;
static int hf_afp_uams_offset = -1;
static int hf_afp_icon_offset = -1;
static int hf_afp_signature_offset = -1;
static int hf_afp_network_address_offset = -1;
static int hf_afp_directory_services_offset = -1;
static int hf_afp_utf8_server_name_offset = -1;

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

#define AFP_NUM_PROCEDURES     256

static void
afpstat_init(struct register_srt* srt _U_, GArray* srt_array)
{
	srt_stat_table *afp_srt_table;
	guint32 i;

	afp_srt_table = init_srt_table("AFP Commands", NULL, srt_array, AFP_NUM_PROCEDURES, NULL, "afp.command", NULL);
	for (i = 0; i < AFP_NUM_PROCEDURES; i++)
	{
		gchar* tmp_str = val_to_str_ext_wmem(NULL, i, &CommandCode_vals_ext, "Unknown(%u)");
		init_srt_table_row(afp_srt_table, i, tmp_str);
		wmem_free(NULL, tmp_str);
	}
}

static tap_packet_status
afpstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
	guint i = 0;
	srt_stat_table *afp_srt_table;
	srt_data_t *data = (srt_data_t *)pss;
	const afp_request_val *request_val = (const afp_request_val *)prv;

	/* if we haven't seen the request, just ignore it */
	if (!request_val) {
		return TAP_PACKET_DONT_REDRAW;
	}

	afp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);

	add_srt_table_data(afp_srt_table, request_val->command, &request_val->req_time, pinfo);

	return TAP_PACKET_REDRAW;
}



#define hash_init_count 20

/* Forward declarations */

/* Hash functions */
static gint  afp_equal (gconstpointer v, gconstpointer v2);
static guint afp_hash  (gconstpointer v);

typedef struct {
	guint32 conversation;
	guint16	tid;
} afp_request_key;

static wmem_map_t *afp_request_hash = NULL;

static guint Vol;      /* volume */
static guint Did;      /* parent directory ID */

/*
* Returns the UTF-16 byte order, as an ENC_xxx_ENDIAN value,
* by checking the 2-byte byte order mark.
* If there is no byte order mark, 0xFFFFFFFF is returned.
*/
static guint
spotlight_get_utf16_string_byte_order(tvbuff_t *tvb, gint offset, gint query_length, guint encoding) {
	guint byte_order;

	/* check for byte order mark */
	byte_order = 0xFFFFFFFF;
	if (query_length >= 2) {
		guint16 byte_order_mark;
		byte_order_mark = tvb_get_guint16(tvb, offset, encoding);

		if (byte_order_mark == 0xFFFE) {
			byte_order = ENC_BIG_ENDIAN;
		}
		else if (byte_order_mark == 0xFEFF) {
			byte_order = ENC_LITTLE_ENDIAN;
		}
	}

	return byte_order;
}

/* Hash Functions */
static gint  afp_equal (gconstpointer v, gconstpointer v2)
{
	const afp_request_key *val1 = (const afp_request_key*)v;
	const afp_request_key *val2 = (const afp_request_key*)v2;

	if (val1->conversation == val2->conversation &&
			val1->tid == val2->tid) {
		return 1;
	}
	return 0;
}

static guint afp_hash  (gconstpointer v)
{
	const afp_request_key *afp_key = (const afp_request_key*)v;
	return afp_key->tid;
}

/* --------------------------
*/
#define PAD(x)      { proto_tree_add_item(tree, hf_afp_pad, tvb, offset,  x, ENC_NA); offset += x; }

static guint16
decode_vol_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	guint16	 bitmap;
	static int * const bitmaps[] = {
		&hf_afp_vol_bitmap_Attributes,
		&hf_afp_vol_bitmap_Signature,
		&hf_afp_vol_bitmap_CreateDate,
		&hf_afp_vol_bitmap_ModDate,
		&hf_afp_vol_bitmap_BackupDate,
		&hf_afp_vol_bitmap_ID,
		&hf_afp_vol_bitmap_BytesFree,
		&hf_afp_vol_bitmap_BytesTotal,
		&hf_afp_vol_bitmap_Name,
		&hf_afp_vol_bitmap_ExtBytesFree,
		&hf_afp_vol_bitmap_ExtBytesTotal,
		&hf_afp_vol_bitmap_BlockSize,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_vol_bitmap,
					ett_afp_vol_bitmap, bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohs(tvb, offset);

	return bitmap;
}

/* -------------------------- */
static guint16
decode_vol_attribute (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	guint16	 bitmap;
	static int * const bitmaps[] = {
		&hf_afp_vol_attribute_ReadOnly,
		&hf_afp_vol_attribute_HasVolumePassword,
		&hf_afp_vol_attribute_SupportsFileIDs,
		&hf_afp_vol_attribute_SupportsCatSearch,
		&hf_afp_vol_attribute_SupportsBlankAccessPrivs,
		&hf_afp_vol_attribute_SupportsUnixPrivs,
		&hf_afp_vol_attribute_SupportsUTF8Names,
		&hf_afp_vol_attribute_NoNetworkUserID,
		&hf_afp_vol_attribute_DefaultPrivsFromParent,
		&hf_afp_vol_attribute_NoExchangeFiles,
		&hf_afp_vol_attribute_SupportsExtAttrs,
		&hf_afp_vol_attribute_SupportsACLs,
		&hf_afp_vol_attribute_CaseSensitive,
		&hf_afp_vol_attribute_SupportsTMLockSteal,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_vol_attribute,
					ett_afp_vol_attribute, bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohs(tvb, offset);

	return bitmap;
}

/* --------------------------
	cf AFP3.0.pdf page 38
	date  are number of seconds from 12:00am on 01.01.2000 GMT
	backup : 0x8000000 not set
	from netatalk adouble.h
*/
#define DATE_NOT_SET	     0x80000000
#define AD_DATE_DELTA	      946684800
#define AD_DATE_TO_UNIX(x)    (x + AD_DATE_DELTA)
static void
print_date(proto_tree *tree,int id, tvbuff_t *tvb, gint offset)
{
	time_t date = tvb_get_ntohl(tvb, offset);
	nstime_t tv;

	tv.secs = AD_DATE_TO_UNIX(date);
	tv.nsecs = 0;
	proto_tree_add_time(tree, id, tvb, offset, 4, &tv);
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
		proto_tree_add_item(tree, hf_afp_vol_signature,tvb, offset, 2, ENC_BIG_ENDIAN);
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
		proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if ((bitmap & kFPVolBytesFreeBit)) {
		proto_tree_add_item(tree, hf_afp_vol_bytes_free,tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if ((bitmap & kFPVolBytesTotalBit)) {
		proto_tree_add_item(tree, hf_afp_vol_bytes_total,tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if ((bitmap & kFPVolNameBit)) {
		nameoff = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_vol_name_offset,tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if ((bitmap & kFPVolExtBytesFreeBit)) {
		proto_tree_add_item(tree, hf_afp_vol_ex_bytes_free,tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}
	if ((bitmap & kFPVolExtBytesTotalBit)) {
		proto_tree_add_item(tree, hf_afp_vol_ex_bytes_total,tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}
	if ((bitmap & kFPVolBlockSizeBit)) {
		proto_tree_add_item(tree, hf_afp_vol_block_size,tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (nameoff) {
		guint8 len;

		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_afp_vol_name, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
		offset += len +1;

	}
	return offset;
}

/* -------------------------- */
static guint16
decode_file_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	guint16	 bitmap;
	static int * const bitmaps[] = {
		&hf_afp_file_bitmap_Attributes,
		&hf_afp_file_bitmap_ParentDirID,
		&hf_afp_file_bitmap_CreateDate,
		&hf_afp_file_bitmap_ModDate,
		&hf_afp_file_bitmap_BackupDate,
		&hf_afp_file_bitmap_FinderInfo,
		&hf_afp_file_bitmap_LongName,
		&hf_afp_file_bitmap_ShortName,
		&hf_afp_file_bitmap_NodeID,
		&hf_afp_file_bitmap_DataForkLen,
		&hf_afp_file_bitmap_RsrcForkLen,
		&hf_afp_file_bitmap_ExtDataForkLen,
		&hf_afp_file_bitmap_LaunchLimit,
		&hf_afp_file_bitmap_UTF8Name,
		&hf_afp_file_bitmap_ExtRsrcForkLen,
		&hf_afp_file_bitmap_UnixPrivs,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_file_bitmap,
					ett_afp_file_bitmap, bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohs(tvb, offset);

	return bitmap;
}

/* -------------------------- */
static guint16
decode_file_attribute(proto_tree *tree, tvbuff_t *tvb, gint offset, int shared)
{
	guint16	    attribute;
	static int * const not_shared_attr[] = {
		&hf_afp_file_attribute_Invisible,
		&hf_afp_file_attribute_MultiUser,
		&hf_afp_file_attribute_System,
		&hf_afp_file_attribute_DAlreadyOpen,
		&hf_afp_file_attribute_RAlreadyOpen,
		/* writeinhibit is file only but Macs are setting it with FPSetFileDirParms too */
		&hf_afp_file_attribute_WriteInhibit,
		&hf_afp_file_attribute_BackUpNeeded,
		&hf_afp_file_attribute_RenameInhibit,
		&hf_afp_file_attribute_DeleteInhibit,
		&hf_afp_file_attribute_CopyProtect,
		&hf_afp_file_attribute_SetClear,
		NULL
	};

	static int * const shared_attr[] = {
		&hf_afp_file_attribute_Invisible,
		&hf_afp_file_attribute_System,
		&hf_afp_file_attribute_WriteInhibit,
		&hf_afp_file_attribute_BackUpNeeded,
		&hf_afp_file_attribute_RenameInhibit,
		&hf_afp_file_attribute_DeleteInhibit,
		&hf_afp_file_attribute_SetClear,
		NULL
	};

	if (!shared)
	{
		proto_tree_add_bitmask(tree, tvb, offset, hf_afp_file_attribute,
					ett_afp_file_attribute, not_shared_attr, ENC_BIG_ENDIAN);
	}
	else
	{
		proto_tree_add_bitmask(tree, tvb, offset, hf_afp_file_attribute,
					ett_afp_file_attribute, shared_attr, ENC_BIG_ENDIAN);
	}

	attribute = tvb_get_ntohs(tvb, offset);
	return(attribute);
}

static void
decode_access_rights (proto_tree *tree, tvbuff_t *tvb, int hf, gint offset)
{
	static int * const rights[] = {
		&hf_afp_dir_ar_o_search,
		&hf_afp_dir_ar_o_read,
		&hf_afp_dir_ar_o_write,
		&hf_afp_dir_ar_g_search,
		&hf_afp_dir_ar_g_read,
		&hf_afp_dir_ar_g_write,
		&hf_afp_dir_ar_e_search,
		&hf_afp_dir_ar_e_read,
		&hf_afp_dir_ar_e_write,
		&hf_afp_dir_ar_u_search,
		&hf_afp_dir_ar_u_read,
		&hf_afp_dir_ar_u_write,
		&hf_afp_dir_ar_blank,
		&hf_afp_dir_ar_u_own,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf,
					ett_afp_dir_ar, rights, ENC_BIG_ENDIAN);
}

static void
decode_unix_privs (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	proto_tree *sub_tree;

	if (tree) {
		sub_tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_afp_unix_privs, NULL,
		    "UNIX privileges");

		proto_tree_add_item(sub_tree, hf_afp_unix_privs_uid, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_unix_privs_gid, tvb, offset+4, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_unix_privs_permissions, tvb, offset+8, 4, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_long_name_offset,tvb, offset, 2, ENC_BIG_ENDIAN);
	if (lnameoff) {
		tp_ofs = lnameoff +org_offset;
		len = tvb_get_guint8(tvb, tp_ofs);
		proto_tree_add_item(tree, hf_afp_path_len, tvb, tp_ofs,	 1, ENC_BIG_ENDIAN);
		tp_ofs++;
		proto_tree_add_item(tree, hf_afp_path_name, tvb, tp_ofs, len, ENC_UTF_8);
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
	proto_tree_add_item(tree, hf_afp_unicode_name_offset,tvb, offset, 2, ENC_BIG_ENDIAN);
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
		proto_tree_add_item( tree, hf_afp_path_unicode_hint, tvb, tp_ofs, 4, ENC_BIG_ENDIAN);
		tp_ofs += 4;

		len = tvb_get_ntohs(tvb, tp_ofs);
		proto_tree_add_item( tree, hf_afp_path_unicode_len, tvb, tp_ofs, 2, ENC_BIG_ENDIAN);
		tp_ofs += 2;

		proto_tree_add_item(tree, hf_afp_path_name, tvb, tp_ofs, len, ENC_UTF_8);
		tp_ofs += len;
	}
	return tp_ofs;
}

/* -------------------------- */
static gint
parse_file_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 bitmap, int shared)
{
	/* guint16 snameoff = 0; */
	gint	max_offset = 0;

	gint	org_offset = offset;

	if ((bitmap & kFPAttributeBit)) {
		decode_file_attribute(tree, tvb, offset, shared);
		offset += 2;
	}
	if ((bitmap & kFPParentDirIDBit)) {
		proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
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
		proto_tree_add_item(tree, hf_afp_finder_info,tvb, offset, 32, ENC_NA);
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
		proto_tree_add_item(tree, hf_afp_short_name_offset,tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if ((bitmap & kFPNodeIDBit)) {
		proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if ((bitmap & kFPDataForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_file_DataForkLen, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if ((bitmap & kFPRsrcForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_file_RsrcForkLen, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if ((bitmap & kFPExtDataForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_file_ExtDataForkLen, tvb, offset, 8, ENC_BIG_ENDIAN);
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
		proto_tree_add_item(tree, hf_afp_file_ExtRsrcForkLen, tvb, offset, 8, ENC_BIG_ENDIAN);
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
	guint16	 bitmap;
	static int * const bitmaps[] = {
		&hf_afp_dir_bitmap_Attributes,
		&hf_afp_dir_bitmap_ParentDirID,
		&hf_afp_dir_bitmap_CreateDate,
		&hf_afp_dir_bitmap_ModDate,
		&hf_afp_dir_bitmap_BackupDate,
		&hf_afp_dir_bitmap_FinderInfo,
		&hf_afp_dir_bitmap_LongName,
		&hf_afp_dir_bitmap_ShortName,
		&hf_afp_dir_bitmap_NodeID,
		&hf_afp_dir_bitmap_OffspringCount,
		&hf_afp_dir_bitmap_OwnerID,
		&hf_afp_dir_bitmap_GroupID,
		&hf_afp_dir_bitmap_AccessRights,
		&hf_afp_dir_bitmap_UTF8Name,
		&hf_afp_dir_bitmap_UnixPrivs,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_dir_bitmap,
					ett_afp_dir_bitmap, bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohs(tvb, offset);

	return bitmap;
}

/* -------------------------- */
static guint16
decode_dir_attribute(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	guint16	 attribute;
	static int * const attributes[] = {
		&hf_afp_dir_attribute_Invisible,
		&hf_afp_dir_attribute_IsExpFolder,
		&hf_afp_dir_attribute_System,
		&hf_afp_dir_attribute_Mounted,
		&hf_afp_dir_attribute_InExpFolder,
		&hf_afp_dir_attribute_BackUpNeeded,
		&hf_afp_dir_attribute_RenameInhibit,
		&hf_afp_dir_attribute_DeleteInhibit,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_dir_attribute,
					ett_afp_dir_attribute, attributes, ENC_BIG_ENDIAN);
	attribute = tvb_get_ntohs(tvb, offset);

	return(attribute);
}

/* -------------------------- */
static gint
parse_dir_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	/* guint16 snameoff = 0; */
	gint	max_offset = 0;

	gint	org_offset = offset;

	if ((bitmap & kFPAttributeBit)) {
		decode_dir_attribute(tree, tvb, offset);
		offset += 2;
	}
	if ((bitmap & kFPParentDirIDBit)) {
		proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
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
		proto_tree_add_item(tree, hf_afp_finder_info,tvb, offset, 32, ENC_NA);
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
		proto_tree_add_item(tree, hf_afp_short_name_offset,tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	if ((bitmap & kFPNodeIDBit)) {
		proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if ((bitmap & kFPOffspringCountBit)) {
		proto_tree_add_item(tree, hf_afp_dir_offspring, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;		/* error in AFP3.0.pdf */
	}
	if ((bitmap & kFPOwnerIDBit)) {
		proto_tree_add_item(tree, hf_afp_dir_OwnerID, tvb, offset, 4,	ENC_BIG_ENDIAN);
		offset += 4;
	}
	if ((bitmap & kFPGroupIDBit)) {
		proto_tree_add_item(tree, hf_afp_dir_GroupID, tvb, offset, 4,	ENC_BIG_ENDIAN);
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
static guint8 *
name_in_bitmap(tvbuff_t *tvb, gint offset, guint16 bitmap, int isdir)
{
	guint8 *name;
	gint	org_offset = offset;
	guint16 nameoff;
	guint8	len;
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
			/* XXX - code page,, e.g. Mac{Roman,Japanese,etc.} */
			name = tvb_get_string_enc(wmem_packet_scope(), tvb, tp_ofs, len, ENC_ASCII|ENC_NA);
			return name;
		}
		offset += 2;
	}

	if ((bitmap & kFPShortNameBit))		/* 7 */
		offset += 2;
	if ((bitmap & kFPNodeIDBit))		/* 8 */
		offset += 4;

	if (isdir) {
		if ((bitmap & kFPOffspringCountBit))	/* 9 */
			offset += 2;
		if ((bitmap & kFPOwnerIDBit))		/* 10*/
			offset += 4;
		if ((bitmap & kFPGroupIDBit))		/* 11*/
			offset += 4;
		if ((bitmap & kFPAccessRightsBit))	/* 12*/
			offset += 4;
	}
	else {
		if ((bitmap & kFPDataForkLenBit))	/* 9 */
			offset += 4;
		if ((bitmap & kFPRsrcForkLenBit))	/* 10*/
			offset += 4;
		if ((bitmap & kFPExtDataForkLenBit))	/* 11*/
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
			name = tvb_get_string_enc(wmem_packet_scope(), tvb, tp_ofs, len16, ENC_UTF_8|ENC_NA);
			return name;
		}
	}
	return NULL;
}

/* -------------------------- */
static guint8 *
name_in_dbitmap(tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	guint8 *name;

	name = name_in_bitmap(tvb, offset, bitmap, 1);
	if (name != NULL)
		return name;
	/*
		check UTF8 name
	*/

	return name;
}

/* -------------------------- */
static guint8 *
name_in_fbitmap(tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	guint8 *name;

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
decode_vol(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	Vol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	return offset + 2;
}

/* -------------------------- */
static gint
decode_vol_did(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	Vol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	Did = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
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
		string = tvb_format_text(wmem_packet_scope(), tvb,offset, len);
		break;
	case 3:
		len = tvb_get_ntohs(tvb, offset +4);
		offset += 6;
		string = tvb_format_text(wmem_packet_scope(), tvb,offset, len);
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

	if (pinfo) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Vol=%u Did=%u", Vol, Did);
		if (len) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " Name=%s", name);
		}
	}

	if (tree) {
		sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, len +header,
				ett_afp_path_name, NULL, label, name);

		proto_tree_add_item( sub_tree, hf_afp_path_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		if (type == 3) {
			proto_tree_add_item( sub_tree, hf_afp_path_unicode_hint, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item( sub_tree, hf_afp_path_unicode_len, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		else {
			proto_tree_add_item( sub_tree, hf_afp_path_len,	 tvb, offset, 1, ENC_BIG_ENDIAN);
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
	if (ofork) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Fork=%u", ofork);
	}
}

/* -------------------------- */
static void
add_info_vol(tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint16 vol;

	vol = tvb_get_ntohs(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ": Vol=%u", vol);
}

/* ************************** */
static gint
dissect_query_afp_open_vol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	int len;
	const gchar *rep;

	PAD(1);

	decode_vol_bitmap(tree, tvb, offset);
	offset += 2;

	len = tvb_get_guint8(tvb, offset);

	rep = get_name(tvb, offset, 2);
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", rep);

	if (!tree)
		return offset;

	proto_tree_add_item(tree, hf_afp_vol_name, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len +1;

	len = tvb_reported_length_remaining(tvb,offset);
	if (len >= 8) {
		/* optional password */
		proto_tree_add_item(tree, hf_afp_passwd, tvb, offset, 8, ENC_UTF_8|ENC_NA);
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
	guint8 i;
	proto_tree *sub_tree;
	proto_item *item;

	static int * const flags[] = {
		&hf_afp_vol_flag_passwd,
		&hf_afp_vol_flag_has_config,
		NULL
	};

	if (!tree)
		return offset;

	print_date(tree, hf_afp_server_time,tvb, offset);
	offset += 4;

	num = tvb_get_guint8(tvb, offset);
	sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
						ett_afp_server_vol, NULL, "Volumes : %d", num);
	offset++;

	for (i = 0; i < num; i++) {
		const gchar *rep;

		tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1,
				ett_afp_vol_list, NULL, "Volume");

		item = proto_tree_add_bitmask(tree, tvb, offset, hf_afp_vol_flag,
					ett_afp_vol_flag, flags, ENC_BIG_ENDIAN);
		offset++;

		len = tvb_get_guint8(tvb, offset) +1;
		rep = get_name(tvb, offset, 2);
		proto_item_set_text(item, "%s", rep);
		proto_item_set_len(item, len +1);

		proto_tree_add_item(tree, hf_afp_vol_name, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);

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

	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	return offset;
}

/* ************************** */
static gint
dissect_query_afp_open_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	static int * const access[] = {
		&hf_afp_access_read,
		&hf_afp_access_write,
		&hf_afp_access_deny_read,
		&hf_afp_access_deny_write,
		NULL
	};

	proto_tree_add_item(tree, hf_afp_fork_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	offset = decode_vol_did(tree, tvb, offset);

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;
	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_access_mode,
					ett_afp_access_mode, access, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
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

	proto_tree_add_item(tree, hf_afp_req_count, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_start_index32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_max_reply_size32, tvb, offset, 4, ENC_BIG_ENDIAN);
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

	proto_tree_add_item(tree, hf_afp_req_count, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_start_index, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_max_reply_size, tvb, offset, 2, ENC_BIG_ENDIAN);
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
	guint8	*name;
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
				tree = proto_tree_add_subtree(ptree, tvb, offset, size,
										ett_afp_enumerate_line, NULL, (const char*)name);
			}
			else {
				tree = proto_tree_add_subtree_format(ptree, tvb, offset, size,
									ett_afp_enumerate_line, NULL, "line %d", i+1);
			}
		}
		if (ext) {
			proto_tree_add_item(tree, hf_afp_struct_size16, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		else {
			proto_tree_add_item(tree, hf_afp_struct_size, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}

		proto_tree_add_item(tree, hf_afp_file_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
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
		item = proto_tree_add_item(tree, hf_afp_req_count, tvb, offset, 2, ENC_BIG_ENDIAN);
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
catsearch_spec(tvbuff_t *tvb, proto_tree *ptree, gint offset, int ext, guint32	r_bitmap, const gchar *label)
{
	proto_tree *tree;
	guint16	size;
	gint	org;

	org = offset;

	if (ext) {
		size = tvb_get_ntohs(tvb, offset) +2;
	}
	else {
		size = tvb_get_guint8(tvb, offset) +2;
	}

	tree = proto_tree_add_subtree(ptree, tvb, offset, size, ett_afp_cat_spec, NULL, label);

	if (ext) {
		proto_tree_add_item(tree, hf_afp_struct_size16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	else {
		proto_tree_add_item(tree, hf_afp_struct_size, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		PAD(1);
	}

	/* AFP 3.1 spec pdf: The low-order word of ReqBitmap is equivalent to the
	File and Directory bitmaps used by the FPGetFileDirParms command. */
	parse_file_bitmap(tree, tvb, offset, (guint16) r_bitmap,0);
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

	proto_tree_add_item(ptree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(ptree, hf_afp_cat_req_matches, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(ptree, hf_afp_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	proto_tree_add_item(ptree, hf_afp_cat_position, tvb, offset, 16, ENC_NA);
	offset += 16;

	f_bitmap = decode_file_bitmap(ptree, tvb, offset);
	offset += 2;

	d_bitmap = decode_dir_bitmap(ptree, tvb, offset);
	offset += 2;

	r_bitmap = tvb_get_ntohl(tvb, offset);
	/* Already checked this above: if (ptree) */ {
		item = proto_tree_add_item(ptree, hf_afp_request_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
		sub_tree = proto_item_add_subtree(item, ett_afp_cat_r_bitmap);

		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_Attributes , tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ParentDirID, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_CreateDate , tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ModDate    , tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_BackupDate , tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_FinderInfo , tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_LongName   , tvb, offset, 4, ENC_BIG_ENDIAN);

		if (d_bitmap == 0) {
			/* Only for file-only searches */
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_DataForkLen	   , tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_RsrcForkLen	   , tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ExtDataForkLen , tvb, offset, 4, ENC_BIG_ENDIAN);
		}
		if (f_bitmap == 0) {
			/* Only for directory-only searches */
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_OffspringCount , tvb, offset, 4, ENC_BIG_ENDIAN);
		}

		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_UTF8Name , tvb, offset, 4, ENC_BIG_ENDIAN);

		if (d_bitmap == 0) {
			/* Only for file-only searches */
			proto_tree_add_item(sub_tree, hf_afp_request_bitmap_ExtRsrcForkLen , tvb, offset, 4, ENC_BIG_ENDIAN);
		}
		proto_tree_add_item(sub_tree, hf_afp_request_bitmap_PartialNames , tvb, offset, 4, ENC_BIG_ENDIAN);
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

	proto_tree_add_item(tree, hf_afp_cat_position, tvb, offset, 16, ENC_NA);
	offset += 16;

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	d_bitmap = decode_dir_bitmap(tree, tvb, offset);
	offset += 2;

	count = tvb_get_ntohl(tvb, offset);
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_cat_count, tvb, offset, 4, ENC_BIG_ENDIAN);
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

	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	bitmap = decode_vol_bitmap(tree, tvb, offset);
	offset += 2;

	offset = parse_vol_bitmap(tree, tvb, offset, bitmap);

	return offset;
}

/* ***************************/
static gint
decode_uam_parameters(const gchar *uam, int len_uam, tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	int len;

	if (!g_ascii_strncasecmp(uam, "Cleartxt passwrd", len_uam)) {
		if ((offset & 1))
			PAD(1);

		len = 8; /* tvb_strsize(tvb, offset);*/
		proto_tree_add_item(tree, hf_afp_passwd, tvb, offset, len, ENC_UTF_8|ENC_NA);
		offset += len;
	}
	else if (!g_ascii_strncasecmp(uam, "DHCAST128", len_uam)) {
		if ((offset & 1))
			PAD(1);

		len = 16;
		proto_tree_add_item(tree, hf_afp_random, tvb, offset, len, ENC_NA);
		offset += len;
	}
	else if (!g_ascii_strncasecmp(uam, "2-Way Randnum exchange", len_uam)) {
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
	const gchar *uam;

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_Version, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len +1;
	len_uam = tvb_get_guint8(tvb, offset);
	uam = (const gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset +1, len_uam, ENC_UTF_8|ENC_NA);
	proto_tree_add_item(tree, hf_afp_UAM, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len_uam +1;

	if (!g_ascii_strncasecmp(uam, "No User Authent", len_uam)) {
		return offset;
	}

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_user, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len +1;

	return decode_uam_parameters(uam, len_uam, tvb, tree, offset);
}

/* ***************************/
static gint
dissect_query_afp_login_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	int len;
	int len_uam;
	const gchar *uam;
	guint8 path_type;

	PAD(1);
	proto_tree_add_item(tree, hf_afp_login_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_Version, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len +1;

	len_uam = tvb_get_guint8(tvb, offset);
	uam = (const gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset +1, len_uam, ENC_UTF_8|ENC_NA);
	proto_tree_add_item(tree, hf_afp_UAM, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len_uam +1;

	proto_tree_add_item(tree, hf_afp_user_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	/* only type 3 */
	len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_user_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_user_name, tvb, offset, len, ENC_UTF_8);
	offset += len;

	/* directory service */
	path_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_path_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	/* FIXME use 16 bit len + unicode from smb dissector */
	switch (path_type) {
	case 1:
	case 2:
		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_afp_path_len, tvb, offset,	 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_afp_path_name, tvb, offset, len, ENC_UTF_8);
		offset += len;
		break;
	case 3:
		len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item( tree, hf_afp_path_unicode_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_afp_path_name, tvb, offset, len, ENC_UTF_8);
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
	int param;


	proto_tree_add_item(tree, hf_afp_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
	param = tvb_get_ntohl(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Offset=%d", param);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_rw_count, tvb, offset, 4, ENC_BIG_ENDIAN);
	param = tvb_get_ntohl(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Size=%d", param);
	offset += 4;

	return offset;
}

static gint
dissect_reply_afp_write(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_last_written, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_write_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_item(tree, hf_afp_rw_count64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

static gint
dissect_reply_afp_write_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_last_written64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_read(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	int param;

	PAD(1);

	add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
	param = tvb_get_ntohl(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Offset=%d", param);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_rw_count, tvb, offset, 4, ENC_BIG_ENDIAN);
	param = tvb_get_ntohl(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Size=%d", param);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_newline_mask, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_afp_newline_char, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_read_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);

	add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_item(tree, hf_afp_rw_count64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

/* **************************
   Open desktop call
   query is the same than	AFP_FLUSH, AFP_CLOSEVOL

*/
static gint
dissect_reply_afp_open_dt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* **************************
	calls using the same format :
		1 pad byte
		fork number
	AFP_FLUSHFORK
	AFP_CLOSEFORK
	AFP_SYNCFORK
*/
static gint
dissect_query_afp_with_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	add_info_fork(tvb, pinfo, offset);
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_file_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_create_dir(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	if ((bitmap & kFPExtDataForkLenBit) || (bitmap & kFPExtRsrcForkLenBit)) {
		proto_tree_add_item(tree, hf_afp_ofork_len64, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}
	else {
		proto_tree_add_item(tree, hf_afp_ofork_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		param = tvb_get_ntohl(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, " Size=%d", param);
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

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
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

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	offset = decode_name_label(tree, pinfo, tvb, offset, "Source path: %s");
	offset = decode_name_label(tree, NULL, tvb, offset,  "Dest path:   %s");

	return offset;
}
/* ************************** */
static gint
dissect_query_afp_copy_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	proto_tree *sub_tree;

	PAD(1);
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_afp_vol_did, NULL, "Source volume");

	offset = decode_vol_did(sub_tree, tvb, offset);

	sub_tree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_afp_vol_did, NULL, "Dest volume");

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
	proto_tree *sub_tree;
	guint8 flag;

	flag = tvb_get_guint8(tvb, offset);
	sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
					ett_afp_lock_flags, NULL, "Flags: 0x%02x", flag);

	proto_tree_add_item(sub_tree, hf_afp_lock_op, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_afp_lock_from, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_lock_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_lock_len, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_byte_lock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_lock_range_start, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_byte_lock_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree *sub_tree;
	guint8 flag;

	flag = tvb_get_guint8(tvb, offset);
	sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
						ett_afp_lock_flags, NULL, "Flags: 0x%02x", flag);

	proto_tree_add_item(sub_tree, hf_afp_lock_op, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_afp_lock_from, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_lock_offset64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_item(tree, hf_afp_lock_len64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;
	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_byte_lock_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_lock_range_start64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_add_cmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint8 len;

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	if ((offset & 1))
		PAD(1);

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_comment, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len +1;

	return offset;
}


/* ************************** */
static gint
dissect_query_afp_get_cmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_comment, tvb, offset, 1, ENC_UTF_8|ENC_BIG_ENDIAN);
	offset += len +1;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_icon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4, ENC_UTF_8);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_file_type, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	PAD(1);

	proto_tree_add_item(tree, hf_afp_icon_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_icon_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_index, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_icon_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	proto_tree_add_item(tree, hf_afp_icon_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_file_type, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	PAD(1);
	proto_tree_add_item(tree, hf_afp_icon_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_add_icon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_file_type, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	PAD(1);
	proto_tree_add_item(tree, hf_afp_icon_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_icon_length, tvb, offset, 2, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	Did = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	return offset;
}

/* -------------------------- */
static gint
dissect_query_afp_add_appl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{

	PAD(1);
	offset = decode_dt_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_appl_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
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

	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_appl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_dt_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_file_creator, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_appl_index, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_appl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_appl_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_create_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_afp_create_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_map_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if ( type < 5) {
		proto_tree_add_item(tree, hf_afp_map_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	else {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
	}

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_map_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	int len;
	int size = 1;

	len = tvb_get_guint8(tvb, offset);
	/* for type 3 and 4 len is 16 bits but we don't keep the type from the request
	 * XXX assume name < 256, ie the first byte is zero.
	*/
	if (!len) {
		len = tvb_get_guint8(tvb, offset +1);
		if (!len) {
			/*
			 * Assume it's kUserUUIDToUTF8Name or
			 * kGroupUUIDToUTF8Name.
			 */
			proto_tree_add_item(tree, hf_afp_map_id_reply_type, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tree, hf_afp_map_id, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			size = 2;
			len = tvb_get_guint8(tvb, offset +1);

		}
		else {
			gint remain = tvb_reported_length_remaining(tvb,offset);
			if (remain == len +2) {
			size = 2;
			}
			else {
			/* give up */
			len = remain;
			size = 0;
			}
		}
	}
	if (size) {
		proto_tree_add_item(tree, hf_afp_map_name, tvb, offset, size, ENC_ASCII|ENC_BIG_ENDIAN);
	}
	else {
		proto_tree_add_item(tree, hf_afp_unknown, tvb, offset, len, ENC_NA);
	}
	offset += len +size;
	return offset;
}

/* ************************** */
static gint
dissect_query_afp_map_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	int len;
	int type;
	int size;

	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_map_name_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	switch (type) {
	case 5:
	case 6:
		/*
		 * Maps to UUID, UTF-8 string
		 *
		 * XXX - the spec doesn't say the string length is 2 bytes
		 * for this case.
		 */
		size = 2;
		len = tvb_get_ntohs(tvb, offset);
		break;
	default:
		/* Maps to UID/GID */
		size = 1;
		len = tvb_get_guint8(tvb, offset);
		break;
	}
	proto_tree_add_item(tree, hf_afp_map_name, tvb, offset, size, ENC_ASCII|ENC_BIG_ENDIAN);
	offset += len +size;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_map_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	gint remain;

	/* We don't keep the type from the request */
	/* If remain == 16, assume UUID */
	remain = tvb_reported_length(tvb);
	if (remain == 16) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
	}
	else {
		proto_tree_add_item(tree, hf_afp_map_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_disconnect_old_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint32 token_len;

	PAD(1);

	proto_tree_add_item(tree, hf_afp_session_token_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item_ret_uint(tree, hf_afp_session_token_len,
			tvb, offset, 4, ENC_BIG_ENDIAN, &token_len);
	offset += 4;

	if ((guint32)offset + token_len > G_MAXINT)
		return offset;

	proto_tree_add_item(tree, hf_afp_session_token,
			tvb, offset, (gint)token_len, ENC_NA);
	offset += (gint)token_len;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_session_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16	token;
	guint32	token_len;

	PAD(1);

	token = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_afp_session_token_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	if (token == kLoginWithoutID || token == kGetKerberosSessionKey) /* 0 || 8 */
		return offset;

	proto_tree_add_item_ret_uint(tree, hf_afp_session_token_len,
			tvb, offset, 4, ENC_BIG_ENDIAN, &token_len);
	offset += 4;

	if (token==kLoginWithTimeAndID || token==kReconnWithTimeAndID) {
		proto_tree_add_item(tree, hf_afp_session_token_timestamp,
				tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if ((guint32)offset + token_len > G_MAXINT)
		return offset;

	proto_tree_add_item(tree, hf_afp_session_token,
			tvb, offset, (gint)token_len, ENC_NA);
	offset += (gint)token_len;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_session_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	int size;
	guint32 token_len;

	/* FIXME spec and capture disagree : or it's 4 bytes with no token type, or it's 2 bytes */
	size = 4;
	/* [cm]: FIXME continued:  Since size is set to 4, this test is never true.
	if (size == 2) {
		proto_tree_add_item(tree, hf_afp_session_token_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	*/
	proto_tree_add_item_ret_uint(tree, hf_afp_session_token_len,
			tvb, offset, size, ENC_BIG_ENDIAN, &token_len);
	offset += size;

	if ((guint32)offset + token_len > G_MAXINT)
		return offset;

	proto_tree_add_item(tree, hf_afp_session_token,
			tvb, offset, (gint)token_len, ENC_NA);
	offset += (gint)token_len;

	return offset;
}

/* ************************** */
static int * const afp_message_bitmaps[] = {
	&hf_afp_message_bitmap_REQ,
	&hf_afp_message_bitmap_UTF,
	NULL
};

static gint
dissect_query_afp_get_server_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	PAD(1);
	proto_tree_add_item(tree, hf_afp_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_message_bitmap,
					ett_afp_message_bitmap, afp_message_bitmaps, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* ************************** */
static gint
dissect_reply_afp_get_server_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16	 bitmap;
	guint16 len = 0;

	/* FIXME: APF 3.1 specs also specify a long reply format, yet unused */

	proto_tree_add_item(tree, hf_afp_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_message_bitmap,
					ett_afp_message_bitmap, afp_message_bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohs(tvb, offset);
	offset += 2;

	/*
	 * XXX - the spec says that the 0x01 bit indicates whether
	 * the ServerMessage field contains a server message or a login
	 * message.
	 */
	if (bitmap & 0x02) {
		/* Message is UTF-8, and message length is 2 bytes */
		len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_message_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		if (len) {
			proto_tree_add_item(tree, hf_afp_message, tvb, offset, len , ENC_UTF_8);
			offset += len;
		}
	} else {
		/*
		 * Message is not UTF-8, and message length is 1 byte.
		 *
		 * Is the message in some Mac encoding? Always Mac Roman,
		 * or possibly some other encoding for other locales?
		 */
		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_afp_message_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		if (len) {
			proto_tree_add_item(tree, hf_afp_message, tvb, offset, len , ENC_ASCII);
			offset += len;
		}
	}

	return offset;
}

/* ************************** */
static int * const afp_user_bitmaps[] = {
	&hf_afp_user_bitmap_UID,
	&hf_afp_user_bitmap_GID,
	&hf_afp_user_bitmap_UUID,
	NULL
};

static gint
dissect_query_afp_get_user_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{

	proto_tree_add_item(tree, hf_afp_user_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_afp_user_ID, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_user_bitmap,
					ett_afp_user_bitmap, afp_user_bitmaps, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_user_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint16	 bitmap;

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_user_bitmap,
					ett_afp_user_bitmap, afp_user_bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohs(tvb, offset);

	offset += 2;
	if ((bitmap & 1)) {
		proto_tree_add_item(tree, hf_afp_user_ID, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if ((bitmap & 2)) {
		proto_tree_add_item(tree, hf_afp_group_ID, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if ((bitmap & 4)) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, ENC_BIG_ENDIAN);
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

		name = tvb_format_text(pinfo->pool, tvb,offset+2, len);
		sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, len + 2,
										ett_afp_extattr_names, NULL, label, name);

		proto_tree_add_item(sub_tree, hf_afp_extattr_namelen, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_afp_extattr_name, tvb, offset +2, len, ENC_UTF_8);
	}
	offset += 2 +len;

	return offset;
}

/* ************************** */
static gint
decode_attr_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	static int * const bitmaps[] = {
		&hf_afp_extattr_bitmap_NoFollow,
		&hf_afp_extattr_bitmap_Create,
		&hf_afp_extattr_bitmap_Replace,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_extattr_bitmap,
					ett_afp_extattr_bitmap, bitmaps, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;
	/* 8byte reqcount */
	proto_tree_add_item(tree, hf_afp_reqcount64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* maxreply */
	proto_tree_add_item(tree, hf_afp_extattr_reply_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	offset = decode_attr_name(tree, pinfo, tvb, offset, "Attribute: %s");

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_ext_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	guint32	 extattr_len;

	offset = decode_attr_bitmap(tree, tvb, offset);

	proto_tree_add_item_ret_uint(tree, hf_afp_extattr_len,
			tvb, offset, 4, ENC_BIG_ENDIAN, &extattr_len);
	offset += 4;

	if ((guint32)offset + extattr_len > G_MAXINT)
		return offset;

	proto_tree_add_item(tree, hf_afp_extattr_data,
			tvb, offset, (gint)extattr_len, ENC_NA);
	offset += (gint)extattr_len;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_set_ext_attr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint32	 len;

	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	offset = decode_attr_bitmap(tree, tvb, offset);

	/* 8byte offset */
	proto_tree_add_item(tree, hf_afp_offset64, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	offset = decode_name(tree, pinfo, tvb, offset);

	offset = decode_attr_name(tree, pinfo, tvb, offset, "Attribute: %s");

	proto_tree_add_item_ret_uint(tree, hf_afp_extattr_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_extattr_data, tvb, offset, len, ENC_NA);
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

	proto_tree_add_item(tree, hf_afp_extattr_req_count, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_extattr_start_index, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_extattr_reply_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_list_ext_attrs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	proto_tree *sub_tree;
	guint len_field = 0;
	gint length;
	gint remain;

	offset = decode_attr_bitmap(tree, tvb, offset);

	proto_tree_add_item_ret_uint(tree, hf_afp_extattr_reply_size,
			tvb, offset, 4, ENC_BIG_ENDIAN, &len_field);
	offset += 4;
	if (len_field > G_MAXINT) {
		/* XXX - add expert info */
		return offset;
	}

	/* If reply_size was 0 on request, server only reports the size of
	   the entries without actually adding any entries */
	remain = tvb_reported_length_remaining(tvb, offset);
	if (remain < (gint)len_field)
		return offset;

	sub_tree = proto_tree_add_subtree(tree, tvb, offset, remain,
			ett_afp_extattr_names, NULL, "Attributes");
	while (remain > 0) {
		length = (gint)tvb_strsize(tvb, offset);

		proto_tree_add_item(sub_tree, hf_afp_extattr_name, tvb, offset, length, ENC_UTF_8);
		offset += length;
		remain -= length;
	}

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
	static int * const bitmaps[] = {
		&hf_afp_acl_access_bitmap_read_data,
		&hf_afp_acl_access_bitmap_write_data,
		&hf_afp_acl_access_bitmap_execute,
		&hf_afp_acl_access_bitmap_delete,
		&hf_afp_acl_access_bitmap_append_data,
		&hf_afp_acl_access_bitmap_delete_child,
		&hf_afp_acl_access_bitmap_read_attrs,
		&hf_afp_acl_access_bitmap_write_attrs,
		&hf_afp_acl_access_bitmap_read_extattrs,
		&hf_afp_acl_access_bitmap_write_extattrs,
		&hf_afp_acl_access_bitmap_read_security,
		&hf_afp_acl_access_bitmap_write_security,
		&hf_afp_acl_access_bitmap_change_owner,
		&hf_afp_acl_access_bitmap_synchronize,
		&hf_afp_acl_access_bitmap_generic_all,
		&hf_afp_acl_access_bitmap_generic_execute,
		&hf_afp_acl_access_bitmap_generic_write,
		&hf_afp_acl_access_bitmap_generic_read,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_acl_access_bitmap,
					ett_afp_acl_access_bitmap, bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohl(tvb, offset);

	return bitmap;
}

/* ************************** */
static gint
dissect_query_afp_access(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_access_bitmap, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, ENC_BIG_ENDIAN);
	offset += 16;

	decode_acl_access_bitmap(tvb, tree, offset);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_with_did(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	PAD(1);
	offset = decode_vol_did(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/* ************************** */

#define SQ_TYPE_NULL    0x0000
#define SQ_TYPE_COMPLEX 0x0200
#define SQ_TYPE_INT64   0x8400
#define SQ_TYPE_BOOL    0x0100
#define SQ_TYPE_FLOAT   0x8500
#define SQ_TYPE_DATA    0x0700
#define SQ_TYPE_CNIDS   0x8700
#define SQ_TYPE_UUID    0x0e00
#define SQ_TYPE_DATE    0x8600

#define SQ_CPX_TYPE_ARRAY		0x0a00
#define SQ_CPX_TYPE_STRING		0x0c00
#define SQ_CPX_TYPE_UTF16_STRING	0x1c00
#define SQ_CPX_TYPE_DICT		0x0d00
#define SQ_CPX_TYPE_CNIDS		0x1a00
#define SQ_CPX_TYPE_FILEMETA 		0x1b00

#define SUBQ_SAFETY_LIM 20

static gint
spotlight_int64(tvbuff_t *tvb, proto_tree *tree, gint offset, guint encoding)
{
	guint count, i;
	guint64 query_data64;

	query_data64 = tvb_get_guint64(tvb, offset, encoding);
	count = (guint)(query_data64 >> 32);
	offset += 8;

	for (i = 0; i < count; i++) {
		proto_tree_add_item(tree, hf_afp_int64, tvb, offset, 8, encoding);
		offset += 8;
	}

	return count;
}

static gint
spotlight_date(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, guint encoding)
{
	guint count, i;
	guint64 query_data64;
	nstime_t t;

	query_data64 = tvb_get_guint64(tvb, offset, encoding);
	count = (guint)(query_data64 >> 32);
	offset += 8;

	if (count > SUBQ_SAFETY_LIM) {
		expert_add_info_format(pinfo, tree, &ei_afp_subquery_count_over_safety_limit,
							   "Subquery count (%d) > safety limit (%d)", count, SUBQ_SAFETY_LIM);
		return -1;
	}

	for (i = 0; i < count; i++) {
		query_data64 = tvb_get_guint64(tvb, offset, encoding) >> 24;
		t.secs = (time_t)(query_data64 - SPOTLIGHT_TIME_DELTA);
		t.nsecs = 0;
		proto_tree_add_time(tree, hf_afp_spotlight_date, tvb, offset, 8, &t);
		offset += 8;
	}

	return count;
}

static gint
spotlight_uuid(tvbuff_t *tvb, proto_tree *tree, gint offset, guint encoding)
{
	guint count, i;
	guint64 query_data64;

	query_data64 = tvb_get_guint64(tvb, offset, encoding);
	count = (guint)(query_data64 >> 32);
	offset += 8;

	for (i = 0; i < count; i++) {
		proto_tree_add_item(tree, hf_afp_spotlight_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
	}

	return count;
}

static gint
spotlight_float(tvbuff_t *tvb, proto_tree *tree, gint offset, guint encoding)
{
	guint count, i;
	guint64 query_data64;

	query_data64 = tvb_get_guint64(tvb, offset, encoding);
	count = (guint)(query_data64 >> 32);
	offset += 8;

	for (i = 0; i < count; i++) {
		proto_tree_add_item(tree, hf_afp_float, tvb, offset, 8, encoding);
		offset += 8;
	}

	return count;
}

static gint
spotlight_CNID_array(tvbuff_t *tvb, proto_tree *tree, gint offset, guint encoding)
{
	guint count;
	guint64 query_data64;
	guint16 unknown1;
	guint32 unknown2;

	query_data64 = tvb_get_guint64(tvb, offset, encoding);
	count = (guint)(query_data64 & 0xffff);
	unknown1 = (query_data64 & 0xffff0000) >> 16;
	unknown2 = (guint32)(query_data64 >> 32);

	proto_tree_add_uint(tree, hf_afp_unknown16, tvb, offset + 2, 2, unknown1);
	proto_tree_add_uint(tree, hf_afp_unknown32, tvb, offset + 4, 4, unknown2);
	offset += 8;


	while (count --) {
		proto_tree_add_item(tree, hf_afp_cnid, tvb, offset, 8, encoding);
		offset += 8;
	}

	return 0;
}

static const val64_string qtype_string_values[] = {
	{SQ_TYPE_NULL, "null" },
	{SQ_TYPE_COMPLEX, "complex"},
	{SQ_TYPE_INT64, "int64" },
	{SQ_TYPE_BOOL, "bool"},
	{SQ_TYPE_FLOAT, "float" },
	{SQ_TYPE_DATA, "data"},
	{SQ_TYPE_CNIDS, "CNIDs" },
	{0, NULL}
};

static const val64_string cpx_qtype_string_values[] = {
	{SQ_CPX_TYPE_ARRAY, "array" },
	{SQ_CPX_TYPE_STRING, "string"},
	{SQ_CPX_TYPE_UTF16_STRING, "utf-16 string" },
	{SQ_CPX_TYPE_DICT, "dictionary"},
	{SQ_CPX_TYPE_CNIDS, "CNIDs" },
	{SQ_CPX_TYPE_FILEMETA, "FileMeta"},
	{0, NULL}
};

static gint
spotlight_dissect_query_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
			     guint64 cpx_query_type, gint count, gint toc_offset, guint encoding)
{
	gint i, j;
	gint subquery_count;
	gint toc_index;
	guint64 query_data64;
	gint query_length;
	guint64 query_type;
	guint64 complex_query_type;
	guint byte_order;
	gboolean mark_exists;
	tvbuff_t *spotlight_tvb;
	gchar *str_tmp;

	proto_item *item_query;
	proto_tree *sub_tree;

	/*
	 * This loops through a possibly nested query data structure.
	 * The outermost one is always without count and called from
	 * dissect_spotlight() with count = INT_MAX thus the while (...)
	 * loop terminates if (offset >= toc_offset).
	 * If nested structures are found, these will have an encoded element
	 * count which is used in a recursive call to
	 * spotlight_dissect_query_loop as count parameter, thus in this case
	 * the while (...) loop will terminate when count reaches 0.
	 */
	while ((offset < (toc_offset - 8)) && (count > 0)) {
		query_data64 = tvb_get_guint64(tvb, offset, encoding);
		query_length = ((gint)query_data64 & 0xffff) * 8;
		if (query_length == 0) {
			/* XXX - report this as an error */
			break;
		}
		query_type = (query_data64 & 0xffff0000) >> 16;

		switch (query_type) {
		case SQ_TYPE_COMPLEX:
			toc_index = (gint)((query_data64 >> 32) - 1);
			query_data64 = tvb_get_guint64(tvb, toc_offset + toc_index * 8, encoding);
			complex_query_type = (query_data64 & 0xffff0000) >> 16;

			switch (complex_query_type) {
			case SQ_CPX_TYPE_ARRAY:
			case SQ_CPX_TYPE_DICT:
				subquery_count = (gint)(query_data64 >> 32);
				sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, query_length,
								 ett_afp_spotlight_query_line, NULL,
								 "%s, toc index: %u, children: %u",
								 val64_to_str_const(complex_query_type, cpx_qtype_string_values, "Unknown"),
								 toc_index + 1,
								 subquery_count);
				break;
			case SQ_CPX_TYPE_STRING:
				subquery_count = 1;
				query_data64 = tvb_get_guint64(tvb, offset + 8, encoding);
				query_length = ((gint)query_data64 & 0xffff) * 8;
				sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, query_length + 8,
								 ett_afp_spotlight_query_line, NULL,
								 "%s, toc index: %u, string: '%s'",
								 val64_to_str_const(complex_query_type, cpx_qtype_string_values, "Unknown"),
								 toc_index + 1,
								 tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 16, query_length - 8, ENC_UTF_8|ENC_NA));
				break;
			case SQ_CPX_TYPE_UTF16_STRING:
				/*
				* This is an UTF-16 string.
				* Dissections show the typical byte order mark 0xFFFE or 0xFEFF, respectively.
				* However the existence of such a mark can not be assumed.
				* If the mark is missing, big endian encoding is assumed.
				* XXX - assume the encoding given by "encoding"?
				*/

				subquery_count = 1;
				query_data64 = tvb_get_guint64(tvb, offset + 8, encoding);
				query_length = ((gint)query_data64 & 0xffff) * 8;

				byte_order = spotlight_get_utf16_string_byte_order(tvb, offset + 16, query_length - 8, encoding);
				if (byte_order == 0xFFFFFFFF) {
					byte_order = ENC_BIG_ENDIAN;
					mark_exists = FALSE;
				} else
					mark_exists = TRUE;

				sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, query_length + 8,
								 ett_afp_spotlight_query_line, NULL,
								 "%s, toc index: %u, utf-16 string: '%s'",
								 val64_to_str_const(complex_query_type, cpx_qtype_string_values, "Unknown"),
								 toc_index + 1,
								 tvb_get_string_enc(wmem_packet_scope(), tvb, offset + (mark_exists ? 18 : 16),
								 query_length - (mark_exists? 10 : 8), ENC_UTF_16 | byte_order));
				break;
			default:
				subquery_count = 1;
				sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, query_length,
								 ett_afp_spotlight_query_line, NULL,
								 "type: %s (%s), toc index: %u, children: %u",
								 val64_to_str_const(query_type, qtype_string_values, "Unknown"),
								 val64_to_str_const(complex_query_type, cpx_qtype_string_values, "Unknown"),
								 toc_index + 1,
								 subquery_count);
				break;
			}

			offset += 8;
			offset = spotlight_dissect_query_loop(tvb, pinfo, sub_tree, offset, complex_query_type, subquery_count, toc_offset, encoding);
			count--;
			break;
		case SQ_TYPE_NULL:
			subquery_count = (gint)(query_data64 >> 32);
			if (subquery_count > count) {
				item_query = proto_tree_add_item(tree, hf_afp_null, tvb, offset, query_length, ENC_NA);
				expert_add_info_format(pinfo, item_query, &ei_afp_subquery_count_over_query_count,
					"Subquery count (%d) > query count (%d)", subquery_count, count);
				count = 0;
			} else if (subquery_count > 20) {
				item_query = proto_tree_add_item(tree, hf_afp_null, tvb, offset, query_length, ENC_NA);
				expert_add_info_format(pinfo, item_query, &ei_afp_abnormal_num_subqueries,
					"Abnormal number of subqueries (%d)", subquery_count);
				count -= subquery_count;
			} else {
				for (i = 0; i < subquery_count; i++, count--)
					proto_tree_add_item(tree, hf_afp_null, tvb, offset, query_length, encoding);
			}
			offset += query_length;
			break;
		case SQ_TYPE_BOOL:
			proto_tree_add_uint64_format_value(tree, hf_afp_bool, tvb, offset, query_length, (query_data64 >> 32), "%s", (query_data64 >> 32) ? "true" : "false");
			count--;
			offset += query_length;
			break;
		case SQ_TYPE_INT64:
			sub_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_afp_spotlight_query_line, NULL, "int64");
			j = spotlight_int64(tvb, sub_tree, offset, encoding);
			count -= j;
			offset += query_length;
			break;
		case SQ_TYPE_UUID:
			sub_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_afp_spotlight_query_line, NULL, "UUID");
			j = spotlight_uuid(tvb, sub_tree, offset, encoding);
			count -= j;
			offset += query_length;
			break;
		case SQ_TYPE_FLOAT:
			sub_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_afp_spotlight_query_line, NULL, "float");
			j = spotlight_float(tvb, sub_tree, offset, encoding);
			count -= j;
			offset += query_length;
			break;
		case SQ_TYPE_DATA:
			switch (cpx_query_type) {
			case SQ_CPX_TYPE_STRING:
				str_tmp = (gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 8, query_length - 8, ENC_UTF_8|ENC_NA);
				proto_tree_add_string(tree, hf_afp_string, tvb, offset, query_length, str_tmp);
				break;
			case SQ_CPX_TYPE_UTF16_STRING: {
				/* description see above */
				byte_order = spotlight_get_utf16_string_byte_order(tvb, offset + 16, query_length - 8, encoding);
				if (byte_order == 0xFFFFFFFF) {
					byte_order = ENC_BIG_ENDIAN;
					mark_exists = FALSE;
				} else
					mark_exists = TRUE;

				str_tmp = (gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + (mark_exists ? 10 : 8),
								query_length - (mark_exists? 10 : 8), ENC_UTF_16 | byte_order);
				proto_tree_add_string(tree, hf_afp_utf_16_string, tvb, offset, query_length, str_tmp);
				break;
			}
			case SQ_CPX_TYPE_FILEMETA:
				sub_tree = proto_tree_add_subtree(tree, tvb, offset, query_length,
											ett_afp_spotlight_query_line, &item_query, "filemeta");
				if (query_length <= 8) {
					proto_item_append_text(item_query, " (empty)");
				} else {
					spotlight_tvb = tvb_new_subset_length(tvb, offset+8, query_length);
					call_dissector(spotlight_handle, spotlight_tvb, pinfo, sub_tree);
				}
				break;
			}
			count--;
			offset += query_length;
			break;
		case SQ_TYPE_CNIDS:
			sub_tree = proto_tree_add_subtree(tree, tvb, offset, query_length,
							ett_afp_spotlight_query_line, &item_query, "CNID Array");
			if (query_length <= 8) {
				proto_item_append_text(item_query, " (empty)");
			} else {
				spotlight_CNID_array(tvb, sub_tree, offset + 8, encoding);
			}
			count--;
			offset += query_length;
			break;
		case SQ_TYPE_DATE:
			if ((j = spotlight_date(tvb, pinfo, tree, offset, encoding)) == -1)
				return offset;
			count -= j;
			offset += query_length;
			break;
		default:
			proto_tree_add_string(tree, hf_afp_query_type, tvb, offset, query_length, val64_to_str_const(query_type, qtype_string_values, "Unknown"));
			count--;
			offset += query_length;
			break;
		}
	}

	return offset;
}

static const val64_string endian_vals[] = {
	{0,	"Little Endian" },
	{1,	"Big Endian" },
	{0,	NULL } };

static gint
dissect_spotlight(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint encoding;
	gint i;
	gint offset = 0;
	guint64 toc_offset;
	guint64 querylen;
	gint toc_entries;
	guint64 toc_entry;

	proto_tree *sub_tree_queries;
	proto_tree *sub_tree_toc;
	proto_item *ti;

	if (strncmp((gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 8, ENC_UTF_8|ENC_NA), "md031234", 8) == 0)
		encoding = ENC_BIG_ENDIAN;
	else
		encoding = ENC_LITTLE_ENDIAN;
	proto_tree_add_uint64(tree, hf_afp_endianness, tvb, offset, 8, (encoding == ENC_BIG_ENDIAN));
	offset += 8;

	toc_offset = (tvb_get_guint64(tvb, offset, encoding) >> 32) * 8;
	if (toc_offset < 8) {
		ti = proto_tree_add_uint64(tree, hf_afp_toc_offset, tvb, offset, 8, toc_offset);
		expert_add_info_format(pinfo, ti, &ei_afp_toc_offset, "%" PRIu64 " < 8 (bogus)", toc_offset);
		return tvb_captured_length(tvb);
	}
	toc_offset -= 8;
	if (offset + toc_offset + 8 > G_MAXINT) {
		ti = proto_tree_add_uint64(tree, hf_afp_toc_offset, tvb, offset, 8, toc_offset);
		expert_add_info_format(pinfo, ti, &ei_afp_toc_offset, "%" PRIu64 " > %u (bogus)", toc_offset, G_MAXINT - 8 - offset);
		return tvb_captured_length(tvb);
	}
	querylen = (tvb_get_guint64(tvb, offset, encoding) & 0xffffffff) * 8;
	if (querylen < 8) {
		ti = proto_tree_add_uint64(tree, hf_afp_toc_offset, tvb, offset, 8, toc_offset);
		expert_add_info_format(pinfo, ti, &ei_afp_toc_offset, "%" PRIu64 " Bytes, Query length: %" PRIu64 " < 8 (bogus)",
				    toc_offset, querylen);
		return tvb_captured_length(tvb);
	}
	querylen -= 8;
	if (querylen > G_MAXINT) {
		ti = proto_tree_add_uint64(tree, hf_afp_toc_offset, tvb, offset, 8, toc_offset);
		expert_add_info_format(pinfo, ti, &ei_afp_toc_offset, "%" PRIu64 " Bytes, Query length: %" PRIu64 " > %u (bogus)",
				    toc_offset, querylen, G_MAXINT);
		return tvb_captured_length(tvb);
	}
	proto_tree_add_uint64(tree, hf_afp_toc_offset, tvb, offset, 8, toc_offset);
	proto_tree_add_uint64(tree, hf_afp_query_len, tvb, offset, 8, querylen);
	offset += 8;

	toc_entries = (gint)(tvb_get_guint64(tvb, offset + (gint)toc_offset, encoding) & 0xffff);

	sub_tree_queries = proto_tree_add_subtree(tree, tvb, offset, (gint)toc_offset,
						ett_afp_spotlight_queries, NULL,
						"Spotlight RPC data");

	/* Queries */
	offset = spotlight_dissect_query_loop(tvb, pinfo, sub_tree_queries, offset, SQ_CPX_TYPE_ARRAY, INT_MAX, offset + (gint)toc_offset + 8, encoding);

	/* ToC */
	sub_tree_toc = proto_tree_add_subtree_format(tree, tvb, offset,
				       (gint)querylen - (gint)toc_offset,
				       ett_afp_spotlight_toc, &ti,
				       "Complex types ToC (%u entries)",
				       toc_entries);
	if (toc_entries < 1) {
		proto_item_append_text(ti, " (%u < 1 - bogus)", toc_entries);
		return tvb_captured_length(tvb);
	}
	proto_item_append_text(ti, " (%u entries)", toc_entries);

	toc_entries -= 1;
	proto_tree_add_uint(sub_tree_toc, hf_afp_num_toc_entries, tvb, offset, 2, toc_entries);
	proto_tree_add_item(sub_tree_toc, hf_afp_unknown16, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree_toc, hf_afp_unknown32, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

	offset += 8;
	for (i = 0; i < toc_entries; i++, offset += 8) {
		toc_entry = tvb_get_guint64(tvb, offset, encoding);
		switch((toc_entry & 0xffff0000) >> 16)
		{
		case SQ_CPX_TYPE_ARRAY:
		case SQ_CPX_TYPE_DICT:
			proto_tree_add_uint64_format(sub_tree_toc, hf_afp_toc_entry, tvb, offset, 8, toc_entry,
						"%u: count: %" PRIu64 ", type: %s, offset: %" PRIu64,
						i+1, toc_entry >> 32, val64_to_str_const((toc_entry & 0xffff0000) >> 16, cpx_qtype_string_values, "Unknown"),
						(toc_entry & 0xffff) * 8);
			break;
		case SQ_CPX_TYPE_STRING:
		case SQ_CPX_TYPE_UTF16_STRING:
			proto_tree_add_uint64_format(sub_tree_toc, hf_afp_toc_entry, tvb, offset, 8, toc_entry,
						"%u: pad byte count: %" PRIx64 ", type: %s, offset: %" PRIu64,
						i+1, 8 - (toc_entry >> 32), val64_to_str_const((toc_entry & 0xffff0000) >> 16, cpx_qtype_string_values, "Unknown"),
						(toc_entry & 0xffff) * 8);
			break;
		default:
			proto_tree_add_uint64_format(sub_tree_toc, hf_afp_toc_entry, tvb, offset, 8, toc_entry,
						"%u: unknown: 0x%08" PRIx64 ", type: %s, offset: %" PRIu64,
						i+1, toc_entry >> 32, val64_to_str_const((toc_entry & 0xffff0000) >> 16, cpx_qtype_string_values, "Unknown"),
						(toc_entry & 0xffff) * 8);
		}
	}

	return offset;
}

static gint
dissect_query_afp_spotlight(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, afp_request_val *request_val)
{
	gint len;
	tvbuff_t *spotlight_tvb;

	PAD(1);
	offset = decode_vol(tree, tvb, offset);

	proto_tree_add_item(tree, hf_afp_spotlight_request_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_spotlight_request_command, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_spotlight_request_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	switch (request_val->spotlight_req_command) {

	case SPOTLIGHT_CMD_GET_VOLPATH:
		tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_UTF_8|ENC_NA);
		proto_tree_add_item(tree, hf_afp_spotlight_volpath_client, tvb, offset, len, ENC_UTF_8);
		offset += len;
		break;

	case SPOTLIGHT_CMD_GET_VOLID:
		/* empty */
		break;

	case SPOTLIGHT_CMD_GET_THREE:
		proto_tree_add_item(tree, hf_afp_spotlight_volflags, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_afp_spotlight_reqlen, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		spotlight_tvb = tvb_new_subset_remaining(tvb, offset);
		offset += call_dissector(spotlight_handle, spotlight_tvb, pinfo, tree);
		break;
	}
	return offset;
}

/* ************************** */
static guint16
decode_acl_list_bitmap(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	guint16 bitmap;
	static int * const bitmaps[] = {
		&hf_afp_acl_list_bitmap_UUID,
		&hf_afp_acl_list_bitmap_GRPUUID,
		&hf_afp_acl_list_bitmap_ACL,
		&hf_afp_acl_list_bitmap_REMOVEACL,
		&hf_afp_acl_list_bitmap_Inherit,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_acl_list_bitmap,
					ett_afp_acl_list_bitmap, bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohs(tvb, offset);
	return bitmap;
}


/* ************************** */
static guint32
decode_ace_flags_bitmap(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	guint32 bitmap;

	static int * const bitmaps[] = {
		&hf_afp_ace_flags_allow,
		&hf_afp_ace_flags_deny,
		&hf_afp_ace_flags_inherited,
		&hf_afp_ace_flags_fileinherit,
		&hf_afp_ace_flags_dirinherit,
		&hf_afp_ace_flags_limitinherit,
		&hf_afp_ace_flags_onlyinherit,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_afp_ace_flags,
					ett_afp_ace_flags, bitmaps, ENC_BIG_ENDIAN);
	bitmap = tvb_get_ntohl(tvb, offset);

	return bitmap;
}

static gint
decode_kauth_ace(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	/* FIXME: preliminary decoding... */
	if (tree) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, ENC_BIG_ENDIAN);
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

#define AFP_MAX_ACL_ENTRIES 500 /* Arbitrary. */
static gint
decode_kauth_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint32     num_entries, i;
	proto_tree *sub_tree, *ace_tree;
	proto_item *item;

	item = proto_tree_add_item_ret_uint(tree, hf_afp_acl_entrycount,
			tvb, offset, 4, ENC_BIG_ENDIAN, &num_entries);
	sub_tree = proto_item_add_subtree(item, ett_afp_ace_entries);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_acl_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (num_entries > AFP_MAX_ACL_ENTRIES) {
		expert_add_info_format(pinfo, item, &ei_afp_too_many_acl_entries,
				"Too many ACL entries (%u). Stopping dissection.",
				num_entries);
		return offset;
	}

	for (i = 0; i < num_entries; i++) {
		ace_tree = proto_tree_add_subtree_format(sub_tree, tvb, offset, 24, ett_afp_ace_entry, NULL, "ACE: %u", i);
		offset = decode_kauth_ace(tvb, ace_tree, offset);
	}

	return offset;
}

static gint
decode_uuid_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, guint16 bitmap)
{
	if ((offset & 1))
		PAD(1);

	if ((bitmap & kFileSec_UUID)) {
		proto_tree_add_item(tree, hf_afp_UUID, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
	}

	if ((bitmap & kFileSec_GRPUUID)) {
		proto_tree_add_item(tree, hf_afp_GRPUUID, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
	}

	if ((bitmap & kFileSec_ACL)) {
		offset = decode_kauth_acl(tvb, pinfo, tree, offset);
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

	offset = decode_uuid_acl(tvb, pinfo, tree, offset, bitmap);

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

	proto_tree_add_item(tree, hf_afp_max_reply_size32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	offset = decode_name(tree, pinfo, tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	bitmap = decode_acl_list_bitmap(tvb, tree, offset);
	offset += 2;

	offset = decode_uuid_acl(tvb, pinfo, tree, offset, bitmap);

	return offset;
}

/* ************************** */
static gint
dissect_reply_afp_spotlight(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, afp_request_val *request_val)
{
	gint len;
	tvbuff_t *spotlight_tvb;

	switch (request_val->spotlight_req_command) {

	case SPOTLIGHT_CMD_GET_VOLPATH:
		proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_afp_spotlight_reply_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_UTF_8|ENC_NA);
		proto_tree_add_item(tree, hf_afp_spotlight_volpath_server, tvb, offset, len, ENC_UTF_8);
		offset += len;
		break;

	case SPOTLIGHT_CMD_GET_VOLID:
		proto_tree_add_item(tree, hf_afp_spotlight_volflags, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		break;

	case SPOTLIGHT_CMD_GET_THREE:
		proto_tree_add_item(tree, hf_afp_spotlight_returncode, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		spotlight_tvb = tvb_new_subset_remaining(tvb, offset);
		offset += call_dissector(spotlight_handle, spotlight_tvb, pinfo, tree);
		break;
	}
	return offset;
}

/* -----------------------------
	from netatalk/etc/afpd/status.c
*/

/* server flags */
#define AFPSRVRINFO_COPY         (1<<0)  /* supports copyfile */
#define AFPSRVRINFO_PASSWD       (1<<1)  /* supports change password */
#define AFPSRVRINFO_NOSAVEPASSWD (1<<2)  /* don't allow save password */
#define AFPSRVRINFO_SRVMSGS      (1<<3)  /* supports server messages */
#define AFPSRVRINFO_SRVSIGNATURE (1<<4)  /* supports server signature */
#define AFPSRVRINFO_TCPIP        (1<<5)  /* supports tcpip */
#define AFPSRVRINFO_SRVNOTIFY    (1<<6)  /* supports server notifications */
#define AFPSRVRINFO_SRVRECONNECT (1<<7)  /* supports reconnect */
#define AFPSRVRINFO_SRVDIRECTORY (1<<8)  /* supports directory services */
#define AFPSRVRINFO_SRVUTF8      (1<<9)  /* supports UTF8 names AFP 3.1 */
#define AFPSRVRINFO_UUID         (1<<10) /* supports UUIDs AFP 3.2 */
#define AFPSRVRINFO_EXT_SLEEP    (1<<11) /* supports extended sleep, AFP 3.3 */
#define AFPSRVRINFO_FASTBOZO     (1<<15) /* fast copying */

#define AFPSTATUS_MACHOFF     0
#define AFPSTATUS_VERSOFF     2
#define AFPSTATUS_UAMSOFF     4
#define AFPSTATUS_ICONOFF     6
#define AFPSTATUS_FLAGOFF     8
#define AFPSTATUS_PRELEN     10
#define AFPSTATUS_POSTLEN     4
#define AFPSTATUS_LEN        (AFPSTATUS_PRELEN + AFPSTATUS_POSTLEN)

#define INET6_ADDRLEN  16

static gint
dissect_afp_server_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	int		offset = 0;
	proto_tree      *sub_tree;

	guint16 flag;
	guint8  server_name_len;
	guint16 sign_ofs = 0;
	guint16 adr_ofs = 0;
	guint16 dir_ofs = 0;
	guint16 utf_ofs = 0;
	gint    variable_data_offset;
	guint8	nbe;
	guint   len;
	guint   i;

	static int * const flags[] = {
		&hf_afp_server_flag_copyfile,
		&hf_afp_server_flag_passwd,
		&hf_afp_server_flag_no_save_passwd,
		&hf_afp_server_flag_srv_msg,
		&hf_afp_server_flag_srv_sig,
		&hf_afp_server_flag_tcpip,
		&hf_afp_server_flag_notify,
		&hf_afp_server_flag_reconnect,
		&hf_afp_server_flag_directory,
		&hf_afp_server_flag_utf8_name,
		&hf_afp_server_flag_uuid,
		&hf_afp_server_flag_ext_sleep,
		&hf_afp_server_flag_fast_copy,
		NULL
	};

	tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_afp_status, NULL, "Get Status");

	proto_tree_add_item(tree, hf_afp_machine_offset, tvb, AFPSTATUS_MACHOFF, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_afp_version_offset, tvb, AFPSTATUS_VERSOFF, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_afp_uams_offset, tvb, AFPSTATUS_UAMSOFF, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_afp_icon_offset, tvb, AFPSTATUS_ICONOFF, 2, ENC_BIG_ENDIAN);

	flag = tvb_get_ntohs(tvb, AFPSTATUS_FLAGOFF);

	proto_tree_add_bitmask(tree, tvb, AFPSTATUS_FLAGOFF, hf_afp_server_flag,
					ett_afp_status_server_flag, flags, ENC_BIG_ENDIAN);

	offset = AFPSTATUS_PRELEN;
	server_name_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_server_name, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
	offset += 1 + server_name_len;	/* 1 for the length byte */

	if ((flag & AFPSRVRINFO_SRVSIGNATURE)) {
		if ((offset & 1))
			offset++;
		sign_ofs = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_signature_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if ((flag & AFPSRVRINFO_TCPIP)) {
		if ((offset & 1))
			offset++;
		adr_ofs = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_network_address_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if ((flag & AFPSRVRINFO_SRVDIRECTORY)) {
		if ((offset & 1))
			offset++;
		dir_ofs = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_directory_services_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if ((flag & AFPSRVRINFO_SRVUTF8)) {
		if ((offset & 1))
			offset++;
		utf_ofs = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_utf8_server_name_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	/*
	 * XXX - should also check for overlap between "variable data" fields;
	 * that requires keeping all the offsets and lengths and checking
	 * against all the ones we've dissected so far.
	 *
	 * XXX - should report an error if there's overlap, rather than
	 * just ignoring the field.
	 */
	variable_data_offset = offset;
	offset = tvb_get_ntohs(tvb, AFPSTATUS_MACHOFF);
	if (offset) {
		if (offset >= variable_data_offset) {
			proto_tree_add_item(tree, hf_afp_server_type, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
		}
	}

	offset = tvb_get_ntohs(tvb, AFPSTATUS_VERSOFF);
	if (offset) {
		if (offset >= variable_data_offset) {
			nbe = tvb_get_guint8(tvb, offset);
			sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
									ett_afp_vers, NULL, "Version list: %u", nbe);
			offset++;
			for (i = 0; i < nbe; i++) {
				len = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(sub_tree, hf_afp_server_vers, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
				offset += len + 1;
			}
		}
	}

	offset = tvb_get_ntohs(tvb, AFPSTATUS_UAMSOFF);
	if (offset) {
		if (offset >= variable_data_offset) {
			nbe = tvb_get_guint8(tvb, offset);
			sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
										ett_afp_uams, NULL, "UAMS list: %u", nbe);
			offset++;
			for (i = 0; i < nbe; i++) {
				len = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(sub_tree, hf_afp_server_uams, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
				offset += len + 1;
			}
		}
	}

	offset = tvb_get_ntohs(tvb, AFPSTATUS_ICONOFF);
	if (offset) {
		if (offset >= variable_data_offset)
			proto_tree_add_item(tree, hf_afp_server_icon, tvb, offset, 256, ENC_NA);
	}

	if ((flag & AFPSRVRINFO_SRVSIGNATURE)) {
		if (sign_ofs >= variable_data_offset)
			proto_tree_add_item(tree, hf_afp_server_signature, tvb, sign_ofs, 16, ENC_NA);
	}

	if ((flag & AFPSRVRINFO_TCPIP)) {
		if (adr_ofs >= variable_data_offset) {
			proto_tree *adr_tree;
			unsigned char *tmp;
			guint16 net;
			guint8  node;
			guint16 port;

			offset = adr_ofs;
			nbe = tvb_get_guint8(tvb, offset);
			adr_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
						ett_afp_server_addr, NULL, "Address list: %d", nbe);
			offset++;
			for (i = 0; i < nbe; i++) {
				guint8 type;

				len = tvb_get_guint8(tvb, offset);
				type =  tvb_get_guint8(tvb, offset +1);
				switch (type) {
				case 1:	/* IP */
					sub_tree = proto_tree_add_subtree_format(adr_tree, tvb, offset, len, ett_afp_server_addr_line, NULL, "IP: %s", tvb_ip_to_str(pinfo->pool, tvb, offset+2));
					break;
				case 2: /* IP + port */
					port = tvb_get_ntohs(tvb, offset+6);
					sub_tree = proto_tree_add_subtree_format(adr_tree, tvb, offset, len,
										ett_afp_server_addr_line, NULL,
										"IP: %s:%d", tvb_ip_to_str(pinfo->pool, tvb, offset+2), port);
					break;
				case 3: /* DDP, atalk_addr_to_str want host order not network */
					net  = tvb_get_ntohs(tvb, offset+2);
					node = tvb_get_guint8(tvb, offset +4);
					port = tvb_get_guint8(tvb, offset +5);
					sub_tree = proto_tree_add_subtree_format(adr_tree, tvb, offset, len,
										ett_afp_server_addr_line, NULL,
										"DDP: %u.%u:%u", net, node, port);
					break;
				case 4: /* DNS */
				case 5: /* SSH tunnel */
					/*
					 * The AFP specifcation says of
					 * the SSH tunnel type:
					 *
					 *  IP address (four bytes) with port
					 *  number (2 bytes). If this tag is
					 *  present and the client is so
					 *  configured, the client attempts
					 *  to build a Secure Shell (SSH)
					 *  tunnel between itself and the
					 *  server and tries to connect
					 *  through it. This functionality
					 *  is deprecated.
					 *
					 * and, in the only place I've seen
					 * it, it was like DNS.
					 *
					 * So we treat it as DNS.
					 *
					 * XXX - should we treat it as
					 * IP+port if this is transported
					 * over ASP rather DSI?  The old
					 * ASP code to dissect this
					 * dissected it as IP+port.
					 */
					if (len > 2) {
						/* XXX - internationalized DNS? */
						tmp = tvb_get_string_enc(wmem_packet_scope(), tvb, offset +2, len -2, ENC_ASCII|ENC_NA);
						sub_tree = proto_tree_add_subtree_format(adr_tree, tvb, offset, len, ett_afp_server_addr_line, NULL, "%s: %s", (type==4)?"DNS":"IP (SSH tunnel)", tmp);
						break;
					}
					else {
						sub_tree = proto_tree_add_subtree(adr_tree, tvb, offset, len,
										ett_afp_server_addr_line, NULL, "Malformed DNS address");
					}
					break;
				case 6: /* IP6 */
					sub_tree = proto_tree_add_subtree_format(adr_tree, tvb, offset, len, ett_afp_server_addr_line, NULL, "IPv6: %s", tvb_ip6_to_str(pinfo->pool, tvb, offset+2));
					break;
				case 7: /* IP6 + 2bytes port */
					port = tvb_get_ntohs(tvb, offset+ 2+INET6_ADDRLEN);
					sub_tree = proto_tree_add_subtree_format(adr_tree, tvb, offset, len,
										ett_afp_server_addr_line, NULL,
										"IPv6: %s:%d", tvb_ip6_to_str(pinfo->pool, tvb, offset+2), port);
					break;
				default:
					sub_tree = proto_tree_add_subtree_format(adr_tree, tvb, offset, len, ett_afp_server_addr_line, NULL, "Unknown type: %u", type);
					break;
				}
				len -= 2;
				proto_tree_add_item(sub_tree, hf_afp_server_addr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				proto_tree_add_item(sub_tree, hf_afp_server_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				proto_tree_add_item(sub_tree, hf_afp_server_addr_value,tvb, offset, len, ENC_NA);
				offset += len;
			}
		}
	}

	if ((flag & AFPSRVRINFO_SRVDIRECTORY)) {
		if (dir_ofs >= variable_data_offset) {
			offset = dir_ofs;
			nbe = tvb_get_guint8(tvb, offset);
			sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
						ett_afp_directory, NULL, "Directory services list: %d", nbe);
			offset++;
			for (i = 0; i < nbe; i++) {
				len = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(sub_tree, hf_afp_server_directory, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
				offset += len + 1;
			}
		}
	}

	if ((flag & AFPSRVRINFO_SRVUTF8)) {
		if (utf_ofs >= variable_data_offset) {
			guint16 ulen;
			char *tmp;

			offset = utf_ofs;
			ulen = tvb_get_ntohs(tvb, offset);
			tmp = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 2, ulen, ENC_UTF_8|ENC_NA);
			sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, ulen + 2,
						ett_afp_utf8_name, NULL, "UTF-8 server name: %s", tmp);
			proto_tree_add_uint(sub_tree, hf_afp_utf8_server_name_len, tvb, offset, 2, ulen);
			offset += 2;
			proto_tree_add_string(sub_tree, hf_afp_utf8_server_name, tvb, offset, ulen, tmp);
			offset += ulen;
		}
	}

	return offset;
}

/* ************************** */
static int
dissect_afp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct atp_asp_dsi_info	*atp_asp_dsi_info = (struct atp_asp_dsi_info*)data;
	proto_tree	*afp_tree = NULL;
	proto_item	*ti;
	conversation_t	*conversation;
	gint		offset = 0;
	afp_request_key request_key, *new_request_key;
	afp_request_val *request_val;
	guint8		afp_command;
	nstime_t	delta_ts;
	int		len;

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;

	len = tvb_reported_length(tvb);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AFP");
	col_clear(pinfo->cinfo, COL_INFO);

	conversation = find_or_create_conversation(pinfo);

	request_key.conversation = conversation->conv_index;
	request_key.tid = atp_asp_dsi_info->tid;

	request_val = (afp_request_val *) wmem_map_lookup(
								afp_request_hash, &request_key);

	if (!request_val && !atp_asp_dsi_info->reply) {
		afp_command = tvb_get_guint8(tvb, offset);
		new_request_key = wmem_new(wmem_file_scope(), afp_request_key);
		*new_request_key = request_key;

		request_val = wmem_new(wmem_file_scope(), afp_request_val);
		request_val->command = afp_command;

		if (afp_command == AFP_SPOTLIGHTRPC)
			request_val->spotlight_req_command = tvb_get_ntohl(tvb, offset + 2 + 2 + 4);
		else
			request_val->spotlight_req_command = -1;

		request_val->frame_req = pinfo->num;
		request_val->frame_res = 0;
		request_val->req_time=pinfo->abs_ts;

		wmem_map_insert(afp_request_hash, new_request_key,
								request_val);
	}

	if (!request_val) {	/* missing request */
		col_set_str(pinfo->cinfo, COL_INFO, "[Reply without query?]");
		return tvb_captured_length(tvb);
	}

	afp_command = request_val->command;
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		     val_to_str_ext(afp_command, &CommandCode_vals_ext,
				"Unknown command (%u)"),
		     atp_asp_dsi_info->reply ? "reply" : "request");
	if (atp_asp_dsi_info->reply && atp_asp_dsi_info->code != 0) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s (%d)",
			val_to_str_ext(atp_asp_dsi_info->code, &asp_error_vals_ext,
				"Unknown error (%u)"), atp_asp_dsi_info->code);
	}

	ti = proto_tree_add_item(tree, proto_afp, tvb, offset, -1, ENC_NA);
	afp_tree = proto_item_add_subtree(ti, ett_afp);

	if (!atp_asp_dsi_info->reply)  {

		ti = proto_tree_add_uint(afp_tree, hf_afp_command, tvb,offset, 1, afp_command);
		if (afp_command != tvb_get_guint8(tvb, offset)) {
			/* we have the same conversation for different connections eg:
			 * ip1:2048 --> ip2:548
			 * ip1:2048 --> ip2:548 <RST>
			 * ....
			 * ip1:2048 --> ip2:548 <SYN> use the same port but it's a new session!
			 */
			col_set_str(pinfo->cinfo, COL_INFO,
				    "[Error!IP port reused, you need to split the capture file]");
			expert_add_info(pinfo, ti, &ei_afp_ip_port_reused);
			return tvb_captured_length(tvb);
		}

		/*
		 * Put in a field for the frame number of the frame to which
		 * this is a response if we know that frame number (i.e.,
		 * it's not 0).
		 */
		if (request_val->frame_res != 0) {
			ti = proto_tree_add_uint(afp_tree, hf_afp_response_in,
			    tvb, 0, 0, request_val->frame_res);
			proto_item_set_generated(ti);
		}

		offset++;
		switch (afp_command) {
		case AFP_BYTELOCK:
			offset = dissect_query_afp_byte_lock(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_BYTELOCK_EXT:
			offset = dissect_query_afp_byte_lock_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_OPENDT:	/* same as close vol */
		case AFP_FLUSH:
		case AFP_CLOSEVOL:
			offset = dissect_query_afp_with_vol_id(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CLOSEDIR:
			/* offset = dissect_query_afp_close_dir(tvb, pinfo, afp_tree, offset); */
			break;
		case AFP_CLOSEDT:
			offset = dissect_query_afp_close_dt(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_FLUSHFORK: /* same packet as closefork */
		case AFP_SYNCFORK:
		case AFP_CLOSEFORK:
			offset = dissect_query_afp_with_fork(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_COPYFILE:
			offset = dissect_query_afp_copy_file(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CREATEFILE:
			offset = dissect_query_afp_create_file(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_DISCTOLDSESS:
			offset = dissect_query_afp_disconnect_old_session(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ENUMERATE_EXT2:
			offset = dissect_query_afp_enumerate_ext2(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ENUMERATE_EXT:
		case AFP_ENUMERATE:
			offset = dissect_query_afp_enumerate(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETFORKPARAM:
			offset = dissect_query_afp_get_fork_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETSESSTOKEN:
			offset = dissect_query_afp_get_session_token(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETUSERINFO:
			offset = dissect_query_afp_get_user_info(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETSRVINFO:
			/* offset = dissect_query_afp_get_server_info(tvb, pinfo, afp_tree, offset); */
			break;
		case AFP_GETSRVPARAM:
			break;					/* no parameters */
		case AFP_GETVOLPARAM:
			offset = dissect_query_afp_get_vol_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_LOGIN_EXT:
			offset = dissect_query_afp_login_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_LOGIN:
			offset = dissect_query_afp_login(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_LOGINCONT:
		case AFP_LOGOUT:
			break;
		case AFP_MAPID:
			offset = dissect_query_afp_map_id(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_MAPNAME:
			offset = dissect_query_afp_map_name(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_MOVE:
			offset = dissect_query_afp_move(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_OPENVOL:
			offset = dissect_query_afp_open_vol(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_OPENDIR:
			break;
		case AFP_OPENFORK:
			offset = dissect_query_afp_open_fork(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_READ:
			offset = dissect_query_afp_read(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_READ_EXT:
			offset = dissect_query_afp_read_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_RENAME:
			offset = dissect_query_afp_rename(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SETDIRPARAM:
			offset = dissect_query_afp_set_dir_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SETFILEPARAM:
			offset = dissect_query_afp_set_file_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SETFORKPARAM:
			offset = dissect_query_afp_set_fork_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SETVOLPARAM:
			offset = dissect_query_afp_set_vol_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_WRITE:
			offset = dissect_query_afp_write(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_WRITE_EXT:
			offset = dissect_query_afp_write_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETFLDRPARAM:
			offset = dissect_query_afp_get_fldr_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SETFLDRPARAM:
			offset = dissect_query_afp_set_fldr_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CHANGEPW:
			break;
		case AFP_GETSRVRMSG:
			offset = dissect_query_afp_get_server_message(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_DELETE:	/* same as create_id */
		case AFP_CREATEDIR:
		case AFP_CREATEID:
			offset = dissect_query_afp_create_id(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_DELETEID:
			offset = dissect_query_afp_delete_id(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_RESOLVEID:
			offset = dissect_query_afp_resolve_id(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_EXCHANGEFILE:
			offset = dissect_query_afp_exchange_file(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CATSEARCH_EXT:
			offset = dissect_query_afp_cat_search_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CATSEARCH:
			offset = dissect_query_afp_cat_search(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETICON:
			offset = dissect_query_afp_get_icon(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GTICNINFO:
			offset = dissect_query_afp_get_icon_info(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ADDAPPL:
			offset = dissect_query_afp_add_appl(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_RMVAPPL:
			offset = dissect_query_afp_rmv_appl(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETAPPL:
			offset = dissect_query_afp_get_appl(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ADDCMT:
			offset = dissect_query_afp_add_cmt(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_RMVCMT: /* same as get_cmt */
		case AFP_GETCMT:
			offset = dissect_query_afp_get_cmt(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ADDICON:
			offset = dissect_query_afp_add_icon(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETEXTATTR:
			offset = dissect_query_afp_get_ext_attr(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SETEXTATTR:
			offset = dissect_query_afp_set_ext_attr(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_LISTEXTATTR:
			offset = dissect_query_afp_list_ext_attrs(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_REMOVEATTR:
			offset = dissect_query_afp_remove_ext_attr(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETACL:
			offset = dissect_query_afp_get_acl(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SETACL:
			offset = dissect_query_afp_set_acl(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ACCESS:
			offset = dissect_query_afp_access(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SYNCDIR:
			offset = dissect_query_afp_with_did(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SPOTLIGHTRPC:
			offset = dissect_query_afp_spotlight(tvb, pinfo, afp_tree, offset, request_val);
			break;
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
			proto_item_set_generated(ti);
			nstime_delta(&delta_ts, &pinfo->abs_ts, &request_val->req_time);
			ti = proto_tree_add_time(afp_tree, hf_afp_time, tvb,
			    0, 0, &delta_ts);
			proto_item_set_generated(ti);
		}

		/*
		 * Set "frame_res" if it's not already known.
		 */
		if (request_val->frame_res == 0)
			request_val->frame_res = pinfo->num;

		/*
		 * Tap the packet before the dissectors are called so we
		 * still get the tap listener called even if there is an
		 * exception.
		 */
		tap_queue_packet(afp_tap, pinfo, request_val);

		if (!len) {
			/* for some calls if the reply is an error there's no data
			*/
			return tvb_captured_length(tvb);
		}

		switch (afp_command) {
		case AFP_BYTELOCK:
			offset = dissect_reply_afp_byte_lock(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_BYTELOCK_EXT:
			offset = dissect_reply_afp_byte_lock_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ENUMERATE_EXT2:
		case AFP_ENUMERATE_EXT:
			offset = dissect_reply_afp_enumerate_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_ENUMERATE:
			offset = dissect_reply_afp_enumerate(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_OPENVOL:
			offset = dissect_reply_afp_open_vol(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_OPENFORK:
			offset = dissect_reply_afp_open_fork(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_RESOLVEID:
		case AFP_GETFORKPARAM:
			offset = dissect_reply_afp_get_fork_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETUSERINFO:
			offset = dissect_reply_afp_get_user_info(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETSRVPARAM:
			offset = dissect_reply_afp_get_server_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETSRVRMSG:
			offset = dissect_reply_afp_get_server_message(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CREATEDIR:
			offset = dissect_reply_afp_create_dir(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_MAPID:
			offset = dissect_reply_afp_map_id(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_MAPNAME:
			offset = dissect_reply_afp_map_name(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_MOVE:		/* same as create_id */
		case AFP_CREATEID:
			offset = dissect_reply_afp_create_id(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETSESSTOKEN:
			offset = dissect_reply_afp_get_session_token(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETVOLPARAM:
			offset = dissect_reply_afp_get_vol_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETFLDRPARAM:
			offset = dissect_reply_afp_get_fldr_param(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_OPENDT:
			offset = dissect_reply_afp_open_dt(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CATSEARCH_EXT:
			offset = dissect_reply_afp_cat_search_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_CATSEARCH:
			offset = dissect_reply_afp_cat_search(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GTICNINFO:
			offset = dissect_reply_afp_get_icon_info(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETAPPL:
			offset = dissect_reply_afp_get_appl(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETCMT:
			offset = dissect_reply_afp_get_cmt(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_WRITE:
			offset = dissect_reply_afp_write(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_WRITE_EXT:
			offset = dissect_reply_afp_write_ext(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETEXTATTR:
			offset = dissect_reply_afp_get_ext_attr(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_LISTEXTATTR:
			offset = dissect_reply_afp_list_ext_attrs(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_GETACL:
			offset = dissect_reply_afp_get_acl(tvb, pinfo, afp_tree, offset);
			break;
		case AFP_SPOTLIGHTRPC:
			offset = dissect_reply_afp_spotlight(tvb, pinfo, afp_tree, offset, request_val);
			break;
		}
	}
	if (offset < len) {
		call_data_dissector(tvb_new_subset_remaining(tvb, offset),
		    pinfo, afp_tree);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_afp(void)
{

	static hf_register_info hf[] = {
		{ &hf_afp_command,
		  { "Command",      "afp.command",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &CommandCode_vals_ext, 0x0,
		    "AFP function", HFILL }},

		{ &hf_afp_pad,
		  { "Pad",    	"afp.pad",
		    FT_NONE,   BASE_NONE, NULL, 0,
		    "Pad Byte",	HFILL }},

		{ &hf_afp_Version,
		  { "AFP Version",  "afp.Version",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "Client AFP version", HFILL }},

		{ &hf_afp_UAM,
		  { "UAM",          "afp.UAM",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "User Authentication Method", HFILL }},

		{ &hf_afp_user,
		  { "User",         "afp.user",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

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
		    FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_random,
		  { "Random number",         "afp.random",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
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
		  { "Flags",         "afp.login_flags",
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
		    NULL, HFILL }},

		{ &hf_afp_vol_attribute_DefaultPrivsFromParent,
		  { "Inherit parent privileges",         "afp.vol_attribute.inherit_parent_privs",
		    FT_BOOLEAN, 16, NULL, kDefaultPrivsFromParent,
		    NULL, HFILL }},

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

		{ &hf_afp_vol_attribute_CaseSensitive,
		  { "Case sensitive",         "afp.vol_attribute.case_sensitive",
		    FT_BOOLEAN, 16, NULL, kCaseSensitive,
		    "Supports case-sensitive filenames", HFILL }},

		{ &hf_afp_vol_attribute_SupportsTMLockSteal,
		  { "TM lock steal",         "afp.vol_attribute.TM_lock_steal",
		    FT_BOOLEAN, 16, NULL, kSupportsTMLockSteal,
		    "Supports Time Machine lock stealing", HFILL }},

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

		{ &hf_afp_dir_attribute,
		  { "Directory Attributes",         "afp.dir_attribute",
		    FT_UINT16, BASE_HEX, NULL,  0x0,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_dir_attribute_DeleteInhibit,
		  { "Delete inhibit",         "afp.dir_attribute.delete_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPDeleteInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_file_bitmap,
		  { "File bitmap",         "afp.file_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

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
		{ &hf_afp_file_attribute,
		  { "File Attributes",         "afp.file_attribute",
		    FT_UINT16, BASE_HEX, NULL,  0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_Invisible,
		  { "Invisible",         "afp.file_attribute.invisible",
		    FT_BOOLEAN, 16, NULL,  kFPInvisibleBit,
		    "File is not visible", HFILL }},

		{ &hf_afp_file_attribute_MultiUser,
		  { "Multi user",         "afp.file_attribute.multi_user",
		    FT_BOOLEAN, 16, NULL,  kFPMultiUserBit,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_BackUpNeeded,
		  { "Backup needed",         "afp.file_attribute.backup_needed",
		    FT_BOOLEAN, 16, NULL,  kFPBackUpNeededBit,
		    "File needs to be backed up", HFILL }},

		{ &hf_afp_file_attribute_RenameInhibit,
		  { "Rename inhibit",         "afp.file_attribute.rename_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPRenameInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_DeleteInhibit,
		  { "Delete inhibit",         "afp.file_attribute.delete_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPDeleteInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_CopyProtect,
		  { "Copy protect",         "afp.file_attribute.copy_protect",
		    FT_BOOLEAN, 16, NULL,  kFPCopyProtectBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_SetClear,
		  { "Set",         "afp.file_attribute.set_clear",
		    FT_BOOLEAN, 16, NULL,  kFPSetClearBit,
		    "Clear/set attribute", HFILL }},
		/* ---------- */

		{ &hf_afp_vol_name,
		  { "Volume",         "afp.vol_name",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "Volume name", HFILL }},

		{ &hf_afp_vol_flag,
		  { "Flags",         "afp.vol_flag",
		    FT_UINT8, BASE_HEX, NULL,  0x0,
		    NULL, HFILL }},

		{ &hf_afp_vol_flag_passwd,
		  { "Password",         "afp.vol_flag_passwd",
		    FT_BOOLEAN, 8, NULL,  128,
		    "Volume is password-protected", HFILL }},

		{ &hf_afp_vol_flag_has_config,
		  { "Has config",         "afp.vol_flag_has_config",
		    FT_BOOLEAN, 8, NULL,  1,
		    "Volume has Apple II config info", HFILL }},

		{ &hf_afp_vol_id,
		  { "Volume id",         "afp.vol_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

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
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    "Volume creation date", HFILL }},

		{ &hf_afp_vol_modification_date,
		  { "Modification date",         "afp.vol_modification_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    "Volume modification date", HFILL }},

		{ &hf_afp_vol_backup_date,
		  { "Backup date",         "afp.vol_backup_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
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
		    NULL, HFILL }},

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
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_modification_date,
		  { "Modification date",         "afp.modification_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_backup_date,
		  { "Backup date",         "afp.backup_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_finder_info,
		  { "Finder info",         "afp.finder_info",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_unix_privs_ua_permissions,
		  { "User's access rights",     "afp.unix_privs.ua_permissions",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_id,
		  { "File ID",         "afp.file_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "File/directory ID", HFILL }},

		{ &hf_afp_file_DataForkLen,
		  { "Data fork size",         "afp.data_fork_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_RsrcForkLen,
		  { "Resource fork size",         "afp.resource_fork_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_ExtDataForkLen,
		  { "Extended data fork size",         "afp.ext_data_fork_len",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Extended (>2GB) data fork length", HFILL }},

		{ &hf_afp_file_ExtRsrcForkLen,
		  { "Extended resource fork size",         "afp.ext_resource_fork_len",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Extended (>2GB) resource fork length", HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_start_index32,
		  { "Start index",         "afp.start_index32",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "First structure returned", HFILL }},

		{ &hf_afp_max_reply_size32,
		  { "Reply size",         "afp.reply_size32",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_flag,
		  { "Dir",         "afp.file_flag",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    "Is a dir", HFILL }},

		{ &hf_afp_create_flag,
		  { "Hard create",         "afp.create_flag",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    "Soft/hard create file", HFILL }},

		{ &hf_afp_request_bitmap,
		  { "Request Bitmap",         "afp.request_bitmap",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

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
		    NULL, HFILL }},

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

		{ &hf_afp_ofork_len,
		  { "New length",         "afp.ofork_len",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

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
		    FT_UINT32, BASE_HEX|BASE_EXT_STRING, &unicode_hint_vals_ext, 0x0,
		    NULL, HFILL }},

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
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    "Fork access mode", HFILL }},

		{ &hf_afp_access_read,
		  { "Read",         "afp.access.read",
		    FT_BOOLEAN, 16, NULL, 0x0001,
		    "Open for reading", HFILL }},

		{ &hf_afp_access_write,
		  { "Write",         "afp.access.write",
		    FT_BOOLEAN, 16, NULL, 0x0002,
		    "Open for writing", HFILL }},

		{ &hf_afp_access_deny_read,
		  { "Deny read",         "afp.access.deny_read",
		    FT_BOOLEAN, 16, NULL, 0x0010,
		    NULL, HFILL }},

		{ &hf_afp_access_deny_write,
		  { "Deny write",         "afp.access.deny_write",
		    FT_BOOLEAN, 16, NULL, 0x0020,
		    NULL, HFILL }},

		{ &hf_afp_comment,
		  { "Comment",         "afp.comment",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "File/folder comment", HFILL }},

		/*
		 * XXX - should this be a type that's displayed as
		 * text if it's all printable ASCII and hex otherwise,
		 * or something such as that?
		 */
		{ &hf_afp_file_creator,
		  { "File creator",         "afp.file_creator",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/*
		 * XXX - should this be a type that's displayed as
		 * text if it's all printable ASCII and hex otherwise,
		 * or something such as that?
		 */
		{ &hf_afp_file_type,
		  { "File type",         "afp.file_type",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_icon_type,
		  { "Icon type",         "afp.icon_type",
		    FT_UINT8, BASE_HEX, NULL , 0,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_o_read,
		  { "Owner has read access",        "afp.dir_ar.o_read",
		    FT_BOOLEAN, 32, NULL, AR_O_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_o_write,
		  { "Owner has write access",       "afp.dir_ar.o_write",
		    FT_BOOLEAN, 32, NULL, AR_O_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_g_search,
		  { "Group has search access",      "afp.dir_ar.g_search",
		    FT_BOOLEAN, 32, NULL, AR_G_SEARCH,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_g_read,
		  { "Group has read access",        "afp.dir_ar.g_read",
		    FT_BOOLEAN, 32, NULL, AR_G_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_g_write,
		  { "Group has write access",       "afp.dir_ar.g_write",
		    FT_BOOLEAN, 32, NULL, AR_G_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_e_search,
		  { "Everyone has search access",   "afp.dir_ar.e_search",
		    FT_BOOLEAN, 32, NULL, AR_E_SEARCH,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_e_read,
		  { "Everyone has read access",     "afp.dir_ar.e_read",
		    FT_BOOLEAN, 32, NULL, AR_E_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_e_write,
		  { "Everyone has write access",    "afp.dir_ar.e_write",
		    FT_BOOLEAN, 32, NULL, AR_E_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_search,
		  { "User has search access",   "afp.dir_ar.u_search",
		    FT_BOOLEAN, 32, NULL, AR_U_SEARCH,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_read,
		  { "User has read access",     "afp.dir_ar.u_read",
		    FT_BOOLEAN, 32, NULL, AR_U_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_write,
		  { "User has write access",     "afp.dir_ar.u_write",
		    FT_BOOLEAN, 32, NULL, AR_U_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_blank,
		  { "Blank access right",     "afp.dir_ar.blank",
		    FT_BOOLEAN, 32, NULL, AR_BLANK,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_own,
		  { "User is the owner",     "afp.dir_ar.u_owner",
		    FT_BOOLEAN, 32, NULL, AR_U_OWN,
		    "Current user is the directory owner", HFILL }},

		{ &hf_afp_server_time,
		  { "Server time",         "afp.server_time",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_cat_req_matches,
		  { "Max answers",         "afp.cat_req_matches",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Maximum number of matches to return.", HFILL }},

		{ &hf_afp_reserved,
		  { "Reserved",         "afp.reserved",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_cat_count,
		  { "Cat count",         "afp.cat_count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of structures returned", HFILL }},

		{ &hf_afp_cat_position,
		  { "Position",         "afp.cat_position",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Catalog position", HFILL }},

		{ &hf_afp_map_name_type,
		  { "Type",      "afp.map_name_type",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &map_name_type_vals_ext, 0x0,
		    "Map name type", HFILL }},

		{ &hf_afp_map_id_type,
		  { "Type",      "afp.map_id_type",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &map_id_type_vals_ext, 0x0,
		    "Map ID type", HFILL }},

		{ &hf_afp_map_id,
		  { "ID",             "afp.map_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "User/Group ID", HFILL }},

		{ &hf_afp_map_id_reply_type,
		  { "Reply type",      "afp.map_id_reply_type",
		    FT_UINT32, BASE_DEC, VALS(map_id_reply_type_vals), 0x0,
		    "Map ID reply type", HFILL }},

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
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &token_type_vals_ext, 0x0,
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
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Session token", HFILL }},

		{ &hf_afp_user_flag,
		  { "Flag",         "afp.user_flag",
		    FT_UINT8, BASE_HEX, VALS(user_flag_vals), 0x01,
		    "User Info flag", HFILL }},

		{ &hf_afp_user_ID,
		  { "User ID",         "afp.user_ID",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_group_ID,
		  { "Group ID",         "afp.group_ID",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_UUID,
		  { "UUID",         "afp.uuid",
		    FT_GUID, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_GRPUUID,
		  { "GRPUUID",         "afp.grpuuid",
		    FT_GUID, BASE_NONE, NULL, 0x0,
		    "Group UUID", HFILL }},

		{ &hf_afp_user_bitmap,
		  { "Bitmap",         "afp.user_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "User Info bitmap", HFILL }},

		{ &hf_afp_user_bitmap_UID,
		  { "User ID",         "afp.user_bitmap.UID",
		    FT_BOOLEAN, 16, NULL, 0x01,
		    NULL, HFILL }},

		{ &hf_afp_user_bitmap_GID,
		  { "Primary group ID",         "afp.user_bitmap.GID",
		    FT_BOOLEAN, 16, NULL, 0x02,
		    NULL, HFILL }},

		{ &hf_afp_user_bitmap_UUID,
		  { "UUID",         "afp.user_bitmap.UUID",
		    FT_BOOLEAN, 16, NULL, 0x04,
		    NULL, HFILL }},

		{ &hf_afp_message_type,
		  { "Type",         "afp.message_type",
		    FT_UINT16, BASE_HEX, VALS(server_message_type), 0,
		    "Type of server message", HFILL }},

		{ &hf_afp_message_bitmap,
		  { "Bitmap",         "afp.message_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Message bitmap", HFILL }},

		/*
		 * XXX - in the reply, this indicates whether the message
		 * is a server message or a login message.
		 */
		{ &hf_afp_message_bitmap_REQ,
		  { "Request message",         "afp.message_bitmap.requested",
		    FT_BOOLEAN, 16, NULL, 0x01,
		    "Message Requested", HFILL }},

		{ &hf_afp_message_bitmap_UTF,
		  { "Message is UTF-8",         "afp.message_bitmap.utf8",
		    FT_BOOLEAN, 16, NULL, 0x02,
		    NULL, HFILL }},

		{ &hf_afp_message_len,
		  { "Len",         "afp.message_length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Message length", HFILL }},

		{ &hf_afp_message,
		  { "Message",  "afp.message",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

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
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Extended attribute data", HFILL }},

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
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_acl_list_bitmap_REMOVEACL,
		  { "Remove ACL",         "afp.acl_list_bitmap.REMOVEACL",
		    FT_BOOLEAN, 16, NULL, kFileSec_REMOVEACL,
		    NULL, HFILL }},

		{ &hf_afp_acl_list_bitmap_Inherit,
		  { "Inherit",         "afp.acl_list_bitmap.Inherit",
		    FT_BOOLEAN, 16, NULL, kFileSec_Inherit,
		    "Inherit ACL", HFILL }},

		{ &hf_afp_acl_entrycount,
		  { "ACEs count",         "afp.acl_entrycount",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Number of ACL entries", HFILL }},

		{ &hf_afp_acl_flags,
		  { "ACL flags",         "afp.acl_flags",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_write_attrs,
		  { "Write attributes",         "afp.acl_access_bitmap.write_attrs",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_ATTRIBUTES,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_read_extattrs,
		  { "Read extended attributes", "afp.acl_access_bitmap.read_extattrs",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_write_extattrs,
		  { "Write extended attributes", "afp.acl_access_bitmap.write_extattrs",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_synchronize,
		  { "Synchronize",         "afp.acl_access_bitmap.synchronize",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_SYNCHRONIZE,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_all,
		  { "Generic all",         "afp.acl_access_bitmap.generic_all",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_ALL,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_execute,
		  { "Generic execute",         "afp.acl_access_bitmap.generic_execute",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_EXECUTE,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_write,
		  { "Generic write",         "afp.acl_access_bitmap.generic_write",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_read,
		  { "Generic read",         "afp.acl_access_bitmap.generic_read",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_READ,
		    NULL, HFILL }},

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
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_fileinherit,
		  { "File inherit",         "afp.ace_flags.file_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_FILE_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_dirinherit,
		  { "Dir inherit",         "afp.ace_flags.directory_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_DIR_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_limitinherit,
		  { "Limit inherit",         "afp.ace_flags.limit_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_LIMIT_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_onlyinherit,
		  { "Only inherit",         "afp.ace_flags.only_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_ONLY_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_request_flags,
		  { "Flags",               "afp.spotlight.flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Spotlight RPC Flags", HFILL }},

		{ &hf_afp_spotlight_request_command,
		  { "Command",               "afp.spotlight.command",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Spotlight RPC Command", HFILL }},

		{ &hf_afp_spotlight_request_reserved,
		  { "Padding",               "afp.spotlight.reserved",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Spotlight RPC Padding", HFILL }},

		{ &hf_afp_spotlight_reply_reserved,
		  { "Reserved",               "afp.spotlight.reserved",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Spotlight RPC Padding", HFILL }},

		{ &hf_afp_spotlight_volpath_client,
		  { "Client's volume path",               "afp.spotlight.volpath_client",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_volpath_server,
		  { "Server's volume path",               "afp.spotlight.volpath_server",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Servers's volume path", HFILL }},

		{ &hf_afp_spotlight_returncode,
		  { "Return code",               "afp.spotlight.return",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_volflags,
		  { "Volume flags",               "afp.spotlight.volflags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_reqlen,
		  { "Length",               "afp.spotlight.reqlen",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_uuid,
		  { "UUID",               "afp.spotlight.uuid",
		    FT_GUID, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_date,
		  { "Date",               "afp.spotlight.date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_unknown,
		  { "Unknown parameter",         "afp.unknown_bytes",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Status stuff from ASP or DSI */
		{ &hf_afp_utf8_server_name_len,
		  { "UTF-8 server name length",          "afp.utf8_server_name_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_utf8_server_name,
		  { "UTF-8 server name",         "afp.utf8_server_name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_server_name,
		  { "Server name",         "afp.server_name",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_server_type,
		  { "Server type",         "afp.server_type",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_server_vers,
		  { "AFP version",         "afp.server_vers",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_server_uams,
		  { "UAM",         "afp.server_uams",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_server_icon,
		  { "Icon bitmap",         "afp.server_icon",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Server icon bitmap", HFILL }},

		{ &hf_afp_server_directory,
		  { "Directory service",         "afp.server_directory",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "Server directory service", HFILL }},

		{ &hf_afp_server_signature,
		  { "Server signature",         "afp.server_signature",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_server_flag,
		  { "Flag",         "afp.server_flag",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    "Server capabilities flag", HFILL }},
		{ &hf_afp_server_flag_copyfile,
		  { "Support copyfile",      "afp.server_flag.copyfile",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_COPY,
		    "Server support copyfile", HFILL }},
		{ &hf_afp_server_flag_passwd,
		  { "Support change password",      "afp.server_flag.passwd",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_PASSWD,
		    "Server support change password", HFILL }},
		{ &hf_afp_server_flag_no_save_passwd,
		  { "Don't allow save password",      "afp.server_flag.no_save_passwd",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_NOSAVEPASSWD,
		    NULL, HFILL }},
		{ &hf_afp_server_flag_srv_msg,
		  { "Support server message",      "afp.server_flag.srv_msg",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVMSGS,
		    NULL, HFILL }},
		{ &hf_afp_server_flag_srv_sig,
		  { "Support server signature",      "afp.server_flag.srv_sig",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVSIGNATURE,
		    NULL, HFILL }},
		{ &hf_afp_server_flag_tcpip,
		  { "Support TCP/IP",      "afp.server_flag.tcpip",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_TCPIP,
		    "Server support TCP/IP", HFILL }},
		{ &hf_afp_server_flag_notify,
		  { "Support server notifications",      "afp.server_flag.notify",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVNOTIFY,
		    "Server support notifications", HFILL }},
		{ &hf_afp_server_flag_reconnect,
		  { "Support server reconnect",      "afp.server_flag.reconnect",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVRECONNECT,
		    "Server support reconnect", HFILL }},
		{ &hf_afp_server_flag_directory,
		  { "Support directory services",      "afp.server_flag.directory",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVDIRECTORY,
		    "Server support directory services", HFILL }},
		{ &hf_afp_server_flag_utf8_name,
		  { "Support UTF-8 server name",      "afp.server_flag.utf8_name",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVUTF8,
		    "Server support UTF-8 server name", HFILL }},
		{ &hf_afp_server_flag_uuid,
		  { "Support UUIDs",      "afp.server_flag.uuids",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_UUID,
		    "Server supports UUIDs", HFILL }},
		{ &hf_afp_server_flag_ext_sleep,
		  { "Support extended sleep",      "afp.server_flag.ext_sleep",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_EXT_SLEEP,
		    "Server supports extended sleep", HFILL }},
		{ &hf_afp_server_flag_fast_copy,
		  { "Support fast copy",      "afp.server_flag.fast_copy",
		    FT_BOOLEAN, 16, NULL, AFPSRVRINFO_FASTBOZO,
		    "Server support fast copy", HFILL }},


		{ &hf_afp_server_addr_len,
		  { "Length",          "afp.server_addr.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Address length.", HFILL }},

		{ &hf_afp_server_addr_type,
		  { "Type",          "afp.server_addr.type",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &afp_server_addr_type_vals_ext, 0x0,
		    "Address type.", HFILL }},

		{ &hf_afp_server_addr_value,
		  { "Value",          "afp.server_addr.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Address value", HFILL }},

		/* Generated from convert_proto_tree_add_text.pl */
		{ &hf_afp_int64, { "int64", "afp.int64", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_float, { "float", "afp.float", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_unknown16, { "unknown1", "afp.unknown", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_unknown32, { "unknown2", "afp.unknown", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_cnid, { "CNID", "afp.cnid", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_null, { "null", "afp.null", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_string, { "string", "afp.string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_utf_16_string, { "utf-16 string", "afp.utf_16_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_bool, { "bool", "afp.bool", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_query_type, { "type", "afp.query_type", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_toc_offset, { "ToC Offset", "afp.toc_offset", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_toc_entry, { "ToC Entry", "afp.toc_entry", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_endianness, { "Endianness", "afp.endianness", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(endian_vals), 0x0, NULL, HFILL }},
		{ &hf_afp_query_len, { "Query length", "afp.query_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_num_toc_entries, { "Number of entries", "afp.num_toc_entries", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_machine_offset, { "Machine offset", "afp.machine_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_version_offset, { "Version offset", "afp.version_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_uams_offset, { "UAMS offset", "afp.uams_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_icon_offset, { "Icon offset", "afp.icon_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_signature_offset, { "Signature offset", "afp.signature_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_network_address_offset, { "Network address offset", "afp.network_address_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_directory_services_offset, { "Directory services offset", "afp.directory_services_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_afp_utf8_server_name_offset, { "UTF-8 server name offset", "afp.utf8_server_name_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
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
		&ett_afp_spotlight_queries,
		&ett_afp_spotlight_query_line,
		&ett_afp_spotlight_query,
		&ett_afp_spotlight_data,
		&ett_afp_spotlight_toc,

		/* Status stuff from ASP or DSI */
		&ett_afp_status,
		&ett_afp_status_server_flag,
		&ett_afp_vers,
		&ett_afp_uams,
		&ett_afp_server_addr,
		&ett_afp_server_addr_line,
		&ett_afp_directory,
		&ett_afp_utf8_name
	};

	static ei_register_info ei[] = {
		{ &ei_afp_subquery_count_over_safety_limit, { "afp.subquery_count_over_safety_limit", PI_MALFORMED, PI_ERROR, "Subquery count > safety limit ", EXPFILL }},
		{ &ei_afp_subquery_count_over_query_count, { "afp.subquery_count_over_query_count", PI_MALFORMED, PI_ERROR, "Subquery count > query count", EXPFILL }},
		{ &ei_afp_abnormal_num_subqueries, { "afp.abnormal_num_subqueries", PI_PROTOCOL, PI_WARN, "Abnormal number of subqueries", EXPFILL }},
		{ &ei_afp_too_many_acl_entries, { "afp.too_many_acl_entries", PI_UNDECODED, PI_WARN, "Too many ACL entries", EXPFILL }},
		{ &ei_afp_ip_port_reused, { "afp.ip_port_reused", PI_SEQUENCE, PI_WARN, "IP port reused, you need to split the capture file", EXPFILL }},
		{ &ei_afp_toc_offset, { "afp.toc_offset.bogus", PI_PROTOCOL, PI_WARN, "ToC offset bogus", EXPFILL }},
	};
	expert_module_t* expert_afp;

	proto_afp = proto_register_protocol("Apple Filing Protocol", "AFP", "afp");
	proto_register_field_array(proto_afp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_afp = expert_register_protocol(proto_afp);
	expert_register_field_array(expert_afp, ei, array_length(ei));

	afp_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), afp_hash, afp_equal);

	register_dissector("afp", dissect_afp, proto_afp);
	register_dissector("afp_server_status", dissect_afp_server_status,
	    proto_afp);
	register_dissector("afp_spotlight", dissect_spotlight, proto_afp);

	afp_tap = register_tap("afp");

	register_srt_table(proto_afp, NULL, 1, afpstat_packet, afpstat_init, NULL);
}

void
proto_reg_handoff_afp(void)
{
	spotlight_handle = find_dissector_add_dependency("afp_spotlight", proto_afp);
}

/* -------------------------------
	end
*/

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
