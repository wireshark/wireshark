/* packet-afp.c
 * Routines for afp packet dissection
 * Copyright 2002, Didier Gautheron <dgautheron@magic.fr>
 *
 * $Id: packet-afp.c,v 1.1 2002/04/25 23:58:02 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>

#include "packet-afp.h"

/* The information in this module (AFP) comes from:

  AFP 2.1 & 2.2.pdf contained in AppleShare_IP_6.3_SDK
  available from http://www.apple.com
 
  AFP3.0.pdf from http://www.apple.com
  
  The netatalk source code by Wesley Craig & Adrian Sun
	http://netatalk.sf.net
*/
/* from netatalk/include/afp.h */
#define AFPTRANS_NONE          0
#define AFPTRANS_DDP          (1 << 0)
#define AFPTRANS_TCP          (1 << 1)
#define AFPTRANS_ALL          (AFPTRANS_DDP | AFPTRANS_TCP)

/* server flags */
#define AFPSRVRINFO_COPY	 		(1<<0)  /* supports copyfile */
#define AFPSRVRINFO_PASSWD	 		(1<<1)	/* supports change password */
#define AFPSRVRINFO_NOSAVEPASSWD 	(1<<2)  /* don't allow save password */
#define AFPSRVRINFO_SRVMSGS      	(1<<3)  /* supports server messages */
#define AFPSRVRINFO_SRVSIGNATURE 	(1<<4)  /* supports server signature */
#define AFPSRVRINFO_TCPIP        	(1<<5)  /* supports tcpip */
#define AFPSRVRINFO_SRVNOTIFY    	(1<<6)  /* supports server notifications */ 
#define AFPSRVRINFO_FASTBOZO	 	(1<<15) /* fast copying */

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
#define AFP_ADDICON        192

/* ----------------------------- */
static int proto_afp = -1;
static int hf_afp_flags = -1;
static int hf_afp_requestid = -1;
static int hf_afp_code = -1;
static int hf_afp_length = -1;
static int hf_afp_reserved = -1;

static int hf_afp_command = -1;		/* CommandCode */
static int hf_afp_AFPVersion = -1; 
static int hf_afp_UAM = -1; 
static int hf_afp_user = -1; 
static int hf_afp_passwd = -1; 
static int hf_afp_pad = -1;

static int hf_afp_vol_bitmap = -1;
static int hf_afp_bitmap_offset = -1;
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

static int hf_afp_did = -1;
static int hf_afp_file_id = -1;
static int hf_afp_dir_bitmap = -1;
static int hf_afp_dir_off_spring = -1;

static int hf_afp_file_bitmap = -1;
static int hf_afp_req_count = -1;
static int hf_afp_start_index = -1;
static int hf_afp_max_reply_size = -1;
static int hf_afp_file_flag = -1;
static int hf_afp_struct_size = -1;

static int hf_afp_creation_date = -1;
static int hf_afp_modification_date = -1;
static int hf_afp_backup_date = -1;
static int hf_afp_finder_info = -1;

static int hf_afp_path_type = -1;
static int hf_afp_path_name = -1;

static int hf_afp_flag    = -1;
static int hf_afp_ofork   = -1;
static int hf_afp_offset  = -1;
static int hf_afp_rw_count = 1;
static int hf_afp_fork_type			= -1;
static int hf_afp_access_mode		= -1;
static int hf_afp_access_read		= -1;
static int hf_afp_access_write		= -1;
static int hf_afp_access_deny_read  = -1;
static int hf_afp_access_deny_write = -1;

static gint ett_afp = -1;

static gint ett_afp_vol_attribute = -1;
static gint ett_afp_enumerate = -1;
static gint ett_afp_enumerate_line = -1;
static gint ett_afp_access_mode = -1;

static gint ett_afp_vol_bitmap = -1;
static gint ett_afp_dir_bitmap = -1;
static gint ett_afp_file_bitmap = -1;

static dissector_handle_t afp_handle;
static dissector_handle_t data_handle;

static const value_string vol_signature_vals[] = {
	{1, "Flat"},
	{2,  "Fixed Directory ID"},
	{3,  "Variable Directory ID (deprecated)"},
	{0,				 NULL } };

static const value_string CommandCode_vals[] = {
  {AFP_BYTELOCK,	"afpByteRangeLock" },
  {AFP_CLOSEVOL,	"afpVolClose" },
  {AFP_CLOSEDIR,	"afpDirClose" },
  {AFP_CLOSEFORK,	"afpForkClose" },
  {AFP_COPYFILE,	"afpCopyFile" },
  {AFP_CREATEDIR,	"afpDirCreate" },
  {AFP_CREATEFILE,	"afpFileCreate" },
  {AFP_DELETE,		"afpDelete" },
  {AFP_ENUMERATE,	"afpEnumerate" },
  {AFP_FLUSH,		"afpFlush" },
  {AFP_FLUSHFORK,	"afpForkFlush" },
  {AFP_GETFORKPARAM,"afpGetForkParms" },
  {AFP_GETSRVINFO,	"afpGetSInfo" },
  {AFP_GETSRVPARAM,	"afpGetSParms" },
  {AFP_GETVOLPARAM,	"afpGetVolParms" },
  {AFP_LOGIN,		"afpLogin" },
  {AFP_LOGINCONT,	"afpContLogin" },
  {AFP_LOGOUT,		"afpLogout" },
  {AFP_MAPID,		"afpMapID" },
  {AFP_MAPNAME,		"afpMapName" },
  {AFP_MOVE,		"afpMove" },
  {AFP_OPENVOL,		"afpOpenVol" },
  {AFP_OPENDIR,		"afpOpenDir" },
  {AFP_OPENFORK,	"afpOpenFork" },
  {AFP_READ,		"afpRead" },
  {AFP_RENAME,		"afpRename" },
  {AFP_SETDIRPARAM,	"afpSetDirParms" },
  {AFP_SETFILEPARAM,"afpSetFileParms" },
  {AFP_SETFORKPARAM,"afpSetForkParms" },
  {AFP_SETVOLPARAM,	"afpSetVolParms" },
  {AFP_WRITE,		"afpWrite" },
  {AFP_GETFLDRPARAM,"afpGetFlDrParms" },
  {AFP_SETFLDRPARAM,"afpSetFlDrParms" },
  {AFP_CHANGEPW,	"afpChangePw" },
  {AFP_GETSRVRMSG,	"afpGetSrvrMsg" },
  {AFP_CREATEID,	"afpCreateID" },
  {AFP_DELETEID,	"afpDeleteID" },
  {AFP_RESOLVEID,	"afpResolveID" },
  {AFP_EXCHANGEFILE,"afpExchangeFiles" },
  {AFP_CATSEARCH,	"afpCatSearch" },
  {AFP_OPENDT,		"afpDTOpen" },
  {AFP_CLOSEDT,		"afpDTClose" },
  {AFP_GETICON,		"afpGetIcon" },
  {AFP_GTICNINFO,	"afpGtIcnInfo" },
  {AFP_ADDAPPL,		"afpAddAPPL" },
  {AFP_RMVAPPL,		"afpRmvAPPL" },
  {AFP_GETAPPL,		"afpGetAPPL" },
  {AFP_ADDCMT,		"afpAddCmt" },
  {AFP_RMVCMT,		"afpRmvCmt" },
  {AFP_GETCMT,		"afpGetCmt" },
  {AFP_ADDICON,		"afpAddIcon" },
  {0,				 NULL } };


/* volume bitmap
  from Apple AFP3.0.pdf 
  Table 1-2 p. 20
*/
#define kFPVolAttributeBit 		(1 << 0)
#define kFPVolSignatureBit 		(1 << 1)
#define kFPVolCreateDateBit 	(1 << 2)
#define kFPVolModDateBit 		(1 << 3)
#define kFPVolBackupDateBit 	(1 << 4)
#define kFPVolIDBit 			(1 << 5)
#define kFPVolBytesFreeBit  	(1 << 6)
#define kFPVolBytesTotalBit	 	(1 << 7)
#define kFPVolNameBit 			(1 << 8)
#define kFPVolExtBytesFreeBit 	(1 << 9)
#define kFPVolExtBytesTotalBit	(1 << 10)
#define kFPVolBlockSizeBit 	  	(1 << 11)

static int hf_afp_vol_bitmap_Attribute 		= -1;
static int hf_afp_vol_bitmap_Signature 		= -1;
static int hf_afp_vol_bitmap_CreateDate 	= -1;
static int hf_afp_vol_bitmap_ModDate 		= -1;
static int hf_afp_vol_bitmap_BackupDate 	= -1;
static int hf_afp_vol_bitmap_ID 			= -1;
static int hf_afp_vol_bitmap_BytesFree 		= -1;
static int hf_afp_vol_bitmap_BytesTotal 	= -1;
static int hf_afp_vol_bitmap_Name 			= -1;
static int hf_afp_vol_bitmap_ExtBytesFree 	= -1;
static int hf_afp_vol_bitmap_ExtBytesTotal 	= -1;
static int hf_afp_vol_bitmap_BlockSize 		= -1;

static int hf_afp_vol_attribute_ReadOnly                    = -1;
static int hf_afp_vol_attribute_HasVolumePassword			= -1;
static int hf_afp_vol_attribute_SupportsFileIDs             = -1;
static int hf_afp_vol_attribute_SupportsCatSearch           = -1;
static int hf_afp_vol_attribute_SupportsBlankAccessPrivs    = -1;
static int hf_afp_vol_attribute_SupportsUnixPrivs           = -1;
static int hf_afp_vol_attribute_SupportsUTF8Names           = -1;

static int hf_afp_dir_bitmap_Attribute		= -1;
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

static int hf_afp_file_bitmap_Attribute		 = -1;
static int hf_afp_file_bitmap_ParentDirID    = -1;
static int hf_afp_file_bitmap_CreateDate     = -1;
static int hf_afp_file_bitmap_ModDate        = -1;
static int hf_afp_file_bitmap_BackupDate     = -1;
static int hf_afp_file_bitmap_FinderInfo     = -1;
static int hf_afp_file_bitmap_LongName       = -1;
static int hf_afp_file_bitmap_ShortName      = -1;
static int hf_afp_file_bitmap_NodeID         = -1;
static int hf_afp_file_bitmap_OffspringCount = -1;
static int hf_afp_file_bitmap_UTF8Name       = -1;
static int hf_afp_file_bitmap_UnixPrivs      = -1;

static const value_string vol_bitmap_vals[] = {
  {kFPVolAttributeBit,          "VolAttribute"},
  {kFPVolSignatureBit,			"VolSignature"},
  {kFPVolCreateDateBit,			"VolCreateDate"},
  {kFPVolModDateBit,			"VolModDate"},
  {kFPVolBackupDateBit,			"VolBackupDate"},
  {kFPVolIDBit,					"VolID"},
  {kFPVolBytesFreeBit,			"VolBytesFree"},
  {kFPVolBytesTotalBit,			"VolBytesTotal"},
  {kFPVolNameBit,				"VolNameBit"},
  {kFPVolExtBytesFreeBit,		"VolExtBytesFree"},
  {kFPVolExtBytesTotalBit,		"VolExtBytesTotal"},
  {kFPVolBlockSizeBit,	  		"VolBlockSize"},
  {0,				 NULL } };

static const value_string flag_vals[] = {
  {0,	"Start" },
  {1,	"End" },
  {0,			NULL } };

static const value_string path_type_vals[] = {
  {1,	"Short names" },
  {2,	"Long names" },
  {3,	"Unicode names" },
  {0,			NULL } };

/*
  volume attribute from Apple AFP3.0.pdf 
  Table 1-3 p. 22
*/
#define kReadOnly 					(1 << 0)
#define kHasVolumePassword 			(1 << 1)
#define kSupportsFileIDs 			(1 << 2)
#define kSupportsCatSearch 			(1 << 3)
#define kSupportsBlankAccessPrivs 	(1 << 4)
#define kSupportsUnixPrivs 			(1 << 5)
#define kSupportsUTF8Names 			(1 << 6)

/*
  directory bitmap from Apple AFP3.0.pdf 
  Table 1-4 p. 31
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
#define kFPOffspringCountBit 	(1 << 9)
#define kFPOwnerIDBit 			(1 << 10)
#define kFPGroupIDBit 			(1 << 11)
#define kFPAccessRightsBit 		(1 << 12)
#define kFPUTF8NameBit 			(1 << 13)
#define kFPUnixPrivsBit 		(1 << 14)

/*
  file bitmap AFP3.0.pdf 
  Table 1-7 p. 36
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

#define kFPDataForkLenBit 			(1 << 9)
#define kFPRsrcForkLenBit 			(1 << 10)
#define kFPExtDataForkLenBit 		(1 << 11)
#define kFPLaunchLimitBit 			(1 << 12)

#define kFPExtRsrcForkLenBit 		(1 << 14)
#define kFPUnixPrivsBit_file 		(1 << 15)	/* :( */

#define hash_init_count 20

/* Hash functions */
static gint  afp_equal (gconstpointer v, gconstpointer v2);
static guint afp_hash  (gconstpointer v);
 
static guint afp_packet_init_count = 200;

typedef struct {
	guint32 conversation;
	guint16	seq;
} afp_request_key;
 
typedef struct {
	guint8	command;
} afp_request_val;
 
static GHashTable *afp_request_hash = NULL;
static GMemChunk *afp_request_keys = NULL;
static GMemChunk *afp_request_vals = NULL;

/* Hash Functions */
static gint  afp_equal (gconstpointer v, gconstpointer v2)
{
	afp_request_key *val1 = (afp_request_key*)v;
	afp_request_key *val2 = (afp_request_key*)v2;

	if (val1->conversation == val2->conversation &&
			val1->seq == val2->seq) {
		return 1;
	}
	return 0;
}

static guint afp_hash  (gconstpointer v)
{
        afp_request_key *afp_key = (afp_request_key*)v;
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
	
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_Attribute, 		tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_Signature, 		tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_CreateDate, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_ModDate, 		tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_BackupDate, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_ID, 			tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_BytesFree, 		tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_BytesTotal, 	tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_vol_bitmap_Name, 			tvb, offset, 2,FALSE);
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
                                                                               
	return bitmap;                                                             
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
		proto_tree_add_item(tree, hf_afp_vol_creation_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPVolModDateBit)) {
		proto_tree_add_item(tree, hf_afp_vol_modification_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPVolBackupDateBit)) {
		proto_tree_add_item(tree, hf_afp_vol_backup_date,tvb, offset, 4, FALSE);
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
		proto_tree_add_item(tree, hf_afp_bitmap_offset,tvb, offset, 2, FALSE);
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
	int len;

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
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_Attribute      , tvb, offset, 2,FALSE);  
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ParentDirID    , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_CreateDate     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ModDate        , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_BackupDate     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_FinderInfo     , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_LongName       , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_ShortName      , tvb, offset, 2,FALSE);
	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_NodeID         , tvb, offset, 2,FALSE);

	proto_tree_add_item(sub_tree, hf_afp_file_bitmap_UTF8Name	   , tvb, offset, 2,FALSE);

	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_UnixPrivs      , tvb, offset, 2,FALSE);

	return bitmap;
}

/* -------------------------- */
static gint
parse_file_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	guint16 lnameoff = 0;
	guint16 snameoff = 0;
	guint16 unameoff = 0;
	gint 	max_offset = 0;

	gint 	org_offset = offset;

	if ((bitmap & kFPAttributeBit)) {
		offset += 2;
	}
	if ((bitmap & kFPParentDirIDBit)) {
		proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
		offset += 4;
	}
	if ((bitmap & kFPCreateDateBit)) {
		proto_tree_add_item(tree, hf_afp_creation_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPModDateBit)) {
		proto_tree_add_item(tree, hf_afp_modification_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPBackupDateBit)) {
		proto_tree_add_item(tree, hf_afp_backup_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPFinderInfoBit)) {
		proto_tree_add_item(tree, hf_afp_finder_info,tvb, offset, 32, FALSE);
		offset += 32;
	}
	if ((bitmap & kFPLongNameBit)) {
	gint tp_ofs;
	guint8 len;
		lnameoff = tvb_get_ntohs(tvb, offset);
		if (lnameoff) {
			tp_ofs = lnameoff +org_offset;
			proto_tree_add_item(tree, hf_afp_bitmap_offset,tvb, offset, 2, FALSE);
			len = tvb_get_guint8(tvb, tp_ofs);
			proto_tree_add_item(tree, hf_afp_path_name, tvb, tp_ofs, 1,FALSE);
			tp_ofs += len +1;
			max_offset = (tp_ofs >max_offset)?tp_ofs:max_offset;
		}
		offset += 2;
	}
	if ((bitmap & kFPShortNameBit)) {
		snameoff = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_bitmap_offset,tvb, offset, 2, FALSE);
		offset += 2;
	}
	if ((bitmap & kFPNodeIDBit)) {
		proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4,FALSE);
		offset += 4;
	}

	return offset;
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
	
	proto_tree_add_item(sub_tree, hf_afp_dir_bitmap_Attribute      , tvb, offset, 2,FALSE);  
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
static gint
parse_dir_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	guint16 lnameoff = 0;
	guint16 snameoff = 0;
	guint16 unameoff = 0;
	gint 	max_offset = 0;

	gint 	org_offset = offset;

	if ((bitmap & kFPAttributeBit)) {
		offset += 2;
	}
	if ((bitmap & kFPParentDirIDBit)) {
		proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
		offset += 4;
	}
	if ((bitmap & kFPCreateDateBit)) {
		proto_tree_add_item(tree, hf_afp_creation_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPModDateBit)) {
		proto_tree_add_item(tree, hf_afp_modification_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPBackupDateBit)) {
		proto_tree_add_item(tree, hf_afp_backup_date,tvb, offset, 4, FALSE);
		offset += 4;
	}
	if ((bitmap & kFPFinderInfoBit)) {
		proto_tree_add_item(tree, hf_afp_finder_info,tvb, offset, 32, FALSE);
		offset += 32;
	}
	if ((bitmap & kFPLongNameBit)) {
		gint tp_ofs;
		guint8 len;
		lnameoff = tvb_get_ntohs(tvb, offset);
		if (lnameoff) {
			tp_ofs = lnameoff +org_offset;
			proto_tree_add_item(tree, hf_afp_bitmap_offset,tvb, offset, 2, FALSE);
			len = tvb_get_guint8(tvb, tp_ofs);
			proto_tree_add_item(tree, hf_afp_path_name, tvb, tp_ofs, 1,FALSE);
			tp_ofs += len +1;
			max_offset = (tp_ofs >max_offset)?tp_ofs:max_offset;
		}
		offset += 2;
	}
	if ((bitmap & kFPShortNameBit)) {
		snameoff = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_afp_bitmap_offset,tvb, offset, 2, FALSE);
		offset += 2;
	}
	if ((bitmap & kFPNodeIDBit)) {
		proto_tree_add_item(tree, hf_afp_file_id, tvb, offset, 4,FALSE);
		offset += 4;
	}
	if ((bitmap & kFPOffspringCountBit)) {
		proto_tree_add_item(tree, hf_afp_dir_off_spring, tvb, offset, 2,FALSE);
		offset += 2;		/* error in AFP3.0.pdf */
	}
	if ((bitmap & kFPOwnerIDBit)) {
		offset += 4;
	}
	if ((bitmap & kFPGroupIDBit)) {
		offset += 4;
	}
	if ((bitmap & kFPAccessRightsBit)) {
		offset += 4;
	}
	if ((bitmap & kFPUTF8NameBit)) {
		offset += 2;
	}
	if ((bitmap & kFPUnixPrivsBit)) {
		unameoff = tvb_get_ntohs(tvb, offset);
		offset += 4;
	}
	return (max_offset)?max_offset:offset;
}

/* -------------------------- */
static gchar *
name_in_bitmap(tvbuff_t *tvb, gint *offset, guint16 bitmap)
{
	gchar *name;
	gint 	org_offset = *offset;
	guint16 nameoff;
	guint8  len;
	gint	tp_ofs;
	
	name = NULL;
	if ((bitmap & kFPAttributeBit)) 
		*offset += 2;
	if ((bitmap & kFPParentDirIDBit))
		*offset += 4;
	if ((bitmap & kFPCreateDateBit)) 
		*offset += 4;
	if ((bitmap & kFPModDateBit))
		*offset += 4;
	if ((bitmap & kFPBackupDateBit)) 
		*offset += 4;
	if ((bitmap & kFPFinderInfoBit)) 
		*offset += 32;
	
	if ((bitmap & kFPLongNameBit)) {
		nameoff = tvb_get_ntohs(tvb, *offset);
		if (nameoff) {
			tp_ofs = nameoff +org_offset;
			len = tvb_get_guint8(tvb, tp_ofs);
			tp_ofs++;
			if (!(name = g_malloc(len +1)))
				return name;
			tvb_memcpy(tvb, name, tp_ofs, len);
			*(name +len) = 0;
			return name;
		}
	}
	/* short name ? */
	return name;
}

/* -------------------------- */
static gchar *
name_in_dbitmap(tvbuff_t *tvb, gint offset, guint16 bitmap)
{
	gchar *name;
	
	name = name_in_bitmap(tvb, &offset, bitmap);
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
	
	name = name_in_bitmap(tvb, &offset, bitmap);
	if (name != NULL)
		return name;
	/*
		check UTF8 name 
	*/
	
	return name;
}

/* -------------------------- */
static gint
decode_vol_did_file_dir_bitmap (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;
	
	decode_dir_bitmap(tree, tvb, offset);
	offset += 2;
	
	return offset;
}

/* -------------------------- */
static gint
decode_name (proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	int len;

	proto_tree_add_item(tree, hf_afp_path_type, tvb, offset, 1,FALSE);
	offset += 1;

	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_path_name, tvb, offset, 1,FALSE);
	offset += len +1;

	return offset;
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
#if 0	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		gchar	*func_str;

		if ((func_str = match_strval(afp_command, CommandCode_vals)))
		{
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", func_str, aspinfo->reply?"reply":"");
		}
	}
#endif	
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
dissect_reply_afp_open_vol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	bitmap = decode_vol_bitmap(tree, tvb, offset);
	offset += 2;
	offset = parse_vol_bitmap(tree, tvb, offset, bitmap);

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
	
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_did, tvb, offset, 4,FALSE);
	offset += 4;

	decode_file_bitmap(tree, tvb, offset);
	offset += 2;
	if (tree) {
		item = proto_tree_add_item(tree, hf_afp_access_mode, tvb, offset, 2,FALSE);
		sub_tree = proto_item_add_subtree(item, ett_afp_access_mode);
	}
	item = proto_tree_add_item(sub_tree, hf_afp_access_read      , tvb, offset, 2,FALSE);
	item = proto_tree_add_item(sub_tree, hf_afp_access_write     , tvb, offset, 2,FALSE);
	item = proto_tree_add_item(sub_tree, hf_afp_access_deny_read , tvb, offset, 2,FALSE);
	item = proto_tree_add_item(sub_tree, hf_afp_access_deny_write, tvb, offset, 2,FALSE);

	offset += 2;

	offset = decode_name(tree,tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_open_fork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	int f_bitmap;

	f_bitmap = decode_file_bitmap(tree, tvb, offset);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	offset = parse_file_bitmap(tree, tvb, offset, f_bitmap);

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

	offset = decode_name(tree,tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_enumerate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
  	proto_tree *sub_tree = NULL;
  	proto_item *item;
	int count;
	int f_bitmap;
	int d_bitmap;
	guint8	flags;
	guint8	size;
	gint	org;
	int i;
	gchar *name;
	
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
	/* loop */
	if (tree) for (i = 0; i < count; i++) {
		org = offset;
		name = NULL;
		size = tvb_get_guint8(tvb, offset);
		flags = tvb_get_guint8(tvb, offset +1);

		if (flags) {
			name = name_in_dbitmap(tvb, offset +2, d_bitmap);
		}
		else {
			name = name_in_fbitmap(tvb, offset +2, f_bitmap);
		}
		if (!name) {
			if (!(name = g_malloc(50))) { /* no memory ! */
			}
			snprintf(name, 50,"line %d", i +1);
		}
		item = proto_tree_add_text(sub_tree, tvb, offset, size, name);
		tree = proto_item_add_subtree(item, ett_afp_enumerate_line);

		proto_tree_add_item(tree, hf_afp_struct_size, tvb, offset, 1,FALSE);
		offset++;

		proto_tree_add_item(tree, hf_afp_file_flag, tvb, offset, 1,FALSE);
		offset++;
		if (flags) {
			offset = parse_dir_bitmap(tree, tvb, offset, d_bitmap);
		}
		else {
			offset = parse_file_bitmap(tree, tvb, offset, f_bitmap);
		}
		if ((offset & 1)) 
			PAD(1);
		offset = org +size;		/* play safe */
		g_free((gpointer)name);
	}	
	return(offset);

}

/* **************************/
static gint
dissect_query_afp_get_vol_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	if (!tree)
		return offset;
	PAD(1)
	proto_tree_add_item(tree, hf_afp_vol_id, tvb, offset, 2,FALSE);
	offset += 2;

	decode_vol_bitmap(tree, tvb, offset);
	offset += 2;
	
	return offset;	
}

/* ------------------------ */
static gint
dissect_reply_afp_get_vol_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	guint16 bitmap;

	if (!tree)
		return offset;
	bitmap = decode_vol_bitmap(tree, tvb, offset);
	offset += 2;

	offset = parse_vol_bitmap(tree, tvb, offset, bitmap);

	return offset;
}

/* ***************************/
static gint
dissect_query_afp_login(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	int len;
	
	if (!tree)
		return offset;
	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_AFPVersion, tvb, offset, 1,FALSE);
	offset += len +1;
	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_UAM, tvb, offset, 1,FALSE);
	offset += len +1;

	/* clear text */
	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_afp_user, tvb, offset, 1,FALSE);
	offset += len +1;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_afp_passwd, tvb, offset, len,FALSE);
	offset += len;

	return(offset);
}

/* ************************** */
static gint
dissect_query_afp_write(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	int len;
	
	if (!tree)
		return offset;
	proto_tree_add_item(tree, hf_afp_flag, tvb, offset, 1,FALSE);
	offset += 1;

	proto_tree_add_item(tree, hf_afp_ofork, tvb, offset, 2,FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_afp_offset, tvb, offset, 4,FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_afp_rw_count, tvb, offset, 4,FALSE);
	offset += 4;

	return offset;
}

/* ************************** */
static gint
dissect_query_afp_get_fldr_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	if (!tree)
		return offset;
	PAD(1);
	offset = decode_vol_did_file_dir_bitmap(tree, tvb, offset);

	offset = decode_name(tree, tvb, offset);

	return offset;
}

/* -------------------------- */
static gint
dissect_reply_afp_get_fldr_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
guint8	flags;
guint16 f_bitmap, d_bitmap;

	if (!tree)
		return offset;
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
		offset = parse_file_bitmap(tree, tvb, offset, f_bitmap);
	}
	return offset;
}

/* ************************** */
static void
dissect_afp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct aspinfo *aspinfo = pinfo->private_data;
	proto_tree      *afp_tree = NULL;
	proto_item	*ti;
	conversation_t	*conversation;
	gint		offset = 0;
	afp_request_key request_key, *new_request_key;
	afp_request_val *request_val;

	gchar	*func_str;

	guint8	afp_flags,afp_command;
	guint16 afp_requestid;
	gint32 	afp_code;
	guint32 afp_length;
	guint32 afp_reserved;
	int     len =  tvb_reported_length_remaining(tvb,0);
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AFP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	conversation = find_conversation(&pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	if (conversation == NULL)
	{
		conversation = conversation_new(&pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}

	request_key.conversation = conversation->index;	
	request_key.seq = aspinfo->seq;

	request_val = (afp_request_val *) g_hash_table_lookup(
								afp_request_hash, &request_key);

	if (!request_val && !aspinfo->reply)  {
		afp_command = tvb_get_guint8(tvb, offset);
		new_request_key = g_mem_chunk_alloc(afp_request_keys);
		*new_request_key = request_key;

		request_val = g_mem_chunk_alloc(afp_request_vals);
		request_val->command = tvb_get_guint8(tvb, offset);

		g_hash_table_insert(afp_request_hash, new_request_key,
								request_val);
	}

	if (!request_val) {	/* missing request */
		return;
	}

	afp_command = request_val->command;
	if (check_col(pinfo->cinfo, COL_INFO)) {
		gchar	*func_str;

		if ((func_str = match_strval(afp_command, CommandCode_vals)))
		{
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", func_str, aspinfo->reply?"reply":"");
		}
	}

	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_afp, tvb, offset, -1,FALSE);
		afp_tree = proto_item_add_subtree(ti, ett_afp);
	}
	if (!aspinfo->reply)  {
		proto_tree_add_uint(afp_tree, hf_afp_command, tvb,offset, 1, afp_command);
		offset++;
		switch(afp_command) {
		case AFP_BYTELOCK:
		case AFP_CLOSEVOL:
		case AFP_CLOSEDIR:
		case AFP_CLOSEFORK:
		case AFP_COPYFILE:
		case AFP_CREATEDIR:
		case AFP_CREATEFILE:
		case AFP_DELETE:
			break;
		case AFP_ENUMERATE:
			offset = dissect_query_afp_enumerate(tvb, pinfo, afp_tree, offset);break;
		case AFP_FLUSH:
		case AFP_FLUSHFORK:
		case AFP_GETFORKPARAM:
		case AFP_GETSRVINFO:
		case AFP_GETSRVPARAM:
			break;
		case AFP_GETVOLPARAM:
			offset = dissect_query_afp_get_vol_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_LOGIN:
			offset = dissect_query_afp_login(tvb, pinfo, afp_tree, offset);break;
		case AFP_LOGINCONT:
		case AFP_LOGOUT:
		case AFP_MAPID:
		case AFP_MAPNAME:
		case AFP_MOVE:
			break;
		case AFP_OPENVOL:
			offset = dissect_query_afp_open_vol(tvb, pinfo, afp_tree, offset);break;
		case AFP_OPENDIR:
			break;
		case AFP_OPENFORK:
			offset = dissect_query_afp_open_fork(tvb, pinfo, afp_tree, offset);break;
		case AFP_READ:
		case AFP_RENAME:
		case AFP_SETDIRPARAM:
		case AFP_SETFILEPARAM:
		case AFP_SETFORKPARAM:
		case AFP_SETVOLPARAM:
			break;
		case AFP_WRITE:
			offset = dissect_query_afp_write(tvb, pinfo, afp_tree, offset);break;
		case AFP_GETFLDRPARAM:
			offset = dissect_query_afp_get_fldr_param(tvb, pinfo, afp_tree, offset);break;
		case AFP_SETFLDRPARAM:
		case AFP_CHANGEPW:
		case AFP_GETSRVRMSG:
		case AFP_CREATEID:
		case AFP_DELETEID:
		case AFP_RESOLVEID:
		case AFP_EXCHANGEFILE:
		case AFP_CATSEARCH:
		case AFP_OPENDT:
		case AFP_CLOSEDT:
		case AFP_GETICON:
		case AFP_GTICNINFO:
		case AFP_ADDAPPL:
		case AFP_RMVAPPL:
		case AFP_GETAPPL:
		case AFP_ADDCMT:
		case AFP_RMVCMT:
		case AFP_GETCMT:
		case AFP_ADDICON:
			break;
 		}
	}
 	else {
 		switch(afp_command) {
 		case AFP_ENUMERATE:
 			offset = dissect_reply_afp_enumerate(tvb, pinfo, afp_tree, offset);break;
 		case AFP_OPENVOL:
 			offset = dissect_reply_afp_open_vol(tvb, pinfo, afp_tree, offset);break;
		case AFP_OPENFORK:
			offset = dissect_reply_afp_open_fork(tvb, pinfo, afp_tree, offset);break;
		case AFP_FLUSH:
		case AFP_FLUSHFORK:
		case AFP_GETFORKPARAM:
		case AFP_GETSRVINFO:
		case AFP_GETSRVPARAM:
			break;
		case AFP_GETVOLPARAM:
			offset = dissect_reply_afp_get_vol_param(tvb, pinfo, afp_tree, offset);break;
 		case AFP_GETFLDRPARAM:
 			offset = dissect_reply_afp_get_fldr_param(tvb, pinfo, afp_tree, offset);break;
		}
	}
	if (tree && offset < len)
		call_dissector(data_handle,tvb_new_subset(tvb, offset,-1,tvb_reported_length_remaining(tvb,offset)), pinfo, afp_tree);
}

static void afp_reinit( void)
{

	if (afp_request_hash)
		g_hash_table_destroy(afp_request_hash);
	if (afp_request_keys)
		g_mem_chunk_destroy(afp_request_keys);
	if (afp_request_vals)
		g_mem_chunk_destroy(afp_request_vals);

	afp_request_hash = g_hash_table_new(afp_hash, afp_equal);

	afp_request_keys = g_mem_chunk_new("afp_request_keys",
		sizeof(afp_request_key),
		afp_packet_init_count * sizeof(afp_request_key),
		G_ALLOC_AND_FREE);
	afp_request_vals = g_mem_chunk_new("afp_request_vals",
		sizeof(afp_request_val),
		afp_packet_init_count * sizeof(afp_request_val),
		G_ALLOC_AND_FREE);

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
	  { "pad",    		"afp.pad",    
		FT_NONE,   BASE_NONE, NULL, 0, 
		"Pad Byte",	HFILL }},

    { &hf_afp_AFPVersion,
      { "AFP Version",  "afp.AFPVersion",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"client AFP version", HFILL }},

    { &hf_afp_UAM,
      { "UAM",          "afp.UAM",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"USer Authentication method", HFILL }},

    { &hf_afp_user,
      { "user",         "afp.user",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"User", HFILL }},

    { &hf_afp_passwd,
      { "password",     "afp.passwd",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
      	"password", HFILL }},

    { &hf_afp_vol_bitmap,
      { "bitmap",         "afp.vol_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0 /* 0x0FFF*/,
      	"Volume bitmap", HFILL }},

	{ &hf_afp_vol_bitmap_Attribute,
      { "attribute",         "afp.vol_bitmap.attribute",
		FT_BOOLEAN, 16, NULL, kFPVolAttributeBit,
      	"Volume attribute", HFILL }},

	    { &hf_afp_vol_attribute, { "attribute",         "afp.vol_attribute",
			FT_UINT16, BASE_HEX, NULL, 0 , "Volume attribute", HFILL }},

	    { &hf_afp_vol_attribute_ReadOnly, 
	     { "read only",         "afp.vol_attribute.read_only",
		 FT_BOOLEAN, 16, NULL, kReadOnly,
      	 "Read only volume", HFILL }},

	    { &hf_afp_vol_attribute_HasVolumePassword,
	     { "volume password",         "afp.vol_attribute.passwd",
		 FT_BOOLEAN, 16, NULL, kHasVolumePassword,
      	 "Has a volume password", HFILL }},

	    { &hf_afp_vol_attribute_SupportsFileIDs,
 	     { "files ID",         "afp.vol_attribute.fileIDs",
		 FT_BOOLEAN, 16, NULL, kSupportsFileIDs,
      	 "Supports files ID", HFILL }},

	    { &hf_afp_vol_attribute_SupportsCatSearch,
	     { "cat search",         "afp.vol_attribute.cat_search",
		 FT_BOOLEAN, 16, NULL, kSupportsCatSearch,
      	 "Supports cat search call", HFILL }},

	    { &hf_afp_vol_attribute_SupportsBlankAccessPrivs,
	     { "blank access privs",         "afp.vol_attribute.blank_access_privs",
		 FT_BOOLEAN, 16, NULL, kSupportsBlankAccessPrivs,
      	 "Supports blank access priv.", HFILL }},

	    { &hf_afp_vol_attribute_SupportsUnixPrivs,
	    { "blank access privs",         "afp.vol_attribute.unix_privs",
		 FT_BOOLEAN, 16, NULL, kSupportsUnixPrivs,
      	 "Supports Unix access priv.", HFILL }},

	    { &hf_afp_vol_attribute_SupportsUTF8Names,
	    { "blank access privs",         "afp.vol_attribute.utf8_names",
		 FT_BOOLEAN, 16, NULL, kSupportsUTF8Names,
      	 "Supports UTF8 names.", HFILL }},

    { &hf_afp_vol_bitmap_Signature,
      { "signature",         "afp.vol_bitmap.signature",
		FT_BOOLEAN, 16, NULL, kFPVolSignatureBit,
      	"Volume signature", HFILL }},
    { &hf_afp_vol_bitmap_CreateDate,
      { "creation date",      "afp.vol_bitmap.create_date",
		FT_BOOLEAN, 16, NULL, kFPVolCreateDateBit,
      	"Volume creation date", HFILL }},
    { &hf_afp_vol_bitmap_ModDate,
      { "modification date",  "afp.vol_bitmap.mod_date",
		FT_BOOLEAN, 16, NULL, kFPVolModDateBit,
      	"Volume modification date", HFILL }},
    { &hf_afp_vol_bitmap_BackupDate,
      { "backup date",        "afp.vol_bitmap.backup_date",
		FT_BOOLEAN, 16, NULL, kFPVolBackupDateBit,
      	"Volume backup date", HFILL }},
    { &hf_afp_vol_bitmap_ID,
      { "ID",         "afp.vol_bitmap.id",
		FT_BOOLEAN, 16, NULL,  kFPVolIDBit,
      	"Volume ID", HFILL }},
    { &hf_afp_vol_bitmap_BytesFree,
      { "bytes free",         "afp.vol_bitmap.bytes_free",
		FT_BOOLEAN, 16, NULL,  kFPVolBytesFreeBit,
      	"Volume free bytes", HFILL }},
    { &hf_afp_vol_bitmap_BytesTotal,
      { "bytes total",         "afp.vol_bitmap.bytes_total",
		FT_BOOLEAN, 16, NULL,  kFPVolBytesTotalBit,
      	"Volume total bytes", HFILL }},
    { &hf_afp_vol_bitmap_Name,
      { "name",         "afp.vol_bitmap.name",
		FT_BOOLEAN, 16, NULL,  kFPVolNameBit,
      	"Volume name", HFILL }},
    { &hf_afp_vol_bitmap_ExtBytesFree,
      { "ex. bytes free",         "afp.vol_bitmap.ex_bytes_free",
		FT_BOOLEAN, 16, NULL,  kFPVolExtBytesFreeBit,
      	"Volume ext. free bytes", HFILL }},
    { &hf_afp_vol_bitmap_ExtBytesTotal,
      { "ex bytes total",         "afp.vol_bitmap.ex_bytes_total",
		FT_BOOLEAN, 16, NULL,  kFPVolExtBytesTotalBit,
      	"Volume ex. total byte", HFILL }},
    { &hf_afp_vol_bitmap_BlockSize,
      { "block size",         "afp.vol_bitmap.block_size",
		FT_BOOLEAN, 16, NULL,  kFPVolBlockSizeBit,
      	"Volume block size", HFILL }},

    { &hf_afp_dir_bitmap_Attribute,        
      { "attribute",         "afp.dir_bitmap.attribute",
	    FT_BOOLEAN, 16, NULL,  kFPAttributeBit,
      	"directory attribute", HFILL }},
    { &hf_afp_dir_bitmap_ParentDirID,	   
      { "DID",         "afp.dir_bitmap.did",
    	FT_BOOLEAN, 16, NULL,  kFPParentDirIDBit,
      	"parent directory ID", HFILL }},
    { &hf_afp_dir_bitmap_CreateDate,	   
      { "creation date",         "afp.dir_bitmap.create_date",
	    FT_BOOLEAN, 16, NULL,  kFPCreateDateBit,
      	"directory creation date", HFILL }},
    { &hf_afp_dir_bitmap_ModDate,		   
      { "modification date",         "afp.dir_bitmap.mod_date",
    	FT_BOOLEAN, 16, NULL,  kFPModDateBit,
      	"directory modification date", HFILL }},
    { &hf_afp_dir_bitmap_BackupDate,	   
      { "backup date",         "afp.dir_bitmap.backup_date",
	    FT_BOOLEAN, 16, NULL,  kFPBackupDateBit,
      	"directory backup date", HFILL }},
    { &hf_afp_dir_bitmap_FinderInfo,	   
      { "Finder info",         "afp.dir_bitmap.finder_info",
    	FT_BOOLEAN, 16, NULL,  kFPFinderInfoBit,
      	"directory finder info", HFILL }},
    { &hf_afp_dir_bitmap_LongName,		   
      { "long name",         "afp.dir_bitmap.long_name",
	    FT_BOOLEAN, 16, NULL,  kFPLongNameBit,
      	"directory long name", HFILL }},
    { &hf_afp_dir_bitmap_ShortName,		   
      { "short name",         "afp.dir_bitmap.short_name",
    	FT_BOOLEAN, 16, NULL,  kFPShortNameBit,
      	"directory short name", HFILL }},
    { &hf_afp_dir_bitmap_NodeID,		   
      { "file ID",         "afp.dir_bitmap.fid",
	    FT_BOOLEAN, 16, NULL,  kFPNodeIDBit,
      	"directory file ID", HFILL }},
    { &hf_afp_dir_bitmap_OffspringCount,   
      { "offspring count",         "afp.dir_bitmap.off_spring_count",
    	FT_BOOLEAN, 16, NULL,  kFPOffspringCountBit,
      	"directory offSpring count", HFILL }},
    { &hf_afp_dir_bitmap_OwnerID,		   
      { "owner id",         "afp.dir_bitmap.owner_id",
	    FT_BOOLEAN, 16, NULL,  kFPOwnerIDBit,
      	"directory owner id", HFILL }},
    { &hf_afp_dir_bitmap_GroupID,		   
      { "group id",         "afp.dir_bitmap.group_id",
    	FT_BOOLEAN, 16, NULL,  kFPGroupIDBit,
      	"directory group id", HFILL }},
    { &hf_afp_dir_bitmap_AccessRights,	   
      { "access rights",         "afp.dir_bitmap.access_rights",
	    FT_BOOLEAN, 16, NULL,  kFPAccessRightsBit,
      	"directory access rights", HFILL }},
    { &hf_afp_dir_bitmap_UTF8Name,		   
      { "UTF8 name",         "afp.dir_bitmap.UTF8_name",
    	FT_BOOLEAN, 16, NULL,  kFPUTF8NameBit,
      	"directory UTF8 name", HFILL }},
    { &hf_afp_dir_bitmap_UnixPrivs,		   
      { "unix privs",         "afp.dir_bitmap.unix_privs",
	    FT_BOOLEAN, 16, NULL,  kFPUnixPrivsBit,
      	"directory unix privs", HFILL }},

    { &hf_afp_file_bitmap_Attribute,        
      { "attribute",         "afp.file_bitmap.attribute",
	    FT_BOOLEAN, 16, NULL,  kFPAttributeBit,
      	"file attribute", HFILL }},
    { &hf_afp_file_bitmap_ParentDirID,	   
      { "DID",         "afp.file_bitmap.did",
    	FT_BOOLEAN, 16, NULL,  kFPParentDirIDBit,
      	"parent directory ID", HFILL }},
    { &hf_afp_file_bitmap_CreateDate,	   
      { "creation date",         "afp.file_bitmap.create_date",
	    FT_BOOLEAN, 16, NULL,  kFPCreateDateBit,
      	"file creation date", HFILL }},
    { &hf_afp_file_bitmap_ModDate,		   
      { "modification date",         "afp.file_bitmap.mod_date",
    	FT_BOOLEAN, 16, NULL,  kFPModDateBit,
      	"file modification date", HFILL }},
    { &hf_afp_file_bitmap_BackupDate,	   
      { "backup date",         "afp.file_bitmap.backup_date",
	    FT_BOOLEAN, 16, NULL,  kFPBackupDateBit,
      	"file backup date", HFILL }},
    { &hf_afp_file_bitmap_FinderInfo,	   
      { "Finder info",         "afp.file_bitmap.finder_info",
    	FT_BOOLEAN, 16, NULL,  kFPFinderInfoBit,
      	"file finder info", HFILL }},
    { &hf_afp_file_bitmap_LongName,		   
      { "long name",         "afp.file_bitmap.long_name",
	    FT_BOOLEAN, 16, NULL,  kFPLongNameBit,
      	"file long name", HFILL }},
    { &hf_afp_file_bitmap_ShortName,		   
      { "short name",         "afp.file_bitmap.short_name",
    	FT_BOOLEAN, 16, NULL,  kFPShortNameBit,
      	"file short name", HFILL }},
    { &hf_afp_file_bitmap_NodeID,		   
      { "file ID",         "afp.file_bitmap.fid",
	    FT_BOOLEAN, 16, NULL,  kFPNodeIDBit,
      	"file file ID", HFILL }},
    { &hf_afp_file_bitmap_UTF8Name,		   
      { "UTF8 name",         "afp.file_bitmap.UTF8_name",
    	FT_BOOLEAN, 16, NULL,  kFPUTF8NameBit,
      	"file UTF8 name", HFILL }},
    { &hf_afp_file_bitmap_UnixPrivs,		   
      { "unix privs",         "afp.file_bitmap.unix_privs",
	    FT_BOOLEAN, 16, NULL,  kFPUnixPrivsBit,
      	"file unix privs", HFILL }},

    { &hf_afp_vol_name,
      { "Volume",         "afp.vol_name",
	FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"Volume name", HFILL }},
    { &hf_afp_vol_id,
      { "volume id",         "afp.vol_id",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Volume id", HFILL }},
    { &hf_afp_vol_signature,
      { "signature",         "afp.vol_signature",
		FT_UINT16, BASE_DEC, VALS(vol_signature_vals), 0x0,
      	"Volume signature", HFILL }},
    { &hf_afp_bitmap_offset,
      { "offset",         "afp.bitmap_offset",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"name offset in packet", HFILL }},
    { &hf_afp_vol_creation_date,
      { "creation date",         "afp.vol_creation_date",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"volume creation date", HFILL }},
    { &hf_afp_vol_modification_date,
      { "modification date",         "afp.vol_modification_date",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"volume modification date", HFILL }},
    { &hf_afp_vol_backup_date,
      { "backup date",         "afp.vol_backup_date",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"volume backup date", HFILL }},
    { &hf_afp_vol_bytes_free,
      { "bytes free",         "afp.vol_bytes_free",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"free space", HFILL }},
    { &hf_afp_vol_bytes_total,
      { "bytes total",         "afp.vol_bytes_total",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"volume size ", HFILL }},
    { &hf_afp_vol_ex_bytes_free,
      { "ex. bytes free",         "afp.vol_ex_bytes_free",
		FT_UINT64, BASE_DEC, NULL, 0x0,
      	"ex. free space", HFILL }},
    { &hf_afp_vol_ex_bytes_total,
      { "ex. bytes total",         "afp.vol_ex_bytes_total",
		FT_UINT64, BASE_DEC, NULL, 0x0,
      	"ex. volume size ", HFILL }},
    { &hf_afp_vol_block_size,
      { "block size",         "afp.vol_block_size",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"volume block size", HFILL }},

    { &hf_afp_did,
      { "did",         "afp.did",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"parent directory id", HFILL }},

    { &hf_afp_dir_bitmap,
      { "dir bitmap",         "afp.dir_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0x0,
      	"directory bitmap", HFILL }},

    { &hf_afp_dir_off_spring,
      { "off spring",         "afp.dir_off_spring",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"directory offspring", HFILL }},

    { &hf_afp_creation_date,
      { "creation date",         "afp.creation_date",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"creation date", HFILL }},
    { &hf_afp_modification_date,
      { "modification date",         "afp.modification_date",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"modification date", HFILL }},
    { &hf_afp_backup_date,
      { "backup date",         "afp.backup_date",
		FT_UINT32, BASE_HEX, NULL, 0x0,
      	"backup date", HFILL }},

    { &hf_afp_finder_info,
      { "finder info",         "afp.finder_info",
		FT_BYTES, BASE_HEX, NULL, 0x0,
      	"finder info", HFILL }},

    { &hf_afp_file_id,
      { "file id",         "afp.file_id",
		FT_UINT32, BASE_DEC, NULL, 0x0,
      	"file/directory id", HFILL }},
    
    { &hf_afp_file_bitmap,
      { "file bitmap",         "afp.file_bitmap",
		FT_UINT16, BASE_HEX, NULL, 0x0,
      	"file bitmap", HFILL }},
    
    { &hf_afp_req_count,
      { "req count",         "afp.req_count",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Maximum number of structures returned", HFILL }},

    { & hf_afp_start_index, 
      { "start index",         "afp.start_index",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"first structure returned", HFILL }},
    
    { &hf_afp_max_reply_size,
      { "reply size",         "afp.reply_size",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"first structure returned", HFILL }},

    { &hf_afp_file_flag,
      { "dir",         "afp.flag",
		FT_BOOLEAN, 8, NULL, 0x80,
      	"is a dir", HFILL }},

    { &hf_afp_struct_size,
      { "struct size",         "afp.struct_size",
		FT_UINT8, BASE_DEC, NULL,0,
      	"sizeof of struct", HFILL }},
    
    { &hf_afp_flag,
      { "from",         "afp.flag",
		FT_UINT8, BASE_HEX, VALS(flag_vals), 0x80,
      	"offset is relative to start/end of the fork", HFILL }},

    { &hf_afp_ofork,
      { "fork",         "afp.ofork",
		FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Open fork reference number", HFILL }},

    { &hf_afp_offset,
      { "offset",         "afp.offset",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"offset ", HFILL }},
    
    { &hf_afp_rw_count,
      { "count",         "afp.rw_count",
		FT_INT32, BASE_DEC, NULL, 0x0,
      	"number of bytes to be written ", HFILL }},
      
    { &hf_afp_path_type,
      { "path type ",         "afp.path_type",
		FT_UINT8, BASE_HEX, VALS(path_type_vals), 0,
      	"type of names", HFILL }},

    { &hf_afp_path_name,
      { "Name ",  "afp.path_name",
		FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      	"path name", HFILL }},

    { &hf_afp_fork_type,
      { "ressource fork",         "afp.fork_type",
		FT_BOOLEAN, 8, NULL, 0x80,
      	"data/ressource fork", HFILL }},

    { &hf_afp_access_mode,
      { "access mode",         "afp.access",
		FT_UINT8, BASE_HEX, NULL, 0x0,
      	"fork access mode", HFILL }},
    { &hf_afp_access_read,
      { "read",         "afp.access.read",
    	FT_BOOLEAN, 8, NULL,  1,
      	"open for reading", HFILL }},
    { &hf_afp_access_write,
      { "write",         "afp.access.write",
    	FT_BOOLEAN, 8, NULL,  1,
      	"open for writing", HFILL }},
    { &hf_afp_access_deny_read,
      { "deny read",         "afp.access.deny_read",
    	FT_BOOLEAN, 8, NULL,  1,
      	"deny read", HFILL }},
    { &hf_afp_access_deny_write,
      { "deny write",         "afp.access.deny_write",
    	FT_BOOLEAN, 8, NULL,  1,
      	"deny write", HFILL }},

  };

  static gint *ett[] = {
    &ett_afp,
	&ett_afp_vol_bitmap,
	&ett_afp_vol_attribute,
	&ett_afp_dir_bitmap,
	&ett_afp_file_bitmap,
	&ett_afp_enumerate,
	&ett_afp_enumerate_line,
	&ett_afp_access_mode,
  };

  proto_afp = proto_register_protocol("AppleTalk Filing Protocol", "AFP", "afp");
  proto_register_field_array(proto_afp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_init_routine( &afp_reinit);

  register_dissector("afp", dissect_afp, proto_afp);
}

void
proto_reg_handoff_afp(void)
{
  data_handle = find_dissector("data");
}

/* -------------------------------
   end
*/
