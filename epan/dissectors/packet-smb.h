/* packet-smb.h
 * Defines for SMB packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998, 1999 Gerald Combs
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

#ifndef __PACKET_SMB_H__
#define __PACKET_SMB_H__


WS_VAR_IMPORT gboolean sid_name_snooping;

/* SMB command codes, from the SNIA CIFS spec. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_VAR_IMPORT value_string_ext smb_cmd_vals_ext;
WS_VAR_IMPORT value_string_ext trans2_cmd_vals_ext;
WS_VAR_IMPORT value_string_ext nt_cmd_vals_ext;


#define SMB_COM_CREATE_DIRECTORY		0x00
#define SMB_COM_DELETE_DIRECTORY		0x01
#define SMB_COM_OPEN				0x02
#define SMB_COM_CREATE				0x03
#define SMB_COM_CLOSE				0x04
#define SMB_COM_FLUSH				0x05
#define SMB_COM_DELETE				0x06
#define SMB_COM_RENAME				0x07
#define SMB_COM_QUERY_INFORMATION		0x08
#define SMB_COM_SET_INFORMATION			0x09
#define SMB_COM_READ				0x0A
#define SMB_COM_WRITE				0x0B
#define SMB_COM_LOCK_BYTE_RANGE			0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE		0x0D
#define SMB_COM_CREATE_TEMPORARY		0x0E
#define SMB_COM_CREATE_NEW			0x0F
#define SMB_COM_CHECK_DIRECTORY			0x10
#define SMB_COM_PROCESS_EXIT			0x11
#define SMB_COM_SEEK				0x12
#define SMB_COM_LOCK_AND_READ			0x13
#define SMB_COM_WRITE_AND_UNLOCK		0x14
#define SMB_COM_READ_RAW			0x1A
#define SMB_COM_READ_MPX			0x1B
#define SMB_COM_READ_MPX_SECONDARY		0x1C
#define SMB_COM_WRITE_RAW			0x1D
#define SMB_COM_WRITE_MPX			0x1E
#define SMB_COM_WRITE_MPX_SECONDARY		0x1F
#define SMB_COM_WRITE_COMPLETE			0x20
#define SMB_COM_QUERY_SERVER			0x21
#define SMB_COM_SET_INFORMATION2		0x22
#define SMB_COM_QUERY_INFORMATION2		0x23
#define SMB_COM_LOCKING_ANDX			0x24
#define SMB_COM_TRANSACTION			0x25
#define SMB_COM_TRANSACTION_SECONDARY		0x26
#define SMB_COM_IOCTL				0x27
#define SMB_COM_IOCTL_SECONDARY			0x28
#define SMB_COM_COPY				0x29
#define SMB_COM_MOVE				0x2A
#define SMB_COM_ECHO				0x2B
#define SMB_COM_WRITE_AND_CLOSE			0x2C
#define SMB_COM_OPEN_ANDX			0x2D
#define SMB_COM_READ_ANDX			0x2E
#define SMB_COM_WRITE_ANDX			0x2F
#define SMB_COM_NEW_FILE_SIZE			0x30
#define SMB_COM_CLOSE_AND_TREE_DISC		0x31
#define SMB_COM_TRANSACTION2			0x32
#define SMB_COM_TRANSACTION2_SECONDARY		0x33
#define SMB_COM_FIND_CLOSE2			0x34
#define SMB_COM_FIND_NOTIFY_CLOSE		0x35
/* Used by Xenix/Unix		0x60-0x6E */
#define SMB_COM_TREE_CONNECT			0x70
#define SMB_COM_TREE_DISCONNECT			0x71
#define SMB_COM_NEGOTIATE			0x72
#define SMB_COM_SESSION_SETUP_ANDX		0x73
#define SMB_COM_LOGOFF_ANDX			0x74
#define SMB_COM_TREE_CONNECT_ANDX		0x75
#define SMB_COM_QUERY_INFORMATION_DISK		0x80
#define SMB_COM_SEARCH				0x81
#define SMB_COM_FIND				0x82
#define SMB_COM_FIND_UNIQUE			0x83
#define SMB_COM_FIND_CLOSE			0x84
#define SMB_COM_NT_TRANSACT			0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY		0xA1
#define SMB_COM_NT_CREATE_ANDX			0xA2
#define SMB_COM_NT_CANCEL			0xA4
#define SMB_COM_NT_RENAME			0xA5
#define SMB_COM_OPEN_PRINT_FILE			0xC0
#define SMB_COM_WRITE_PRINT_FILE		0xC1
#define SMB_COM_CLOSE_PRINT_FILE		0xC2
#define SMB_COM_GET_PRINT_QUEUE			0xC3
#define SMB_COM_READ_BULK			0xD8
#define SMB_COM_WRITE_BULK			0xD9
#define SMB_COM_WRITE_BULK_DATA			0xDA

/* Error codes */

#define SMB_SUCCESS 0x00  /* All OK */
#define SMB_ERRDOS  0x01  /* DOS based error */
#define SMB_ERRSRV  0x02  /* server error, network file manager */
#define SMB_ERRHRD  0x03  /* Hardware style error */
#define SMB_ERRCMD  0x04  /* Not an SMB format command */

/* Error codes for the ERRSRV class */

#define SMBE_error 1               /* Non specific error code */
#define SMBE_badpw 2               /* Bad password */
#define SMBE_badtype 3             /* reserved */
#define SMBE_access 4              /* No permissions to do the requested operation */
#define SMBE_invnid 5              /* tid invalid */
#define SMBE_invnetname 6          /* Invalid servername */
#define SMBE_invdevice 7           /* Invalid device */
#define SMBE_qfull 49              /* Print queue full */
#define SMBE_qtoobig 50            /* Queued item too big */
#define SMBE_qeof 51               /* EOF in print queue dump */
#define SMBE_invpfid 52            /* Invalid print file in smb_fid */
#define SMBE_smbcmd 64             /* Unrecognised command */
#define SMBE_srverror 65           /* smb server internal error */
#define SMBE_filespecs 67          /* fid and pathname invalid combination */
#define SMBE_badlink 68
#define SMBE_badpermits 69         /* Access specified for a file is not valid */
#define SMBE_badpid 70
#define SMBE_setattrmode 71        /* attribute mode invalid */
#define SMBE_paused 81             /* Message server paused */
#define SMBE_msgoff 82             /* Not receiving messages */
#define SMBE_noroom 83             /* No room for message */
#define SMBE_rmuns 87              /* too many remote usernames */
#define SMBE_timeout 88            /* operation timed out */
#define SMBE_noresource  89        /* No resources currently available for request. */
#define SMBE_toomanyuids 90        /* too many userids */
#define SMBE_baduid 91             /* bad userid */
#define SMBE_useMPX 250            /* temporarily unable to use raw mode, use MPX mode */
#define SMBE_useSTD 251            /* temporarily unable to use raw mode, use standard mode */
#define SMBE_contMPX 252           /* resume MPX mode */
#define SMBE_badPW 253             /* Check this out ... */
#define SMBE_nosupport 0xFFFF
#define SMBE_unknownsmb 22         /* from NT 3.5 response */

/* Error codes for the ERRHRD class */

#define SMBE_nowrite 19     /* read only media */
#define SMBE_badunit 20     /* Unknown device */
#define SMBE_notready 21    /* Drive not ready */
#define SMBE_badcmd 22      /* Unknown command */
#define SMBE_data 23        /* Data (CRC) error */
#define SMBE_badreq 24      /* Bad request structure length */
#define SMBE_seek 25        /* Seek error */
#define SMBE_badmedia 26    /* Unknown media type */
#define SMBE_badsector 27   /* Sector not found */
#define SMBE_nopaper 28     /* Printer out of paper */
#define SMBE_write 29       /* Write fault */
#define SMBE_read 30        /* Read fault */
#define SMBE_general 31     /* General failure */
#define SMBE_badshare 32    /* An open conflicts with an existing open */
#define SMBE_lock 33        /* Lock conflict or invalid mode, or unlock of
                               lock held by another process */
#define SMBE_wrongdisk 34   /* The wrong disk was found in a drive */
#define SMBE_FCBunavail 35  /* No FCBs are available to process request */
#define SMBE_sharebufexc 36 /* A sharing buffer has been exceeded */
#define SMBE_diskfull 39

/* Used for SMB Export Object feature */
typedef struct _smb_eo_t {
        guint8 cmd;
        int     tid,uid,fid;
        guint32  pkt_num;
        gchar   *hostname;
        gchar   *filename;
        int fid_type;
        gint64  end_of_file;
        gchar   *content_type;
        guint32  payload_len;
        const guint8 *payload_data;
        guint64 smb_file_offset;
        guint32 smb_chunk_len;
} smb_eo_t;

/* Strings that describes the SMB object type */
WS_VAR_IMPORT const value_string smb_fid_types[];

/* the information we need to keep around for NT transatcion commands */
typedef struct {
	int subcmd;
	int fid_type;
	guint32 ioctl_function;
} smb_nt_transact_info_t;

/* the information we need to keep around for transaction2 commands */
typedef struct {
	int subcmd;
	int info_level;
	gboolean resume_keys; /* if "return resume" keys set in T2 FIND_FIRST request */
	const char *name;
} smb_transact2_info_t;

/*
 * The information we need to save about a request in order to show the
 * frame number of the request in the dissection of the reply.
 */
#define SMB_SIF_TID_IS_IPC	0x0001
#define SMB_SIF_IS_CONTINUED	0x0002
typedef enum {
	SMB_EI_NONE,		/* Unassigned / NULL */
	SMB_EI_FID,		/* FID */
	SMB_EI_NTI,		/* smb_nt_transact_info_t * */
	SMB_EI_TRI,		/* smb_transact_info_t * */
	SMB_EI_T2I,		/* smb_transact2_info_t * */
	SMB_EI_TIDNAME,	/* tid tracking char * */
	SMB_EI_FILEDATA,	/* fid tracking */
	SMB_EI_FILENAME,	/* filename tracking */
	SMB_EI_UID,		/* smb_uid_t */
	SMB_EI_RWINFO,		/* read/write offset/count info */ 
	SMB_EI_LOCKDATA,	/* locking and x data */
	SMB_EI_RENAMEDATA,	/* rename data */
	SMB_EI_DIALECTS		/* negprot dialects */
} smb_extra_info_t;
typedef struct _smb_fid_into_t smb_fid_info_t;
typedef struct {
	guint32 frame_req, frame_res;
	nstime_t req_time;
	guint16 flags;
	guint8 cmd;
	void *extra_info;
	smb_extra_info_t extra_info_type;
	/* we save the fid in each transaction so that we can get fid filters
	   to match both request and response */
	gboolean fid_seen_in_request;
	guint16 fid;
} smb_saved_info_t;

/*
 * The information we need to save about a Transaction request in order
 * to dissect the reply; this includes information for use by the
 * Remote API and Mailslot dissectors.
 * XXX - have an additional data structure hung off of this by the
 * subdissectors?
 */
typedef struct {
	int subcmd;
	int trans_subcmd;
	int function;
        /* Unification of fid variable type (was int) */
        guint16 fid;
	guint16 lanman_cmd;
	guchar *param_descrip;  /* Keep these descriptors around */
	guchar *data_descrip;
	guchar *aux_data_descrip;
	int info_level;
} smb_transact_info_t;

/*
 * Subcommand type.
 */
#define TRANSACTION_PIPE	0
#define TRANSACTION_MAILSLOT	1

/* these are defines used to represent different types of TIDs.
   dont use the value 0 for any of these */
#define TID_NORMAL	1
#define TID_IPC		2

/* this is the structure which is associated with each conversation */
typedef struct conv_tables {
	/* these two tables are used to match requests with responses */
	GHashTable *unmatched;
	GHashTable *matched;

	/* This table is used to track TID->services for a conversation */
	GHashTable *tid_service;
        gboolean raw_ntlmssp;   /* Do extended security exc use raw ntlmssp */

	/* track fid to fidstruct (filename/openframe/closeframe */
	emem_tree_t *fid_tree;
        /* We'll use a GSL list instead */
        GSList  *GSL_fid_info;

	/* track tid to fidstruct (sharename/shareframe/unshareframe */
	emem_tree_t *tid_tree;

	/* track uid to username mappings */
	emem_tree_t *uid_tree;
} conv_tables_t;

typedef struct smb_info {
  guint8 cmd;
  int tid, pid, uid, mid;
  guint32 nt_status;
  gboolean unicode;		/* Are strings in this SMB Unicode? */
  gboolean request;		/* Is this a request? */
  gboolean unidir;
  int info_level;
  int info_count;
  smb_saved_info_t *sip;	/* smb_saved_info_t, if any, for this */
  conv_tables_t *ct;
} smb_info_t;

/*
 * Show file data for a read or write.
 */
extern int dissect_file_data(tvbuff_t *tvb, proto_tree *tree, int offset,
    guint16 bc, guint16 datalen);


#define SMB_FID_TYPE_UNKNOWN	0
#define SMB_FID_TYPE_FILE	1
#define SMB_FID_TYPE_DIR	2
#define SMB_FID_TYPE_PIPE	3

/* used for tracking filenames from rename request to response */
typedef struct _smb_rename_saved_info_t {
	char *old_name;
	char *new_name;
} smb_rename_saved_info_t;

/* used for tracking lock data between lock request/response */
typedef struct _smb_lock_info_t {
  struct _smb_lock_info_t *next;
	guint16 pid;
	guint64 offset;
	guint64 length;
} smb_lock_info_t;
typedef struct _smb_locking_saved_info_t {
	guint8 type;
	guint8 oplock_level;
	guint16 num_lock;
	guint16 num_unlock;
	smb_lock_info_t *locks;
	smb_lock_info_t *unlocks;
} smb_locking_saved_info_t;
/* used for tracking fid/tid to filename/sharename openedframe closedframe */
typedef struct _smb_fid_saved_info_t {
	char *filename;
	guint32 create_flags;
	guint32 access_mask;
	guint32 file_attributes;
	guint32 share_access;
	guint32 create_options;
	guint32 create_disposition;
} smb_fid_saved_info_t;
struct _smb_fid_into_t {
        guint16 tid,fid;
        /* The end_of_file will store the last registered offset or
           the reported end_of_file from the SMB protocol */
        gint64  end_of_file;
        /* These two were int */
	guint opened_in;
	guint closed_in;
	int type;
	smb_fid_saved_info_t *fsi;
};

/* used for tracking tid to sharename openedframe closedframe */
typedef struct _smb_tid_into_t {
	int opened_in;
	int closed_in;
	char *filename;
	int type;
} smb_tid_info_t;


/*
 * Dissect an smb FID
 */
extern smb_fid_info_t *dissect_smb_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int len, guint16 fid, gboolean is_created, gboolean is_closed, gboolean is_generated);

/*
 * Dissect named pipe state information.
 */
extern int dissect_ipc_state(tvbuff_t *tvb, proto_tree *parent_tree,
    int offset, gboolean setstate);

extern gboolean smb_dcerpc_reassembly;

extern int dissect_file_ext_attr(tvbuff_t *tvb, proto_tree *parent_tree, int offset);

extern const value_string create_disposition_vals[];

extern int dissect_nt_create_options(tvbuff_t *tvb, proto_tree *parent_tree, int offset);

extern int dissect_nt_share_access(tvbuff_t *tvb, proto_tree *parent_tree, int offset);

extern int dissect_smb_access_mask(tvbuff_t *tvb, proto_tree *parent_tree, int offset);

extern const value_string oa_open_vals[];
extern const value_string impersonation_level_vals[];

extern gboolean sid_display_hex;

extern int dissect_security_information_mask(tvbuff_t *tvb, proto_tree *parent_tree, int offset);

extern int dissect_qfsi_FS_VOLUME_INFO(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, guint16 *bcp, int unicode);
extern int dissect_qfsi_FS_SIZE_INFO(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, guint16 *bcp);
extern int dissect_qfsi_FS_DEVICE_INFO(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, guint16 *bcp);
extern int dissect_qfsi_FS_ATTRIBUTE_INFO(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, guint16 *bcp, int unicode);
extern int dissect_nt_quota(tvbuff_t *tvb, proto_tree *tree, int offset, guint16 *bcp);
extern int dissect_qfsi_FS_OBJECTID_INFO(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, guint16 *bcp);
extern int dissect_qfsi_FS_FULL_SIZE_INFO(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, guint16 *bcp);
extern int dissect_qfi_SMB_FILE_EA_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qfi_SMB_FILE_STREAM_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint16 *bcp, gboolean *trunc, int unicode);
extern int dissect_qfi_SMB_FILE_NAME_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qfi_SMB_FILE_STANDARD_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qfi_SMB_FILE_INTERNAL_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qsfi_SMB_FILE_POSITION_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qsfi_SMB_FILE_MODE_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qfi_SMB_FILE_ALIGNMENT_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qfi_SMB_FILE_COMPRESSION_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qfi_SMB_FILE_NETWORK_OPEN_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qfi_SMB_FILE_ATTRIBUTE_TAG_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qsfi_SMB_FILE_ALLOCATION_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_qsfi_SMB_FILE_ENDOFFILE_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);
extern int dissect_nt_notify_completion_filter(tvbuff_t *tvb, proto_tree *parent_tree, int offset);
extern int dissect_sfi_SMB_FILE_PIPE_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 *bcp, gboolean *trunc);

#endif
