/* smb.h
 * Defines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: smb.h,v 1.29 2001/12/05 08:20:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

/*
 * Don't include if already included
 */

#ifndef _SMB_H
#define _SMB_H

/* SMB command codes, from the SNIA CIFS spec. */

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

/* SMB X/Open error codes for the ERRDOS error class */
#define SMBE_badfunc 1             /* Invalid function (or system call) */
#define SMBE_badfile 2             /* File not found (pathname error) */
#define SMBE_badpath 3             /* Directory not found */
#define SMBE_nofids 4              /* Too many open files */
#define SMBE_noaccess 5            /* Access denied */
#define SMBE_badfid 6              /* Invalid fid */
#define SMBE_nomem 8               /* Out of memory */
#define SMBE_badmem 9              /* Invalid memory block address */
#define SMBE_badenv 10             /* Invalid environment */
#define SMBE_badaccess 12          /* Invalid open mode */
#define SMBE_baddata 13            /* Invalid data (only from ioctl call) */
#define SMBE_res 14 
#define SMBE_baddrive 15           /* Invalid drive */
#define SMBE_remcd 16              /* Attempt to delete current directory */
#define SMBE_diffdevice 17         /* rename/move across different filesystems */
#define SMBE_nofiles 18            /* no more files found in file search */
#define SMBE_badshare 32           /* Share mode on file conflict with open mode */
#define SMBE_lock 33               /* Lock request conflicts with existing lock */
#define SMBE_unsup 50              /* Request unsupported, returned by Win 95, RJS 20Jun98 */
#define SMBE_nosuchshare 67        /* Share does not exits */
#define SMBE_filexists 80          /* File in operation already exists */
#define SMBE_cannotopen 110        /* Cannot open the file specified */
#define SMBE_unknownlevel 124
#define SMBE_alreadyexists 183     /* File already exists */
#define SMBE_badpipe 230           /* Named pipe invalid */
#define SMBE_pipebusy 231          /* All instances of pipe are busy */
#define SMBE_pipeclosing 232       /* named pipe close in progress */
#define SMBE_notconnected 233      /* No process on other end of named pipe */
#define SMBE_moredata 234          /* More data to be returned */
#define SMBE_baddirectory 267      /* Invalid directory name in a path. */
#define SMBE_eas_didnt_fit 275     /* Extended attributes didn't fit */
#define SMBE_eas_nsup 282          /* Extended attributes not supported */
#define SMBE_notify_buf_small 1022 /* Buffer too small to return change notify. */
#define SMBE_unknownipc 2142
#define SMBE_noipc 66              /* don't support ipc */

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

#define SMBE_nowrite 19   /* read only media */
#define SMBE_badunit 20   /* Unknown device */
#define SMBE_notready 21  /* Drive not ready */
#define SMBE_badcmd 22    /* Unknown command */
#define SMBE_data 23      /* Data (CRC) error */
#define SMBE_badreq 24    /* Bad request structure length */
#define SMBE_seek 25
#define SMBE_badmedia 26
#define SMBE_badsector 27
#define SMBE_nopaper 28
#define SMBE_write 29 
#define SMBE_read 30 
#define SMBE_general 31 
#define SMBE_badshare 32 
#define SMBE_lock 33 
#define SMBE_wrongdisk 34
#define SMBE_FCBunavail 35
#define SMBE_sharebufexc 36
#define SMBE_diskfull 39

/*
 * The information we need to save about a request in order to show the
 * frame number of the request in the dissection of the reply.
 */
typedef struct {
	guint32 frame_req, frame_res;
	void *extra_info;
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
	int fid;
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

/* this is the structure which is associated with each conversation */
typedef struct conv_tables {
	/* these two tables are used to match requests with responses */
	GHashTable *unmatched;
	GHashTable *matched;
	/* this tables is used by DCERPC over SMB reassembly*/
	GHashTable *dcerpc_fid_to_frame;
} conv_tables_t;

typedef struct smb_info {
  int cmd, mid;
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
extern int dissect_file_data(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, guint16 bc, guint16 datalen);

/*
 * Add a FID to the protocol tree and the Info column.
 */
extern void add_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int len, guint16 fid);

/*
 * Dissect named pipe state information.
 */
extern int dissect_ipc_state(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, gboolean setstate);

extern gboolean smb_dcerpc_reassembly;
extern GHashTable *dcerpc_fragment_table;

#endif
