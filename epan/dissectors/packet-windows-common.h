/* packet-windows-common.h
 * Declarations for dissecting various Windows data types
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_WINDOWS_COMMON_H__
#define __PACKET_WINDOWS_COMMON_H__

/*
 * DOS error codes used by other dissectors.
 * At least some of these are from the SMB X/Open spec, as errors for
 * the ERRDOS error class, but they might be error codes returned from
 * DOS.
 */
#define SMBE_badfunc 1             /* Invalid function (or system call) */
#define SMBE_badfile 2             /* File not found (pathname error) */
#define SMBE_badpath 3             /* Directory not found */
#define SMBE_nofids 4              /* Too many open files */
#define SMBE_noaccess 5            /* Access denied */
#define SMBE_badfid 6              /* Invalid fid */
#define SMBE_badmcb 7              /* Memory control blocks destroyed */
#define SMBE_nomem 8               /* Out of memory */
#define SMBE_badmem 9              /* Invalid memory block address */
#define SMBE_badenv 10             /* Invalid environment */
#define SMBE_badformat 11          /* Invalid format */
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
#define SMBE_nosuchshare 67        /* Share does not exist */
#define SMBE_filexists 80          /* File in operation already exists */
#define SMBE_invalidparam 87	   /* Invalid parameter */
#define SMBE_cannotopen 110        /* Cannot open the file specified */
#define SMBE_insufficientbuffer 122/* Insufficient buffer size */
#define SMBE_invalidname 123       /* Invalid name */
#define SMBE_unknownlevel 124      /* Unknown info level */
#define SMBE_alreadyexists 183     /* File already exists */
#define SMBE_badpipe 230           /* Named pipe invalid */
#define SMBE_pipebusy 231          /* All instances of pipe are busy */
#define SMBE_pipeclosing 232       /* named pipe close in progress */
#define SMBE_notconnected 233      /* No process on other end of named pipe */
#define SMBE_moredata 234          /* More data to be returned */
#define SMBE_nomoreitems 259       /* No more items */
#define SMBE_baddirectory 267      /* Invalid directory name in a path. */
#define SMBE_eas_didnt_fit 275     /* Extended attributes didn't fit */
#define SMBE_eas_nsup 282          /* Extended attributes not supported */
#define SMBE_notify_buf_small 1022 /* Buffer too small to return change notify. */
#define SMBE_serverunavailable 1722/* Server unavailable */
#define SMBE_unknownipc 2142
#define SMBE_noipc 66              /* don't support ipc */

/* These errors seem to be only returned by the NT printer driver system */

#define SMBE_invalidowner 1307	/* Invalid security descriptor owner */
#define SMBE_invalidsecuritydescriptor 1338 /* Invalid security descriptor */
#define SMBE_unknownprinterdriver 1797 /* Unknown printer driver */
#define SMBE_invalidprintername 1801   /* Invalid printer name */
#define SMBE_printeralreadyexists 1802 /* Printer already exists */
#define SMBE_invaliddatatype 1804      /* Invalid datatype */
#define SMBE_invalidenvironment 1805   /* Invalid environment */
#define SMBE_invalidformsize    1903   /* Invalid form size */
#define SMBE_printerdriverinuse 3001   /* Printer driver in use */

extern const value_string DOS_errors[];

/*
 * NT error codes used by other dissectors.
 */
extern const value_string NT_errors[];

extern const value_string ms_country_codes[];

int dissect_nt_64bit_time(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date);

int dissect_nt_sid(tvbuff_t *tvb, int offset, proto_tree *parent_tree, 
		   const char *name, char **sid_str, int hf_sid);

/* 
 * Stuff for dissecting NT access masks 
 */

/*
 * Access mask values
 */

/* Generic rights */

#define GENERIC_RIGHTS_MASK    0xF0000000

#define GENERIC_ALL_ACCESS     0x10000000
#define GENERIC_EXECUTE_ACCESS 0x20000000
#define GENERIC_WRITE_ACCESS   0x40000000
#define GENERIC_READ_ACCESS    0x80000000

/* Misc/reserved */

#define ACCESS_SACL_ACCESS     0x00800000
#define SYSTEM_SECURITY_ACCESS 0x01000000
#define MAXIMUM_ALLOWED_ACCESS 0x02000000

/* Standard rights */

#define STANDARD_RIGHTS_MASK 0x00FF0000

#define DELETE_ACCESS        0x00010000
#define READ_CONTROL_ACCESS  0x00020000
#define WRITE_DAC_ACCESS     0x00040000
#define WRITE_OWNER_ACCESS   0x00080000
#define SYNCHRONIZE_ACCESS   0x00100000

/* Specific rights */

#define SPECIFIC_RIGHTS_MASK 0x0000FFFF /* Specific rights defined per-object */

typedef void (nt_access_mask_fn_t)(tvbuff_t *tvb, gint offset,
				   proto_tree *tree, guint32 access);

/* Map generic access permissions to specific permissions */

struct generic_mapping {
	guint32 generic_read;
	guint32 generic_write;
	guint32 generic_execute;
	guint32 generic_all;
};

/* Map standard access permissions to specific permissions */

struct standard_mapping {
	guint32 std_read;
	guint32 std_write;
	guint32 std_execute;
	guint32 std_all;
};

struct access_mask_info {
	const char *specific_rights_name;
	nt_access_mask_fn_t *specific_rights_fn;
	struct generic_mapping *generic_mapping;
	struct standard_mapping *standard_mapping;
};

int
dissect_nt_access_mask(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, guint8 *drep, int hfindex,
		       struct access_mask_info *ami,
		       guint32 *perms);

int
dissect_nt_sec_desc(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *parent_tree, guint8 *drep,
		    gboolean len_supplied, int len,
		    struct access_mask_info *ami);

void
proto_do_register_windows_common(int proto_smb);

const char *
get_well_known_rid_name(guint32);

#endif

