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

/* Win32 errors.
 * These defines specify the WERR error codes often encountered in ms DCE/RPC
 * interfaces (those that do not return NT status that is)
 *
 * The list is generated from the samba doserr.h file by running :
(echo "#include \"doserr.h\"";echo "#define W_ERROR(x) x";cat doserr.h | grep "^#define WERR" | grep -v "FOOBAR" | sed -e "s/^#define[ \t]//" | while read WERR junk;do echo int foo${WERR}=${WERR}";" ; done ) | cpp | grep "^int foo" | sed -e "s/^int foo/#define /" -e "s/=/ /" -e "s/;$//"
 */
#define WERR_OK 0
#define WERR_BADFUNC 1
#define WERR_BADFILE 2
#define WERR_ACCESS_DENIED 5
#define WERR_BADFID 6
#define WERR_NOMEM 8
#define WERR_GENERAL_FAILURE 31
#define WERR_NOT_SUPPORTED 50
#define WERR_BAD_NETPATH 53
#define WERR_UNEXP_NET_ERR 59
#define WERR_PRINTQ_FULL 61
#define WERR_NO_SPOOL_SPACE 62
#define WERR_NO_SUCH_SHARE 67
#define WERR_FILE_EXISTS 80
#define WERR_BAD_PASSWORD 86
#define WERR_INVALID_PARAM 87
#define WERR_INSUFFICIENT_BUFFER 122
#define WERR_INVALID_NAME 123
#define WERR_UNKNOWN_LEVEL 124
#define WERR_OBJECT_PATH_INVALID 161
#define WERR_ALREADY_EXISTS 183
#define WERR_NO_MORE_ITEMS 259
#define WERR_MORE_DATA 234
#define WERR_CAN_NOT_COMPLETE 1003
#define WERR_NOT_FOUND 1168
#define WERR_INVALID_COMPUTERNAME 1210
#define WERR_INVALID_DOMAINNAME 1212
#define WERR_UNKNOWN_REVISION 1305
#define WERR_REVISION_MISMATCH 1306
#define WERR_INVALID_OWNER 1307
#define WERR_NO_SUCH_PRIVILEGE 1313
#define WERR_PRIVILEGE_NOT_HELD 1314
#define WERR_NO_SUCH_USER 1317
#define WERR_INVALID_SECURITY_DESCRIPTOR 1338
#define WERR_NO_SUCH_DOMAIN 1355
#define WERR_NO_SYSTEM_RESOURCES 1450
#define WERR_SERVER_UNAVAILABLE 1722
#define WERR_INVALID_FORM_NAME 1902
#define WERR_INVALID_FORM_SIZE 1903
#define WERR_ALREADY_SHARED 2118
#define WERR_BUF_TOO_SMALL 2123
#define WERR_JOB_NOT_FOUND 2151
#define WERR_DEST_NOT_FOUND 2152
#define WERR_NOT_LOCAL_DOMAIN 2320
#define WERR_DEVICE_NOT_AVAILABLE 4319
#define WERR_STATUS_MORE_ENTRIES 0x0105
#define WERR_PRINTER_DRIVER_ALREADY_INSTALLED 1795
#define WERR_UNKNOWN_PORT 1796
#define WERR_UNKNOWN_PRINTER_DRIVER 1797
#define WERR_UNKNOWN_PRINTPROCESSOR 1798
#define WERR_INVALID_SEPARATOR_FILE 1799
#define WERR_INVALID_PRIORITY 1800
#define WERR_INVALID_PRINTER_NAME 1801
#define WERR_PRINTER_ALREADY_EXISTS 1802
#define WERR_INVALID_PRINTER_COMMAND 1803
#define WERR_INVALID_DATATYPE 1804
#define WERR_INVALID_ENVIRONMENT 1805
#define WERR_UNKNOWN_PRINT_MONITOR 3000
#define WERR_PRINTER_DRIVER_IN_USE 3001
#define WERR_SPOOL_FILE_NOT_FOUND 3002
#define WERR_SPL_NO_STARTDOC 3003
#define WERR_SPL_NO_ADDJOB 3004
#define WERR_PRINT_PROCESSOR_ALREADY_INSTALLED 3005
#define WERR_PRINT_MONITOR_ALREADY_INSTALLED 3006
#define WERR_INVALID_PRINT_MONITOR 3007
#define WERR_PRINT_MONITOR_IN_USE 3008
#define WERR_PRINTER_HAS_JOBS_QUEUED 3009
#define WERR_CLASS_NOT_REGISTERED 0x40154
#define WERR_NO_SHUTDOWN_IN_PROGRESS 0x45c
#define WERR_SHUTDOWN_ALREADY_IN_PROGRESS 0x45b
#define WERR_NET_NAME_NOT_FOUND (2100)+210
#define WERR_DEVICE_NOT_SHARED (2100)+211
#define WERR_DFS_NO_SUCH_VOL (2100)+562
#define WERR_DFS_NO_SUCH_SHARE (2100)+565
#define WERR_DFS_NO_SUCH_SERVER (2100)+573
#define WERR_DFS_INTERNAL_ERROR (2100)+590
#define WERR_DFS_CANT_CREATE_JUNCT (2100)+569
#define WERR_DS_SERVICE_BUSY 0x0000200e
#define WERR_DS_SERVICE_UNAVAILABLE 0x0000200f
#define WERR_DS_NO_SUCH_OBJECT 0x00002030
#define WERR_DS_OBJ_NOT_FOUND 0x0000208d
#define WERR_DS_DRA_INVALID_PARAMETER 0x000020f5
#define WERR_DS_DRA_BAD_DN 0x000020f7
#define WERR_DS_DRA_BAD_NC 0x000020f8
#define WERR_DS_DRA_INTERNAL_ERROR 0x000020fa
#define WERR_DS_DRA_OUT_OF_MEM 0x000020fe
#define WERR_DS_SINGLE_VALUE_CONSTRAINT 0x00002081
#define WERR_DS_DRA_DB_ERROR 0x00002103
#define WERR_DS_DRA_NO_REPLICA 0x00002104
#define WERR_DS_DRA_ACCESS_DENIED 0x00002105
#define WERR_DS_DNS_LOOKUP_FAILURE 0x0000214c
#define WERR_DS_WRONG_LINKED_ATTRIBUTE_SYNTAX 0x00002150
#define WERR_SEC_E_ALGORITHM_MISMATCH 0x80090331

extern const value_string WERR_errors[];


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

