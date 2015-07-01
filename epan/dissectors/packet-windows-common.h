/* packet-windows-common.h
 * Declarations for dissecting various Windows data types
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_WINDOWS_COMMON_H__
#define __PACKET_WINDOWS_COMMON_H__

#include "ws_symbol_export.h"
#include "packet-dcerpc.h"

/* Win32 errors.
 * These defines specify the WERR error codes often encountered in ms DCE/RPC
 * interfaces (those that do not return NT status that is)
 *
 * The list is generated from the samba doserr.h file by running :
     (echo "#include \"doserr.h\"";echo "#define W_ERROR(x) x";cat doserr.h | grep "^#define WERR" | grep -v "FOOBAR" | sed -e "s/^#define[ \t]//" | while read WERR junk;do echo int foo${WERR}=${WERR}";" ; done ) | cpp | grep "^int foo" | sed -e "s/^int foo/#define /" -e "s/=/ /" -e "s/;$//"
 *
 * [11/18/2013] The WERR_errors list was hand-edited to have all values be decimal, and then sorted by value.
 *
 * [11/19/2013] XXX - The samba doserr.h file no longer contains any WERR related entries.
 *                    WERR_errors list below left as is for now.
 */
#define WERR_errors_VALUE_STRING_LIST(XXX)             \
    XXX( WERR_OK,                                   0) \
    XXX( WERR_BADFUNC,                              1) \
    XXX( WERR_BADFILE,                              2) \
    XXX( WERR_ACCESS_DENIED,                        5) \
    XXX( WERR_BADFID,                               6) \
    XXX( WERR_NOMEM,                                8) \
    XXX( WERR_GENERAL_FAILURE,                     31) \
    XXX( WERR_NOT_SUPPORTED,                       50) \
    XXX( WERR_BAD_NETPATH,                         53) \
    XXX( WERR_UNEXP_NET_ERR,                       59) \
    XXX( WERR_PRINTQ_FULL,                         61) \
    XXX( WERR_NO_SPOOL_SPACE,                      62) \
    XXX( WERR_NO_SUCH_SHARE,                       67) \
    XXX( WERR_FILE_EXISTS,                         80) \
    XXX( WERR_BAD_PASSWORD,                        86) \
    XXX( WERR_INVALID_PARAM,                       87) \
    XXX( WERR_INSUFFICIENT_BUFFER,                122) \
    XXX( WERR_INVALID_NAME,                       123) \
    XXX( WERR_UNKNOWN_LEVEL,                      124) \
    XXX( WERR_OBJECT_PATH_INVALID,                161) \
    XXX( WERR_ALREADY_EXISTS,                     183) \
    XXX( WERR_MORE_DATA,                          234) \
    XXX( WERR_NO_MORE_ITEMS,                      259) \
    XXX( WERR_STATUS_MORE_ENTRIES,                261) /* 0x0105 */ \
    XXX( WERR_CAN_NOT_COMPLETE,                  1003) \
    XXX( WERR_SHUTDOWN_ALREADY_IN_PROGRESS,      1115) /* 0x45b */  \
    XXX( WERR_NO_SHUTDOWN_IN_PROGRESS,           1116) /* 0x45c */  \
    XXX( WERR_NOT_FOUND,                         1168) \
    XXX( WERR_INVALID_COMPUTERNAME,              1210) \
    XXX( WERR_INVALID_DOMAINNAME,                1212) \
    XXX( WERR_UNKNOWN_REVISION,                  1305) \
    XXX( WERR_REVISION_MISMATCH,                 1306) \
    XXX( WERR_INVALID_OWNER,                     1307) \
    XXX( WERR_NO_SUCH_PRIVILEGE,                 1313) \
    XXX( WERR_PRIVILEGE_NOT_HELD,                1314) \
    XXX( WERR_NO_SUCH_USER,                      1317) \
    XXX( WERR_INVALID_SECURITY_DESCRIPTOR,       1338) \
    XXX( WERR_NO_SUCH_DOMAIN,                    1355) \
    XXX( WERR_NO_SYSTEM_RESOURCES,               1450) \
    XXX( WERR_TIMEOUT,                           1460) \
    XXX( WERR_SERVER_UNAVAILABLE,                1722) \
    XXX( WERR_PRINTER_DRIVER_ALREADY_INSTALLED,  1795) \
    XXX( WERR_UNKNOWN_PORT,                      1796) \
    XXX( WERR_UNKNOWN_PRINTER_DRIVER,            1797) \
    XXX( WERR_UNKNOWN_PRINTPROCESSOR,            1798) \
    XXX( WERR_INVALID_SEPARATOR_FILE,            1799) \
    XXX( WERR_INVALID_PRIORITY,                  1800) \
    XXX( WERR_INVALID_PRINTER_NAME,              1801) \
    XXX( WERR_PRINTER_ALREADY_EXISTS,            1802) \
    XXX( WERR_INVALID_PRINTER_COMMAND,           1803) \
    XXX( WERR_INVALID_DATATYPE,                  1804) \
    XXX( WERR_INVALID_ENVIRONMENT,               1805) \
    XXX( WERR_INVALID_FORM_NAME,                 1902) \
    XXX( WERR_INVALID_FORM_SIZE,                 1903) \
    XXX( WERR_ALREADY_SHARED,                    2118) \
    XXX( WERR_BUF_TOO_SMALL,                     2123) \
    XXX( WERR_JOB_NOT_FOUND,                     2151) \
    XXX( WERR_DEST_NOT_FOUND,                    2152) \
    XXX( WERR_NET_NAME_NOT_FOUND,                2310) /* (2100)+210 */ \
    XXX( WERR_DEVICE_NOT_SHARED,                 2311) /* (2100)+211 */ \
    XXX( WERR_SESSION_NOT_FOUND,                 2312) \
    XXX( WERR_FID_NOT_FOUND,                     2314) \
    XXX( WERR_NOT_LOCAL_DOMAIN,                  2320) \
    XXX( WERR_DFS_NO_SUCH_VOL,                   2662) /* (2100)+562 */ \
    XXX( WERR_DFS_NO_SUCH_SHARE,                 2665) /* (2100)+565 */ \
    XXX( WERR_DFS_CANT_CREATE_JUNCT,             2669) /* (2100)+569 */ \
    XXX( WERR_DFS_NO_SUCH_SERVER,                2673) /* (2100)+573 */ \
    XXX( WERR_DFS_INTERNAL_ERROR,                2690) /* (2100)+590 */ \
    XXX( WERR_UNKNOWN_PRINT_MONITOR,             3000) \
    XXX( WERR_PRINTER_DRIVER_IN_USE,             3001) \
    XXX( WERR_SPOOL_FILE_NOT_FOUND,              3002) \
    XXX( WERR_SPL_NO_STARTDOC,                   3003) \
    XXX( WERR_SPL_NO_ADDJOB,                     3004) \
    XXX( WERR_PRINT_PROCESSOR_ALREADY_INSTALLED, 3005) \
    XXX( WERR_PRINT_MONITOR_ALREADY_INSTALLED,   3006) \
    XXX( WERR_INVALID_PRINT_MONITOR,             3007) \
    XXX( WERR_PRINT_MONITOR_IN_USE,              3008) \
    XXX( WERR_PRINTER_HAS_JOBS_QUEUED,           3009) \
    XXX( WERR_DEVICE_NOT_AVAILABLE,              4319) \
    XXX( WERR_INVALID_STATE,                     5023) \
    XXX( WERR_DS_SERVICE_BUSY,                   8206) /* 0x0000200e */ \
    XXX( WERR_DS_SERVICE_UNAVAILABLE,            8207) /* 0x0000200f */ \
    XXX( WERR_DS_NO_SUCH_OBJECT,                 8240) /* 0x00002030 */ \
    XXX( WERR_DS_SINGLE_VALUE_CONSTRAINT,        8321) /* 0x00002081 */ \
    XXX( WERR_DS_OBJ_NOT_FOUND,                  8333) /* 0x0000208d */ \
    XXX( WERR_DS_DRA_INVALID_PARAMETER,          8437) /* 0x000020f5 */ \
    XXX( WERR_DS_DRA_BAD_DN,                     8439) /* 0x000020f7 */ \
    XXX( WERR_DS_DRA_BAD_NC,                     8440) /* 0x000020f8 */ \
    XXX( WERR_DS_DRA_INTERNAL_ERROR,             8442) /* 0x000020fa */ \
    XXX( WERR_DS_DRA_OUT_OF_MEM,                 8446) /* 0x000020fe */ \
    XXX( WERR_DS_DRA_DB_ERROR,                   8451) /* 0x00002103 */ \
    XXX( WERR_DS_DRA_NO_REPLICA,                 8452) /* 0x00002104 */ \
    XXX( WERR_DS_DRA_ACCESS_DENIED,              8453) /* 0x00002105 */ \
    XXX( WERR_DS_DNS_LOOKUP_FAILURE,             8524) /* 0x0000214c */ \
    XXX( WERR_DS_WRONG_LINKED_ATTRIBUTE_SYNTAX,  8528) /* 0x00002150 */ \
    XXX( WERR_CLASS_NOT_REGISTERED,            262484) /* 0x00040154 */  \
    XXX( WERR_SEC_E_ALGORITHM_MISMATCH,    2148074289U)/* 0x80090331 */

#if 0  /* WERR_... symbols not referenced within Wireshark */
VALUE_STRING_ENUM2(WERR_errors);
#endif
VALUE_STRING_ARRAY2_GLOBAL_DCL(WERR_errors);  /* XXX: Remove once all PIDL generated dissectors ref WERR_errors_ext */
extern value_string_ext WERR_errors_ext;

/*
 * DOS error codes used by other dissectors.
 * At least some of these are from the SMB X/Open spec, as errors for
 * the ERRDOS error class, but they might be error codes returned from
 * DOS.
 */

#define DOS_errors_VALUE_STRING_LIST(XXX) \
    XXX( SMBE_DOS_success,                           0, "Success") \
    XXX( SMBE_DOS_badfunc,                           1, "Invalid function (or system call)") \
    XXX( SMBE_DOS_badfile,                           2, "File not found (pathname error)") \
    XXX( SMBE_DOS_badpath,                           3, "Directory not found") \
    XXX( SMBE_DOS_nofids,                            4, "Too many open files") \
    XXX( SMBE_DOS_noaccess,                          5, "Access denied") \
    XXX( SMBE_DOS_badfid,                            6, "Invalid fid") \
    XXX( SMBE_DOS_badmcb,                            7, "Memory control blocks destroyed") /* ??? */ \
    XXX( SMBE_DOS_nomem,                             8, "Out of memory") \
    XXX( SMBE_DOS_badmem,                            9, "Invalid memory block address") \
    XXX( SMBE_DOS_badenv,                           10, "Invalid environment") \
    XXX( SMBE_DOS_badformat,                        11, "Invalid format")  /* ??? */ \
    XXX( SMBE_DOS_badaccess,                        12, "Invalid open mode") \
    XXX( SMBE_DOS_baddata,                          13, "Invalid data (only from ioctl call)") \
    XXX( SMBE_DOS_res,                              14, "Reserved error code?")              /* out of memory ? */ \
    XXX( SMBE_DOS_baddrive,                         15, "Invalid drive") \
    XXX( SMBE_DOS_remcd,                            16, "Attempt to delete current directory") \
    XXX( SMBE_DOS_diffdevice,                       17, "Rename/move across different filesystems") \
    XXX( SMBE_DOS_nofiles,                          18, "No more files found in file search") \
    XXX( SMBE_DOS_general,                          31, "General failure")                   /* Also "SMBE_HRD" */ \
    XXX( SMBE_DOS_badshare,                         32, "Share mode on file conflict with open mode") \
    XXX( SMBE_DOS_lock,                             33, "Lock request conflicts with existing lock") \
    XXX( SMBE_DOS_unsup,                            50, "Request unsupported, returned by Win 95") /* RJS 20Jun98 */ \
    XXX( SMBE_DOS_netnamedel,                       64, "Network name deleted or not available") \
    XXX( SMBE_DOS_noipc,                            66, "Don't support ipc")   \
    XXX( SMBE_DOS_nosuchshare,                      67, "Requested share does not exist") \
    XXX( SMBE_DOS_filexists,                        80, "File in operation already exists") \
    XXX( SMBE_DOS_invalidparam,                     87, "Invalid parameter") \
    XXX( SMBE_DOS_cannotopen,                      110, "Cannot open the file specified") \
    XXX( SMBE_DOS_bufferoverflow,                  111, "Buffer overflow") \
    XXX( SMBE_DOS_insufficientbuffer,              122, "Insufficient buffer") \
    XXX( SMBE_DOS_invalidname,                     123, "Invalid name") \
    XXX( SMBE_DOS_unknownlevel,                    124, "Unknown info level") \
    XXX( SMBE_DOS_notlocked,                       158, "This region is not locked by this locking context.") \
    XXX( SMBE_DOS_invalidpath,                     161, "Invalid Path") \
    XXX( SMBE_DOS_cancelviolation,                 173, "Cancel violation") \
    XXX( SMBE_DOS_noatomiclocks,                   174, "No atomic clocks") \
    XXX( SMBE_DOS_alreadyexists,                   183, "File already exists") /* 'rename" ? */ \
    XXX( SMBE_DOS_badpipe,                         230, "Named pipe invalid") \
    XXX( SMBE_DOS_pipebusy,                        231, "All instances of pipe are busy") \
    XXX( SMBE_DOS_pipeclosing,                     232, "Named pipe close in progress") \
    XXX( SMBE_DOS_notconnected,                    233, "No process on other end of named pipe") \
    XXX( SMBE_DOS_moredata,                        234, "More data to be returned") \
    XXX( SMBE_DOS_eainconsistent,                  255, "ea inconsistent") /* from EMC */ \
    XXX( SMBE_DOS_nomoreitems,                     259, "No more items") \
    XXX( SMBE_DOS_baddirectory,                    267, "Invalid directory name in a path.") \
    XXX( SMBE_DOS_eas_didnt_fit,                   275, "Extended attributes didn't fit") \
    XXX( SMBE_DOS_eas_nsup,                        282, "Extended attributes not supported") \
    XXX( SMBE_DOS_notify_buf_small,               1022, "Buffer too small to return change notify.") \
    XXX( SMBE_DOS_invalidowner,                   1307, "Invalid security descriptor owner") /* NT printer driver system only */ \
    XXX( SMBE_DOS_logonfailure,                   1326, "Unknown username or bad password") \
    XXX( SMBE_DOS_invalidsecuritydescriptor,      1338, "Invalid security descriptor")       /* NT printer driver system only */ \
    XXX( SMBE_DOS_serverunavailable,              1722, "Server unavailable") \
    XXX( SMBE_DOS_driveralreadyinstalled,         1795, "Printer driver already installed")  /* NT printer driver system only */ \
    XXX( SMBE_DOS_unknownprinterport,             1796, "Error unknown port")                /* NT printer driver system only */ \
    XXX( SMBE_DOS_unknownprinterdriver,           1797, "Unknown printer driver")            /* NT printer driver system only */ \
    XXX( SMBE_DOS_unknownprintprocessor,          1798, "Unknown print processor")           /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidseparatorfile,           1799, "Invalid separator file")            /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidjobpriority,             1800, "Invalid priority")                  /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidprintername,             1801, "Invalid printer name")              /* NT printer driver system only */ \
    XXX( SMBE_DOS_printeralreadyexists,           1802, "Printer already exists")            /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidprintercommand,          1803, "Invalid printer command")           /* NT printer driver system only */ \
    XXX( SMBE_DOS_invaliddatatype,                1804, "Invalid datatype")                  /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidenvironment,             1805, "Invalid environment")               /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidformsize,                1903, "Invalid form size")                 /* NT printer driver system only */ \
    XXX( SMBE_DOS_buftoosmall,                    2123, "Buffer too small") \
    XXX( SMBE_DOS_unknownipc,                     2142, "Unknown IPC Operation") \
    XXX( SMBE_DOS_nosuchprintjob,                 2151, "No such print job")                 /* NT printer driver system only ?? */ \
    XXX( SMBE_DOS_invgroup,                       2455, "Invalid Group") \
    XXX( SMBE_DOS_unknownprintmonitor,            3000, "Unknown print monitor")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_printerdriverinuse,             3001, "Printer driver in use")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_spoolfilenotfound,              3002, "Spool file not found")              /* NT printer driver system only */ \
    XXX( SMBE_DOS_nostartdoc,                     3003, "Error_spl_no_startdoc")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_noaddjob,                       3004, "Spl no addjob")                     /* NT printer driver system only */ \
    XXX( SMBE_DOS_printprocessoralreadyinstalled, 3005, "Print processor already installed") /* NT printer driver system only */ \
    XXX( SMBE_DOS_printmonitoralreadyinstalled,   3006, "Print monitor already installed")   /* NT printer driver system only */ \
    XXX( SMBE_DOS_invalidprintmonitor,            3007, "Invalid print monitor")             /* NT printer driver system only */ \
    XXX( SMBE_DOS_printmonitorinuse,              3008, "Print monitor in use")              /* NT printer driver system only */ \
    XXX( SMBE_DOS_printerhasjobsqueued,           3009, "Printer has jobs queued")           /* NT printer driver system only */

VALUE_STRING_ENUM(DOS_errors);
extern value_string_ext DOS_errors_ext;

/*
 * NT error codes used by other dissectors.
 */
extern const value_string NT_errors[]; /* XXX: Remove once all PIDL generated dissectors ref NT_errors_ext */
extern value_string_ext NT_errors_ext;

extern value_string_ext ms_country_codes_ext;

WS_DLL_PUBLIC
int dissect_nt_64bit_time(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date);
WS_DLL_PUBLIC
int dissect_nt_64bit_time_opt(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date, gboolean onesec_resolution);
WS_DLL_PUBLIC
int dissect_nt_64bit_time_ex(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date, proto_item **createdItem, gboolean onesec_resolution);

/*
 *  SIDs and RIDs
 */

typedef struct _sid_strings {
	const char* sid;
	const char* name;
} sid_strings;

/* Dissect a NT SID.  Label it with 'name' and return a string version
 * of the SID in the 'sid_str' parameter which has a packet lifetime
 * scope and should NOT be freed by the caller. hf_sid can be -1 if
 * the caller doesn't care what name is used and then "nt.sid" will be
 * the default instead. If the caller wants a more appropriate hf
 * field, it will just pass a FT_STRING hf field here
 */

WS_DLL_PUBLIC
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
		       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex,
		       struct access_mask_info *ami,
		       guint32 *perms);

int
dissect_nt_sec_desc(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *parent_tree, guint8 *drep,
		    gboolean len_supplied, int len,
		    struct access_mask_info *ami);

void
proto_do_register_windows_common(int proto_smb);

int
dissect_nt_security_information(tvbuff_t *tvb, int offset, proto_tree *parent_tree);

#endif

