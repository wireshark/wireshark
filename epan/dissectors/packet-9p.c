/* packet-9p.c
 * Routines for 9P dissection
 * Copyright 2005, Nils O. Selaasdal
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * File permission bits decoding taken from packet-nfs.c
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

#include "config.h"

#include <string.h>
#include <stdio.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>

#include <epan/wmem/wmem.h>

#define FIRSTPASS(pinfo) (pinfo->fd->flags.visited == 0)

/**
 * enum _9p_msg_t - 9P message types
 * @_9P_TLERROR:   not used
 * @_9P_RLERROR:   response for any failed request for 9P2000.L
 * @_9P_TSTATFS:   file system status request
 * @_9P_RSTATFS:   file system status response
 * @_9P_TSYMLINK:  make symlink request
 * @_9P_RSYMLINK:  make symlink response
 * @_9P_TMKNOD:    create a special file object request
 * @_9P_RMKNOD:    create a special file object response
 * @_9P_TLCREATE:  prepare a handle for I/O on an new file for 9P2000.L
 * @_9P_RLCREATE:  response with file access information for 9P2000.L
 * @_9P_TRENAME:   rename request
 * @_9P_RRENAME:   rename response
 * @_9P_TMKDIR:    create a directory request
 * @_9P_RMKDIR:    create a directory response
 * @_9P_TVERSION:  version handshake request
 * @_9P_RVERSION:  version handshake response
 * @_9P_TAUTH:     request to establish authentication channel
 * @_9P_RAUTH:     response with authentication information
 * @_9P_TATTACH:   establish user access to file service
 * @_9P_RATTACH:   response with top level handle to file hierarchy
 * @_9P_TERROR:    not used
 * @_9P_RERROR:    response for any failed request
 * @_9P_TFLUSH:    request to abort a previous request
 * @_9P_RFLUSH:    response when previous request has been cancelled
 * @_9P_TWALK:     descend a directory hierarchy
 * @_9P_RWALK:     response with new handle for position within hierarchy
 * @_9P_TOPEN:     prepare a handle for I/O on an existing file
 * @_9P_ROPEN:     response with file access information
 * @_9P_TCREATE:   prepare a handle for I/O on a new file
 * @_9P_RCREATE:   response with file access information
 * @_9P_TREAD:     request to transfer data from a file or directory
 * @_9P_RREAD:     response with data requested
 * @_9P_TWRITE:    reuqest to transfer data to a file
 * @_9P_RWRITE:    response with out much data was transfered to file
 * @_9P_TCLUNK:    forget about a handle to an entity within the file system
 * @_9P_RCLUNK:    response when server has forgotten about the handle
 * @_9P_TREMOVE:   request to remove an entity from the hierarchy
 * @_9P_RREMOVE:   response when server has removed the entity
 * @_9P_TSTAT:     request file entity attributes
 * @_9P_RSTAT:     response with file entity attributes
 * @_9P_TWSTAT:    request to update file entity attributes
 * @_9P_RWSTAT:    response when file entity attributes are updated
 *
 * There are 14 basic operations in 9P2000, paired as
 * requests and responses.  The one special case is ERROR
 * as there is no @_9P_TERROR request for clients to transmit to
 * the server, but the server may respond to any other request
 * with an @_9P_RERROR.
 *
 * See Also: http://plan9.bell-labs.com/sys/man/5/INDEX.html
 */

enum _9p_msg_t {
	_9P_TLERROR = 6,
	_9P_RLERROR,
	_9P_TSTATFS = 8,
	_9P_RSTATFS,
	_9P_TLOPEN = 12,
	_9P_RLOPEN,
	_9P_TLCREATE = 14,
	_9P_RLCREATE,
	_9P_TSYMLINK = 16,
	_9P_RSYMLINK,
	_9P_TMKNOD = 18,
	_9P_RMKNOD,
	_9P_TRENAME = 20,
	_9P_RRENAME,
	_9P_TREADLINK = 22,
	_9P_RREADLINK,
	_9P_TGETATTR = 24,
	_9P_RGETATTR,
	_9P_TSETATTR = 26,
	_9P_RSETATTR,
	_9P_TXATTRWALK = 30,
	_9P_RXATTRWALK,
	_9P_TXATTRCREATE = 32,
	_9P_RXATTRCREATE,
	_9P_TREADDIR = 40,
	_9P_RREADDIR,
	_9P_TFSYNC = 50,
	_9P_RFSYNC,
	_9P_TLOCK = 52,
	_9P_RLOCK,
	_9P_TGETLOCK = 54,
	_9P_RGETLOCK,
	_9P_TLINK = 70,
	_9P_RLINK,
	_9P_TMKDIR = 72,
	_9P_RMKDIR,
	_9P_TRENAMEAT = 74,
	_9P_RRENAMEAT,
	_9P_TUNLINKAT = 76,
	_9P_RUNLINKAT,
	_9P_TVERSION = 100,
	_9P_RVERSION,
	_9P_TAUTH = 102,
	_9P_RAUTH,
	_9P_TATTACH = 104,
	_9P_RATTACH,
	_9P_TERROR = 106,
	_9P_RERROR,
	_9P_TFLUSH = 108,
	_9P_RFLUSH,
	_9P_TWALK = 110,
	_9P_RWALK,
	_9P_TOPEN = 112,
	_9P_ROPEN,
	_9P_TCREATE = 114,
	_9P_RCREATE,
	_9P_TREAD = 116,
	_9P_RREAD,
	_9P_TWRITE = 118,
	_9P_RWRITE,
	_9P_TCLUNK = 120,
	_9P_RCLUNK,
	_9P_TREMOVE = 122,
	_9P_RREMOVE,
	_9P_TSTAT = 124,
	_9P_RSTAT,
	_9P_TWSTAT = 126,
	_9P_RWSTAT
};

/* 9P Msg types to name mapping */
static const value_string ninep_msg_type[] =
{
	{_9P_TLERROR,	   "Tlerror"},
	{_9P_RLERROR,	   "Rlerror"},
	{_9P_TSTATFS,	   "Tstatfs"},
	{_9P_RSTATFS,	   "Rstatfs"},
	{_9P_TLOPEN,	   "Tlopen"},
	{_9P_RLOPEN,	   "Rlopen"},
	{_9P_TLCREATE,	   "Tlcreate"},
	{_9P_RLCREATE,	   "Rlcreate"},
	{_9P_TSYMLINK,	   "Tsymlink"},
	{_9P_RSYMLINK,	   "Rsymlink"},
	{_9P_TMKNOD,	   "Tmknod"},
	{_9P_RMKNOD,	   "Rmknod"},
	{_9P_TRENAME,	   "Trename"},
	{_9P_RRENAME,	   "Rrename"},
	{_9P_TREADLINK,	   "Treadlink"},
	{_9P_RREADLINK,	   "Rreadlink"},
	{_9P_TGETATTR,	   "Tgetattr"},
	{_9P_RGETATTR,	   "Rgetattr"},
	{_9P_TSETATTR,	   "Tsetattr"},
	{_9P_RSETATTR,	   "Rsetattr"},
	{_9P_TXATTRWALK,   "Txattrwalk"},
	{_9P_RXATTRWALK,   "Rxattrwalk"},
	{_9P_TXATTRCREATE, "Txattrcreate"},
	{_9P_RXATTRCREATE, "Rxattrcreate"},
	{_9P_TREADDIR,	   "Treaddir"},
	{_9P_RREADDIR,	   "Rreaddir"},
	{_9P_TFSYNC,	   "Tfsync"},
	{_9P_RFSYNC,	   "Rfsync"},
	{_9P_TLOCK,	   "Tlock"},
	{_9P_RLOCK,	   "Rlock"},
	{_9P_TGETLOCK,	   "Tgetlock"},
	{_9P_RGETLOCK,	   "Rgetlock"},
	{_9P_TLINK,	   "Tlink"},
	{_9P_RLINK,	   "Rlink"},
	{_9P_TMKDIR,	   "Tmkdir"},
	{_9P_RMKDIR,	   "Rmkdir"},
	{_9P_TRENAMEAT,	   "Trenameat"},
	{_9P_RRENAMEAT,	   "Rrenameat"},
	{_9P_TUNLINKAT,	   "Tunlinkat"},
	{_9P_RUNLINKAT,	   "Runlinkat"},
	{_9P_TVERSION,	   "Tversion"},
	{_9P_RVERSION,	   "Rversion"},
	{_9P_TAUTH,	   "Tauth"},
	{_9P_RAUTH,	   "Rauth"},
	{_9P_TATTACH,	   "Tattach"},
	{_9P_RATTACH,	   "Rattach"},
	{_9P_TERROR,	   "Terror"},
	{_9P_RERROR,	   "Rerror"},
	{_9P_TFLUSH,	   "Tflush"},
	{_9P_RFLUSH,	   "Rflush"},
	{_9P_TWALK,	   "Twalk"},
	{_9P_RWALK,	   "Rwalk"},
	{_9P_TOPEN,	   "Topen"},
	{_9P_ROPEN,	   "Ropen"},
	{_9P_TCREATE,	   "Tcreate"},
	{_9P_RCREATE,	   "Rcreate"},
	{_9P_TREAD,	   "Tread"},
	{_9P_RREAD,	   "Rread"},
	{_9P_TWRITE,	   "Twrite"},
	{_9P_RWRITE,	   "Rwrite"},
	{_9P_TCLUNK,	   "Tclunk"},
	{_9P_RCLUNK,	   "Rclunk"},
	{_9P_TREMOVE,	   "Tremove"},
	{_9P_RREMOVE,	   "Rremove"},
	{_9P_TSTAT,	   "Tstat"},
	{_9P_RSTAT,	   "Rstat"},
	{_9P_TWSTAT,	   "Twstat"},
	{_9P_RWSTAT,	   "Rwstat"},
	{0, NULL},
};
static value_string_ext ninep_msg_type_ext = VALUE_STRING_EXT_INIT(ninep_msg_type);

enum _9p_version {
	_9P = 1,
	_9P2000,
	_9P2000_L,
	_9P2000_u
};

static const value_string ninep_version[] =
{
	{_9P,		"9P"},
	{_9P2000,	"9P2000"},
	{_9P2000_L,	"9P2000.L"},
	{_9P2000_u,	"9P2000.u"},
	{0,		NULL},
};
static value_string_ext ninep_version_ext = VALUE_STRING_EXT_INIT(ninep_version);


/* File open modes */
#define	_9P_OREAD           0x0
#define	_9P_OWRITE          0x1
#define	_9P_ORDWR	    0x2
#define	_9P_OEXEC           0x3
#define	_9P_MODEMASK        0x3
#define _9P_OTRUNC         0x10
#define	_9P_ORCLOSE    	   0x40

/* Open/Create modes */
static const value_string ninep_mode_vals[] =
{
	{_9P_OREAD,	"Read Access"},
	{_9P_OWRITE,	"Write Access"},
	{_9P_ORDWR,	"Read/Write Access "},
	{_9P_OEXEC,	"Execute Access"},
	{0,		NULL},
};
static value_string_ext ninep_mode_vals_ext = VALUE_STRING_EXT_INIT(ninep_mode_vals);


/* stat mode flags */
#define DMDIR           0x80000000 /* Directory */
#define	DMAPPEND        0x40000000 /* Append only */
#define	DMEXCL	        0x20000000 /* Exclusive use */
#define	DMMOUNT	        0x10000000 /* Mounted channel */
#define DMAUTH          0x08000000 /* Authentication */
#define	DMTMP          	0x04000000 /* Temporary */


/**
 * enum _9p_qid_t - QID types
 * @_9P_QTDIR:     directory
 * @_9P_QTAPPEND:  append-only
 * @_9P_QTEXCL:    excluse use (only one open handle allowed)
 * @_9P_QTMOUNT:   mount points
 * @_9P_QTAUTH:    authentication file
 * @_9P_QTTMP:     non-backed-up files
 * @_9P_QTSYMLINK: symbolic links (9P2000.u)
 * @_9P_QTLINK:    hard-link (9P2000.u)
 * @_9P_QTFILE:    normal files
 *
 * QID types are a subset of permissions - they are primarily
 * used to differentiate semantics for a file system entity via
 * a jump-table.  Their value is also the most signifigant 16 bits
 * of the permission_t
 *
 * See Also: http://plan9.bell-labs.com/magic/man2html/2/stat
 */
enum _9p_qid_t {
	_9P_QTDIR     = 0x80,
	_9P_QTAPPEND  = 0x40,
	_9P_QTEXCL    = 0x20,
	_9P_QTMOUNT   = 0x10,
	_9P_QTAUTH    = 0x08,
	_9P_QTTMP     = 0x04,
	_9P_QTSYMLINK = 0x02,
	_9P_QTLINK    = 0x01,
	_9P_QTFILE    = 0x00
};

/* 9P Magic Numbers */
#define _9P_NOTAG	(guint16)(~0)
#define _9P_NOFID	(guint32)(~0)
#define _9P_NONUNAME	(guint32)(~0)
#define _9P_MAXWELEM	16

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif


/**
 * @brief Length prefixed string type
 *
 * The protocol uses length prefixed strings for all
 * string data, so we replicate that for our internal
 * string members.
 */

struct _9p_str {
	guint16  len; /* Length of the string */
	char *str; /* The string */
};

/**
 * @brief file system entity information
 *
 * qids are /identifiers used by 9P servers to track file system
 * entities.  The type is used to differentiate semantics for operations
 * on the entity (ie. read means something different on a directory than
 * on a file).  The path provides a server unique index for an entity
 * (roughly analogous to an inode number), while the version is updated
 * every time a file is modified and can be used to maintain cache
 * coherency between clients and serves.
 * Servers will often differentiate purely synthetic entities by setting
 * their version to 0, signaling that they should never be cached and
 * should be accessed synchronously.
 *
 * See Also://plan9.bell-labs.com/magic/man2html/2/stat
 */

struct _9p_qid {
	guint8 type;     /* Type */
	guint32 version; /* Monotonically incrementing version number */
	guint64 path;    /* Per-server-unique ID for a file system element */
};


/* Bit values for getattr valid field.
 */
#define _9P_GETATTR_MODE         0x00000001U
#define _9P_GETATTR_NLINK        0x00000002U
#define _9P_GETATTR_UID          0x00000004U
#define _9P_GETATTR_GID          0x00000008U
#define _9P_GETATTR_RDEV         0x00000010U
#define _9P_GETATTR_ATIME        0x00000020U
#define _9P_GETATTR_MTIME        0x00000040U
#define _9P_GETATTR_CTIME        0x00000080U
#define _9P_GETATTR_INO          0x00000100U
#define _9P_GETATTR_SIZE         0x00000200U
#define _9P_GETATTR_BLOCKS       0x00000400U

#define _9P_GETATTR_BTIME        0x00000800U
#define _9P_GETATTR_GEN          0x00001000U
#define _9P_GETATTR_DATA_VERSION 0x00002000U

#if 0
#define _9P_GETATTR_BASIC        0x000007ffU  /* Mask for fields up to BLOCKS */
#endif
#define _9P_GETATTR_ALL          0x00003fffU  /* Mask for All fields above */


/* Bit values for setattr valid field from <linux/fs.h>.
 */
#define _9P_SETATTR_MODE         0x00000001U
#define _9P_SETATTR_UID          0x00000002U
#define _9P_SETATTR_GID          0x00000004U
#define _9P_SETATTR_SIZE         0x00000008U
#define _9P_SETATTR_ATIME        0x00000010U
#define _9P_SETATTR_MTIME        0x00000020U
#define _9P_SETATTR_CTIME        0x00000040U
#define _9P_SETATTR_ATIME_SET    0x00000080U
#define _9P_SETATTR_MTIME_SET    0x00000100U

#define _9P_SETATTR_ALL	0x000001FFU

/* 9p2000.L open flags */
#define _9P_DOTL_RDONLY		00000000
#define _9P_DOTL_WRONLY		00000001
#define _9P_DOTL_RDWR		00000002
#define _9P_DOTL_NOACCESS	00000003
#define _9P_DOTL_CREATE		00000100
#define _9P_DOTL_EXCL		00000200
#define _9P_DOTL_NOCTTY		00000400
#define _9P_DOTL_TRUNC		00001000
#define _9P_DOTL_APPEND		00002000
#define _9P_DOTL_NONBLOCK	00004000
#define _9P_DOTL_DSYNC		00010000
#define _9P_DOTL_FASYNC		00020000
#define _9P_DOTL_DIRECT		00040000
#define _9P_DOTL_LARGEFILE	00100000
#define _9P_DOTL_DIRECTORY	00200000
#define _9P_DOTL_NOFOLLOW	00400000
#define _9P_DOTL_NOATIME	01000000
#define _9P_DOTL_CLOEXEC	02000000
#define _9P_DOTL_SYNC		04000000


/* Bit values for lock type.
 */
#define _9P_LOCK_TYPE_RDLCK 0
#define _9P_LOCK_TYPE_WRLCK 1
#define _9P_LOCK_TYPE_UNLCK 2

/* 9P lock type to string table */
static const value_string ninep_lock_type[] =
{
	{_9P_LOCK_TYPE_RDLCK,	"Read lock"},
	{_9P_LOCK_TYPE_WRLCK,	"Write lock"},
	{_9P_LOCK_TYPE_UNLCK,	"Unlock"},
	{ 0,			NULL},
};
static value_string_ext ninep_lock_type_ext = VALUE_STRING_EXT_INIT(ninep_lock_type);

/* Bit values for lock status.
 */
#define _9P_LOCK_SUCCESS 0
#define _9P_LOCK_BLOCKED 1
#define _9P_LOCK_ERROR   2
#define _9P_LOCK_GRACE   3

/* 9P lock status to string table */
static const value_string ninep_lock_status[] =
{
	{_9P_LOCK_SUCCESS,	"Success"},
	{_9P_LOCK_BLOCKED,	"Blocked"},
	{_9P_LOCK_ERROR,	"Error"},
	{_9P_LOCK_GRACE,	"Grace"},
	{ 0,			NULL},
};
static value_string_ext ninep_lock_status_ext = VALUE_STRING_EXT_INIT(ninep_lock_status);

/* Bit values for lock flags.
 */
#define _9P_LOCK_FLAGS_NONE    0
#define _9P_LOCK_FLAGS_BLOCK   1
#define _9P_LOCK_FLAGS_RECLAIM 2

/* 9P lock flag to string table */
static const value_string ninep_lock_flag[] =
{
	{_9P_LOCK_FLAGS_NONE,   "No flag"},
	{_9P_LOCK_FLAGS_BLOCK,	"Block"},
	{_9P_LOCK_FLAGS_RECLAIM,"Reclaim"},
	{ 0,			NULL},
};
static value_string_ext ninep_lock_flag_ext = VALUE_STRING_EXT_INIT(ninep_lock_flag);

static const char *const invalid_fid_str = "<invalid fid>";
static const char *const afid_str = "<afid>";

/* Structures for Protocol Operations */
struct _9p_rlerror {
	guint32 ecode;
};
struct _9p_tstatfs {
	guint32 fid;
};
struct _9p_rstatfs {
	guint32 type;
	guint32 bsize;
	guint64 blocks;
	guint64 bfree;
	guint64 bavail;
	guint64 files;
	guint64 ffree;
	guint64 fsid;
	guint32 namelen;
};
struct _9p_tlopen {
	guint32 fid;
	guint32 flags;
};
struct _9p_rlopen {
	struct _9p_qid qid;
	guint32 iounit;
};
struct _9p_tlcreate {
	guint32 fid;
	struct _9p_str name;
	guint32 flags;
	guint32 mode;
	guint32 gid;
};
struct _9p_rlcreate {
	struct _9p_qid qid;
	guint32 iounit;
};
struct _9p_tsymlink {
	guint32 fid;
	struct _9p_str name;
	struct _9p_str symtgt;
	guint32 gid;
};
struct _9p_rsymlink {
	struct _9p_qid qid;
};
struct _9p_tmknod {
	guint32 fid;
	struct _9p_str name;
	guint32 mode;
	guint32 major;
	guint32 minor;
	guint32 gid;
};
struct _9p_rmknod {
	struct _9p_qid qid;
};
struct _9p_trename {
	guint32 fid;
	guint32 dfid;
	struct _9p_str name;
};
#if 0
struct _9p_rrename {
};
#endif
struct _9p_treadlink {
	guint32 fid;
};
struct _9p_rreadlink {
	struct _9p_str target;
};
struct _9p_tgetattr {
	guint32 fid;
	guint64 request_mask;
};
struct _9p_rgetattr {
	guint64 valid;
	struct _9p_qid qid;
	guint32 mode;
	guint32 uid;
	guint32 gid;
	guint64 nlink;
	guint64 rdev;
	guint64 size;
	guint64 blksize;
	guint64 blocks;
	guint64 atime_sec;
	guint64 atime_nsec;
	guint64 mtime_sec;
	guint64 mtime_nsec;
	guint64 ctime_sec;
	guint64 ctime_nsec;
	guint64 btime_sec;
	guint64 btime_nsec;
	guint64 gen;
	guint64 data_version;
};
struct _9p_tsetattr {
	guint32 fid;
	guint32 valid;
	guint32 mode;
	guint32 uid;
	guint32 gid;
	guint64 size;
	guint64 atime_sec;
	guint64 atime_nsec;
	guint64 mtime_sec;
	guint64 mtime_nsec;
};
#if 0
struct _9p_rsetattr {
};
#endif
struct _9p_txattrwalk {
	guint32 fid;
	guint32 attrfid;
	struct _9p_str name;
};
struct _9p_rxattrwalk {
	guint64 size;
};
struct _9p_txattrcreate {
	guint32 fid;
	struct _9p_str name;
	guint64 size;
	guint32 flag;
};
#if 0
struct _9p_rxattrcreate {
};
#endif
struct _9p_treaddir {
	guint32 fid;
	guint64 offset;
	guint32 count;
};
struct _9p_rreaddir {
	guint32 count;
	guint8 *data;
};
struct _9p_tfsync {
	guint32 fid;
};
#if 0
struct _9p_rfsync {
};
#endif
struct _9p_tlock {
	guint32 fid;
	guint8 type;
	guint32 flags;
	guint64 start;
	guint64 length;
	guint32 proc_id;
	struct _9p_str client_id;
};
struct _9p_rlock {
	guint8 status;
};
struct _9p_tgetlock {
	guint32 fid;
	guint8 type;
	guint64 start;
	guint64 length;
	guint32 proc_id;
	struct _9p_str client_id;
};
struct _9p_rgetlock {
	guint8 type;
	guint64 start;
	guint64 length;
	guint32 proc_id;
	struct _9p_str client_id;
};
struct _9p_tlink {
	guint32 dfid;
	guint32 fid;
	struct _9p_str name;
};
#if 0
struct _9p_rlink {
};
#endif
struct _9p_tmkdir {
	guint32 fid;
	struct _9p_str name;
	guint32 mode;
	guint32 gid;
};
struct _9p_rmkdir {
	struct _9p_qid qid;
};
struct _9p_trenameat {
	guint32 olddirfid;
	struct _9p_str oldname;
	guint32 newdirfid;
	struct _9p_str newname;
};
#if 0
struct _9p_rrenameat {
};
#endif
struct _9p_tunlinkat {
	guint32 dirfid;
	struct _9p_str name;
	guint32 flags;
};
#if 0
struct _9p_runlinkat {
};
#endif
struct _9p_tawrite {
	guint32 fid;
	guint8 datacheck;
	guint64 offset;
	guint32 count;
	guint32 rsize;
	guint8 *data;
	guint32 check;
};
struct _9p_rawrite {
	guint32 count;
};
struct _9p_tversion {
	guint32  msize              ;
	struct _9p_str version ;
};
struct _9p_rversion {
	guint32 msize;
	struct _9p_str version;
};
struct _9p_tauth {
	guint32 afid;
	struct _9p_str uname;
	struct _9p_str aname;
	guint32 n_uname;		/* 9P2000.u extensions */
};
struct _9p_rauth {
	struct _9p_qid qid;
};
struct _9p_rerror {
	struct _9p_str error;
	guint32 errnum;		/* 9p2000.u extension */
};
struct _9p_tflush {
	guint16 oldtag;
};
#if 0
struct _9p_rflush {
};
#endif
struct _9p_tattach {
	guint32 fid;
	guint32 afid;
	struct _9p_str uname;
	struct _9p_str aname;
	guint32 n_uname;		/* 9P2000.u extensions */
};
struct _9p_rattach {
	struct _9p_qid qid;
};
struct _9p_twalk {
	guint32 fid;
	guint32 newfid;
	guint16 nwname;
	struct _9p_str wnames[_9P_MAXWELEM];
};
struct _9p_rwalk {
	guint16 nwqid;
	struct _9p_qid wqids[_9P_MAXWELEM];
};
struct _9p_topen {
	guint32 fid;
	guint8 mode;
};
struct _9p_ropen {
	struct _9p_qid qid;
	guint32 iounit;
};
struct _9p_tcreate {
	guint32 fid;
	struct _9p_str name;
	guint32 perm;
	guint8 mode;
	struct _9p_str extension;
};
struct _9p_rcreate {
	struct _9p_qid qid;
	guint32 iounit;
};
struct _9p_tread {
	guint32 fid;
	guint64 offset;
	guint32 count;
};
struct _9p_rread {
	guint32 count;
	guint8 *data;
};
struct _9p_twrite {
	guint32 fid;
	guint64 offset;
	guint32 count;
	guint8 *data;
};
struct _9p_rwrite {
	guint32 count;
};
struct _9p_tclunk {
	guint32 fid;
};
#if 0
struct _9p_rclunk {
};
#endif
struct _9p_tremove {
	guint32 fid;
};
#if 0
struct _9p_rremove {
};

union _9p_tmsg {
} ;
#endif
#define NINEPORT 564

/* Forward declarations */
void proto_register_9P(void);
void proto_reg_handoff_9P(void);

/* Initialize the protocol and registered fields */
static int proto_9P = -1;
static int hf_9P_msgsz = -1;
static int hf_9P_msgtype = -1;
static int hf_9P_tag = -1;
static int hf_9P_oldtag = -1;
static int hf_9P_parmsz = -1;
static int hf_9P_maxsize = -1;
static int hf_9P_fid = -1;
static int hf_9P_nqid = -1;
static int hf_9P_mode = -1;
static int hf_9P_mode_rwx = -1;
static int hf_9P_mode_t = -1;
static int hf_9P_mode_c = -1;
static int hf_9P_iounit = -1;
static int hf_9P_count = -1;
static int hf_9P_offset = -1;
static int hf_9P_perm = -1;
static int hf_9P_qidtype = -1;
static int hf_9P_qidtype_dir = -1;
static int hf_9P_qidtype_append = -1;
static int hf_9P_qidtype_exclusive = -1;
static int hf_9P_qidtype_mount = -1;
static int hf_9P_qidtype_auth_file = -1;
static int hf_9P_qidtype_temp_file = -1;
static int hf_9P_qidvers = -1;
static int hf_9P_qidpath = -1;
static int hf_9P_dm_dir = -1;
static int hf_9P_dm_append = -1;
static int hf_9P_dm_exclusive = -1;
static int hf_9P_dm_mount = -1;
static int hf_9P_dm_auth_file = -1;
static int hf_9P_dm_temp_file = -1;
static int hf_9P_dm_read_owner = -1;
static int hf_9P_dm_write_owner = -1;
static int hf_9P_dm_exec_owner = -1;
static int hf_9P_dm_read_group = -1;
static int hf_9P_dm_write_group = -1;
static int hf_9P_dm_exec_group = -1;
static int hf_9P_dm_read_others = -1;
static int hf_9P_dm_write_others = -1;
static int hf_9P_dm_exec_others = -1;
static int hf_9P_stattype = -1;
static int hf_9P_statmode = -1;
static int hf_9P_atime = -1;
static int hf_9P_mtime = -1;
static int hf_9P_ctime = -1;
static int hf_9P_btime = -1;
static int hf_9P_length = -1;
static int hf_9P_dev = -1;
static int hf_9P_wname = -1;
static int hf_9P_version = -1;
static int hf_9P_afid = -1;
static int hf_9P_uname = -1;
static int hf_9P_aname = -1;
static int hf_9P_ename = -1;
static int hf_9P_enum = -1;
static int hf_9P_name = -1;
static int hf_9P_filename = -1;
static int hf_9P_sdlen = -1;
static int hf_9P_user = -1;
static int hf_9P_group = -1;
static int hf_9P_uid = -1;
static int hf_9P_gid = -1;
static int hf_9P_muid = -1;
static int hf_9P_nwalk = -1;
static int hf_9P_newfid = -1;
static int hf_9P_dfid = -1;
static int hf_9P_getattr_flags = -1;
static int hf_9P_getattr_mode = -1;
static int hf_9P_getattr_nlink = -1;
static int hf_9P_getattr_uid = -1;
static int hf_9P_getattr_gid = -1;
static int hf_9P_getattr_rdev = -1;
static int hf_9P_getattr_atime = -1;
static int hf_9P_getattr_mtime = -1;
static int hf_9P_getattr_ctime = -1;
static int hf_9P_getattr_ino = -1;
static int hf_9P_getattr_size = -1;
static int hf_9P_getattr_blocks = -1;
static int hf_9P_getattr_btime = -1;
static int hf_9P_getattr_gen = -1;
static int hf_9P_getattr_dataversion = -1;
static int hf_9P_setattr_flags = -1;
static int hf_9P_setattr_mode = -1;
static int hf_9P_setattr_uid = -1;
static int hf_9P_setattr_gid = -1;
static int hf_9P_setattr_size = -1;
static int hf_9P_setattr_atime = -1;
static int hf_9P_setattr_mtime = -1;
static int hf_9P_setattr_ctime = -1;
static int hf_9P_setattr_atime_set = -1;
static int hf_9P_setattr_mtime_set = -1;
static int hf_9P_nlink = -1;
static int hf_9P_rdev = -1;
static int hf_9P_size = -1;
static int hf_9P_blksize = -1;
static int hf_9P_blocks = -1;
static int hf_9P_gen = -1;
static int hf_9P_dataversion = -1;
static int hf_9P_fstype = -1;
static int hf_9P_bfree = -1;
static int hf_9P_bavail = -1;
static int hf_9P_files = -1;
static int hf_9P_ffree = -1;
static int hf_9P_fsid = -1;
static int hf_9P_namelen = -1;
static int hf_9P_mknod_major = -1;
static int hf_9P_mknod_minor = -1;
static int hf_9P_lflags = -1;
static int hf_9P_lflags_rdonly = -1;
static int hf_9P_lflags_wronly = -1;
static int hf_9P_lflags_rdwr = -1;
static int hf_9P_lflags_create = -1;
static int hf_9P_lflags_excl = -1;
static int hf_9P_lflags_noctty = -1;
static int hf_9P_lflags_trunc = -1;
static int hf_9P_lflags_append = -1;
static int hf_9P_lflags_nonblock = -1;
static int hf_9P_lflags_dsync = -1;
static int hf_9P_lflags_fasync = -1;
static int hf_9P_lflags_direct = -1;
static int hf_9P_lflags_largefile = -1;
static int hf_9P_lflags_directory = -1;
static int hf_9P_lflags_nofollow = -1;
static int hf_9P_lflags_noatime = -1;
static int hf_9P_lflags_cloexec = -1;
static int hf_9P_lflags_sync = -1;
static int hf_9P_xattr_flag = -1;
static int hf_9P_lock_type = -1;
static int hf_9P_lock_flag = -1;
static int hf_9P_lock_start = -1;
static int hf_9P_lock_length = -1;
static int hf_9P_lock_procid = -1;
static int hf_9P_lock_status = -1;

/*handle for dissecting data in 9P msgs*/
static dissector_handle_t data_handle;

/* subtree pointers */
static gint ett_9P = -1;
static gint ett_9P_omode = -1;
static gint ett_9P_dm = -1;
static gint ett_9P_wname = -1;
static gint ett_9P_aname = -1;
static gint ett_9P_ename = -1;
static gint ett_9P_uname = -1;
static gint ett_9P_user = -1;
static gint ett_9P_group = -1;
static gint ett_9P_muid = -1;
static gint ett_9P_filename = -1;
static gint ett_9P_version = -1;
static gint ett_9P_qid = -1;
static gint ett_9P_qidtype = -1;
static gint ett_9P_getattr_flags = -1;
static gint ett_9P_setattr_flags = -1;
static gint ett_9P_lflags = -1;

static GHashTable *_9p_hashtable = NULL;

static void dissect_9P_mode(tvbuff_t *tvb,  proto_item *tree, int offset);
static void dissect_9P_dm(tvbuff_t *tvb,  proto_item *tree, int offset, int iscreate);
static void dissect_9P_qid(tvbuff_t *tvb,  proto_tree *tree, int offset);
static void dissect_9P_lflags(tvbuff_t *tvb, proto_tree *tree, int offset);
static void dissect_9P_getattrflags(tvbuff_t *tvb, proto_tree *tree, int offset);
static void dissect_9P_setattrflags(tvbuff_t *tvb, proto_tree *tree, int offset);

struct _9p_hashkey {
	guint32 conv_index;
	guint16 tag;
	guint32 fid;
};

struct _9p_hashval {
	gsize len;
	void *data;
};

struct _9p_taginfo {
	enum _9p_msg_t msgtype;
	guint32 fid;
	/* fid path used for create and lcreate */
	char *fid_path;
};

static gint _9p_hash_equal(gconstpointer k1, gconstpointer k2) {
	const struct _9p_hashkey *key1 = (const struct _9p_hashkey *)k1, *key2 = (const struct _9p_hashkey *)k2;

	return ((key1->conv_index == key2->conv_index) && (key1->tag == key2->tag) && (key1->fid == key2->fid));
}

static guint _9p_hash_hash(gconstpointer k)
{
	const struct _9p_hashkey *key = (const struct _9p_hashkey *)k;

	return (key->conv_index ^ key->tag ^ key->fid);
}

static gboolean _9p_hash_free_all(gpointer key _U_, gpointer value _U_, gpointer user_data _U_)
{
	return TRUE;
}

static void _9p_hash_free_val(gpointer value)
{
	struct _9p_hashval *val = (struct _9p_hashval *)value;

	if (val->data && val->len) {
		g_free(val->data);
		val->data = NULL;
	}

	g_free(value);
}

static struct _9p_hashval *_9p_hash_new_val(gsize len)
{
	struct _9p_hashval *val;
	val = (struct _9p_hashval *)g_malloc(sizeof(struct _9p_hashval));

	val->data = g_malloc(len);
	val->len = len;

	return val;
}

static void _9p_hash_init(void)
{
	if (_9p_hashtable != NULL) {
		g_hash_table_foreach_remove(_9p_hashtable, _9p_hash_free_all, NULL);
	} else {
		_9p_hashtable = g_hash_table_new_full(_9p_hash_hash, _9p_hash_equal, g_free, _9p_hash_free_val);
	}
}

static void _9p_hash_set(packet_info *pinfo, guint16 tag, guint32 fid, struct _9p_hashval *val)
{
	struct _9p_hashkey *key;
	struct _9p_hashval *oldval;
	conversation_t *conv;

	conv = find_or_create_conversation(pinfo);

	key = (struct _9p_hashkey *)g_malloc(sizeof(struct _9p_hashkey));

	key->conv_index = conv->index;
	key->tag = tag;
	key->fid = fid;

	/* remove eventual old entry */
	oldval = (struct _9p_hashval *)g_hash_table_lookup(_9p_hashtable, key);
	if (oldval) {
		g_hash_table_remove(_9p_hashtable, key);
	}
	g_hash_table_insert(_9p_hashtable, key, val);
}

static struct _9p_hashval *_9p_hash_get(packet_info *pinfo, guint16 tag, guint32 fid)
{
	struct _9p_hashkey key;
	conversation_t *conv;

	conv = find_or_create_conversation(pinfo);

	key.conv_index = conv->index;
	key.tag = tag;
	key.fid = fid;

	return (struct _9p_hashval *)g_hash_table_lookup(_9p_hashtable, &key);
}

static void _9p_hash_free(packet_info *pinfo, guint16 tag, guint32 fid)
{
	struct _9p_hashkey key;
	conversation_t *conv;

	conv = find_or_create_conversation(pinfo);

	key.conv_index = conv->index;
	key.tag = tag;
	key.fid = fid;

	g_hash_table_remove(_9p_hashtable, &key);
}

static void conv_set_version(packet_info *pinfo, enum _9p_version version)
{
	struct _9p_hashval *val;

	val = _9p_hash_new_val(sizeof(enum _9p_version));


	*(enum _9p_version*)val->data = version;

	_9p_hash_set(pinfo, _9P_NOTAG, _9P_NOFID, val);
}

static enum _9p_version conv_get_version(packet_info *pinfo)
{
	struct _9p_hashval *val;

	val = _9p_hash_get(pinfo, _9P_NOTAG, _9P_NOFID);

	return val ? *(enum _9p_version*)val->data : _9P;
}

static void conv_set_fid_nocopy(packet_info *pinfo, guint32 fid, const char *path)
{
	struct _9p_hashval *val;

	if (!FIRSTPASS(pinfo) || fid == _9P_NOFID)
		return;

	/* get or create&insert fid tree */
	val = _9p_hash_get(pinfo, _9P_NOTAG, fid);
	if (!val) {
		val = _9p_hash_new_val(0);
		val->data = wmem_tree_new(wmem_file_scope());
		/* val->len is intentionnaly left to 0 so the tree won't be freed */
		_9p_hash_set(pinfo, _9P_NOTAG, fid, val);
	}

	/* fill it */
	wmem_tree_insert32((wmem_tree_t *)val->data, pinfo->fd->num, (void *)path);
}

static void conv_set_fid(packet_info *pinfo, guint32 fid, const gchar *path, gsize len)
{
	char *str;

	if (!FIRSTPASS(pinfo) || fid == _9P_NOFID || len == 0)
		return;

	str = (char*)wmem_alloc(wmem_file_scope(), len);
	g_strlcpy(str, path, len);
	conv_set_fid_nocopy(pinfo, fid, str);
}

static const char *conv_get_fid(packet_info *pinfo, guint32 fid)
{
	struct _9p_hashval *val;

	if (fid == _9P_NOFID)
		return invalid_fid_str;

	val = _9p_hash_get(pinfo, _9P_NOTAG, fid);
	if (!val)
		return invalid_fid_str;

	/* -1 because the fid needs to have been set on a previous message.
	   Let's ignore the possibility of num == 0... */
	return (char*)wmem_tree_lookup32_le((wmem_tree_t*)val->data, pinfo->fd->num-1);
}

static inline void conv_free_fid(packet_info *pinfo, guint32 fid)
{
	conv_set_fid_nocopy(pinfo, fid, invalid_fid_str);
}

static void conv_set_tag(packet_info *pinfo, guint16 tag, enum _9p_msg_t msgtype, guint32 fid, wmem_strbuf_t *fid_path)
{
	struct _9p_hashval *val;
	struct _9p_taginfo *taginfo;

	if (!FIRSTPASS(pinfo) || tag == _9P_NOTAG)
		return;

	val = _9p_hash_new_val(sizeof(struct _9p_taginfo));
	taginfo = (struct _9p_taginfo*)val->data;

	taginfo->msgtype = msgtype;
	taginfo->fid = fid;
	if (fid_path) {
		taginfo->fid_path = (char*)wmem_alloc(wmem_file_scope(), wmem_strbuf_get_len(fid_path)+1);
		g_strlcpy(taginfo->fid_path, wmem_strbuf_get_str(fid_path), wmem_strbuf_get_len(fid_path)+1);
	} else {
		taginfo->fid_path = NULL;
	}

	_9p_hash_set(pinfo, tag, _9P_NOFID, val);
}

static inline struct _9p_taginfo *conv_get_tag(packet_info *pinfo, guint16 tag)
{
	struct _9p_hashval *val;

	/* get tag only makes sense on first pass, as tree isn't built like fid */
	if (!FIRSTPASS(pinfo) || tag == _9P_NOTAG)
		return NULL;

	/* check that length matches? */
	val = _9p_hash_get(pinfo, tag, _9P_NOFID);

	return val ? (struct _9p_taginfo*)val->data : NULL;
}

static inline void conv_free_tag(packet_info *pinfo, guint16 tag)
{
	if (!FIRSTPASS(pinfo) || tag == _9P_NOTAG)
		return;

	_9p_hash_free(pinfo, tag, _9P_NOFID);
}

/* Dissect 9P messages*/
static int dissect_9P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint32             u32, i, fid, dfid, newfid;
	guint16             u16, tag, _9p_len;
	enum _9p_msg_t      ninemsg;
	guint               offset    = 0;
	const char         *mname, *fid_path;
	char               *tvb_s;
	wmem_strbuf_t      *tmppath   = NULL;
	gint                len, reportedlen;
	tvbuff_t           *next_tvb;
	proto_item         *ti;
	proto_tree         *ninep_tree, *sub_tree;
	struct _9p_taginfo *taginfo;
	nstime_t            tv;
	int                 _9p_version;
	const int           firstpass = FIRSTPASS(pinfo);

	_9p_version = conv_get_version(pinfo);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, val_to_str_ext_const(_9p_version, &ninep_version_ext, "9P"));

	col_clear(pinfo->cinfo, COL_INFO);

	/*ninesz = tvb_get_letohl(tvb, offset);*/
	ninemsg = (enum _9p_msg_t)tvb_get_guint8(tvb, offset + 4);

	mname = val_to_str_ext_const(ninemsg, &ninep_msg_type_ext, "Unknown");

	if(strcmp(mname, "Unknown") == 0) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "9P Data (Message type %u)", (guint)ninemsg);
		return 0;
	}

	tag = tvb_get_letohs(tvb, offset+5);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s Tag=%u", mname, (guint)tag);

	ti = proto_tree_add_item(tree, proto_9P, tvb, 0, -1, ENC_NA);
	ninep_tree = proto_item_add_subtree(ti, ett_9P);
	proto_tree_add_item(ninep_tree, hf_9P_msgsz, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+= 4;

	proto_tree_add_item(ninep_tree, hf_9P_msgtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	++offset;
	proto_tree_add_item(ninep_tree, hf_9P_tag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	switch(ninemsg) {
	case _9P_RVERSION:
	case _9P_TVERSION:
		proto_tree_add_item(ninep_tree, hf_9P_maxsize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_version, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_version);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);

		if (firstpass) {
			tvb_s = tvb_get_string_enc(NULL, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);

			if (!strncmp(tvb_s, "9P2000.L", _9p_len)) {
				u32 = _9P2000_L;
			} else if (!strncmp(tvb_s, "9P2000", _9p_len)) {
				u32 = _9P2000;
			} else if (!strncmp(tvb_s, "9P2000.u", _9p_len)) {
				u32 = _9P2000_u;
			} else {
				u32 = _9P;
			}

			conv_set_version(pinfo, (enum _9p_version)u32);
			g_free(tvb_s);
		}

		/* don't set tag for tversion/free it for rversion,
		   we need that for the actual version number */
		break;

	case _9P_TAUTH:
		proto_tree_add_item(ninep_tree, hf_9P_afid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		fid = tvb_get_letohl(tvb, offset);
		conv_set_fid_nocopy(pinfo, fid, afid_str);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_uname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_uname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_aname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_aname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		conv_set_tag(pinfo, tag, ninemsg, fid, NULL);
		break;

	case _9P_RERROR:
		if (_9p_version == _9P2000_L) {
			u32 = tvb_get_letohl(tvb, offset);
			ti = proto_tree_add_item(ninep_tree, hf_9P_enum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			proto_item_append_text(ti, " (%s)", g_strerror(u32));
			offset += 4;
		} else {
			_9p_len = tvb_get_letohs(tvb, offset);
			ti = proto_tree_add_item(ninep_tree, hf_9P_ename, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
			sub_tree = proto_item_add_subtree(ti, ett_9P_ename);
			proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2 + _9p_len;
		}

		/* conv_get_tag checks we're in first pass */
		taginfo = conv_get_tag(pinfo, tag);
		if (taginfo && (taginfo->msgtype == _9P_TWALK || taginfo->msgtype == _9P_TATTACH))
			conv_free_fid(pinfo, taginfo->fid);

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TFLUSH:
		u16 = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_oldtag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		conv_free_tag(pinfo, u16);

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TATTACH:
		fid = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_afid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_uname, tvb, offset+2, _9p_len, ENC_ASCII|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_uname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_aname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_aname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		if(firstpass) {
			tvb_s = tvb_get_string_enc(NULL, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
			conv_set_fid(pinfo, fid, tvb_s, _9p_len+1);
			g_free(tvb_s);
		}
		offset += _9p_len + 2;

		proto_tree_add_item(ninep_tree, hf_9P_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

		conv_set_tag(pinfo, tag, ninemsg, fid, NULL);
		break;

	case _9P_TWALK:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		fid_path = conv_get_fid(pinfo, fid);
		proto_item_append_text(ti, " (%s)", fid_path);
		if (firstpass) {
			tmppath = wmem_strbuf_sized_new(wmem_packet_scope(), 0, MAXPATHLEN);
			wmem_strbuf_append(tmppath, fid_path);
		}
		offset += 4;

		fid = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_newfid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		u16 = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_nwalk, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		/* I can't imagine anyone having a directory depth more than 25,
		   Limit to 10 times that to be sure, 2^16 is too much */
		if(u16 > 250) {
			sub_tree = proto_tree_add_text(ninep_tree, tvb, 0, 0, "Only first 250 items shown");
			PROTO_ITEM_SET_GENERATED(sub_tree);
		}

		for(i = 0 ; i < u16; i++) {
			_9p_len = tvb_get_letohs(tvb, offset);

			if (i < 250) {
				ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
				sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
				proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			}

			if (firstpass) {
				tvb_s = tvb_get_string_enc(NULL, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
				wmem_strbuf_append_c(tmppath, '/');
				wmem_strbuf_append(tmppath, tvb_s);
				g_free(tvb_s);
			}

			offset += _9p_len + 2;
		}

		if (firstpass) {
			conv_set_fid(pinfo, fid, wmem_strbuf_get_str(tmppath), wmem_strbuf_get_len(tmppath)+1);
		}

		conv_set_tag(pinfo, tag, ninemsg, fid, NULL);
		break;

	case _9P_RWALK:
		u16 = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_nqid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		/* I can't imagine anyone having a directory depth more than 25,
		   Limit to 10 times that to be sure, 2^16 is too much */
		if(u16 > 250) {
			u16 = 250;
			sub_tree = proto_tree_add_text(ninep_tree, tvb, 0, 0, "Only first 250 items shown");
			PROTO_ITEM_SET_GENERATED(sub_tree);
		}

		for(i = 0; i < u16; i++) {
			dissect_9P_qid(tvb, ninep_tree, offset);
			offset += 13;
		}

		conv_free_tag(pinfo, tag);
		break;
	case _9P_TLOPEN:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_lflags(tvb, ti, offset);
		offset += 4;
		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TOPEN:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		ti = proto_tree_add_item(ninep_tree, hf_9P_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		dissect_9P_mode(tvb, ti, offset);
		offset += 1;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TCREATE:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		fid_path = conv_get_fid(pinfo, fid);
		proto_item_append_text(ti, " (%s)", fid_path);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_name, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_filename);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		if (firstpass) {
			tmppath = wmem_strbuf_sized_new(wmem_packet_scope(), 0, MAXPATHLEN);
			wmem_strbuf_append(tmppath, fid_path);
			wmem_strbuf_append_c(tmppath, '/');
			tvb_s = tvb_get_string_enc(NULL, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
			wmem_strbuf_append(tmppath, tvb_s);
			g_free(tvb_s);
		}
		offset += _9p_len + 2;

		ti = proto_tree_add_item(ninep_tree, hf_9P_perm, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 1);
		offset += 4;

		ti = proto_tree_add_item(ninep_tree, hf_9P_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		dissect_9P_mode(tvb, ti, offset);
		offset += 1;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_set_tag(pinfo, tag, ninemsg, fid, tmppath);
		break;

	case _9P_TLCREATE:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		fid_path = conv_get_fid(pinfo, fid);
		proto_item_append_text(ti, " (%s)", fid_path);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_name, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_filename);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		if (firstpass) {
			tmppath = wmem_strbuf_sized_new(wmem_packet_scope(), 0, MAXPATHLEN);
			wmem_strbuf_append(tmppath, fid_path);
			wmem_strbuf_append_c(tmppath, '/');
			tvb_s = tvb_get_string_enc(NULL, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
			wmem_strbuf_append(tmppath, tvb_s);
			g_free(tvb_s);
		}
		offset += _9p_len + 2;

		ti = proto_tree_add_item(ninep_tree, hf_9P_lflags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_lflags(tvb, ti, offset);
		offset += 4;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 0);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_set_tag(pinfo, tag, ninemsg, fid, tmppath);
		break;

	case _9P_TREAD:
	case _9P_TREADDIR:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_RREAD:
	case _9P_RREADDIR:
		u32 = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		len = tvb_reported_length_remaining(tvb, offset);
		reportedlen = ((gint)u32&0xffff) > len ? len : (gint)u32&0xffff;
		next_tvb = tvb_new_subset(tvb, offset, len, reportedlen);
		call_dissector(data_handle, next_tvb, pinfo, tree);

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TWRITE:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		u32 = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		len = tvb_reported_length_remaining(tvb, offset);
		reportedlen = ((gint)u32&0xffff) > len ? len : (gint)u32&0xffff;
		next_tvb = tvb_new_subset(tvb, offset, len, reportedlen);
		call_dissector(data_handle, next_tvb, pinfo, tree);

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_RWRITE:
		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);

		conv_free_tag(pinfo, tag);
		break;

	case _9P_RSTAT:
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(ninep_tree, hf_9P_sdlen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(ninep_tree, hf_9P_stattype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(ninep_tree, hf_9P_dev, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		dissect_9P_qid(tvb, ninep_tree, offset);
		offset += 13;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 0);
		offset += 4;

		tv.secs = tvb_get_letohl(tvb, offset);
		tv.nsecs = 0;
		proto_tree_add_time(ninep_tree, hf_9P_atime, tvb, offset, 4, &tv);
		offset += 4;

		tv.secs = tvb_get_letohl(tvb, offset);
		tv.nsecs = 0;
		proto_tree_add_time(ninep_tree, hf_9P_mtime, tvb, offset, 4, &tv);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_filename, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_filename);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_user, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_user);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_group, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_group);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_muid, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_muid);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TWSTAT:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(ninep_tree, hf_9P_sdlen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(ninep_tree, hf_9P_stattype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(ninep_tree, hf_9P_dev, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		dissect_9P_qid(tvb, ninep_tree, offset);
		offset += 13;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 0);
		offset += 4;

		tv.secs = tvb_get_letohl(tvb, offset);
		tv.nsecs = 0;
		proto_tree_add_time(ninep_tree, hf_9P_atime, tvb, offset, 4, &tv);
		offset += 4;

		tv.secs = tvb_get_letohl(tvb, offset);
		tv.nsecs = 0;
		proto_tree_add_time(ninep_tree, hf_9P_mtime, tvb, offset, 4, &tv);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_filename, tvb, offset+2, _9p_len, ENC_ASCII|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_filename);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_user, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_user);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_group, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_group);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_muid, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_muid);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TGETATTR:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		ti = proto_tree_add_item(ninep_tree, hf_9P_getattr_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		dissect_9P_getattrflags(tvb, ti, offset);
		offset += 8;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_RGETATTR:
		ti = proto_tree_add_item(ninep_tree, hf_9P_getattr_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		dissect_9P_getattrflags(tvb, ti, offset);
		offset += 8;

		dissect_9P_qid(tvb, ninep_tree, offset);
		offset += 13;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 0);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_nlink, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_rdev, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_blksize, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		tv.secs = (time_t)tvb_get_letoh64(tvb, offset);
		tv.nsecs = (guint32)tvb_get_letoh64(tvb, offset+8);
		proto_tree_add_time(ninep_tree, hf_9P_atime, tvb, offset, 16, &tv);
		offset += 16;

		tv.secs = (time_t)tvb_get_letoh64(tvb, offset);
		tv.nsecs = (guint32)tvb_get_letoh64(tvb, offset+8);
		proto_tree_add_time(ninep_tree, hf_9P_mtime, tvb, offset, 16, &tv);
		offset += 16;

		tv.secs = (time_t)tvb_get_letoh64(tvb, offset);
		tv.nsecs = (guint32)tvb_get_letoh64(tvb, offset+8);
		proto_tree_add_time(ninep_tree, hf_9P_ctime, tvb, offset, 16, &tv);
		offset += 16;

		tv.secs = (time_t)tvb_get_letoh64(tvb, offset);
		tv.nsecs = (guint32)tvb_get_letoh64(tvb, offset+8);
		proto_tree_add_time(ninep_tree, hf_9P_btime, tvb, offset, 16, &tv);
		offset += 16;

		proto_tree_add_item(ninep_tree, hf_9P_gen, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_dataversion, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TSETATTR:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		ti = proto_tree_add_item(ninep_tree, hf_9P_setattr_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_setattrflags(tvb, ti, offset);
		offset += 4;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 0);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		tv.secs = (time_t)tvb_get_letoh64(tvb, offset);
		tv.nsecs = (guint32)tvb_get_letoh64(tvb, offset+8);
		proto_tree_add_time(ninep_tree, hf_9P_atime, tvb, offset, 16, &tv);
		offset += 16;

		tv.secs = (time_t)tvb_get_letoh64(tvb, offset);
		tv.nsecs = (guint32)tvb_get_letoh64(tvb, offset+8);
		proto_tree_add_time(ninep_tree, hf_9P_mtime, tvb, offset, 16, &tv);
		offset += 16;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_RSTATFS:
		proto_tree_add_item(ninep_tree, hf_9P_fstype, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_blksize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_bfree, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_bavail, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_files, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_ffree, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_fsid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_namelen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TSYMLINK:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TMKNOD:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 0);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_mknod_major, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_mknod_minor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TRENAME:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		dfid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_dfid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		fid_path = conv_get_fid(pinfo, dfid);
		proto_item_append_text(ti, " (%s)", fid_path);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		if (firstpass) {
			tmppath = wmem_strbuf_sized_new(wmem_packet_scope(), 0, MAXPATHLEN);
			wmem_strbuf_append(tmppath, conv_get_fid(pinfo, dfid));
			wmem_strbuf_append_c(tmppath, '/');

			tvb_s = tvb_get_string_enc(NULL, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
			wmem_strbuf_append(tmppath, tvb_s);
			g_free(tvb_s);

			conv_set_fid(pinfo, fid, wmem_strbuf_get_str(tmppath), wmem_strbuf_get_len(tmppath)+1);
		}
		offset += _9p_len + 2;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_RREADLINK:
		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TXATTRWALK:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		fid_path = conv_get_fid(pinfo, fid);
		proto_item_append_text(ti, " (%s)", fid_path);
		offset += 4;

		newfid = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ninep_tree, hf_9P_newfid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		conv_set_fid_nocopy(pinfo, newfid, fid_path);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_RXATTRWALK:
		proto_tree_add_item(ninep_tree, hf_9P_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TXATTRCREATE:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		proto_tree_add_item(ninep_tree, hf_9P_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_xattr_flag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TLOCK:
	case _9P_TGETLOCK:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_lock_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(ninep_tree, hf_9P_lock_flag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_lock_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_lock_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_lock_procid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_RLOCK:
		proto_tree_add_item(ninep_tree, hf_9P_lock_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		conv_free_tag(pinfo, tag);
		break;

	case _9P_RGETLOCK:
		proto_tree_add_item(ninep_tree, hf_9P_lock_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(ninep_tree, hf_9P_lock_flag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_lock_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_lock_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(ninep_tree, hf_9P_lock_procid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		conv_free_tag(pinfo, tag);
		break;

	case _9P_TLINK:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_dfid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TMKDIR:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		ti = proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		dissect_9P_dm(tvb, ti, offset, 0);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TRENAMEAT:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_dfid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_newfid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;
		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TUNLINKAT:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_dfid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		offset += 4;

		_9p_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset+2, _9p_len, ENC_UTF_8|ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_9P_wname);
		proto_tree_add_item(sub_tree, hf_9P_parmsz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += _9p_len + 2;

		/* missing 32bit flag, no clue what meaning it has */

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	case _9P_TREMOVE:
	case _9P_TCLUNK:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));
		conv_free_fid(pinfo, fid);

		conv_set_tag(pinfo, tag, ninemsg, fid, NULL);
		break;

	/* Request with only fid */
	case _9P_TSTATFS:
	case _9P_TREADLINK:
	case _9P_TFSYNC:
	case _9P_TSTAT:
		fid = tvb_get_letohl(tvb, offset);
		ti = proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti, " (%s)", conv_get_fid(pinfo, fid));

		conv_set_tag(pinfo, tag, ninemsg, _9P_NOFID, NULL);
		break;

	/* Reply with qid and ionuit */
	case _9P_RCREATE:
	case _9P_RLCREATE:
		dissect_9P_qid(tvb, ninep_tree, offset);
		offset += 13;
		proto_tree_add_item(ninep_tree, hf_9P_iounit, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		taginfo = conv_get_tag(pinfo, tag);
		if (taginfo && taginfo->fid_path) {
			conv_set_fid_nocopy(pinfo, taginfo->fid, taginfo->fid_path);
		}

		conv_free_tag(pinfo, tag);
		break;

	case _9P_ROPEN:
	case _9P_RLOPEN:
		dissect_9P_qid(tvb, ninep_tree, offset);
		offset += 13;
		proto_tree_add_item(ninep_tree, hf_9P_iounit, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		conv_free_tag(pinfo, tag);
		break;

	/* Reply with only qid */
	case _9P_RSYMLINK:
	case _9P_RMKNOD:
	case _9P_RMKDIR:
	case _9P_RAUTH:
	case _9P_RATTACH:
		dissect_9P_qid(tvb, ninep_tree, offset);
		offset += 13;

		conv_free_tag(pinfo, tag);
		break;

	/* Empty reply */
	case _9P_RRENAME:
	case _9P_RSETATTR:
	case _9P_RXATTRCREATE:
	case _9P_RFSYNC:
	case _9P_RLINK:
	case _9P_RRENAMEAT:
	case _9P_RUNLINKAT:
	case _9P_RFLUSH:
	case _9P_RCLUNK:
	case _9P_RREMOVE:
	/* Unhandled reply */
	case _9P_RWSTAT:
	case _9P_RLERROR:
		conv_free_tag(pinfo, tag);
		break;

	/* Should-not-happen query */
	case _9P_TLERROR:
	case _9P_TERROR:
	default:
		proto_tree_add_text(ninep_tree, tvb, 0, 0, "This message type should not happen");
		break;
	}
	return offset;
}
/* dissect 9P open mode flags */
static void dissect_9P_mode(tvbuff_t *tvb,  proto_item *item, int offset)
{
	proto_item *mode_tree;
	guint8 mode;

	mode = tvb_get_guint8(tvb, offset);
	mode_tree = proto_item_add_subtree(item, ett_9P_omode);
	if(!mode_tree)
		return;
	proto_tree_add_boolean(mode_tree, hf_9P_mode_c, tvb, offset, 1, mode);
	proto_tree_add_boolean(mode_tree, hf_9P_mode_t, tvb, offset, 1, mode);
	proto_tree_add_uint(mode_tree, hf_9P_mode_rwx, tvb, offset, 1, mode);
}

/* dissect 9P Qid */
static void dissect_9P_qid(tvbuff_t *tvb,  proto_tree *tree, int offset)
{
	proto_item *qidtype_item;
	proto_tree *qid_tree,*qidtype_tree;
	guint64 path;
	guint32 vers;
	guint8 type;

	if(!tree)
		return;

	type = tvb_get_guint8(tvb, offset);
	vers = tvb_get_letohs(tvb, offset+1);
	path = tvb_get_letoh64(tvb, offset+1+4);

	qid_tree = proto_tree_add_subtree_format(tree, tvb, offset, 13, ett_9P_qid, NULL,
                    "Qid type=0x%02x vers=%d path=%" G_GINT64_MODIFIER "u", type, vers, path);

	qidtype_item = proto_tree_add_item(qid_tree, hf_9P_qidtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	qidtype_tree = proto_item_add_subtree(qidtype_item, ett_9P_qidtype);

	proto_tree_add_item(qidtype_tree, hf_9P_qidtype_dir,       tvb, offset,     1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qidtype_tree, hf_9P_qidtype_append,    tvb, offset,     1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qidtype_tree, hf_9P_qidtype_exclusive, tvb, offset,     1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qidtype_tree, hf_9P_qidtype_mount,     tvb, offset,     1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qidtype_tree, hf_9P_qidtype_auth_file, tvb, offset,     1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qidtype_tree, hf_9P_qidtype_temp_file, tvb, offset,     1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(qid_tree, hf_9P_qidvers,               tvb, offset+1,   4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qid_tree, hf_9P_qidpath,               tvb, offset+1+4, 8, ENC_LITTLE_ENDIAN);
}

/*dissect 9P stat mode and create perm flags */
static void dissect_9P_dm(tvbuff_t *tvb,  proto_item *item, int offset, int iscreate)
{
	proto_item *mode_tree;


	mode_tree = proto_item_add_subtree(item, ett_9P_dm);
	if(!mode_tree)
		return;

	proto_tree_add_item(mode_tree, hf_9P_dm_dir, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	if(!iscreate) { /* Not applicable to Tcreate (?) */
		proto_tree_add_item(mode_tree, hf_9P_dm_append,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(mode_tree, hf_9P_dm_exclusive, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(mode_tree, hf_9P_dm_mount,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(mode_tree, hf_9P_dm_auth_file, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(mode_tree, hf_9P_dm_temp_file, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}

	proto_tree_add_item(mode_tree, hf_9P_dm_read_owner,   tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_write_owner,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_exec_owner,   tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_read_group,   tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_write_group,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_exec_group,   tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_read_others,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_write_others, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(mode_tree, hf_9P_dm_exec_others,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect 9P getattr_flags */
static void dissect_9P_getattrflags(tvbuff_t *tvb, proto_item *item, int offset)
{
	proto_item *attrmask_tree;

	attrmask_tree = proto_item_add_subtree(item, ett_9P_getattr_flags);
	if(!attrmask_tree)
		return;

	/* fixme: This is actually 8 bytes (64bit) long, but masks have to fit on 32bit. */
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_mode,        tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_nlink,       tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_uid,         tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_gid,         tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_rdev,        tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_atime,       tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_mtime,       tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_ctime,       tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_ino,         tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_size,        tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_blocks,      tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_btime,       tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_gen,         tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_getattr_dataversion, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect 9P setattr_flags */
static void dissect_9P_setattrflags(tvbuff_t *tvb, proto_item *item, int offset)
{
	proto_item *attrmask_tree;

	attrmask_tree = proto_item_add_subtree(item, ett_9P_setattr_flags);
	if(!attrmask_tree)
		return;

	proto_tree_add_item(attrmask_tree, hf_9P_setattr_mode,      tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_uid,       tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_gid,       tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_size,      tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_atime,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_mtime,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_ctime,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_atime_set, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_setattr_mtime_set, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect 9P lflags */
static void dissect_9P_lflags(tvbuff_t *tvb, proto_item *item, int offset)
{
	proto_item *attrmask_tree;

	attrmask_tree = proto_item_add_subtree(item, ett_9P_lflags);
	if(!attrmask_tree)
		return;

	proto_tree_add_item(attrmask_tree, hf_9P_lflags_rdonly,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_wronly,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_rdwr,      tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_create,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_excl,      tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_noctty,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_trunc,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_append,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_nonblock,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_dsync,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_fasync,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_direct,    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_largefile, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_directory, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_nofollow,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_noatime,   tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_cloexec,   tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(attrmask_tree, hf_9P_lflags_sync,      tvb, offset, 4, ENC_LITTLE_ENDIAN);
}


/* Register 9P with Wireshark */
void proto_register_9P(void)
{
	static hf_register_info hf[] = {
		{&hf_9P_msgsz,
		 {"Msg length", "9p.msglen", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "9P Message Length", HFILL}},
		{&hf_9P_msgtype,
		 {"Msg Type", "9p.msgtype", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ninep_msg_type_ext, 0x0,
		  "Message Type", HFILL}},
		{&hf_9P_tag,
		 {"Tag", "9p.tag", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "9P Tag", HFILL}},
		{&hf_9P_oldtag,
		 {"Old tag", "9p.oldtag", FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_parmsz,
		 {"Param length", "9p.paramsz", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Parameter length", HFILL}},
		{&hf_9P_maxsize,
		 {"Max msg size", "9p.maxsize", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Max message size", HFILL}},
		{&hf_9P_fid,
		 {"Fid", "9p.fid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "File ID", HFILL}},
		{&hf_9P_nqid,
		 {"Nr Qids", "9p.nqid", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Number of Qid results", HFILL}},
		{&hf_9P_mode,
		 {"Mode", "9p.mode", FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_mode_rwx,
		 {"Open/Create Mode", "9p.mode.rwx", FT_UINT8, BASE_OCT | BASE_EXT_STRING, &ninep_mode_vals_ext, _9P_MODEMASK,
		  NULL, HFILL}},
		{&hf_9P_mode_t,
		 {"Trunc", "9p.mode.trunc", FT_BOOLEAN, 8, TFS(&tfs_set_notset), _9P_OTRUNC,
		  "Truncate", HFILL}},
		{&hf_9P_mode_c,
		 {"Remove on close", "9p.mode.orclose", FT_BOOLEAN, 8, TFS(&tfs_set_notset), _9P_ORCLOSE,
		  NULL, HFILL}},
		{&hf_9P_iounit,
		 {"I/O Unit", "9p.iounit", FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_count,
		 {"Count", "9p.count", FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_offset,
		 {"Offset", "9p.offset", FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_perm,
		 {"Permissions", "9p.perm", FT_UINT32, BASE_OCT, NULL, 0x0,
		  "Permission bits", HFILL}},
		{&hf_9P_qidpath,
		 {"Qid path", "9p.qidpath", FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_dm_dir,
		 {"Directory", "9p.dm.dir", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x80000000,
		  NULL, HFILL}},
		{&hf_9P_dm_append,
		 {"Append only", "9p.dm.append", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x40000000,
		  NULL, HFILL}},
		{&hf_9P_dm_exclusive,
		 {"Exclusive use", "9p.dm.exclusive", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x20000000,
		  NULL, HFILL}},
		{&hf_9P_dm_mount,
		 {"Mounted channel", "9p.dm.mount", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x10000000,
		  NULL, HFILL}},
		{&hf_9P_dm_auth_file,
		 {"Authentication file", "9p.dm.auth_file", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x08000000,
		  NULL, HFILL}},
		{&hf_9P_dm_temp_file,
		 {"Temporary file (not backed up)", "9p.dm.temp_file", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x04000000,
		  NULL, HFILL}},
		{&hf_9P_dm_read_owner,
		 {"Read permission for owner", "9p.dm.read_owner", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000400,
		  NULL, HFILL}},
		{&hf_9P_dm_write_owner,
		 {"Write permission for owner", "9p.dm.write_owner", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000200,
		  NULL, HFILL}},
		{&hf_9P_dm_exec_owner,
		 {"Execute permission for owner", "9p.dm.exec_owner", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000100,
		  NULL, HFILL}},
		{&hf_9P_dm_read_group,
		 {"Read permission for group", "9p.dm.read_group", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000040,
		  NULL, HFILL}},
		{&hf_9P_dm_write_group,
		 {"Write permission for group", "9p.dm.write_group", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000020,
		  NULL, HFILL}},
		{&hf_9P_dm_exec_group,
		 {"Execute permission for group", "9p.dm.exec_group", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000010,
		  NULL, HFILL}},
		{&hf_9P_dm_read_others,
		 {"Read permission for others", "9p.dm.read_others", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
		  NULL, HFILL}},
		{&hf_9P_dm_write_others,
		 {"Write permission for others", "9p.dm.write_others", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
		  NULL, HFILL}},
		{&hf_9P_dm_exec_others,
		 {"Execute permission for others", "9p.dm.exec_others", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
		  NULL, HFILL}},
		{&hf_9P_qidvers,
		 {"Qid version", "9p.qidvers", FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_qidtype,
		 {"Qid type", "9p.qidtype", FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_qidtype_dir,
		 {"Directory", "9p.qidtype.dir", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
		  NULL, HFILL}},
		{&hf_9P_qidtype_append,
		 {"Append only", "9p.qidtype.append", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
		  NULL, HFILL}},
		{&hf_9P_qidtype_exclusive,
		 {"Exclusive use", "9p.qidtype.exclusive", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
		  NULL, HFILL}},
		{&hf_9P_qidtype_mount,
		 {"Mounted channel", "9p.qidtype.mount", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
		  NULL, HFILL}},
		{&hf_9P_qidtype_auth_file,
		 {"Authentication file", "9p.qidtype.auth_file", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
		  NULL, HFILL}},
		{&hf_9P_qidtype_temp_file,
		 {"Temporary file (not backed up)", "9p.qidtype.temp_file", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
		  NULL, HFILL}},
		{&hf_9P_statmode,
		 {"Mode", "9p.statmode", FT_UINT32, BASE_OCT, NULL, 0x0,
		  "File mode flags", HFILL}},
		{&hf_9P_stattype,
		 {"Type", "9p.stattype", FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_atime,
		 {"Atime", "9p.atime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "Access Time", HFILL}},
		{&hf_9P_mtime,
		 {"Mtime", "9p.mtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "Modified Time", HFILL}},
		{&hf_9P_ctime,
		 {"Ctime", "9p.ctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "Creation Time", HFILL}},
		{&hf_9P_btime,
		 {"Btime", "9p.btime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "Btime (Synchronization information)", HFILL}},
		{&hf_9P_length,
		 {"Length", "9p.length", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "File Length", HFILL}},
		{&hf_9P_dev,
		 {"Dev", "9p.dev", FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_wname,
		 {"Wname", "9p.wname", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Path Name Element", HFILL}},
		{&hf_9P_version,
		 {"Version", "9p.version", FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_afid,
		 {"Afid", "9p.afid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Authenticating FID", HFILL}},
		{&hf_9P_uname,
		 {"Uname", "9p.uname", FT_STRING, BASE_NONE, NULL, 0x0,
		  "User Name", HFILL}},
		{&hf_9P_aname,
		 {"Aname", "9p.aname", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Access Name", HFILL}},
		{&hf_9P_ename,
		 {"Ename", "9p.ename", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Error", HFILL}},
		{&hf_9P_enum,
		 {"Enum", "9p.enum", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Error", HFILL}},
		{&hf_9P_name,
		 {"Name", "9p.name", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Name of file", HFILL}},
		{&hf_9P_sdlen,
		 {"Stat data length", "9p.sdlen", FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_filename,
		 {"File name", "9p.filename", FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_user,
		 {"User", "9p.user", FT_STRING, BASE_NONE, NULL, 0x0,
		  "User name", HFILL}},
		{&hf_9P_group,
		 {"Group", "9p.group", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Group name", HFILL}},
		{&hf_9P_uid,
		 {"Uid", "9p.uid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "User id", HFILL}},
		{&hf_9P_gid,
		 {"Gid", "9p.gid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Group id", HFILL}},
		{&hf_9P_muid,
		 {"Muid", "9p.muid", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Last modifiers uid", HFILL}},
		{&hf_9P_newfid,
		 {"New fid", "9p.newfid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "New file ID", HFILL}},
		{&hf_9P_dfid,
		 {"Directory fid", "9p.dfid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Directory ID", HFILL}},
		{&hf_9P_nwalk,
		 {"Nr Walks", "9p.nwalk", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Nr of walk items", HFILL}},
		{&hf_9P_nlink,
		 {"nlink", "9p.nlink", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Number of links", HFILL}},
		{&hf_9P_getattr_flags,
		 {"getattr_flags", "9p.getattr.flags", FT_UINT64, BASE_HEX, NULL, _9P_GETATTR_ALL,
		  "Getattr flags", HFILL}},
		{&hf_9P_getattr_mode,
		 {"Mode", "9p.getattr.mode", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_MODE,
		  NULL, HFILL}},
		{&hf_9P_getattr_nlink,
		 {"Nlink", "9p.getattr.nlink", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_NLINK,
		  NULL, HFILL}},
		{&hf_9P_getattr_uid,
		 {"UID", "9p.getattr.uid", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_UID,
		  NULL, HFILL}},
		{&hf_9P_getattr_gid,
		 {"GID", "9p.getattr.gid", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_GID,
		  NULL, HFILL}},
		{&hf_9P_getattr_rdev,
		 {"Rdev", "9p.getattr.rdev", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_RDEV,
		  NULL, HFILL}},
		{&hf_9P_getattr_atime,
		 {"Atime", "9p.getattr.atime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_ATIME,
		  NULL, HFILL}},
		{&hf_9P_getattr_mtime,
		 {"Mtime", "9p.getattr.mtime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_MTIME,
		  NULL, HFILL}},
		{&hf_9P_getattr_ctime,
		 {"Ctime", "9p.getattr.ctime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_CTIME,
		  NULL, HFILL}},
		{&hf_9P_getattr_ino,
		 {"Inode", "9p.getattr.inode", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_INO,
		  NULL, HFILL}},
		{&hf_9P_getattr_size,
		 {"Size", "9p.getattr.size", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_SIZE,
		  NULL, HFILL}},
		{&hf_9P_getattr_blocks,
		 {"Blocks", "9p.getattr.blocks", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_BLOCKS,
		  NULL, HFILL}},
		{&hf_9P_getattr_btime,
		 {"Btime", "9p.getattr.btime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_BTIME,
		  NULL, HFILL}},
		{&hf_9P_getattr_gen,
		 {"Gen", "9p.getattr.gen", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_GEN,
		  NULL, HFILL}},
		{&hf_9P_getattr_dataversion,
		 {"Data version", "9p.getattr.dataversion", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_GETATTR_DATA_VERSION,
		  NULL, HFILL}},
		{&hf_9P_setattr_flags,
		 {"setattr_flags", "9p.setattr.flags", FT_UINT32, BASE_HEX, NULL, _9P_SETATTR_ALL,
		  "Setattr flags", HFILL}},
		{&hf_9P_setattr_mode,
		 {"Mode", "9p.setattr.mode", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_MODE,
		  NULL, HFILL}},
		{&hf_9P_setattr_uid,
		 {"UID", "9p.setattr.uid", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_UID,
		  NULL, HFILL}},
		{&hf_9P_setattr_gid,
		 {"GID", "9p.setattr.gid", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_GID,
		  NULL, HFILL}},
		{&hf_9P_setattr_size,
		 {"Size", "9p.setattr.size", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_SIZE,
		  NULL, HFILL}},
		{&hf_9P_setattr_atime,
		 {"Atime", "9p.setattr.atime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_ATIME,
		  NULL, HFILL}},
		{&hf_9P_setattr_mtime,
		 {"Mtime", "9p.setattr.mtime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_MTIME,
		  NULL, HFILL}},
		{&hf_9P_setattr_ctime,
		 {"Ctime", "9p.setattr.ctime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_CTIME,
		  NULL, HFILL}},
		{&hf_9P_setattr_atime_set,
		 {"Atime set", "9p.setattr.atimeset", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_ATIME_SET,
		  NULL, HFILL}},
		{&hf_9P_setattr_mtime_set,
		 {"Mtime set", "9p.setattr.mtimeset", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_SETATTR_MTIME_SET,
		  NULL, HFILL}},
		{&hf_9P_rdev,
		 {"rdev", "9p.rdev", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Device associated with file", HFILL}},
		{&hf_9P_size,
		 {"Size", "9p.size", FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_blksize,
		 {"Blksize", "9p.blksize", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Block size", HFILL}},
		{&hf_9P_blocks,
		 {"Blocks", "9p.blocks", FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_9P_gen,
		 {"Gen", "9p.gen", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "inode generation number", HFILL}},
		{&hf_9P_dataversion,
		 {"Dataversion", "9p.dataversion", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Data version", HFILL}},
		{&hf_9P_fstype,
		 {"fstype", "9p.fstype", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Filesystem type", HFILL}},
		{&hf_9P_bfree,
		 {"bfree", "9p.bfree", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Free blocks", HFILL}},
		{&hf_9P_bavail,
		 {"bavail", "9p.bavail", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Available blocks", HFILL}},
		{&hf_9P_files,
		 {"files", "9p.files", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Total files", HFILL}},
		{&hf_9P_ffree,
		 {"ffree", "9p.ffree", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Free files", HFILL}},
		{&hf_9P_fsid,
		 {"fsid", "9p.fsid", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Filesystem id", HFILL}},
		{&hf_9P_namelen,
		 {"namelen", "9p.namelen", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Max name length", HFILL}},
		{&hf_9P_mknod_major,
		 {"mknod_major", "9p.mknod.major", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Major node number", HFILL}},
		{&hf_9P_mknod_minor,
		 {"mknod_minor", "9p.mknod.minor", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Minor node number", HFILL}},
		{&hf_9P_lflags,
		 {"lflags", "9p.lcreate.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Lcreate flags", HFILL}},
		/* rdonly is 0x00, check instead that we are neither wronly nor rdwrite */
		{&hf_9P_lflags_rdonly,
		 {"Read only", "9p.lflags.rdonly", FT_BOOLEAN, 32, TFS(&tfs_no_yes), _9P_DOTL_WRONLY|_9P_DOTL_RDWR,
		  NULL, HFILL}},
		{&hf_9P_lflags_wronly,
		 {"Write only", "9p.lflags.wronly", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_WRONLY,
		  NULL, HFILL}},
		{&hf_9P_lflags_rdwr,
		 {"Read Write", "9p.lflags.rdwr", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_RDWR,
		  NULL, HFILL}},
		{&hf_9P_lflags_create,
		 {"Create", "9p.lflags.create", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_CREATE,
		  NULL, HFILL}},
		{&hf_9P_lflags_excl,
		 {"Exclusive", "9p.lflags.excl", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_EXCL,
		  NULL, HFILL}},
		{&hf_9P_lflags_noctty,
		 {"noctty", "9p.lflags.noctty", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_NOCTTY,
		  NULL, HFILL}},
		{&hf_9P_lflags_trunc,
		 {"Truncate", "9p.lflags.trunc", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_TRUNC,
		  NULL, HFILL}},
		{&hf_9P_lflags_append,
		 {"Append", "9p.lflags.append", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_APPEND,
		  NULL, HFILL}},
		{&hf_9P_lflags_nonblock,
		 {"Nonblock", "9p.lflags.nonblock", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_NONBLOCK,
		  NULL, HFILL}},
		{&hf_9P_lflags_dsync,
		 {"dsync", "9p.lflags.dsync", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_DSYNC,
		  NULL, HFILL}},
		{&hf_9P_lflags_fasync,
		 {"fasync", "9p.lflags.fasync", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_FASYNC,
		  NULL, HFILL}},
		{&hf_9P_lflags_direct,
		 {"Direct", "9p.lflags.direct", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_DIRECT,
		  NULL, HFILL}},
		{&hf_9P_lflags_largefile,
		 {"Large File", "9p.lflags.largefile", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_LARGEFILE,
		  NULL, HFILL}},
		{&hf_9P_lflags_directory,
		 {"Directory", "9p.lflags.directory", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_DIRECTORY,
		  NULL, HFILL}},
		{&hf_9P_lflags_nofollow,
		 {"No follow", "9p.lflags.nofollow", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_NOFOLLOW,
		  NULL, HFILL}},
		{&hf_9P_lflags_noatime,
		 {"No atime", "9p.lflags.noatime", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_NOATIME,
		  NULL, HFILL}},
		{&hf_9P_lflags_cloexec,
		 {"cloexec", "9p.lflags.cloexec", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_CLOEXEC,
		  NULL, HFILL}},
		{&hf_9P_lflags_sync,
		 {"Sync", "9p.lflags.sync", FT_BOOLEAN, 32, TFS(&tfs_yes_no), _9P_DOTL_SYNC,
		  NULL, HFILL}},
		{&hf_9P_xattr_flag,
		 {"xattr_flag", "9p.xattr.flag", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Xattr flag", HFILL}},
		{&hf_9P_lock_type,
		 {"lock_type", "9p.lock.type", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &ninep_lock_type_ext, 0x0,
		  "Lock type", HFILL}},
		{&hf_9P_lock_flag,
		 {"lock_flag", "9p.lock.flag", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &ninep_lock_flag_ext, 0x0,
		  "Lock flag", HFILL}},
		{&hf_9P_lock_start,
		 {"lock_start", "9p.lock.start", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Lock start", HFILL}},
		{&hf_9P_lock_length,
		 {"lock_length", "9p.lock.length", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Lock length", HFILL}},
		{&hf_9P_lock_procid,
		 {"lock_procid", "9p.lock.procid", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Lock procid", HFILL}},
		{&hf_9P_lock_status,
		 {"lock_status", "9p.lock.status", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ninep_lock_status_ext, 0x0,
		  "Lock status", HFILL}}
	};

	static gint *ett[] = {
		&ett_9P,
		&ett_9P_omode,
		&ett_9P_dm,
		&ett_9P_wname,
		&ett_9P_aname,
		&ett_9P_ename,
		&ett_9P_uname,
		&ett_9P_user,
		&ett_9P_group,
		&ett_9P_muid,
		&ett_9P_filename,
		&ett_9P_version,
		&ett_9P_qid,
		&ett_9P_qidtype,
		&ett_9P_getattr_flags,
		&ett_9P_setattr_flags,
		&ett_9P_lflags,
	};

	proto_9P = proto_register_protocol("Plan 9", "9P", "9p");

	proto_register_field_array(proto_9P, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine(_9p_hash_init);
}

void proto_reg_handoff_9P(void)
{
	dissector_handle_t ninep_handle;

	data_handle = find_dissector("data");

	ninep_handle = new_create_dissector_handle(dissect_9P, proto_9P);

	dissector_add_uint("tcp.port", NINEPORT, ninep_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
