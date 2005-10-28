/* packet-pvfs.c
 * Routines for pvfs2 packet dissection
 * By Mike Frisch <mfrisch@platform.com>
 * Joint and Several Copyright 2005, Mike Frisch and Platform Computing Inc.
 *
 * $Id: packet-pvfs.c,v 1.32 2005/10/05 21:13:30 mfrisch Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c and others
 *
 * TODO
 *
 *    - Add filename snooping (match file handles with file names),
 *      similar to how packet-rpc.c/packet-nfs.c implements it
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/strutil.h>

#define TCP_PORT_PVFS2 3334

#define PVFS2_FH_LENGTH 8

/* Header incl. magic number, mode, tag, size */
#define BMI_HEADER_SIZE 24

/* Forward declaration we need below */
void proto_reg_handoff_pvfs(void);

/* Initialize the protocol and registered fields */
static int proto_pvfs = -1;
static int hf_pvfs_magic_nr = -1;
static int hf_pvfs_mode = -1;
static int hf_pvfs_tag = -1;
static int hf_pvfs_size = -1;
static int hf_pvfs_release_number = -1;
static int hf_pvfs_encoding = -1;
static int hf_pvfs_server_op = -1;
static int hf_pvfs_handle = -1;
static int hf_pvfs_fs_id = -1;
static int hf_pvfs_attrmask = -1;
static int hf_pvfs_attr = -1;
static int hf_pvfs_ds_type = -1;
static int hf_pvfs_error = -1;
static int hf_pvfs_atime = -1;
static int hf_pvfs_atime_sec = -1;
static int hf_pvfs_atime_nsec = -1;
static int hf_pvfs_mtime = -1;
static int hf_pvfs_mtime_sec = -1;
static int hf_pvfs_mtime_nsec = -1;
static int hf_pvfs_ctime = -1;
static int hf_pvfs_ctime_sec = -1;
static int hf_pvfs_ctime_nsec = -1;
static int hf_pvfs_parent_atime = -1;
static int hf_pvfs_parent_atime_sec = -1;
static int hf_pvfs_parent_atime_nsec = -1;
static int hf_pvfs_parent_mtime = -1;
static int hf_pvfs_parent_mtime_sec = -1;
static int hf_pvfs_parent_mtime_nsec = -1;
static int hf_pvfs_parent_ctime = -1;
static int hf_pvfs_parent_ctime_sec = -1;
static int hf_pvfs_parent_ctime_nsec = -1;
static int hf_pvfs_dirent_count = -1;
static int hf_pvfs_directory_version = -1;
static int hf_pvfs_path = -1;
static int hf_pvfs_total_completed = -1;
static int hf_pvfs_io_dist = -1;
static int hf_pvfs_aggregate_size = -1;
static int hf_pvfs_io_type = -1;
static int hf_pvfs_flowproto_type = -1;
static int hf_pvfs_server_param = -1;
static int hf_pvfs_prev_value = -1;
static int hf_pvfs_ram_free_bytes = -1;
static int hf_pvfs_bytes_available = -1;
static int hf_pvfs_bytes_total = -1;
static int hf_pvfs_ram_bytes_total = -1;
static int hf_pvfs_ram_bytes_free = -1;
static int hf_pvfs_load_average_1s = -1;
static int hf_pvfs_load_average_5s = -1;
static int hf_pvfs_load_average_15s = -1;
static int hf_pvfs_uptime_seconds = -1;
static int hf_pvfs_handles_available = -1;
static int hf_pvfs_handles_total = -1;
static int hf_pvfs_unused = -1;
static int hf_pvfs_context_id = -1;
static int hf_pvfs_offset = -1;
static int hf_pvfs_stride = -1;
static int hf_pvfs_lb = -1;
static int hf_pvfs_ub = -1;
static int hf_pvfs_end_time_ms = -1;
static int hf_pvfs_cur_time_ms = -1;
static int hf_pvfs_start_time_ms = -1;
static int hf_pvfs_bytes_written = -1;
static int hf_pvfs_bytes_read = -1;
static int hf_pvfs_metadata_write = -1;
static int hf_pvfs_metadata_read = -1;
static int hf_pvfs_b_size = -1;
static int hf_pvfs_k_size = -1;
static int hf_pvfs_id_gen_t = -1;
static int hf_pvfs_attribute_key = -1;
static int hf_pvfs_attribute_value = -1;
static int hf_pvfs_strip_size = -1;
static int hf_pvfs_ereg = -1;
static int hf_pvfs_sreg = -1;
static int hf_pvfs_num_eregs = -1;
static int hf_pvfs_num_blocks = -1;
static int hf_pvfs_num_contig_chunks = -1;
static int hf_pvfs_server_nr = -1;
static int hf_pvfs_server_count = -1;
static int hf_pvfs_fh_length = -1;
static int hf_pvfs_fh_hash = -1;

/* Initialize the subtree pointers */
static gint ett_pvfs = -1;
static gint ett_pvfs_hdr = -1;
static gint ett_pvfs_credentials = -1;
static gint ett_pvfs_server_config = -1;
static gint ett_pvfs_server_config_branch = -1;
static gint ett_pvfs_attrmask = -1;
static gint ett_pvfs_time = -1;
static gint ett_pvfs_extent_array_tree = -1;
static gint ett_pvfs_extent_item = -1;
static gint ett_pvfs_string = -1;
static gint ett_pvfs_attr_tree = -1;
static gint ett_pvfs_distribution = -1;
static gint ett_pvfs_mgmt_perf_stat = -1;
static gint ett_pvfs_mgmt_dspace_info = -1;
static gint ett_pvfs_attr = -1;
static gint ett_pvfs_fh = -1;

#define BMI_MAGIC_NR 51903

static const value_string names_pvfs_mode[] = 
{
#define TCP_MODE_IMMED 1
	{ TCP_MODE_IMMED, "TCP_MODE_IMMED" },
#define TCP_MODE_UNEXP 2
	{ TCP_MODE_UNEXP, "TCP_MODE_UNEXP" },
#define TCP_MODE_EAGER 4
	{ TCP_MODE_EAGER, "TCP_MODE_EAGER" },
#define TCP_MODE_REND 8
	{ TCP_MODE_REND,  "TCP_MODE_REND" },
	{ 0, NULL }
};

static const value_string names_pvfs_encoding[] =
{
#define PVFS_ENCODING_DIRECT 1
	{ PVFS_ENCODING_DIRECT, "ENCODING_DIRECT" },
#define PVFS_ENCODING_LE_BFIELD 2
	{ PVFS_ENCODING_LE_BFIELD, "ENCODING_LE_BFIELD" },
#define PVFS_ENCODING_XDR 3
	{ PVFS_ENCODING_XDR, "ENCODING_XDR" },
	{ 0, NULL }
};

static const value_string names_pvfs_io_type[] =
{
#define PVFS_IO_READ 1
	{ PVFS_IO_READ, "PVFS_IO_READ" },
#define PVFS_IO_WRITE 2
	{ PVFS_IO_WRITE, "PVFS_IO_WRITE" },
	{ 0, NULL }
};

static const value_string names_pvfs_flowproto_type[] =
{
#define FLOWPROTO_DUMP_OFFSETS 1
	{ FLOWPROTO_DUMP_OFFSETS, "FLOWPROTO_DUMP_OFFSETS" },
#define FLOWPROTO_BMI_CACHE 2
	{ FLOWPROTO_BMI_CACHE, "FLOWPROTO_BMI_CACHE" },
#define FLOWPROTO_MULTIQUEUE 3
	{ FLOWPROTO_MULTIQUEUE, "FLOWPROTO_MULTIQUEUE" },
	{ 0, NULL }
};

static const value_string names_pvfs_server_param[] =
{
#define PVFS_SERV_PARAM_INVALID 0
	{ PVFS_SERV_PARAM_INVALID, "PVFS_SERV_PARAM_INVALID" },
#define PVFS_SERV_PARAM_GOSSIP_MASK 1
	{ PVFS_SERV_PARAM_GOSSIP_MASK, "PVFS_SERV_PARAM_GOSSIP_MASK" },
#define PVFS_SERV_PARAM_FSID_CHECK 2
	{ PVFS_SERV_PARAM_FSID_CHECK, "PVFS_SERV_PARAM_FSID_CHECK" },
#define PVFS_SERV_PARAM_ROOT_CHECK 3
	{ PVFS_SERV_PARAM_ROOT_CHECK, "PVFS_SERV_PARAM_ROOT_CHECK" },
#define PVFS_SERV_PARAM_MODE 4
	{ PVFS_SERV_PARAM_MODE, "PVFS_SERV_PARAM_MODE" },
#define PVFS_SERV_PARAM_EVENT_ON 5
	{ PVFS_SERV_PARAM_EVENT_ON, "PVFS_SERV_PARAM_EVENT_ON" },
#define PVFS_SERV_PARAM_EVENT_MASKS 6
	{ PVFS_SERV_PARAM_EVENT_MASKS, "PVFS_SERV_PARAM_EVENT_MASKS" },
	{ 0, NULL }
};

static const value_string names_pvfs_server_mode[] = 
{
#define PVFS_SERVER_NORMAL_MODE 1
	{ PVFS_SERVER_NORMAL_MODE, "PVFS_SERVER_NORMAL_MODE" },
#define PVFS_SERVER_ADMIN_MODE 2
	{ PVFS_SERVER_ADMIN_MODE, "PVFS_SERVER_ADMIN_MODE" },
	{ 0, NULL }
};

/* Forward declaration */
static gboolean
dissect_pvfs_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		gboolean dissect_other_as_continuation);

static int
dissect_pvfs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PVFS");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	dissect_pvfs_common(tvb, pinfo, tree, FALSE);

	return tvb_length(tvb);
}

static gboolean
dissect_pvfs_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* TODO: determine if this is a PVFS packet using heuristics */

	return dissect_pvfs_common(tvb, pinfo, tree, FALSE);
}

static const value_string names_pvfs_server_op[] =
{
#define PVFS_SERV_INVALID 0
	{ PVFS_SERV_INVALID, "PVFS_SERV_INVALID" },
#define PVFS_SERV_CREATE 1
	{ PVFS_SERV_CREATE, "PVFS_SERV_CREATE" },
#define PVFS_SERV_REMOVE 2
	{ PVFS_SERV_REMOVE, "PVFS_SERV_REMOVE" }, 
#define PVFS_SERV_IO 3
	{ PVFS_SERV_IO, "PVFS_SERV_IO" }, 
#define PVFS_SERV_GETATTR 4
	{ PVFS_SERV_GETATTR, "PVFS_SERV_GETATTR" }, 
#define PVFS_SERV_SETATTR 5
	{ PVFS_SERV_SETATTR, "PVFS_SERV_SETATTR" }, 
#define PVFS_SERV_LOOKUP_PATH 6
	{ PVFS_SERV_LOOKUP_PATH, "PVFS_SERV_LOOKUP_PATH" }, 
#define PVFS_SERV_CRDIRENT 7
	{ PVFS_SERV_CRDIRENT, "PVFS_SERV_CRDIRENT" }, 
#define PVFS_SERV_RMDIRENT 8
	{ PVFS_SERV_RMDIRENT, "PVFS_SERV_RMDIRENT" }, 
#define PVFS_SERV_CHDIRENT 9
	{ PVFS_SERV_CHDIRENT, "PVFS_SERV_CHDIRENT" }, 
#define PVFS_SERV_TRUNCATE 10
	{ PVFS_SERV_TRUNCATE, "PVFS_SERV_TRUNCATE" }, 
#define PVFS_SERV_MKDIR 11
	{ PVFS_SERV_MKDIR, "PVFS_SERV_MKDIR" }, 
#define PVFS_SERV_READDIR 12
	{ PVFS_SERV_READDIR, "PVFS_SERV_READDIR" }, 
#define PVFS_SERV_GETCONFIG 13
	{ PVFS_SERV_GETCONFIG, "PVFS_SERV_GETCONFIG" }, 
#define PVFS_SERV_WRITE_COMPLETION 14
	{ PVFS_SERV_WRITE_COMPLETION, "PVFS_SERV_WRITE_COMPLETION" }, 
#define PVFS_SERV_FLUSH 15
	{ PVFS_SERV_FLUSH, "PVFS_SERV_FLUSH" }, 
#define PVFS_SERV_MGMT_SETPARAM 16
	{ PVFS_SERV_MGMT_SETPARAM, "PVFS_SERV_MGMT_SETPARAM" }, 
#define PVFS_SERV_MGMT_NOOP 17
	{ PVFS_SERV_MGMT_NOOP, "PVFS_SERV_MGMT_NOOP" }, 
#define PVFS_SERV_STATFS 18
	{ PVFS_SERV_STATFS, "PVFS_SERV_STATFS" }, 
#define PVFS_SERV_PERF_UPDATE 19  /* not a real protocol request */
	{ PVFS_SERV_PERF_UPDATE, "PVFS_SERV_PERF_UPDATE" }, 
#define PVFS_SERV_MGMT_PERF_MON 20
	{ PVFS_SERV_MGMT_PERF_MON, "PVFS_SERV_MGMT_PERF_MON" }, 
#define PVFS_SERV_MGMT_ITERATE_HANDLES 21
	{ PVFS_SERV_MGMT_ITERATE_HANDLES, "PVFS_SERV_MGMT_ITERATE_HANDLES" }, 
#define PVFS_SERV_MGMT_DSPACE_INFO_LIST 22
	{ PVFS_SERV_MGMT_DSPACE_INFO_LIST, "PVFS_SERV_MGMT_DSPACE_INFO_LIST" }, 
#define PVFS_SERV_MGMT_EVENT_MON 23
	{ PVFS_SERV_MGMT_EVENT_MON, "PVFS_SERV_MGMT_EVENT_MON" }, 
#define PVFS_SERV_MGMT_REMOVE_OBJECT 24
	{ PVFS_SERV_MGMT_REMOVE_OBJECT, "PVFS_SERV_MGMT_REMOVE_OBJECT" }, 
#define PVFS_SERV_MGMT_REMOVE_DIRENT 25
	{ PVFS_SERV_MGMT_REMOVE_DIRENT, "PVFS_SERV_MGMT_REMOVE_DIRENT" }, 
#define PVFS_SERV_MGMT_GET_DIRDATA_HANDLE 26
	{ PVFS_SERV_MGMT_GET_DIRDATA_HANDLE, "PVFS_SERV_MGMT_GET_DIRDATA_HANDLE" }, 
#define PVFS_SERV_JOB_TIMER 27    /* not a real protocol request */
	{ PVFS_SERV_JOB_TIMER, "PVFS_SERV_JOB_TIMER" }, 
#define PVFS_SERV_PROTO_ERROR 28
	{ PVFS_SERV_PROTO_ERROR, "PVFS_SERV_PROTO_ERROR" }, 
#define PVFS_SERV_GETEATTR 29
	{ PVFS_SERV_GETEATTR, "PVFS_SERV_GETEATTR" }, 
#define PVFS_SERV_SETEATTR 30
	{ PVFS_SERV_SETEATTR, "PVFS_SERV_SETEATTR" }, 
#define PVFS_SERV_DELEATTR 31
	{ PVFS_SERV_DELEATTR, "PVFS_SERV_DELEATTR" }, 
	{ 0, NULL }
};

/* special bits used to differentiate PVFS error codes from system
 *  * errno values
 *   */
#define PVFS_ERROR_BIT           (1 << 30)

/* a shorthand to make the error code definitions more readable */
#define E(num) (num|PVFS_ERROR_BIT)

static const value_string names_pvfs_error[] = {
	{ 0, "Success" },
#define PVFS_EPERM            E(1) /* Operation not permitted */
	{ PVFS_EPERM, "PVFS_EPERM" },
#define PVFS_ENOENT           E(2) /* No such file or directory */
	{ PVFS_ENOENT, "PVFS_ENOENT" },
#define PVFS_EINTR            E(3) /* Interrupted system call */
	{ PVFS_EINTR, "PVFS_EINTR" },
#define PVFS_EIO              E(4) /* I/O error */
	{ PVFS_EIO, "PVFS_EIO" },
#define PVFS_ENXIO            E(5) /* No such device or address */
	{ PVFS_ENXIO, "PVFS_ENXIO" },
#define PVFS_EBADF            E(6) /* Bad file number */
	{ PVFS_EBADF, "PVFS_EBADF" },
#define PVFS_EAGAIN           E(7) /* Try again */
	{ PVFS_EAGAIN, "PVFS_EAGAIN" },
#define PVFS_ENOMEM           E(8) /* Out of memory */
	{ PVFS_ENOMEM, "PVFS_ENOMEM" },
#define PVFS_EFAULT           E(9) /* Bad address */
	{ PVFS_EFAULT, "PVFS_EFAULT" },
#define PVFS_EBUSY           E(10) /* Device or resource busy */
	{ PVFS_EBUSY, "PVFS_EBUSY" },
#define PVFS_EEXIST          E(11) /* File exists */
	{ PVFS_EEXIST, "PVFS_EEXIST" },
#define PVFS_ENODEV          E(12) /* No such device */
	{ PVFS_ENODEV, "PVFS_ENODEV" },
#define PVFS_ENOTDIR         E(13) /* Not a directory */
	{ PVFS_ENOTDIR, "PVFS_ENOTDIR" },
#define PVFS_EISDIR          E(14) /* Is a directory */
	{ PVFS_EISDIR, "PVFS_EISDIR" },
#define PVFS_EINVAL          E(15) /* Invalid argument */
	{ PVFS_EINVAL, "PVFS_EINVAL" },
#define PVFS_EMFILE          E(16) /* Too many open files */
	{ PVFS_EMFILE, "PVFS_EMFILE" },
#define PVFS_EFBIG           E(17) /* File too large */
	{ PVFS_EFBIG, "PVFS_EFBIG" },
#define PVFS_ENOSPC          E(18) /* No space left on device */
	{ PVFS_ENOSPC, "PVFS_ENOSPC" },
#define PVFS_EROFS           E(19) /* Read-only file system */
	{ PVFS_EROFS, "PVFS_EROFS" },
#define PVFS_EMLINK          E(20) /* Too many links */
	{ PVFS_EMLINK, "PVFS_EMLINK" },
#define PVFS_EPIPE           E(21) /* Broken pipe */
	{ PVFS_EPIPE, "PVFS_EPIPE" },
#define PVFS_EDEADLK         E(22) /* Resource deadlock would occur */
	{ PVFS_EDEADLK, "PVFS_EDEADLK" },
#define PVFS_ENAMETOOLONG    E(23) /* File name too long */
	{ PVFS_ENAMETOOLONG, "PVFS_ENAMETOOLONG" },
#define PVFS_ENOLCK          E(24) /* No record locks available */
	{ PVFS_ENOLCK, "PVFS_ENOLCK" },
#define PVFS_ENOSYS          E(25) /* Function not implemented */
	{ PVFS_ENOSYS, "PVFS_ENOSYS" },
#define PVFS_ENOTEMPTY       E(26) /* Directory not empty */
	{ PVFS_ENOTEMPTY, "PVFS_ENOTEMPTY" },
#define PVFS_ELOOP           E(27) /* Too many symbolic links encountered */
	{ PVFS_ELOOP, "PVFS_ELOOP" },
#define PVFS_EWOULDBLOCK     E(28) /* Operation would block */
	{ PVFS_EWOULDBLOCK, "PVFS_EWOULDBLOCK" },
#define PVFS_ENOMSG          E(29) /* No message of desired type */
	{ PVFS_ENOMSG, "PVFS_ENOMSG" },
#define PVFS_EUNATCH         E(30) /* Protocol driver not attached */
	{ PVFS_EUNATCH, "PVFS_EUNATCH" },
#define PVFS_EBADR           E(31) /* Invalid request descriptor */
	{ PVFS_EBADR, "PVFS_EBADR" },
#define PVFS_EDEADLOCK       E(32)
	{ PVFS_EDEADLOCK, "PVFS_EDEADLOCK" },
#define PVFS_ENODATA         E(33) /* No data available */
	{ PVFS_ENODATA, "PVFS_ENODATA" },
#define PVFS_ETIME           E(34) /* Timer expired */
	{ PVFS_ETIME, "PVFS_ETIME" },
#define PVFS_ENONET          E(35) /* Machine is not on the network */
	{ PVFS_ENONET, "PVFS_ENONET" },
#define PVFS_EREMOTE         E(36) /* Object is remote */
	{ PVFS_EREMOTE, "PVFS_EREMOTE" },
#define PVFS_ECOMM           E(37) /* Communication error on send */
	{ PVFS_ECOMM, "PVFS_ECOMM" },
#define PVFS_EPROTO          E(38) /* Protocol error */
	{ PVFS_EPROTO, "PVFS_EPROTO" },
#define PVFS_EBADMSG         E(39) /* Not a data message */
	{ PVFS_EBADMSG, "PVFS_EBADMSG" },
#define PVFS_EOVERFLOW       E(40) /* Value too large for defined data type */
	{ PVFS_EOVERFLOW, "PVFS_EOVERFLOW" },
#define PVFS_ERESTART        E(41) /* Interrupted system call should be restarted */
	{ PVFS_ERESTART, "PVFS_ERESTART" },
#define PVFS_EMSGSIZE        E(42) /* Message too long */
	{ PVFS_EMSGSIZE, "PVFS_EMSGSIZE" },
#define PVFS_EPROTOTYPE      E(43) /* Protocol wrong type for socket */
	{ PVFS_EPROTOTYPE, "PVFS_EPROTOTYPE" },
#define PVFS_ENOPROTOOPT     E(44) /* Protocol not available */
	{ PVFS_ENOPROTOOPT, "PVFS_ENOPROTOOPT" },
#define PVFS_EPROTONOSUPPORT E(45) /* Protocol not supported */
	{ PVFS_EPROTONOSUPPORT, "PVFS_EPROTONOSUPPORT" },
#define PVFS_EOPNOTSUPP      E(46) /* Operation not supported on transport endpoint */
	{ PVFS_EOPNOTSUPP, "PVFS_EOPNOTSUPP" },
#define PVFS_EADDRINUSE      E(47) /* Address already in use */
	{ PVFS_EADDRINUSE, "PVFS_EADDRINUSE" },
#define PVFS_EADDRNOTAVAIL   E(48) /* Cannot assign requested address */
	{ PVFS_EADDRNOTAVAIL, "PVFS_EADDRNOTAVAIL" },
#define PVFS_ENETDOWN        E(49) /* Network is down */
	{ PVFS_ENETDOWN, "PVFS_ENETDOWN" },
#define PVFS_ENETUNREACH     E(50) /* Network is unreachable */
	{ PVFS_ENETUNREACH, "PVFS_ENETUNREACH" },
#define PVFS_ENETRESET       E(51) /* Network dropped connection because of reset */
	{ PVFS_ENETRESET, "PVFS_ENETRESET" },
#define PVFS_ENOBUFS         E(52) /* No buffer space available */
	{ PVFS_ENOBUFS, "PVFS_ENOBUFS" },
#define PVFS_ETIMEDOUT       E(53) /* Connection timed out */
	{ PVFS_ETIMEDOUT, "PVFS_ETIMEDOUT" },
#define PVFS_ECONNREFUSED    E(54) /* Connection refused */
	{ PVFS_ECONNREFUSED, "PVFS_ECONNREFUSED" },
#define PVFS_EHOSTDOWN       E(55) /* Host is down */
	{ PVFS_EHOSTDOWN, "PVFS_EHOSTDOWN" },
#define PVFS_EHOSTUNREACH    E(56) /* No route to host */
	{ PVFS_EHOSTUNREACH, "PVFS_EHOSTUNREACH" },
#define PVFS_EALREADY        E(57) /* Operation already in progress */
	{ PVFS_EALREADY, "PVFS_EALREADY" },
#define PVFS_EACCES          E(58) /* Operation already in progress */
	{ PVFS_EACCES, "PVFS_EACCES" },
	{ 0, NULL }
};

static int
dissect_pvfs2_error(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	gint32 err;
	const char *errmsg = NULL;

	err = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_pvfs_error, tvb, offset, 4, -err);
	offset += 4;

	if ((err != 0) && check_col(pinfo->cinfo, COL_INFO))
	{
		errmsg = val_to_str(-err, names_pvfs_error, "Unknown error: %u");
		col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", errmsg);
	}

	return offset;
}

static int
dissect_pvfs_credentials(tvbuff_t *tvb, proto_tree *parent_tree, 
		int offset)
{
	proto_item *item = NULL;
	proto_tree *hcred_tree = NULL;
	guint32 uid = 0, gid = 0;

	uid = tvb_get_letohl(tvb, offset);
	gid = tvb_get_letohl(tvb, offset + 4);

	if (parent_tree) 
	{
		item = proto_tree_add_text(parent_tree, tvb, offset, 8, 
				"Credentials (UID: %d, GID: %d)", uid, gid);

		if (item)
			hcred_tree = proto_item_add_subtree(item, ett_pvfs_credentials);
	}

	/* UID */
	proto_tree_add_text(hcred_tree, tvb, offset, 4, "UID: %d", uid);
	offset += 4;

	/* GID */
	proto_tree_add_text(hcred_tree, tvb, offset, 4, "GID: %d", gid);
	offset += 4;

	return offset;
}

static const value_string names_pvfs_attr[] = 
{
#define PVFS_ATTR_COMMON_UID   (1 << 0)
#define PVFS_ATTR_BIT_COMMON_UID 0
	{ PVFS_ATTR_BIT_COMMON_UID, "PVFS_ATTR_COMMON_UID" },

#define PVFS_ATTR_COMMON_GID   (1 << 1)
#define PVFS_ATTR_BIT_COMMON_GID 1
	{ PVFS_ATTR_BIT_COMMON_GID, "PVFS_ATTR_COMMON_GID" },

#define PVFS_ATTR_COMMON_PERM  (1 << 2)
#define PVFS_ATTR_BIT_COMMON_PERM 2
	{ PVFS_ATTR_BIT_COMMON_PERM, "PVFS_ATTR_COMMON_PERM" },

#define PVFS_ATTR_COMMON_ATIME (1 << 3)
#define PVFS_ATTR_BIT_COMMON_ATIME 3
	{ PVFS_ATTR_BIT_COMMON_ATIME, "PVFS_ATTR_COMMON_ATIME" },

#define PVFS_ATTR_COMMON_CTIME (1 << 4)
#define PVFS_ATTR_BIT_COMMON_CTIME 4
	{ PVFS_ATTR_BIT_COMMON_CTIME, "PVFS_ATTR_COMMON_CTIME" },

#define PVFS_ATTR_COMMON_MTIME (1 << 5)
#define PVFS_ATTR_BIT_COMMON_MTIME 5
	{ PVFS_ATTR_BIT_COMMON_MTIME, "PVFS_ATTR_COMMON_MTIME" },

#define PVFS_ATTR_COMMON_TYPE  (1 << 6)
#define PVFS_ATTR_BIT_COMMON_TYPE 6
	{ PVFS_ATTR_BIT_COMMON_TYPE, "PVFS_ATTR_COMMON_TYPE" },

#if 0
#define PVFS_ATTR_COMMON_ALL                       \
	(PVFS_ATTR_COMMON_UID   | PVFS_ATTR_COMMON_GID   | \
	  PVFS_ATTR_COMMON_PERM  | PVFS_ATTR_COMMON_ATIME | \
	  PVFS_ATTR_COMMON_CTIME | PVFS_ATTR_COMMON_MTIME | \
	  PVFS_ATTR_COMMON_TYPE)
#endif

/* internal attribute masks for metadata objects */
#define PVFS_ATTR_META_DIST    (1 << 10)
#define PVFS_ATTR_BIT_META_DIST 10
	{ PVFS_ATTR_BIT_META_DIST, "PVFS_ATTR_META_DIST" },

#define PVFS_ATTR_META_DFILES  (1 << 11)
#define PVFS_ATTR_BIT_META_DFILES 11
	{ PVFS_ATTR_BIT_META_DFILES, "PVFS_ATTR_META_DFILES" },

#if 0
#define PVFS_ATTR_META_ALL \
	(PVFS_ATTR_META_DIST | PVFS_ATTR_META_DFILES)
#endif

/* internal attribute masks for datafile objects */
#define PVFS_ATTR_DATA_SIZE            (1 << 15)
#define PVFS_ATTR_BIT_DATA_SIZE 15
	{ PVFS_ATTR_BIT_DATA_SIZE, "PVFS_ATTR_DATA_SIZE" },

#if 0
#define PVFS_ATTR_DATA_ALL   PVFS_ATTR_DATA_SIZE
#endif

/* internal attribute masks for symlink objects */
#define PVFS_ATTR_SYMLNK_TARGET            (1 << 18)
#define PVFS_ATTR_BIT_SYMLINK_TARGET 18
	{ PVFS_ATTR_BIT_SYMLINK_TARGET, "PVFS_ATTR_SYMLNK_TARGET" },

#if 0
#define PVFS_ATTR_SYMLNK_ALL PVFS_ATTR_SYMLNK_TARGET
#endif

/* internal attribute masks for directory objects */
#define PVFS_ATTR_DIR_DIRENT_COUNT         (1 << 19)
#define PVFS_ATTR_BIT_DIR_DIRENT_COUNT 19
	{ PVFS_ATTR_BIT_DIR_DIRENT_COUNT, "PVFS_ATTR_DIR_DIRENT_COUNT" },

#if 0
#define PVFS_ATTR_DIR_ALL PVFS_ATTR_DIR_DIRENT_COUNT
#endif

/* attribute masks used by system interface callers */
#define PVFS_ATTR_SYS_SIZE                  (1 << 20)
#define PVFS_ATTR_BIT_SYS_SIZE 20
	{ PVFS_ATTR_BIT_SYS_SIZE, "PVFS_ATTR_SYS_SIZE" },

#define PVFS_ATTR_SYS_LNK_TARGET            (1 << 24)
#define PVFS_ATTR_BIT_SYS_LNK_TARGET 24
	{ PVFS_ATTR_BIT_SYS_LNK_TARGET, "PVFS_ATTR_SYS_LNK_TARGET" },

#define PVFS_ATTR_SYS_DFILE_COUNT           (1 << 25)
#define PVFS_ATTR_BIT_SYS_DFILE_COUNT 25
	{ PVFS_ATTR_BIT_SYS_DFILE_COUNT, "PVFS_ATTR_SYS_DFILE_COUNT" },

#define PVFS_ATTR_SYS_DIRENT_COUNT          (1 << 26)
#define PVFS_ATTR_BIT_SYS_DIRENT_COUNT 26
	{ PVFS_ATTR_BIT_SYS_DIRENT_COUNT, "PVFS_ATTR_SYS_DIRENT_COUNT" },

#if 0
#define PVFS_ATTR_SYS_UID        PVFS_ATTR_COMMON_UID
#define PVFS_ATTR_SYS_GID        PVFS_ATTR_COMMON_GID
#define PVFS_ATTR_SYS_PERM       PVFS_ATTR_COMMON_PERM
#define PVFS_ATTR_SYS_ATIME      PVFS_ATTR_COMMON_ATIME
#define PVFS_ATTR_SYS_CTIME      PVFS_ATTR_COMMON_CTIME
#define PVFS_ATTR_SYS_MTIME      PVFS_ATTR_COMMON_MTIME
#define PVFS_ATTR_SYS_TYPE       PVFS_ATTR_COMMON_TYPE
#endif
	{ 0, NULL }
};

#if 0
#define PVFS_ATTR_SYS_ALL                    \
	(PVFS_ATTR_COMMON_ALL | PVFS_ATTR_SYS_SIZE | \
	  PVFS_ATTR_SYS_LNK_TARGET | PVFS_ATTR_SYS_DFILE_COUNT | \
	  PVFS_ATTR_SYS_DIRENT_COUNT)

#define PVFS_ATTR_SYS_ALL_NOSIZE                   \
	(PVFS_ATTR_COMMON_ALL | PVFS_ATTR_SYS_LNK_TARGET | \
	  PVFS_ATTR_SYS_DFILE_COUNT | PVFS_ATTR_SYS_DIRENT_COUNT)

#define PVFS_ATTR_SYS_ALL_SETABLE \
	(PVFS_ATTR_COMMON_ALL-PVFS_ATTR_COMMON_TYPE)
#endif


static int
dissect_pvfs2_attrmask(tvbuff_t *tvb, proto_tree *tree, int offset,
		guint32 *pattrmask)
{
	guint32 attrmask = 0, i = 0;
	proto_item *attritem = NULL;
	proto_tree *attrtree = NULL;

	attrmask = tvb_get_letohl(tvb, offset);

	attritem = proto_tree_add_text(tree, tvb, offset, 4, 
			"Attribute Mask: %d", attrmask);

	if (attritem)
		attrtree = proto_item_add_subtree(attritem, ett_pvfs_attrmask);

	for (i = 0; i < 32; i++)
	{
		if (attrmask & (1 << i))
			proto_tree_add_uint(attrtree, hf_pvfs_attr, tvb, offset, 4, i);
	}

	offset += 4;

	if (pattrmask)
		*pattrmask = attrmask;

	return offset;
}

static const value_string names_pvfs_ds_type[] = {
#define PVFS_TYPE_NONE 0
	{ PVFS_TYPE_NONE, "PVFS_TYPE_NONE" },
#define PVFS_TYPE_METAFILE (1 << 0)
	{ PVFS_TYPE_METAFILE, "PVFS_TYPE_METAFILE" },
#define PVFS_TYPE_DATAFILE (1 << 1)
	{ PVFS_TYPE_DATAFILE, "PVFS_TYPE_DATAFILE" },
#define PVFS_TYPE_DIRECTORY (1 << 2)
	{ PVFS_TYPE_DIRECTORY, "PVFS_TYPE_DIRECTORY" },
#define PVFS_TYPE_SYMLINK (1 << 3)
	{ PVFS_TYPE_SYMLINK, "PVFS_TYPE_SYMLINK" },
#define PVFS_TYPE_DIRDATA (1 << 4)
	{ PVFS_TYPE_DIRDATA, "PVFS_TYPE_DIRDATA" },
	{ 0, NULL }
};

static int
dissect_pvfs2_ds_type(tvbuff_t *tvb, proto_tree *tree, int offset,
		int *pds_type)
{
	guint32 ds_type = 0;

	ds_type = tvb_get_letohl(tvb, offset);

	if (tree)
		proto_tree_add_uint(tree, hf_pvfs_ds_type, tvb, offset, 4, ds_type);

	offset += 4;

	if (pds_type)
		*pds_type = ds_type;

	return offset;
}

#define roundup4(x) (((x) + 3) & ~3)
#define roundup8(x) (((x) + 7) & ~7)

int
dissect_pvfs_opaque_data(tvbuff_t *tvb, int offset,
    proto_tree *tree,
    packet_info *pinfo _U_,
    int hfindex,
    gboolean fixed_length, guint32 length,
    gboolean string_data, char **string_buffer_ret)
{
	int data_offset;
	proto_item *string_item = NULL;
	proto_tree *string_tree = NULL;

	guint32 string_length;
	guint32 string_length_full;
	guint32 string_length_packet;
	guint32 string_length_captured;
	guint32 string_length_copy;

	int fill_truncated;
	guint32 fill_length;
	guint32 fill_length_packet;
	guint32 fill_length_captured;
	guint32 fill_length_copy;

	int exception = 0;

	char *string_buffer = NULL;
	char *string_buffer_print = NULL;

	if (fixed_length) {
		string_length = length;
		data_offset = offset;
	} else {
		string_length = tvb_get_letohl(tvb,offset+0);
		data_offset = offset + 4;

		/* 
		 * Variable-length strings include NULL terminator on-the-wire but 
		 * NULL terminator is not included in string length.
		 */

		if (string_data)
			string_length += 1;
	}

	string_length_captured = tvb_length_remaining(tvb, data_offset);
	string_length_packet = tvb_reported_length_remaining(tvb, data_offset);

	/*
	 * Strangeness...  the protocol basically says that the length plus
	 * the string must be padded out to an 8-byte boundary.
	 */

	if (!string_data)
		string_length_full = roundup4(string_length);
	else
		string_length_full = roundup8(4 + string_length);

	if (string_length_captured < string_length) {
		/* truncated string */
		string_length_copy = string_length_captured;
		fill_truncated = 2;
		fill_length = 0;
		fill_length_copy = 0;

		if (string_length_packet < string_length)
			exception = ReportedBoundsError;
		else
			exception = BoundsError;
	}
	else {
		/* full string data */
		string_length_copy = string_length;

		if (!string_data)
			fill_length = string_length_full - string_length;
		else
			fill_length = string_length_full - string_length - 4;

		fill_length_captured = tvb_length_remaining(tvb,
		    data_offset + string_length);
		fill_length_packet = tvb_reported_length_remaining(tvb,
		    data_offset + string_length);

		if (fill_length_captured < fill_length) {
			/* truncated fill bytes */
			fill_length_copy = fill_length_packet;
			fill_truncated = 1;
			if (fill_length_packet < fill_length)
				exception = ReportedBoundsError;
			else
				exception = BoundsError;
		}
		else {
			/* full fill bytes */
			fill_length_copy = fill_length;
			fill_truncated = 0;
		}
	}

	if (string_data) {
		char *tmpstr;

		tmpstr = (char *) tvb_get_ephemeral_string(tvb, data_offset, 
				string_length_copy);

		string_buffer = memcpy(ep_alloc(string_length_copy+1), tmpstr, string_length_copy);
	} else {
		string_buffer = (char *) tvb_memcpy(tvb, 
				ep_alloc(string_length_copy+1), data_offset, string_length_copy);
	}

	string_buffer[string_length_copy] = '\0';

	/* calculate a nice printable string */
	if (string_length) {
		if (string_length != string_length_copy) {
			if (string_data) {
				char *formatted;
				guint16 string_buffer_size = 0;

				formatted = format_text((guint8 *)string_buffer, 
						strlen(string_buffer));

				string_buffer_size = strlen(formatted) + 12 + 1;

				/* alloc maximum data area */
				string_buffer_print = (char*) ep_alloc(string_buffer_size);
				/* copy over the data */
				g_snprintf(string_buffer_print, string_buffer_size - 1, 
						"%s<TRUNCATED>", formatted);
				/* append <TRUNCATED> */
				/* This way, we get the TRUNCATED even
				   in the case of totally wrong packets,
				   where \0 are inside the string.
				   TRUNCATED will appear at the
				   first \0 or at the end (where we
				   put the securing \0).
				*/
			} else {
				string_buffer_print="<DATA><TRUNCATED>";
			}
		} else {
			if (string_data) {
				string_buffer_print = (char *)
				    ep_strdup(format_text((guint8 *) string_buffer, 
								 strlen(string_buffer)));
			} else {
				string_buffer_print="<DATA>";
			}
		}
	} else {
		string_buffer_print="<EMPTY>";
	}

	if (tree) {
		string_item = proto_tree_add_text(tree, tvb,offset+0, -1,
		    "%s: %s", proto_registrar_get_name(hfindex),
		    string_buffer_print);

		if (string_item)
			string_tree = proto_item_add_subtree(string_item,
		    	ett_pvfs_string);
	}
	if (!fixed_length) {
		if (string_tree)
			proto_tree_add_text(string_tree, tvb,offset+0,4,
				"length: %u (excl. NULL terminator)", string_length - 1);
		offset += 4;
	}

	if (string_tree) {
		if (string_data) {
			proto_tree_add_string_format(string_tree,
			    hfindex, tvb, offset, string_length_copy,
			    string_buffer,
			    "contents: %s", string_buffer_print);
		} else {
			proto_tree_add_bytes_format(string_tree,
			    hfindex, tvb, offset, string_length_copy,
			    (guint8 *) string_buffer,
			    "contents: %s", string_buffer_print);
		}
	}

	offset += string_length_copy;

	if (fill_length) {
		if (string_tree) {
			if (fill_truncated) {
				proto_tree_add_text(string_tree, tvb,
				offset,fill_length_copy,
				"fill bytes: opaque data<TRUNCATED>");
			}
			else {
				proto_tree_add_text(string_tree, tvb,
				offset,fill_length_copy,
				"fill bytes: opaque data");
			}
		}
		offset += fill_length_copy;
	}

	if (string_item)
		proto_item_set_end(string_item, tvb, offset);

	if (string_buffer_ret != NULL)
		*string_buffer_ret = string_buffer_print;

	/*
	 * If the data was truncated, throw the appropriate exception,
	 * so that dissection stops and the frame is properly marked.
	 */
	if (exception != 0)
		THROW(exception);

	return offset;
}

static int
dissect_pvfs_string(tvbuff_t *tvb, proto_tree *tree, int hfindex, 
		int offset, char **string_buffer_ret)
{
	return dissect_pvfs_opaque_data(tvb, offset, tree, NULL, hfindex,
			FALSE, 0, TRUE, string_buffer_ret);
}

static void
dissect_fhandle_data_unknown(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint sublen;
	guint bytes_left;
	gboolean first_line;

	bytes_left = PVFS2_FH_LENGTH;
	first_line = TRUE;
	while (bytes_left != 0) {
		sublen = 16;
		if (sublen > bytes_left)
			sublen = bytes_left;
		proto_tree_add_text(tree, tvb, offset, sublen,
					"%s%s",
					first_line ? "data: " :
					             "      ",
					tvb_bytes_to_str(tvb,offset,sublen));
		bytes_left -= sublen;
		offset += sublen;
		first_line = FALSE;
	}
}

static void
dissect_fhandle_data(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
    proto_tree *tree, guint32 *hash)
{
	guint32 fhhash;
	guint32 i;

	/* Not all bytes there. Any attempt to deduce the type would be
		senseless. */
	if (!tvb_bytes_exist(tvb, offset, PVFS2_FH_LENGTH))
		goto type_ready;

	/* create a semiunique hash value for the filehandle */
	for(fhhash=0,i=0;i<(PVFS2_FH_LENGTH-3);i+=4){
		guint32 val;
		val = tvb_get_ntohl(tvb, offset+i);
		fhhash ^= val;
		fhhash += val;
	}

	proto_tree_add_uint(tree, hf_pvfs_fh_hash, tvb, offset, PVFS2_FH_LENGTH, 
			fhhash);

	if (hash)
		*hash = fhhash;

	/* TODO: add file name snooping code here */

type_ready:
	dissect_fhandle_data_unknown(tvb, offset, tree);
}

static int
dissect_pvfs_fh(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		proto_tree *tree, const char *name, guint32 *hash)
{
	proto_item* fitem = NULL;
	proto_tree* ftree = NULL;

	if (tree) 
	{
		fitem = proto_tree_add_text(tree, tvb, offset, PVFS2_FH_LENGTH, 
				"%s", name);

		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_pvfs_fh);
	}

	/* TODO: add fh to file name snooping code here */

	proto_tree_add_uint(ftree, hf_pvfs_fh_length, tvb, offset, 0, 
			PVFS2_FH_LENGTH);

	dissect_fhandle_data(tvb, offset, pinfo, ftree, hash);

	offset += PVFS2_FH_LENGTH;

	return offset;
}

static int
dissect_pvfs_handle_extent(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo, guint32 nCount)
{
	proto_item *extent_item = NULL;
	proto_tree *extent_tree = NULL;

	if (tree)
	{
		extent_item = proto_tree_add_text(tree, tvb, offset, 8, 
				"Item %d", nCount);

		if (extent_item)
			extent_tree = proto_item_add_subtree(extent_item,
					ett_pvfs_extent_item);
	}

	/* first handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, extent_tree, "first handle", 
			NULL);

	/* last handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, extent_tree, "last handle",
			NULL);

	return offset;
}

static int
dissect_pvfs_handle_extent_array(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	guint32 extent_count = 0;
	guint32 nCount;
	proto_item *extent_array_item = NULL;
	proto_tree *extent_array_tree = NULL;

	/* extent count */
	extent_count = tvb_get_letohl(tvb, offset);

	if (tree)
		extent_array_item = proto_tree_add_text(tree, tvb, offset, 4,
					"Handle Extent Array (count = %d)", extent_count);

	offset += 4;

	if (extent_count > 0)
	{
		if (extent_array_item)
			extent_array_tree = proto_item_add_subtree(extent_array_item,
					ett_pvfs_extent_array_tree);

		/* Add extent array items */
		for (nCount = 0; nCount < extent_count; nCount++)
			offset = dissect_pvfs_handle_extent(tvb, extent_array_tree, offset,
					pinfo, nCount);
	}

	return offset;
}

static int
dissect_pvfs_time(tvbuff_t *tvb, proto_tree *tree, int offset, 
		int hf_time, int hf_time_sec, int hf_time_nsec)
{
	guint32 seconds;
	guint32 nseconds;
	nstime_t ts;
	proto_item *time_item = NULL;
	proto_tree *time_tree = NULL;

	ts.secs = seconds = tvb_get_letohl(tvb, offset);
	ts.nsecs = nseconds = tvb_get_letohl(tvb, offset + 4);

	if (tree)
	{
		time_item = proto_tree_add_time(tree, hf_time, tvb, offset, 8, &ts);

		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ett_pvfs_time);
	}

	if (time_tree)
	{
		proto_tree_add_uint(time_tree, hf_time_sec, tvb, offset, 4, seconds);
		proto_tree_add_uint(time_tree, hf_time_nsec, tvb, offset + 4, 4,
				nseconds);
	}

	offset += 8;
	return offset;
}

static
int dissect_pvfs_uint64(tvbuff_t *tvb, proto_tree *tree, int offset,
		int hfindex, guint64 *pvalue)
{
	guint64 val;

	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);

	proto_tree_add_uint64(tree, hfindex, tvb, offset, 8, val);

	if (pvalue)
		*pvalue = val;

	return offset + 8;
}

/* Taken from pvfs2-dist-simple-stripe.h */
#define PVFS_DIST_SIMPLE_STRIPE_NAME "simple_stripe"
#define PVFS_DIST_SIMPLE_STRIPE_NAME_SIZE 14

static int
dissect_pvfs_distribution(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_item *dist_item = NULL;
	proto_tree *dist_tree = NULL;
	char *distname = NULL;
	guint32 distlen = 0;
	char *tmpstr = NULL;
	guint8 issimplestripe = 0;

	/* Get distribution name length */
	distlen = tvb_get_letohl(tvb, offset);

	/* Get distribution name */
	tmpstr = (char *) tvb_get_ephemeral_string(tvb, offset + 4, distlen);

	if (tree) 
	{
		guint32 total_len;
		
		/* 'distlen' does not include the NULL terminator */
		total_len = roundup8(4 + distlen + 1);

		if (((distlen + 1) == PVFS_DIST_SIMPLE_STRIPE_NAME_SIZE) && 
				(strncasecmp(tmpstr, PVFS_DIST_SIMPLE_STRIPE_NAME, 
								 distlen) == 0))
		{
			/* Parameter for 'simple_stripe' is 8 bytes */
			total_len += 8;

			issimplestripe = 1;
		}

		dist_item = proto_tree_add_text(tree, tvb, offset, total_len + 8,
				"Distribution: %s", tmpstr);

		if (dist_item)
			dist_tree = proto_item_add_subtree(dist_item, ett_pvfs_distribution);
	}

	/* io_dist */
	offset = dissect_pvfs_string(tvb, dist_tree, hf_pvfs_io_dist, offset, 
			&distname);

	/* TODO: only one distribution type is currently supported */
	if (issimplestripe)
		offset = dissect_pvfs_uint64(tvb, dist_tree, offset, 
				hf_pvfs_strip_size, NULL);

	offset += 8;

	return offset;
}

static int
dissect_pvfs_meta_attr_dfiles(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	guint32 dfile_count, i;

	/* dfile_count */
	dfile_count = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "dfile_count: %d",
			dfile_count);
	offset += 4;

	for (i = 0; i < dfile_count; i++)
		offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs_object_attr(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	gint32 ds_type = 0;
	guint32 attrmask = 0;
	proto_item *attr_item = NULL;
	proto_tree *attr_tree = NULL;

	if (tree) 
	{
		attr_item = proto_tree_add_text(tree, tvb, offset, -1, "Attributes");

		if (attr_item)
			attr_tree = proto_item_add_subtree(attr_item, ett_pvfs_attr_tree);
	}

	/* UID */
	proto_tree_add_text(attr_tree, tvb, offset, 4, "UID: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* GID */
	proto_tree_add_text(attr_tree, tvb, offset, 4, "GID: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* Permissions */
	proto_tree_add_text(attr_tree, tvb, offset, 4, "Permissions: %o", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	offset += 4;

	/* atime */
	offset = dissect_pvfs_time(tvb, attr_tree, offset, hf_pvfs_atime,
			hf_pvfs_atime_sec, hf_pvfs_atime_nsec);

	/* mtime */
	offset = dissect_pvfs_time(tvb, attr_tree, offset, hf_pvfs_mtime,
			hf_pvfs_mtime_sec, hf_pvfs_mtime_nsec);

	/* ctime */
	offset = dissect_pvfs_time(tvb, attr_tree, offset, hf_pvfs_ctime,
			hf_pvfs_ctime_sec, hf_pvfs_ctime_nsec);

	/* attrmask */
	offset = dissect_pvfs2_attrmask(tvb, attr_tree, offset, &attrmask);

	/* objtype */
	offset = dissect_pvfs2_ds_type(tvb, attr_tree, offset, &ds_type);

	if (attrmask & PVFS_ATTR_META_DIST)
	{
		offset = dissect_pvfs_distribution(tvb, attr_tree, offset);

		offset = dissect_pvfs_meta_attr_dfiles(tvb, attr_tree, offset, pinfo);
	}
	else
	{
		if (attrmask & PVFS_ATTR_META_DFILES)
		{
			offset = dissect_pvfs_meta_attr_dfiles(tvb, attr_tree, offset, pinfo);
		}
		else
		{
			if (attrmask & PVFS_ATTR_DATA_SIZE)
			{
				offset = dissect_pvfs_uint64(tvb, attr_tree, offset, hf_pvfs_size,
						NULL);
			}
			else
			{
				if (attrmask & PVFS_ATTR_SYMLNK_TARGET)
				{
					/* target_path_len */
					proto_tree_add_text(attr_tree, tvb, offset, 4, 
							"target_path_len: %d", tvb_get_letohl(tvb, offset));
					offset += 4;

					offset += 4;

					/* target_path */
					offset = dissect_pvfs_string(tvb, attr_tree, hf_pvfs_path,
							offset, NULL);
				}
				else
				{
					if (attrmask & PVFS_ATTR_DIR_DIRENT_COUNT)
					{
						offset = dissect_pvfs_uint64(tvb, attr_tree, offset,
								hf_pvfs_size, NULL);
					}
				}
			}
		}
	}

	return offset;
}

static int
dissect_pvfs_io_type(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_tree_add_uint(tree, hf_pvfs_io_type, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs_flowproto_type(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_tree_add_uint(tree, hf_pvfs_flowproto_type, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs_server_param(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	guint32 server_param = 0;
	guint32 lowpart;

	/* server_param */
	server_param = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_pvfs_server_param, tvb, offset, 4,
			server_param);
	offset += 4;

	switch (server_param)
	{
		case PVFS_SERV_PARAM_MODE:
			lowpart = tvb_get_letohl(tvb, offset);

			proto_tree_add_text(tree, tvb, offset, 8, 
					"Server Mode: %s (%u)", 
					val_to_str(lowpart, names_pvfs_server_mode, "%u"), lowpart);
			break;

		case PVFS_SERV_PARAM_FSID_CHECK:
			lowpart = tvb_get_letohl(tvb, offset);
			proto_tree_add_uint(tree, hf_pvfs_fs_id, tvb, offset, 4, lowpart);
			proto_tree_add_uint(tree, hf_pvfs_unused, tvb, offset + 4, 4, 
					tvb_get_letohl(tvb, offset + 4));
			break;

		case PVFS_SERV_PARAM_ROOT_CHECK:
			offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);
			break;
	}

	offset += 8;

	return offset;
}

static int
dissect_pvfs_fs_id(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	if (tree)
		proto_tree_add_uint(tree, hf_pvfs_fs_id, tvb, offset, 4, 
				tvb_get_letohl(tvb, offset));

	offset += 4;

	return offset;
}

/* 
 * =======================================================================
 * Request handlers
 * =======================================================================
 */

static int
dissect_pvfs2_create_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* type */
	offset = dissect_pvfs2_ds_type(tvb, tree, offset, NULL);

	offset += 4;

	offset = dissect_pvfs_handle_extent_array(tvb, tree, offset, pinfo);

	return offset;
}

static int
dissect_pvfs2_remove_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	return offset;
}

static int
dissect_pvfs_pint_request(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint64 val = 0;
	gint32 ereg, sreg;

	/* offset */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_offset, tvb, offset, 8, val);
	offset += 8;

	/* TODO: num_eregs */
	proto_tree_add_uint(tree, hf_pvfs_num_eregs, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* TODO: num_blocks */
	proto_tree_add_uint(tree, hf_pvfs_num_blocks, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* TODO: stride */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_stride, tvb, offset, 8, val);
	offset += 8;

	/* TODO: ub */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_ub, tvb, offset, 8, val);
	offset += 8;

	/* TODO: lb */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_lb, tvb, offset, 8, val);
	offset += 8;

	/* TODO: aggregate size */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_aggregate_size, tvb, offset, 8, val);
	offset += 8;

	/* num_contig_chunks */
	proto_tree_add_uint(tree, hf_pvfs_num_contig_chunks, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* depth */
	proto_tree_add_text(tree, tvb, offset, 4, "depth: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* num_nested_req */
	proto_tree_add_text(tree, tvb, offset, 4, "num_nested_req: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* committed */
	proto_tree_add_text(tree, tvb, offset, 4, "committed: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* refcount */
	proto_tree_add_text(tree, tvb, offset, 4, "refcount: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* documented */
	offset += 4;

	/* ereg */
	ereg = tvb_get_letohl(tvb, offset);
	proto_tree_add_int(tree, hf_pvfs_ereg, tvb, offset, 4, ereg);
	offset += 4;

	/* sreg */
	sreg = tvb_get_letohl(tvb, offset);
	proto_tree_add_int(tree, hf_pvfs_sreg, tvb, offset, 4, sreg);
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_io_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	guint64 val;

	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* skip4 as per source code */
	offset += 4;

	/* io_type */
	offset = dissect_pvfs_io_type(tvb, tree, offset);

	/* flow_type */
	offset = dissect_pvfs_flowproto_type(tvb, tree, offset);

	/* server_nr */
	proto_tree_add_uint(tree, hf_pvfs_server_nr, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* server_ct */
	proto_tree_add_uint(tree, hf_pvfs_server_count, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* Distribution */
	offset = dissect_pvfs_distribution(tvb, tree, offset);

	proto_tree_add_text(tree, tvb, offset, 4, "numreq: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* */
	offset += 4;

	offset = dissect_pvfs_pint_request(tvb, tree, offset);

	/* TODO: remove this!!! */
	offset = tvb_length(tvb) - 16;

	/* offset */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_offset, tvb, offset, 8, val);
	offset += 8;

	/* size */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_size, tvb, offset, 8, val);
	offset += 8;

	return offset;
}

static int
dissect_pvfs2_getattr_request(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* attrmask */
	offset = dissect_pvfs2_attrmask(tvb, tree, offset, NULL);

	return offset;
}

static int
dissect_pvfs2_setattr_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* parent_ref: fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	offset = dissect_pvfs_object_attr(tvb, tree, offset, pinfo);

	return offset;
}

/* As per pvfs2-1.2.0/src/proto/pvfs2-req-proto.h */
static int
dissect_pvfs2_lookup_path_request(tvbuff_t *tvb, proto_tree *tree,
		int offset, packet_info *pinfo)
{
	/* Path */
	offset = dissect_pvfs_string(tvb, tree, hf_pvfs_path, offset, NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	/* starting_handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* attribute mask */
	offset = dissect_pvfs2_attrmask(tvb, tree, offset, NULL);

	return offset;
}

static int
dissect_pvfs2_crdirent_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	/* Filename */
	offset = dissect_pvfs_string(tvb, tree, hf_pvfs_path, offset, NULL);

	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "file handle", NULL);

	/* parent_handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "parent handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	/* atime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_atime,
			hf_pvfs_atime_sec, hf_pvfs_atime_nsec);

	/* mtime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_mtime,
			hf_pvfs_mtime_sec, hf_pvfs_mtime_nsec);

	/* ctime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_ctime,
			hf_pvfs_ctime_sec, hf_pvfs_ctime_nsec);

	return offset;
}

/* TODO: incomplete */
static int
dissect_pvfs2_rmdirent_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	/* path */
	offset = dissect_pvfs_string(tvb, tree, hf_pvfs_path, offset, NULL);
	
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	/* atime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_atime,
			hf_pvfs_atime_sec, hf_pvfs_atime_nsec);

	/* mtime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_mtime,
			hf_pvfs_mtime_sec, hf_pvfs_mtime_nsec);

	/* ctime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_ctime,
			hf_pvfs_ctime_sec, hf_pvfs_ctime_nsec);

	return offset;
}

static int
dissect_pvfs2_chdirent_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	/* path */
	offset = dissect_pvfs_string(tvb, tree, hf_pvfs_path, offset, NULL);

	/* New directory entry handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "new directory handle",
			NULL);

	/* Parent handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "parent handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* Parent atime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_parent_atime,
			hf_pvfs_parent_atime_sec, hf_pvfs_parent_atime_nsec);

	/* Parent mtime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_parent_mtime,
			hf_pvfs_parent_mtime_sec, hf_pvfs_parent_mtime_nsec);

	/* Parent ctime */
	offset = dissect_pvfs_time(tvb, tree, offset, hf_pvfs_parent_ctime,
			hf_pvfs_parent_ctime_sec, hf_pvfs_parent_ctime_nsec);

	return offset;
}

static int
dissect_pvfs2_truncate_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	guint64 val;

	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	/* size */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_size, tvb, offset, 8, val);
	offset += 8;

	/* TODO: flags */
	proto_tree_add_text(tree, tvb, offset, 4, "flags: %u", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_mkdir_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	guint count, i;

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	/* attr */
	offset = dissect_pvfs_object_attr(tvb, tree, offset, pinfo);

	/* handle_extent_array */
	count = tvb_get_letohl(tvb, offset);
	offset += 4;

	for (i = 0; i < count; i++)
		offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs2_readdir_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo)
{
	/* object_ref: handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* object_ref: fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* ds_position */
	proto_tree_add_text(tree, tvb, offset, 4, "ds_position: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* dirent_limit */
	proto_tree_add_text(tree, tvb, offset, 4, "dirent_limit: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_flush_request(tvbuff_t *tvb, proto_tree *tree, 
		int offset, packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* flags */
	proto_tree_add_text(tree, tvb, offset, 4, "flags: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_mgmt_setparam_request(tvbuff_t *tvb, proto_tree *tree,
		int offset, packet_info *pinfo)
{
	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* server_param */
	offset = dissect_pvfs_server_param(tvb, tree, offset, pinfo);

	return offset;
}

static int
dissect_pvfs2_statfs_request(tvbuff_t *tvb, proto_tree *tree, int offset, 
		packet_info *pinfo _U_)
{
	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);
	
	return offset;
}

static int
dissect_pvfs2_mgmt_perf_mon_request(tvbuff_t *tvb _U_, proto_tree *tree _U_,
		int offset, packet_info *pinfo _U_)
{
	/* TODO: next_id */
	proto_tree_add_text(tree, tvb, offset, 4, "next_id: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* TODO: count */
	proto_tree_add_text(tree, tvb, offset, 4, "count: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_mgmt_iterate_handles_request(tvbuff_t *tvb, proto_tree *tree, 
		int offset, packet_info *pinfo)
{
	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs2_mgmt_dspace_info_list_request(tvbuff_t *tvb, 
		proto_tree *tree, int offset, packet_info *pinfo)
{
	guint32 handle_count, i;

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* handle count */
	handle_count = tvb_get_letohl(tvb, offset);
	offset += 4;

	for (i = 0; i < handle_count; i++)
	{
		/* handle */
		offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);
	}

	return offset;
}

static int
dissect_pvfs2_mgmt_event_mon_request(tvbuff_t *tvb, proto_tree *tree,
		int offset, packet_info *pinfo _U_)
{
	/* event_count */
	proto_tree_add_text(tree, tvb, offset, 4, "Event count: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_mgmt_remove_object_request(tvbuff_t *tvb, proto_tree *tree, 
		int offset, packet_info *pinfo)
{
	/* Handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	return offset;
}

static int
dissect_pvfs2_mgmt_remove_dirent_request(tvbuff_t *tvb,
		proto_tree *tree, int offset, packet_info *pinfo)
{
	/* Handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* */
	offset += 4;

	/* entry */
	offset = dissect_pvfs_string(tvb, tree, hf_pvfs_path, offset, NULL);

	return offset;
}

static int
dissect_pvfs2_mgmt_get_dirdata_handle_request(tvbuff_t *tvb, 
		proto_tree *tree, int offset, packet_info *pinfo)
{
	/* Handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	return offset;
}

/* TODO: untested/incomplete */
static int
dissect_pvfs_ds_keyval(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* attribute key */
	offset = dissect_pvfs_string(tvb, tree, hf_pvfs_attribute_key, offset, 
			NULL);

	/* attribute value */
	offset = dissect_pvfs_string(tvb, tree, hf_pvfs_attribute_value, offset,
			NULL);

	return offset;
}

/* TODO: incomplete/untested */
static int
dissect_ds_keyval_array(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint32 nKey, i;

	/* number of keys and vals */
	nKey = tvb_get_letohl(tvb, offset);
	offset += 4;

	for (i = 0; i < nKey; i++)
		offset = dissect_pvfs_ds_keyval(tvb, tree, offset);

	return offset;
}

/* TODO: incomplete/untested */
static int
dissect_pvfs2_geteattr_request(tvbuff_t *tvb, proto_tree *tree,
		int offset, packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	offset = dissect_ds_keyval_array(tvb, tree, offset);

	return offset;
}

/* TODO: incomplete/untested */
static int
dissect_pvfs2_seteattr_request(tvbuff_t *tvb, proto_tree *tree,
		int offset, packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	offset += 4;

	offset = dissect_ds_keyval_array(tvb, tree, offset);

	return offset;
}

/* TODO: untested */
static int
dissect_pvfs2_deleattr_request(tvbuff_t *tvb, proto_tree *tree,
		int offset, packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* key */
	offset = dissect_pvfs_ds_keyval(tvb, tree, offset);

	return offset;
}

static int
dissect_pvfs2_release_number(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint32 release_nr = tvb_get_letohl(tvb, offset);

	proto_tree_add_text(tree, tvb, offset, 4, 
			"PVFS2 Release Number: %d (%d.%d.%d)", 
			release_nr,
			release_nr / 10000,
			(release_nr % 10000) / 100,
			(release_nr % 10000) % 100);
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_common_header(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* PVFS release number */
	offset = dissect_pvfs2_release_number(tvb, tree, offset);

	/* wire encoding type */
	proto_tree_add_uint(tree, hf_pvfs_encoding, tvb, offset, 
			4, tvb_get_letohl(tvb, offset));
	offset += 4;

	/* server op */
	proto_tree_add_uint(tree, hf_pvfs_server_op, tvb, offset, 4,
		tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
dissect_pvfs2_request(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo, guint32 server_op)
{
	/* context_id */
	proto_tree_add_uint(tree, hf_pvfs_context_id, tvb, offset, 
			4, tvb_get_letohl(tvb, offset));
	offset += 4;

	/* credentials */
	offset = dissect_pvfs_credentials(tvb, tree, offset);

	switch (server_op)
	{
		case  PVFS_SERV_CREATE:
			offset = dissect_pvfs2_create_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_REMOVE:
			offset = dissect_pvfs2_remove_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_IO:
			offset = dissect_pvfs2_io_request(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_GETATTR:
			offset = dissect_pvfs2_getattr_request(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_SETATTR:
			offset = dissect_pvfs2_setattr_request(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_LOOKUP_PATH:
			offset = dissect_pvfs2_lookup_path_request(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_CRDIRENT:
			offset = dissect_pvfs2_crdirent_request(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_RMDIRENT:
			offset = dissect_pvfs2_rmdirent_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_CHDIRENT:
			offset = dissect_pvfs2_chdirent_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_TRUNCATE:
			offset = dissect_pvfs2_truncate_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_MKDIR:
			offset = dissect_pvfs2_mkdir_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_READDIR:
			offset = dissect_pvfs2_readdir_request(tvb, tree, offset, pinfo);
			break;

#if 0
		case PVFS_SERV_GETCONFIG:
			/* No parameters in request */
			break;
#endif

#if 0
		case  PVFS_SERV_WRITE_COMPLETION:
			/* No parameters in request */
			break;
#endif

		case  PVFS_SERV_FLUSH:
			offset = dissect_pvfs2_flush_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_MGMT_SETPARAM:
			offset = dissect_pvfs2_mgmt_setparam_request(tvb, tree, offset, 
					pinfo);
			break;

#if 0
		case  PVFS_SERV_MGMT_NOOP:
			/* No parameters in request */
			break;
#endif

		case  PVFS_SERV_STATFS:
			offset = dissect_pvfs2_statfs_request(tvb, tree, offset, pinfo);
			break;

#if 0
		case  PVFS_SERV_PERF_UPDATE:
			/* No parameters in request */
			break;
#endif

		case  PVFS_SERV_MGMT_PERF_MON:
			offset = dissect_pvfs2_mgmt_perf_mon_request(tvb, tree, offset, 
					pinfo);
			break;

		case  PVFS_SERV_MGMT_ITERATE_HANDLES:
			offset = dissect_pvfs2_mgmt_iterate_handles_request(tvb, tree, 
					offset, pinfo);
			break;

		case  PVFS_SERV_MGMT_DSPACE_INFO_LIST:
			offset = dissect_pvfs2_mgmt_dspace_info_list_request(tvb, tree, 
					offset, pinfo);
			break;

		case  PVFS_SERV_MGMT_EVENT_MON:
			offset = dissect_pvfs2_mgmt_event_mon_request(tvb, tree, offset, 
					pinfo);
			break;

		case  PVFS_SERV_MGMT_REMOVE_OBJECT:
			offset = dissect_pvfs2_mgmt_remove_object_request(tvb, tree, offset, 
					pinfo);
			break;

		case  PVFS_SERV_MGMT_REMOVE_DIRENT:
			offset = dissect_pvfs2_mgmt_remove_dirent_request(tvb, tree, offset, 
					pinfo);
			break;

		case  PVFS_SERV_MGMT_GET_DIRDATA_HANDLE:
			offset = dissect_pvfs2_mgmt_get_dirdata_handle_request(tvb, tree, 
					offset, pinfo);
			break;

#if 0
		case  PVFS_SERV_JOB_TIMER:
			/* No parameters in request */
			break;
#endif

		case  PVFS_SERV_PROTO_ERROR:
			/* TODO: is this necessary? */
			break;

		case  PVFS_SERV_GETEATTR:
			offset = dissect_pvfs2_geteattr_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_SETEATTR:
			offset = dissect_pvfs2_seteattr_request(tvb, tree, offset, pinfo);
			break;

		case  PVFS_SERV_DELEATTR:
			offset = dissect_pvfs2_deleattr_request(tvb, tree, offset, pinfo);
			break;

		default:
			/* TODO: what should we do here? */
			break;
	}

	return offset;
}

/* 
 * =======================================================================
 * Response handlers
 * =======================================================================
 */

static int
dissect_pvfs2_create_response(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	/* Handle */
	return dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);
}

static int
dissect_pvfs2_io_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	return dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_size, NULL);
}

static int
dissect_pvfs2_getattr_response(tvbuff_t *tvb, proto_tree *tree,
		int offset, packet_info *pinfo)
{
	offset = dissect_pvfs_object_attr(tvb, tree, offset, pinfo);

	return offset;
}

static int
dissect_pvfs2_lookup_path_response(tvbuff_t *tvb, proto_tree *tree, 
		int offset, packet_info *pinfo)
{
	guint32 nCount = 0;
	guint32 handle_count = 0;
	guint32 attr_count = 0;
	proto_item *attr_item = NULL;
	proto_tree *attr_tree = NULL;

	offset += 4;

	/* handle_count */
	handle_count = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Handle Count: %d", 
			handle_count);
	offset += 4;

	/* TODO: add bounds checking */
	for (nCount = 0; nCount < handle_count; nCount++)
		offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	offset += 4;

	/* array of attributes */
	attr_count = tvb_get_letohl(tvb, offset);

	if (tree)
	{
		attr_item = proto_tree_add_text(tree, tvb, offset, 4, 
				"Attribute array (total items: %d)", attr_count);

		if (attr_item)
			attr_tree = proto_item_add_subtree(attr_item, ett_pvfs_attr);
	}

	offset += 4;

	/* Array of attributes */
	for (nCount = 0; nCount < attr_count; nCount++)
		offset = dissect_pvfs_object_attr(tvb, attr_tree, offset, pinfo);

	return offset;
}

static int
dissect_pvfs2_rmdirent_response(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	/* Handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs2_chdirent_response(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	/* Handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs2_mkdir_response(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	/* Handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs2_readdir_response(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	guint64 val;
	guint32 dirent_count = 0;
	guint32 nCount = 0;

	/* ds_position */
	proto_tree_add_text(tree, tvb, offset, 4, "ds_position: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	offset += 4;

	/* directory_version */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);
	proto_tree_add_uint64(tree, hf_pvfs_directory_version, tvb, offset, 8, 
			val);
	offset += 8;

	offset += 4;

	/* dirent_count */
	dirent_count = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "dirent_count: %d",
			dirent_count);
	offset += 4;
			
	for (nCount = 0; nCount < dirent_count; nCount++)
	{
		offset = dissect_pvfs_string(tvb, tree, hf_pvfs_path, offset, NULL);
		offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);
	}

	return offset;
}

/*
 * TODO: this code needs work!  Not finished yet!
 */
static int
dissect_pvfs2_getconfig_response(tvbuff_t *tvb, proto_tree *parent_tree, 
		int offset)
{
	guint32 i;
	guint32 total_bytes = 0, total_config_bytes = 0, total_lines = 0;
	guint32 bytes_processed = 0;
	guint32 length_remaining = 0;
	char *ptr = NULL;
	proto_item *item = NULL, *config_item = NULL;
	proto_tree *tree = NULL, *config_tree = NULL;
	guint8 truncated = 0;

	if (parent_tree)
	{
		item = proto_tree_add_text(parent_tree, tvb, offset, 12, 
				"Server Config");

		if (item)
			tree = proto_item_add_subtree(item, ett_pvfs_server_config);
	}

	/* Total number of bytes in server config (incl. entry count) */
	total_bytes = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Total Bytes: %d",
			total_bytes);
	offset += 4;

	/* There must be at least 4 bytes of data returned to determine the
	 * size of the server config data
	 */
	if (total_bytes < 4)
	{
		/* Server config not returned, bail out */
		return offset;
	}

	/* Number of entries in server config */
	total_lines = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Lines: %d", total_lines);
	offset += 4;

	/* Number of bytes in server config */
	total_config_bytes = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Config Bytes: %d",
			total_config_bytes);
	offset += 4;

	/* Get pointer to server config data */
	ptr = (char *) tvb_get_ptr(tvb, offset, total_config_bytes);

	/* Check if all data is available */
	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining < total_config_bytes)
	{
		total_config_bytes = length_remaining;

		truncated = 1;
	}

	bytes_processed = 0;

	for (i = 0; i < total_lines; i++)
	{
		guint8 entry[256], *pentry = entry, *tmp_entry = NULL;
		guint32 entry_length = 0, tmp_entry_length = 0;
		guint32 bufsiz = sizeof(entry);

		while ((*ptr != '\n') && (*ptr != '\0') && 
				(bytes_processed < total_config_bytes) &&
				(entry_length < bufsiz))
		{
			*pentry++ = *ptr++;

			bytes_processed++;
			entry_length++;
		}

		if ((entry_length == bufsiz) && 
				((entry[entry_length - 1] != '\n') || 
				 (entry[entry_length - 1] != '\0')))
		{
			/*
			 * Single line of config data doesn't fit into provided buffer,
			 * config data is malformed.
			 */

			break;
		}

		if (bytes_processed == total_config_bytes)
		{
			/* Oops...  ran out of data before we could complete the entry */
			break;
		}

		*pentry= '\0';

		tmp_entry = entry;
		tmp_entry_length = entry_length;

		/* Remove all whitespace from front of entry */
		while ((tmp_entry_length > 0) && (!isalnum(*tmp_entry)) && 
				(*tmp_entry != '<'))
		{
			tmp_entry++;
			tmp_entry_length--;
		}

		if (tmp_entry[0] == '<')
		{
 			if (tmp_entry[tmp_entry_length - 1] == '>') 
			{
				/* Token */
				if (tmp_entry[1] != '/')
				{
					/* Opening token, create new tree root */
					config_item = proto_tree_add_text(tree, tvb, offset, 
							tmp_entry_length, "%s", tmp_entry);

					if (config_item)
						config_tree = proto_item_add_subtree(config_item, 
								ett_pvfs_server_config_branch);
				}
				else
				{
					/* Closing token */
					config_item = NULL;
					config_tree = NULL;
				}
			}
			else
			{
				/* Malformed token */
				break;
			}
		}
		else
		{
			/* Insert items into the root config tree if there's no subtree
			 * defined.
			 */
			if (config_tree == NULL)
				config_tree = tree;

			if (tmp_entry_length > 0)
			{
				proto_tree_add_text(config_tree, tvb, offset, tmp_entry_length,
						"%s", tmp_entry);
			}
		}

		offset += entry_length + 1;

		ptr++;
		bytes_processed++;
	}

	if (bytes_processed < total_config_bytes)
	{
		/* We ran out of server config data */
		proto_tree_add_text(config_tree, tvb, offset, -1, 
				"<MALFORMED OR TRUNCATED DATA>");
	}

	return offset;
}

static int
dissect_pvfs2_write_completion_response(tvbuff_t *tvb, proto_tree *tree, 
		int offset)
{
	/* size */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_total_completed,
			NULL);
	
	return offset;
}

static int
dissect_pvfs2_mgmt_setparam_response(tvbuff_t *tvb, proto_tree *tree, 
		int offset)
{
	guint64 val;

	/* old_value */
	val = ((guint64) tvb_get_letohl(tvb, offset + 4)) << 32 |
		tvb_get_letohl(tvb, offset);

	proto_tree_add_uint64(tree, hf_pvfs_prev_value, tvb, offset, 8, val);

	offset += 8;

	return offset;
}

static int
dissect_pvfs2_statfs_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	offset += 4;

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	/* bytes_available */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_bytes_available,
			NULL);

	/* bytes_total */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_bytes_total,
			NULL);

	/* RAM bytes total */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_ram_bytes_total,
			NULL);

	/* RAM bytes free */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_ram_bytes_free,
			NULL);

	/* load average (1s) */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_load_average_1s,
			NULL);

	/* load average (5s) */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_load_average_5s,
			NULL);

	/* load average (15s) */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_load_average_15s,
			NULL);

	/* uptime (seconds) */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_uptime_seconds,
			NULL);

	/* handles_available_count */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_handles_available,
			NULL);

	/* handles_total_count */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_handles_total,
			NULL);

	return offset;
}

static int
dissect_pvfs_mgmt_perf_stat(tvbuff_t *tvb, proto_tree *tree, int offset,
		int nItem)
{
	proto_item *stat_item = NULL;
	proto_tree *stat_tree = NULL;

	if (tree)
	{
		stat_item = proto_tree_add_text(tree, tvb, offset, 48, 
				"Stat Array - Element %d", nItem);

		if (stat_item)
			stat_tree = proto_item_add_subtree(stat_item, 
					ett_pvfs_mgmt_perf_stat);
	}

	/* TODO: valid_flag */
	proto_tree_add_text(stat_tree, tvb, offset, 4, "valid_flag: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* TODO: id */
	proto_tree_add_text(stat_tree, tvb, offset, 4, "id: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	offset = dissect_pvfs_uint64(tvb, stat_tree, offset, hf_pvfs_start_time_ms,
			NULL);
	offset = dissect_pvfs_uint64(tvb, stat_tree, offset, hf_pvfs_bytes_written,
			NULL);
	offset = dissect_pvfs_uint64(tvb, stat_tree, offset, hf_pvfs_bytes_read,
			NULL);
	offset = dissect_pvfs_uint64(tvb, stat_tree, offset, hf_pvfs_metadata_write,
			NULL);
	offset = dissect_pvfs_uint64(tvb, stat_tree, offset, hf_pvfs_metadata_read,
			NULL);

	return offset;
}

static int
dissect_pvfs2_mgmt_perf_mon_response(tvbuff_t *tvb, proto_tree *tree,
		int offset)
{
	guint32 perf_array_count, i;

	/* TODO: suggested_next_id */
	proto_tree_add_text(tree, tvb, offset, 4, "suggested_next_id: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	offset += 4;

	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_end_time_ms,
			NULL);
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_cur_time_ms,
			NULL);

	offset += 4;

	/* TODO: perf_array_count */
	perf_array_count = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "perf_array_count: %d", 
			perf_array_count);
	offset += 4;

	for (i = 0; i < perf_array_count; i++)
		offset = dissect_pvfs_mgmt_perf_stat(tvb, tree, offset, i);

	return offset;
}

static int
dissect_pvfs2_mgmt_iterate_handles_response(tvbuff_t *tvb, proto_tree *tree, 
		int offset, packet_info *pinfo)
{
	guint32 handle_count, i;

	/* ds_position */
	proto_tree_add_text(tree, tvb, offset, 4, "ds_position: %d",
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* handle_count */
	handle_count = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "handle_count: %d",
			handle_count);
	offset += 4;

	/* TODO: this could be improved */
	for (i = 0; i < handle_count; i++)
		offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs2_mgmt_dspace_info(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo)
{
	offset = dissect_pvfs2_error(tvb, tree, offset, pinfo);
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);
	offset = dissect_pvfs2_ds_type(tvb, tree, offset, NULL);
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_b_size,
			NULL);
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_k_size,
			NULL);
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

static int
dissect_pvfs2_mgmt_dspace_info_list_response(tvbuff_t *tvb, proto_tree *tree, 
		int offset, packet_info *pinfo)
{
	guint32 dspace_info_count, i;
	proto_item *arr_item = NULL;
	proto_tree *arr_tree = NULL;

	offset += 4;

	/* dspace_info_count */
	dspace_info_count = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "dspace_info_count: %d",
			dspace_info_count);

	if ((dspace_info_count > 0) && (tree))
	{
		arr_item = proto_tree_add_text(tree, tvb, offset, 
				dspace_info_count * 40, "dspace_info Array (%d items)",
				dspace_info_count);

		if (arr_item)
			arr_tree = proto_item_add_subtree(arr_item, 
					ett_pvfs_mgmt_dspace_info);
	}

	for (i = 0; i < dspace_info_count; i++)
		offset = dissect_pvfs2_mgmt_dspace_info(tvb, arr_tree, offset, pinfo);

	return offset;
}

static int
dissect_pvfs2_mgmt_event_mon_response(tvbuff_t *tvb, proto_tree *tree,
		int offset)
{
	/* api */
	proto_tree_add_text(tree, tvb, offset, 4, "api: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* operation */
	proto_tree_add_text(tree, tvb, offset, 4, "operation: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* value */
	proto_tree_add_text(tree, tvb, offset, 4, "value: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* id */
	offset = dissect_pvfs_uint64(tvb, tree, offset, hf_pvfs_id_gen_t,
			NULL);

	/* flags */
	proto_tree_add_text(tree, tvb, offset, 4, "flags: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* tv_sec */
	proto_tree_add_text(tree, tvb, offset, 4, "tv_sec: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	/* tv_usec */
	proto_tree_add_text(tree, tvb, offset, 4, "tv_usec: %d", 
			tvb_get_letohl(tvb, offset));
	offset += 4;

	offset += 4;

	return offset;
}

static int
dissect_pvfs2_mgmt_remove_object_response(tvbuff_t *tvb, proto_tree *tree, 
		int offset, packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	/* fs_id */
	offset = dissect_pvfs_fs_id(tvb, tree, offset);

	return offset;
}

static int
dissect_pvfs2_mgmt_get_dirdata_handle_response(tvbuff_t *tvb,
		proto_tree *tree, int offset, packet_info *pinfo)
{
	/* handle */
	offset = dissect_pvfs_fh(tvb, offset, pinfo, tree, "handle", NULL);

	return offset;
}

/* TODO: untested */
static int
dissect_pvfs2_geteattr_response(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo _U_)
{
	offset += 4;

	/* Dissect nKey & ds_keyval array */
	offset = dissect_ds_keyval_array(tvb, tree, offset);

	return offset;
}

static int
dissect_pvfs2_response(tvbuff_t *tvb, proto_tree *tree, int offset,
		packet_info *pinfo, guint32 server_op)
{
	/* error code */
	offset = dissect_pvfs2_error(tvb, tree, offset, pinfo);

	switch (server_op)
	{
		case PVFS_SERV_CREATE:
			offset = dissect_pvfs2_create_response(tvb, tree, offset, pinfo);
			break;

#if 0
		case PVFS_SERV_REMOVE:
			/* No result data */
			break;
#endif

		case PVFS_SERV_IO:
			offset = dissect_pvfs2_io_response(tvb, tree, offset);
			break;

		case PVFS_SERV_GETATTR:
			offset = dissect_pvfs2_getattr_response(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_SETATTR:
			/* No result data */
			break;

		case PVFS_SERV_LOOKUP_PATH:
			offset = dissect_pvfs2_lookup_path_response(tvb, tree, offset, pinfo);
			break;

#if 0
		case PVFS_SERV_CRDIRENT:
			/* No result data */
			break;
#endif

		case PVFS_SERV_RMDIRENT:
			offset = dissect_pvfs2_rmdirent_response(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_CHDIRENT:
			offset = dissect_pvfs2_chdirent_response(tvb, tree, offset, pinfo);
			break;

#if 0
		case PVFS_SERV_TRUNCATE:
			/* No result data */
			break;
#endif

		case PVFS_SERV_MKDIR:
			offset = dissect_pvfs2_mkdir_response(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_READDIR:
			offset = dissect_pvfs2_readdir_response(tvb, tree, offset, pinfo);
			break;

		case PVFS_SERV_GETCONFIG:
			offset = dissect_pvfs2_getconfig_response(tvb, tree, offset);
			break;

		case PVFS_SERV_WRITE_COMPLETION:
			offset = dissect_pvfs2_write_completion_response(tvb, tree, offset);
			break;

#if 0
		case PVFS_SERV_FLUSH:
			/* No result data */
			break;
#endif

		case PVFS_SERV_MGMT_SETPARAM:
			offset = dissect_pvfs2_mgmt_setparam_response(tvb, tree, offset);
			break;

#if 0
		case PVFS_SERV_MGMT_NOOP:
			/* No result data */
			break;
#endif

		case PVFS_SERV_STATFS:
			offset = dissect_pvfs2_statfs_response(tvb, tree, offset);
			break;

#if 0
		case PVFS_SERV_PERF_UPDATE:
			/* No result data */
			break;
#endif

		case PVFS_SERV_MGMT_PERF_MON:
			offset = dissect_pvfs2_mgmt_perf_mon_response(tvb, tree, offset);
			break;

		case PVFS_SERV_MGMT_ITERATE_HANDLES:
			offset = dissect_pvfs2_mgmt_iterate_handles_response(tvb, tree, 
					offset, pinfo);
			break;

		case PVFS_SERV_MGMT_DSPACE_INFO_LIST:
			offset = dissect_pvfs2_mgmt_dspace_info_list_response(tvb, tree, 
					offset, pinfo);
			break;

		case PVFS_SERV_MGMT_EVENT_MON:
			offset = dissect_pvfs2_mgmt_event_mon_response(tvb, tree, offset);
			break;

		case PVFS_SERV_MGMT_REMOVE_OBJECT:
			offset = dissect_pvfs2_mgmt_remove_object_response(tvb, tree, offset,
					pinfo);
			break;

#if 0
		case PVFS_SERV_MGMT_REMOVE_DIRENT:
			/* No result data */
			break;
#endif

		case PVFS_SERV_MGMT_GET_DIRDATA_HANDLE:
			offset = dissect_pvfs2_mgmt_get_dirdata_handle_response(tvb, tree, 
					offset, pinfo);
			break;

#if 0
		case PVFS_SERV_JOB_TIMER:
			/* No result data */
			break;
#endif

		case PVFS_SERV_PROTO_ERROR:
			/* No result data */
			break;

			/* TODO: untested */
		case PVFS_SERV_GETEATTR:
			offset = dissect_pvfs2_geteattr_response(tvb, tree, offset, pinfo);
			break;

#if 0
		case PVFS_SERV_SETEATTR:
			/* No result data */
			break;
#endif

#if 0
		case PVFS_SERV_DELEATTR:
			/* No result data */
			break;
#endif

		default:
			/* TODO: what do we do here? */
			break;
	}

	return offset;
}

static GHashTable *pvfs2_io_tracking_value_table = NULL;

typedef struct pvfs2_io_tracking_key
{
	guint64 tag;
} pvfs2_io_tracking_key_t;

typedef struct pvfs2_io_tracking_value
{
	guint32 request_frame_num;
	guint32 response_frame_num;
	guint32 flow_frame_num;

} pvfs2_io_tracking_value_t;

static gint
pvfs2_io_tracking_equal(gconstpointer k1, gconstpointer k2)
{
	const pvfs2_io_tracking_key_t *key1 = (const pvfs2_io_tracking_key_t *) k1;
	const pvfs2_io_tracking_key_t *key2 = (const pvfs2_io_tracking_key_t *) k2;

	return (key1->tag == key2->tag);
}

static guint
pvfs2_io_tracking_hash(gconstpointer k)
{
	const pvfs2_io_tracking_key_t *key = (const pvfs2_io_tracking_key_t *) k;

	return (key->tag >> 32) ^ ((guint32) key->tag);
}

static void
pvfs2_io_tracking_init(void)
{
	if (pvfs2_io_tracking_value_table != NULL)
		g_hash_table_destroy(pvfs2_io_tracking_value_table);

	pvfs2_io_tracking_value_table = g_hash_table_new(pvfs2_io_tracking_hash,
			pvfs2_io_tracking_equal);
}

static pvfs2_io_tracking_value_t *
pvfs2_io_tracking_new_with_tag(guint64 tag, guint32 num)
{
	pvfs2_io_tracking_value_t *value;
	pvfs2_io_tracking_key_t *newkey;

	newkey = (pvfs2_io_tracking_key_t *) se_alloc(sizeof(*newkey));
	memset(newkey, 0, sizeof(*newkey));
	newkey->tag = tag;

	value = se_alloc(sizeof(*value));
	memset(value, 0, sizeof(*value));

	g_hash_table_insert(pvfs2_io_tracking_value_table, newkey, value);

	value->request_frame_num = num;

	return value;
}

static gboolean
dissect_pvfs_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
		gboolean dissect_other_as_continuation _U_)
{
	guint32 magic_nr = 0, mode = 0;
	proto_item *item = NULL, *hitem = NULL;
	proto_tree *pvfs_tree = NULL, *pvfs_htree = NULL;
	int offset = 0;
	guint64 tag;
	guint32 server_op;
	pvfs2_io_tracking_value_t *val = NULL;

	if (parent_tree) 
	{
		item = proto_tree_add_item(parent_tree, proto_pvfs, tvb, 0, -1, FALSE);

		if (item)
			pvfs_tree = proto_item_add_subtree(item, ett_pvfs);
	}

	proto_tree_add_text(pvfs_tree, tvb, 0, -1, "Version: 2");

	/*
	 * Validate magic number.  For the time being, assume that an invalid
	 * magic number is an indication of a continuation packet.
	 */

	if ((magic_nr = tvb_get_letohl(tvb, offset)) != BMI_MAGIC_NR)
	{
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");

		proto_tree_add_text(pvfs_tree, tvb, 0, -1, "<data>");

		return TRUE;
	}

	/* PVFS packet header is 24 bytes */
	hitem = proto_tree_add_text(pvfs_tree, tvb, 0, BMI_HEADER_SIZE, 
			"BMI Header");
	if (hitem)
		pvfs_htree = proto_item_add_subtree(hitem, ett_pvfs_hdr);

	/* Magic number */
	proto_tree_add_uint(pvfs_htree, hf_pvfs_magic_nr, tvb, offset, 4, magic_nr);
	offset += 4;

	/* TCP message mode (32-bit) */
	mode = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(pvfs_htree, hf_pvfs_mode, tvb, offset, 4, mode);
	offset += 4;

	/* tag (64-bit) */
	offset = dissect_pvfs_uint64(tvb, pvfs_htree, offset, hf_pvfs_tag, &tag);

	/* size (64-bit) */
	offset = dissect_pvfs_uint64(tvb, pvfs_htree, offset, hf_pvfs_size, NULL);

	/* Lookahead to get server_op (invalid if frame contains flow data) */
	server_op = tvb_get_letohl(tvb, offset + 8);

	if (mode == TCP_MODE_UNEXP)
	{
		/* Add entry to tracking table for PVFS_SERV_IO request */
		if ((server_op == PVFS_SERV_IO) && !pinfo->fd->flags.visited)
			val = pvfs2_io_tracking_new_with_tag(tag, pinfo->fd->num);
	}
	else
	{
		pvfs2_io_tracking_key_t key;

		memset(&key, 0, sizeof(key));
		key.tag = tag;

		val = g_hash_table_lookup(pvfs2_io_tracking_value_table, &key);

		/* If this frame contains a known PVFS_SERV_IO tag, track it */
		if (val && !pinfo->fd->flags.visited)
		{
			/* If response HAS NOT been seen, mark this frame as response */
			if (val->response_frame_num == 0)
				val->response_frame_num = pinfo->fd->num;
			else
			{
				/* If response HAS been seen, this frame is flow data */
				if (val->flow_frame_num == 0)
					val->flow_frame_num = pinfo->fd->num;
			}
		}
	}

	if (val && (val->flow_frame_num == pinfo->fd->num))
	{
		/* This frame is marked as being flow data */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "PVFS flow data");

		proto_tree_add_text(pvfs_tree, tvb, offset, -1, "<data>");

		return TRUE;
	}

	/* Extract common part of packet found in requests and responses */
	offset = dissect_pvfs2_common_header(tvb, pvfs_htree, offset);

	/* Update column info display */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_set_str(pinfo->cinfo, COL_INFO, 
				val_to_str(server_op, names_pvfs_server_op, "%u (unknown)"));

		col_append_fstr(pinfo->cinfo, COL_INFO, 
				(mode == TCP_MODE_UNEXP)? " (request)": " (response)");
	}

	/* TODO: handle all modes */
	if (mode == TCP_MODE_UNEXP)
	{
		/* Request */
		offset = dissect_pvfs2_request(tvb, pvfs_tree, offset, pinfo, server_op);
	}
	else
	{
		/* TODO: re-examine this! */
#if 0
		if (mode == TCP_MODE_REND)
		{
			/*
			 * TODO: move this code outside so it's common for requests and
			 * responses
			 */

			if (check_col(pinfo->cinfo, COL_INFO))
				col_set_str(pinfo->cinfo, COL_INFO, "PVFS2 DATA (request)");
		}
		else
#endif
		{
			/* Response */
			offset = dissect_pvfs2_response(tvb, pvfs_tree, offset, pinfo,
					server_op);
		}
	}

	return TRUE;
}

/* Register the protocol with Ethereal */
void
proto_register_pvfs(void)
{
	static hf_register_info hf[] = {
		{ &hf_pvfs_magic_nr, 
			{ "Magic Number", "pvfs.magic_nr", FT_UINT32, BASE_DEC, 
				NULL, 0, "Magic Number", HFILL }},

		{ &hf_pvfs_mode,
			{ "Mode", "pvfs.mode", FT_UINT32, BASE_DEC, 
				VALS(names_pvfs_mode), 0, "Mode", HFILL }},

		{ &hf_pvfs_tag,
			{ "Tag", "pvfs.tag", FT_UINT64, BASE_DEC,
				NULL, 0, "Tag", HFILL }},

		{ &hf_pvfs_size,
			{ "Size", "pvfs.size", FT_UINT64, BASE_DEC,
				NULL, 0, "Size", HFILL }},

		{ &hf_pvfs_release_number,
			{ "Release Number", "pvfs.release_number", FT_UINT32, BASE_DEC,
				NULL, 0, "Release Number", HFILL }},

		{ &hf_pvfs_encoding,
			{ "Encoding", "pvfs.encoding", FT_UINT32, BASE_DEC, 
				VALS(names_pvfs_encoding), 0, "Encoding", HFILL }},

		{ &hf_pvfs_server_op,
			{ "Server Operation", "pvfs.server_op", FT_UINT32, BASE_DEC,
				VALS(names_pvfs_server_op), 0, "Server Operation", HFILL }},

		{ &hf_pvfs_handle,
			{ "Handle", "pvfs.handle", FT_BYTES, BASE_HEX,
				NULL, 0, "Handle", HFILL }},

		{ &hf_pvfs_fs_id,
			{ "fs_id", "pvfs.fs_id", FT_UINT32, BASE_HEX,
				NULL, 0, "File System ID", HFILL }},

		{ &hf_pvfs_attrmask,
			{ "attrmask", "pvfs.attrmask", FT_UINT32, BASE_HEX,
				NULL, 0, "Attribute Mask", HFILL }},

		{ &hf_pvfs_attr,
			{ "attr", "pvfs.attribute", FT_UINT32, BASE_HEX,
				VALS(names_pvfs_attr), 0, "Attribute", HFILL }},

		{ &hf_pvfs_ds_type,
			{ "ds_type", "pvfs.ds_type", FT_UINT32, BASE_HEX,
				VALS(names_pvfs_ds_type), 0, "Type", HFILL }},

		{ &hf_pvfs_error,
			{ "Result", "pvfs.error", FT_UINT32, BASE_HEX,
				VALS(names_pvfs_error), 0, "Result", HFILL }},

		{ &hf_pvfs_atime,
			{ "atime", "pvfs.atime", FT_ABSOLUTE_TIME, BASE_NONE,
				NULL, 0, "Access Time", HFILL }},

		{ &hf_pvfs_atime_sec,
			{ "seconds", "pvfs.atime.sec", FT_UINT32, BASE_DEC,
				NULL, 0, "Access Time (seconds)", HFILL }},

		{ &hf_pvfs_atime_nsec,
			{ "microseconds", "pvfs.atime.usec", FT_UINT32, BASE_DEC,
				NULL, 0, "Access Time (microseconds)", HFILL }},

		{ &hf_pvfs_mtime,
			{ "mtime", "pvfs.mtime", FT_ABSOLUTE_TIME, BASE_NONE,
				NULL, 0, "Modify Time", HFILL }},

		{ &hf_pvfs_mtime_sec,
			{ "seconds", "pvfs.mtime.sec", FT_UINT32, BASE_DEC,
				NULL, 0, "Modify Time (seconds)", HFILL }},

		{ &hf_pvfs_mtime_nsec,
			{ "microseconds", "pvfs.mtime.usec", FT_UINT32, BASE_DEC,
				NULL, 0, "Modify Time (microseconds)", HFILL }},

		{ &hf_pvfs_ctime,
			{ "ctime", "pvfs.ctime", FT_ABSOLUTE_TIME, BASE_NONE,
				NULL, 0, "Creation Time", HFILL }},

		{ &hf_pvfs_ctime_sec,
			{ "seconds", "pvfs.ctime.sec", FT_UINT32, BASE_DEC,
				NULL, 0, "Creation Time (seconds)", HFILL }},

		{ &hf_pvfs_ctime_nsec,
			{ "microseconds", "pvfs.ctime.usec", FT_UINT32, BASE_DEC,
				NULL, 0, "Creation Time (microseconds)", HFILL }},

		{ &hf_pvfs_parent_atime,
			{ "Parent atime", "pvfs.parent_atime", FT_ABSOLUTE_TIME, BASE_NONE,
				NULL, 0, "Access Time", HFILL }},

		{ &hf_pvfs_parent_atime_sec,
			{ "seconds", "pvfs.parent_atime.sec", FT_UINT32, BASE_DEC,
				NULL, 0, "Access Time (seconds)", HFILL }},

		{ &hf_pvfs_parent_atime_nsec,
			{ "microseconds", "pvfs.parent_atime.usec", FT_UINT32, BASE_DEC,
				NULL, 0, "Access Time (microseconds)", HFILL }},

		{ &hf_pvfs_parent_mtime,
			{ "Parent mtime", "pvfs.parent_mtime", FT_ABSOLUTE_TIME, BASE_NONE,
				NULL, 0, "Modify Time", HFILL }},

		{ &hf_pvfs_parent_mtime_sec,
			{ "seconds", "pvfs.parent_mtime.sec", FT_UINT32, BASE_DEC,
				NULL, 0, "Modify Time (seconds)", HFILL }},

		{ &hf_pvfs_parent_mtime_nsec,
			{ "microseconds", "pvfs.parent_mtime.usec", FT_UINT32, BASE_DEC,
				NULL, 0, "Modify Time (microseconds)", HFILL }},

		{ &hf_pvfs_parent_ctime,
			{ "Parent ctime", "pvfs.parent_ctime", FT_ABSOLUTE_TIME, BASE_NONE,
				NULL, 0, "Creation Time", HFILL }},

		{ &hf_pvfs_parent_ctime_sec,
			{ "seconds", "pvfs.parent_ctime.sec", FT_UINT32, BASE_DEC,
				NULL, 0, "Creation Time (seconds)", HFILL }},

		{ &hf_pvfs_parent_ctime_nsec,
			{ "microseconds", "pvfs.parent_ctime.usec", FT_UINT32, BASE_DEC,
				NULL, 0, "Creation Time (microseconds)", HFILL }},

		{ &hf_pvfs_dirent_count,
			{ "Dir Entry Count", "pvfs.dirent_count", FT_UINT64, BASE_DEC,
				NULL, 0, "Directory Entry Count", HFILL }},

		{ &hf_pvfs_directory_version,
			{ "Directory Version", "pvfs.directory_version", FT_UINT64, BASE_HEX,
				NULL, 0, "Directory Version", HFILL }},

		{ &hf_pvfs_path,
			{ "Path", "pvfs.path", FT_STRING, BASE_DEC, 
				NULL, 0, "Path", HFILL }},

		{ &hf_pvfs_total_completed,
			{ "Bytes Completed", "pvfs.bytes_completed", FT_UINT64, BASE_DEC,
				NULL, 0, "Bytes Completed", HFILL }},

		{ &hf_pvfs_io_dist,
			 { "Name", "pvfs.distribution.name", FT_STRING, BASE_DEC,
				 NULL, 0, "Distribution Name", HFILL }},

		{ &hf_pvfs_aggregate_size,
			{ "Aggregate Size", "pvfs.aggregate_size", FT_UINT64, BASE_DEC,
				NULL, 0, "Aggregate Size", HFILL }},

		{ &hf_pvfs_io_type,
			{ "I/O Type", "pvfs.io_type", FT_UINT32, BASE_DEC,
				VALS(names_pvfs_io_type), 0, "I/O Type", HFILL }},

		{ &hf_pvfs_flowproto_type,
			{ "Flow Protocol Type", "pvfs.flowproto_type", FT_UINT32, BASE_DEC,
				VALS(names_pvfs_flowproto_type), 0, "Flow Protocol Type", HFILL }},

		{ &hf_pvfs_server_param,
			{ "Server Parameter", "pvfs.server_param", FT_UINT32, BASE_DEC,
				VALS(names_pvfs_server_param), 0, "Server Parameter", HFILL }},

		{ &hf_pvfs_prev_value,
			{ "Previous Value", "pvfs.prev_value", FT_UINT64, BASE_DEC,
				NULL, 0, "Previous Value", HFILL }},

		{ &hf_pvfs_ram_free_bytes,
			{ "RAM Free Bytes", "pvfs.ram.free_bytes", FT_UINT64, BASE_DEC,
				NULL, 0, "RAM Free Bytes", HFILL }},

		{ &hf_pvfs_bytes_available,
			{ "Bytes Available", "pvfs.bytes_available", FT_UINT64, BASE_DEC,
				NULL, 0, "Bytes Available", HFILL }},

		{ &hf_pvfs_bytes_total,
			{ "Bytes Total", "pvfs.bytes_total", FT_UINT64, BASE_DEC,
				NULL, 0, "Bytes Total", HFILL }},

		{ &hf_pvfs_ram_bytes_total,
			{ "RAM Bytes Total", "pvfs.ram_bytes_total", FT_UINT64, BASE_DEC,
				NULL, 0, "RAM Bytes Total", HFILL }},

		{ &hf_pvfs_ram_bytes_free,
			{ "RAM Bytes Free", "pvfs.ram_bytes_free", FT_UINT64, BASE_DEC,
				NULL, 0, "RAM Bytes Free", HFILL }},

		{ &hf_pvfs_load_average_1s,
			{ "Load Average (1s)", "pvfs.load_average.1s", FT_UINT64, BASE_DEC,
				NULL, 0, "Load Average (1s)", HFILL }},

		{ &hf_pvfs_load_average_5s,
			{ "Load Average (5s)", "pvfs.load_average.5s", FT_UINT64, BASE_DEC,
				NULL, 0, "Load Average (5s)", HFILL }},

		{ &hf_pvfs_load_average_15s,
			{ "Load Average (15s)", "pvfs.load_average.15s", FT_UINT64, BASE_DEC,
				NULL, 0, "Load Average (15s)", HFILL }},

		{ &hf_pvfs_uptime_seconds,
			{ "Uptime (seconds)", "pvfs.uptime", FT_UINT64, BASE_DEC,
				NULL, 0, "Uptime (seconds)", HFILL }},

		{ &hf_pvfs_handles_available,
			{ "Handles Available", "pvfs.handles_available", FT_UINT64, BASE_DEC,
				NULL, 0, "Handles Available", HFILL }},

		{ &hf_pvfs_handles_total,
			{ "Total Handles", "pvfs.total_handles", FT_UINT64, BASE_DEC,
				NULL, 0, "Total Handles", HFILL }},

		/*
		 * This is used when the field returns 64-bits but we're only interested
		 * in the lower 32-bit bits.
		 */
		{ &hf_pvfs_unused,
			{ "Unused", "", FT_UINT32, BASE_DEC,
				NULL, 0, "Unused", HFILL }},

		{ &hf_pvfs_context_id,
			{ "Context ID", "pvfs.context_id", FT_UINT32, BASE_DEC,
				NULL, 0, "Context ID", HFILL }},

		{ &hf_pvfs_offset,
			{ "Offset", "pvfs.offset", FT_UINT64, BASE_DEC,
				NULL, 0, "Offset", HFILL }},

		{ &hf_pvfs_stride,
			{ "Stride", "pvfs.stride", FT_UINT64, BASE_DEC,
				NULL, 0, "Stride", HFILL }},

		{ &hf_pvfs_ub,
			{ "ub", "pvfs.ub", FT_UINT64, BASE_DEC,
				NULL, 0, "ub", HFILL }},

		{ &hf_pvfs_lb,
			{ "lb", "pvfs.lb", FT_UINT64, BASE_DEC,
				NULL, 0, "lb", HFILL }},

		{ &hf_pvfs_end_time_ms,
			{ "end_time_ms", "pvfs.end_time_ms", FT_UINT64, BASE_DEC,
				NULL, 0, "end_time_ms", HFILL }},

		{ &hf_pvfs_cur_time_ms,
			{ "cur_time_ms", "pvfs.cur_time_ms", FT_UINT64, BASE_DEC,
				NULL, 0, "cur_time_ms", HFILL }},

		{ &hf_pvfs_start_time_ms,
			{ "start_time_ms", "pvfs.start_time_ms", FT_UINT64, BASE_DEC,
				NULL, 0, "start_time_ms", HFILL }},

		{ &hf_pvfs_bytes_written,
			{ "bytes_written", "pvfs.bytes_written", FT_UINT64, BASE_DEC,
				NULL, 0, "bytes_written", HFILL }},

		{ &hf_pvfs_bytes_read,
			{ "bytes_read", "pvfs.bytes_read", FT_UINT64, BASE_DEC,
				NULL, 0, "bytes_read", HFILL }},

		{ &hf_pvfs_metadata_write,
			{ "metadata_write", "pvfs.metadata_write", FT_UINT64, BASE_DEC,
				NULL, 0, "metadata_write", HFILL }},

		{ &hf_pvfs_metadata_read,
			{ "metadata_read", "pvfs.metadata_read", FT_UINT64, BASE_DEC,
				NULL, 0, "metadata_read", HFILL }},

		{ &hf_pvfs_b_size,
			{ "Size of bstream (if applicable)", "pvfs.b_size", FT_UINT64,
				BASE_DEC, NULL, 0, "Size of bstream", HFILL }},

		{ &hf_pvfs_k_size,
			{ "Number of keyvals (if applicable)", "pvfs.k_size", FT_UINT64,
				BASE_DEC, NULL, 0, "Number of keyvals", HFILL }},

		{ &hf_pvfs_id_gen_t,
			{ "id_gen_t", "pvfs.id_gen_t", FT_UINT64, BASE_DEC,
				NULL, 0, "id_gen_t", HFILL }},

		{ &hf_pvfs_attribute_key,
			{ "Attribute key", "pvfs.attribute.key", FT_STRING, BASE_DEC,
				NULL, 0, "Attribute key", HFILL }},

		{ &hf_pvfs_attribute_value,
			{ "Attribute value", "pvfs.attribute.value", FT_STRING, BASE_DEC,
				NULL, 0, "Attribute value", HFILL }},

		{ &hf_pvfs_strip_size,
			{ "Strip size", "pvfs.strip_size", FT_UINT64, BASE_DEC,
				NULL, 0, "Strip size (bytes)", HFILL }},

		/* TODO: need description */
		{ &hf_pvfs_ereg,
			{ "ereg", "pvfs.ereg", FT_INT32, BASE_DEC,
				NULL, 0, "ereg", HFILL }},

		/* TODO: need description */
		{ &hf_pvfs_sreg,
			{ "sreg", "pvfs.sreg", FT_INT32, BASE_DEC,
				NULL, 0, "sreg", HFILL }},

		{ &hf_pvfs_num_eregs,
			{ "Number of eregs", "pvfs.num_eregs", FT_UINT32, BASE_DEC,
				NULL, 0, "Number of eregs", HFILL }},

		{ &hf_pvfs_num_blocks,
			{ "Number of blocks", "pvfs.num_blocks", FT_UINT32, BASE_DEC,
				NULL, 0, "Number of blocks", HFILL }},

		{ &hf_pvfs_num_contig_chunks,
			{ "Number of contig_chunks", "pvfs.num_contig_chunks", FT_UINT32, 
				BASE_DEC, NULL, 0, "Number of contig_chunks", HFILL }},

		{ &hf_pvfs_server_nr,
			{ "Server #", "pvfs.server_nr", FT_UINT32, BASE_DEC,
				NULL, 0, "Server #", HFILL }},

		{ &hf_pvfs_server_count,
			{ "Number of servers", "pvfs.server_count", FT_UINT32, BASE_DEC,
				NULL, 0, "Number of servers", HFILL }},

		{ &hf_pvfs_fh_length,
			{ "length", "pvfs.fh.length", FT_UINT32, BASE_DEC,
				NULL, 0, "file handle length", HFILL }},

		{ &hf_pvfs_fh_hash,
			{ "hash", "pvfs.fh.hash", FT_UINT32, BASE_HEX,
				NULL, 0, "file handle hash", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_pvfs,
		&ett_pvfs_hdr,
		&ett_pvfs_credentials,
		&ett_pvfs_server_config,
		&ett_pvfs_server_config_branch,
		&ett_pvfs_attrmask,
		&ett_pvfs_time,
		&ett_pvfs_extent_array_tree,
		&ett_pvfs_extent_item,
		&ett_pvfs_string,
		&ett_pvfs_attr_tree,
		&ett_pvfs_distribution,
		&ett_pvfs_mgmt_perf_stat,
		&ett_pvfs_mgmt_dspace_info,
		&ett_pvfs_attr,
		&ett_pvfs_fh
	};

	/* Register the protocol name and description */
	proto_pvfs = proto_register_protocol("Parallel Virtual File System",
			"PVFS", "pvfs");

	/*
	 * Required function calls to register the header fields and
	 * subtrees used
	 */

	proto_register_field_array(proto_pvfs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine(pvfs2_io_tracking_init);
}

void
proto_reg_handoff_pvfs(void)
{
	dissector_handle_t pvfs_handle;

	pvfs_handle = new_create_dissector_handle(dissect_pvfs, proto_pvfs);
	dissector_add("tcp.port", TCP_PORT_PVFS2, pvfs_handle);

/*	heur_dissector_add("tcp", dissect_pvfs_heur, proto_pvfs);*/
}

