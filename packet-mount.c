/* packet-mount.c
 * Routines for mount dissection
 *
 * $Id: packet-mount.c,v 1.1 1999/11/11 21:21:59 nneul Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
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
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#include "packet-rpc.h"
#include "packet-mount.h"

static int proto_mount = -1;
static int hf_mount_path = -1;

/* Dissect a unmount call */
int dissect_unmount_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_mount_path);
	}
	
	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */

const vsff mount_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MOUNT,   "MOUNT",      
		NULL, NULL },
    { MOUNTPROC_UNMOUNT, "UNMOUNT",        
		dissect_unmount_call, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of mount version 1 */


void
proto_register_mount(void)
{
	static hf_register_info hf[] = {
		{ &hf_mount_path, {
			"Path", "mount.path", FT_STRING, BASE_DEC,
			NULL, 0, "Path" }},
	};

	proto_mount = proto_register_protocol("Mount Service", "mount");
	proto_register_field_array(proto_mount, hf, array_length(hf));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_mount, MOUNT_PROGRAM, ETT_MOUNT);
	/* Register the procedure tables */
	rpc_init_proc_table(MOUNT_PROGRAM, 1, mount_proc);
}

