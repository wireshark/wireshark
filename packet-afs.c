/* packet-afs.c
 * Routines for AFS packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 * Based on routines from tcpdump patches by
 *   Ken Hornstein <kenh@cmf.nrl.navy.mil>
 * Portions based on information retrieved from the RX definitions
 *   in Arla, the free AFS client at http://www.stacken.kth.se/project/arla/
 * Portions based on information/specs retrieved from the OpenAFS sources at
 *   www.openafs.org, Copyright IBM. 
 *
 * $Id: packet-afs.c,v 1.22 2000/11/03 22:11:36 nneul Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "conversation.h"
#include "resolv.h"

#include "packet-rx.h"
#include "packet-afs.h"
#include "packet-afs-defs.h"
#include "packet-afs-macros.h"


int afs_packet_init_count = 100;

struct afs_request_key {
  guint32 conversation, callnumber;
  guint16 service;
};

struct afs_request_val {
  guint32 opcode;
};

GHashTable *afs_request_hash = NULL;
GMemChunk *afs_request_keys = NULL;
GMemChunk *afs_request_vals = NULL;



/*
 * Dissector prototypes
 */
static void dissect_fs_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_fs_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_cb_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_cb_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_bos_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_bos_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vol_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vol_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_ubik_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_ubik_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_kauth_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_kauth_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_prot_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_prot_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vldb_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vldb_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_backup_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_backup_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);


/*
 * Hash Functions
 */
static gint
afs_equal(gconstpointer v, gconstpointer w)
{
  struct afs_request_key *v1 = (struct afs_request_key *)v;
  struct afs_request_key *v2 = (struct afs_request_key *)w;

  if (v1 -> conversation == v2 -> conversation &&
      v1 -> service == v2 -> service &&
      v1 -> callnumber == v2 -> callnumber ) {

    return 1;
  }

  return 0;
}

static guint
afs_hash (gconstpointer v)
{
	struct afs_request_key *key = (struct afs_request_key *)v;
	guint val;

	val = key -> conversation + key -> service + key -> callnumber;

	return val;
}

/*
 * Protocol initialization
 */
static void
afs_init_protocol(void)
{
	if (afs_request_hash)
		g_hash_table_destroy(afs_request_hash);
	if (afs_request_keys)
		g_mem_chunk_destroy(afs_request_keys);
	if (afs_request_vals)
		g_mem_chunk_destroy(afs_request_vals);

	afs_request_hash = g_hash_table_new(afs_hash, afs_equal);
	afs_request_keys = g_mem_chunk_new("afs_request_keys",
		sizeof(struct afs_request_key),
		afs_packet_init_count * sizeof(struct afs_request_key),
		G_ALLOC_AND_FREE);
	afs_request_vals = g_mem_chunk_new("afs_request_vals",
		sizeof(struct afs_request_val),
		afs_packet_init_count * sizeof(struct afs_request_val),
		G_ALLOC_AND_FREE);
}



/*
 * Dissection routines
 */

void
dissect_afs(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *afs_tree, *afs_op_tree, *ti;
	struct rx_header *rxh;
	struct afs_header *afsh;
	int port, node, typenode, opcode;
	value_string const *vals;
	int reply = 0;
	int doffset = 0;
	conversation_t *conversation;
	struct afs_request_key request_key, *new_request_key;
	struct afs_request_val *request_val;
	void (*dissector)(const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree, int opcode);

	OLD_CHECK_DISPLAY_AS_DATA(proto_afs, pd, offset, fd, tree);

	/* get at least a full packet structure */
	if ( !BYTES_ARE_IN_FRAME(offset, sizeof(struct rx_header)) )
		return;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "AFS (RX)");

	rxh = (struct rx_header *) &pd[offset];
	doffset = offset + sizeof(struct rx_header);
	afsh = (struct afs_header *) &pd[doffset];

	reply = (rxh->flags & RX_CLIENT_INITIATED) == 0;
	port = ((reply == 0) ? pi.destport : pi.srcport );

	/*
	 * Find out what conversation this packet is part of.
	 * XXX - this should really be done by the transport-layer protocol,
	 * although for connectionless transports, we may not want to do that
	 * unless we know some higher-level protocol will want it - or we
	 * may want to do it, so you can say e.g. "show only the packets in
	 * this UDP 'connection'".
	 *
	 * Note that we don't have to worry about the direction this packet
	 * was going - the conversation code handles that for us, treating
	 * packets from A:X to B:Y as being part of the same conversation as
	 * packets from B:Y to A:X.
	 */
	conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
	    pi.srcport, pi.destport, 0);
	if (conversation == NULL) {
		/* It's not part of any conversation - create a new one. */
		conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
		    pi.srcport, pi.destport, NULL, 0);
	}

	request_key.conversation = conversation->index;	
	request_key.service = pntohs(&rxh->serviceId);
	request_key.callnumber = pntohl(&rxh->callNumber);

	request_val = (struct afs_request_val *) g_hash_table_lookup(
		afs_request_hash, &request_key);

	/* only allocate a new hash element when it's a request */
	opcode = 0;
	if ( !request_val && !reply)
	{
		new_request_key = g_mem_chunk_alloc(afs_request_keys);
		*new_request_key = request_key;

		request_val = g_mem_chunk_alloc(afs_request_vals);
		request_val -> opcode = pntohl(&afsh->opcode);

		g_hash_table_insert(afs_request_hash, new_request_key,
			request_val);
	}

	if ( request_val )
	{
		opcode = request_val->opcode;
	}

	

	node = 0;
	typenode = 0;
	vals = NULL;
	dissector = NULL;
	switch (port)
	{
		case AFS_PORT_FS:
			typenode = hf_afs_fs;
			node = hf_afs_fs_opcode;
			vals = fs_req;
			dissector = reply ? dissect_fs_reply : dissect_fs_request;
			break;
		case AFS_PORT_CB:
			typenode = hf_afs_cb;
			node = hf_afs_cb_opcode;
			vals = cb_req;
			dissector = reply ? dissect_cb_reply : dissect_cb_request;
			break;
		case AFS_PORT_PROT:
			typenode = hf_afs_prot;
			node = hf_afs_prot_opcode;
			vals = prot_req;
			dissector = reply ? dissect_prot_reply : dissect_prot_request;
			break;
		case AFS_PORT_VLDB:
			typenode = hf_afs_vldb;
			node = hf_afs_vldb_opcode;
			vals = vldb_req;
			dissector = reply ? dissect_vldb_reply : dissect_vldb_request;
			break;
		case AFS_PORT_KAUTH:
			typenode = hf_afs_kauth;
			node = hf_afs_kauth_opcode;
			vals = kauth_req;
			dissector = reply ? dissect_kauth_reply : dissect_kauth_request;
			break;
		case AFS_PORT_VOL:
			typenode = hf_afs_vol;
			node = hf_afs_vol_opcode;
			vals = vol_req;
			dissector = reply ? dissect_vol_reply : dissect_vol_request;
			break;
		case AFS_PORT_ERROR:
			typenode = hf_afs_error;
			node = hf_afs_error_opcode;
			/* dissector = reply ? dissect_error_reply : dissect_error_request; */
			break;
		case AFS_PORT_BOS:
			typenode = hf_afs_bos;
			node = hf_afs_bos_opcode;
			vals = bos_req;
			dissector = reply ? dissect_bos_reply : dissect_bos_request;
			break;
		case AFS_PORT_UPDATE:
			typenode = hf_afs_update;
			node = hf_afs_update_opcode;
			vals = update_req;
			/* dissector = reply ? dissect_update_reply : dissect_update_request; */
			break;
		case AFS_PORT_RMTSYS:
			typenode = hf_afs_rmtsys;
			node = hf_afs_rmtsys_opcode;
			vals = rmtsys_req;
			/* dissector = reply ? dissect_rmtsys_reply : dissect_rmtsys_request; */
			break;
		case AFS_PORT_BACKUP:
			typenode = hf_afs_backup;
			node = hf_afs_backup_opcode;
			vals = backup_req;
			dissector = reply ? dissect_backup_reply : dissect_backup_request;
			break;
	}
	if ( (opcode >= VOTE_LOW && opcode <= VOTE_HIGH) ||
		(opcode >= DISK_LOW && opcode <= DISK_HIGH) )
	{
		typenode = hf_afs_ubik;
		node = hf_afs_ubik_opcode;
		vals = ubik_req;
		dissector = reply ? dissect_ubik_reply : dissect_ubik_request;
	}

	if ( vals )
	{
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "%s %s: %s (%d)",
			val_to_str(port, port_types_short, "Unknown(%d)"),
			reply ? "Reply" : "Request",
			val_to_str(opcode, vals, "Unknown(%d)"), opcode);
	}
	else
	{
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "%s %s: Unknown(%d)",
			val_to_str(port, port_types_short, "Unknown(%d)"),
			reply ? "Reply" : "Request",
			opcode);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_afs, NullTVB, doffset, END_OF_FRAME, FALSE);
		afs_tree = proto_item_add_subtree(ti, ett_afs);

		if ( !BYTES_ARE_IN_FRAME(offset, sizeof(struct rx_header) +
			sizeof(struct afs_header)) )
		{
			proto_tree_add_text(afs_tree, NullTVB, doffset, END_OF_FRAME,
				"Service: %s %s (Truncated)",
				val_to_str(port, port_types, "Unknown(%d)"),
				reply ? "Reply" : "Request");
				return;
		}
		else
		{
			proto_tree_add_text(afs_tree, NullTVB, doffset, END_OF_FRAME,
				"Service: %s %s",
				val_to_str(port, port_types, "Unknown(%d)"),
				reply ? "Reply" : "Request");
		}

		/* until we do cache, can't handle replies */
		ti = NULL;
		if ( !reply && node != 0 )
		{
			ti = proto_tree_add_uint(afs_tree,
				node, NullTVB, doffset, 4, opcode);
		}
		else if ( reply && node != 0 )
		{
			/* the opcode isn't in this packet */
			ti = proto_tree_add_uint(afs_tree,
				node, NullTVB, doffset, 0, opcode);
		}
		else
		{
			ti = proto_tree_add_text(afs_tree, NullTVB,
				doffset, 0, "Operation: Unknown");
		}

		/* Add the subtree for this particular service */
		afs_op_tree = proto_item_add_subtree(ti, ett_afs_op);

		if ( typenode != 0 )
		{
			/* indicate the type of request */
			proto_tree_add_boolean_hidden(afs_tree, typenode, NullTVB, doffset, 0, 1);
		}

		/* Process the packet according to what service it is */
		if ( dissector )
		{
			(*dissector)(pd,offset,fd,afs_op_tree,opcode);
		}
	}

	/* if it's the last packet, and it's a reply, remove opcode
		from hash */
	/* ignoring for now, I'm not sure how the chunk deallocation works */
	if ( rxh->flags & RX_LAST_PACKET && reply )
	{

	}
}


/*
 * Here is a helper routine for adding an AFS acl to the proto tree
 * This is to be used with FS packets only
 *
 * An AFS ACL is a string that has the following format:
 *
 * <positive> <negative>
 * <uid1> <aclbits1>
 * ....
 *
 * "positive" and "negative" are integers which contain the number of
 * positive and negative ACL's in the string.  The uid/aclbits pair are
 * ASCII strings containing the UID/PTS record and and a ascii number
 * representing a logical OR of all the ACL permission bits
 */

static void dissect_acl(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	int pos, neg, acl;
	int n, i, bytes;
	u_char const *s;
	u_char const *end;
	char user[128];
	int curoffset;
	int soff,eoff;

	curoffset = offset;

	TRUNC(sizeof(guint32));
	bytes = pntohl(&pd[curoffset]);
	OUT_UINT(hf_afs_fs_acl_datasize);

	TRUNC(bytes);

	soff = curoffset;
	eoff = curoffset+bytes;

	s = &pd[soff];
	end = &pd[eoff];

	if (sscanf((char *) s, "%d %n", &pos, &n) != 1)
		return;
	s += n;
	TRUNC(1);
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_positive, NullTVB, curoffset, n, pos);
	curoffset += n;

	if (sscanf((char *) s, "%d %n", &neg, &n) != 1)
		return;
	s += n;
	TRUNC(1);
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_negative, NullTVB, curoffset, n, neg);
	curoffset += n;


	/*
	 * This wacky order preserves the order used by the "fs" command
	 */

	for (i = 0; i < pos; i++) {
		if (sscanf((char *) s, "%s %d %n", user, &acl, &n) != 2)
			return;
		s += n;
		ACLOUT(user,1,acl,n);
		curoffset += n;
		TRUNC(1);
	}

	for (i = 0; i < neg; i++) {
		if (sscanf((char *) s, "%s %d %n", user, &acl, &n) != 2)
			return;
		s += n;
		ACLOUT(user,0,acl,n);
		curoffset += n;
		if (s > end)
			return;
	}
}

/*
 * Here are the helper dissection routines
 */

static void
dissect_fs_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;
	int seq;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	seq = pntohl(&rxh->seq);

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 130: /* fetch data */
				if ( seq == 1 ) /* only on first packet */
				{
					OUT_FS_AFSFetchStatus("Status");
					OUT_FS_AFSCallBack();
					OUT_FS_AFSVolSync();
				}
				OUT_BYTES_ALL(hf_afs_fs_data);
				break;
			case 131: /* fetch acl */
				dissect_acl(pd,curoffset,fd,tree);
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
			case 132: /* Fetch status */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;	
			case 133: /* Store data */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
			case 134: /* Store ACL */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
	 		case 135: /* Store status */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();	
				break;
			case 136: /* Remove file */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
			case 137: /* create file */
				OUT_FS_AFSFid("New File");
				OUT_FS_AFSFetchStatus("File Status");
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;
			case 138: /* rename */
				OUT_FS_AFSFetchStatus("Old Directory Status");
				OUT_FS_AFSFetchStatus("New Directory Status");
				OUT_FS_AFSVolSync();
				break;
			case 139: /* symlink */
				OUT_FS_AFSFid("Symlink");
				OUT_FS_AFSFetchStatus("Symlink Status");
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSVolSync();
				break;
			case 140: /* link */
				OUT_FS_AFSFetchStatus("Symlink Status");
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSVolSync();
				break;	
			case 141: /* make dir */
				OUT_FS_AFSFid("New Directory");
				OUT_FS_AFSFetchStatus("File Status");
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;
			case 142: /* rmdir */
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSVolSync();
				break;
			case 143: /* old set lock */
				/* nothing returned */
				break;
			case 144: /* old extend lock */
				/* nothing returned */
				break;
			case 145: /* old release lock */
				/* nothing returned */
				break;
			case 146: /* get statistics */
				OUT_FS_ViceStatistics();
				break;
			case 147: /* give up callbacks */
				/* nothing returned */
				break;
			case 148: /* get volume info */
				OUT_FS_VolumeInfo();
				break;
			case 149: /* get volume status */
				OUT_FS_AFSFetchVolumeStatus();
				OUT_STRING(hf_afs_fs_volname);
				OUT_STRING(hf_afs_fs_offlinemsg);
				OUT_STRING(hf_afs_fs_motd);
				break;
			case 150: /* set volume status */
				/* nothing returned */
				break;
			case 151: /* root volume */
				OUT_STRING(hf_afs_fs_volname);
				break;
			case 152: /* check token */ 
				/* nothing returned */
				break;
			case 153: /* get time */
				OUT_TIMESTAMP(hf_afs_fs_timestamp);
				break;
			case 154: /* n-get-volume-info */
				OUT_FS_VolumeInfo();
				break;
			case 155: /* bulk status */
				OUT_FS_AFSBulkStats();
				OUT_FS_AFSCBs();
				OUT_FS_AFSVolSync();
				break;
			case 156: /* set lock */
				OUT_FS_AFSVolSync();
				break;
			case 157: /* extend lock */
				OUT_FS_AFSVolSync();
				break;
			case 158: /* release lock */
				OUT_FS_AFSVolSync();
				break;
			case 159: /* x-stats-version */
				OUT_UINT(hf_afs_fs_xstats_version);
				break;
			case 160: /* get xstats */
				OUT_UINT(hf_afs_fs_xstats_version);
				OUT_DATE(hf_afs_fs_xstats_timestamp);
				OUT_FS_AFS_CollData();
				break;
			case 161: /* lookup */
				OUT_FS_AFSFid("File");
				OUT_FS_AFSFetchStatus("File Status");
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;
			case 162: /* flush cps */
				OUT_UINT(hf_afs_fs_cps_spare2);
				OUT_UINT(hf_afs_fs_cps_spare3);
				break;
			case 163: /* dfs symlink */
				OUT_FS_AFSFid("File");
				OUT_FS_AFSFetchStatus("File Status");
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_fs_errcode);
	}
}

static void
dissect_fs_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
		case 130: /* Fetch data */
			OUT_FS_AFSFid("Source");
			OUT_UINT(hf_afs_fs_offset);
			OUT_UINT(hf_afs_fs_length);
			break;
		case 131: /* Fetch ACL */
			OUT_FS_AFSFid("Target");
			break;		
		case 132: /* Fetch Status */
			OUT_FS_AFSFid("Target");
			break;
		case 133: /* Store Data */
			OUT_FS_AFSFid("Destination");
			OUT_FS_AFSStoreStatus("Status");
			OUT_UINT(hf_afs_fs_offset);
			OUT_UINT(hf_afs_fs_length);
			OUT_UINT(hf_afs_fs_flength);
			break;
		case 134: /* Store ACL */
			OUT_FS_AFSFid("Target");
			dissect_acl(pd,curoffset,fd,tree);
			break;
		case 135: /* Store Status */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 136: /* Remove File */
			OUT_FS_AFSFid("Remove File");
			OUT_STRING(hf_afs_fs_name);
			break;
		case 137: /* Create File */
			OUT_FS_AFSFid("Target");
			OUT_STRING(hf_afs_fs_name);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 138: /* Rename file */
			OUT_FS_AFSFid("Old");
			OUT_STRING(hf_afs_fs_oldname);
			OUT_FS_AFSFid("New");
			OUT_STRING(hf_afs_fs_newname);
			break;
		case 139: /* Symlink */
			OUT_FS_AFSFid("File");
			OUT_STRING(hf_afs_fs_symlink_name);
			OUT_STRING(hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 140: /* Link */
			OUT_FS_AFSFid("Link To (New File)");
			OUT_STRING(hf_afs_fs_name);
			OUT_FS_AFSFid("Link From (Old File)");
			break;
		case 141: /* Make dir */
			OUT_FS_AFSFid("Target");
			OUT_STRING(hf_afs_fs_name);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 142: /* Remove dir */
			OUT_FS_AFSFid("Target");
			OUT_STRING(hf_afs_fs_name);
			break;
		case 143: /* Old Set Lock */
			OUT_FS_AFSFid("Target");
			OUT_UINT(hf_afs_fs_vicelocktype);
			OUT_FS_AFSVolSync();
			break;
		case 144: /* Old Extend Lock */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSVolSync();
			break;
		case 145: /* Old Release Lock */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSVolSync();
			break;
		case 146: /* Get statistics */
			/* no params */
			break;
		case 147: /* Give up callbacks */
			OUT_FS_AFSCBFids();
			OUT_FS_AFSCBs();
			break;
		case 148: /* Get vol info */
			OUT_STRING(hf_afs_fs_volname);
			break;
		case 149: /* Get vol stats */
			OUT_UINT(hf_afs_fs_volid);
			break;
		case 150: /* Set vol stats */
			OUT_UINT(hf_afs_fs_volid);
			OUT_FS_AFSStoreVolumeStatus();
			OUT_STRING(hf_afs_fs_volname);
			OUT_STRING(hf_afs_fs_offlinemsg);
			OUT_STRING(hf_afs_fs_motd);
			break;
		case 151: /* get root volume */
			/* no params */
			break;
		case 152: /* check token */
			OUT_UINT(hf_afs_fs_viceid);
			OUT_FS_AFSTOKEN();
			break;
		case 153: /* get time */
			/* no params */
			break;
		case 154: /* new get vol info */
			OUT_STRING(hf_afs_fs_volname);
			break;
		case 155: /* bulk stat */
			OUT_FS_AFSCBFids();
			break;
		case 156: /* Set Lock */
			OUT_FS_AFSFid("Target");
			OUT_UINT(hf_afs_fs_vicelocktype);
			break;
		case 157: /* Extend Lock */
			OUT_FS_AFSFid("Target");
			break;
		case 158: /* Release Lock */
			OUT_FS_AFSFid("Target");
			break;
		case 159: /* xstats version */
			/* no params */
			break;
		case 160: /* get xstats */
			OUT_UINT(hf_afs_fs_xstats_clientversion);
			OUT_UINT(hf_afs_fs_xstats_collnumber);
			break;
		case 161: /* lookup */
			OUT_FS_AFSFid("Target");
			OUT_STRING(hf_afs_fs_name);
			break;
		case 162: /* flush cps */
			OUT_FS_ViceIds();
			OUT_FS_IPAddrs();
			OUT_UINT(hf_afs_fs_cps_spare1);
			break;
		case 163: /* dfs symlink */
			OUT_FS_AFSFid("Target");
			OUT_STRING(hf_afs_fs_symlink_name);
			OUT_STRING(hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus("Symlink Status");
			break;
	}
}

/*
 * BOS Helpers
 */
static void
dissect_bos_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 80: /* create bnode */
				/* no output */
				break;
			case 81: /* delete bnode */
				/* no output */
				break;
			case 82: /* set status */
				/* no output */
				break;
			case 83: /* get status */
				OUT_INT(hf_afs_bos_status);
				OUT_STRING(hf_afs_bos_statusdesc);
				break;
			case 84: /* enumerate instance */
				OUT_STRING(hf_afs_bos_instance);
				break;
			case 85: /* get instance info */
				OUT_STRING(hf_afs_bos_type);
				OUT_BOS_STATUS();
				break;
			case 86: /* get instance parm */
				OUT_STRING(hf_afs_bos_parm);
				break;
			case 87: /* add siperuser */
				/* no output */
				break;
			case 88: /* delete superuser */
				/* no output */
				break;
			case 89: /* list superusers */
				OUT_STRING(hf_afs_bos_user);
				break;
			case 90: /* list keys */
				OUT_UINT(hf_afs_bos_kvno);
				OUT_BOS_KEY();
				OUT_BOS_KEYINFO();
				break;
			case 91: /* add key */
				/* no output */
				break;
			case 92: /* delete key */
				/* no output */
				break;
			case 93: /* set cell name */
				/* no output */
				break;
			case 94: /* get cell name */
				OUT_STRING(hf_afs_bos_cell);
				break;
			case 95: /* get cell host */
				OUT_STRING(hf_afs_bos_host);
				break;
			case 96: /* add cell host */
				/* no output */
				break;
			case 97: /* delete cell host */
				/* no output */
				break;
			case 98: /* set tstatus */
				/* no output */
				break;
			case 99: /* shutdown all */
				/* no output */
				break;
			case 100: /* restart all */
				/* no output */
				break;
			case 101: /* startup all */
				/* no output */
				break;
			case 102: /* set noauth flag */
				/* no output */
				break;
			case 103: /* rebozo */
				/* no output */
				break;
			case 104: /* restart */
				/* no output */
				break;
			case 105: /* install */
				/* no output */
				break;
			case 106: /* uninstall */
				/* no output */
				break;
			case 107: /* get dates */
				OUT_DATE(hf_afs_bos_newtime);
				OUT_DATE(hf_afs_bos_baktime);
				OUT_DATE(hf_afs_bos_oldtime);
				break;
			case 108: /* exec */
				/* no output */
				break;
			case 109: /* prune */
				/* no output */
				break;
			case 110: /* set restart time */
				/* no output */
				break;
			case 111: /* get restart time */
				OUT_BOS_TIME();
				break;
			case 112: /* get log */
				/* need to make this dump a big string somehow */
				OUT_BYTES_ALL(hf_afs_bos_data);
				break;
			case 113: /* wait all */
				/* no output */
				break;
			case 114: /* get instance strings */
				OUT_STRING(hf_afs_bos_error);
				OUT_STRING(hf_afs_bos_spare1);
				OUT_STRING(hf_afs_bos_spare2);
				OUT_STRING(hf_afs_bos_spare3);
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_bos_errcode);
	}
}

static void
dissect_bos_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();
	
	switch ( opcode )
	{
		case 80: /* create b node */
			OUT_STRING(hf_afs_bos_type);
			OUT_STRING(hf_afs_bos_instance);
			OUT_STRING(hf_afs_bos_parm);
			OUT_STRING(hf_afs_bos_parm);
			OUT_STRING(hf_afs_bos_parm);
			OUT_STRING(hf_afs_bos_parm);
			OUT_STRING(hf_afs_bos_parm);
			OUT_STRING(hf_afs_bos_parm);
			break;
		case 81: /* delete b node */
			OUT_STRING(hf_afs_bos_instance);
			break;
		case 82: /* set status */
			OUT_STRING(hf_afs_bos_instance);
			OUT_UINT(hf_afs_bos_status);
			break;
		case 83: /* get status */
			OUT_STRING(hf_afs_bos_instance);
			break;
		case 84: /* enumerate instance */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 85: /* get instance info */
			OUT_STRING(hf_afs_bos_instance);
			break;
		case 86: /* get instance parm */
			OUT_STRING(hf_afs_bos_instance);
			OUT_UINT(hf_afs_bos_num);
			break;
		case 87: /* add super user */
			OUT_STRING(hf_afs_bos_user);
			break;
		case 88: /* delete super user */
			OUT_STRING(hf_afs_bos_user);
			break;
		case 89: /* list super users */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 90: /* list keys */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 91: /* add key */
			OUT_UINT(hf_afs_bos_num);
			OUT_BOS_KEY();
			break;
		case 92: /* delete key */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 93: /* set cell name */
			OUT_STRING(hf_afs_bos_content);
			break;
		case 95: /* set cell host */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 96: /* add cell host */
			OUT_STRING(hf_afs_bos_content);
			break;
		case 97: /* delete cell host */
			OUT_STRING(hf_afs_bos_content);
			break;
		case 98: /* set t status */
			OUT_STRING(hf_afs_bos_content);
			OUT_UINT(hf_afs_bos_status);
			break;
		case 99: /* shutdown all */
			/* no params */
			break;
		case 100: /* restart all */
			/* no params */
			break;
		case 101: /* startup all */
			/* no params */
			break;
		case 102: /* set no-auth flag */
			OUT_UINT(hf_afs_bos_flags);
			break;
		case 103: /* re-bozo? */
			/* no params */
			break;
		case 104: /* restart */
			OUT_STRING(hf_afs_bos_instance);
			break;
		case 105: /* install */
			OUT_STRING(hf_afs_bos_path);
			OUT_UINT(hf_afs_bos_size);
			OUT_UINT(hf_afs_bos_flags);
			OUT_UINT(hf_afs_bos_date);
			break;
		case 106: /* uninstall */
			OUT_STRING(hf_afs_bos_path);
			break;
		case 107: /* get dates */
			OUT_STRING(hf_afs_bos_path);
			break;
		case 108: /* exec */
			OUT_STRING(hf_afs_bos_cmd);
			break;
		case 109: /* prune */
			OUT_UINT(hf_afs_bos_flags);
			break;
		case 110: /* set restart time */
			OUT_UINT(hf_afs_bos_num);
			OUT_BOS_TIME();
			break;
		case 111: /* get restart time */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 112: /* get log */
			OUT_STRING(hf_afs_bos_file);
			break;
		case 113: /* wait all */
			/* no params */
			break;
		case 114: /* get instance strings */
			OUT_STRING(hf_afs_bos_content);
			break;
	}
}

/*
 * VOL Helpers
 */
static void
dissect_vol_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 121:
				/* should loop here maybe */
				OUT_UINT(hf_afs_vol_count);
				VECOUT(hf_afs_vol_name, 32); /* not sure on  */
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_vol_errcode);
	}
}

static void
dissect_vol_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
		case 121: /* list one vol */
			OUT_UINT(hf_afs_vol_count);
			OUT_UINT(hf_afs_vol_id);
			break;
	}
}

/*
 * KAUTH Helpers
 */
static void
dissect_kauth_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_kauth_errcode);
	}
}

static void
dissect_kauth_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
		case 1: /* authenticate old */
		case 21: /* authenticate */
		case 22: /* authenticate v2 */
		case 2: /* change pw */
		case 5: /* set fields */
		case 6: /* create user */
		case 7: /* delete user */
		case 8: /* get entry */
		case 14: /* unlock */
		case 15: /* lock status */
			OUT_STRING(hf_afs_kauth_princ);
			OUT_STRING(hf_afs_kauth_realm);
			OUT_BYTES_ALL(hf_afs_kauth_data);
			break;
		case 3: /* getticket-old */
		case 23: /* getticket */
			OUT_UINT(hf_afs_kauth_kvno);
			OUT_STRING(hf_afs_kauth_domain);
			OUT_STRING(hf_afs_kauth_data);
			OUT_STRING(hf_afs_kauth_princ);
			OUT_STRING(hf_afs_kauth_realm);
			break;
		case 4: /* set pass */
			OUT_STRING(hf_afs_kauth_princ);
			OUT_STRING(hf_afs_kauth_realm);
			OUT_UINT(hf_afs_kauth_kvno);
			break;
		case 12: /* get pass */
			OUT_STRING(hf_afs_kauth_name);
			break;
	}
}

/*
 * CB Helpers
 */
static void
dissect_cb_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_cb_errcode);
	}
}

static void
dissect_cb_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
		case 204: /* callback */
		{
			unsigned int i,j;

			TRUNC(4);
			j = GETINT();

			for (i=0; i<j; i++)
			{
				OUT_CB_AFSFid("Target");
			}

			TRUNC(4);
			j = GETINT();
			for (i=0; i<j; i++)
			{
				OUT_CB_AFSCallBack();
			}
		}
	}
}

/*
 * PROT Helpers
 */
static void
dissect_prot_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 504: /* name to id */
				{
					unsigned int i, j;

					TRUNC(4);
					j = GETINT();
					OUT_UINT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						OUT_UINT(hf_afs_prot_id);
					}
				}
				break;
			case 505: /* id to name */
				{
					unsigned int i, j;

					TRUNC(4);
					j = GETINT();
					OUT_UINT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						VECOUT(hf_afs_prot_name, PRNAMEMAX);
					}
				}
				break;
			case 508: /* get cps */
			case 514: /* list elements */
			case 517: /* list owned */
			case 518: /* get cps2 */
			case 519: /* get host cps */
				{
					unsigned int i, j;

					TRUNC(4);
					j = GETINT();
					OUT_UINT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						OUT_UINT(hf_afs_prot_id);
					}
				}
				break;
			case 510: /* list max */
				OUT_UINT(hf_afs_prot_maxuid);
				OUT_UINT(hf_afs_prot_maxgid);
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_prot_errcode);
	}
}

static void
dissect_prot_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
		case 500: /* new user */
			OUT_STRING(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_id);
			OUT_UINT(hf_afs_prot_oldid);
			break;
		case 501: /* where is it */
		case 506: /* delete */
		case 508: /* get cps */
		case 512: /* list entry */
		case 514: /* list elements */
		case 517: /* list owned */
		case 519: /* get host cps */
			OUT_UINT(hf_afs_prot_id);
			break;
		case 502: /* dump entry */
			OUT_UINT(hf_afs_prot_pos);
			break;
		case 503: /* add to group */
		case 507: /* remove from group */
		case 515: /* is a member of? */
			OUT_UINT(hf_afs_prot_uid);
			OUT_UINT(hf_afs_prot_gid);
			break;
		case 504: /* name to id */
			{
				unsigned int i, j;

				TRUNC(4);
				j = GETINT();
				OUT_UINT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					VECOUT(hf_afs_prot_name,PRNAMEMAX);
				}
			}
			break;
		case 505: /* id to name */
			{
				unsigned int i, j;

				TRUNC(4);
				j = GETINT();
				OUT_UINT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					OUT_UINT(hf_afs_prot_id);
				}
			}
			break;
		case 509: /* new entry */
			OUT_STRING(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_flag);
			OUT_UINT(hf_afs_prot_oldid);
			break;
		case 511: /* set max */
			OUT_UINT(hf_afs_prot_id);
			OUT_UINT(hf_afs_prot_flag);
			break;
		case 513: /* change entry */
			OUT_UINT(hf_afs_prot_id);
			OUT_STRING(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_oldid);
			OUT_UINT(hf_afs_prot_newid);
			break;
		case 520: /* update entry */
			OUT_UINT(hf_afs_prot_id);
			OUT_STRING(hf_afs_prot_name);
			break;
	}
}

/*
 * VLDB Helpers
 */
static void
dissect_vldb_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 510: /* list entry */
				OUT_UINT(hf_afs_vldb_count);
				OUT_UINT(hf_afs_vldb_nextindex);
				break;
			case 503: /* get entry by id */
			case 504: /* get entry by name */
				{
					int nservers,i,j;
					VECOUT(hf_afs_vldb_name, VLNAMEMAX);
					TRUNC(4);
					nservers = GETINT();
					OUT_UINT(hf_afs_vldb_numservers);
					for (i=0; i<8; i++)
					{
						if ( i<nservers )
						{
							OUT_IP(hf_afs_vldb_server);
						}
						else
						{
							SKIP(4);
						}
					}
					for (i=0; i<8; i++)
					{
						char part[8];
						TRUNC(4);
						j = GETINT();
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, NullTVB,
								curoffset, 4, part);
						}
						SKIP(4);
					}
					SKIP(8 * sizeof(guint32));
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
				}
				break;
			case 505: /* get new volume id */
				OUT_UINT(hf_afs_vldb_id);
				break;
			case 521: /* list entry */
			case 529: /* list entry U */
				OUT_UINT(hf_afs_vldb_count);
				OUT_UINT(hf_afs_vldb_nextindex);
				break;
			case 518: /* get entry by id n */
			case 519: /* get entry by name N */
				{
					int nservers,i,j;
					VECOUT(hf_afs_vldb_name, VLNAMEMAX);
					TRUNC(4);
					nservers = GETINT();
					OUT_UINT(hf_afs_vldb_numservers);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_IP(hf_afs_vldb_server);
						}
						else
						{
							SKIP(4);
						}
					}
					for (i=0; i<13; i++)
					{
						char part[8];
						TRUNC(4);
						j = GETINT();
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, NullTVB,
								curoffset, 4, part);
						}
						SKIP(4);
					}
					SKIP(13 * sizeof(guint32));
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
				}
				break;
			case 526: /* get entry by id u */
			case 527: /* get entry by name u */
				{
					int nservers,i,j;
					VECOUT(hf_afs_vldb_name, VLNAMEMAX);
					TRUNC(4);
					nservers = GETINT();
					OUT_UINT(hf_afs_vldb_numservers);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_BYTES(hf_afs_vldb_serveruuid, 11*sizeof(guint32));
						}
						else
						{
							SKIP(11*sizeof(guint32));
						}
					}
					for (i=0; i<13; i++)
					{
						char part[8];
						TRUNC(4);
						j = GETINT();
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, NullTVB,
								curoffset, 4, part);
						}
						SKIP(4);
					}
					SKIP(13 * sizeof(guint32));
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
				}
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_vldb_errcode);
	}
}

static void
dissect_vldb_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
		case 501: /* create new volume */
		case 517: /* create entry N */
			VECOUT(hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 502: /* delete entry */
		case 503: /* get entry by id */
		case 507: /* update entry */
		case 508: /* set lock */
		case 509: /* release lock */
		case 518: /* get entry by id */
			OUT_UINT(hf_afs_vldb_id);
			OUT_UINT(hf_afs_vldb_type);
			break;
		case 504: /* get entry by name */
		case 519: /* get entry by name N */
		case 524: /* update entry by name */
		case 527: /* get entry by name U */
			OUT_STRING(hf_afs_vldb_name);
			break;
		case 505: /* get new vol id */
			OUT_UINT(hf_afs_vldb_bump);
			break;
		case 506: /* replace entry */
		case 520: /* replace entry N */
			OUT_UINT(hf_afs_vldb_id);
			OUT_UINT(hf_afs_vldb_type);
			VECOUT(hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 510: /* list entry */
		case 521: /* list entry N */
			OUT_UINT(hf_afs_vldb_index);
			break;
	}
}

/*
 * UBIK Helpers
 */
static void
dissect_ubik_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 10000: /* beacon */
				proto_tree_add_boolean(tree,hf_afs_ubik_votetype, NullTVB,0,0,0);
				break;
			case 20004: /* get version */
				OUT_UBIKVERSION("DB Version");
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		switch ( opcode )
		{
			case 10000:
				proto_tree_add_boolean(tree,hf_afs_ubik_votetype, NullTVB,0,0,1);
				OUT_DATE(hf_afs_ubik_voteend);
				break;
			default:
				OUT_UINT(hf_afs_ubik_errcode);
				break;
		}
	}
}

static void
dissect_ubik_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
		case 10000: /* beacon */
			OUT_UINT(hf_afs_ubik_syncsite);
			OUT_DATE(hf_afs_ubik_votestart);
			OUT_UBIKVERSION("DB Version");
			OUT_UBIKVERSION("TID");
			break;
		case 10003: /* get sync site */
			OUT_IP(hf_afs_ubik_site);
			break;
		case 20000: /* begin */
		case 20001: /* commit */
		case 20007: /* abort */
		case 20008: /* release locks */
		case 20010: /* writev */
			OUT_UBIKVERSION("TID");
			break;
		case 20002: /* lock */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_pos);
			OUT_UINT(hf_afs_ubik_length);
			OUT_UINT(hf_afs_ubik_locktype);
			break;
		case 20003: /* write */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_pos);
			break;
		case 20005: /* get file */
			OUT_UINT(hf_afs_ubik_file);
			break;
		case 20006: /* send file */
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_length);
			OUT_UBIKVERSION("DB Version");
			break;
		case 20009: /* truncate */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_length);
			break;
		case 20012: /* set version */
			OUT_UBIKVERSION("TID");
			OUT_UBIKVERSION("Old DB Version");
			OUT_UBIKVERSION("New DB Version");
			break;
	}
}

/*
 * BACKUP Helpers
 */
static void
dissect_backup_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_backup_errcode);
	}
}

static void
dissect_backup_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	SKIP_OPCODE();

	switch ( opcode )
	{
	}
}

/*
 * Registration code for registering the protocol and fields
 */

void
proto_register_afs(void)
{
	static hf_register_info hf[] = {
#include "packet-afs-register-info.h"
	};
	static gint *ett[] = {
		&ett_afs,
		&ett_afs_op,
		&ett_afs_acl,
		&ett_afs_fid,
		&ett_afs_callback,
		&ett_afs_ubikver,
		&ett_afs_status,
		&ett_afs_status_mask,
		&ett_afs_volsync,
		&ett_afs_volumeinfo,
		&ett_afs_vicestat,
	};

	proto_afs = proto_register_protocol("Andrew File System (AFS)", "afs");
	proto_register_field_array(proto_afs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&afs_init_protocol);
}
