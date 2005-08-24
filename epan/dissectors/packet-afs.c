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
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>

#include "packet-rx.h"
#include "packet-afs.h"
#include "packet-afs-defs.h"
#include "packet-afs-macros.h"

#define GETSTR ((const char *)tvb_get_ptr(tvb,offset,tvb_ensure_length_remaining(tvb,offset)))

#define VALID_OPCODE(opcode) ((opcode >= OPCODE_LOW && opcode <= OPCODE_HIGH) || \
		(opcode >= VOTE_LOW && opcode <= VOTE_HIGH) || \
		(opcode >= DISK_LOW && opcode <= DISK_HIGH))

struct afs_request_key {
  guint32 conversation, callnumber;
  guint16 service;
};

struct afs_request_val {
  guint32 opcode;
  guint req_num;
  guint rep_num;
  nstime_t req_time;
};

static GHashTable *afs_request_hash = NULL;


/*
 * Dissector prototypes
 */
static int dissect_acl(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset);
static void dissect_fs_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_fs_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_bos_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_bos_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vol_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vol_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_kauth_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_kauth_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_cb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_cb_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_prot_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_prot_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vldb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vldb_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_ubik_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_ubik_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_backup_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_backup_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);

/*
 * Hash Functions
 */
static gint
afs_equal(gconstpointer v, gconstpointer w)
{
  const struct afs_request_key *v1 = (const struct afs_request_key *)v;
  const struct afs_request_key *v2 = (const struct afs_request_key *)w;

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
	const struct afs_request_key *key = (const struct afs_request_key *)v;
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

	afs_request_hash = g_hash_table_new(afs_hash, afs_equal);
}



/*
 * Dissection routines
 */

static void
dissect_afs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct rxinfo *rxinfo = pinfo->private_data;
	int reply = 0;
	conversation_t *conversation;
	struct afs_request_key request_key, *new_request_key;
	struct afs_request_val *request_val=NULL;
	proto_tree      *afs_tree, *afs_op_tree, *ti;
	int port, node, typenode, opcode;
	value_string const *vals;
	int offset = 0;
	nstime_t delta_ts;

	void (*dissector)(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode);


	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AFS (RX)");
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
	}

	reply = (rxinfo->flags & RX_CLIENT_INITIATED) == 0;
	port = ((reply == 0) ? pinfo->destport : pinfo->srcport );

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
	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
	    pinfo->srcport, pinfo->destport, 0);
	if (conversation == NULL) {
		/* It's not part of any conversation - create a new one. */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}

	request_key.conversation = conversation->index;
	request_key.service = rxinfo->serviceid;
	request_key.callnumber = rxinfo->callnumber;

	request_val = (struct afs_request_val *) g_hash_table_lookup(
		afs_request_hash, &request_key);

	/* only allocate a new hash element when it's a request */
	opcode = 0;
	if(!pinfo->fd->flags.visited){
		if ( !request_val && !reply) {
			new_request_key = se_alloc(sizeof(struct afs_request_key));
			*new_request_key = request_key;

			request_val = se_alloc(sizeof(struct afs_request_val));
			request_val -> opcode = tvb_get_ntohl(tvb, offset);
			request_val -> req_num = pinfo->fd->num;
			request_val -> rep_num = 0;
			request_val -> req_time = pinfo->fd->abs_ts;

			g_hash_table_insert(afs_request_hash, new_request_key,
				request_val);
		}
		if( request_val && reply ) {
			request_val -> rep_num = pinfo->fd->num;
		}
	}

	if ( request_val ) {
		opcode = request_val->opcode;
	}


	node = 0;
	typenode = 0;
	vals = NULL;
	dissector = NULL;
	switch (port) {
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
		(opcode >= DISK_LOW && opcode <= DISK_HIGH) ) {
		typenode = hf_afs_ubik;
		node = hf_afs_ubik_opcode;
		vals = ubik_req;
		dissector = reply ? dissect_ubik_reply : dissect_ubik_request;
	}


	if ( VALID_OPCODE(opcode) ) {
		if ( vals ) {
			if (check_col(pinfo->cinfo, COL_INFO))
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s %s: %s (%d)",
				typenode == hf_afs_ubik ? "UBIK-" : "",
				val_to_str(port, port_types_short, "Unknown(%d)"),
				reply ? "Reply" : "Request",
				val_to_str(opcode, vals, "Unknown(%d)"), opcode);
		} else {
			if (check_col(pinfo->cinfo, COL_INFO))
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s %s: Unknown(%d)",
				typenode == hf_afs_ubik ? "UBIK-" : "",
				val_to_str(port, port_types_short, "Unknown(%d)"),
				reply ? "Reply" : "Request",
				opcode);
		}
	} else {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "Encrypted %s %s",
			val_to_str(port, port_types_short, "Unknown(%d)"),
			reply ? "Reply" : "Request"
			);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_afs, tvb, offset, -1,
				FALSE);
		afs_tree = proto_item_add_subtree(ti, ett_afs);

		proto_tree_add_text(afs_tree, tvb, 0, 0,
			"Service: %s%s%s %s",
			VALID_OPCODE(opcode) ? "" : "Encrypted ",
			typenode == hf_afs_ubik ? "UBIK - " : "",
			val_to_str(port, port_types, "Unknown(%d)"),
			reply ? "Reply" : "Request");

		if( request_val && !reply && request_val->rep_num) {
			proto_tree_add_uint_format(afs_tree, hf_afs_repframe,
			    tvb, 0, 0, request_val->rep_num,
			    "The reply to this request is in frame %u",
			    request_val->rep_num);
		}
		if( request_val && reply && request_val->rep_num) {
			proto_tree_add_uint_format(afs_tree, hf_afs_reqframe,
			    tvb, 0, 0, request_val->req_num,
			    "This is a reply to a request in frame %u",
			    request_val->req_num);
			nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &request_val->req_time);
			proto_tree_add_time(afs_tree, hf_afs_time, tvb, offset, 0,
				&delta_ts);
		}


		if ( VALID_OPCODE(opcode) ) {
			/* until we do cache, can't handle replies */
			ti = NULL;
			if ( !reply && node != 0 ) {
				if ( rxinfo->seq == 1 )
				{
					ti = proto_tree_add_uint(afs_tree,
						node, tvb, offset, 4, opcode);
				} else {
					ti = proto_tree_add_uint(afs_tree,
						node, tvb, 0, 0, opcode);
				}
			} else if ( reply && node != 0 ) {
				/* the opcode isn't in this packet */
				ti = proto_tree_add_uint(afs_tree,
					node, tvb, 0, 0, opcode);
			} else {
				ti = proto_tree_add_text(afs_tree, tvb,
					0, 0, "Operation: Unknown");
			}

			/* Add the subtree for this particular service */
			afs_op_tree = proto_item_add_subtree(ti, ett_afs_op);

			
			if ( typenode != 0 ) {
				/* indicate the type of request */
				proto_tree_add_boolean_hidden(afs_tree, typenode, tvb, offset, 0, 1);
			}

			/* Process the packet according to what service it is */
			if ( dissector ) {
				(*dissector)(tvb, rxinfo, afs_op_tree, offset, opcode);
			}
		}
	}

	/* if it's the last packet, and it's a reply, remove opcode
		from hash */
	/* ignoring for now, I'm not sure how the chunk deallocation works */
	if ( rxinfo->flags & RX_LAST_PACKET && reply ){

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
/*
 * XXX - FIXME:
 *
 *	sscanf is probably quite dangerous if we run outside the packet.
 *
 *	"GETSTR" doesn't guarantee that the resulting string is
 *	null-terminated.
 *
 * Should this just scan the string itself, rather than using "sscanf()"?
 */
static int
dissect_acl(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset)
{
	int old_offset;
	gint32 bytes;
	int i, n, pos, neg, acl;
	char user[128]; /* Be sure to adjust sscanf()s below if length is changed... */

	old_offset = offset;
	bytes = tvb_get_ntohl(tvb, offset);
	OUT_UINT(hf_afs_fs_acl_datasize);


	if (sscanf(GETSTR, "%d %n", &pos, &n) != 1) {
		/* does not matter what we return, if this fails,
		 * we cant dissect anything else in the packet either.
		 */
		return offset;
	}
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_positive, tvb,
		offset, n, pos);
	offset += n;


	if (sscanf(GETSTR, "%d %n", &neg, &n) != 1) {
		return offset;
	}
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_negative, tvb,
		offset, n, neg);
	offset += n;

	/*
	 * This wacky order preserves the order used by the "fs" command
	 */
	for (i = 0; i < pos; i++) {
		if (sscanf(GETSTR, "%127s %d %n", user, &acl, &n) != 2) {
			return offset;
		}
		ACLOUT(user,1,acl,n);
		offset += n;
	}
	for (i = 0; i < neg; i++) {
		if (sscanf(GETSTR, "%127s %d %n", user, &acl, &n) != 2) {
			return offset;
		}
		ACLOUT(user,0,acl,n);
		offset += n;
		if (offset >= old_offset+bytes ) {
			return offset;
		}
	}

	return offset;
}

/*
 * Here are the helper dissection routines
 */

static void
dissect_fs_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 130: /* fetch data */
				/* only on first packet */
				if ( rxinfo->seq == 1 )
				{
					OUT_FS_AFSFetchStatus("Status");
					OUT_FS_AFSCallBack();
					OUT_FS_AFSVolSync();
				}
				OUT_BYTES_ALL(hf_afs_fs_data);
				break;
			case 131: /* fetch acl */
				offset = dissect_acl(tvb, rxinfo, tree, offset);
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
			case 132: /* Fetch status */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;
			case 133: /* Store data */
			case 134: /* Store ACL */
	 		case 135: /* Store status */
			case 136: /* Remove file */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
			case 137: /* create file */
			case 141: /* make dir */
			case 161: /* lookup */
			case 163: /* dfs symlink */
				OUT_FS_AFSFid((opcode == 137)? "New File" : ((opcode == 141)? "New Directory" : "File"));
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
			case 140: /* link */
				OUT_FS_AFSFetchStatus("Symlink Status");
			case 142: /* rmdir */
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSVolSync();
				break;
			case 143: /* old set lock */
			case 144: /* old extend lock */
			case 145: /* old release lock */
			case 147: /* give up callbacks */
			case 150: /* set volume status */
			case 152: /* check token */
				/* nothing returned */
				break;
			case 146: /* get statistics */
				OUT_FS_ViceStatistics();
				break;
			case 148: /* get volume info */
			case 154: /* n-get-volume-info */
				OUT_FS_VolumeInfo();
				break;
			case 149: /* get volume status */
				OUT_FS_AFSFetchVolumeStatus();
				OUT_RXString(hf_afs_fs_volname);
				OUT_RXString(hf_afs_fs_offlinemsg);
				OUT_RXString(hf_afs_fs_motd);
				break;
			case 151: /* root volume */
				OUT_RXString(hf_afs_fs_volname);
				break;
			case 153: /* get time */
				OUT_TIMESTAMP(hf_afs_fs_timestamp);
				break;
			case 155: /* bulk status */
				OUT_FS_AFSBulkStats();
				SKIP(4);
				OUT_FS_AFSCBs();
				OUT_FS_AFSVolSync();
				break;
			case 156: /* set lock */
			case 157: /* extend lock */
			case 158: /* release lock */
				OUT_FS_AFSVolSync();
				break;
			case 159: /* x-stats-version */
				OUT_UINT(hf_afs_fs_xstats_version);
				break;
			case 160: /* get xstats */
				OUT_UINT(hf_afs_fs_xstats_version);
				OUT_TIMESECS(hf_afs_fs_xstats_timestamp);
				OUT_FS_AFS_CollData();
				break;
			case 162: /* flush cps */
				OUT_UINT(hf_afs_fs_cps_spare2);
				OUT_UINT(hf_afs_fs_cps_spare3);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_fs_errcode);
	}
}

static void
dissect_fs_request(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	/* skip the opcode if this is the first packet in the stream */
	if ( rxinfo->seq == 1 )
	{
		offset += 4;  /* skip the opcode */
	}

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
			if ( rxinfo->seq == 1 )
			{
				OUT_FS_AFSFid("Destination");
				OUT_FS_AFSStoreStatus("Status");
				OUT_UINT(hf_afs_fs_offset);
				OUT_UINT(hf_afs_fs_length);
				OUT_UINT(hf_afs_fs_flength);
			}
			OUT_BYTES_ALL(hf_afs_fs_data);
			break;
		case 134: /* Store ACL */
			OUT_FS_AFSFid("Target");
			offset = dissect_acl(tvb, rxinfo, tree, offset);
			break;
		case 135: /* Store Status */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 136: /* Remove File */
			OUT_FS_AFSFid("Remove File");
			OUT_RXString(hf_afs_fs_name);
			break;
		case 137: /* Create File */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_name);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 138: /* Rename file */
			OUT_FS_AFSFid("Old");
			OUT_RXString(hf_afs_fs_oldname);
			OUT_FS_AFSFid("New");
			OUT_RXString(hf_afs_fs_newname);
			break;
		case 139: /* Symlink */
			OUT_FS_AFSFid("File");
			OUT_RXString(hf_afs_fs_symlink_name);
			OUT_RXString(hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 140: /* Link */
			OUT_FS_AFSFid("Link To (New File)");
			OUT_RXString(hf_afs_fs_name);
			OUT_FS_AFSFid("Link From (Old File)");
			break;
		case 141: /* Make dir */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_name);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 142: /* Remove dir */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_name);
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
			OUT_RXString(hf_afs_fs_volname);
			break;
		case 149: /* Get vol stats */
			OUT_UINT(hf_afs_fs_volid);
			break;
		case 150: /* Set vol stats */
			OUT_UINT(hf_afs_fs_volid);
			OUT_FS_AFSStoreVolumeStatus();
			OUT_RXString(hf_afs_fs_volname);
			OUT_RXString(hf_afs_fs_offlinemsg);
			OUT_RXString(hf_afs_fs_motd);
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
			OUT_RXString(hf_afs_fs_volname);
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
			OUT_RXString(hf_afs_fs_name);
			break;
		case 162: /* flush cps */
			OUT_FS_ViceIds();
			OUT_FS_IPAddrs();
			OUT_UINT(hf_afs_fs_cps_spare1);
			break;
		case 163: /* dfs symlink */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_symlink_name);
			OUT_RXString(hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus("Symlink Status");
			break;
		case 220: /* residencycmd */
			OUT_FS_AFSFid("Target");
			/* need residency inputs here */
			break;
		case 65536: /* inline bulk status */
			OUT_FS_AFSCBFids();
			break;
		case 65537: /* fetch-data-64 */
			OUT_FS_AFSFid("Target");
			OUT_INT64(hf_afs_fs_offset64);
			OUT_INT64(hf_afs_fs_length64);
			/* need more here */
			break;
		case 65538: /* store-data-64 */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSStoreStatus("Status");
			OUT_INT64(hf_afs_fs_offset64);
			OUT_INT64(hf_afs_fs_length64);
			OUT_INT64(hf_afs_fs_flength64);
			/* need residency inputs here */
			break;
		case 65539: /* give up all cbs */
			break;
		case 65540: /* get capabilities */
			break;
	}
}

/*
 * BOS Helpers
 */
static void
dissect_bos_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
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
				OUT_RXString(hf_afs_bos_statusdesc);
				break;
			case 84: /* enumerate instance */
				OUT_RXString(hf_afs_bos_instance);
				break;
			case 85: /* get instance info */
				OUT_RXString(hf_afs_bos_type);
				OUT_BOS_STATUS();
				break;
			case 86: /* get instance parm */
				OUT_RXString(hf_afs_bos_parm);
				break;
			case 87: /* add siperuser */
				/* no output */
				break;
			case 88: /* delete superuser */
				/* no output */
				break;
			case 89: /* list superusers */
				OUT_RXString(hf_afs_bos_user);
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
				OUT_RXString(hf_afs_bos_cell);
				break;
			case 95: /* get cell host */
				OUT_RXString(hf_afs_bos_host);
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
				OUT_TIMESECS(hf_afs_bos_newtime);
				OUT_TIMESECS(hf_afs_bos_baktime);
				OUT_TIMESECS(hf_afs_bos_oldtime);
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
				OUT_RXString(hf_afs_bos_error);
				OUT_RXString(hf_afs_bos_spare1);
				OUT_RXString(hf_afs_bos_spare2);
				OUT_RXString(hf_afs_bos_spare3);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_bos_errcode);
	}
}

static void
dissect_bos_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 80: /* create b node */
			OUT_RXString(hf_afs_bos_type);
			OUT_RXString(hf_afs_bos_instance);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			break;
		case 81: /* delete b node */
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 82: /* set status */
			OUT_RXString(hf_afs_bos_instance);
			OUT_INT(hf_afs_bos_status);
			break;
		case 83: /* get status */
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 84: /* enumerate instance */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 85: /* get instance info */
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 86: /* get instance parm */
			OUT_RXString(hf_afs_bos_instance);
			OUT_UINT(hf_afs_bos_num);
			break;
		case 87: /* add super user */
			OUT_RXString(hf_afs_bos_user);
			break;
		case 88: /* delete super user */
			OUT_RXString(hf_afs_bos_user);
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
			OUT_RXString(hf_afs_bos_content);
			break;
		case 95: /* set cell host */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 96: /* add cell host */
			OUT_RXString(hf_afs_bos_content);
			break;
		case 97: /* delete cell host */
			OUT_RXString(hf_afs_bos_content);
			break;
		case 98: /* set t status */
			OUT_RXString(hf_afs_bos_content);
			OUT_INT(hf_afs_bos_status);
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
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 105: /* install */
			OUT_RXString(hf_afs_bos_path);
			OUT_UINT(hf_afs_bos_size);
			OUT_UINT(hf_afs_bos_flags);
			OUT_UINT(hf_afs_bos_date);
			break;
		case 106: /* uninstall */
			OUT_RXString(hf_afs_bos_path);
			break;
		case 107: /* get dates */
			OUT_RXString(hf_afs_bos_path);
			break;
		case 108: /* exec */
			OUT_RXString(hf_afs_bos_cmd);
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
			OUT_RXString(hf_afs_bos_file);
			break;
		case 113: /* wait all */
			/* no params */
			break;
		case 114: /* get instance strings */
			OUT_RXString(hf_afs_bos_content);
			break;
	}
}

/*
 * VOL Helpers
 */
static void
dissect_vol_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 121:
				/* should loop here maybe */
				OUT_UINT(hf_afs_vol_count);
				OUT_RXStringV(hf_afs_vol_name, 32); /* not sure on  */
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_vol_errcode);
	}
}

static void
dissect_vol_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

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
dissect_kauth_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_kauth_errcode);
	}
}

static void
dissect_kauth_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

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
			OUT_RXString(hf_afs_kauth_princ);
			OUT_RXString(hf_afs_kauth_realm);
			OUT_BYTES_ALL(hf_afs_kauth_data);
			break;
		case 3: /* getticket-old */
		case 23: /* getticket */
			OUT_KAUTH_GetTicket();
			break;
		case 4: /* set pass */
			OUT_RXString(hf_afs_kauth_princ);
			OUT_RXString(hf_afs_kauth_realm);
			OUT_UINT(hf_afs_kauth_kvno);
			break;
		case 12: /* get pass */
			OUT_RXString(hf_afs_kauth_name);
			break;
	}
}

/*
 * CB Helpers
 */
static void
dissect_cb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_cb_errcode);
	}
}

static void
dissect_cb_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 204: /* callback */
		{
			unsigned int i,j;

			j = tvb_get_ntohl(tvb, offset);
			offset += 4;

			for (i=0; i<j; i++)
			{
				OUT_CB_AFSFid("Target");
			}

			j = tvb_get_ntohl(tvb, offset);
			offset += 4;
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
dissect_prot_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 504: /* name to id */
				{
					unsigned int i, j;

					j = tvb_get_ntohl(tvb, offset);
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

					j = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						OUT_RXStringV(hf_afs_prot_name, PRNAMEMAX);
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

					j = tvb_get_ntohl(tvb, offset);
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
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_prot_errcode);
	}
}

static void
dissect_prot_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 500: /* new user */
			OUT_RXString(hf_afs_prot_name);
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

				j = tvb_get_ntohl(tvb, offset);
				OUT_UINT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					OUT_RXStringV(hf_afs_prot_name,PRNAMEMAX);
				}
			}
			break;
		case 505: /* id to name */
			{
				unsigned int i, j;

				j = tvb_get_ntohl(tvb, offset);
				OUT_UINT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					OUT_UINT(hf_afs_prot_id);
				}
			}
			break;
		case 509: /* new entry */
			OUT_RXString(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_flag);
			OUT_UINT(hf_afs_prot_oldid);
			break;
		case 511: /* set max */
			OUT_UINT(hf_afs_prot_id);
			OUT_UINT(hf_afs_prot_flag);
			break;
		case 513: /* change entry */
			OUT_UINT(hf_afs_prot_id);
			OUT_RXString(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_oldid);
			OUT_UINT(hf_afs_prot_newid);
			break;
		case 520: /* update entry */
			OUT_UINT(hf_afs_prot_id);
			OUT_RXString(hf_afs_prot_name);
			break;
	}
}

/*
 * VLDB Helpers
 */
static void
dissect_vldb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
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
					OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
					SKIP(4);
					nservers = tvb_get_ntohl(tvb, offset);
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
						j = tvb_get_ntohl(tvb, offset);
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, tvb,
								offset, 4, part);
						}
						SKIP(4);
					}
					SKIP(8 * sizeof(guint32));
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
					OUT_UINT(hf_afs_vldb_clonevol);
					OUT_VLDB_Flags();
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
					OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
					nservers = tvb_get_ntohl(tvb, offset);
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
						j = tvb_get_ntohl(tvb, offset);
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, tvb,
								offset, 4, part);
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
					OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
					nservers = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_vldb_numservers);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_UUID(hf_afs_vldb_serveruuid);
						}
						else
						{
							SKIP_UUID();
						}
					}
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_UINT(hf_afs_vldb_serveruniq);
						}
						else
						{
							SKIP(sizeof(guint32));
						}
					}
					for (i=0; i<13; i++)
					{
						char part[8];
						j = tvb_get_ntohl(tvb, offset);
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, tvb,
								offset, 4, part);
						}
						SKIP(4);
					}
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_UINT(hf_afs_vldb_serverflags);
						}
						else
						{
							SKIP(sizeof(guint32));
						}
					}
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
					OUT_UINT(hf_afs_vldb_clonevol);
					OUT_UINT(hf_afs_vldb_flags);
					OUT_UINT(hf_afs_vldb_spare1);
					OUT_UINT(hf_afs_vldb_spare2);
					OUT_UINT(hf_afs_vldb_spare3);
					OUT_UINT(hf_afs_vldb_spare4);
					OUT_UINT(hf_afs_vldb_spare5);
					OUT_UINT(hf_afs_vldb_spare6);
					OUT_UINT(hf_afs_vldb_spare7);
					OUT_UINT(hf_afs_vldb_spare8);
					OUT_UINT(hf_afs_vldb_spare9);
				}
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_vldb_errcode);
	}
}

static void
dissect_vldb_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 501: /* create new volume */
		case 517: /* create entry N */
			OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
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
			OUT_RXString(hf_afs_vldb_name);
			break;
		case 505: /* get new vol id */
			OUT_UINT(hf_afs_vldb_bump);
			break;
		case 506: /* replace entry */
		case 520: /* replace entry N */
			OUT_UINT(hf_afs_vldb_id);
			OUT_UINT(hf_afs_vldb_type);
			OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 510: /* list entry */
		case 521: /* list entry N */
			OUT_UINT(hf_afs_vldb_index);
			break;
		case 532: /* regaddr */
			OUT_UUID(hf_afs_vldb_serveruuid);
			OUT_UINT(hf_afs_vldb_spare1);
			OUT_VLDB_BulkAddr();
			break;
	}
}

/*
 * UBIK Helpers
 */
static void
dissect_ubik_reply(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	switch ( opcode )
	{
		case 10000: /* vote-beacon */
			break;
		case 10001: /* vote-debug-old */
			OUT_UBIK_DebugOld();
			break;
		case 10002: /* vote-sdebug-old */
			OUT_UBIK_SDebugOld();
			break;
		case 10003: /* vote-get syncsite */
			break;
		case 10004: /* vote-debug */
			OUT_UBIK_DebugOld();
			OUT_UBIK_InterfaceAddrs();
			break;
		case 10005: /* vote-sdebug */
			OUT_UBIK_SDebugOld();
			OUT_UBIK_InterfaceAddrs();
			break;
		case 10006: /* vote-xdebug */
			OUT_UBIK_DebugOld();
			OUT_UBIK_InterfaceAddrs();
			OUT_UINT(hf_afs_ubik_isclone);
			break;
		case 10007: /* vote-xsdebug */
			OUT_UBIK_SDebugOld();
			OUT_UBIK_InterfaceAddrs();
			OUT_UINT(hf_afs_ubik_isclone);
			break;
		case 20000: /* disk-begin */
			break;
		case 20004: /* get version */
			OUT_UBIKVERSION("DB Version");
			break;
		case 20010: /* disk-probe */
			break;
		case 20012: /* disk-interfaceaddr */
			OUT_UBIK_InterfaceAddrs();
			break;
	}
}

static void
dissect_ubik_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 10000: /* vote-beacon */
			OUT_UINT(hf_afs_ubik_state);
			OUT_TIMESECS(hf_afs_ubik_votestart);
			OUT_UBIKVERSION("DB Version");
			OUT_UBIKVERSION("TID");
			break;
		case 10001: /* vote-debug-old */
			break;
		case 10002: /* vote-sdebug-old */
			OUT_UINT(hf_afs_ubik_site);
			break;
		case 10003: /* vote-get sync site */
			OUT_IP(hf_afs_ubik_site);
			break;
		case 10004: /* vote-debug */
		case 10005: /* vote-sdebug */
			OUT_IP(hf_afs_ubik_site);
			break;
		case 20000: /* disk-begin */
			OUT_UBIKVERSION("TID");
			break;
		case 20001: /* disk-commit */
			OUT_UBIKVERSION("TID");
			break;
		case 20002: /* disk-lock */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_pos);
			OUT_UINT(hf_afs_ubik_length);
			OUT_UINT(hf_afs_ubik_locktype);
			break;
		case 20003: /* disk-write */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_pos);
			break;
		case 20004: /* disk-get version */
			break;
		case 20005: /* disk-get file */
			OUT_UINT(hf_afs_ubik_file);
			break;
		case 20006: /* disk-send file */
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_length);
			OUT_UBIKVERSION("DB Version");
			break;
		case 20007: /* disk-abort */
		case 20008: /* disk-release locks */
		case 20010: /* disk-probe */
			break;
		case 20009: /* disk-truncate */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_length);
			break;
		case 20011: /* disk-writev */
			OUT_UBIKVERSION("TID");
			break;
		case 20012: /* disk-interfaceaddr */
			OUT_UBIK_InterfaceAddrs();
			break;
		case 20013: /* disk-set version */
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
dissect_backup_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_backup_errcode);
	}
}

static void
dissect_backup_request(tvbuff_t *tvb _U_, struct rxinfo *rxinfo _U_, proto_tree *tree _U_, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

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
		&ett_afs_vldb_flags,
	};

	proto_afs = proto_register_protocol("Andrew File System (AFS)",
	    "AFS (RX)", "afs");
	proto_register_field_array(proto_afs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&afs_init_protocol);

	register_dissector("afs", dissect_afs, proto_afs);
}
