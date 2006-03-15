/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified to allow NCP over TCP/IP decodes by James Coe <jammer@cin.net>
 * Modified to decode server op-lock, packet signature,
 * & NDS packets by Greg Morris <gmorris@novell.com>
 *
 * Portions Copyright (c) by Gilbert Ramirez 2000-2002
 * Portions Copyright (c) by James Coe 2000-2002
 * Portions Copyright (c) Novell, Inc. 2000-2003
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2000 Gerald Combs
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include "packet-ipx.h"
#include "packet-tcp.h"
#include "packet-ncp-int.h"
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/tap.h>

int proto_ncp = -1;
static int hf_ncp_ip_ver = -1;
static int hf_ncp_ip_length = -1;
static int hf_ncp_ip_rplybufsize = -1;
static int hf_ncp_ip_sig = -1;
static int hf_ncp_ip_packetsig = -1;
static int hf_ncp_type = -1;
static int hf_ncp_seq = -1;
static int hf_ncp_connection = -1;
static int hf_ncp_task = -1;
static int hf_ncp_stream_type = -1;
static int hf_ncp_system_flags = -1;
static int hf_ncp_system_flags_abt = -1;
static int hf_ncp_system_flags_eob = -1;
static int hf_ncp_system_flags_sys = -1;
static int hf_ncp_system_flags_bsy = -1;
static int hf_ncp_system_flags_lst = -1;
static int hf_ncp_src_connection = -1;
static int hf_ncp_dst_connection = -1;
static int hf_ncp_packet_seqno = -1;
static int hf_ncp_delay_time = -1;
static int hf_ncp_burst_seqno = -1;
static int hf_ncp_ack_seqno = -1;
static int hf_ncp_burst_len = -1;
static int hf_ncp_burst_offset = -1;
static int hf_ncp_data_offset = -1;
static int hf_ncp_data_bytes = -1;
static int hf_ncp_missing_fraglist_count = -1;
static int hf_ncp_missing_data_offset = -1;
static int hf_ncp_missing_data_count = -1;
static int hf_ncp_oplock_flag = -1;
static int hf_ncp_oplock_handle = -1;
static int hf_ncp_completion_code = -1;
static int hf_ncp_connection_status = -1;
static int hf_ncp_slot = -1;
static int hf_ncp_control_code = -1;
static int hf_ncp_fragment_handle = -1;
static int hf_lip_echo = -1;
static int hf_ncp_burst_command = -1;
static int hf_ncp_burst_file_handle = -1;
static int hf_ncp_burst_reserved = -1;

gint ett_ncp = -1;
gint ett_nds = -1;
gint ett_nds_segments = -1;
gint ett_nds_segment = -1;
static gint ett_ncp_system_flags = -1;

static struct novell_tap ncp_tap;
struct ncp_common_header	header;
struct ncp_common_header    *ncp_hdr;

/* Tables for reassembly of fragments. */ 
GHashTable *nds_fragment_table = NULL;
GHashTable *nds_reassembled_table = NULL;
dissector_handle_t nds_data_handle;

/* desegmentation of NCP over TCP */
static gboolean ncp_desegment = TRUE;

static dissector_handle_t data_handle;

static proto_item *expert_item = NULL;

#define TCP_PORT_NCP		524
#define UDP_PORT_NCP		524

#define NCP_RQST_HDR_LENGTH	7
#define NCP_RPLY_HDR_LENGTH	8

/* These are the header structures to handle NCP over IP */
#define	NCPIP_RQST	0x446d6454	/* "DmdT" */
#define NCPIP_RPLY	0x744e6350	/* "tNcP" */

struct ncp_ip_header {
	guint32	signature;
	guint32 length;
};

/* This header only appears on NCP over IP request packets */
struct ncp_ip_rqhdr {
	guint32 version;
	guint32 rplybufsize;
};

static const value_string ncp_ip_signature[] = {
	{ NCPIP_RQST, "Demand Transport (Request)" },
	{ NCPIP_RPLY, "Transport is NCP (Reply)" },
	{ 0, NULL },
};

static const value_string burst_command[] = {
	{ 0x01000000, "Burst Read" },
	{ 0x02000000, "Burst Write" },
	{ 0, NULL },
};

/* The information in this module comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke

  And:
	Programmer's Guide to the NetWare Core Protocol
	Steve Conner & Diane Conner
	(c) 1996 by Steve Conner & Diane Conner
	Published by Annabooks, San Diego, California
        ISBN: 0-929392-31-0
        
 And:
    http:developer.novell.com
    NCP documentation        

*/

static value_string ncp_type_vals[] = {
	{ NCP_ALLOCATE_SLOT,	"Create a service connection" },
	{ NCP_SERVICE_REQUEST,	"Service request" },
	{ NCP_SERVICE_REPLY,	"Service reply" },
	{ NCP_WATCHDOG,		"Watchdog" },
	{ NCP_DEALLOCATE_SLOT,	"Destroy service connection" },
	{ NCP_BROADCAST_SLOT,   "Server Broadcast" },
	{ NCP_BURST_MODE_XFER,	"Burst mode transfer" },
	{ NCP_POSITIVE_ACK,	"Request being processed" },
	{ NCP_LIP_ECHO,		"Large Internet Packet Echo" },
	{ 0,			NULL }
};

static value_string ncp_oplock_vals[] = {
    { 0x21, "Message Waiting" },
    { 0x24, "Clear Op-lock" },
    { 0, NULL }
};

/* Conversation Struct so we can detect NCP server sessions */

typedef struct {
	conversation_t	*conversation;
    guint32         nwconnection;
    guint8          nwtask;
} mncp_rhash_key;

/* Store the packet number for the start of the NCP session.
 * Note sessions are defined as
 * NCP Connection + NCP Task == Unique NCP server session
 * It is normal for multiple sessions per connection to exist
 * These are normally different applications running on multi-tasking
 * Operating Systems.
 */
typedef struct {
        guint32  session_start_packet_num;
} mncp_rhash_value;

static GHashTable *mncp_rhash = NULL;

/* Hash Functions */
static gint
mncp_equal(gconstpointer v, gconstpointer v2)
{
	const mncp_rhash_key	*val1 = (const mncp_rhash_key*)v;
	const mncp_rhash_key	*val2 = (const mncp_rhash_key*)v2;

	if (val1->conversation == val2->conversation && val1->nwconnection == val2->nwconnection && val1->nwtask == val2->nwtask) {
		return 1;
	}
	return 0;
}

static guint
mncp_hash(gconstpointer v)
{
	const mncp_rhash_key	*mncp_key = (const mncp_rhash_key*)v;
	return GPOINTER_TO_UINT(mncp_key->conversation)+mncp_key->nwconnection+mncp_key->nwtask;
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in ethereal */
static void
mncp_init_protocol(void)
{
	if (mncp_rhash)
		g_hash_table_destroy(mncp_rhash);

	mncp_rhash = g_hash_table_new(mncp_hash, mncp_equal);
}

/* After the sequential run, we don't need the ncp_request hash and keys
 * anymore; the lookups have already been done and the vital info
 * saved in the reply-packets' private_data in the frame_data struct. */
static void
mncp_postseq_cleanup(void)
{
}

static mncp_rhash_value*
mncp_hash_insert(conversation_t *conversation, guint32 nwconnection, guint8 nwtask, packet_info *pinfo)
{
	mncp_rhash_key		*key;
	mncp_rhash_value	*value;

	/* Now remember the request, so we can find it if we later
	   a reply to it. Track by conversation, connection, and task number.
       in NetWare these values determine each unique session */
	key = se_alloc(sizeof(mncp_rhash_key));
	key->conversation = conversation;
    key->nwconnection = nwconnection;
    key->nwtask = nwtask;

	value = se_alloc(sizeof(mncp_rhash_value));
       
	g_hash_table_insert(mncp_rhash, key, value);
    
    if (ncp_echo_conn && nwconnection != 65535) {
        expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Detected New Server Session. Connection %d, Task %d", nwconnection, nwtask);
        value->session_start_packet_num = pinfo->fd->num;
    }

	return value;
}

/* Returns the ncp_rec*, or NULL if not found. */
static mncp_rhash_value*
mncp_hash_lookup(conversation_t *conversation, guint32 nwconnection, guint8 nwtask)
{
	mncp_rhash_key		key;

	key.conversation = conversation;
    key.nwconnection = nwconnection;
    key.nwtask = nwtask;

	return g_hash_table_lookup(mncp_rhash, &key);
}

/*
 * Burst packet system flags.
 */
#define ABT	0x04		/* Abort request */
#define BSY 0x08        /* Server Busy */
#define EOB	0x10		/* End of burst */
#define LST 0x40        /* Include Fragment List */
#define SYS	0x80		/* System packet */

static void
dissect_ncp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean is_tcp)
{
	proto_tree			*ncp_tree = NULL;
	proto_item			*ti;
	struct ncp_ip_header		ncpiph;
	struct ncp_ip_rqhdr		ncpiphrq;
	guint16				ncp_burst_seqno, ncp_ack_seqno;
	guint16				flags = 0;
	proto_tree			*flags_tree = NULL;
	int				hdr_offset = 0;
	int				commhdr = 0;
	int				offset = 0;
	gint				length_remaining;
	tvbuff_t       			*next_tvb;
	guint32				testvar = 0, ncp_burst_command, burst_len, burst_off, burst_file;
	guint8				subfunction;
	guint32				nw_connection = 0, data_offset;
	guint16				data_len = 0;
	guint16				missing_fraglist_count = 0;
	mncp_rhash_value		*request_value = NULL;
	conversation_t			*conversation;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	hdr_offset = 0;
	ncp_hdr = &header;
    commhdr = hdr_offset;

    ti = proto_tree_add_item(tree, proto_ncp, tvb, 0, -1, FALSE);
    ncp_tree = proto_item_add_subtree(ti, ett_ncp);
    if (is_tcp) {
        if (tvb_get_ntohl(tvb, hdr_offset) != NCPIP_RQST && tvb_get_ntohl(tvb, hdr_offset) != NCPIP_RPLY) 
            commhdr += 1;
        /* Get NCPIP Header data */
        ncpiph.signature	= tvb_get_ntohl(tvb, commhdr);
        proto_tree_add_uint(ncp_tree, hf_ncp_ip_sig, tvb, commhdr, 4, ncpiph.signature);
        ncpiph.length		= (0x7fffffff & tvb_get_ntohl(tvb, commhdr+4));
        proto_tree_add_uint(ncp_tree, hf_ncp_ip_length, tvb, commhdr+4, 4, ncpiph.length);
        commhdr += 8;
        if (ncpiph.signature == NCPIP_RQST) {
            ncpiphrq.version	= tvb_get_ntohl(tvb, commhdr);
            proto_tree_add_uint(ncp_tree, hf_ncp_ip_ver, tvb, commhdr, 4, ncpiphrq.version);
            commhdr += 4;
            ncpiphrq.rplybufsize	= tvb_get_ntohl(tvb, commhdr);
            proto_tree_add_uint(ncp_tree, hf_ncp_ip_rplybufsize, tvb, commhdr, 4, ncpiphrq.rplybufsize);
            commhdr += 4;
        }
        /* Check to see if this is a valid offset, otherwise increment for packet signature */
        if (match_strval(tvb_get_ntohs(tvb, commhdr), ncp_type_vals)==NULL) {
            proto_tree_add_item(ncp_tree, hf_ncp_ip_packetsig, tvb, commhdr, 8, FALSE);
            commhdr += 8;
        }
    }
    header.type		    = tvb_get_ntohs(tvb, commhdr);
    header.sequence		= tvb_get_guint8(tvb, commhdr+2);
    header.conn_low		= tvb_get_guint8(tvb, commhdr+3);
    header.task         = tvb_get_guint8(tvb, commhdr+4);
    header.conn_high	= tvb_get_guint8(tvb, commhdr+5);
    proto_tree_add_uint(ncp_tree, hf_ncp_type,	tvb, commhdr, 2, header.type);
    nw_connection = (header.conn_high*256)+header.conn_low;
    
    /* Ok, we need to track the conversation so that we can
     * determine if a new server session is occuring for this
     * connection.
     */
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
        PT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->destport,
        0);
    if ((ncpiph.length & 0x80000000) || ncpiph.signature == NCPIP_RPLY) {
        /* First time through we will record the initial connection and task
         * values
         */
        if (!pinfo->fd->flags.visited) {
            if (conversation != NULL) {
                /* find the record telling us the
                 * request made that caused this
                 * reply
                 */
                request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
                /* if for some reason we have no
                 * conversation in our hash, create
                 * one */
                if (request_value == NULL) {
                    request_value = mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
                }
            } else {
                /* It's not part of any conversation
                 * - create a new one.
                 */
                conversation = conversation_new(pinfo->fd->num, &pinfo->src,
                    &pinfo->dst, PT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->destport, 0);
                request_value = mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
            }
            /* If this is a request packet then we 
             * might have a new task
             */
            if (ncpiph.signature == NCPIP_RPLY) {
                /* Now on reply packets we have to
                 * use the state of the original
                 * request packet, so look up the
                 * request value and check the task number
                 */
                request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
            }
        } else {
            /* Get request value data */
            request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
            if (request_value) {
                if ((request_value->session_start_packet_num == pinfo->fd->num) && ncp_echo_conn)
                {
                    expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Detected New Server Session. Connection %d, Task %d", nw_connection, header.task);
                }
            }
        }
    } else {
        if (!pinfo->fd->flags.visited) {
            if (conversation != NULL) {
                /* find the record telling us the
                 * request made that caused this
                 * reply
                 */
                request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
                /* if for some reason we have no
                 * conversation in our hash, create
                 * one */
                if (request_value == NULL) {
                    request_value = mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
                }
            } else {
                /* It's not part of any conversation
                 * - create a new one.
                 */
                conversation = conversation_new(pinfo->fd->num, &pinfo->src,
                    &pinfo->dst, PT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->destport, 0);
                request_value = mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
            }
            /* find the record telling us the request
             * made that caused this reply
             */
        } else {
            request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
            if (request_value) {
                if ((request_value->session_start_packet_num == pinfo->fd->num) && ncp_echo_conn)
                {
                    expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Detected New Server Session. Connection %d, Task %d", nw_connection, header.task);
                }
            }
        }
	}

	tap_queue_packet(ncp_tap.hdr, pinfo, ncp_hdr);

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_add_fstr(pinfo->cinfo, COL_INFO,
		    "%s",
		    val_to_str(header.type, ncp_type_vals, "Unknown type (0x%04x)"));
	}

	/*
	 * Process the packet-type-specific header.
	 */
	switch (header.type) {

	case NCP_BROADCAST_SLOT:    /* Server Broadcast */
		proto_tree_add_uint(ncp_tree, hf_ncp_seq,	tvb, commhdr + 2, 1, header.sequence);
		proto_tree_add_uint(ncp_tree, hf_ncp_connection,tvb, commhdr + 3, 3, nw_connection);
		proto_tree_add_item(ncp_tree, hf_ncp_task,	tvb, commhdr + 4, 1, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_oplock_flag, tvb, commhdr + 9, 1, tvb_get_guint8(tvb, commhdr+9));
		proto_tree_add_item(ncp_tree, hf_ncp_oplock_handle, tvb, commhdr + 10, 4, FALSE);
        if ((tvb_get_guint8(tvb, commhdr+9)==0x24) && ncp_echo_file)
        {
            expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Server requesting station to clear oplock on handle - %08x", tvb_get_ntohl(tvb, commhdr+10));
        }
		break;

	case NCP_LIP_ECHO:    /* Lip Echo Packet */
		proto_tree_add_item(ncp_tree, hf_lip_echo, tvb, commhdr, 13, FALSE);
		break;

	case NCP_BURST_MODE_XFER:	/* Packet Burst Packet */
		/*
		 * XXX - we should keep track of whether there's a burst
		 * outstanding on a connection and, if not, treat the
		 * beginning of the data as a burst header.
		 *
		 * The burst header contains:
		 *
		 *	4 bytes of little-endian function number:
		 *	    1 = read, 2 = write;
		 *
		 *	4 bytes of file handle;
		 *
		 *	8 reserved bytes;
		 *
		 *	4 bytes of big-endian file offset;
		 *
		 *	4 bytes of big-endian byte count.
		 *
		 * The data follows for a burst write operation.
		 *
		 * The first packet of a burst read reply contains:
		 *
		 *	4 bytes of little-endian result code:
		 *	   0: No error
		 *	   1: Initial error
		 *	   2: I/O error
		 *	   3: No data read;
		 *
		 *	4 bytes of returned byte count (big-endian?).
		 *
		 * The data follows.
		 *
		 * Each burst of a write request is responded to with a
		 * burst packet with a 2-byte little-endian result code:
		 *
		 *	0: Write successful
		 *	4: Write error
		 */
		flags = tvb_get_guint8(tvb, commhdr + 2);

		ti = proto_tree_add_uint(ncp_tree, hf_ncp_system_flags,
		    tvb, commhdr + 2, 1, flags);
		flags_tree = proto_item_add_subtree(ti, ett_ncp_system_flags);

		proto_tree_add_item(flags_tree, hf_ncp_system_flags_abt,
		    tvb, commhdr + 2, 1, FALSE);
		if (flags & ABT) {
			proto_item_append_text(ti, "  ABT");
		}
		flags&=(~( ABT ));

		proto_tree_add_item(flags_tree, hf_ncp_system_flags_bsy,
		    tvb, commhdr + 2, 1, FALSE);
		if (flags & BSY) {
			proto_item_append_text(ti, "  BSY");
		}
		flags&=(~( BSY ));

		proto_tree_add_item(flags_tree, hf_ncp_system_flags_eob,
		    tvb, commhdr + 2, 1, FALSE);
		if (flags & EOB) {
			proto_item_append_text(ti, "  EOB");
		}
		flags&=(~( EOB ));

		proto_tree_add_item(flags_tree, hf_ncp_system_flags_lst,
		    tvb, commhdr + 2, 1, FALSE);
		if (flags & LST) {
			proto_item_append_text(ti, "  LST");
		}
		flags&=(~( LST ));

		proto_tree_add_item(flags_tree, hf_ncp_system_flags_sys,
		    tvb, commhdr + 2, 1, FALSE);
		if (flags & SYS) {
			proto_item_append_text(ti, "  SYS");
		}
		flags&=(~( SYS ));


		proto_tree_add_item(ncp_tree, hf_ncp_stream_type,
		    tvb, commhdr + 3, 1, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_src_connection,
		    tvb, commhdr + 4, 4, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_dst_connection,
		    tvb, commhdr + 8, 4, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_packet_seqno,
		    tvb, commhdr + 12, 4, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_delay_time,
		    tvb, commhdr + 16, 4, FALSE);
		ncp_burst_seqno = tvb_get_ntohs(tvb, commhdr+20);
		proto_tree_add_item(ncp_tree, hf_ncp_burst_seqno,
		    tvb, commhdr + 20, 2, FALSE);
		ncp_ack_seqno = tvb_get_ntohs(tvb, commhdr+22);
		proto_tree_add_item(ncp_tree, hf_ncp_ack_seqno,
		    tvb, commhdr + 22, 2, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_burst_len,
		    tvb, commhdr + 24, 4, FALSE);
		data_offset = tvb_get_ntohl(tvb, commhdr + 28);
		proto_tree_add_uint(ncp_tree, hf_ncp_data_offset,
		    tvb, commhdr + 28, 4, data_offset);
		data_len = tvb_get_ntohs(tvb, commhdr + 32);
		proto_tree_add_uint(ncp_tree, hf_ncp_data_bytes,
		    tvb, commhdr + 32, 2, data_len);
		missing_fraglist_count = tvb_get_ntohs(tvb, commhdr + 34);
		proto_tree_add_item(ncp_tree, hf_ncp_missing_fraglist_count,
		    tvb, commhdr + 34, 2, FALSE);
		offset = commhdr + 36;
		if (!(flags & SYS) && ncp_burst_seqno == ncp_ack_seqno &&
		    data_offset == 0) {
			/*
			 * This is either a Burst Read or Burst Write
			 * command.  The data length includes the burst
			 * mode header, plus any data in the command
			 * (there shouldn't be any in a read, but there
			 * might be some in a write).
			 */
			if (data_len < 4)
				return;
			ncp_burst_command = tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(ncp_tree, hf_ncp_burst_command,
			    tvb, offset, 4, FALSE);
			offset += 4;
			data_len -= 4;

			if (data_len < 4)
				return;
			burst_file = tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(ncp_tree, hf_ncp_burst_file_handle,
			    tvb, offset, 4, FALSE);
			offset += 4;
			data_len -= 4;

			if (data_len < 8)
				return;
			proto_tree_add_item(ncp_tree, hf_ncp_burst_reserved,
			    tvb, offset, 8, FALSE);
			offset += 8;
			data_len -= 8;

			if (data_len < 4)
				return;
			burst_off = tvb_get_ntohl(tvb, offset);
			proto_tree_add_uint(ncp_tree, hf_ncp_burst_offset,
			    tvb, offset, 4, burst_off);
			offset += 4;
			data_len -= 4;

			if (data_len < 4)
				return;
			burst_len = tvb_get_ntohl(tvb, offset);
			proto_tree_add_uint(ncp_tree, hf_ncp_burst_len,
			    tvb, offset, 4, burst_len);
			offset += 4;
			data_len -= 4;

			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_fstr(pinfo->cinfo, COL_INFO,
				    "%s %d bytes starting at offset %d in file 0x%08x",
				    val_to_str(ncp_burst_command,
				      burst_command, "Unknown (0x%08x)"),
				     burst_len, burst_off, burst_file);
			}
			break;
		} else {
			if (tvb_get_guint8(tvb, commhdr + 2) & 0x10) {
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_set_str(pinfo->cinfo, COL_INFO,
					    "End of Burst");
				}
			}
		}
		break;

	case NCP_ALLOCATE_SLOT:		/* Allocate Slot Request */
		length_remaining = tvb_length_remaining(tvb, commhdr + 4);
		if (length_remaining > 4) { 
			testvar = tvb_get_ntohl(tvb, commhdr+4);
			if (testvar == 0x4c495020) {
				proto_tree_add_item(ncp_tree, hf_lip_echo, tvb, commhdr+4, 13, FALSE);
				break;
			}
		}
		/* otherwise fall through */
    
	case NCP_POSITIVE_ACK:		/* Positive Acknowledgement */
	case NCP_SERVICE_REQUEST:	/* Server NCP Request */
	case NCP_SERVICE_REPLY:		/* Server NCP Reply */
	case NCP_WATCHDOG:		/* Watchdog Packet */
	case NCP_DEALLOCATE_SLOT:	/* Deallocate Slot Request */
	default:
		proto_tree_add_uint(ncp_tree, hf_ncp_seq,	tvb, commhdr + 2, 1, header.sequence);
		proto_tree_add_uint(ncp_tree, hf_ncp_connection,tvb, commhdr + 3, 3, nw_connection);
		proto_tree_add_item(ncp_tree, hf_ncp_task,	tvb, commhdr + 4, 1, FALSE);
		break;
	}

	/*
	 * Process the packet body.
	 */
	switch (header.type) {

	case NCP_ALLOCATE_SLOT:		/* Allocate Slot Request */
		length_remaining = tvb_length_remaining(tvb, commhdr + 4);
		if (length_remaining > 4) {
			testvar = tvb_get_ntohl(tvb, commhdr+4);
			if (testvar == 0x4c495020) {
				proto_tree_add_text(ncp_tree, tvb, commhdr, -1,
				    "Lip Echo Packet");
				/*break;*/
			}
		}
		next_tvb = tvb_new_subset(tvb, commhdr, -1, -1);
		dissect_ncp_request(next_tvb, pinfo, nw_connection,
		    header.sequence, header.type, ncp_tree);
		break;

	case NCP_DEALLOCATE_SLOT:	/* Deallocate Slot Request */
		next_tvb = tvb_new_subset(tvb, commhdr, -1, -1);
		dissect_ncp_request(next_tvb, pinfo, nw_connection,
		    header.sequence, header.type, ncp_tree);
		break;

	case NCP_SERVICE_REQUEST:	/* Server NCP Request */
	case NCP_BROADCAST_SLOT:	/* Server Broadcast Packet */
		next_tvb = tvb_new_subset(tvb, commhdr, -1, -1);
		if (tvb_get_guint8(tvb, commhdr+6) == 0x68) {
			subfunction = tvb_get_guint8(tvb, commhdr+7);
			switch (subfunction) {

			case 0x02:	/* NDS Frag Packet to decode */
				dissect_nds_request(next_tvb, pinfo,
				    nw_connection, header.sequence,
				    header.type, ncp_tree);
				break;

			case 0x01:	/* NDS Ping */
				dissect_ping_req(next_tvb, pinfo,
				    nw_connection, header.sequence,
				    header.type, ncp_tree);
				break;

			default:
				dissect_ncp_request(next_tvb, pinfo,
				    nw_connection, header.sequence,
				    header.type, ncp_tree);
				break;
			 }
		} else {
			dissect_ncp_request(next_tvb, pinfo, nw_connection,
			    header.sequence, header.type, ncp_tree);
		}
		break;

	case NCP_SERVICE_REPLY:		/* Server NCP Reply */
		next_tvb = tvb_new_subset(tvb, commhdr, -1, -1);
		nds_defrag(next_tvb, pinfo, nw_connection, header.sequence,
		    header.type, ncp_tree, &ncp_tap);
		break;

	case NCP_POSITIVE_ACK:		/* Positive Acknowledgement */
		/*
		 * XXX - this used to call "nds_defrag()", which would
		 * clear out "frags".  Was that the right thing to
		 * do?
		 */
		next_tvb = tvb_new_subset(tvb, commhdr, -1, -1);
		dissect_ncp_reply(next_tvb, pinfo, nw_connection,
		    header.sequence, header.type, ncp_tree, &ncp_tap);
		break;

	case NCP_WATCHDOG:		/* Watchdog Packet */
		/*
		 * XXX - should the completion code be interpreted as
		 * it is in "packet-ncp2222.inc"?  If so, this
		 * packet should be handled by "dissect_ncp_reply()".
		 */
		proto_tree_add_item(ncp_tree, hf_ncp_completion_code,
		    tvb, commhdr + 6, 1, TRUE);
		proto_tree_add_item(ncp_tree, hf_ncp_connection_status,
		    tvb, commhdr + 7, 1, TRUE);
		proto_tree_add_item(ncp_tree, hf_ncp_slot,
		    tvb, commhdr + 8, 1, TRUE);
		proto_tree_add_item(ncp_tree, hf_ncp_control_code,
		    tvb, commhdr + 9, 1, TRUE);
		/*
		 * Display the rest of the packet as data.
		 */
		if (tvb_offset_exists(tvb, commhdr + 10)) {
			call_dissector(data_handle,
			    tvb_new_subset(tvb, commhdr + 10, -1, -1),
			    pinfo, ncp_tree);
		}
		break;

	case NCP_BURST_MODE_XFER:	/* Packet Burst Packet */
		if (flags & SYS) {
			/*
			 * System packet; show missing fragments if there
			 * are any.
			 */
			while (missing_fraglist_count != 0) {
				proto_tree_add_item(ncp_tree, hf_ncp_missing_data_offset,
				    tvb, offset, 4, FALSE);
				offset += 4;
				proto_tree_add_item(ncp_tree, hf_ncp_missing_data_count,
				    tvb, offset, 2, FALSE);
				offset += 2;
				missing_fraglist_count--;
			}
		} else {
			/*
			 * XXX - do this by using -1 and -1 as the length
			 * arguments to "tvb_new_subset()" and then calling
			 * "tvb_set_reported_length()"?  That'll throw an
			 * exception if "data_len" goes past the reported
			 * length of the packet, but that's arguably a
			 * feature in this case.
			 */
			length_remaining = tvb_length_remaining(tvb, offset);
			if (length_remaining > data_len)
				length_remaining = data_len;
			if (data_len != 0) {
				call_dissector(data_handle,
				    tvb_new_subset(tvb, offset,
					length_remaining, data_len),
				    pinfo, ncp_tree);
			}
		}
		break;

	case NCP_LIP_ECHO:		/* LIP Echo Packet */
		proto_tree_add_text(ncp_tree, tvb, commhdr, -1,
		    "Lip Echo Packet");
		break;

	default:
		if (tree) {
		    expert_item = proto_tree_add_text(ncp_tree, tvb, commhdr + 6, -1,
			    "%s packets not supported yet",
			    val_to_str(header.type, ncp_type_vals,
				"Unknown type (0x%04x)"));
            if (ncp_echo_err) {
                expert_add_info_format(pinfo, expert_item, PI_UNDECODED, PI_NOTE, "%s packets not supported yet", val_to_str(header.type, ncp_type_vals,
                    "Unknown type (0x%04x)"));
            }
		}
		break;
 	}
}

static void
dissect_ncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ncp_common(tvb, pinfo, tree, FALSE);
}

static guint
get_ncp_pdu_len(tvbuff_t *tvb, int offset)
{
  guint32 signature;

  /*
   * Check the NCP-over-TCP header signature, to make sure it's there.
   * If it's not there, we cannot trust the next 4 bytes to be a
   * packet length+"has signature" flag, so we just say the length is
   * "what remains in the packet".
   */
  signature = tvb_get_ntohl(tvb, offset);
  if (signature != NCPIP_RQST && signature != NCPIP_RPLY)
    return tvb_length_remaining(tvb, offset);

  /*
   * Get the length of the NCP-over-TCP packet.  Strip off the "has
   * signature" flag.
   */

  return tvb_get_ntohl(tvb, offset + 4) & 0x7fffffff;
}

static void
dissect_ncp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_ncp_common(tvb, pinfo, tree, TRUE);
}

static void
dissect_ncp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, ncp_desegment, 8, get_ncp_pdu_len,
	dissect_ncp_tcp_pdu);
}

void
proto_register_ncp(void)
{
  static hf_register_info hf[] = {
    { &hf_ncp_ip_sig,
      { "NCP over IP signature",	"ncp.ip.signature",
        FT_UINT32, BASE_HEX, VALS(ncp_ip_signature), 0x0,
        "", HFILL }},
    { &hf_ncp_ip_length,
      { "NCP over IP length",		"ncp.ip.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }},
    { &hf_ncp_ip_ver,
      { "NCP over IP Version",		"ncp.ip.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }},
    { &hf_ncp_ip_rplybufsize,
      { "NCP over IP Reply Buffer Size",	"ncp.ip.replybufsize",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }},
    { &hf_ncp_ip_packetsig,
      { "NCP over IP Packet Signature",	"ncp.ip.packetsig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    { &hf_ncp_type,
      { "Type",			"ncp.type",
	FT_UINT16, BASE_HEX, VALS(ncp_type_vals), 0x0,
	"NCP message type", HFILL }},
    { &hf_ncp_seq,
      { "Sequence Number",     	"ncp.seq",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_connection,
      { "Connection Number",    "ncp.connection",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_task,
      { "Task Number",     	"ncp.task",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_oplock_flag,
      { "Broadcast Message Flag",    "ncp.msg_flag",
	FT_UINT8, BASE_HEX, VALS(ncp_oplock_vals), 0x0,
	"", HFILL }},
    { &hf_ncp_oplock_handle,
      { "File Handle",    "ncp.oplock_handle",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_stream_type,
      { "Stream Type",     	"ncp.stream_type",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"Type of burst", HFILL }},
    { &hf_ncp_system_flags,
      { "System Flags",     	"ncp.system_flags",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_system_flags_abt,
      { "ABT",     	"ncp.system_flags.abt",
	FT_BOOLEAN, 8, NULL, ABT,
	"Is this an abort request?", HFILL }},
    { &hf_ncp_system_flags_eob,
      { "EOB",     	"ncp.system_flags.eob",
	FT_BOOLEAN, 8, NULL, EOB,
	"Is this the last packet of the burst?", HFILL }},
    { &hf_ncp_system_flags_sys,
      { "SYS",     	"ncp.system_flags.sys",
	FT_BOOLEAN, 8, NULL, SYS,
	"Is this a system packet?", HFILL }},
    { &hf_ncp_system_flags_bsy,
      { "BSY",     	"ncp.system_flags.bsy",
	FT_BOOLEAN, 8, NULL, BSY,
	"Is the server busy?", HFILL }},
    { &hf_ncp_system_flags_lst,
      { "LST",     	"ncp.system_flags.lst",
	FT_BOOLEAN, 8, NULL, LST,
	"Return Fragment List?", HFILL }},
    { &hf_ncp_src_connection,
      { "Source Connection ID",    "ncp.src_connection",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The workstation's connection identification number", HFILL }},
    { &hf_ncp_dst_connection,
      { "Destination Connection ID",    "ncp.dst_connection",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The server's connection identification number", HFILL }},
    { &hf_ncp_packet_seqno,
      { "Packet Sequence Number",    "ncp.packet_seqno",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Sequence number of this packet in a burst", HFILL }},
    { &hf_ncp_delay_time,
      { "Delay Time",    "ncp.delay_time",	/* in 100 us increments */
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Delay time between consecutive packet sends (100 us increments)", HFILL }},
    { &hf_ncp_burst_seqno,
      { "Burst Sequence Number",    "ncp.burst_seqno",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Sequence number of this packet in the burst", HFILL }},
    { &hf_ncp_ack_seqno,
      { "ACK Sequence Number",    "ncp.ack_seqno",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Next expected burst sequence number", HFILL }},
    { &hf_ncp_burst_len,
      { "Burst Length",    "ncp.burst_len",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Total length of data in this burst", HFILL }},
    { &hf_ncp_burst_offset,
      { "Burst Offset",    "ncp.burst_offset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Offset of data in the burst", HFILL }},
    { &hf_ncp_data_offset,
      { "Data Offset",    "ncp.data_offset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Offset of this packet", HFILL }},
    { &hf_ncp_data_bytes,
      { "Data Bytes",    "ncp.data_bytes",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of data bytes in this packet", HFILL }},
    { &hf_ncp_missing_fraglist_count,
      { "Missing Fragment List Count",    "ncp.missing_fraglist_count",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of missing fragments reported", HFILL }},
    { &hf_ncp_missing_data_offset,
      { "Missing Data Offset",    "ncp.missing_data_offset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Offset of beginning of missing data", HFILL }},
    { &hf_ncp_missing_data_count,
      { "Missing Data Count",    "ncp.missing_data_count",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of bytes of missing data", HFILL }},
    { &hf_ncp_completion_code,
      { "Completion Code",    "ncp.completion_code",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_connection_status,
      { "Connection Status",    "ncp.connection_status",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_slot,
      { "Slot",    "ncp.slot",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_control_code,
      { "Control Code",    "ncp.control_code",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_fragment_handle,
      { "Fragment Handle",    "ncp.fragger_hndl",
    FT_UINT16, BASE_HEX, NULL, 0x0,
    "", HFILL }},
    { &hf_lip_echo,
      { "Large Internet Packet Echo",    "ncp.lip_echo",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "", HFILL }},
    { &hf_ncp_burst_command,
      { "Burst Command",    "ncp.burst_command",
	FT_UINT32, BASE_HEX, VALS(burst_command), 0x0,
	"Packet Burst Command", HFILL }},
    { &hf_ncp_burst_file_handle,
      { "Burst File Handle",    "ncp.file_handle",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Packet Burst File Handle", HFILL }},
 	{ &hf_ncp_burst_reserved,
	{ "Reserved", "ncp.burst_reserved", 
    FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
  
  };
  static gint *ett[] = {
    &ett_ncp,
    &ett_ncp_system_flags,
    &ett_nds,
	&ett_nds_segments,
	&ett_nds_segment,
  };
  module_t *ncp_module;

  proto_ncp = proto_register_protocol("NetWare Core Protocol", "NCP", "ncp");
  proto_register_field_array(proto_ncp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ncp_module = prefs_register_protocol(proto_ncp, NULL);
  prefs_register_obsolete_preference(ncp_module, "initial_hash_size");
  prefs_register_bool_preference(ncp_module, "desegment",
    "Reassemble NCP-over-TCP messages spanning multiple TCP segments",
    "Whether the NCP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &ncp_desegment);
  prefs_register_bool_preference(ncp_module, "defragment_nds",
    "Reassemble fragmented NDS messages spanning multiple reply packets",
    "Whether the NCP dissector should defragment NDS messages spanning multiple reply packets.",
     &nds_defragment);
  prefs_register_bool_preference(ncp_module, "eid_2_expert",
    "Expert: EID to Name lookups?",
    "Whether the NCP dissector should echo the NDS Entry ID to name resolves to the expert table.",
    &nds_echo_eid);
  prefs_register_bool_preference(ncp_module, "connection_2_expert",
    "Expert: NCP Connections?",
    "Whether the NCP dissector should echo NCP connection information to the expert table.",
    &ncp_echo_conn);
  prefs_register_bool_preference(ncp_module, "error_2_expert",
    "Expert: NCP Errors?",
    "Whether the NCP dissector should echo protocol errors to the expert table.",
    &ncp_echo_err);
  prefs_register_bool_preference(ncp_module, "server_2_expert",
    "Expert: Server Information?",
    "Whether the NCP dissector should echo server information to the expert table.",
    &ncp_echo_server);
  prefs_register_bool_preference(ncp_module, "file_2_expert",
    "Expert: File Information?",
    "Whether the NCP dissector should echo file information to the expert table.",
    &ncp_echo_file);
  register_init_routine(&mncp_init_protocol);
  ncp_tap.stat=register_tap("ncp_srt");
  ncp_tap.hdr=register_tap("ncp_hdr");
  register_postseq_cleanup_routine(&mncp_postseq_cleanup);
}

void
proto_reg_handoff_ncp(void)
{
  dissector_handle_t ncp_handle;
  dissector_handle_t ncp_tcp_handle;

  ncp_handle = create_dissector_handle(dissect_ncp, proto_ncp);
  ncp_tcp_handle = create_dissector_handle(dissect_ncp_tcp, proto_ncp);
  dissector_add("tcp.port", TCP_PORT_NCP, ncp_tcp_handle);
  dissector_add("udp.port", UDP_PORT_NCP, ncp_handle);
  dissector_add("ipx.packet_type", IPX_PACKET_TYPE_NCP, ncp_handle);
  dissector_add("ipx.socket", IPX_SOCKET_NCP, ncp_handle);

  data_handle = find_dissector("data");
}
