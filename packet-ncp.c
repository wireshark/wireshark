/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified to allow NCP over TCP/IP decodes by James Coe <jammer@cin.net>
 * Modified to decode server op-lock
 * & NDS packets by Greg Morris <gmorris@novell.com>
 *
 * $Id: packet-ncp.c,v 1.70 2002/09/25 00:37:01 jmayer Exp $
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
#include <epan/conversation.h>
#include "prefs.h"
#include "packet-ipx.h"
#include "packet-tcp.h"
#include "packet-ncp-int.h"

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
static int hf_ncp_src_connection = -1;
static int hf_ncp_dst_connection = -1;
static int hf_ncp_packet_seqno = -1;
static int hf_ncp_delay_time = -1;
static int hf_ncp_burst_seqno = -1;
static int hf_ncp_ack_seqno = -1;
static int hf_ncp_burst_len = -1;
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
/*static int hf_ping_version = -1;*/

gint ett_ncp = -1;
gint ett_nds = -1;
static gint ett_ncp_system_flags = -1;

/* desegmentation of NCP over TCP */
static gboolean ncp_desegment = TRUE;
/*static int ncp_nds_true = FALSE;*/

static dissector_handle_t data_handle;

#define TCP_PORT_NCP		524
#define UDP_PORT_NCP		524

#define NCP_RQST_HDR_LENGTH	7
#define NCP_RPLY_HDR_LENGTH	8


/* Hash functions */
gint  ncp_equal (gconstpointer v, gconstpointer v2);
guint ncp_hash  (gconstpointer v);

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

/*
 * Every NCP packet has this common header (except for burst packets).
 */
struct ncp_common_header {
	guint16	type;
	guint8	sequence;
	guint8	conn_low;
	guint8	task;
	guint8	conn_high; /* type=0x5555 doesn't have this */
};


static value_string ncp_type_vals[] = {
	{ NCP_ALLOCATE_SLOT,	"Create a service connection" },
	{ NCP_SERVICE_REQUEST,	"Service request" },
	{ NCP_SERVICE_REPLY,	"Service reply" },
	{ NCP_WATCHDOG,		"Watchdog" },
	{ NCP_DEALLOCATE_SLOT,	"Destroy service connection" },
    { NCP_BROADCAST_SLOT,   "Server Broadcast" },
	{ NCP_BURST_MODE_XFER,	"Burst mode transfer" },
	{ NCP_POSITIVE_ACK,	"Request being processed" },
    { NCP_LIP_ECHO, "Large Internet Packet Echo" },
	{ 0,			NULL }
};


/*
 * Burst packet system flags.
 */
#define ABT	0x04		/* Abort request */
#define EOB	0x10		/* End of burst */
#define SYS	0x80		/* System packet */

static void
dissect_ncp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean is_tcp)
{
	proto_tree			*ncp_tree = NULL;
	proto_item			*ti;
	struct ncp_ip_header		ncpiph;
	struct ncp_ip_rqhdr		ncpiphrq;
	gboolean			is_signed = FALSE;
	struct ncp_common_header	header;
	guint16				nw_connection;
	guint16				flags = 0;
	char				flags_str[1+3+1+3+1+3+1+1];
	char				*sep;
	proto_tree			*flags_tree = NULL;
	guint16				data_len = 0;
	guint16				missing_fraglist_count = 0;
	guint16				ncp_nds_verb;
	int				hdr_offset = 0;
	int				commhdr;
	int				offset;
	gint				length_remaining;
	tvbuff_t       			*next_tvb;
    guint32             testvar=0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (is_tcp) {
		ncpiph.signature	= tvb_get_ntohl(tvb, 0);
		ncpiph.length		= tvb_get_ntohl(tvb, 4);
		hdr_offset += 8;
		if ( ncpiph.signature == NCPIP_RQST ) {
			ncpiphrq.version	= tvb_get_ntohl(tvb, hdr_offset);
			hdr_offset += 4;
			ncpiphrq.rplybufsize	= tvb_get_ntohl(tvb, hdr_offset);
			hdr_offset += 4;
		}
		if (ncpiph.length & 0x80000000) {
			/*
			 * This appears to indicate that this packet
			 * is signed; the signature is 8 bytes long.
			 *
			 * XXX - that bit does *not* appear to be set
			 * in signed replies, and we can't dissect the
			 * reply enough to find the matching request
			 * without knowing whether the reply is
			 * signed.
			 *
			 * XXX - what about NCP-over-IPX signed
			 * messages?
			 */
			is_signed = TRUE;
			hdr_offset += 8;
			ncpiph.length &= 0x7fffffff;
		}
	}

	/* Record the offset where the NCP common header starts */
	commhdr = hdr_offset;

	header.type		    = tvb_get_ntohs(tvb, commhdr);
	header.sequence		= tvb_get_guint8(tvb, commhdr+2);
	header.conn_low		= tvb_get_guint8(tvb, commhdr+3);
	header.conn_high	= tvb_get_guint8(tvb, commhdr+5);

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_add_fstr(pinfo->cinfo, COL_INFO,
		    "%s",
		    val_to_str(header.type, ncp_type_vals, "Unknown type (0x%04x)"));

	}

	nw_connection = (header.conn_high << 16) + header.conn_low;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ncp, tvb, 0, -1, FALSE);
		ncp_tree = proto_item_add_subtree(ti, ett_ncp);

		if (is_tcp) {
			proto_tree_add_uint(ncp_tree, hf_ncp_ip_sig, tvb, 0, 4, ncpiph.signature);
			proto_tree_add_uint(ncp_tree, hf_ncp_ip_length, tvb, 4, 4, ncpiph.length);
			if (ncpiph.signature == NCPIP_RQST) {
				proto_tree_add_uint(ncp_tree, hf_ncp_ip_ver, tvb, 8, 4, ncpiphrq.version);
				proto_tree_add_uint(ncp_tree, hf_ncp_ip_rplybufsize, tvb, 12, 4, ncpiphrq.rplybufsize);
			}
			if (is_signed)
				proto_tree_add_item(ncp_tree, hf_ncp_ip_packetsig, tvb, 16, 8, FALSE);
		}
		proto_tree_add_uint(ncp_tree, hf_ncp_type,	tvb, commhdr + 0, 2, header.type);
	}


	/*
	 * Process the packet-type-specific header.
	 */
	switch (header.type) {

    case NCP_BROADCAST_SLOT:    /* Server Broadcast */
        proto_tree_add_uint(ncp_tree, hf_ncp_seq,	tvb, commhdr + 2, 1, header.sequence);
		proto_tree_add_uint(ncp_tree, hf_ncp_connection,tvb, commhdr + 3, 3, nw_connection);
		proto_tree_add_item(ncp_tree, hf_ncp_task,	tvb, commhdr + 4, 1, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_oplock_flag, tvb, commhdr + 9, 1, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_oplock_handle, tvb, commhdr + 10, 4, FALSE);
        break;

    case NCP_LIP_ECHO:    /* Lip Echo Packet */
        proto_tree_add_item(ncp_tree, hf_lip_echo, tvb, commhdr, 2, FALSE);
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
		strcpy(flags_str, "");
		sep = " (";
		if (flags & ABT) {
			strcat(flags_str, sep);
			strcat(flags_str, "ABT");
			sep = ",";
		}
		if (flags & EOB) {
			strcat(flags_str, sep);
			strcat(flags_str, "EOB");
			sep = ",";
		}
		if (flags & SYS) {
			strcat(flags_str, sep);
			strcat(flags_str, "SYS");
		}
		if (flags_str[0] != '\0')
			strcat(flags_str, ")");
		ti = proto_tree_add_uint_format(ncp_tree, hf_ncp_system_flags,
		    tvb, commhdr + 2, 1, flags, "Flags: 0x%04x%s", flags,
		    flags_str);
		flags_tree = proto_item_add_subtree(ti, ett_ncp_system_flags);
		proto_tree_add_item(flags_tree, hf_ncp_system_flags_abt,
		    tvb, commhdr + 2, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_ncp_system_flags_eob,
		    tvb, commhdr + 2, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_ncp_system_flags_sys,
		    tvb, commhdr + 2, 1, FALSE);

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
		proto_tree_add_item(ncp_tree, hf_ncp_burst_seqno,
		    tvb, commhdr + 20, 2, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_ack_seqno,
		    tvb, commhdr + 22, 2, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_burst_len,
		    tvb, commhdr + 24, 4, FALSE);
		proto_tree_add_item(ncp_tree, hf_ncp_data_offset,
		    tvb, commhdr + 28, 4, FALSE);
		data_len = tvb_get_ntohs(tvb, commhdr + 32);
		proto_tree_add_uint(ncp_tree, hf_ncp_data_bytes,
		    tvb, commhdr + 32, 2, data_len);
		missing_fraglist_count = tvb_get_ntohs(tvb, commhdr + 34);
		proto_tree_add_item(ncp_tree, hf_ncp_missing_fraglist_count,
		    tvb, commhdr + 34, 2, FALSE);
		break;

	case NCP_ALLOCATE_SLOT:		/* Allocate Slot Request */
        length_remaining = tvb_length_remaining(tvb, commhdr + 4);
        if (length_remaining > 4)
        { 
            testvar = tvb_get_ntohl(tvb, commhdr+4);
            if( testvar == 0x4c495020)
            {
                proto_tree_add_item(ncp_tree, hf_lip_echo, tvb, commhdr+4, 13, FALSE);
                break;
            }
        }
    
	case NCP_POSITIVE_ACK:		/* Positive Acknowledgement */
    case NCP_SERVICE_REQUEST:	/* Server NCP Request */
    case NCP_SERVICE_REPLY:		/* Server NCP Reply */
	case NCP_WATCHDOG:		    /* Watchdog Packet */
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
        if (length_remaining > 4)
        {
            testvar = tvb_get_ntohl(tvb, commhdr+4);
            if( testvar == 0x4c495020)
            {
                proto_tree_add_text(ncp_tree, tvb, commhdr, -1,
                    "Lip Echo Packet");
                /*break;*/
            }
        }
    case NCP_SERVICE_REQUEST:	/* Server NCP Request */
	case NCP_DEALLOCATE_SLOT:	/* Deallocate Slot Request */
    case NCP_BROADCAST_SLOT:	/* Server Broadcast Packet */
		next_tvb = tvb_new_subset(tvb, hdr_offset, -1, -1);
        if (tvb_get_guint8(tvb, commhdr+6)==0x68) {
            ncp_nds_verb = tvb_get_ntohl(tvb, commhdr+4);
            if (tvb_get_guint8(tvb, commhdr+7)==0x02) {  /* NDS Frag Packet to decode */
                dissect_nds_request(next_tvb, pinfo, nw_connection, 
                    header.sequence, header.type, ncp_tree);
            }
            else 
            {
                if(tvb_get_guint8(tvb, commhdr+7)==0x01) { /* NDS Ping */
                    dissect_ping_req(next_tvb, pinfo, nw_connection,
                        header.sequence, header.type, ncp_tree);
                }
                else
                {
                    dissect_ncp_request(next_tvb, pinfo, nw_connection,
                        header.sequence, header.type, ncp_tree);
                }
            }
        }
        else
        {
        dissect_ncp_request(next_tvb, pinfo, nw_connection,
			header.sequence, header.type, ncp_tree);
        }
		break;

    case NCP_SERVICE_REPLY:		/* Server NCP Reply */
	case NCP_POSITIVE_ACK:		/* Positive Acknowledgement */
		next_tvb = tvb_new_subset(tvb, hdr_offset, -1, -1);
		dissect_ncp_reply(next_tvb, pinfo, nw_connection,
			header.sequence, header.type, ncp_tree);
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
			offset = commhdr + 36;
			while (missing_fraglist_count != 0) {
				proto_tree_add_item(ncp_tree, hf_ncp_missing_data_offset,
				    tvb, offset, 4, FALSE);
				proto_tree_add_item(ncp_tree, hf_ncp_missing_data_count,
				    tvb, offset, 2, FALSE);
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
			length_remaining = tvb_length_remaining(tvb, commhdr + 36);
			if (length_remaining > data_len)
				length_remaining = data_len;
			if (data_len != 0) {
				call_dissector(data_handle,
				    tvb_new_subset(tvb, commhdr + 36,
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
		    proto_tree_add_text(ncp_tree, tvb, commhdr + 6, -1,
			    "%s packets not supported yet",
			    val_to_str(header.type, ncp_type_vals,
				"Unknown type (0x%04x)"));
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
      { "Oplock Flag",    "ncp.oplock_flag",
	FT_UINT8, BASE_HEX, NULL, 0x0,
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
    { &hf_ncp_data_offset,
      { "Data Offset",    "ncp.data_offset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Offset of this packet in the burst", HFILL }},
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
  
  };
  static gint *ett[] = {
    &ett_ncp,
    &ett_ncp_system_flags,
    &ett_nds,
  };
  module_t *ncp_module;

  proto_ncp = proto_register_protocol("NetWare Core Protocol", "NCP", "ncp");
  proto_register_field_array(proto_ncp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ncp_module = prefs_register_protocol(proto_ncp, NULL);
  prefs_register_obsolete_preference(ncp_module, "initial_hash_size");
  prefs_register_bool_preference(ncp_module, "desegment",
    "Desegment all NCP-over-TCP messages spanning multiple segments",
    "Whether the NCP dissector should desegment all messages spanning multiple TCP segments",
    &ncp_desegment);
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


