/* packet-ldss.c
 * Routines for Local Download Sharing Service dissection
 * Copyright 2009, Vasantha Crabb <vcrabb@managesoft.com.au>
 *  and Chris Adams <cadams@managesoft.com.au>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* LDSS is a protocol for peers on a LAN to co-operatively download
 * files from a WAN. The peers ask each other about files and can
 * send files to each other, thus WAN use is minimized. However
 * if no peer possesses a file, a peer can download it via the WAN.
 * Usually the download uses HTTP, but WAN downloads are beyond
 * the scope of this dissector. To avoid saturating the WAN link,
 * peers also tell each other what they are fetching and how fast
 * they're downloading. Files are identified only by digests.
 * Broadcasts are sent via UDP and files transferred via TCP. Both
 * UDP and TCP portions of the protocol are handled in this dissector.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/dissectors/packet-tcp.h>

/* The digest is up to 32 bytes long */
#define DIGEST_LEN 32

#define MESSAGE_ID_NEEDFILE	0
#define MESSAGE_ID_WILLSEND	1


static const value_string ldss_message_id_value[] = {
	{ MESSAGE_ID_NEEDFILE,	"Need file"	},
	{ MESSAGE_ID_WILLSEND,	"Will send"	},
	{ 0,			NULL		}
};

/* Message detail is inferred from various contents in the packet */
#define INFERRED_PEERSHUTDOWN	0
#define INFERRED_SEARCH		1
#define INFERRED_OFFER		2
#define INFERRED_PROMISE	3
#define INFERRED_WANDOWNLOAD	4
#define INFERRED_NONE		5

/* Displayed in the info column */
static const value_string ldss_inferred_info[] = {
	{ INFERRED_PEERSHUTDOWN, 	" - peer shutting down"	},
	{ INFERRED_SEARCH,		" - search"		},
	{ INFERRED_OFFER,		" - offer"		},
	{ INFERRED_PROMISE,		" - promise"		},
	{ INFERRED_WANDOWNLOAD,		" - WAN download start"	},
	{ INFERRED_NONE,		""			},
	{ 0, NULL			                        }
};

/* Displayed in the tree as a generated item */
static const value_string ldss_inferred_value[] = {
	{ INFERRED_PEERSHUTDOWN, 	"Peer shutdown"	},
	{ INFERRED_SEARCH,		"File search"	},
	{ INFERRED_OFFER,		"File offer"	},
	{ INFERRED_PROMISE,		"Promise (download in progress)" },
	{ INFERRED_WANDOWNLOAD,		"WAN download start"	},
	{ INFERRED_NONE,		""		},
	{ 0, NULL			}
};


#define DIGEST_TYPE_UNKNOWN	0
#define DIGEST_TYPE_MD5		1
#define DIGEST_TYPE_SHA1	2
#define DIGEST_TYPE_SHA256	3


static const value_string ldss_digest_type_value[] = {
	{ DIGEST_TYPE_UNKNOWN,	"Unknown"	},
	{ DIGEST_TYPE_MD5,	"MD5"		},
	{ DIGEST_TYPE_SHA1,	"SHA1"		},
	{ DIGEST_TYPE_SHA256,	"SHA256"	},
	{ 0,			NULL		}
};


#define COMPRESSION_NONE	0
#define COMPRESSION_GZIP	1


static const value_string ldss_compression_value[] = {
	{ COMPRESSION_NONE,		"None"		},
	{ COMPRESSION_GZIP,		"gzip"		},
	{ 0,			NULL		}
};

/* Info about a broadcaster */
typedef struct _ldss_broadcaster_t {
	address addr;
	guint16 port;
} ldss_broadcaster_t;

/* Info about a file */
typedef struct _ldss_file_t {
	guint8 *digest;
	guint8 digest_type;
} ldss_file_t;

/* Info about a broadcast packet */
typedef struct _ldss_broadcast_t {
	guint32 num;
	nstime_t ts;
	guint16 message_id;
	guint16 message_detail;
	guint16 port;
	guint64 size;
	guint64 offset;
	guint8 compression;
	ldss_file_t *file;
	ldss_broadcaster_t *broadcaster;
} ldss_broadcast_t;

/* Info about a file as seen in a file request */
typedef struct _ldss_file_req_t {
	guint32 num;
	nstime_t ts;
	guint64 size;
	guint64 offset;
	guint8 compression;
	ldss_file_t *file;
} ldss_file_request_t;

/* Info attached to a file transfer conversation */
typedef struct _ldss_transfer_info_t {
	guint32 resp_num;
	nstime_t resp_ts;
	/* Refers either to the file in the request (for pull)
	 * or the file in the broadcast (for push) */
	ldss_file_t *file;
	ldss_file_request_t *req;
	ldss_broadcast_t *broadcast;
} ldss_transfer_info_t;

/* Define udp_port for LDSS (IANA assigned) */
#define UDP_PORT_LDSS 6087

void proto_register_ldss(void);
void proto_reg_handoff_ldss(void);

/* Define the ldss proto */
static int	proto_ldss		= -1;

/* Define headers for ldss */
static int	hf_ldss_message_id	= -1;
static int	hf_ldss_message_detail	= -1;
static int	hf_ldss_digest_type	= -1;
static int	hf_ldss_compression	= -1;
static int	hf_ldss_cookie		= -1;
static int	hf_ldss_digest		= -1;
static int	hf_ldss_size		= -1;
static int	hf_ldss_offset		= -1;
static int	hf_ldss_target_time	= -1;
static int	hf_ldss_reserved_1	= -1;
static int	hf_ldss_port		= -1;
static int	hf_ldss_rate		= -1;
static int	hf_ldss_priority	= -1;
static int	hf_ldss_property_count	= -1;
static int	hf_ldss_properties	= -1;
static int	hf_ldss_file_data	= -1;
static int	hf_ldss_response_in	= -1;
static int	hf_ldss_response_to	= -1;
static int	hf_ldss_initiated_by	= -1;
static int	hf_ldss_transfer_response_time	= -1;
static int	hf_ldss_transfer_completed_in	= -1;

/* Define the tree for ldss */
static int ett_ldss_broadcast	 = -1;
static int ett_ldss_transfer     = -1;
static int ett_ldss_transfer_req = -1;

static dissector_handle_t	ldss_handle;

/* Global variables associated with the preferences for ldss */
static guint	global_udp_port_ldss	= UDP_PORT_LDSS;

/* Avoid creating conversations and data twice */
static unsigned int highest_num_seen = 0;

/* When seeing a broadcast talking about an open TCP port on a host, create
 * a conversation to dissect anything sent/received at that address.  Setup
 * protocol data so the TCP dissection knows what broadcast triggered it. */
static void
prepare_ldss_transfer_conv(ldss_broadcast_t *broadcast)
{
	conversation_t *transfer_conv;
	ldss_transfer_info_t *transfer_info;

	transfer_info = se_alloc0(sizeof(ldss_transfer_info_t));
	transfer_info->broadcast = broadcast;

	/* Preparation for later push/pull dissection */
	transfer_conv = conversation_new (broadcast->num, &broadcast->broadcaster->addr, &broadcast->broadcaster->addr,
					  PT_TCP, broadcast->broadcaster->port, broadcast->broadcaster->port, NO_ADDR2|NO_PORT2);
	conversation_add_proto_data(transfer_conv, proto_ldss, transfer_info);
	conversation_set_dissector(transfer_conv, ldss_handle);
}

/* Broadcasts are searches, offers or promises.
 *
 * Searches are sent by
 * a peer when it needs a file (ie. while applying its policy, when it needs
 * files such as installers to install software.)
 *
 * Each broadcast relates to one file and each file is identified only by its
 * checksum - no file names are ever used. A search times out after 10 seconds
 * (configurable) and the peer will then attempt to act on any offers by
 * downloading (via push or pull - see dissect_ldss_transfer) from those peers.
 *
 * If no offers are received, the search fails and the peer fetches the file
 * from a remote server, generally a HTTP server on the other side of a WAN.
 * The protocol exists to minimize the number of WAN downloads needed.
 *
 * While downloading from WAN the peer sends promises to inform other peers
 * when it will be available for them to download. This prevents multiple peers
 * simultaneously downloading the same file. Promises also inform other peers
 * how much download bandwidth is being used by their download. Other peers use
 * this information and the configured knowledge of the WAN bandwidth to avoid
 * saturating the WAN link, as file downloads are a non-time-critical and
 * non-business-critical network function. LDSS is intended for networks of
 * 5-20 machines connected by slow WAN link. The current implementation of the
 * protocol allows administrator to configure "time windows" when WAN usage is
 * throttled/unthrottled, though this isn't visible in LDSS.
 *
 * Once a WAN download or a LAN transfer (see below above dissect_ldss_transfer)
 * has complete the peer will offer the file to other peers on the LAN so they
 * don't need to download it themselves.
 *
 * Peers also notify when they shut down in case any other peer is waiting for
 * a file. */
static int
dissect_ldss_broadcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16	messageID;
	guint8 digest_type;
	guint8 compression;
	guint32 cookie;
	guint8 *digest;
	guint64	size;
	guint64	offset;
	guint32	targetTime;
	guint16 port;
	guint16	rate;
	guint16 messageDetail = INFERRED_NONE;

	proto_tree	*ti, *ldss_tree;

	const gchar *packet_type, *packet_detail;

	messageID   = tvb_get_ntohs  (tvb,  0);
	digest_type = tvb_get_guint8 (tvb,  2);
	compression = tvb_get_guint8 (tvb,  3);
	cookie      = tvb_get_ntohl  (tvb,  4);
	digest      = tvb_memdup     (tvb,  8, DIGEST_LEN);
	size	    = tvb_get_ntoh64 (tvb, 40);
	offset	    = tvb_get_ntoh64 (tvb, 48);
	targetTime  = tvb_get_ntohl  (tvb, 56);
	port        = tvb_get_ntohs  (tvb, 64);
	rate	    = tvb_get_ntohs  (tvb, 66);

	packet_type = val_to_str(messageID, ldss_message_id_value, "unknown");

	if (messageID == MESSAGE_ID_WILLSEND) {
		if (cookie == 0) {
			/* Shutdown: Dishonor promises from this peer. Current
			 * implementation abuses WillSend for this. */
			messageDetail = INFERRED_PEERSHUTDOWN;
		}
		else if (size == 0 && offset == 0) {
			/* NeedFile search failed - going to WAN */
			messageDetail = INFERRED_WANDOWNLOAD;
		}
		else if (size > 0) {
			/* Size is known (not always the case) */
			if (size == offset) {
				/* File is available for pull on this peer's TCP port */
				messageDetail = INFERRED_OFFER;
			}
			else {
				/* WAN download progress announcement from this peer */
				messageDetail = INFERRED_PROMISE;
			}
		}
	}
	else if (messageID == MESSAGE_ID_NEEDFILE) {
		messageDetail = INFERRED_SEARCH;
	}
	packet_detail = val_to_str(messageDetail, ldss_inferred_info, "unknown");

	/* Set the info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "LDSS Broadcast (%s%s)",
			     packet_type,
			     packet_detail);
	}

	/* If we have a non-null tree (ie we are building the proto_tree
	 * instead of just filling out the columns), then give more detail. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_ldss,
					 tvb, 0, (tvb_length(tvb) > 72) ? tvb_length(tvb) : 72, FALSE);
		ldss_tree = proto_item_add_subtree(ti, ett_ldss_broadcast);

		proto_tree_add_item(ldss_tree, hf_ldss_message_id,
				    tvb, 0, 2, FALSE);
		ti = proto_tree_add_uint(ldss_tree, hf_ldss_message_detail,
					 tvb, 0, 0, messageDetail);
		PROTO_ITEM_SET_GENERATED(ti);
		proto_tree_add_item(ldss_tree, hf_ldss_digest_type,
				    tvb, 2,	    1,	FALSE);
		proto_tree_add_item(ldss_tree, hf_ldss_compression,
				    tvb, 3,	    1,	FALSE);
		proto_tree_add_uint_format_value(ldss_tree, hf_ldss_cookie,
						 tvb, 4,	    4,	FALSE,
						 "0x%x%s",
						 cookie,
						 (cookie == 0)
						 ? " - shutdown (promises from this peer are no longer valid)"
						 : "");
		proto_tree_add_item(ldss_tree, hf_ldss_digest,
				    tvb, 8,	    DIGEST_LEN, FALSE);
		proto_tree_add_item(ldss_tree, hf_ldss_size,
				    tvb, 40,    8,	FALSE);
		proto_tree_add_item(ldss_tree, hf_ldss_offset,
				    tvb, 48,    8,	FALSE);
		proto_tree_add_uint_format_value(ldss_tree, hf_ldss_target_time,
						 tvb, 56,    4,	FALSE,
						 "%d:%02d:%02d",
						 (int)(targetTime / 3600),
						 (int)((targetTime / 60) % 60),
						 (int)(targetTime % 60));
		proto_tree_add_item(ldss_tree, hf_ldss_reserved_1,
				    tvb, 60,    4,	FALSE);
		proto_tree_add_uint_format_value(ldss_tree, hf_ldss_port,
						 tvb, 64,    2,	FALSE,
						 "%d%s",
						 port,
						 (messageID == MESSAGE_ID_WILLSEND &&
						  size > 0 &&
						  size == offset)
						 ? " - file can be pulled at this TCP port"
						 : (messageID == MESSAGE_ID_NEEDFILE
						    ? " - file can be pushed to this TCP port"
						    : ""));
		proto_tree_add_uint_format_value(ldss_tree, hf_ldss_rate,
						 tvb, 66,    2,	FALSE,
						 "%ld",
						 (rate > 0)
						 ? (long)floor(exp(rate * G_LN2 / 2048))
						 : 0);
		proto_tree_add_item(ldss_tree, hf_ldss_priority,
				    tvb, 68, 2, FALSE);
		proto_tree_add_item(ldss_tree, hf_ldss_property_count,
				    tvb, 70, 2, FALSE);
		if (tvb_length(tvb) > 72) {
			proto_tree_add_item(ldss_tree, hf_ldss_properties,
					    tvb, 72, tvb_length(tvb) - 72, FALSE);
		}
	}

	/* Finally, store the broadcast and register ourselves to dissect
	 * any pushes or pulls that result from this broadcast. All data
	 * is pushed/pulled over TCP using the port from the broadcast
	 * packet's port field.
	 * Track each by a TCP conversation with the remote end wildcarded.
	 * The TCP conv tracks back to a broadcast conv to determine what it
	 * is in response to.
	 *
	 * These steps only need to be done once per packet, so a variable
	 * tracks the highest frame number seen. Handles the case of first frame
	 * being frame zero. */
	if (messageDetail != INFERRED_PEERSHUTDOWN &&
	    (highest_num_seen == 0 ||
	     highest_num_seen < pinfo->fd->num)) {

		ldss_broadcast_t *data;

		/* Populate data from the broadcast */
		data = se_alloc0(sizeof(ldss_broadcast_t));
		data->num = pinfo->fd->num;
		data->ts = pinfo->fd->abs_ts;
		data->message_id = messageID;
		data->message_detail = messageDetail;
		data->port = port;
		data->size = size;
		data->offset = offset;
		data->compression = compression;

		data->file = se_alloc0(sizeof(ldss_file_t));
		data->file->digest = digest;
		data->file->digest_type = digest_type;

		data->broadcaster = se_alloc0(sizeof(ldss_broadcaster_t));
		COPY_ADDRESS(&data->broadcaster->addr, &pinfo->src);
		data->broadcaster->port = port;

		/* Dissect any future pushes/pulls */
		if (port > 0) {
			prepare_ldss_transfer_conv(data);
		}

		/* Record that the frame was processed */
		highest_num_seen = pinfo->fd->num;
	}

	return tvb_length(tvb);
}

/* Transfers happen in response to broadcasts, they are always TCP and are
 * used to send the file to the port mentioned in the broadcast. There are
 * 2 types of transfers: Pushes, which are direct responses to searches,
 * in which the peer that has the file connects to the peer that doesnt and
 * sends it, then disconnects. The other type of transfer is a pull, where
 * the peer that doesn't have the file connects to the peer that does and
 * requests it be sent.
 *
 * Pulls have a file request which identifies the desired file,
 * while pushes simply send the file. In practice this works because every
 * file the implementation sends searches for is on a different TCP port
 * on the searcher's machine. */
static int
dissect_ldss_transfer (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	conversation_t *transfer_conv;
	ldss_transfer_info_t *transfer_info;
	struct tcpinfo *transfer_tcpinfo;

	proto_tree	*ti, *line_tree = NULL, *ldss_tree = NULL;

	nstime_t broadcast_response_time;

	/* Look for the transfer conversation; this was created during
	 * earlier broadcast dissection (see prepate_ldss_transfer_conv) */
	transfer_conv = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
					   PT_TCP, pinfo->srcport, pinfo->destport, 0);
	transfer_info = conversation_get_proto_data(transfer_conv, proto_ldss);
	transfer_tcpinfo = pinfo->private_data;

	/* For a pull, the first packet in the TCP connection is the file request.
	 * First packet is identified by relative seq/ack numbers of 1.
	 * File request only appears on a pull (triggered by an offer - see above
	 * about broadcasts) */
	if (transfer_tcpinfo->seq == 1 &&
	    transfer_tcpinfo->lastackseq == 1 &&
	    transfer_info->broadcast->message_id == MESSAGE_ID_WILLSEND) {
		/* LDSS pull transfers look a lot like HTTP.
		 * Sample request:
		 * md5:01234567890123...
		 * Size: 2550
		 * Start: 0
		 * Compression: 0
		 * (remote end sends the file identified by the digest) */
		guint offset = 0;
		gboolean already_dissected = TRUE;

		col_set_str(pinfo->cinfo, COL_INFO, "LDSS File Transfer (Requesting file - pull)");

		if (highest_num_seen == 0 ||
		    highest_num_seen < pinfo->fd->num) {

			already_dissected = FALSE;
			transfer_info->req = se_alloc0(sizeof(ldss_file_request_t));
			transfer_info->req->file = se_alloc0(sizeof(ldss_file_t));
			highest_num_seen = pinfo->fd->num;
		}

		if (tree) {
			ti = proto_tree_add_item(tree, proto_ldss,
						 tvb, 0, tvb_reported_length(tvb), FALSE);
			ldss_tree = proto_item_add_subtree(ti, ett_ldss_transfer);
		}

		/* Populate digest data into the file struct in the request */
		transfer_info->file = transfer_info->req->file;

		/* Grab each line from the packet, there should be 4 but lets
		 * not walk off the end looking for more. */
		while (offset < tvb_reported_length(tvb)) {
			gint next_offset;
			const guint8 *line;
			int linelen;
			gboolean is_digest_line;
			guint digest_type_len;

			linelen = tvb_find_line_end(tvb, offset,
						    tvb_ensure_length_remaining(tvb, offset), &next_offset,
						    FALSE);

			/* Include new-line in line */
			line = tvb_memdup(tvb, offset, linelen+1); /* XXX - memory leak? */

			if (tree) {
				ti = proto_tree_add_text(ldss_tree, tvb, offset, linelen,
							 "%s",
							 tvb_format_text(tvb, offset, next_offset-offset));
				line_tree = proto_item_add_subtree(ti, ett_ldss_transfer_req);
			}

			/* Reduce code duplication processing digest lines.
			 * There are too many locals to pass to a function - the signature
			 * looked pretty ugly when I tried! */
			is_digest_line = FALSE;

			if (strncmp(line,"md5:",4)==0) {
				is_digest_line = TRUE;
				digest_type_len = 4;
				transfer_info->file->digest_type = DIGEST_TYPE_MD5;
			}
			else if (strncmp(line, "sha1:", 5)==0) {
				is_digest_line = TRUE;
				digest_type_len = 5;
				transfer_info->file->digest_type = DIGEST_TYPE_SHA1;
			}
			else if (strncmp(line, "sha256:", 7)==0) {
				is_digest_line = TRUE;
				digest_type_len = 7;
				transfer_info->file->digest_type = DIGEST_TYPE_SHA256;
			}
			else if (strncmp(line, "unknown:", 8)==0) {
				is_digest_line = TRUE;
				digest_type_len = 8;
				transfer_info->file->digest_type = DIGEST_TYPE_UNKNOWN;
			}
			else if (strncmp(line, "Size: ", 6)==0) {
				/* Sample size line:
				 * Size: 2550\n */
				transfer_info->req->size = g_ascii_strtoull(line+6, NULL, 10);
				if (tree) {
					ti = proto_tree_add_uint64(line_tree, hf_ldss_size,
								   tvb, offset+6, linelen-6, transfer_info->req->size);
					PROTO_ITEM_SET_GENERATED(ti);
				}
			}
			else if (strncmp(line, "Start: ", 7)==0) {
				/* Sample offset line:
				 * Start: 0\n */
				transfer_info->req->offset = g_ascii_strtoull(line+7, NULL, 10);
				if (tree) {
					ti = proto_tree_add_uint64(line_tree, hf_ldss_offset,
								   tvb, offset+7, linelen-7, transfer_info->req->offset);
					PROTO_ITEM_SET_GENERATED(ti);
				}
			}
			else if (strncmp(line, "Compression: ", 13)==0) {
				/* Sample compression line:
				 * Compression: 0\n */
				transfer_info->req->compression = (gint8)strtol(line+13, NULL, 10); /* XXX - bad cast */
				if (tree) {
					ti = proto_tree_add_uint(line_tree, hf_ldss_compression,
								 tvb, offset+13, linelen-13, transfer_info->req->compression);
					PROTO_ITEM_SET_GENERATED(ti);
				}
			}
			else {
				if (tree) {
					ti = proto_tree_add_text(line_tree, tvb, offset, linelen,
								 "Unrecognized line ignored");
					PROTO_ITEM_SET_GENERATED(ti);
				}
			}

			if (is_digest_line) {
				/* Sample digest-type/digest line:
				 * md5:0123456789ABCDEF\n */
				if (!already_dissected) {
					GByteArray *digest_bytes;

					digest_bytes = g_byte_array_new();
					hex_str_to_bytes(
						tvb_get_ptr(tvb, offset+digest_type_len, linelen-digest_type_len),
						digest_bytes, FALSE);

					if(digest_bytes->len >= DIGEST_LEN)
						digest_bytes->len = (DIGEST_LEN-1);
					/* Ensure the digest is zero-padded */
					transfer_info->file->digest = se_alloc0(DIGEST_LEN);
					memcpy(transfer_info->file->digest, digest_bytes->data, digest_bytes->len);

					g_byte_array_free(digest_bytes, TRUE);
				}
				if (tree) {
					proto_item *tii = NULL;

					tii = proto_tree_add_uint(line_tree, hf_ldss_digest_type,
								 tvb, offset, digest_type_len, transfer_info->file->digest_type);
					PROTO_ITEM_SET_GENERATED(tii);
					tii = proto_tree_add_bytes(line_tree, hf_ldss_digest,
								  tvb, offset+digest_type_len, linelen-digest_type_len,
								  transfer_info->file->digest);
					PROTO_ITEM_SET_GENERATED(tii);
				}
			}

			offset = next_offset;
		}

		/* Link forwards to the response for this pull. */
		if (tree && transfer_info->resp_num != 0) {
			ti = proto_tree_add_uint(ldss_tree, hf_ldss_response_in,
						 tvb, 0, 0, transfer_info->resp_num);
			PROTO_ITEM_SET_GENERATED(ti);
		}

		transfer_info->req->num = pinfo->fd->num;
		transfer_info->req->ts = pinfo->fd->abs_ts;
	}
	/* Remaining packets are the file response */
	else {
		guint64 size;
		guint64 offset;
		guint8 compression;

		/* size, digest, compression come from the file request for a pull but
		 * they come from the broadcast for a push. Pushes don't bother
		 * with a file request - they just send the data. We have to get file
		 * info from the offer broadcast which triggered this transfer.
		 * If we cannot find the file request, default to the broadcast. */
		if (transfer_info->broadcast->message_id == MESSAGE_ID_WILLSEND &&
		    transfer_info->req != NULL) {
			transfer_info->file = transfer_info->req->file;
			size = transfer_info->req->size;
			offset = transfer_info->req->offset;
			compression = transfer_info->req->compression;
		}
		else {
			transfer_info->file = transfer_info->broadcast->file;
			size = transfer_info->broadcast->size;
			offset = transfer_info->broadcast->offset;
			compression = transfer_info->broadcast->compression;
		}

		/* Remaining data in this TCP connection is all file data.
		 * Always desegment if the size is 0 (ie. unknown)
		 */
		if (pinfo->can_desegment) {
			if (size == 0 || tvb_length(tvb) < size) {
				pinfo->desegment_offset = 0;
				pinfo->desegment_len = DESEGMENT_UNTIL_FIN;
				return 0;
			}
		}

		/* OK. Now we have the whole file that was transferred. */
		transfer_info->resp_num = pinfo->fd->num;
		transfer_info->resp_ts = pinfo->fd->abs_ts;

		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "LDSS File Transfer (Sending file - %s)",
				     transfer_info->broadcast->message_id == MESSAGE_ID_WILLSEND
				     ? "pull"
				     : "push");
		}

		if (tree) {
			ti = proto_tree_add_item(tree, proto_ldss,
						 tvb, 0, tvb_reported_length(tvb), FALSE);
			ldss_tree = proto_item_add_subtree(ti, ett_ldss_transfer);
			proto_tree_add_bytes_format(ldss_tree, hf_ldss_file_data,
						    tvb, 0, tvb_length(tvb), NULL,
						    compression == COMPRESSION_GZIP
						    ? "Gzip compressed data: %d bytes"
						    : "File data: %d bytes",
						    tvb_length(tvb));
#ifdef HAVE_LIBZ
			/* Be nice and uncompress the file data. */
			if (compression == COMPRESSION_GZIP) {
				tvbuff_t *uncomp_tvb = NULL;
				uncomp_tvb = tvb_uncompress(tvb, 0, tvb_length(tvb));
				if (uncomp_tvb != NULL) {
					proto_tree_add_bytes_format_value(ldss_tree, hf_ldss_file_data,
									  uncomp_tvb, 0, tvb_length(uncomp_tvb),
									  NULL, "Uncompressed data: %d bytes",
									  tvb_length(uncomp_tvb));
				}
			}
#endif
			ti = proto_tree_add_uint(ldss_tree, hf_ldss_digest_type,
						 tvb, 0, 0, transfer_info->file->digest_type);
			PROTO_ITEM_SET_GENERATED(ti);
			if (transfer_info->file->digest != NULL) {
				/* This is ugly. You can't add bytes of nonzero length and have
				 * filtering work correctly unless you give a valid location in
				 * the packet. This hack pretends the first 32 bytes of the packet
				 * are the digest, which they aren't: they're actually the first 32
				 * bytes of the file that was sent. */
				ti = proto_tree_add_bytes(ldss_tree, hf_ldss_digest,
							  tvb, 0, DIGEST_LEN, transfer_info->file->digest);
			}
			PROTO_ITEM_SET_GENERATED(ti);
			ti = proto_tree_add_uint64(ldss_tree, hf_ldss_size,
						   tvb, 0, 0, size);
			PROTO_ITEM_SET_GENERATED(ti);
			ti = proto_tree_add_uint64(ldss_tree, hf_ldss_offset,
						   tvb, 0, 0, offset);
			PROTO_ITEM_SET_GENERATED(ti);
			ti = proto_tree_add_uint(ldss_tree, hf_ldss_compression,
						 tvb, 0, 0, compression);
			PROTO_ITEM_SET_GENERATED(ti);
			/* Link to the request for a pull. */
			if (transfer_info->broadcast->message_id == MESSAGE_ID_WILLSEND &&
			    transfer_info->req != NULL &&
			    transfer_info->req->num != 0) {
				ti = proto_tree_add_uint(ldss_tree, hf_ldss_response_to,
							 tvb, 0, 0, transfer_info->req->num);
				PROTO_ITEM_SET_GENERATED(ti);
			}
		}
	}

	/* Print the pull response time */
	if (transfer_info->broadcast->message_id == MESSAGE_ID_WILLSEND &&
	    transfer_info->req != NULL &&
	    transfer_info->resp_num != 0) {
		nstime_t pull_response_time;
		nstime_delta(&pull_response_time, &transfer_info->resp_ts,
			     &transfer_info->req->ts);
		ti = proto_tree_add_time(ldss_tree, hf_ldss_transfer_response_time,
					 tvb, 0, 0, &pull_response_time);
		PROTO_ITEM_SET_GENERATED(ti);
	}

	/* Link the transfer back to the initiating broadcast. Response time is
	 * calculated as the time from broadcast to completed transfer. */
	ti = proto_tree_add_uint(ldss_tree, hf_ldss_initiated_by,
				 tvb, 0, 0, transfer_info->broadcast->num);
	PROTO_ITEM_SET_GENERATED(ti);

	if (transfer_info->resp_num != 0) {
		nstime_delta(&broadcast_response_time, &transfer_info->resp_ts,
			     &transfer_info->broadcast->ts);
		ti = proto_tree_add_time(ldss_tree, hf_ldss_transfer_completed_in,
					 tvb, 0, 0, &broadcast_response_time);
		PROTO_ITEM_SET_GENERATED(ti);
	}

	/* This conv got its addr2/port2 set by the TCP dissector because a TCP
	 * connection was established. Make a new one to handle future connections
	 * to the addr/port mentioned in the broadcast, because that socket is
	 * still open. */
	if (transfer_tcpinfo->seq == 1 &&
	    transfer_tcpinfo->lastackseq == 1) {

		prepare_ldss_transfer_conv(transfer_info->broadcast);
	}

	return tvb_length(tvb);
}

static gboolean
is_broadcast(address* addr)
{
	static address broadcast_addr;
	static const guint8 broadcast_addr_bytes[6] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	SET_ADDRESS(&broadcast_addr, AT_ETHER, 6, broadcast_addr_bytes);
	return ADDRESSES_EQUAL(addr, &broadcast_addr);
}

static int
dissect_ldss (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (is_broadcast(&pinfo->dl_dst) &&
	    pinfo->ipproto == IP_PROTO_UDP) {

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDSS");
		return dissect_ldss_broadcast(tvb, pinfo, tree);
	}
	else if (pinfo->ipproto == IP_PROTO_TCP) {

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDSS");
		return dissect_ldss_transfer(tvb, pinfo, tree);
	}
	else {
		/* Definitely not LDSS */
		return 0;
	}
}

/* Initialize the highest num seen each time a
 * new file is loaded or re-loaded in wireshark */
static void
ldss_init_protocol(void)
{
	/* We haven't dissected anything yet. */
	highest_num_seen = 0;
}

void
proto_register_ldss (void) {
	static hf_register_info hf[] =	{
		{   &hf_ldss_message_id,
		    {	"LDSS Message ID",
			"ldss.message_id",
			FT_UINT16, BASE_DEC, ldss_message_id_value, 0x0,
			NULL, HFILL
		    }
		},
		{   &hf_ldss_message_detail,
		    {	"Inferred meaning",
			"ldss.inferred_meaning",
			FT_UINT16, BASE_DEC, ldss_inferred_value, 0x0,
			"Inferred meaning of the packet", HFILL
		    }
		},
		{   &hf_ldss_digest_type,
		    {	"Digest Type",
			"ldss.digest_type",
			FT_UINT8, BASE_DEC, ldss_digest_type_value, 0x0,
			NULL, HFILL
		    }
		},
		{   &hf_ldss_compression,
		    {	"Compressed Format",
			"ldss.compression",
			FT_UINT8, BASE_DEC, ldss_compression_value, 0x0,
			NULL, HFILL
		    }
		},
		{   &hf_ldss_cookie,
		    {	"Cookie",
			"ldss.cookie",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Random value used for duplicate rejection", HFILL
		    }
		},
		{   &hf_ldss_digest,
		    {	"Digest",
			"ldss.digest",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Digest of file padded with 0x00", HFILL
		    }
		},
		{   &hf_ldss_size,
		    {	"Size",
			"ldss.size",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"Size of complete file", HFILL
		    }
		},
		{   &hf_ldss_offset,
		    {	"Offset",
			"ldss.offset",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"Size of currently available portion of file", HFILL
		    }
		},
		{   &hf_ldss_target_time,
		    {	"Target time (relative)",
			"ldss.target_time",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Time until file will be needed/available", HFILL
		    }
		},
		{   &hf_ldss_reserved_1,
		    {	"Reserved",
			"ldss.reserved_1",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Unused field - should be 0x00000000", HFILL
		    }
		},
		{   &hf_ldss_port,
		    {	"Port",
			"ldss.port",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"TCP port for push (Need file) or pull (Will send)", HFILL
		    }
		},
		{   &hf_ldss_rate,
		    {	"Rate (B/s)",
			"ldss.rate",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Estimated current download rate", HFILL
		    }
		},
		{   &hf_ldss_priority,
		    {	"Priority",
			"ldss.priority",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL
		    }
		},
		{   &hf_ldss_property_count,
		    {	"Property Count",
			"ldss.property_count",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL
		    }
		},
		{   &hf_ldss_properties,
		    {	"Properties",
			"ldss.properties",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL
		    }
		},
		{   &hf_ldss_file_data,
		    {	"File data",
			"ldss.file_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL
		    }
		},
		{   &hf_ldss_response_in,
		    { "Response In",
		      "ldss.response_in",
		      FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		      "The response to this file pull request is in this frame", HFILL }
		},
		{   &hf_ldss_response_to,
		    { "Request In",
		      "ldss.response_to",
		      FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		      "This is a response to the file pull request in this frame", HFILL }
		},
		{   &hf_ldss_initiated_by,
		    { "Initiated by",
		      "ldss.initiated_by",
		      FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		      "The broadcast that initiated this file transfer", HFILL }
		},
		{   &hf_ldss_transfer_response_time,
		    { "Transfer response time",
		      "ldss.transfer_response_time",
		      FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		      "The time between the request and the response for a pull transfer", HFILL }
		},
		{   &hf_ldss_transfer_completed_in,
		    { "Transfer completed in",
		      "ldss.transfer_completed_in",
		      FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		      "The time between requesting the file and completion of the file transfer", HFILL }
		}
	};

	static gint  *ett[] = { &ett_ldss_broadcast, &ett_ldss_transfer, &ett_ldss_transfer_req };

	module_t     *ldss_module;

	proto_ldss = proto_register_protocol(	"Local Download Sharing Service",
						"LDSS", "ldss");
	proto_register_field_array(proto_ldss, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ldss_module = prefs_register_protocol(	proto_ldss,
						proto_reg_handoff_ldss);
	prefs_register_uint_preference(		ldss_module, "udp_port",
						"LDSS UDP Port",
						"The UDP port on which "
						"Local Download Sharing Service "
						"broadcasts will be sent",
						10, &global_udp_port_ldss);

	register_init_routine(&ldss_init_protocol);
}


/* The registration hand-off routine */
void
proto_reg_handoff_ldss (void)
{
	static guint	  saved_udp_port_ldss;
	static gboolean	  ldss_initialized	= FALSE;

	if (!ldss_initialized) {
		ldss_handle = new_create_dissector_handle(dissect_ldss, proto_ldss);
		ldss_initialized = TRUE;
	}
	else {
		dissector_delete_uint("udp.port", saved_udp_port_ldss, ldss_handle);
	}
	dissector_add_uint("udp.port", global_udp_port_ldss, ldss_handle);
	saved_udp_port_ldss = global_udp_port_ldss;
}
