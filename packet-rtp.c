/* packet-rtp.c
 * Routines for RTP packet disassembly
 *
 * Jason Lango <jal@netapp.com>
 *
 * $Id: packet-rtp.c,v 1.4 2000/05/31 05:07:37 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
 */

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <ctype.h>
#include <stddef.h>

#include <glib.h>
#include "packet.h"
#include "packet-rtp.h"

static int proto_rtp = -1;

static gint ett_rtp = -1;

#define _RTP_FLAG_BITS(hdr, s, n) \
	((u_int)(((hdr)->rtp_flag_bits >> (8 - (s) - (n))) & ((1 << (n)) - 1)))
#define RTP_VERSION(hdr)	_RTP_FLAG_BITS(hdr, 0, 2)
#define RTP_PADDING(hdr)	_RTP_FLAG_BITS(hdr, 2, 1)
#define RTP_EXTENSION(hdr)	_RTP_FLAG_BITS(hdr, 3, 1)
#define RTP_CSRC_COUNT(hdr)	_RTP_FLAG_BITS(hdr, 4, 4)

#define RTP_MARKER(hdr)		((u_int)((hdr)->rtp_type_bits >> 7))
#define RTP_PAYLOAD_TYPE(hdr)	((u_int)((hdr)->rtp_type_bits & 0x7F))

typedef struct rtp_hdr {
	guint8	rtp_flag_bits;
	guint8	rtp_type_bits;
	guint16	rtp_seq;
	guint32	rtp_timestamp;
	guint32	rtp_ssrc;
} rtp_hdr_t;

typedef struct rtp_hdr_ext {
	guint16	rtp_ext_app;	/* defined by RTP profile */
	guint16	rtp_ext_length;	/* length of extension data in 32 bit words */
} rtp_hdr_ext_t;

void
dissect_rtp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*rtp_tree;
	proto_item	*ti;
	const u_char	*data, *dataend;
	rtp_hdr_t	hdr;
	int		end_offset;
	int		ii;
	guint32		*csrc_ptr;
	rtp_hdr_ext_t	ext;

	data = &pd[offset];
	dataend = data + END_OF_FRAME;
	end_offset = offset + END_OF_FRAME;

	memcpy(&hdr, data, END_OF_FRAME < sizeof(rtp_hdr_t) ?
		END_OF_FRAME : sizeof(rtp_hdr_t));
	hdr.rtp_seq = ntohs(hdr.rtp_seq);
	hdr.rtp_timestamp = ntohl(hdr.rtp_timestamp);
	hdr.rtp_ssrc = ntohl(hdr.rtp_ssrc);

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RTP");
	if (check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "SSRC=%lu, Seq=%u, Time=%lu%s",
			(u_long) hdr.rtp_ssrc,
			(u_int) hdr.rtp_seq,
			(u_long) hdr.rtp_timestamp,
			RTP_MARKER(&hdr) ? ", Mark" : "");
	}

	rtp_tree = NULL;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rtp, NullTVB, offset, END_OF_FRAME,
			FALSE);
		rtp_tree = proto_item_add_subtree(ti, ett_rtp);
	}

	if (!rtp_tree)
		return;

	if (offset >= end_offset)
		goto bad_len;
	proto_tree_add_text(rtp_tree, NullTVB, offset, 1, "Version: %u (%s)",
		RTP_VERSION(&hdr),
		RTP_VERSION(&hdr) == 3 ? "New Unknown Version" :
		RTP_VERSION(&hdr) == 2 ? "RFC 1889 Version" :
		RTP_VERSION(&hdr) == 1 ? "First Draft Version" :
		"Old Vat Version");
	proto_tree_add_text(rtp_tree, NullTVB, offset, 1, "Padding: %u",
		RTP_PADDING(&hdr));
	proto_tree_add_text(rtp_tree, NullTVB, offset, 1, "Extension: %u",
		RTP_EXTENSION(&hdr));
	proto_tree_add_text(rtp_tree, NullTVB, offset, 1, "CSRC Count: %u",
		RTP_CSRC_COUNT(&hdr));
	offset++;

	if (offset >= end_offset)
		goto bad_len;
	proto_tree_add_text(rtp_tree, NullTVB, offset, 1, "Marker: %u",
		RTP_MARKER(&hdr));
	proto_tree_add_text(rtp_tree, NullTVB, offset, 1, "Payload Type: %u",
		RTP_PAYLOAD_TYPE(&hdr));
	offset++;

	if (offset >= end_offset)
		goto bad_len;
	proto_tree_add_text(rtp_tree, NullTVB, offset, 2, "Seq: %u",
		(u_int) hdr.rtp_seq);
	offset += 2;

	if (offset >= end_offset)
		goto bad_len;
	proto_tree_add_text(rtp_tree, NullTVB, offset, 4, "Timestamp: %lu",
		(u_long) hdr.rtp_timestamp);
	offset += 4;

	if (offset >= end_offset)
		goto bad_len;
	proto_tree_add_text(rtp_tree, NullTVB, offset, 4, "SSRC: %lu",
		(u_long) hdr.rtp_ssrc);
	offset += 4;

	csrc_ptr = (guint32*) (data + sizeof(rtp_hdr_t));
	for (ii = 0; ii < RTP_CSRC_COUNT(&hdr); ii++) {
		guint32 csrc;
		if (offset >= end_offset)
			goto bad_len;
		csrc = pntohl(csrc_ptr);
		proto_tree_add_text(rtp_tree, NullTVB, offset, 4, "CSRC %d: %lu",
			ii + 1, (u_long) csrc);
		offset += 4;
		csrc_ptr++;
	}

	if (RTP_EXTENSION(&hdr)) {
		memcpy(&ext, data + sizeof(rtp_hdr_t),
			END_OF_FRAME < sizeof(rtp_hdr_ext_t) ?
			END_OF_FRAME : sizeof(rtp_hdr_ext_t));
		ext.rtp_ext_app = ntohs(ext.rtp_ext_app);
		ext.rtp_ext_length = ntohs(ext.rtp_ext_length);

		proto_tree_add_text(rtp_tree, NullTVB, offset, 2,
			"Extension-defined: %x", (u_int) ext.rtp_ext_app);
		offset += 2;
		proto_tree_add_text(rtp_tree, NullTVB, offset, 2,
			"Extension length: %u", (u_int) ext.rtp_ext_length);
		offset += 2;
		proto_tree_add_text(rtp_tree, NullTVB, offset, 4 * ext.rtp_ext_length,
			"Extension Data (%d bytes)",
			(int) 4 * ext.rtp_ext_length);
		offset += 4 * ext.rtp_ext_length;
	}

	proto_tree_add_text(rtp_tree, NullTVB, offset, END_OF_FRAME,
		"Data (%d bytes)", END_OF_FRAME);

	return;

bad_len:
	proto_tree_add_text(rtp_tree, NullTVB, end_offset, 0,
		"Unexpected end of packet");
}

void
proto_register_rtp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "rtp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_rtp,
	};

	proto_rtp = proto_register_protocol("Realtime Transport Protocol", "rtp");
 /*       proto_register_field_array(proto_rtp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
