/* etherpeek.c
 * Routines for opening etherpeek files
 * Copyright (c) 2001, Daniel Thompson <d.thompson@gmx.net>
 *
 * $Id: etherpeek.c,v 1.3 2001/03/10 06:33:57 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "etherpeek.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* CREDITS
 *
 * This file decoder could not have been writen without examining how
 * tcptrace (http://www.tcptrace.org/) handles etherpeek files.
 */

/* master header */
typedef struct etherpeek_master_header {
	guint8  version;
	guint8  status;
} etherpeek_master_header_t;
#define ETHERPEEK_MASTER_HDR_SIZE 2

/* secondary header (Mac V5,V6,V7) */
typedef struct etherpeek_m567_header {
	guint32 filelength;
	guint32 numPackets;
	guint32 timeDate;
	guint32 timeStart;
	guint32 timeStop;
	guint32 reserved[7];
} etherpeek_m567_header_t;
#define ETHERPEEK_M567_HDR_SIZE 48

/* full header */
typedef struct etherpeek_header {
	etherpeek_master_header_t master;
	union {
		etherpeek_m567_header_t m567;
	} secondary;
} etherpeek_header_t;

/* packet header (Mac V5, V6) */
typedef struct etherpeek_m56_packet {
	guint16 length;
	guint16 sliceLength;
	guint8  flags;
	guint8  status;
	guint32 timestamp;
	guint16 destNum;
	guint16 srcNum;
	guint16 protoNum;
	char    protoStr[8];
} etherpeek_m56_packet_t;
#define ETHERPEEK_M56_PKT_SIZE 24

/* 64-bit time in micro seconds from the (Mac) epoch */
typedef struct etherpeek_utime {
	guint32 upper;
	guint32 lower;
} etherpeek_utime;

/* packet header (Mac V7) */
typedef struct etherpeek_m7_packet {
	guint16 protoNum;
	guint16 length;
	guint16 sliceLength;
	guint8  flags;
	guint8  status;
	etherpeek_utime
	        timestamp;
} etherpeek_m7_packet_t;
#define ETHERPEEK_M7_PKT_SIZE 16

typedef struct etherpeek_encap_lookup {
	guint16 protoNum;
	int     encap;
} etherpeek_encap_lookup_t;

static const unsigned int mac2unix = 2082844800u;
static const etherpeek_encap_lookup_t etherpeek_encap[] = {
	{ 1400, WTAP_ENCAP_ETHERNET }
};
#define NUM_ETHERPEEK_ENCAPS \
	(sizeof (etherpeek_encap) / sizeof (etherpeek_encap[0]))

static gboolean etherpeek_read_m7(wtap *wth, int *err, int *data_offset);
static gboolean etherpeek_read_m56(wtap *wth, int *err, int *data_offset);

int etherpeek_open(wtap *wth, int *err)
{
	etherpeek_header_t ep_hdr;

	/* etherpeek files to not start with a magic value large enough
	 * to be unique hence we use the following algorithm to determine
	 * the type of an unknown file
	 *  - populate the master header and reject file if there is no match
	 *  - populate the secondary header and check that the reserved space
	 *      is zero; there is an obvious flaw here so this algorithm will
	 *      probably need to be revisiting when improving etherpeek
	 *      support
	 */
	
	g_assert(sizeof(ep_hdr.master) == ETHERPEEK_MASTER_HDR_SIZE);
	wtap_file_read_unknown_bytes(
		&ep_hdr.master, sizeof(ep_hdr.master), wth->fh, err);
	wth->data_offset += sizeof(ep_hdr.master);

	/* switch on the file version */
	switch (ep_hdr.master.version) {
		case 5:
		case 6:
		case 7:
			/* get the secondary header */
			g_assert(sizeof(ep_hdr.secondary.m567) ==
			        ETHERPEEK_M567_HDR_SIZE);
			wtap_file_read_unknown_bytes(
				&ep_hdr.secondary.m567,
				sizeof(ep_hdr.secondary.m567), wth->fh, err);
			wth->data_offset += sizeof(ep_hdr.secondary.m567);
			
			if ((0 != ep_hdr.secondary.m567.reserved[0]) ||
			    (0 != ep_hdr.secondary.m567.reserved[1]) ||
			    (0 != ep_hdr.secondary.m567.reserved[2]) ||
			    (0 != ep_hdr.secondary.m567.reserved[3])) {
				/* still unknown */
				return 0;
			}

			/* we have a match for a Mac V5, V6 or V7,
			 * so it is worth preforming byte swaps
			 */
			ep_hdr.secondary.m567.filelength =
				ntohl(ep_hdr.secondary.m567.filelength);
			ep_hdr.secondary.m567.numPackets =
				ntohl(ep_hdr.secondary.m567.numPackets);
			ep_hdr.secondary.m567.timeDate =
				ntohl(ep_hdr.secondary.m567.timeDate);
			ep_hdr.secondary.m567.timeStart =
				ntohl(ep_hdr.secondary.m567.timeStart);
			ep_hdr.secondary.m567.timeStop =
				ntohl(ep_hdr.secondary.m567.timeStop);

			/* populate the pseudo header */
			wth->pseudo_header.etherpeek.reference_time.tv_sec  =
				ep_hdr.secondary.m567.timeDate - mac2unix;
			wth->pseudo_header.etherpeek.reference_time.tv_usec =
				0;
			break;
		default:
			return 0;
	}

	/* at this point we have recognised the file type and have populated
	 * the whole ep_hdr structure in host byte order
	 */
	
	switch (ep_hdr.master.version) {
		case 5:
		case 6:
			wth->file_type = WTAP_FILE_ETHERPEEK_MAC_V56;
			wth->subtype_read = etherpeek_read_m56;
			wth->subtype_seek_read = wtap_def_seek_read;
			break;
		case 7:
			wth->file_type = WTAP_FILE_ETHERPEEK_MAC_V7;
			wth->subtype_read = etherpeek_read_m7;
			wth->subtype_seek_read = wtap_def_seek_read;
			break;
		default:
			/* this is impossible */
			g_assert_not_reached();
	};

	wth->file_encap	       = WTAP_ENCAP_PER_PACKET;
	wth->snapshot_length   = 16384; /* just guessing */

	return 1;
}

static gboolean etherpeek_read_m7(wtap *wth, int *err, int *data_offset)
{
	etherpeek_m7_packet_t ep_pkt;
	double  t;
	int i;

	g_assert(sizeof(ep_pkt) == ETHERPEEK_M7_PKT_SIZE);
	wtap_file_read_expected_bytes(&ep_pkt, sizeof(ep_pkt), wth->fh, err);
	wth->data_offset += sizeof(ep_pkt);

	/* byte swaps */
	ep_pkt.protoNum = ntohs(ep_pkt.protoNum);
	ep_pkt.length = ntohs(ep_pkt.length);
	ep_pkt.sliceLength = ntohs(ep_pkt.sliceLength);
	ep_pkt.timestamp.upper = ntohl(ep_pkt.timestamp.upper);
	ep_pkt.timestamp.lower = ntohl(ep_pkt.timestamp.lower);

	/* force sliceLength to be the actual length of the packet */
	if (0 == ep_pkt.sliceLength) {
		ep_pkt.sliceLength = ep_pkt.length;
	}

	/* test for corrupt data */
	if (ep_pkt.sliceLength > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	*data_offset = wth->data_offset;

	/* read the frame data */
	buffer_assure_space(wth->frame_buffer, ep_pkt.sliceLength);
	wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
	                              ep_pkt.sliceLength, wth->fh, err);
	wth->data_offset += ep_pkt.sliceLength;
	
	/* fill in packet header values */
	wth->phdr.len    = ep_pkt.length;
	wth->phdr.caplen = ep_pkt.sliceLength;
	
	t =  (double) ep_pkt.timestamp.lower +
	     (double) ep_pkt.timestamp.upper * 4294967296.0;
	t -= (double) mac2unix * 1000000.0;
	wth->phdr.ts.tv_sec  = (time_t)  (t/1000000.0);
	wth->phdr.ts.tv_usec = (guint32) (t - (double) wth->phdr.ts.tv_sec *
	                                               1000000.0);
	wth->phdr.pkt_encap = WTAP_ENCAP_UNKNOWN;
	for (i=0; i<NUM_ETHERPEEK_ENCAPS; i++) {
		if (etherpeek_encap[i].protoNum == ep_pkt.protoNum) {
			wth->phdr.pkt_encap = etherpeek_encap[i].encap;
		}
	}

	return TRUE;
}

static gboolean etherpeek_read_m56(wtap *wth, int *err, int *data_offset)
{
	etherpeek_m56_packet_t ep_pkt;
	int i;

	g_assert(sizeof(ep_pkt) == ETHERPEEK_M56_PKT_SIZE);
	wtap_file_read_expected_bytes(&ep_pkt, sizeof(ep_pkt), wth->fh, err);
	wth->data_offset += sizeof(ep_pkt);

	/* byte swaps */
	ep_pkt.length = ntohs(ep_pkt.length);
	ep_pkt.sliceLength = ntohs(ep_pkt.sliceLength);
	ep_pkt.timestamp = ntohl(ep_pkt.timestamp);
	ep_pkt.destNum = ntohs(ep_pkt.destNum);
	ep_pkt.srcNum = ntohs(ep_pkt.srcNum);
	ep_pkt.protoNum = ntohs(ep_pkt.protoNum);

	/* force sliceLength to be the actual length of the packet */
	if (0 == ep_pkt.sliceLength) {
		ep_pkt.sliceLength = ep_pkt.length;
	}

	/* test for corrupt data */
	if (ep_pkt.sliceLength > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	*data_offset = wth->data_offset;

	/* fill in packet header values */
	wth->phdr.len        = ep_pkt.length;
	wth->phdr.caplen     = ep_pkt.sliceLength;
	/* timestamp is in milliseconds since reference_time */
	wth->phdr.ts.tv_sec  = wth->pseudo_header.etherpeek.
		reference_time.tv_sec + (ep_pkt.timestamp / 1000);
	wth->phdr.ts.tv_usec = 1000 * (ep_pkt.timestamp % 1000);
	
	wth->phdr.pkt_encap = WTAP_ENCAP_UNKNOWN;
	for (i=0; i<NUM_ETHERPEEK_ENCAPS; i++) {
		if (etherpeek_encap[i].protoNum == ep_pkt.protoNum) {
			wth->phdr.pkt_encap = etherpeek_encap[i].encap;
		}
	}

	return TRUE;
}
