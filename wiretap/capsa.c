/* capsa.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "capsa.h"

/*
 * A file begins with a header containing:
 *
 *   a 4-byte magic number, with 'c', 'p', 's', 'e';
 *
 *   either a 2-byte little-endian "format indicator" (version number?),
 *   or a 1-byte major version number followed by a 1-byte minor version
 *   number, or a 1-byte "format indicator" followed by something else
 *   that's always been 0;
 *
 *   a 2-byte 0xe8 0x03 (1000 - a data rate?  megabits/second?)
 *
 *   4 bytes of 0x01 0x00 0x01 0x00;
 *
 *   either a 4-byte little-endian file size followed by 0x00 0x00 0x00 0x00
 *   or an 8-byte little-endian file size;
 *
 *   a 4-byte little-endian packet count (in dns_error_of_udp, it exceeds?)
 *
 *   a 4-byte little-endian number?
 *
 *   hex 2c 01 c8 00 00 00 da 36 00 00 00 00 00 00;
 *
 *   the same 4-byte little-endian number as above (yes, misaligned);
 *
 *   0x01 or 0x03;
 *
 *   a bunch of 0s, up to an offset of 0x36d6;
 *
 *   more stuff.
 *
 * Following that is a sequence of { record offset block, up to 200 records }
 * pairs.
 *
 * A record offset block has 1 byte with the value 0xfe, a sequence of
 * up to 200 4-byte little-endian record offsets, and 4 or more bytes
 * of unknown data, making the block 805 bytes long.
 *
 * The record offsets are offsets, from the beginning of the record offset
 * block (i.e., from the 0xfe byte), of the records following the block.
 */

/* Magic number in Capsa files. */
static const char capsa_magic[] = {
	'c', 'p', 's', 'e'
};

/*
 * Before each group of 200 or fewer records there's a block of frame
 * offsets, giving the offsets, from the beginning of that block minus
 * one(1), of the next N records.
 */
#define N_RECORDS_PER_GROUP	200

/* Capsa (format indicator 1) record header. */
struct capsarec_hdr {
	guint32 unknown1;	/* low-order 32 bits of a number? */
	guint32 unknown2;	/* 0x00 0x00 0x00 0x00 */
	guint32 timestamplo;	/* low-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	guint32 timestamphi;	/* high-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	guint16	rec_len;	/* length of record */
	guint16	incl_len;	/* number of octets captured in file */
	guint16	orig_len;	/* actual length of packet */
	guint16 unknown5;	/* 0x00 0x00 */
	guint8 count1;		/* count1*4 bytes after unknown8 */
	guint8 count2;		/* count2*4 bytes after that */
	guint16 unknown7;	/* 0x01 0x10 */
	guint32 unknown8;	/* 0x00 0x00 0x00 0x00 or random numbers */
};

/* Packet Builder (format indicator 2) record header. */
struct pbrec_hdr {
	guint16	rec_len;	/* length of record */
	guint16	incl_len;	/* number of octets captured in file */
	guint16	orig_len;	/* actual length of packet */
	guint16 unknown1;
	guint16 unknown2;
	guint16 unknown3;
	guint32 unknown4;
	guint32 timestamplo;	/* low-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	guint32 timestamphi;	/* high-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	guint32 unknown5;
	guint32 unknown6;
};

typedef struct {
	guint16 format_indicator;
	guint32 number_of_frames;
	guint32 frame_count;
	gint64 base_offset;
	guint32 record_offsets[N_RECORDS_PER_GROUP];
} capsa_t;

static gboolean capsa_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean capsa_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);
static int capsa_read_packet(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info);

wtap_open_return_val capsa_open(wtap *wth, int *err, gchar **err_info)
{
	char magic[sizeof capsa_magic];
	guint16 format_indicator;
	int file_type_subtype;
	guint32 number_of_frames;
	capsa_t *capsa;

	/* Read in the string that should be at the start of a Capsa file */
	if (!wtap_read_bytes(wth->fh, magic, sizeof magic, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(magic, capsa_magic, sizeof capsa_magic) != 0) {
		return WTAP_OPEN_NOT_MINE;
	}

	/* Read the mysterious "format indicator" */
	if (!wtap_read_bytes(wth->fh, &format_indicator, sizeof format_indicator,
	    err, err_info))
		return WTAP_OPEN_ERROR;
	format_indicator = GUINT16_FROM_LE(format_indicator);

	/*
	 * Make sure it's a format we support.
	 */
	switch (format_indicator) {

	case 1:		/* Capsa */
		file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_COLASOFT_CAPSA;
		break;

	case 2:		/* Packet Builder */
		file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_COLASOFT_PACKET_BUILDER;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("capsa: format indicator %u unsupported",
		    format_indicator);
		return WTAP_OPEN_ERROR;
	}

	/*
	 * Link speed, in megabytes/second?
	 */
	if (!file_skip(wth->fh, 2, err))
		return WTAP_OPEN_ERROR;

	/*
	 * Flags of some sort?  Four 1-byte numbers, two of which are 1
	 * and two of which are zero?  Two 2-byte numbers or flag fields,
	 * both of which are 1?
	 */
	if (!file_skip(wth->fh, 4, err))
		return WTAP_OPEN_ERROR;

	/*
	 * File size, in bytes.
	 */
	if (!file_skip(wth->fh, 4, err))
		return WTAP_OPEN_ERROR;

	/*
	 * Zeroes?  Or upper 4 bytes of file size?
	 */
	if (!file_skip(wth->fh, 4, err))
		return WTAP_OPEN_ERROR;

	/*
	 * Count of packets.
	 */
	if (!wtap_read_bytes(wth->fh, &number_of_frames, sizeof number_of_frames,
	    err, err_info))
		return WTAP_OPEN_ERROR;
	number_of_frames = GUINT32_FROM_LE(number_of_frames);

	/*
	 * Skip past what we think is file header.
	 */
	if (!file_seek(wth->fh, 0x44ef, SEEK_SET, err))
		return WTAP_OPEN_ERROR;

	wth->file_type_subtype = file_type_subtype;
	capsa = (capsa_t *)g_malloc(sizeof(capsa_t));
	capsa->format_indicator = format_indicator;
	capsa->number_of_frames = number_of_frames;
	capsa->frame_count = 0;
	wth->priv = (void *)capsa;
	wth->subtype_read = capsa_read;
	wth->subtype_seek_read = capsa_seek_read;
	/*
	 * XXX - we've never seen a Wi-Fi Capsa capture, so we don't
	 * yet know how to handle them.
	 */
	wth->file_encap = WTAP_ENCAP_ETHERNET;
	wth->snapshot_length = 0;	/* not available in header */
	wth->file_tsprec = WTAP_TSPREC_USEC;
	return WTAP_OPEN_MINE;
}

/* Read the next packet */
static gboolean capsa_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	capsa_t *capsa = (capsa_t *)wth->priv;
	guint32 frame_within_block;
	int	padbytes;

	if (capsa->frame_count == capsa->number_of_frames) {
		/*
		 * No more frames left.  Return an EOF.
		 */
		*err = 0;
		return FALSE;
	}
	frame_within_block = capsa->frame_count % N_RECORDS_PER_GROUP;
	if (frame_within_block == 0) {
		/*
		 * Here's a record offset block.
		 * Get the offset of the block, and then skip the
		 * first byte.
		 */
		capsa->base_offset = file_tell(wth->fh);
		if (!file_skip(wth->fh, 1, err))
			return FALSE;

		/*
		 * Now read the record offsets.
		 */
		if (!wtap_read_bytes(wth->fh, &capsa->record_offsets,
		    sizeof capsa->record_offsets, err, err_info))
			return FALSE;

		/*
		 * And finish processing all 805 bytes by skipping
		 * the last 4 bytes.
		 */
		if (!file_skip(wth->fh, 4, err))
			return FALSE;
	}

	*data_offset = capsa->base_offset +
	    GUINT32_FROM_LE(capsa->record_offsets[frame_within_block]);
	if (!file_seek(wth->fh, *data_offset, SEEK_SET, err))
		return FALSE;

	padbytes = capsa_read_packet(wth, wth->fh, &wth->phdr,
	    wth->frame_buffer, err, err_info);
	if (padbytes == -1)
		return FALSE;

	/*
	 * Skip over the padding, if any.
	 */
	if (padbytes != 0) {
		if (!file_skip(wth->fh, padbytes, err))
			return FALSE;
	}

	capsa->frame_count++;

	return TRUE;
}

static gboolean
capsa_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (capsa_read_packet(wth, wth->random_fh, phdr, buf, err, err_info) == -1) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

static int
capsa_read_packet(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
	capsa_t *capsa = (capsa_t *)wth->priv;
	struct capsarec_hdr capsarec_hdr;
	struct pbrec_hdr pbrec_hdr;
	guint32 rec_size;
	guint32	packet_size;
	guint32 orig_size;
	guint32 header_size;
	guint64 timestamp;

	/* Read record header. */
	switch (capsa->format_indicator) {

	case 1:
		if (!wtap_read_bytes_or_eof(fh, &capsarec_hdr,
		    sizeof capsarec_hdr, err, err_info))
			return -1;
		rec_size = GUINT16_FROM_LE(capsarec_hdr.rec_len);
		orig_size = GUINT16_FROM_LE(capsarec_hdr.orig_len);
		packet_size = GUINT16_FROM_LE(capsarec_hdr.incl_len);
		header_size = sizeof capsarec_hdr;
		timestamp = (((guint64)GUINT32_FROM_LE(capsarec_hdr.timestamphi))<<32) + GUINT32_FROM_LE(capsarec_hdr.timestamplo);

		/*
		 * OK, the rest of this is variable-length.
		 * We skip: (count1+count2)*4 bytes.
		 * XXX - what is that?  Measured statistics?
		 * Calculated statistics?
		 */
		if (!file_skip(fh, (capsarec_hdr.count1 + capsarec_hdr.count2)*4,
		    err))
			return -1;
		header_size += (capsarec_hdr.count1 + capsarec_hdr.count2)*4;
		break;

	case 2:
		if (!wtap_read_bytes_or_eof(fh, &pbrec_hdr,
		    sizeof pbrec_hdr, err, err_info))
			return -1;
		rec_size = GUINT16_FROM_LE(pbrec_hdr.rec_len);
		orig_size = GUINT16_FROM_LE(pbrec_hdr.orig_len);
		packet_size = GUINT16_FROM_LE(pbrec_hdr.incl_len);
		header_size = sizeof pbrec_hdr;
		timestamp = (((guint64)GUINT32_FROM_LE(pbrec_hdr.timestamphi))<<32) + GUINT32_FROM_LE(pbrec_hdr.timestamplo);
		/*
		 * XXX - from the results of some conversions between
		 * Capsa format and pcap by Colasoft Packet Builder,
		 * I do not trust its conversion of time stamps (at
		 * least one of Colasoft's sample files, when
		 * converted to pcap format, has, as its time stamps,
		 * time stamps on the day after the conversion was
		 * done, which seems like more than just coincidence).
		 */
		break;

	default:
		g_assert_not_reached();
		*err = WTAP_ERR_INTERNAL;
		return -1;
	}
	if (orig_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("capsa: File has %u-byte original length, bigger than maximum of %u",
		    orig_size, WTAP_MAX_PACKET_SIZE);
		return -1;
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("capsa: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		return -1;
	}
	if (header_size + packet_size > rec_size) {
		/*
		 * Probably a corrupt capture file.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("capsa: File has %u-byte packet with %u-byte record header, bigger than record size %u",
		    packet_size, header_size, rec_size);
		return -1;
	}

	/*
	 * The "on the wire" record size always includes the CRC.
	 * If it's greater than the "captured" size by 4, then
	 * we subtract 4 from it, to reflect the way the "on the wire"
	 * record size works for other file formats.
	 */
	if (orig_size == packet_size + 4)
		orig_size = packet_size;

	/*
	 * We assume there's no FCS in this frame.
	 * XXX - is there ever one?
	 */
	phdr->pseudo_header.eth.fcs_len = 0;

	phdr->rec_type = REC_TYPE_PACKET;
	phdr->caplen = packet_size;
	phdr->len = orig_size;
	phdr->presence_flags = WTAP_HAS_CAP_LEN|WTAP_HAS_TS;
	phdr->ts.secs = (time_t)(timestamp / 1000000);
	phdr->ts.nsecs = ((int)(timestamp % 1000000))*1000;

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(fh, buf, packet_size, err, err_info))
		return -1;	/* failed */

	return rec_size - (header_size + packet_size);
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
