/* capsa.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "capsa.h"

#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/ws_assert.h>

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
	uint32_t unknown1;	/* low-order 32 bits of a number? */
	uint32_t unknown2;	/* 0x00 0x00 0x00 0x00 */
	uint32_t timestamplo;	/* low-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	uint32_t timestamphi;	/* high-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	uint16_t rec_len;	/* length of record */
	uint16_t incl_len;	/* number of octets captured in file */
	uint16_t orig_len;	/* actual length of packet */
	uint16_t unknown5;	/* 0x00 0x00 */
	uint8_t  count1;	/* count1*4 bytes after unknown8 */
	uint8_t  count2;	/* count2*4 bytes after that */
	uint16_t unknown7;	/* 0x01 0x10 */
	uint32_t unknown8;	/* 0x00 0x00 0x00 0x00 or random numbers */
};

/* Packet Builder (format indicator 2) record header. */
struct pbrec_hdr {
	uint16_t rec_len;	/* length of record */
	uint16_t incl_len;	/* number of octets captured in file */
	uint16_t orig_len;	/* actual length of packet */
	uint16_t unknown1;
	uint16_t unknown2;
	uint16_t unknown3;
	uint32_t unknown4;
	uint32_t timestamplo;	/* low-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	uint32_t timestamphi;	/* high-order 32 bits of the time stamp, in microseconds since January 1, 1970, 00:00:00 UTC */
	uint32_t unknown5;
	uint32_t unknown6;
};

typedef struct {
	uint16_t format_indicator;
	uint32_t number_of_frames;
	uint32_t frame_count;
	int64_t  base_offset;
	uint32_t record_offsets[N_RECORDS_PER_GROUP];
} capsa_t;

static bool capsa_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);
static bool capsa_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static int capsa_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info);

static int capsa_file_type_subtype = -1;
static int packet_builder_file_type_subtype = -1;

void register_capsa(void);

wtap_open_return_val capsa_open(wtap *wth, int *err, char **err_info)
{
	char magic[sizeof capsa_magic];
	uint16_t format_indicator;
	int file_type_subtype;
	uint32_t number_of_frames;
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
		file_type_subtype = capsa_file_type_subtype;
		break;

	case 2:		/* Packet Builder */
		file_type_subtype = packet_builder_file_type_subtype;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("capsa: format indicator %u unsupported",
		    format_indicator);
		return WTAP_OPEN_ERROR;
	}

	/*
	 * Link speed, in megabytes/second?
	 */
	if (!wtap_read_bytes(wth->fh, NULL, 2, err, err_info))
		return WTAP_OPEN_ERROR;

	/*
	 * Flags of some sort?  Four 1-byte numbers, two of which are 1
	 * and two of which are zero?  Two 2-byte numbers or flag fields,
	 * both of which are 1?
	 */
	if (!wtap_read_bytes(wth->fh, NULL, 4, err, err_info))
		return WTAP_OPEN_ERROR;

	/*
	 * File size, in bytes.
	 */
	if (!wtap_read_bytes(wth->fh, NULL, 4, err, err_info))
		return WTAP_OPEN_ERROR;

	/*
	 * Zeroes?  Or upper 4 bytes of file size?
	 */
	if (!wtap_read_bytes(wth->fh, NULL, 4, err, err_info))
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
	capsa = g_new(capsa_t, 1);
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

	/*
	 * Add an IDB; we don't know how many interfaces were
	 * involved, so we just say one interface, about which
	 * we only know the link-layer type, snapshot length,
	 * and time stamp resolution.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE;
}

/* Read the next packet */
static bool capsa_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
	capsa_t *capsa = (capsa_t *)wth->priv;
	uint32_t frame_within_block;
	int	padbytes;

	if (capsa->frame_count == capsa->number_of_frames) {
		/*
		 * No more frames left.  Return an EOF.
		 */
		*err = 0;
		return false;
	}
	frame_within_block = capsa->frame_count % N_RECORDS_PER_GROUP;
	if (frame_within_block == 0) {
		/*
		 * Here's a record offset block.
		 * Get the offset of the block, and then skip the
		 * first byte.
		 */
		capsa->base_offset = file_tell(wth->fh);
		if (!wtap_read_bytes(wth->fh, NULL, 1, err, err_info))
			return false;

		/*
		 * Now read the record offsets.
		 */
		if (!wtap_read_bytes(wth->fh, &capsa->record_offsets,
		    sizeof capsa->record_offsets, err, err_info))
			return false;

		/*
		 * And finish processing all 805 bytes by skipping
		 * the last 4 bytes.
		 */
		if (!wtap_read_bytes(wth->fh, NULL, 4, err, err_info))
			return false;
	}

	*data_offset = capsa->base_offset +
	    GUINT32_FROM_LE(capsa->record_offsets[frame_within_block]);
	if (!file_seek(wth->fh, *data_offset, SEEK_SET, err))
		return false;

	padbytes = capsa_read_packet(wth, wth->fh, rec, buf, err, err_info);
	if (padbytes == -1)
		return false;

	/*
	 * Skip over the padding, if any.
	 */
	if (padbytes != 0) {
		if (!wtap_read_bytes(wth->fh, NULL, padbytes, err, err_info))
			return false;
	}

	capsa->frame_count++;

	return true;
}

static bool
capsa_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	if (capsa_read_packet(wth, wth->random_fh, rec, buf, err, err_info) == -1) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return false;
	}
	return true;
}

static int
capsa_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info)
{
	capsa_t *capsa = (capsa_t *)wth->priv;
	struct capsarec_hdr capsarec_hdr;
	struct pbrec_hdr pbrec_hdr;
	uint32_t rec_size;
	uint32_t packet_size;
	uint32_t orig_size;
	uint32_t header_size;
	uint64_t timestamp;

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
		timestamp = (((uint64_t)GUINT32_FROM_LE(capsarec_hdr.timestamphi))<<32) + GUINT32_FROM_LE(capsarec_hdr.timestamplo);

		/*
		 * OK, the rest of this is variable-length.
		 * We skip: (count1+count2)*4 bytes.
		 * XXX - what is that?  Measured statistics?
		 * Calculated statistics?
		 */
		if (!wtap_read_bytes(fh, NULL,
		    (capsarec_hdr.count1 + capsarec_hdr.count2)*4,
		    err, err_info))
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
		timestamp = (((uint64_t)GUINT32_FROM_LE(pbrec_hdr.timestamphi))<<32) + GUINT32_FROM_LE(pbrec_hdr.timestamplo);
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
		ws_assert_not_reached();
		*err = WTAP_ERR_INTERNAL;
		*err_info = ws_strdup_printf("capsa: format indicator is %u", capsa->format_indicator);
		return -1;
	}
	if (orig_size > WTAP_MAX_PACKET_SIZE_STANDARD) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("capsa: File has %u-byte original length, bigger than maximum of %u",
		    orig_size, WTAP_MAX_PACKET_SIZE_STANDARD);
		return -1;
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE_STANDARD) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("capsa: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE_STANDARD);
		return -1;
	}
	if (header_size + packet_size > rec_size) {
		/*
		 * Probably a corrupt capture file.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("capsa: File has %u-byte packet with %u-byte record header, bigger than record size %u",
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
	rec->rec_header.packet_header.pseudo_header.eth.fcs_len = 0;

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->rec_header.packet_header.caplen = packet_size;
	rec->rec_header.packet_header.len = orig_size;
	rec->presence_flags = WTAP_HAS_CAP_LEN|WTAP_HAS_TS;
	rec->ts.secs = (time_t)(timestamp / 1000000);
	rec->ts.nsecs = ((int)(timestamp % 1000000))*1000;

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(fh, buf, packet_size, err, err_info))
		return -1;	/* failed */

	return rec_size - (header_size + packet_size);
}

static const struct supported_block_type capsa_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info capsa_info = {
	"Colasoft Capsa format", "capsa", "cscpkt", NULL,
	false, BLOCKS_SUPPORTED(capsa_blocks_supported),
	NULL, NULL, NULL
};

static const struct supported_block_type packet_builder_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info packet_builder_info = {
	"Colasoft Packet Builder format", "colasoft-pb", "cscpkt", NULL,
	false, BLOCKS_SUPPORTED(packet_builder_blocks_supported),
	NULL, NULL, NULL
};

void register_capsa(void)
{
	capsa_file_type_subtype = wtap_register_file_type_subtype(&capsa_info);
	packet_builder_file_type_subtype = wtap_register_file_type_subtype(&packet_builder_info);

	/*
	 * Register names for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("COLASOFT_CAPSA",
	    capsa_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("COLASOFT_PACKET_BUILDER",
	    packet_builder_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
