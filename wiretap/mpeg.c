/* mpeg.c
 *
 * MPEG-1/2 file format decoder for the Wiretap library.
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
 *
 * MPEG-1/2 Program Streams (ISO/IEC 11172-1, ISO/IEC 13818-1 / ITU-T H.220.0)
 * MPEG-1/2 Video bitstream (ISO/IEC 11172-2, ISO/IEC 13818-2 / ITU-T H.262)
 * MPEG-1/2 Audio files (ISO/IEC 11172-3, ISO/IEC 13818-3)
 *
 * Does not handle other MPEG-2 container formats such as Transport Streams
 * (also ISO/IEC 13818-1 / ITU-T H.222.0) or MPEG-4 containers such as
 * MPEG-4 Part 14 / MP4 (ISO/IEC 14496-14). Support in wiretap for those
 * two formats is provided in mp2t.c and mp4.c, respectively.
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "mpeg.h"

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "wsutil/mpeg-audio.h"

#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "file_wrappers.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PES_PREFIX 1
#define PES_VALID(n) (((n) >> 8 & 0xffffff) == PES_PREFIX)

typedef struct {
	nstime_t now;
	time_t t0;
	bool is_audio;
} mpeg_t;

static int mpeg_file_type_subtype = -1;

void register_mpeg(void);

static int
mpeg_resync(FILE_T fh, int *err)
{
	int64_t offset = file_tell(fh);
	int count = 0;
	int byte = file_getc(fh);

	while (byte != EOF) {
		if (byte == 0xff && count > 0) {
			byte = file_getc(fh);
			if (byte != EOF && (byte & 0xe0) == 0xe0)
				break;
		} else
			byte = file_getc(fh);
		count++;
	}
	if (file_seek(fh, offset, SEEK_SET, err) == -1)
		return 0;
	return count;
}

#define SCRHZ 27000000

static unsigned int
mpeg_read_audio_packet(wtap *wth, FILE_T fh, bool is_random, int *err, char **err_info)
{
	mpeg_t *mpeg = (mpeg_t *)wth->priv;
	unsigned int packet_size;
	uint32_t n;
	if (!wtap_read_bytes_or_eof(fh, &n, sizeof n, err, err_info))
		return 0;
	if (file_seek(fh, -(int64_t)(sizeof n), SEEK_CUR, err) == -1)
		return 0;
	n = g_ntohl(n);
	struct mpa mpa;

	MPA_UNMARSHAL(&mpa, n);
	if (MPA_VALID(&mpa)) {
		packet_size = MPA_BYTES(&mpa);
		if (!is_random) {
			mpeg->now.nsecs += MPA_DURATION_NS(&mpa);
			if (mpeg->now.nsecs >= 1000000000) {
				mpeg->now.secs++;
				mpeg->now.nsecs -= 1000000000;
			}
		}
	} else {
		if ((n & 0xffffff00) == 0x49443300) {
			/* We have an ID3v2 header; read the size */
			if (file_seek(fh, 6, SEEK_CUR, err) == -1)
				return 0;
			if (!wtap_read_bytes_or_eof(fh, &n, sizeof n, err, err_info))
				return 0;
			if (file_seek(fh, -(int64_t)(6+sizeof(n)), SEEK_CUR, err) == -1)
				return 0;
			n = g_ntohl(n);

			/* ID3v2 size does not include the 10-byte header */
			packet_size = decode_synchsafe_int(n) + 10;
		} else {
			packet_size = mpeg_resync(fh, err);
		}
	}
	return packet_size;
}

static unsigned int
mpeg_read_pes_packet(wtap *wth, FILE_T fh, bool is_random, int *err, char **err_info)
{
	mpeg_t *mpeg = (mpeg_t *)wth->priv;
	unsigned int packet_size = 0;
	uint32_t n;
	while (1) {
		if (!wtap_read_bytes_or_eof(fh, &n, sizeof n, err, err_info))
			return 0;
		if (file_seek(fh, -(int64_t)(sizeof n), SEEK_CUR, err) == -1)
			return 0;
		n = g_ntohl(n);
		if (PES_VALID(n)) {
			break;
		} else if (n == PES_PREFIX) {
			if (!wtap_read_bytes(fh, NULL, 1, err, err_info))
				return 0;
			break;
		} else if (n != 0) {
			/* XXX: We could try to recover from errors and
			 * resynchronize to the next start code.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup("mpeg: Non-zero stuffing bytes before start code");
			return 0;
		}
		if (!wtap_read_bytes(fh, NULL, 2, err, err_info))
			return 0;
	}

	int64_t offset = file_tell(fh);
	uint8_t stream;

	if (!wtap_read_bytes(fh, NULL, 3, err, err_info))
		return 0;

	if (!wtap_read_bytes(fh, &stream, sizeof stream, err, err_info))
		return 0;

	if (stream == 0xba) {
		uint32_t pack1;
		uint32_t pack0;
		uint64_t pack;
		uint8_t stuffing;

		if (!wtap_read_bytes(fh, &pack1, sizeof pack1, err, err_info))
			return 0;
		if (!wtap_read_bytes(fh, &pack0, sizeof pack0, err, err_info))
			return 0;
		pack = (uint64_t)g_ntohl(pack1) << 32 | g_ntohl(pack0);

		switch (pack >> 62) {
			case 1:
				if (!wtap_read_bytes(fh, NULL, 1, err,
				    err_info))
					return false;
				if (!wtap_read_bytes(fh, &stuffing,
				    sizeof stuffing, err, err_info))
					return false;
				stuffing &= 0x07;
				packet_size = 14 + stuffing;

				if (!is_random) {
					uint64_t bytes = pack >> 16;
					uint64_t ts_val =
						(bytes >> 43 & 0x0007) << 30 |
						(bytes >> 27 & 0x7fff) << 15 |
						(bytes >> 11 & 0x7fff) << 0;
					unsigned ext = (unsigned)((bytes >> 1) & 0x1ff);
					uint64_t cr = 300 * ts_val + ext;
					unsigned rem = (unsigned)(cr % SCRHZ);
					mpeg->now.secs
						= mpeg->t0 + (time_t)(cr / SCRHZ);
					mpeg->now.nsecs
						= (int)(INT64_C(1000000000) * rem / SCRHZ);
				}
				break;
			default:
				packet_size = 12;
		}
	} else if (stream == 0xb9) {
		/* MPEG_program_end_code */
		packet_size = 4;
	} else {
		uint16_t length;
		if (!wtap_read_bytes(fh, &length, sizeof length, err, err_info))
			return false;
		length = g_ntohs(length);
		packet_size = 6 + length;
	}

	if (file_seek(fh, offset, SEEK_SET, err) == -1)
		return 0;

	return packet_size;
}

static bool
mpeg_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec, Buffer *buf,
    bool is_random, int *err, char **err_info)
{
	mpeg_t *mpeg = (mpeg_t *)wth->priv;
	unsigned int packet_size;
	nstime_t ts = mpeg->now;

	if (mpeg->is_audio) {
		/* mpeg_read_audio_packet calculates the duration of this
		 * packet to determine an updated relative timestamp for the
		 * next packet, if possible.
		 */
		packet_size = mpeg_read_audio_packet(wth, fh, is_random, err, err_info);
	} else {
		/* mpeg_read_pes_packet uses the System Clock Reference counter
		 * to produce a relative timestamp for this packet, if possible.
		 */
		packet_size = mpeg_read_pes_packet(wth, fh, is_random, err, err_info);
	}

	if (packet_size == 0)
		return false;

	if (!wtap_read_packet_bytes(fh, buf, packet_size, err, err_info))
		return false;

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);

	rec->presence_flags = 0; /* we may or may not have a time stamp */
	if (!is_random) {
		/* XXX - relative, not absolute, time stamps */
		rec->presence_flags = WTAP_HAS_TS;
		rec->ts = ts;
	}
	rec->rec_header.packet_header.caplen = packet_size;
	rec->rec_header.packet_header.len = packet_size;

	return true;
}

static bool
mpeg_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
		char **err_info, int64_t *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return mpeg_read_packet(wth, wth->fh, rec, buf, false, err, err_info);
}

static bool
mpeg_seek_read(wtap *wth, int64_t seek_off,
		wtap_rec *rec, Buffer *buf,
		int *err, char **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	if (!mpeg_read_packet(wth, wth->random_fh, rec, buf, true, err,
	    err_info)) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return false;
	}
	return true;
}

struct _mpeg_magic {
	size_t len;
	const char* match;
	bool is_audio;
} magic[] = {
	{ 3, "TAG", true }, /* ID3v1 */
	/* XXX: ID3v1 tags come at the end of MP3 files, so in practice the
	 * untagged magic number is used instead.
	 */
	{ 3, "ID3", true }, /* ID3v2 */
	{ 3, "\0\0\1", false }, /* MPEG PES */
	{ 2, "\xff\xfb", true }, /* MP3 (MPEG-1 Audio Layer 3, no CRC), taken from https://en.wikipedia.org/wiki/MP3#File_structure */
#if 0
	/* XXX: The value above is for MPEG-1 Audio Layer 3 with no CRC.
	 * Only the first three nibbles are the guaranteed sync byte.
	 * For the fourth nibble, the first bit is '1' for MPEG-1 and
	 * '0' for MPEG-2 (i.e., extension to lower sampling rates),
	 * the next two bits indicate the layer (1 for layer 3, 2 for
	 * layer 2, 3 for layer 1, 0 reserved), and the last ("protection")
	 * bit is 1 if there is no CRC and 0 if there is a CRC.
	 *
	 * The mpeg-audio dissector handles these, so wiretap should open
	 * them. Including all of them might increase false positives though.
	 */
	{ 2, "\xff\xf2", true }, /* MPEG-2 Audio Layer 3, CRC */
	{ 2, "\xff\xf3", true }, /* MPEG-2 Audio Layer 3, No CRC */
	{ 2, "\xff\xf4", true }, /* MPEG-2 Audio Layer 2, CRC */
	{ 2, "\xff\xf5", true }, /* MPEG-2 Audio Layer 2, No CRC */
	{ 2, "\xff\xf6", true }, /* MPEG-2 Audio Layer 1, CRC */
	{ 2, "\xff\xf7", true }, /* MPEG-2 Audio Layer 1, No CRC */
	{ 2, "\xff\xfa", true }, /* MPEG-1 Audio Layer 3, CRC */
	{ 2, "\xff\xfc", true }, /* MPEG-1 Audio Layer 2, CRC */
	{ 2, "\xff\xfd", true }, /* MPEG-1 Audio Layer 2, No CRC */
	{ 2, "\xff\xfe", true }, /* MPEG-1 Audio Layer 1, CRC */
	{ 2, "\xff\xff", true }, /* MPEG-1 Audio Layer 1, No CRC */
#endif
	{ 0, NULL, false }
};

/*
 * Even though this dissector uses magic numbers, it is registered in
 * file_access.c as OPEN_INFO_HEURISTIC because the magic numbers are
 * short and prone to false positives.
 *
 * XXX: There's room for improvement in detection if needed. A Program Stream
 * starts with the pack_start_code, \x00\x00\x01\xba, and an uncontainered
 * Video bitstream starts with the sequence_header_code, \x00\x00\x01\xb3.
 * We could use those instead of matching any PES packet, which would greatly
 * reduce false positives with e.g. PacketLogger files. (Unlike Transport
 * Streams, unaligned file starts are unlikely with PS.)
 *
 * Untagged MPEG Audio files would still have to be heuristics, though.
 */
wtap_open_return_val
mpeg_open(wtap *wth, int *err, char **err_info)
{
	char magic_buf[16];
	struct _mpeg_magic* m;
	mpeg_t *mpeg;

	if (!wtap_read_bytes(wth->fh, magic_buf, sizeof magic_buf,
	    err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	for (m=magic; m->match; m++) {
		if (memcmp(magic_buf, m->match, m->len) == 0)
			goto good_magic;
	}

	return WTAP_OPEN_NOT_MINE;

good_magic:
	/* This appears to be a file with MPEG data. */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	wth->file_type_subtype = mpeg_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_MPEG;
	wth->file_tsprec = WTAP_TSPREC_NSEC;
	wth->subtype_read = mpeg_read;
	wth->subtype_seek_read = mpeg_seek_read;
	wth->snapshot_length = 0;

	mpeg = g_new(mpeg_t, 1);
	wth->priv = (void *)mpeg;
	mpeg->now.secs = 0;
	mpeg->now.nsecs = 0;
	mpeg->t0 = mpeg->now.secs;
	mpeg->is_audio = m->is_audio;

	return WTAP_OPEN_MINE;
}

static const struct supported_block_type mpeg_blocks_supported[] = {
	/*
	 * This file format divides the file up into a "packet" for
	 * each frame, and doesn't support any options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info mpeg_info = {
	"MPEG", "mpeg", "mpeg", "mpg;mp3",
	false, BLOCKS_SUPPORTED(mpeg_blocks_supported),
	NULL, NULL, NULL
};

void register_mpeg(void)
{
	mpeg_file_type_subtype = wtap_register_file_type_subtype(&mpeg_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("MPEG",
	    mpeg_file_type_subtype);
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
