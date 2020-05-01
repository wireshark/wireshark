/* mpeg.c
 *
 * MPEG file format decoder for the Wiretap library.
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "mpeg.h"
#include "wsutil/mpeg-audio.h"

#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "file_wrappers.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PES_PREFIX 1
#define PES_VALID(n) (((n) >> 8 & 0xffffff) == PES_PREFIX)

typedef struct {
	nstime_t now;
	time_t t0;
} mpeg_t;

static int
mpeg_resync(FILE_T fh, int *err)
{
	gint64 offset = file_tell(fh);
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

static gboolean
mpeg_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec, Buffer *buf,
    gboolean is_random, int *err, gchar **err_info)
{
	mpeg_t *mpeg = (mpeg_t *)wth->priv;
	guint32 n;
	unsigned int packet_size;
	nstime_t ts = mpeg->now;

	/*
	 * All packets have at least 4 bytes in them.  Read the first
	 * 4 bytes and determine whether it's a PES packet or not
	 * based on that.
	 *
	 * XXX - can an MPEG file contain a mixture of PES and non-PES
	 * packets?  If not, can we determine whether the packets will
	 * be PES packets or not based on the magic number (i.e., if the
	 * file begins with 0x00 0x00 0x01, it contains PES packets,
	 * otherwise it doesn't)?
	 */
	if (!wtap_read_bytes_or_eof(fh, &n, sizeof n, err, err_info))
		return FALSE;
	if (file_seek(fh, -(gint64)(sizeof n), SEEK_CUR, err) == -1)
		return FALSE;
	n = g_ntohl(n);
	if (PES_VALID(n)) {
		gint64 offset = file_tell(fh);
		guint8 stream;

		if (!wtap_read_bytes(fh, NULL, 3, err, err_info))
			return FALSE;

		if (!wtap_read_bytes(fh, &stream, sizeof stream, err, err_info))
			return FALSE;

		if (stream == 0xba) {
			guint32 pack1;
			guint32 pack0;
			guint64 pack;
			guint8 stuffing;

			if (!wtap_read_bytes(fh, &pack1, sizeof pack1, err, err_info))
				return FALSE;
			if (!wtap_read_bytes(fh, &pack0, sizeof pack0, err, err_info))
				return FALSE;
			pack = (guint64)g_ntohl(pack1) << 32 | g_ntohl(pack0);

			switch (pack >> 62) {
				case 1:
					if (!wtap_read_bytes(fh, NULL, 1, err,
					    err_info))
						return FALSE;
					if (!wtap_read_bytes(fh, &stuffing,
					    sizeof stuffing, err, err_info))
						return FALSE;
					stuffing &= 0x07;
					packet_size = 14 + stuffing;

					if (!is_random) {
						guint64 bytes = pack >> 16;
						guint64 ts_val =
							(bytes >> 43 & 0x0007) << 30 |
							(bytes >> 27 & 0x7fff) << 15 |
							(bytes >> 11 & 0x7fff) << 0;
						guint ext = (guint)((bytes >> 1) & 0x1ff);
						guint64 cr = 300 * ts_val + ext;
						guint rem = (guint)(cr % SCRHZ);
						mpeg->now.secs
							= mpeg->t0 + (time_t)(cr / SCRHZ);
						mpeg->now.nsecs
							= (int)(G_GINT64_CONSTANT(1000000000) * rem / SCRHZ);
					}
					ts = mpeg->now;
					break;
				default:
					packet_size = 12;
			}
		} else {
			guint16 length;
			if (!wtap_read_bytes(fh, &length, sizeof length, err, err_info))
				return FALSE;
			length = g_ntohs(length);
			packet_size = 6 + length;
		}

		if (file_seek(fh, offset, SEEK_SET, err) == -1)
			return FALSE;
	} else {
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
			packet_size = mpeg_resync(fh, err);
			if (packet_size == 0)
				return FALSE;
		}
	}

	if (!wtap_read_packet_bytes(fh, buf, packet_size, err, err_info))
		return FALSE;

	rec->rec_type = REC_TYPE_PACKET;

	rec->presence_flags = 0; /* we may or may not have a time stamp */
	if (!is_random) {
		/* XXX - relative, not absolute, time stamps */
		rec->presence_flags = WTAP_HAS_TS;
		rec->ts = ts;
	}
	rec->rec_header.packet_header.caplen = packet_size;
	rec->rec_header.packet_header.len = packet_size;

	return TRUE;
}

static gboolean
mpeg_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
		gchar **err_info, gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return mpeg_read_packet(wth, wth->fh, rec, buf, FALSE, err, err_info);
}

static gboolean
mpeg_seek_read(wtap *wth, gint64 seek_off,
		wtap_rec *rec, Buffer *buf,
		int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!mpeg_read_packet(wth, wth->random_fh, rec, buf, TRUE, err,
	    err_info)) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

struct _mpeg_magic {
	size_t len;
	const gchar* match;
} magic[] = {
	{ 3, "TAG" }, /* ID3v1 */
	{ 3, "ID3" }, /* ID3v2 */
	{ 3, "\0\0\1" }, /* MPEG PES */
	{ 2, "\xff\xfb" }, /* MP3, taken from https://en.wikipedia.org/wiki/MP3#File_structure */
	{ 0, NULL }
};

wtap_open_return_val
mpeg_open(wtap *wth, int *err, gchar **err_info)
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

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_MPEG;
	wth->file_encap = WTAP_ENCAP_MPEG;
	wth->file_tsprec = WTAP_TSPREC_NSEC;
	wth->subtype_read = mpeg_read;
	wth->subtype_seek_read = mpeg_seek_read;
	wth->snapshot_length = 0;

	mpeg = (mpeg_t *)g_malloc(sizeof(mpeg_t));
	wth->priv = (void *)mpeg;
	mpeg->now.secs = 0;
	mpeg->now.nsecs = 0;
	mpeg->t0 = mpeg->now.secs;

	return WTAP_OPEN_MINE;
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
