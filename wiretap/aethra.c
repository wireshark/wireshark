/* aethra.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "aethra.h"

/* Magic number in Aethra PC108 files. */
#define MAGIC_SIZE	5

static const guchar aethra_magic[MAGIC_SIZE] = {
	'V', '0', '2', '0', '8'
};

/* Aethra file header. */
struct aethra_hdr {
	guchar	magic[MAGIC_SIZE];
	guint8	unknown1[39];
	guchar	sw_vers[60];	/* software version string, not null-terminated */
	guint8	unknown2[118];
	guint8	start_sec;	/* seconds of capture start time */
	guint8	start_min;	/* minutes of capture start time */
	guint8	start_hour;	/* hour of capture start time */
	guint8	unknown3[5007];
	guint8	start_year[2];	/* year of capture start date */
	guint8	start_month[2];	/* month of capture start date */
	guint8	unknown4[2];
	guint8	start_day[2];	/* day of capture start date */
	guint8	unknown5[8];
	guchar	com_info[16];	/* COM port and speed, null-padded(?) */
	guint8	unknown6[107];
	guchar	xxx_vers[41];	/* unknown version string (longer, null-padded?) */
};

/* Aethra record header.  Yes, the alignment is weird.
   All multi-byte fields are little-endian. */
struct aethrarec_hdr {
	guint8 rec_size[2];	/* record length, not counting the length itself */
	guint8 rec_type;	/* record type */
	guint8 timestamp[4];	/* milliseconds since start of capture */
	guint8 flags;		/* low-order bit: 0 = N->U, 1 = U->N */
};

/*
 * Record types.
 *
 * XXX - is a record type of 0 used for anything other than "end of
 * capture"?  In at least one capture there's a record with a rec_type
 * of 0, a timestamp of 0, and a flags value of 4, as well as a trailing
 * record which is probably a "Stop Monitor" record with a rec_type of 0,
 * a non-zero timestamp (not checked to see whether it gives the same
 * time stamp as PC108 displays for the Stop Monitor record), and a
 * flags value of 0.
 */
#define AETHRA_STOP_MONITOR	0	/* end of capture */
#define AETHRA_PACKET		1	/* packet */

/*
 * Flags.
 *
 * XXX - what does this mean for AETHRA_STOP_MONITOR records?
 */
#define AETHRA_U_TO_N		0x01

typedef struct {
	time_t	start;
} aethra_t;

static gboolean aethra_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean aethra_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static gboolean aethra_read_rec_header(FILE_T fh, struct aethrarec_hdr *hdr,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean aethra_read_rec_data(FILE_T fh, guint8 *pd, int length,
    int *err, gchar **err_info);

int aethra_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	struct aethra_hdr hdr;
	struct tm tm;
	aethra_t *aethra;

	/* Read in the string that should be at the start of a "aethra" file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(hdr.magic, sizeof hdr.magic, wth->fh);
	if (bytes_read != sizeof hdr.magic) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof hdr.magic;

	if (memcmp(hdr.magic, aethra_magic, sizeof aethra_magic) != 0)
		return 0;

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read((char *)&hdr + sizeof hdr.magic,
	    sizeof hdr - sizeof hdr.magic, wth->fh);
	if (bytes_read != sizeof hdr - sizeof hdr.magic) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof hdr - sizeof hdr.magic;
	wth->file_type = WTAP_FILE_AETHRA;
	aethra = (aethra_t *)g_malloc(sizeof(aethra_t));
	wth->priv = (void *)aethra;
	wth->subtype_read = aethra_read;
	wth->subtype_seek_read = aethra_seek_read;

	/*
	 * Convert the time stamp to a "time_t".
	 */
	tm.tm_year = pletohs(&hdr.start_year) - 1900;
	tm.tm_mon = pletohs(&hdr.start_month) - 1;
	tm.tm_mday = pletohs(&hdr.start_day);
	tm.tm_hour = hdr.start_hour;
	tm.tm_min = hdr.start_min;
	tm.tm_sec = hdr.start_sec;
	tm.tm_isdst = -1;
	aethra->start = mktime(&tm);

	/*
	 * We've only seen ISDN files, so, for now, we treat all
	 * files as ISDN.
	 */
	wth->file_encap = WTAP_ENCAP_ISDN;
	wth->snapshot_length = 0;	/* not available in header */
	wth->tsprecision = WTAP_FILE_TSPREC_MSEC;
	return 1;
}

/* Read the next packet */
static gboolean aethra_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	aethra_t *aethra = (aethra_t *)wth->priv;
	struct aethrarec_hdr hdr;
	guint32	rec_size;
	guint32	packet_size;
	guint32	msecs;

	/*
	 * Keep reading until we see an AETHRA_PACKET record or get
	 * an end-of-file.
	 */
	do {
		*data_offset = wth->data_offset;

		/* Read record header. */
		if (!aethra_read_rec_header(wth->fh, &hdr, &wth->pseudo_header,
		    err, err_info))
			return FALSE;

		rec_size = pletohs(hdr.rec_size);
		if (rec_size < (sizeof hdr - sizeof hdr.rec_size)) {
			/* The record is shorter than a record header. */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("aethra: File has %u-byte record, less than minimum of %u",
			    rec_size, (unsigned int)(sizeof hdr - sizeof hdr.rec_size));
			return FALSE;
		}
		wth->data_offset += sizeof hdr;

		/*
		 * XXX - if this is big, we might waste memory by
		 * growing the buffer to handle it.
		 */
		packet_size = rec_size - (sizeof hdr - sizeof hdr.rec_size);
		if (packet_size != 0) {
			buffer_assure_space(wth->frame_buffer, packet_size);
			if (!aethra_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
			    packet_size, err, err_info))
				return FALSE;	/* Read error */
			wth->data_offset += packet_size;
		}
	} while (hdr.rec_type != AETHRA_PACKET);

	msecs = pletohl(hdr.timestamp);
	wth->phdr.ts.secs = aethra->start + (msecs / 1000);
	wth->phdr.ts.nsecs = (msecs % 1000) * 1000000;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = packet_size;

	return TRUE;
}

static gboolean
aethra_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	struct aethrarec_hdr hdr;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!aethra_read_rec_header(wth->random_fh, &hdr, pseudo_header, err, err_info))
		return FALSE;

	/*
	 * Read the packet data.
	 */
	if (!aethra_read_rec_data(wth->random_fh, pd, length, err, err_info))
		return FALSE;	/* failed */

	return TRUE;
}

static gboolean
aethra_read_rec_header(FILE_T fh, struct aethrarec_hdr *hdr,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info)
{
	int	bytes_read;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(hdr, sizeof *hdr, fh);
	if (bytes_read != sizeof *hdr) {
		*err = file_error(fh, err_info);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	pseudo_header->isdn.uton = hdr->flags & AETHRA_U_TO_N;
	pseudo_header->isdn.channel = 0;	/* XXX - D channel */

	return TRUE;
}

static gboolean
aethra_read_rec_data(FILE_T fh, guint8 *pd, int length, int *err,
    gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}
