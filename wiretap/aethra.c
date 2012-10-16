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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
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
 * As the indications from the device and signalling messages appear not
 * to have the 8th bit set, and at least some B-channel records do, we
 * assume, for now, that the 8th bit indicates bearer information.
 *
 * 0x9F is the record type seen for B31 channel records; that might be
 * 0x80|31, so, for now, we assume that if the 8th bit is set, the B
 * channel number is in the low 7 bits.
 */
#define AETHRA_BEARER		0x80	/* bearer information */

#define AETHRA_DEVICE		0x00	/* indication from the monitoring device */
#define AETHRA_ISDN_LINK	0x01	/* information from the ISDN link */

/*
 * In AETHRA_DEVICE records, the flags field has what appears to
 * be a record subtype.
 */
#define AETHRA_DEVICE_STOP_MONITOR	0x00	/* Stop Monitor */
#define AETHRA_DEVICE_START_MONITOR	0x04	/* Start Monitor */
#define AETHRA_DEVICE_ACTIVATION	0x05	/* Activation */
#define AETHRA_DEVICE_START_CAPTURE	0x5F	/* Start Capture */

/*
 * In AETHRA_ISDN_LINK and bearer channel records, the flags field has
 * a direction flag and possibly some other bits.
 *
 * In AETHRA_ISDN_LINK records, at least some of the other bits are
 * a subtype.
 *
 * In bearer channel records, there are records with data and
 * "Constant Value" records with a single byte.  Data has a
 * flags value of 0x14 ORed with the direction flag, and Constant Value
 * records have a flags value of 0x16 ORed with the direction flag.
 * There are also records of an unknown type with 0x02, probably
 * ORed with the direction flag.
 */
#define AETHRA_U_TO_N				0x01	/* set for TE->NT */

#define AETHRA_ISDN_LINK_SUBTYPE		0xFE
#define AETHRA_ISDN_LINK_LAPD			0x00	/* LAPD frame */
#define AETHRA_ISDN_LINK_SA_BITS		0x2E	/* 2048K PRI Sa bits (G.704 section 2.3.2) */
#define AETHRA_ISDN_LINK_ALL_ALARMS_CLEARED	0x30	/* All Alarms Cleared */

typedef struct {
	time_t	start;
} aethra_t;

static gboolean aethra_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean aethra_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, guint8 *pd, int length,
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

#if 0
static guint packet = 0;
#endif

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
	 * Keep reading until we see an AETHRA_ISDN_LINK with a subtype
	 * of AETHRA_ISDN_LINK_LAPD record or get an end-of-file.
	 */
	for (;;) {
		*data_offset = file_tell(wth->fh);

		/* Read record header. */
		if (!aethra_read_rec_header(wth->fh, &hdr, &wth->phdr.pseudo_header,
		    err, err_info))
			return FALSE;

		rec_size = pletohs(hdr.rec_size);
		if (rec_size < (sizeof hdr - sizeof hdr.rec_size)) {
			/* The record is shorter than a record header. */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("aethra: File has %u-byte record, less than minimum of %u",
			    rec_size, (unsigned int)(sizeof hdr - sizeof hdr.rec_size));
			return FALSE;
		}

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
		}
#if 0
packet++;
#endif
		switch (hdr.rec_type) {

		case AETHRA_ISDN_LINK:
#if 0
fprintf(stderr, "Packet %u: type 0x%02x (AETHRA_ISDN_LINK)\n",
packet, hdr.rec_type);
#endif
			switch (hdr.flags & AETHRA_ISDN_LINK_SUBTYPE) {

			case AETHRA_ISDN_LINK_LAPD:
				/*
				 * The data is a LAPD frame.
				 */
#if 0
fprintf(stderr, "    subtype 0x%02x (AETHRA_ISDN_LINK_LAPD)\n", hdr.flags & AETHRA_ISDN_LINK_SUBTYPE);
#endif
				goto found;

			case AETHRA_ISDN_LINK_SA_BITS:
				/*
				 * These records have one data byte, which
				 * has the Sa bits in the lower 5 bits.
				 *
				 * XXX - what about stuff other than 2048K
				 * PRI lines?
				 */
#if 0
fprintf(stderr, "    subtype 0x%02x (AETHRA_ISDN_LINK_SA_BITS)\n", hdr.flags & AETHRA_ISDN_LINK_SUBTYPE);
#endif
				break;

			case AETHRA_ISDN_LINK_ALL_ALARMS_CLEARED:
				/*
				 * No data, just an "all alarms cleared"
				 * indication.
				 */
#if 0
fprintf(stderr, "    subtype 0x%02x (AETHRA_ISDN_LINK_ALL_ALARMS_CLEARED)\n", hdr.flags & AETHRA_ISDN_LINK_SUBTYPE);
#endif
				break;

			default:
#if 0
fprintf(stderr, "    subtype 0x%02x, packet_size %u, direction 0x%02x\n",
hdr.flags & AETHRA_ISDN_LINK_SUBTYPE, packet_size, hdr.flags & AETHRA_U_TO_N);
#endif
				break;
			}
			break;

		default:
#if 0
fprintf(stderr, "Packet %u: type 0x%02x, packet_size %u, flags 0x%02x\n",
packet, hdr.rec_type, packet_size, hdr.flags);
#endif
			break;
		}
	}

found:
	msecs = pletohl(hdr.timestamp);
	wth->phdr.presence_flags = WTAP_HAS_TS;
	wth->phdr.ts.secs = aethra->start + (msecs / 1000);
	wth->phdr.ts.nsecs = (msecs % 1000) * 1000000;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = packet_size;

	return TRUE;
}

static gboolean
aethra_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
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

	pseudo_header->isdn.uton = (hdr->flags & AETHRA_U_TO_N);
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
