/* airopeek9.c
 * Routines for opening AiroPeek V9 files
 *
 * $Id: airopeek9.c,v 1.2 2003/12/02 20:27:14 guy Exp $
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
#include <stdlib.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "airopeek9.h"

/* CREDITS
 *
 * This file decoder could not have been writen without examining
 * http://www.varsanofiev.com/inside/airopeekv9.htm, the help from
 * Martin Regner and Guy Harris, and the etherpeek.c file.
 */

/* section header */
typedef struct airopeek_section_header {
	gint8   section_id[4];
	guint32 section_len;
	guint32 section_const;
} airopeek_section_header_t;

#define AIROPEEK_V9_LENGTH_OFFSET		2
#define AIROPEEK_V9_TIMESTAMP_LOWER_OFFSET	8
#define AIROPEEK_V9_TIMESTAMP_UPPER_OFFSET	14
#define AIROPEEK_V9_FLAGS_OFFSET		20
#define AIROPEEK_V9_STATUS_OFFSET		22
#define AIROPEEK_V9_CHANNEL_OFFSET		26
#define AIROPEEK_V9_RATE_OFFSET			32
#define AIROPEEK_V9_SIGNAL_PERC_OFFSET		38
#define AIROPEEK_V9_SIGNAL_DBM_OFFSET		44
#define AIROPEEK_V9_NOISE_PERC_OFFSET		50
#define AIROPEEK_V9_NOISE_DBM_OFFSET		56
#define AIROPEEK_V9_SLICE_LENGTH_OFFSET		62

#define AIROPEEK_V9_PKT_SIZE			66

/* 64-bit time in nano seconds from the (Mac) epoch */
typedef struct airopeek_utime {
	guint32 upper;
	guint32 lower;
} airopeek_utime;

static const unsigned int mac2unix = 2082844800u;

static gboolean airopeek_read_v9(wtap *wth, int *err, long *data_offset);
static gboolean airopeek_seek_read_v9(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err);

static int wtap_file_read_pattern (wtap *wth, char *pattern, int *err)
{
    int c;
    char *cp;

    cp = pattern;
    while (*cp)
    {
	c = file_getc(wth->fh);
	if (c == EOF) {
	    if (file_eof(wth->fh))
		return 0;	/* EOF */
	    else {
		/* We (presumably) got an error (there's no equivalent to
		   "ferror()" in zlib, alas, so we don't have a wrapper
		   to check for an error). */
		*err = file_error(wth->fh);
		return -1;	/* error */
	    }
	}
	if (c == *cp)
	    cp++;
	else
	{
	    if (c == pattern[0])
		cp = &pattern[1];
	    else
		cp = pattern;
	}
    }
    return (*cp == '\0' ? 1 : 0);
}


static int wtap_file_read_till_separator (wtap *wth, char *buffer, int buflen,
					char *separators, int *err)
{
    int c;
    char *cp;
    int i;

    for (cp = buffer, i = 0; i < buflen; i++, cp++)
    {
	c = file_getc(wth->fh);
	if (c == EOF) {
	    if (file_eof(wth->fh))
		return 0;	/* EOF */
	    else {
		/* We (presumably) got an error (there's no equivalent to
		   "ferror()" in zlib, alas, so we don't have a wrapper
		   to check for an error). */
		*err = file_error(wth->fh);
		return -1;	/* error */
	    }
	}
	if (strchr (separators, c))
	{
	    *cp = '\0';
	    break;
	}
	else
	    *cp = c;
    }
    return i;
}


static int wtap_file_read_number (wtap *wth, guint32 *num, int *err)
{
    int ret;
    char str_num[12];
    unsigned long long value;
    char *p;

    ret = wtap_file_read_till_separator (wth, str_num, sizeof (str_num)-1, "<",
					 err);
    if (ret != 1) {
	/* 0 means EOF, which means "not a valid AiroPeek V9 file";
	   -1 means error, and "err" has been set. */
	return ret;
    }
    value = strtoul (str_num, &p, 10);
    if (p == str_num || value > UINT_MAX)
	return 0;
    *num = value;
    return 1;
}


int airopeek9_open(wtap *wth, int *err)
{
    airopeek_section_header_t ap_hdr;
    int ret;
    guint32 fileVersion;
    guint32 mediaType;
    int file_encap;

    wtap_file_read_unknown_bytes(&ap_hdr, sizeof(ap_hdr), wth->fh, err);

    if (memcmp (ap_hdr.section_id, "\177ver", sizeof(ap_hdr.section_id)) != 0)
	return 0;	/* doesn't begin with a "\177ver" section */

    /*
     * XXX - we should get the length of the "\177ver" section, check
     * that it's followed by a little-endian 0x00000200, and then,
     * when reading the XML, make sure we don't go past the end of
     * that section, and skip to the end of tha section when
     * we have the file version (and possibly check to make sure all
     * tags are properly opened and closed).
     */
    ret = wtap_file_read_pattern (wth, "<FileVersion>", err);
    if (ret != 1) {
	/* 0 means EOF, which means "not a valid AiroPeek V9 file";
	   -1 means error, and "err" has been set. */
	return ret;
    }
    ret = wtap_file_read_number (wth, &fileVersion, err);
    if (ret != 1) {
	/* 0 means EOF, which means "not a valid AiroPeek V9 file";
	   -1 means error, and "err" has been set. */
	return ret;
    }

    /* If we got this far, we assume it's an AiroPeek V9 file. */
    if (fileVersion != 9) {
	/* We only support version 9 and later. */
	g_message("airopeekv9: version %u unsupported", fileVersion);
	*err = WTAP_ERR_UNSUPPORTED;
	return -1;
    }

    /*
     * XXX - once we've skipped the "\177ver" section, we should
     * check for a "sess" section and fail if we don't see it.
     * Then we should get the length of the "sess" section, check
     * that it's followed by a little-endian 0x00000200, and then,
     * when reading the XML, make sure we don't go past the end of
     * that section, and skip to the end of tha section when
     * we have the file version (and possibly check to make sure all
     * tags are properly opened and closed).
     */
    ret = wtap_file_read_pattern (wth, "<MediaType>", err);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	g_message("airopeekv9: <MediaType> tag not found");
	*err = WTAP_ERR_UNSUPPORTED;
	return -1;
    }
    /* XXX - this appears to be 0, which is also the media type for
       802.11 in the older AiroPeek format; should we require it to be
       0?  And should we check the MediaSubType value as well? */
    ret = wtap_file_read_number (wth, &mediaType, err);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	g_message("airopeekv9: <MediaType> value not found");
	*err = WTAP_ERR_UNSUPPORTED;
	return -1;
    }

    ret = wtap_file_read_pattern (wth, "pkts", err);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_SHORT_READ;
	return -1;
    }

    /* skip 8 zero bytes */
    if (file_seek (wth->fh, 8L, SEEK_CUR, err) == -1)
	return 0;

    /*
     * This is an AiroPeek V9 file.
     */

    wth->data_offset = file_tell (wth->fh);

    file_encap = WTAP_ENCAP_IEEE_802_11_WITH_RADIO;

    wth->file_type = WTAP_FILE_AIROPEEK_V9;
    wth->file_encap = file_encap;
    wth->subtype_read = airopeek_read_v9;
    wth->subtype_seek_read = airopeek_seek_read_v9;

    wth->snapshot_length   = 0; /* not available in header */

    return 1;
}

static gboolean airopeek_read_v9(wtap *wth, int *err, long *data_offset)
{
    guchar ap_pkt[AIROPEEK_V9_PKT_SIZE];
    guint32 length;
    guint32 sliceLength;
    airopeek_utime timestamp;
    double  t;

    *data_offset = wth->data_offset;

    wtap_file_read_expected_bytes(ap_pkt, sizeof(ap_pkt), wth->fh, err);
    wth->data_offset += sizeof(ap_pkt);

    /* Extract the fields from the packet */
    length = pletohl(&ap_pkt[AIROPEEK_V9_LENGTH_OFFSET]);
    sliceLength = pletohl(&ap_pkt[AIROPEEK_V9_SLICE_LENGTH_OFFSET]);
    timestamp.upper = pletohl(&ap_pkt[AIROPEEK_V9_TIMESTAMP_UPPER_OFFSET]);
    timestamp.lower = pletohl(&ap_pkt[AIROPEEK_V9_TIMESTAMP_LOWER_OFFSET]);

    /* force sliceLength to be the actual length of the packet */
    if (sliceLength == 0) {
	sliceLength = length;
    }

    /* fill in packet header length values before slicelength may be
       adjusted */
    wth->phdr.len    = length;
    wth->phdr.caplen = sliceLength;

    /*
     * Fill the pseudo header with radio information.
     * XXX - we should supply the additional information;
     * the pseudo-header should probably be supplied in a fashion
     * similar to the new BSD radio header, so that the 802.11
     * dissector can determine which, if any, information items
     * are present.
     */
    wth->pseudo_header.ieee_802_11.channel =
	    pletohl(&ap_pkt[AIROPEEK_V9_CHANNEL_OFFSET]);
    wth->pseudo_header.ieee_802_11.data_rate =
	    pletohl(&ap_pkt[AIROPEEK_V9_RATE_OFFSET]);
    wth->pseudo_header.ieee_802_11.signal_level =
	    pletohl(&ap_pkt[AIROPEEK_V9_SIGNAL_PERC_OFFSET]);

    /* read the frame data */
    buffer_assure_space(wth->frame_buffer, sliceLength);
    wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
				  sliceLength, wth->fh, err);
    wth->data_offset += sliceLength;

    /* recalculate and fill in packet time stamp */
    t =  (double) timestamp.lower +
	 (double) timestamp.upper * 4294967296.0;

    t = t / 1000.0;	/* nano seconds -> micro seconds */
    t -= (double) mac2unix * 1000000.0;
    wth->phdr.ts.tv_sec  = (time_t)  (t/1000000.0);
    wth->phdr.ts.tv_usec = (guint32) (t - (double) wth->phdr.ts.tv_sec *
						   1000000.0);

    /*
     * The last 4 bytes sometimes contains the FCS but on a lot of
     * interfaces these are zero. To eleminate problems we reduce
     * the length by 4.
     *
     * XXX - is there any way to find out whether it's an FCS or not?
     */
    wth->phdr.len -= 4;
    wth->phdr.caplen -= 4;

    wth->phdr.pkt_encap = wth->file_encap;
    return TRUE;
}


static gboolean
airopeek_seek_read_v9(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err)
{
    guchar ap_pkt[AIROPEEK_V9_PKT_SIZE];

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	return FALSE;

    /* Read the packet header. */
    wtap_file_read_expected_bytes(ap_pkt, sizeof(ap_pkt), wth->random_fh, err);

    pseudo_header->ieee_802_11.channel =
	    pletohl(&ap_pkt[AIROPEEK_V9_CHANNEL_OFFSET]);
    pseudo_header->ieee_802_11.data_rate =
	    pletohl(&ap_pkt[AIROPEEK_V9_RATE_OFFSET]);
    pseudo_header->ieee_802_11.signal_level =
	    pletohl(&ap_pkt[AIROPEEK_V9_SIGNAL_PERC_OFFSET]);

    /*
     * XXX - should "errno" be set in "wtap_file_read_expected_bytes()"?
     */
    errno = WTAP_ERR_CANT_READ;
    wtap_file_read_expected_bytes(pd, length, wth->random_fh, err);
    return TRUE;
}
