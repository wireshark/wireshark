/* airopeek9.c
 * Routines for opening EtherPeek and AiroPeek V9 files
 *
 * $Id: airopeek9.c,v 1.6 2004/02/06 02:11:52 guy Exp $
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

/*
 * NOTE: it says "airopeek" because the first files seen that use this
 * format were AiroPeek files; however, EtherPeek files using it have
 * also been seen.
 */

/* section header */
typedef struct airopeek_section_header {
	gint8   section_id[4];
	guint32 section_len;
	guint32 section_const;
} airopeek_section_header_t;

#define TAG_AIROPEEK_V9_LENGTH			0x0000
#define TAG_AIROPEEK_V9_TIMESTAMP_LOWER		0x0001
#define TAG_AIROPEEK_V9_TIMESTAMP_UPPER		0x0002
#define TAG_AIROPEEK_V9_FLAGS_AND_STATUS	0x0003
#define TAG_AIROPEEK_V9_CHANNEL			0x0004
#define TAG_AIROPEEK_V9_RATE			0x0005
#define TAG_AIROPEEK_V9_SIGNAL_PERC		0x0006
#define TAG_AIROPEEK_V9_SIGNAL_DBM		0x0007
#define TAG_AIROPEEK_V9_NOISE_PERC		0x0008
#define TAG_AIROPEEK_V9_NOISE_DBM		0x0009
#define TAG_AIROPEEK_V9_UNKNOWN_0x000D		0x000D
#define TAG_AIROPEEK_V9_SLICE_LENGTH		0xffff

/* 64-bit time in nano seconds from the (Mac) epoch */
typedef struct airopeek_utime {
	guint32 upper;
	guint32 lower;
} airopeek_utime;

static const unsigned int mac2unix = 2082844800u;

static gboolean airopeekv9_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset);
static gboolean airopeekv9_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info);

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
    unsigned long value;
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


int airopeek9_open(wtap *wth, int *err, gchar **err_info)
{
    airopeek_section_header_t ap_hdr;
    int ret;
    guint32 fileVersion;
    guint32 mediaType;
    guint32 mediaSubType;
    int file_encap;
    static const int airopeek9_encap[] = {
	WTAP_ENCAP_ETHERNET,
	WTAP_ENCAP_UNKNOWN,
	WTAP_ENCAP_UNKNOWN,
	WTAP_ENCAP_IEEE_802_11_WITH_RADIO
    };
    #define NUM_AIROPEEK9_ENCAPS (sizeof airopeek9_encap / sizeof airopeek9_encap[0])

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
	*err = WTAP_ERR_UNSUPPORTED;
	*err_info = g_strdup_printf("airopeekv9: version %u unsupported",
	    fileVersion);
	return -1;
    }

    /*
     * XXX - once we've skipped the "\177ver" section, we should
     * check for a "sess" section and fail if we don't see it.
     * Then we should get the length of the "sess" section, check
     * that it's followed by a little-endian 0x00000200, and then,
     * when reading the XML, make sure we don't go past the end of
     * that section, and skip to the end of the section when
     * we have the file version (and possibly check to make sure all
     * tags are properly opened and closed).
     */
    ret = wtap_file_read_pattern (wth, "<MediaType>", err);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_UNSUPPORTED;
	*err_info = g_strdup("airopeekv9: <MediaType> tag not found");
	return -1;
    }
    /* XXX - this appears to be 0 in both the EtherPeek and AiroPeek
       files we've seen; should we require it to be 0? */
    ret = wtap_file_read_number (wth, &mediaType, err);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_UNSUPPORTED;
	*err_info = g_strdup("airopeekv9: <MediaType> value not found");
	return -1;
    }

    ret = wtap_file_read_pattern (wth, "<MediaSubType>", err);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_UNSUPPORTED;
	*err_info = g_strdup("airopeekv9: <MediaSubType> tag not found");
	return -1;
    }
    ret = wtap_file_read_number (wth, &mediaSubType, err);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_UNSUPPORTED;
	*err_info = g_strdup("airopeekv9: <MediaSubType> value not found");
	return -1;
    }
    if (mediaSubType >= NUM_AIROPEEK9_ENCAPS
        || airopeek9_encap[mediaSubType] == WTAP_ENCAP_UNKNOWN) {
	*err = WTAP_ERR_UNSUPPORTED_ENCAP;
	*err_info = g_strdup_printf("airopeekv9: network type %u unknown or unsupported",
	    mediaSubType);
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

    file_encap = airopeek9_encap[mediaSubType];

    wth->file_type = WTAP_FILE_AIROPEEK_V9;
    wth->file_encap = file_encap;
    wth->subtype_read = airopeekv9_read;
    wth->subtype_seek_read = airopeekv9_seek_read;

    wth->snapshot_length   = 0; /* not available in header */

    return 1;
}

typedef struct {
    guint32 length;
    guint32 sliceLength;
    airopeek_utime timestamp;
    struct ieee_802_11_phdr ieee_802_11;
} hdr_info_t;

/*
 * Process the packet header.
 *
 * XXX - we should supply the additional radio information;
 * the pseudo-header should probably be supplied in a fashion
 * similar to the new BSD radio header, so that the 802.11
 * dissector can determine which, if any, information items
 * are present.
 */
static int
airopeekv9_process_header(FILE_T fh, hdr_info_t *hdr_info, int *err)
{
    long header_len = 0;
    int bytes_read;
    guint8 tag_value[6];
    guint16 tag;

    hdr_info->ieee_802_11.fcs_len = 0;		/* no FCS for 802.11 */

    /* Extract the fields from the packet header */
    do {
	/* Get the tag and value.
	   XXX - this assumes all values are 4 bytes long. */
	bytes_read = file_read(tag_value, 1, sizeof tag_value, fh);
	if (bytes_read != (int) sizeof tag_value) {
	    *err = file_error(fh);
	    if (*err == 0) {
		if (bytes_read > 0)
		    *err = WTAP_ERR_SHORT_READ;
		else if (bytes_read == 0) {
		    /*
		     * Short read if we've read something already;
		     * just an EOF if we haven't.
		     */
		    if (header_len != 0)
			*err = WTAP_ERR_SHORT_READ;
		}
	    }
	    return -1;
	}
	header_len += sizeof(tag_value);
	tag = pletohs(&tag_value[0]);
	switch (tag) {

	case TAG_AIROPEEK_V9_LENGTH:
	    hdr_info->length = pletohl(&tag_value[2]);
	    break;
    
	case TAG_AIROPEEK_V9_TIMESTAMP_LOWER:
	    hdr_info->timestamp.lower = pletohl(&tag_value[2]);
	    break;

	case TAG_AIROPEEK_V9_TIMESTAMP_UPPER:
	    hdr_info->timestamp.upper = pletohl(&tag_value[2]);
	    break;

	case TAG_AIROPEEK_V9_CHANNEL:
	    hdr_info->ieee_802_11.channel = pletohl(&tag_value[2]);
	    break;

	case TAG_AIROPEEK_V9_RATE:
	    hdr_info->ieee_802_11.data_rate = pletohl(&tag_value[2]);
	    break;

	case TAG_AIROPEEK_V9_SIGNAL_PERC:
	    hdr_info->ieee_802_11.signal_level = pletohl(&tag_value[2]);
	    break;

	case TAG_AIROPEEK_V9_SIGNAL_DBM:
	    /* XXX - not used yet */
	    break;

	case TAG_AIROPEEK_V9_NOISE_PERC:
	    /* XXX - not used yet */
	    break;

	case TAG_AIROPEEK_V9_NOISE_DBM:
	    /* XXX - not used yet */
	    break;

	case TAG_AIROPEEK_V9_UNKNOWN_0x000D:
	    /* XXX - seen in an EtherPeek capture; value unknown */
	    break;

	case TAG_AIROPEEK_V9_SLICE_LENGTH:
	    hdr_info->sliceLength = pletohl(&tag_value[2]);
	    break;

	default:
	    break;
        }
    } while (tag != TAG_AIROPEEK_V9_SLICE_LENGTH);	/* last tag */

    return header_len;
}

static gboolean airopeekv9_read(wtap *wth, int *err, gchar **err_info _U_,
    long *data_offset)
{
    hdr_info_t hdr_info;
    int hdrlen;
    double  t;

    *data_offset = wth->data_offset;

    /* Process the packet header. */
    hdrlen = airopeekv9_process_header(wth->fh, &hdr_info, err);
    if (hdrlen == -1)
	return FALSE;
    wth->data_offset += hdrlen;

    /* force sliceLength to be the actual length of the packet */
    if (hdr_info.sliceLength == 0)
	hdr_info.sliceLength = hdr_info.length;

    /* fill in packet header length values before slicelength may be
       adjusted */
    wth->phdr.len    = hdr_info.length;
    wth->phdr.caplen = hdr_info.sliceLength;

    switch (wth->file_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	wth->pseudo_header.ieee_802_11 = hdr_info.ieee_802_11;
	break;

    case WTAP_ENCAP_ETHERNET:
	wth->pseudo_header.eth.fcs_len = 0;	/* XXX - always? */
	break;
    }

    /* read the frame data */
    buffer_assure_space(wth->frame_buffer, hdr_info.sliceLength);
    wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
				  hdr_info.sliceLength, wth->fh, err);
    wth->data_offset += hdr_info.sliceLength;

    /* recalculate and fill in packet time stamp */
    t =  (double) hdr_info.timestamp.lower +
	 (double) hdr_info.timestamp.upper * 4294967296.0;

    t = t / 1000.0;	/* nano seconds -> micro seconds */
    t -= (double) mac2unix * 1000000.0;
    wth->phdr.ts.tv_sec  = (time_t)  (t/1000000.0);
    wth->phdr.ts.tv_usec = (guint32) (t - (double) wth->phdr.ts.tv_sec *
						   1000000.0);

    switch (wth->file_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	/*
	 * The last 4 bytes sometimes contains the FCS but on a lot of
	 * interfaces these are zero. To eleminate problems we reduce
	 * the length by 4.
	 *
	 * XXX - is there any way to find out whether it's an FCS or not?
	 */
	wth->phdr.len -= 4;
	wth->phdr.caplen -= 4;
	break;
    }

    wth->phdr.pkt_encap = wth->file_encap;
    return TRUE;
}


static gboolean
airopeekv9_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info _U_)
{
    hdr_info_t hdr_info;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	return FALSE;

    /* Process the packet header. */
    if (airopeekv9_process_header(wth->random_fh, &hdr_info, err) == -1)
	return FALSE;

    switch (wth->file_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	pseudo_header->ieee_802_11 = hdr_info.ieee_802_11;
	break;

    case WTAP_ENCAP_ETHERNET:
	pseudo_header->eth.fcs_len = 0;	/* XXX - always? */
	break;
    }

    /*
     * XXX - should "errno" be set in "wtap_file_read_expected_bytes()"?
     */
    errno = WTAP_ERR_CANT_READ;
    wtap_file_read_expected_bytes(pd, length, wth->random_fh, err);
    return TRUE;
}
