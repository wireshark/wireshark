/* peektagged.c
 * Routines for opening files in what WildPackets calls the tagged file
 * format in the description of their "PeekRdr Sample Application" (C++
 * source code to read their capture files, downloading of which requires
 * a maintenance contract, so it's not free as in beer and probably not
 * as in speech, either).
 *
 * As that description says, it's used by AiroPeek and AiroPeek NX 2.0
 * and later, EtherPeek 6.0 and later, EtherPeek NX 3.0 and later,
 * EtherPeek VX 1.0 and later, GigaPeek NX 1.0 and later, Omni3 1.0
 * and later (both OmniPeek and the Remote Engine), and WANPeek NX
 * 1.0 and later.  They also say it'll be used by future WildPackets
 * products.
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
#include <stdlib.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "peektagged.h"

/* CREDITS
 *
 * This file decoder could not have been writen without examining
 * http://www.varsanofiev.com/inside/peektagged.htm, the help from
 * Martin Regner and Guy Harris, and the etherpeek.c file (as it
 * was called before renaming it to peekclassic.c).
 */

/* section header */
typedef struct peektagged_section_header {
	gint8   section_id[4];
	guint32 section_len;
	guint32 section_const;
} peektagged_section_header_t;

/*
 * Network subtype values.
 *
 * XXX - do different network subtype values for 802.11 indicate different
 * network adapter types, with some adapters supplying the FCS and others
 * not supplying the FCS?
 */
#define PEEKTAGGED_NST_ETHERNET		0
#define PEEKTAGGED_NST_802_11		1	/* 802.11 with 0's at the end */
#define PEEKTAGGED_NST_802_11_2		2	/* 802.11 with 0's at the end */
#define PEEKTAGGED_NST_802_11_WITH_FCS	3	/* 802.11 with FCS at the end */

/* tags for fields in packet header */
#define TAG_PEEKTAGGED_LENGTH			0x0000
#define TAG_PEEKTAGGED_TIMESTAMP_LOWER		0x0001
#define TAG_PEEKTAGGED_TIMESTAMP_UPPER		0x0002
#define TAG_PEEKTAGGED_FLAGS_AND_STATUS		0x0003
#define TAG_PEEKTAGGED_CHANNEL			0x0004
#define TAG_PEEKTAGGED_RATE			0x0005
#define TAG_PEEKTAGGED_SIGNAL_PERC		0x0006
#define TAG_PEEKTAGGED_SIGNAL_DBM		0x0007
#define TAG_PEEKTAGGED_NOISE_PERC		0x0008
#define TAG_PEEKTAGGED_NOISE_DBM		0x0009
#define TAG_PEEKTAGGED_UNKNOWN_0x000D		0x000D
#define TAG_PEEKTAGGED_SLICE_LENGTH		0xffff

/* 64-bit time in nanoseconds from the (Windows FILETIME) epoch */
typedef struct peektagged_utime {
	guint32 upper;
	guint32 lower;
} peektagged_utime;

typedef struct {
	gboolean	has_fcs;
} peektagged_t;

static gboolean peektagged_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean peektagged_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);

static int wtap_file_read_pattern (wtap *wth, const char *pattern, int *err,
				gchar **err_info)
{
    int c;
    const char *cp;

    cp = pattern;
    while (*cp)
    {
	c = file_getc(wth->fh);
	if (c == EOF) {
	    if (file_eof(wth->fh))
		return 0;	/* EOF */
	    else {
		*err = file_error(wth->fh, err_info);
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
					const char *separators, int *err,
					gchar **err_info)
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
		*err = file_error(wth->fh, err_info);
		return -1;	/* error */
	    }
	}
	if (strchr (separators, c) != NULL)
	{
	    *cp = '\0';
	    break;
	}
	else
	    *cp = c;
    }
    return i;
}


static int wtap_file_read_number (wtap *wth, guint32 *num, int *err,
				gchar **err_info)
{
    int ret;
    char str_num[12];
    unsigned long value;
    char *p;

    ret = wtap_file_read_till_separator (wth, str_num, sizeof (str_num)-1, "<",
					 err, err_info);
    if (ret != 1) {
	/* 0 means EOF, which means "not a valid Peek tagged file";
	   -1 means error, and "err" has been set. */
	return ret;
    }
    value = strtoul (str_num, &p, 10);
    if (p == str_num || value > G_MAXUINT32)
	return 0;
    *num = (guint32)value;
    return 1;
}


int peektagged_open(wtap *wth, int *err, gchar **err_info)
{
    peektagged_section_header_t ap_hdr;
    int ret;
    guint32 fileVersion;
    guint32 mediaType;
    guint32 mediaSubType = 0;
    int file_encap;
    static const int peektagged_encap[] = {
	WTAP_ENCAP_ETHERNET,
	WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
	WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
	WTAP_ENCAP_IEEE_802_11_WITH_RADIO
    };
    #define NUM_PEEKTAGGED_ENCAPS (sizeof peektagged_encap / sizeof peektagged_encap[0])
    peektagged_t *peektagged;

    wtap_file_read_unknown_bytes(&ap_hdr, sizeof(ap_hdr), wth->fh, err,
                                 err_info);

    if (memcmp (ap_hdr.section_id, "\177ver", sizeof(ap_hdr.section_id)) != 0)
	return 0;	/* doesn't begin with a "\177ver" section */

    /*
     * XXX - we should get the length of the "\177ver" section, check
     * that it's followed by a little-endian 0x00000200, and then,
     * when reading the XML, make sure we don't go past the end of
     * that section, and skip to the end of that section when
     * we have the file version (and possibly check to make sure all
     * tags are properly opened and closed).
     */
    ret = wtap_file_read_pattern (wth, "<FileVersion>", err, err_info);
    if (ret != 1) {
	/* 0 means EOF, which means "not a valid Peek tagged file";
	   -1 means error, and "err" has been set. */
	return ret;
    }
    ret = wtap_file_read_number (wth, &fileVersion, err, err_info);
    if (ret != 1) {
	/* 0 means EOF, which means "not a valid Peek tagged file";
	   -1 means error, and "err" has been set. */
	return ret;
    }

    /* If we got this far, we assume it's a Peek tagged file. */
    if (fileVersion != 9) {
	/* We only support version 9. */
	*err = WTAP_ERR_UNSUPPORTED;
	*err_info = g_strdup_printf("peektagged: version %u unsupported",
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
    ret = wtap_file_read_pattern (wth, "<MediaType>", err, err_info);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: <MediaType> tag not found");
	return -1;
    }
    /* XXX - this appears to be 0 in both the EtherPeek and AiroPeek
       files we've seen; should we require it to be 0? */
    ret = wtap_file_read_number (wth, &mediaType, err, err_info);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: <MediaType> value not found");
	return -1;
    }

    ret = wtap_file_read_pattern (wth, "<MediaSubType>", err, err_info);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: <MediaSubType> tag not found");
	return -1;
    }
    ret = wtap_file_read_number (wth, &mediaSubType, err, err_info);
    if (ret == -1)
	return -1;
    if (ret == 0) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: <MediaSubType> value not found");
	return -1;
    }
    if (mediaSubType >= NUM_PEEKTAGGED_ENCAPS
        || peektagged_encap[mediaSubType] == WTAP_ENCAP_UNKNOWN) {
	*err = WTAP_ERR_UNSUPPORTED_ENCAP;
	*err_info = g_strdup_printf("peektagged: network type %u unknown or unsupported",
	    mediaSubType);
	return -1;
    }

    ret = wtap_file_read_pattern (wth, "pkts", err, err_info);
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
     * This is an Peek tagged file.
     */
    file_encap = peektagged_encap[mediaSubType];

    wth->file_type = WTAP_FILE_PEEKTAGGED;
    wth->file_encap = file_encap;
    wth->subtype_read = peektagged_read;
    wth->subtype_seek_read = peektagged_seek_read;
    wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

    peektagged = (peektagged_t *)g_malloc(sizeof(peektagged_t));
    wth->priv = (void *)peektagged;
    switch (mediaSubType) {

    case PEEKTAGGED_NST_ETHERNET:
    case PEEKTAGGED_NST_802_11:
    case PEEKTAGGED_NST_802_11_2:
	peektagged->has_fcs = FALSE;
	break;

    case PEEKTAGGED_NST_802_11_WITH_FCS:
	peektagged->has_fcs = TRUE;
	break;
    }

    wth->snapshot_length   = 0; /* not available in header */

    return 1;
}

typedef struct {
    guint32 length;
    guint32 sliceLength;
    peektagged_utime timestamp;
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
peektagged_process_header(FILE_T fh, hdr_info_t *hdr_info, int *err,
    gchar **err_info)
{
    int header_len = 0;
    int bytes_read;
    guint8 tag_value[6];
    guint16 tag;
    gboolean saw_length = FALSE;
    gboolean saw_timestamp_lower = FALSE;
    gboolean saw_timestamp_upper = FALSE;

    /* Extract the fields from the packet header */
    do {
	/* Get the tag and value.
	   XXX - this assumes all values are 4 bytes long. */
	bytes_read = file_read(tag_value, sizeof tag_value, fh);
	if (bytes_read != (int) sizeof tag_value) {
	    *err = file_error(fh, err_info);
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
	    return 0;
	}
	header_len += (int) sizeof(tag_value);
	tag = pletohs(&tag_value[0]);
	switch (tag) {

	case TAG_PEEKTAGGED_LENGTH:
	    if (saw_length) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("peektagged: record has two length fields");
		return 0;
	    }
	    hdr_info->length = pletohl(&tag_value[2]);
	    saw_length = TRUE;
	    break;
    
	case TAG_PEEKTAGGED_TIMESTAMP_LOWER:
	    if (saw_timestamp_lower) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("peektagged: record has two timestamp-lower fields");
		return 0;
	    }
	    hdr_info->timestamp.lower = pletohl(&tag_value[2]);
	    saw_timestamp_lower = TRUE;
	    break;

	case TAG_PEEKTAGGED_TIMESTAMP_UPPER:
	    if (saw_timestamp_upper) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("peektagged: record has two timestamp-upper fields");
		return 0;
	    }
	    hdr_info->timestamp.upper = pletohl(&tag_value[2]);
	    saw_timestamp_upper = TRUE;
	    break;

	case TAG_PEEKTAGGED_FLAGS_AND_STATUS:
	    /* XXX - not used yet */
	    break;

	case TAG_PEEKTAGGED_CHANNEL:
	    hdr_info->ieee_802_11.channel = pletohl(&tag_value[2]);
	    break;

	case TAG_PEEKTAGGED_RATE:
	    hdr_info->ieee_802_11.data_rate = pletohl(&tag_value[2]);
	    break;

	case TAG_PEEKTAGGED_SIGNAL_PERC:
	    hdr_info->ieee_802_11.signal_level = pletohl(&tag_value[2]);
	    break;

	case TAG_PEEKTAGGED_SIGNAL_DBM:
	    /* XXX - not used yet */
	    break;

	case TAG_PEEKTAGGED_NOISE_PERC:
	    /* XXX - not used yet */
	    break;

	case TAG_PEEKTAGGED_NOISE_DBM:
	    /* XXX - not used yet */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x000D:
	    /* XXX - seen in an EtherPeek capture; value unknown */
	    break;

	case TAG_PEEKTAGGED_SLICE_LENGTH:
	    hdr_info->sliceLength = pletohl(&tag_value[2]);
	    break;

	default:
	    break;
        }
    } while (tag != TAG_PEEKTAGGED_SLICE_LENGTH);	/* last tag */

    if (!saw_length) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: record has no length field");
	return 0;
    }
    if (!saw_timestamp_lower) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: record has no timestamp-lower field");
	return 0;
    }
    if (!saw_timestamp_upper) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: record has no timestamp-upper field");
	return 0;
    }

    return header_len;
}

/*
 * Time stamps appear to be in nanoseconds since the Windows epoch
 * as used in FILETIMEs, i.e. midnight, January 1, 1601.
 *
 * This magic number came from "nt_time_to_nstime()" in "packet-smb.c".
 * 1970-1601 is 369; I'm not sure what the extra 3 days and 6 hours are
 * that are being subtracted.
 */
#define TIME_FIXUP_CONSTANT (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))

static gboolean peektagged_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
    peektagged_t *peektagged = (peektagged_t *)wth->priv;
    hdr_info_t hdr_info;
    int hdrlen;
    double  t;

    *data_offset = file_tell(wth->fh);

    /* Process the packet header. */
    hdrlen = peektagged_process_header(wth->fh, &hdr_info, err, err_info);
    if (hdrlen == 0)
	return FALSE;

    /*
     * If sliceLength is 0, force it to be the actual length of the packet.
     */
    if (hdr_info.sliceLength == 0)
	hdr_info.sliceLength = hdr_info.length;

    if (hdr_info.sliceLength > WTAP_MAX_PACKET_SIZE) {
	/*
	 * Probably a corrupt capture file; don't blow up trying
	 * to allocate space for an immensely-large packet.
	 */
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup_printf("peektagged: File has %u-byte packet, bigger than maximum of %u",
	    hdr_info.sliceLength, WTAP_MAX_PACKET_SIZE);
	return FALSE;
    }

    wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

    /* fill in packet header length values before slicelength may be
       adjusted */
    wth->phdr.len    = hdr_info.length;
    wth->phdr.caplen = hdr_info.sliceLength;

    /* read the frame data */
    buffer_assure_space(wth->frame_buffer, hdr_info.sliceLength);
    wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
				  hdr_info.sliceLength, wth->fh, err,
				  err_info);

    /* recalculate and fill in packet time stamp */
    t =  (double) hdr_info.timestamp.lower +
	 (double) hdr_info.timestamp.upper * 4294967296.0;

    t *= 1.0e-9;
    t -= TIME_FIXUP_CONSTANT;
    wth->phdr.ts.secs  = (time_t) t;
    wth->phdr.ts.nsecs = (guint32) ((t - wth->phdr.ts.secs)*1000000000);

    switch (wth->file_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	/*
	 * The last 4 bytes sometimes contains the FCS but on a lot of
	 * interfaces these are zero.  Is there some way to determine
	 * from the packet header whether it's an FCS or not?
	 *
	 * For now, we just discard those bytes; if we can determine
	 * whether it's an FCS or not, we should use that to determine
	 * whether to supply it as an FCS or discard it.
	 */
	wth->pseudo_header.ieee_802_11 = hdr_info.ieee_802_11;
	if (peektagged->has_fcs)
	    wth->pseudo_header.ieee_802_11.fcs_len = 4;
	else {
	    wth->pseudo_header.ieee_802_11.fcs_len = 0;
	    wth->phdr.len -= 4;
	    wth->phdr.caplen -= 4;
	}
	wth->pseudo_header.ieee_802_11.decrypted = FALSE;
	break;

    case WTAP_ENCAP_ETHERNET:
	/*
	 * The last 4 bytes appear to be 0 in the captures I've seen;
	 * are there any captures where it's an FCS?
	 */
	wth->pseudo_header.eth.fcs_len = 0;
	wth->phdr.len -= 4;
	wth->phdr.caplen -= 4;
	break;
    }

    return TRUE;
}


static gboolean
peektagged_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
    peektagged_t *peektagged = (peektagged_t *)wth->priv;
    hdr_info_t hdr_info;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	return FALSE;

    /* Process the packet header. */
    if (peektagged_process_header(wth->random_fh, &hdr_info, err, err_info) == -1)
	return FALSE;

    switch (wth->file_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	pseudo_header->ieee_802_11 = hdr_info.ieee_802_11;
	if (peektagged->has_fcs)
	    pseudo_header->ieee_802_11.fcs_len = 4;
	else
	    pseudo_header->ieee_802_11.fcs_len = 0;
	pseudo_header->ieee_802_11.decrypted = FALSE;
	break;

    case WTAP_ENCAP_ETHERNET:
	pseudo_header->eth.fcs_len = 0;
	break;
    }

    /*
     * XXX - should "errno" be set in "wtap_file_read_expected_bytes()"?
     */
    errno = WTAP_ERR_CANT_READ;
    wtap_file_read_expected_bytes(pd, length, wth->random_fh, err, err_info);
    return TRUE;
}
