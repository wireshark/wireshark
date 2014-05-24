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
 * http://www.varsanofiev.com/inside/airopeekv9.htm, the help from
 * Martin Regner and Guy Harris, and the etherpeek.c file (as it
 * was called before renaming it to peekclassic.c).
 */

/*
 * Section header.
 *
 * A Peek tagged file consists of multiple sections, each of which begins
 * with a header in the following format.
 *
 * The section ID is a 4-character string saying what type of section
 * it is.  The section length is a little-endian field giving the
 * length of the section, in bytes, including the section header
 * itself.  The other field of the section header is a little-endian
 * constant that always appears to be 0x00000200.
 *
 * Files we've seen have the following sections, in order:
 *
 * "\177vers" - version information.  The contents are XML, giving
 * the file format version and application version information.
 *
 * "sess" - capture session information.  The contents are XML, giving
 * various information about the capture session.
 *
 * "pkts" - captured packets.  The contents are binary records, one for
 * each packet, with the record being a list of tagged values followed
 * by the raw packet data.
 */
typedef struct peektagged_section_header {
	gint8   section_id[4];		/* string identifying the section */
	guint32 section_len;		/* little-endian section length */
	guint32 section_const;		/* little-endian 0x00000200 */
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
#define TAG_PEEKTAGGED_UNKNOWN_0x000A		0x000A
#define TAG_PEEKTAGGED_UNKNOWN_0x000D		0x000D	/* frequency? */
#define TAG_PEEKTAGGED_UNKNOWN_0x000E		0x000E
#define TAG_PEEKTAGGED_UNKNOWN_0x000F		0x000F	/* 000F-0013 - dBm values? */
#define TAG_PEEKTAGGED_UNKNOWN_0x0010		0x0010
#define TAG_PEEKTAGGED_UNKNOWN_0x0011		0x0011
#define TAG_PEEKTAGGED_UNKNOWN_0x0012		0x0012
#define TAG_PEEKTAGGED_UNKNOWN_0x0013		0x0013
#define TAG_PEEKTAGGED_UNKNOWN_0x0014		0x0014
#define TAG_PEEKTAGGED_UNKNOWN_0x0015		0x0015

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
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);

static int wtap_file_read_pattern (wtap *wth, const char *pattern, int *err,
				gchar **err_info)
{
    int c;
    const char *cp;

    cp = pattern;
    while (*cp)
    {
	c = file_getc(wth->fh);
	if (c == EOF)
	{
	    *err = file_error(wth->fh, err_info);
	    if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
		return -1;	/* error */
	    return 0;	/* EOF */
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
	if (c == EOF)
	{
	    *err = file_error(wth->fh, err_info);
	    if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
		return -1;	/* error */
	    return 0;	/* EOF */
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
    int bytes_read;
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

    bytes_read = file_read(&ap_hdr, (int)sizeof(ap_hdr), wth->fh);
    if (bytes_read != (int)sizeof(ap_hdr)) {
    	*err = file_error(wth->fh, err_info);
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
            return -1;
        return 0;
    }

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

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PEEKTAGGED;
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
 * Time stamps appear to be in nanoseconds since the Windows epoch
 * as used in FILETIMEs, i.e. midnight, January 1, 1601.
 *
 * This magic number came from "nt_time_to_nstime()" in "packet-smb.c".
 * 1970-1601 is 369; I'm not sure what the extra 3 days and 6 hours are
 * that are being subtracted.
 */
#define TIME_FIXUP_CONSTANT (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))

/*
 * Read the packet.
 *
 * XXX - we should supply the additional radio information;
 * the pseudo-header should probably be supplied in a fashion
 * similar to the radiotap radio header, so that the 802.11
 * dissector can determine which, if any, information items
 * are present.
 */
static int
peektagged_read_packet(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
                       Buffer *buf, int *err, gchar **err_info)
{
    peektagged_t *peektagged = (peektagged_t *)wth->priv;
    hdr_info_t hdr_info;
    int header_len = 0;
    int bytes_read;
    guint8 tag_value[6];
    guint16 tag;
    gboolean saw_length = FALSE;
    gboolean saw_timestamp_lower = FALSE;
    gboolean saw_timestamp_upper = FALSE;
    int skip_len = 0;
    double  t;

    memset(&hdr_info, 0, sizeof(hdr_info_t));

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
	    return -1;
	}
	header_len += (int) sizeof(tag_value);
	tag = pletoh16(&tag_value[0]);
	switch (tag) {

	case TAG_PEEKTAGGED_LENGTH:
	    if (saw_length) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("peektagged: record has two length fields");
		return -1;
	    }
	    hdr_info.length = pletoh32(&tag_value[2]);
	    saw_length = TRUE;
	    break;

	case TAG_PEEKTAGGED_TIMESTAMP_LOWER:
	    if (saw_timestamp_lower) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("peektagged: record has two timestamp-lower fields");
		return -1;
	    }
	    hdr_info.timestamp.lower = pletoh32(&tag_value[2]);
	    saw_timestamp_lower = TRUE;
	    break;

	case TAG_PEEKTAGGED_TIMESTAMP_UPPER:
	    if (saw_timestamp_upper) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("peektagged: record has two timestamp-upper fields");
		return -1;
	    }
	    hdr_info.timestamp.upper = pletoh32(&tag_value[2]);
	    saw_timestamp_upper = TRUE;
	    break;

	case TAG_PEEKTAGGED_FLAGS_AND_STATUS:
	    /* XXX - not used yet */
	    break;

	case TAG_PEEKTAGGED_CHANNEL:
	    hdr_info.ieee_802_11.channel = pletoh32(&tag_value[2]);
	    break;

	case TAG_PEEKTAGGED_RATE:
	    hdr_info.ieee_802_11.data_rate = pletoh32(&tag_value[2]);
	    break;

	case TAG_PEEKTAGGED_SIGNAL_PERC:
	    hdr_info.ieee_802_11.signal_level = pletoh32(&tag_value[2]);
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

	case TAG_PEEKTAGGED_UNKNOWN_0x000A:
	    /* XXX - seen in an OmniPeek 802.11n capture; value unknown */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x000D:
	    /* XXX - seen in an EtherPeek capture; value unknown */
	    /* XXX - seen in an AiroPeek/OmniPeek capture; frequency? */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x000E:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; value unknown */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x000F:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; dBm value? */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x0010:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; dBm value? */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x0011:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; dBm value? */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x0012:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; dBm value? */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x0013:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; dBm value? */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x0014:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; value unknown */
	    break;

	case TAG_PEEKTAGGED_UNKNOWN_0x0015:
	    /* XXX - seen in an AiroPeek/OmniPeek capture; value unknown */
	    break;

	case TAG_PEEKTAGGED_SLICE_LENGTH:
	    hdr_info.sliceLength = pletoh32(&tag_value[2]);
	    break;

	default:
	    break;
        }
    } while (tag != TAG_PEEKTAGGED_SLICE_LENGTH);	/* last tag */

    if (!saw_length) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: record has no length field");
	return -1;
    }
    if (!saw_timestamp_lower) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: record has no timestamp-lower field");
	return -1;
    }
    if (!saw_timestamp_upper) {
	*err = WTAP_ERR_BAD_FILE;
	*err_info = g_strdup("peektagged: record has no timestamp-upper field");
	return -1;
    }

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
	return -1;
    }

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    phdr->len    = hdr_info.length;
    phdr->caplen = hdr_info.sliceLength;

    /* calculate and fill in packet time stamp */
    t =  (double) hdr_info.timestamp.lower +
	 (double) hdr_info.timestamp.upper * 4294967296.0;
    t *= 1.0e-9;
    t -= TIME_FIXUP_CONSTANT;
    phdr->ts.secs  = (time_t) t;
    phdr->ts.nsecs = (guint32) ((t - phdr->ts.secs)*1000000000);

    switch (wth->file_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	phdr->pseudo_header.ieee_802_11 = hdr_info.ieee_802_11;
	if (peektagged->has_fcs)
	    phdr->pseudo_header.ieee_802_11.fcs_len = 4;
	else {
	    if (phdr->len < 4 || phdr->caplen < 4) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("peektagged: 802.11 packet has length < 4");
		return FALSE;
	    }
	    phdr->pseudo_header.ieee_802_11.fcs_len = 0;
	    phdr->len -= 4;
	    phdr->caplen -= 4;
	    skip_len = 4;
	}
	phdr->pseudo_header.ieee_802_11.decrypted = FALSE;
	break;

    case WTAP_ENCAP_ETHERNET:
	/*
	 * The last 4 bytes appear to be 0 in the captures I've seen;
	 * are there any captures where it's an FCS?
	 */
	if (phdr->len < 4 || phdr->caplen < 4) {
	    *err = WTAP_ERR_BAD_FILE;
	    *err_info = g_strdup_printf("peektagged: Ethernet packet has length < 4");
	    return FALSE;
	}
	phdr->pseudo_header.eth.fcs_len = 0;
	phdr->len -= 4;
	phdr->caplen -= 4;
	skip_len = 4;
	break;
    }

    /* Read the packet data. */
    if (!wtap_read_packet_bytes(fh, buf, phdr->caplen, err, err_info))
        return -1;

    return skip_len;
}

static gboolean peektagged_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
    int skip_len;

    *data_offset = file_tell(wth->fh);

    /* Read the packet. */
    skip_len = peektagged_read_packet(wth, wth->fh, &wth->phdr,
                                      wth->frame_buffer, err, err_info);
    if (skip_len == -1)
	return FALSE;

    if (skip_len != 0) {
	/* Skip extra junk at the end of the packet data. */
        if (!file_skip(wth->fh, skip_len, err))
	    return FALSE;
    }

    return TRUE;
}

static gboolean
peektagged_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	return FALSE;

    /* Read the packet. */
    if (peektagged_read_packet(wth, wth->random_fh, phdr, buf, err, err_info) == -1) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
	return FALSE;
    }
    return TRUE;
}
