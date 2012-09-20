/* btsnoop.c
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
#include "atm.h"
#include "btsnoop.h"

/*
 * Symbian's btsnoop format is derived from Sun's snoop format.
 * See RFC 1761 for a description of the "snoop" file format.
 */

/* Magic number in "btsnoop" files. */
static const char btsnoop_magic[] = {
	'b', 't', 's', 'n', 'o', 'o', 'p', '\0'
};

/* "btsnoop" file header (minus magic number). */
struct btsnoop_hdr {
	guint32	version;	/* version number (should be 1) */
	guint32	datalink;	/* datalink type */
};

/* "btsnoop" record header. */
struct btsnooprec_hdr {
	guint32	orig_len;	/* actual length of packet */
	guint32	incl_len;	/* number of octets captured in file */
	guint32	flags;		/* packet flags */
	guint32	cum_drops;	/* cumulative number of dropped packets */
	gint64	ts_usec;	/* timestamp microseconds */
};

/* H1 is unframed data with the packet type encoded in the flags field of capture header */
/* It can be used for any datalink by placing logging above the datalink layer of HCI */
#define KHciLoggerDatalinkTypeH1		1001
/* H4 is the serial HCI with packet type encoded in the first byte of each packet */
#define KHciLoggerDatalinkTypeH4		1002
/* CSR's PPP derived bluecore serial protocol - in practice we log in H1 format after deframing */
#define KHciLoggerDatalinkTypeBCSP		1003
/* H5 is the official three wire serial protocol derived from BCSP*/
#define KHciLoggerDatalinkTypeH5		1004

#define KHciLoggerHostToController		0
#define KHciLoggerControllerToHost		0x00000001
#define KHciLoggerACLDataFrame			0
#define KHciLoggerCommandOrEvent		0x00000002

const gint64 KUnixTimeBase = G_GINT64_CONSTANT(0x00dcddb30f2f8000); /* offset from symbian - unix time */

static gboolean btsnoop_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean btsnoop_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static gboolean snoop_read_rec_data(FILE_T fh, guint8 *pd, int length, int *err,
    gchar **err_info);

int btsnoop_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic[sizeof btsnoop_magic];
	struct btsnoop_hdr hdr;

	int file_encap=WTAP_ENCAP_UNKNOWN;

	/* Read in the string that should be at the start of a "btsnoop" file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	if (memcmp(magic, btsnoop_magic, sizeof btsnoop_magic) != 0) {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	/*
	 * Make sure it's a version we support.
	 */
	hdr.version = g_ntohl(hdr.version);
	if (hdr.version != 1) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("btsnoop: version %u unsupported", hdr.version);
		return -1;
	}

	hdr.datalink = g_ntohl(hdr.datalink);
	switch (hdr.datalink) {
	case KHciLoggerDatalinkTypeH1:
		file_encap=WTAP_ENCAP_BLUETOOTH_HCI;
		break;
	case KHciLoggerDatalinkTypeBCSP:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("btsnoop: BCSP capture logs unsupported");
		return -1;
	case KHciLoggerDatalinkTypeH5:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("btsnoop: H5 capture logs unsupported");
		return -1;
	case KHciLoggerDatalinkTypeH4:
		file_encap=WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR;
		break;
	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("btsnoop: datalink type %u unknown or unsupported", hdr.datalink);
		return -1;
	}

	wth->subtype_read = btsnoop_read;
	wth->subtype_seek_read = btsnoop_seek_read;
	wth->file_encap = file_encap;
	wth->snapshot_length = 0;	/* not available in header */
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;
	wth->file_type = WTAP_FILE_BTSNOOP;
	return 1;
}

static gboolean btsnoop_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	guint32 packet_size;
	guint32 flags;
	guint32 orig_size;
	int	bytes_read;
	struct btsnooprec_hdr hdr;
	gint64 ts;

	/* As the send/receive flag is stored in the middle of the capture header 
	but needs to go in the pseudo header for wiretap, the header needs to be reread
	in the seek_read function*/
	*data_offset = file_tell(wth->fh);

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	packet_size = g_ntohl(hdr.incl_len);
	orig_size = g_ntohl(hdr.orig_len);
	flags = g_ntohl(hdr.flags);
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("btsnoop: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	buffer_assure_space(wth->frame_buffer, packet_size);
	if (!snoop_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
		packet_size, err, err_info)) {
		return FALSE;	/* Read error */
	}

	ts = GINT64_FROM_BE(hdr.ts_usec);
	ts -= KUnixTimeBase;

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
	wth->phdr.ts.secs = (guint)(ts / 1000000);
	wth->phdr.ts.nsecs = (guint)((ts % 1000000) * 1000);
	wth->phdr.caplen = packet_size;
	wth->phdr.len = orig_size;
	if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR)
	{
		wth->pseudo_header.p2p.sent = (flags & KHciLoggerControllerToHost) ? FALSE : TRUE;
	}
	else if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_HCI)
	{
		wth->pseudo_header.bthci.sent = (flags & KHciLoggerControllerToHost) ? FALSE : TRUE;
		if(flags & KHciLoggerCommandOrEvent)
		{
			if(wth->pseudo_header.bthci.sent)
			{
				wth->pseudo_header.bthci.channel = BTHCI_CHANNEL_COMMAND;
			}
			else
			{
				wth->pseudo_header.bthci.channel = BTHCI_CHANNEL_EVENT;
			}
		}
		else
		{
			wth->pseudo_header.bthci.channel = BTHCI_CHANNEL_ACL;
		}
	}
	return TRUE;
}

static gboolean btsnoop_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info) {
	int	bytes_read;
	struct btsnooprec_hdr hdr;
	guint32 flags;
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->random_fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->random_fh, err_info);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	flags = g_ntohl(hdr.flags);

	/*
	 * Read the packet data.
	 */
	if (!snoop_read_rec_data(wth->random_fh, pd, length, err, err_info))
		return FALSE;	/* failed */

	if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR)
	{
		pseudo_header->p2p.sent = (flags & KHciLoggerControllerToHost) ? FALSE : TRUE;
	}
	else if(wth->file_encap == WTAP_ENCAP_BLUETOOTH_HCI)
	{
		pseudo_header->bthci.sent = (flags & KHciLoggerControllerToHost) ? FALSE : TRUE;
		if(flags & KHciLoggerCommandOrEvent)
		{
			if(pseudo_header->bthci.sent)
			{
				pseudo_header->bthci.channel = BTHCI_CHANNEL_COMMAND;
			}
			else
			{
				pseudo_header->bthci.channel = BTHCI_CHANNEL_EVENT;
			}
		}
		else
		{
			pseudo_header->bthci.channel = BTHCI_CHANNEL_ACL;
		}
	}
	return TRUE;
}

static gboolean
snoop_read_rec_data(FILE_T fh, guint8 *pd, int length, int *err,
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

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int btsnoop_dump_can_write_encap(int encap)
{
    /* Per-packet encapsulations aren't supported. */
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    /* XXX - for now we only support WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR */
    if (encap != WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR)
        return WTAP_ERR_UNSUPPORTED_ENCAP;

    return 0;
}

struct hci_flags_mapping
{
    guint8 hci_type;
    guint8 sent;
    guint8 flags;
};

static const struct hci_flags_mapping hci_flags[] =
{
    { 0x02, TRUE,   KHciLoggerHostToController|KHciLoggerACLDataFrame   }, /* HCI_H4_TYPE_ACL */
    { 0x02, FALSE,  KHciLoggerControllerToHost|KHciLoggerACLDataFrame   }, /* HCI_H4_TYPE_ACL */
    { 0x01, TRUE,   KHciLoggerHostToController|KHciLoggerCommandOrEvent }, /* HCI_H4_TYPE_CMD */
    { 0x04, FALSE,  KHciLoggerControllerToHost|KHciLoggerCommandOrEvent }, /* HCI_H4_TYPE_EVT */
};

static guint8 btsnoop_lookup_flags(guint8 hci_type, gboolean sent, guint8 *flags)
{
    guint8 i;

    for (i=0; i < G_N_ELEMENTS(hci_flags); ++i)
    {
        if (hci_flags[i].hci_type == hci_type &&
            hci_flags[i].sent == sent)
        {
            *flags = hci_flags[i].flags;
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean btsnoop_dump_partial_rec_hdr(wtap_dumper *wdh _U_,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header,
    const guint8 *pd, int *err,
    struct btsnooprec_hdr *rec_hdr)
{
    gint64 ts_usec;
    guint8 flags = 0;

    if (!btsnoop_lookup_flags(*pd, pseudo_header->p2p.sent, &flags)) {
        *err = WTAP_ERR_UNSUPPORTED;
        return FALSE;
    }

    ts_usec  = ((gint64) phdr->ts.secs * 1000000) + ((gint64) phdr->ts.nsecs / 1000);
    ts_usec += KUnixTimeBase;

    rec_hdr->flags = GUINT32_TO_BE(flags);
    rec_hdr->cum_drops = GUINT32_TO_BE(0);
    rec_hdr->ts_usec = GINT64_TO_BE(ts_usec);

    return TRUE;
}

/* FIXME: How do we support multiple backends?*/
static gboolean btsnoop_dump_h1(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header,
    const guint8 *pd, int *err)
{
    struct btsnooprec_hdr rec_hdr;

    if (!btsnoop_dump_partial_rec_hdr(wdh, phdr, pseudo_header, pd, err, &rec_hdr))
        return FALSE;

    rec_hdr.incl_len = GUINT32_TO_BE(phdr->caplen-1);
    rec_hdr.orig_len = GUINT32_TO_BE(phdr->len-1);

    if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof rec_hdr;

    /* Skip HCI packet type */
    ++pd;

    if (!wtap_dump_file_write(wdh, pd, phdr->caplen-1, err))
        return FALSE;

    wdh->bytes_dumped += phdr->caplen-1;

    return TRUE;
}

static gboolean btsnoop_dump_h4(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header,
    const guint8 *pd, int *err)
{
    struct btsnooprec_hdr rec_hdr;

    if (!btsnoop_dump_partial_rec_hdr(wdh, phdr, pseudo_header, pd, err, &rec_hdr))
        return FALSE;

    rec_hdr.incl_len = GUINT32_TO_BE(phdr->caplen);
    rec_hdr.orig_len = GUINT32_TO_BE(phdr->len);

    if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof rec_hdr;

    if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
        return FALSE;

    wdh->bytes_dumped += phdr->caplen;

    return TRUE;
}

/* FIXME: How do we support multiple backends?*/
gboolean btsnoop_dump_open_h1(wtap_dumper *wdh, int *err)
{
    struct btsnoop_hdr file_hdr;

    /* This is a libpcap file */
    wdh->subtype_write = btsnoop_dump_h1;
    wdh->subtype_close = NULL;

    /* Write the file header. */
    switch (wdh->file_type) {

    case WTAP_FILE_BTSNOOP:
        wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
        break;

    default:
        /* We should never get here - our open routine
           should only get called for the types above. */
        *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
        return FALSE;
    }

    if (!wtap_dump_file_write(wdh, btsnoop_magic, sizeof btsnoop_magic, err))
        return FALSE;

    wdh->bytes_dumped += sizeof btsnoop_magic;

    /* current "btsnoop" format is 1 */
    file_hdr.version  = GUINT32_TO_BE(1);
    /* HCI type encoded in first byte */
    file_hdr.datalink = GUINT32_TO_BE(KHciLoggerDatalinkTypeH1);

    if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof file_hdr;

    return TRUE;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean btsnoop_dump_open_h4(wtap_dumper *wdh, int *err)
{
    struct btsnoop_hdr file_hdr;

    /* This is a libpcap file */
    wdh->subtype_write = btsnoop_dump_h4;
    wdh->subtype_close = NULL;

    /* Write the file header. */
    switch (wdh->file_type) {

    case WTAP_FILE_BTSNOOP:
        wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
        break;

    default:
        /* We should never get here - our open routine
           should only get called for the types above. */
        *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
        return FALSE;
    }

    if (!wtap_dump_file_write(wdh, btsnoop_magic, sizeof btsnoop_magic, err))
        return FALSE;

    wdh->bytes_dumped += sizeof btsnoop_magic;

    /* current "btsnoop" format is 1 */
    file_hdr.version  = GUINT32_TO_BE(1);
    /* HCI type encoded in first byte */
    file_hdr.datalink = GUINT32_TO_BE(KHciLoggerDatalinkTypeH4);

    if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
        return FALSE;

    wdh->bytes_dumped += sizeof file_hdr;

    return TRUE;
}

