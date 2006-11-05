/* 5views.c
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
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "5views.h"


typedef struct
{
	guint32	Signature;
	guint32	Size;		/* Total size of Header in bytes (included Signature) */
	guint32	Version;	/* Identify version and so the format of this record */
	guint32	DataSize;	/* Total size of data included in the Info Record (except the header size) */
	guint32	FileType;	/* Type of the file */
	guint32	Reserved[3];	/* Reserved for future use */
}t_5VW_Info_Header;

typedef struct
{
	guint32	Type;	/* Id of the attribute */
	guint16	Size;	/* Size of the data part of the attribute (not including header size) */
	guint16	Nb;	/* Number of elements */
}t_5VW_Attributes_Header;


#define CST_5VW_INFO_HEADER_KEY		0xAAAAAAAA		/* signature */

#define	CST_5VW_INFO_RECORD_VERSION	0x00010000		/* version */

#define CST_5VW_DECALE_FILE_TYPE	24
#define CST_5VW_SECTION_CAPTURES	0x08
#define CST_5VW_CAPTURES_FILE		(CST_5VW_SECTION_CAPTURES << CST_5VW_DECALE_FILE_TYPE)		/* 0x08000000 */
#define CST_5VW_FLAT_FILE		0x10000000
#define CST_5VW_CAPTURE_FILEID		(CST_5VW_FLAT_FILE | CST_5VW_CAPTURES_FILE)
#define CST_5VW_FAMILY_CAP_ETH		0x01
#define CST_5VW_FAMILY_CAP_WAN		0x02
#define CST_5VW_DECALE_FILE_FAMILY	12
#define CST_5VW_CAP_ETH			(CST_5VW_FAMILY_CAP_ETH << CST_5VW_DECALE_FILE_FAMILY)	/* 0x00001000 */
#define CST_5VW_CAP_WAN			(CST_5VW_FAMILY_CAP_WAN << CST_5VW_DECALE_FILE_FAMILY)	/* 0x00002000 */
#define CST_5VW_CAPTURE_ETH_FILEID	(CST_5VW_CAPTURE_FILEID | CST_5VW_CAP_ETH)
#define CST_5VW_CAPTURE_WAN_FILEID	(CST_5VW_CAPTURE_FILEID | CST_5VW_CAP_WAN)

#define CST_5VW_CAPTURE_FILE_TYPE_MASK	0xFF000000

#define CST_5VW_FRAME_RECORD		0x00000000
#define CST_5VW_RECORDS_HEADER_KEY	0x3333EEEE

typedef struct
{
	t_5VW_Info_Header	Info_Header;
	t_5VW_Attributes_Header	HeaderDateCreation;
	guint32			Time;
	t_5VW_Attributes_Header	HeaderNbFrames;
	guint32			TramesStockeesInFile;
}t_5VW_Capture_Header;

typedef struct
{
	guint32	Key;			/* 0x3333EEEE */
	guint16	HeaderSize;		/* Actual size of this header in bytes (32) */
	guint16	HeaderType;		/* Exact type of this header (0x4000) */
	guint32	RecType;		/* Type of record */
	guint32	RecSubType;		/* Subtype of record */
	guint32	RecSize;		/* Size of one record */
	guint32	RecNb;			/* Number of records */
	guint32	Utc;
	guint32	NanoSecondes;
	guint32	RecInfo;		/* Info about Alarm / Event / Frame captured */
}t_5VW_TimeStamped_Header;


#define CST_5VW_IA_CAP_INF_NB_TRAMES_STOCKEES	0x20000000
#define CST_5VW_IA_DATE_CREATION		0x80000007	/* Struct t_Attrib_Date_Create */
#define CST_5VW_TIMESTAMPED_HEADER_TYPE		0x4000
#define CST_5VW_CAPTURES_RECORD		(CST_5VW_SECTION_CAPTURES << 28)	/* 0x80000000 */
#define CST_5VW_SYSTEM_RECORD		0x00000000

static gboolean _5views_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean _5views_read_rec_data(FILE_T fh, guchar *pd, int length,
    int *err);
static int _5views_read_header(wtap *wth, FILE_T fh,
    t_5VW_TimeStamped_Header  *hdr, int *err);
static gboolean _5views_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info);


static gboolean _5views_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
							 const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);
static gboolean _5views_dump_close(wtap_dumper *wdh, int *err);


int _5views_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	t_5VW_Capture_Header Capture_Header;
	int encap = WTAP_ENCAP_UNKNOWN;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&Capture_Header.Info_Header, 1, sizeof(t_5VW_Info_Header), wth->fh);
	if (bytes_read != sizeof(t_5VW_Info_Header)) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	wth->data_offset+=bytes_read;

	/*	Check whether that's 5Views format or not */
	if(Capture_Header.Info_Header.Signature != CST_5VW_INFO_HEADER_KEY)
	{
		return 0;
	}

	/* Check Version */
	Capture_Header.Info_Header.Version =
	    pletohl(&Capture_Header.Info_Header.Version);
	switch (Capture_Header.Info_Header.Version) {

	case CST_5VW_INFO_RECORD_VERSION:
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("5views: header version %u unsupported", Capture_Header.Info_Header.Version);
		return -1;
	}

	/* Check File Type */
	Capture_Header.Info_Header.FileType =
	    pletohl(&Capture_Header.Info_Header.FileType);
	if((Capture_Header.Info_Header.FileType & CST_5VW_CAPTURE_FILE_TYPE_MASK) != CST_5VW_CAPTURE_FILEID)
	{
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("5views: file is not a capture file (filetype is %u)", Capture_Header.Info_Header.Version);
		return -1;
	}

	/* Check possible Encap */
	switch (Capture_Header.Info_Header.FileType) {
	case CST_5VW_CAPTURE_ETH_FILEID:
		encap = WTAP_ENCAP_ETHERNET;
		break;
/*	case CST_5VW_CAPTURE_WAN_FILEID:
		break;
*/
	default:
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("5views: network type %u unknown or unsupported",
		    Capture_Header.Info_Header.FileType);
		return -1;
	}

	/* read the remaining header information */
	bytes_read = file_read(&Capture_Header.HeaderDateCreation, 1, sizeof (t_5VW_Capture_Header) - sizeof(t_5VW_Info_Header), wth->fh);
	if (bytes_read != sizeof (t_5VW_Capture_Header)- sizeof(t_5VW_Info_Header) ) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset+=bytes_read;

	/* This is a 5views capture file */
	wth->file_type = WTAP_FILE_5VIEWS;
	wth->subtype_read = _5views_read;
	wth->subtype_seek_read = _5views_seek_read;
	wth->file_encap = encap;
	wth->snapshot_length = 0;	/* not available in header */
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

	return 1;
}

/* Read the next packet */
static gboolean
_5views_read(wtap *wth, int *err, gchar **err_info _U_, gint64 *data_offset)
{
	t_5VW_TimeStamped_Header TimeStamped_Header;
	int	bytes_read;
	guint packet_size;
	guint orig_size;

	do
	{
		bytes_read = _5views_read_header(wth, wth->fh, &TimeStamped_Header, err);
		if (bytes_read == -1) {
			/*
			 * We failed to read the header.
			 */
			return FALSE;
		}
		wth->data_offset += bytes_read;

		TimeStamped_Header.Key = pletohl(&TimeStamped_Header.Key);
		if(TimeStamped_Header.Key != CST_5VW_RECORDS_HEADER_KEY)
			return FALSE;

		TimeStamped_Header.RecSubType =
		    pletohl(&TimeStamped_Header.RecSubType);
		TimeStamped_Header.RecSize =
		    pletohl(&TimeStamped_Header.RecSize);
		if(TimeStamped_Header.RecSubType != CST_5VW_FRAME_RECORD) {
			if (file_seek(wth->fh, TimeStamped_Header.RecSize, SEEK_SET, err) == -1)
				return FALSE;
			wth->data_offset += TimeStamped_Header.RecSize;
		} else
			break;
	} while (1);

	packet_size = TimeStamped_Header.RecSize;
	orig_size = TimeStamped_Header.RecSize;

	*data_offset = wth->data_offset;

	buffer_assure_space(wth->frame_buffer, packet_size);
	if (!_5views_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
	    packet_size, err))
		return FALSE;	/* Read error */

	wth->data_offset += packet_size;
	TimeStamped_Header.Utc = pletohl(&TimeStamped_Header.Utc);
	TimeStamped_Header.NanoSecondes =
	    pletohl(&TimeStamped_Header.NanoSecondes);
	wth->phdr.ts.secs = TimeStamped_Header.Utc;
	wth->phdr.ts.nsecs = TimeStamped_Header.NanoSecondes;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = orig_size;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		wth->pseudo_header.eth.fcs_len = 0;
		break;
	}

	return TRUE;
}



static gboolean
_5views_read_rec_data(FILE_T fh, guchar *pd, int length, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, 1, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}


/* Read the header of the next packet; if "silent" is TRUE, don't complain
   to the console, as we're testing to see if the file appears to be of a
   particular type.

   Return -1 on an error, or the number of bytes of header read on success. */
static int
_5views_read_header(wtap *wth _U_, FILE_T fh, t_5VW_TimeStamped_Header  *hdr,   int *err)
{
	int	bytes_read, bytes_to_read;

	bytes_to_read = sizeof(t_5VW_TimeStamped_Header);

	/* Read record header. */
	bytes_read = file_read(hdr, 1, bytes_to_read, fh);
	if (bytes_read != bytes_to_read) {
		*err = file_error(fh);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	return bytes_read;
}

static gboolean
_5views_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info _U_)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;
	/*
	 * Read the packet data.
	 */
	if (!_5views_read_rec_data(wth->random_fh, pd, length, err))
		return FALSE;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		pseudo_header->eth.fcs_len = 0;
		break;
	}

	return TRUE;
}



static const int wtap_encap[] = {
	-1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
	CST_5VW_CAPTURE_ETH_FILEID,		/* WTAP_ENCAP_ETHERNET -> Ehernet Ethernet */
	-1,		/* WTAP_ENCAP_TOKEN_RING -> unsupported */
	-1,		/* WTAP_ENCAP_SLIP -> unsupported */
	-1,		/* WTAP_ENCAP_PPP -> unsupported */
	-1,		/* WTAP_ENCAP_FDDI -> unsupported */
	-1,		/* WTAP_ENCAP_FDDI_BITSWAPPED -> unsupported */
	-1,		/* WTAP_ENCAP_RAW_IP -> unsupported */
	-1,		/* WTAP_ENCAP_ARCNET -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_RFC1483 -> unsupported */
	-1,		/* WTAP_ENCAP_LINUX_ATM_CLIP -> unsupported */
	-1,		/* WTAP_ENCAP_LAPB -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_PDUS -> unsupported */
	-1		/* WTAP_ENCAP_NULL -> unsupported */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int _5views_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (encap < 0 || (unsigned) encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean _5views_dump_open(wtap_dumper *wdh, gboolean cant_seek _U_, int *err)
{

	/* We can't fill in all the fields in the file header, as we
	   haven't yet written any packets.  As we'll have to rewrite
	   the header when we've written out all the packets, we just
	   skip over the header for now. */
	if (fseek(wdh->fh, sizeof(t_5VW_Capture_Header), SEEK_SET) == -1) {
		*err = errno;
		return FALSE;
	}

	/* This is a 5Views file */
	wdh->subtype_write = _5views_dump;
	wdh->subtype_close = _5views_dump_close;
	wdh->dump._5views = g_malloc(sizeof(_5views_dump_t));
	wdh->dump._5views->nframes = 0;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean _5views_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guchar *pd, int *err)
{

	size_t nwritten;
	static t_5VW_TimeStamped_Header HeaderFrame;

	/* Frame Header */
	/* constant fields */
	HeaderFrame.Key = htolel(CST_5VW_RECORDS_HEADER_KEY);
	HeaderFrame.HeaderSize = htoles(sizeof(t_5VW_TimeStamped_Header));
	HeaderFrame.HeaderType = htoles(CST_5VW_TIMESTAMPED_HEADER_TYPE);
	HeaderFrame.RecType = htolel(CST_5VW_CAPTURES_RECORD | CST_5VW_SYSTEM_RECORD);
	HeaderFrame.RecSubType = htolel(CST_5VW_FRAME_RECORD);
	HeaderFrame.RecNb = htolel(1);

	/* record-dependant fields */
	HeaderFrame.Utc = htolel(phdr->ts.secs);
	HeaderFrame.NanoSecondes = htolel(phdr->ts.nsecs);
	HeaderFrame.RecSize = htolel(phdr->len);
	HeaderFrame.RecInfo = htolel(0);

	/* write the record header */
	nwritten = fwrite(&HeaderFrame, 1, sizeof(t_5VW_TimeStamped_Header), wdh->fh);
	if (nwritten != sizeof(t_5VW_TimeStamped_Header)) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	/* write the data */
	nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
	if (nwritten != phdr->caplen) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	wdh->dump._5views->nframes ++;

	return TRUE;
}

static gboolean _5views_dump_close(wtap_dumper *wdh, int *err)
{
	t_5VW_Capture_Header file_hdr;
	size_t nwritten;

	if (fseek(wdh->fh, 0, SEEK_SET) == -1) {
		*err = errno;
		return FALSE;
	}

	/* fill in the Info_Header */
	file_hdr.Info_Header.Signature = htolel(CST_5VW_INFO_HEADER_KEY);
	file_hdr.Info_Header.Size = htolel(sizeof(t_5VW_Info_Header));	/* Total size of Header in bytes (included Signature) */
	file_hdr.Info_Header.Version = htolel(CST_5VW_INFO_RECORD_VERSION); /* Identify version and so the format of this record */
	file_hdr.Info_Header.DataSize = htolel(sizeof(t_5VW_Attributes_Header)
					+ sizeof(guint32)
					+ sizeof(t_5VW_Attributes_Header)
					+ sizeof(guint32));
					/* Total size of data included in the Info Record (except the header size) */
	file_hdr.Info_Header.FileType = htolel(wtap_encap[wdh->encap]);	/* Type of the file */
	file_hdr.Info_Header.Reserved[0] = 0;	/* Reserved for future use */
	file_hdr.Info_Header.Reserved[1] = 0;	/* Reserved for future use */
	file_hdr.Info_Header.Reserved[2] = 0;	/* Reserved for future use */

	/* fill in the HeaderDateCreation */
	file_hdr.HeaderDateCreation.Type = htolel(CST_5VW_IA_DATE_CREATION);	/* Id of the attribute */
	file_hdr.HeaderDateCreation.Size = htoles(sizeof(guint32));	/* Size of the data part of the attribute (not including header size) */
	file_hdr.HeaderDateCreation.Nb = htoles(1);			/* Number of elements */

	/* fill in the Time field */
#ifdef _WIN32
	_tzset();
#endif
	file_hdr.Time = htolel(time(NULL));

	/* fill in the Time field */
	file_hdr.HeaderNbFrames.Type = htolel(CST_5VW_IA_CAP_INF_NB_TRAMES_STOCKEES);	/* Id of the attribute */
	file_hdr.HeaderNbFrames.Size = htoles(sizeof(guint32));	/* Size of the data part of the attribute (not including header size) */
	file_hdr.HeaderNbFrames.Nb = htoles(1);			/* Number of elements */

	/* fill in the number of frames saved */
	file_hdr.TramesStockeesInFile = htolel(wdh->dump._5views->nframes);

	/* Write the file header. */
	nwritten = fwrite(&file_hdr, 1, sizeof(t_5VW_Capture_Header), wdh->fh);
	if (nwritten != sizeof(t_5VW_Capture_Header)) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	return TRUE;
}
