/* 5views.c
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


#define CST_5VW_INFO_HEADER_KEY		0xAAAAAAAAU		/* signature */

#define	CST_5VW_INFO_RECORD_VERSION	0x00010000U		/* version */

#define CST_5VW_DECALE_FILE_TYPE	24
#define CST_5VW_SECTION_CAPTURES	0x08U
#define CST_5VW_CAPTURES_FILE		(CST_5VW_SECTION_CAPTURES << CST_5VW_DECALE_FILE_TYPE)		/* 0x08000000 */
#define CST_5VW_FLAT_FILE		0x10000000U
#define CST_5VW_CAPTURE_FILEID		(CST_5VW_FLAT_FILE | CST_5VW_CAPTURES_FILE)
#define CST_5VW_FAMILY_CAP_ETH		0x01U
#define CST_5VW_FAMILY_CAP_WAN		0x02U
#define CST_5VW_DECALE_FILE_FAMILY	12
#define CST_5VW_CAP_ETH			(CST_5VW_FAMILY_CAP_ETH << CST_5VW_DECALE_FILE_FAMILY)	/* 0x00001000 */
#define CST_5VW_CAP_WAN			(CST_5VW_FAMILY_CAP_WAN << CST_5VW_DECALE_FILE_FAMILY)	/* 0x00002000 */
#define CST_5VW_CAPTURE_ETH_FILEID	(CST_5VW_CAPTURE_FILEID | CST_5VW_CAP_ETH)
#define CST_5VW_CAPTURE_WAN_FILEID	(CST_5VW_CAPTURE_FILEID | CST_5VW_CAP_WAN)

#define CST_5VW_CAPTURE_FILE_TYPE_MASK	0xFF000000U

#define CST_5VW_FRAME_RECORD		0x00000000U
#define CST_5VW_RECORDS_HEADER_KEY	0x3333EEEEU

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


#define CST_5VW_IA_CAP_INF_NB_TRAMES_STOCKEES	0x20000000U
#define CST_5VW_IA_DATE_CREATION		0x80000007U	/* Struct t_Attrib_Date_Create */
#define CST_5VW_TIMESTAMPED_HEADER_TYPE		0x4000U
#define CST_5VW_CAPTURES_RECORD		(CST_5VW_SECTION_CAPTURES << 28)	/* 0x80000000 */
#define CST_5VW_SYSTEM_RECORD		0x00000000U

static gboolean _5views_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean _5views_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);
static int _5views_read_header(wtap *wth, FILE_T fh, t_5VW_TimeStamped_Header *hdr,
    struct wtap_pkthdr *phdr, int *err, gchar **err_info);

static gboolean _5views_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr, const guint8 *pd, int *err, gchar **err_info);
static gboolean _5views_dump_finish(wtap_dumper *wdh, int *err);


wtap_open_return_val
_5views_open(wtap *wth, int *err, gchar **err_info)
{
	t_5VW_Capture_Header Capture_Header;
	int encap = WTAP_ENCAP_UNKNOWN;

	if (!wtap_read_bytes(wth->fh, &Capture_Header.Info_Header,
	    sizeof(t_5VW_Info_Header), err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/*	Check whether that's 5Views format or not */
	if(Capture_Header.Info_Header.Signature != CST_5VW_INFO_HEADER_KEY)
	{
		return WTAP_OPEN_NOT_MINE;
	}

	/* Check Version */
	Capture_Header.Info_Header.Version =
	    pletoh32(&Capture_Header.Info_Header.Version);
	switch (Capture_Header.Info_Header.Version) {

	case CST_5VW_INFO_RECORD_VERSION:
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("5views: header version %u unsupported", Capture_Header.Info_Header.Version);
		return WTAP_OPEN_ERROR;
	}

	/* Check File Type */
	Capture_Header.Info_Header.FileType =
	    pletoh32(&Capture_Header.Info_Header.FileType);
	if((Capture_Header.Info_Header.FileType & CST_5VW_CAPTURE_FILE_TYPE_MASK) != CST_5VW_CAPTURE_FILEID)
	{
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("5views: file is not a capture file (filetype is %u)", Capture_Header.Info_Header.Version);
		return WTAP_OPEN_ERROR;
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
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("5views: network type %u unknown or unsupported",
		    Capture_Header.Info_Header.FileType);
		return WTAP_OPEN_ERROR;
	}

	/* read the remaining header information */
	if (!wtap_read_bytes(wth->fh, &Capture_Header.HeaderDateCreation,
	    sizeof (t_5VW_Capture_Header) - sizeof(t_5VW_Info_Header), err, err_info))
		return WTAP_OPEN_ERROR;

	/* This is a 5views capture file */
	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_5VIEWS;
	wth->subtype_read = _5views_read;
	wth->subtype_seek_read = _5views_seek_read;
	wth->file_encap = encap;
	wth->snapshot_length = 0;	/* not available in header */
	wth->file_tsprec = WTAP_TSPREC_NSEC;

	return WTAP_OPEN_MINE;
}

/* Read the next packet */
static gboolean
_5views_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	t_5VW_TimeStamped_Header TimeStamped_Header;

	/*
	 * Keep reading until we see a record with a subtype of
	 * CST_5VW_FRAME_RECORD.
	 */
	do
	{
		*data_offset = file_tell(wth->fh);

		/* Read record header. */
		if (!_5views_read_header(wth, wth->fh, &TimeStamped_Header,
		    &wth->phdr, err, err_info))
			return FALSE;

		if (TimeStamped_Header.RecSubType == CST_5VW_FRAME_RECORD) {
			/*
			 * OK, this is a packet.
			 */
			break;
		}

		/*
		 * Not a packet - skip to the next record.
		 */
		if (file_seek(wth->fh, TimeStamped_Header.RecSize, SEEK_CUR, err) == -1)
			return FALSE;
	} while (1);

	if (wth->phdr.caplen > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("5views: File has %u-byte packet, bigger than maximum of %u",
		    wth->phdr.caplen, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	return wtap_read_packet_bytes(wth->fh, wth->frame_buffer,
	    wth->phdr.caplen, err, err_info);
}

static gboolean
_5views_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
	t_5VW_TimeStamped_Header TimeStamped_Header;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/*
	 * Read the header.
	 */
	if (!_5views_read_header(wth, wth->random_fh, &TimeStamped_Header,
	    phdr, err, err_info)) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	/*
	 * Read the packet data.
	 */
	return wtap_read_packet_bytes(wth->random_fh, buf, phdr->caplen,
	    err, err_info);
}

/* Read the header of the next packet.  Return TRUE on success, FALSE
   on error. */
static gboolean
_5views_read_header(wtap *wth, FILE_T fh, t_5VW_TimeStamped_Header *hdr,
    struct wtap_pkthdr *phdr, int *err, gchar **err_info)
{
	/* Read record header. */
	if (!wtap_read_bytes_or_eof(fh, hdr, (unsigned int)sizeof(t_5VW_TimeStamped_Header),
	    err, err_info))
		return FALSE;

	hdr->Key = pletoh32(&hdr->Key);
	if (hdr->Key != CST_5VW_RECORDS_HEADER_KEY) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("5views: Time-stamped header has bad key value 0x%08X",
		    hdr->Key);
		return FALSE;
	}

	hdr->RecSubType = pletoh32(&hdr->RecSubType);
	hdr->RecSize = pletoh32(&hdr->RecSize);
	hdr->Utc = pletoh32(&hdr->Utc);
	hdr->NanoSecondes = pletoh32(&hdr->NanoSecondes);

	phdr->rec_type = REC_TYPE_PACKET;
	phdr->presence_flags = WTAP_HAS_TS;
	phdr->ts.secs = hdr->Utc;
	phdr->ts.nsecs = hdr->NanoSecondes;
	phdr->caplen = hdr->RecSize;
	phdr->len = hdr->RecSize;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		phdr->pseudo_header.eth.fcs_len = 0;
		break;
	}

	return TRUE;
}

typedef struct {
	guint32	nframes;
} _5views_dump_t;

static const int wtap_encap[] = {
	-1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
	CST_5VW_CAPTURE_ETH_FILEID,		/* WTAP_ENCAP_ETHERNET -> Ethernet */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int _5views_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (encap < 0 || (unsigned int) encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNWRITABLE_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean _5views_dump_open(wtap_dumper *wdh, int *err)
{
	_5views_dump_t *_5views;

	/* We can't fill in all the fields in the file header, as we
	   haven't yet written any packets.  As we'll have to rewrite
	   the header when we've written out all the packets, we just
	   skip over the header for now. */
	if (wtap_dump_file_seek(wdh, sizeof(t_5VW_Capture_Header), SEEK_SET, err) == -1)
		return FALSE;

	/* This is a 5Views file */
	wdh->subtype_write = _5views_dump;
	wdh->subtype_finish = _5views_dump_finish;
	_5views = (_5views_dump_t *)g_malloc(sizeof(_5views_dump_t));
	wdh->priv = (void *)_5views;
	_5views->nframes = 0;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean _5views_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const guint8 *pd, int *err, gchar **err_info _U_)
{
	_5views_dump_t *_5views = (_5views_dump_t *)wdh->priv;
	t_5VW_TimeStamped_Header HeaderFrame;

	/* We can only write packet records. */
	if (phdr->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_UNWRITABLE_REC_TYPE;
		return FALSE;
	}

	/* Don't write out something bigger than we can read. */
	if (phdr->caplen > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return FALSE;
	}

	/* Frame Header */
	/* constant fields */
	HeaderFrame.Key = GUINT32_TO_LE(CST_5VW_RECORDS_HEADER_KEY);
	HeaderFrame.HeaderSize = GUINT16_TO_LE(sizeof(t_5VW_TimeStamped_Header));
	HeaderFrame.HeaderType = GUINT16_TO_LE(CST_5VW_TIMESTAMPED_HEADER_TYPE);
	HeaderFrame.RecType = GUINT32_TO_LE(CST_5VW_CAPTURES_RECORD | CST_5VW_SYSTEM_RECORD);
	HeaderFrame.RecSubType = GUINT32_TO_LE(CST_5VW_FRAME_RECORD);
	HeaderFrame.RecNb = GUINT32_TO_LE(1);

	/* record-dependent fields */
	HeaderFrame.Utc = GUINT32_TO_LE(phdr->ts.secs);
	HeaderFrame.NanoSecondes = GUINT32_TO_LE(phdr->ts.nsecs);
	HeaderFrame.RecSize = GUINT32_TO_LE(phdr->len);
	HeaderFrame.RecInfo = GUINT32_TO_LE(0);

	/* write the record header */
	if (!wtap_dump_file_write(wdh, &HeaderFrame,
	    sizeof(t_5VW_TimeStamped_Header), err))
		return FALSE;

	/* write the data */
	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;

	_5views->nframes ++;

	return TRUE;
}

static gboolean _5views_dump_finish(wtap_dumper *wdh, int *err)
{
	_5views_dump_t *_5views = (_5views_dump_t *)wdh->priv;
	t_5VW_Capture_Header file_hdr;

	if (wtap_dump_file_seek(wdh, 0, SEEK_SET, err) == -1)
		return FALSE;

	/* fill in the Info_Header */
	file_hdr.Info_Header.Signature = GUINT32_TO_LE(CST_5VW_INFO_HEADER_KEY);
	file_hdr.Info_Header.Size = GUINT32_TO_LE(sizeof(t_5VW_Info_Header));	/* Total size of Header in bytes (included Signature) */
	file_hdr.Info_Header.Version = GUINT32_TO_LE(CST_5VW_INFO_RECORD_VERSION); /* Identify version and so the format of this record */
	file_hdr.Info_Header.DataSize = GUINT32_TO_LE(sizeof(t_5VW_Attributes_Header)
					+ sizeof(guint32)
					+ sizeof(t_5VW_Attributes_Header)
					+ sizeof(guint32));
					/* Total size of data included in the Info Record (except the header size) */
	file_hdr.Info_Header.FileType = GUINT32_TO_LE(wtap_encap[wdh->encap]);	/* Type of the file */
	file_hdr.Info_Header.Reserved[0] = 0;	/* Reserved for future use */
	file_hdr.Info_Header.Reserved[1] = 0;	/* Reserved for future use */
	file_hdr.Info_Header.Reserved[2] = 0;	/* Reserved for future use */

	/* fill in the HeaderDateCreation */
	file_hdr.HeaderDateCreation.Type = GUINT32_TO_LE(CST_5VW_IA_DATE_CREATION);	/* Id of the attribute */
	file_hdr.HeaderDateCreation.Size = GUINT16_TO_LE(sizeof(guint32));	/* Size of the data part of the attribute (not including header size) */
	file_hdr.HeaderDateCreation.Nb = GUINT16_TO_LE(1);			/* Number of elements */

	/* fill in the Time field */
#ifdef _WIN32
	_tzset();
#endif
	file_hdr.Time = GUINT32_TO_LE(time(NULL));

	/* fill in the Time field */
	file_hdr.HeaderNbFrames.Type = GUINT32_TO_LE(CST_5VW_IA_CAP_INF_NB_TRAMES_STOCKEES);	/* Id of the attribute */
	file_hdr.HeaderNbFrames.Size = GUINT16_TO_LE(sizeof(guint32));	/* Size of the data part of the attribute (not including header size) */
	file_hdr.HeaderNbFrames.Nb = GUINT16_TO_LE(1);			/* Number of elements */

	/* fill in the number of frames saved */
	file_hdr.TramesStockeesInFile = GUINT32_TO_LE(_5views->nframes);

	/* Write the file header. */
	if (!wtap_dump_file_write(wdh, &file_hdr, sizeof(t_5VW_Capture_Header),
	    err))
		return FALSE;

	return TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
