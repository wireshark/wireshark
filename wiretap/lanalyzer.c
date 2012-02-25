/* lanalyzer.c
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
#include <stdlib.h>
#include <errno.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "lanalyzer.h"

/* The LANalyzer format is documented (at least in part) in Novell document
   TID022037, which can be found at, among other places:

	http://www.windowsecurity.com/whitepapers/Description_of_the_LANalysers_output_file.html
 */

/*    Record header format */

typedef struct {
	guint8	record_type[2];
	guint8	record_length[2];
} LA_RecordHeader;

#define LA_RecordHeaderSize 4

/*    Record type codes:                */

#define     RT_HeaderRegular       0x1001
#define     RT_HeaderCyclic        0x1007
#define     RT_RxChannelName       0x1006
#define     RT_TxChannelName       0x100b
#define     RT_FilterName          0x1032
#define     RT_RxTemplateName      0x1035
#define     RT_TxTemplateName      0x1036
#define     RT_DisplayOptions      0x100a
#define     RT_Summary             0x1002
#define     RT_SubfileSummary      0x1003
#define     RT_CyclicInformation   0x1009
#define     RT_Index               0x1004
#define     RT_PacketData          0x1005

#define     LA_ProFileLimit       (1024 * 1024 * 32)

typedef guint8  Eadr[6];
typedef guint16 TimeStamp[3];  /* 0.5 microseconds since start of trace */

/*
 * These records have only 2-byte alignment for 4-byte quantities,
 * so the structures aren't necessarily valid; they're kept as comments
 * for reference purposes.
 */

/*
 * typedef struct {
 *       guint8      day;
 *       guint8      mon;
 *       gint16      year;
 *       } Date;
 */

/*
 * typedef struct {
 *       guint8      second;
 *       guint8      minute;
 *       guint8      hour;
 *       guint8      day;
 *       gint16      reserved;
 *       } Time;
 */

/*
 * RT_Summary:
 *
 * typedef struct {
 *       Date        datcre;
 *       Date        datclo;
 *       Time        timeopn;
 *       Time        timeclo;
 *       Eadr        statadr;
 *       gint16      mxseqno;
 *       gint16      slcoff;
 *       gint16      mxslc;
 *       gint32      totpktt;
 *       gint32      statrg;
 *       gint32      stptrg;
 *       gint32      mxpkta[36];
 *       gint16      board_type;
 *       gint16      board_version;
 *       gint8       reserved[18];
 *       } Summary;
 */

#define SummarySize (18+22+(4*36)+6+6+6+4+4)

/*
 * typedef struct {
 *       gint16      rid;
 *       gint16      rlen;
 *       Summary     s;
 *       } LA_SummaryRecord;
 */

#define LA_SummaryRecordSize (SummarySize + 4)

/* LANalyzer board types (which indicate the type of network on which
   the capture was done). */
#define BOARD_325		226	/* LANalyzer 325 (Ethernet) */
#define BOARD_325TR		227	/* LANalyzer 325TR (Token-ring) */


/*
 * typedef struct {
 *       gint16      rid;
 *       gint16      rlen;
 *       gint16      seqno;
 *       gint32      totpktf;
 *       } LA_SubfileSummaryRecord;
 */

#define LA_SubfileSummaryRecordSize 10


#define LA_IndexSize 500

/*
 * typedef struct {
 *       gint16      rid;
 *       gint16      rlen;
 *       gint16      idxsp;                    = LA_IndexSize
 *       gint16      idxct;
 *       gint8       idxgranu;
 *       gint8       idxvd;
 *       gint32      trcidx[LA_IndexSize + 2]; +2 undocumented but used by La 2.2
 *       } LA_IndexRecord;
 */

#define LA_IndexRecordSize (10 + 4 * (LA_IndexSize + 2))


/*
 * typedef struct {
 *       guint16     rx_channels;
 *       guint16     rx_errors;
 *       gint16      rx_frm_len;
 *       gint16      rx_frm_sln;
 *       TimeStamp   rx_time;
 *       guint32     pktno;
 *       gint16      prvlen;
 *       gint16      offset;
 *       gint16      tx_errs;
 *       gint16      rx_filters;
 *       gint8       unused[2];
 *       gint16      hwcolls;
 *       gint16      hwcollschans;
 *       Packetdata ....;
 *       } LA_PacketRecord;
 */

#define LA_PacketRecordSize 32

typedef struct {
      gboolean        init;
      struct timeval  start;
      guint32         pkts;
      int             encap;
      int             lastlen;
      } LA_TmpInfo;

static const guint8 LA_HeaderRegularFake[] = {
0x01,0x10,0x4c,0x00,0x01,0x05,0x54,0x72,0x61,0x63,0x65,0x20,0x44,0x69,0x73,0x70,
0x6c,0x61,0x79,0x20,0x54,0x72,0x61,0x63,0x65,0x20,0x46,0x69,0x6c,0x65,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
      };

static const guint8 LA_RxChannelNameFake[] = {
0x06,0x10,0x80,0x00,0x43,0x68,0x61,0x6e ,0x6e,0x65,0x6c,0x31,0x00,0x43,0x68,0x61,
0x6e,0x6e,0x65,0x6c,0x32,0x00,0x43,0x68 ,0x61,0x6e,0x6e,0x65,0x6c,0x33,0x00,0x43,
0x68,0x61,0x6e,0x6e,0x65,0x6c,0x34,0x00 ,0x43,0x68,0x61,0x6e,0x6e,0x65,0x6c,0x35,
0x00,0x43,0x68,0x61,0x6e,0x6e,0x65,0x6c ,0x36,0x00,0x43,0x68,0x61,0x6e,0x6e,0x65,
0x6c,0x37,0x00,0x43,0x68,0x61,0x6e,0x6e ,0x65,0x6c,0x38,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00
      };

static const guint8 LA_TxChannelNameFake[] = {
                    0x0b,0x10,0x36,0x00 ,0x54,0x72,0x61,0x6e,0x73,0x31,0x00,0x00,
0x00,0x54,0x72,0x61,0x6e,0x73,0x32,0x00 ,0x00,0x00,0x54,0x72,0x61,0x6e,0x73,0x33,
0x00,0x00,0x00,0x54,0x72,0x61,0x6e,0x73 ,0x34,0x00,0x00,0x00,0x54,0x72,0x61,0x6e,
0x73,0x35,0x00,0x00,0x00,0x54,0x72,0x61 ,0x6e,0x73,0x36,0x00,0x00,0x00
      };

static const guint8 LA_RxTemplateNameFake[] = {
                                                                       0x35,0x10,
0x90,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00
      };

static const guint8 LA_TxTemplateNameFake[] = {
          0x36,0x10,0x36,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00
      };

static const guint8 LA_DisplayOptionsFake[] = {
                                                             0x0a,0x10,0x0a,0x01,
0x00,0x00,0x01,0x00,0x01,0x02,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00
      };

static const guint8 LA_CyclicInformationFake[] = {
                                                   0x09,0x10,0x1a,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
      };

typedef struct {
	time_t	start;
} lanalyzer_t;

static gboolean lanalyzer_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean lanalyzer_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static gboolean lanalyzer_dump_close(wtap_dumper *wdh, int *err);

int lanalyzer_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	LA_RecordHeader rec_header;
	char summary[210];
	guint16 board_type, mxslc;
	guint16 record_type, record_length;
	guint8 cr_day, cr_month;
	guint16 cr_year;
	struct tm tm;
	lanalyzer_t *lanalyzer;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&rec_header, LA_RecordHeaderSize, wth->fh);
	if (bytes_read != LA_RecordHeaderSize) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += LA_RecordHeaderSize;
	record_type = pletohs(rec_header.record_type);
	record_length = pletohs(rec_header.record_length); /* make sure to do this for while() loop */

	if (record_type != RT_HeaderRegular && record_type != RT_HeaderCyclic) {
		return 0;
	}

	/* If we made it this far, then the file is a LANAlyzer file.
	 * Let's get some info from it. Note that we get wth->snapshot_length
	 * from a record later in the file. */
	wth->file_type = WTAP_FILE_LANALYZER;
	lanalyzer = (lanalyzer_t *)g_malloc(sizeof(lanalyzer_t));;
	wth->priv = (void *)lanalyzer;
	wth->subtype_read = lanalyzer_read;
	wth->subtype_seek_read = lanalyzer_seek_read;
	wth->snapshot_length = 0;
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

	/* Read records until we find the start of packets */
	while (1) {
		if (file_seek(wth->fh, record_length, SEEK_CUR, err) == -1) {
			g_free(wth->priv);
			return -1;
		}
		wth->data_offset += record_length;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(&rec_header, LA_RecordHeaderSize, wth->fh);
		if (bytes_read != LA_RecordHeaderSize) {
			*err = file_error(wth->fh, err_info);
			if (*err != 0) {
				g_free(wth->priv);
				return -1;
			}
			g_free(wth->priv);
			return 0;
		}
		wth->data_offset += LA_RecordHeaderSize;

		record_type = pletohs(rec_header.record_type);
		record_length = pletohs(rec_header.record_length);

		/*g_message("Record 0x%04X Length %d", record_type, record_length);*/
		switch (record_type) {
			/* Trace Summary Record */
			case RT_Summary:
				errno = WTAP_ERR_CANT_READ;
				bytes_read = file_read(summary, sizeof summary,
				    wth->fh);
				if (bytes_read != sizeof summary) {
					*err = file_error(wth->fh, err_info);
					if (*err != 0) {
						g_free(wth->priv);
						return -1;
					}
					g_free(wth->priv);
					return 0;
				}
				wth->data_offset += sizeof summary;

				/* Assume that the date of the creation of the trace file
				 * is the same date of the trace. Lanalyzer doesn't
				 * store the creation date/time of the trace, but only of
				 * the file. Unless you traced at 11:55 PM and saved at 00:05
				 * AM, the assumption that trace.date == file.date is true.
				 */
				cr_day = summary[0];
				cr_month = summary[1];
				cr_year = pletohs(&summary[2]);
				/*g_message("Day %d Month %d Year %d (%04X)", cr_day, cr_month,
						cr_year, cr_year);*/

				/* Get capture start time. I learned how to do
				 * this from Guy's code in ngsniffer.c
				 */
				tm.tm_year = cr_year - 1900;
				tm.tm_mon = cr_month - 1;
				tm.tm_mday = cr_day;
				tm.tm_hour = 0;
				tm.tm_min = 0;
				tm.tm_sec = 0;
				tm.tm_isdst = -1;
				lanalyzer->start = mktime(&tm);
				/*g_message("Day %d Month %d Year %d", tm.tm_mday,
						tm.tm_mon, tm.tm_year);*/
				mxslc = pletohs(&summary[30]);
				wth->snapshot_length = mxslc;

				record_length = 0; /* to fake the next iteration of while() */
				board_type = pletohs(&summary[188]);
				switch (board_type) {
					case BOARD_325:
						wth->file_encap = WTAP_ENCAP_ETHERNET;
						break;
					case BOARD_325TR:
						wth->file_encap = WTAP_ENCAP_TOKEN_RING;
						break;
					default:
						g_free(wth->priv);
						*err = WTAP_ERR_UNSUPPORTED_ENCAP;
						*err_info = g_strdup_printf("lanalyzer: board type %u unknown",
						    board_type);
						return -1;
				}
				break;

			/* Trace Packet Data Record */
			case RT_PacketData:
				/* Go back header number of bytes so that lanalyzer_read
				 * can read this header */
				if (file_seek(wth->fh, -LA_RecordHeaderSize, SEEK_CUR, err) == -1) {
					g_free(wth->priv);
					return -1;
				}
				wth->data_offset -= LA_RecordHeaderSize;
				return 1;

			default:
				; /* no action */
		}
	}
}

#define DESCRIPTOR_LEN	32

/* Read the next packet */
static gboolean lanalyzer_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	int		packet_size = 0;
	int		bytes_read;
	char		LE_record_type[2];
	char		LE_record_length[2];
	guint16		record_type, record_length;
	gchar		descriptor[DESCRIPTOR_LEN];
	guint16		time_low, time_med, time_high, true_size;
	guint64		t;
	time_t		tsecs;
	lanalyzer_t	*lanalyzer;

	/* read the record type and length. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(LE_record_type, 2, wth->fh);
	if (bytes_read != 2) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}
	wth->data_offset += 2;
	bytes_read = file_read(LE_record_length, 2, wth->fh);
	if (bytes_read != 2) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	wth->data_offset += 2;

	record_type = pletohs(LE_record_type);
	record_length = pletohs(LE_record_length);

	/* Only Trace Packet Data Records should occur now that we're in
	 * the middle of reading packets.  If any other record type exists
	 * after a Trace Packet Data Record, mark it as an error. */
	if (record_type != RT_PacketData) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("lanalyzer: record type %u seen after trace summary record",
		    record_type);
		return FALSE;
	}
	else {
		if (record_length < DESCRIPTOR_LEN) {
			/*
			 * Uh-oh, the record isn't big enough to even have a
			 * descriptor.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("lanalyzer: file has a %u-byte record, too small to have even a packet descriptor",
			    record_length);
			return FALSE;
		}
		packet_size = record_length - DESCRIPTOR_LEN;
	}

	/* Read the descriptor data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(descriptor, DESCRIPTOR_LEN, wth->fh);
	if (bytes_read != DESCRIPTOR_LEN) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	wth->data_offset += DESCRIPTOR_LEN;

	/* Read the packet data */
	buffer_assure_space(wth->frame_buffer, packet_size);
	*data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer),
		packet_size, wth->fh);

	if (bytes_read != packet_size) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	wth->data_offset += packet_size;

	true_size = pletohs(&descriptor[4]);
	packet_size = pletohs(&descriptor[6]);

	/*
	 * OK, is the frame data size greater than than what's left of the
	 * record?
	 */
	if (packet_size > record_length - DESCRIPTOR_LEN) {
		/*
		 * Yes - treat this as an error.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("lanalyzer: Record length is less than packet size");
		return FALSE;
	}

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	time_low = pletohs(&descriptor[8]);
	time_med = pletohs(&descriptor[10]);
	time_high = pletohs(&descriptor[12]);
	t = (((guint64)time_low) << 0) + (((guint64)time_med) << 16) +
	    (((guint64)time_high) << 32);
	tsecs = (time_t) (t/2000000);
	lanalyzer = (lanalyzer_t *)wth->priv;
	wth->phdr.ts.secs = tsecs + lanalyzer->start;
	wth->phdr.ts.nsecs = ((guint32) (t - tsecs*2000000)) * 500;

	if (true_size - 4 >= packet_size) {
		/*
		 * It appears that the "true size" includes the FCS;
		 * make it reflect the non-FCS size (the "packet size"
		 * appears never to include the FCS, even if no slicing
		 * is done).
		 */
		true_size -= 4;
	}
	wth->phdr.len = true_size;
	wth->phdr.caplen = packet_size;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		wth->pseudo_header.eth.fcs_len = 0;
		break;
	}

	return TRUE;
}

static gboolean lanalyzer_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	int bytes_read;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/*
	 * Read the packet data.
	 */
	bytes_read = file_read(pd, length, wth->random_fh);
	if (bytes_read != length) {
		*err = file_error(wth->random_fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		pseudo_header->eth.fcs_len = 0;
		break;
	}

	return TRUE;
}

/*---------------------------------------------------
 * Returns TRUE on success, FALSE on error
 * Write "cnt" bytes of zero with error control
 *---------------------------------------------------*/
static gboolean s0write(wtap_dumper *wdh, size_t cnt, int *err)
{
	static const guint8 z64[64];
	size_t snack;

	while (cnt) {
		snack = cnt > 64 ? 64 : cnt;

		if (!wtap_dump_file_write(wdh, z64, snack, err))
			return FALSE;
		cnt -= snack;
	}
	return TRUE; /* ok */
}

/*---------------------------------------------------
 * Returns TRUE on success, FALSE on error
 * Write an 8-bit value with error control
 *---------------------------------------------------*/
static gboolean s8write(wtap_dumper *wdh, const guint8 s8, int *err)
{
	return wtap_dump_file_write(wdh, &s8, 1, err);
}
/*---------------------------------------------------
 * Returns TRUE on success, FALSE on error
 * Write a 16-bit value with error control
 *---------------------------------------------------*/
static gboolean s16write(wtap_dumper *wdh, const guint16 s16, int *err)
{
	return wtap_dump_file_write(wdh, &s16, 2, err);
}
/*---------------------------------------------------
 * Returns TRUE on success, FALSE on error
 * Write a 32-bit value with error control
 *---------------------------------------------------*/
static gboolean s32write(wtap_dumper *wdh, const guint32 s32, int *err)
{
	return wtap_dump_file_write(wdh, &s32, 4, err);
}
/*---------------------------------------------------
 *
 * calculates C.c = A.a - B.b
 *---------------------------------------------------*/
static void my_timersub(const struct timeval *a,
                        const struct timeval *b,
                              struct timeval *c)
{
      gint32 usec = a->tv_usec;

      c->tv_sec = a->tv_sec - b->tv_sec;
      if (b->tv_usec > usec) {
           c->tv_sec--;
           usec += 1000000;
           }
      c->tv_usec = usec - b->tv_usec;
}
/*---------------------------------------------------
 * Write a record for a packet to a dump file.
 * Returns TRUE on success, FALSE on failure.
 *---------------------------------------------------*/
static gboolean lanalyzer_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guint8 *pd, int *err)
{
      double x;
      int    i;
      int    len;
	  struct timeval tv;

      LA_TmpInfo *itmp = (LA_TmpInfo*)(wdh->priv);
      struct timeval td;
      int    thisSize = phdr->caplen + LA_PacketRecordSize + LA_RecordHeaderSize;

      if (wdh->bytes_dumped + thisSize > LA_ProFileLimit) {
            /* printf(" LA_ProFileLimit reached\n");     */
            *err = EFBIG;
            return FALSE; /* and don't forget the header */
            }

      len = phdr->caplen + (phdr->caplen ? LA_PacketRecordSize : 0);

      if (!s16write(wdh, htoles(0x1005), err))
            return FALSE;
      if (!s16write(wdh, htoles(len), err))
            return FALSE;

      tv.tv_sec  = (long int) phdr->ts.secs;
      tv.tv_usec = phdr->ts.nsecs / 1000;

      if (!itmp->init) {
            /* collect some information for the
             * finally written header
             */
		    /* XXX - this conversion could probably improved, if the start uses ns */
            itmp->start   = tv;
            itmp->pkts    = 0;
            itmp->init    = TRUE;
            itmp->encap   = wdh->encap;
            itmp->lastlen = 0;
            }

      my_timersub(&(tv),&(itmp->start),&td);

      x   = (double) td.tv_usec;
      x  += (double) td.tv_sec * 1000000;
      x  *= 2;

      if (!s16write(wdh, htoles(0x0001), err))             /* pr.rx_channels */
            return FALSE;
      if (!s16write(wdh, htoles(0x0008), err))             /* pr.rx_errors   */
            return FALSE;
      if (!s16write(wdh, htoles(phdr->len + 4), err))      /* pr.rx_frm_len  */
            return FALSE;
      if (!s16write(wdh, htoles(phdr->caplen), err))       /* pr.rx_frm_sln  */
            return FALSE;

      for (i = 0; i < 3; i++) {
            if (!s16write(wdh, htoles((guint16) x), err))  /* pr.rx_time[i]  */
                  return FALSE;
            x /= 0xffff;
      }

      if (!s32write(wdh, htolel(++itmp->pkts), err))       /* pr.pktno      */
            return FALSE;
      if (!s16write(wdh, htoles(itmp->lastlen), err))      /* pr.prlen      */
            return FALSE;
      itmp->lastlen = len;

      if (!s0write(wdh, 12, err))
            return FALSE;

      if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
            return FALSE;

      wdh->bytes_dumped += thisSize;

      return TRUE;
}

/*---------------------------------------------------
 * Returns 0 if we could write the specified encapsulation type,
 * an error indication otherwise.
 *---------------------------------------------------*/
int lanalyzer_dump_can_write_encap(int encap)
{
      /* Per-packet encapsulations aren't supported. */
      if (encap == WTAP_ENCAP_PER_PACKET)
                  return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

      if ( encap != WTAP_ENCAP_ETHERNET
        && encap != WTAP_ENCAP_TOKEN_RING )
                  return WTAP_ERR_UNSUPPORTED_ENCAP;
      /*
       * printf("lanalyzer_dump_can_write_encap(%d)\n",encap);
       */
      return 0;
}

/*---------------------------------------------------
 * Returns TRUE on success, FALSE on failure; sets "*err" to an
 * error code on failure
 *---------------------------------------------------*/
gboolean lanalyzer_dump_open(wtap_dumper *wdh, int *err)
{
      int   jump;
      void  *tmp;

      tmp = g_malloc(sizeof(LA_TmpInfo));
      if (!tmp) {
	      *err = errno;
	      return FALSE;
            }

      ((LA_TmpInfo*)tmp)->init = FALSE;
      wdh->priv          = tmp;
      wdh->subtype_write = lanalyzer_dump;
      wdh->subtype_close = lanalyzer_dump_close;

      /* Some of the fields in the file header aren't known yet so
       just skip over it for now.  It will be created after all
       of the packets have been written. */

      jump = sizeof (LA_HeaderRegularFake)
           + sizeof (LA_RxChannelNameFake)
           + sizeof (LA_TxChannelNameFake)
           + sizeof (LA_RxTemplateNameFake)
           + sizeof (LA_TxTemplateNameFake)
           + sizeof (LA_DisplayOptionsFake)
           + LA_SummaryRecordSize
           + LA_SubfileSummaryRecordSize
           + sizeof (LA_CyclicInformationFake)
           + LA_IndexRecordSize;

      if (fseek(wdh->fh, jump, SEEK_SET) == -1) {
	      *err = errno;
	      return FALSE;
            }
      wdh->bytes_dumped = jump;
      return TRUE;
}

/*---------------------------------------------------
 *
 *---------------------------------------------------*/
static gboolean lanalyzer_dump_header(wtap_dumper *wdh, int *err)
{
      LA_TmpInfo *itmp   = (LA_TmpInfo*)(wdh->priv);
      guint16 board_type = itmp->encap == WTAP_ENCAP_TOKEN_RING
                              ? BOARD_325TR     /* LANalyzer Board Type */
                              : BOARD_325;      /* LANalyzer Board Type */
      time_t secs;
      struct tm *fT;

      /* The secs variable is needed to work around 32/64-bit time_t issues.
         itmp->start is a timeval struct, which declares its tv_sec field
         (itmp->start.tv_sec) as a long (typically 32 bits). time_t can be 32
         or 64 bits, depending on the platform. Invoking as follows could
         pass a pointer to a 32-bit long where a pointer to a 64-bit time_t
         is expected: localtime((time_t*) &(itmp->start.tv_sec)) */
      secs = itmp->start.tv_sec;
      fT = localtime(&secs);
      if (fT == NULL)
            return FALSE;

      fseek(wdh->fh, 0, SEEK_SET);

      if (!wtap_dump_file_write(wdh, &LA_HeaderRegularFake,
                                sizeof LA_HeaderRegularFake, err))
		return FALSE;
      if (!wtap_dump_file_write(wdh, &LA_RxChannelNameFake,
                                sizeof LA_RxChannelNameFake, err))
		return FALSE;
      if (!wtap_dump_file_write(wdh, &LA_TxChannelNameFake,
                                sizeof LA_TxChannelNameFake, err))
		return FALSE;
      if (!wtap_dump_file_write(wdh, &LA_RxTemplateNameFake,
                                sizeof LA_RxTemplateNameFake, err))
		return FALSE;
      if (!wtap_dump_file_write(wdh, &LA_TxTemplateNameFake,
                                sizeof LA_TxTemplateNameFake, err))
		return FALSE;
      if (!wtap_dump_file_write(wdh, &LA_DisplayOptionsFake,
                                sizeof LA_DisplayOptionsFake, err))
		return FALSE;
      /*-----------------------------------------------------------------*/
      if (!s16write(wdh, htoles(RT_Summary), err))         /* rid */
            return FALSE;
      if (!s16write(wdh, htoles(SummarySize), err))        /* rlen */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_mday, err))        /* s.datcre.day */
            return FALSE;
      if (!s8write(wdh, (guint8) (fT->tm_mon+1), err))     /* s.datcre.mon */
            return FALSE;
      if (!s16write(wdh, htoles(fT->tm_year + 1900), err)) /* s.datcre.year */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_mday, err))        /* s.datclo.day */
            return FALSE;
      if (!s8write(wdh, (guint8) (fT->tm_mon+1), err))     /* s.datclo.mon */
            return FALSE;
      if (!s16write(wdh, htoles(fT->tm_year + 1900), err)) /* s.datclo.year */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_sec, err))         /* s.timeopn.second */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_min, err))         /* s.timeopn.minute */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_hour, err))        /* s.timeopn.hour */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_mday, err))        /* s.timeopn.mday */
            return FALSE;
      if (!s0write(wdh, 2, err))
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_sec, err))         /* s.timeclo.second */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_min, err))         /* s.timeclo.minute */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_hour, err))        /* s.timeclo.hour */
            return FALSE;
      if (!s8write(wdh, (guint8) fT->tm_mday, err))        /* s.timeclo.mday */
            return FALSE;
      if (!s0write(wdh, 2, err))
            return FALSE;
      if (!s0write(wdh, 6, err))                           /* EAddr  == 0      */
            return FALSE;
      if (!s16write(wdh, htoles(1), err))                  /* s.mxseqno */
            return FALSE;
      if (!s16write(wdh, htoles(0), err))                  /* s.slcoffo */
            return FALSE;
      if (!s16write(wdh, htoles(1514), err))               /* s.mxslc */
            return FALSE;
      if (!s32write(wdh, htolel(itmp->pkts), err))         /* s.totpktt */
            return FALSE;
      /*
       * statrg == 0; ? -1
       * stptrg == 0; ? -1
       * s.mxpkta[0]=0
       */
      if (!s0write(wdh, 12, err))
            return FALSE;
      if (!s32write(wdh, htolel(itmp->pkts), err))         /* sr.s.mxpkta[1]  */
            return FALSE;
      if (!s0write(wdh, 34*4, err))                        /* s.mxpkta[2-33]=0  */
            return FALSE;
      if (!s16write(wdh, htoles(board_type), err))
            return FALSE;
      if (!s0write(wdh, 20, err))                             /* board_version == 0 */
            return FALSE;
      /*-----------------------------------------------------------------*/
      if (!s16write(wdh, htoles(RT_SubfileSummary), err))     /* ssr.rid */
            return FALSE;
      if (!s16write(wdh, htoles(LA_SubfileSummaryRecordSize-4), err)) /* ssr.rlen */
            return FALSE;
      if (!s16write(wdh, htoles(1), err))                     /* ssr.seqno */
            return FALSE;
      if (!s32write(wdh, htolel(itmp->pkts), err))            /* ssr.totpkts */
            return FALSE;
      /*-----------------------------------------------------------------*/
      if (!wtap_dump_file_write(wdh, &LA_CyclicInformationFake,
                                sizeof LA_CyclicInformationFake, err))
            return FALSE;
      /*-----------------------------------------------------------------*/
      if (!s16write(wdh, htoles(RT_Index), err))              /* rid */
            return FALSE;
      if (!s16write(wdh, htoles(LA_IndexRecordSize -4), err)) /* rlen */
            return FALSE;
      if (!s16write(wdh, htoles(LA_IndexSize), err))          /* idxsp */
            return FALSE;
      if (!s0write(wdh, LA_IndexRecordSize - 6, err))
            return FALSE;

      return TRUE;
}

/*---------------------------------------------------
 * Finish writing to a dump file.
 * Returns TRUE on success, FALSE on failure.
 *---------------------------------------------------*/
static gboolean lanalyzer_dump_close(wtap_dumper *wdh, int *err)
{
      lanalyzer_dump_header(wdh,err);
      return *err ? FALSE : TRUE;
}
