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

	http://secinf.net/info/nw/lan/trace.txt
 */

/* LANalyzer board types (which indicate the type of network on which
   the capture was done). */
#define BOARD_325		226	/* LANalyzer 325 (Ethernet) */
#define BOARD_325TR		227	/* LANalyzer 325TR (Token-ring) */


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

static gboolean lanalyzer_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean lanalyzer_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info);
static void     lanalyzer_close(wtap *wth);
static gboolean lanalyzer_dump_close(wtap_dumper *wdh, int *err);

int lanalyzer_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char LE_record_type[2];
	char LE_record_length[2];
	char summary[210];
	guint16 board_type, mxslc;
	guint16 record_type, record_length;
	guint8 cr_day, cr_month;
	guint16 cr_year;
	struct tm tm;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(LE_record_type, 1, 2, wth->fh);
	bytes_read += file_read(LE_record_length, 1, 2, wth->fh);
	if (bytes_read != 4) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += 4;
	record_type = pletohs(LE_record_type);
	record_length = pletohs(LE_record_length); /* make sure to do this for while() loop */

	if (record_type != RT_HeaderRegular && record_type != RT_HeaderCyclic) {
		return 0;
	}

	/* If we made it this far, then the file is a LANAlyzer file.
	 * Let's get some info from it. Note that we get wth->snapshot_length
	 * from a record later in the file. */
	wth->file_type = WTAP_FILE_LANALYZER;
	wth->capture.lanalyzer = g_malloc(sizeof(lanalyzer_t));
	wth->subtype_read = lanalyzer_read;
	wth->subtype_seek_read = lanalyzer_seek_read;
	wth->subtype_close = lanalyzer_close;
	wth->snapshot_length = 0;
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

	/* Read records until we find the start of packets */
	while (1) {
		if (file_seek(wth->fh, record_length, SEEK_CUR, err) == -1) {
			g_free(wth->capture.lanalyzer);
			return -1;
		}
		wth->data_offset += record_length;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(LE_record_type, 1, 2, wth->fh);
		bytes_read += file_read(LE_record_length, 1, 2, wth->fh);
		if (bytes_read != 4) {
			*err = file_error(wth->fh);
			if (*err != 0) {
				g_free(wth->capture.lanalyzer);
				return -1;
			}
			g_free(wth->capture.lanalyzer);
			return 0;
		}
		wth->data_offset += 4;

		record_type = pletohs(LE_record_type);
		record_length = pletohs(LE_record_length);

		/*g_message("Record 0x%04X Length %d", record_type, record_length);*/
		switch (record_type) {
			/* Trace Summary Record */
			case RT_Summary:
				errno = WTAP_ERR_CANT_READ;
				bytes_read = file_read(summary, 1, sizeof summary,
				    wth->fh);
				if (bytes_read != sizeof summary) {
					*err = file_error(wth->fh);
					if (*err != 0) {
						g_free(wth->capture.lanalyzer);
						return -1;
					}
					g_free(wth->capture.lanalyzer);
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
				wth->capture.lanalyzer->start = mktime(&tm);
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
						g_free(wth->capture.lanalyzer);
						*err = WTAP_ERR_UNSUPPORTED_ENCAP;
						*err_info = g_strdup_printf("lanalyzer: board type %u unknown",
						    board_type);
						return -1;
				}
				break;

			/* Trace Packet Data Record */
			case RT_PacketData:
				/* Go back header number ob ytes so that lanalyzer_read
				 * can read this header */
				if (file_seek(wth->fh, -bytes_read, SEEK_CUR, err) == -1) {
					g_free(wth->capture.lanalyzer);
					return -1;
				}
				wth->data_offset -= bytes_read;
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

	/* read the record type and length. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(LE_record_type, 1, 2, wth->fh);
	if (bytes_read != 2) {
		*err = file_error(wth->fh);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}
	wth->data_offset += 2;
	bytes_read = file_read(LE_record_length, 1, 2, wth->fh);
	if (bytes_read != 2) {
		*err = file_error(wth->fh);
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
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("lanalyzer: record type %u seen after trace summary record",
		    record_type);
		return FALSE;
	}
	else {
		packet_size = record_length - DESCRIPTOR_LEN;
	}

	/* Read the descriptor data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(descriptor, 1, DESCRIPTOR_LEN, wth->fh);
	if (bytes_read != DESCRIPTOR_LEN) {
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	wth->data_offset += DESCRIPTOR_LEN;

	/* Read the packet data */
	buffer_assure_space(wth->frame_buffer, packet_size);
	*data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer), 1,
		packet_size, wth->fh);

	if (bytes_read != packet_size) {
		*err = file_error(wth->fh);
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
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup("lanalyzer: Record length is less than packet size");
		return FALSE;
	}

	time_low = pletohs(&descriptor[8]);
	time_med = pletohs(&descriptor[10]);
	time_high = pletohs(&descriptor[12]);
	t = (((guint64)time_low) << 0) + (((guint64)time_med) << 16) +
	    (((guint64)time_high) << 32);
	tsecs = (time_t) (t/2000000);
	wth->phdr.ts.secs = tsecs + wth->capture.lanalyzer->start;
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
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info _U_)
{
	int bytes_read;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/*
	 * Read the packet data.
	 */
	bytes_read = file_read(pd, sizeof(guint8), length, wth->random_fh);
	if (bytes_read != length) {
		*err = file_error(wth->random_fh);
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

static void
lanalyzer_close(wtap *wth)
{
	g_free(wth->capture.lanalyzer);
}

/*---------------------------------------------------
 * Returns 0 or error
 * Write one block with error control
 *---------------------------------------------------*/
static int swrite(const void* what, guint size, FILE *hd)
{
	size_t nwritten;

	nwritten = fwrite(what, 1, size, hd);
	if (nwritten != size) {
		if (nwritten == 0 && ferror(hd))
			return errno;
		else
			return WTAP_ERR_SHORT_WRITE;
            }
	return 0; /* ok */
}

/*---------------------------------------------------
 * Returns 0 or error
 * Write one block with error control
 *---------------------------------------------------*/
static int s0write(guint cnt, FILE *hd)
{
	static guint8 z64[64];
	size_t nwritten;
	size_t snack;

	while (cnt) {
            snack = cnt > 64 ? 64 : cnt;
            nwritten = fwrite(z64, 1, snack, hd);
            if (nwritten != snack) {
		      if (nwritten == 0 && ferror(hd))
			      return errno;
		      else
			      return WTAP_ERR_SHORT_WRITE;
                  }
            cnt -= snack;
            }
	return 0; /* ok */
}

/*---------------------------------------------------
 * Returns 0 or error
 * Write one block with error control
 *---------------------------------------------------*/
static int s8write(const guint8 s8, FILE *hd)
{
	size_t nwritten;

	nwritten = fwrite(&s8, 1, 1, hd);
	if (nwritten != 1) {
		if (nwritten == 0 && ferror(hd))
			return errno;
		else
			return WTAP_ERR_SHORT_WRITE;
            }
	return 0; /* ok */
}
/*---------------------------------------------------
 * Returns 0 or error
 * Write one block with error control
 *---------------------------------------------------*/
static int s16write(const guint16 s16, FILE *hd)
{
	size_t nwritten;

	nwritten = fwrite(&s16, 1, 2, hd);
	if (nwritten != 2) {
		if (nwritten == 0 && ferror(hd))
			return errno;
		else
			return WTAP_ERR_SHORT_WRITE;
            }
	return 0; /* ok */
}
/*---------------------------------------------------
 * Returns 0 or error
 * Write one block with error control
 *---------------------------------------------------*/
static int s32write(const guint32 s32, FILE *hd)
{
	size_t nwritten;

	nwritten = fwrite(&s32, 1, 4, hd);
	if (nwritten != 4) {
		if (nwritten == 0 && ferror(hd))
			return errno;
		else
			return WTAP_ERR_SHORT_WRITE;
            }
	return 0; /* ok */
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
	const guchar *pd, int *err)
{
      double x;
      int    i;
      int    len;
	  struct timeval tv;

      LA_TmpInfo *itmp = (LA_TmpInfo*)(wdh->dump.opaque);
      struct timeval td;
      int    thisSize = phdr->caplen + LA_PacketRecordSize + LA_RecordHeaderSize;

      if (wdh->bytes_dumped + thisSize > LA_ProFileLimit) {
            /* printf(" LA_ProFileLimit reached\n");     */
            *err = EFBIG;
            return FALSE; /* and don't forget the header */
            }

      len = phdr->caplen + (phdr->caplen ? LA_PacketRecordSize : 0);

      *err = s16write(htoles(0x1005), wdh->fh);
      if (*err)
            return FALSE;
      *err = s16write(htoles(len), wdh->fh);
      if (*err)
            return FALSE;

	  tv.tv_sec  = phdr->ts.secs;
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

      *err = s16write(htoles(0x0001), wdh->fh);           /* pr.rx_channels */
      if (*err)
            return FALSE;
      *err = s16write(htoles(0x0008), wdh->fh);           /* pr.rx_errors   */
      if (*err)
            return FALSE;
      *err = s16write(htoles(phdr->len + 4), wdh->fh);    /* pr.rx_frm_len  */
      if (*err)
            return FALSE;
      *err = s16write(htoles(phdr->caplen), wdh->fh);     /* pr.rx_frm_sln  */
      if (*err)
            return FALSE;

      for (i = 0; i < 3; i++) {
            *err = s16write(htoles((guint16) x), wdh->fh);/* pr.rx_time[i]  */
            if (*err)
                  return FALSE;
            x /= 0xffff;
            }

      *err = s32write(htolel(++itmp->pkts), wdh->fh);      /* pr.pktno      */
      if (*err)
            return FALSE;
      *err = s16write(htoles(itmp->lastlen), wdh->fh);     /* pr.prlen      */
      if (*err)
            return FALSE;
      itmp->lastlen = len;

      *err = s0write(12, wdh->fh);
      if (*err)
		return FALSE;

      *err = swrite(pd , phdr->caplen , wdh->fh);
      if (*err)
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
gboolean lanalyzer_dump_open(wtap_dumper *wdh, gboolean cant_seek, int *err)
{
      int   jump;
      void  *tmp;

      /* This is a LANalyzer file.  We can't fill in some fields in the
         header until all the packets have been written, so we can't
         write to a pipe. */
      if (cant_seek) {
	      *err = WTAP_ERR_CANT_WRITE_TO_PIPE;
	      return FALSE;
            }

      tmp = g_malloc(sizeof(LA_TmpInfo));
      if (!tmp) {
	      *err = errno;
	      return FALSE;
            }

      ((LA_TmpInfo*)tmp)->init = FALSE;
      wdh->dump.opaque         = tmp;
      wdh->subtype_write       = lanalyzer_dump;
      wdh->subtype_close       = lanalyzer_dump_close;

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
      LA_TmpInfo *itmp   = (LA_TmpInfo*)(wdh->dump.opaque);
      struct tm  *fT     = localtime(&(itmp->start.tv_sec));
      guint16 board_type = itmp->encap == WTAP_ENCAP_TOKEN_RING
                              ? BOARD_325TR     /* LANalyzer Board Type */
                              : BOARD_325;      /* LANalyzer Board Type */

      fseek(wdh->fh, 0, SEEK_SET);

      *err = swrite(&LA_HeaderRegularFake,  sizeof LA_HeaderRegularFake, wdh->fh);
      if (*err)
		return FALSE;
      *err = swrite(&LA_RxChannelNameFake , sizeof LA_RxChannelNameFake , wdh->fh);
      if (*err)
		return FALSE;
      *err = swrite(&LA_TxChannelNameFake , sizeof LA_TxChannelNameFake , wdh->fh);
      if (*err)
		return FALSE;
      *err = swrite(&LA_RxTemplateNameFake, sizeof LA_RxTemplateNameFake, wdh->fh);
      if (*err)
		return FALSE;
      *err = swrite(&LA_TxTemplateNameFake, sizeof LA_TxTemplateNameFake, wdh->fh);
      if (*err)
		return FALSE;
      *err = swrite(&LA_DisplayOptionsFake, sizeof LA_DisplayOptionsFake, wdh->fh);
      if (*err)
		return FALSE;
      /*-----------------------------------------------------------------*/
      *err = s16write(htoles(RT_Summary), wdh->fh);        /* rid */
      if (*err)
            return FALSE;
      *err = s16write(htoles(SummarySize), wdh->fh);       /* rlen */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_mday, wdh->fh);       /* s.datcre.day */
      if (*err)
            return FALSE;
      *err = s8write((guint8) (fT->tm_mon+1), wdh->fh);    /* s.datcre.mon */
      if (*err)
            return FALSE;
      *err = s16write(htoles(fT->tm_year + 1900), wdh->fh);/* s.datcre.year */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_mday, wdh->fh);       /* s.datclo.day */
      if (*err)
            return FALSE;
      *err = s8write((guint8) (fT->tm_mon+1), wdh->fh);    /* s.datclo.mon */
      if (*err)
            return FALSE;
      *err = s16write(htoles(fT->tm_year + 1900), wdh->fh);/* s.datclo.year */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_sec, wdh->fh);        /* s.timeopn.second */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_min, wdh->fh);        /* s.timeopn.minute */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_hour, wdh->fh);       /* s.timeopn.hour */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_mday, wdh->fh);       /* s.timeopn.mday */
      if (*err)
            return FALSE;
      *err = s0write(2, wdh->fh);
      if (*err)
		return FALSE;
      *err = s8write((guint8) fT->tm_sec, wdh->fh);        /* s.timeclo.second */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_min, wdh->fh);        /* s.timeclo.minute */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_hour, wdh->fh);       /* s.timeclo.hour */
      if (*err)
            return FALSE;
      *err = s8write((guint8) fT->tm_mday, wdh->fh);       /* s.timeclo.mday */
      if (*err)
            return FALSE;
      *err = s0write(2, wdh->fh);
      if (*err)
		return FALSE;
      *err = s0write(6, wdh->fh);                          /* EAddr  == 0      */
      if (*err)
		return FALSE;
      *err = s16write(htoles(1), wdh->fh);                 /* s.mxseqno */
      if (*err)
            return FALSE;
      *err = s16write(htoles(0), wdh->fh);                 /* s.slcoffo */
      if (*err)
            return FALSE;
      *err = s16write(htoles(1514), wdh->fh);              /* s.mxslc */
      if (*err)
            return FALSE;
      *err = s32write(htolel(itmp->pkts), wdh->fh);        /* s.totpktt */
      if (*err)
            return FALSE;
      *err = s0write(12, wdh->fh);                         /* statrg == 0; ? -1*/
      if (*err)                                            /* stptrg == 0; ? -1*/
		return FALSE;                                  /* s.mxpkta[0]=0    */
      *err = s32write(htolel(itmp->pkts), wdh->fh);        /* sr.s.mxpkta[1]  */
      if (*err)
            return FALSE;
      *err = s0write(34*4, wdh->fh);                       /* s.mxpkta[2-33]=0  */
      if (*err)
		return FALSE;
      *err = s16write(htoles(board_type), wdh->fh);
      if (*err)
            return FALSE;
      *err = s0write(20, wdh->fh);                         /* board_version == 0 */
      if (*err)
            return FALSE;
      /*-----------------------------------------------------------------*/
      *err = s16write(htoles(RT_SubfileSummary), wdh->fh);    /* ssr.rid */
      if (*err)
            return FALSE;
      *err = s16write(htoles(LA_SubfileSummaryRecordSize-4), wdh->fh);    /* ssr.rlen */
      if (*err)
            return FALSE;
      *err = s16write(htoles(1), wdh->fh);                    /* ssr.seqno */
      if (*err)
            return FALSE;
      *err = s32write(htolel(itmp->pkts), wdh->fh);           /* ssr.totpkts */
      if (*err)
            return FALSE;
      /*-----------------------------------------------------------------*/
      *err = swrite(&LA_CyclicInformationFake, sizeof LA_CyclicInformationFake, wdh->fh);
      if (*err)
		return FALSE;
      /*-----------------------------------------------------------------*/
      *err = s16write(htoles(RT_Index), wdh->fh);             /* rid */
      if (*err)
            return FALSE;
      *err = s16write(htoles(LA_IndexRecordSize -4), wdh->fh);/* rlen */
      if (*err)
            return FALSE;
      *err = s16write(htoles(LA_IndexSize), wdh->fh);         /* idxsp */
      if (*err)
            return FALSE;
      *err = s0write(LA_IndexRecordSize - 6, wdh->fh);
      if (*err)
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
