/* dbs-etherwatch.c
 *
 * $Id: dbs-etherwatch.c,v 1.6 2002/03/05 05:58:40 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 2001 by Marc Milgram <mmilgram@arrayinc.com>
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
#include "wtap-int.h"
#include "buffer.h"
#include "dbs-etherwatch.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* This module reads the text output of the 'DBS-ETHERTRACE' command in VMS
 * It was initially based on vms.c.
 */

/*
   Example 'TCPIPTRACE' output data:
ETHERWATCH  X5-008
42 names and addresses were loaded
Reading recorded data from PERSISTENCE
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   60 byte buffer at 10-OCT-2001 10:20:45.16
  [E..<8.....Ò.....]-    0-[45 00 00 3C 38 93 00 00 1D 06 D2 12 80 93 11 1A]
  [...Ö.Ò...(¤.....]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 90 00 00 00 00]
  [.....½.....´....]-   32-[A0 02 FF FF 95 BD 00 00 02 04 05 B4 03 03 04 01]
  [......å.....    ]-   48-[01 01 08 0A 90 90 E5 14 00 00 00 00]
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   50 byte buffer at 10-OCT-2001 10:20:45.17
  [E..(8.....Ò%....]-    0-[45 00 00 28 38 94 00 00 1D 06 D2 25 80 93 11 1A]
  [...Ö.Ò...(¤.Z.4w]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 91 5A 1C 34 77]
  [P.#(Ás.....´....]-   32-[50 10 23 28 C1 73 00 00 02 04 05 B4 03 03 00 00]
  [..              ]-   48-[02 04]
 */

/* Magic text to check for DBS-ETHERWATCH-ness of file */
static const char dbs_etherwatch_hdr_magic[]  =
{ 'E', 'T', 'H', 'E', 'R', 'W', 'A', 'T', 'C', 'H', ' ', ' '};
#define DBS_ETHERWATCH_HDR_MAGIC_SIZE  \
        (sizeof dbs_etherwatch_hdr_magic  / sizeof dbs_etherwatch_hdr_magic[0])

/* Magic text for start of packet */
static const char dbs_etherwatch_rec_magic[]  =
{'F', 'r', 'o', 'm', ' '};
#define DBS_ETHERWATCH_REC_MAGIC_SIZE \
	(sizeof dbs_etherwatch_rec_magic  / sizeof dbs_etherwatch_rec_magic[0])

/*
 * XXX - is this the biggest packet we can get?
 */
#define DBS_ETHERWATCH_MAX_PACKET_LEN	16384

static gboolean dbs_etherwatch_read(wtap *wth, int *err, long *data_offset);
static int dbs_etherwatch_seek_read(wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len, int *err);
static gboolean parse_single_hex_dump_line(char* rec, guint8 *buf, long byte_offset);
static int parse_dbs_etherwatch_hex_dump(FILE_T fh, int pkt_len, guint8* buf, int *err);
static int parse_dbs_etherwatch_rec_hdr(wtap *wth, FILE_T fh, int *err);

/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure, and sets "*err" to the error. */
static long dbs_etherwatch_seek_next_packet(wtap *wth, int *err)
{
  int byte;
  unsigned int level = 0;
  long cur_off;

  while ((byte = file_getc(wth->fh)) != EOF) {
    if (byte == dbs_etherwatch_rec_magic[level]) {
      level++;
      if (level >= DBS_ETHERWATCH_REC_MAGIC_SIZE) {
        /* note: we're leaving file pointer right after the magic characters */
        cur_off = file_tell(wth->fh);
        if (cur_off == -1) {
          /* Error. */
          *err = file_error(wth->fh);
          return -1;
        }
        return cur_off + 1;
      }
    } else {
      level = 0;
    }
  }
  if (file_eof(wth->fh)) {
    /* We got an EOF. */
    *err = 0;
  } else {
    /* We (presumably) got an error (there's no equivalent to "ferror()"
       in zlib, alas, so we don't have a wrapper to check for an error). */
    *err = file_error(wth->fh);
  }
  return -1;
}

#define DBS_ETHERWATCH_HEADER_LINES_TO_CHECK	200
#define DBS_ETHERWATCH_LINE_LENGTH		240

/* Look through the first part of a file to see if this is
 * a DBS Ethertrace text trace file.
 *
 * Returns TRUE if it is, FALSE if it isn't or if we get an I/O error;
 * if we get an I/O error, "*err" will be set to a non-zero value.
 */
static gboolean dbs_etherwatch_check_file_type(wtap *wth, int *err)
{
	char	buf[DBS_ETHERWATCH_LINE_LENGTH];
	int	line, byte;
	unsigned int reclen, i, level;
	
	buf[DBS_ETHERWATCH_LINE_LENGTH-1] = 0;

	for (line = 0; line < DBS_ETHERWATCH_HEADER_LINES_TO_CHECK; line++) {
		if (file_gets(buf, DBS_ETHERWATCH_LINE_LENGTH, wth->fh)!=NULL){

			reclen = strlen(buf);
			if (reclen < DBS_ETHERWATCH_HDR_MAGIC_SIZE)
				continue;

			level = 0;
			for (i = 0; i < reclen; i++) {
				byte = buf[i];
				if (byte == dbs_etherwatch_hdr_magic[level]) {
					level++;
					if (level >=
					      DBS_ETHERWATCH_HDR_MAGIC_SIZE) {
						return TRUE;
					}
				}
				else
					level = 0;
			}
		}
		else {
			/* EOF or error. */
			if (file_eof(wth->fh))
				*err = 0;
			else
				*err = file_error(wth->fh);
			return FALSE;
		}
	}
	*err = 0;
	return FALSE;
}


int dbs_etherwatch_open(wtap *wth, int *err)
{
	/* Look for DBS ETHERWATCH header */
	if (!dbs_etherwatch_check_file_type(wth, err)) {
		if (*err == 0)
			return 0;
		else
			return -1;
	}

	wth->data_offset = 0;
	wth->file_encap = WTAP_ENCAP_RAW_IP;
	wth->file_type = WTAP_FILE_DBS_ETHERWATCH;
	wth->snapshot_length = 0;	/* not known */
	wth->subtype_read = dbs_etherwatch_read;
	wth->subtype_seek_read = dbs_etherwatch_seek_read;

	return 1;
}

/* Find the next packet and parse it; called from wtap_loop(). */
static gboolean dbs_etherwatch_read(wtap *wth, int *err, long *data_offset)
{
	long	offset = 0;
	guint8	*buf;
	int	pkt_len;

	/* Find the next packet */
	offset = dbs_etherwatch_seek_next_packet(wth, err);
	if (offset < 1)
		return FALSE;

	/* Parse the header */
	pkt_len = parse_dbs_etherwatch_rec_hdr(wth, wth->fh, err);
	if (pkt_len == -1)
		return FALSE;

	/* Make sure we have enough room for the packet */
	buffer_assure_space(wth->frame_buffer, DBS_ETHERWATCH_MAX_PACKET_LEN);
	buf = buffer_start_ptr(wth->frame_buffer);

	/* Convert the ASCII hex dump to binary data */
	if (parse_dbs_etherwatch_hex_dump(wth->fh, pkt_len, buf, err) == -1)
		return FALSE;

	wth->data_offset = offset;
	*data_offset = offset;
	return TRUE;
}

/* Used to read packets in random-access fashion */
static int
dbs_etherwatch_seek_read (wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header _U_,
	guint8 *pd, int len, int *err)
{
	int	pkt_len;

	if (file_seek(wth->random_fh, seek_off - 1, SEEK_SET) == -1) {
		*err = file_error(wth->random_fh);
		return -1;
	}

	pkt_len = parse_dbs_etherwatch_rec_hdr(NULL, wth->random_fh, err);

	if (pkt_len != len) {
		if (pkt_len != -1)
			*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}

	if (parse_dbs_etherwatch_hex_dump(wth->random_fh, pkt_len, pd, err) == -1)
		return -1;

	return 0;
}

/* Parses a packet record header. */
static int
parse_dbs_etherwatch_rec_hdr(wtap *wth, FILE_T fh, int *err)
{
	char	line[DBS_ETHERWATCH_LINE_LENGTH];
	int	num_items_scanned;
	int	pkt_len, csec;
	struct tm time;
	char mon[4];
	guchar *p;
	static guchar months[] = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";

	pkt_len = 0;

	/* Our file pointer should be on the first line containing the
	 * summary information for a packet. Read in that line and
	 * extract the useful information
	 */
	if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
		*err = file_error(fh);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	/* But that line only contains the mac addresses, so we will ignore
	   that line for now.  Read the next line */
	if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
		*err = file_error(fh);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	num_items_scanned = sscanf(line+33, "%d byte buffer at %d-%3s-%d %d:%d:%d.%d",
				   &pkt_len,
				   &time.tm_mday, mon,
				   &time.tm_year, &time.tm_hour, &time.tm_min,
				   &time.tm_sec, &csec);

	if (num_items_scanned != 8) {
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}

	if (wth) {
		p = strstr(months, mon);
		if (p)
			time.tm_mon = (p - months) / 3;
		time.tm_year -= 1900;

		wth->phdr.ts.tv_sec = mktime(&time);

		wth->phdr.ts.tv_usec = csec * 10000;
		wth->phdr.caplen = pkt_len;
		wth->phdr.len = pkt_len;
		wth->phdr.pkt_encap = WTAP_ENCAP_RAW_IP;
	}

	return pkt_len;
}

/* Converts ASCII hex dump to binary data */
static int
parse_dbs_etherwatch_hex_dump(FILE_T fh, int pkt_len, guint8* buf, int *err)
{
	guchar	line[DBS_ETHERWATCH_LINE_LENGTH];
	int	i, hex_lines;

	/* Calculate the number of hex dump lines, each
	 * containing 16 bytes of data */
	hex_lines = pkt_len / 16 + ((pkt_len % 16) ? 1 : 0);

	for (i = 0; i < hex_lines; i++) {
		if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
			*err = file_error(fh);
			if (*err == 0) {
				*err = WTAP_ERR_SHORT_READ;
			}
			return -1;
		}
		if (!parse_single_hex_dump_line(line, buf, i * 16)) {
			*err = WTAP_ERR_BAD_RECORD;
			return -1;
		}
	}
	return 0;
}

/*
          1         2         3         4
0123456789012345678901234567890123456789012345
  [E..(8.....Ò.....]-    0-[45 00 00 28 38 9B 00 00 1D 06 D2 1E 80 93 11 1A]
  [...Ö.Ò...(¤¿Z.4y]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 BF 5A 1C 34 79]
  [P.#(ÁC...00000..]-   32-[50 10 23 28 C1 43 00 00 03 30 30 30 30 30 00 00]
  [.0              ]-   48-[03 30]
*/

#define START_POS	28
#define HEX_LENGTH	((16 * 2) + 15) /* sixteen clumps of 2 bytes with 15 inner spaces */
/* Take a string representing one line from a hex dump and converts the
 * text to binary data. We check the printed offset with the offset
 * we are passed to validate the record. We place the bytes in the buffer
 * at the specified offset.
 *
 * In the process, we're going to write all over the string.
 *
 * Returns TRUE if good hex dump, FALSE if bad.
 */
static gboolean
parse_single_hex_dump_line(char* rec, guint8 *buf, long byte_offset) {

	int		pos, i;
	char		*s;
	long		value;


	/* Get the byte_offset directly from the record */
	rec[26] = '\0';
	s = rec + 21;
	value = strtol(s, NULL, 10);
	
	if (value != byte_offset) {
		return FALSE;
	}

	/* Go through the substring representing the values and:
	 * 	1. Replace any spaces with '0's
	 * 	2. Place \0's every 3 bytes (to terminate the string)
	 *
	 * Then read the eight sets of hex bytes
	 */

	for (pos = START_POS; pos < START_POS + HEX_LENGTH; pos++) {
		if (rec[pos] == ' ') {
			rec[pos] = '0';
		}
	}

	pos = START_POS;
	for (i = 0; i < 16; i++) {
		rec[pos+2] = '\0';

		buf[byte_offset + i] = (guint8) strtoul(&rec[pos], NULL, 16);
		pos += 3;
	}

	return TRUE;
}
