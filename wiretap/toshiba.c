/* toshiba.c
 *
 * $Id: toshiba.c,v 1.6 2000/01/01 04:01:41 gram Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap.h"
#include "buffer.h"
#include "toshiba.h"
#include "file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This module reads the output of the 'snoop' command in the Toshiba
 * TR-600 and TR-650 "Compact" ISDN Routers. You can telnet to the
 * router and run 'snoop' on the different channels, and at different
 * detail levels. Be sure to choose 'dump' to get the hex dump.
 * The 'snoop' command has nothing to do with the Solaris 'snoop'
 * command, except that they both capture packets.
 */

/*
   Example 'snoop' output data:
  

Script started on Thu Sep  9 21:48:49 1999
]0;gram@nirvana:/tmp$ telnet 10.0.0.254
Trying 10.0.0.254...
Connected to 10.0.0.254.
Escape character is '^]'.


TR-600(tr600) System Console

Login:admin
Password:*******
*--------------------------------------------------------*
|             T O S H I B A    T R - 6 0 0               |
|                 <  Compact Router >                    |
|                       V1.02.02                         |
|                                                        |
|  (C) Copyright TOSHIBA Corp. 1997 All rights reserved. |
*--------------------------------------------------------*

tr600>snoop dump b1
 Trace start?(on/off/dump/dtl)->dump
 IP Address?->b1
B1 Port Filetering
Trace start(Dump Mode)...

tr600>[No.1] 00:00:09.14 B1:1 Tx 207.193.26.136->151.164.1.8 DNS  SPORT=1028 LEN=38 CHKSUM=4FD4 ID=2390 Query RD QCNT=1 pow.zing.org?
OFFSET 0001-0203-0405-0607-0809-0A0B-0C0D-0E0F 0123456789ABCDEF LEN=67
0000 : FF03 003D C000 0008 2145 0000 3A12 6500 ...=....!E..:.e.
0010 : 003F 11E6 58CF C11A 8897 A401 0804 0400 .?..X...........
0020 : 3500 264F D409 5601 0000 0100 0000 0000 5.&O..V.........
0030 : 0003 706F 7704 7A69 6E67 036F 7267 0000 ..pow.zing.org..
0040 : 0100 01                                 ...

[No.2] 00:00:09.25 B1:1 Rx 151.164.1.8->207.193.26.136 DNS  DPORT=1028 LEN=193 CHKSUM=3E06 ID=2390 Answer RD RA QCNT=1 pow.zing.org? ANCNT=1 pow.zing.org=206.57.36.90 TTL=2652
OFFSET 0001-0203-0405-0607-0809-0A0B-0C0D-0E0F 0123456789ABCDEF LEN=222
0000 : FF03 003D C000 0013 2145 0000 D590 9340 ...=....!E.....@
0010 : 00F7 116F 8E97 A401 08CF C11A 8800 3504 ...o..........5.
0020 : 0400 C13E 0609 5681 8000 0100 0100 0300 ...>..V.........
0030 : 0303 706F 7704 7A69 6E67 036F 7267 0000 ..pow.zing.org..
0040 : 0100 01C0 0C00 0100 0100 000A 5C00 04CE ............\...
0050 : 3924 5A04 5A49 4E47 036F 7267 0000 0200 9$Z.ZING.org....
0060 : 0100 016F 5B00 0D03 4841 4E03 5449 5703 ...o[...HAN.TIW.
0070 : 4E45 5400 C02E 0002 0001 0001 6F5B 0006 NET.........o[..
0080 : 034E 5331 C02E C02E 0002 0001 0001 6F5B .NS1..........o[
0090 : 001C 0854 414C 4945 5349 4E0D 434F 4E46 ...TALIESIN.CONF
00A0 : 4142 554C 4154 494F 4E03 434F 4D00 C042 ABULATION.COM..B
00B0 : 0001 0001 0001 51EC 0004 CE39 2406 C05B ......Q....9$..[
00C0 : 0001 0001 0001 6F5B 0004 CE39 245A C06D ......o[...9$Z.m
00D0 : 0001 0001 0001 4521 0004 187C 1F01      ......E!...|..

 */

/* Magic text to check for toshiba-ness of file */
static const char toshiba_hdr_magic[]  =
{ 'T', ' ', 'O', ' ', 'S', ' ', 'H', ' ', 'I', ' ', 'B', ' ', 'A' };
#define TOSHIBA_HDR_MAGIC_SIZE  (sizeof toshiba_hdr_magic  / sizeof toshiba_hdr_magic[0])

/* Magic text for start of packet */
static const char toshiba_rec_magic[]  = { '[', 'N', 'o', '.' };
#define TOSHIBA_REC_MAGIC_SIZE  (sizeof toshiba_rec_magic  / sizeof toshiba_rec_magic[0])

static int toshiba_read(wtap *wth, int *err);
static gboolean parse_single_hex_dump_line(char* rec, guint8 *buf, int byte_offset);
static int parse_toshiba_hex_dump(FILE *fh, int pkt_len, guint8* buf, int *err);
static int parse_toshiba_rec_hdr(wtap *wth, FILE *fh, int *err);
static int parse_toshiba(FILE *fh, guint8 *pd, int len);

/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure. */
/* XXX - Handle I/O errors. */
static int toshiba_seek_next_packet(wtap *wth)
{
  int byte;
  int level = 0;

  while ((byte = file_getc(wth->fh)) != EOF) {
    if (byte == toshiba_rec_magic[level]) {
      level++;
      if (level >= TOSHIBA_REC_MAGIC_SIZE) {
	      /* note: we're leaving file pointer right after the magic characters */
        return file_tell(wth->fh) + 1;
      }
    } else {
      level = 0;
    }
  }
  return -1;
}

#define TOSHIBA_HEADER_LINES_TO_CHECK	200
#define TOSHIBA_LINE_LENGTH		240

/* Look through the first part of a file to see if this is
 * a Toshiba trace file.
 *
 * Returns TRUE if it is, FALSE if it isn't.
 */
static gboolean toshiba_check_file_type(wtap *wth)
{
	char	buf[TOSHIBA_LINE_LENGTH];
	int	reclen, i, line, byte, level;

	buf[TOSHIBA_LINE_LENGTH-1] = 0;

	for (line = 0; line < TOSHIBA_HEADER_LINES_TO_CHECK; line++) {
		if (file_gets(buf, TOSHIBA_LINE_LENGTH, wth->fh) != NULL) {

			reclen = strlen(buf);
			if (reclen < TOSHIBA_HDR_MAGIC_SIZE) {
				continue;
			}

			level = 0;
			for (i = 0; i < reclen; i++) {
				byte = buf[i];
				if (byte == toshiba_hdr_magic[level]) {
					level++;
					if (level >= TOSHIBA_HDR_MAGIC_SIZE) {
						return TRUE;
					}
				}
				else {
					level = 0;
				}
			}
		}
		else {
			return FALSE;
		}
	}
	return FALSE;
}


/* XXX - return -1 on I/O error and actually do something with 'err'. */
int toshiba_open(wtap *wth, int *err)
{
	/* Reset file position and look for Toshiba header */
	file_seek(wth->fh, 0, SEEK_SET);
 
	if (!toshiba_check_file_type(wth)) {
		return 0;
	}

	wth->data_offset = 0;
	wth->file_encap = WTAP_ENCAP_PER_PACKET;
	wth->file_type = WTAP_FILE_TOSHIBA;
	wth->snapshot_length = 16384; /* just guessing */
	wth->subtype_read = toshiba_read;

	return 1;
}

/* Find the next packet and parse it; called from wtap_loop(). */
static int toshiba_read(wtap *wth, int *err)
{
	int	offset = 0;
	guint8	*buf;
	int	pkt_len;

	/* Find the next packet */
	offset = toshiba_seek_next_packet(wth);
	if (offset < 1) {
		return 0;
	}

	/* Parse the header */
	pkt_len = parse_toshiba_rec_hdr(wth, wth->fh, err);

	/* Make sure we have enough room for the packet */
	buffer_assure_space(wth->frame_buffer, wth->snapshot_length);
	buf = buffer_start_ptr(wth->frame_buffer);

	/* Convert the ASCII hex dump to binary data */
	parse_toshiba_hex_dump(wth->fh, pkt_len, buf, err);

	wth->data_offset = offset;
	return offset;
}

/* Used to read packets in random-access fashion */
int
toshiba_seek_read (FILE *fh, int seek_off, guint8 *pd, int len)
{
	file_seek(fh, seek_off - 1, SEEK_SET);
	return parse_toshiba(fh, pd, len);
}

/* Used to read packets in random-access fashion */
static int
parse_toshiba(FILE *fh, guint8 *pd, int len)
{
	int	pkt_len;
	int	err;

	pkt_len = parse_toshiba_rec_hdr(NULL, fh, &err);

	if (pkt_len != len) {
		return -1;
	}

	parse_toshiba_hex_dump(fh, pkt_len, pd, &err);

	return 0;
}

/* Parses a packet record header. */
static int
parse_toshiba_rec_hdr(wtap *wth, FILE *fh, int *err)
{
	char	line[TOSHIBA_LINE_LENGTH];
	int	num_items_scanned;
	int	pkt_len, pktnum, hr, min, sec, csec;
	char	channel[10], direction[10];

	/* Our file pointer should be on the line containing the
	 * summary information for a packet. Read in that line and
	 * extract the useful information
	 */
	if (file_gets(line, TOSHIBA_LINE_LENGTH, fh) == NULL) {
		*err = file_error(fh);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	/* Find text in line after "[No.". Limit the length of the
	 * two strings since we have fixed buffers for channel[] and
	 * direction[] */
	num_items_scanned = sscanf(line, "%d] %d:%d:%d.%d %9s %9s",
			&pktnum, &hr, &min, &sec, &csec, channel, direction);

	if (num_items_scanned != 7) {
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}

	/* The next line contains mostly junk, but it does contain the
	 * packet length. */
	if (file_gets(line, TOSHIBA_LINE_LENGTH, fh) == NULL) {
		*err = file_error(fh);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	num_items_scanned = sscanf(line+64, "LEN=%d", &pkt_len);
	if (num_items_scanned != 1) {
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}

	if (wth) {
		wth->phdr.ts.tv_sec = hr * 3600 + min * 60 + sec;
		wth->phdr.ts.tv_usec = csec * 10000;
		wth->phdr.caplen = pkt_len;
		wth->phdr.len = pkt_len;
		switch (channel[0]) {
			case 'B':
				wth->phdr.pkt_encap = WTAP_ENCAP_PPP;
				break;

			case 'D':
				wth->phdr.pkt_encap = WTAP_ENCAP_LAPD;
				wth->phdr.pseudo_header.lapd.from_network_to_user = 
					(direction[0] == 'R' ? TRUE : FALSE );
				break;
			
			default:
				wth->phdr.pkt_encap = WTAP_ENCAP_ETHERNET;
				break;
		}
	}
	return pkt_len;
}

/* Converts ASCII hex dump to binary data */
static int
parse_toshiba_hex_dump(FILE *fh, int pkt_len, guint8* buf, int *err)
{
	char	line[TOSHIBA_LINE_LENGTH];
	int	i, hex_lines;
	
	/* Calculate the number of hex dump lines, each
	 * containing 16 bytes of data */
	hex_lines = pkt_len / 16 + ((pkt_len % 16) ? 1 : 0);

	for (i = 0; i < hex_lines; i++) {
		if (file_gets(line, TOSHIBA_LINE_LENGTH, fh) == NULL) {
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
0000 : FF03 003D C000 0008 2145 0000 3A12 6500 ...=....!E..:.e.
0010 : 003F 11E6 58CF C11A 8897 A401 0804 0400 .?..X...........
0020 : 0100 01                                 ...
*/

#define START_POS	7
#define HEX_LENGTH	((8 * 4) + 7) /* eight clumps of 4 bytes with 7 inner spaces */

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
parse_single_hex_dump_line(char* rec, guint8 *buf, int byte_offset) {

	int		pos, i;
	char		*s;
	unsigned long	value;
	guint16		word_value;

	/* Get the byte_offset directly from the record */
	rec[4] = '\0';
	s = rec;
	value = strtoul(s, NULL, 16);

	if (value != byte_offset) {
		return FALSE;
	}

	/* Go through the substring representing the values and:
	 * 	1. Replace any spaces with '0's
	 * 	2. Place \0's every 5 bytes (to terminate the string)
	 *
	 * Then read the eight sets of hex bytes
	 */

	for (pos = START_POS; pos < START_POS + HEX_LENGTH; pos++) {
		if (rec[pos] == ' ') {
			rec[pos] = '0';
		}
	}

	pos = START_POS;
	for (i = 0; i < 8; i++) {
		rec[pos+4] = '\0';

		word_value = (guint16) strtoul(&rec[pos], NULL, 16);
		buf[byte_offset + i * 2 + 0] = (guint8) (word_value >> 8);
		buf[byte_offset + i * 2 + 1] = (guint8) (word_value & 0x00ff);
		pos += 5;
	}

	return TRUE;
}
