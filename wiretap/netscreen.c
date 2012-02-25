/* netscreen.c
 *
 * $Id$
 *
 * Juniper NetScreen snoop output parser
 * Created by re-using a lot of code from cosine.c
 * Copyright (c) 2007 by Sake Blok <sake@euronet.nl>
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
#include "wtap-int.h"
#include "buffer.h"
#include "netscreen.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* XXX TODO:
 *
 * o  Create a wiki-page with instruction on how to make tracefiles
 *    on Juniper NetScreen devices. Also put a few examples up
 *    on the wiki (Done: wiki-page added 2007-08-03)
 *
 * o  Use the interface names to properly detect the encapsulation
 *    type (ie adsl packets are now not properly dissected)
 *    (Done: adsl packets are now correctly seen as PPP, 2007-08-03)
 *
 * o  Pass the interface names and the traffic direction to either
 *    the frame-structure, a pseudo-header or use PPI. This needs
 *    to be discussed on the dev-list first
 *    (Posted a message to wireshark-dev abou this 2007-08-03)
 *
 */



static gboolean empty_line(const gchar *line);
static gboolean info_line(const gchar *line);
static gint64 netscreen_seek_next_packet(wtap *wth, int *err, gchar **err_info,
	char *hdr);
static gboolean netscreen_check_file_type(wtap *wth, int *err,
	gchar **err_info);
static gboolean netscreen_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean netscreen_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd,
	int len, int *err, gchar **err_info);
static int parse_netscreen_rec_hdr(wtap *wth, const char *line,
	char *cap_int, gboolean *cap_dir, char *cap_dst,
	union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static int parse_netscreen_hex_dump(FILE_T fh, int pkt_len, guint8* buf,
	int *err, gchar **err_info);
static int parse_single_hex_dump_line(char* rec, guint8 *buf,
	guint byte_offset);

/* Returns TRUE if the line appears to be an empty line. Otherwise it
   returns FALSE. */
static gboolean empty_line(const gchar *line)
{
	while (*line) {
		if (isspace((guchar)*line)) {
			line++;
			continue;
		} else {
			break;
		}
	}
	if (*line == '\0')
		return TRUE;
	else
		return FALSE;
}

/* Returns TRUE if the line appears to be a line with protocol info.
   Otherwise it returns FALSE. */
static gboolean info_line(const gchar *line)
{
	int i=NETSCREEN_SPACES_ON_INFO_LINE;
	
	while (i-- > 0) {
		if (isspace((guchar)*line)) {
			line++;
			continue;
		} else {
			return FALSE;
		}
	}
	return TRUE;
}

/* Seeks to the beginning of the next packet, and returns the
   byte offset. Copy the header line to hdr. Returns -1 on failure,
   and sets "*err" to the error, sets "*err_info" to null or an
   additional error string, and sets hdr to NULL. */
static gint64 netscreen_seek_next_packet(wtap *wth, int *err, gchar **err_info,
    char *hdr)
{
	gint64 cur_off;
	char buf[NETSCREEN_LINE_LENGTH];

	while (1) {
		cur_off = file_tell(wth->fh);
		if (cur_off == -1) {
			/* Error */
			*err = file_error(wth->fh, err_info);
			hdr = NULL;
			return -1;
		}
		if (file_gets(buf, sizeof(buf), wth->fh) != NULL) {
			if (strstr(buf, NETSCREEN_REC_MAGIC_STR1) ||
			    strstr(buf, NETSCREEN_REC_MAGIC_STR2)) {
				g_strlcpy(hdr, buf, NETSCREEN_LINE_LENGTH);
				return cur_off;
			}
		} else {
			if (file_eof(wth->fh)) {
				/* We got an EOF. */
				*err = 0;
			} else {
				/* We got an error. */
				*err = file_error(wth->fh, err_info);
			}
			break;
		}
	}
	hdr = NULL;
	return -1;
}

/* Look through the first part of a file to see if this is
 * NetScreen snoop output.
 *
 * Returns TRUE if it is, FALSE if it isn't or if we get an I/O error;
 * if we get an I/O error, "*err" will be set to a non-zero value and
 * "*err_info" is set to null or an additional error string.
 */
static gboolean netscreen_check_file_type(wtap *wth, int *err, gchar **err_info)
{
	char	buf[NETSCREEN_LINE_LENGTH];
	guint	reclen, line;

	buf[NETSCREEN_LINE_LENGTH-1] = '\0';

	for (line = 0; line < NETSCREEN_HEADER_LINES_TO_CHECK; line++) {
		if (file_gets(buf, NETSCREEN_LINE_LENGTH, wth->fh) != NULL) {

			reclen = (guint) strlen(buf);
			if (reclen < strlen(NETSCREEN_HDR_MAGIC_STR1) ||
				reclen < strlen(NETSCREEN_HDR_MAGIC_STR2)) {
				continue;
			}

			if (strstr(buf, NETSCREEN_HDR_MAGIC_STR1) ||
			    strstr(buf, NETSCREEN_HDR_MAGIC_STR2)) {
				return TRUE;
			}
		} else {
			/* EOF or error. */
			if (file_eof(wth->fh))
				*err = 0;
			else
				*err = file_error(wth->fh, err_info);
			return FALSE;
		}
	}
	*err = 0;
	return FALSE;
}


int netscreen_open(wtap *wth, int *err, gchar **err_info)
{

	/* Look for a NetScreen snoop header line */
	if (!netscreen_check_file_type(wth, err, err_info)) {
		if (*err == 0)
			return 0;
		else
			return -1;
	}

	if (file_seek(wth->fh, 0L, SEEK_SET, err) == -1)	/* rewind */
		return -1;

	wth->data_offset = 0;
	wth->file_encap = WTAP_ENCAP_UNKNOWN;
	wth->file_type = WTAP_FILE_NETSCREEN;
	wth->snapshot_length = 0; /* not known */
	wth->subtype_read = netscreen_read;
	wth->subtype_seek_read = netscreen_seek_read;
	wth->tsprecision = WTAP_FILE_TSPREC_DSEC;
	
	return 1;
}

/* Find the next packet and parse it; called from wtap_read(). */
static gboolean netscreen_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	gint64		offset;
	guint8		*buf;
	int		pkt_len, caplen;
	char		line[NETSCREEN_LINE_LENGTH];
	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
	gboolean	cap_dir;
	char		cap_dst[13];
	gchar		dststr[13];

	/* Find the next packet */
	offset = netscreen_seek_next_packet(wth, err, err_info, line);
	if (offset < 0)
		return FALSE;

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	/* Parse the header */
	pkt_len = parse_netscreen_rec_hdr(wth, line, cap_int, &cap_dir, cap_dst,
		&wth->pseudo_header, err, err_info);
	if (pkt_len == -1)
		return FALSE;

	/* Make sure we have enough room for the packet */
	buffer_assure_space(wth->frame_buffer, NETSCREEN_MAX_PACKET_LEN);
	buf = buffer_start_ptr(wth->frame_buffer);

	/* Convert the ASCII hex dump to binary data */
	if ((caplen = parse_netscreen_hex_dump(wth->fh, pkt_len, buf, err,
	    err_info)) == -1) {
		return FALSE;
	}

	/*
	 * Determine the encapsulation type, based on the
	 * first 4 characters of the interface name
	 *
	 * XXX  convert this to a 'case' structure when adding more
	 *      (non-ethernet) interfacetypes
	 */
	if (strncmp(cap_int, "adsl", 4) == 0) {
                /* The ADSL interface can be bridged with or without
                 * PPP encapsulation. Check whether the first six bytes
                 * of the hex data are the same as the destination mac
                 * address in the header. If they are, assume ethernet
                 * LinkLayer or else PPP
                 */
                g_snprintf(dststr, 13, "%02x%02x%02x%02x%02x%02x",
                   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
                if (strncmp(dststr, cap_dst, 12) == 0) 
		        wth->phdr.pkt_encap = WTAP_ENCAP_ETHERNET;
                else
		        wth->phdr.pkt_encap = WTAP_ENCAP_PPP;
                }
	else if (strncmp(cap_int, "seri", 4) == 0)
		wth->phdr.pkt_encap = WTAP_ENCAP_PPP;
	else
		wth->phdr.pkt_encap = WTAP_ENCAP_ETHERNET;

	/*
	 * If the per-file encapsulation isn't known, set it to this
	 * packet's encapsulation.
	 *
	 * If it *is* known, and it isn't this packet's encapsulation,
	 * set it to WTAP_ENCAP_PER_PACKET, as this file doesn't
	 * have a single encapsulation for all packets in the file.
	 */
	if (wth->file_encap == WTAP_ENCAP_UNKNOWN)
		wth->file_encap = wth->phdr.pkt_encap;
	else {
		if (wth->file_encap != wth->phdr.pkt_encap)
			wth->file_encap = WTAP_ENCAP_PER_PACKET;
	}

	wth->data_offset = offset;
	wth->phdr.caplen = caplen;
	*data_offset = offset;
	return TRUE;
}

/* Used to read packets in random-access fashion */
static gboolean
netscreen_seek_read (wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info)
{
	char		line[NETSCREEN_LINE_LENGTH];
	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
	gboolean	cap_dir;
	char		cap_dst[13];

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
		return FALSE;
	}

	if (file_gets(line, NETSCREEN_LINE_LENGTH, wth->random_fh) == NULL) {
		*err = file_error(wth->random_fh, err_info);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	if (parse_netscreen_rec_hdr(NULL, line, cap_int, &cap_dir, cap_dst,
           pseudo_header, err, err_info) == -1) {
		return FALSE;
	}

	if (parse_netscreen_hex_dump(wth->random_fh, len, pd, err, err_info)
	    == -1) {
		return FALSE;
	}
	return TRUE;
}

/* Parses a packet record header. There are a few possible formats:
 * 
 * XXX list extra formats here!
6843828.0: trust(o) len=98:00121ebbd132->00600868d659/0800
              192.168.1.1 -> 192.168.1.10/6
              vhl=45, tos=00, id=37739, frag=0000, ttl=64 tlen=84
              tcp:ports 2222->2333, seq=3452113890, ack=1540618280, flag=5018/ACK
              00 60 08 68 d6 59 00 12 1e bb d1 32 08 00 45 00     .`.h.Y.....2..E.
              00 54 93 6b 00 00 40 06 63 dd c0 a8 01 01 c0 a8     .T.k..@.c.......
              01 0a 08 ae 09 1d cd c3 13 e2 5b d3 f8 28 50 18     ..........[..(P.
              1f d4 79 21 00 00 e7 76 89 64 16 e2 19 0a 80 09     ..y!...v.d......
              31 e7 04 28 04 58 f3 d9 b1 9f 3d 65 1a db d8 61     1..(.X....=e...a
              2c 21 b6 d3 20 60 0c 8c 35 98 88 cf 20 91 0e a9     ,!...`..5.......
              1d 0b                                               ..


 */
static int
parse_netscreen_rec_hdr(wtap *wth, const char *line, char *cap_int,
    gboolean *cap_dir, char *cap_dst, union wtap_pseudo_header *pseudo_header _U_,
    int *err, gchar **err_info)
{
	int	sec;
	int	dsec, pkt_len;
	char	direction[2];
	char	cap_src[13];

	if (sscanf(line, "%9d.%9d: %15[a-z0-9/:.](%1[io]) len=%9d:%12s->%12s/",
		   &sec, &dsec, cap_int, direction, &pkt_len, cap_src, cap_dst) < 5) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("netscreen: Can't parse packet-header");
		return -1;
	}

	*cap_dir = (direction[0] == 'o' ? NETSCREEN_EGRESS : NETSCREEN_INGRESS);

	if (wth) {
		wth->phdr.ts.secs  = sec;
		wth->phdr.ts.nsecs = dsec * 100000000;
		wth->phdr.len = pkt_len;
	}

	return pkt_len;
}

/* Converts ASCII hex dump to binary data. Returns the capture length.
   If any error is encountered, -1 is returned. */
static int
parse_netscreen_hex_dump(FILE_T fh, int pkt_len, guint8* buf, int *err, gchar **err_info)
{
	gchar	line[NETSCREEN_LINE_LENGTH];
	int	n, i = 0, offset = 0;

	while(1) {

		/* The last packet is not delimited by an empty line, but by EOF
		 * So accept EOF as a valid delimiter too
		 */
		if (file_gets(line, NETSCREEN_LINE_LENGTH, fh) == NULL) {
			break;
		}

		/* packets are delimited with empty lines */
		if (empty_line(line)) {
			break;
		}
		
		/* terminate the line before the ascii-data to prevent the 
		 * parser from parsing one or more extra bytes from the 
		 * ascii-data.
		 * Check for longer lines to prevent wireless hexdumps to
		 * be cut in the middle (they can have 14 extra spaces
		 * before the hex-data)
		 */
		if(strlen(line) != 98) 
			line[62] = '\0';
		else
			line[76] = '\0';

		n = parse_single_hex_dump_line(line, buf, offset);

		/* the smallest packet has a length of 6 bytes, if
		 * the first hex-data is less then check whether 
		 * it is a info-line and act accordingly
		 */
		if (offset == 0 && n < 6) {
			if (info_line(line)) {
				if (++i <= NETSCREEN_MAX_INFOLINES) {
					continue;
				}
			} else {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = g_strdup("netscreen: cannot parse hex-data");
				return -1;
			}
		}

		/* If there is no more data and the line was not empty,
		 * then there must be an error in the file
		 */
		if(n == -1) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("netscreen: cannot parse hex-data");
			return -1;
		}

		/* Adjust the offset to the data that was just added to the buffer */
		offset += n;

		/* If there was more hex-data than was announced in the len=x 
		 * header, then then there must be an error in the file
		 */
		if(offset > pkt_len) {
			*err = WTAP_ERR_BAD_FILE;
                        *err_info = g_strdup("netscreen: to much hex-data");
                        return -1;
		}
	}
	return offset;
}


/* Take a string representing one line from a hex dump and converts
 * the text to binary data. We place the bytes in the buffer at the
 * specified offset.
 *
 * Returns number of bytes successfully read, -1 if bad.  */
static int
parse_single_hex_dump_line(char* rec, guint8 *buf, guint byte_offset)
{
	int num_items_scanned, i;
	unsigned int bytes[16];

	num_items_scanned = sscanf(rec, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
			       &bytes[0], &bytes[1], &bytes[2], &bytes[3],
			       &bytes[4], &bytes[5], &bytes[6], &bytes[7],
			       &bytes[8], &bytes[9], &bytes[10], &bytes[11],
			       &bytes[12], &bytes[13], &bytes[14], &bytes[15]);
	if (num_items_scanned == 0)
		return -1;

	if (num_items_scanned > 16)
		num_items_scanned = 16;

	for (i=0; i<num_items_scanned; i++) {
		buf[byte_offset + i] = (guint8)bytes[i];
	}

	return num_items_scanned;
}
