/* vms.c
 *
 * $Id: vms.c,v 1.5 2002/01/30 18:58:04 guy Exp $
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap-int.h"
#include "buffer.h"
#include "vms.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* This module reads the output of the 'TCPIPTRACE' command in VMS
 * It was initially based on toshiba.c.
 */

/*
   Example 'TCPIPTRACE' output data:
   TCPIPtrace full display RCV packet 8 at 10-JUL-2001 14:54:19.56

   IP Version = 4,  IHL = 5,  TOS = 00,   Total Length = 84 = ^x0054
   IP Identifier  = ^x178F,  Flags (0=0,DF=0,MF=0),
         Fragment Offset = 0 = ^x0000,   Calculated Offset = 0 = ^x0000
   IP TTL = 64 = ^x40,  Protocol = 17 = ^x11,  Header Checksum = ^x4C71
   IP Source Address      = 10.12.1.80
   IP Destination Address = 10.12.1.50

   UDP Source Port = 731,   UDP Destination Port = 111
   UDP Header and Datagram Length = 64 = ^x0040,   Checksum = ^xB6C0

   50010C0A   714C1140   00008F17   54000045    0000    E..T....@.Lq...P
   27E54C3C | C0B64000   6F00DB02 | 32010C0A    0010    ...2...o.@..<L.'
   02000000   A0860100   02000000   00000000    0020    ................
   00000000   00000000   00000000   03000000    0030    ................
   06000000   01000000   A5860100   00000000    0040    ................
                                    00000000    0050    ....

--------------------------------------------------------------------------------

 */

/* Magic text to check for VMS-ness of file */
static const char vms_hdr_magic[]  =
{ 'T', 'C', 'P', 'I', 'P', 't', 'r', 'a', 'c', 'e', ' '};
#define VMS_HDR_MAGIC_SIZE  (sizeof vms_hdr_magic  / sizeof vms_hdr_magic[0])

/* Magic text for start of packet */
#define vms_rec_magic vms_hdr_magic
#define VMS_REC_MAGIC_SIZE  (sizeof vms_rec_magic  / sizeof vms_rec_magic[0])

static gboolean vms_read(wtap *wth, int *err, long *data_offset);
static int vms_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int len);
static gboolean parse_single_hex_dump_line(char* rec, guint8 *buf, long byte_offset, int in_off, int remaining_bytes);
static int parse_vms_hex_dump(FILE_T fh, int pkt_len, guint8* buf, int *err);
static int parse_vms_rec_hdr(wtap *wth, FILE_T fh, int *err);


/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure. */
/* XXX - Handle I/O errors. */
static long vms_seek_next_packet(wtap *wth)
{
  int byte;
  unsigned int level = 0;

  while ((byte = file_getc(wth->fh)) != EOF) {
    if ((level == 3) && (byte != vms_rec_magic[level]))
      level += 2;  /* Accept TCPtrace as well as TCPIPtrace */
    if (byte == vms_rec_magic[level]) {
      level++;
      if (level >= VMS_REC_MAGIC_SIZE) {
          /* note: we're leaving file pointer right after the magic characters */
        return file_tell(wth->fh) + 1;
      }
    } else {
      level = 0;
    }
  }
  return -1;
}

#define VMS_HEADER_LINES_TO_CHECK    200
#define VMS_LINE_LENGTH        240

/* Look through the first part of a file to see if this is
 * a VMS trace file.
 *
 * Returns TRUE if it is, FALSE if it isn't.
 *
 * Leaves file handle at begining of line that contains the VMS Magic
 * identifier.
 */
static gboolean vms_check_file_type(wtap *wth)
{
    char    buf[VMS_LINE_LENGTH];
    int    line, byte;
    unsigned int reclen, i, level;
    long mpos;
   
    buf[VMS_LINE_LENGTH-1] = 0;

    for (line = 0; line < VMS_HEADER_LINES_TO_CHECK; line++) {
        mpos = file_tell(wth->fh);
        if (file_gets(buf, VMS_LINE_LENGTH, wth->fh) != NULL) {

            reclen = strlen(buf);
            if (reclen < VMS_HDR_MAGIC_SIZE)
                continue;

            level = 0;
            for (i = 0; i < reclen; i++) {
                byte = buf[i];
		if ((level == 3) && (byte != vms_hdr_magic[level]))
		    level += 2; /* Accept TCPIPtrace as well as TCPtrace */
                if (byte == vms_hdr_magic[level]) {
                    level++;
                    if (level >= VMS_HDR_MAGIC_SIZE) {
                        file_seek(wth->fh, mpos, SEEK_SET);
                        return TRUE;
                    }
                }
                else
                    level = 0;
            }
        }
        else
            return FALSE;
    }
    return FALSE;
}


/* XXX - return -1 on I/O error and actually do something with 'err'. */
int vms_open(wtap *wth, int *err)
{
    /* Look for VMS header */
    if (!vms_check_file_type(wth)) {
        return 0;
    }

    wth->data_offset = 0;
    wth->file_encap = WTAP_ENCAP_RAW_IP;
    wth->file_type = WTAP_FILE_VMS;
    wth->snapshot_length = 16384; /* just guessing */
    wth->subtype_read = vms_read;
    wth->subtype_seek_read = vms_seek_read;

    return 1;
}

/* Find the next packet and parse it; called from wtap_loop(). */
static gboolean vms_read(wtap *wth, int *err, long *data_offset)
{
    long   offset = 0;
    guint8    *buf;
    int    pkt_len;

    /* Find the next packet */
    offset = vms_seek_next_packet(wth);
    if (offset < 1) {
        *err = 0;    /* XXX - assume, for now, that it's an EOF */
        return FALSE;
    }

    /* Parse the header */
    pkt_len = parse_vms_rec_hdr(wth, wth->fh, err);

    if (pkt_len == -1)
	return FALSE;

    /* Make sure we have enough room for the packet */
    buffer_assure_space(wth->frame_buffer, pkt_len);
    buf = buffer_start_ptr(wth->frame_buffer);

    /* Convert the ASCII hex dump to binary data */
    parse_vms_hex_dump(wth->fh, pkt_len, buf, err);

    wth->data_offset = offset;
    *data_offset = offset;
    return TRUE;
}

/* Used to read packets in random-access fashion */
static int
vms_seek_read (wtap *wth, long seek_off, union wtap_pseudo_header *pseudo_header,
    guint8 *pd, int len)
{
    int    pkt_len;
    int    err;

    file_seek(wth->random_fh, seek_off - 1, SEEK_SET);

    pkt_len = parse_vms_rec_hdr(NULL, wth->random_fh, &err);

    if (pkt_len != len) {
        return -1;
    }

    parse_vms_hex_dump(wth->random_fh, pkt_len, pd, &err);

    return 0;
}

/* isdumpline assumes that dump lines start with some spaces followed by a
 * hex number.
 */
static int
isdumpline( guchar *line )
{
    int i = 0;

    while (i<VMS_LINE_LENGTH && !isalnum(line[i]))
        i++;

    if (! isxdigit(line[i]))
        return 0;

    while (i<VMS_LINE_LENGTH && isxdigit(line[i]))
        i++;

    return isspace(line[i]);
}

/* Parses a packet record header. */
static int
parse_vms_rec_hdr(wtap *wth, FILE_T fh, int *err)
{
    char    line[VMS_LINE_LENGTH];
    int    num_items_scanned;
    int	   pkt_len = 0;
    int	   pktnum;
    int	   csec = 101;
    struct tm time;
    char mon[4] = {'J', 'A', 'N', 0};
    guchar *p;
    static guchar months[] = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";

    time.tm_year = 1970;
    time.tm_hour = 1;
    time.tm_min = 1;
    time.tm_sec = 1;


    /* Skip lines until one starts with a hex number */
    do {
        if (file_gets(line, VMS_LINE_LENGTH, fh) == NULL) {
            *err = file_error(fh);
	    if ((*err == 0) && (csec != 101)) {
		*err = WTAP_ERR_SHORT_READ;
            }
            return -1;
        }
	if ((csec == 101) && (p = strstr(line, "packet "))
	    && (! strstr(line, "could not save "))) {
	    /* Find text in line starting with "packet ". */
	    num_items_scanned = sscanf(p,
				       "packet %d at %d-%3s-%d %d:%d:%d.%d",
				       &pktnum, &time.tm_mday, mon,
				       &time.tm_year, &time.tm_hour,
				       &time.tm_min, &time.tm_sec, &csec);

	    if (num_items_scanned != 8) {
	        *err = WTAP_ERR_BAD_RECORD;
		return -1;
	    }
	}
        if ( (! pkt_len) && (p = strstr(line, "Length"))) {
            p += sizeof("Length ");
            while (*p && ! isdigit(*p))
                p++;

            if ( !*p ) {
                *err = WTAP_ERR_BAD_RECORD;
                return -1;
            }

            pkt_len = atoi(p);
	    break;
        }
    } while (! isdumpline(line));

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
parse_vms_hex_dump(FILE_T fh, int pkt_len, guint8* buf, int *err)
{
    guchar line[VMS_LINE_LENGTH];
    int    i;
    int    offset = 0;

    for (i = 0; i < pkt_len; i += 16) {
        if (file_gets(line, VMS_LINE_LENGTH, fh) == NULL) {
            *err = file_error(fh);
            if (*err == 0) {
                *err = WTAP_ERR_SHORT_READ;
            }
            return -1;
        }
        if (i == 0) {
	    while (! isdumpline(line)) /* advance to start of hex data */
	        if (file_gets(line, VMS_LINE_LENGTH, fh) == NULL) {
		    *err = file_error(fh);
		    if (*err == 0) {
		        *err = WTAP_ERR_SHORT_READ;
		    }
		    return -1;
		}
            while (line[offset] && !isxdigit(line[offset]))
                offset++;
	}
	if (!parse_single_hex_dump_line(line, buf, i,
					offset, pkt_len - i)) {
            *err = WTAP_ERR_BAD_RECORD;
            return -1;
        }
    }
    /* Avoid TCPIPTRACE-W-BUFFERSFUL, TCPIPtrace could not save n packets.
     * errors. */
    file_gets(line, VMS_LINE_LENGTH, fh);
    return 0;
}

/*
          1         2         3         4
0123456789012345678901234567890123456789012345
   50010C0A   A34C0640   00009017   2C000045    0000    E..,....@.L....P
   00000000   14945E52   0A00DC02 | 32010C0A    0010    ...2....R^......
       0000 | B4050402   00003496   00020260    0020    `....4........
*/

#define START_POS    7
#define HEX_LENGTH    ((8 * 4) + 7) /* eight clumps of 4 bytes with 7 inner spaces */
/* Take a string representing one line from a hex dump and converts the
 * text to binary data. We check the printed offset with the offset
 * we are passed to validate the record. We place the bytes in the buffer
 * at the specified offset.
 *
 * Returns TRUE if good hex dump, FALSE if bad.
 */
static gboolean
parse_single_hex_dump_line(char* rec, guint8 *buf, long byte_offset,
               int in_off, int remaining) {

    int        i;
    char        *s;
    int        value;
    static int offsets[16] = {39,37,35,33,28,26,24,22,17,15,13,11,6,4,2,0};
    char lbuf[3] = {0,0,0};
   

    /* Get the byte_offset directly from the record */
    s = rec;
    value = strtoul(s + 45 + in_off, NULL, 16);
   
    if (value != byte_offset) {
        return FALSE;
    }

    if (remaining > 16)
	remaining = 16;

    /* Read the octets right to left, as that is how they are displayed
     * in VMS.
     */

    for (i = 0; i < remaining; i++) {
        lbuf[0] = rec[offsets[i] + in_off];
        lbuf[1] = rec[offsets[i] + 1 + in_off];

        buf[byte_offset + i] = (guint8) strtoul(lbuf, NULL, 16);
    }

    return TRUE;
}
